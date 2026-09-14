"""graphql_authz_probe: GraphQL-aware sibling of idor_probe -- fires the SAME query/mutation as two
identities and diffs the results, covering both field-level broken access control (a mutation that
should require an elevated role) and nested-query IDOR (a nested selection keyed by another
identity's own ID) with the same mechanism. Critically GraphQL-aware unlike a raw REST comparison:
a 200 response with a populated "errors" array is a denial, not a success.
"""
import httpx
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import native
from agent.tools.registry import get_tool, get_tools_by_category

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    """Same isolation as tests/test_authenticated_identity.py -- save_identity_credentials must
    never touch the real data/credentials/ directory during a test run."""
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    native._authenticated_clients.clear()
    yield
    native._authenticated_clients.clear()


def test_is_registered_as_an_exploit_tier_tool():
    spec = get_tool("graphql_authz_probe")
    assert spec.requires_allowed_target is True
    assert spec.allows_repeated_attempts is True
    assert "graphql_authz_probe" in {s.name for s in get_tools_by_category("exploit")}
    assert "graphql_authz_probe" in {s.name for s in get_tools_by_category("scan")}


def test_low_priv_identity_getting_the_same_real_data_is_flagged_likely_broken_access_control(monkeypatch):
    """Both identities succeed with no errors and near-identical data -- exactly the shape of a
    low-privilege identity reaching data/actions it shouldn't."""
    native.save_identity_credentials("usr_authz_bola", {
        "user_a": {"username": "", "password": "", "login_url": "", "cookie": "low=1", "authorization_header": ""},
        "user_b": {"username": "", "password": "", "login_url": "", "cookie": "high=1", "authorization_header": ""},
    })

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"user": {"id": 5, "email": "victim@example.com"}}})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.graphql_authz_probe({
        "_session_id": "usr_authz_bola", "target": "https://api.example.com/graphql",
        "query": "{ user(id: 5) { id email } }", "identity_a": "user_a", "identity_b": "user_b",
    })

    assert result["status"] == "ok"
    assert result["likely_broken_access_control"] is True
    assert result["identity_a"]["has_errors"] is False
    assert result["identity_a"]["has_real_data"] is True


def test_denied_access_returns_200_with_errors_and_is_never_misread_as_success(monkeypatch):
    """The exact misread a naive port of idor_probe's status-code-only check would make: this is a
    200 response, but it's a real denial (errors array populated, no real data)."""
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("cookie") == "low=1":
            return httpx.Response(200, json={"errors": [{"message": "not authorized"}], "data": None})
        return httpx.Response(200, json={"data": {"user": {"id": 5, "email": "victim@example.com"}}})

    native.save_identity_credentials("usr_authz_denied", {
        "user_a": {"username": "", "password": "", "login_url": "", "cookie": "low=1", "authorization_header": ""},
        "user_b": {"username": "", "password": "", "login_url": "", "cookie": "high=1", "authorization_header": ""},
    })
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.graphql_authz_probe({
        "_session_id": "usr_authz_denied", "target": "https://api.example.com/graphql",
        "query": "{ user(id: 5) { id email } }", "identity_a": "user_a", "identity_b": "user_b",
    })

    assert result["status"] == "ok"
    assert result["identity_a"]["status_code"] == 200
    assert result["identity_a"]["has_errors"] is True
    assert result["likely_broken_access_control"] is False


def test_unauthenticated_fallback_when_identity_b_omitted(monkeypatch):
    native.save_identity_credentials("usr_authz_anon", {"user_a": {"username": "", "password": "", "login_url": "", "cookie": "low=1", "authorization_header": ""}})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {"ping": "pong"}})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.graphql_authz_probe({
        "_session_id": "usr_authz_anon", "target": "https://api.example.com/graphql",
        "query": "{ ping }", "identity_a": "user_a",
    })

    assert result["status"] == "ok"
    assert result["identity_b"]["name"] == "unauthenticated"


def test_errors_for_an_unconfigured_identity():
    result = native.graphql_authz_probe({
        "_session_id": "usr_authz_none", "target": "https://api.example.com/graphql",
        "query": "{ ping }", "identity_a": "user_a",
    })
    assert result["status"] == "error"
    assert "user_a" in result["error"]
