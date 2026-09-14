"""authenticated_crawl (real endpoint discovery via a logged-in identity, replacing blind guessed
paths) and idor_probe (a single deterministic same-resource, two-identity comparison instead of
two authenticated_request calls compared by eye). Same real-httpx.MockTransport approach as
test_authenticated_identity.py -- exercises actual cookie/login/same-origin-filter/similarity
logic, not a crude monkeypatch of the whole function. Also covers the two core.py integration
points both new tools share with authenticated_request: server-injected session_id (never
model-controlled) and idor_probe's exemption from the per-finding one-shot-attempt cap.
"""
import asyncio

import httpx
import pytest

from agent.core import RunContext, _run_exploit_for_finding
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import allowed_targets, native
from agent.tools.allowed_targets import add_allowed_target
from agent.tools.registry import TOOL_REGISTRY
from sessions import store

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _run(coro):
    return asyncio.run(coro)


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    native._authenticated_clients.clear()
    yield
    native._authenticated_clients.clear()


# --- authenticated_crawl ---


def test_authenticated_crawl_errors_for_an_unconfigured_identity():
    result = native.authenticated_crawl({"_session_id": "usr_none", "identity": "user_a", "start_url": "https://example.com/"})
    assert result["status"] == "error"
    assert "user_a" in result["error"]


def test_authenticated_crawl_follows_same_origin_links_and_skips_offsite_ones(monkeypatch):
    native.save_identity_credentials("usr_crawl", {"user_a": {"username": "", "password": "", "login_url": "", "cookie": "sessionid=abc", "authorization_header": ""}})

    pages = {
        "/": '<html><body><a href="/orders/1">order</a><a href="https://evil.example/">offsite</a></body></html>',
        "/orders/1": '<html><body>order detail, <a href="/profile">profile</a></body></html>',
        "/profile": "<html><body>profile page</body></html>",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text=pages.get(request.url.path, "not found"))

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_crawl({"_session_id": "usr_crawl", "identity": "user_a", "start_url": "https://example.com/"})

    assert result["status"] == "ok"
    visited_urls = {page["url"] for page in result["pages"]}
    assert visited_urls == {"https://example.com/", "https://example.com/orders/1", "https://example.com/profile"}
    assert "https://evil.example/" not in visited_urls


def test_authenticated_crawl_respects_the_max_pages_cap(monkeypatch):
    native.save_identity_credentials("usr_cap", {"user_a": {"username": "", "password": "", "login_url": "", "cookie": "a=1", "authorization_header": ""}})

    def handler(request: httpx.Request) -> httpx.Response:
        # Every page links to a fresh next page, so an uncapped crawl would never terminate.
        n = int(request.url.path.replace("/page", "") or 0)
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f'<a href="/page{n + 1}">next</a>')

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_crawl({"_session_id": "usr_cap", "identity": "user_a", "start_url": "https://example.com/page0", "max_pages": 3})

    assert result["status"] == "ok"
    assert result["pages_crawled"] == 3


def test_authenticated_crawl_works_unauthenticated_when_no_identity_given(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>public page</html>")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_crawl({"start_url": "https://example.com/"})

    assert result["status"] == "ok"
    assert result["identity"] == "unauthenticated"
    assert result["pages_crawled"] == 1


# --- idor_probe ---


def test_idor_probe_errors_for_an_unconfigured_identity_a():
    result = native.idor_probe({"_session_id": "usr_none", "identity_a": "user_a", "target": "https://example.com/orders/1"})
    assert result["status"] == "error"
    assert "user_a" in result["error"]


def test_idor_probe_flags_likely_idor_when_both_identities_see_the_same_resource(monkeypatch):
    native.save_identity_credentials(
        "usr_idor_confirm",
        {
            "user_a": {"username": "", "password": "", "login_url": "", "cookie": "a=1", "authorization_header": ""},
            "user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""},
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        # Same order data regardless of which identity's cookie made the request -- an IDOR.
        return httpx.Response(200, text="order #1: 4 widgets, shipped to 12 Main St")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.idor_probe({"_session_id": "usr_idor_confirm", "identity_a": "user_a", "identity_b": "user_b", "target": "https://example.com/orders/1"})

    assert result["status"] == "ok"
    assert result["identity_a"]["status_code"] == 200
    assert result["identity_b"]["status_code"] == 200
    assert result["body_similarity"] == 1.0
    assert result["likely_idor"] is True


def test_idor_probe_does_not_flag_idor_when_access_control_actually_works(monkeypatch):
    native.save_identity_credentials(
        "usr_idor_denied",
        {
            "user_a": {"username": "", "password": "", "login_url": "", "cookie": "a=1", "authorization_header": ""},
            "user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""},
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        cookie = request.headers.get("cookie")
        if cookie == "a=1":
            return httpx.Response(200, text="order #1: 4 widgets")
        return httpx.Response(403, text="forbidden")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.idor_probe({"_session_id": "usr_idor_denied", "identity_a": "user_a", "identity_b": "user_b", "target": "https://example.com/orders/1"})

    assert result["status"] == "ok"
    assert result["identity_a"]["status_code"] == 200
    assert result["identity_b"]["status_code"] == 403
    assert result["likely_idor"] is False


def test_idor_probe_compares_against_unauthenticated_when_identity_b_omitted(monkeypatch):
    native.save_identity_credentials("usr_idor_anon", {"user_a": {"username": "", "password": "", "login_url": "", "cookie": "a=1", "authorization_header": ""}})

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("cookie") == "a=1":
            return httpx.Response(200, text="order #1")
        return httpx.Response(401, text="login required")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.idor_probe({"_session_id": "usr_idor_anon", "identity_a": "user_a", "target": "https://example.com/orders/1"})

    assert result["status"] == "ok"
    assert result["identity_b"]["name"] == "unauthenticated"
    assert result["identity_b"]["status_code"] == 401


# --- core.py integration: session_id injection + one-shot-attempt-cap exemption ---


class _IdorProbeLLM:
    """Calls idor_probe twice (as a real deep-dive might, once per candidate adjacent resource
    ID), then ends the phase -- to prove neither call gets skipped by the one-shot-attempt cap.
    """
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self._calls = [
            ("idor_probe", {"identity_a": "user_a", "identity_b": "user_b", "target": "https://example.com/orders/1"}),
            ("idor_probe", {"identity_a": "user_a", "identity_b": "user_b", "target": "https://example.com/orders/2"}),
        ]
        self._n = 0

    def complete(self, messages, tools=None, stop_check=None):
        self._n += 1
        if self._calls:
            name, arguments = self._calls.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self._n}", name=name, arguments=arguments)])
        return LLMResponse(
            content='{"action": "exploit_attempted", "tool": "idor_probe", "exploitation_scenario": "remote_direct", "reasoning": "IDOR confirmed"}',
            tool_calls=[],
        )


def test_idor_probe_is_exempt_from_the_one_shot_attempt_cap_and_gets_session_id_injected(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    add_allowed_target("example.com")
    native.save_identity_credentials(
        "usr_idor_core",
        {
            "user_a": {"username": "", "password": "", "login_url": "", "cookie": "a=1", "authorization_header": ""},
            "user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""},
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="order data")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    session = {
        "session_id": "usr_idor_core", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "exploit_approved": True,
    }
    llm = _IdorProbeLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    finding = {"title": "Order IDs are sequential and guessable", "severity": "High", "verification": "verified"}
    tool_spec = next(s for s in TOOL_REGISTRY if s.name == "idor_probe")

    action, trace = _run(_run_exploit_for_finding(ctx, "example.com", finding, [tool_spec]))

    # Both calls ran (not skipped by the cap), and each succeeded without the model ever
    # supplying a session_id itself -- proof _session_id was injected server-side both times.
    tool_statuses = [entry["result"].get("status") for entry in trace]
    assert tool_statuses.count("ok") == 2
    assert action["action"] == "exploit_attempted"
