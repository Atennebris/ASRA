"""Authenticated-identity testing (IDOR/broken access control): credential storage
(save_identity_credentials/_load_credentials), the authenticated_request tool itself (using a
real httpx.MockTransport, not a crude monkeypatch, so cookie/header/login-POST behavior is
actually exercised), and the two core.py integration points -- session_id injected server-side
(never model-controlled) and exemption from the per-finding one-shot-attempt cap (a real IDOR
comparison needs at least two calls).
"""
import asyncio

import httpx
import pytest

from agent.core import RunContext, _run_exploit_for_finding
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import native
from agent.tools import allowed_targets
from agent.tools.allowed_targets import add_allowed_target
from agent.tools.registry import TOOL_REGISTRY
from sessions import store

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _run(coro):
    return asyncio.run(coro)


def _mock_httpx_client(handler):
    """A factory matching httpx.Client's call signature, backed by a MockTransport instead of
    real sockets — built from the real Client class captured above so patching httpx.Client with
    this doesn't recurse into itself.
    """
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


def test_save_identity_credentials_writes_only_non_empty_identities(tmp_path):
    native.save_identity_credentials(
        "usr_a",
        {
            "user_a": {"username": "alice", "password": "pw", "login_url": "", "cookie": "", "authorization_header": ""},
            "user_b": {"username": "", "password": "", "login_url": "", "cookie": "", "authorization_header": ""},
        },
    )
    stored = native._load_credentials("usr_a")
    assert "user_a" in stored
    assert "user_b" not in stored


def test_save_identity_credentials_writes_nothing_when_everything_is_empty(tmp_path):
    native.save_identity_credentials(
        "usr_b",
        {
            "user_a": {"username": "", "password": "", "login_url": "", "cookie": "", "authorization_header": ""},
            "user_b": {"username": "", "password": "", "login_url": "", "cookie": "", "authorization_header": ""},
        },
    )
    assert native._load_credentials("usr_b") == {}
    assert not (native._CREDENTIALS_DIR / "usr_b.json").exists()


def test_register_discovered_credential_writes_a_usable_identity():
    native.register_discovered_credential("usr_discovered", "discovered_1", "admin", "hunter2", "https://example.com/login")

    stored = native._load_credentials("usr_discovered")
    assert stored["discovered_1"] == {"username": "admin", "password": "hunter2", "login_url": "https://example.com/login"}


def test_register_discovered_credential_upserts_without_clobbering_other_identities():
    native.save_identity_credentials("usr_discovered_upsert", {"user_a": {"username": "alice", "password": "pw", "login_url": "", "cookie": "", "authorization_header": ""}})

    native.register_discovered_credential("usr_discovered_upsert", "discovered_1", "admin", "hunter2", "https://example.com/login")

    stored = native._load_credentials("usr_discovered_upsert")
    assert "user_a" in stored
    assert stored["discovered_1"] == {"username": "admin", "password": "hunter2", "login_url": "https://example.com/login"}


def test_register_discovered_credential_is_immediately_usable_by_authenticated_request(monkeypatch):
    native.register_discovered_credential("usr_discovered_use", "discovered_1", "admin", "hunter2", "https://example.com/login")

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "sessionid=fresh; Path=/"})
        return httpx.Response(200, text="authenticated page")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_request({"_session_id": "usr_discovered_use", "identity": "discovered_1", "target": "https://example.com/admin"})

    assert result["status"] == "ok"
    assert calls == ["/login", "/admin"]


def test_authenticated_request_errors_for_an_unconfigured_identity():
    result = native.authenticated_request({"_session_id": "usr_none", "identity": "user_a", "target": "https://example.com/x"})
    assert result["status"] == "error"
    assert "user_a" in result["error"]
    # Real, confirmed incident this fixes: a project with zero configured identities got retried
    # across a DIFFERENT identity name or target each time (evading the exact-signature dedup that
    # would otherwise catch a verbatim repeat), because the message never said this condition is
    # permanent for the whole project -- same wording family as is_target_allowed's own permanence
    # fix (agent/tools/runner.py's _check_guardrail).
    assert "permanent" in result["error"]
    assert "New Project form" in result["error"]


def test_interpret_missing_identity_matches_the_permanent_error_and_registers_for_every_affected_tool():
    """Real, confirmed incident this fixes (a real HackerOne rescan session): a project with zero
    configured identities still saw cors_credentialed_check retried 8 times across ~30 minutes,
    each time varying only the identity name or target URL -- the error text already says this is
    permanent, but nothing was wired into _PERMANENT_ERROR_HINTS to make that retry unreachable."""
    from agent.core import _PERMANENT_ERROR_HINTS
    from agent.tools.native import interpret_missing_identity

    result = native.authenticated_request({"_session_id": "usr_none", "identity": "user_a", "target": "https://example.com/x"})
    assert interpret_missing_identity(result) == result["error"]
    assert interpret_missing_identity({"status": "error", "error": "some other error"}) is None
    assert interpret_missing_identity({"status": "ok"}) is None
    for tool_name in (
        "cors_credentialed_check", "authenticated_request", "authenticated_crawl",
        "idor_probe", "graphql_authz_probe", "graphql_batching_probe",
    ):
        assert _PERMANENT_ERROR_HINTS[tool_name] is interpret_missing_identity


def test_authenticated_request_sends_a_stored_cookie(monkeypatch):
    native.save_identity_credentials("usr_cookie", {"user_a": {"username": "", "password": "", "login_url": "", "cookie": "sessionid=abc123", "authorization_header": ""}})

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["cookie"] = request.headers.get("cookie")
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_request({"_session_id": "usr_cookie", "identity": "user_a", "target": "https://example.com/api/me"})

    assert result["status"] == "ok"
    assert result["status_code"] == 200
    assert seen["cookie"] == "sessionid=abc123"


def test_authenticated_request_performs_a_login_post_when_configured(monkeypatch):
    native.save_identity_credentials(
        "usr_login",
        {"user_a": {"username": "alice", "password": "hunter2", "login_url": "https://example.com/login", "cookie": "", "authorization_header": ""}},
    )

    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "sessionid=fresh; Path=/"})
        return httpx.Response(200, text="authenticated page")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_request({"_session_id": "usr_login", "identity": "user_a", "target": "https://example.com/dashboard"})

    assert result["status"] == "ok"
    assert calls == ["/login", "/dashboard"]


def test_authenticated_request_login_sends_both_username_and_email_when_both_given(monkeypatch):
    """username and email are separate New Project form fields now (not one ambiguous "username
    or email" box) -- a real login endpoint might key off either one, so both actually-given
    values must reach the login POST body, not just whichever field happened to be first.
    """
    native.save_identity_credentials(
        "usr_both",
        {"user_a": {
            "username": "alice", "email": "alice@example.com", "password": "hunter2",
            "login_url": "https://example.com/login", "cookie": "", "authorization_header": "",
        }},
    )

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            seen["body"] = dict(pair.split("=") for pair in request.content.decode().split("&"))
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_request({"_session_id": "usr_both", "identity": "user_a", "target": "https://example.com/dashboard"})

    assert result["status"] == "ok"
    assert seen["body"] == {"username": "alice", "email": "alice%40example.com", "password": "hunter2"}


def test_authenticated_request_login_works_with_only_email_no_username(monkeypatch):
    native.save_identity_credentials(
        "usr_email_only",
        {"user_a": {
            "username": "", "email": "bob@example.com", "password": "hunter2",
            "login_url": "https://example.com/login", "cookie": "", "authorization_header": "",
        }},
    )

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            seen["body"] = request.content.decode()
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_request({"_session_id": "usr_email_only", "identity": "user_a", "target": "https://example.com/dashboard"})

    assert result["status"] == "ok"
    assert "email=bob" in seen["body"]
    assert "username=" not in seen["body"]


def test_authenticated_request_reuses_the_cached_client_no_second_login(monkeypatch):
    native.save_identity_credentials(
        "usr_reuse",
        {"user_a": {"username": "alice", "password": "hunter2", "login_url": "https://example.com/login", "cookie": "", "authorization_header": ""}},
    )

    login_calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            login_calls.append(1)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    native.authenticated_request({"_session_id": "usr_reuse", "identity": "user_a", "target": "https://example.com/a"})
    native.authenticated_request({"_session_id": "usr_reuse", "identity": "user_a", "target": "https://example.com/b"})

    assert len(login_calls) == 1


class _AuthedRequestLLM:
    """Calls authenticated_request twice (as would a real IDOR comparison: identity A then B),
    then ends the phase -- to prove neither call gets skipped by the one-shot-attempt cap.
    """
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self._calls = [
            ("authenticated_request", {"identity": "user_a", "target": "https://example.com/orders/1"}),
            ("authenticated_request", {"identity": "user_b", "target": "https://example.com/orders/1"}),
        ]
        self._n = 0

    def complete(self, messages, tools=None, stop_check=None):
        self._n += 1
        if self._calls:
            name, arguments = self._calls.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self._n}", name=name, arguments=arguments)])
        return LLMResponse(
            content='{"action": "exploit_attempted", "tool": "authenticated_request", "exploitation_scenario": "remote_direct", "reasoning": "IDOR confirmed"}',
            tool_calls=[],
        )


def test_get_identity_browser_creds_forwards_a_raw_cookie_header(monkeypatch):
    """The manually-pasted-cookie identity shape (creds["cookie"]) is set on the httpx client as a
    raw Cookie HEADER (_get_authenticated_client), never touching client.cookies.jar -- reading only
    the jar would silently strip this identity's cookie out of the browser bridge entirely."""
    native.save_identity_credentials(
        "usr_browser_cookie",
        {"user_a": {"username": "", "password": "", "login_url": "", "cookie": "sessionid=abc123", "authorization_header": ""}},
    )

    result = native.get_identity_browser_creds("usr_browser_cookie", "user_a")

    assert result["status"] == "ok"
    assert result["cookies"] == []
    assert result["headers"] == {"Cookie": "sessionid=abc123"}


def test_get_identity_browser_creds_translates_login_cookie_jar_for_playwright(monkeypatch):
    """A login_url flow's Set-Cookie response DOES land in client.cookies.jar -- must be translated
    into Playwright's add_cookies() shape (name/value/domain/path/expires/secure), not just passed
    as a raw header like the manual-cookie case above."""
    native.save_identity_credentials(
        "usr_browser_login",
        {"user_a": {"username": "alice", "password": "hunter2", "login_url": "https://example.com/login", "cookie": "", "authorization_header": ""}},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, headers={"set-cookie": "sessionid=fresh; Path=/; Domain=example.com"})
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.get_identity_browser_creds("usr_browser_login", "user_a")

    assert result["status"] == "ok"
    assert len(result["cookies"]) == 1
    cookie = result["cookies"][0]
    assert cookie["name"] == "sessionid"
    assert cookie["value"] == "fresh"
    assert cookie["path"] == "/"
    assert cookie["expires"] == -1  # session cookie, no Expires/Max-Age given
    assert result["headers"] == {}


def test_get_identity_browser_creds_forwards_the_authorization_header(monkeypatch):
    native.save_identity_credentials(
        "usr_browser_bearer",
        {"user_a": {"username": "", "password": "", "login_url": "", "cookie": "", "authorization_header": "Bearer tok123"}},
    )

    result = native.get_identity_browser_creds("usr_browser_bearer", "user_a")

    assert result["status"] == "ok"
    assert result["headers"] == {"Authorization": "Bearer tok123"}


def test_get_identity_browser_creds_errors_for_an_unconfigured_identity():
    result = native.get_identity_browser_creds("usr_browser_none", "user_a")
    assert result["status"] == "error"
    assert "user_a" in result["error"]


def test_authenticated_request_is_exempt_from_the_one_shot_attempt_cap(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    add_allowed_target("example.com")
    native.save_identity_credentials(
        "usr_idor",
        {
            "user_a": {"username": "", "password": "", "login_url": "", "cookie": "a=1", "authorization_header": ""},
            "user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""},
        },
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="order data")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    session = {
        "session_id": "usr_idor", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "exploit_approved": True,  # skip the human-approval wait for this test
    }
    llm = _AuthedRequestLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    finding = {"title": "Order IDs are sequential and guessable", "severity": "High", "verification": "verified"}
    tool_spec = next(s for s in TOOL_REGISTRY if s.name == "authenticated_request")

    action, trace = _run(_run_exploit_for_finding(ctx, "example.com", finding, [tool_spec]))

    # Both calls must have actually run (not the second one skipped as "one attempt already used").
    tool_statuses = [entry["result"].get("status") for entry in trace]
    assert tool_statuses.count("ok") == 2
    assert action["action"] == "exploit_attempted"
