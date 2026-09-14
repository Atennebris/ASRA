"""cors_credentialed_check -- the real, deterministic proof step for a CORS finding cors_check
already flagged verdict="reflects_any_origin" AND allows_credentials=True for. Real incident this
closes: three High/"qualifying" CORS findings all got skipped_no_suitable_tool with reasoning that
never even considered whether Access-Control-Allow-Credentials was set -- nothing checked it
(cors_check didn't track it at all), nothing told Exploit the answer, and there was no tool that
could attempt a real credentialed cross-origin read even if the model had thought to try.

No headless browser needed: a browser's decision to expose a cross-origin response to JS is a
deterministic function of the response's own Access-Control-Allow-Origin/-Credentials headers
versus the request's Origin -- replaying the exact request server-side with a real identity's real
session attached and checking those same headers on the real reply IS a faithful simulation, not
an approximation.

Gated exactly like authenticated_request (same credential store, same exploitation-allowlist +
human-approved-session gate, via the same requires_allowed_target=True mechanism) -- this is a
real authenticated request against a live target using a real test account's session, not a
passive probe, and must never be reachable without exactly the same safety check authenticated_
request itself already requires.
"""
import asyncio

import httpx
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _cors_credential_task_addendum,
    _run_exploit_for_finding,
    _track_cors_check_verdict,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import allowed_targets, native
from agent.tools.allowed_targets import add_allowed_target
from agent.tools.registry import TOOL_REGISTRY, categories_of, get_tools_by_category
from sessions import store

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    native._authenticated_clients.clear()
    yield
    native._authenticated_clients.clear()


def _save_creds(session_id: str, identity: str = "user_a", cookie: str = "session=real-token") -> None:
    native.save_identity_credentials(session_id, {
        identity: {"username": "", "password": "", "login_url": "", "cookie": cookie, "authorization_header": ""},
    })


# --- native function: pure unit tests ---


def test_errors_for_an_unconfigured_identity():
    result = native.cors_credentialed_check({"_session_id": "usr_none", "identity": "user_a", "target": "https://api.example.com"})
    assert result["status"] == "error"
    assert "user_a" in result["error"]


def test_confirms_a_real_credentialed_cross_origin_read(monkeypatch):
    _save_creds("usr_confirmed")
    seen_cookie = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_cookie.append(request.headers.get("cookie"))
        return httpx.Response(200, text="{\"account_balance\": 42}", headers={
            "access-control-allow-origin": native._CORS_UNRELATED_TEST_ORIGIN,
            "access-control-allow-credentials": "true",
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_credentialed_check({"_session_id": "usr_confirmed", "identity": "user_a", "target": "https://api.example.com/me"})

    assert result["status"] == "ok"
    assert result["confirmed_credentialed_cross_origin_read"] is True
    assert "account_balance" in result["body_preview"]
    assert seen_cookie == ["session=real-token"]  # the real identity's own session was actually sent


def test_never_confirms_for_a_static_wildcard_acao_even_with_credentials_header(monkeypatch):
    """The same critical browser-spec nuance as cors_check's own allows_credentials: a literal "*"
    never grants a credentialed read in a real browser, no matter what Access-Control-Allow-
    Credentials says."""
    _save_creds("usr_wildcard")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="secret data", headers={
            "access-control-allow-origin": "*", "access-control-allow-credentials": "true",
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_credentialed_check({"_session_id": "usr_wildcard", "identity": "user_a", "target": "https://api.example.com/me"})

    assert result["confirmed_credentialed_cross_origin_read"] is False
    assert result["body_preview"] is None


def test_not_confirmed_when_credentials_header_is_absent(monkeypatch):
    _save_creds("usr_no_creds_header")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="secret data", headers={"access-control-allow-origin": native._CORS_UNRELATED_TEST_ORIGIN})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_credentialed_check({"_session_id": "usr_no_creds_header", "identity": "user_a", "target": "https://api.example.com/me"})

    assert result["confirmed_credentialed_cross_origin_read"] is False
    assert result["body_preview"] is None


def test_reports_a_real_network_failure_as_an_error(monkeypatch):
    _save_creds("usr_network_fail")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("simulated failure", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.cors_credentialed_check({"_session_id": "usr_network_fail", "identity": "user_a", "target": "https://api.example.com/me"})

    assert result["status"] == "error"


# --- registration: gated exactly like authenticated_request ---


def test_is_registered_in_the_exploit_category_and_gated_like_authenticated_request():
    spec = next(s for s in TOOL_REGISTRY if s.name == "cors_credentialed_check")
    assert "exploit" in categories_of(spec)
    assert spec.requires_allowed_target is True
    assert spec.allows_repeated_attempts is True


# --- safety-critical integration: the allowlist gate actually blocks a real dispatch ---


class _CallsCorsCredentialedCheckLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self):
        self._called = False

    def complete(self, messages, tools=None, stop_check=None):
        if self._called:
            return LLMResponse(content="done", tool_calls=[])
        self._called = True
        return LLMResponse(
            content=None,
            tool_calls=[ToolCallRequest(
                id="call_1", name="cors_credentialed_check",
                arguments={"target": "https://api.example.com/me", "identity": "user_a"},
            )],
        )


def test_a_target_not_in_the_allowlist_is_skipped_and_never_actually_dispatched(monkeypatch):
    _save_creds("usr_not_allowed")
    fired = []

    def handler(request: httpx.Request) -> httpx.Response:
        fired.append(request)
        return httpx.Response(200)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    # Deliberately no add_allowed_target() call -- api.example.com is not in scope.

    session = {
        "session_id": "usr_not_allowed", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "exploit_approved": True,
    }
    ctx = RunContext(llm=_CallsCorsCredentialedCheckLLM(), session=session, session_id=session["session_id"])
    finding = {"title": "CORS Misconfiguration on api.example.com", "severity": "High", "verification": "verified"}
    tool_spec = next(s for s in TOOL_REGISTRY if s.name == "cors_credentialed_check")

    action, trace = _run(_run_exploit_for_finding(ctx, "example.com", finding, [tool_spec]))

    assert not fired  # the real HTTP layer was never even reached
    assert trace[-1]["result"]["status"] == "skipped"
    assert "exploitation allowlist" in trace[-1]["result"]["reason"]


def test_an_approved_in_scope_call_actually_dispatches_for_real(monkeypatch):
    _save_creds("usr_allowed")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="real data", headers={
            "access-control-allow-origin": native._CORS_UNRELATED_TEST_ORIGIN,
            "access-control-allow-credentials": "true",
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    add_allowed_target("api.example.com")

    session = {
        "session_id": "usr_allowed", "target": "api.example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "exploit_approved": True,
    }
    ctx = RunContext(llm=_CallsCorsCredentialedCheckLLM(), session=session, session_id=session["session_id"])
    finding = {"title": "CORS Misconfiguration on api.example.com", "severity": "High", "verification": "verified"}
    tool_spec = next(s for s in TOOL_REGISTRY if s.name == "cors_credentialed_check")

    action, trace = _run(_run_exploit_for_finding(ctx, "api.example.com", finding, [tool_spec]))

    assert trace[-1]["result"]["status"] == "ok"
    assert trace[-1]["result"]["confirmed_credentialed_cross_origin_read"] is True


# --- _track_cors_check_verdict: the new cors_check_credentials tracking + refined hints ---


def _make_ctx_for_tracking(session_id="usr_tracking"):
    session = {"session_id": session_id, "logs": []}
    return RunContext(llm=None, session=session, session_id=session_id)


def test_track_cors_check_verdict_records_allows_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    ctx = _make_ctx_for_tracking()
    result = {
        "hostname": "api.example.com", "verdict": "reflects_any_origin",
        "same_suffix_origin_tested": "x", "unrelated_origin_tested": "y", "allows_credentials": True,
    }

    _track_cors_check_verdict(ctx, result)

    assert ctx.session["cors_check_credentials"] == {"api.example.com": True}
    assert "cors_credentialed_check" in result["hint"]


def test_track_cors_check_verdict_hint_when_credentials_not_allowed(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    ctx = _make_ctx_for_tracking()
    result = {
        "hostname": "api.example.com", "verdict": "reflects_any_origin",
        "same_suffix_origin_tested": "x", "unrelated_origin_tested": "y", "allows_credentials": False,
    }

    _track_cors_check_verdict(ctx, result)

    assert ctx.session["cors_check_credentials"] == {"api.example.com": False}
    assert "corrected_severity" in result["hint"]
    assert "NOT" in result["hint"]


def test_track_cors_check_verdict_records_none_when_origin_not_reflected(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    ctx = _make_ctx_for_tracking()
    result = {
        "hostname": "api.example.com", "verdict": "no_origin_reflection_detected",
        "same_suffix_origin_tested": "x", "unrelated_origin_tested": "y", "allows_credentials": None,
    }

    _track_cors_check_verdict(ctx, result)

    assert ctx.session["cors_check_credentials"] == {"api.example.com": None}


# --- _cors_credential_task_addendum ---


def test_addendum_empty_when_finding_is_not_cors_related():
    session = {"cors_check_credentials": {"api.example.com": True}}
    finding = {"title": "SQL Injection on api.example.com", "description": "blind SQLi"}
    assert _cors_credential_task_addendum(session, finding) == ""


def test_addendum_empty_when_no_credentials_fact_tracked_yet():
    session = {"cors_check_credentials": {}}
    finding = {"title": "CORS Misconfiguration on api.example.com"}
    assert _cors_credential_task_addendum(session, finding) == ""


def test_addendum_empty_for_an_unrelated_host_sharing_no_mention():
    session = {"cors_check_credentials": {"other.example.com": True}}
    finding = {"title": "CORS Misconfiguration on api.example.com"}
    assert _cors_credential_task_addendum(session, finding) == ""


def test_addendum_points_at_cors_credentialed_check_when_credentials_allowed():
    session = {"cors_check_credentials": {"api.example.com": True}}
    finding = {"title": "CORS Misconfiguration on api.example.com"}
    addendum = _cors_credential_task_addendum(session, finding)
    assert "cors_credentialed_check" in addendum
    assert "api.example.com" in addendum


def test_addendum_nudges_toward_correction_when_credentials_not_allowed():
    session = {"cors_check_credentials": {"api.example.com": False}}
    finding = {"title": "CORS Misconfiguration on api.example.com"}
    addendum = _cors_credential_task_addendum(session, finding)
    assert "corrected_severity" in addendum
    assert "corrected_qualifies_for_bounty" in addendum


# --- integration: the addendum actually reaches Exploit's real task text ---


def test_exploit_task_actually_includes_the_cors_credential_addendum(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    captured_messages = []

    class _CapturingLLM:
        provider_id = "test-provider"
        model = "test-model"
        def complete(self, messages, tools=None, stop_check=None):
            captured_messages.append(list(messages))
            return LLMResponse(
                content=None,
                tool_calls=[ToolCallRequest(
                    id="call_1", name="record_exploit_decision",
                    arguments={"action": "skipped_no_suitable_tool", "exploitation_scenario": "unchanged", "reasoning": "x"},
                )],
            )

    session = {
        "session_id": "usr_cors_addendum_integration", "findings": [], "logs": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "cors_check_credentials": {"api.example.com": True},
    }
    ctx = RunContext(llm=_CapturingLLM(), session=session, session_id=session["session_id"])
    finding = {"title": "CORS Misconfiguration on api.example.com", "severity": "High", "verification": "verified"}
    exploit_tools = get_tools_by_category("exploit")

    _run(_run_exploit_for_finding(ctx, "api.example.com", finding, exploit_tools))

    task_text = captured_messages[0][-1]["content"]
    assert "cors_credentialed_check" in task_text
