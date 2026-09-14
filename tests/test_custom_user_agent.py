"""Custom User-Agent header: some bug-bounty programs require a specific string on all test
traffic so their team can tell it apart from a real attack in their logs (New Project form's
"Custom User-Agent header"). Unlike free-text custom instructions, this has to be a real header on
real requests, not just something the model is told about -- agent/core.py's _run_tool_with_retry
injects it server-side into every tool call's params["_user_agent"] (never in any tool's own JSON
schema, so the model can't see or override it), native.py applies it directly to every httpx.Client
that talks to the actual target, and the nuclei/sqlmap builders add their own CLI flag for it.
"""
import asyncio
import dataclasses

import httpx
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _custom_user_agent_task_addendum, _run_tool_with_retry
from agent.llm_client import LLMResponse
from agent.tools import native
from agent.tools.builders.nuclei import build_nuclei_command
from agent.tools.builders.sqlmap import build_sqlmap_command
from agent.tools.native import _target_client_kwargs
from agent.tools.registry import TOOL_REGISTRY
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session

_RealHTTPXClient = httpx.Client


def _run(coro):
    return asyncio.run(coro)


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


# --- New Project form field -> session storage ---


@pytest.fixture
def _isolated_project_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    yield
    project_paths.resolve_projects_base_dir.cache_clear()


def test_create_session_defaults_custom_user_agent_to_blank(_isolated_project_storage):
    session_id = create_session("example.com")
    assert load_session(session_id)["custom_user_agent"] == ""


def test_create_session_stores_and_strips_custom_user_agent(_isolated_project_storage):
    session_id = create_session("example.com", custom_user_agent="  Mozilla/5.0 (BugBounty)  ")
    assert load_session(session_id)["custom_user_agent"] == "Mozilla/5.0 (BugBounty)"


# --- native.py: real target-facing HTTP requests actually carry the header ---


def test_target_client_kwargs_empty_when_no_user_agent_given():
    # verify=False always -- see _target_client_kwargs's own docstring for why (a self-signed/
    # mismatched-hostname cert on a real in-scope host is the normal case, not a rare edge case).
    assert _target_client_kwargs({}) == {"verify": False}
    assert _target_client_kwargs({"target": "https://example.com"}) == {"verify": False}


def test_target_client_kwargs_carries_the_header_when_given():
    assert _target_client_kwargs({"_user_agent": "MyBugBountyUA/1.0"}) == {
        "headers": {"User-Agent": "MyBugBountyUA/1.0"},
        "verify": False,
    }


def test_http_request_sends_the_custom_user_agent(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ua"] = request.headers.get("user-agent")
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.http_request({"target": "https://example.com", "_user_agent": "MyBugBountyUA/1.0"})

    assert result["status"] == "ok"
    assert seen["ua"] == "MyBugBountyUA/1.0"


def test_http_request_uses_httpx_default_user_agent_when_none_configured(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["ua"] = request.headers.get("user-agent")
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    native.http_request({"target": "https://example.com"})

    assert seen["ua"] is not None and "python-httpx" in seen["ua"]


def test_authenticated_request_login_and_followup_both_carry_the_custom_user_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    native._authenticated_clients.clear()
    native.save_identity_credentials(
        "usr_ua_auth",
        {"user_a": {
            "username": "alice", "password": "hunter2", "login_url": "https://example.com/login",
            "cookie": "", "authorization_header": "",
        }},
    )

    seen_uas = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_uas.append(request.headers.get("user-agent"))
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_request({
        "_session_id": "usr_ua_auth", "identity": "user_a", "target": "https://example.com/dashboard",
        "_user_agent": "MyBugBountyUA/1.0",
    })

    assert result["status"] == "ok"
    assert seen_uas == ["MyBugBountyUA/1.0", "MyBugBountyUA/1.0"]  # login POST, then the real request
    native._authenticated_clients.clear()


# --- subprocess builders: nuclei/sqlmap get their own CLI flag ---


def test_nuclei_command_includes_user_agent_header_flag_when_configured():
    command = build_nuclei_command({"target": "https://example.com", "_user_agent": "MyBugBountyUA/1.0"})
    assert "-H" in command
    assert "User-Agent: MyBugBountyUA/1.0" in command


def test_nuclei_command_omits_user_agent_flag_when_not_configured():
    command = build_nuclei_command({"target": "https://example.com"})
    assert "-H" not in command


def test_sqlmap_command_includes_user_agent_flag_when_configured():
    command = build_sqlmap_command({"target": "https://example.com/?id=1", "_user_agent": "MyBugBountyUA/1.0"})
    assert "--user-agent" in command
    assert command[command.index("--user-agent") + 1] == "MyBugBountyUA/1.0"


def test_sqlmap_command_omits_user_agent_flag_when_not_configured():
    command = build_sqlmap_command({"target": "https://example.com/?id=1"})
    assert "--user-agent" not in command


# --- agent/core.py: server-side injection into every tool call, never model-visible ---


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content="done", tool_calls=[])


def test_run_tool_with_retry_injects_user_agent_into_every_tool_call(monkeypatch):
    seen_params = {}

    def fake_native_function(params):
        seen_params.update(params)
        return {"status": "ok"}

    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "http_request")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, native_function=fake_native_function)
    try:
        spec = TOOL_REGISTRY[index]
        session = {
            "session_id": "usr_inject", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "custom_user_agent": "MyBugBountyUA/1.0",
        }
        ctx = RunContext(llm=_ScriptedLLM(), session=session, session_id=session["session_id"])

        _run(_run_tool_with_retry(ctx, spec, {"target": "https://example.com"}))

        assert seen_params["_user_agent"] == "MyBugBountyUA/1.0"
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_run_tool_with_retry_never_exposes_user_agent_in_the_tool_schema():
    """The model must never be able to see or override this value -- it's not one of the tool's
    own declared parameters, only ever injected after the model's call already happened."""
    spec = next(s for s in TOOL_REGISTRY if s.name == "http_request")
    assert "_user_agent" not in spec.parameters_schema.get("properties", {})


def test_custom_user_agent_task_addendum_is_empty_when_blank():
    assert _custom_user_agent_task_addendum({"custom_user_agent": ""}) == ""
    assert _custom_user_agent_task_addendum({}) == ""


def test_custom_user_agent_task_addendum_mentions_the_configured_string():
    addendum = _custom_user_agent_task_addendum({"custom_user_agent": "MyBugBountyUA/1.0"})
    assert "MyBugBountyUA/1.0" in addendum
    assert "nikto" in addendum  # tells the model to add it itself for free-form discovered tools
