"""Custom HTTP Headers: some bug-bounty programs (HackerOne's own "Session Layer" guidance is a
real example) ask researchers to add an identifying header to every request, e.g.
"X-HackerOne-Research: <handle>" -- on top of, or instead of, a custom User-Agent
(tests/test_custom_user_agent.py). Same "real header on every real request, not just something the
model is told about" shape: agent/core.py's _run_tool_with_retry parses session["custom_headers"]
(one "Name: Value" pair per line) and injects it server-side into every tool call's
params["_extra_headers"] (never in any tool's own JSON schema, so the model can't see or override
it), native.py applies it directly to every httpx.Client that talks to the actual target, and the
structured builders add their own header flag(s) for it.
"""
import asyncio
import dataclasses

import httpx
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _custom_headers_task_addendum, _parse_custom_headers, _run_tool_with_retry
from agent.llm_client import LLMResponse
from agent.tools import native
from agent.tools.builders.nuclei import build_nuclei_command
from agent.tools.builders.sqlmap import build_sqlmap_command
from agent.tools.native import _merged_target_headers, _target_client_kwargs
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


def test_create_session_defaults_custom_headers_to_blank(_isolated_project_storage):
    session_id = create_session("example.com")
    assert load_session(session_id)["custom_headers"] == ""


def test_create_session_stores_and_strips_custom_headers(_isolated_project_storage):
    session_id = create_session("example.com", custom_headers="  X-HackerOne-Research: my_handle  ")
    assert load_session(session_id)["custom_headers"] == "X-HackerOne-Research: my_handle"


# --- agent/core.py: parsing the raw textarea into a header dict ---


def test_parse_custom_headers_empty_for_blank_input():
    assert _parse_custom_headers(None) == {}
    assert _parse_custom_headers("") == {}
    assert _parse_custom_headers("   \n  \n") == {}


def test_parse_custom_headers_reads_one_pair_per_line():
    headers = _parse_custom_headers("X-HackerOne-Research: my_handle\nX-Bug-Bounty: my_handle")
    assert headers == {"X-HackerOne-Research": "my_handle", "X-Bug-Bounty": "my_handle"}


def test_parse_custom_headers_trims_whitespace_around_name_and_value():
    assert _parse_custom_headers("  X-Foo  :   bar baz  ") == {"X-Foo": "bar baz"}


def test_parse_custom_headers_skips_malformed_lines_without_a_colon():
    headers = _parse_custom_headers("not-a-header-line\nX-Real-Header: value")
    assert headers == {"X-Real-Header": "value"}


def test_parse_custom_headers_preserves_colons_inside_the_value():
    # A header value may legitimately contain its own colon (a URL, a time) -- only the FIRST
    # colon on the line is the name/value separator.
    assert _parse_custom_headers("X-Callback-Url: https://example.com:8080/cb") == {
        "X-Callback-Url": "https://example.com:8080/cb"
    }


# --- native.py: real target-facing HTTP requests actually carry the headers ---


def test_merged_target_headers_empty_when_nothing_configured():
    assert _merged_target_headers({}) == {}


def test_merged_target_headers_combines_user_agent_and_extra_headers():
    merged = _merged_target_headers({
        "_user_agent": "MyBugBountyUA/1.0",
        "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert merged == {"User-Agent": "MyBugBountyUA/1.0", "X-HackerOne-Research": "my_handle"}


def test_target_client_kwargs_carries_extra_headers_with_no_user_agent():
    # verify=False always -- see _target_client_kwargs's own docstring for why (a self-signed/
    # mismatched-hostname cert on a real in-scope host is the normal case, not a rare edge case).
    assert _target_client_kwargs({"_extra_headers": {"X-HackerOne-Research": "my_handle"}}) == {
        "headers": {"X-HackerOne-Research": "my_handle"},
        "verify": False,
    }


def test_http_request_sends_the_extra_headers(monkeypatch):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["h1n1"] = request.headers.get("x-hackerone-research")
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.http_request({
        "target": "https://example.com", "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })

    assert result["status"] == "ok"
    assert seen["h1n1"] == "my_handle"


def test_authenticated_request_login_and_followup_both_carry_extra_headers(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    native._authenticated_clients.clear()
    native.save_identity_credentials(
        "usr_headers_auth",
        {"user_a": {
            "username": "alice", "password": "hunter2", "login_url": "https://example.com/login",
            "cookie": "", "authorization_header": "",
        }},
    )

    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers.get("x-hackerone-research"))
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authenticated_request({
        "_session_id": "usr_headers_auth", "identity": "user_a", "target": "https://example.com/dashboard",
        "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })

    assert result["status"] == "ok"
    assert seen_headers == ["my_handle", "my_handle"]  # login POST, then the real request
    native._authenticated_clients.clear()


# --- subprocess builders: nuclei/sqlmap get their own CLI flag(s) ---


def test_nuclei_command_adds_a_repeated_h_flag_per_extra_header():
    command = build_nuclei_command({
        "target": "https://example.com",
        "_user_agent": "MyBugBountyUA/1.0",
        "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert command.count("-H") == 2
    assert "User-Agent: MyBugBountyUA/1.0" in command
    assert "X-HackerOne-Research: my_handle" in command


def test_nuclei_command_omits_extra_header_flags_when_not_configured():
    command = build_nuclei_command({"target": "https://example.com"})
    assert "-H" not in command


def test_sqlmap_command_merges_model_headers_and_extra_headers_into_one_flag():
    command = build_sqlmap_command({
        "target": "https://example.com/?id=1",
        "headers": "X-Forwarded-For: 127.0.0.1",
        "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert command.count("--headers") == 1
    value = command[command.index("--headers") + 1]
    assert value == "X-Forwarded-For: 127.0.0.1\\nX-HackerOne-Research: my_handle"


def test_sqlmap_command_extra_headers_alone_still_add_the_flag():
    command = build_sqlmap_command({
        "target": "https://example.com/?id=1", "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert command[command.index("--headers") + 1] == "X-HackerOne-Research: my_handle"


# --- agent/core.py: server-side injection into every tool call, never model-visible ---


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content="done", tool_calls=[])


def test_run_tool_with_retry_injects_extra_headers_into_every_tool_call(monkeypatch):
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
            "session_id": "usr_inject_headers", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "custom_headers": "X-HackerOne-Research: my_handle",
        }
        ctx = RunContext(llm=_ScriptedLLM(), session=session, session_id=session["session_id"])

        _run(_run_tool_with_retry(ctx, spec, {"target": "https://example.com"}))

        assert seen_params["_extra_headers"] == {"X-HackerOne-Research": "my_handle"}
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_run_tool_with_retry_never_exposes_extra_headers_in_the_tool_schema():
    """The model must never be able to see or override this value -- it's not one of the tool's
    own declared parameters, only ever injected after the model's call already happened."""
    spec = next(s for s in TOOL_REGISTRY if s.name == "http_request")
    assert "_extra_headers" not in spec.parameters_schema.get("properties", {})


def test_custom_headers_task_addendum_is_empty_when_blank():
    assert _custom_headers_task_addendum({"custom_headers": ""}) == ""
    assert _custom_headers_task_addendum({}) == ""


def test_custom_headers_task_addendum_mentions_the_configured_headers():
    addendum = _custom_headers_task_addendum({"custom_headers": "X-HackerOne-Research: my_handle"})
    assert "X-HackerOne-Research: my_handle" in addendum
    assert "nikto" in addendum  # tells the model to add it itself for free-form discovered tools
