"""agent/opencode_local_provider.py -- the local `opencode serve` LLMProvider. Every real
subprocess/network call is mocked (httpx.Client, subprocess.Popen) so these run at unit-test
speed with no real opencode CLI/server involved -- mirrors tests/test_codex_provider.py's own
"mock the transport, test the translation/parsing logic" approach for a different backend.
"""
import threading
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest

from agent.llm_client import EmptyResponseError, ToolCallRequest
from agent.opencode_local_provider import (
    OpenCodeLocalProvider,
    _describe_assistant_error,
    _find_free_port,
    _live_opencode_models,
    _PermissionDenier,
    _render_transcript,
    _resolve_opencode_binary,
    list_opencode_local_models,
)


# --- _render_transcript -----------------------------------------------------------------------


def test_render_transcript_collects_system_messages_separately():
    system, transcript = _render_transcript([
        {"role": "system", "content": "You are a terse assistant."},
        {"role": "user", "content": "hello"},
    ])
    assert system == "You are a terse assistant."
    assert "hello" in transcript
    assert "You are a terse assistant." not in transcript


def test_render_transcript_merges_multiple_system_messages():
    system, _ = _render_transcript([
        {"role": "system", "content": "first"},
        {"role": "system", "content": "second"},
        {"role": "user", "content": "hi"},
    ])
    assert system == "first\n\nsecond"


def test_render_transcript_renders_tool_results():
    _, transcript = _render_transcript([
        {"role": "tool", "tool_call_id": "call_1", "content": '{"status": "ok"}'},
    ])
    assert transcript == 'Tool result:\n{"status": "ok"}'


def test_render_transcript_renders_assistant_tool_calls():
    _, transcript = _render_transcript([
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "nmap_scan", "arguments": '{"target": "1.2.3.4"}'}}],
        },
    ])
    assert transcript == 'Assistant: [called nmap_scan with {"target": "1.2.3.4"}]'


def test_render_transcript_labels_user_and_assistant_text():
    _, transcript = _render_transcript([
        {"role": "user", "content": "scan example.com"},
        {"role": "assistant", "content": "starting the scan"},
    ])
    assert transcript == "User: scan example.com\n\nAssistant: starting the scan"


def test_render_transcript_skips_empty_messages():
    """A message with no content and no tool_calls (e.g. an assistant turn that only triggered a
    tool call ASRA already rendered elsewhere) contributes nothing -- no stray blank block."""
    _, transcript = _render_transcript([
        {"role": "user", "content": "hi"},
        {"role": "assistant", "content": ""},
    ])
    assert transcript == "User: hi"


# --- _describe_assistant_error ----------------------------------------------------------------


def test_describe_assistant_error_none():
    assert _describe_assistant_error(None) == "unknown error"


def test_describe_assistant_error_with_data_message():
    assert _describe_assistant_error({"name": "APIError", "data": {"message": "quota exceeded"}}) == "quota exceeded"


def test_describe_assistant_error_falls_back_to_name():
    assert _describe_assistant_error({"name": "ContextOverflowError", "data": {}}) == "ContextOverflowError"


# --- OpenCodeLocalProvider.__init__ ------------------------------------------------------------


def test_init_defaults():
    provider = OpenCodeLocalProvider()
    assert provider.provider_id == "opencode-local"
    assert provider.model == "big-pickle"
    assert provider.context_limit is None


def test_init_with_explicit_model():
    provider = OpenCodeLocalProvider(model="some-other-model")
    assert provider.model == "some-other-model"


# --- OpenCodeLocalProvider._parse_response ------------------------------------------------------


def test_parse_response_joins_text_parts():
    provider = OpenCodeLocalProvider()
    response = provider._parse_response(
        {"info": {}, "parts": [{"type": "text", "text": "PONG"}]}, had_tools=False,
    )
    assert response.content == "PONG"
    assert response.tool_calls == []
    assert response.finish_reason == "stop"


def test_parse_response_extracts_usage_from_tokens():
    provider = OpenCodeLocalProvider()
    response = provider._parse_response(
        {"info": {"tokens": {"input": 5812, "output": 4}}, "parts": [{"type": "text", "text": "PONG"}]},
        had_tools=False,
    )
    assert response.usage == {"prompt_tokens": 5812, "completion_tokens": 4}


def test_parse_response_no_usage_when_tokens_absent():
    provider = OpenCodeLocalProvider()
    response = provider._parse_response({"info": {}, "parts": [{"type": "text", "text": "x"}]}, had_tools=False)
    assert response.usage is None


def test_parse_response_raises_empty_response_error_when_error_and_no_text():
    provider = OpenCodeLocalProvider()
    with pytest.raises(EmptyResponseError, match="quota exceeded"):
        provider._parse_response(
            {"info": {"error": {"name": "APIError", "data": {"message": "quota exceeded"}}}, "parts": []},
            had_tools=False,
        )


def test_parse_response_does_not_raise_when_error_but_some_text_present():
    """A provider error flag alongside SOME real text isn't treated as empty -- the text is kept,
    not discarded, the same tolerant "use what's there" discipline this project's own
    _normalize_message_content already follows for a different malformed-response shape."""
    provider = OpenCodeLocalProvider()
    response = provider._parse_response(
        {"info": {"error": {"name": "SomeError"}}, "parts": [{"type": "text", "text": "partial answer"}]},
        had_tools=False,
    )
    assert response.content == "partial answer"


def test_parse_response_extracts_tool_calls_only_when_had_tools():
    provider = OpenCodeLocalProvider()
    payload = {"info": {}, "parts": [{"type": "text", "text": '<tool_call>{"name": "get_weather", "arguments": {"city": "Paris"}}</tool_call>'}]}

    with_tools = provider._parse_response(payload, had_tools=True)
    assert with_tools.tool_calls == [ToolCallRequest(id="prompt_call_0", name="get_weather", arguments={"city": "Paris"})]
    assert with_tools.finish_reason == "tool_use"

    without_tools = provider._parse_response(payload, had_tools=False)
    assert without_tools.tool_calls == []


# --- OpenCodeLocalProvider.complete -- the tool-call disclaimer ---------------------------------


def test_complete_injects_disclaimer_system_message_when_tools_given():
    """Confirmed live (see this module's own docstring): without this disclaimer the model,
    running inside opencode's own real agentic harness, reliably tries to invoke the prompt-
    injected tool the same way it invokes its real tools and fails -- this disclaimer is the
    actual fix, so its presence is what this test protects, not just "some system text exists".
    """
    provider = OpenCodeLocalProvider()
    captured = {}

    def _fake_run_turn(self_unused, system_text, transcript_text):
        captured["system_text"] = system_text
        captured["transcript_text"] = transcript_text
        return {"info": {}, "parts": [{"type": "text", "text": "ok"}]}

    tools = [{"type": "function", "function": {"name": "get_weather", "description": "d", "parameters": {}}}]
    with patch.object(OpenCodeLocalProvider, "_run_turn", _fake_run_turn):
        provider.complete([{"role": "user", "content": "weather?"}], tools=tools)

    assert "NOT part of your real tool environment" in captured["system_text"]


def test_complete_does_not_inject_disclaimer_when_no_tools():
    provider = OpenCodeLocalProvider()
    captured = {}

    def _fake_run_turn(self_unused, system_text, transcript_text):
        captured["system_text"] = system_text
        return {"info": {}, "parts": [{"type": "text", "text": "ok"}]}

    with patch.object(OpenCodeLocalProvider, "_run_turn", _fake_run_turn):
        provider.complete([{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])

    assert "NOT part of your real tool environment" not in captured["system_text"]
    assert captured["system_text"] == "sys"


# --- _find_free_port / _resolve_opencode_binary -------------------------------------------------


def test_find_free_port_returns_a_usable_port():
    port = _find_free_port()
    assert isinstance(port, int)
    assert 0 < port < 65536
    # The port is released the instant _find_free_port's own `with` block closes -- immediately
    # bindable again is the whole point (a real caller passes it straight to `opencode serve`).
    with __import__("socket").socket(__import__("socket").AF_INET, __import__("socket").SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", port))


def test_resolve_opencode_binary_raises_actionable_error_when_missing(monkeypatch):
    monkeypatch.setattr("agent.opencode_local_provider.shutil.which", lambda name: None)
    with pytest.raises(ValueError, match="opencode CLI is not installed"):
        _resolve_opencode_binary()


def test_resolve_opencode_binary_returns_the_resolved_path(monkeypatch):
    monkeypatch.setattr("agent.opencode_local_provider.shutil.which", lambda name: "/usr/local/bin/opencode")
    assert _resolve_opencode_binary() == "/usr/local/bin/opencode"


# --- _live_opencode_models (the pure live-server fetch, no catalog fill-in) ----------------------


def test_live_opencode_models_derives_free_flag_from_cost(monkeypatch):
    fake_server = MagicMock(base_url="http://127.0.0.1:1")
    monkeypatch.setattr("agent.opencode_local_provider._get_shared_server", lambda: fake_server)

    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {
        "providers": [
            {
                "id": "opencode",
                "models": {
                    "big-pickle": {"cost": {"input": 0, "output": 0}},
                    "some-paid-model": {"cost": {"input": 0.5, "output": 1.5}},
                },
            },
        ],
    }

    class _FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, url):
            return fake_response

    monkeypatch.setattr("agent.opencode_local_provider.httpx.Client", lambda timeout=None: _FakeClient())

    models = _live_opencode_models()
    assert models == {
        "big-pickle": {"free": True},
        "some-paid-model": {"free": False},
    }


def test_live_opencode_models_returns_empty_dict_on_failure(monkeypatch):
    def _raise():
        raise ValueError("opencode CLI is not installed")

    monkeypatch.setattr("agent.opencode_local_provider._get_shared_server", _raise)
    assert _live_opencode_models() == {}


def test_live_opencode_models_returns_empty_dict_when_no_opencode_provider_listed(monkeypatch):
    fake_server = MagicMock(base_url="http://127.0.0.1:1")
    monkeypatch.setattr("agent.opencode_local_provider._get_shared_server", lambda: fake_server)

    fake_response = MagicMock()
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {"providers": [{"id": "some-other-provider", "models": {}}]}

    class _FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, url):
            return fake_response

    monkeypatch.setattr("agent.opencode_local_provider.httpx.Client", lambda timeout=None: _FakeClient())
    assert _live_opencode_models() == {}


# --- list_opencode_local_models (live + models.dev catalog fill-in) -------------------------------


def test_list_opencode_local_models_merges_live_and_catalog(monkeypatch):
    """Real, confirmed operator complaint this fixes: with no `opencode auth login` on this
    machine, the live server lists only its free tier (a handful of models) -- opencode itself
    genuinely supports well over a hundred more once signed in, and a picker showing only the live
    few reads as "barely supports anything" instead of "sign in to unlock the rest." The catalog
    fill-in must never override a live entry's own real cost data with a guess."""
    monkeypatch.setattr(
        "agent.opencode_local_provider._live_opencode_models",
        lambda: {"big-pickle": {"free": True}},
    )
    monkeypatch.setattr(
        "agent.providers.models_dev.list_models",
        lambda provider_id: ["big-pickle", "claude-opus-5-5", "gpt-5.5"],
    )
    monkeypatch.setattr(
        "agent.providers.models_dev.is_model_free",
        lambda provider_id, model_id: {"claude-opus-5-5": False, "gpt-5.5": None}.get(model_id),
    )

    models = list_opencode_local_models()
    assert models == {
        "big-pickle": {"free": True, "available": True},
        "claude-opus-5-5": {"free": False, "available": False},
        "gpt-5.5": {"free": False, "available": False},
    }


def test_list_opencode_local_models_degrades_to_live_only_when_catalog_unreachable(monkeypatch):
    monkeypatch.setattr(
        "agent.opencode_local_provider._live_opencode_models",
        lambda: {"big-pickle": {"free": True}},
    )
    monkeypatch.setattr("agent.providers.models_dev.list_models", lambda provider_id: [])

    models = list_opencode_local_models()
    assert models == {"big-pickle": {"free": True, "available": True}}


# --- _PermissionDenier -------------------------------------------------------------------------


def test_permission_denier_replies_reject_to_every_pending_request(monkeypatch):
    pending_payload = [{"id": "per_123", "permission": "bash"}]
    get_calls = []
    post_calls = []

    class _FakeResponse:
        def __init__(self, payload):
            self.is_success = True
            self._payload = payload

        def json(self):
            return self._payload

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            self._first = True

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, url):
            get_calls.append(url)
            # Only the FIRST poll has a pending request -- this also exercises the thread settling
            # into an idle "nothing pending" steady state without getting stuck re-denying forever.
            if self._first:
                self._first = False
                return _FakeResponse(pending_payload)
            return _FakeResponse([])

        def post(self, url, json=None):
            post_calls.append((url, json))
            return _FakeResponse(True)

    monkeypatch.setattr("agent.opencode_local_provider.httpx.Client", _FakeClient)
    # Real interval would be 0.4s per module default -- the test only needs a couple of iterations
    # to happen quickly, so shrink it rather than waiting on the real-world default.
    monkeypatch.setattr("agent.opencode_local_provider._PERMISSION_POLL_INTERVAL_SECONDS", 0.01)

    stop_event = threading.Event()
    denier = _PermissionDenier("http://127.0.0.1:1", stop_event)
    denier.start()
    try:
        deadline = time.monotonic() + 2.0
        while not post_calls and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        stop_event.set()
        denier.join(timeout=2.0)

    assert not denier.is_alive()
    assert post_calls == [("http://127.0.0.1:1/permission/per_123/reply", {"reply": "reject"})]


def test_permission_denier_survives_a_failed_poll(monkeypatch):
    """A transient poll failure (server mid-restart) must not kill the thread -- it logs and
    retries next tick, per the class's own docstring."""

    class _FailingClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, url):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr("agent.opencode_local_provider.httpx.Client", _FailingClient)
    monkeypatch.setattr("agent.opencode_local_provider._PERMISSION_POLL_INTERVAL_SECONDS", 0.01)

    stop_event = threading.Event()
    denier = _PermissionDenier("http://127.0.0.1:1", stop_event)
    denier.start()
    time.sleep(0.1)
    stop_event.set()
    denier.join(timeout=2.0)
    assert not denier.is_alive()
