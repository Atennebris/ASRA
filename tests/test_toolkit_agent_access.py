"""The native toolkit's tools (send_raw_request/list_captured_traffic/decode_value/diff_requests/
intruder_run/sequencer_analyze, the last added in a later log-review-audit follow-up) becoming
real, settings-toggle-gated agent tool calls. Covers:
- _toolkit_tool_extras(): pure unit tests, same style as _subagent_delegation_extras' own.
- Every real phase call site (recon/analyze/reverify/exploit/chain) actually offers the enabled
  tools in the schema handed to the LLM, same "verified against the real phase function, not
  inferred from reading the source" discipline as tests/test_subagent_delegation_addendum.py.
- _run_tool_with_retry injects _session_id for the session-scoped tools, not decode_value.
- _delegate_to_subagent_impl filters a subagent profile's own allowed_tools by the same toggles.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _delegate_to_subagent_impl,
    _run_analyze,
    _run_chain,
    _run_exploit_for_finding,
    _run_recon,
    _run_reverify,
    _run_tool_with_retry,
    _toolkit_tool_extras,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import subagent_store, toolkit_settings_store
from agent.tools.registry import get_tool, get_tools_by_category
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_settings_store, "TOOLKIT_AGENT_SETTINGS_STORE_PATH", tmp_path / "toolkit_agent_settings.json")
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _enable(**overrides) -> None:
    settings = {key: False for key in toolkit_settings_store.BOOL_KEYS}
    settings.update(overrides)
    toolkit_settings_store.save_toolkit_agent_settings(settings)


# --- _toolkit_tool_extras: pure unit tests ------------------------------------------------------


def test_extras_are_empty_when_every_toggle_is_off(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert _toolkit_tool_extras() == []


def test_extras_include_only_the_enabled_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_decoder_enabled=True)

    names = {spec.name for spec in _toolkit_tool_extras()}
    assert names == {"decode_value"}


def test_extras_include_every_enabled_tool_independently(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(
        toolkit_proxy_enabled=True, toolkit_repeater_enabled=True, toolkit_decoder_enabled=True,
        toolkit_comparer_enabled=True, toolkit_intruder_enabled=True, toolkit_sequencer_enabled=True,
    )

    names = {spec.name for spec in _toolkit_tool_extras()}
    assert names == {
        "list_captured_traffic", "send_raw_request", "decode_value", "diff_requests",
        "intruder_run", "sequencer_analyze",
    }


def test_extras_include_only_intruder_when_only_that_toggle_is_on(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_intruder_enabled=True)

    names = {spec.name for spec in _toolkit_tool_extras()}
    assert names == {"intruder_run"}


def test_extras_include_only_sequencer_when_only_that_toggle_is_on(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_sequencer_enabled=True)

    names = {spec.name for spec in _toolkit_tool_extras()}
    assert names == {"sequencer_analyze"}


# --- integration: every real phase call site actually offers the enabled tools ------------------


class _CapturingLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, final_response: LLMResponse):
        self._final_response = final_response
        self.captured_tool_names: list[set] = []

    def complete(self, messages, tools=None, stop_check=None):
        self.captured_tool_names.append({t["function"]["name"] for t in (tools or [])})
        return self._final_response


def test_recon_phase_offers_the_enabled_toolkit_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_proxy_enabled=True)
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_recon_toolkit_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    assert "list_captured_traffic" in llm.captured_tool_names[0]


def test_recon_phase_offers_intruder_run_when_its_own_toggle_is_on(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_intruder_enabled=True)
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_recon_intruder_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    assert "intruder_run" in llm.captured_tool_names[0]


def test_analyze_phase_offers_the_enabled_toolkit_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_decoder_enabled=True)
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_analyze_toolkit_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", {"targets": [], "cves": []}))

    assert "decode_value" in llm.captured_tool_names[0]


def test_reverify_phase_offers_the_enabled_toolkit_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_comparer_enabled=True)
    llm = _CapturingLLM(LLMResponse(
        content=None,
        tool_calls=[ToolCallRequest(id="call_1", name="record_reverification_result", arguments={"verification_outcome": "confirmed_fixed", "reasoning": "gone"})],
    ))
    session = {
        "session_id": "usr_reverify_toolkit_test", "logs": [], "findings": [],
        "carried_over_findings": [{"title": "Old Finding"}],
    }
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert "diff_requests" in llm.captured_tool_names[0]


def test_exploit_for_finding_offers_the_enabled_toolkit_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_repeater_enabled=True)
    llm = _CapturingLLM(LLMResponse(
        content=None,
        tool_calls=[ToolCallRequest(id="c1", name="record_exploit_decision", arguments={"action": "skipped_no_suitable_tool"})],
    ))
    session = {"session_id": "usr_exploit_toolkit_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    finding = {"title": "Test Finding", "verification": "verified"}

    # record_exploit_decision is the phase's own terminal_tool -- must be in the offered set for
    # the loop to resolve the model's terminal call at all, same as the real _run_exploit always
    # passing get_tools_by_category("exploit") (which includes it) rather than an empty list.
    exploit_tools = get_tools_by_category("exploit")
    _run(_run_exploit_for_finding(ctx, "example.com", finding, exploit_tools))

    assert "send_raw_request" in llm.captured_tool_names[0]


def test_chain_phase_offers_the_enabled_toolkit_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_proxy_enabled=True)
    llm = _CapturingLLM(LLMResponse(content="no chain found", tool_calls=[]))
    session = {"session_id": "usr_chain_toolkit_test", "logs": [], "findings": [{"title": "F1", "severity": "High"}]}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_chain(ctx))

    assert "list_captured_traffic" in llm.captured_tool_names[0]


def test_toolkit_tool_absent_from_every_phase_when_all_toggles_off(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_recon_toolkit_off_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    toolkit_names = {
        "send_raw_request", "list_captured_traffic", "decode_value", "diff_requests",
        "intruder_run", "sequencer_analyze",
    }
    assert not (toolkit_names & llm.captured_tool_names[0])


# --- _run_tool_with_retry: session_id injection for the three session-scoped tools --------------


def test_run_tool_with_retry_injects_session_id_for_toolkit_tools_that_need_it(monkeypatch):
    captured = {}

    def fake_run_tool(spec, arguments):
        captured["arguments"] = arguments
        return {"status": "ok"}

    monkeypatch.setattr("agent.core.run_tool", fake_run_tool)
    session = {"session_id": "usr_inject_test", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id="usr_inject_test")

    for name in ("send_raw_request", "list_captured_traffic", "diff_requests", "intruder_run", "sequencer_analyze"):
        spec = get_tool(name)
        _run(_run_tool_with_retry(ctx, spec, {}))
        assert captured["arguments"]["_session_id"] == "usr_inject_test", f"{name} did not get _session_id injected"


def test_run_tool_with_retry_does_not_inject_session_id_for_decode_value(monkeypatch):
    captured = {}

    def fake_run_tool(spec, arguments):
        captured["arguments"] = arguments
        return {"status": "ok"}

    monkeypatch.setattr("agent.core.run_tool", fake_run_tool)
    session = {"session_id": "usr_inject_test", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id="usr_inject_test")

    spec = get_tool("decode_value")
    _run(_run_tool_with_retry(ctx, spec, {}))
    assert "_session_id" not in captured["arguments"]


# --- _delegate_to_subagent_impl: a subagent never gets a wider toolkit toolset than the toggles --


def _profile_with_tools(name: str, allowed_tools: list[str]) -> dict:
    profile_store = subagent_store.add_profile(name, allowed_tools, "", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    return subagent_store.update_profile(profile_id, enabled=True)


async def _delegate_and_await_completion(session: dict, subagent_name: str) -> None:
    """Spawns the delegation exactly like a real model-triggered call, then awaits the actual
    background asyncio.Task it creates (agent/tools/subagent_tasks.py's own
    _RUNNING_SUBAGENT_TASKS registry) inside the SAME event loop -- asyncio.create_task()'s own
    task would otherwise never get a chance to actually run before a bare asyncio.run() around
    only the delegate call itself tears the loop down."""
    from agent.tools import subagent_tasks
    result = await _delegate_to_subagent_impl({
        "_session_id": session["session_id"], "_session": session,
        "subagent_name": subagent_name, "task_description": "do something",
    })
    assert result["status"] == "ok", result
    task = subagent_tasks._RUNNING_SUBAGENT_TASKS[result["task_id"]]
    await task


def test_subagent_never_gets_a_toolkit_tool_the_operator_has_not_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _profile_with_tools("Recon Bot", ["decode_value", "diff_requests"])  # neither toggle enabled

    llm = _CapturingLLM(LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="report_subagent_result", arguments={"summary": "done"})]))
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: llm)
    session = {"session_id": "usr_subagent_toolkit_test", "logs": [], "subagent_tasks": {}}

    _run(_delegate_and_await_completion(session, "Recon Bot"))

    assert llm.captured_tool_names
    assert "decode_value" not in llm.captured_tool_names[0]
    assert "diff_requests" not in llm.captured_tool_names[0]


def test_subagent_gets_a_toolkit_tool_once_the_operator_enables_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable(toolkit_decoder_enabled=True)
    _profile_with_tools("Recon Bot", ["decode_value"])

    llm = _CapturingLLM(LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="report_subagent_result", arguments={"summary": "done"})]))
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: llm)
    session = {"session_id": "usr_subagent_toolkit_test2", "logs": [], "subagent_tasks": {}}

    _run(_delegate_and_await_completion(session, "Recon Bot"))

    assert llm.captured_tool_names
    assert "decode_value" in llm.captured_tool_names[0]
