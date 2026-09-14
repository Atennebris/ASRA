"""A delegated subagent must never be able to call delegate_to_subagent/check_subagent_task itself
-- agent/core.py's _delegate_to_subagent_impl now strips both unconditionally from tool_specs
regardless of what a profile's own allowed_tools stores.

Real, confirmed incident this closes: a real session's subagent (blocked by a since-fixed httpx
validation bug) used delegate_to_subagent to spawn a SECOND, nested subagent task instead of
reporting back "I couldn't do this" -- contributing to that one delegation running 85 LLM turns /
81 tool calls (21 exact repeats, 64 not-ok outcomes) instead of the small, bounded task it was
meant to be. The whole point of delegation is one bounded unit of work reported back to the main
agent; a subagent that can recursively delegate defeats that.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import _delegate_to_subagent_impl
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import subagent_store, subagent_tasks
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(subagent_tasks, "_RUNNING_SUBAGENT_TASKS", {})


def _run(coro):
    return asyncio.run(coro)


class _CapturesOfferedToolsThenReports:
    """Reports its own tool names back via the summary (cheap, no need for a real tools= capture
    hook) then finishes immediately."""
    provider_id = "test-subagent-provider"
    model = "test-model"
    context_limit = None

    def __init__(self):
        self.captured_tool_names = None

    def complete(self, messages, tools=None, stop_check=None):
        if self.captured_tool_names is None:
            self.captured_tool_names = [t["function"]["name"] for t in (tools or [])]
        return LLMResponse(
            content=None,
            tool_calls=[ToolCallRequest(id="c1", name="report_subagent_result", arguments={"summary": "done"})],
        )


def test_a_subagent_never_receives_delegate_to_subagent_or_check_subagent_task(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    # Deliberately includes both recursion-enabling tools in the profile's own allowed_tools --
    # proves the runtime filter strips them regardless of what's stored (a profile saved before
    # the Subagents-page checklist itself started excluding them could still have this shape).
    profile_store = subagent_store.add_profile(
        "Recon Bot", ["delegate_to_subagent", "check_subagent_task", "dns_lookup"], "test", None, None,
    )
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)

    fake_llm = _CapturesOfferedToolsThenReports()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: fake_llm)

    session_id = "usr_no_recursive_delegation_test"
    session = {"session_id": session_id, "logs": [], "findings": [], "subagent_tasks": {}}

    async def _spawn_and_await():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check things",
            "_session_id": session_id, "_session": session,
        })
        assert result["status"] == "ok"
        task_id = result["task_id"]
        await subagent_tasks._RUNNING_SUBAGENT_TASKS[task_id]

    _run(_spawn_and_await())

    assert fake_llm.captured_tool_names is not None
    assert "delegate_to_subagent" not in fake_llm.captured_tool_names
    assert "check_subagent_task" not in fake_llm.captured_tool_names
    # The rest of the profile's own real, non-recursive tool choice is untouched by the filter.
    assert "dns_lookup" in fake_llm.captured_tool_names
    assert "report_subagent_result" in fake_llm.captured_tool_names


def test_a_subagent_never_receives_record_finding_or_record_target(tmp_path, monkeypatch):
    """Real, confirmed incident: a subagent called record_finding 7 times for real, distinct
    findings and got "status": "ok" every single time, because that native_function just validates
    and returns ok — the actual append into session["findings"] only happens inside each phase's
    own execute() closure, which a subagent's own _run_llm_tool_loop call never gets. None of the
    7 ever reached the final report; the subagent timed out before it could summarize them back via
    report_subagent_result, the only path that's actually wired to reach the main agent. Fixed the
    same way as the recursive-delegation incident above: strip both from tool_specs unconditionally
    regardless of what a profile's own allowed_tools stores.
    """
    profile_store = subagent_store.add_profile(
        "Recon Bot", ["record_finding", "record_target", "dns_lookup"], "test", None, None,
    )
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)

    fake_llm = _CapturesOfferedToolsThenReports()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: fake_llm)

    session_id = "usr_no_subagent_recording_test"
    session = {"session_id": session_id, "logs": [], "findings": [], "subagent_tasks": {}}

    async def _spawn_and_await():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check things",
            "_session_id": session_id, "_session": session,
        })
        assert result["status"] == "ok"
        task_id = result["task_id"]
        await subagent_tasks._RUNNING_SUBAGENT_TASKS[task_id]

    _run(_spawn_and_await())

    assert fake_llm.captured_tool_names is not None
    assert "record_finding" not in fake_llm.captured_tool_names
    assert "record_target" not in fake_llm.captured_tool_names
    assert "dns_lookup" in fake_llm.captured_tool_names
    assert "report_subagent_result" in fake_llm.captured_tool_names


def test_a_subagent_never_receives_the_phase_terminal_recording_tools(tmp_path, monkeypatch):
    """Same structural gap as record_finding/record_target directly above, for their six siblings:
    record_hypothesis/resolve_hypothesis/record_exploit_decision/record_chain_result/
    record_reverification_result/record_skeptical_verification_result are each a phase's own
    terminal_tool or live-recording tool — validated and returned "status": "ok" by their own
    native_function, but only actually applied (ending a phase's _run_llm_tool_loop, writing back
    to session["findings"]/session["hypotheses"]) inside that PHASE's own execute()/terminal_tool
    handling in agent/core.py, which a subagent's own _run_llm_tool_loop call never gets. Missed
    when the record_finding/record_target fix above first landed; a real operator profile
    ("Default Subagent") had all six checked in its own allowed_tools at the time this was found.
    """
    six_recording_tools = [
        "record_hypothesis", "resolve_hypothesis", "record_exploit_decision",
        "record_chain_result", "record_reverification_result", "record_skeptical_verification_result",
    ]
    profile_store = subagent_store.add_profile(
        "Recon Bot", six_recording_tools + ["dns_lookup"], "test", None, None,
    )
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)

    fake_llm = _CapturesOfferedToolsThenReports()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: fake_llm)

    session_id = "usr_no_subagent_terminal_recording_test"
    session = {"session_id": session_id, "logs": [], "findings": [], "subagent_tasks": {}}

    async def _spawn_and_await():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check things",
            "_session_id": session_id, "_session": session,
        })
        assert result["status"] == "ok"
        task_id = result["task_id"]
        await subagent_tasks._RUNNING_SUBAGENT_TASKS[task_id]

    _run(_spawn_and_await())

    assert fake_llm.captured_tool_names is not None
    for tool_name in six_recording_tools:
        assert tool_name not in fake_llm.captured_tool_names
    assert "dns_lookup" in fake_llm.captured_tool_names
    assert "report_subagent_result" in fake_llm.captured_tool_names
