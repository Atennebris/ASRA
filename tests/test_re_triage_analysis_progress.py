"""RE-triage stall/progress fixes.

- Task 3: a SUCCESSFUL, non-duplicate RE analysis call (radare2/ghidra/custom_re_script) counts as
  real progress, so a productive-but-silent triage pass isn't cut by the no-progress stall guard
  with a misleading "recorded nothing" -- while re-running the IDENTICAL call still counts as
  spinning and is caught.
- Task 2: record_hypothesis/resolve_hypothesis are category="post_exploit", so the bare "re"
  category sweep never offers them; they must be explicitly appended to the triage toolset (the
  prompt tells the model to call record_hypothesis, and the resume logic reads session["hypotheses"]).
"""
import asyncio

import pytest

from agent.core import (
    RunContext,
    _STALL_REPEAT_THRESHOLD,
    _run_llm_tool_loop,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import ToolSpec, get_tool
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _make_tool(name: str) -> ToolSpec:
    return ToolSpec(
        name=name, category="re", tool_tier=2, executable="true",
        build_command=lambda args: ["true"], requires_allowed_target=False, installed_by_default=True,
    )


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


async def _ok_execute(spec, arguments):
    return {"status": "ok", "tool": spec.name}


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_re_progress_test")


def test_distinct_analysis_calls_count_as_progress_and_do_not_trip_the_stall():
    # 20 distinct radare2 decompiles, recording nothing durable -- with the OLD behavior this would
    # trip a progress_stall_threshold=4 almost immediately; now each fresh analysis call is progress,
    # so the pass runs to completion.
    script = [("radare2", {"file_path": "/tmp/b", "analysis": "decompile", "function": f"fcn.{i:06x}"}) for i in range(20)]
    llm = _ScriptedLLM(script)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("radare2")], "re_triage",
        execute_tool=_ok_execute, expect_json_final=False, progress_stall_threshold=4,
    ))

    assert llm.calls_made == len(script) + 1
    assert not ctx.session.get("stall_events")


def test_identical_analysis_calls_still_trip_the_stall():
    # Re-running the EXACT same radare2 call is spinning, not progress: only the first is credited,
    # the rest increment the no-progress counter until the stall fires. progress_stall_threshold=4
    # is below the back-to-back _STALL_REPEAT_THRESHOLD so the progress guard is what stops it.
    assert _STALL_REPEAT_THRESHOLD > 4
    script = [("radare2", {"file_path": "/tmp/b", "analysis": "decompile", "function": "fcn.401000"})] * 20
    llm = _ScriptedLLM(script)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("radare2")], "re_triage",
        execute_tool=_ok_execute, expect_json_final=False, progress_stall_threshold=4,
    ))

    # call1 credits progress; calls 2-5 increment to the threshold -> stop, +1 forced summary turn.
    assert llm.calls_made == 6
    assert ctx.session.get("stall_events")
    assert ctx.session["stall_events"][-1]["tool"] == "no_progress"


def test_failed_analysis_call_does_not_count_as_progress():
    async def _fail_execute(spec, arguments):
        return {"status": "failed", "error": "boom"}

    # Distinct-but-failing radare2 calls record nothing AND aren't successful progress, so the
    # progress guard must still stop the pass.
    script = [("radare2", {"file_path": "/tmp/b", "analysis": "decompile", "function": f"fcn.{i:06x}"}) for i in range(20)]
    llm = _ScriptedLLM(script)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("radare2")], "re_triage",
        execute_tool=_fail_execute, expect_json_final=False, progress_stall_threshold=4,
    ))

    assert llm.calls_made == 5
    assert ctx.session.get("stall_events")


def test_hypothesis_tools_exist_and_are_outside_the_re_category():
    # Task 2: these must be fetchable by name (so run_re_triage can append them) AND must NOT be in
    # the "re" category (which is exactly why they need the explicit append -- the bare category
    # sweep would never surface them, so the model could not record a hypothesis during triage).
    for name in ("record_hypothesis", "resolve_hypothesis"):
        spec = get_tool(name)
        assert spec is not None, f"{name} must be registered"
        assert spec.category != "re"
