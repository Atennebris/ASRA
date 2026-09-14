"""_MAX_IDENTICAL_FAILURES_PER_PHASE -- a narrower, earlier guard than the stall detector
(_STALL_REPEAT_THRESHOLD, test_tool_loop_stall.py). Real incident this fixes: a session called
dns_lookup on the same non-resolving domain 8 times total across one recon phase, in two separate
bursts of 3 and 5 with a different call landing in between -- both bursts stayed under the 6-in-a-
row stall bar, so neither ever tripped it, even though every one of the 8 independently failed
with the identical error. Keying this guard off FAILURE specifically (not repeats in general)
means it can never wrongly cut off a legitimately repeated SUCCESSFUL call (a deliberate poll, a
periodic recheck) -- only a call that keeps failing with identical arguments, which has no
legitimate reason to keep being retried verbatim.
"""
import asyncio

import pytest

from agent.core import RunContext, _MAX_IDENTICAL_FAILURES_PER_PHASE, _run_llm_tool_loop
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import ToolSpec
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _make_tool(name: str) -> ToolSpec:
    return ToolSpec(
        name=name, category="recon", tool_tier=2, executable="true",
        build_command=lambda args: ["true"], requires_allowed_target=False, installed_by_default=True,
    )


class _ScriptedLLM:
    """One tool call per turn, same shape as test_tool_loop_stall.py's own stand-in -- each
    scripted call lands as its own separate turn (not a same-turn batch), matching the real
    cross-turn pattern this guard targets."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_failure_cap_test")


def test_a_call_stops_dispatching_after_it_fails_enough_times_in_a_row():
    dispatched = []

    async def _always_fails(spec, arguments):
        dispatched.append(arguments)
        return {"status": "failed", "error": "No address associated with hostname"}

    # One more attempt scripted than the cap allows -- the LAST one must never really dispatch.
    repeats = _MAX_IDENTICAL_FAILURES_PER_PHASE + 1
    llm = _ScriptedLLM([("dns_lookup", {"domain": "super-id.net"})] * repeats)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_always_fails, expect_json_final=False,
    ))

    assert len(dispatched) == _MAX_IDENTICAL_FAILURES_PER_PHASE  # the cap, not the full script
    # Every log entry for this signature: the first N are real failures, anything past the cap is
    # a "skipped" block instead of a repeated real dispatch.
    dns_entries = [e for e in ctx.session["logs"] if e.get("command") and "dns_lookup" in e["command"]]
    statuses = [e["status"] for e in dns_entries]
    assert statuses == (["failed"] * _MAX_IDENTICAL_FAILURES_PER_PHASE) + (["skipped"] * (repeats - _MAX_IDENTICAL_FAILURES_PER_PHASE))
    assert "already failed" in dns_entries[-1]["error"]


def test_the_block_survives_a_different_call_landing_in_between():
    # The real observed shape: 3 identical failures, ONE different (successful) call, then 5 more
    # identical failures -- the stall detector's strict back-to-back streak resets on the
    # different call in between, but this guard's phase-wide failure count must not.
    dispatched = []

    async def _execute(spec, arguments):
        dispatched.append(arguments)
        if arguments.get("domain") == "super-id.net":
            return {"status": "failed", "error": "No address associated with hostname"}
        return {"status": "ok", "result": "resolved"}

    llm = _ScriptedLLM([
        ("dns_lookup", {"domain": "super-id.net"}),
        ("dns_lookup", {"domain": "super-id.net"}),
        ("dns_lookup", {"domain": "knime.superid.net"}),  # a different, successful call in between
        ("dns_lookup", {"domain": "super-id.net"}),  # already at the cap (2) -- must be blocked
        ("dns_lookup", {"domain": "super-id.net"}),  # still blocked
    ])
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_execute, expect_json_final=False,
    ))

    real_super_id_dispatches = [a for a in dispatched if a.get("domain") == "super-id.net"]
    assert len(real_super_id_dispatches) == _MAX_IDENTICAL_FAILURES_PER_PHASE
    assert len(dispatched) == 3  # 2 real super-id.net failures + 1 real knime.superid.net success


def test_different_arguments_are_never_blocked_by_each_others_failures():
    dispatched = []

    async def _always_fails(spec, arguments):
        dispatched.append(arguments)
        return {"status": "failed", "error": "boom"}

    many_distinct = [("dns_lookup", {"domain": f"host{i}.example.com"}) for i in range(_MAX_IDENTICAL_FAILURES_PER_PHASE * 3)]
    llm = _ScriptedLLM(many_distinct)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_always_fails, expect_json_final=False,
    ))

    assert len(dispatched) == len(many_distinct)  # every one is a genuinely different call


def test_a_repeatedly_successful_call_is_never_blocked():
    # The guard is scoped to FAILURES specifically -- a deliberate poll/recheck that keeps
    # succeeding with identical arguments must never be treated as waste.
    dispatched = []

    async def _always_succeeds(spec, arguments):
        dispatched.append(arguments)
        return {"status": "ok", "result": "still running"}

    repeats = _MAX_IDENTICAL_FAILURES_PER_PHASE + 3
    llm = _ScriptedLLM([("check_subagent_task", {"task_id": "abc123"})] * repeats)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("check_subagent_task")], "analyze",
        execute_tool=_always_succeeds, expect_json_final=False,
    ))

    assert len(dispatched) == repeats  # every poll actually ran -- none blocked
