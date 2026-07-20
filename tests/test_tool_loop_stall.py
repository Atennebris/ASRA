"""_run_llm_tool_loop's stall detector — the replacement for the old per-phase call-count cap
(MAX_TOOL_ITERATIONS_PER_PHASE). Real work (varied tool calls) must never be cut short no matter
how many calls it takes; only a genuine stuck loop (the exact same call repeated back-to-back)
should stop a phase early.
"""
import asyncio

import pytest

from agent.core import RunContext, _STALL_REPEAT_THRESHOLD, _run_llm_tool_loop
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import ToolSpec
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    # _append_log() saves the session on every logged step (real behavior, not test-specific) —
    # redirect storage so that never touches the real data/sessions/.
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _make_tool(name: str) -> ToolSpec:
    # tool_tier=2 (external-subprocess shape) rather than 1: execute_tool bypasses real dispatch
    # entirely in these tests, but tier=1 requires a native_function to pass ToolSpec's own
    # validation, which is irrelevant machinery this test has no reason to set up.
    return ToolSpec(
        name=name, category="recon", tool_tier=2, executable="true",
        build_command=lambda args: ["true"], requires_allowed_target=False, installed_by_default=True,
    )


class _ScriptedLLM:
    """Feeds back canned tool-call responses, then a plain text final reply once the script
    runs out — mirrors a real model's "done calling tools" turn."""

    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


async def _noop_execute(spec, arguments):
    return {"status": "ok", "tool": spec.name}


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_stall_test")


def test_stall_detector_stops_after_identical_repeats_not_before():
    # One fewer than the threshold, all identical — must NOT trigger the stall stop; the loop
    # keeps going until the script naturally runs out (proves it doesn't cut off early).
    repeats = _STALL_REPEAT_THRESHOLD - 1
    llm = _ScriptedLLM([("dns_lookup", {"domain": "example.com"})] * repeats)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    # llm.complete was called once per scripted tool call, plus one final "no more tools" turn.
    assert llm.calls_made == repeats + 1


def test_stall_detector_stops_exactly_at_the_repeat_threshold():
    # Far more identical calls scripted than the threshold — the loop must stop itself once the
    # threshold is hit, not exhaust the whole (much longer) script.
    llm = _ScriptedLLM([("dns_lookup", {"domain": "example.com"})] * (_STALL_REPEAT_THRESHOLD * 5))
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    assert llm.calls_made == _STALL_REPEAT_THRESHOLD


def test_varied_calls_never_trip_the_stall_detector():
    # A different target each time (real, distinct work) — must run to completion regardless of
    # how many calls that takes, exactly the scenario a fixed count cap used to break.
    many_distinct_calls = [("dns_lookup", {"domain": f"host{i}.example.com"}) for i in range(_STALL_REPEAT_THRESHOLD * 10)]
    llm = _ScriptedLLM(many_distinct_calls)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    assert llm.calls_made == len(many_distinct_calls) + 1
