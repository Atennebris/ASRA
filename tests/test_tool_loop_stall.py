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

    # +1: a safeguard stop (this stall break) now makes one forced "summarize what you found"
    # call (tools=None) before the phase truly ends, same as the natural/other safeguard paths --
    # see agent/core.py's own comment on that branch for the real incident this fixes.
    assert llm.calls_made == _STALL_REPEAT_THRESHOLD + 1


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


async def _running_background_job_execute(spec, arguments):
    return {"status": "running"} if spec.name == "background_job_check" else {"status": "ok", "tool": spec.name}


def test_background_job_check_polling_a_running_job_never_trips_the_stall_detector():
    # Far more identical background_job_check("running") polls scripted than the stall threshold --
    # unlike dns_lookup's identical-repeat case above, this must run the WHOLE script instead of
    # being cut off: the job it's waiting on is still genuinely in flight, an independent OS-level
    # subprocess with its own deadline, not a stuck model. Real, confirmed incident this fixes: a
    # live hydra RDP brute-force got cut off from the only phase polling it after 6 checks in 18
    # seconds by this exact detector, then quietly succeeded with 6 valid credentials a few minutes
    # later that nothing ever saw (see agent/core.py's _auto_record_cracked_credentials_finding).
    script = [("background_job_check", {"job_id": "j1"})] * (_STALL_REPEAT_THRESHOLD * 5)
    llm = _ScriptedLLM(list(script))
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("background_job_check")], "exploit",
        execute_tool=_running_background_job_execute, expect_json_final=False,
    ))

    assert llm.calls_made == len(script) + 1
    assert not ctx.session.get("stall_events")


def test_background_job_check_still_trips_once_it_stops_reporting_running():
    # The exemption above only applies while status stays "running" -- a call that keeps returning
    # the exact same TERMINAL status (the model re-checking a job that already errored out, learning
    # nothing new each time) is a genuine stuck loop and must still trip normal stall detection.
    async def _stuck_error_execute(spec, arguments):
        return {"status": "error", "error": "boom"}

    llm = _ScriptedLLM([("background_job_check", {"job_id": "j1"})] * (_STALL_REPEAT_THRESHOLD * 5))
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("background_job_check")], "exploit",
        execute_tool=_stuck_error_execute, expect_json_final=False,
    ))

    assert llm.calls_made == _STALL_REPEAT_THRESHOLD + 1
    assert ctx.session.get("stall_events")


def test_progress_stall_stops_when_nothing_is_recorded():
    # Distinct calls (never trip the back-to-back detector) that record no durable state — with
    # progress_stall_threshold set, the loop must stop itself once that many calls pass with nothing
    # recorded, instead of grinding through the whole (much longer) script. This is the RE-triage
    # runaway (93 calls, 0 findings) the back-to-back detector could never catch.
    llm = _ScriptedLLM([("dns_lookup", {"domain": f"host{i}.example.com"}) for i in range(50)])
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "re_triage",
        execute_tool=_noop_execute, expect_json_final=False, progress_stall_threshold=4,
    ))

    # +1: a safeguard stop (this progress-stall break) now makes one forced "summarize what you
    # found" call (tools=None) before the phase truly ends -- see agent/core.py's own comment on
    # that branch for the real incident this fixes.
    assert llm.calls_made == 5
    assert ctx.session.get("stall_events")
    assert ctx.session["stall_events"][-1]["tool"] == "no_progress"


def test_progress_stall_is_reset_by_a_recording_call():
    # A successful record_target_profile mid-stream resets the no-progress counter, so a pass that
    # keeps recording real state runs to completion no matter how many read calls sit between records.
    script = (
        [("dns_lookup", {"domain": f"a{i}.example.com"}) for i in range(3)]
        + [("record_target_profile", {"label": "Language", "value": "Go"})]
        + [("dns_lookup", {"domain": f"b{i}.example.com"}) for i in range(3)]
    )
    llm = _ScriptedLLM(script)
    tools = [_make_tool("dns_lookup"), _make_tool("record_target_profile")]
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", tools, "re_triage",
        execute_tool=_noop_execute, expect_json_final=False, progress_stall_threshold=4,
    ))

    # Never 4-in-a-row without a record (the record resets it), so it runs the full script + final turn.
    assert llm.calls_made == len(script) + 1
    assert not ctx.session.get("stall_events")


def test_progress_stall_disabled_by_default():
    # Without the opt-in threshold, a long record-nothing run is untouched by this guard (every
    # other phase keeps its existing behavior).
    llm = _ScriptedLLM([("dns_lookup", {"domain": f"host{i}.example.com"}) for i in range(20)])
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    assert llm.calls_made == 21
    assert not ctx.session.get("stall_events")


class _OneTurnBatchLLM:
    """One turn emitting several tool calls with a shared reasoning `content`, then a final reply —
    to prove the turn's thought is logged once, not copied onto every tool entry of the batch."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, tool_calls):
        self._tool_calls = tool_calls
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self.calls_made == 1:
            return LLMResponse(
                content="the shared reasoning for this whole turn",
                tool_calls=[ToolCallRequest(id=f"c{i}", name=n, arguments=a) for i, (n, a) in enumerate(self._tool_calls)],
            )
        return LLMResponse(content="done", tool_calls=[])


def test_turn_thought_logged_once_per_batch_not_per_tool_call():
    llm = _OneTurnBatchLLM([
        ("dns_lookup", {"domain": "a.example.com"}),
        ("dns_lookup", {"domain": "b.example.com"}),
        ("dns_lookup", {"domain": "c.example.com"}),
    ])
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    tool_logs = [entry for entry in ctx.session["logs"] if entry.get("command")]
    assert tool_logs[0]["thought"] == "the shared reasoning for this whole turn"
    assert all(entry["thought"] is None for entry in tool_logs[1:])
