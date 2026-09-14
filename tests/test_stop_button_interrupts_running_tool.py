"""A Stop click must interrupt a tool call that's already running, not just be noticed once that
call finishes on its own.

Real, confirmed incident: NinthCircle-crackmes-usr_573a1e (a real RE-mode session) hung on a
radare2 decompile_function call; the operator clicked RE mode's Stop button 19 seconds in, and the
session kept polling as "processing" for 80+ more real seconds with zero effect (TOOL_TIMEOUT_
SECONDS itself is 600s in this project's real .env), forcing the operator to kill the whole process
by hand. request_session_stop() only ever flipped a cooperative asyncio.Event (get_stop_event) that
_run_tool_with_retry's own dispatch never checked -- once a tool call was dispatched it always ran
to completion regardless of the operator. _dispatch_tool_interruptible (agent/core.py) races the
real dispatch against that event and cancels it on a Stop, letting _dispatch_tool's own existing
current_subprocess_registry kill-on-CancelledError machinery (see test_subprocess_cancellation.py)
actually reach the live OS process -- same real-subprocess-and-poll-for-Popen technique as that
file, applied one layer up at _run_tool_with_retry, the single chokepoint every phase's own
`execute` closure (recon/analyze/exploit/re_triage/reverify/chain/...) already dispatches through.
"""
import asyncio
import subprocess

import agent.tools.runner as runner
from agent.core import RunContext, SessionStopRequested, _run_tool_with_retry, request_session_stop
from agent.tools.registry import ToolSpec


def _sleep_spec(seconds: float) -> ToolSpec:
    return ToolSpec(
        name="slow_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", f"import time; time.sleep({seconds})"],
        requires_allowed_target=False, installed_by_default=True,
    )


def test_stop_click_kills_a_tool_call_already_in_flight(monkeypatch):
    monkeypatch.setattr(runner, "_timeout_for", lambda spec: 30)  # long enough our Stop wins the race
    real_popen = subprocess.Popen
    captured: list[subprocess.Popen] = []

    def _capturing_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        captured.append(process)
        return process

    monkeypatch.setattr(runner.subprocess, "Popen", _capturing_popen)

    session_id = "usr_stop_button_test"
    ctx = RunContext(llm=object(), session={"session_id": session_id}, session_id=session_id)

    async def _scenario():
        spec = _sleep_spec(5)
        task = asyncio.create_task(_run_tool_with_retry(ctx, spec, {}))
        # Give the worker thread time to actually spawn the real subprocess before clicking Stop --
        # otherwise this test could "pass" for the wrong reason (stopping before it ever started).
        for _ in range(100):
            if captured:
                break
            await asyncio.sleep(0.05)
        assert captured, "the real subprocess was never spawned in time for this test to be meaningful"
        request_session_stop(session_id)
        try:
            await task
            assert False, "expected SessionStopRequested, the tool call returned a result instead"
        except SessionStopRequested:
            pass

    asyncio.run(_scenario())

    process = captured[0]
    # Same reasoning as test_subprocess_cancellation.py: give the OS a moment to actually reap it,
    # then confirm it's really gone, not still running the full 5s sleep in the background.
    returncode = process.wait(timeout=2)
    assert returncode is not None
    assert returncode != 0  # killed, not a clean voluntary exit


def test_stop_already_requested_before_the_call_starts_never_dispatches(monkeypatch):
    """If Stop was already clicked (e.g. a queued-up second tool call in the same batch after the
    first one already noticed Stop), a fresh dispatch must not even start a new subprocess."""
    real_popen = subprocess.Popen
    captured: list[subprocess.Popen] = []
    monkeypatch.setattr(runner.subprocess, "Popen", lambda *a, **k: captured.append(real_popen(*a, **k)) or captured[-1])

    session_id = "usr_stop_button_prerequested_test"
    ctx = RunContext(llm=object(), session={"session_id": session_id}, session_id=session_id)
    request_session_stop(session_id)

    async def _scenario():
        try:
            await _run_tool_with_retry(ctx, _sleep_spec(5), {})
            assert False, "expected SessionStopRequested"
        except SessionStopRequested:
            pass

    asyncio.run(_scenario())
    assert not captured, "a tool call must not dispatch a real subprocess once Stop was already requested"
