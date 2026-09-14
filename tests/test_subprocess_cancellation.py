"""Cancelling the coroutine that dispatched a real subprocess call must actually kill that OS
process, not just mark the awaiting coroutine itself as cancelled/timed out.

Real, confirmed incident: a subagent's own asyncio.wait_for(timeout=900) fired while its worker
thread was still blocked inside a live nuclei subprocess call — the coroutine was correctly marked
"timeout" (agent/tools/subagent_tasks.py's _reap), but the real nuclei process kept running for
another 86 real seconds, finishing (and logging its own completion) well after the whole session
had already been recorded as completed. Cancelling an asyncio Task awaiting asyncio.to_thread does
NOT stop the underlying worker thread's blocking call on its own — a documented asyncio/threading
limitation — so agent/core.py's _dispatch_tool now tracks the live Popen handle (via
runner.current_subprocess_registry, propagated into the worker thread the same way
agent/utils/debug.py's current_session_id propagates) and kills it explicitly on CancelledError.
"""
import asyncio
import subprocess

import pytest

import agent.tools.runner as runner
from agent.core import _dispatch_tool
from agent.tools.registry import ToolSpec


def _sleep_spec(seconds: float) -> ToolSpec:
    return ToolSpec(
        name="slow_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", f"import time; time.sleep({seconds})"],
        requires_allowed_target=False, installed_by_default=True,
    )


def test_cancelling_the_dispatching_coroutine_kills_the_real_subprocess(monkeypatch):
    monkeypatch.setattr(runner, "_timeout_for", lambda spec: 30)  # long enough our cancel wins the race
    real_popen = subprocess.Popen
    captured: list[subprocess.Popen] = []

    def _capturing_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        captured.append(process)
        return process

    monkeypatch.setattr(runner.subprocess, "Popen", _capturing_popen)

    async def _scenario():
        spec = _sleep_spec(5)
        task = asyncio.create_task(_dispatch_tool(spec, {}))
        # Give the worker thread time to actually spawn the real subprocess before cancelling —
        # otherwise this test could "pass" for the wrong reason (cancelling before Popen ever ran).
        for _ in range(100):
            if captured:
                break
            await asyncio.sleep(0.05)
        assert captured, "the real subprocess was never spawned in time for this test to be meaningful"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(_scenario())

    process = captured[0]
    # kill() was sent synchronously inside _dispatch_tool's own CancelledError handler above —
    # give the OS a moment to actually reap it, then confirm it's really gone, not still running
    # the full 5s sleep in the background.
    returncode = process.wait(timeout=2)
    assert returncode is not None
    assert returncode != 0  # killed, not a clean voluntary exit


def test_a_normal_non_cancelled_dispatch_is_unaffected(monkeypatch):
    """The tracking machinery itself must be invisible on the ordinary, non-cancelled path —
    same result shape and behavior subprocess.run() always gave."""
    spec = ToolSpec(
        name="fast_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", "print('hi')"],
        requires_allowed_target=False, installed_by_default=True,
    )

    result = asyncio.run(_dispatch_tool(spec, {}))

    assert result["status"] == "ok"
    assert "hi" in result["stdout"]
    # The registry set was created and torn down around this one dispatch — nothing about it
    # should leak into module state afterward.
    assert runner.current_subprocess_registry.get() is None
