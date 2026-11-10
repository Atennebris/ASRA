"""Settings/subagent "Test" buttons (test-llm) run as tracked background threads instead of a
blocking request.

Why: _call_with_backoff's retry schedule (agent/llm_client.py) can legitimately take a long time of
silent waiting on a degraded/unreachable model (2s/4s/8s/16s/30s backoff between up to 6 attempts,
each attempt itself able to hang for the provider's whole request timeout). A plain blocking POST
left the button showing "Testing..." for that entire stretch with zero visibility into which retry
attempt it was on and no way to cancel -- a real, confirmed operator complaint, and one that has
nothing to do with any particular model being flaky: it's the same silent wait regardless of why the
provider is slow to answer. Same "start now, poll status" shape agent/tools/arsenal_install.py
already established for a different slow operation, adapted for an in-process Python call (a
background thread, not a subprocess) rather than a subprocess+log file.

Keyed by an arbitrary caller-supplied `key` (in practice, the Test button's own DOM target_id --
see templates/partials/llm_test_status.html) -- NOT the single-slot design this module started
with. Real, confirmed regression that forced this: once more than one Test button existed on the
same page at once (the main AI Provider & Model picker, Secondary verification, every Reserve
providers chain row, a subagent profile's own picker), a single shared slot meant clicking Test on
one row while another's test was still running didn't start a second test at all -- it just showed
that OTHER row's own in-flight progress/result under this row's label, or (once that mismatch was
caught and surfaced honestly) refused to start a real concurrent test at all when the operator
clearly expected one. Keying by target_id, same dict[str, ...] pattern
agent/tools/background_jobs.py's own _RUNNING_PROCESSES already uses for a different kind of
concurrent job, gives every widget its own real thread/cancel_event/state -- true concurrent tests,
each independently cancellable, with no cross-widget mismatch to detect or explain in the UI at all.

A job's "running" state is its own flag, not the worker thread's liveness: a request already in
flight cannot be killed, so Cancel / the watchdog timeout / being superseded by a newer Test on the
same key end the job immediately for the operator while the orphaned thread finishes (and is
ignored) in the background -- see _finish.
"""
from __future__ import annotations

import os
import threading
import time

from agent.chat import _format_llm_error
from agent.llm_client import current_retry_progress_sink, get_provider
from agent.utils.logger import get_logger

logger = get_logger("LLM")

# In-memory only, keyed by the caller's own target_id -- thread/cancel_event are not
# JSON-serializable and only meaningful within this process's own lifetime, same reasoning
# arsenal_install.py's own _STATE documents for its Popen handle. A finished (non-running) entry
# is pruned the next time ANY start_test() runs if it's older than _FINISHED_JOB_TTL_SECONDS, so a
# page that keeps generating fresh target_ids (Reserve chain rows added/removed over a long-running
# server) doesn't leak one dict entry per test ever run.
_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()
_FINISHED_JOB_TTL_SECONDS = 3600.0

_IDLE_STATUS = {
    "running": False, "provider": None, "model": None, "state": "idle",
    "attempt": None, "total_attempts": None, "wait_seconds": None, "message": None, "elapsed_ms": None,
    "action": None, "action_label": None,
}


def _is_running(key: str) -> bool:
    """State-based on purpose, not thread.is_alive(): a call already in flight on the network cannot
    be killed (Python can't preempt a blocking HTTP request), so after Cancel / timeout / being
    superseded its thread lingers for up to the provider's own request timeout (observed: ~90s after
    a Cancel click, ~12 min for a dead free-tier model). Judging "running" by the thread kept the
    whole key locked for that long and swallowed every later Test click on it."""
    job = _JOBS.get(key)
    return job is not None and job["state"] == "running"


def _prune_finished_jobs() -> None:
    cutoff = time.monotonic() - _FINISHED_JOB_TTL_SECONDS
    stale = [k for k, job in _JOBS.items() if not _is_running(k) and job.get("finished_at", 0.0) < cutoff]
    for k in stale:
        del _JOBS[k]


def _finish(job: dict, state: str, message: str, **extra) -> bool:
    """Moves `job` to a terminal state exactly once (caller holds _LOCK); returns False if it was
    already terminal. First writer wins, so a worker thread that was abandoned by Cancel/timeout and
    only returns later can never overwrite what the operator was already shown."""
    if job["state"] != "running":
        return False
    job.update(state=state, message=message, finished_at=time.monotonic(), **extra)
    return True


def _test_timeout_seconds() -> float:
    return float(os.getenv("LLM_TEST_TIMEOUT_SECONDS", "90"))


def start_test(key: str, provider: str, model: str) -> dict:
    """Starts the test call in a background thread under this key. Returns
    status="already_running" (not a second thread) only if THIS key is already testing the SAME
    provider/model -- a different key runs fully independently (see this module's own docstring), and
    the same key asked to test something DIFFERENT supersedes the old test instead of being refused:
    the operator changed the dropdown and clicked Test again, so the old result no longer matters.
    Refusing (the earlier behavior) made the panel keep showing the stale job's progress under the
    newly picked provider while the real test never started."""
    with _LOCK:
        _prune_finished_jobs()
        current = _JOBS.get(key)
        if current is not None and current["state"] == "running":
            if (current["provider"], current["model"]) == (provider, model):
                logger.debug("test_llm_job: start requested for key=%s but it already tests %s/%s", key, provider, model)
                return {"status": "already_running", **_status_locked(key)}
            logger.debug(
                "test_llm_job: key=%s superseding running test %s/%s with %s/%s",
                key, current["provider"], current["model"], provider, model,
            )
            current["cancel_event"].set()
            _finish(current, "cancelled", "Superseded by a newer test.")

        cancel_event = threading.Event()
        job = {
            "thread": None, "cancel_event": cancel_event, "provider": provider, "model": model,
            "state": "running", "attempt": None, "total_attempts": None,
            "wait_seconds": None, "message": None, "elapsed_ms": None, "finished_at": 0.0,
            "action": None, "action_label": None,
        }
        _JOBS[key] = job

    timeout_seconds = _test_timeout_seconds()

    def on_progress(attempt: int, total_attempts: int, wait_seconds: float) -> None:
        with _LOCK:
            job["attempt"] = attempt
            job["total_attempts"] = total_attempts
            job["wait_seconds"] = wait_seconds

    def on_timeout() -> None:
        # A Test must answer "does this model respond right now", not replay a whole scan's retry
        # budget (6 attempts x ~60s request timeout + backoff measured ~12 minutes on a dead model).
        cancel_event.set()
        with _LOCK:
            timed_out = _finish(
                job, "error",
                f"No answer from {provider}/{model} within {int(timeout_seconds)}s -- the provider looks unresponsive or overloaded.",
            )
        if timed_out:
            logger.debug("test_llm_job: key=%s provider=%s model=%s timed out after %ss", key, provider, model, timeout_seconds)

    watchdog = threading.Timer(timeout_seconds, on_timeout) if timeout_seconds > 0 else None

    def run() -> None:
        # ContextVar, not a parameter -- set here (this thread's own context), read inside
        # _call_with_backoff regardless of how deep the actual retry loop is nested. See
        # llm_client.py's current_retry_progress_sink docstring for the full reasoning.
        current_retry_progress_sink.set(on_progress)
        started_at = time.monotonic()
        try:
            llm = get_provider(provider, model)
            response = llm.complete([{"role": "user", "content": "ping"}], stop_check=cancel_event.is_set)
            elapsed_ms = int((time.monotonic() - started_at) * 1000)
            with _LOCK:
                if not response.content and response.finish_reason not in ("length", "max_tokens"):
                    logger.debug("test_llm_job: key=%s provider=%s model=%s empty response, finish_reason=%s", key, provider, model, response.finish_reason)
                    _finish(job, "error", f"Model returned an empty response (finish_reason: {response.finish_reason or 'none'}).", elapsed_ms=elapsed_ms)
                elif _finish(job, "ok", f"Model is available ({elapsed_ms}ms).", elapsed_ms=elapsed_ms):
                    logger.debug("test_llm_job: key=%s provider=%s model=%s ok elapsed_ms=%d", key, provider, model, elapsed_ms)
        except Exception as exc:
            with _LOCK:
                if cancel_event.is_set():
                    logger.debug("test_llm_job: key=%s provider=%s model=%s cancelled by operator", key, provider, model)
                    _finish(job, "cancelled", "Cancelled.")
                else:
                    logger.debug("test_llm_job: key=%s provider=%s model=%s failed: %s", key, provider, model, exc)
                    # An error that knows its own one-click fix (agent/opencode_cli.py) hands the
                    # UI an action id, so the failure message can carry its fix button right there.
                    _finish(
                        job, "error", _format_llm_error(exc, provider, model),
                        action=getattr(exc, "fix_action", None), action_label=getattr(exc, "fix_label", None),
                    )
        finally:
            if watchdog is not None:
                watchdog.cancel()

    thread = threading.Thread(target=run, daemon=True)
    with _LOCK:
        job["thread"] = thread
    if watchdog is not None:
        watchdog.daemon = True
        watchdog.start()
    thread.start()
    logger.debug("test_llm_job: started key=%s provider=%s model=%s timeout=%ss", key, provider, model, timeout_seconds)
    return {"status": "started", **test_status(key)}


def cancel_test(key: str) -> dict:
    """Ends THIS key's running test at once, as far as the operator can see: sets the cancel flag
    (_call_with_backoff polls it during backoff waits, so the worker thread stops at its next
    wait) AND marks the job cancelled immediately, rather than waiting for the worker to notice --
    a request already in flight can't be interrupted and used to keep the panel on "Testing..." for
    its whole remaining timeout after Cancel was clicked."""
    with _LOCK:
        job = _JOBS.get(key)
        if job is not None and job["state"] == "running":
            job["cancel_event"].set()
            _finish(job, "cancelled", "Cancelled.")
            logger.debug("test_llm_job: cancel requested key=%s provider=%s model=%s", key, job.get("provider"), job.get("model"))
    return test_status(key)


def _status_locked(key: str) -> dict:
    job = _JOBS.get(key)
    if job is None:
        return dict(_IDLE_STATUS)
    return {
        "running": job["state"] == "running",
        "provider": job["provider"],
        "model": job["model"],
        "state": job["state"],
        "attempt": job["attempt"],
        "total_attempts": job["total_attempts"],
        "wait_seconds": job["wait_seconds"],
        "message": job["message"],
        "elapsed_ms": job["elapsed_ms"],
        "action": job["action"],
        "action_label": job["action_label"],
    }


def test_status(key: str) -> dict:
    """Current state for the polling panel under this key -- never the raw thread/cancel_event
    handles, those stay internal to this module. A key with no job yet (or one long since pruned)
    reads as idle, same shape a freshly-started one would have before its first progress update."""
    with _LOCK:
        return _status_locked(key)
