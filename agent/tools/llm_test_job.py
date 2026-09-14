"""Settings/subagent "Test" buttons (test-llm) run as tracked background threads instead of a
blocking request.

Why: _call_with_backoff's retry schedule (agent/llm_client.py) can legitimately take up to ~60s of
silent waiting on a degraded/unreachable model (2s/4s/8s/16s/30s backoff between up to 6 attempts).
A plain blocking POST left the button showing "Testing..." for that entire stretch with zero
visibility into which retry attempt it was on and no way to cancel -- a real, confirmed operator
complaint, and one that has nothing to do with any particular model being flaky: it's the same
silent wait regardless of why the provider is slow to answer. Same "start now, poll status" shape
agent/tools/arsenal_install.py already established for a different slow operation, adapted for an
in-process Python call (a background thread, not a subprocess) rather than a subprocess+log file.

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
"""
from __future__ import annotations

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
}


def _is_running(key: str) -> bool:
    job = _JOBS.get(key)
    thread = job.get("thread") if job else None
    return thread is not None and thread.is_alive()


def _prune_finished_jobs() -> None:
    cutoff = time.monotonic() - _FINISHED_JOB_TTL_SECONDS
    stale = [k for k, job in _JOBS.items() if not _is_running(k) and job.get("finished_at", 0.0) < cutoff]
    for k in stale:
        del _JOBS[k]


def start_test(key: str, provider: str, model: str) -> dict:
    """Starts the test call in a background thread under this key. Returns
    status="already_running" (not a second thread) if THIS key already has one in flight, same
    guard arsenal_install.start_arsenal_install uses -- a different key runs fully independently,
    see this module's own docstring for why that's now the point."""
    with _LOCK:
        _prune_finished_jobs()
    if _is_running(key):
        logger.debug("test_llm_job: start requested for key=%s but it already has a test running", key)
        return {"status": "already_running", **test_status(key)}

    cancel_event = threading.Event()
    with _LOCK:
        _JOBS[key] = {
            "thread": None, "cancel_event": cancel_event, "provider": provider, "model": model,
            "state": "running", "attempt": None, "total_attempts": None,
            "wait_seconds": None, "message": None, "elapsed_ms": None, "finished_at": 0.0,
        }

    def on_progress(attempt: int, total_attempts: int, wait_seconds: float) -> None:
        with _LOCK:
            job = _JOBS.get(key)
            if job is None:
                return
            job["attempt"] = attempt
            job["total_attempts"] = total_attempts
            job["wait_seconds"] = wait_seconds

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
                job = _JOBS[key]
                if not response.content and response.finish_reason not in ("length", "max_tokens"):
                    logger.debug("test_llm_job: key=%s provider=%s model=%s empty response, finish_reason=%s", key, provider, model, response.finish_reason)
                    job["state"] = "error"
                    job["message"] = f"Model returned an empty response (finish_reason: {response.finish_reason or 'none'})."
                else:
                    logger.debug("test_llm_job: key=%s provider=%s model=%s ok elapsed_ms=%d", key, provider, model, elapsed_ms)
                    job["state"] = "ok"
                    job["message"] = f"Model is available ({elapsed_ms}ms)."
                job["elapsed_ms"] = elapsed_ms
                job["finished_at"] = time.monotonic()
        except Exception as exc:
            with _LOCK:
                job = _JOBS[key]
                if cancel_event.is_set():
                    logger.debug("test_llm_job: key=%s provider=%s model=%s cancelled by operator", key, provider, model)
                    job["state"] = "cancelled"
                    job["message"] = "Cancelled."
                else:
                    logger.debug("test_llm_job: key=%s provider=%s model=%s failed: %s", key, provider, model, exc)
                    job["state"] = "error"
                    job["message"] = _format_llm_error(exc, provider, model)
                job["finished_at"] = time.monotonic()

    thread = threading.Thread(target=run, daemon=True)
    with _LOCK:
        _JOBS[key]["thread"] = thread
    thread.start()
    logger.debug("test_llm_job: started key=%s provider=%s model=%s", key, provider, model)
    return {"status": "started", **test_status(key)}


def cancel_test(key: str) -> dict:
    """Sets the cancel flag _call_with_backoff's own stop_check polling already honors (the same
    interruptible-wait mechanism a session's Stop button uses) -- takes effect within one poll
    interval, not only between whole retry attempts. Only ever touches THIS key's own job."""
    job = _JOBS.get(key)
    if job is not None and job.get("cancel_event") is not None and _is_running(key):
        job["cancel_event"].set()
        logger.debug("test_llm_job: cancel requested key=%s provider=%s model=%s", key, job.get("provider"), job.get("model"))
    return test_status(key)


def test_status(key: str) -> dict:
    """Current state for the polling panel under this key -- never the raw thread/cancel_event
    handles, those stay internal to this module. A key with no job yet (or one long since pruned)
    reads as idle, same shape a freshly-started one would have before its first progress update."""
    with _LOCK:
        job = _JOBS.get(key)
        if job is None:
            return dict(_IDLE_STATUS)
        return {
            "running": _is_running(key),
            "provider": job["provider"],
            "model": job["model"],
            "state": job["state"],
            "attempt": job["attempt"],
            "total_attempts": job["total_attempts"],
            "wait_seconds": job["wait_seconds"],
            "message": job["message"],
            "elapsed_ms": job["elapsed_ms"],
        }
