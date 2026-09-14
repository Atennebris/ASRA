"""Async task-tracking for Subagent delegation -- the LLM-conversation equivalent of
agent/tools/background_jobs.py's subprocess tracking, but for a genuinely concurrent
asyncio.Task (a subagent's own _run_llm_tool_loop conversation) instead of an OS subprocess.
Same "start now, check later, reap once at the right checkpoint" shape as background_jobs.py --
_RUNNING_SUBAGENT_TASKS mirrors its _RUNNING_PROCESSES, session["subagent_tasks"][task_id] mirrors
session["background_jobs"][job_id], and await_all_running_subagent_tasks/
reconcile_orphaned_subagent_tasks mirror await_all_running_jobs/reconcile_orphaned_background_jobs.

Deliberately import-safe with respect to agent/core.py: this module must never import from
agent.core (agent.core imports the WHOLE agent.tools package at its own module level to populate
TOOL_REGISTRY -- agent.tools -> agent.core would be a real circular import). The actual task-
SPAWNING logic (needs agent.core's RunContext/_run_llm_tool_loop/get_provider) therefore lives in
agent/core.py itself; this module only tracks/reaps/reconciles whatever asyncio.Task handle that
spawning function registers here via register_task().

Unlike background_jobs.py's subprocess.Popen (which needs manual PID/os.kill(pid, 0) tracking
across a process restart), an asyncio.Task simply ceases to exist the instant this Python process
does -- there is no orphan process to find and kill on the next startup, only a stale "running"
status left over from a run that never got to update it. reconcile_orphaned_subagent_tasks reflects
exactly that: no kill step, just an honest status correction.
"""
from __future__ import annotations

import asyncio
import json
import time

from agent.utils.logger import get_logger
from sessions.store import reload_merge_save

logger = get_logger("SUBAGENT")

# In-memory only, keyed by task_id -- the real asyncio.Task handle, needed to check/cancel a
# running delegation. Never persisted (not JSON-serializable, and only meaningful within this
# process's own lifetime) -- session["subagent_tasks"][task_id] holds the JSON-safe metadata
# (status/profile_name/deadline/...) that DOES survive a restart, used for orphan reconciliation.
_RUNNING_SUBAGENT_TASKS: dict[str, asyncio.Task] = {}

# The SAME list object agent/core.py's _run_llm_tool_loop mutates in place as the subagent's own
# conversation makes real tool calls (see _run_llm_tool_loop's external_trace param) -- kept here,
# separately from the task handle above, specifically so a task that gets cut off by its own
# asyncio.wait_for() deadline still has something real to report. Real incident this fixes: an
# auto-delegated 6-host overflow task hit its 900s deadline after making 29 genuinely successful
# tool calls (per host_health) and still ended up with result=None -- asyncio.wait_for() fully
# cancels the wrapped coroutine on timeout, so there is no way to recover its local state
# afterward; only a reference captured from OUTSIDE, before the timeout, survives the cancellation.
_LIVE_TRACES: dict[str, list[dict]] = {}

# Same lifecycle/reasoning as _LIVE_TRACES right above -- the one-element [total_seconds]
# accumulator object agent/core.py's _delegate_to_subagent_impl creates and threads into
# agent.llm_client's current_backoff_accumulator ContextVar for this task's whole lifetime,
# stored here so _synthesize_partial_result can read it after the task ends (cancelled or not)
# even though the coroutine's own local state is gone by then. See that ContextVar's own
# docstring (agent/llm_client.py) for the confirmed incident this exists to correctly attribute.
_LIVE_BACKOFF_SECONDS: dict[str, list[float]] = {}

_POLL_INTERVAL_SECONDS = 2.0
# How often await_all_running_subagent_tasks' own "still waiting" line repeats -- confirmed live:
# logging it on every single _POLL_INTERVAL_SECONDS tick produced 471 identical lines (~20% of one
# real session's whole debug.log) with zero new information between them, violating the project's
# own "don't log trivial things" rule. Still logs once immediately when the wait starts, so the
# very first entry into a real wait is never silently missing.
_WAIT_LOG_INTERVAL_SECONDS = 20.0


def register_task(
    session_id: str, session: dict, task_id: str, profile_name: str, task: asyncio.Task, deadline: float,
    trace: list[dict], triggered_by: str = "model", chat_thread_id: str | None = None,
    backoff_accumulator: list[float] | None = None,
) -> None:
    """Called by agent/core.py's own spawning function right after asyncio.create_task() --
    kept here (not returned to the caller to store itself) so every part of a task's lifetime
    (register/reap/kill/reconcile) goes through this one module's own bookkeeping, same as
    background_jobs.py's start_background_job populates _RUNNING_PROCESSES directly rather than
    handing the Popen object back to its own caller.

    triggered_by ("model" | "auto_overflow") records WHICH of the two independent paths into
    _delegate_to_subagent_impl actually created this task -- the model calling delegate_to_subagent
    on its own initiative, or agent/core.py's _auto_delegate_recon_overflow firing deterministically
    once enough discovered-but-not-literally-in-scope hosts pile up. Both paths funnel through the
    exact same implementation, so without this the UI (and the operator) has no way to tell which
    one actually happened for a given task -- confirmed real confusion, not a hypothetical.

    chat_thread_id (set only when agent/chat.py's own delegate_to_subagent call supplied
    "_chat_thread_id") records which CHAT thread this task's eventual result belongs to --
    agent/core.py's _on_subagent_task_done reads it back off this same entry to route delivery to
    that chat thread (agent/chat.py's deliver_subagent_result_to_chat) instead of the shared
    instruction queue only a live scan's own phase loop ever drains. None for every other caller
    (the model delegating during a real scan phase, or _auto_delegate_recon_overflow), which keeps
    today's queue-based delivery exactly as it was.

    trace is the same mutable list the subagent's own _run_llm_tool_loop appends to as it works --
    stored in _LIVE_TRACES (see that dict's own comment) so a timeout can still recover whatever
    real progress was made instead of losing it outright.
    """
    _RUNNING_SUBAGENT_TASKS[task_id] = task
    _LIVE_TRACES[task_id] = trace
    if backoff_accumulator is not None:
        _LIVE_BACKOFF_SECONDS[task_id] = backoff_accumulator
    tasks = session.setdefault("subagent_tasks", {})
    tasks[task_id] = {
        "profile_name": profile_name,
        "status": "running",
        "started_at": time.time(),
        "deadline": deadline,
        "result": None,
        "triggered_by": triggered_by,
        "chat_thread_id": chat_thread_id,
        # False until this task's eventual result is actually folded into a live conversation
        # (agent/core.py's _run_llm_tool_loop_impl draining it) or a chat thread (always an
        # immediate, durable write, so chat-routed tasks never need this flag at all). See
        # agent/core.py's _requeue_undelivered_subagent_results for the real incident this closes:
        # a task that outlives the main session (a crash, or the operator closing ASRA) finishes
        # into an in-memory queue nothing is left listening to -- the result already survives on
        # disk in this same entry's own "result" field, but nothing ever automatically revisits it.
        "delivered": False,
    }
    # Reload-merge-save, not a blind save_session(session_id, session) -- `session` here is the
    # same live object agent/core.py's _run_tool_with_retry injects into every tool call (including
    # ones made mid-chat-turn, where it can be a long-lived stale snapshot loaded well before a
    # concurrently-running phase/reverify pass's own later save). Same fix class as
    # agent/tools/background_jobs.py's own start_background_job -- only this one new task entry is
    # merged onto whatever's freshest on disk right now.
    reload_merge_save(session_id, lambda s: s.setdefault("subagent_tasks", {}).__setitem__(task_id, tasks[task_id]))
    logger.debug(
        "subagent_tasks: session=%s registered task=%s profile=%r triggered_by=%r",
        session_id, task_id, profile_name, triggered_by,
    )


# Mirrors agent/core.py's own _TOOL_RESULT_CHAR_LIMIT -- this module must stay import-safe with
# respect to agent.core (see this file's own module docstring), so the number is duplicated here
# rather than imported. A live tool result delivered mid-conversation is already capped to this
# size before it ever reaches a model (agent/core.py's own messages.append at the tool-result
# site); a trace entry salvaged after a subagent timeout deserves no less protection just because
# it's assembled after the fact instead of turn-by-turn.
_TRACE_RESULT_CHAR_LIMIT = 8000


def _capped_trace(trace: list[dict]) -> list[dict]:
    """Caps each trace entry's own "result" to _TRACE_RESULT_CHAR_LIMIT before it can ever reach
    session.json or a model's conversation. Real incident this fixes: a real bug-bounty session's
    auto-delegated overflow subagent timed out mid-sweep with two `nuclei` calls still in its trace
    whose raw stdout was 2.27MB/1.73MB each -- embedded verbatim, that alone pushed session.json to
    4.7MB and, once _push_subagent_result/_drain_subagent_results (agent/core.py) delivered this
    same dict into the MAIN phase's own conversation, blew every subsequent LLM request in that
    phase past 2 million tokens. Every configured provider (including a 1M-token-context one)
    rejected the request, and the whole session ended in status="failed" with the LLM API call
    itself as the visible symptom, not the real cause.

    A small entry (the overwhelming majority in practice -- http_request/whatweb/ssl_cert_info
    results are a couple KB at most) is returned completely unmodified, not even copied, so exact
    equality against the original trace still holds for anything that never needed capping.
    """
    capped: list[dict] = []
    for entry in trace:
        serialized_result = json.dumps(entry.get("result"))
        if len(serialized_result) <= _TRACE_RESULT_CHAR_LIMIT:
            capped.append(entry)
            continue
        capped.append({
            **entry,
            "result": serialized_result[:_TRACE_RESULT_CHAR_LIMIT] + f"... [truncated, {len(serialized_result)} chars total]",
        })
    return capped


def _synthesize_partial_result(
    task_id: str, cutoff_reason: str = "hit its time budget before calling report_subagent_result",
) -> dict | None:
    """Builds a best-effort result from whatever the subagent's own trace accumulated before it got
    cut off -- None (matching the old behavior) only when truly nothing was ever attempted. Pops
    _LIVE_TRACES so a long session's many delegations don't leak memory once each is reaped.

    cutoff_reason describes WHY the subagent stopped early -- callers each cut it off for a
    different reason (a time budget, an operator Stop, a server shutdown) and the summary should
    say which one actually happened, not always claim a timeout. Real, confirmed incident this
    parameterization fixes: kill_all_running_subagent_tasks and two "stopped" branches in _reap
    below used to discard the live trace outright (a bare _LIVE_TRACES.pop with no result built),
    so real work already done by a subagent the operator stopped mid-run (confirmed live: ~19
    minutes, 22-29 real tool calls across two tasks) vanished — result stayed None, and a resumed
    session had no way to know that work had already happened.
    """
    trace = _LIVE_TRACES.pop(task_id, None)
    backoff_seconds = _LIVE_BACKOFF_SECONDS.pop(task_id, [0.0])[0]
    if not trace:
        return None
    summary = (
        f"Subagent {cutoff_reason} -- {len(trace)} real "
        "tool call(s) were made before the cutoff (see tool_calls/partial_trace below for what was "
        "attempted and found). No final structured summary was produced, so treat this as real but "
        "incomplete progress, not a finished report."
    )
    # Only worth mentioning past a small floor (a couple of ordinary retries is normal and not
    # worth calling out) -- see current_backoff_accumulator's own docstring for the confirmed
    # incident (43% of one real task's whole budget) this attribution fixes.
    if backoff_seconds >= 30:
        summary += (
            f" Of that budget, ~{backoff_seconds:.0f}s were spent waiting on LLM provider retries/"
            "backoff (timeouts, rate limits, provider fallback switches) rather than idle or stuck "
            "subagent work -- treat this as provider flakiness eating into the budget, not evidence "
            "the subagent itself was slow or inefficient."
        )
    return {
        "summary": summary,
        "tool_calls": len(trace),
        "partial_trace": _capped_trace(trace),
    }


def _reap(session_id: str, session: dict, task_id: str, entry: dict) -> None:
    """Checks one still-"running" task for real completion, updating its status/result in place
    if so -- a no-op if it's genuinely still running. The task's own deadline is enforced by
    asyncio.wait_for() wrapping the coroutine at spawn time (agent/core.py), not by a manual
    deadline check here the way background_jobs.py's _reap must (subprocess.Popen has no built-in
    async timeout the way asyncio.wait_for already gives a coroutine) -- a timed-out task simply
    surfaces as an asyncio.TimeoutError on task.exception() once it's done, handled below like any
    other terminal outcome.
    """
    task = _RUNNING_SUBAGENT_TASKS.get(task_id)
    if task is None:
        return  # no in-memory handle in THIS process's lifetime -- orphan-recovery handles that case
    if not task.done():
        return  # still genuinely running

    _RUNNING_SUBAGENT_TASKS.pop(task_id, None)
    if task.cancelled():
        if time.time() < entry.get("deadline", 0):
            # Cancelled well ahead of its own asyncio.wait_for() deadline -- nothing in this
            # codebase calls .cancel() on a subagent task directly except
            # kill_all_running_subagent_tasks below (which sets status="killed" itself and pops
            # the task BEFORE this ever runs, so that path never reaches here). A cancellation
            # observed here, this early, can only be the whole process going down (Ctrl+C/server
            # shutdown) cancelling every outstanding asyncio.Task the way asyncio always does on
            # exit. Real, confirmed incident this fixes: a chat-triggered delegation was ~4.5
            # minutes into its 900s budget when the server was stopped -- this branch reported it
            # to the operator's chat thread as status="timeout" ("hit its time budget") on the next
            # startup, which is simply false and actively misleading about what actually happened.
            entry["status"] = "stopped"
            entry["result"] = _synthesize_partial_result(
                task_id, "was cut short — the ASRA server was shut down while its own conversation was still running",
            ) or {"summary": "Stopped — the ASRA server was shut down while this subagent's own conversation was still running."}
        else:
            entry["status"] = "timeout"
            entry["result"] = _synthesize_partial_result(task_id)
    else:
        exc = task.exception()
        if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
            entry["status"] = "timeout"
            entry["result"] = _synthesize_partial_result(task_id)
        elif exc is not None and type(exc).__name__ == "SessionStopRequested":
            # Matched by class NAME, not isinstance -- this module must stay import-safe with
            # respect to agent.core (see this file's own top docstring), so it can't import
            # SessionStopRequested directly to check for it properly. Real, confirmed incident
            # this fixes: a subagent's own _llm_complete call noticing the operator's Stop request
            # raises this with NO message (agent/core.py's SessionStopRequested is raised bare),
            # so the generic branch below recorded it as status="error", result={"error": ""} --
            # blank and uninformative, indistinguishable from a real crash to anyone reading
            # session.json. This is an expected, clean outcome, not a failure.
            entry["status"] = "stopped"
            entry["result"] = _synthesize_partial_result(
                task_id, "was cut short — the operator requested this session stop while its own conversation was still running",
            ) or {"summary": "Stopped — the operator requested this session stop while this subagent's own conversation was still running."}
        elif exc is not None:
            entry["status"] = "error"
            entry["result"] = _synthesize_partial_result(
                task_id, f"crashed ({exc}) before calling report_subagent_result",
            ) or {"error": str(exc)}
        else:
            parsed, trace = task.result()
            entry["status"] = "done"
            entry["result"] = parsed if parsed is not None else {
                "summary": "Subagent finished without calling report_subagent_result.",
                "tool_calls": len(trace),
            }
            _LIVE_TRACES.pop(task_id, None)
            _LIVE_BACKOFF_SECONDS.pop(task_id, None)
    # Reload-merge-save -- same fix/reasoning as register_task above.
    reload_merge_save(session_id, lambda s: s.setdefault("subagent_tasks", {}).__setitem__(task_id, entry))
    logger.debug("subagent_tasks: session=%s task=%s finished status=%s", session_id, task_id, entry["status"])


def check_subagent_task(session_id: str, session: dict, task_id: str) -> dict:
    """The explicit fallback poll tool (delegate_to_subagent's own primary delivery is the
    auto-push drain mechanism in agent/core.py, not this) -- also the only path that actually
    updates a finished task's status if, for whatever reason, the done-callback push never
    happened (still safe to call at any time; a no-op once already resolved)."""
    tasks = session.get("subagent_tasks", {})
    entry = tasks.get(task_id)
    if entry is None:
        return {"status": "error", "error": f"unknown subagent task {task_id!r}"}
    if entry.get("status") == "running":
        _reap(session_id, session, task_id, entry)
    return {"status": entry["status"], "result": entry.get("result")}


async def await_all_running_subagent_tasks(session_id: str, session: dict, stop_check=None) -> None:
    """Called at a phase-ending checkpoint that's about to produce a final verdict -- per the
    operator's own explicit rule, the main agent must never block on a subagent otherwise, only
    right before concluding a phase while one is still pending. Polls until every task resolves,
    bounded by each task's own asyncio.wait_for() deadline, so this can never hang indefinitely.

    stop_check: an optional zero-arg callable returning whether an operator Stop has been
    requested (agent/core.py passes get_stop_event(session_id).is_set — this module stays
    import-safe with respect to agent.core, see this file's own docstring, so it can't import
    that check directly). Real, confirmed incident this fixes: an operator's Stop click was
    completely ignored for up to the delegated subagent's own full timeout budget (900s by
    default; observed live at both ~65s and ~15 minutes in two separate real sessions) because
    this loop's own `await asyncio.sleep(...)` never once looked at the stop flag -- the intended
    safety net (kill_all_running_subagent_tasks, wired into agent/core.py's own Stop/cancel
    handling) never got a chance to run, since THIS function never returned to let that happen.
    Checked before every sleep, not just once at the top, so a Stop that lands mid-wait is
    noticed within one poll interval instead of only on the next call.
    """
    wait_started: float | None = None
    last_logged: float | None = None
    while True:
        tasks = session.get("subagent_tasks", {})
        running = [(tid, entry) for tid, entry in tasks.items() if entry.get("status") == "running"]
        if not running:
            if wait_started is not None:
                logger.debug("subagent_tasks: all still-running task(s) finished after %.0fs — phase can conclude", time.monotonic() - wait_started)
            return
        for tid, entry in running:
            _reap(session_id, session, tid, entry)
        if any(entry.get("status") == "running" for _, entry in running):
            if stop_check is not None and stop_check():
                logger.debug("subagent_tasks: stop requested while waiting for %d still-running task(s) — returning early, not waiting for them to finish naturally", len(running))
                return
            now = time.monotonic()
            if wait_started is None:
                wait_started = now
                last_logged = now
                logger.debug("subagent_tasks: waiting for %d still-running task(s) before this phase concludes", len(running))
            elif now - last_logged >= _WAIT_LOG_INTERVAL_SECONDS:
                last_logged = now
                logger.debug("subagent_tasks: still waiting for %d still-running task(s) (%.0fs elapsed)", len(running), now - wait_started)
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)


async def kill_all_running_subagent_tasks(session: dict) -> None:
    """Called when a session is stopped/cancelled -- the operator asked everything to stop, not
    just the main loop, so any subagent still working gets cancelled too. Awaits the real
    cancellation (not just requesting it) so this session's own shutdown doesn't report itself
    done while a subagent task is still mid-unwind."""
    cancelled: list[asyncio.Task] = []
    for task_id, entry in session.get("subagent_tasks", {}).items():
        if entry.get("status") != "running":
            continue
        task = _RUNNING_SUBAGENT_TASKS.pop(task_id, None)
        if task is not None and not task.done():
            task.cancel()
            cancelled.append(task)
        entry["status"] = "killed"
        entry["result"] = _synthesize_partial_result(
            task_id, "was killed — the operator stopped this session while its own conversation was still running",
        )
    if cancelled:
        await asyncio.gather(*cancelled, return_exceptions=True)


def reconcile_orphaned_subagent_tasks(session_id: str, data: dict) -> None:
    """Called from main.py's startup orphaned-session sweep, on the raw dict just loaded from
    disk -- this process has no in-memory handle for ANY task from a previous process's run (that
    registry is empty on a fresh process start). Unlike a background job's real OS subprocess, an
    asyncio.Task cannot outlive the process that created it -- there is nothing left alive to find
    or kill, just a stale "running" status to correct. Mutates data["subagent_tasks"] in place; the
    caller (already saving the session for its own status change) persists this too.
    """
    for task_id, entry in data.get("subagent_tasks", {}).items():
        if entry.get("status") != "running":
            continue
        entry["status"] = "orphaned"
        entry["result"] = None
        logger.debug("subagent_tasks: session=%s marked orphaned task=%s", session_id, task_id)
