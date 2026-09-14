"""Fire-and-check background execution for slow (many-minute) subprocess tools that shouldn't
block the main agent loop -- e.g. a Hydra brute-force run or a CSRF-aware web-login brute-force.

Same "start now, check later" shape as native.py's oob_generate/oob_poll, but a genuinely
different underlying problem: interactsh's state lives on a remote server (nothing local to keep
alive between generate and poll), while a job here IS a real, long-running local subprocess that
must be tracked for its entire lifetime -- Stop has to actually kill it, and a server crash/
restart must never let it keep running as an orphan nobody can see. That second case is the exact
"don't leave background processes running" risk, applied for
real this time: a live brute-force run against a real target, not a coding-session shell -- a
child process is not guaranteed to die just because its parent (this app) did, so an orphaned
"running" job's real OS process can keep hammering a real target indefinitely unless something
explicitly checks and kills it.

Built on plain subprocess.Popen (non-blocking start, poll-based completion check), not
asyncio.create_subprocess_exec -- every native tool function in this registry (agent/tools/
native.py) is a plain sync function, dispatched via asyncio.to_thread from a worker thread with no
event loop of its own to hang an async subprocess/watcher-task off of. Popen.poll() from a plain
sync check call sidesteps that mismatch entirely: there is no separate "watcher" coroutine, a
job's completion is only ever noticed the next time something actually calls check_background_job
(or await_all_running_jobs, right before a session finishes) -- deliberately simple over building
cross-thread event-loop bridging that a plain sync tool function has no clean way to use anyway.
"""
from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir
from sessions.store import get_session_folder, reload_merge_save

logger = get_logger("TOOLS")

# In-memory only, keyed by job_id -- the real subprocess.Popen handle, needed to poll/terminate a
# running job. Never persisted (not JSON-serializable, and only meaningful within this process's
# own lifetime) -- session["background_jobs"][job_id] holds the JSON-safe metadata (status/pid/
# log_path/deadline/...) that DOES survive a restart, used for orphan-recovery reconciliation.
_RUNNING_PROCESSES: dict[str, subprocess.Popen] = {}
# parse_result closures aren't JSON-serializable either, and only make sense within this same
# process's own lifetime -- keyed by job_id alongside the Popen handle above.
_PARSERS: dict[str, Callable[[Path], dict]] = {}

_POLL_INTERVAL_SECONDS = 2.0


def _job_dir(session_id: str) -> Path:
    # Same "active session's own project folder, else the global app dir" fallback convention
    # agent/utils/debug.py's dump_large_payload already uses -- a bare Path(".") fallback here
    # would write into whatever the server process's current working directory happens to be
    # (confirmed live: it landed in this repo's own root during ad-hoc manual testing), which is
    # exactly the kind of unpredictable, potentially-repo-visible location this project's own
    # "new files/folders — check public-safety" rule exists to catch before it becomes a real leak.
    folder = get_session_folder(session_id)
    base = Path(folder) if folder else resolve_global_app_dir()
    job_dir = base / "background-jobs"
    job_dir.mkdir(parents=True, exist_ok=True)
    return job_dir


def start_background_job(
    session_id: str,
    session: dict,
    tool: str,
    setup: Callable[[str, Path], tuple[list[str], Callable[[Path], dict]]],
    max_concurrent: int,
    timeout_seconds: int,
    extra_metadata: dict | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict:
    """Spawns a real background subprocess, tracked in session["background_jobs"]. Returns
    immediately with {"status": "ok", "job_id": ...} -- the caller must poll
    check_background_job(...) later. {"status": "skipped", ...} instead if this session already
    has max_concurrent jobs running (a real cap, not a suggestion -- without it a model could fire
    far more concurrent brute-force runs than reasonable just because nothing stopped it from
    calling this repeatedly).

    setup(job_id, job_dir) -> (argv, parse_result) rather than a plain pre-built argv list -- some
    tools need a job-specific file path baked into their own command (e.g. Hydra's own
    "-o <file> -b json" structured-result flag, confirmed live to need a REAL file, not a pipe --
    same seekability lesson as Arjun's -oJ), which only exists once this job actually has an id and
    a directory. parse_result is created in the same closure so it already knows exactly which
    file(s) (the job's own stdout log, passed to it; Hydra's separate -o result file, captured from
    job_dir/job_id at setup time) to read once the process finishes.

    extra_metadata is merged into the stored job dict as-is (e.g. {"target": ...}) -- same "reserved
    now so a later feature can attach without the shape changing" spirit as the "profile" field
    below. agent/core.py's asset-graph tracking (_update_asset_graph) reads it back at
    background_job_check time to recover which host a web_login_bruteforce job's own credential
    results (which carry no host field of their own, unlike hydra's) were actually found on.

    extra_env merges on TOP of this server process's own inherited environment (opt-in per call,
    never a wholesale replacement) -- e.g. agent/tools/native.py's afl_fuzz_start needs
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 to run at all under WSL2's own default
    /proc/sys/kernel/core_pattern (confirmed live: afl-fuzz refuses to start otherwise).
    """
    jobs = session.setdefault("background_jobs", {})
    running_count = sum(1 for j in jobs.values() if j.get("status") == "running")
    if running_count >= max_concurrent:
        return {
            "status": "skipped",
            "reason": (
                f"{running_count} background job(s) already running for this session "
                f"(max {max_concurrent}) — check on one with its *_check tool before starting another"
            ),
        }

    job_id = uuid.uuid4().hex[:12]
    job_dir = _job_dir(session_id)
    log_path = job_dir / f"{job_id}.log"
    command, parse_result = setup(job_id, job_dir)

    # cwd=job_dir: tools like Hydra write their own state file (hydra.restore) into their CURRENT
    # working directory whenever the run is interrupted (Stop / timeout kill / server shutdown) so
    # it can be resumed with hydra -R later. Without this the subprocess inherits the server
    # process's CWD (the repo root when launched from run.bat) and that snapshot of the run's real
    # target/credentials lands in a repo-visible spot instead of the session's own gitignored
    # folder -- the result paths are all absolute, so changing the child's CWD affects nothing else.
    # stdin=DEVNULL -- see agent/tools/runner.py's _run_tracked for the real incident (a
    # subprocess inheriting this server's own real console stdin instead of getting a fast EOF,
    # hanging on a tool's own interactive prompt for most of its timeout budget) this closes
    # across every subprocess dispatch in this project, not just the one it was first found on.
    # extra_env merges ON TOP of this server process's own inherited environment (never replaces
    # it wholesale) -- e.g. afl_fuzz_start's own AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1, needed
    # because WSL2's own /proc/sys/kernel/core_pattern pipes crash notifications to an external
    # utility by default, which afl-fuzz refuses to start under at all otherwise (confirmed live:
    # "PROGRAM ABORT: Pipe at the beginning of 'core_pattern'") -- a real environment quirk, not
    # something safe to silently work around by rewriting a system-wide kernel setting.
    env = {**os.environ, **extra_env} if extra_env else None
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(command, cwd=job_dir, stdout=log_file, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)

    _RUNNING_PROCESSES[job_id] = process
    _PARSERS[job_id] = parse_result
    jobs[job_id] = {
        "tool": tool,
        "status": "running",
        "pid": process.pid,
        "log_path": str(log_path),
        "started_at": time.time(),
        "deadline": time.time() + timeout_seconds,
        "result": None,
        # Reserved for a future sub-agent-profile mechanism (per-job instructions/tool allowlist,
        # configurable in its own UI tab) -- always None today. Kept here now so that feature can
        # attach to an existing job without this whole shape needing to change later.
        "profile": None,
        **(extra_metadata or {}),
    }
    # Reload-merge-save, not a blind save_session(session_id, session) -- `session` here is the
    # same live object agent/core.py's _run_tool_with_retry injects into every tool call (including
    # ones made mid-chat-turn, where it can be a long-lived stale snapshot loaded well before a
    # concurrently-running phase/reverify pass's own later save). Same fix class as agent/core.py's
    # _track_host_health/_update_asset_graph/_record_missing_capability -- only this one new job
    # entry is merged onto whatever's freshest on disk right now.
    reload_merge_save(session_id, lambda s: s.setdefault("background_jobs", {}).__setitem__(job_id, jobs[job_id]))
    logger.debug("background_jobs: session=%s started job=%s tool=%s pid=%s", session_id, job_id, tool, process.pid)
    return {"status": "ok", "job_id": job_id}


def _reap(session_id: str, session: dict, job_id: str, job: dict) -> None:
    """Checks one still-"running" job for real completion/timeout, updating its status/result in
    place if so -- a no-op if it's genuinely still running and hasn't hit its own deadline yet.
    """
    process = _RUNNING_PROCESSES.get(job_id)
    if process is None:
        return  # no in-memory handle in THIS process's lifetime -- orphan-recovery handles that case

    returncode = process.poll()
    if returncode is None:
        if time.time() >= job.get("deadline", float("inf")):
            process.kill()
            process.wait()
            job["status"] = "timeout"
            _RUNNING_PROCESSES.pop(job_id, None)
            _PARSERS.pop(job_id, None)
            # Reload-merge-save -- same fix/reasoning as start_background_job above.
            reload_merge_save(session_id, lambda s: s.setdefault("background_jobs", {}).__setitem__(job_id, job))
            logger.debug("background_jobs: session=%s job=%s hit its own timeout", session_id, job_id)
        return  # still genuinely running

    parse_result = _PARSERS.pop(job_id, None)
    _RUNNING_PROCESSES.pop(job_id, None)
    log_path = Path(job["log_path"])
    if returncode == 0 and parse_result is not None:
        try:
            job["result"] = parse_result(log_path)
            job["status"] = "ok"
        except Exception as exc:
            job["status"] = "error"
            job["result"] = {"error": f"failed to parse job output: {exc}"}
    else:
        job["status"] = "error"
        job["result"] = {"exit_code": returncode, "log_path": str(log_path)}
    # Reload-merge-save -- same fix/reasoning as start_background_job above.
    reload_merge_save(session_id, lambda s: s.setdefault("background_jobs", {}).__setitem__(job_id, job))
    logger.debug("background_jobs: session=%s job=%s finished status=%s", session_id, job_id, job["status"])


def check_background_job(session_id: str, session: dict, job_id: str) -> dict:
    jobs = session.get("background_jobs", {})
    job = jobs.get(job_id)
    if job is None:
        # Real, confirmed incident this fixes: a model guessed a wrong/hallucinated job_id (or one
        # from a tool that doesn't even run in the background), got this error with no list of what
        # job_id's actually exist, and its single available correction retry guessed wrong a second
        # time too -- a doomed second blind guess. Listing the real keys gives it something to
        # actually pick from instead.
        known = sorted(jobs.keys())
        hint = f" -- known job_id(s) for this session: {known}" if known else " -- this session has no background jobs at all right now"
        return {"status": "error", "error": f"unknown background job {job_id!r}{hint}"}
    if job.get("status") == "running":
        _reap(session_id, session, job_id, job)
    return {"status": job["status"], "result": job.get("result")}


async def await_all_running_jobs(session_id: str, session: dict) -> None:
    """Called right before a session is marked "completed" -- a scan must never report itself
    done while a real background attack it started is still actually running against the target.
    Polls until every job resolves, bounded by each job's own deadline (already enforced inside
    _reap), so this can never hang the session finish indefinitely.
    """
    while True:
        jobs = session.get("background_jobs", {})
        running = [(job_id, job) for job_id, job in jobs.items() if job.get("status") == "running"]
        if not running:
            return
        for job_id, job in running:
            _reap(session_id, session, job_id, job)
        if any(job.get("status") == "running" for _, job in running):
            logger.debug("background_jobs: waiting for %d still-running job(s) before finishing the session", len(running))
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)


def kill_background_job(job_id: str, job: dict) -> None:
    """Best-effort real kill of a still-running job's subprocess -- called from Stop handling.
    Safe to call on an already-finished/unknown job (no-op). Only updates the given job's own
    dict in place (part of session["background_jobs"]); the caller is responsible for
    save_session() afterward, same as every other in-place session mutation in this project.
    """
    process = _RUNNING_PROCESSES.get(job_id)
    if process is not None and process.poll() is None:
        try:
            process.terminate()
            # terminate() alone leaves a zombie entry in the process table until something reaps
            # its exit status -- confirmed live: os.kill(pid, 0) still reports the PID as alive
            # for as long as that zombie lingers, even though the real work has already stopped.
            # Bounded wait (kill -9 as a last resort) so a process that ignores SIGTERM can't hang
            # this call indefinitely.
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        except ProcessLookupError:
            pass
    _RUNNING_PROCESSES.pop(job_id, None)
    _PARSERS.pop(job_id, None)
    if job.get("status") == "running":
        job["status"] = "killed"


def kill_all_running_jobs(session: dict) -> None:
    """Called when a session is stopped/cancelled -- kills every job this session's own
    background_jobs registry still shows as running, not just whichever one happened to be
    checked most recently."""
    for job_id, job in session.get("background_jobs", {}).items():
        if job.get("status") == "running":
            kill_background_job(job_id, job)


def reconcile_orphaned_background_jobs(session_id: str, data: dict) -> None:
    """Called from main.py's startup orphaned-session sweep, on the raw dict just loaded from
    disk -- this process has no in-memory handle for ANY job from a previous process's run (that
    registry is empty on a fresh process start), so a job still marked "running" here survived its
    own parent Python process dying. Its real OS process may or may not still be alive (nothing
    guarantees a child dies just because its parent did) -- check the recorded PID directly and
    kill it for real if so, rather than just rewriting the status and leaving a live brute-force
    run against a real target completely untracked. Mutates data["background_jobs"] in place; the
    caller (already saving the session for its own status change) persists this too.
    """
    for job_id, job in data.get("background_jobs", {}).items():
        if job.get("status") != "running":
            continue
        pid = job.get("pid")
        if pid:
            try:
                os.kill(pid, 0)  # existence check only, sends no real signal
            except OSError:
                pass  # already dead, nothing to kill
            else:
                try:
                    os.kill(pid, signal.SIGTERM)
                    logger.debug("background_jobs: session=%s killed orphaned job=%s pid=%s", session_id, job_id, pid)
                except OSError:
                    pass
        job["status"] = "interrupted"
