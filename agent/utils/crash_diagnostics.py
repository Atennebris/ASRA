"""Unclean-shutdown detection: a periodic heartbeat file + a startup check, so an abrupt stop
(killed from outside this Python process entirely -- a WSL2 VM restart, an OOM, a forced kill)
leaves hard evidence of the last known state behind instead of debug.log simply going silent with
no explanation at all.

Real incident this exists because of: ASRA's own backend (running inside WSL2 on Windows -- see
this project's own runtime-architecture notes) went down mid-session with zero error/exception
logged anywhere. debug.log's last line was main.py's own GRACEFUL lifespan-shutdown cleanup
(agent/tools/browser_manager.py's shutdown()), immediately followed by total silence, while the
operator was mid-way through an unrelated UI action (importing a bug-bounty program page -- a
headless-Chromium navigate followed by a ~26s LLM call). The underlying WSL2 distro itself had been
torn down and rebuilt at that exact second (confirmed after the fact via `wsl.exe -- last reboot` /
`journalctl --list-boots`, matched to the same timestamp) -- something outside this Python process
entirely (not ASRA's own quit path, which never runs a wide `wsl --shutdown`; see
desktop/src-tauri/src/main.rs's stop_backend) told the whole WSL instance to shut down, delivering
SIGTERM to every process inside it including uvicorn -- which is exactly why the lifespan shutdown
hook got to run cleanly before the process actually died. This module can't see WHO issued that
shutdown (that decision happens on the Windows host, outside this process), but it CAN now tell
apart "a graceful signal-driven stop happened" from "the process vanished with no warning at all"
on the very next startup, and it preserves exactly what was active in the moments right before --
which is what was missing while diagnosing this incident.
"""
import json
import os
import time
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("API")

_HEARTBEAT_FILENAME = "last_run_state.json"

# How often the background heartbeat loop (main.py's _lifespan) refreshes the file -- deliberately
# an env var, not hardcoded (this project's own "no hardcoding" rule): a slower interval costs
# less disk I/O but widens the gap between "last known alive" and the actual moment of death.
HEARTBEAT_INTERVAL_SECONDS = float(os.getenv("ASRA_HEARTBEAT_INTERVAL_SECONDS", "5"))

# Mirrors main.py's own _ORPHANABLE_STATUSES. Duplicated here (not imported) on purpose: main.py
# imports THIS module, so importing back from main.py would be a circular import for the sake of
# two literal strings that change together anyway (see sessions/store.py's own status vocabulary).
_ACTIVE_SESSION_STATUSES = ("processing", "awaiting_approval")

# Process-start timestamp, captured at import time (this module is imported once, early, by
# main.py) -- close enough to the real process start for an "uptime_seconds" figure that's only
# ever read for human diagnosis, never for anything timing-sensitive.
_PROCESS_STARTED_AT = time.time()

_LOG_TAIL_LINES = 25


def _heartbeat_path() -> Path:
    return resolve_global_app_dir() / _HEARTBEAT_FILENAME


def _tail_lines(path: Path, count: int) -> list[str]:
    """Best-effort last N lines of a (potentially large) text file, without reading the whole
    thing into memory -- debug.log can grow into the tens of MB over a long session."""
    try:
        with path.open("rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            block = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= count:
                read_size = min(block, size)
                size -= read_size
                f.seek(size)
                data = f.read(read_size) + data
            return data.decode("utf-8", errors="replace").splitlines()[-count:]
    except OSError:
        return []


def _memory_snapshot() -> dict:
    """Current process RSS + system-wide available memory, in MB -- psutil is already a hard
    dependency (requirements.txt). Best-effort: a sandboxed/restricted environment where psutil
    can't read this is not a reason to break the heartbeat itself."""
    try:
        import psutil

        process = psutil.Process()
        rss_mb = round(process.memory_info().rss / (1024 * 1024), 1)
        vm = psutil.virtual_memory()
        return {
            "process_rss_mb": rss_mb,
            "system_available_mb": round(vm.available / (1024 * 1024), 1),
            "system_percent_used": vm.percent,
        }
    except Exception:
        return {}


def _active_sessions_snapshot() -> list[dict]:
    """Which session(s) (if any) were mid-run at this moment -- the cross-cutting picture the
    per-session debug.log/session.json can't give on its own: THAT it died, not which others died
    alongside it when the whole server went down at once."""
    try:
        from sessions.store import get_session_folder, list_session_summaries

        out = []
        for summary in list_session_summaries():
            if summary["status"] not in _ACTIVE_SESSION_STATUSES:
                continue
            session_id = summary["session_id"]
            folder = get_session_folder(session_id)
            last_lines: list[str] = []
            if folder:
                project_log = Path(folder) / "debug.log"
                if project_log.exists():
                    last_lines = _tail_lines(project_log, 10)
            out.append({
                "session_id": session_id,
                "status": summary["status"],
                "last_log_lines": last_lines,
            })
        return out
    except Exception:
        return []


def _gather_state(clean_shutdown: bool, shutdown_reason: str | None) -> dict:
    global_log = resolve_global_app_dir() / "debug.log"
    return {
        "written_at": time.time(),
        "pid": os.getpid(),
        "uptime_seconds": round(time.time() - _PROCESS_STARTED_AT, 1),
        "clean_shutdown": clean_shutdown,
        "shutdown_reason": shutdown_reason,
        "memory": _memory_snapshot(),
        "active_sessions": _active_sessions_snapshot(),
        "global_log_tail": _tail_lines(global_log, _LOG_TAIL_LINES) if global_log.exists() else [],
    }


def write_heartbeat(clean_shutdown: bool = False, shutdown_reason: str | None = None) -> None:
    """Best-effort -- logging/diagnostics must never crash the server, same spirit as
    agent/utils/debug.py's own file-handler error handling. Called every
    HEARTBEAT_INTERVAL_SECONDS while the server runs, and once more with clean_shutdown=True as
    the very first step of the lifespan shutdown sequence (main.py's _lifespan)."""
    try:
        path = _heartbeat_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_gather_state(clean_shutdown, shutdown_reason), indent=2), encoding="utf-8")
    except OSError:
        logger.debug("crash_diagnostics: could not write heartbeat file -- ignored", exc_info=True)


def check_previous_run_and_log() -> None:
    """Called once at startup, BEFORE this run's own first write_heartbeat() overwrites the file
    left by whatever ran last. Silent (DEBUG only) when the previous run shut down cleanly or no
    heartbeat file exists yet (first-ever run); a loud WARNING, with everything that was captured,
    when it looks like the previous run just vanished."""
    path = _heartbeat_path()
    if not path.exists():
        return
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.debug("crash_diagnostics: previous heartbeat file unreadable -- ignored", exc_info=True)
        return

    age_seconds = round(time.time() - previous.get("written_at", 0), 1)
    if previous.get("clean_shutdown"):
        logger.debug(
            "crash_diagnostics: previous run shut down cleanly (%.0fs ago, reason=%s, uptime=%ss)",
            age_seconds, previous.get("shutdown_reason"), previous.get("uptime_seconds"),
        )
        return

    logger.warning(
        "crash_diagnostics: previous ASRA run did NOT shut down cleanly -- last heartbeat was %.0fs ago "
        "(pid=%s, uptime=%ss, memory=%s, active_sessions=%s). This process never got to run its own "
        "graceful shutdown (agent/tools/browser_manager.py's shutdown() etc. never logged) -- it was "
        "killed from outside Python entirely (the host OS, WSL2 itself, or an OOM/forced kill), not a "
        "bug inside a request handler. Last lines the global debug.log saw before it stopped: %s",
        age_seconds, previous.get("pid"), previous.get("uptime_seconds"), previous.get("memory"),
        [s.get("session_id") for s in previous.get("active_sessions", [])],
        previous.get("global_log_tail"),
    )
    for session in previous.get("active_sessions", []):
        if session.get("last_log_lines"):
            logger.warning(
                "crash_diagnostics: session=%s was mid-run when the previous process stopped -- its own "
                "last log lines: %s",
                session.get("session_id"), session.get("last_log_lines"),
            )


async def heartbeat_loop() -> None:
    """Runs for the server's whole lifetime (started in main.py's _lifespan, cancelled on
    shutdown) -- same fire-and-forget polling shape as that file's own _fleet_worker_loop."""
    import asyncio

    while True:
        try:
            await asyncio.to_thread(write_heartbeat, False, None)
        except Exception:
            logger.debug("crash_diagnostics: heartbeat tick failed", exc_info=True)
        await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)


def log_memory_snapshot(category_logger, label: str) -> None:
    """Small DEBUG breadcrumb for a resource-heavy stretch (a headless-Chromium launch/navigate, an
    LLM request) -- cheap enough to call liberally, and exactly the evidence that was missing while
    diagnosing the real incident this module's own docstring describes: next time something dies
    right after one of these, the numbers are already on record instead of having to guess at an
    OOM after the fact."""
    snapshot = _memory_snapshot()
    if snapshot:
        category_logger.debug("%s: process_rss_mb=%s system_available_mb=%s system_percent_used=%s",
                               label, snapshot.get("process_rss_mb"), snapshot.get("system_available_mb"),
                               snapshot.get("system_percent_used"))
