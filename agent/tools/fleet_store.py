"""Fleet mode queue -- an ordered list of session_ids waiting for their turn to actually start, so
many projects can be created up front and worked through automatically within a global
concurrency cap (FLEET_MAX_CONCURRENT_SESSIONS) instead of every "Start" click launching its own
unbounded BackgroundTask immediately (main.py's own pre-existing start_session route has no cap at
all by itself -- fine for one operator clicking Start by hand, not for running a real portfolio of
programs unattended).

Global app data (Documents/ASRA/data, see projects/paths.py), not tied to any one project -- the
queue survives independently of which project folders exist, same convention as
allowed_targets.json/llm_settings.json.
"""
from __future__ import annotations

import json
import os

import psutil

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("API")

FLEET_QUEUE_PATH = resolve_global_app_dir() / "data" / "fleet_queue.json"


def _dynamic_concurrency_enabled() -> bool:
    return os.getenv("FLEET_DYNAMIC_CONCURRENCY_ENABLED", "false").strip().lower() == "true"


def max_concurrent_sessions() -> int:
    """The operator's own configured ceiling (FLEET_MAX_CONCURRENT_SESSIONS) is unchanged and
    still the DEFAULT -- dynamic throttling is opt-in (FLEET_DYNAMIC_CONCURRENCY_ENABLED=false by
    default) and, when on, can only ever narrow that ceiling further under real load, never widen
    it. This governs Fleet mode's own auto-launch queue only (pop_next_runnable_session below) --
    a session the operator starts by hand is never gated by this at all, so throttling here can
    never stop or slow down whatever the operator is actively doing right now, only how many
    ADDITIONAL unattended sessions the queue auto-starts on top of that.
    """
    static_cap = int(os.getenv("FLEET_MAX_CONCURRENT_SESSIONS", "3"))
    if not _dynamic_concurrency_enabled():
        return static_cap

    try:
        # interval=None (not e.g. 0.1) is the non-blocking form -- an instant comparison against
        # psutil's own last call, not a real sleep. Confirmed live this project already hit a
        # near-identical bug once (agent/tools/project_backup.py's own auto-backup loop pinning the
        # event loop in blocking I/O) -- this is called from the same kind of async poll loop
        # (main.py's _fleet_worker_loop), so a blocking call here would freeze the whole server the
        # same way, just every poll tick instead of once at startup.
        cpu_percent = psutil.cpu_percent(interval=None)
        memory_percent = psutil.virtual_memory().percent
    except OSError as exc:
        logger.debug("fleet_store: psutil read failed (%s) -- falling back to the static cap", exc)
        return static_cap

    cpu_threshold = float(os.getenv("FLEET_DYNAMIC_CPU_THRESHOLD", "80"))
    memory_threshold = float(os.getenv("FLEET_DYNAMIC_MEMORY_THRESHOLD", "85"))
    min_cap = max(1, int(os.getenv("FLEET_DYNAMIC_MIN_CONCURRENT_SESSIONS", "1")))

    if cpu_percent >= cpu_threshold or memory_percent >= memory_threshold:
        throttled = min(min_cap, static_cap)
        logger.debug("fleet_store: host under load (cpu=%.0f%% mem=%.0f%%) -- capping fleet concurrency %d -> %d",
                     cpu_percent, memory_percent, static_cap, throttled)
        return throttled
    return static_cap


def load_fleet_queue() -> list[str]:
    """Ordered (oldest-queued-first) list of session_ids -- empty/corrupt file treated as "nothing
    queued" rather than an error, same convention as every other JSON store in this project."""
    if not FLEET_QUEUE_PATH.exists():
        return []
    try:
        with FLEET_QUEUE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("fleet_store: unreadable (%s) -- treating as empty", exc)
        return []
    queue = data.get("queue") if isinstance(data, dict) else None
    return list(queue) if isinstance(queue, list) else []


def _write_fleet_queue(queue: list[str]) -> None:
    FLEET_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = FLEET_QUEUE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump({"queue": queue}, f, indent=2)
    os.replace(tmp_path, FLEET_QUEUE_PATH)


def enqueue_session(session_id: str) -> None:
    """Idempotent -- enqueueing an already-queued session_id a second time (a double click, a
    retried request) is a silent no-op, not a duplicate entry."""
    queue = load_fleet_queue()
    if session_id not in queue:
        queue.append(session_id)
        _write_fleet_queue(queue)
        logger.debug("fleet_store: enqueued session=%s (queue depth=%d)", session_id, len(queue))


def dequeue_session(session_id: str) -> bool:
    """Removes session_id from the queue if present (the operator cancelling a still-waiting
    entry, or the worker having just claimed it). Returns whether it was actually there, so a
    caller can tell "cancelled a real queued entry" from "nothing to cancel" (main.py's own
    dequeue route 404s on the latter instead of silently no-oping)."""
    queue = load_fleet_queue()
    if session_id not in queue:
        return False
    queue.remove(session_id)
    _write_fleet_queue(queue)
    logger.debug("fleet_store: dequeued session=%s (queue depth=%d)", session_id, len(queue))
    return True


def pop_next_runnable_session(active_count: int) -> str | None:
    """The fleet worker's own single decision point, called once per poll tick: with real spare
    capacity (active_count below max_concurrent_sessions()) AND at least one queued entry, pops
    and returns the OLDEST one (FIFO) -- otherwise None, a pure no-op that doesn't touch the file
    at all. A single read-modify-write (not a separate "peek" then "pop" pair) so two overlapping
    calls can never both claim the same queued entry.
    """
    if active_count >= max_concurrent_sessions():
        return None
    queue = load_fleet_queue()
    if not queue:
        return None
    session_id = queue.pop(0)
    _write_fleet_queue(queue)
    return session_id
