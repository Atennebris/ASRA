"""Unattended repeat-scan schedules -- a per-project "re-run this engagement every N seconds"
record. A background worker (main.py's _scheduler_worker_loop) reads this to decide which projects
are due, then prepares an in-place pass (reusing the prior recon, not re-scanning from scratch) and
hands it to the SAME fleet queue every manual Start already uses, so repeat runs respect the one
global concurrency cap instead of spawning a second parallel runner.

Global app data (Documents/ASRA/data, see projects/paths.py), not inside any project folder -- same
convention as fleet_queue.json/allowed_targets.json, so a schedule survives independently and is
never committed to the repo.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("SCHEDULER")

SCHEDULE_STORE_PATH = resolve_global_app_dir() / "data" / "schedules.json"


def min_interval_seconds() -> int:
    """Floor on how often a project may auto-repeat -- a guard against an accidental too-aggressive
    cadence hammering a real bug-bounty target. Operator-overridable, but never below a hard 60s."""
    return max(60, int(os.getenv("SCHEDULER_MIN_INTERVAL_SECONDS", "300")))


def load_schedules() -> dict[str, dict]:
    """session_id -> schedule dict. Empty/corrupt file treated as "no schedules", same convention as
    every other JSON store here."""
    if not SCHEDULE_STORE_PATH.exists():
        return {}
    try:
        with SCHEDULE_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("schedule_store: unreadable (%s) -- treating as empty", exc)
        return {}
    return data if isinstance(data, dict) else {}


def _write_schedules(schedules: dict[str, dict]) -> None:
    SCHEDULE_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SCHEDULE_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(schedules, f, indent=2)
    os.replace(tmp_path, SCHEDULE_STORE_PATH)


def get_schedule(session_id: str) -> dict | None:
    return load_schedules().get(session_id)


def set_schedule(session_id: str, interval_seconds: int, enabled: bool = True) -> dict:
    """Create or update a project's schedule. interval_seconds is floored at min_interval_seconds().
    On first creation last_triggered_at is stamped to now, so the first auto-run fires one full
    interval AFTER the operator set it up -- never immediately, which would surprise someone who
    just finished a scan and only wanted the NEXT one later. An update keeps the existing
    last_triggered_at so changing the interval doesn't reset the clock."""
    interval = max(min_interval_seconds(), int(interval_seconds))
    now_iso = datetime.now(timezone.utc).isoformat()
    schedules = load_schedules()
    existing = schedules.get(session_id)
    if existing:
        existing["interval_seconds"] = interval
        existing["enabled"] = bool(enabled)
        existing["updated_at"] = now_iso
        schedule = existing
    else:
        schedule = {
            "enabled": bool(enabled),
            "interval_seconds": interval,
            "last_triggered_at": now_iso,
            "created_at": now_iso,
            "updated_at": now_iso,
        }
        schedules[session_id] = schedule
    _write_schedules(schedules)
    logger.debug("schedule_store: set session=%s interval=%ds enabled=%s", session_id, interval, enabled)
    return schedule


def set_enabled(session_id: str, enabled: bool) -> bool:
    """Pause/resume without losing the interval. Returns whether a schedule existed to toggle."""
    schedules = load_schedules()
    schedule = schedules.get(session_id)
    if schedule is None:
        return False
    schedule["enabled"] = bool(enabled)
    schedule["updated_at"] = datetime.now(timezone.utc).isoformat()
    _write_schedules(schedules)
    logger.debug("schedule_store: session=%s enabled=%s", session_id, enabled)
    return True


def delete_schedule(session_id: str) -> bool:
    """Remove a schedule entirely. Returns whether one was actually there (the route 404s otherwise,
    same as fleet dequeue)."""
    schedules = load_schedules()
    if session_id not in schedules:
        return False
    schedules.pop(session_id)
    _write_schedules(schedules)
    logger.debug("schedule_store: deleted session=%s", session_id)
    return True


def mark_triggered(session_id: str, when: datetime | None = None) -> None:
    """Record that the worker just launched a run for this project -- resets its due clock. A no-op
    if the schedule was deleted between the due check and here (a concurrent operator delete)."""
    schedules = load_schedules()
    schedule = schedules.get(session_id)
    if schedule is None:
        return
    schedule["last_triggered_at"] = (when or datetime.now(timezone.utc)).isoformat()
    _write_schedules(schedules)


def is_due(schedule: dict, now: datetime) -> bool:
    """Pure/side-effect-free so the worker's decision is unit-testable without any file or clock
    fixture. Due when enabled AND at least interval_seconds have elapsed since the last trigger. A
    missing/garbled last_triggered_at is treated as "due now" rather than silently never firing."""
    if not schedule.get("enabled"):
        return False
    interval = schedule.get("interval_seconds")
    if not interval:
        return False
    last = schedule.get("last_triggered_at")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
    except (ValueError, TypeError):
        return True
    return (now - last_dt).total_seconds() >= interval


def due_session_ids(now: datetime | None = None) -> list[str]:
    """Every session_id whose schedule is enabled and due right now -- the worker's one read."""
    moment = now or datetime.now(timezone.utc)
    return [sid for sid, schedule in load_schedules().items() if is_due(schedule, moment)]
