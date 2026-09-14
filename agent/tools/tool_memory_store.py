"""Persistent, cross-session memory of which SCAN TOOL actually produced signal against a target
with a given tech/WAF fingerprint -- deliberately separate from agent/tools/playbook_store.py, which
remembers proven EXPLOITATION TECHNIQUES/payloads under the same kind of fingerprint. Playbook
answers "what payload worked here before"; this module answers "which scanner is worth reaching for
first here" -- a coarser, tool-selection-level question, not a technique-level one. Same on-disk
convention as playbook_store.py (atomic tmp-file + os.replace, corrupt/missing file treated as
"nothing stored yet") and the same resolve_global_app_dir() location, but its own file and its own
schema -- no import of/from playbook_store.py.

Shape: {fingerprint_key: [entry, ...]}. fingerprint_key is a caller-built opaque string (agent/
core.py's _current_target_fingerprint + the same _playbook_fingerprint_key-shaped JSON encoding) --
this module never inspects it.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

TOOL_MEMORY_STORE_PATH = resolve_global_app_dir() / "data" / "tool_memory" / "tool_outcomes.json"

_VALID_OUTCOMES = ("productive", "empty", "failed")

def _stale_days() -> int:
    """A productive tool not seen running again in this many days is flagged "may be outdated" by
    _tool_memory_task_addendum -- never suppressed outright, just a calibration hint. 0 disables."""
    return int(os.getenv("TOOL_MEMORY_STALE_DAYS", "180"))


def is_stale(entry: dict) -> bool:
    """A productive entry whose last run predates _stale_days() -- same "worth a fresh check" signal
    as playbook_store.is_stale, mirrored here for tool-level records. A "failed"/"empty" entry never
    goes stale (it's already framed as tentative, nothing to re-flag)."""
    stale_days = _stale_days()
    if stale_days <= 0 or entry.get("outcome") != "productive":
        return False
    ts = entry.get("last_run_at")
    if not ts:
        return False
    try:
        dt = datetime.fromisoformat(str(ts))
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0
    return age_days > stale_days


def load_tool_memory_store() -> dict:
    if not TOOL_MEMORY_STORE_PATH.exists():
        return {}
    try:
        with TOOL_MEMORY_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("tool_outcomes.json unreadable (%s) — treating as empty store", exc)
        return {}
    if not isinstance(data, dict):
        logger.debug("tool_outcomes.json does not contain an object — treating as empty store")
        return {}
    return {
        key: entries for key, entries in data.items()
        if isinstance(key, str) and isinstance(entries, list)
    }


def _write_tool_memory_store(store: dict) -> None:
    TOOL_MEMORY_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = TOOL_MEMORY_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, TOOL_MEMORY_STORE_PATH)


def record_tool_run(fingerprint_key: str, tool: str, outcome: str, session_id: str, error: str | None = None) -> str | None:
    """Appends a new entry for `tool` under `fingerprint_key`, or -- if one already exists for that
    exact tool under that same key -- bumps it in place instead of piling up a duplicate per rescan.
    Non-punitive by design, same philosophy as playbook_store.record_technique's dedup: a tool that
    has ever been productive here stays "has worked here" even if a later run against the same
    fingerprint comes back empty or fails -- outcome only ever upgrades toward "productive" via
    credit_tool_run below, never silently downgrades from one ordinary run.
    """
    if outcome not in _VALID_OUTCOMES:
        logger.debug("record_tool_run: ignoring invalid outcome=%r for tool=%r", outcome, tool)
        return None
    store = load_tool_memory_store()
    entries = store.setdefault(fingerprint_key, [])
    now = datetime.now(timezone.utc).isoformat()
    existing = next((e for e in entries if e.get("tool") == tool), None)
    if existing is not None:
        existing["times_run"] = int(existing.get("times_run", 0)) + 1
        existing["last_run_at"] = now
        if outcome == "failed":
            existing["last_error"] = error
        elif existing.get("outcome") != "productive":
            # Only overwrite a non-productive verdict -- a tool already known productive here keeps
            # that status regardless of one later empty/failed run.
            existing["outcome"] = outcome
            existing["last_error"] = error if outcome == "failed" else None
        source_sessions = existing.setdefault("source_session_ids", [])
        if session_id not in source_sessions:
            source_sessions.append(session_id)
        _write_tool_memory_store(store)
        logger.debug("record_tool_run: bumped existing entry under key=%r tool=%r (times_run=%d)", fingerprint_key, tool, existing["times_run"])
        return existing.get("id")
    entry = {
        "id": uuid.uuid4().hex[:12],
        "tool": tool,
        "outcome": outcome,
        "times_run": 1,
        "led_to_finding_count": 0,
        "last_run_at": now,
        "last_productive_at": None,
        "last_error": error if outcome == "failed" else None,
        "source_session_ids": [session_id],
    }
    entries.append(entry)
    _write_tool_memory_store(store)
    logger.debug("record_tool_run: new entry under key=%r tool=%r outcome=%r", fingerprint_key, tool, outcome)
    return entry["id"]


def credit_tool_run(fingerprint_key: str, tool_names: set[str]) -> None:
    """Called once a finding is genuinely recorded with real evidence -- upgrades every tool named in
    that finding's own tool_timeline (under this same fingerprint) to outcome="productive" and bumps
    led_to_finding_count/last_productive_at. Deferred-credit, same two-phase shape as playbook_store's
    injected_count/led_to_finding_count: a dispatch alone only ever gets recorded as "empty", real
    credit only ever comes from here.
    """
    if not tool_names:
        return
    store = load_tool_memory_store()
    entries = store.get(fingerprint_key) or []
    if not entries:
        return
    now = datetime.now(timezone.utc).isoformat()
    changed = False
    for entry in entries:
        if entry.get("tool") in tool_names:
            entry["outcome"] = "productive"
            entry["led_to_finding_count"] = int(entry.get("led_to_finding_count", 0)) + 1
            entry["last_productive_at"] = now
            changed = True
    if changed:
        _write_tool_memory_store(store)
        logger.debug("credit_tool_run: credited %d tool(s) under key=%r", len(tool_names), fingerprint_key)


def find_tool_history(fingerprint_key: str) -> list[dict]:
    """The read side -- whatever's stored for an EXACT fingerprint match. No fuzzy/semantic scoring
    like playbook_store's find_similar_techniques: tool selection is a coarser-grained question than
    technique matching, an exact tech/WAF fingerprint match is the right bar here (KISS)."""
    return load_tool_memory_store().get(fingerprint_key) or []
