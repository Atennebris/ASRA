"""File-based session storage: create_session/load_session/save_session, atomic writes.

Every new session gets its own real, user-visible project folder (see projects/paths.py) instead
of being just another anonymous file in data/sessions/ — the same "one project = one folder"
model as the desktop reference this UI is modeled after. A lightweight index
(data/sessions_index.json) maps session_id -> that folder so lookups don't need to search the
whole Documents tree. Sessions created before this existed have no index entry; _session_path()
falls back to the legacy flat data/sessions/<id>.json for them, untouched.
"""
from __future__ import annotations

import copy
import json
import os
import re
import secrets
import shutil
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from agent.utils.logger import get_logger
from projects import icons as project_icons
from projects.paths import resolve_global_app_dir, resolve_projects_base_dir

logger = get_logger("SESSION")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder --
# same reasoning as every other store under agent/tools/*_store.py.
SESSIONS_DIR = resolve_global_app_dir() / "data" / "sessions"
INDEX_PATH = resolve_global_app_dir() / "data" / "sessions_index.json"
# A small, separate cache -- session_id -> the handful of cheap fields list_session_summaries()
# actually needs (name/target/status/findings_count/created_at/resumable_from/phase/
# rescanned_from_name), kept in sync by save_session(). Deliberately its own file, not folded into
# INDEX_PATH's existing {session_id: folder} shape -- that shape is read all over this module
# (_session_path, _create_project_folder, get_session_folder, delete_session) as a bare string, and
# changing it to a richer value would touch every one of those for no benefit to them.
SUMMARY_INDEX_PATH = resolve_global_app_dir() / "data" / "sessions_summary.json"
# Same literal path as agent/tools/native.py's _CREDENTIALS_DIR, duplicated rather than imported
# (that import would pull agent/tools/__init__.py's full tool-registration side effect into every
# module that just wants session persistence) — a module-level constant here, not inlined in
# delete_session(), so a test can monkeypatch it the same way SESSIONS_DIR/INDEX_PATH already are.
_CREDENTIALS_DIR = resolve_global_app_dir() / "data" / "credentials"

_SESSION_FILENAME = "session.json"


def _sanitize_folder_name(target: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", target).strip("-")
    return name[:60] or "target"


def _load_index() -> dict[str, str]:
    if not INDEX_PATH.exists():
        return {}
    try:
        with INDEX_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_index(index: dict[str, str]) -> None:
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = INDEX_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, INDEX_PATH)


# Guards the read-modify-write cycle every _load_summary_index()/_save_summary_index() pair below
# is part of -- an active scan calls save_session() (and therefore this cycle) on essentially every
# tool call/log line, and two of those can genuinely race within the same process (a background job
# reaping on its own thread, a concurrent chat turn, two sessions scanning at once). Real, confirmed
# incident this fixes: with no lock and a non-atomic write, a reader (list_session_summaries(), the Projects list route)
# could observe a torn/mid-write file mid-update from a concurrent save_session() call, which
# _load_summary_index()'s own except-clause below silently treats as "the whole cache is empty" --
# not just a miss for the one session actually being written, EVERY session on disk -- forcing
# list_session_summaries() to fall back to fully re-parsing every single session.json on disk, the
# exact "Projects list takes forever to load while a scan is running" symptom.
_SUMMARY_INDEX_LOCK = threading.Lock()


def _load_summary_index() -> dict[str, dict]:
    if not SUMMARY_INDEX_PATH.exists():
        return {}
    try:
        with SUMMARY_INDEX_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_summary_index(index: dict[str, dict]) -> None:
    # Atomic (tmp-file + os.replace()), same pattern _save_index()/save_session() already use for
    # the real session data -- an EARLIER version of this function was a deliberate plain write,
    # reasoning that "a rare torn write here is harmless, a cache miss just falls back to one real
    # load_session() + rebuild" -- true for ONE session, but a torn/partial READ of this file (by a
    # concurrent list_session_summaries() call, not just a torn write) makes _load_summary_index()'s
    # own except-clause return an EMPTY dict, which list_session_summaries() then treats as a cache
    # miss for EVERY session on disk, not one -- see _SUMMARY_INDEX_LOCK's own comment above for the
    # real incident. os.replace() is a single atomic syscall, so any concurrent reader now only ever
    # sees the fully-old or fully-new file, never a partial one.
    SUMMARY_INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SUMMARY_INDEX_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(index, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, SUMMARY_INDEX_PATH)


def _build_summary(data: dict) -> dict:
    """The handful of cheap, small fields list_session_summaries() actually needs -- never
    session["logs"]/session["findings"] IN FULL, which is what made rendering the Projects list,
    the sidebar's active-session poll (base.html, every 5s, on every single page in this app), and
    the home page's recent-projects poll (also every 5s) each do a full json.load() of every
    session file, every few seconds, forever. Real incident this fixes: one session's own logging
    bug (see agent/core.py's _describe_command / agent/tools/runner.py's _loggable_params -- a
    catastrophic self-referential embedding of the whole session dict into its own log entries)
    alone made that ONE session.json 364 MB -- with every page in the app re-parsing it in full
    every 5 seconds, the whole app (not just that one project's page) became barely usable: slow
    startup (_mark_orphaned_sessions_interrupted did this too, once, for every session, before it
    could serve a single request) and "жутко долго" tab switching (every navigation re-triggers the
    same 5s poll cycle fresh, on top of whatever poll was already in flight).

    Called with the full session dict already in memory (save_session has it for free; a cache-miss
    backfill in list_session_summaries pays one real read) -- never re-reads the file itself.
    """
    logs = data.get("logs") or []
    resumable_from = data.get("resumable_from")
    if not resumable_from and data.get("status") in ("interrupted", "failed"):
        # Same rule as agent/core.py's compute_resume_entry_point, duplicated here (3 lines) rather
        # than imported -- agent.core already imports FROM this module (create_session/load_session/
        # save_session), so importing back would be a real circular import.
        if data.get("findings"):
            resumable_from = "exploit"
        elif (data.get("recon_result") or {}).get("targets"):
            resumable_from = "analyze"
        else:
            resumable_from = "recon"
    return {
        "name": data.get("name") or data.get("session_id"),
        "target": data.get("target", ""),
        "status": data.get("status", "unknown"),
        # "agent" for every pre-existing session (missing the field entirely), "interactive" for a
        # chat-only console project -- lets the Projects list tell the two apart without a full load.
        "mode": data.get("mode", "agent"),
        # Decorative per-project glyph + color for the list; None on pre-icon sessions (the template
        # falls back to the default shield in the default text color).
        "icon": data.get("icon"),
        "icon_color": data.get("icon_color"),
        "findings_count": len(data.get("findings") or []),
        "created_at": data.get("created_at", ""),
        "resumable_from": resumable_from,
        "phase": logs[-1].get("phase") if logs else None,
        "rescanned_from_name": data.get("rescanned_from_name"),
        # The forward half of the rescan link (session_fragment.html's own backward
        # "Rescan of X" line already reads rescanned_from_name above) — lets a project's own page
        # look up any NEW-project rescans made FROM it (main.py's rescan_session) without a second,
        # separate index. Self-heals the same way every other field here does: a session's cached
        # summary only reflects this once that session is saved again after this field was added,
        # so a rescan created before this existed won't show up as a forward link until it's next
        # touched (e.g. resumed) — acceptable since the field is None until then, never wrong.
        "rescanned_from": data.get("rescanned_from"),
        # Small, deterministic, already-aggregated bookkeeping (never session["logs"]/["findings"]
        # in full) -- carried into the cache so agent/core.py's compute_provider_leaderboard can
        # rank providers across every project on disk from list_session_summaries() alone, the same
        # cache this whole function exists to make cheap, instead of a full load_session() per
        # project on every Summary tab render (which live sessions re-render every
        # _SSE_POLL_INTERVAL_SECONDS -- exactly the "re-parse everything, every few seconds, on
        # every page" cost this function's own docstring above already fixed once).
        "phase_efficiency": data.get("phase_efficiency") or {},
        "stall_events": data.get("stall_events") or [],
        "llm_usage": data.get("llm_usage") or [],
        # Cheap enough to compute here (chat_threads is already in memory) that main.py's own
        # startup orphan sweep can find a stuck chat turn without a full load_session() on every
        # session just to check it -- a chat thread's own pending=True can outlive the process that
        # was running its background turn regardless of the SESSION's own status (interactive,
        # completed, whatever), so it isn't caught by that sweep's existing _ORPHANABLE_STATUSES
        # filter at all. Self-heals the same way every other field here does: reflects the last save.
        "has_pending_chat": any(t.get("pending") for t in (data.get("chat_threads") or [])),
    }


def list_session_summaries() -> list[dict]:
    """Fast summaries for every session -- the Projects list, the sidebar's active-session poll,
    and the home page's recent-projects poll all call this (via main.py's own _load_all_sessions)
    instead of iterating + fully parsing every session.json (see _build_summary's own docstring for
    the real incident this replaces). Reads the small cached index kept in sync by save_session();
    any session_id missing from the cache (created before this existed, or the cache file itself is
    missing/corrupt) is read once here and backfilled into the cache, so the slow path only ever
    happens once per session, never on the next poll 5 seconds later.
    """
    summary_index = _load_summary_index()
    cache_dirty = False

    def _summary_for(session_id: str, path: Path) -> dict | None:
        nonlocal cache_dirty
        cached = summary_index.get(session_id)
        if cached is not None:
            return cached
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        cached = _build_summary(data)
        summary_index[session_id] = cached
        cache_dirty = True
        return cached

    results = []
    folder_index = _load_index()
    for session_id, folder in folder_index.items():
        path = Path(folder) / _SESSION_FILENAME
        if not path.exists():
            continue
        summary = _summary_for(session_id, path)
        if summary is None or summary.get("mode") == "standalone":
            # mode="standalone" is the top-level, project-less Quick Chat (main.py's GET /chat,
            # get_or_create_quick_chat_session) -- a real session on disk like any other, but this
            # is the one shared choke point every project listing (Projects list, sidebar's
            # active-session poll, home page's recent-projects poll -- see this function's own
            # docstring) and every backend sweep that iterates "every project" (orphan recovery,
            # rescan lookups, provider leaderboard) reads from, so filtering it out HERE is enough
            # to keep it invisible everywhere at once, without a separate check at each call site.
            continue
        results.append({"session_id": session_id, "folder": folder, **summary})

    if SESSIONS_DIR.exists():
        for path in SESSIONS_DIR.glob("*.json"):
            session_id = path.stem
            if session_id in folder_index:
                continue  # already covered above
            summary = _summary_for(session_id, path)
            if summary is None or summary.get("mode") == "standalone":
                continue
            results.append({"session_id": session_id, "folder": None, **summary})

    if cache_dirty:
        _save_summary_index(summary_index)
    return results


def _session_path(session_id: str) -> Path:
    index = _load_index()
    if session_id in index:
        return Path(index[session_id]) / _SESSION_FILENAME
    return SESSIONS_DIR / f"{session_id}.json"


def _create_project_folder(session_id: str, name: str) -> Path | None:
    project_dir = resolve_projects_base_dir() / f"{_sanitize_folder_name(name)}-{session_id}"
    try:
        project_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        # A session must still be creatable even if the Documents folder isn't reachable
        # (permissions, a WSL2 interop hiccup, PROJECTS_DIR pointing somewhere broken) — the
        # legacy data/sessions/ path below is the fallback, not a hard failure.
        logger.debug("_create_project_folder: failed for name=%s (%s), using legacy data/sessions", name, exc)
        return None

    index = _load_index()
    index[session_id] = str(project_dir)
    _save_index(index)
    logger.debug("_create_project_folder: session=%s folder=%s", session_id, project_dir)
    return project_dir


def name_exists(name: str) -> bool:
    """Case-insensitive check across every session (legacy + project-folder) — used to reject a
    duplicate project name before create_session() ever runs, not after. Uses the same summary
    cache as list_session_summaries() (name is one of its cheap fields) instead of its own
    dedicated full-parse loop over every session file."""
    needle = name.strip().lower()
    return any(summary.get("name", "").strip().lower() == needle for summary in list_session_summaries())


def reset_plan_for_new_pass(plan: dict | None) -> dict:
    """Returns a fresh copy of `plan` with the SAME phase/task/subtask structure but every status
    reset back to "pending" and every per-entry timing (started_at/finished_at) cleared -- the
    working roadmap a rescan should keep and refine, not a wall of already-"done" entries that reads
    as finished/dead and gives the model no reason to touch it again.

    Two rescan symptoms this addresses directly: a new-project rescan used to start with no plan at
    all ("No plan yet." until the model slowly rebuilt one from scratch), and a same-project
    (in-place) rescan carried the prior pass's plan forward with every subtask still marked "done",
    so the whole plan sat visibly complete/inert for the entire new pass. Resetting to "pending"
    turns the carried plan back into an actionable to-do list for THIS pass while preserving the
    structure the last pass already worked out; each phase's own update_plan call still replaces its
    entry with a fresher one the moment that phase actually re-runs.

    Statuses are set directly rather than re-derived (an all-"pending" tree derives to "pending" at
    every level anyway, agent/tools/native.py's _derive_plan_status) so this stays a pure,
    dependency-free copy with no import back into the tool layer.
    """
    if not plan or not plan.get("phases"):
        return {"phases": [], "version": 0, "updated_at": None}
    fresh = copy.deepcopy(plan)
    for phase_entry in fresh.get("phases", []):
        phase_entry["status"] = "pending"
        phase_entry.pop("started_at", None)
        phase_entry.pop("finished_at", None)
        for task in phase_entry.get("tasks", []):
            task["status"] = "pending"
            task.pop("started_at", None)
            task.pop("finished_at", None)
            for subtask in task.get("subtasks", []):
                subtask["status"] = "pending"
                subtask.pop("started_at", None)
                subtask.pop("finished_at", None)
    # A plain bump so a resumed/rescanned session can still tell "never touched" from "carried over
    # and reset for a fresh pass" -- same counter create_session() seeds at 0.
    fresh["version"] = int(plan.get("version") or 0) + 1
    fresh["updated_at"] = datetime.now(timezone.utc).isoformat()
    return fresh


def reset_host_health_streaks_for_new_pass(recon_result: dict | None) -> dict:
    """Returns a copy of `recon_result` with every host_health entry's CURRENT failure streak
    (consecutive_failures/consecutive_failure_tools) reset to 0, while lifetime failures/successes/
    last_error are preserved untouched.

    agent/core.py's _dead_host_blocked hard-blocks a host once its streak crosses a threshold, and
    that block is a real, useful within-pass protection -- but host_health rides inside recon_result,
    which is carried straight into a new rescan/in-place pass so nmap/dns_lookup don't get re-run for
    hosts already found. Without this reset, a host that tripped the block at the END of a prior pass
    starts the NEW pass already blocked, with zero real attempt made in this pass at all -- exactly
    the "carry forward a stale verdict with no fresh check" failure this project's rescan work is
    meant to avoid. A host that's genuinely still dead re-accumulates its own streak and re-blocks
    within the new pass on its own; only the streak inherited from a DIFFERENT pass is cleared here.
    """
    if not recon_result:
        return recon_result or {}
    fresh = copy.deepcopy(recon_result)
    host_health = fresh.get("host_health")
    if not host_health:
        return fresh
    for entry in host_health.values():
        entry["consecutive_failures"] = 0
        entry["consecutive_failure_tools"] = []
    return fresh


def create_session(
    target: str,
    name: str | None = None,
    enumerate_subdomains: bool = False,
    qualifying_vulnerabilities: str = "",
    non_qualifying_vulnerabilities: str = "",
    initial_hypotheses: list[str] | None = None,
    custom_instructions: str = "",
    goal: str = "",
    custom_user_agent: str = "",
    custom_headers: str = "",
    out_of_scope: list[str] | None = None,
    out_of_scope_notes: list[str] | None = None,
    authorize_exploit: bool = False,
    llm_provider: str | None = None,
    initial_status: str = "pending",
    identity_a_configured: bool = False,
    identity_b_configured: bool = False,
    extra_identities_configured: int = 0,
    time_budget_seconds: int | None = None,
    mode: str = "agent",
    re_experience_level: str = "hobbyist",
    icon: str = "",
    icon_color: str = "",
    program_url: str = "",
    enabled_subagent_ids: list[str] | None = None,
) -> str:
    session_id = f"usr_{secrets.token_hex(3)}"
    resolved_name = name or target
    _create_project_folder(session_id, resolved_name)

    # Purely decorative project icon + color. Random when the operator picks nothing (or an
    # unrecognized value sneaks in), so every project still gets a distinct glyph -- projects/icons.py
    # is the shared source of truth for the pools and the New Project picker alike.
    resolved_icon = icon if project_icons.is_valid_icon(icon) else project_icons.random_icon()
    # Black (#000000) is the picker's neutral default -- treated as "unchosen" so a skipped color
    # becomes a random visible one, never an invisible black glyph on the dark UI.
    _color_chosen = project_icons.is_valid_color(icon_color) and icon_color.strip().lower() != "#000000"
    resolved_icon_color = icon_color if _color_chosen else project_icons.random_color()

    session = {
        "session_id": session_id,
        "name": resolved_name,
        "target": target,
        # Decorative only -- a per-project glyph + color (projects/icons.py), shown in the projects
        # list / recent projects. Random default above; never affects behavior.
        "icon": resolved_icon,
        "icon_color": resolved_icon_color,
        # How this project is driven. "agent" (the default, and every session created before this
        # field existed via session.get("mode")) is the full autonomous pipeline (recon -> analyze
        # -> exploit -> ..., agent/core.py's run_session). "interactive" is the operator's own
        # manual, chat-only console (main.py's start_interactive / session.html's interactive
        # branch): no pipeline ever runs, no target is required up front (it's named in the chat),
        # and exploitation is authorized wholesale for the session (agent/tools/allowed_targets.py's
        # _full_exploitation_authorized) since choosing this mode is itself the authorization.
        "mode": mode,
        # Reverse-Engineering-mode only (ignored by every other mode's own prompts): "novice" /
        # "hobbyist" (default) / "professional" -- picked once at project creation (main.py's
        # start_re), read by agent/prompts.py's RE_TRIAGE_PROMPT/RE_CHAT_PROMPT to adjust how
        # proactive/explanatory vs. terse/technical the agent is, never anything the tool-calling
        # loop itself branches on. "hobbyist" (the neutral middle tier) is the default for every
        # pre-existing session missing this field, same "already-safe default" convention every
        # other mode-shaped field on this dict uses.
        "re_experience_level": re_experience_level,
        # "pending" for every existing caller (agent/core.py's CLI entrypoint, rescan_session,
        # resume_session, every direct store.create_session() test call) -- ready to run the
        # instant a caller schedules _run_session_task. main.py's start_scan (the New Project
        # form's "Create" button) is the one deliberate exception: it passes initial_status=
        # "created" so the project exists but nothing runs until the operator's own later "Start"
        # click (POST /api/session/{id}/start) flips this to "pending" itself.
        "status": initial_status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "logs": [],
        "findings": [],
        "approvals": [],
        # One entry per real "the agent needed X, wasn't installed" event (agent/core.py's
        # _record_missing_capability) -- generic over whatever X is (python2, a C/C++ compiler,
        # anything else added to agent/tools/capability_registry.py later), not python2-specific.
        # Empty until the first real gap happens, same "exists once something real happens, not
        # before" posture as plan/chain_attempts below.
        "missing_capabilities": [],
        # Suspected-but-unconfirmed attack angles (agent/core.py's record_hypothesis/
        # resolve_hypothesis, agent/tools/native.py) — deliberately weaker than a finding (no proof
        # yet), stronger than a passing thought, so a raw-evidence lead recon/analyze notices
        # survives as real structured data instead of only living in that one turn's own reasoning.
        # Same entry shape as agent/core.py's _persist_new_hypothesis produces (id/text/evidence/
        # source_phase/source/status/resolution_note/created_at/resolved_at) -- built directly here
        # rather than via that function since no RunContext/live session exists yet at creation
        # time. Pre-seeded from the New Project form's own "Hypotheses to check" field (optional,
        # empty by default): each becomes a real, structured lead the end-of-session hypothesis
        # gate (_run_hypothesis_resolution_gate) deterministically requires the agent to confirm or
        # rule out, source="user" so the UI can tell an operator's own suspicion apart from one the
        # agent found on its own.
        "hypotheses": [
            {
                "id": secrets.token_hex(6),
                "text": text,
                "evidence": "",
                "source_phase": "pre_scan",
                "source": "user",
                "status": "unconfirmed",
                "resolution_note": None,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "resolved_at": None,
            }
            for text in (initial_hypotheses or [])
        ],
        # Raw per-phase tool-call counts (agent/core.py's _log_phase_efficiency_summary) and stall
        # events (_run_llm_tool_loop_impl's stall detector) — the inputs to compute_efficiency_score,
        # never edited by hand, always accumulated deterministically as the session runs.
        "phase_efficiency": {},
        "stall_events": [],
        # One entry per distinct (provider_id, model) actually dispatched to this session --
        # agent/core.py's _record_llm_usage_event, called from the SAME choke point
        # (_llm_complete) phase_efficiency above is. Deliberately separate from llm_provider above:
        # that field is the operator's CONFIGURED intent (can be None, can name a provider whose
        # Reserve-providers fallback chain later switched away from it mid-run); this is what was
        # ACTUALLY dispatched to, call by call, including any such switch. Each entry is
        # {"provider_id", "model", "calls", "total_latency_seconds", "prompt_tokens",
        # "completion_tokens", "calls_with_usage"} -- calls_with_usage lets a reader tell "0 tokens
        # reported" apart from "this provider never reports usage at all" (see LLMResponse.usage's
        # own docstring), so a cost estimate can flag itself partial instead of silently landing on
        # $0.00. Empty until the first real LLM call, same "exists once something real happens, not
        # before" posture as plan/chain_attempts above. Feeds agent/core.py's
        # compute_llm_usage_summary (this session) and compute_provider_leaderboard (cross-session,
        # via sessions.store.list_session_summaries -- see _build_summary below for why this field is
        # cached there too).
        "llm_usage": [],
        "chat": {"summary": "", "messages": []},
        # Off by default — the New Project form's "Enumerate subdomains" checkbox, a project-wide
        # equivalent of writing every scope entry as *.example.com without having to type it per
        # entry. Read by agent/core.py's _run_recon alongside _has_wildcard_scope(target).
        "enumerate_subdomains": enumerate_subdomains,
        # Optional bug-bounty program scope rules (New Project form) — free text, not a fixed
        # taxonomy. Both blank by default, meaning the agent scans exactly as it does today with
        # no extra constraint. When set, agent/core.py's _run_analyze injects them into the Analyze
        # task so the model can prioritize Qualifying classes and mark matching findings via
        # record_finding's qualifies_for_bounty field (agent/tools/native.py).
        "scope_rules": {
            "qualifying": qualifying_vulnerabilities.strip(),
            "non_qualifying": non_qualifying_vulnerabilities.strip(),
        },
        # Optional, free-text program-specific rules beyond the qualifying/non-qualifying vuln-class
        # table above (New Project form) — blank by default, meaning no extra constraint. Read by
        # agent/core.py's _custom_instructions_task_addendum and appended to every phase's task
        # message (recon/analyze/exploit), not just Analyze.
        "custom_instructions": custom_instructions.strip(),
        # Optional, free-text (New Project form, next to Time budget) — what the operator is
        # actually trying to achieve this engagement ("deepen an existing foothold", "reach the
        # admin panel", "full compromise"), distinct from custom_instructions above: an ASPIRATION
        # to prioritize toward, not a constraint on how to scan. Blank by default, meaning no extra
        # prioritization. Read by agent/core.py's _goal_task_addendum, appended at the same call
        # sites as custom_instructions (recon/analyze/reverify/exploit/hypothesis phases).
        "goal": goal.strip(),
        # Optional — some bug-bounty programs require a specific User-Agent string on all test
        # traffic so their team can tell it apart from a real attack in their logs (New Project
        # form). Blank by default, meaning every tool's own normal default is used unchanged.
        # agent/core.py's _run_tool_with_retry injects this into every tool call server-side
        # (params["_user_agent"]) — never something the model can see or override.
        "custom_user_agent": custom_user_agent.strip(),
        # Optional — the New Project form's "Custom HTTP Headers" field, one "Name: Value" pair
        # per line. Some bug-bounty programs (HackerOne's own "Session Layer" guidance is a real
        # example) ask for a research-identifying header on top of/instead of a custom User-Agent
        # (e.g. "X-HackerOne-Research: <handle>") — this is the general-purpose sibling of
        # custom_user_agent above for that case. Blank by default, same "no extra header sent"
        # posture. Stored as raw text (parsed on use by agent/core.py's _parse_custom_headers, the
        # same "parse where it's consumed" choice already made for out_of_scope_notes) rather than
        # a structured list, so a human editing this field never has to think about JSON shape.
        # agent/core.py's _run_tool_with_retry injects the parsed dict into every tool call server-
        # side (params["_extra_headers"]) — never something the model can see or override.
        "custom_headers": custom_headers.strip(),
        # Optional — the New Project wizard's "Study program page" button (main.py's
        # wizard_import_program) prefills this with the bug-bounty PROGRAM page it just read
        # (never the pentest target itself — see prepare_target_only), and it stays freely
        # editable afterward (POST /api/session/{id}/program-url). Blank by default, meaning no
        # program association at all — every existing project and every non-bug-bounty scan
        # behaves exactly as before this field existed. When set, agent/core.py's
        # _program_url_task_addendum tells every phase's task message the program is there and
        # that the agent may browse it / call check_disclosed_reports on it at its own
        # discretion, and agent/tools/bugbounty_import.py's refresh_program_check keeps a cheap,
        # TTL-gated Hacktivity cache fresh for _persist_new_finding's own duplicate-detection.
        "program_url": program_url.strip(),
        # Bookkeeping for the above — never edited by hand, only by refresh_program_check.
        # disclosed_reports_text is HackerOne/Bugcrowd/YesWeHack-only (see
        # _disclosed_reports_feed_url); last_checked covers any program_url (a plain reachability
        # read for platforms this feature doesn't cover).
        "program_check": {
            "last_checked": None,
            "last_error": None,
            "disclosed_reports_text": "",
            "disclosed_reports_checked_at": None,
        },
        # Optional — the New Project form's "Out of scope" field. Hosts/domains (same
        # comma-separated, "*.domain"-wildcard-capable syntax as the Target(s) field) the operator
        # explicitly excludes from this engagement, e.g. a subdomain that would otherwise fall
        # under a wildcard-scope target. Empty by default, meaning no exclusion. Checked
        # deterministically before every real tool call — agent/core.py's _out_of_scope_target via
        # agent/tools/allowed_targets.py's is_target_out_of_scope — not just mentioned to the model
        # in a prompt; see also _out_of_scope_task_addendum, which tells the model about it too so
        # a skipped call isn't a silent mystery.
        "out_of_scope": [entry for entry in (out_of_scope or []) if entry],
        # Optional — the same "Out of scope" field, but for entries that don't parse as a
        # concrete host/domain/URL/wildcard (e.g. "All domains or subdomains not listed in the
        # above list of Scopes" — a real, commonly-seen bug-bounty scope-table phrasing). There is
        # no deterministic way to match a live tool-call target against free-form English, so
        # these are surfaced to the model as a qualitative instruction (agent/core.py's
        # _out_of_scope_notes_task_addendum) instead of being enforced like "out_of_scope" above.
        "out_of_scope_notes": [entry for entry in (out_of_scope_notes or []) if entry],
        # Whether the human actually ticked "Authorize exploitation" for this project — the side
        # effect (agent/tools/allowed_targets.py's data/allowed_targets.json) is global and has no
        # per-session record of intent on its own, so main.py's rescan route needs this to know
        # whether to replay that widening for a new session covering the same target(s). False by
        # default, same off-by-default posture as the checkbox itself.
        "authorize_exploit": authorize_exploit,
        # Optional wall-clock work budget in seconds (New Project form's Time budget field, fixed
        # presets or a custom value) — None (the default) means the existing, unlimited behavior:
        # the pipeline runs once and stops the moment it's genuinely done, exactly as before this
        # field existed. When set, agent/core.py's run_session computes a real deadline
        # (started_at + this many seconds) once the run actually starts, and — instead of stopping
        # at the first natural completion — keeps looping additional full passes (each one folding
        # this pass's own findings into the next as carried_over_findings to actively re-verify,
        # same mechanism main.py's rescan_session_in_place already uses) for as long as real time
        # remains, so a target that's fully explored in 10 minutes of a 2-hour budget still gets the
        # rest of that time spent digging deeper (further chaining, additional distinct
        # vulnerabilities) rather than stopping early just because the first pass succeeded.
        "time_budget_seconds": time_budget_seconds,
        # The New Project form's own LLM provider choice, if any (main.py's start_scan validates
        # it against PROVIDER_REGISTRY before this ever gets here) -- None means "use whatever
        # DEFAULT_PROVIDER/Settings resolves to", the same fallback _run_session_task(provider_id=
        # None) already had before this existed. Persisted (not just handed straight to
        # background_tasks.add_task the way it used to be) because the actual run no longer starts
        # at creation time -- the later POST /api/session/{id}/start route needs to read the exact
        # same choice back, potentially a separate HTTP request entirely.
        "llm_provider": llm_provider,
        # Whether the New Project form's optional Identity A/B credential fields were filled in --
        # deliberately just a bool, never the real values (those live only in
        # agent/tools/native.py's own separate, per-session credentials store, _CREDENTIALS_DIR;
        # this field exists purely so the Overview tab can show "configured" without ever loading
        # a real password/cookie/auth header back into a rendered page).
        "identity_a_configured": identity_a_configured,
        "identity_b_configured": identity_b_configured,
        # Count of "+ Add another account" identity cards (new_project_form.html) beyond the fixed
        # user_a/user_b pair that had at least one non-empty field -- same "bool/count only, never
        # the real values" posture as identity_a_configured/identity_b_configured just above.
        "extra_identities_configured": extra_identities_configured,
        # The agent's own working plan (update_plan tool, agent/tools/native.py) — empty until the
        # model actually calls it, same "exists once something real happens, not before" posture as
        # recon_result/subagent_tasks (neither of which live in this literal either). "phases" is a
        # list of {"phase", "rationale", "status", "tasks": [{"text", "status",
        # "subtasks": [{"text","status","recommended_tools"}]}]} entries — three levels
        # (phase -> task -> subtask), tools/status only ever set directly on a subtask, with
        # task/phase "status" always derived from their own children (native.py's
        # _derive_plan_status), never independently settable, so they can never silently drift out
        # of sync with what's actually been completed. "version" is a plain incrementing counter
        # (bumped by whichever core.py helper applies an update) so a resumed/rescanned session can
        # tell "never touched" from "explicitly emptied" without inspecting phases itself.
        "plan": {"phases": [], "version": 0, "updated_at": None},
        # One entry per _run_chain pass (agent/core.py) — a real, honest record of what that phase
        # looked at and concluded, even "no_chain_found", so an operator can see it actually ran
        # instead of only ever seeing its side effect (a new chained finding, if any). Empty until
        # Chain first runs, same "exists once something real happens" posture as "plan" above.
        "chain_attempts": [],
        # Deterministic (no LLM) credential-reuse tracking (agent/core.py's _update_asset_graph) --
        # every credential default_creds_check/hydra_start/web_login_bruteforce_start actually finds
        # gets one entry here, checked against every other host this session discovers so a
        # credential found on host A automatically gets suggested (via record_hypothesis, not
        # silently forgotten) against host B too. Empty until the first real credential is found.
        "asset_graph": {"credentials": []},
        # Per-project Subagent access (New Project form's own checklist, next to the global
        # Subagents settings tab) -- None (every existing session, and every caller that predates
        # this field) means NO restriction at all: agent/core.py reads every currently-enabled
        # profile (agent/tools/subagent_store.py's get_enabled_profiles), exactly the pre-existing
        # behavior, and a profile enabled globally AFTER this project was created is picked up
        # automatically. An explicit list (main.py's start_scan, possibly empty) means the operator
        # actually narrowed it down for THIS project specifically -- checked against globally-
        # enabled profiles only, so this can only ever narrow access, never grant a profile that's
        # disabled (or later gets disabled) on the Subagents tab itself.
        "enabled_subagent_ids": enabled_subagent_ids,
    }
    save_session(session_id, session)
    logger.debug(
        "create_session: id=%s name=%s target=%s mode=%s status=%s enumerate_subdomains=%s scope_rules_set=%s "
        "custom_instructions_set=%s goal_set=%s custom_user_agent_set=%s custom_headers_set=%s out_of_scope=%s "
        "out_of_scope_notes=%s authorize_exploit=%s llm_provider=%s identity_a_configured=%s identity_b_configured=%s "
        "extra_identities_configured=%s time_budget_seconds=%s program_url_set=%s enabled_subagent_ids=%s",
        session_id, resolved_name, target, mode, initial_status, enumerate_subdomains,
        bool(session["scope_rules"]["qualifying"] or session["scope_rules"]["non_qualifying"]),
        bool(session["custom_instructions"]), bool(session["goal"]), bool(session["custom_user_agent"]), bool(session["custom_headers"]),
        session["out_of_scope"], session["out_of_scope_notes"], authorize_exploit,
        llm_provider, identity_a_configured, identity_b_configured, extra_identities_configured, time_budget_seconds,
        bool(session["program_url"]), enabled_subagent_ids,
    )
    return session_id


_LOAD_RETRY_ATTEMPTS = int(os.getenv("LOAD_SESSION_RETRY_ATTEMPTS", "20"))
_LOAD_RETRY_DELAY_SECONDS = float(os.getenv("LOAD_SESSION_RETRY_DELAY_SECONDS", "0.2"))

# In-memory, per-process revision counter -- bumped once by save_session() on every real write
# (reload_merge_save funnels through save_session() too, so this covers every mutation path with
# no second call site to remember). Exists purely so a live-update poll (main.py's stream_session)
# can answer "has anything changed since I last looked?" with one O(1) integer comparison instead
# of loading the whole session from disk and re-hashing a full `json.dumps(session, ...)` of it --
# real, confirmed root cause of a live session's own UI getting progressively laggier (and, on a
# real 4.5-hour bug-bounty run, the Map tab's graph disappearing outright) the longer a scan ran:
# stream_session's poll loop re-serialized and SHA-256'd the ENTIRE session dict every single
# second, for as long as any browser tab had the page open, with a cost that grows with total
# accumulated session size (logs, findings, recon_result, hypotheses, ...) and no ceiling -- a
# synchronous, CPU-bound block sitting directly in an async generator with no `await` around it,
# so it stalls the WHOLE event loop (every other concurrent request, including the agent's own)
# for however long that dump+hash takes once the session has grown large. Resets on a server
# restart (an empty dict here just means "unknown, push once" -- see stream_session's own
# last_revision=None handling), which is fine: a restart makes every existing browser tab
# reconnect anyway.
_session_revisions: dict[str, int] = {}
_REVISION_LOCK = threading.Lock()

# Serializes the actual on-disk write (tmp-file write + replace/fallback) per session_id -- real,
# confirmed incident this fixes: several save_session() calls for the SAME session landing close
# together (e.g. a Map drag with "magnetism" nudging half a dozen neighbor nodes, each one's own
# debounced position-save firing within the same ~150ms window) all write to the exact same
# tmp_path filename, and _replace_with_retry's own non-atomic fallback (path.open("w") when
# os.replace() keeps failing on this DrvFs-mounted path, see that function's own docstring) has no
# protection at all against a second writer's open("w") truncating the file out from under the
# first one mid-write. Confirmed live: this produced a genuinely corrupted session.json on disk --
# one complete JSON document with another write's leftover trailing bytes appended straight after
# it, "Extra data" on every single subsequent load -- NOT the transient torn-read case
# load_session's own retry loop already handles (that one self-heals within a few seconds; this one
# doesn't, because the bad bytes are really sitting on disk, not just a reader catching an in-flight
# rename). Scoped to exactly this write, never held across anything else, so it can't become a
# bottleneck for some OTHER session's own concurrent save.
_SAVE_LOCKS: dict[str, threading.Lock] = {}
_SAVE_LOCKS_META_LOCK = threading.Lock()


def _save_lock_for(session_id: str) -> threading.Lock:
    with _SAVE_LOCKS_META_LOCK:
        lock = _SAVE_LOCKS.get(session_id)
        if lock is None:
            lock = threading.Lock()
            _SAVE_LOCKS[session_id] = lock
        return lock


def _bump_session_revision(session_id: str) -> None:
    with _REVISION_LOCK:
        _session_revisions[session_id] = _session_revisions.get(session_id, 0) + 1


def get_session_revision(session_id: str) -> int:
    """Current write-count for this session, or 0 if this process has never saved it (a session
    loaded fresh from disk, or one saved by a since-restarted process) -- see the counter's own
    module-level docstring above for why stream_session uses this instead of hashing the session."""
    with _REVISION_LOCK:
        return _session_revisions.get(session_id, 0)


def load_session(session_id: str) -> dict | None:
    """Real, confirmed incident this retry exists for: `save_session()` writes atomically
    (tmp-file + `os.replace()`, see `_replace_with_retry` below) and reports success with no
    exception raised at all -- yet a `load_session()` call landing at that exact instant on the
    same Windows-mounted (DrvFS) path, from inside WSL2, still read a complete valid JSON object
    followed by a leftover tail of the PREVIOUS (longer) file's bytes: `json.JSONDecodeError:
    Extra data`. This is a different failure shape than the already-documented `os.replace()`
    PermissionError/EIO (which IS raised and already has its own retry) -- here Python sees no
    error on the write side at all, so only the read side can catch it. Confirmed self-healing
    within a few seconds every time it hit a UI route (a bare 500, gone on the next poll), but
    fatal the one time it hit `_track_host_health`'s `reload_merge_save` mid-scan with nothing to
    catch it, killing an entire 26-minute run with zero findings recorded seconds before it would
    have crashed anyway. Retrying here (same tuning shape as `_replace_with_retry`'s own write-side
    retry) lets a transient torn read resolve itself instead of taking down the caller.
    """
    path = _session_path(session_id)
    if not path.exists():
        return None

    last_exc: json.JSONDecodeError | None = None
    for attempt in range(_LOAD_RETRY_ATTEMPTS):
        if attempt > 0:
            time.sleep(_LOAD_RETRY_DELAY_SECONDS)
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            # Re-hydrates each thread's own messages/queued_messages from its own file (see the
            # per-thread-file storage docstring above save_session) -- a no-op for a thread that
            # already carries "messages" inline (an old session.json that hasn't been re-saved
            # through the split path yet), so this is transparent either way.
            threads = data.get("chat_threads")
            if isinstance(threads, list):
                threads_dir = _chat_threads_dir(path)
                data["chat_threads"] = [_hydrate_thread(threads_dir, t) if isinstance(t, dict) else t for t in threads]
            return data
        except json.JSONDecodeError as exc:
            last_exc = exc

    logger.debug(
        "load_session: id=%s still unreadable after %d attempt(s) (%s) -- giving up",
        session_id, _LOAD_RETRY_ATTEMPTS, last_exc,
    )
    raise last_exc


_REPLACE_RETRY_ATTEMPTS = int(os.getenv("SAVE_SESSION_RETRY_ATTEMPTS", "30"))
_REPLACE_RETRY_DELAY_SECONDS = float(os.getenv("SAVE_SESSION_RETRY_DELAY_SECONDS", "0.2"))

# Paths whose most recent save already needed the direct-write fallback below -- real incident:
# a session left open in a browser tab (its SSE stream re-reading session.json on an interval for
# as long as the tab stays open) held the lock for the file's ENTIRE remaining lifetime, so every
# single subsequent save during that same run paid the full ~6s retry budget before falling back
# anyway, over and over, for as long as the tab stayed open. Once a path is known-blocked, later
# saves skip straight to one quick check (in case the lock actually cleared) instead of re-paying
# the whole retry budget on a rename that's already proven doomed for this file right now.
_KNOWN_BLOCKED_PATHS: set[Path] = set()


def _replace_with_retry(tmp_path: Path, path: Path, data: dict) -> None:
    """os.replace() on a project folder's real path (Documents/ASRA Projects/..., a Windows-
    mounted DrvFs path even from inside WSL2) can transiently fail with PermissionError if another
    process/handle has `path` open at that exact instant -- Windows file-locking semantics apply
    here even though this is a POSIX rename() call. Real incident this fixes: this raced with the
    session page's own SSE stream re-reading the same file (main.py's /stream route polls
    load_session on an interval, and never stops for as long as a browser tab is left open on that
    session's page -- even long after the scan itself finished, surviving a server restart via the
    browser's own EventSource auto-reconnect) and crashed run_session outright on an unhandled
    PermissionError -- including, worst case, on the very save that was trying to record the run's
    own failure, leaving the session stuck showing status="processing" (looking alive) for hours
    after the process had actually died, with no Resume/Stop control doing anything real.

    If the retries still don't get past it, falls back to a direct (non-atomic) in-place write
    instead of losing the save entirely -- confirmed live on the actual incident this fixes: the
    block was specifically on the RENAME (something else held a handle open without
    FILE_SHARE_DELETE, e.g. an antivirus/indexer/Explorer touch on Windows, not a full continuous
    lock), and a plain in-place write to the same path succeeded instantly even while os.replace()
    kept failing on that exact file for minutes straight. A crash mid-write here is no worse than
    any other unexpected process kill already tolerated elsewhere; silently losing the save
    outright (the previous behavior) was strictly worse.
    """
    last_exc: OSError | None = None
    attempts = 1 if path in _KNOWN_BLOCKED_PATHS else _REPLACE_RETRY_ATTEMPTS
    for attempt in range(attempts):
        if attempt > 0:
            time.sleep(_REPLACE_RETRY_DELAY_SECONDS)
        try:
            os.replace(tmp_path, path)
            _KNOWN_BLOCKED_PATHS.discard(path)
            return
        # Real, confirmed incident this widens to: this originally caught only PermissionError,
        # but the same DrvFS mount (Documents/ASRA Projects/... under WSL2) can also raise a plain
        # OSError with errno=EIO ("Input/output error") on a transient rename failure -- a
        # different errno, same underlying "Windows-mounted path I/O isn't 100% reliable" class
        # this retry/fallback exists for, but it used to sail straight past the narrow catch and
        # crash the caller uncaught instead of falling back to the in-place write below.
        except OSError as exc:
            last_exc = exc

    _KNOWN_BLOCKED_PATHS.add(path)
    logger.debug(
        "save_session: os.replace kept failing after %d attempt(s) (%s) -- falling back to a direct in-place write",
        attempts, last_exc,
    )
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp_path.unlink(missing_ok=True)


def _preserve_newer_chat(path: Path, data: dict) -> None:
    """Legacy-schema fallback (session["chat"], the flat single-conversation shape before chat
    threads existed) -- only still reachable when NEITHER side of a save has migrated to
    session["chat_threads"] yet (see _preserve_newer_chat_threads below, the real entry point
    save_session calls). Kept as its own function/still exercised by its own tests rather than
    deleted outright: a session that predates the threads feature and hasn't been read by
    agent/chat.py (which migrates on any read) since upgrading still needs this exact behavior.

    session["chat"] (agent/chat.py) is maintained by a completely separate writer from the main
    scan loop (agent/core.py's run_session): chat loads/saves its own independent copy of this same
    session dict per turn, while run_session can hold ONE long-lived in-memory copy across an
    entire multi-hour scan, saving that copy's own version of every field on every single tool call
    -- including whatever "chat" looked like the one time it was ever loaded, forever after (the
    scan loop never reads or mutates "chat" itself, so its own in-memory copy of that one field
    never changes). Without this, any scan-triggered save after a chat message arrives reverts or
    outright deletes it -- confirmed live during a real session (chat's own reply vanished within
    seconds of being persisted, every time), not a theoretical race.

    "chat" only ever grows (messages are appended, never deleted, by both writers), so the safe
    merge rule is simply: keep whichever "chat" — the caller's own `data`, or whatever is currently
    on disk — has the longer messages list; on a tie, trust the caller's own value (the more
    deliberate write, e.g. a distillation-style rewrite that keeps message count exactly the same).
    Mutates `data` in place so the caller's own in-memory object picks up the newer chat too, not
    just this one file on disk -- self-healing for whatever OTHER stale copy that caller might save
    again later.
    """
    if not path.exists():
        return
    try:
        on_disk = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    if not isinstance(on_disk, dict):
        return
    on_disk_chat = on_disk.get("chat")
    if not isinstance(on_disk_chat, dict):
        return
    incoming_chat = data.get("chat")
    incoming_len = len((incoming_chat or {}).get("messages") or [])
    on_disk_len = len(on_disk_chat.get("messages") or [])
    if on_disk_len > incoming_len:
        data["chat"] = on_disk_chat


def _thread_updated_at(thread: dict) -> str:
    return thread.get("updated_at") or thread.get("created_at") or ""


def _preserve_newer_chat_threads(path: Path, data: dict) -> None:
    """Generalizes _preserve_newer_chat above to session["chat_threads"] (a LIST of independent
    conversations, agent/chat.py) — the same real, already-confirmed incident (the scan loop's own
    long-lived in-memory session silently reverting chat's writes on every scan-triggered save), now
    also possible per-thread once a session can have several. For each thread id present on either
    side, keeps whichever version — the caller's own `data`, or whatever is on disk — has the more
    recent `updated_at`; a thread id that exists on only one side is kept as-is, never dropped.
    `active_chat_thread_id` is trusted from the incoming caller's own value when it still points at
    a thread that survives the merge (the caller's own recent /new or thread-switch), else falls
    back to whatever's on disk.

    Merge key is `updated_at`, not `len(messages)` (an earlier version of this function compared
    message counts — a real, confirmed-live bug this replaces, not a style choice). Every real
    mutation agent/chat.py makes to a thread bumps `updated_at`
    (datetime.now(timezone.utc).isoformat(), lexicographically sortable in that exact format) — a
    new message, a newly appended segment, AND an in-place field update on an already-existing
    segment. Message count only captures the first two. `_update_last_tool_call_segment_and_save`
    (agent/chat.py) flips an EXISTING tool_call segment's own done/output fields in place once a
    tool finishes — no new message, no new segment, so the thread's message count is identical
    right before and right after that write. Confirmed live: a browser tool call's own card
    rendered correctly (done=True, real output) for a moment, then reverted to a permanent
    "(running…)" spinner — and, downstream, the chat panel's whole form stayed disabled forever,
    since its own sync logic keys off any lingering ".asra-spinner" in the DOM. Root cause was a
    scan loop's stale in-memory session (loaded before that specific update) saving moments later:
    it tied on message count with the just-updated on-disk version, and the old tie-break rule
    ("on a tie, trust the caller's own incoming value") handed the win to the stale, less-complete
    copy, silently undoing a completed tool call back to "pending" forever. updated_at has no such
    blind spot — it moves on every one of these mutations, not just the ones that also happen to
    add a message.

    Falls back entirely to the legacy _preserve_newer_chat (flat "chat") when NEITHER side has
    chat_threads yet — a session whose in-memory copy hasn't been migrated by an agent/chat.py read
    in this particular process run. Once EITHER side has chat_threads, that's authoritative; a
    stray legacy "chat" key still sitting in the OTHER side's stale snapshot is not reconciled back
    in (the very next agent/chat.py read migrates it via _ensure_chat_threads, same as it always
    does today) — a narrow, one-time transitional gap, not a recurring one.

    session["deleted_chat_thread_ids"] (agent/chat.py's delete_chat_thread) is a tombstone list,
    merged as a plain union of both sides and consulted BEFORE the per-thread merge above: a
    deliberate delete looks, to the per-thread logic alone, identical to a stale caller's snapshot
    simply predating a thread that was created after it loaded (the exact case "a thread id that
    exists on only one side is kept as-is" exists to protect) — both are "on-disk has this id,
    incoming doesn't". Without the tombstone, that protection would silently resurrect a thread the
    operator just deleted the next time any stale in-memory session (the scan loop's own long-lived
    copy, never having heard about the delete) saves — confirmed live: deleting a chat thread had
    no visible effect at all, the very next save brought it right back.
    """
    if not path.exists():
        return
    try:
        on_disk = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    if not isinstance(on_disk, dict):
        return

    on_disk_threads = on_disk.get("chat_threads")
    incoming_threads = data.get("chat_threads")
    if not isinstance(on_disk_threads, list) and not isinstance(incoming_threads, list):
        _preserve_newer_chat(path, data)
        return
    if not isinstance(on_disk_threads, list):
        return  # nothing durable on disk yet to preserve
    if not isinstance(incoming_threads, list):
        # Caller never touched chat_threads at all this run (e.g. the scan loop's own in-memory
        # session, loaded before chat existed for this session) -- on-disk is strictly newer.
        data["chat_threads"] = on_disk_threads
        if "active_chat_thread_id" not in data and "active_chat_thread_id" in on_disk:
            data["active_chat_thread_id"] = on_disk["active_chat_thread_id"]
        return

    deleted_ids = set(on_disk.get("deleted_chat_thread_ids") or []) | set(data.get("deleted_chat_thread_ids") or [])

    incoming_by_id = {
        t["id"]: t for t in incoming_threads
        if isinstance(t, dict) and isinstance(t.get("id"), str) and t["id"] not in deleted_ids
    }
    on_disk_by_id = {
        t["id"]: t for t in on_disk_threads
        if isinstance(t, dict) and isinstance(t.get("id"), str) and t["id"] not in deleted_ids
    }

    merged: dict[str, dict] = dict(incoming_by_id)
    for thread_id, on_disk_thread in on_disk_by_id.items():
        incoming_thread = incoming_by_id.get(thread_id)
        if incoming_thread is None:
            merged[thread_id] = on_disk_thread
            continue
        if _thread_updated_at(on_disk_thread) > _thread_updated_at(incoming_thread):
            merged[thread_id] = on_disk_thread

    # Incoming's own ordering first (its own intent, e.g. a just-created thread appended last),
    # then any on-disk-only threads (created by some other writer this caller never saw).
    ordered_ids = list(incoming_by_id.keys()) + [tid for tid in on_disk_by_id if tid not in incoming_by_id]
    data["chat_threads"] = [merged[tid] for tid in ordered_ids]
    if deleted_ids:
        data["deleted_chat_thread_ids"] = sorted(deleted_ids)

    incoming_active = data.get("active_chat_thread_id")
    if incoming_active not in merged:
        on_disk_active = on_disk.get("active_chat_thread_id")
        if on_disk_active in merged:
            data["active_chat_thread_id"] = on_disk_active
        elif ordered_ids:
            # Neither side's own "active" pointer survived the merge (both pointed at the thread
            # that just got deleted) -- fall back to whatever thread did survive rather than
            # leaving active_chat_thread_id dangling on a now-nonexistent id.
            data["active_chat_thread_id"] = ordered_ids[0]


def _preserve_appended_hypotheses(path: Path, data: dict) -> None:
    """Reintroduces any hypothesis that's on disk but missing from `data`'s own in-memory list --
    same root cause _preserve_newer_chat_threads exists for (a long-lived in-memory session silently
    reverting a concurrent writer's save), on the one other list a scan's own chat panel can append
    to mid-run. `_persist_new_hypothesis` already merges its OWN single new entry onto disk via
    reload_merge_save the moment it's recorded -- but a scan process holds ctx.session in memory for
    a long-running phase and calls plain save_session on it many times for OTHER reasons
    (phase_timings, plan updates, status) in between. Any one of those blind saves carries along
    ctx.session's own hypotheses SNAPSHOT, taken before a concurrent chat-triggered
    record_hypothesis call's own reload_merge_save landed on disk -- overwriting that already-
    durable entry right back out, the same "existed for a moment and then quietly didn't" incident
    _persist_new_finding's own docstring already describes for creation-time loss, just reachable
    through a different save path than the one already fixed there.

    Deliberately simpler than the chat-thread merge above: session["hypotheses"] has no delete
    feature and no shrink/replace either (every mutation is either `.append()` or an in-place field
    edit -- status/resolution_note/resolved_at -- on an entry `data` already has), so trusting
    `data`'s own version of any id it already has and only ever ADDING BACK an id it's missing
    entirely is enough to never lose either side's work, with no tombstone needed. Matched by id
    (record_hypothesis always assigns one).

    NOT extended to session["findings"] despite the identical-looking race there: unlike hypotheses,
    findings genuinely DOES get replaced with a smaller list on purpose (_run_validate's own dedup
    collapse, `session["findings"] = await _run_validate(ctx)` at several call sites) -- a real,
    confirmed incident this narrowing exists because of: an earlier version of this function applied
    the identical "add back whatever's on disk but missing from data" logic to findings too, and it
    silently undid every single Validate dedup collapse in the test suite (and would have in
    production) -- re-adding the very duplicate Validate had just correctly removed, because that
    duplicate was still sitting in an EARLIER on-disk save from before the collapse. Fixing the
    findings race for real needs a tombstone (which titles were deliberately removed, not just
    absent) the same way deleted_chat_thread_ids does for threads -- a separate, larger change, not
    this narrow one.
    """
    if not path.exists():
        return
    try:
        on_disk = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    if not isinstance(on_disk, dict):
        return

    incoming_hypotheses = data.get("hypotheses")
    on_disk_hypotheses = on_disk.get("hypotheses")
    if isinstance(incoming_hypotheses, list) and isinstance(on_disk_hypotheses, list):
        known_ids = {h.get("id") for h in incoming_hypotheses if isinstance(h, dict)}
        for hypothesis in on_disk_hypotheses:
            if isinstance(hypothesis, dict) and hypothesis.get("id") not in known_ids:
                incoming_hypotheses.append(hypothesis)
                known_ids.add(hypothesis.get("id"))


# Per-thread message storage -- session.json's own "chat_threads" list keeps only per-thread
# METADATA (id/title/summary/provider/model/pending/created_at/updated_at/color); each thread's own
# "messages"/"queued_messages" -- the part that actually grows without bound over a session's real
# lifetime -- lives in its own small file under this directory instead. Real, confirmed incident
# this fixes: session.json is re-serialized and rewritten IN FULL on every single save_session()
# call (a new chat message, a tool-call segment finishing, a thread rename, ...) -- for a session
# meant to accumulate real history for MONTHS (the top-level, project-less Quick Chat specifically,
# see main.py's get_or_create_quick_chat_session: "old threads are never destroyed, just no longer
# active"), every one of those saves would re-write the FULL text of every OTHER thread's own
# history too, even ones untouched for weeks, with no ceiling on how large that rewrite gets over
# time -- the exact same "one session.json re-parsed/rewritten in full, every single mutation"
# shape _build_summary's own docstring already documents as a real, confirmed incident (a 364 MB
# session file making the whole app "жутко долго" on every tab switch), just from message volume
# rather than a logging bug this time.
_CHAT_THREADS_DIRNAME = "chat_threads"


def _chat_threads_dir(session_path: Path) -> Path:
    return session_path.parent / _CHAT_THREADS_DIRNAME


def _thread_file_path(threads_dir: Path, thread_id: str) -> Path:
    return threads_dir / f"{thread_id}.json"


def _load_thread_body(threads_dir: Path, thread_id: str) -> dict:
    """{"messages": [...], "queued_messages": [...]} for one thread's own file -- empty defaults
    (never an error) for a thread with no file yet (freshly created and not saved through the
    split path yet) or a corrupt/missing file, same graceful-degrade tolerance every other store in
    this project already applies to its own cache/index files."""
    path = _thread_file_path(threads_dir, thread_id)
    if not path.exists():
        return {"messages": [], "queued_messages": []}
    try:
        with path.open("r", encoding="utf-8") as f:
            body = json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"messages": [], "queued_messages": []}
    if not isinstance(body, dict):
        return {"messages": [], "queued_messages": []}
    return {"messages": body.get("messages") or [], "queued_messages": body.get("queued_messages") or []}


def _save_thread_body(threads_dir: Path, thread_id: str, messages: list, queued_messages: list) -> None:
    threads_dir.mkdir(parents=True, exist_ok=True)
    path = _thread_file_path(threads_dir, thread_id)
    tmp_path = path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump({"messages": messages, "queued_messages": queued_messages}, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)


def _hydrate_thread(threads_dir: Path, thread: dict) -> dict:
    """A COPY of `thread` with messages/queued_messages filled in from its own file, when the dict
    doesn't already carry them (the on-disk, split-format shape). A thread dict that already has a
    real "messages" key -- an old, not-yet-migrated session.json that still embeds it inline, or
    the caller's own already-hydrated in-memory copy -- is returned completely unchanged, no file
    read at all: this is what makes the split format a transparent, automatic migration the first
    time an old session is next saved, rather than needing an explicit migration pass."""
    if "messages" in thread:
        return thread
    return {**thread, **_load_thread_body(threads_dir, thread["id"])}


def _thin_thread(thread: dict) -> dict:
    """The ON-DISK session.json copy of one thread -- strips messages/queued_messages, the two
    fields that now live in that thread's own file (see this section's own module-level docstring
    above)."""
    return {k: v for k, v in thread.items() if k not in ("messages", "queued_messages")}


# In-memory only: (session_id, thread_id) -> the updated_at this process last actually WROTE to
# that thread's own file. Lets save_session() skip rewriting a thread's file when nothing about it
# changed since the last save -- e.g. a message sent in the session's currently-active thread must
# never also rewrite every OTHER, untouched thread's own (already large, unrelated) history file --
# without needing a second on-disk read just to check. Every real mutation agent/chat.py makes to a
# thread bumps its own updated_at (_preserve_newer_chat_threads' own docstring), so an unchanged
# updated_at reliably means unchanged content. Resets on a process restart, same accepted tradeoff
# as _session_revisions below: the very next save for any given thread just re-writes its file once
# more than strictly necessary, then the skip-check is warm again.
_written_thread_updated_at: dict[tuple[str, str], str] = {}


def _split_chat_threads_for_write(session_id: str, threads_dir: Path, threads: list) -> list:
    """Writes each CHANGED thread's own message file (skipping ones whose updated_at didn't move
    since this process last wrote them), removes any thread file that no longer has a live thread
    id (a real delete, or a tombstoned merge loser -- see _preserve_newer_chat_threads), and returns
    the THIN (messages-stripped) list session.json itself should actually store. Never mutates the
    `threads` list/dicts passed in -- the caller's own in-memory session dict keeps its full,
    hydrated thread objects exactly as it already had them."""
    live_ids: set[str] = set()
    thin: list = []
    for thread in threads:
        if not isinstance(thread, dict) or not isinstance(thread.get("id"), str):
            thin.append(thread)
            continue
        thread_id = thread["id"]
        live_ids.add(thread_id)
        updated_at = _thread_updated_at(thread)
        key = (session_id, thread_id)
        if _written_thread_updated_at.get(key) != updated_at:
            _save_thread_body(threads_dir, thread_id, thread.get("messages") or [], thread.get("queued_messages") or [])
            _written_thread_updated_at[key] = updated_at
        thin.append(_thin_thread(thread))

    if threads_dir.exists():
        for existing in threads_dir.glob("*.json"):
            if existing.stem not in live_ids:
                try:
                    existing.unlink()
                except OSError:
                    pass
                _written_thread_updated_at.pop((session_id, existing.stem), None)
    return thin


def save_session(session_id: str, data: dict) -> None:
    path = _session_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    _preserve_newer_chat_threads(path, data)
    _preserve_appended_hypotheses(path, data)

    # Split chat_threads out to their own per-thread files (see this section's own module-level
    # docstring above) -- data["chat_threads"] itself is first re-hydrated so the CALLER's own dict
    # (which keeps using it after this function returns -- e.g. reload_merge_save's own return
    # value) always has real messages on every thread, regardless of which side _preserve_newer_
    # chat_threads decided won the merge for any given thread id. data_to_write is a SEPARATE,
    # thinned copy used only for the actual on-disk session.json -- never assigned back onto `data`.
    threads = data.get("chat_threads")
    if isinstance(threads, list):
        threads_dir = _chat_threads_dir(path)
        hydrated = [_hydrate_thread(threads_dir, t) if isinstance(t, dict) else t for t in threads]
        data["chat_threads"] = hydrated
        data_to_write = {**data, "chat_threads": _split_chat_threads_for_write(session_id, threads_dir, hydrated)}
    else:
        data_to_write = data

    tmp_path = path.with_suffix(".json.tmp")

    with _save_lock_for(session_id):
        with tmp_path.open("w", encoding="utf-8") as f:
            json.dump(data_to_write, f, indent=2, ensure_ascii=False)
        _replace_with_retry(tmp_path, path, data_to_write)
    _bump_session_revision(session_id)

    logger.debug(
        "save_session: id=%s status=%s findings=%d logs=%d path=%s",
        session_id,
        data.get("status"),
        len(data.get("findings", [])),
        len(data.get("logs", [])),
        path,
    )

    try:
        # Lock scoped to just this load-mutate-save cycle -- serializes concurrent WRITERS (two
        # save_session calls racing, e.g. an active scan plus a background job reaping on its own
        # thread) so one can't silently clobber the other's already-merged entry with its own
        # stale-loaded copy. Never held across slow I/O beyond this cycle's own tiny JSON
        # read/write, so it can't become a bottleneck for unrelated sessions' own saves.
        with _SUMMARY_INDEX_LOCK:
            summary_index = _load_summary_index()
            summary_index[session_id] = _build_summary(data)
            _save_summary_index(summary_index)
    except OSError as exc:
        # The summary cache is a derived speed-up, not the source of truth (session.json itself,
        # already durably written above, is) -- a failure here must never fail the actual save.
        logger.debug("save_session: failed to refresh summary cache for id=%s (%s)", session_id, exc)


def reload_merge_save(session_id: str, apply: Callable[[dict], None]) -> dict | None:
    """Reload-merge-save: loads whatever is CURRENTLY on disk for this session, lets `apply` mutate
    only the field(s) this call site actually owns, and saves that fresh copy back -- never a blind
    save_session(session_id, some_long-lived_in-memory_dict), which can silently overwrite whatever
    a concurrent writer (a chat turn holding its own stale snapshot for a long tool loop, a
    different phase/subagent/background job) already persisted in the meantime.

    Lives here (not agent/core.py, where this pattern originated with record_finding/
    record_hypothesis) so agent/tools/background_jobs.py and agent/tools/subagent_tasks.py can use
    the exact same fix for their own per-job/per-task saves without importing agent.core, which
    both those modules' own docstrings explicitly avoid for circular-import reasons. agent/core.py
    imports this under its own historical `_reload_merge_save` name rather than every call site
    being renamed.

    Real, confirmed incident this generalizes from: a Reverse Engineering session's chat turn
    loaded session.json once at turn start and held that snapshot across several minutes of tool
    calls; a concurrently-running "Re-verify all findings" pass finished correctly in the meantime
    and saved status="completed" — but the chat turn's own later tool-call side effect (host-health
    tracking) then blind-saved its stale snapshot straight over that, permanently reverting the
    session to status="processing" with no further code path to ever correct it. Returns the
    freshly-saved session, or None if the session vanished from disk before this could run.
    """
    fresh_session = load_session(session_id)
    if fresh_session is None:
        return None
    apply(fresh_session)
    save_session(session_id, fresh_session)
    return fresh_session


def delete_session(session_id: str) -> bool:
    """Removes a session's project folder (if it has one) plus the legacy flat file and index
    entry — whichever of those actually exist for this id. Returns False when nothing was found,
    so the route can 404 instead of pretending the delete did something.

    Refuses a mode="standalone" session (the top-level, project-less Quick Chat) outright --
    list_session_summaries() already keeps it out of every listing delete_all_sessions and the
    Projects UI read from, so this is defense-in-depth against a direct delete_session(the-one-
    real-id) call, not the primary guard."""
    existing = load_session(session_id)
    if existing is not None and existing.get("mode") == "standalone":
        logger.debug("delete_session: refusing to delete the standalone Quick Chat session id=%s", session_id)
        return False

    index = _load_index()
    project_dir = index.pop(session_id, None)
    found = project_dir is not None

    if project_dir is not None:
        shutil.rmtree(project_dir, ignore_errors=True)
        _save_index(index)

    legacy_path = SESSIONS_DIR / f"{session_id}.json"
    if legacy_path.exists():
        legacy_path.unlink()
        found = True

    # Pre-existing gap, closed here rather than left to grow: real plaintext identity credentials
    # (agent/tools/native.py's _CREDENTIALS_DIR, "data/credentials/<id>.json") were never cleaned
    # up on delete.
    credentials_path = _CREDENTIALS_DIR / f"{session_id}.json"
    if credentials_path.exists():
        credentials_path.unlink()

    try:
        with _SUMMARY_INDEX_LOCK:
            summary_index = _load_summary_index()
            if summary_index.pop(session_id, None) is not None:
                _save_summary_index(summary_index)
    except OSError as exc:
        logger.debug("delete_session: failed to drop summary cache entry for id=%s (%s)", session_id, exc)

    logger.debug("delete_session: id=%s folder=%s found=%s", session_id, project_dir, found)
    return found


def delete_all_sessions() -> int:
    """Bulk version of delete_session() above, for the Projects tab's "Delete all" action —
    reuses that same function per id rather than duplicating its folder/legacy-file/credentials/
    summary-cache cleanup logic. list_session_summaries() (not _load_index() alone) is the id
    source so this also catches legacy flat-file sessions that never got a project folder. One
    bad id's real OSError (e.g. Windows file-locking, see this project's own documented WSL2/
    DrvFs rename-retry lesson) must not stop the rest of the loop -- log and keep going, same
    "one item's failure can't kill the whole batch" discipline as every other startup/cleanup
    loop in this codebase. Returns how many were actually deleted."""
    session_ids = [summary["session_id"] for summary in list_session_summaries()]
    deleted = 0
    for session_id in session_ids:
        try:
            if delete_session(session_id):
                deleted += 1
        except OSError as exc:
            logger.debug("delete_all_sessions: failed to delete id=%s (%s)", session_id, exc)
    logger.debug("delete_all_sessions: requested=%d deleted=%d", len(session_ids), deleted)
    return deleted


def iter_all_session_paths() -> list[Path]:
    """Every session's JSON file, legacy flat storage plus every indexed project folder — the
    single place that knows both locations, so callers never scan data/sessions/ directly."""
    paths = list(SESSIONS_DIR.glob("*.json")) if SESSIONS_DIR.exists() else []
    for folder in _load_index().values():
        candidate = Path(folder) / _SESSION_FILENAME
        if candidate.exists():
            paths.append(candidate)
    return paths


def get_session_folder(session_id: str) -> str | None:
    """The real on-disk project folder for a session, for display purposes — None for sessions
    that predate the project-folder model (legacy data/sessions/ storage, no index entry)."""
    return _load_index().get(session_id)
