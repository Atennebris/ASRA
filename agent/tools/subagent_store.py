"""Persistent storage for Subagent profiles -- named, pre-configured worker profiles (own
allowed-tool list, own instructions/personality, own LLM provider/model) the main agent can
delegate a bounded sub-task to via agent/tools/subagent_tasks.py's delegate_to_subagent, without
blocking its own work. Same on-disk convention as agent/tools/wordlist_store.py (load/_write pair,
atomic tmp-file + os.replace, empty/corrupt file treated as "nothing stored yet" rather than an
error) -- app-level state (spans every session/project), not tied to one session's own schema.

Ships with exactly one default profile, disabled, so the Subagents settings tab is never empty on
a fresh install -- it only actually gets written to data/subagent_profiles.json once the operator
makes a real change (add/update/delete); until then, load_subagent_profiles() returns this seed
value from memory alone.
"""
from __future__ import annotations

import json
import os
import uuid

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("SUBAGENT")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
SUBAGENT_STORE_PATH = resolve_global_app_dir() / "data" / "subagent_profiles.json"

_DEFAULT_PROFILE = {
    "id": "default",
    "name": "Default Subagent",
    "enabled": False,
    "allowed_tools": [],
    "instructions": "",
    "provider": None,
    "model": None,
    "icon": "robot",
    "icon_color": "#60a5fa",
}


def load_subagent_profiles() -> dict:
    if not SUBAGENT_STORE_PATH.exists():
        return {"profiles": [dict(_DEFAULT_PROFILE)]}

    try:
        with SUBAGENT_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("subagent_profiles.json unreadable (%s) — treating as the default seed", exc)
        return {"profiles": [dict(_DEFAULT_PROFILE)]}

    if not isinstance(data, dict):
        logger.debug("subagent_profiles.json does not contain an object — treating as the default seed")
        return {"profiles": [dict(_DEFAULT_PROFILE)]}

    profiles = data.get("profiles")
    return {"profiles": profiles if isinstance(profiles, list) else [dict(_DEFAULT_PROFILE)]}


def _write_subagent_profiles(data: dict) -> None:
    SUBAGENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SUBAGENT_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, SUBAGENT_STORE_PATH)


def add_profile(
    name: str, allowed_tools: list[str], instructions: str, provider: str | None, model: str | None,
    icon: str | None = None, icon_color: str | None = None,
) -> dict:
    store = load_subagent_profiles()
    profile = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "enabled": False,
        "allowed_tools": list(allowed_tools),
        "instructions": instructions,
        "provider": provider,
        "model": model,
        "icon": icon,
        "icon_color": icon_color,
    }
    store["profiles"].append(profile)
    _write_subagent_profiles(store)
    logger.debug("subagent_store: added profile id=%s name=%r", profile["id"], name)
    return store


def update_profile(profile_id: str, **fields) -> dict:
    """fields may include any of name/enabled/allowed_tools/instructions/provider/model/icon/
    icon_color -- unrecognized keys are ignored rather than raising, same tolerance as the rest of
    this project's "accept a real-world variant" discipline (a caller passing an extra, harmless
    key shouldn't have to know this function's exact whitelist to avoid an error)."""
    allowed_fields = {"name", "enabled", "allowed_tools", "instructions", "provider", "model", "icon", "icon_color"}
    store = load_subagent_profiles()
    for profile in store["profiles"]:
        if profile["id"] == profile_id:
            for key, value in fields.items():
                if key in allowed_fields:
                    profile[key] = value
            break
    else:
        raise ValueError(f"unknown subagent profile id {profile_id!r}")
    _write_subagent_profiles(store)
    logger.debug("subagent_store: updated profile id=%s fields=%s", profile_id, sorted(fields))
    return store


def delete_profile(profile_id: str) -> dict:
    store = load_subagent_profiles()
    store["profiles"] = [p for p in store["profiles"] if p["id"] != profile_id]
    _write_subagent_profiles(store)
    logger.debug("subagent_store: deleted profile id=%s", profile_id)
    return store


def get_enabled_profiles(allowed_ids: list[str] | None = None) -> list[dict]:
    """Every globally-enabled Subagent profile (Subagents settings tab), optionally narrowed to
    just the ids one specific project chose to grant access to (New Project form's per-project
    picker, session["enabled_subagent_ids"] -- see sessions/store.py's create_session docstring
    for that field). allowed_ids=None means no restriction at all -- every caller that predates
    the per-project picker (and every session created before it existed) keeps seeing every
    globally-enabled profile exactly as before. An explicit (possibly empty) list means a specific
    project narrowed it down -- checked against enabled profiles only, so a profile disabled
    globally after a project picked it never comes back just because that project's own list still
    names its id."""
    profiles = [p for p in load_subagent_profiles()["profiles"] if p.get("enabled")]
    if allowed_ids is None:
        return profiles
    allowed = set(allowed_ids)
    return [p for p in profiles if p.get("id") in allowed]


def get_profile_by_name(name: str, allowed_ids: list[str] | None = None) -> dict | None:
    """delegate_to_subagent's own lookup key is the operator-chosen name, not the internal id --
    the model names the subagent it wants by the same name shown to it, never an id it never saw.
    allowed_ids is the same per-project narrowing get_enabled_profiles() takes -- a subagent must
    be both globally enabled AND (when the project restricts it) in that project's own allowlist
    to ever be delegated to."""
    return next((p for p in get_enabled_profiles(allowed_ids) if p.get("name") == name), None)


def import_profiles(incoming: dict, source_label: str = "import") -> int:
    """Merges an exported/portable profile pack ({"profiles": [profile, ...]}) into the store,
    appending only profiles whose id isn't already present -- same "dedup by id, re-importing never
    duplicates" discipline as playbook_store.import_entries. Malformed shapes are skipped, never
    raised -- an operator's own upload shouldn't be able to crash the app.

    Every imported profile lands disabled regardless of what the source file says, exactly like a
    freshly hand-added one (add_profile) -- an imported profile's allowed_tools/provider may not
    match what's actually installed/configured on THIS machine, so it must be reviewed and
    explicitly turned on here, never silently active the moment the import completes."""
    if not isinstance(incoming, dict):
        return 0
    profiles = incoming.get("profiles")
    if not isinstance(profiles, list):
        return 0
    store = load_subagent_profiles()
    existing_ids = {p.get("id") for p in store["profiles"]}
    added = 0
    for profile in profiles:
        if not isinstance(profile, dict) or not str(profile.get("name", "")).strip():
            continue
        pid = str(profile.get("id") or uuid.uuid4().hex[:12])
        if pid in existing_ids:
            continue
        store["profiles"].append({
            "id": pid,
            "name": str(profile.get("name", "")).strip(),
            "enabled": False,
            "allowed_tools": list(profile.get("allowed_tools") or []),
            "instructions": str(profile.get("instructions") or ""),
            "provider": profile.get("provider") or None,
            "model": profile.get("model") or None,
            "icon": profile.get("icon") or None,
            "icon_color": profile.get("icon_color") or None,
        })
        existing_ids.add(pid)
        added += 1
    if added:
        _write_subagent_profiles(store)
    logger.debug("subagent_store: imported %d profile(s) from %s", added, source_label)
    return added
