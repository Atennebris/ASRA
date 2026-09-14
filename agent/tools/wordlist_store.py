"""Persistent storage for the wordlist catalog's user-facing state: wordlists the operator
downloaded through the Settings UI (agent/tools/wordlist_catalog.py only ever detects what's
*already* on disk -- it has no memory of where a file came from), and which wordlist each tool
role should actually use. Same on-disk convention as agent/tools/allowed_targets.py
(load/_write pair, atomic tmp-file + os.replace, empty/corrupt file treated as "nothing stored
yet" rather than an error).

Kept in its own file (data/wordlist_assignments.json) rather than folded into any per-tool
config -- this is app-level state (spans every session/project), same category as
allowed_targets.json/llm_settings.json.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
WORDLIST_STORE_PATH = resolve_global_app_dir() / "data" / "wordlist_assignments.json"

# Every tool/role that can consult an assigned wordlist instead of its own hardcoded default --
# see agent/tools/builders/ffuf.py, agent/tools/native.py's arjun_probe/hydra_start/
# web_login_bruteforce_start for where each of these is actually read (wiring done once this
# store exists to wire against).
ASSIGNABLE_ROLES = (
    "ffuf",
    "arjun",
    "hydra_usernames",
    "hydra_passwords",
    "web_login_bruteforce_usernames",
    "web_login_bruteforce_passwords",
    "subdomain_enum",
)

_DEFAULT_STORE = {"downloaded": [], "assignments": {}}


def load_wordlist_store() -> dict:
    if not WORDLIST_STORE_PATH.exists():
        return {"downloaded": [], "assignments": {}}

    try:
        with WORDLIST_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("wordlist_assignments.json unreadable (%s) — treating as empty store", exc)
        return {"downloaded": [], "assignments": {}}

    if not isinstance(data, dict):
        logger.debug("wordlist_assignments.json does not contain an object — treating as empty store")
        return {"downloaded": [], "assignments": {}}

    downloaded = data.get("downloaded")
    assignments = data.get("assignments")
    return {
        "downloaded": downloaded if isinstance(downloaded, list) else [],
        "assignments": assignments if isinstance(assignments, dict) else {},
    }


def _write_wordlist_store(data: dict) -> None:
    WORDLIST_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = WORDLIST_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, WORDLIST_STORE_PATH)


def add_downloaded_wordlist(path: str, name: str, source_url: str, kind: str) -> dict:
    """Registers metadata for a wordlist the operator just downloaded (agent/tools/wordlist_catalog.py
    only sees the file itself -- it has no idea where it came from). Re-downloading the same path
    updates its metadata in place rather than appending a duplicate entry."""
    store = load_wordlist_store()
    entry = {
        "path": path, "name": name, "source_url": source_url, "kind": kind,
        "added_at": time.time(),
    }
    store["downloaded"] = [d for d in store["downloaded"] if d.get("path") != path]
    store["downloaded"].append(entry)
    _write_wordlist_store(store)
    logger.debug("wordlist_store: registered downloaded wordlist %r (kind=%s)", path, kind)
    return store


def set_assignment(role: str, path: str | None) -> dict:
    """path=None clears the assignment (the tool falls back to its own built-in default again)."""
    if role not in ASSIGNABLE_ROLES:
        raise ValueError(f"role must be one of {ASSIGNABLE_ROLES}, got {role!r}")

    store = load_wordlist_store()
    if path:
        store["assignments"][role] = path
    else:
        store["assignments"].pop(role, None)
    _write_wordlist_store(store)
    logger.debug("wordlist_store: assignment for role=%s set to %r", role, path)
    return store


def get_assigned_wordlist(role: str) -> str | None:
    """The single read path every tool wires against (task: agent/tools/builders/ffuf.py,
    agent/tools/native.py). Returns None (not an error) if nothing is assigned or the assigned
    file no longer exists on disk -- a stale assignment (the file got deleted/moved outside this
    app) must fall back to the tool's own built-in default, never raise."""
    store = load_wordlist_store()
    path = store["assignments"].get(role)
    if path and Path(path).exists():
        return path
    return None
