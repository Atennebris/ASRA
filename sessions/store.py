"""File-based session storage: create_session/load_session/save_session, atomic writes.

Every new session gets its own real, user-visible project folder (see projects/paths.py) instead
of being just another anonymous file in data/sessions/ — the same "one project = one folder"
model as the desktop reference this UI is modeled after. A lightweight index
(data/sessions_index.json) maps session_id -> that folder so lookups don't need to search the
whole Documents tree. Sessions created before this existed have no index entry; _session_path()
falls back to the legacy flat data/sessions/<id>.json for them, untouched.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
from datetime import datetime, timezone
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_projects_base_dir

logger = get_logger("SESSION")

SESSIONS_DIR = Path("data/sessions")
INDEX_PATH = Path("data/sessions_index.json")

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
    duplicate project name before create_session() ever runs, not after."""
    needle = name.strip().lower()
    for path in iter_all_session_paths():
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if data.get("name", "").strip().lower() == needle:
            return True
    return False


def create_session(target: str, name: str | None = None) -> str:
    session_id = f"usr_{secrets.token_hex(3)}"
    resolved_name = name or target
    _create_project_folder(session_id, resolved_name)

    session = {
        "session_id": session_id,
        "name": resolved_name,
        "target": target,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "logs": [],
        "findings": [],
        "approvals": [],
        "chat": {"summary": "", "messages": []},
    }
    save_session(session_id, session)
    logger.debug("create_session: id=%s name=%s target=%s", session_id, resolved_name, target)
    return session_id


def load_session(session_id: str) -> dict | None:
    path = _session_path(session_id)
    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_session(session_id: str, data: dict) -> None:
    path = _session_path(session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")

    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)

    logger.debug(
        "save_session: id=%s status=%s findings=%d logs=%d path=%s",
        session_id,
        data.get("status"),
        len(data.get("findings", [])),
        len(data.get("logs", [])),
        path,
    )


def delete_session(session_id: str) -> bool:
    """Removes a session's project folder (if it has one) plus the legacy flat file and index
    entry — whichever of those actually exist for this id. Returns False when nothing was found,
    so the route can 404 instead of pretending the delete did something."""
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

    logger.debug("delete_session: id=%s folder=%s found=%s", session_id, project_dir, found)
    return found


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
