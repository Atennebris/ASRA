"""Operator-supplied filesystem paths for optional interpreters/compilers (Settings -> Optional
interpreters/compilers -> "specify path"), for the case a capability is installed somewhere PATH
doesn't cover -- a non-standard python2 build, for instance. Same load/atomic-write shape as
agent/settings.py's own data/llm_settings.json, a separate file since this is a different concern
(local tool paths, not LLM provider config) that happens to want the exact same persistence pattern.

data/tool_paths.json holds local filesystem paths only, nothing secret -- still gitignored
alongside every other data/*.json runtime file (see .gitignore), same public-safety discipline
applied whether or not the content actually turns out sensitive.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
TOOL_PATHS_PATH = resolve_global_app_dir() / "data" / "tool_paths.json"


def load_tool_paths() -> dict[str, str]:
    if not TOOL_PATHS_PATH.exists():
        return {}
    try:
        with TOOL_PATHS_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("tool_paths: unreadable (%s) -- treating as unset", exc)
        return {}
    return data if isinstance(data, dict) else {}


def save_tool_path(capability_id: str, path: str) -> None:
    existing = load_tool_paths()
    clean_path = path.strip()
    if clean_path:
        existing[capability_id] = clean_path
    else:
        existing.pop(capability_id, None)
    TOOL_PATHS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = TOOL_PATHS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    os.replace(tmp_path, TOOL_PATHS_PATH)
    logger.debug("tool_paths: capability=%s path=%r saved", capability_id, clean_path or None)


def resolve_interpreter_path(capability_id: str) -> str | None:
    """The saved override, if set and it still actually exists on disk, else whatever's on PATH --
    used for real by exploit_db_run to pick the interpreter it runs, not just a Settings-page
    status display. A stale override (the operator moved/removed the binary since saving it) falls
    back to PATH rather than failing outright, same "don't trust stale config blindly" instinct as
    agent/settings.py's own fallback to .env when a saved provider/model has since disappeared.
    """
    override = load_tool_paths().get(capability_id)
    if override and Path(override).exists():
        return override
    return shutil.which(capability_id)


def get_capability_status(capability_id: str) -> dict:
    """Feeds the Settings row: whether this capability is available right now, where from."""
    override = load_tool_paths().get(capability_id)
    if override and Path(override).exists():
        return {"installed": True, "path": override, "source": "override"}
    found = shutil.which(capability_id)
    if found:
        return {"installed": True, "path": found, "source": "path"}
    return {"installed": False, "path": None, "source": None}
