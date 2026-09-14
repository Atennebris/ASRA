"""Named string variables ({{name}}) for the MANUAL Repeater/Intruder/Racer forms only -- lets the
operator define a reusable value once (a session token, an API key, a CSRF value) and reference it
as {{name}} in the URL/headers/body instead of copy-pasting it into every send by hand. This is
the manual-toolkit equivalent of Caido's own "Environments" feature.

Substitution happens ONLY in the manual UI's own send routes (main.py's post_toolkit_repeater_send/
post_toolkit_intruder_run/post_toolkit_racer_run) -- the agent-facing tools (send_raw_request/
intruder_run/racer_run) never see or apply this at all. The agent already has its own, more
capable session/identity-aware mechanism for reused auth (native.py's authenticated_request,
user_a/user_b credentials with a real persistent cookie jar) -- this module exists purely to save
the HUMAN operator repeated copy-pasting, same "manual UI always works independently of the agent"
posture the rest of this toolkit already follows.

Same per-project-or-standalone storage shape as toolkit_store.py's own traffic.jsonl (a real
session_id's own project folder, or the standalone global app dir when session_id is None) --
atomic tmp-file + os.replace, same convention as toolkit_agent_settings.json/traffic.jsonl's own
folder resolution.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir
from sessions.store import get_session_folder

logger = get_logger("TOOLKIT")

_TOOLKIT_SUBDIR = "toolkit"
_VARIABLES_FILENAME = "variables.json"

_PLACEHOLDER_RE = re.compile(r"\{\{(\w+)\}\}")


def _variables_path(session_id: str | None) -> Path | None:
    if session_id is None:
        return resolve_global_app_dir() / _TOOLKIT_SUBDIR / _VARIABLES_FILENAME
    folder = get_session_folder(session_id)
    if not folder:
        return None
    return Path(folder) / _TOOLKIT_SUBDIR / _VARIABLES_FILENAME


def load_variables(session_id: str | None) -> dict[str, str]:
    """Every {name: value} pair stored for this session (or the standalone global store).
    Empty dict for a session with no project folder or nothing saved yet -- never raises."""
    path = _variables_path(session_id)
    if path is None or not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("toolkit_variables: unreadable store for session=%s (%s) -- treating as empty", session_id, exc)
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


def _save_variables(session_id: str | None, variables: dict[str, str]) -> bool:
    path = _variables_path(session_id)
    if path is None:
        logger.debug("toolkit_variables: no project folder for session=%s, cannot save", session_id)
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(variables, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)
    logger.debug("toolkit_variables: saved %d variable(s) for session=%s", len(variables), session_id)
    return True


def set_variable(session_id: str | None, name: str, value: str) -> dict[str, str]:
    """Adds/overwrites one variable and returns the full, up-to-date variable dict. `name` is
    trimmed of surrounding whitespace; a blank name is a no-op (returns the unchanged dict) --
    the manual "add" form has no other validation layer to catch that."""
    name = name.strip()
    variables = load_variables(session_id)
    if not name:
        return variables
    variables[name] = value
    _save_variables(session_id, variables)
    return variables


def delete_variable(session_id: str | None, name: str) -> dict[str, str]:
    variables = load_variables(session_id)
    variables.pop(name, None)
    _save_variables(session_id, variables)
    return variables


def substitute(text: str, variables: dict[str, str]) -> str:
    """Replaces every {{name}} in `text` with variables[name] -- a name with no matching entry is
    left as literal, unmodified {{name}} text (never an error): the manual toolkit is a trusted
    human operator's own tool, and silently sending a request with a genuinely undefined
    placeholder still visible in it is safer/more obvious than either guessing a value or blocking
    the send entirely."""
    if not text or "{{" not in text:
        return text
    return _PLACEHOLDER_RE.sub(lambda m: variables.get(m.group(1), m.group(0)), text)
