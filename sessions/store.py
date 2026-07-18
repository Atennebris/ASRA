"""File-based session storage: create_session/load_session/save_session, atomic writes."""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from agent.utils.logger import get_logger

logger = get_logger("SESSION")

SESSIONS_DIR = Path("data/sessions")


def _session_path(session_id: str) -> Path:
    return SESSIONS_DIR / f"{session_id}.json"


def create_session(target: str) -> str:
    session_id = f"usr_{secrets.token_hex(3)}"
    session = {
        "session_id": session_id,
        "target": target,
        "status": "pending",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "logs": [],
        "findings": [],
    }
    save_session(session_id, session)
    logger.debug("create_session: id=%s target=%s", session_id, target)
    return session_id


def load_session(session_id: str) -> dict | None:
    path = _session_path(session_id)
    if not path.exists():
        return None

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_session(session_id: str, data: dict) -> None:
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    path = _session_path(session_id)
    tmp_path = path.with_suffix(".json.tmp")

    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path)

    logger.debug(
        "save_session: id=%s status=%s findings=%d logs=%d",
        session_id,
        data.get("status"),
        len(data.get("findings", [])),
        len(data.get("logs", [])),
    )
