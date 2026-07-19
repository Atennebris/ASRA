"""Smoke tests (4.4.1): starting a session creates a real file, and its JSON structure is valid."""
import json
import re

import pytest

from sessions import store


@pytest.fixture(autouse=True)
def _isolated_sessions_dir(tmp_path, monkeypatch):
    """Every test gets its own throwaway directory — never touches the real data/sessions/."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    return tmp_path


def test_create_session_writes_a_real_file(_isolated_sessions_dir):
    session_id = store.create_session("example.com")
    assert (_isolated_sessions_dir / f"{session_id}.json").exists()


def test_create_session_id_shape():
    session_id = store.create_session("example.com")
    assert re.fullmatch(r"usr_[0-9a-f]{6}", session_id)


def test_create_session_json_structure_is_valid(_isolated_sessions_dir):
    session_id = store.create_session("example.com")
    with (_isolated_sessions_dir / f"{session_id}.json").open() as f:
        data = json.load(f)

    assert data == {
        "session_id": session_id,
        "target": "example.com",
        "status": "pending",
        "created_at": data["created_at"],  # presence/format checked separately below
        "logs": [],
        "findings": [],
        "approvals": [],
    }
    # ISO 8601 with timezone — datetime.fromisoformat round-trips it without raising.
    from datetime import datetime

    datetime.fromisoformat(data["created_at"])


def test_load_session_returns_none_for_unknown_id():
    assert store.load_session("usr_ffffff") is None


def test_load_session_round_trips_after_save():
    session_id = store.create_session("example.com")
    store.save_session(session_id, {**store.load_session(session_id), "status": "completed"})

    reloaded = store.load_session(session_id)
    assert reloaded["status"] == "completed"
    assert reloaded["session_id"] == session_id


def test_save_session_leaves_no_temp_file_behind(_isolated_sessions_dir):
    session_id = store.create_session("example.com")
    store.save_session(session_id, store.load_session(session_id))

    leftover_tmp_files = list(_isolated_sessions_dir.glob("*.json.tmp"))
    assert leftover_tmp_files == []
