"""Smoke tests: starting a session creates a real file, and its JSON structure is valid.

Every session now gets its own project folder (sessions/store.py + projects/paths.py) instead of
a flat data/sessions/<id>.json — these tests redirect all three storage knobs (legacy dir, index
file, and the PROJECTS_DIR a new folder is created under) into tmp_path, so a test run never
touches the real data/sessions/ or the user's actual Documents folder.
"""
import json
import re

import pytest

from projects import paths as project_paths
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    """Every test gets its own throwaway directories — never touches real storage."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    return tmp_path


def _project_session_file(base, session_id, target="example.com"):
    folder = f"{store._sanitize_folder_name(target)}-{session_id}"
    return base / "projects" / folder / "session.json"


def test_create_session_creates_its_own_project_folder(_isolated_storage):
    session_id = store.create_session("example.com")
    assert _project_session_file(_isolated_storage, session_id).exists()


def test_create_session_id_shape(_isolated_storage):
    session_id = store.create_session("example.com")
    assert re.fullmatch(r"usr_[0-9a-f]{6}", session_id)


def test_create_session_json_structure_is_valid(_isolated_storage):
    session_id = store.create_session("example.com")
    with _project_session_file(_isolated_storage, session_id).open() as f:
        data = json.load(f)

    assert data == {
        "session_id": session_id,
        "name": "example.com",
        "target": "example.com",
        "status": "pending",
        "created_at": data["created_at"],  # presence/format checked separately below
        "logs": [],
        "findings": [],
        "approvals": [],
        "chat": {"summary": "", "messages": []},
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


def test_save_session_leaves_no_temp_file_behind(_isolated_storage):
    session_id = store.create_session("example.com")
    store.save_session(session_id, store.load_session(session_id))

    project_dir = _project_session_file(_isolated_storage, session_id).parent
    assert list(project_dir.glob("*.json.tmp")) == []


def test_create_session_falls_back_to_legacy_dir_when_project_folder_unwritable(_isolated_storage, monkeypatch):
    # Point PROJECTS_DIR at a path that can't be created (its parent is a file, not a dir) —
    # the exact kind of real-world failure (permissions, a broken override) create_session must
    # survive without losing the session entirely.
    blocked = _isolated_storage / "blocked-file"
    blocked.write_text("not a directory")
    monkeypatch.setenv("PROJECTS_DIR", str(blocked / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()

    session_id = store.create_session("example.com")

    legacy_path = (_isolated_storage / "legacy") / f"{session_id}.json"
    assert legacy_path.exists()
    assert store.load_session(session_id)["target"] == "example.com"


def test_create_session_stores_explicit_name(_isolated_storage):
    session_id = store.create_session("example.com", name="acme-pentest")
    assert store.load_session(session_id)["name"] == "acme-pentest"


def test_create_session_uses_target_as_name_when_omitted(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["name"] == "example.com"


def test_name_exists_is_case_insensitive(_isolated_storage):
    store.create_session("example.com", name="Acme Pentest")
    assert store.name_exists("acme pentest") is True
    assert store.name_exists("ACME PENTEST") is True


def test_name_exists_false_for_unused_name(_isolated_storage):
    store.create_session("example.com", name="Acme Pentest")
    assert store.name_exists("Someone Else's Project") is False


def test_iter_all_session_paths_finds_legacy_and_project_sessions(_isolated_storage):
    new_id = store.create_session("example.com")

    legacy_dir = _isolated_storage / "legacy"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "usr_legacy.json").write_text(json.dumps({
        "session_id": "usr_legacy", "target": "old.example.com", "status": "completed",
        "created_at": "2020-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
    }))

    found_ids = {p.parent.name if p.name == "session.json" else p.stem for p in store.iter_all_session_paths()}
    assert new_id in found_ids or f"{store._sanitize_folder_name('example.com')}-{new_id}" in found_ids
    assert "usr_legacy" in found_ids
