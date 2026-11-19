"""In-session change of a Reverse Engineering project's experience level
(session["re_experience_level"], set at creation by main.py's start_re, now also changeable
mid-engagement via POST /api/session/{id}/re-experience-level).

The level is consumed per-turn by agent/core.py's _re_experience_level_addendum, which reads it
fresh from the session each chat/triage turn -- so persisting it here is the whole live mechanism;
these tests lock in the persistence + validation, which is all this route owns.
"""
from fastapi.testclient import TestClient

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.tools import allowed_targets, native
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    monkeypatch.setattr(main, "_CREDENTIALS_DIR", tmp_path / "credentials")


def _re_session(level="hobbyist"):
    session_id = create_session("firmware.bin", name="RE project", mode="reverse_engineering", re_experience_level=level)
    return session_id


def test_valid_level_updates_and_persists(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("hobbyist")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-experience-level", data={"re_experience_level": "professional"})
        assert resp.status_code == 200
        # Reloaded from disk -- the change was actually persisted, not just held in memory.
        assert load_session(session_id)["re_experience_level"] == "professional"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_every_known_level_is_accepted(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("hobbyist")
        client = TestClient(main.app)
        for level in ("novice", "hobbyist", "professional"):
            resp = client.post(f"/api/session/{session_id}/re-experience-level", data={"re_experience_level": level})
            assert resp.status_code == 200
            assert load_session(session_id)["re_experience_level"] == level
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_invalid_level_is_rejected_and_current_kept(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("hobbyist")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-experience-level", data={"re_experience_level": "expert"})
        # Not an error to the caller -- just ignored, current level untouched.
        assert resp.status_code == 200
        assert load_session(session_id)["re_experience_level"] == "hobbyist"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_empty_value_is_rejected_and_current_kept(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("professional")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-experience-level", data={"re_experience_level": ""})
        assert resp.status_code == 200
        assert load_session(session_id)["re_experience_level"] == "professional"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_non_re_session_is_a_noop(tmp_path, monkeypatch):
    """The field is meaningful in Reverse Engineering mode only -- a post against another mode's
    session must not change its re_experience_level (create_session stamps the neutral "hobbyist"
    default on every mode, so the proof is that the post leaves that default untouched)."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = create_session("example.com", name="Agent project", mode="agent")
        assert load_session(session_id)["re_experience_level"] == "hobbyist"
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-experience-level", data={"re_experience_level": "professional"})
        assert resp.status_code == 200
        assert load_session(session_id)["re_experience_level"] == "hobbyist"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_unknown_session_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post("/api/session/usr_nope/re-experience-level", data={"re_experience_level": "novice"})
        assert resp.status_code == 404
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_change_is_tagged_with_the_session_in_debug_log(tmp_path, monkeypatch):
    """The persist route tags its debug line with current_session_id (so it reaches that session's
    own project-folder debug.log), then clears it -- same discipline as the re-triage control
    routes."""
    from agent.utils.debug import current_session_id

    _isolate(tmp_path, monkeypatch)
    try:
        seen = []
        original_debug = main.logger.debug

        def _capturing_debug(*args, **kwargs):
            seen.append(current_session_id.get())
            return original_debug(*args, **kwargs)

        monkeypatch.setattr(main.logger, "debug", _capturing_debug)
        session_id = _re_session("hobbyist")
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/re-experience-level", data={"re_experience_level": "novice"})
        assert current_session_id.get() is None  # reset in finally, never leaked
        assert session_id in seen
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
