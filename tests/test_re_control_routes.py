"""Reverse Engineering mode's Start/Pause/Stop/Resume/Re-scan control bar routes.

Real, confirmed incident these tests lock in: an operator started a baseline triage pass, it
finished on its own in the background, but the control bar (a static block back then) kept showing
the now-meaningless Stop button. Clicking that stale Stop hit /re-triage/stop on an already-
completed session, which answered with a raw HTTPException(400) JSON body -- and because the button
is a plain (non-htmx) form submit, the desktop webview rendered that {"detail": ...} as a whole-page
dead-end. Two halves of the fix, both covered here:
  * The stop/pause/resume/rescan routes are now idempotent -- a stale click on an already-halted (or
    already-running) pass redirects back to the session page instead of raising 400.
  * A new GET /re-triage/controls route re-renders the control bar so the poll on re_control_bar.html
    can swap the stale Stop for the terminal buttons live, before the operator ever clicks it.
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


def _re_session(status):
    session_id = create_session("firmware.bin", name="RE project", mode="reverse_engineering")
    session = load_session(session_id)
    session["status"] = status
    store.save_session(session_id, session)
    return session_id


def test_stop_is_idempotent_on_an_already_completed_pass(tmp_path, monkeypatch):
    """The exact incident: Stop on a completed session must NOT 400 -- it redirects back to the
    page (the operator's desired end state, "not running", is already true)."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("completed")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-triage/stop", follow_redirects=False)
        assert resp.status_code == 303
        assert resp.headers["location"].rstrip("/").endswith(f"/session/{session_id}")
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_pause_is_idempotent_on_an_already_completed_pass(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("completed")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-triage/pause", follow_redirects=False)
        assert resp.status_code == 303
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_resume_redirects_instead_of_400_when_not_resumable(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("completed")  # completed is not a resumable state
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-triage/resume", follow_redirects=False)
        assert resp.status_code == 303
        # No-op: the completed session was not flipped to pending.
        assert load_session(session_id)["status"] == "completed"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_rescan_redirects_instead_of_400_when_not_completed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = _re_session("processing")  # rescan requires completed
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-triage/rescan", follow_redirects=False)
        assert resp.status_code == 303
        # No-op: the running session was not disturbed.
        assert load_session(session_id)["status"] == "processing"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_stop_still_actually_signals_a_running_pass(tmp_path, monkeypatch):
    """Idempotence must not have neutered the real Stop: a genuinely running pass still records the
    stop intent and fires request_session_stop."""
    _isolate(tmp_path, monkeypatch)
    try:
        calls = {"stop": [], "intent": []}
        monkeypatch.setattr(main, "request_session_stop", lambda sid: calls["stop"].append(sid))
        monkeypatch.setattr(main, "set_re_stop_intent", lambda sid, intent: calls["intent"].append((sid, intent)))
        session_id = _re_session("processing")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/re-triage/stop", follow_redirects=False)
        assert resp.status_code == 303
        assert calls["stop"] == [session_id]
        assert calls["intent"] == [(session_id, "stop")]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_stop_pause_resume_rescan_all_tag_their_debug_log_line_with_the_session(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (123321123321222222-usr_3cb010): every one of this
    file's own control-bar routes logged via a bare logger.debug with no current_session_id set,
    so the click landed only in the GLOBAL debug.log, never that session's own project-folder log
    -- a log-review pass of one specific session could never confirm from ITS OWN debug.log
    whether the operator's Stop/Pause/Resume/Rescan click actually reached the server."""
    from agent.utils.debug import current_session_id

    _isolate(tmp_path, monkeypatch)
    try:
        seen_session_ids = []
        monkeypatch.setattr(main, "request_session_stop", lambda sid: None)
        monkeypatch.setattr(main, "set_re_stop_intent", lambda sid, intent: None)
        monkeypatch.setattr(main, "_run_re_triage_task", lambda *a, **k: None)
        original_debug = main.logger.debug

        def _capturing_debug(*args, **kwargs):
            seen_session_ids.append(current_session_id.get())
            return original_debug(*args, **kwargs)

        monkeypatch.setattr(main.logger, "debug", _capturing_debug)
        client = TestClient(main.app)

        running = _re_session("processing")
        client.post(f"/api/session/{running}/re-triage/stop", follow_redirects=False)
        paused = _re_session("processing")
        client.post(f"/api/session/{paused}/re-triage/pause", follow_redirects=False)
        resumable = _re_session("paused")
        client.post(f"/api/session/{resumable}/re-triage/resume", follow_redirects=False)
        completed = _re_session("completed")
        client.post(f"/api/session/{completed}/re-triage/rescan", follow_redirects=False)

        # current_session_id must be unset again right after each call (reset in finally) --
        # never leaked to whatever logs next in this same process.
        assert current_session_id.get() is None
        assert running in seen_session_ids
        assert paused in seen_session_ids
        assert resumable in seen_session_ids
        assert completed in seen_session_ids
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_controls_fragment_polls_while_running_and_stops_when_done(tmp_path, monkeypatch):
    """The live-update half: the control bar carries hx-trigger while the pass runs (so it keeps
    polling and swaps in the terminal buttons the moment the pass ends), and drops hx-trigger once
    terminal (so htmx stops polling) -- same self-terminating pattern re_triage_stage uses."""
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)

        running = _re_session("processing")
        resp = client.get(f"/api/session/{running}/re-triage/controls")
        assert resp.status_code == 200
        assert 'hx-trigger="every 3s"' in resp.text
        assert "/re-triage/stop" in resp.text

        done = _re_session("completed")
        resp = client.get(f"/api/session/{done}/re-triage/controls")
        assert resp.status_code == 200
        assert 'hx-trigger="every 3s"' not in resp.text
        assert "/re-triage/rescan" in resp.text  # terminal buttons, no stale Stop
        assert "/re-triage/stop" not in resp.text
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_controls_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.get("/api/session/usr_nope/re-triage/controls")
        assert resp.status_code == 404
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
