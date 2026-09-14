"""main.py's _mark_orphaned_sessions_interrupted (runs on every app startup): a real incident where
one session's file was persistently locked (something else had it open, outlasting save_session's
own bounded retry -- sessions/store.py's _replace_with_retry) and the resulting PermissionError
propagated all the way up through this startup handler, crashing the entire app before it could
serve a single request. One uncooperative file must never be able to take the whole app -- or any
other session's own recovery -- down with it.
"""
import main
import pytest
from projects import paths as project_paths
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()


def test_orphaned_session_gets_marked_interrupted(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = store.create_session("example.com", name="Orphaned project")
        session = store.load_session(session_id)
        session["status"] = "processing"
        store.save_session(session_id, session)

        main._mark_orphaned_sessions_interrupted()

        reloaded = store.load_session(session_id)
        assert reloaded["status"] == "interrupted"
        assert reloaded["resumable_from"]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_reconcile_orphaned_chat_threads_sweep_clears_a_stuck_pending_thread(tmp_path, monkeypatch):
    """A chat thread's own pending=True can outlive the process that was running its background
    turn regardless of the SESSION's own status -- status="completed" here (not in
    _ORPHANABLE_STATUSES, so _mark_orphaned_sessions_interrupted's own sweep would never touch it)
    is exactly the case that sweep misses and _reconcile_orphaned_chat_threads_sweep exists for.
    Real, confirmed incident: an operator's Stop click and resent follow-ups all silently piled up
    against a thread stuck this way, with nothing left alive to ever react to either."""
    _isolate(tmp_path, monkeypatch)
    try:
        session_id = store.create_session("example.com", name="Stuck chat project")
        session = store.load_session(session_id)
        session["status"] = "completed"
        session["chat_threads"] = [{
            "id": "thread_1", "title": "Chat", "summary": "", "pending": True,
            "queued_messages": [{"id": "q1", "text": "still there?", "at": "2026-01-01T00:00:00+00:00"}],
            "messages": [{"role": "user", "at": "2026-01-01T00:00:00+00:00", "segments": [{"type": "text", "content": "hi"}]}],
            "provider": None, "model": None, "created_at": "2026-01-01T00:00:00+00:00", "updated_at": "2026-01-01T00:00:00+00:00",
        }]
        session["active_chat_thread_id"] = "thread_1"
        store.save_session(session_id, session)

        main._reconcile_orphaned_chat_threads_sweep()

        reloaded = store.load_session(session_id)
        assert reloaded["status"] == "completed"  # untouched -- this sweep never rewrites session status
        thread = reloaded["chat_threads"][0]
        assert thread["pending"] is False
        assert thread["queued_messages"] == []
        assert thread["messages"][-1]["segments"][-1]["error"] is True
        assert "Interrupted" in thread["messages"][-1]["segments"][-1]["content"]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_one_locked_session_does_not_block_recovery_of_the_others_or_crash_startup(tmp_path, monkeypatch):
    """The actual real incident: session A's save_session() raises OSError (a persistent Windows
    file lock) -- this must not propagate out of _mark_orphaned_sessions_interrupted (which would
    crash the whole app at startup), and session B must still get recovered normally."""
    _isolate(tmp_path, monkeypatch)
    try:
        locked_id = store.create_session("example.com", name="Locked project")
        locked_session = store.load_session(locked_id)
        locked_session["status"] = "processing"
        store.save_session(locked_id, locked_session)

        healthy_id = store.create_session("other.example.com", name="Healthy project")
        healthy_session = store.load_session(healthy_id)
        healthy_session["status"] = "awaiting_approval"
        store.save_session(healthy_id, healthy_session)

        real_save_session = main.save_session

        def flaky_save_session(session_id, data):
            if session_id == locked_id:
                raise PermissionError("simulated persistent Windows file lock")
            return real_save_session(session_id, data)

        monkeypatch.setattr(main, "save_session", flaky_save_session)

        main._mark_orphaned_sessions_interrupted()  # must not raise

        # The locked session is left exactly as it was -- not silently marked "interrupted"
        # without the write actually having happened, and not left in a half-updated state.
        assert store.load_session(locked_id)["status"] == "processing"
        # The other, unaffected session still got recovered normally.
        assert store.load_session(healthy_id)["status"] == "interrupted"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_orphaned_session_recovery_kills_a_real_orphaned_background_job(tmp_path, monkeypatch):
    """A background job (e.g. Hydra) still "running" when the process orphaning its OWN session
    also orphans that job -- its real OS process is not guaranteed to die just because its parent
    did. The startup sweep must reconcile it for real, not just rewrite the status, or a genuine
    brute-force run against a real target keeps going completely untracked."""
    import os
    import subprocess
    import sys

    _isolate(tmp_path, monkeypatch)
    try:
        session_id = store.create_session("example.com", name="Orphaned background job project")
        session = store.load_session(session_id)
        session["status"] = "processing"
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        try:
            session["background_jobs"] = {"job1": {"tool": "hydra", "status": "running", "pid": proc.pid}}
            store.save_session(session_id, session)

            main._mark_orphaned_sessions_interrupted()

            reloaded = store.load_session(session_id)
            assert reloaded["status"] == "interrupted"
            assert reloaded["background_jobs"]["job1"]["status"] == "interrupted"
            proc.wait(timeout=5)  # this test is the real parent -- reap before checking liveness
            with pytest.raises(OSError):
                os.kill(proc.pid, 0)  # the real process is actually gone, not just relabeled
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
