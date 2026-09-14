"""main.py's fleet-mode routes (/api/session/{id}/enqueue, /api/fleet/{id}/dequeue, GET /fleet)
plus _fleet_worker_loop -- the background task that actually starts a queued project once real
capacity frees up. See tests/test_fleet_store.py for the underlying queue's own pure unit tests.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.tools import fleet_store
from fastapi.testclient import TestClient
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(fleet_store, "FLEET_QUEUE_PATH", tmp_path / "fleet_queue.json")


def _base_session(session_id, **overrides):
    session = {
        "session_id": session_id, "name": session_id, "target": "example.com", "status": "created",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


# --- /api/session/{id}/enqueue -------------------------------------------------------------------


def test_enqueue_route_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_missing/enqueue", follow_redirects=False)

    assert resp.status_code == 404


def test_enqueue_route_400s_for_a_session_that_already_started(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store.save_session("usr_a", _base_session("usr_a", status="processing"))
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_a/enqueue", follow_redirects=False)

    assert resp.status_code == 400
    assert fleet_store.load_fleet_queue() == []


def test_enqueue_route_queues_a_created_session_and_redirects_to_fleet(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store.save_session("usr_a", _base_session("usr_a"))
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_a/enqueue", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/fleet"
    assert fleet_store.load_fleet_queue() == ["usr_a"]
    # The project itself is untouched -- still "created", not silently flipped to "pending" just
    # by being queued (that only happens once the worker actually claims and starts it).
    assert store.load_session("usr_a")["status"] == "created"


# --- /api/fleet/{id}/dequeue ----------------------------------------------------------------------


def test_dequeue_route_404s_when_not_queued(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/fleet/usr_missing/dequeue", follow_redirects=False)

    assert resp.status_code == 404


def test_dequeue_route_removes_a_queued_entry_and_redirects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    fleet_store.enqueue_session("usr_a")
    client = TestClient(main.app)

    resp = client.post("/api/fleet/usr_a/dequeue", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/fleet"
    assert fleet_store.load_fleet_queue() == []


# --- GET /fleet ------------------------------------------------------------------------------------


def test_fleet_page_renders_empty_state(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/fleet")

    assert resp.status_code == 200
    assert "Fleet" in resp.text
    assert "Nothing queued" in resp.text
    assert "Nothing running" in resp.text


def test_fleet_page_shows_queued_and_running_sessions(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store.save_session("usr_queued", _base_session("usr_queued", name="Queued Project"))
    store.save_session("usr_running", _base_session("usr_running", name="Running Project", status="processing"))
    fleet_store.enqueue_session("usr_queued")
    client = TestClient(main.app)

    resp = client.get("/fleet")

    assert "Queued Project" in resp.text
    assert "Running Project" in resp.text


# --- _fleet_worker_loop -----------------------------------------------------------------------


def _run_one_tick(monkeypatch):
    """Runs _fleet_worker_loop for long enough to complete exactly one iteration of its own body,
    then cancels it -- the loop itself never terminates on its own (by design, it runs for the
    server's whole lifetime), so a real test can't just await it to completion."""
    monkeypatch.setattr(main, "_FLEET_POLL_INTERVAL_SECONDS", 100)  # never actually reached here

    async def _drive():
        task = asyncio.create_task(main._fleet_worker_loop())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(_drive())


def test_worker_starts_a_queued_session_when_capacity_is_free(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("FLEET_MAX_CONCURRENT_SESSIONS", "3")
    store.save_session("usr_a", _base_session("usr_a"))
    fleet_store.enqueue_session("usr_a")

    started = []

    async def fake_run_session_task(session_id, provider_id, entry_point="recon"):
        started.append(session_id)

    monkeypatch.setattr(main, "_run_session_task", fake_run_session_task)

    _run_one_tick(monkeypatch)

    assert started == ["usr_a"]
    assert store.load_session("usr_a")["status"] == "pending"
    assert fleet_store.load_fleet_queue() == []


def test_worker_does_not_start_anything_when_already_at_capacity(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("FLEET_MAX_CONCURRENT_SESSIONS", "1")
    store.save_session("usr_running", _base_session("usr_running", status="processing"))
    store.save_session("usr_queued", _base_session("usr_queued"))
    fleet_store.enqueue_session("usr_queued")

    async def _fail_if_called(session_id, provider_id, entry_point="recon"):
        raise AssertionError("must not start a new session while already at capacity")

    monkeypatch.setattr(main, "_run_session_task", _fail_if_called)

    _run_one_tick(monkeypatch)

    assert fleet_store.load_fleet_queue() == ["usr_queued"]  # left untouched
    assert store.load_session("usr_queued")["status"] == "created"


def test_worker_skips_a_queue_entry_whose_session_was_deleted(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("FLEET_MAX_CONCURRENT_SESSIONS", "3")
    fleet_store.enqueue_session("usr_deleted")  # no matching session.json ever saved

    async def _fail_if_called(session_id, provider_id, entry_point="recon"):
        raise AssertionError("must not try to start a session that no longer exists")

    monkeypatch.setattr(main, "_run_session_task", _fail_if_called)

    _run_one_tick(monkeypatch)  # must not raise

    assert fleet_store.load_fleet_queue() == []  # still removed from the queue, not retried forever
