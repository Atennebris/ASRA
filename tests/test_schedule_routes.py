"""The schedule control's own routes (main.py: set/toggle/delete) -- each returns the re-rendered
control partial so an hx-post swaps it in place live. Pins that a POST actually persists the
schedule and that the returned HTML reflects the new state."""
import pytest
from fastapi.testclient import TestClient

import main
from agent.tools import schedule_store


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(schedule_store, "SCHEDULE_STORE_PATH", tmp_path / "schedules.json")


@pytest.fixture
def session_id():
    from sessions import store
    sid = "usr_schedule_route_test"
    store.save_session(sid, {
        "session_id": sid, "name": "sched test", "target": "https://unrelated.example",
        "status": "completed", "created_at": "2026-01-01T00:00:00+00:00",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    })
    return sid


def test_set_schedule_persists_and_renders_active(isolated_store, session_id):
    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/schedule", data={"interval": "2", "unit": "hours"})
    assert resp.status_code == 200
    saved = schedule_store.get_schedule(session_id)
    assert saved["enabled"] is True
    assert saved["interval_seconds"] == 7200
    assert "Active" in resp.text
    assert "2 hours" in resp.text


def test_toggle_pauses_then_resumes(isolated_store, session_id):
    client = TestClient(main.app)
    client.post(f"/api/session/{session_id}/schedule", data={"interval": "30", "unit": "minutes"})
    paused = client.post(f"/api/session/{session_id}/schedule/toggle")
    assert schedule_store.get_schedule(session_id)["enabled"] is False
    assert "Paused" in paused.text
    resumed = client.post(f"/api/session/{session_id}/schedule/toggle")
    assert schedule_store.get_schedule(session_id)["enabled"] is True
    assert "Active" in resumed.text


def test_toggle_without_a_schedule_is_404(isolated_store, session_id):
    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/schedule/toggle")
    assert resp.status_code == 404


def test_delete_removes_the_schedule_and_renders_the_setup_form(isolated_store, session_id):
    client = TestClient(main.app)
    client.post(f"/api/session/{session_id}/schedule", data={"interval": "1", "unit": "days"})
    resp = client.post(f"/api/session/{session_id}/schedule/delete")
    assert resp.status_code == 200
    assert schedule_store.get_schedule(session_id) is None
    assert "Enable auto-repeat" in resp.text  # back to the empty setup form


def test_set_schedule_on_a_missing_session_is_404(isolated_store):
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_does_not_exist/schedule", data={"interval": "2", "unit": "hours"})
    assert resp.status_code == 404


def test_interval_below_floor_is_raised(isolated_store, session_id, monkeypatch):
    monkeypatch.setenv("SCHEDULER_MIN_INTERVAL_SECONDS", "300")
    client = TestClient(main.app)
    client.post(f"/api/session/{session_id}/schedule", data={"interval": "1", "unit": "minutes"})  # 60s < 300s floor
    assert schedule_store.get_schedule(session_id)["interval_seconds"] == 300
