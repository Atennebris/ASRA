"""main._run_due_schedules -- one scheduler worker tick, factored out of the async loop so the real
"due project -> reuse recon -> enqueue to fleet" behaviour is testable without an event loop. This
is the live proof the scheduler actually prepares an in-place pass (reusing prior recon) and hands
it to the same fleet queue a manual Start uses, respecting the one concurrency cap."""
from datetime import datetime, timedelta, timezone

import pytest

import main
from agent.tools import fleet_store, schedule_store
from sessions import store


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(schedule_store, "SCHEDULE_STORE_PATH", tmp_path / "schedules.json")
    monkeypatch.setattr(fleet_store, "FLEET_QUEUE_PATH", tmp_path / "fleet_queue.json")


def _save_session(sid, status, **extra):
    session = {
        "session_id": sid, "name": "sched", "target": "https://unrelated.example", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "findings": [{"title": "Prior bug", "verification": "verified", "severity": "High"}],
        "recon_result": {"targets": [{"host": "x.example", "port": 443}], "host_health": {}},
    }
    session.update(extra)
    store.save_session(sid, session)
    return sid


def _make_due(sid):
    schedule_store.set_schedule(sid, 300)
    schedule_store.mark_triggered(sid, datetime.now(timezone.utc) - timedelta(seconds=10_000))


def test_due_idle_project_is_prepared_reusing_recon_and_enqueued(isolated):
    sid = _save_session("usr_sched_tick_idle", "completed")
    _make_due(sid)

    main._run_due_schedules()

    refreshed = store.load_session(sid)
    # Prepared for a fresh pass, reusing what's already known (same session, recon untouched).
    assert refreshed["status"] == "created"
    assert refreshed["carried_over_findings"][0]["title"] == "Prior bug"
    assert refreshed["recon_result"]["targets"][0]["host"] == "x.example"  # recon reused, not wiped
    # Handed to the SAME fleet queue a manual Start uses.
    assert sid in fleet_store.load_fleet_queue()
    # Its due clock was reset so it doesn't re-fire every tick.
    assert not schedule_store.is_due(schedule_store.get_schedule(sid), datetime.now(timezone.utc))


def test_a_live_project_is_skipped_not_stacked(isolated):
    sid = _save_session("usr_sched_tick_live", "processing")
    _make_due(sid)

    main._run_due_schedules()

    assert store.load_session(sid)["status"] == "processing"  # untouched
    assert sid not in fleet_store.load_fleet_queue()  # never double-launched


def test_schedule_for_a_vanished_project_is_dropped(isolated):
    schedule_store.set_schedule("usr_never_existed", 300)
    schedule_store.mark_triggered("usr_never_existed", datetime.now(timezone.utc) - timedelta(seconds=10_000))

    main._run_due_schedules()

    assert schedule_store.get_schedule("usr_never_existed") is None


def test_a_not_yet_due_project_is_left_alone(isolated):
    sid = _save_session("usr_sched_tick_fresh", "completed")
    schedule_store.set_schedule(sid, 300)  # just set -> clock is now, not due yet

    main._run_due_schedules()

    assert store.load_session(sid)["status"] == "completed"
    assert sid not in fleet_store.load_fleet_queue()
