"""schedule_store: per-project unattended repeat-scan schedules (agent/tools/schedule_store.py).
is_due is the pure decision the worker loop relies on, so it's tested without any file/clock; the
CRUD is tested against a tmp store path so a test run never touches the real Documents/ASRA data."""
from datetime import datetime, timedelta, timezone

import pytest

from agent.tools import schedule_store


@pytest.fixture
def store_path(tmp_path, monkeypatch):
    path = tmp_path / "schedules.json"
    monkeypatch.setattr(schedule_store, "SCHEDULE_STORE_PATH", path)
    return path


# ---- is_due (pure) ----------------------------------------------------------------------------

def _now():
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_disabled_schedule_is_never_due():
    schedule = {"enabled": False, "interval_seconds": 300, "last_triggered_at": "2020-01-01T00:00:00+00:00"}
    assert schedule_store.is_due(schedule, _now()) is False


def test_due_once_a_full_interval_has_elapsed():
    last = (_now() - timedelta(seconds=301)).isoformat()
    schedule = {"enabled": True, "interval_seconds": 300, "last_triggered_at": last}
    assert schedule_store.is_due(schedule, _now()) is True


def test_not_due_before_the_interval_elapses():
    last = (_now() - timedelta(seconds=120)).isoformat()
    schedule = {"enabled": True, "interval_seconds": 300, "last_triggered_at": last}
    assert schedule_store.is_due(schedule, _now()) is False


def test_missing_last_triggered_is_treated_as_due():
    assert schedule_store.is_due({"enabled": True, "interval_seconds": 300}, _now()) is True


def test_garbled_last_triggered_is_treated_as_due_not_silently_never():
    schedule = {"enabled": True, "interval_seconds": 300, "last_triggered_at": "not-a-date"}
    assert schedule_store.is_due(schedule, _now()) is True


# ---- CRUD -------------------------------------------------------------------------------------

def test_set_and_get_round_trip(store_path):
    schedule_store.set_schedule("usr_x", 600)
    got = schedule_store.get_schedule("usr_x")
    assert got["enabled"] is True
    assert got["interval_seconds"] == 600
    assert got["last_triggered_at"]  # stamped so the first run is a full interval out, not immediate


def test_interval_is_floored_at_the_minimum(store_path, monkeypatch):
    monkeypatch.setenv("SCHEDULER_MIN_INTERVAL_SECONDS", "300")
    schedule_store.set_schedule("usr_x", 10)  # below the floor
    assert schedule_store.get_schedule("usr_x")["interval_seconds"] == 300


def test_updating_an_existing_schedule_keeps_its_trigger_clock(store_path):
    schedule_store.set_schedule("usr_x", 600)
    original_trigger = schedule_store.get_schedule("usr_x")["last_triggered_at"]
    schedule_store.set_schedule("usr_x", 900)  # change interval only
    updated = schedule_store.get_schedule("usr_x")
    assert updated["interval_seconds"] == 900
    assert updated["last_triggered_at"] == original_trigger  # clock not reset


def test_set_enabled_toggles_without_losing_interval(store_path):
    schedule_store.set_schedule("usr_x", 600)
    assert schedule_store.set_enabled("usr_x", False) is True
    paused = schedule_store.get_schedule("usr_x")
    assert paused["enabled"] is False
    assert paused["interval_seconds"] == 600


def test_set_enabled_on_a_missing_schedule_returns_false(store_path):
    assert schedule_store.set_enabled("nope", True) is False


def test_delete_schedule(store_path):
    schedule_store.set_schedule("usr_x", 600)
    assert schedule_store.delete_schedule("usr_x") is True
    assert schedule_store.get_schedule("usr_x") is None
    assert schedule_store.delete_schedule("usr_x") is False  # nothing left to delete


def test_mark_triggered_resets_the_due_clock(store_path):
    schedule_store.set_schedule("usr_x", 600)
    schedule_store.mark_triggered("usr_x", datetime(2026, 5, 5, tzinfo=timezone.utc))
    assert schedule_store.get_schedule("usr_x")["last_triggered_at"] == "2026-05-05T00:00:00+00:00"


def test_mark_triggered_on_a_deleted_schedule_is_a_noop(store_path):
    schedule_store.mark_triggered("gone")  # must not raise
    assert schedule_store.get_schedule("gone") is None


def test_due_session_ids_lists_only_enabled_and_elapsed(store_path):
    schedule_store.set_schedule("due_one", 300)
    schedule_store.set_schedule("paused", 300)
    schedule_store.set_enabled("paused", False)
    schedule_store.set_schedule("fresh", 300)  # just set -> clock is now, not due yet
    # Age out due_one's clock.
    schedule_store.mark_triggered("due_one", datetime.now(timezone.utc) - timedelta(seconds=400))
    due = schedule_store.due_session_ids()
    assert "due_one" in due
    assert "paused" not in due
    assert "fresh" not in due
