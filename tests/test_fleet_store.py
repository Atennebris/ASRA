"""agent/tools/fleet_store.py -- the fleet-mode queue: an ordered list of session_ids waiting for
real capacity to free up (FLEET_MAX_CONCURRENT_SESSIONS), so many projects can be created up front
and worked through automatically instead of every Start click launching an unbounded background
task. See tests/test_fleet_routes.py for the main.py routes/worker loop built on top of this.
"""
import pytest

from agent.tools import fleet_store


@pytest.fixture(autouse=True)
def _isolated_queue_path(tmp_path, monkeypatch):
    monkeypatch.setattr(fleet_store, "FLEET_QUEUE_PATH", tmp_path / "fleet_queue.json")
    return tmp_path


def test_load_returns_empty_list_when_file_missing():
    assert fleet_store.load_fleet_queue() == []


def test_enqueue_then_load_round_trips():
    fleet_store.enqueue_session("usr_a")
    assert fleet_store.load_fleet_queue() == ["usr_a"]


def test_enqueue_preserves_fifo_order():
    fleet_store.enqueue_session("usr_a")
    fleet_store.enqueue_session("usr_b")
    fleet_store.enqueue_session("usr_c")
    assert fleet_store.load_fleet_queue() == ["usr_a", "usr_b", "usr_c"]


def test_enqueue_is_idempotent():
    fleet_store.enqueue_session("usr_a")
    fleet_store.enqueue_session("usr_a")
    assert fleet_store.load_fleet_queue() == ["usr_a"]


def test_dequeue_removes_and_reports_true():
    fleet_store.enqueue_session("usr_a")
    fleet_store.enqueue_session("usr_b")
    assert fleet_store.dequeue_session("usr_a") is True
    assert fleet_store.load_fleet_queue() == ["usr_b"]


def test_dequeue_reports_false_when_not_present():
    assert fleet_store.dequeue_session("usr_missing") is False


def test_load_returns_empty_list_for_corrupt_json(_isolated_queue_path):
    fleet_store.FLEET_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fleet_store.FLEET_QUEUE_PATH.write_text("{not valid json")
    assert fleet_store.load_fleet_queue() == []


def test_load_returns_empty_list_when_file_is_not_the_expected_shape(_isolated_queue_path):
    fleet_store.FLEET_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fleet_store.FLEET_QUEUE_PATH.write_text('{"not_queue": [1, 2, 3]}')
    assert fleet_store.load_fleet_queue() == []


def test_save_leaves_no_temp_file_behind(_isolated_queue_path):
    fleet_store.enqueue_session("usr_a")
    assert list(_isolated_queue_path.glob("*.json.tmp")) == []


def test_pop_next_runnable_session_returns_none_when_at_capacity(monkeypatch):
    monkeypatch.setenv("FLEET_MAX_CONCURRENT_SESSIONS", "2")
    fleet_store.enqueue_session("usr_a")
    assert fleet_store.pop_next_runnable_session(active_count=2) is None
    assert fleet_store.load_fleet_queue() == ["usr_a"]  # never touched


def test_pop_next_runnable_session_returns_none_when_queue_is_empty(monkeypatch):
    monkeypatch.setenv("FLEET_MAX_CONCURRENT_SESSIONS", "3")
    assert fleet_store.pop_next_runnable_session(active_count=0) is None


def test_pop_next_runnable_session_pops_the_oldest_entry_when_capacity_is_free(monkeypatch):
    monkeypatch.setenv("FLEET_MAX_CONCURRENT_SESSIONS", "3")
    fleet_store.enqueue_session("usr_a")
    fleet_store.enqueue_session("usr_b")

    popped = fleet_store.pop_next_runnable_session(active_count=1)

    assert popped == "usr_a"
    assert fleet_store.load_fleet_queue() == ["usr_b"]  # removed from the queue, not just returned


def test_max_concurrent_sessions_defaults_to_three(monkeypatch):
    monkeypatch.delenv("FLEET_MAX_CONCURRENT_SESSIONS", raising=False)
    assert fleet_store.max_concurrent_sessions() == 3


def test_max_concurrent_sessions_reads_the_env_override(monkeypatch):
    monkeypatch.setenv("FLEET_MAX_CONCURRENT_SESSIONS", "10")
    assert fleet_store.max_concurrent_sessions() == 10
