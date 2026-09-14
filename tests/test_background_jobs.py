"""agent/tools/background_jobs.py: fire-and-check background subprocess execution for slow
(many-minute) tools like Hydra. Uses real subprocess.Popen (via sys.executable -c scripts, fast
and deterministic) rather than mocking subprocess internals -- same "exercise the real mechanism"
discipline as tests/test_custom_exploit_run.py.

Real incidents this guards against:
- Stop must actually kill a running job's real process, not just mark it "killed" in metadata.
- A server crash/restart orphans a job's real OS process (nothing guarantees a child dies just
  because its parent did) -- orphan-recovery must check the real PID and kill it for real, not
  just rewrite the status.
"""
import asyncio
import os
import subprocess
import sys
import time

import pytest

from agent.tools import background_jobs as bg
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    from projects import paths as project_paths
    project_paths.resolve_projects_base_dir.cache_clear()
    yield
    project_paths.resolve_projects_base_dir.cache_clear()
    # Never let a real test leak a still-running process or dangling registry entry into a later test.
    bg._RUNNING_PROCESSES.clear()
    bg._PARSERS.clear()


def _base_session(session_id):
    return {"session_id": session_id, "background_jobs": {}}


def _quick_ok_setup(job_id, job_dir):
    command = [sys.executable, "-c", "print('done')"]
    return command, lambda log_path: {"parsed": True}


def _quick_fail_setup(job_id, job_dir):
    command = [sys.executable, "-c", "import sys; sys.exit(1)"]
    return command, lambda log_path: {"parsed": True}


def _sleep_setup(seconds):
    def setup(job_id, job_dir):
        command = [sys.executable, "-c", f"import time; time.sleep({seconds})"]
        return command, lambda log_path: {"parsed": True}
    return setup


def test_start_background_job_returns_ok_and_a_job_id(tmp_path):
    session_id = "usr_bg_start_test"
    session = _base_session(session_id)
    result = bg.start_background_job(session_id, session, "test-tool", _quick_ok_setup, max_concurrent=2, timeout_seconds=10)
    assert result["status"] == "ok"
    assert result["job_id"]
    assert session["background_jobs"][result["job_id"]]["status"] == "running"
    assert session["background_jobs"][result["job_id"]]["tool"] == "test-tool"


def test_start_background_job_merges_extra_metadata_into_the_job_dict(tmp_path):
    """agent/core.py's asset-graph tracking needs to recover which host a web_login_bruteforce
    job's own parsed credentials (no host field of their own) were found on -- extra_metadata is
    how the caller (native.py's web_login_bruteforce_start/hydra_start) stashes the original
    target argument for that later lookup."""
    session_id = "usr_bg_extra_metadata"
    session = _base_session(session_id)
    result = bg.start_background_job(
        session_id, session, "web_login_bruteforce", _quick_ok_setup, max_concurrent=2, timeout_seconds=10,
        extra_metadata={"target": "https://example.com/login"},
    )
    assert session["background_jobs"][result["job_id"]]["target"] == "https://example.com/login"


def test_start_background_job_with_no_extra_metadata_adds_nothing_extra(tmp_path):
    session_id = "usr_bg_no_extra_metadata"
    session = _base_session(session_id)
    result = bg.start_background_job(session_id, session, "hydra", _quick_ok_setup, max_concurrent=2, timeout_seconds=10)
    assert "target" not in session["background_jobs"][result["job_id"]]


def test_start_background_job_respects_the_concurrency_cap(tmp_path):
    session_id = "usr_bg_cap_test"
    session = _base_session(session_id)
    setup = _sleep_setup(2)
    first = bg.start_background_job(session_id, session, "test-tool", setup, max_concurrent=1, timeout_seconds=10)
    assert first["status"] == "ok"

    second = bg.start_background_job(session_id, session, "test-tool", setup, max_concurrent=1, timeout_seconds=10)
    assert second["status"] == "skipped"
    assert "already running" in second["reason"]

    bg.kill_all_running_jobs(session)  # cleanup -- don't leave the sleep(2) process running past this test


def test_check_background_job_reaps_a_finished_job_and_parses_its_result(tmp_path):
    session_id = "usr_bg_check_ok_test"
    session = _base_session(session_id)
    start = bg.start_background_job(session_id, session, "test-tool", _quick_ok_setup, max_concurrent=2, timeout_seconds=10)
    job_id = start["job_id"]

    deadline = time.time() + 5
    result = {"status": "running"}
    while time.time() < deadline:
        result = bg.check_background_job(session_id, session, job_id)
        if result["status"] != "running":
            break
        time.sleep(0.1)

    assert result["status"] == "ok"
    assert result["result"] == {"parsed": True}
    assert session["background_jobs"][job_id]["status"] == "ok"


def test_check_background_job_reports_a_real_nonzero_exit_as_error(tmp_path):
    session_id = "usr_bg_check_fail_test"
    session = _base_session(session_id)
    start = bg.start_background_job(session_id, session, "test-tool", _quick_fail_setup, max_concurrent=2, timeout_seconds=10)
    job_id = start["job_id"]

    deadline = time.time() + 5
    result = {"status": "running"}
    while time.time() < deadline:
        result = bg.check_background_job(session_id, session, job_id)
        if result["status"] != "running":
            break
        time.sleep(0.1)

    assert result["status"] == "error"
    assert result["result"]["exit_code"] == 1


def test_check_background_job_on_unknown_job_id_returns_a_clean_error(tmp_path):
    session = _base_session("usr_bg_unknown_test")
    result = bg.check_background_job("usr_bg_unknown_test", session, "not-a-real-job-id")
    assert result["status"] == "error"


def test_check_background_job_reports_running_while_the_process_is_still_alive(tmp_path):
    session_id = "usr_bg_running_test"
    session = _base_session(session_id)
    start = bg.start_background_job(session_id, session, "test-tool", _sleep_setup(3), max_concurrent=2, timeout_seconds=30)
    job_id = start["job_id"]

    result = bg.check_background_job(session_id, session, job_id)
    assert result["status"] == "running"

    bg.kill_all_running_jobs(session)  # cleanup


def test_kill_background_job_actually_terminates_the_real_process(tmp_path):
    session_id = "usr_bg_kill_test"
    session = _base_session(session_id)
    start = bg.start_background_job(session_id, session, "test-tool", _sleep_setup(30), max_concurrent=2, timeout_seconds=60)
    job_id = start["job_id"]
    pid = session["background_jobs"][job_id]["pid"]

    # The real OS process is genuinely alive right now.
    os.kill(pid, 0)  # raises if not

    bg.kill_background_job(job_id, session["background_jobs"][job_id])

    assert session["background_jobs"][job_id]["status"] == "killed"
    time.sleep(0.3)  # give the OS a moment to actually reap it
    with pytest.raises(OSError):
        os.kill(pid, 0)  # really gone, not just relabeled


def test_kill_all_running_jobs_kills_every_running_job_not_just_one(tmp_path):
    session_id = "usr_bg_kill_all_test"
    session = _base_session(session_id)
    setup = _sleep_setup(30)
    first = bg.start_background_job(session_id, session, "test-tool", setup, max_concurrent=5, timeout_seconds=60)
    second = bg.start_background_job(session_id, session, "test-tool", setup, max_concurrent=5, timeout_seconds=60)
    pid1 = session["background_jobs"][first["job_id"]]["pid"]
    pid2 = session["background_jobs"][second["job_id"]]["pid"]

    bg.kill_all_running_jobs(session)

    assert session["background_jobs"][first["job_id"]]["status"] == "killed"
    assert session["background_jobs"][second["job_id"]]["status"] == "killed"
    time.sleep(0.3)
    with pytest.raises(OSError):
        os.kill(pid1, 0)
    with pytest.raises(OSError):
        os.kill(pid2, 0)


def test_job_hitting_its_own_timeout_is_killed_and_marked_timeout(tmp_path):
    session_id = "usr_bg_timeout_test"
    session = _base_session(session_id)
    start = bg.start_background_job(session_id, session, "test-tool", _sleep_setup(30), max_concurrent=2, timeout_seconds=0)
    job_id = start["job_id"]
    # timeout_seconds=0 means the deadline is already in the past the instant this job started.
    time.sleep(0.2)

    result = bg.check_background_job(session_id, session, job_id)
    assert result["status"] == "timeout"


def test_reconcile_orphaned_background_jobs_kills_a_real_orphaned_process(tmp_path):
    """Simulates a fresh process start (empty in-memory registries) reconciling a job that a
    PREVIOUS process's run left "running" -- confirms the real OS process gets killed by PID, not
    just relabeled, closing the exact gap a "don't leave background processes
    running" behind-the-scenes job could otherwise open."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        data = {
            "session_id": "usr_bg_orphan_test",
            "background_jobs": {"orphanjob1": {"tool": "hydra", "status": "running", "pid": proc.pid}},
        }

        bg.reconcile_orphaned_background_jobs("usr_bg_orphan_test", data)

        assert data["background_jobs"]["orphanjob1"]["status"] == "interrupted"
        # In production this PID belongs to a genuinely different (already-exited) process, whose
        # OS-level reaping is handled by init/a subreaper, not this one -- reconcile_orphaned_
        # background_jobs only has a bare PID to signal, never a Popen handle to wait() on. Here,
        # though, this test IS the real parent (it created proc itself), so it must reap the exit
        # status itself before checking liveness, or the killed child lingers as a zombie (still
        # a valid, "alive" PID to os.kill(pid, 0)) until something calls wait() on it.
        proc.wait(timeout=5)
        with pytest.raises(OSError):
            os.kill(proc.pid, 0)  # really gone, not just relabeled
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def test_reconcile_orphaned_background_jobs_handles_an_already_dead_pid_gracefully(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=5)  # already exited before reconciliation ever runs

    data = {
        "session_id": "usr_bg_orphan_dead_test",
        "background_jobs": {"orphanjob2": {"tool": "hydra", "status": "running", "pid": proc.pid}},
    }

    bg.reconcile_orphaned_background_jobs("usr_bg_orphan_dead_test", data)  # must not raise

    assert data["background_jobs"]["orphanjob2"]["status"] == "interrupted"


def test_reconcile_orphaned_background_jobs_leaves_non_running_jobs_alone(tmp_path):
    data = {
        "session_id": "usr_bg_orphan_ok_test",
        "background_jobs": {"donejob": {"tool": "hydra", "status": "ok", "pid": 999999, "result": {"credentials": []}}},
    }
    bg.reconcile_orphaned_background_jobs("usr_bg_orphan_ok_test", data)
    assert data["background_jobs"]["donejob"]["status"] == "ok"  # untouched


def test_await_all_running_jobs_waits_until_the_job_actually_finishes(tmp_path):
    session_id = "usr_bg_await_test"
    session = _base_session(session_id)
    start = bg.start_background_job(session_id, session, "test-tool", _sleep_setup(1), max_concurrent=2, timeout_seconds=10)
    job_id = start["job_id"]

    asyncio.run(bg.await_all_running_jobs(session_id, session))

    assert session["background_jobs"][job_id]["status"] == "ok"


def test_await_all_running_jobs_is_a_fast_noop_with_nothing_running(tmp_path):
    session_id = "usr_bg_await_noop_test"
    session = _base_session(session_id)
    start_time = time.monotonic()
    asyncio.run(bg.await_all_running_jobs(session_id, session))
    assert time.monotonic() - start_time < 1.0
