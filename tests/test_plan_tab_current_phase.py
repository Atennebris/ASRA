"""Plan tab (templates/partials/session_fragment.html): while a session is still processing, the
model's own subtask statuses give no live "in progress" signal -- confirmed live, update_plan only
ever gets called once at the very start of a phase (everything "pending") and again right at the
end (everything flipped straight to "done"), never anything in between. So the currently-running
phase used to look completely untouched until the instant it finished. The last log entry's own
phase is the same fact status_badge's phase suffix already derives -- this reuses it to force a
distinct "in progress" visual on the phase currently running, regardless of its derived status.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _log_entry(step, phase):
    return {
        "step": step, "phase": phase, "thought": None, "command": "dns_lookup({})",
        "status": "success", "error": None, "finding_title": None, "duration_ms": 120.0,
        "subagent_task_id": None, "subagent_name": None, "at": "2026-01-01T00:00:00+00:00",
    }


def _plan_phase(phase, status):
    return {
        "phase": phase, "rationale": "", "status": status,
        "tasks": [{"text": "Some task", "status": status, "subtasks": [
            {"text": "Some subtask", "status": status, "recommended_tools": []},
        ]}],
    }


def _session(session_id, status, logs_phases, plan_phases):
    logs = [_log_entry(i, phase) for i, phase in enumerate(logs_phases)]
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": logs, "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "plan": {"phases": plan_phases, "version": 1, "updated_at": "2026-01-01T00:00:00+00:00"},
    }


def test_the_phase_matching_the_most_recent_log_entry_is_shown_in_progress(tmp_path, monkeypatch):
    session_id = "usr_plan_current_phase_test"
    plan_phases = [_plan_phase("recon", "pending"), _plan_phase("analyze", "pending")]
    session = _session(session_id, "processing", logs_phases=["recon", "analyze"], plan_phases=plan_phases)
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "In progress" in resp.text


def test_a_phase_that_already_finished_is_not_shown_as_in_progress(tmp_path, monkeypatch):
    """The active-phase override only ever applies to the phase matching the last log entry --
    an earlier, already-"done" phase must never be relabeled "in progress" just because it's not
    the current one."""
    session_id = "usr_plan_current_phase_done_test"
    plan_phases = [_plan_phase("recon", "done"), _plan_phase("analyze", "pending")]
    session = _session(session_id, "processing", logs_phases=["recon", "analyze"], plan_phases=plan_phases)
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    # plan_status_icon's own spinner ALSO carries a title="In progress" tooltip for any "active"
    # status (a substring match on the bare phrase would double-count it) -- the phase card's own
    # dedicated label (">In progress<", never inside an attribute) is what actually needs to be
    # scoped to exactly the currently-running phase.
    assert resp.text.count(">In progress<") == 1


def test_no_phase_is_marked_in_progress_once_the_session_is_completed(tmp_path, monkeypatch):
    session_id = "usr_plan_current_phase_completed_test"
    plan_phases = [_plan_phase("recon", "done"), _plan_phase("exploit", "done")]
    session = _session(session_id, "completed", logs_phases=["recon", "exploit"], plan_phases=plan_phases)
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "In progress" not in resp.text


def test_no_error_when_the_plan_or_logs_are_empty(tmp_path, monkeypatch):
    session_id = "usr_plan_current_phase_empty_test"
    session = _session(session_id, "pending", logs_phases=[], plan_phases=[])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
