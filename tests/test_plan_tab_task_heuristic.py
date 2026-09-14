"""Plan tab: exactly ONE task/subtask across the whole currently-running phase is ever shown as
"active"/spinning -- the FIRST one, in document (top-to-bottom) order, that isn't done yet.
Deliberately NOT the model's own raw per-subtask status: confirmed live, the model marks several
different subtasks "active" at once in the same update_plan call (e.g. three parallel tool calls
from one turn, each against a different subtask), which rendered as several spinners going at once
-- the operator's own real complaint ("why are several circles spinning at once, only one should
spin, and it should move top to bottom step by step"). This deterministic top-to-bottom rule
replaces an earlier tool-name-matching heuristic (removed) that could miss entirely when the last
tool didn't map to any subtask's recommended_tools.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _log_entry(step, phase, command):
    return {
        "step": step, "phase": phase, "thought": None, "command": command,
        "status": "success", "error": None, "finding_title": None, "duration_ms": 120.0,
        "subagent_task_id": None, "subagent_name": None, "at": "2026-01-01T00:00:00+00:00",
    }


def _plan_phase_multiple_active_subtasks():
    """Mirrors the real incident: the model marked THREE different subtasks "active" at once."""
    return {
        "phase": "recon", "rationale": "", "status": "active",
        "tasks": [{"text": "Enumerate domain metadata", "status": "active", "subtasks": [
            {"text": "WHOIS lookup", "status": "active", "recommended_tools": ["whois_lookup"]},
            {"text": "Resolve DNS", "status": "active", "recommended_tools": ["dns_lookup"]},
            {"text": "Pull historical URLs", "status": "active", "recommended_tools": ["wayback_urls"]},
        ]}],
    }


def _session(session_id, logs, plan_phases):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": "processing",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": logs, "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "plan": {"phases": plan_phases, "version": 1, "updated_at": "2026-01-01T00:00:00+00:00"},
    }


def test_only_the_first_active_subtask_gets_the_live_now_marker(tmp_path, monkeypatch):
    session_id = "usr_plan_single_spinner_test"
    logs = [_log_entry(0, "recon", "whois_lookup(...)")]
    session = _session(session_id, logs, [_plan_phase_multiple_active_subtasks()])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    # Exactly one "now" marker, ever -- not one per subtask the model happened to mark "active".
    assert resp.text.count(">&#9679; now<") == 1


def test_the_now_marker_is_on_the_topmost_not_done_subtask(tmp_path, monkeypatch):
    session_id = "usr_plan_single_spinner_order_test"
    logs = [_log_entry(0, "recon", "whois_lookup(...)")]
    session = _session(session_id, logs, [_plan_phase_multiple_active_subtasks()])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    whois_idx = resp.text.index("WHOIS lookup")
    now_idx = resp.text.index(">&#9679; now<")
    dns_idx = resp.text.index("Resolve DNS")
    # The marker sits between WHOIS (first, topmost) and DNS (second) -- proving it landed on the
    # first not-done subtask in document order, not an arbitrary one.
    assert whois_idx < now_idx < dns_idx


def test_a_done_subtask_before_the_current_one_is_never_marked_now(tmp_path, monkeypatch):
    phase = _plan_phase_multiple_active_subtasks()
    phase["tasks"][0]["subtasks"][0]["status"] = "done"  # WHOIS already resolved
    session_id = "usr_plan_single_spinner_skip_done_test"
    logs = [_log_entry(0, "recon", "dns_lookup(...)")]
    session = _session(session_id, logs, [phase])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    now_idx = resp.text.index(">&#9679; now<")
    dns_idx = resp.text.index("Resolve DNS")
    wayback_idx = resp.text.index("Pull historical URLs")
    # DNS (the first NOT-done subtask, since WHOIS is already done) gets the marker, not WHOIS.
    assert dns_idx < now_idx < wayback_idx


def test_no_subtask_is_marked_now_once_the_session_is_completed(tmp_path, monkeypatch):
    session_id = "usr_plan_single_spinner_completed_test"
    phase = _plan_phase_multiple_active_subtasks()
    logs = [_log_entry(0, "recon", "whois_lookup(...)")]
    session = _session(session_id, logs, [phase])
    session["status"] = "completed"
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert ">&#9679; now<" not in resp.text


def test_phase_and_task_durations_render_when_timings_are_present(tmp_path, monkeypatch):
    session_id = "usr_plan_duration_test"
    session = _session(session_id, logs=[_log_entry(0, "recon", "nmap -F -sV example.com")], plan_phases=[_plan_phase_multiple_active_subtasks()])
    session["phase_timings"] = {"recon": {"started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:05:00+00:00"}}
    session["plan"]["phases"][0]["tasks"][0]["started_at"] = "2026-01-01T00:00:00+00:00"
    session["plan"]["phases"][0]["tasks"][0]["finished_at"] = "2026-01-01T00:02:00+00:00"
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "5m" in resp.text  # phase duration
    assert "2m" in resp.text  # task duration
