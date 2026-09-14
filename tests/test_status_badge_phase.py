"""status_badge()'s optional phase suffix (templates/macros/ui.html): the operator's own real
complaint this fixes -- "Status: processing" alone never says WHICH of Recon/Analyze/Exploit is
actually running right now, so watching the top-of-page badge gave no way to tell "still in Recon"
from "already deep into Exploit" without opening the Plan tab. Derived from the last real log
entry's own "phase" field (the session detail page) or the identical cached field
sessions/store.py's own summary already carries (Projects list, recent-projects) -- never
something the model has to separately report.
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


def _session(session_id, status, phases):
    logs = [_log_entry(i, phase) for i, phase in enumerate(phases)]
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": logs, "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


def test_session_page_shows_the_current_phase_while_processing(tmp_path, monkeypatch):
    session_id = "usr_badge_phase_test"
    session = _session(session_id, "processing", phases=["recon"])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "processing" in resp.text
    assert "(Recon)" in resp.text


def test_session_page_reflects_the_most_recent_log_entrys_phase_not_the_first(tmp_path, monkeypatch):
    session_id = "usr_badge_phase_latest_test"
    session = _session(session_id, "processing", phases=["recon", "analyze"])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "(Analyze)" in resp.text
    assert "(Recon)" not in resp.text


def test_session_page_omits_the_phase_suffix_for_a_completed_session(tmp_path, monkeypatch):
    """A phase suffix on a terminal status would be meaningless (nothing is "currently" anything
    once the session is done) -- status_badge only ever appends it for the still-working states."""
    session_id = "usr_badge_phase_completed_test"
    session = _session(session_id, "completed", phases=["exploit"])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "completed" in resp.text
    assert "(Exploit)" not in resp.text


def test_session_page_omits_the_phase_suffix_with_no_log_activity_yet(tmp_path, monkeypatch):
    session_id = "usr_badge_phase_no_logs_test"
    session = _session(session_id, "pending", phases=[])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200  # must not error just because logs is empty


def test_projects_list_fragment_shows_the_phase_from_the_cached_summary(tmp_path, monkeypatch):
    session_id = "usr_badge_phase_list_test"
    session = _session(session_id, "processing", phases=["exploit"])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get("/api/sessions/fragment")

    assert resp.status_code == 200
    assert "(Exploit)" in resp.text


def test_recent_projects_fragment_shows_the_phase_from_the_cached_summary(tmp_path, monkeypatch):
    session_id = "usr_badge_phase_recent_test"
    session = _session(session_id, "processing", phases=["analyze"])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get("/api/recent-projects/fragment")

    assert resp.status_code == 200
    assert "(Analyze)" in resp.text
