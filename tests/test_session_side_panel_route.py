"""main.py's session_side_panel route (GET /api/session/{id}/side-panel) -- the Agent-mode
collapsed-chat side panel's live half (Pulse status + Pinned rail + Activity ticker), polled every
3s by partials/session_collapsed_panel.html. Read-only, same shape as re_summary_tab/
interactive_findings.
"""
from fastapi.testclient import TestClient

import main


def _session(session_id):
    return {
        "session_id": session_id, "name": "test", "target": "example.com", "status": "processing",
        "mode": "agent", "created_at": "2026-01-01T00:00:00+00:00",
        "logs": [
            {"step": 1, "phase": "recon", "status": "success", "command": "nmap(target=example.com)", "duration_ms": 1200},
        ],
        "findings": [{"title": "SQLi in login", "severity": "High"}],
        "approvals": [], "chat": {"summary": "", "messages": []},
        "pinned_refs": ["F1"],
    }


def test_side_panel_shows_status_and_last_log_line():
    from sessions import store
    session_id = "usr_side_panel_test"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/api/session/{session_id}/side-panel")

    assert resp.status_code == 200
    assert "nmap" in resp.text
    store.delete_session(session_id)


def test_side_panel_shows_pinned_finding():
    from sessions import store
    session_id = "usr_side_panel_pinned_test"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/api/session/{session_id}/side-panel")

    assert "SQLi in login" in resp.text
    store.delete_session(session_id)


def test_side_panel_shows_recent_tool_call_in_activity_ticker():
    from sessions import store
    session_id = "usr_side_panel_activity_test"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/api/session/{session_id}/side-panel")

    assert "nmap" in resp.text
    store.delete_session(session_id)


def test_side_panel_for_a_missing_session_returns_404():
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_does_not_exist/side-panel")
    assert resp.status_code == 404
