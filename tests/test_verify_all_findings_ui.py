"""The Findings tab's "Verify/recheck all" button and its backend route
(/api/session/{id}/findings/verify-all) -- mirrors test_hypothesis_ui.py's own bulk-button
coverage for the Hypotheses tab, built on run_all_findings_verification (agent/core.py).
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, findings=None, status="completed"):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": findings or [], "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


def _finding(**overrides):
    finding = {
        "title": "CORS misconfiguration", "severity": "Low", "description": "desc",
        "verification": "verified", "exploited": False,
    }
    finding.update(overrides)
    return finding


def test_verify_all_findings_button_shown_on_an_idle_session_with_findings():
    session_id = "usr_finding_ui_verify_all_shown"
    store.save_session(session_id, _session(session_id, findings=[_finding()], status="completed"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert f"/api/session/{session_id}/findings/verify-all" in resp.text
    assert "Verify/recheck all" in resp.text


def test_verify_all_findings_button_hidden_on_a_live_session():
    session_id = "usr_finding_ui_verify_all_hidden_live"
    store.save_session(session_id, _session(session_id, findings=[_finding()], status="processing"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert f"/api/session/{session_id}/findings/verify-all" not in resp.text


def test_verify_all_findings_button_hidden_with_no_findings():
    session_id = "usr_finding_ui_verify_all_hidden_empty"
    store.save_session(session_id, _session(session_id, findings=[], status="completed"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert f"/api/session/{session_id}/findings/verify-all" not in resp.text


def test_verify_all_findings_route_starts_a_background_task_on_an_idle_session(monkeypatch):
    session_id = "usr_finding_ui_verify_all_post"
    store.save_session(session_id, _session(session_id, findings=[_finding()], status="completed"))
    started = []
    monkeypatch.setattr(main, "run_all_findings_verification", lambda sid: started.append(sid))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/findings/verify-all")

    assert resp.status_code == 200
    assert started == [session_id]


def test_verify_all_findings_route_rejects_a_live_session():
    session_id = "usr_finding_ui_verify_all_live_reject"
    store.save_session(session_id, _session(session_id, findings=[_finding()], status="processing"))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/findings/verify-all")

    assert resp.status_code == 409


def test_verify_all_findings_route_unknown_session_is_404():
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_does_not_exist/findings/verify-all")

    assert resp.status_code == 404
