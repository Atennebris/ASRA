"""session["program_url"] (sessions/store.py's create_session) + the Overview tab's own editable
"Program URL" field / POST /api/session/{id}/program-url (main.py's update_program_url): lets the
operator attach, change, or clear the bug-bounty program a project belongs to at any time, not just
via the New Project wizard. Same TestClient-against-a-real-saved-session pattern as
tests/test_recon_add_item_ui.py.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, status="completed", **overrides):
    session = {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "hypotheses": [], "chain_attempts": [],
        "out_of_scope": [], "authorize_exploit": False, "enumerate_subdomains": False,
        "program_url": "", "program_check": {"last_checked": None, "last_error": None, "disclosed_reports_text": "", "disclosed_reports_checked_at": None},
    }
    session.update(overrides)
    return session


def test_overview_tab_shows_no_program_link_when_unset():
    session_id = "usr_program_url_unset"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "No bug-bounty program linked to this project yet" in resp.text
    assert f'/api/session/{session_id}/program-url' in resp.text


def test_overview_tab_shows_the_program_link_and_last_checked_when_set():
    session_id = "usr_program_url_set"
    store.save_session(session_id, _session(
        session_id, program_url="https://hackerone.com/example",
        program_check={"last_checked": "2026-01-02T00:00:00+00:00", "last_error": None, "disclosed_reports_text": "", "disclosed_reports_checked_at": None},
    ))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert 'href="https://hackerone.com/example"' in resp.text
    assert "Recheck now" in resp.text
    assert "No bug-bounty program linked to this project yet" not in resp.text


def test_update_program_url_saves_a_valid_url_and_schedules_a_refresh(monkeypatch):
    session_id = "usr_program_url_update"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    calls = []

    async def fake_refresh(sid, url, force=False):
        calls.append((sid, url, force))

    monkeypatch.setattr(main, "refresh_program_check", fake_refresh)

    resp = client.post(f"/api/session/{session_id}/program-url", data={"program_url": "hackerone.com/example"})

    assert resp.status_code == 200
    saved = store.load_session(session_id)
    assert saved["program_url"] == "https://hackerone.com/example"
    assert calls == [(session_id, "https://hackerone.com/example", True)]


def test_update_program_url_resets_the_cached_check_when_the_url_changes(monkeypatch):
    session_id = "usr_program_url_change_resets_cache"
    store.save_session(session_id, _session(
        session_id, program_url="https://hackerone.com/old",
        program_check={"last_checked": "2026-01-01T00:00:00+00:00", "last_error": None, "disclosed_reports_text": "stale text", "disclosed_reports_checked_at": "2026-01-01T00:00:00+00:00"},
    ))
    client = TestClient(main.app)
    monkeypatch.setattr(main, "refresh_program_check", lambda *a, **k: None)

    resp = client.post(f"/api/session/{session_id}/program-url", data={"program_url": "https://hackerone.com/new"})

    assert resp.status_code == 200
    saved = store.load_session(session_id)
    assert saved["program_url"] == "https://hackerone.com/new"
    assert saved["program_check"] == {"last_checked": None, "last_error": None, "disclosed_reports_text": "", "disclosed_reports_checked_at": None}


def test_update_program_url_can_clear_it(monkeypatch):
    session_id = "usr_program_url_clear"
    store.save_session(session_id, _session(session_id, program_url="https://hackerone.com/example"))
    client = TestClient(main.app)
    monkeypatch.setattr(main, "refresh_program_check", lambda *a, **k: None)

    resp = client.post(f"/api/session/{session_id}/program-url", data={"program_url": ""})

    assert resp.status_code == 200
    saved = store.load_session(session_id)
    assert saved["program_url"] == ""


def test_update_program_url_rejects_an_invalid_url():
    session_id = "usr_program_url_invalid"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/program-url", data={"program_url": "not a url at all!!"})

    assert resp.status_code == 400
    saved = store.load_session(session_id)
    assert saved["program_url"] == ""


def test_update_program_url_404s_for_a_missing_session():
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_does_not_exist/program-url", data={"program_url": "https://hackerone.com/example"})

    assert resp.status_code == 404


def test_start_scan_persists_the_program_url_from_the_new_project_form(monkeypatch):
    monkeypatch.setattr(main, "refresh_program_check", lambda *a, **k: None)
    client = TestClient(main.app)

    resp = client.post("/api/scan", data={
        "name": "Program URL create test", "target": "example.com", "program_url": "hackerone.com/example",
    }, follow_redirects=False)

    assert resp.status_code in (200, 303)
    session_id = resp.headers["location"].split("/session/")[-1] if "location" in resp.headers else None
    if session_id is None:
        # htmx-style responses carry HX-Redirect instead of a Location header.
        session_id = resp.headers.get("hx-redirect", "").split("/session/")[-1]
    saved = store.load_session(session_id)
    assert saved["program_url"] == "https://hackerone.com/example"


def test_start_scan_drops_an_invalid_program_url_without_failing_the_form():
    client = TestClient(main.app)

    resp = client.post("/api/scan", data={
        "name": "Program URL invalid create test", "target": "example.com", "program_url": "not a url!!",
    }, follow_redirects=False)

    assert resp.status_code in (200, 303)
    session_id = resp.headers["location"].split("/session/")[-1] if "location" in resp.headers else None
    if session_id is None:
        session_id = resp.headers.get("hx-redirect", "").split("/session/")[-1]
    saved = store.load_session(session_id)
    assert saved["program_url"] == ""
