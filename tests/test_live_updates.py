"""Live updates for the Projects page and the home page's "Recent projects" list: before this,
both rendered their session summaries exactly once at page load and never again -- a status or
finding-count change while either page was open needed a manual reload or navigating away and back
to notice, unlike the session detail page (session.html), which already had SSE + morph for this.
sessions_list_fragment.html/recent_projects_fragment.html now back both pages AND a polling
fragment endpoint each (main.py), so the same summary-rendering logic can be re-fetched on its own.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _make_session(tmp_path, monkeypatch, session_id, name, status, findings_count=0):
    _isolated_storage(tmp_path, monkeypatch)
    session = {
        "session_id": session_id, "name": name, "target": "example.com", "status": status,
        "created_at": "2026-07-22T00:00:00+00:00", "logs": [],
        "findings": [{"title": f"finding {i}"} for i in range(findings_count)],
        "approvals": [], "chat": {"summary": "", "messages": []},
    }
    store.save_session(session_id, session)
    return session


def test_sessions_fragment_endpoint_reflects_current_status(tmp_path, monkeypatch):
    _make_session(tmp_path, monkeypatch, "usr_live1", "Live Project", "processing", findings_count=2)

    client = TestClient(main.app)
    resp = client.get("/api/sessions/fragment")

    assert resp.status_code == 200
    assert "Live Project" in resp.text
    assert "2 finding(s)" in resp.text


def test_sessions_fragment_endpoint_picks_up_a_status_change(tmp_path, monkeypatch):
    """The actual bug being fixed: the same summary data, fetched a second time, must reflect a
    status change that happened in between -- proving this endpoint is safe to poll, not just that
    it renders once."""
    _make_session(tmp_path, monkeypatch, "usr_live2", "Changing Project", "processing")
    client = TestClient(main.app)

    first = client.get("/api/sessions/fragment")
    assert "processing" in first.text.lower() or "Changing Project" in first.text

    session = store.load_session("usr_live2")
    session["status"] = "completed"
    store.save_session("usr_live2", session)

    second = client.get("/api/sessions/fragment")
    assert "completed" in second.text.lower()


def test_sessions_page_wires_up_polling_for_its_fragment(tmp_path, monkeypatch):
    _isolated_storage(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/sessions")

    assert resp.status_code == 200
    assert 'hx-get="/api/sessions/fragment"' in resp.text
    assert 'hx-trigger="every 5s"' in resp.text


def test_recent_projects_fragment_endpoint_reflects_current_status(tmp_path, monkeypatch):
    _make_session(tmp_path, monkeypatch, "usr_live3", "Home Page Project", "awaiting_approval")

    client = TestClient(main.app)
    resp = client.get("/api/recent-projects/fragment")

    assert resp.status_code == 200
    assert "Home Page Project" in resp.text


def test_recent_projects_fragment_endpoint_limits_to_five(tmp_path, monkeypatch):
    _isolated_storage(tmp_path, monkeypatch)
    for i in range(7):
        session = {
            "session_id": f"usr_many{i}", "name": f"Project {i}", "target": "example.com", "status": "completed",
            "created_at": f"2026-07-22T00:00:0{i}+00:00", "logs": [], "findings": [],
            "approvals": [], "chat": {"summary": "", "messages": []},
        }
        store.save_session(f"usr_many{i}", session)

    client = TestClient(main.app)
    resp = client.get("/api/recent-projects/fragment")

    shown = sum(f"Project {i}" in resp.text for i in range(7))
    assert shown == 5


def test_home_page_wires_up_polling_for_its_fragment(tmp_path, monkeypatch):
    _isolated_storage(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/")

    assert resp.status_code == 200
    assert 'hx-get="/api/recent-projects/fragment"' in resp.text
    assert 'hx-trigger="every 5s"' in resp.text
