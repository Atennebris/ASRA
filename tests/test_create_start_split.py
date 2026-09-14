"""Create vs. Start: POST /api/scan (the New Project form) now only creates a project --
status="created", nothing scheduled -- and POST /api/session/{id}/start is the deliberate second
step that actually schedules the scan. Covers both routes' own wiring; sessions/store.py's
create_session(initial_status=...) itself is covered by tests/test_sessions_store.py.
"""
from fastapi.testclient import TestClient

import main
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)


# --- POST /api/scan ("Create") -------------------------------------------------------------------


def test_create_project_lands_in_created_status_not_pending(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/scan", data={"name": "Create Split Project", "target": "example.com"}, follow_redirects=False)
    assert resp.status_code == 303
    session_id = resp.headers["location"].rsplit("/", 1)[-1]
    assert load_session(session_id)["status"] == "created"


def test_create_project_does_not_schedule_a_background_run(tmp_path, monkeypatch):
    """The real regression this guards: start_scan used to background_tasks.add_task the scan
    immediately -- run_session must never be invoked just from hitting "Create"."""
    from unittest.mock import MagicMock
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_session", MagicMock())
    client = TestClient(main.app)
    client.post("/api/scan", data={"name": "No Auto Start", "target": "example.com"}, follow_redirects=False)
    main.run_session.assert_not_called()


def test_create_project_persists_the_llm_provider_choice_for_start_to_use_later(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post(
        "/api/scan", data={"name": "Provider Persist", "target": "example.com", "llm_provider": "qwen"},
        follow_redirects=False,
    )
    session_id = resp.headers["location"].rsplit("/", 1)[-1]
    assert load_session(session_id)["llm_provider"] == "qwen"


def test_create_project_duplicate_name_htmx_returns_the_form_fragment_inline(tmp_path, monkeypatch):
    """Real bug: submitting the New Project dialog (htmx) with a name that already exists used to
    navigate the whole tab to a bare /api/scan page, closing the dialog and re-showing the same
    form inline on a fresh index.html -- instead of the error appearing in the still-open dialog.
    An htmx-originated request must get back just the form partial (not the full page) at 200 (so
    htmx's default responseHandling actually swaps it), with the error banner inside it."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    client.post("/api/scan", data={"name": "dup", "target": "example.com"}, follow_redirects=False)

    resp = client.post(
        "/api/scan", data={"name": "dup", "target": "example.com"},
        headers={"HX-Request": "true"}, follow_redirects=False,
    )
    assert resp.status_code == 200
    assert "already exists" in resp.text
    assert "<html" not in resp.text.lower()  # a fragment, not the full index.html page
    assert 'id="new-project-form-container"' in resp.text


def test_create_project_duplicate_name_non_htmx_still_returns_400_full_page(tmp_path, monkeypatch):
    """The plain <form method="post" action="/api/scan"> fallback (no-JS/back-button, index.html's
    own docstring) must keep getting a real 400 + the full page -- only the htmx-enhanced path
    changes behavior."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    client.post("/api/scan", data={"name": "dup2", "target": "example.com"}, follow_redirects=False)

    resp = client.post("/api/scan", data={"name": "dup2", "target": "example.com"}, follow_redirects=False)
    assert resp.status_code == 400
    assert "already exists" in resp.text
    assert "<html" in resp.text.lower()


def test_create_project_htmx_success_uses_hx_redirect_header(tmp_path, monkeypatch):
    """htmx never auto-follows a plain 3xx into a real browser navigation -- HX-Redirect is what
    makes it actually change the URL (window.location) instead of swapping a redirected page's
    HTML into the dialog."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post(
        "/api/scan", data={"name": "HX Redirect Project", "target": "example.com"},
        headers={"HX-Request": "true"}, follow_redirects=False,
    )
    assert resp.status_code == 200
    assert resp.headers["HX-Redirect"].startswith("/session/")


def test_create_project_non_htmx_success_still_uses_a_real_303_redirect(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post(
        "/api/scan", data={"name": "Native Redirect Project", "target": "example.com"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/session/")
    assert "HX-Redirect" not in resp.headers


def test_create_project_records_identity_configured_flags_without_the_raw_values(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post(
        "/api/scan",
        data={
            "name": "Identity Flags", "target": "example.com",
            "user_a_username": "alice", "user_b_email": "",
        },
        follow_redirects=False,
    )
    session_id = resp.headers["location"].rsplit("/", 1)[-1]
    session = load_session(session_id)
    assert session["identity_a_configured"] is True
    assert session["identity_b_configured"] is False
    assert "alice" not in str(session)  # the real value lives only in the separate credentials store


def test_create_project_saves_extra_identity_cards_beyond_a_and_b(tmp_path, monkeypatch):
    """new_project_form.html's "+ Add another account" button -- these arrive as raw
    identity_extra_<n>_<field> form fields (main.py's _parse_extra_identities), no fixed Form(...)
    params/hardcoded cap, unlike user_a/user_b."""
    _isolate(tmp_path, monkeypatch)
    from agent.tools import native
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    client = TestClient(main.app)
    resp = client.post(
        "/api/scan",
        data={
            "name": "Extra Identities", "target": "example.com",
            "identity_extra_1_username": "carol", "identity_extra_1_password": "hunter2",
            "identity_extra_2_username": "dave",
        },
        follow_redirects=False,
    )
    session_id = resp.headers["location"].rsplit("/", 1)[-1]
    session = load_session(session_id)
    assert session["extra_identities_configured"] == 2
    stored = native._load_credentials(session_id)
    assert stored["identity_extra_1"]["username"] == "carol"
    assert stored["identity_extra_1"]["password"] == "hunter2"
    assert stored["identity_extra_2"]["username"] == "dave"
    assert "carol" not in str(session)  # the real value lives only in the separate credentials store


# --- POST /api/session/{id}/start ------------------------------------------------------------


def test_start_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_missing/start")
    assert resp.status_code == 404


def test_start_400s_for_a_session_that_was_already_started(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = create_session("example.com", initial_status="pending")
    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/start")
    assert resp.status_code == 400


def test_start_flips_status_to_pending_and_redirects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = create_session("example.com", initial_status="created")
    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/start", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/session/{session_id}"
    assert load_session(session_id)["status"] == "pending"


def test_start_schedules_the_background_run_with_the_persisted_provider(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_session", AsyncMock())
    session_id = create_session("example.com", initial_status="created", llm_provider="qwen")
    client = TestClient(main.app)
    client.post(f"/api/session/{session_id}/start")
    main.run_session.assert_called_once_with(session_id, provider_id="qwen", entry_point="recon")
