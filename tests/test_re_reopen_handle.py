"""Reverse Engineering mode's "back to chat" reopen-handle (session.html's
#interactive-reopen-handle) -- always clickable now, regardless of session.status.

Real, confirmed incident this locks in: it used to be server-rendered `disabled` while
session.status was "pending"/"processing", re-enabled only by a live 3s poll
(partials/re_triage_stage.html) the instant the ORIGINAL baseline triage finished -- but that same
poll never runs again for any LATER processing state (a Re-verify pass kicked off from the
Findings tab while chat was already open and then collapsed, for one real example), so the button
stayed stuck disabled with no other path that ever re-enabled it. Reported live: chat collapsed
mid-session, then no working way back to it short of a full page reload. Removing the disabled
state entirely (this file's own tests) removes the whole class of "this flag drifted out of sync"
bugs instead of chasing one specific trigger -- see session.html's own comment on the button for
why clicking it while triage is genuinely still live is completely safe regardless.
"""
from fastapi.testclient import TestClient

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.tools import allowed_targets, native
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    monkeypatch.setattr(main, "_CREDENTIALS_DIR", tmp_path / "credentials")


def _re_session(status):
    session_id = create_session("firmware.bin", name="RE project", mode="reverse_engineering")
    session = load_session(session_id)
    session["status"] = status
    store.save_session(session_id, session)
    return session_id


def test_reopen_handle_is_never_disabled_while_triage_is_processing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = _re_session("processing")
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert 'id="interactive-reopen-handle"' in resp.text
    button_html = resp.text.split('id="interactive-reopen-handle"', 1)[1].split("</button>", 1)[0]
    assert "disabled" not in button_html
    assert "is-unavailable" not in button_html
    assert 'title="Back to chat"' in button_html


def test_reopen_handle_is_never_disabled_while_triage_is_pending(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = _re_session("pending")
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    button_html = resp.text.split('id="interactive-reopen-handle"', 1)[1].split("</button>", 1)[0]
    assert "disabled" not in button_html


def test_reopen_handle_is_never_disabled_once_triage_has_completed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = _re_session("completed")
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    button_html = resp.text.split('id="interactive-reopen-handle"', 1)[1].split("</button>", 1)[0]
    assert "disabled" not in button_html


def test_chat_placeholder_renders_the_live_triage_spinner_while_processing(tmp_path, monkeypatch):
    # The reopen-handle's own safety argument depends on this: .interactive-chat-pane must still
    # hold a real, live-updating placeholder (never an empty/broken pane) while triage genuinely
    # hasn't finished yet, since the button no longer stops the operator from revealing it early.
    _isolate(tmp_path, monkeypatch)
    session_id = _re_session("processing")
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Baseline triage is running" in resp.text
    assert f'hx-get="/api/session/{session_id}/re-triage-stage"' in resp.text


def test_re_triage_stage_route_no_longer_touches_the_reopen_handle_via_script(tmp_path, monkeypatch):
    # The two inline <script> blocks that used to set/clear the disabled attribute are gone --
    # the poll response for either branch (still running, or now showing real chat) must not
    # reference interactive-reopen-handle at all anymore.
    _isolate(tmp_path, monkeypatch)
    processing_id = _re_session("processing")
    completed_id = _re_session("completed")
    client = TestClient(main.app)

    resp_running = client.get(f"/api/session/{processing_id}/re-triage-stage")
    resp_done = client.get(f"/api/session/{completed_id}/re-triage-stage")

    assert "interactive-reopen-handle" not in resp_running.text
    assert "interactive-reopen-handle" not in resp_done.text
