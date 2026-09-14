"""The Recon tab's Credentials card (templates/partials/session_fragment.html): configured
identities (masked, eye-reveal), the "Add credential" form, and the two asset_graph credential
tables (added by the operator vs. obtained by the agent). Same TestClient-against-a-real-saved-
session pattern as tests/test_recon_add_item_ui.py.
"""
from fastapi.testclient import TestClient

import main
from agent.tools import native
from sessions import store


def _session(session_id, status="completed", **overrides):
    session = {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "hypotheses": [], "chain_attempts": [],
        "out_of_scope": [], "authorize_exploit": False, "enumerate_subdomains": False,
        "asset_graph": {"credentials": []},
    }
    session.update(overrides)
    return session


def test_recon_tab_shows_a_configured_identity_masked_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    session_id = "usr_creds_masked"
    store.save_session(session_id, _session(session_id))
    native.save_identity_credentials(session_id, {"user_a": {"username": "alice", "email": "", "password": "hunter2", "login_url": "", "cookie": "", "authorization_header": ""}})
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Identity A" in resp.text
    assert "hunter2" not in resp.text  # never rendered in plaintext by default
    assert "••••••••" in resp.text  # the mask placeholder
    assert f"/api/session/{session_id}/identity/user_a/reveal/password" in resp.text


def test_reveal_identity_field_returns_the_real_value(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    session_id = "usr_creds_reveal"
    store.save_session(session_id, _session(session_id))
    native.save_identity_credentials(session_id, {"user_a": {"username": "alice", "email": "", "password": "hunter2", "login_url": "", "cookie": "", "authorization_header": ""}})
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/identity/user_a/reveal/password")

    assert resp.status_code == 200
    assert "hunter2" in resp.text


def test_reveal_identity_field_404s_for_an_empty_or_unknown_field(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    session_id = "usr_creds_reveal_missing"
    store.save_session(session_id, _session(session_id))
    native.save_identity_credentials(session_id, {"user_a": {"username": "alice", "email": "", "password": "hunter2", "login_url": "", "cookie": "", "authorization_header": ""}})
    client = TestClient(main.app)

    assert client.post(f"/api/session/{session_id}/identity/user_a/reveal/cookie").status_code == 404
    assert client.post(f"/api/session/{session_id}/identity/nonexistent/reveal/password").status_code == 404


def test_add_manual_credential_appends_to_asset_graph_and_registers_an_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    session_id = "usr_creds_manual_add"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(
        f"/api/session/{session_id}/credentials/add",
        data={"username": "bob", "password": "hunter2", "found_on_host": "app.example.com"},
    )

    assert resp.status_code == 200
    session = store.load_session(session_id)
    creds = session["asset_graph"]["credentials"]
    assert len(creds) == 1
    assert creds[0]["username"] == "bob" and creds[0]["source_tool"] == "manual"
    assert creds[0]["identity_name"] == "manual_1"
    assert native._load_credentials(session_id)["manual_1"]["username"] == "bob"
    # Manually-added credentials render unmasked -- the operator just typed this in themselves.
    assert "bob:hunter2" in resp.text


def test_add_manual_credential_requires_a_username(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    session_id = "usr_creds_manual_missing_username"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/credentials/add", data={"username": "  "})

    assert resp.status_code == 400


def test_recon_tab_splits_operator_and_agent_credentials_into_separate_sections(tmp_path, monkeypatch):
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    session_id = "usr_creds_split"
    session = _session(session_id, asset_graph={"credentials": [
        {"id": "1", "username": "manualuser", "password": "pw1", "found_on_host": "a.example.com", "source_tool": "manual", "identity_name": "manual_1", "discovered_at": None, "suggested_hosts": []},
        {"id": "2", "username": "cracked", "password": "pw2", "found_on_host": "b.example.com", "source_tool": "web_self_register", "identity_name": "self_registered_1", "discovered_at": None, "suggested_hosts": []},
    ]})
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Added by the operator" in resp.text
    assert "Obtained by the agent" in resp.text
    assert "Self-registered by agent" in resp.text
