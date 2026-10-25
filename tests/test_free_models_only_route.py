"""main.py's Settings-page "Free models only" switch: POST /api/settings/free-models-only (same
"one toggle, one independent request" Form(None)-checked/unchecked convention already tested for
/api/toolkit-agent-settings/{field} in tests/test_toolkit_agent_settings_routes.py) and the
checkbox's own presence/checked-state on GET /settings.
"""
from fastapi.testclient import TestClient

import main
from agent import settings


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SETTINGS_PATH", tmp_path / "llm_settings.json")


def test_post_free_models_only_checked_persists_true(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/free-models-only", data={"enabled": "on"})

    assert resp.status_code == 204
    assert settings.get_free_models_only() is True


def test_post_free_models_only_unchecked_persists_false(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    settings.set_free_models_only(True)
    client = TestClient(main.app)

    # A real unchecked checkbox omits the field entirely from the submitted form -- never sends
    # enabled="" or enabled="off".
    resp = client.post("/api/settings/free-models-only", data={})

    assert resp.status_code == 204
    assert settings.get_free_models_only() is False


def test_settings_page_shows_the_free_models_only_toggle_unchecked_by_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert 'id="free-models-only-toggle"' in resp.text


def test_settings_page_shows_the_free_models_only_toggle_checked_when_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    settings.set_free_models_only(True)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    checkbox_start = resp.text.index('id="free-models-only-toggle"')
    # The checkbox is the toggle_switch macro's own <input> -- its "checked" attribute (if any)
    # sits within the same tag, well before the next tag closes.
    tag_slice = resp.text[max(0, checkbox_start - 200):checkbox_start + 200]
    assert "checked" in tag_slice
