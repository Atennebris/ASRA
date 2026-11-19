"""Settings -> Customization -> "Show helper descriptions" switch: POST /api/settings/ui-descriptions
(checked = show, so the stored flag is inverted) plus the body-level data-hide-descriptions attribute
that drives the app-wide collapse. Isolated from the real llm_settings.json exactly like
tests/test_free_models_only_route.py.
"""
from fastapi.testclient import TestClient

import main
from agent import settings


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SETTINGS_PATH", tmp_path / "llm_settings.json")


def test_hidden_defaults_false(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert settings.get_ui_descriptions_hidden() is False


def test_post_checked_shows_descriptions(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    settings.set_ui_descriptions_hidden(True)
    client = TestClient(main.app)

    # Checked ("Show helper descriptions" on) => NOT hidden.
    resp = client.post("/api/settings/ui-descriptions", data={"enabled": "on"})

    assert resp.status_code == 204
    assert settings.get_ui_descriptions_hidden() is False


def test_post_unchecked_hides_descriptions(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    # A real unchecked checkbox omits the field entirely from the submitted form.
    resp = client.post("/api/settings/ui-descriptions", data={})

    assert resp.status_code == 204
    assert settings.get_ui_descriptions_hidden() is True


def test_settings_page_shows_the_toggle(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "/api/settings/ui-descriptions" in resp.text
    assert "Show helper descriptions" in resp.text


def test_body_hides_descriptions_when_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    # Shown by default: no hide attribute, but the mechanism (script) is still present.
    shown = client.get("/")
    assert 'data-hide-descriptions="true"' not in shown.text
    assert "ui_descriptions.js" in shown.text

    settings.set_ui_descriptions_hidden(True)
    hidden = client.get("/")
    assert 'data-hide-descriptions="true"' in hidden.text
    assert "window.ASRA_HIDE_DESCRIPTIONS = true" in hidden.text
