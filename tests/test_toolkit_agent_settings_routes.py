"""main.py's Settings-page native-toolkit-access routes: GET /settings' "Native toolkit access"
section, and the six independent per-field POST toggles (send_raw_request/list_captured_traffic/
decode_value/diff_requests/intruder_run/sequencer_analyze, the last added in a later
log-review-audit follow-up). Same "one toggle, one independent request" pattern already tested
for /api/chat-settings in tests/test_chat_routes.py.
"""
from fastapi.testclient import TestClient

import main
from agent.tools import toolkit_settings_store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_settings_store, "TOOLKIT_AGENT_SETTINGS_STORE_PATH", tmp_path / "toolkit_agent_settings.json")


def test_get_settings_renders_the_native_toolkit_access_section(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "Native toolkit access" in resp.text
    assert "Proxy (list_captured_traffic)" in resp.text
    assert "Repeater (send_raw_request)" in resp.text
    assert "Decoder (decode_value)" in resp.text
    assert "Comparer (diff_requests)" in resp.text
    assert "Intruder (intruder_run)" in resp.text
    assert "Sequencer (sequencer_analyze)" in resp.text


def test_toolkit_agent_settings_post_toggles_one_field_on(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/toolkit-agent-settings/toolkit_decoder_enabled", data={"enabled": "on"})

    assert resp.status_code == 204
    settings = toolkit_settings_store.load_toolkit_agent_settings()
    assert settings["toolkit_decoder_enabled"] is True
    assert settings["toolkit_proxy_enabled"] is False
    assert settings["toolkit_repeater_enabled"] is False
    assert settings["toolkit_comparer_enabled"] is False


def test_toolkit_agent_settings_post_toggles_one_field_off_without_touching_the_others(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    toolkit_settings_store.save_toolkit_agent_settings(dict.fromkeys(toolkit_settings_store.BOOL_KEYS, True))
    client = TestClient(main.app)

    resp = client.post("/api/toolkit-agent-settings/toolkit_repeater_enabled", data={})

    assert resp.status_code == 204
    settings = toolkit_settings_store.load_toolkit_agent_settings()
    assert settings["toolkit_repeater_enabled"] is False
    assert settings["toolkit_proxy_enabled"] is True
    assert settings["toolkit_decoder_enabled"] is True
    assert settings["toolkit_comparer_enabled"] is True


def test_toolkit_agent_settings_post_rejects_an_unknown_field(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/toolkit-agent-settings/not_a_real_field", data={"enabled": "on"})

    assert resp.status_code == 404


def test_toolkit_agent_settings_post_toggles_intruder_field(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/toolkit-agent-settings/toolkit_intruder_enabled", data={"enabled": "on"})

    assert resp.status_code == 204
    settings = toolkit_settings_store.load_toolkit_agent_settings()
    assert settings["toolkit_intruder_enabled"] is True


def test_toolkit_agent_settings_post_toggles_sequencer_field(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/toolkit-agent-settings/toolkit_sequencer_enabled", data={"enabled": "on"})

    assert resp.status_code == 204
    settings = toolkit_settings_store.load_toolkit_agent_settings()
    assert settings["toolkit_sequencer_enabled"] is True
