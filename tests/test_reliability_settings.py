"""Phase 8: the Settings -> Reliability store, its GUI -> env -> default resolution order, the save
route's validation, and the settings context. The autouse conftest fixture already points
reliability_settings.SETTINGS_PATH at a throwaway file and resets its cache per test."""
import pytest
from fastapi.testclient import TestClient

import main
from agent import core, llm_client, reliability_settings


def test_store_round_trip_and_saved_raw():
    reliability_settings.save_reliability_setting("WEAK_MODEL_MAX_TOOLS", "7")
    assert reliability_settings.load_reliability_settings()["WEAK_MODEL_MAX_TOOLS"] == "7"
    assert reliability_settings.saved_raw("WEAK_MODEL_MAX_TOOLS") == "7"
    assert reliability_settings.saved_raw("WEAK_SIGNAL_WINDOW") is None


def test_save_rejects_unknown_key():
    with pytest.raises(ValueError):
        reliability_settings.save_reliability_setting("NOT_A_KEY", "1")


def test_load_tolerates_broken_file():
    reliability_settings.SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    reliability_settings.SETTINGS_PATH.write_text("{ not json", encoding="utf-8")
    reliability_settings._settings_cache = None
    assert reliability_settings.load_reliability_settings() == {}


def test_raw_setting_resolution_order(monkeypatch):
    monkeypatch.delenv("WEAK_MODEL_MAX_TOOLS", raising=False)
    assert reliability_settings.raw_setting("WEAK_MODEL_MAX_TOOLS") is None
    monkeypatch.setenv("WEAK_MODEL_MAX_TOOLS", "9")
    assert reliability_settings.raw_setting("WEAK_MODEL_MAX_TOOLS") == "9"
    reliability_settings.save_reliability_setting("WEAK_MODEL_MAX_TOOLS", "5")
    assert reliability_settings.raw_setting("WEAK_MODEL_MAX_TOOLS") == "5"  # GUI wins over env


def test_saved_value_reaches_float_resolver(monkeypatch):
    monkeypatch.delenv("LLM_TOOL_CALL_TEMPERATURE", raising=False)
    assert llm_client._tool_call_temperature() == pytest.approx(0.2)  # hardcoded default
    monkeypatch.setenv("LLM_TOOL_CALL_TEMPERATURE", "0.4")
    assert llm_client._tool_call_temperature() == pytest.approx(0.4)  # env under GUI
    reliability_settings.save_reliability_setting("LLM_TOOL_CALL_TEMPERATURE", "0.7")
    assert llm_client._tool_call_temperature() == pytest.approx(0.7)  # GUI wins


def test_saved_value_reaches_bool_resolver(monkeypatch):
    monkeypatch.delenv("TOOL_ARG_COERCION", raising=False)
    assert core._tool_arg_coercion_enabled() is True  # on by default
    reliability_settings.save_reliability_setting("TOOL_ARG_COERCION", "false")
    assert core._tool_arg_coercion_enabled() is False  # GUI wins


def test_save_route_persists_valid(monkeypatch):
    monkeypatch.delenv("WEAK_SIGNAL_WINDOW", raising=False)
    client = TestClient(main.app)
    resp = client.post("/api/settings/reliability", data={"key": "WEAK_SIGNAL_WINDOW", "value": "25"})
    assert resp.status_code == 204
    assert core._weak_signal_window() == 25


def test_save_route_rejects_out_of_range():
    client = TestClient(main.app)
    assert client.post("/api/settings/reliability", data={"key": "LLM_TOOL_CALL_TEMPERATURE", "value": "5"}).status_code == 400
    assert client.post("/api/settings/reliability", data={"key": "WEAK_MODEL_MAX_TOOLS", "value": "0"}).status_code == 400
    assert client.post("/api/settings/reliability", data={"key": "WEAK_MODEL_MODE", "value": "sometimes"}).status_code == 400


def test_save_route_rejects_unknown_key():
    client = TestClient(main.app)
    assert client.post("/api/settings/reliability", data={"key": "SOMETHING_ELSE", "value": "1"}).status_code == 404


def test_save_route_normalizes_bool():
    client = TestClient(main.app)
    resp = client.post("/api/settings/reliability", data={"key": "WEAK_SIGNAL_ENABLED", "value": "off"})
    assert resp.status_code == 204
    assert reliability_settings.saved_raw("WEAK_SIGNAL_ENABLED") == "false"


def test_context_returns_all_twelve_keys():
    ctx = main._reliability_settings_context()["reliability_settings"]
    assert set(ctx.keys()) == set(reliability_settings.ALLOWED_KEYS)
    assert len(ctx) == 12
