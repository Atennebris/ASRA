"""Settings/Subagents route + agent/llm_client.py wiring for "Sign in with GitHub Copilot" -- the
plumbing that gets CopilotOAuthProvider actually reachable from the UI, mirroring
tests/test_codex_settings_routes.py's own coverage for the ChatGPT counterpart.
"""
from fastapi.testclient import TestClient

import agent.copilot_oauth as copilot_oauth
import main
from agent.copilot_provider import COPILOT_MODELS
from agent.llm_client import (
    COPILOT_PROVIDER_ID,
    all_provider_choices,
    get_model_choices,
    get_provider,
    is_known_provider_id,
)


def test_copilot_provider_id_is_known_and_listed():
    assert is_known_provider_id(COPILOT_PROVIDER_ID)
    assert COPILOT_PROVIDER_ID in dict(all_provider_choices())


def test_copilot_model_choices_fall_back_to_the_static_list_when_not_signed_in():
    models = get_model_choices(COPILOT_PROVIDER_ID)
    assert set(models) == set(COPILOT_MODELS.keys())


def test_get_provider_raises_value_error_when_signed_out():
    """ValueError specifically (not copilot_oauth's own RuntimeError) -- get_next_chain_step's own
    `except ValueError: skip this step` fallback-chain handling depends on this, see
    agent/llm_client.py's _get_copilot_provider docstring."""
    import pytest
    with pytest.raises(ValueError, match="Not signed in"):
        get_provider(COPILOT_PROVIDER_ID, "gpt-4.1")


def test_get_provider_returns_a_copilot_provider_once_signed_in():
    copilot_oauth.save_tokens({"github_token": "gho_1"})
    provider = get_provider(COPILOT_PROVIDER_ID, "gpt-4.1")
    assert provider.provider_id == COPILOT_PROVIDER_ID
    assert provider.model == "gpt-4.1"


client = TestClient(main.app)


def test_settings_page_renders_signed_out_state():
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Sign in with GitHub Copilot" in resp.text
    assert "Not signed in" in resp.text


def test_settings_page_renders_signed_in_state():
    copilot_oauth.save_tokens({"github_token": "gho_1"})
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Signed in" in resp.text
    assert "Sign out" in resp.text


def test_settings_page_renders_when_copilot_is_the_saved_main_provider():
    """The real KeyError risk this guards: _llm_settings_context()/settings.html both subscript
    PROVIDER_REGISTRY-only dicts (provider_is_local, provider_key_status, ...) by current_provider
    -- COPILOT_PROVIDER_ID must be special-cased everywhere that happens, or saving it as the main
    AI Provider & Model choice would 500 the whole Settings page on the very next load.
    """
    from agent.settings import save_llm_settings
    save_llm_settings(COPILOT_PROVIDER_ID, "gpt-4.1")
    resp = client.get("/settings")
    assert resp.status_code == 200


def test_model_options_endpoint_for_copilot_provider():
    resp = client.get("/api/settings/model-options", params={"provider": COPILOT_PROVIDER_ID})
    assert resp.status_code == 200
    assert "gpt-4.1" in resp.text


def test_save_llm_accepts_copilot_provider_id():
    resp = client.post("/api/settings/llm", data={"provider": COPILOT_PROVIDER_ID, "model": "gpt-4.1"}, follow_redirects=False)
    assert resp.status_code == 303


def test_login_start_route_returns_whatever_start_login_flow_produces(monkeypatch):
    """Route-level plumbing only -- the real device-flow/polling behavior behind start_login_flow
    itself is exercised by test_copilot_oauth.py's own dedicated tests. Stubbed here so this test
    never makes a real network call to GitHub."""
    monkeypatch.setattr(main, "start_copilot_login_flow", lambda: {
        "device_code": "dc_1", "user_code": "ABCD-1234", "verification_uri": "https://github.com/login/device", "interval": 5, "expires_in": 900,
    })
    resp = client.post("/api/settings/providers/github-copilot/login/start")
    assert resp.status_code == 200
    assert resp.json()["user_code"] == "ABCD-1234"


def test_login_start_route_turns_a_runtime_error_into_a_json_error_shape(monkeypatch):
    monkeypatch.setattr(main, "start_copilot_login_flow", lambda: (_ for _ in ()).throw(RuntimeError("GitHub is unreachable")))
    resp = client.post("/api/settings/providers/github-copilot/login/start")
    assert resp.status_code == 200
    assert resp.json() == {"error": "GitHub is unreachable"}


def test_login_status_route_forwards_get_login_status(monkeypatch):
    monkeypatch.setattr(main, "get_copilot_login_status", lambda device_code: {"status": "success", "message": f"got {device_code}"})
    resp = client.get("/api/settings/providers/github-copilot/login/status", params={"device_code": "abc"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "success", "message": "got abc"}


def test_login_status_missing_device_code_is_an_error():
    resp = client.get("/api/settings/providers/github-copilot/login/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"


def test_logout_route_clears_tokens_and_redirects():
    copilot_oauth.save_tokens({"github_token": "gho_1"})
    resp = client.post("/api/settings/providers/github-copilot/logout", follow_redirects=False)
    assert resp.status_code == 303
    assert copilot_oauth.load_tokens() is None


def test_subagents_page_offers_copilot_only_when_signed_in():
    resp_signed_out = client.get("/subagents")
    assert resp_signed_out.status_code == 200
    assert "GitHub Copilot sign-in" not in resp_signed_out.text

    copilot_oauth.save_tokens({"github_token": "gho_1"})
    resp_signed_in = client.get("/subagents")
    assert resp_signed_in.status_code == 200
    assert "GitHub Copilot sign-in" in resp_signed_in.text


def test_system_health_considers_copilot_sign_in_a_usable_provider(monkeypatch):
    """A machine with zero API keys and zero custom providers, but signed in to GitHub Copilot,
    must not report "No LLM provider is configured" -- see _check_system_health's own
    has_usable_provider."""
    from agent.llm_client import PROVIDER_REGISTRY
    for cfg in PROVIDER_REGISTRY.values():
        monkeypatch.delenv(cfg.api_key_env, raising=False)
    copilot_oauth.save_tokens({"github_token": "gho_1"})

    healthy, reason = main._check_system_health()
    assert healthy, reason
