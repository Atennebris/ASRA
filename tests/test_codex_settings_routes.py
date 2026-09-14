"""Settings/Subagents route + agent/llm_client.py wiring for "Sign in with ChatGPT" -- the plumbing
that gets CodexOAuthProvider actually reachable from the UI (dropdown options, model lists, the
settings.html/subagents.html render paths that would KeyError on a PROVIDER_REGISTRY-only dict if
CODEX_PROVIDER_ID weren't special-cased everywhere those dicts get subscripted by current_provider).
"""
import time

from fastapi.testclient import TestClient

import agent.codex_oauth as codex_oauth
import main
from agent.llm_client import (
    CODEX_PROVIDER_ID,
    all_provider_choices,
    get_model_choices,
    get_provider,
    is_known_provider_id,
)


def test_codex_provider_id_is_known_and_listed():
    assert is_known_provider_id(CODEX_PROVIDER_ID)
    assert CODEX_PROVIDER_ID in dict(all_provider_choices())


def test_codex_model_choices_are_the_static_codex_list():
    models = get_model_choices(CODEX_PROVIDER_ID)
    assert "gpt-5.3-codex" in models
    assert len(models) > 0


def test_get_provider_raises_value_error_when_signed_out():
    """ValueError specifically (not codex_oauth's own RuntimeError) -- get_next_chain_step's own
    `except ValueError: skip this step` fallback-chain handling depends on this, see
    agent/llm_client.py's _get_codex_provider docstring."""
    import pytest
    with pytest.raises(ValueError, match="Not signed in"):
        get_provider(CODEX_PROVIDER_ID, "gpt-5.3-codex")


def test_get_provider_returns_a_codex_provider_once_signed_in():
    codex_oauth.save_tokens({"access": "a", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"})
    provider = get_provider(CODEX_PROVIDER_ID, "gpt-5.3-codex")
    assert provider.provider_id == CODEX_PROVIDER_ID
    assert provider.model == "gpt-5.3-codex"


client = TestClient(main.app)


def test_settings_page_renders_signed_out_state():
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Sign in with ChatGPT" in resp.text
    assert "Not signed in" in resp.text


def test_settings_page_renders_signed_in_state():
    codex_oauth.save_tokens({"access": "a", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_12345678"})
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "Signed in" in resp.text
    assert "acct_123" in resp.text  # account_id[:8] truncation
    assert "Sign out" in resp.text


def test_settings_page_renders_when_codex_is_the_saved_main_provider():
    """The real KeyError risk this guards: _llm_settings_context()/settings.html both subscript
    PROVIDER_REGISTRY-only dicts (provider_is_local, provider_key_status, ...) by current_provider
    -- CODEX_PROVIDER_ID must be special-cased everywhere that happens, or saving it as the main
    AI Provider & Model choice would 500 the whole Settings page on the very next load.
    """
    from agent.settings import save_llm_settings
    save_llm_settings(CODEX_PROVIDER_ID, "gpt-5.3-codex")
    resp = client.get("/settings")
    assert resp.status_code == 200


def test_model_options_endpoint_for_codex_provider():
    resp = client.get("/api/settings/model-options", params={"provider": CODEX_PROVIDER_ID})
    assert resp.status_code == 200
    assert "gpt-5.3-codex" in resp.text


def test_save_llm_accepts_codex_provider_id():
    resp = client.post("/api/settings/llm", data={"provider": CODEX_PROVIDER_ID, "model": "gpt-5.3-codex"}, follow_redirects=False)
    assert resp.status_code == 303


def test_login_start_route_returns_whatever_start_login_flow_produces(monkeypatch):
    """Route-level plumbing only (does main.py forward the JSON correctly) -- the real PKCE/state/
    local-listener behavior behind start_login_flow itself is exercised end-to-end, through a real
    socket, by test_codex_oauth.py's own dedicated tests. Stubbed here so this test doesn't also
    bind the real port 1455 for up to 300s just to check a route forwards a dict.
    """
    monkeypatch.setattr(main, "start_codex_login_flow", lambda: {"state": "fake-state", "auth_url": "https://auth.openai.com/oauth/authorize?state=fake-state"})
    resp = client.post("/api/settings/providers/openai-chatgpt/login/start")
    assert resp.status_code == 200
    assert resp.json() == {"state": "fake-state", "auth_url": "https://auth.openai.com/oauth/authorize?state=fake-state"}


def test_login_status_route_forwards_get_login_status(monkeypatch):
    monkeypatch.setattr(main, "get_codex_login_status", lambda state: {"status": "success", "message": f"got {state}"})
    resp = client.get("/api/settings/providers/openai-chatgpt/login/status", params={"state": "abc"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "success", "message": "got abc"}


def test_login_status_missing_state_is_an_error():
    resp = client.get("/api/settings/providers/openai-chatgpt/login/status")
    assert resp.status_code == 200
    assert resp.json()["status"] == "error"


def test_logout_route_clears_tokens_and_redirects():
    codex_oauth.save_tokens({"access": "a", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"})
    resp = client.post("/api/settings/providers/openai-chatgpt/logout", follow_redirects=False)
    assert resp.status_code == 303
    assert codex_oauth.load_tokens() is None


def test_subagents_page_offers_codex_only_when_signed_in():
    resp_signed_out = client.get("/subagents")
    assert resp_signed_out.status_code == 200
    assert "ChatGPT sign-in" not in resp_signed_out.text

    codex_oauth.save_tokens({"access": "a", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"})
    resp_signed_in = client.get("/subagents")
    assert resp_signed_in.status_code == 200
    assert "ChatGPT sign-in" in resp_signed_in.text


def test_system_health_considers_codex_sign_in_a_usable_provider(monkeypatch):
    """A machine with zero API keys and zero custom providers, but signed in to ChatGPT, must not
    report "No LLM provider is configured" -- see _check_system_health's own has_usable_provider.
    """
    from agent.llm_client import PROVIDER_REGISTRY
    for cfg in PROVIDER_REGISTRY.values():
        monkeypatch.delenv(cfg.api_key_env, raising=False)
    codex_oauth.save_tokens({"access": "a", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"})

    healthy, reason = main._check_system_health()
    assert healthy, reason
