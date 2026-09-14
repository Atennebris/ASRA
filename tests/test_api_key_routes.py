"""main.py's three Settings API-key routes (save/clear/test) -- mocked at the agent.llm_client
boundary so these tests never touch the real .env or make a real network call. The one thing they
must prove beyond route wiring: a submitted key value never comes back out in the rendered HTML.
"""
from fastapi.testclient import TestClient

import main
from agent.llm_client import PROVIDER_REGISTRY


def _provider_id():
    return next(iter(PROVIDER_REGISTRY))


def test_save_api_key_400s_for_unknown_provider():
    client = TestClient(main.app)
    resp = client.post("/api/settings/api-key", data={"provider": "not-real", "api_key": "sk-x"})
    assert resp.status_code == 400


def test_save_api_key_blank_value_is_a_no_op(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "save_provider_api_key", lambda provider, key: calls.append((provider, key)))
    client = TestClient(main.app)
    resp = client.post("/api/settings/api-key", data={"provider": _provider_id(), "api_key": "  "}, follow_redirects=False)
    assert resp.status_code == 303
    assert calls == []


def test_save_api_key_saves_a_non_blank_value(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "save_provider_api_key", lambda provider, key: calls.append((provider, key)))
    pid = _provider_id()
    client = TestClient(main.app)
    resp = client.post("/api/settings/api-key", data={"provider": pid, "api_key": " sk-real-value "}, follow_redirects=False)
    assert resp.status_code == 303
    assert calls == [(pid, "sk-real-value")]


def test_clear_api_key_400s_for_unknown_provider():
    client = TestClient(main.app)
    resp = client.post("/api/settings/clear-api-key", data={"provider": "not-real"})
    assert resp.status_code == 400


def test_clear_api_key_clears_the_configured_provider(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "clear_provider_api_key", lambda provider: calls.append(provider))
    pid = _provider_id()
    client = TestClient(main.app)
    resp = client.post("/api/settings/clear-api-key", data={"provider": pid}, follow_redirects=False)
    assert resp.status_code == 303
    assert calls == [pid]


def test_test_api_key_reports_unknown_provider():
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-api-key", data={"provider": "not-real", "api_key": "sk-x"})
    assert "Unknown provider" in resp.text


def test_test_api_key_reports_no_key_to_test_for_a_required_provider(monkeypatch):
    required_pid = next(pid for pid, cfg in PROVIDER_REGISTRY.items() if cfg.api_key_required)
    monkeypatch.delenv(PROVIDER_REGISTRY[required_pid].api_key_env, raising=False)
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-api-key", data={"provider": required_pid, "api_key": ""})
    assert "No key to test" in resp.text


def test_test_api_key_renders_a_mocked_success_result(monkeypatch):
    monkeypatch.setattr(main, "check_api_key", lambda provider, key, base_url=None: {"ok": True, "message": "Key accepted."})
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-api-key", data={"provider": _provider_id(), "api_key": "sk-x"})
    assert "Key accepted." in resp.text


def test_test_api_key_renders_a_mocked_failure_result(monkeypatch):
    monkeypatch.setattr(main, "check_api_key", lambda provider, key, base_url=None: {"ok": False, "message": "Rejected: authentication failed."})
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-api-key", data={"provider": _provider_id(), "api_key": "sk-x"})
    assert "Rejected: authentication failed." in resp.text


def test_test_api_key_never_echoes_the_submitted_key_value(monkeypatch):
    monkeypatch.setattr(main, "check_api_key", lambda provider, key, base_url=None: {"ok": True, "message": "Key accepted."})
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-api-key", data={"provider": _provider_id(), "api_key": "sk-super-secret-value"})
    assert "sk-super-secret-value" not in resp.text


def test_settings_page_renders_provider_key_status(monkeypatch):
    pid = _provider_id()
    monkeypatch.setenv(PROVIDER_REGISTRY[pid].api_key_env, "sk-configured")
    client = TestClient(main.app)
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "configured" in resp.text
    assert "sk-configured" not in resp.text


def test_test_api_key_reports_no_key_to_test_when_only_the_env_example_placeholder_is_set(monkeypatch):
    """Real incident this guards: a fresh .env.example -> .env copy leaves every *_API_KEY line set
    to its own literal "your_x_api_key_here" placeholder -- a non-empty string that used to read as
    a real saved key here (falling back to it via `os.getenv(...) or ""`), letting the Test button
    silently send that garbage to the real provider instead of telling the operator no real key is
    saved yet."""
    required_pid = next(pid for pid, cfg in PROVIDER_REGISTRY.items() if cfg.api_key_required)
    config = PROVIDER_REGISTRY[required_pid]
    monkeypatch.setenv(config.api_key_env, f"your_{required_pid}_api_key_here")
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-api-key", data={"provider": required_pid, "api_key": ""})
    assert "No key to test" in resp.text


def test_llm_settings_context_does_not_mark_a_placeholder_only_provider_as_configured(monkeypatch):
    """The other half of the same real incident: Settings' own "Configured" badge (provider_key_
    status, main.py's _llm_settings_context) must not light up for a provider whose .env value is
    still literally .env.example's own unfilled placeholder text -- confirmed live, this used to
    show every one of 13 built-ins as "Configured" on a completely fresh install, before the
    operator had touched a single field."""
    pid = _provider_id()
    monkeypatch.setenv(PROVIDER_REGISTRY[pid].api_key_env, f"your_{pid}_api_key_here")
    assert main._llm_settings_context()["provider_key_status"][pid] is False
