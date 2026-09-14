"""Settings -> Secondary verification provider (main.py's /api/settings/secondary-verification
route + settings.html's own section) -- the UI half of agent/settings.py's
get_secondary_verification_provider/save_secondary_verification_provider (already unit-tested
directly in tests/test_settings.py). Isolated to a tmp_path settings file, unlike
tests/test_fallback_chain_settings_route.py's own pre-existing convention of writing to the real
machine settings file -- both are fine, this one just doesn't need to touch real state to prove
the route/template wiring.
"""
from fastapi.testclient import TestClient

import main
from agent import settings


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SETTINGS_PATH", tmp_path / "llm_settings.json")


def test_settings_page_renders_the_secondary_verification_section(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "Secondary verification provider" in resp.text
    assert 'id="secondary-verification-provider-select"' in resp.text
    assert 'id="secondary-verification-model-select"' in resp.text
    assert "(disabled)" in resp.text


def test_save_secondary_verification_persists_and_redisplays(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    client = TestClient(main.app)

    resp = client.post(
        "/api/settings/secondary-verification",
        data={"provider": "qwen", "model": "qwen-plus"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert settings.get_secondary_verification_provider() == {"provider": "qwen", "model": "qwen-plus"}

    page = client.get("/settings")
    assert 'value="qwen" selected' in page.text
    assert 'value="qwen-plus" selected' in page.text


def test_save_secondary_verification_blank_clears_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    settings.save_secondary_verification_provider("qwen", "qwen-plus")
    client = TestClient(main.app)

    resp = client.post(
        "/api/settings/secondary-verification",
        data={"provider": "", "model": ""},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert settings.get_secondary_verification_provider() is None


def test_settings_page_shows_disabled_by_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert 'value="" selected' in resp.text or 'value=""selected' in resp.text


def _clear_all_provider_keys(monkeypatch):
    from agent.llm_client import PROVIDER_REGISTRY
    for config in PROVIDER_REGISTRY.values():
        monkeypatch.delenv(config.api_key_env, raising=False)


def test_secondary_verification_dropdown_excludes_an_unconfigured_provider(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _clear_all_provider_keys(monkeypatch)
    context = main._secondary_verification_context()
    ids = {pid for pid, _ in context["secondary_verification_provider_choices"]}
    assert "qwen" not in ids
    assert "opencode-zen" in ids


def test_secondary_verification_dropdown_includes_a_configured_provider(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _clear_all_provider_keys(monkeypatch)
    monkeypatch.setenv("QWEN_API_KEY", "sk-real-looking-key-123")
    context = main._secondary_verification_context()
    ids = {pid for pid, _ in context["secondary_verification_provider_choices"]}
    assert "qwen" in ids


def test_secondary_verification_dropdown_keeps_a_saved_but_now_unconfigured_provider_visible(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    settings.save_secondary_verification_provider("qwen", "qwen-plus")
    _clear_all_provider_keys(monkeypatch)

    context = main._secondary_verification_context()
    ids = {pid for pid, _ in context["secondary_verification_provider_choices"]}
    assert "qwen" in ids
    assert context["secondary_verification_provider"] == "qwen"


def test_secondary_verification_dropdown_excludes_a_local_provider_that_is_not_reachable(tmp_path, monkeypatch):
    """conftest.py's own autouse fixture already stubs this to "nothing reachable" for every test
    -- this test just makes that behavior explicit and pins it down as a real regression guard."""
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "_reachable_local_provider_ids", lambda: set())
    context = main._secondary_verification_context()
    ids = {pid for pid, _ in context["secondary_verification_provider_choices"]}
    assert "lmstudio" not in ids
    assert "ollama" not in ids


def test_secondary_verification_dropdown_includes_a_reachable_local_provider(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "_reachable_local_provider_ids", lambda: {"lmstudio"})
    context = main._secondary_verification_context()
    ids = {pid for pid, _ in context["secondary_verification_provider_choices"]}
    assert "lmstudio" in ids
    assert "ollama" not in ids


def test_secondary_verification_dropdown_keeps_a_saved_but_now_unreachable_local_provider_visible(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    settings.save_secondary_verification_provider("lmstudio", "local-model")
    monkeypatch.setattr(main, "_reachable_local_provider_ids", lambda: set())

    context = main._secondary_verification_context()
    ids = {pid for pid, _ in context["secondary_verification_provider_choices"]}
    assert "lmstudio" in ids
    assert context["secondary_verification_provider"] == "lmstudio"
