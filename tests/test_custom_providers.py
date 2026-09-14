"""agent/custom_providers.py: arbitrary, operator-named custom LLM provider instances on top of
PROVIDER_REGISTRY's 6 built-ins (agent/llm_client.py). Covers the CRUD module itself, its
integration into get_provider/get_model_choices/all_provider_choices/is_known_provider_id, and the
Settings routes (main.py) that expose it.
"""
from unittest.mock import patch

from fastapi.testclient import TestClient

import agent.custom_providers as custom_providers
import agent.llm_client as llm_client
import main


# --- agent/custom_providers.py: plain CRUD ---


def test_create_then_load_round_trips():
    entry = custom_providers.create_custom_provider("My Provider", "https://example.test/v1", "sk-test", "some-model")
    assert entry["name"] == "My Provider"
    assert entry["base_url"] == "https://example.test/v1"
    assert entry["api_key"] == "sk-test"
    assert entry["model"] == "some-model"
    assert entry["enabled"] is True
    assert entry["id"].startswith("custom-")
    assert custom_providers.load_custom_providers() == [entry]


def test_create_defaults_to_universal_type_for_an_unknown_type():
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1", type="not-a-real-preset")
    assert entry["type"] == "universal"


def test_get_custom_provider_returns_none_when_missing():
    assert custom_providers.get_custom_provider("custom-doesnotexist") is None


def test_update_custom_provider_only_touches_known_fields():
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1")
    updated = custom_providers.update_custom_provider(entry["id"], name="Renamed", enabled=False, not_a_real_field="ignored")
    assert updated["name"] == "Renamed"
    assert updated["enabled"] is False
    assert "not_a_real_field" not in updated
    assert updated["id"] == entry["id"]  # id itself is never overwritable


def test_update_custom_provider_returns_none_for_unknown_id():
    assert custom_providers.update_custom_provider("custom-doesnotexist", name="X") is None


def test_delete_custom_provider_removes_it_and_reports_success():
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1")
    assert custom_providers.delete_custom_provider(entry["id"]) is True
    assert custom_providers.load_custom_providers() == []


def test_delete_custom_provider_returns_false_for_unknown_id():
    assert custom_providers.delete_custom_provider("custom-doesnotexist") is False


def test_is_custom_provider_id():
    assert custom_providers.is_custom_provider_id("custom-abc123") is True
    assert custom_providers.is_custom_provider_id("qwen") is False


def test_load_returns_empty_list_when_file_missing():
    assert custom_providers.load_custom_providers() == []


def test_load_returns_empty_list_for_corrupt_json(tmp_path):
    custom_providers.CUSTOM_PROVIDERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    custom_providers.CUSTOM_PROVIDERS_PATH.write_text("{not valid json")
    assert custom_providers.load_custom_providers() == []


# --- agent/llm_client.py integration ---


def test_get_provider_resolves_a_custom_instance():
    entry = custom_providers.create_custom_provider("My Provider", "https://example.test/v1", "sk-test", "some-model")
    provider = llm_client.get_provider(entry["id"])
    assert provider.provider_id == entry["id"]
    assert provider.model == "some-model"


def test_get_provider_explicit_model_overrides_the_saved_one():
    entry = custom_providers.create_custom_provider("My Provider", "https://example.test/v1", model="default-model")
    provider = llm_client.get_provider(entry["id"], "override-model")
    assert provider.model == "override-model"


def test_get_provider_raises_for_a_disabled_custom_instance():
    entry = custom_providers.create_custom_provider("My Provider", "https://example.test/v1", model="m")
    custom_providers.update_custom_provider(entry["id"], enabled=False)
    try:
        llm_client.get_provider(entry["id"])
        assert False, "expected ValueError for a disabled custom provider"
    except ValueError as exc:
        assert "disabled" in str(exc)


def test_get_provider_raises_when_a_custom_instance_has_no_model_at_all():
    entry = custom_providers.create_custom_provider("My Provider", "https://example.test/v1")  # no model
    try:
        llm_client.get_provider(entry["id"])
        assert False, "expected ValueError for a custom provider with no model"
    except ValueError as exc:
        assert "No model" in str(exc)


def test_get_provider_raises_for_an_unknown_custom_id():
    try:
        llm_client.get_provider("custom-doesnotexist", "m")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "Unknown LLM provider" in str(exc)


def test_all_provider_choices_includes_built_ins_and_enabled_custom_instances():
    entry = custom_providers.create_custom_provider("My Custom Name", "https://example.test/v1")
    choices = dict(llm_client.all_provider_choices())
    assert choices["qwen"] == "Qwen"
    assert choices[entry["id"]] == "My Custom Name"


def test_all_provider_choices_excludes_disabled_custom_instances():
    entry = custom_providers.create_custom_provider("Disabled One", "https://example.test/v1")
    custom_providers.update_custom_provider(entry["id"], enabled=False)
    choices = dict(llm_client.all_provider_choices())
    assert entry["id"] not in choices


def test_is_known_provider_id_recognizes_both_kinds():
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1")
    assert llm_client.is_known_provider_id("qwen") is True
    assert llm_client.is_known_provider_id(entry["id"]) is True
    assert llm_client.is_known_provider_id("not-a-real-provider") is False


def test_get_model_choices_queries_the_custom_instance_live(monkeypatch):
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1", "sk-test")
    monkeypatch.setattr(llm_client, "_fetch_local_model_ids", lambda base_url, api_key: ["model-a", "model-b"])
    assert llm_client.get_model_choices(entry["id"]) == ["model-a", "model-b"]


def test_get_model_choices_empty_for_unknown_custom_id():
    assert llm_client.get_model_choices("custom-doesnotexist") == []


# --- main.py routes ---


def test_settings_page_shows_a_created_custom_provider():
    custom_providers.create_custom_provider("My Custom Provider", "https://example.test/v1")
    client = TestClient(main.app)
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert "My Custom Provider" in resp.text


def test_add_custom_provider_route_creates_and_redirects():
    client = TestClient(main.app)
    resp = client.post(
        "/api/settings/providers/custom",
        data={"name": "New One", "type": "universal", "base_url": "https://example.test/v1", "api_key": "sk-x", "model": "m"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    saved = custom_providers.load_custom_providers()
    assert len(saved) == 1
    assert saved[0]["name"] == "New One"


def test_add_custom_provider_route_activates_a_builtin_instead_of_creating_a_custom_entry():
    """Real incident this covers: Type="openrouter" used to create a SEPARATE custom_providers.json
    entry that duplicated OpenRouter's own name/badge (confusing -- see agent/custom_providers.py's
    own CUSTOM_PROVIDER_TYPE_PRESETS docstring for the full incident). Picking a real
    PROVIDER_REGISTRY id from the Add Provider Type dropdown must activate that REAL built-in row
    (save its key/endpoint, mark it added) and create NO custom-provider entry at all."""
    client = TestClient(main.app)
    resp = client.post(
        "/api/settings/providers/custom",
        data={"name": "ignored for a built-in", "type": "openrouter", "base_url": "", "api_key": "sk-or-test", "model": ""},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert custom_providers.load_custom_providers() == []
    import agent.settings as settings_mod
    assert "openrouter" in settings_mod.get_added_providers()
    import os
    assert os.getenv("OPENROUTER_API_KEY") == "sk-or-test"


def test_add_custom_provider_route_rejects_a_blank_name():
    client = TestClient(main.app)
    resp = client.post(
        "/api/settings/providers/custom",
        data={"name": "", "type": "universal", "base_url": "https://example.test/v1"},
    )
    assert resp.status_code == 400
    assert "name is required" in resp.text.lower()
    assert custom_providers.load_custom_providers() == []


def test_add_custom_provider_route_rejects_no_base_url_for_universal_type():
    client = TestClient(main.app)
    resp = client.post(
        "/api/settings/providers/custom",
        data={"name": "X", "type": "universal", "base_url": ""},
    )
    assert resp.status_code == 400
    assert "base url" in resp.text.lower()


def test_toggle_custom_provider_route_flips_enabled_state():
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1")
    client = TestClient(main.app)
    resp = client.post(f"/api/settings/providers/custom/{entry['id']}/toggle", follow_redirects=False)
    assert resp.status_code == 303
    assert custom_providers.get_custom_provider(entry["id"])["enabled"] is False


def test_toggle_custom_provider_route_404s_for_unknown_id():
    client = TestClient(main.app)
    resp = client.post("/api/settings/providers/custom/custom-doesnotexist/toggle")
    assert resp.status_code == 404


def test_delete_custom_provider_route_removes_it():
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1")
    client = TestClient(main.app)
    resp = client.post(f"/api/settings/providers/custom/{entry['id']}/delete", follow_redirects=False)
    assert resp.status_code == 303
    assert custom_providers.load_custom_providers() == []


def test_delete_custom_provider_route_404s_for_unknown_id():
    client = TestClient(main.app)
    resp = client.post("/api/settings/providers/custom/custom-doesnotexist/delete")
    assert resp.status_code == 404


def test_test_custom_provider_route_reports_a_blank_base_url():
    client = TestClient(main.app)
    resp = client.post("/api/settings/providers/custom/test", data={"base_url": "", "api_key": ""})
    assert resp.status_code == 200
    assert "Base URL" in resp.text or "base url" in resp.text.lower()


def test_test_custom_provider_route_reports_a_connection_failure_cleanly():
    client = TestClient(main.app)
    with patch("main.test_custom_provider_connection", return_value={"ok": False, "message": "Could not reach the provider."}):
        resp = client.post(
            "/api/settings/providers/custom/test",
            data={"base_url": "https://unreachable.example.test/v1", "api_key": ""},
        )
    assert resp.status_code == 200
    assert "Could not reach the provider." in resp.text


def test_save_llm_accepts_a_custom_provider_as_the_main_choice():
    entry = custom_providers.create_custom_provider("X", "https://example.test/v1", model="m")
    client = TestClient(main.app)
    resp = client.post("/api/settings/llm", data={"provider": entry["id"], "model": "m"}, follow_redirects=False)
    assert resp.status_code == 303

    from agent.settings import load_llm_settings
    assert load_llm_settings()["provider"] == entry["id"]
