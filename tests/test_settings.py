"""agent/settings.py: load/save the global LLM provider+model choice (Settings screen)."""
import pytest

from agent import settings


@pytest.fixture(autouse=True)
def _isolated_settings_path(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SETTINGS_PATH", tmp_path / "llm_settings.json")
    return tmp_path


def test_load_returns_empty_dict_when_file_missing():
    assert settings.load_llm_settings() == {}


def test_save_then_load_round_trips():
    settings.save_llm_settings("qwen", "qwen-plus")
    assert settings.load_llm_settings() == {"provider": "qwen", "model": "qwen-plus"}


def test_save_leaves_no_temp_file_behind(_isolated_settings_path):
    settings.save_llm_settings("opencode-zen", "big-pickle")
    assert list(_isolated_settings_path.glob("*.json.tmp")) == []


def test_load_returns_empty_dict_for_corrupt_json(_isolated_settings_path):
    settings.SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings.SETTINGS_PATH.write_text("{not valid json")
    assert settings.load_llm_settings() == {}


def test_load_returns_empty_dict_when_file_is_not_a_json_object(_isolated_settings_path):
    settings.SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    settings.SETTINGS_PATH.write_text("[1, 2, 3]")
    assert settings.load_llm_settings() == {}


# --- save_llm_settings/save_fallback_chain_settings: two separate Settings forms sharing one file
# -- each must MERGE onto whatever the other already saved, not clobber it. Real bug this guards:
# save_llm_settings used to json.dump({"provider": ..., "model": ...}) unconditionally, which would
# have silently wiped out a previously-saved fallback_chain the instant the provider/model form was
# submitted again.


def test_saving_provider_model_does_not_erase_a_previously_saved_fallback_chain():
    settings.save_fallback_chain_settings(True, [{"provider": "qwen", "model": "qwen-plus"}])
    settings.save_llm_settings("mistral", "mistral-small-latest")

    saved = settings.load_llm_settings()
    assert saved["provider"] == "mistral"
    assert saved["model"] == "mistral-small-latest"
    assert saved["fallback_chain_enabled"] is True
    assert saved["fallback_chain"] == [{"provider": "qwen", "model": "qwen-plus"}]


def test_saving_fallback_chain_does_not_erase_a_previously_saved_provider_model():
    settings.save_llm_settings("mistral", "mistral-small-latest")
    settings.save_fallback_chain_settings(True, [{"provider": "qwen", "model": "qwen-plus"}])

    saved = settings.load_llm_settings()
    assert saved["provider"] == "mistral"
    assert saved["model"] == "mistral-small-latest"
    assert saved["fallback_chain_enabled"] is True


def test_save_fallback_chain_settings_preserves_row_order():
    """Order is meaningful (the chain is tried top to bottom) -- several rows for the same provider
    is how "try this model, then that one" is expressed, so order must survive a save/load round
    trip exactly, not just membership."""
    chain = [
        {"provider": "qwen", "model": "qwen-plus"},
        {"provider": "qwen", "model": "qwen-turbo"},
        {"provider": "mistral", "model": "mistral-small-latest"},
    ]
    settings.save_fallback_chain_settings(True, chain)
    assert settings.load_llm_settings()["fallback_chain"] == chain


# --- get_secondary_verification_provider/save_secondary_verification_provider: opt-in ensemble
# second-opinion check for Skeptical Verification (agent/core.py's _run_skeptical_verification) --
# None by default (feature off), same "nothing set -> no behavior change" convention as everything
# else in this module.


def test_secondary_verification_provider_is_none_by_default():
    assert settings.get_secondary_verification_provider() is None


def test_save_then_get_secondary_verification_provider_round_trips():
    settings.save_secondary_verification_provider("mistral", "mistral-small-latest")
    assert settings.get_secondary_verification_provider() == {"provider": "mistral", "model": "mistral-small-latest"}


def test_save_secondary_verification_provider_with_blank_values_clears_it():
    settings.save_secondary_verification_provider("mistral", "mistral-small-latest")
    settings.save_secondary_verification_provider(None, None)
    assert settings.get_secondary_verification_provider() is None


def test_save_secondary_verification_provider_does_not_erase_the_main_provider_choice():
    settings.save_llm_settings("mistral", "mistral-small-latest")
    settings.save_secondary_verification_provider("qwen", "qwen-plus")

    saved = settings.load_llm_settings()
    assert saved["provider"] == "mistral"
    assert saved["model"] == "mistral-small-latest"
    assert saved["secondary_verification_provider"] == "qwen"
    assert saved["secondary_verification_model"] == "qwen-plus"
