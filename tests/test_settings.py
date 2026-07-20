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
