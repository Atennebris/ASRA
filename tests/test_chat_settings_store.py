"""agent/tools/chat_settings_store.py — the chat panel's own web_fetch/browser/subagent capability
toggles, plus the last provider/model the operator explicitly picked in the chat picker. Same
on-disk convention as agent/tools/wordlist_store.py (load/_write pair, atomic tmp+os.replace,
corrupt/missing file treated as defaults, never an error).
"""
import json

from agent.tools import chat_settings_store

_DEFAULTS = {
    "web_fetch_enabled": True,
    "browser_enabled": True,
    "subagents_enabled": False,
    "dork_engine_enabled": True,
    "last_provider": None,
    "last_model": None,
    "quick_chat_session_id": None,
}


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(chat_settings_store, "CHAT_SETTINGS_STORE_PATH", tmp_path / "chat_settings.json")


def test_load_chat_settings_returns_defaults_when_file_is_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert chat_settings_store.load_chat_settings() == _DEFAULTS


def test_load_chat_settings_treats_corrupt_json_as_defaults(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.CHAT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    chat_settings_store.CHAT_SETTINGS_STORE_PATH.write_text("{not valid json", encoding="utf-8")
    assert chat_settings_store.load_chat_settings() == _DEFAULTS


def test_load_chat_settings_treats_a_non_object_json_as_defaults(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.CHAT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    chat_settings_store.CHAT_SETTINGS_STORE_PATH.write_text("[1, 2, 3]", encoding="utf-8")
    assert chat_settings_store.load_chat_settings() == _DEFAULTS


def test_load_chat_settings_backfills_a_missing_key_with_its_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.CHAT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    chat_settings_store.CHAT_SETTINGS_STORE_PATH.write_text(json.dumps({"web_fetch_enabled": False}), encoding="utf-8")

    assert chat_settings_store.load_chat_settings() == {
        "web_fetch_enabled": False, "browser_enabled": True, "subagents_enabled": False, "dork_engine_enabled": True, "last_provider": None, "last_model": None, "quick_chat_session_id": None,
    }


def test_save_chat_settings_persists_all_three_values(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = chat_settings_store.save_chat_settings(False, True, True)

    expected = {"web_fetch_enabled": False, "browser_enabled": True, "subagents_enabled": True, "dork_engine_enabled": True, "last_provider": None, "last_model": None, "quick_chat_session_id": None}
    assert saved == expected
    assert chat_settings_store.load_chat_settings() == expected


def test_save_chat_settings_defaults_subagents_enabled_to_false_when_omitted(tmp_path, monkeypatch):
    """save_chat_settings(web_fetch_enabled, browser_enabled) with no third argument -- an older
    caller shaped like this must not crash, and must not silently enable subagent delegation."""
    _isolate(tmp_path, monkeypatch)
    saved = chat_settings_store.save_chat_settings(True, True)
    assert saved["subagents_enabled"] is False


def test_save_chat_settings_overwrites_a_previous_save(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(True, True, True)

    chat_settings_store.save_chat_settings(False, False, False)

    assert chat_settings_store.load_chat_settings() == {
        "web_fetch_enabled": False, "browser_enabled": False, "subagents_enabled": False, "dork_engine_enabled": True, "last_provider": None, "last_model": None, "quick_chat_session_id": None,
    }


# --- last_provider/last_model: the chat panel's own remembered provider/model pick ---


def test_save_last_chat_llm_persists_provider_and_model(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = chat_settings_store.save_last_chat_llm("ollama", "big-pickle")

    assert saved["last_provider"] == "ollama"
    assert saved["last_model"] == "big-pickle"
    assert chat_settings_store.load_chat_settings()["last_provider"] == "ollama"
    assert chat_settings_store.load_chat_settings()["last_model"] == "big-pickle"


def test_save_last_chat_llm_treats_blank_as_none(tmp_path, monkeypatch):
    """An explicit "(same as main agent)" pick (empty string from the <select>) is remembered as
    blank too, not coerced into some other truthy placeholder."""
    _isolate(tmp_path, monkeypatch)
    saved = chat_settings_store.save_last_chat_llm("", "")
    assert saved["last_provider"] is None
    assert saved["last_model"] is None


def test_save_last_chat_llm_does_not_clobber_the_capability_toggles(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, True)

    chat_settings_store.save_last_chat_llm("ollama", "big-pickle")

    settings = chat_settings_store.load_chat_settings()
    assert settings["web_fetch_enabled"] is False
    assert settings["browser_enabled"] is False
    assert settings["subagents_enabled"] is True


def test_save_chat_settings_does_not_clobber_a_previously_saved_last_provider(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.save_last_chat_llm("ollama", "big-pickle")

    chat_settings_store.save_chat_settings(False, True, False)

    settings = chat_settings_store.load_chat_settings()
    assert settings["last_provider"] == "ollama"
    assert settings["last_model"] == "big-pickle"


# --- quick_chat_session_id: the real session id backing the top-level, project-less Quick Chat ---


def test_save_quick_chat_session_id_persists_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = chat_settings_store.save_quick_chat_session_id("usr_abc123")

    assert saved["quick_chat_session_id"] == "usr_abc123"
    assert chat_settings_store.load_chat_settings()["quick_chat_session_id"] == "usr_abc123"


def test_save_quick_chat_session_id_does_not_clobber_the_capability_toggles(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, True)

    chat_settings_store.save_quick_chat_session_id("usr_abc123")

    settings = chat_settings_store.load_chat_settings()
    assert settings["subagents_enabled"] is True
    assert settings["quick_chat_session_id"] == "usr_abc123"
