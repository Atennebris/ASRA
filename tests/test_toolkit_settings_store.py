"""agent/tools/toolkit_settings_store.py -- the native toolkit's independent agent/chat/subagent
access toggles. Same on-disk convention as agent/tools/chat_settings_store.py (atomic
tmp+os.replace, corrupt/missing file treated as defaults, never an error) -- a separate
module/file, not an extension of it, since these are read by the main session loop and subagents
too, not just chat.
"""
import json

from agent.tools import toolkit_settings_store

# Built from BOOL_KEYS itself, not a hardcoded literal dict -- stays correct automatically as more
# toolkit capabilities get their own toggle.
_DEFAULTS = dict.fromkeys(toolkit_settings_store.BOOL_KEYS, False)


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_settings_store, "TOOLKIT_AGENT_SETTINGS_STORE_PATH", tmp_path / "toolkit_agent_settings.json")


def test_load_toolkit_agent_settings_returns_defaults_when_file_is_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert toolkit_settings_store.load_toolkit_agent_settings() == _DEFAULTS


def test_load_toolkit_agent_settings_treats_corrupt_json_as_defaults(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    toolkit_settings_store.TOOLKIT_AGENT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    toolkit_settings_store.TOOLKIT_AGENT_SETTINGS_STORE_PATH.write_text("{not valid json", encoding="utf-8")
    assert toolkit_settings_store.load_toolkit_agent_settings() == _DEFAULTS


def test_load_toolkit_agent_settings_treats_a_non_object_json_as_defaults(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    toolkit_settings_store.TOOLKIT_AGENT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    toolkit_settings_store.TOOLKIT_AGENT_SETTINGS_STORE_PATH.write_text("[1, 2, 3]", encoding="utf-8")
    assert toolkit_settings_store.load_toolkit_agent_settings() == _DEFAULTS


def test_load_toolkit_agent_settings_backfills_a_missing_key_with_its_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    toolkit_settings_store.TOOLKIT_AGENT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    toolkit_settings_store.TOOLKIT_AGENT_SETTINGS_STORE_PATH.write_text(json.dumps({"toolkit_proxy_enabled": True}), encoding="utf-8")

    expected = dict(_DEFAULTS)
    expected["toolkit_proxy_enabled"] = True
    assert toolkit_settings_store.load_toolkit_agent_settings() == expected


def test_save_toolkit_agent_settings_persists_all_values(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    given = dict(_DEFAULTS)
    given.update({"toolkit_proxy_enabled": True, "toolkit_repeater_enabled": True, "toolkit_comparer_enabled": True})
    saved = toolkit_settings_store.save_toolkit_agent_settings(given)

    assert saved == given
    assert toolkit_settings_store.load_toolkit_agent_settings() == given


def test_save_toolkit_agent_settings_defaults_missing_keys_to_false(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = toolkit_settings_store.save_toolkit_agent_settings({"toolkit_proxy_enabled": True})
    expected = dict(_DEFAULTS)
    expected["toolkit_proxy_enabled"] = True
    assert saved == expected


def test_save_toolkit_agent_settings_persists_the_intruder_toggle_independently(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = toolkit_settings_store.save_toolkit_agent_settings({"toolkit_intruder_enabled": True})
    assert saved["toolkit_intruder_enabled"] is True
    assert saved["toolkit_proxy_enabled"] is False


def test_save_toolkit_agent_settings_persists_the_sequencer_toggle_independently(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = toolkit_settings_store.save_toolkit_agent_settings({"toolkit_sequencer_enabled": True})
    assert saved["toolkit_sequencer_enabled"] is True
    assert saved["toolkit_proxy_enabled"] is False


def test_save_toolkit_agent_settings_overwrites_a_previous_save(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    toolkit_settings_store.save_toolkit_agent_settings(dict.fromkeys(toolkit_settings_store.BOOL_KEYS, True))

    toolkit_settings_store.save_toolkit_agent_settings(dict.fromkeys(toolkit_settings_store.BOOL_KEYS, False))

    assert toolkit_settings_store.load_toolkit_agent_settings() == _DEFAULTS
