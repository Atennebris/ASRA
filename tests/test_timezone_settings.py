"""Regression coverage for agent/timezone_settings.py's _load_raw() cache -- real, confirmed
incident (2026-11-08): main.py's _human_dt Jinja filter calls load_display_timezone() once PER
TIMESTAMP rendered, and a real session page with a lot of history profiled at 949 separate calls,
each paying its own fresh disk read -- ~3.2s of a ~4.1s total page render on its own. Fixed with a
short TTL cache, same shape as agent/settings.py's own _settings_cache.
"""
import agent.timezone_settings as timezone_settings


def test_load_display_timezone_does_not_reread_disk_within_the_ttl_window(tmp_path, monkeypatch):
    monkeypatch.setattr(timezone_settings, "SETTINGS_PATH", tmp_path / "tz.json")
    timezone_settings.save_display_timezone("Europe/Chisinau")

    import json as json_mod
    real_load = json_mod.load
    calls = []

    def counting_load(f):
        calls.append(1)
        return real_load(f)

    monkeypatch.setattr(timezone_settings.json, "load", counting_load)

    for _ in range(50):
        assert timezone_settings.load_display_timezone() == "Europe/Chisinau"

    assert len(calls) == 1


def test_save_display_timezone_invalidates_the_cache_immediately(tmp_path, monkeypatch):
    monkeypatch.setattr(timezone_settings, "SETTINGS_PATH", tmp_path / "tz.json")
    timezone_settings.save_display_timezone("Europe/Chisinau")
    assert timezone_settings.load_display_timezone() == "Europe/Chisinau"

    timezone_settings.save_display_timezone("America/New_York")

    assert timezone_settings.load_display_timezone() == "America/New_York"
