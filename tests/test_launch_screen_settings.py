"""Settings -> Customization -> Visual's "Launch screen" picker: animated intro (default), dragon
progress bar, or nothing. Stored as two boolean env vars in .env (agent/intro_settings.py) because
the Rust desktop shell reads them before this backend exists -- these tests pin that the three
choices map onto those flags in both directions, that a .env written before the loader flag existed
keeps its meaning, and that the rendered page reflects the saved choice.
"""
import re

import pytest
from dotenv import dotenv_values
from fastapi.testclient import TestClient

import main
from agent import intro_settings


def _isolate_env(tmp_path, monkeypatch, initial: str = ""):
    env_path = tmp_path / ".env"
    env_path.write_text(initial)
    monkeypatch.setattr(intro_settings, "_ENV_PATH", str(env_path))
    return env_path


def _checked_options(html: str) -> list[str]:
    """Option values whose radio input carries the `checked` attribute."""
    checked = []
    for value in intro_settings.LAUNCH_SCREENS:
        marker = f'name="style" value="{value}"'
        start = html.index(marker)
        tag_end = html.index(">", start)
        if "checked" in html[start:tag_end]:
            checked.append(value)
    return checked


@pytest.mark.parametrize(
    ("choice", "intro_flag", "loader_flag"),
    [("intro", "true", "false"), ("dragon", "false", "true"), ("none", "false", "false")],
)
def test_each_choice_writes_its_two_flags(tmp_path, monkeypatch, choice, intro_flag, loader_flag):
    env_path = _isolate_env(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/intro", data={"style": choice})

    assert resp.status_code == 204
    saved = dotenv_values(env_path)
    assert (saved["ASRA_INTRO_ENABLED"], saved["ASRA_LAUNCH_LOADER_ENABLED"]) == (intro_flag, loader_flag)
    assert intro_settings.load_launch_screen() == choice


def test_unknown_launch_screen_is_rejected_without_touching_env(tmp_path, monkeypatch):
    env_path = _isolate_env(tmp_path, monkeypatch, "ASRA_INTRO_ENABLED=true\n")
    client = TestClient(main.app)

    resp = client.post("/api/settings/intro", data={"style": "spinner"})

    assert resp.status_code == 400
    assert dotenv_values(env_path) == {"ASRA_INTRO_ENABLED": "true"}


def test_missing_flags_mean_the_intro(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)

    assert intro_settings.load_launch_screen() == "intro"


def test_env_written_before_the_loader_flag_existed_means_dragon(tmp_path, monkeypatch):
    # Old meaning of ASRA_INTRO_ENABLED=false was "plain loader", which is now the dragon bar.
    _isolate_env(tmp_path, monkeypatch, "ASRA_INTRO_ENABLED=false\n")

    assert intro_settings.load_launch_screen() == "dragon"


@pytest.mark.parametrize(
    ("initial", "expected"),
    [
        ("", "intro"),
        ("ASRA_INTRO_ENABLED=false\n", "dragon"),
        ("ASRA_INTRO_ENABLED=false\nASRA_LAUNCH_LOADER_ENABLED=false\n", "none"),
    ],
)
def test_settings_page_checks_the_saved_choice(tmp_path, monkeypatch, initial, expected):
    _isolate_env(tmp_path, monkeypatch, initial)
    client = TestClient(main.app)

    html = client.get("/settings").text

    assert _checked_options(html) == [expected]


def test_intro_sound_toggle_is_locked_off_in_the_sounds_tab(tmp_path, monkeypatch):
    # Even a saved "true" must render unchecked and disabled: the soundtrack does not work yet.
    _isolate_env(tmp_path, monkeypatch, "ASRA_INTRO_SOUND_ENABLED=true\n")
    client = TestClient(main.app)

    html = client.get("/settings").text

    sounds_tab = html[html.index('data-customization-subtab="sounds"'):]
    card = sounds_tab[sounds_tab.index("Launch intro sound"):]
    checkbox = re.search(r'<input type="checkbox"[^>]*>', card).group(0)
    assert "disabled" in checkbox
    assert not re.search(r"\schecked[\s>]", checkbox)
    assert "coming soon" in card[:card.index("</label>")].lower()
    # ...and it no longer lives in the Launch screen block: the label exists once, in Sounds.
    assert html.count("Play intro sound") == 1
