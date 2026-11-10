"""Settings -> Customization -> Visual's "Launch screen" -- what the desktop shell shows while the
backend starts: the animated intro, the dragon progress bar, or nothing at all
(desktop/src-tauri/dist/index.html).

Stored as two independent boolean env vars rather than one enum, so a .env written before the
dragon loader existed keeps its meaning: ASRA_INTRO_ENABLED=false alone used to mean "plain
loader", which is now the dragon bar.
  ASRA_INTRO_ENABLED=true                                  -> intro
  ASRA_INTRO_ENABLED=false, ASRA_LAUNCH_LOADER_ENABLED=true -> dragon progress bar
  both false                                               -> nothing (Start button only)

Written straight to .env as real env vars, same on-disk convention as
agent/tools/tool_api_keys.py's own keys -- not a JSON store under resolve_global_app_dir(), because
the thing that actually needs to read these values (the Rust desktop shell's own
get_start_config(), main.rs) runs BEFORE this Python backend exists at all on every launch; .env is
the one place both sides already agree to read/write. The running backend itself has no live use
for either value -- they only matter to the NEXT launch's start screen.

Both default to enabled when their key is absent, matching main.rs's own
env_flag_default(text, key, true) -- an operator who has never touched the picker sees the full
intro on both sides with no drift between them.

The intro's own soundtrack (ASRA_INTRO_SOUND_ENABLED) is deliberately not managed here: it does not
work yet, so Settings shows it locked off and main.rs defaults it to off.
"""
from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values, find_dotenv, set_key

from agent.utils.logger import get_logger

logger = get_logger("API")

INTRO_ENV_VAR = "ASRA_INTRO_ENABLED"
LOADER_ENV_VAR = "ASRA_LAUNCH_LOADER_ENABLED"
LAUNCH_SCREENS = ("intro", "dragon", "none")
_ENV_PATH = find_dotenv(usecwd=True) or str(Path(__file__).resolve().parent.parent / ".env")


def _load_flag(env_var: str) -> bool:
    raw = dotenv_values(_ENV_PATH).get(env_var)
    if raw is None:
        return True
    return raw.strip().lower() in ("true", "1", "yes", "on")


def _save_flag(env_var: str, enabled: bool) -> None:
    set_key(_ENV_PATH, env_var, "true" if enabled else "false")


def load_launch_screen() -> str:
    if _load_flag(INTRO_ENV_VAR):
        return "intro"
    return "dragon" if _load_flag(LOADER_ENV_VAR) else "none"


def save_launch_screen(screen: str) -> None:
    if screen not in LAUNCH_SCREENS:
        raise ValueError(f"unknown launch screen: {screen!r}")
    _save_flag(INTRO_ENV_VAR, screen == "intro")
    _save_flag(LOADER_ENV_VAR, screen == "dragon")
    logger.debug("intro_settings: saved launch screen=%s", screen)
