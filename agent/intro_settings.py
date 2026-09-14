"""Settings -> Customization -> Visual -- whether the desktop shell's own pre-launch intro
animation plays before the backend is ready, or the plain "Starting backend..." loader
(desktop/src-tauri/dist/index.html) is shown instead. Also owns the sibling toggle for that same
intro's sound (the ambient warp-space drone plus the three glass-impact hits, all synthesized
client-side in that same file -- no audio files shipped, same convention as
agent/sound_settings.py's own event sounds) -- on by default alongside the intro itself, off
independently if an operator wants the visuals without audio.

Both are written straight to .env as real env vars (ASRA_INTRO_ENABLED, ASRA_INTRO_SOUND_ENABLED),
same on-disk convention as agent/tools/tool_api_keys.py's own keys -- not a JSON store under
resolve_global_app_dir(), because the thing that actually needs to read these values (the Rust
desktop shell's own get_start_config(), main.rs) runs BEFORE this Python backend exists at all on
every launch; .env is the one place both sides already agree to read/write. The running backend
itself has no live use for either value -- they only matter to the NEXT launch's start screen.

Both default to enabled when their key is absent, matching main.rs's own
env_flag_default(text, key, true) -- an operator who has never touched either toggle sees the full
intro (visuals + sound) on both sides with no drift between them.
"""
from __future__ import annotations

from pathlib import Path

from dotenv import dotenv_values, find_dotenv, set_key

from agent.utils.logger import get_logger

logger = get_logger("API")

ENV_VAR = "ASRA_INTRO_ENABLED"
SOUND_ENV_VAR = "ASRA_INTRO_SOUND_ENABLED"
_ENV_PATH = find_dotenv(usecwd=True) or str(Path(__file__).resolve().parent.parent / ".env")


def _load_flag(env_var: str) -> bool:
    raw = dotenv_values(_ENV_PATH).get(env_var)
    if raw is None:
        return True
    return raw.strip().lower() in ("true", "1", "yes", "on")


def load_intro_enabled() -> bool:
    return _load_flag(ENV_VAR)


def save_intro_enabled(enabled: bool) -> None:
    set_key(_ENV_PATH, ENV_VAR, "true" if enabled else "false")
    logger.debug("intro_settings: saved %s=%s", ENV_VAR, enabled)


def load_intro_sound_enabled() -> bool:
    return _load_flag(SOUND_ENV_VAR)


def save_intro_sound_enabled(enabled: bool) -> None:
    set_key(_ENV_PATH, SOUND_ENV_VAR, "true" if enabled else "false")
    logger.debug("intro_settings: saved %s=%s", SOUND_ENV_VAR, enabled)
