"""Weak-model reliability settings (tool-call temperature, structured output, the weak-model
profile, argument coercion, fuzzy tool-name matching, the weak-model quality signal, and the
secondary-verification hint), persisted to data/reliability_settings.json.

Each key is the exact name of the matching env var. Resolution order for every one of these
settings is: the value saved from the Settings -> Reliability screen, else the .env default, else
the hardcoded default in the resolver itself. So .env stays the quiet default UNDER the GUI control
-- an operator tunes all of this visually, never by hand-editing .env. Every stored value is a
plain string (same shape an env var has), so each resolver keeps its own existing parse + default
logic unchanged and only swaps where the raw value comes from.
"""
from __future__ import annotations

import json
import os
import threading
import time

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("API")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder --
# same convention as agent/settings.py's llm_settings.json. Holds only numbers/flags, nothing private.
SETTINGS_PATH = resolve_global_app_dir() / "data" / "reliability_settings.json"

# The settings this store is allowed to hold -- the env var names of every Phase 1-7 knob. A write
# for any other key is rejected, so the save route can't be coaxed into writing arbitrary data.
ALLOWED_KEYS = frozenset({
    "LLM_TOOL_CALL_TEMPERATURE",
    "LLM_STRUCTURED_OUTPUT",
    "WEAK_MODEL_MODE",
    "WEAK_MODEL_CONTEXT_LIMIT_THRESHOLD",
    "WEAK_MODEL_MAX_TOOLS",
    "TOOL_ARG_COERCION",
    "TOOL_NAME_FUZZY_MATCH",
    "TOOL_NAME_FUZZY_CUTOFF",
    "WEAK_SIGNAL_ENABLED",
    "WEAK_SIGNAL_WINDOW",
    "WEAK_SIGNAL_INVALID_RATE",
    "WEAK_MODEL_VERIFICATION_HINT",
})

# Short-TTL cache, same rationale as agent/settings.py: these resolvers are called on hot paths
# (every tool-call turn reads the temperature/coercion flags), so an uncached disk read + JSON parse
# per call would be wasteful. Self-invalidated on every write, so a Save is reflected on the very
# next read regardless of the TTL -- this only ever collapses repeat reads within the same window.
_SETTINGS_CACHE_TTL_SECONDS = float(os.getenv("RELIABILITY_SETTINGS_CACHE_TTL_SECONDS", "2"))
_settings_cache: tuple[float, dict] | None = None
_settings_cache_lock = threading.Lock()


def load_reliability_settings() -> dict:
    global _settings_cache
    now = time.monotonic()
    with _settings_cache_lock:
        if _settings_cache is not None and now - _settings_cache[0] < _SETTINGS_CACHE_TTL_SECONDS:
            return dict(_settings_cache[1])
    if not SETTINGS_PATH.exists():
        data: dict = {}
    else:
        try:
            with SETTINGS_PATH.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("reliability_settings: unreadable (%s) -- treating as unset", exc)
            loaded = {}
        data = loaded if isinstance(loaded, dict) else {}
    with _settings_cache_lock:
        _settings_cache = (now, data)
    return dict(data)


def _write_reliability_settings(data: dict) -> None:
    global _settings_cache
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SETTINGS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, SETTINGS_PATH)
    with _settings_cache_lock:
        _settings_cache = None


def save_reliability_setting(key: str, value: str) -> None:
    """Merge one setting onto whatever is already saved (never clobbering the others). value is
    stored as a plain string so a resolver reads it exactly as it would read its env var. Rejects
    any key outside ALLOWED_KEYS so a bad request can't write arbitrary data into the file."""
    if key not in ALLOWED_KEYS:
        raise ValueError(f"unknown reliability setting {key!r}")
    existing = load_reliability_settings()
    existing[key] = str(value)
    _write_reliability_settings(existing)
    logger.debug("reliability_settings: saved %s=%s", key, value)


def saved_raw(key: str) -> str | None:
    """The GUI-saved raw string for key, or None when the operator has never set it here."""
    value = load_reliability_settings().get(key)
    return str(value) if value is not None else None


def raw_setting(key: str) -> str | None:
    """The effective raw value for key in resolution order: GUI-saved first, then the env var, then
    None (the caller then applies its own hardcoded default). This is the single place the
    GUI -> env -> default order lives; each resolver keeps its own parse + default on top of it."""
    saved = saved_raw(key)
    if saved is not None:
        return saved
    return os.getenv(key)
