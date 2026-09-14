"""Persistent storage for the chat panel's own capability toggles -- whether chat is allowed to
use web_fetch (read external pages), the browser automation tools (fallback for a CAPTCHA/WAF-
gated or interactive page), and subagent delegation at all -- plus the last provider/model the
operator explicitly picked in the chat panel's own picker (separate from Settings' own main-agent
choice in llm_settings.json). Same on-disk convention as agent/tools/wordlist_store.py (load/_write
pair, atomic tmp-file + os.replace, empty/corrupt file treated as "nothing stored yet" rather than
an error) -- app-level state (spans every session/project), not tied to one session's own schema,
same category as subagent_profiles.json/llm_settings.json.

web_fetch/browser/dork_engine default True: the point of adding these capabilities is turning them
on; an operator who doesn't want chat touching the network at all has an easy Settings toggle to
turn any of them back off. dork_engine specifically is a read-mostly recon capability (builds a
search-engine dork/OSINT lookup, agent/tools/dork_engine.py) already available to the main agent's
own recon phase unconditionally (category="recon") -- this toggle only controls whether CHAT's own
curated tool set additionally offers it, same as web_fetch/browser.
subagents_enabled defaults False -- delegation spawns real background work sharing the same
SUBAGENT_MAX_CONCURRENT_TASKS concurrency slots the main agent's own phases use, a bigger
behavioral change than "chat can read a page", so it's opt-in rather than on-by-default.

last_provider/last_model default None (nobody's picked anything in chat yet, so a brand-new thread
falls back to "same as main agent" exactly like before this pair existed). Real, confirmed operator
complaint this fixes: every brand-new chat thread (agent/chat.py's _new_thread) used to hardcode
provider=None/model=None regardless of what the operator had last explicitly chosen in the chat
picker, so /new (and a server restart, which starts every session with no in-memory thread state at
all) always fell back to whatever Settings' own main-agent provider happened to be -- never what the
operator had actually been using in chat.

quick_chat_session_id: the real sessions/store.py session id backing the top-level "Chat" nav
entry's project-less Quick Chat (main.py's GET /chat, get_or_create_quick_chat_session) -- a normal
session created via sessions.store.create_session(mode="standalone") like any other project, just
never shown in the Projects list/sidebar/dashboard (list_session_summaries filters mode="standalone"
out at the source, so nothing downstream needs its own separate check). Stored here rather than a
fixed, hardcoded id so it survives the exact same "one project = one folder" creation path (and
therefore the exact same field defaults) every other session gets, instead of a hand-built dict that
would silently drift out of sync with whatever agent/core.py/sessions.store.create_session comes to
expect on a session dict over time. None until the operator's first-ever visit to /chat.
"""
from __future__ import annotations

import json
import os

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("CHAT")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
CHAT_SETTINGS_STORE_PATH = resolve_global_app_dir() / "data" / "chat_settings.json"

_BOOL_KEYS = ("web_fetch_enabled", "browser_enabled", "subagents_enabled", "dork_engine_enabled")
_DEFAULT_SETTINGS = {
    "web_fetch_enabled": True,
    "browser_enabled": True,
    "subagents_enabled": False,
    "dork_engine_enabled": True,
    "last_provider": None,
    "last_model": None,
    "quick_chat_session_id": None,
}


def load_chat_settings() -> dict:
    if not CHAT_SETTINGS_STORE_PATH.exists():
        return dict(_DEFAULT_SETTINGS)

    try:
        with CHAT_SETTINGS_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("chat_settings.json unreadable (%s) — treating as defaults", exc)
        return dict(_DEFAULT_SETTINGS)

    if not isinstance(data, dict):
        logger.debug("chat_settings.json does not contain an object — treating as defaults")
        return dict(_DEFAULT_SETTINGS)

    settings = dict(_DEFAULT_SETTINGS)
    for key in _BOOL_KEYS:
        if key in data:
            settings[key] = bool(data[key])
    for key in ("last_provider", "last_model", "quick_chat_session_id"):
        value = data.get(key)
        settings[key] = value if isinstance(value, str) and value else None
    return settings


def _write_chat_settings(settings: dict) -> dict:
    CHAT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CHAT_SETTINGS_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)
    os.replace(tmp_path, CHAT_SETTINGS_STORE_PATH)
    return settings


def save_chat_settings(
    web_fetch_enabled: bool, browser_enabled: bool, subagents_enabled: bool = False, dork_engine_enabled: bool = True,
) -> dict:
    # Merges onto whatever's already on disk (in particular last_provider/last_model) rather than
    # blindly overwriting the whole file -- this function's own callers (the /chat-settings toggle
    # routes) never know about the provider/model pair, so a plain replace would silently wipe it
    # out on the next unrelated toggle click.
    settings = {
        **load_chat_settings(),
        "web_fetch_enabled": bool(web_fetch_enabled),
        "browser_enabled": bool(browser_enabled),
        "subagents_enabled": bool(subagents_enabled),
        "dork_engine_enabled": bool(dork_engine_enabled),
    }
    _write_chat_settings(settings)
    logger.debug(
        "chat_settings_store: saved web_fetch_enabled=%s browser_enabled=%s subagents_enabled=%s dork_engine_enabled=%s",
        settings["web_fetch_enabled"], settings["browser_enabled"], settings["subagents_enabled"], settings["dork_engine_enabled"],
    )
    return settings


def save_quick_chat_session_id(session_id: str) -> dict:
    """Remembers the real session id backing the top-level Quick Chat page, the first time it's
    lazily created (main.py's get_or_create_quick_chat_session) -- merges onto the existing settings
    the same way save_chat_settings/save_last_chat_llm do, for the same reason."""
    settings = {**load_chat_settings(), "quick_chat_session_id": session_id}
    _write_chat_settings(settings)
    logger.debug("chat_settings_store: saved quick_chat_session_id=%s", session_id)
    return settings


def save_last_chat_llm(provider: str | None, model: str | None) -> dict:
    """Remembers the provider/model the operator just explicitly picked in the chat panel's own
    picker, so the next brand-new thread (_new_thread in agent/chat.py) can be pre-filled with it
    instead of always resetting to blank ("same as main agent"). Merges onto the existing toggles
    the same way save_chat_settings does, for the same reason."""
    settings = {**load_chat_settings(), "last_provider": provider or None, "last_model": model or None}
    _write_chat_settings(settings)
    logger.debug(
        "chat_settings_store: saved last_provider=%s last_model=%s", settings["last_provider"], settings["last_model"],
    )
    return settings
