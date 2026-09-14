"""Persistent storage for whether the autonomous agent (agent/core.py's main ReAct loop), chat
(agent/chat.py), and subagents (agent/core.py's _delegate_to_subagent_impl) can use the native
toolkit's tools -- send_raw_request/list_captured_traffic/decode_value/diff_requests/intruder_run/
sequencer_analyze/racer_run, one independent boolean per capability (Proxy/Repeater/Decoder/
Comparer/Intruder/Sequencer/Racer). Sequencer's own toggle (toolkit_sequencer_enabled) and Racer's
own toggle (toolkit_racer_enabled) were each added in a later follow-up pass -- their real engines
and manual UI routes were built first, but an agent-facing tool for each wasn't registered until
that follow-up.

A separate module/file from agent/tools/chat_settings_store.py, not an extension of it -- that
store's own docstring is explicit that its toggles are "the chat panel's own capability toggles",
read by chat only. These seven have to be read by the main session loop, chat, AND subagents alike,
so they don't belong under a name that says "chat panel's own". Same on-disk convention regardless
(atomic tmp-file + os.replace, empty/corrupt file treated as "nothing stored yet" rather than an
error) -- app-level state (spans every session/project), not tied to one session's own schema, same
category as chat_settings.json/subagent_profiles.json/llm_settings.json.

All seven default False -- unlike chat's own web_fetch/browser (on by default, safe read-only
research), send_raw_request/intruder_run/racer_run can send arbitrary attacker-chosen
method/headers/body to the real target (all three registered with requires_allowed_target=True,
gated by the same "authorize exploitation" allowlist real exploit tools use -- intruder_run/
racer_run potentially many times over, one real request per payload/race attempt),
list_captured_traffic/diff_requests read this session's own captured traffic verbatim (real
headers/cookies/tokens from a live target) straight into the model's context, and
sequencer_analyze's own mode="live" fires real repeated requests too (gated the same way, just
checked manually inside its native_function -- see toolkit_agent_tools.py's
_sequencer_analyze_native for why) -- opt-in for the model, matching the "manual UI always works
regardless of agent access" independence these toggles are meant to preserve, rather than on
unless turned off.
"""
from __future__ import annotations

import json
import os

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLKIT")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
TOOLKIT_AGENT_SETTINGS_STORE_PATH = resolve_global_app_dir() / "data" / "toolkit_agent_settings.json"

BOOL_KEYS = (
    "toolkit_proxy_enabled", "toolkit_repeater_enabled", "toolkit_decoder_enabled",
    "toolkit_comparer_enabled", "toolkit_intruder_enabled", "toolkit_sequencer_enabled",
    "toolkit_racer_enabled",
)
_DEFAULT_SETTINGS = dict.fromkeys(BOOL_KEYS, False)


def load_toolkit_agent_settings() -> dict:
    if not TOOLKIT_AGENT_SETTINGS_STORE_PATH.exists():
        return dict(_DEFAULT_SETTINGS)

    try:
        with TOOLKIT_AGENT_SETTINGS_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("toolkit_agent_settings.json unreadable (%s) — treating as defaults", exc)
        return dict(_DEFAULT_SETTINGS)

    if not isinstance(data, dict):
        logger.debug("toolkit_agent_settings.json does not contain an object — treating as defaults")
        return dict(_DEFAULT_SETTINGS)

    settings = dict(_DEFAULT_SETTINGS)
    for key in BOOL_KEYS:
        if key in data:
            settings[key] = bool(data[key])
    return settings


def save_toolkit_agent_settings(settings: dict) -> dict:
    # Every key re-validated against BOOL_KEYS rather than trusting the caller's dict shape --
    # main.py's own toggle route passes one changed field on top of a freshly-loaded current dict
    # (same "one toggle, one independent request" pattern as chat_settings_store.save_chat_settings),
    # but this function itself never assumes that's the only caller.
    merged = {key: bool(settings.get(key, False)) for key in BOOL_KEYS}
    TOOLKIT_AGENT_SETTINGS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = TOOLKIT_AGENT_SETTINGS_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2)
    os.replace(tmp_path, TOOLKIT_AGENT_SETTINGS_STORE_PATH)
    logger.debug("toolkit_settings_store: saved %s", merged)
    return merged
