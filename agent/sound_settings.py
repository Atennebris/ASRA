"""Settings -> Customization -> Sounds -- a small, event-driven sound-notification system (findings, approvals,
session completion, chat replies). Real operator request: a way to hear that something happened
(a finding landed, the agent needs an approval, a long scan finished) without staring at the tab.

Every sound is synthesized client-side via the Web Audio API (static/js/sound_events.js) -- this
repo ships no audio files at all, so there's nothing to license and nothing to add to the disk.
This module only owns WHICH events exist, WHICH synthesized profile each maps to, and whether each
is actually on -- the synthesis itself lives entirely in JS, this file never touches audio data.

Same one-store-per-domain convention as timezone_settings.py/agent/settings.py -- its own on-disk
file (data/sound_settings.json in resolve_global_app_dir()), not folded into either of those (this
is its own concern, not LLM-scoped or display-scoped).

Defaults: EVERYTHING is off -- the master switch and every individual event -- until the operator
explicitly turns something on from Settings. That's an explicit requirement, not an oversight: an
operator who's never opened Settings -> Customization -> Sounds must hear nothing, ever.

SOUND_EVENTS is the single source of truth for which events exist and what each row in Settings ->
Sounds renders -- adding a new notifiable event later means appending one entry here (id, label,
description, default_sound); the settings.html template loops over this list generically, no
per-event template code to touch.
"""
from __future__ import annotations

import json
import os

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("API")

SETTINGS_PATH = resolve_global_app_dir() / "data" / "sound_settings.json"

# Must match the profile keys static/js/sound_events.js's own SOUND_PROFILES table defines --
# this tuple is only used server-side to validate/default a saved choice, the actual synthesis
# (oscillators, noise bursts, frequency sweeps, filters) lives entirely in that JS file. Grows by
# ADDING, never by removing/renaming an id someone may already have picked -- real operator
# incident: an earlier pass replaced the original plain set with a "hacker terminal" set instead of
# keeping both, which silently deleted profiles an operator could already have saved a choice
# against. The original plain six (chime/ping/success/alert/pop/error), the first "hacker terminal"
# batch (access_granted/breach_alert/critical/glitch/intrusion/data_stream/terminal_click), and a
# second, punchier batch (laser_zap/power_up/impact_hit/countdown/static_swell/encrypted_ping) all
# coexist -- every one stays selectable from Settings -> Customization -> Sounds, forever, once added.
SOUND_PROFILES = (
    "chime", "ping", "success", "alert", "pop", "error",
    "access_granted", "breach_alert", "critical", "glitch", "intrusion", "data_stream", "terminal_click",
    "laser_zap", "power_up", "impact_hit", "countdown", "static_swell", "encrypted_ping",
)

SOUND_EVENTS = [
    {
        "id": "finding",
        "label": "New finding",
        "description": "A new finding lands in the session -- the real signal that the agent found something.",
        "default_sound": "data_stream",
    },
    {
        "id": "approval_needed",
        "label": "Approval needed",
        "description": "Session status moves to \"awaiting approval\" -- the agent is waiting on you.",
        "default_sound": "intrusion",
    },
    {
        "id": "session_done",
        "label": "Session finished",
        "description": "Session reaches a final state -- completed, failed, or interrupted. One sound for any of the three.",
        "default_sound": "ping",
    },
    {
        "id": "chat_reply",
        "label": "New chat reply",
        "description": "The agent posts a new reply in Interactive/RE chat.",
        "default_sound": "terminal_click",
    },
    {
        "id": "header_light_toggle",
        "label": "Header light switch",
        "description": "Clicking the header lamp to turn it on or off (Customization -> Header light).",
        "default_sound": "pop",
    },
]

_EVENT_IDS = {event["id"] for event in SOUND_EVENTS}
_DEFAULT_SOUND_BY_EVENT = {event["id"]: event["default_sound"] for event in SOUND_EVENTS}


def _load_raw() -> dict:
    if SETTINGS_PATH.exists():
        try:
            with SETTINGS_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("sound_settings: unreadable (%s) -- starting fresh", exc)
    return {}


def _save_raw(data: dict) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SETTINGS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, SETTINGS_PATH)


def load_sound_settings() -> dict:
    """Fully resolved settings -- every registered event is always present, even if nobody has ever
    saved anything for it yet (falls back to disabled + its own default_sound). Callers (base.html's
    window.ASRA_SOUND_SETTINGS, settings.html's Sounds tab) never need to know about a missing key.
    """
    raw = _load_raw()
    raw_events = raw.get("events") if isinstance(raw.get("events"), dict) else {}
    events = {}
    for event_id, default_sound in _DEFAULT_SOUND_BY_EVENT.items():
        saved = raw_events.get(event_id) if isinstance(raw_events.get(event_id), dict) else {}
        sound = saved.get("sound")
        events[event_id] = {
            "enabled": bool(saved.get("enabled", False)),
            "sound": sound if sound in SOUND_PROFILES else default_sound,
        }
    return {"master_enabled": bool(raw.get("master_enabled", False)), "events": events}


def save_master_sound_enabled(enabled: bool) -> None:
    data = _load_raw()
    data["master_enabled"] = bool(enabled)
    _save_raw(data)
    logger.debug("sound_settings: saved master_enabled=%s", enabled)


def save_sound_event(event_id: str, enabled: bool, sound: str) -> None:
    if event_id not in _EVENT_IDS:
        raise ValueError(f"Unknown sound event: {event_id!r}")
    if sound not in SOUND_PROFILES:
        raise ValueError(f"Unknown sound profile: {sound!r}")
    data = _load_raw()
    events = data.get("events") if isinstance(data.get("events"), dict) else {}
    events[event_id] = {"enabled": bool(enabled), "sound": sound}
    data["events"] = events
    _save_raw(data)
    logger.debug("sound_settings: saved event=%s enabled=%s sound=%s", event_id, enabled, sound)
