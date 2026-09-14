"""Display timezone -- Settings -> Timezone, plus the header clock (templates/base.html).

Purely a rendering preference, its own small on-disk store (data/timezone_settings.json in
resolve_global_app_dir(), same one-store-per-domain convention as toolkit_settings_store.py/
chat_settings_store.py -- agent/settings.py's own llm_settings.json is LLM-scoped by its own
docstring, not a fit for this).

Every timestamp this app actually persists (session.json's started_at/finished_at/logs[].at,
findings' found_at, chat messages' at, ...) is stored as real UTC (datetime.now(timezone.utc)),
deliberately timezone-independent so duration math never depends on the host machine's own
clock/DST -- this setting never touches that storage, only how main.py's human_dt Jinja filter (and
the header clock) DISPLAY those UTC instants to the operator. Real, confirmed incident this fixes:
_human_dt used to hardcode "%H:%M UTC" regardless of where the operator actually is, so every
finding/hypothesis/approval/credential timestamp read hours off from the operator's own wall clock
with no way to change it.

debug.log is a deliberate, documented exception (agent/utils/debug.py's own module docstring) --
it already uses the machine's real local clock with a self-describing UTC offset on every line,
specifically so live-tailing the separate debug console window reads against the operator's own
wall clock with no mental conversion. This setting does not touch it.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from zoneinfo import available_timezones

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("API")

SETTINGS_PATH = resolve_global_app_dir() / "data" / "timezone_settings.json"

_AVAILABLE_TIMEZONES = sorted(available_timezones())


def display_timezone_choices() -> list[str]:
    return _AVAILABLE_TIMEZONES


def _detect_machine_timezone() -> str:
    """Best-effort real IANA zone name for this machine's own local clock (e.g. "Europe/Chisinau")
    -- so a fresh install with nothing saved yet shows times matching the operator's own wall clock
    out of the box, not UTC. /etc/timezone (Debian/Ubuntu, including the WSL2 image this project's
    documented Windows launch path actually runs its Python process on) is the simplest, most
    direct source; /etc/localtime's own symlink target
    (most other Linux distros, macOS) is the fallback. Never raises -- an unreadable/missing/
    unrecognized value just falls through to UTC, same graceful-degrade spirit as every other
    optional platform probe in this codebase (NMAP_PATH-style overrides, the PDF font fallback).
    """
    try:
        candidate = Path("/etc/timezone").read_text(encoding="utf-8").strip()
        if candidate in _AVAILABLE_TIMEZONES:
            return candidate
    except OSError:
        pass
    try:
        target = os.readlink("/etc/localtime")
        candidate = target.rsplit("zoneinfo/", 1)[-1]
        if candidate in _AVAILABLE_TIMEZONES:
            return candidate
    except OSError:
        pass
    return "UTC"


def _load_raw() -> dict:
    """Shared by every load_*/save_* below so a save to one field (e.g. show_clock) never
    clobbers another (e.g. timezone) that happens to already be on disk -- each save_* reads the
    current file, updates only its own key, and writes the whole dict back."""
    if SETTINGS_PATH.exists():
        try:
            with SETTINGS_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("timezone_settings: unreadable (%s) -- starting fresh", exc)
    return {}


def _save_raw(data: dict) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SETTINGS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, SETTINGS_PATH)


def load_display_timezone() -> str:
    """The operator's saved Settings -> Timezone choice, or this machine's own real local zone
    (detected fresh each call -- cheap enough that caching isn't worth the staleness risk if the
    machine's own timezone ever changes) the first time nobody has ever saved one."""
    saved = _load_raw().get("timezone")
    if isinstance(saved, str) and saved in _AVAILABLE_TIMEZONES:
        return saved
    return _detect_machine_timezone()


def save_display_timezone(tz_name: str) -> None:
    if tz_name not in _AVAILABLE_TIMEZONES:
        raise ValueError(f"Unknown IANA timezone: {tz_name!r}")
    data = _load_raw()
    data["timezone"] = tz_name
    _save_raw(data)
    logger.debug("timezone_settings: saved timezone=%s", tz_name)


def load_clock_show_time() -> bool:
    """Whether the sidebar footer clock (templates/base.html) shows the time at all. Defaults to
    on -- the clock existed before this toggle did, so an operator who's never touched this new
    setting must keep seeing exactly what they already had."""
    val = _load_raw().get("show_clock")
    return True if val is None else bool(val)


def load_clock_show_zone_label() -> bool:
    """Whether the sidebar footer clock also shows the zone name (e.g. "Europe/Chisinau") next to
    the time. Defaults to off -- real operator request: by default only the time itself should
    show, the zone name is opt-in clutter next to it."""
    val = _load_raw().get("show_zone_label")
    return False if val is None else bool(val)


def save_clock_show_time(show: bool) -> None:
    data = _load_raw()
    data["show_clock"] = bool(show)
    _save_raw(data)
    logger.debug("timezone_settings: saved show_clock=%s", show)


def save_clock_show_zone_label(show: bool) -> None:
    data = _load_raw()
    data["show_zone_label"] = bool(show)
    _save_raw(data)
    logger.debug("timezone_settings: saved show_zone_label=%s", show)


def load_clock_show_date() -> bool:
    """Whether the sidebar footer clock also shows today's date underneath the time. Defaults to
    off, same "opt-in clutter" convention as show_zone_label -- only the time shows out of the box."""
    val = _load_raw().get("show_date")
    return False if val is None else bool(val)


def save_clock_show_date(show: bool) -> None:
    data = _load_raw()
    data["show_date"] = bool(show)
    _save_raw(data)
    logger.debug("timezone_settings: saved show_date=%s", show)


CLOCK_STYLES = ("minimal", "digital", "terminal")


def load_clock_style() -> str:
    """Which of the 3 sidebar-clock display styles (templates/base.html, static/css/themes.css's
    .clock-style-* rules) is active. Defaults to "minimal" -- the plain HH:MM look that already
    existed before styles were a choice at all."""
    val = _load_raw().get("clock_style")
    return val if val in CLOCK_STYLES else "minimal"


def save_clock_style(style: str) -> None:
    if style not in CLOCK_STYLES:
        raise ValueError(f"Unknown clock style: {style!r}")
    data = _load_raw()
    data["clock_style"] = style
    _save_raw(data)
    logger.debug("timezone_settings: saved clock_style=%s", style)
