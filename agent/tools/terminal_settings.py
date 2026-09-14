"""Standalone Terminal tab's own tiny settings store -- currently just one flag: whether the
"close this terminal?" confirm dialog (static/js/terminal.js, triggered by a middle-click on a
tab) should be skipped entirely.

Deliberately IN-MEMORY ONLY, never written to disk -- a direct, explicit operator instruction:
this flag must reset back to "ask again" every time the ASRA process itself restarts, and only
ever persist across a plain browser reload/tab-switch within that SAME running server. An earlier
version of this file persisted it to a JSON file specifically so it WOULD survive a full process
restart -- the exact opposite of what was actually asked for (the operator's own first request
already said so explicitly: killing the ASRA process and relaunching should ask again). A plain
module-level Python variable already has exactly the lifetime that's actually wanted for free --
resets to its default the instant a fresh process starts, stays put for as long as that one
process keeps running (shared across every browser tab/window talking to it, desktop shell webview
included) -- no on-disk file, and no cross-process persistence, needed or wanted here at all.
"""
from __future__ import annotations

from agent.utils.logger import get_logger

logger = get_logger("TERMINAL")

_skip_close_confirm = False


def load_terminal_settings() -> dict:
    return {"skip_close_confirm": _skip_close_confirm}


def save_skip_close_confirm(skip: bool) -> None:
    global _skip_close_confirm
    _skip_close_confirm = bool(skip)
    logger.debug("terminal_settings: skip_close_confirm=%s (in-memory only -- resets on the next ASRA restart)", _skip_close_confirm)
