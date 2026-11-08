"""Shared GitHub-Releases lookup used by both the git-based project updater (agent/updater.py,
for the non-git fallback it needs) and the desktop-shell binary updater (agent/desktop_update.py)
-- the one piece of "what's the latest tagged release, and is my version behind it" logic neither
module needs its own copy of.
"""
from __future__ import annotations

import httpx

RELEASES_API_URL = "https://api.github.com/repos/Atennebris/ASRA/releases/latest"
HTTP_TIMEOUT_SECONDS = 15.0


def parse_version(text: str) -> tuple[int, ...] | None:
    try:
        return tuple(int(part) for part in text.strip().lstrip("v").split("."))
    except ValueError:
        return None


def fetch_latest_release() -> dict | None:
    """Returns the raw GitHub Releases/latest JSON, or None on any network/HTTP/JSON failure --
    callers decide how to report that (never raises, same convention as the rest of the update
    modules)."""
    try:
        with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
            resp = client.get(RELEASES_API_URL)
            resp.raise_for_status()
            return resp.json()
    except Exception:  # noqa: BLE001 - network/HTTP/JSON errors all treated the same: "unknown"
        return None


def is_version_behind(current: str, latest: str) -> bool:
    current_parsed = parse_version(current)
    latest_parsed = parse_version(latest)
    return bool(current_parsed and latest_parsed and latest_parsed > current_parsed)
