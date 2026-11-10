"""Cache-busting URLs for the app's own static files (css/js under /static).

StaticFiles sends no Cache-Control, so a browser or the desktop webview keeps serving a stale copy
of an edited file on heuristic freshness alone. A hand-bumped `?v=N` in the templates proved
unreliable: an edit that forgot to bump it left the operator on old CSS/JS while the real file on
disk was already fixed (a hidden-clock fix and a header-layout fix both "did not work" for exactly
this reason). The version is the file's own modification time instead, so any edit changes the URL
by itself and nothing has to be remembered.

A stat is cheap on a native filesystem but not on the repo living on a Windows drive mounted into
WSL2 (measured ~1.4 ms each, ~48 ms for the ~34 assets of one page), and this runs on every full
page render. Results are therefore remembered for `cache_seconds`: an edited file is picked up
within that window instead of paying the stat cost on every navigation.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

from agent.utils.logger import get_logger

logger = get_logger("API")

STATIC_URL_PREFIX = "/static/"


def make_static_url(
    static_dir: Path,
    cache_seconds: float = 10.0,
    clock: Callable[[], float] = time.monotonic,
) -> Callable[[str], str]:
    """Return a `static_url("/static/js/x.js")` helper that appends `?v=<mtime>` for files that
    exist under `static_dir`, and returns the URL unchanged (never raises) for ones that do not."""
    remembered: dict[str, tuple[float, str]] = {}

    def static_url(url_path: str) -> str:
        now = clock()
        hit = remembered.get(url_path)
        if hit is not None and now - hit[0] < cache_seconds:
            return hit[1]
        relative = url_path.removeprefix(STATIC_URL_PREFIX)
        try:
            mtime_ms = (static_dir / relative).stat().st_mtime_ns // 1_000_000
            versioned = f"{url_path}?v={mtime_ms}"
        except OSError:
            logger.debug("static_url: no file for %s under %s, serving it unversioned", url_path, static_dir)
            versioned = url_path
        remembered[url_path] = (now, versioned)
        return versioned

    return static_url
