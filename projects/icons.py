"""Project-icon pools: the decorative icon + color every project carries (session["icon"] /
session["icon_color"]). A neutral module (no web/agent imports) so sessions/store.py's create_session
can pull a random default from it without a circular import, while main.py registers the same pools
as Jinja globals for the New Project picker and the list rendering -- one source of truth for both.

All icons are simple, hand-drawn geometric/security-themed SVGs defined in templates/macros/
project_icons.html (this module only holds their NAMES, which must stay in sync with that macro).
Nothing here is copyrighted third-party artwork; colors aren't copyrightable at all.
"""
from __future__ import annotations

import re
import secrets

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

# Must match the names templates/macros/project_icons.html's project_icon() macro knows.
ICON_NAMES: list[str] = [
    "shield", "target", "bug", "key", "lock", "flag", "bolt", "radar",
    "globe", "server", "terminal", "fingerprint", "eye", "ghost", "hexagon", "crosshair", "skull",
]

# A distinct, readable palette (works on the dark surface the icon sits on).
ICON_COLORS: list[str] = [
    "#60a5fa", "#a78bfa", "#f472b6", "#fb7185", "#f59e0b", "#fbbf24",
    "#34d399", "#22d3ee", "#818cf8", "#e879f9",
]


def is_valid_icon(name: str | None) -> bool:
    return name in ICON_NAMES


def is_valid_color(color: str | None) -> bool:
    # Any well-formed #rrggbb hex -- the picker uses a full-spectrum <input type="color">, not the
    # fixed palette (ICON_COLORS is now only the pool the random default draws from).
    return bool(color and _HEX_COLOR_RE.match(color))


def random_icon() -> str:
    return secrets.choice(ICON_NAMES)


def random_color() -> str:
    return secrets.choice(ICON_COLORS)
