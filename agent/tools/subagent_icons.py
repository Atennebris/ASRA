"""Subagent-icon pools: the decorative icon + color a subagent profile carries (data/
subagent_profiles.json's "icon"/"icon_color" fields). Deliberately a SEPARATE pool from
projects/icons.py's own ICON_NAMES/ICON_COLORS -- confirmed live the operator wants a subagent's
own identity mark visually distinct from a project's (a subagent isn't a target/engagement, it's a
worker), so this never reuses that module's names even though the shape (name pool + color pool +
validators) is identical.

All icons are simple, hand-drawn worker/agent-themed SVGs defined in templates/macros/
subagent_icons.html (this module only holds their NAMES, which must stay in sync with that
macro). Nothing here is copyrighted third-party artwork; colors aren't copyrightable at all.
"""
from __future__ import annotations

import re
import secrets

_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")

# Must match the names templates/macros/subagent_icons.html's subagent_icon() macro knows.
SUBAGENT_ICON_NAMES: list[str] = [
    "robot", "gear", "node", "cpu", "wrench", "brain", "compass", "puzzle", "drone", "clone",
]

# A distinct, readable palette (works on the dark surface the icon sits on) -- deliberately its
# own list object, not a shared reference to projects/icons.py's ICON_COLORS, even though the
# actual hex values overlap: a subagent's random default must never covary with a project's just
# because they happen to draw from the exact same underlying pool.
SUBAGENT_ICON_COLORS: list[str] = [
    "#60a5fa", "#a78bfa", "#f472b6", "#fb7185", "#f59e0b", "#fbbf24",
    "#34d399", "#22d3ee", "#818cf8", "#e879f9",
]


def is_valid_icon(name: str | None) -> bool:
    return name in SUBAGENT_ICON_NAMES


def is_valid_color(color: str | None) -> bool:
    # Any well-formed #rrggbb hex -- the picker uses a full-spectrum <input type="color">, not the
    # fixed palette (SUBAGENT_ICON_COLORS is only the pool the random default draws from).
    return bool(color and _HEX_COLOR_RE.match(color))


def random_icon() -> str:
    return secrets.choice(SUBAGENT_ICON_NAMES)


def random_color() -> str:
    return secrets.choice(SUBAGENT_ICON_COLORS)
