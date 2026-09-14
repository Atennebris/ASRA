"""Declarative table of optional interpreters/compilers ASRA can offer to check/install for the
operator (Settings -> Optional interpreters/compilers) -- not needed by any tool out of the box,
only by whatever unreviewed script/PoC (custom_exploit_run, exploit_db_run) happens to require one.

Adding a future capability (a C/C++ compiler, or anything else) means adding one entry here, not
writing a new code path -- that's the whole point of this table existing separately from the
install/path-resolution logic that reads it (agent/tools/capability_install.py,
agent/tools/capability_paths.py).
"""
from __future__ import annotations

OPTIONAL_CAPABILITIES: list[dict] = [
    {
        "id": "python2",
        "label": "Python 2",
        "check": "python2",
        "packages": {"apt": "python2", "dnf": "python2", "pacman": "python2"},
    },
    {
        "id": "gcc",
        "label": "C compiler (gcc)",
        "check": "gcc",
        "packages": {"apt": "gcc", "dnf": "gcc", "pacman": "gcc"},
    },
    {
        "id": "g++",
        "label": "C++ compiler (g++)",
        "check": "g++",
        "packages": {"apt": "g++", "dnf": "gcc-c++", "pacman": "gcc"},
    },
]

_BY_ID = {capability["id"]: capability for capability in OPTIONAL_CAPABILITIES}


def get_capability(capability_id: str) -> dict | None:
    return _BY_ID.get(capability_id)
