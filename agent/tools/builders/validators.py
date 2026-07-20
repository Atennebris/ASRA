"""Shared parameter validation for build_command() functions — defense against command injection.

By design, protection stops at "can't escape this token into a new shell command"
(no control chars / newlines / null bytes in any single argv element). It never restricts *which*
flags a tool is allowed to receive — every build_command() passes argv as a list[str] to subprocess
(never shell=True), so injection characters inside a value can't be reinterpreted as a new command.
"""
from __future__ import annotations

import re

_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Loose hostname/IP/URL shape check — just enough to reject obviously malformed input
# (empty string, whitespace-only, shell metacharacters). Allows query strings (?, =, &, %)
# since sqlmap targets are full URLs with an injectable parameter, not just a hostname. [ and ]
# cover bracketed IPv6 host literals in a URL (http://[2001:db8::1]:8080/); bare IPv6 (no
# brackets) already fits the existing hex-digit + ":" set.
# Not a strict RFC validator — real injection protection is the argv-list barrier (subprocess
# calls take a list, never a shell string), this only rejects shapes that couldn't be a
# legitimate target/URL in the first place.
_TARGET_SHAPE_PATTERN = re.compile(r"^[A-Za-z0-9.\-:_/?=&%\[\]]+$")


def validate_safe_value(value: str) -> str:
    """Rejects control characters, newlines, and null bytes in a single argv token."""
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"Value contains control/newline/null characters: {value!r}")
    return value


def validate_target(target: str) -> str:
    """Validates a target string is a plausible hostname/IP/URL token, free of injection characters."""
    target = target.strip()
    if not target:
        raise ValueError("Target must not be empty.")

    validate_safe_value(target)

    if not _TARGET_SHAPE_PATTERN.match(target):
        raise ValueError(f"Target does not look like a hostname/IP/URL: {target!r}")

    return target
