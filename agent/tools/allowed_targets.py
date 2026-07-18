"""Exploitation allowlist storage.

Backs the run_tool() guardrail for requires_allowed_target tools (Metasploit, sqlmap,
default_creds_check). Deliberately NOT sourced from .env or the scan form: the list is empty
by default and only grows when a human explicitly adds a target through the /settings screen —
see README.md "Test scope / Legal notice" for why.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

ALLOWED_TARGETS_PATH = Path("data/allowed_targets.json")


def load_allowed_targets() -> list[str]:
    if not ALLOWED_TARGETS_PATH.exists():
        return []

    try:
        with ALLOWED_TARGETS_PATH.open("r", encoding="utf-8") as f:
            targets = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("allowed_targets.json unreadable (%s) — treating as empty allowlist", exc)
        return []

    if not isinstance(targets, list):
        logger.debug("allowed_targets.json does not contain a list — treating as empty allowlist")
        return []

    return [str(t) for t in targets]


def _write_allowed_targets(targets: list[str]) -> None:
    ALLOWED_TARGETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = ALLOWED_TARGETS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(targets, f, indent=2)
    os.replace(tmp_path, ALLOWED_TARGETS_PATH)


def add_allowed_target(target: str) -> list[str]:
    targets = load_allowed_targets()
    if target not in targets:
        targets.append(target)
        _write_allowed_targets(targets)
        logger.debug("allowed_targets: added %r (total=%d)", target, len(targets))
    return targets


def remove_allowed_target(target: str) -> list[str]:
    targets = [t for t in load_allowed_targets() if t != target]
    _write_allowed_targets(targets)
    logger.debug("allowed_targets: removed %r (total=%d)", target, len(targets))
    return targets


def is_target_allowed(target: str) -> bool:
    """Matches by hostname, not exact string — sqlmap targets are full URLs (with path/query)
    while the allowlist stores bare hosts (as Metasploit's RHOSTS expects), e.g. an allowlist
    entry "juice-shop.herokuapp.com" must also cover "https://juice-shop.herokuapp.com/rest/...".
    """
    allowed = load_allowed_targets()
    hostname = urlparse(target).hostname
    return target in allowed or (hostname is not None and hostname in allowed)
