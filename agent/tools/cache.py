"""TTL file cache for tier-1 tools hitting external public APIs.

Used by crt_sh_lookup/wayback_urls/exploit_db_lookup/cve_lookup so repeated lookups of the same
target/CVE within one dev/demo session don't hammer third-party services for nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

CACHE_DIR = Path("data/cache")

_DEFAULT_TTL_SECONDS = 3600


def _ttl_seconds() -> int:
    return int(os.getenv("CACHE_TTL_SECONDS", str(_DEFAULT_TTL_SECONDS)))


def _cache_path(tool_name: str, query: str) -> Path:
    query_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
    return CACHE_DIR / tool_name / f"{query_hash}.json"


def cache_get(tool_name: str, query: str, ttl_seconds: int | None = None) -> dict | None:
    path = _cache_path(tool_name, query)
    if not path.exists():
        return None

    ttl = ttl_seconds if ttl_seconds is not None else _ttl_seconds()
    if time.time() - path.stat().st_mtime > ttl:
        return None

    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def cache_set(tool_name: str, query: str, data: dict) -> None:
    path = _cache_path(tool_name, query)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp_path, path)
