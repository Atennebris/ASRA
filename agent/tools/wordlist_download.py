"""Fetches a wordlist file from an operator-supplied URL into this project's own data/wordlists/
directory. Exclusively human-triggered from the Settings UI's "Download wordlist" button
(main.py's /api/settings/wordlists/download route) -- there is no ToolSpec registration for this,
so the LLM agent can never call it itself. The operator is choosing to trust a specific URL they
typed into their own app's UI, same trust boundary as pasting a target into the New Project form.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx

from agent.tools.wordlist_store import add_downloaded_wordlist, load_wordlist_store
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
DOWNLOAD_DIR = resolve_global_app_dir() / "data" / "wordlists"
# Generous enough for rockyou.txt-class lists (~130MB) with real headroom, while still bounding
# how much disk one download click can ever consume -- a streamed response is checked against this
# as it arrives, not just after the fact.
_MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024
_DOWNLOAD_TIMEOUT_SECONDS = 120
_SAFE_NAME_PATTERN = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_filename(name: str, source_url: str) -> str:
    candidate = name.strip() or Path(urlparse(source_url).path).name or "wordlist.txt"
    candidate = _SAFE_NAME_PATTERN.sub("_", candidate).lstrip(".")
    return candidate or "wordlist.txt"


def _resolve_dest_path(filename: str, source_url: str) -> Path:
    """Reuses the same path on a re-download of the SAME url (updates it in place, as intended) --
    but a different, unrelated URL that happens to produce the same filename (e.g. two different
    projects both shipping a "common.txt") gets a short hash-suffixed path instead of silently
    overwriting the first one's file/metadata."""
    dest_path = DOWNLOAD_DIR / filename
    if not dest_path.exists():
        return dest_path
    existing = next((d for d in load_wordlist_store()["downloaded"] if d.get("path") == str(dest_path)), None)
    if existing is None or existing.get("source_url") == source_url:
        return dest_path
    short_hash = hashlib.sha256(source_url.encode()).hexdigest()[:8]
    return DOWNLOAD_DIR / f"{dest_path.stem}_{short_hash}{dest_path.suffix}"


def download_wordlist(source_url: str, name: str, kind: str) -> dict:
    """Streams source_url into data/wordlists/ with a hard size cap so a huge/unbounded response
    can't fill the disk. Raises ValueError for anything the operator should see as a clean error
    message (bad scheme, oversized response, network failure) -- the settings route renders that
    straight into the same partial, no traceback. Returns the updated wordlist store on success.
    """
    parsed = urlparse(source_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must start with http:// or https://")

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    filename = _safe_filename(name, source_url)
    dest_path = _resolve_dest_path(filename, source_url)
    tmp_path = dest_path.with_name(dest_path.name + ".part")

    written = 0
    try:
        with httpx.Client(timeout=_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client, client.stream("GET", source_url) as response:
            response.raise_for_status()
            with tmp_path.open("wb") as f:
                for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                    written += len(chunk)
                    if written > _MAX_DOWNLOAD_BYTES:
                        raise ValueError(f"response exceeded the {_MAX_DOWNLOAD_BYTES // (1024 * 1024)}MB download cap")
                    f.write(chunk)
    except httpx.HTTPError as exc:
        tmp_path.unlink(missing_ok=True)
        raise ValueError(f"download failed: {exc}") from exc
    except ValueError:
        tmp_path.unlink(missing_ok=True)
        raise

    tmp_path.replace(dest_path)
    logger.debug("wordlist_download: fetched %r -> %s (%d bytes)", source_url, dest_path, written)
    return add_downloaded_wordlist(str(dest_path), dest_path.name, source_url, kind)
