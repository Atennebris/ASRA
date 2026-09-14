"""Read-only discovery of wordlist files already present under known WSL install locations --
SecLists picks and rockyou.txt (setup_tools.sh's install_large_wordlists), the ffuf default
(install_ffuf_wordlist), and Metasploit's own bundled lists (install_metasploit_wordlists' own
/usr/share/wordlists/metasploit symlink). Metadata only (path/name/size/line count/kind guess) --
never reads or exposes the wordlist's actual contents.

setup_tools.sh never clones the full SecLists repo (its own comment: "a handful of small,
specifically-picked files ... not a full SecLists clone"), so these known roots normally hold at
most a few dozen real files plus one large rockyou.txt -- a full recursive walk is cheap. The
count/size caps below only guard the edge case of someone manually dropping a real, much bigger
SecLists checkout onto one of these same paths outside this project's own installer.
"""
from __future__ import annotations

from pathlib import Path

from agent.tools.wordlist_store import load_wordlist_store

_SCAN_ROOTS = (
    Path("/usr/share/wordlists"),
    Path("/usr/share/seclists"),
    Path("/usr/share/metasploit-framework/data/wordlists"),
)
_WORDLIST_EXTENSIONS = {".txt", ".lst", ".dict"}
# Bounds for the "someone dropped a full SecLists checkout here manually" edge case -- keeps a
# rescan snappy regardless, without needing to special-case that scenario explicitly.
_MAX_FILES_SCANNED = 500
_MAX_LINE_COUNT_BYTES = 500 * 1024 * 1024

_KIND_HINTS = (
    ("password", "passwords"),
    ("passwd", "passwords"),
    ("rockyou", "passwords"),
    ("credential", "passwords"),
    ("user", "usernames"),
    ("subdomain", "subdomains"),
    ("dns", "subdomains"),
    ("web-content", "content-discovery"),
    ("discovery", "content-discovery"),
    ("directory", "content-discovery"),
    ("param", "parameters"),
    ("fuzz", "content-discovery"),
    ("/wordlists/ffuf/", "content-discovery"),
)


def _guess_kind(path: Path) -> str:
    lowered = str(path).lower()
    for hint, kind in _KIND_HINTS:
        if hint in lowered:
            return kind
    return "general"


def _count_lines(path: Path, size_bytes: int) -> int | None:
    # rockyou.txt-sized files (100MB+) would materialize as a huge list of Python str objects via
    # readlines()/splitlines() just to get a count -- count raw b"\n" bytes in fixed-size chunks
    # instead, which stays O(1) in memory regardless of file size.
    if size_bytes > _MAX_LINE_COUNT_BYTES:
        return None
    count = 0
    try:
        with path.open("rb") as f:
            while chunk := f.read(1024 * 1024):
                count += chunk.count(b"\n")
    except OSError:
        return None
    return count


def _scan_root(root: Path, budget: int) -> list[dict]:
    entries: list[dict] = []
    for path in root.rglob("*"):
        if len(entries) >= budget:
            break
        if not path.is_file() or path.suffix.lower() not in _WORDLIST_EXTENSIONS:
            continue
        try:
            size_bytes = path.stat().st_size
        except OSError:
            continue
        entries.append({
            "path": str(path),
            "name": path.name,
            "size_bytes": size_bytes,
            "line_count": _count_lines(path, size_bytes),
            "kind": _guess_kind(path),
            "source": "detected",
        })
    return entries


def scan_known_wordlists() -> list[dict]:
    """Walks each known root for real wordlist files already on disk. A root that doesn't exist
    (e.g. SecLists picks never installed) contributes nothing -- not an error, just nothing
    detected there. Returns a flat list of {"path", "name", "size_bytes", "line_count", "kind",
    "source"} dicts, sorted by path for a stable, predictable UI listing order."""
    entries: list[dict] = []
    for root in _SCAN_ROOTS:
        if not root.exists():
            continue
        entries.extend(_scan_root(root, _MAX_FILES_SCANNED - len(entries)))
        if len(entries) >= _MAX_FILES_SCANNED:
            break
    entries.sort(key=lambda e: e["path"])
    return entries


def list_all_wordlists() -> list[dict]:
    """scan_known_wordlists()'s auto-detected files, plus whatever the operator downloaded through
    the Settings UI (agent/tools/wordlist_store.py) -- the single combined list the UI actually
    renders. Size/line count for a downloaded entry is computed fresh here rather than trusted from
    the stored metadata, since the file on disk is the source of truth and could have changed (or
    been deleted outside this app) since it was registered; a downloaded entry whose file is gone
    is silently omitted rather than shown as a broken row -- get_assigned_wordlist already treats a
    missing file as "nothing assigned", so a stale catalog row would be misleading either way.
    """
    detected = scan_known_wordlists()
    detected_paths = {e["path"] for e in detected}

    downloaded: list[dict] = []
    for record in load_wordlist_store()["downloaded"]:
        path = Path(record.get("path", ""))
        if record.get("path") in detected_paths or not path.is_file():
            continue
        try:
            size_bytes = path.stat().st_size
        except OSError:
            continue
        downloaded.append({
            "path": str(path),
            "name": record.get("name") or path.name,
            "size_bytes": size_bytes,
            "line_count": _count_lines(path, size_bytes),
            "kind": record.get("kind", "general"),
            "source": "downloaded",
            "source_url": record.get("source_url"),
        })

    return detected + downloaded
