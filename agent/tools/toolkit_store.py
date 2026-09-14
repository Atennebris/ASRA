"""Storage for captured HTTP traffic (native Proxy/Repeater/Decoder/Comparer/Intruder/Sequencer
toolkit) -- either per-project, or a genuinely standalone global store.

Per-project (session_id given): one JSON-lines file living inside that project's own folder next
to session.json -- same "one project = one folder" model sessions/store.py already uses for
everything else, so captured traffic (real headers/cookies/tokens from a live target) never lands
inside this repo's own data/ directory and is never git-tracked: project folders live entirely
under Documents/ASRA Projects/, outside this repo's working tree, so there is nothing here for
this repo's .gitignore to cover.

Standalone (session_id=None): the Toolkit page reachable straight from the sidebar (main.py's
/toolkit route) for ad-hoc manual work on arbitrary URLs -- deliberately NOT a hidden/fake
"project" of any kind (no session.json, never appears in the Projects list, no session_id at all).
Lands in resolve_global_app_dir() (projects/paths.py) -- the SAME app-level directory (Documents/
ASRA/, sibling to "ASRA Projects") the global debug.log already uses for state that isn't tied to
one specific engagement -- under its own "toolkit" subfolder, same relative layout as a real
project's toolkit/traffic.jsonl, just a different root. This is a pure storage-location choice:
every engine built on top of this module (toolkit_repeater/toolkit_decoder/toolkit_comparer/
toolkit_intruder/toolkit_sequencer) works identically either way, since none of them ever branch on
session_id's value beyond passing it through to this module.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from agent.tools import passive_detectors
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir
from sessions.store import get_session_folder

logger = get_logger("TOOLKIT")

_TOOLKIT_SUBDIR = "toolkit"
_TRAFFIC_FILENAME = "traffic.jsonl"

TrafficSource = Literal["proxy", "repeater", "intruder", "racer"]
BodyEncoding = Literal["text", "base64"]

# Content-Types worth decoding as text even though they don't start with "text/" -- kept short and
# explicit rather than a broad heuristic, extended here if a real capture turns up another one.
_TEXT_CONTENT_TYPES = {
    "application/json", "application/javascript", "application/xml",
    "application/xhtml+xml", "application/x-www-form-urlencoded", "application/ld+json",
}


def is_text_content_type(content_type: str) -> bool:
    ct = content_type.split(";")[0].strip().lower()
    return ct.startswith("text/") or ct in _TEXT_CONTENT_TYPES or ct.endswith("+json") or ct.endswith("+xml")


def encode_body(content_type: str, raw_bytes: bytes) -> tuple[str, BodyEncoding]:
    """(body-as-stored, encoding) -- shared by every real producer of a traffic entry (the
    mitmproxy addon, agent/tools/toolkit_proxy.py; the Repeater send engine,
    agent/tools/toolkit_repeater.py) so they can never drift apart on how a body gets encoded.
    Never force-decodes binary bytes as text -- that only ever produces mojibake, not a readable
    body. Real incident this fixes: an image/jpeg response rendered as garbled symbols in the Site
    Map's raw detail view, because the original capture always decoded as text regardless of
    Content-Type. A known text
    Content-Type (or no Content-Type at all, but genuinely valid UTF-8 -- e.g. a plain-text body
    with no header) is stored as real, directly readable text; anything else (images/fonts/other
    binary) is stored as base64 of the real bytes instead, so the actual data is preserved rather
    than lost/garbled -- callers decide how to present base64 content (an <img> preview for
    image/*, a plain "binary, N bytes" notice otherwise)."""
    if not raw_bytes:
        return "", "text"
    if content_type and is_text_content_type(content_type):
        return raw_bytes.decode("utf-8", errors="replace"), "text"
    if not content_type:
        try:
            return raw_bytes.decode("utf-8"), "text"
        except UnicodeDecodeError:
            pass
    return base64.b64encode(raw_bytes).decode("ascii"), "base64"

# One lock per project's traffic file -- guards concurrent appends from the same process (e.g.
# several Playwright BrowserContexts capturing for the same session at once). Different sessions'
# files never contend with each other, so this is keyed by path, not a single global lock.
_write_locks: dict[str, threading.Lock] = {}
_write_locks_guard = threading.Lock()


def _lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _write_locks_guard:
        lock = _write_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _write_locks[key] = lock
        return lock


def _traffic_path(session_id: str | None) -> Path | None:
    """None -> the standalone global store (resolve_global_app_dir()/toolkit/traffic.jsonl, see
    this module's own docstring) -- always resolvable, unlike a per-project folder, so this branch
    never returns None itself. A real session_id with no project folder (e.g. a legacy
    pre-project-folder session) still can, exactly as before."""
    if session_id is None:
        return resolve_global_app_dir() / _TOOLKIT_SUBDIR / _TRAFFIC_FILENAME
    folder = get_session_folder(session_id)
    if not folder:
        return None
    return Path(folder) / _TOOLKIT_SUBDIR / _TRAFFIC_FILENAME


def build_traffic_entry(
    *,
    session_id: str | None,
    method: str,
    url: str,
    request_headers: dict[str, str],
    request_body: str,
    response_status: int | None,
    response_headers: dict[str, str],
    response_body: str,
    source: TrafficSource = "proxy",
    request_body_encoding: BodyEncoding = "text",
    request_content_length: int | None = None,
    response_body_encoding: BodyEncoding = "text",
    response_content_length: int | None = None,
    duration_ms: int | None = None,
    intruder_run_id: str | None = None,
    intruder_payload_values: list[str] | None = None,
) -> dict:
    """Assembles one traffic record in the shared schema -- the only place this shape is built, so
    later producers (mitmproxy addon, Repeater resend, Intruder attempts) can never drift apart on
    field names.

    *_body_encoding: "text" (the *_body string above is the real, directly readable content) or
    "base64" (the target's real bytes weren't text at all -- an image/font/other binary response --
    so *_body holds base64 instead of a force-decoded, garbled string; see
    agent/tools/toolkit_proxy.py's own _encode_body for the real incident this schema field fixes:
    a JPEG response rendered as mojibake in the Site Map's raw detail view before this existed).
    *_content_length: the real original byte count -- callers that already know it (toolkit_proxy.py,
    from the real undecoded bytes) should always pass it explicitly, since len(*_body) is wrong for
    a base64 string (inflated ~4/3x) and only coincidentally right for a plain UTF-8 one; defaults to
    len(*_body) for callers/tests that don't care (always correct for the "text" encoding case).

    duration_ms: wall-clock time the real send took (Repeater/Intruder only -- toolkit_proxy.py's
    passive mitmproxy capture never measures this, so a proxy-sourced entry always leaves it None).
    intruder_run_id/intruder_payload_values: set only by an Intruder attack attempt
    (source="intruder") -- which attack run this entry belongs to, and the exact payload value(s)
    substituted at each §...§ position for this one attempt, in position order. None for every
    proxy/repeater entry -- there's no attack run or payload substitution to record for those.

    flags: agent/tools/passive_detectors.py's deterministic checks (sql_error/open_redirect/
    command_injection/reflected_payload), run against EVERY entry this function ever builds --
    Proxy capture (agent/tools/toolkit_proxy.py's mitmproxy addon), Repeater sends, Intruder
    attempts alike, since they all funnel through this one function already. Closes a real gap:
    before this, these same detectors only ran inside native.py's http_request, so a SQL error or
    open redirect surfacing during ordinary browser-driven recon (never routed through http_request)
    went completely unflagged. Skipped for a base64-encoded (binary) response body -- these
    detectors are text-pattern checks, running them against base64 gibberish can only waste cycles,
    never match."""
    flags = (
        passive_detectors.detect_flags(url, response_status, response_headers, response_body)
        if response_body_encoding == "text" else []
    )
    return {
        "id": secrets.token_hex(8),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "method": method,
        "url": url,
        "request_headers": request_headers,
        "request_body": request_body,
        "request_body_encoding": request_body_encoding,
        "request_content_length": request_content_length if request_content_length is not None else len(request_body),
        "response_status": response_status,
        "response_headers": response_headers,
        "response_body": response_body,
        "response_body_encoding": response_body_encoding,
        "response_content_length": response_content_length if response_content_length is not None else len(response_body),
        "source": source,
        "duration_ms": duration_ms,
        "intruder_run_id": intruder_run_id,
        "intruder_payload_values": intruder_payload_values,
        "flags": flags,
    }


def format_header_lines(headers: dict) -> str:
    """"Name: value" per line -- the shared text shape every manual header editor in the toolkit
    (Repeater, Intruder) uses, so a captured/sent header dict round-trips into an editable textarea
    the same way everywhere, not reimplemented per template."""
    return "\n".join(f"{name}: {value}" for name, value in headers.items())


def parse_header_lines(text: str) -> dict[str, str]:
    """Inverse of format_header_lines -- tolerant of blank lines and lines missing a ':' (silently
    skipped, same "don't fail the whole send over one malformed line" posture as the rest of the
    manual-entry toolkit)."""
    headers: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        if name:
            headers[name] = value.strip()
    return headers


def append_traffic_entry(entry: dict) -> bool:
    """Appends one traffic record for its session (or the standalone global store, entry["session_id"]
    is None) as a JSON line. Returns False (logged, no exception) when a real session_id has no
    project folder yet -- e.g. a legacy pre-project-folder session -- matching agent/utils/debug.py's
    own _session_folder() graceful-degrade convention rather than raising."""
    session_id = entry["session_id"]
    path = _traffic_path(session_id)
    if path is None:
        logger.debug("append_traffic_entry: no project folder for session=%s, skipping", session_id)
        return False

    line = json.dumps(entry, ensure_ascii=False)
    with _lock_for(path):
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as exc:
            logger.debug("append_traffic_entry: write failed for session=%s (%s)", session_id, exc)
            return False

    logger.debug(
        "append_traffic_entry: session=%s method=%s url=%s status=%s source=%s flags=%s",
        session_id, entry["method"], entry["url"], entry["response_status"], entry["source"], entry.get("flags") or [],
    )
    return True


def traffic_file_mtime_ns(session_id: str | None) -> int | None:
    """The traffic store's own last-modified time (nanoseconds, os.stat's st_mtime_ns), or None if
    it doesn't exist yet -- a cheap `stat()` a poller can compare against a previous value to tell
    "nothing new got captured since last time" apart from "go re-read/re-parse the whole file",
    without needing to load_traffic_entries() itself just to find out. Nanoseconds (not the float
    seconds st_mtime) because a fast-scanning session can append several captures within the same
    filesystem mtime tick's second-level resolution on some platforms."""
    path = _traffic_path(session_id)
    if path is None or not path.exists():
        return None
    return path.stat().st_mtime_ns


def load_traffic_entries(session_id: str | None) -> list[dict]:
    """Every captured traffic record for one session (session_id=None: the standalone global
    store), oldest first. Empty list for a session with no project folder or no captured traffic
    yet -- never raises."""
    path = _traffic_path(session_id)
    if path is None or not path.exists():
        return []

    entries: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                logger.debug("load_traffic_entries: skipping corrupt line for session=%s", session_id)
    return entries


_TAIL_READ_CHUNK_BYTES = 65536
_DEFAULT_QUERY_MAX_SCAN_LINES = int(os.getenv("TOOLKIT_QUERY_MAX_SCAN_LINES", "20000"))


def _iter_lines_reverse(path: Path):
    """Yields every non-empty raw line of `path`, newest (end of file) first, reading backward in
    fixed-size chunks -- the same seek-backward technique _read_last_lines uses, generalized into a
    lazy iterator so a caller can stop early (fixed `count`, toolkit_query.filter_entries's own
    match-then-stop scan) without knowing up front how many lines it will actually need."""
    if not path.exists():
        return
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        position = f.tell()
        trailing = b""  # a line fragment split across a chunk boundary, completed by the next (earlier) chunk
        while position > 0:
            read_size = min(_TAIL_READ_CHUNK_BYTES, position)
            position -= read_size
            f.seek(position)
            buffer = f.read(read_size) + trailing
            lines = buffer.split(b"\n")
            if position > 0:
                trailing = lines[0]  # incomplete -- more file precedes it that would complete it
                lines = lines[1:]
            else:
                trailing = b""
            for line in reversed(lines):
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    yield text


def _read_last_lines(path: Path, count: int) -> list[str]:
    """Up to the last `count` non-empty raw lines of a file, oldest-of-the-batch first, WITHOUT
    reading/parsing the whole file -- confirmed live: on a 384MB traffic.jsonl (one real session's
    passively-captured traffic store), load_traffic_entries' full-file parse-every-line approach
    took as long as ~8.6s to answer a list_captured_traffic call that only ever wanted the last
    15-40 entries, and measurably got slower every time the file grew further."""
    lines: list[str] = []
    for line in _iter_lines_reverse(path):
        lines.append(line)
        if len(lines) >= count:
            break
    return list(reversed(lines))


def load_recent_traffic_entries(session_id: str | None, limit: int) -> list[dict]:
    """The newest `limit` traffic entries, oldest-of-the-batch first (same ordering
    load_traffic_entries returns) -- WITHOUT parsing the rest of the file the way
    load_traffic_entries()[-limit:] would. Use this instead whenever a caller only needs a recent
    slice (e.g. list_captured_traffic's own small default limit) -- see _read_last_lines' own
    docstring for the real incident this fixes."""
    path = _traffic_path(session_id)
    if path is None:
        return []
    entries: list[dict] = []
    for line in _read_last_lines(path, limit):
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            logger.debug("load_recent_traffic_entries: skipping corrupt line for session=%s", session_id)
    return entries


def load_matching_traffic_entries(
    session_id: str | None, predicate, limit: int, max_scan: int | None = None,
) -> tuple[list[dict], bool]:
    """Newest-matching-first up to `limit` entries satisfying `predicate` (a callable(entry) ->
    bool, e.g. agent/tools/toolkit_query.compile_query's own return value), oldest-of-the-batch
    first (same convention load_recent_traffic_entries returns) -- scans backward from the end of
    the file via _iter_lines_reverse and stops as soon as either `limit` matches are found or
    `max_scan` raw lines have been examined, whichever comes first. Bounding the scan (rather than
    parsing the whole file the way load_traffic_entries would) matters for the same reason
    _read_last_lines' own docstring documents -- a query over a very large, mostly-irrelevant
    capture must not re-introduce that 384MB/~8.6s full-parse cost just because a filter is now
    involved. Second return value is True when the scan hit `max_scan` before finding `limit`
    matches (or the file end) -- callers should tell the caller (model/operator) results may be
    incomplete rather than silently presenting a partial match set as exhaustive."""
    path = _traffic_path(session_id)
    if path is None:
        return [], False
    scan_cap = max_scan if max_scan is not None else _DEFAULT_QUERY_MAX_SCAN_LINES
    matches: list[dict] = []
    scanned = 0
    truncated = False
    for line in _iter_lines_reverse(path):
        scanned += 1
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if predicate(entry):
            matches.append(entry)
            if len(matches) >= limit:
                break
        if scanned >= scan_cap:
            truncated = True
            break
    return list(reversed(matches)), truncated


def get_traffic_entry(session_id: str | None, entry_id: str) -> dict | None:
    """One captured traffic record by id, for the UI's lazy-loaded raw detail view (the Site Map
    panel's own row-click). A linear scan over load_traffic_entries -- no separate index, deferred
    until a real consumer needs fast pagination; fine at the traffic volume one project's
    Playwright session realistically produces."""
    for entry in load_traffic_entries(session_id):
        if entry["id"] == entry_id:
            return entry
    return None


def delete_traffic_entry(session_id: str | None, entry_id: str) -> bool:
    """Removes one captured traffic record by id -- the append-only JSONL store (append_traffic_entry)
    has no in-place delete, so this rewrites the whole file minus that one line, atomically (tmp
    file + os.replace, same convention as agent/tools/playbook_store.py/asset_baseline_store.py)
    under the same per-path lock append_traffic_entry itself uses, so a delete can never race a
    concurrent append into a half-written file. Returns False (no exception) for a missing
    session/file or an id that isn't there -- same graceful-degrade posture as the rest of this
    module, since the caller (main.py's delete route) only cares whether it can now stop showing
    that row, not why it was already gone.

    Real reason this exists: Repeater's method suggestions (main.py's _repeater_custom_methods) are
    derived live from this same history -- a typo or one-off custom method sent by mistake had no
    way to stop showing up as a "remembered" suggestion forever without this.
    """
    path = _traffic_path(session_id)
    if path is None or not path.exists():
        return False

    with _lock_for(path):
        entries = load_traffic_entries(session_id)
        remaining = [e for e in entries if e.get("id") != entry_id]
        if len(remaining) == len(entries):
            return False  # entry_id wasn't in this store -- nothing to delete

        tmp_path = path.with_suffix(".jsonl.tmp")
        try:
            with tmp_path.open("w", encoding="utf-8") as f:
                for entry in remaining:
                    f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            os.replace(tmp_path, path)
        except OSError as exc:
            logger.debug("delete_traffic_entry: rewrite failed for session=%s entry=%s (%s)", session_id, entry_id, exc)
            return False

    logger.debug("delete_traffic_entry: session=%s entry=%s removed", session_id, entry_id)
    return True
