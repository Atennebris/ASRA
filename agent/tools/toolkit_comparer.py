"""Comparer: line- and character-level diff between two captured traffic entries -- pure stdlib
(difflib), no external dependency. Used by both the manual UI (main.py's comparer routes) and the
agent-facing `diff_requests` native tool, so the two share the exact same diff behavior and
entry-lookup logic -- same "shared engine, two callers" shape as toolkit_repeater.py's
send_raw_request.
"""
from __future__ import annotations

import difflib

from agent.tools import toolkit_store
from agent.utils.logger import get_logger

logger = get_logger("TOOLKIT")

PARTS = ("request", "response")


def _char_spans(a: str, b: str) -> tuple[list[dict], list[dict]]:
    """Character-level breakdown of one changed line pair -- each side's own list of
    {"text": ..., "changed": bool} spans, so a "replace" row can highlight exactly which characters
    differ (e.g. a session token that only changed in 3 places) instead of just marking the whole
    line as different, same as a commercial diff-comparer's own word/byte view."""
    matcher = difflib.SequenceMatcher(None, a, b)
    left_spans: list[dict] = []
    right_spans: list[dict] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            left_spans.append({"text": a[i1:i2], "changed": False})
            right_spans.append({"text": b[j1:j2], "changed": False})
            continue
        if i1 != i2:
            left_spans.append({"text": a[i1:i2], "changed": True})
        if j1 != j2:
            right_spans.append({"text": b[j1:j2], "changed": True})
    return left_spans, right_spans


def diff_lines(text_a: str, text_b: str) -> list[dict]:
    """Line-level diff between two text blobs as a list of side-by-side rows:
    {"tag": "equal"|"delete"|"insert"|"replace", "left_text": str|None, "right_text": str|None,
     "left_spans": [...]|None, "right_spans": [...]|None}
    "replace" rows carry char-level spans (see _char_spans) for the paired lines; "delete"/"insert"
    rows are whole-line (nothing on the other side to diff against)."""
    lines_a = text_a.splitlines()
    lines_b = text_b.splitlines()
    matcher = difflib.SequenceMatcher(None, lines_a, lines_b)
    rows: list[dict] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for a_line, b_line in zip(lines_a[i1:i2], lines_b[j1:j2]):
                rows.append({"tag": "equal", "left_text": a_line, "right_text": b_line, "left_spans": None, "right_spans": None})
        elif tag == "delete":
            for a_line in lines_a[i1:i2]:
                rows.append({"tag": "delete", "left_text": a_line, "right_text": None, "left_spans": None, "right_spans": None})
        elif tag == "insert":
            for b_line in lines_b[j1:j2]:
                rows.append({"tag": "insert", "left_text": None, "right_text": b_line, "left_spans": None, "right_spans": None})
        elif tag == "replace":
            a_chunk = lines_a[i1:i2]
            b_chunk = lines_b[j1:j2]
            # Pair up as many lines 1:1 as both chunks have in common -- a genuinely changed line
            # gets char-level highlighting; any leftover on the longer side is a pure add/remove,
            # not a "changed" pairing with nothing sensible on the other side to compare against.
            paired = min(len(a_chunk), len(b_chunk))
            for k in range(paired):
                left_spans, right_spans = _char_spans(a_chunk[k], b_chunk[k])
                rows.append({"tag": "replace", "left_text": a_chunk[k], "right_text": b_chunk[k], "left_spans": left_spans, "right_spans": right_spans})
            for a_line in a_chunk[paired:]:
                rows.append({"tag": "delete", "left_text": a_line, "right_text": None, "left_spans": None, "right_spans": None})
            for b_line in b_chunk[paired:]:
                rows.append({"tag": "insert", "left_text": None, "right_text": b_line, "left_spans": None, "right_spans": None})
    return rows


def _entry_text(entry: dict, part: str) -> str:
    """One traffic entry's request or response as a single comparable text blob -- the same
    "start line + headers + blank + body" shape a human already sees in the Site Map/Repeater raw
    detail view. A binary (base64-encoded) body is never diffed as text -- same rule main.py's
    _prepare_detail_body already enforces, for the same real incident: a JPEG rendered as mojibake
    before that rule existed -- shown as a placeholder line instead, so a diff against a binary
    body is still meaningful (byte count changed or not) rather than a wall of meaningless base64
    character noise."""
    if part == "request":
        start_line = f"{entry['method']} {entry['url']}"
        headers = entry["request_headers"]
        body, encoding, length = (
            entry["request_body"], entry.get("request_body_encoding", "text"),
            entry.get("request_content_length", len(entry["request_body"])),
        )
    else:
        start_line = str(entry.get("response_status") or "")
        headers = entry["response_headers"]
        body, encoding, length = (
            entry["response_body"], entry.get("response_body_encoding", "text"),
            entry.get("response_content_length", len(entry["response_body"])),
        )
    header_lines = "\n".join(f"{name}: {value}" for name, value in headers.items())
    body_text = body if encoding != "base64" else f"(binary content, {length} bytes -- not compared as text)"
    return f"{start_line}\n{header_lines}\n\n{body_text}"


def diff_entries(*, session_id: str | None, entry_id_a: str, entry_id_b: str, part: str) -> dict:
    """Returns {"status": "ok", "rows": [...]} or {"status": "error", "error": "..."} -- never
    raises, same "structured result, never an exception the caller has to guard against" posture as
    toolkit_repeater.py's send_raw_request and toolkit_decoder.py's run_codec."""
    if part not in PARTS:
        return {"status": "error", "error": f"Unknown part: {part}"}
    entry_a = toolkit_store.get_traffic_entry(session_id, entry_id_a)
    entry_b = toolkit_store.get_traffic_entry(session_id, entry_id_b)
    if entry_a is None or entry_b is None:
        return {"status": "error", "error": "One or both selected traffic entries were not found."}
    rows = diff_lines(_entry_text(entry_a, part), _entry_text(entry_b, part))
    logger.debug(
        "toolkit_comparer: session=%s a=%s b=%s part=%s rows=%d",
        session_id, entry_id_a, entry_id_b, part, len(rows),
    )
    return {"status": "ok", "rows": rows}
