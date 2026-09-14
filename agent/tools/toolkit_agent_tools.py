"""native_function bridges between the agent tool-calling convention (a sync `dict -> dict`
function, agent/tools/registry.py's own ToolSpec.native_function) and the native toolkit's own
engines (toolkit_repeater.send_raw_request / toolkit_store.load_traffic_entries /
toolkit_decoder.run_codec / toolkit_comparer.diff_entries / toolkit_sequencer.analyze_samples).
Same "bridge file, real domain logic stays elsewhere" shape as agent/tools/browser.py, except
these are real, working wrappers (not bypass stubs) -- none of the
toolkit engines need Playwright's own same-event-loop-across-calls constraint or a genuinely
concurrent background asyncio.Task the way browser_*/delegate_to_subagent do, so a plain sync
wrapper dispatched through the ordinary asyncio.to_thread(run_tool, ...) worker-thread path
(agent/tools/runner.py) is enough -- see _send_raw_request_native's own docstring for how the
async engine calls among them (send_raw_request, sequencer's own live-collection mode) still fit
that sync convention.

session_id for all but decode_value comes from params["_session_id"] -- server-injected by
agent/core.py's _run_tool_with_retry (never part of any of these tools' own JSON schema, so the
model can neither see nor override it), same convention already used for authenticated_request/
idor_probe/custom_exploit_run's own session-keyed credential/script lookups.
"""
from __future__ import annotations

import asyncio

from agent.tools import toolkit_intruder, toolkit_racer, toolkit_sequencer, toolkit_store
from agent.tools.allowed_targets import is_target_allowed
from agent.tools.toolkit_comparer import PARTS as _COMPARER_PARTS
from agent.tools.toolkit_comparer import diff_entries
from agent.tools.toolkit_decoder import SCHEMES as _DECODER_SCHEMES
from agent.tools.toolkit_decoder import run_codec
from agent.tools.toolkit_query import QuerySyntaxError, compile_query
from agent.tools.toolkit_repeater import send_raw_request

# Same "cap what's handed to the model" convention as native.py's http_request (body_preview:
# resp.text[:2000]) -- a captured/sent response body can run to ~1MB (confirmed live end-to-end),
# and this is what goes straight into the LLM's own token-priced context, not a
# human's own scrollable dialog (unlike main.py's much larger _TOOLKIT_DETAIL_MAX_BODY_CHARS).
_BODY_PREVIEW_MAX_CHARS = 2000
# A diff between two full HTTP messages (start line + headers + body each side) is naturally bigger
# than a single body preview -- double the single-body budget above, not the same one.
_DIFF_TEXT_MAX_CHARS = 4000
_LIST_TRAFFIC_DEFAULT_LIMIT = 50
_LIST_TRAFFIC_MAX_LIMIT = 200


def _body_preview(entry: dict, field_prefix: str) -> str:
    body = entry[f"{field_prefix}_body"]
    encoding = entry.get(f"{field_prefix}_body_encoding", "text")
    if encoding == "base64":
        # Never force a binary body into the model's context as raw base64 noise -- same rule
        # main.py's _prepare_detail_body and toolkit_comparer.py's _entry_text already enforce, for
        # the same real incident: a JPEG rendered as mojibake before this rule existed anywhere in
        # the toolkit.
        length = entry.get(f"{field_prefix}_content_length", 0)
        return f"(binary content, {length} bytes -- not shown as text)"
    truncated = len(body) > _BODY_PREVIEW_MAX_CHARS
    preview = body[:_BODY_PREVIEW_MAX_CHARS]
    return preview + " …(truncated)" if truncated else preview


def _send_raw_request_native(params: dict) -> dict:
    """Wraps the one genuinely async engine call among these four (toolkit_repeater.py's own
    httpx.AsyncClient) in asyncio.run() -- safe here specifically because this function only ever
    runs inside asyncio.to_thread's worker thread (agent/tools/runner.py's own _run_native), which
    has no event loop of its own to conflict with, unlike browser_*/delegate_to_subagent which must
    stay on the SAME loop across separate calls and so bypass this whole native_function path
    entirely (see agent/tools/browser.py's own docstring). A one-shot, stateless HTTP call has no
    such constraint.

    "target", not "url" -- deliberately matches http_request's own JSON schema field name (agent/
    tools/__init__.py's _HTTP_REQUEST_SCHEMA) so this tool's real, human-authorized target gets the
    exact same automatic out-of-scope/loopback/allowlist coverage every other target-taking tool
    gets "for free" (agent/core.py's _TARGET_SHAPED_ARGUMENT_KEYS / runner.py's _check_guardrail --
    both key off the literal argument name "target", independent of this ToolSpec's own
    requires_allowed_target flag, which is set True here for the SECOND, allowlist-specific gate).
    """
    session_id = params.get("_session_id", "")
    method = (params.get("method") or "GET").strip().upper()
    target = (params.get("target") or "").strip()
    headers = params.get("headers") or {}
    if not isinstance(headers, dict):
        return {"status": "error", "error": "headers must be an object of header name/value pairs, e.g. {\"Cookie\": \"session=abc\"}"}
    body = params.get("body") or ""

    result = asyncio.run(send_raw_request(session_id=session_id, method=method, url=target, headers=headers, body=body))
    if result["status"] != "ok":
        return {"status": "error", "error": result["error"]}

    entry = result["entry"]
    return {
        "status": "ok",
        "entry_id": entry["id"],
        "response_status": entry["response_status"],
        "response_headers": entry["response_headers"],
        "response_body_preview": _body_preview(entry, "response"),
    }


def _list_captured_traffic_native(params: dict) -> dict:
    """query (optional): an HTTPQL-lite filter string (agent/tools/toolkit_query.py) -- when given,
    scans this session's traffic backward from the newest entry looking for `limit` matches instead
    of just returning the newest `limit` entries unfiltered. A malformed query returns a clean
    {"status": "error"} (QuerySyntaxError's own message) rather than a bare traceback, since the
    model is the one writing the query text and needs to be able to react to a mistake in it."""
    session_id = params.get("_session_id", "")
    limit = int(params.get("limit") or _LIST_TRAFFIC_DEFAULT_LIMIT)
    limit = max(1, min(limit, _LIST_TRAFFIC_MAX_LIMIT))
    query_text = (params.get("query") or "").strip()

    truncated = False
    if query_text:
        try:
            predicate = compile_query(query_text)
        except QuerySyntaxError as exc:
            return {"status": "error", "error": f"invalid query: {exc}"}
        matches, truncated = toolkit_store.load_matching_traffic_entries(session_id, predicate, limit)
        entries = list(reversed(matches))
    else:
        # Newest-first, same order as the Site Map sub-tab (main.py's get_toolkit_traffic_list) --
        # the model's own "what just happened" intuition matches the operator's own view of the
        # same data. load_recent_traffic_entries (not load_traffic_entries) -- this only ever wants
        # a small recent slice, and the full-file version measurably slowed down over a session as
        # the underlying traffic.jsonl grew (see its own docstring for the real incident).
        entries = list(reversed(toolkit_store.load_recent_traffic_entries(session_id, limit)))

    result = {
        "status": "ok",
        "count": len(entries),
        "entries": [
            {
                "id": e["id"], "method": e["method"], "url": e["url"],
                "status": e["response_status"], "source": e["source"], "timestamp": e["timestamp"],
                "flags": e.get("flags") or [],
            }
            for e in entries
        ],
    }
    if truncated:
        result["warning"] = (
            "the query hit its scan limit before reaching the start of this session's traffic -- "
            "there may be more matches this call didn't reach; narrow the query or call again"
        )
    return result


def _decode_value_native(params: dict) -> dict:
    return run_codec(scheme=params.get("scheme", ""), mode=params.get("mode", ""), text=params.get("text", ""))


def _diff_rows_to_unified_text(rows: list[dict]) -> str:
    """Git-diff-style "-"/"+"/" " prefixed lines -- the model reads this format natively, unlike
    toolkit_comparer.py's own per-row char-level span structure (built for the UI's <mark>
    highlighting, agent/tools/toolkit_comparer.py's own diff_lines docstring), which would only add
    JSON nesting the model has no use for here. Deliberately re-renders the SAME diff_lines() rows
    the UI's own /toolkit/comparer route consumes -- one diff engine, two different presentations,
    never two competing diff implementations."""
    lines = []
    for row in rows:
        if row["tag"] == "equal":
            lines.append(f"  {row['left_text']}")
        elif row["tag"] == "delete":
            lines.append(f"- {row['left_text']}")
        elif row["tag"] == "insert":
            lines.append(f"+ {row['right_text']}")
        else:  # replace
            lines.append(f"- {row['left_text']}")
            lines.append(f"+ {row['right_text']}")
    text = "\n".join(lines)
    if len(text) > _DIFF_TEXT_MAX_CHARS:
        return text[:_DIFF_TEXT_MAX_CHARS] + "\n…(truncated)"
    return text


def _diff_requests_native(params: dict) -> dict:
    result = diff_entries(
        session_id=params.get("_session_id", ""),
        entry_id_a=params.get("entry_id_a", ""),
        entry_id_b=params.get("entry_id_b", ""),
        part=params.get("part", "response"),
    )
    if result["status"] != "ok":
        return {"status": "error", "error": result["error"]}
    return {"status": "ok", "diff": _diff_rows_to_unified_text(result["rows"])}


def _intruder_run_native(params: dict) -> dict:
    """Wraps toolkit_intruder.run_attack in asyncio.run() -- same reasoning as
    _send_raw_request_native above (this function only ever runs inside asyncio.to_thread's own
    worker thread, which has no event loop of its own to conflict with). AWAITS full completion,
    unlike the manual UI's own fire-and-forget route (main.py's post_toolkit_intruder_run) -- a
    slow tool call just takes as long as it takes, the same convention every other long-running
    tier-1 tool (nmap/sqlmap-equivalent) already follows in this project; there is no separate
    "check status" tool to pair this with.

    "target", not "url" -- same reasoning as _send_raw_request_native: matches
    _TARGET_SHAPED_ARGUMENT_KEYS/_check_guardrail's literal key name, so this tool's real target
    gets the same automatic out-of-scope/loopback/allowlist coverage every other target-taking
    tool gets, independent of any §...§ markers embedded in it (they can only ever land in the
    path/query portion of the URL string in practice, never break hostname extraction)."""
    session_id = params.get("_session_id", "")
    method = (params.get("method") or "GET").strip().upper()
    target = (params.get("target") or "").strip()
    headers_text = params.get("headers_text") or ""
    body = params.get("body") or ""
    mode = params.get("mode") or "sniper"
    payload_text = params.get("payload_text") or ""

    result = asyncio.run(toolkit_intruder.run_attack(
        session_id=session_id, method=method, url=target, headers_text=headers_text, body=body,
        mode=mode, payload_text=payload_text,
    ))
    if result["status"] != "ok":
        return {"status": "error", "error": result["error"]}
    return result


SEND_RAW_REQUEST_SCHEMA = {
    "type": "object",
    "properties": {
        "method": {"type": "string", "description": "HTTP method, e.g. GET/POST/PUT/DELETE (default GET)."},
        "target": {"type": "string", "description": "Full URL to send the request to — checked against this project's scope/allowlist the same way every other target-taking tool is."},
        "headers": {
            "type": "object", "description": "Header name -> value pairs. Optional.",
            "additionalProperties": {"type": "string"},
        },
        "body": {"type": "string", "description": "Raw request body. Optional, empty for none."},
    },
    "required": ["target"],
}

LIST_CAPTURED_TRAFFIC_SCHEMA = {
    "type": "object",
    "properties": {
        "limit": {
            "type": "integer",
            "description": f"Max entries to return, newest first (default {_LIST_TRAFFIC_DEFAULT_LIMIT}, capped at {_LIST_TRAFFIC_MAX_LIMIT}).",
        },
        "query": {
            "type": "string",
            "description": (
                "Optional HTTPQL-lite filter, e.g. 'method.eq:POST AND resp.body.cont:\"stack trace\"' or "
                "'resp.header[\"Set-Cookie\"].ncont:\"HttpOnly\"'. Fields: method, host, path, url, status, "
                "source, flags, req.body, resp.body, req.header.name, req.header.value, resp.header.name, "
                "resp.header.value, req.header[\"Name\"], resp.header[\"Name\"]. Operators: eq/neq, cont/ncont, "
                "like/nlike (SQL LIKE, %/_ wildcards), regex/nregex. Combine terms with AND/OR and parentheses "
                "(AND binds tighter). Omit to just list the newest entries unfiltered."
            ),
        },
    },
}

DECODE_VALUE_SCHEMA = {
    "type": "object",
    "properties": {
        "scheme": {"type": "string", "enum": list(_DECODER_SCHEMES), "description": "Encoding scheme."},
        "mode": {"type": "string", "enum": ["encode", "decode"], "description": "Whether to encode or decode text."},
        "text": {"type": "string", "description": "The input string."},
    },
    "required": ["scheme", "mode", "text"],
}

DIFF_REQUESTS_SCHEMA = {
    "type": "object",
    "properties": {
        "entry_id_a": {"type": "string", "description": "id of the first captured traffic entry (from list_captured_traffic or a value the operator gave you)."},
        "entry_id_b": {"type": "string", "description": "id of the second captured traffic entry."},
        "part": {"type": "string", "enum": list(_COMPARER_PARTS), "description": "Compare each entry's request or response (default response)."},
    },
    "required": ["entry_id_a", "entry_id_b"],
}

INTRUDER_RUN_SCHEMA = {
    "type": "object",
    "properties": {
        "method": {"type": "string", "description": "HTTP method, e.g. GET/POST (default GET)."},
        "target": {
            "type": "string",
            "description": (
                "Full URL, with each attack position wrapped in §...§ (e.g. "
                "https://example.com/user/§1§) -- checked against this project's scope/allowlist "
                "the same way every other target-taking tool is."
            ),
        },
        "headers_text": {
            "type": "string",
            "description": "Raw headers, one 'Name: value' per line. A position can also be wrapped in §...§ inside a header value, e.g. 'Cookie: session=§abc§'.",
        },
        "body": {"type": "string", "description": "Raw request body. Optional, can also contain §...§ positions."},
        "mode": {
            "type": "string", "enum": ["sniper", "pitchfork"],
            "description": "sniper: one payload set attacks each position in turn (num_positions * num_payloads requests). pitchfork: one payload set PER position, stepped together (needs matching column counts).",
        },
        "payload_text": {
            "type": "string",
            "description": (
                "sniper: one payload per line, applied to every position in turn. pitchfork: one "
                "line per attempt, with exactly as many tab-separated values as §...§ positions."
            ),
        },
    },
    "required": ["target", "mode", "payload_text"],
}


def _sequencer_analyze_native(params: dict) -> dict:
    """Wraps toolkit_sequencer's collect_stored_samples/collect_live_samples + analyze_samples --
    same two collection modes the manual UI route (main.py's post_toolkit_sequencer_analyze)
    offers, mirrored here rather than reinvented. mode="stored" (the default) is a pure local read
    off already-captured traffic, no network call and no target at all -- same risk class as
    list_captured_traffic, registered with requires_allowed_target=False. mode="live" fires
    `count` real, repeated requests against a real target (same shape/risk as intruder_run, which
    IS gated by the exploitation allowlist) -- since a single ToolSpec can only carry one static
    requires_allowed_target value and this tool's own stored mode has no target to check at all,
    the allowlist gate for live mode is applied manually here instead, mirroring
    runner.py's _check_guardrail rejection text for consistency. "target", not "url" -- same
    reasoning as _send_raw_request_native/_intruder_run_native: matches
    _TARGET_SHAPED_ARGUMENT_KEYS's literal key name, so this tool's real target gets the same
    automatic out-of-scope/loopback coverage every other target-taking tool gets for free,
    independent of this manual allowlist check.
    """
    session_id = params.get("_session_id", "")
    mode = params.get("mode") or "stored"
    header_name = (params.get("header_name") or "").strip()
    if not header_name:
        return {"status": "error", "error": "header_name is required, e.g. 'X-CSRF-Token' or 'cookie:session'"}

    if mode == "live":
        target = (params.get("target") or "").strip()
        if not target:
            return {"status": "error", "error": "target is required when mode='live'"}
        if not is_target_allowed(target):
            return {
                "status": "skipped",
                "reason": (
                    f"target {target!r} is not in this project's exploitation allowlist. This is a permanent, "
                    "deterministic rejection for this target for the rest of this session — no combination of "
                    "arguments will change the outcome. Use mode='stored' instead if you only need to analyze "
                    "tokens already seen in this session's own captured traffic."
                ),
            }
        method = (params.get("method") or "GET").strip().upper()
        headers_text = params.get("headers_text") or ""
        body = params.get("body") or ""
        count = int(params.get("count") or 20)
        collected = asyncio.run(toolkit_sequencer.collect_live_samples(
            session_id=session_id, method=method, url=target, headers_text=headers_text,
            body=body, header_name=header_name, count=count,
        ))
        samples = collected["samples"]
    else:
        samples = toolkit_sequencer.collect_stored_samples(session_id, header_name)

    analysis = toolkit_sequencer.analyze_samples(samples)
    if analysis["status"] != "ok":
        return {"status": "error", "error": analysis["error"]}
    return analysis


SEQUENCER_ANALYZE_SCHEMA = {
    "type": "object",
    "properties": {
        "header_name": {
            "type": "string",
            "description": (
                "The header or cookie carrying the token to analyze, e.g. 'X-CSRF-Token' or a "
                "cookie via 'cookie:session' (prefix with 'cookie:' plus the cookie's own name)."
            ),
        },
        "mode": {
            "type": "string", "enum": ["stored", "live"],
            "description": (
                "stored (default): analyze the token across every already-captured traffic entry "
                "in this session's own Site Map — no network call, no target needed. live: fire "
                "`count` fresh, identical requests at `target` and extract the token from each real "
                "response — checked against this project's scope/allowlist the same way every other "
                "target-taking tool is. Prefer stored first if this token already appears in traffic "
                "you've already captured; use live only when you need more/fresh samples."
            ),
        },
        "target": {
            "type": "string",
            "description": "Full URL to request repeatedly — only used (and required) when mode='live'.",
        },
        "method": {"type": "string", "description": "HTTP method for mode='live' requests, e.g. GET/POST (default GET)."},
        "headers_text": {"type": "string", "description": "Raw headers for mode='live' requests, one 'Name: value' per line. Optional."},
        "body": {"type": "string", "description": "Raw request body for mode='live' requests. Optional."},
        "count": {
            "type": "integer",
            "description": "How many fresh samples to collect for mode='live' (default 20). Ignored for mode='stored'.",
        },
    },
    "required": ["header_name"],
}


def _racer_run_native(params: dict) -> dict:
    """Wraps toolkit_racer.run_race in asyncio.run() -- same reasoning as _intruder_run_native
    above (this function only ever runs inside asyncio.to_thread's own worker thread). AWAITS full
    completion, same "a slow tool call just takes as long as it takes" convention as intruder_run.

    "target", not "url" -- same reasoning as every other target-taking native wrapper in this file:
    matches _TARGET_SHAPED_ARGUMENT_KEYS/_check_guardrail's literal key name, so this tool's real
    target gets the same automatic out-of-scope/loopback/allowlist coverage every other
    target-taking tool gets for free, independent of this ToolSpec's own requires_allowed_target
    flag (set True below, the SECOND, allowlist-specific gate -- same pattern send_raw_request/
    intruder_run already use)."""
    session_id = params.get("_session_id", "")
    method = (params.get("method") or "GET").strip().upper()
    target = (params.get("target") or "").strip()
    headers_text = params.get("headers_text") or ""
    body = params.get("body") or ""
    strategy = params.get("strategy") or "last_byte"
    request_count = int(params.get("request_count") or 10)

    result = asyncio.run(toolkit_racer.run_race(
        session_id=session_id, method=method, url=target, headers_text=headers_text,
        body=body, request_count=request_count, strategy=strategy,
    ))
    if result["status"] != "ok":
        return {"status": "error", "error": result["error"]}
    # `results` (per-attempt entry_id/status/duration) stays out of what the model sees by default
    # -- response_status_counts already answers the question this tool exists for ("did more than
    # one attempt succeed at the SAME instant"), and list_captured_traffic/diff_requests are the
    # right follow-up tools for inspecting individual attempts, same "summary here, detail via a
    # separate call" shape intruder_run already uses.
    return {
        "status": "ok", "run_id": result["run_id"], "strategy": result["strategy"],
        "requests": result["requests"], "ok": result["ok"], "errors": result["errors"],
        "response_status_counts": result["response_status_counts"],
    }


RACER_RUN_SCHEMA = {
    "type": "object",
    "properties": {
        "method": {"type": "string", "description": "HTTP method, e.g. GET/POST/PUT (default GET)."},
        "target": {
            "type": "string",
            "description": (
                "Full URL to race -- the SAME request is fired `request_count` times concurrently "
                "(strategy='last_byte') or one after another (strategy='sequential'). Checked "
                "against this project's scope/allowlist the same way every other target-taking "
                "tool is."
            ),
        },
        "headers_text": {"type": "string", "description": "Raw headers, one 'Name: value' per line. Optional."},
        "body": {"type": "string", "description": "Raw request body, sent identically on every attempt. Optional."},
        "strategy": {
            "type": "string", "enum": ["last_byte", "sequential"],
            "description": (
                "last_byte (default): opens every connection first, sends everything but the final "
                "byte of each request, then releases that final byte on all connections at once -- "
                "the technique real race-condition PoCs (limit overrun, coupon/voucher reuse, "
                "double-spend, TOCTOU auth bugs) need, far tighter than plain concurrent sends. "
                "sequential: the same request sent one after another with no synchronization at "
                "all -- a baseline to compare against (a bug that only shows up under last_byte, "
                "never sequential, confirms it's genuinely timing-dependent)."
            ),
        },
        "request_count": {
            "type": "integer",
            "description": "How many concurrent (or sequential) copies of the request to fire (default 10, hard-capped for safety -- this concentrates load on one endpoint at effectively one instant).",
        },
    },
    "required": ["target"],
}
