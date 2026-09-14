"""Repeater's send engine: one function that actually sends an arbitrary HTTP request and records
it into the native toolkit's traffic store (agent/tools/toolkit_store.py) -- used by both the
manual UI (main.py's repeater routes) and the agent-facing `send_raw_request` native tool, so the
two can never drift apart on how a resend actually works.

Deliberately does NOT go through agent/tools/toolkit_proxy.py's mitmproxy instance -- this is a
direct outbound call from the ASRA server process itself (httpx), not traffic from the agent's own
Playwright browser. Scope/allowlist gating is deliberately NOT applied here either: this module is
the manual, human-operated half of the toolkit (a commercial repeater tool has no such gate for the
same reason -- a human operator explicitly typing/editing a request is trusted the way an
autonomous agent tool call isn't); `send_raw_request`'s own registration is where
requires_allowed_target=True actually applies, the same way every other agent-facing exploit tool
already does it -- this function itself stays a plain, ungated HTTP client.
"""
from __future__ import annotations

import os
import time

import httpx

from agent.tools import toolkit_store
from agent.tools.toolkit_store import TrafficSource
from agent.utils.errors import describe_exception
from agent.utils.logger import get_logger

logger = get_logger("TOOLKIT")

_DEFAULT_TIMEOUT_SECONDS = 10.0


def _timeout_seconds() -> float:
    # Same env var as native.py's http_request -- conceptually the identical knob ("how long to
    # wait for one HTTP response from a pentest target"), no reason for Repeater to need its own.
    return float(os.getenv("HTTP_REQUEST_TIMEOUT_SECONDS", str(_DEFAULT_TIMEOUT_SECONDS)))


async def send_raw_request(
    *, session_id: str | None, method: str, url: str, headers: dict[str, str], body: str,
    source: TrafficSource = "repeater", intruder_run_id: str | None = None,
    intruder_payload_values: list[str] | None = None,
) -> dict:
    """Sends one HTTP request and records it as a traffic entry (same schema Proxy captures use,
    toolkit_store.build_traffic_entry) so it shows up in the Site Map's history right alongside
    passively-captured traffic, and Comparer can diff an attempt against the original request it
    was built from.

    source/intruder_run_id/intruder_payload_values: Repeater's own manual send/resend never passes
    these (defaults are exactly Repeater's own original behavior), but Intruder's attack engine
    (agent/tools/toolkit_intruder.py) calls this SAME function per attempt with source="intruder"
    and its own run/payload identifiers -- one real send-and-record code path for both features,
    never a second copy that could drift on encoding/storage behavior.

    Returns {"status": "ok", "entry": <the stored traffic entry dict>} on a real response (any
    HTTP status -- a 500 or 404 is still a real, successful send from this function's own point of
    view), or {"status": "error", "error": "..."} when the request itself couldn't complete at all
    (DNS failure, connection refused, timeout, an invalid URL/method) -- nothing is stored in that
    case, there's no real response to record.

    verify=False / follow_redirects=False, same reasoning as every other HTTP client already in
    this project (native.py's http_request, browser_manager.py's ignore_https_errors=True): a real
    pentest target commonly has a self-signed/expired cert, and a manual Repeater resend should
    show the RAW response (a redirect itself is often exactly what's being tested), never silently
    follow it."""
    request_body_bytes = body.encode("utf-8") if body else b""
    started_at = time.monotonic()
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=_timeout_seconds()) as client:
            response = await client.request(method, url, headers=headers, content=request_body_bytes or None)
    except Exception as exc:
        # describe_exception, not str(exc) -- a bare httpx.ConnectTimeout()/ReadTimeout() (real,
        # confirmed here) has an empty str(), which used to log/return "" and leave a model's
        # 1-Step Retry with nothing to react to, only able to resend the identical failing call.
        described = describe_exception(exc)
        logger.debug("toolkit_repeater: send failed session=%s method=%s url=%s (%s)", session_id, method, url, described)
        return {"status": "error", "error": described}
    duration_ms = round((time.monotonic() - started_at) * 1000)

    request_content_type = headers.get("Content-Type") or headers.get("content-type") or ""
    request_body, request_encoding = toolkit_store.encode_body(request_content_type, request_body_bytes)
    response_content_type = response.headers.get("content-type", "")
    response_body, response_encoding = toolkit_store.encode_body(response_content_type, response.content or b"")

    entry = toolkit_store.build_traffic_entry(
        session_id=session_id,
        method=method,
        url=url,
        request_headers=headers,
        request_body=request_body,
        request_body_encoding=request_encoding,
        request_content_length=len(request_body_bytes),
        response_status=response.status_code,
        response_headers=dict(response.headers),
        response_body=response_body,
        response_body_encoding=response_encoding,
        response_content_length=len(response.content or b""),
        source=source,
        duration_ms=duration_ms,
        intruder_run_id=intruder_run_id,
        intruder_payload_values=intruder_payload_values,
    )
    toolkit_store.append_traffic_entry(entry)
    logger.debug(
        "toolkit_repeater: session=%s method=%s url=%s status=%s duration_ms=%s source=%s",
        session_id, method, url, response.status_code, duration_ms, source,
    )
    return {"status": "ok", "entry": entry}
