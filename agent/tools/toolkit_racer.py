"""Racer: race-condition testing via last-byte synchronization -- open several raw TCP connections
to the SAME endpoint, send everything but the final byte of each request, then release that final
byte on every connection in the same asyncio.gather() call so the server sees them arrive within a
fraction of a millisecond of each other. This is the "single-packet"-adjacent technique real race
PoCs (limit-overrun, coupon/voucher reuse, double-spend, TOCTOU auth bugs) depend on -- Caido calls
its own version of this "Last Byte Synchronization" (a Pipeline Replay session strategy); the
underlying idea (hold back the byte that tells the server "this request is complete", flip every
held-back byte together) predates it and is the same one Turbo Intruder's race-condition examples
use. Ordinary concurrent sends (this project's own Intruder, or a plain asyncio.gather of httpx
calls) can't get anywhere near this tight a window -- TCP handshake time, TLS negotiation, and
per-connection scheduling jitter each individually dwarf the race window a real TOCTOU bug needs
closed. httpx has no hook for "send everything except the last byte, then send the rest on command"
(it owns the whole request lifecycle internally), so this module talks raw sockets directly and
carries its own minimal HTTP/1.1 response reader.

Deliberately fires the SAME request template N times (never N different requests, unlike Caido's
own Pipeline, which can queue a mixed batch) -- the overwhelmingly common real race PoC shape is
"the exact same request, many concurrent copies", and every extra bit of scheduling per distinct
request would only work against the tight synchronization the technique exists for. Also offers a
plain "sequential" strategy (send the same template N times, one after another, no synchronization
attempt at all) purely as a baseline to compare against -- reuses toolkit_repeater.send_raw_request
directly rather than the raw-socket engine, since there's no timing to control there.

Every attempt (either strategy) is recorded into toolkit_store as its own traffic entry
(source="racer"), so results show up in the Site Map/list_captured_traffic exactly like any other
toolkit action -- no separate results store to keep in sync.
"""
from __future__ import annotations

import asyncio
import os
import ssl
import time
import uuid
from typing import Literal
from urllib.parse import urlsplit

from agent.tools import toolkit_store
from agent.tools.toolkit_repeater import send_raw_request
from agent.utils.logger import get_logger

logger = get_logger("TOOLKIT")

Strategy = Literal["last_byte", "sequential"]

_DEFAULT_REQUEST_COUNT = 10
# A hard ceiling regardless of what's requested -- deliberately much lower than Intruder's own
# _MAX_ATTEMPTS (500, toolkit_intruder.py): Intruder's attempts are spread over time and bounded by
# its own concurrency cap, while every one of these attempts is aimed at hitting the SAME endpoint
# at effectively the SAME INSTANT -- a categorically bigger, more concentrated shock to the real
# target per unit of "attack size" than a sniper/pitchfork sweep ever produces.
_MAX_ALLOWED_REQUESTS = 50
_DEFAULT_CONNECT_TIMEOUT_SECONDS = 10.0
_DEFAULT_RESPONSE_TIMEOUT_SECONDS = 10.0
# Same "cap what one response can cost to hold in memory" posture as toolkit_proxy.py's
# _MAX_CAPTURED_BODY_BYTES -- this engine reads raw bytes off a socket itself, nothing upstream
# (httpx, mitmproxy) is already enforcing a limit for it.
_MAX_RESPONSE_BODY_BYTES = 2_000_000


def _max_allowed_requests() -> int:
    return int(os.getenv("RACER_MAX_REQUESTS", str(_MAX_ALLOWED_REQUESTS)))


def _connect_timeout_seconds() -> float:
    return float(os.getenv("RACER_CONNECT_TIMEOUT_SECONDS", str(_DEFAULT_CONNECT_TIMEOUT_SECONDS)))


def _response_timeout_seconds() -> float:
    return float(os.getenv("RACER_RESPONSE_TIMEOUT_SECONDS", str(_DEFAULT_RESPONSE_TIMEOUT_SECONDS)))


def validate_request_count(request_count: int) -> dict | None:
    """None if `request_count` is usable, else {"status": "error", "error": ...} -- checked
    upfront by both strategies' own entry points so a bad count never starts partial work."""
    cap = _max_allowed_requests()
    if request_count < 2:
        return {"status": "error", "error": "request_count must be at least 2 -- a race needs at least two concurrent attempts"}
    if request_count > cap:
        return {"status": "error", "error": f"request_count {request_count} exceeds the {cap}-request safety cap for one race run"}
    return None


def _build_raw_request(method: str, host_header: str, path_and_query: str, headers: dict[str, str], body: bytes) -> tuple[bytes, dict[str, str]]:
    """The exact bytes to send, plus the FINAL request_headers dict actually used (Host/
    Content-Length/Connection are always set/overridden here, never left to whatever the operator's
    own headers_text happened to contain) -- so the traffic entry this attempt gets recorded under
    reflects what really went over the wire, not the caller's raw input."""
    final_headers = {name: value for name, value in headers.items() if name.lower() not in ("host", "content-length", "connection")}
    final_headers = {"Host": host_header, **final_headers, "Content-Length": str(len(body)), "Connection": "close"}
    lines = [f"{method} {path_and_query} HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in final_headers.items())
    head = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n"
    return head + body, final_headers


async def _read_raw_response(reader: asyncio.StreamReader, timeout: float) -> dict:
    """Minimal HTTP/1.1 response parser (status line, headers, Content-Length or chunked body, or
    read-until-close as a last resort) -- httpx isn't in the picture at all for this strategy (see
    this module's own docstring for why), so nothing else already does this."""
    status_line = await asyncio.wait_for(reader.readline(), timeout)
    if not status_line:
        raise ConnectionError("connection closed before a status line was received")
    parts = status_line.decode("latin-1", errors="replace").split(None, 2)
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

    headers: dict[str, str] = {}
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout)
        if line in (b"\r\n", b"", b"\n"):
            break
        name, _, value = line.decode("latin-1", errors="replace").partition(":")
        if name:
            headers[name.strip()] = value.strip()

    body = b""
    content_length = headers.get("Content-Length") or headers.get("content-length")
    transfer_encoding = (headers.get("Transfer-Encoding") or headers.get("transfer-encoding") or "").lower()
    if content_length is not None and content_length.isdigit():
        remaining = min(int(content_length), _MAX_RESPONSE_BODY_BYTES)
        body = await asyncio.wait_for(reader.readexactly(remaining), timeout) if remaining else b""
    elif "chunked" in transfer_encoding:
        chunks: list[bytes] = []
        total = 0
        while total < _MAX_RESPONSE_BODY_BYTES:
            size_line = await asyncio.wait_for(reader.readline(), timeout)
            size = int(size_line.split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await asyncio.wait_for(reader.readline(), timeout)  # trailing CRLF after the 0-size chunk
                break
            chunk = await asyncio.wait_for(reader.readexactly(size), timeout)
            await asyncio.wait_for(reader.readline(), timeout)  # CRLF after each chunk's data
            chunks.append(chunk)
            total += size
        body = b"".join(chunks)
    else:
        try:
            body = await asyncio.wait_for(reader.read(_MAX_RESPONSE_BODY_BYTES), timeout)
        except (asyncio.TimeoutError, ConnectionError):
            body = b""

    return {"status": status_code, "headers": headers, "body": body}


async def _open_connection(host: str, port: int, use_tls: bool, timeout: float) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ssl_context = None
    if use_tls:
        ssl_context = ssl.create_default_context()
        # Same "a real pentest target commonly has a self-signed/expired cert" posture as every
        # other HTTP client in this project (native.py's http_request, toolkit_repeater's
        # httpx.AsyncClient(verify=False)) -- verifying here would just fail real, in-scope targets.
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    return await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ssl_context, server_hostname=host if use_tls else None),
        timeout,
    )


async def run_last_byte_race(
    *, session_id: str | None, method: str, url: str, headers_text: str, body: str, request_count: int,
) -> dict:
    """Opens `request_count` raw connections to the same host, sends every byte of each identical
    request except the very last one, waits for every connection to have flushed that prefix, then
    releases the last byte on all of them via one asyncio.gather() call -- the actual
    synchronization step. Falls back to holding back the header block's own final byte when the
    request has no body (a GET with no body still has a final "\r\n" the server waits for before it
    starts processing). Every attempt is recorded as its own traffic entry regardless of whether it
    completed cleanly (a connection error is recorded as its own kind of result, not silently
    dropped, so a race's outcome is never missing entries)."""
    invalid = validate_request_count(request_count)
    if invalid:
        return invalid

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return {"status": "error", "error": f"unsupported scheme {parts.scheme!r} -- only http/https"}
    use_tls = parts.scheme == "https"
    host = parts.hostname or ""
    port = parts.port or (443 if use_tls else 80)
    path_and_query = parts.path or "/"
    if parts.query:
        path_and_query += f"?{parts.query}"

    headers = toolkit_store.parse_header_lines(headers_text)
    body_bytes = body.encode("utf-8") if body else b""
    full_request, request_headers = _build_raw_request(method, parts.netloc, path_and_query, headers, body_bytes)
    if len(full_request) < 2:
        return {"status": "error", "error": "request is too short to split for last-byte synchronization"}
    prefix, last_byte = full_request[:-1], full_request[-1:]

    connect_timeout = _connect_timeout_seconds()
    response_timeout = _response_timeout_seconds()
    run_id = uuid.uuid4().hex[:12]

    async def _connect_and_prime() -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | Exception:
        try:
            reader, writer = await _open_connection(host, port, use_tls, connect_timeout)
            writer.write(prefix)
            await writer.drain()
            return reader, writer
        except Exception as exc:  # noqa: BLE001 -- any connect/TLS/write failure is a real per-attempt result, not a crash
            return exc

    primed = await asyncio.gather(*(_connect_and_prime() for _ in range(request_count)))

    async def _release(index: int, connection) -> dict:
        started_at = time.monotonic()
        if isinstance(connection, Exception):
            return {"index": index, "status": "error", "error": str(connection)}
        reader, writer = connection
        try:
            writer.write(last_byte)
            await writer.drain()
            response = await _read_raw_response(reader, response_timeout)
        except Exception as exc:  # noqa: BLE001 -- a per-connection send/read failure, not a whole-run failure
            return {"index": index, "status": "error", "error": str(exc)}
        finally:
            writer.close()
        duration_ms = round((time.monotonic() - started_at) * 1000)
        response_content_type = response["headers"].get("Content-Type") or response["headers"].get("content-type") or ""
        response_body, response_encoding = toolkit_store.encode_body(response_content_type, response["body"])
        entry = toolkit_store.build_traffic_entry(
            session_id=session_id, method=method, url=url,
            request_headers=request_headers, request_body=body,
            request_content_length=len(body_bytes),
            response_status=response["status"], response_headers=response["headers"],
            response_body=response_body, response_body_encoding=response_encoding,
            response_content_length=len(response["body"]),
            source="racer", duration_ms=duration_ms,
        )
        toolkit_store.append_traffic_entry(entry)
        return {"index": index, "status": "ok", "response_status": response["status"], "entry_id": entry["id"], "duration_ms": duration_ms}

    # asyncio.gather here is the synchronization primitive itself -- every _release coroutine reaches
    # its own `writer.write(last_byte)` line at essentially the same moment because none of them did
    # any awaiting between being scheduled and that line (the connect/prime work already happened,
    # above, before this gather even starts).
    results = await asyncio.gather(*(_release(i, conn) for i, conn in enumerate(primed)))

    ok_results = [r for r in results if r["status"] == "ok"]
    status_counts: dict[str, int] = {}
    for r in ok_results:
        key = str(r["response_status"])
        status_counts[key] = status_counts.get(key, 0) + 1

    logger.debug(
        "toolkit_racer: session=%s run=%s strategy=last_byte requests=%d ok=%d status_counts=%s",
        session_id, run_id, request_count, len(ok_results), status_counts,
    )
    return {
        "status": "ok", "run_id": run_id, "strategy": "last_byte", "requests": request_count,
        "ok": len(ok_results), "errors": request_count - len(ok_results),
        "response_status_counts": status_counts, "results": results,
    }


async def run_sequential_race(
    *, session_id: str | None, method: str, url: str, headers_text: str, body: str, request_count: int,
) -> dict:
    """The same request template sent `request_count` times, one after another, no timing
    synchronization at all -- a deliberately naive baseline to run alongside run_last_byte_race, so
    an operator/model can see whether a race window is real (last_byte wins it, sequential doesn't)
    or the target was never actually vulnerable to begin with (neither wins it)."""
    invalid = validate_request_count(request_count)
    if invalid:
        return invalid

    headers = toolkit_store.parse_header_lines(headers_text)
    run_id = uuid.uuid4().hex[:12]
    results = []
    for index in range(request_count):
        outcome = await send_raw_request(session_id=session_id, method=method, url=url, headers=headers, body=body, source="racer")
        if outcome["status"] == "ok":
            results.append({"index": index, "status": "ok", "response_status": outcome["entry"]["response_status"], "entry_id": outcome["entry"]["id"]})
        else:
            results.append({"index": index, "status": "error", "error": outcome["error"]})

    ok_results = [r for r in results if r["status"] == "ok"]
    status_counts: dict[str, int] = {}
    for r in ok_results:
        key = str(r["response_status"])
        status_counts[key] = status_counts.get(key, 0) + 1

    logger.debug(
        "toolkit_racer: session=%s run=%s strategy=sequential requests=%d ok=%d status_counts=%s",
        session_id, run_id, request_count, len(ok_results), status_counts,
    )
    return {
        "status": "ok", "run_id": run_id, "strategy": "sequential", "requests": request_count,
        "ok": len(ok_results), "errors": request_count - len(ok_results),
        "response_status_counts": status_counts, "results": results,
    }


async def run_race(
    *, session_id: str | None, method: str, url: str, headers_text: str, body: str,
    request_count: int = _DEFAULT_REQUEST_COUNT, strategy: Strategy = "last_byte",
) -> dict:
    """Single entry point dispatching to either strategy -- the agent-facing tool wrapper
    (agent/tools/toolkit_agent_tools.py) and the manual UI route both call this, never the two
    strategy functions directly, so the strategy choice always goes through the same validation."""
    if strategy == "sequential":
        return await run_sequential_race(session_id=session_id, method=method, url=url, headers_text=headers_text, body=body, request_count=request_count)
    return await run_last_byte_race(session_id=session_id, method=method, url=url, headers_text=headers_text, body=body, request_count=request_count)
