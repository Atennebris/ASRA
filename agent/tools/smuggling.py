"""smuggling_probe: HTTP request smuggling / desync detection via the timing technique (PortSwigger's
published safe-for-external-targets method) -- sends a CL.TE and a TE.CL malformed-framing request
and measures whether the response takes materially longer than a clean baseline, or never arrives at
all within the read window.

Deliberately the TIMING variant, not the two-request "differential response" variant: the timing
technique only ever affects the attacker's OWN request (the front-end/back-end disagreement makes
the backend sit waiting for a chunk continuation that never comes, so the response is just slow or
never arrives) -- it never smuggles a payload into a REAL second/victim request the way the
differential technique does. That matches this project's standing rule against traffic shaped like
"generates a large amount of network traffic" or that could disturb other real users on shared
infrastructure (same concern agent/tools/waf_evasion.py's own module docstring documents for its
10-request cap) -- exactly 3 raw requests total here (1 baseline + CL.TE + TE.CL), each its own
fresh, single-use connection.

Raw sockets, not httpx: httpx/httpcore validate and normalize headers before sending (rejecting or
silently fixing a request that declares both Content-Length and Transfer-Encoding with a body that
doesn't match either), which is exactly the malformed shape this technique requires to exist on the
wire byte-for-byte. There is no way to produce it through a conforming HTTP client library.
"""
from __future__ import annotations

import os
import socket
import ssl
import time
from urllib.parse import urlsplit

from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Reuses the same knob http_request's own connect/read budget is keyed off (native.py) for the
# CONNECT phase specifically -- the read-side wait is a separate, larger budget below, since for
# this technique a long read wait on the CL.TE/TE.CL variants IS the signal being measured, not a
# failure to tolerate.
_CONNECT_TIMEOUT_SECONDS = float(os.getenv("HTTP_REQUEST_TIMEOUT_SECONDS", "10"))
_READ_TIMEOUT_SECONDS = float(os.getenv("SMUGGLING_PROBE_READ_TIMEOUT_SECONDS", "10"))
_DELAY_THRESHOLD_SECONDS = float(os.getenv("SMUGGLING_PROBE_DELAY_THRESHOLD_SECONDS", "5"))


def _split_target(target: str) -> tuple[str, int, bool, str]:
    parts = urlsplit(target if "://" in target else f"http://{target}")
    host = parts.hostname
    if not host:
        raise ValueError(f"could not parse a hostname out of target={target!r}")
    use_tls = parts.scheme == "https"
    port = parts.port or (443 if use_tls else 80)
    path = parts.path or "/"
    if parts.query:
        path += f"?{parts.query}"
    return host, port, use_tls, path


def _baseline_request(host: str, path: str) -> bytes:
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()


def _cl_te_request(host: str, path: str) -> bytes:
    # Front-end honors Content-Length (4 bytes: "1\r\nA\r\n") and forwards exactly that much,
    # considering the request complete. Back-end honors Transfer-Encoding: chunked instead, parses
    # "1" as a chunk-size, "A" as that chunk's data, then waits forever for the chunk terminator +
    # next chunk-size line that the truncated body never sends -- real PortSwigger CL.TE example.
    body = "1\r\nA\r\nX"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 4\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def _te_cl_request(host: str, path: str) -> bytes:
    # Mirror image: front-end honors Transfer-Encoding, sees chunk-size "0" as the terminating
    # chunk, and considers the request complete after 5 bytes ("0\r\n\r\n"). Back-end honors
    # Content-Length: 6 instead and waits for one more byte ("X") that the front-end never forwards.
    body = "0\r\n\r\nX"
    return (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: 6\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    ).encode()


def _send_raw(host: str, port: int, use_tls: bool, raw_request: bytes) -> tuple[float, bool]:
    """Opens one fresh TCP connection, sends raw_request verbatim, times how long until the first
    response byte arrives. Hitting the read timeout counts as timed_out=True, not an error -- for
    this technique a response that never arrives within the window IS the positive signal (the
    backend is genuinely stuck waiting on a chunk continuation), not a probe failure.
    """
    start = time.monotonic()
    raw_socket = socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT_SECONDS)
    sock: socket.socket | ssl.SSLSocket = raw_socket
    try:
        if use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_socket, server_hostname=host)
        sock.settimeout(_READ_TIMEOUT_SECONDS)
        sock.sendall(raw_request)
        try:
            sock.recv(1)
            timed_out = False
        except (TimeoutError, socket.timeout):
            timed_out = True
        return time.monotonic() - start, timed_out
    finally:
        sock.close()


def smuggling_probe(params: dict) -> dict:
    # "target" specifically, not "url"/"host" -- same convention every other native tool's params
    # dict follows (agent/tools/runner.py reads this exact key for the guardrail/logging path even
    # when, as here, requires_allowed_target=False).
    target = params["target"]
    try:
        host, port, use_tls, path = _split_target(target)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    logger.debug("smuggling_probe: target=%r host=%s port=%d tls=%s starting (1 baseline + cl_te + te_cl)", target, host, port, use_tls)

    try:
        baseline_elapsed, baseline_timed_out = _send_raw(host, port, use_tls, _baseline_request(host, path))
    except OSError as exc:
        logger.debug("smuggling_probe: target=%r baseline connection failed: %s", target, exc)
        return {"status": "error", "error": f"baseline connection failed: {exc}"}

    variants = []
    for name, build_request in (("cl_te", _cl_te_request), ("te_cl", _te_cl_request)):
        try:
            elapsed, timed_out = _send_raw(host, port, use_tls, build_request(host, path))
        except OSError as exc:
            variants.append({"variant": name, "status": "error", "error": str(exc)})
            continue
        delay_over_baseline = elapsed - baseline_elapsed
        variants.append({
            "variant": name,
            "status": "ok",
            "elapsed_seconds": round(elapsed, 2),
            "timed_out": timed_out,
            "delay_over_baseline_seconds": round(delay_over_baseline, 2),
            "candidate_desync": timed_out or delay_over_baseline >= _DELAY_THRESHOLD_SECONDS,
        })

    candidate_variants = [v["variant"] for v in variants if v.get("candidate_desync")]
    logger.debug("smuggling_probe: target=%r finished baseline_elapsed=%.2f candidate_variants=%s", target, baseline_elapsed, candidate_variants)
    return {
        "status": "ok",
        "baseline_elapsed_seconds": round(baseline_elapsed, 2),
        "baseline_timed_out": baseline_timed_out,
        "variants": variants,
        "candidate_desync_variants": candidate_variants,
    }
