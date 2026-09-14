"""Decoder: encode/decode a string through common webapp encoding schemes -- base64, URL,
HTML entities, hex, gzip -- pure stdlib, no external dependency, no target/network involved. Used
by both the manual UI (main.py's decoder routes) and the agent-facing `decode_value` native tool,
so the two can never drift apart on how a given scheme actually behaves.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import html
import urllib.parse
import zlib

from agent.utils.logger import get_logger

logger = get_logger("TOOLKIT")

SCHEMES = ("base64", "url", "html", "hex", "gzip")


def _encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def _decode_base64(text: str) -> str:
    # Pad/whitespace-forgiving (validate=False + manual re-padding) rather than a strict decode --
    # matches what a human pasting a captured token usually has (trailing newline, missing "="
    # padding), same tolerant posture a commercial decoder tab typically takes.
    stripped = text.strip()
    padded = stripped + "=" * (-len(stripped) % 4)
    return base64.b64decode(padded, validate=False).decode("utf-8", errors="replace")


def _encode_url(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def _decode_url(text: str) -> str:
    return urllib.parse.unquote(text)


def _encode_html(text: str) -> str:
    return html.escape(text, quote=True)


def _decode_html(text: str) -> str:
    return html.unescape(text)


def _encode_hex(text: str) -> str:
    return text.encode("utf-8").hex()


def _decode_hex(text: str) -> str:
    cleaned = "".join(text.split())
    return bytes.fromhex(cleaned).decode("utf-8", errors="replace")


def _encode_gzip(text: str) -> str:
    # gzip output is raw bytes, not printable text on its own -- base64 wraps it so the result
    # still fits the same single-line textarea every other scheme produces.
    return base64.b64encode(gzip.compress(text.encode("utf-8"))).decode("ascii")


def _decode_gzip(text: str) -> str:
    stripped = text.strip()
    padded = stripped + "=" * (-len(stripped) % 4)
    compressed = base64.b64decode(padded, validate=False)
    return gzip.decompress(compressed).decode("utf-8", errors="replace")


_ENCODERS = {
    "base64": _encode_base64,
    "url": _encode_url,
    "html": _encode_html,
    "hex": _encode_hex,
    "gzip": _encode_gzip,
}
_DECODERS = {
    "base64": _decode_base64,
    "url": _decode_url,
    "html": _decode_html,
    "hex": _decode_hex,
    "gzip": _decode_gzip,
}


def run_codec(*, scheme: str, mode: str, text: str) -> dict:
    """Returns {"status": "ok", "result": str} or {"status": "error", "error": str} -- never
    raises, so callers (main.py's route, later the agent tool) don't each need their own
    try/except around what's fundamentally arbitrary, possibly-malformed pasted input (invalid
    base64 padding, odd-length hex, non-gzip bytes)."""
    if scheme not in SCHEMES:
        return {"status": "error", "error": f"Unknown scheme: {scheme}"}
    if mode not in ("encode", "decode"):
        return {"status": "error", "error": f"Unknown mode: {mode}"}
    func = (_ENCODERS if mode == "encode" else _DECODERS)[scheme]
    try:
        result = func(text)
    except (binascii.Error, ValueError, UnicodeDecodeError, zlib.error, EOFError, OSError) as exc:
        logger.debug("toolkit_decoder: %s/%s failed (%s)", scheme, mode, exc)
        return {"status": "error", "error": str(exc)}
    logger.debug("toolkit_decoder: %s/%s ok (%d chars in)", scheme, mode, len(text))
    return {"status": "ok", "result": result}
