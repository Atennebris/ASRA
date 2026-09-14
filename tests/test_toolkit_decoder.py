"""Unit tests for agent/tools/toolkit_decoder.py's run_codec -- each scheme's encode/decode
round-trips, and malformed input produces a structured error instead of raising."""
import base64
import gzip

import pytest

from agent.tools.toolkit_decoder import SCHEMES, run_codec


@pytest.mark.parametrize("scheme", SCHEMES)
def test_encode_then_decode_round_trips(scheme):
    original = "hello world? & <tag> 123"
    encoded = run_codec(scheme=scheme, mode="encode", text=original)
    assert encoded["status"] == "ok"
    decoded = run_codec(scheme=scheme, mode="decode", text=encoded["result"])
    assert decoded["status"] == "ok"
    assert decoded["result"] == original


def test_base64_encode_matches_stdlib():
    result = run_codec(scheme="base64", mode="encode", text="hello")
    assert result == {"status": "ok", "result": base64.b64encode(b"hello").decode("ascii")}


def test_base64_decode_tolerates_missing_padding_and_whitespace():
    # "aGVsbG8" (7 chars) is "hello" base64 without its trailing "=" padding.
    result = run_codec(scheme="base64", mode="decode", text=" aGVsbG8 \n")
    assert result == {"status": "ok", "result": "hello"}


def test_base64_decode_invalid_input_returns_error_not_raise():
    result = run_codec(scheme="base64", mode="decode", text="!!!not-base64!!!")
    assert result["status"] == "error"
    assert result["error"]


def test_url_encode_escapes_reserved_characters():
    result = run_codec(scheme="url", mode="encode", text="a b&c=d")
    assert result == {"status": "ok", "result": "a%20b%26c%3Dd"}


def test_html_encode_escapes_tags_and_quotes():
    result = run_codec(scheme="html", mode="encode", text="<b>\"x\"</b>")
    assert result["status"] == "ok"
    assert "<b>" not in result["result"]
    assert "&lt;b&gt;" in result["result"]


def test_hex_decode_ignores_internal_whitespace():
    result = run_codec(scheme="hex", mode="decode", text="68 65 6c\n6c6f")
    assert result == {"status": "ok", "result": "hello"}


def test_hex_decode_odd_length_returns_error_not_raise():
    result = run_codec(scheme="hex", mode="decode", text="abc")
    assert result["status"] == "error"
    assert result["error"]


def test_gzip_decode_produces_the_original_bytes():
    payload = base64.b64encode(gzip.compress(b"payload")).decode("ascii")
    result = run_codec(scheme="gzip", mode="decode", text=payload)
    assert result == {"status": "ok", "result": "payload"}


def test_gzip_decode_non_gzip_bytes_returns_error_not_raise():
    result = run_codec(scheme="gzip", mode="decode", text=base64.b64encode(b"not gzip data").decode("ascii"))
    assert result["status"] == "error"
    assert result["error"]


def test_unknown_scheme_returns_error():
    result = run_codec(scheme="rot13", mode="encode", text="x")
    assert result == {"status": "error", "error": "Unknown scheme: rot13"}


def test_unknown_mode_returns_error():
    result = run_codec(scheme="base64", mode="scramble", text="x")
    assert result == {"status": "error", "error": "Unknown mode: scramble"}
