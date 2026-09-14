"""smuggling_probe: HTTP request smuggling/desync detection via the timing technique (see
agent/tools/smuggling.py's own module docstring). Raw sockets, not httpx -- mocked via a
fake socket object (socket.create_connection monkeypatched), not httpx.MockTransport, since the
whole point of this tool is sending byte-for-byte malformed framing no conforming HTTP client
would ever construct.
"""
import socket

import pytest

import agent.tools.smuggling as sp
from agent.tools.smuggling import (
    _baseline_request,
    _cl_te_request,
    _split_target,
    _te_cl_request,
    smuggling_probe,
)


# --- pure helpers -- no sockets needed at all ---------------------------------------------------


def test_split_target_defaults_to_http_port_80_and_root_path():
    host, port, use_tls, path = _split_target("example.com")
    assert (host, port, use_tls, path) == ("example.com", 80, False, "/")


def test_split_target_reads_https_scheme_port_and_path():
    host, port, use_tls, path = _split_target("https://example.com:8443/api/search?q=1")
    assert host == "example.com"
    assert port == 8443
    assert use_tls is True
    assert path == "/api/search?q=1"


def test_split_target_raises_on_unparseable_hostname():
    with pytest.raises(ValueError):
        _split_target("://not-a-host")


def test_cl_te_request_declares_a_shorter_content_length_than_the_te_cl_variant():
    cl_te = _cl_te_request("example.com", "/")
    te_cl = _te_cl_request("example.com", "/")
    assert b"Content-Length: 4" in cl_te
    assert b"Content-Length: 6" in te_cl
    assert b"Transfer-Encoding: chunked" in cl_te
    assert b"Transfer-Encoding: chunked" in te_cl


def test_baseline_request_is_a_plain_well_formed_get():
    baseline = _baseline_request("example.com", "/")
    assert baseline.startswith(b"GET / HTTP/1.1\r\n")
    assert b"Transfer-Encoding" not in baseline
    assert b"Content-Length" not in baseline


# --- smuggling_probe itself, fake socket ---------------------------------------------------------


class _FakeSocket:
    """Stands in for a real TCP/TLS socket -- recv()'s behavior is decided by what sendall() saw,
    so different fake instances (baseline vs cl_te vs te_cl, one fresh instance per _send_raw call)
    can behave differently based on the actual raw bytes each real request would have sent."""

    def __init__(self, on_recv):
        self._on_recv = on_recv
        self.sent: bytes | None = None

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        self.sent = data

    def recv(self, size):
        return self._on_recv(self.sent)

    def close(self):
        pass


def test_probe_flags_the_cl_te_variant_when_it_times_out_but_baseline_and_te_cl_respond(monkeypatch):
    def on_recv(sent: bytes) -> bytes:
        if b"Content-Length: 4" in sent:  # the CL.TE payload specifically
            raise socket.timeout()
        return b"H"

    monkeypatch.setattr(sp.socket, "create_connection", lambda addr, timeout: _FakeSocket(on_recv))

    result = smuggling_probe({"target": "http://example.com/"})

    assert result["status"] == "ok"
    assert result["candidate_desync_variants"] == ["cl_te"]
    cl_te_variant = next(v for v in result["variants"] if v["variant"] == "cl_te")
    assert cl_te_variant["timed_out"] is True
    te_cl_variant = next(v for v in result["variants"] if v["variant"] == "te_cl")
    assert te_cl_variant["timed_out"] is False


def test_probe_flags_a_variant_that_responds_materially_slower_than_baseline_without_timing_out(monkeypatch):
    monkeypatch.setattr(sp, "_DELAY_THRESHOLD_SECONDS", 5.0)
    monkeypatch.setattr(sp.socket, "create_connection", lambda addr, timeout: _FakeSocket(lambda sent: b"H"))

    # baseline: t=0 -> t=0.1 (elapsed 0.1); cl_te: t=0.1 -> t=6.2 (elapsed 6.1, over threshold);
    # te_cl: t=6.2 -> t=6.3 (elapsed 0.1, under threshold).
    ticks = iter([0.0, 0.1, 0.1, 6.2, 6.2, 6.3])
    monkeypatch.setattr(sp.time, "monotonic", lambda: next(ticks))

    result = smuggling_probe({"target": "http://example.com/"})

    assert result["candidate_desync_variants"] == ["cl_te"]


def test_probe_finds_no_candidates_when_every_variant_responds_quickly(monkeypatch):
    monkeypatch.setattr(sp.socket, "create_connection", lambda addr, timeout: _FakeSocket(lambda sent: b"H"))

    result = smuggling_probe({"target": "http://example.com/"})

    assert result["status"] == "ok"
    assert result["candidate_desync_variants"] == []
    assert result["baseline_timed_out"] is False


def test_probe_reports_a_clean_error_when_the_baseline_connection_itself_fails(monkeypatch):
    def _raise(addr, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(sp.socket, "create_connection", _raise)

    result = smuggling_probe({"target": "http://example.com/"})

    assert result["status"] == "error"
    assert "baseline" in result["error"]


def test_probe_returns_a_clean_error_for_an_unparseable_target():
    result = smuggling_probe({"target": "://not-a-host"})

    assert result["status"] == "error"
