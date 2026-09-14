"""tcp_port_check's own local self-heal retry on a transient DNS resolver hiccup -- mirrors
http_request's own retry (tests/test_http_request_retry.py) for the identical failure mode. Real
incident this fixes: a real session saw the same hostname flip-flop between resolving fine and
"[Errno -5] No address associated with hostname" several times against the actual scan target, but
tcp_port_check had zero local retry at all (a bare socket.connect_ex() with a single except) unlike
http_request, so every occurrence escalated straight to the costly LLM-driven 1-Step Retry.
"""
import socket

from agent.tools import native
from agent.tools.native import tcp_port_check


class _FakeSocket:
    def __init__(self, on_connect):
        self._on_connect = on_connect

    def settimeout(self, timeout):
        pass

    def connect_ex(self, addr):
        return self._on_connect()

    def close(self):
        pass


def test_tcp_port_check_recovers_from_a_transient_dns_failure(monkeypatch):
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)
    calls = {"count": 0}

    def on_connect():
        calls["count"] += 1
        if calls["count"] == 1:
            raise socket.gaierror(-5, "No address associated with hostname")
        return 0

    monkeypatch.setattr(native.socket, "socket", lambda *a, **k: _FakeSocket(on_connect))

    result = tcp_port_check({"target": "example.test", "port": 443})

    assert result == {"status": "ok", "port": 443, "open": True}
    assert calls["count"] == 2


def test_tcp_port_check_still_reports_error_once_retries_are_exhausted(monkeypatch):
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_ATTEMPTS", 2)
    calls = {"count": 0}

    def on_connect():
        calls["count"] += 1
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(native.socket, "socket", lambda *a, **k: _FakeSocket(on_connect))

    result = tcp_port_check({"target": "does-not-exist.test", "port": 443})

    assert result["status"] == "error"
    assert calls["count"] == 3  # 1 initial attempt + 2 retries, matches the patched attempt count


def test_tcp_port_check_succeeds_first_try_without_any_retry(monkeypatch):
    calls = {"count": 0}

    def on_connect():
        calls["count"] += 1
        return 1  # closed port -- a real, non-error outcome

    monkeypatch.setattr(native.socket, "socket", lambda *a, **k: _FakeSocket(on_connect))

    result = tcp_port_check({"target": "example.test", "port": 443})

    assert result == {"status": "ok", "port": 443, "open": False}
    assert calls["count"] == 1
