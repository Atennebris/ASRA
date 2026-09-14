"""http_request's browser-fingerprint fallback (curl_cffi/curl-impersonate) -- a last resort tried
only once httpx's own local self-heal retry (tests/test_http_request_retry.py) is fully exhausted
and the failure is specifically httpx.RemoteProtocolError ("Server disconnected without sending a
response"). Real incident this fixes: a WAF-fronted target (Telenor's api-app.telenor.se, while the
model was correctly chasing a real Spring Boot Actuator hypothesis) rejected every one of 7
httpx-based attempts this way -- a deterministic rejection of httpx's own TLS/HTTP2 fingerprint, not
rate-limiting (the ddos-guard case _get_with_transient_retry already self-heals from), so no amount
of retrying with the same fingerprint could ever have worked.
"""
import httpx
from curl_cffi import requests as curl_requests

from agent.tools import native
from agent.tools.native import http_request


class _RemoteProtocolErrorClient:
    """Always fails exactly like httpx does against a WAF that fingerprints and drops the
    connection -- every local self-heal attempt inside _get_with_transient_retry hits this too."""

    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def get(self, url):
        raise httpx.RemoteProtocolError("Server disconnected without sending a response.")


def test_falls_back_to_browser_fingerprint_after_remote_protocol_error(monkeypatch):
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(httpx, "Client", _RemoteProtocolErrorClient)
    captured = {}

    class _FakeResponse:
        status_code = 200
        headers = {}
        text = "actuator output"
        history = []

    def fake_curl_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return _FakeResponse()

    monkeypatch.setattr(native.curl_requests, "get", fake_curl_get)

    result = http_request({"target": "https://api-app.telenor.se/actuator/health"})

    assert result["status"] == "ok"
    assert result["status_code"] == 200
    assert result["client_fingerprint_bypass_used"] is True
    assert captured["url"] == "https://api-app.telenor.se/actuator/health"
    assert captured["kwargs"]["impersonate"] == native._IMPERSONATE_BROWSER


def test_reports_a_clear_error_when_the_fallback_is_also_blocked(monkeypatch):
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(httpx, "Client", _RemoteProtocolErrorClient)

    def fake_curl_get(url, **kwargs):
        raise curl_requests.exceptions.ConnectionError("still blocked")

    monkeypatch.setattr(native.curl_requests, "get", fake_curl_get)

    result = http_request({"target": "https://api-app.telenor.se/actuator/health"})

    assert result["status"] == "error"
    assert "browser TLS/HTTP2 fingerprint" in result["error"]
    assert "client_fingerprint_bypass_used" not in result


def test_never_invokes_the_fallback_for_an_ordinary_timeout(monkeypatch):
    """A plain timeout/unreachable host is a different problem (see _HardDeadlineExceeded's own
    docstring) that a different TLS fingerprint can't fix -- the fallback must stay scoped to
    RemoteProtocolError specifically, never fire generically for any failure."""
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)

    class _TimeoutClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def get(self, url):
            raise httpx.ConnectTimeout("timed out")

    monkeypatch.setattr(httpx, "Client", _TimeoutClient)
    calls = {"count": 0}

    def fake_curl_get(url, **kwargs):
        calls["count"] += 1
        raise AssertionError("must not be called for a plain timeout")

    monkeypatch.setattr(native.curl_requests, "get", fake_curl_get)

    result = http_request({"target": "https://example.test/"})

    assert result["status"] == "error"
    assert calls["count"] == 0
