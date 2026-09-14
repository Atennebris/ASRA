"""http_request's own fast, local retry on a transient connection/DNS/timeout error -- added after
a real bug-bounty scan's logs showed the exact same hostname flip between resolving fine and
"[Errno -5] No address associated with hostname" 17 times in one session, each occurrence costing a
full LLM round-trip via agent/core.py's "1-Step Retry" (_run_tool_with_retry) for a failure that was
never about the URL or its parameters -- a one-off resolver hiccup self-heals almost immediately.

_HTTP_REQUEST_RETRY_ATTEMPTS/_HTTP_REQUEST_RETRY_DELAY_SECONDS are read from the environment once at
module import time (same style as the rest of native.py's config), so tests patch the module's own
attributes directly rather than the env var, which would have no effect post-import.
"""
import socket

import httpx

from agent.tools import native
from agent.tools.native import http_request

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def test_http_request_recovers_from_a_transient_dns_failure(monkeypatch):
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.ConnectError("[Errno -5] No address associated with hostname", request=request)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/"})

    assert result["status"] == "ok"
    assert calls["count"] == 2


def test_http_request_recovers_from_a_transient_timeout(monkeypatch):
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] == 1:
            raise httpx.ReadTimeout("The read operation timed out", request=request)
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/"})

    assert result["status"] == "ok"
    assert calls["count"] == 2


def test_http_request_still_reports_error_once_retries_are_exhausted(monkeypatch):
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_ATTEMPTS", 2)
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        raise httpx.ConnectError("[Errno -2] Name or service not known", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/"})

    assert result["status"] == "error"
    assert calls["count"] == 3  # 1 initial attempt + 2 retries, matches the patched attempt count


def test_http_request_treats_a_genuine_nxdomain_as_a_clean_negative_result_not_an_error(monkeypatch):
    """Real, confirmed incident this fixes: three real NXDOMAIN failures in one session
    (three different nonexistent subdomains of the same target) each cost a doomed 1-Step Retry
    -- no corrected URL/argument can ever make a nonexistent hostname resolve. Raises a REAL chained
    socket.gaierror (via `raise httpx.ConnectError(inner) from inner`), the same shape real httpx/
    httpcore actually produce (confirmed live against the real library: httpcore.ConnectError's own
    sole args[0] IS the original gaierror object) -- unlike the string-only ConnectError the sibling
    test above constructs, which has no real gaierror in its cause chain at all and so correctly
    still falls through to status="error" (nothing there for _dns_resolution_errno to find)."""
    monkeypatch.setattr(native, "_HTTP_REQUEST_RETRY_DELAY_SECONDS", 0)

    def handler(request: httpx.Request) -> httpx.Response:
        try:
            raise socket.gaierror(-5, "No address associated with hostname")
        except socket.gaierror as inner:
            raise httpx.ConnectError(inner) from inner

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://this-host-does-not-exist.example.test/"})

    assert result["status"] == "ok"
    assert result["resolved"] is False


def test_http_request_succeeds_first_try_without_any_retry(monkeypatch):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/"})

    assert result["status"] == "ok"
    assert calls["count"] == 1


def test_http_request_follows_redirects_by_default(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "https://example.test/":
            return httpx.Response(302, headers={"location": "https://example.test/landed"})
        return httpx.Response(200, text="landed")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/"})

    assert result["status_code"] == 200  # followed all the way to the final response


def test_http_request_defaults_to_the_module_timeout_when_unset(monkeypatch):
    captured = {}

    def factory(**kwargs):
        captured["timeout"] = kwargs.pop("timeout", None)
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)

    http_request({"target": "https://example.test/"})

    assert captured["timeout"] == native._HTTP_TIMEOUT


def test_http_request_honors_a_custom_timeout_override(monkeypatch):
    """Real, confirmed incident this fixes: a subagent's own web.archive.org CDX search queries
    (broad wildcards there routinely take 20-60s) kept hitting this tool's fixed 10s hard deadline,
    burning most of its time budget on doomed 1-Step Retries that just resent the same slow query --
    wayback_urls already had a configurable timeout for this exact reason, http_request didn't."""
    captured = {}

    def factory(**kwargs):
        captured["timeout"] = kwargs.pop("timeout", None)
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, text="ok")), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)

    result = http_request({"target": "https://example.test/", "timeout": 45})

    assert result["status"] == "ok"
    assert captured["timeout"] == 45.0


def test_http_request_honors_follow_redirects_false(monkeypatch):
    """Real, confirmed incident this fixes: a model correctly tried follow_redirects=False to test
    an open-redirect PoC against a deliberately non-resolving redirect target, but the client
    unconditionally hardcoded follow_redirects=True -- the client actually tried to follow there
    and failed DNS before the redirect could even be observed, and the override was silently
    ignored (the key wasn't wired to anything)."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://example.test/", "must never actually follow the redirect"
        return httpx.Response(302, headers={"location": "https://evil.example.invalid/"})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = http_request({"target": "https://example.test/", "follow_redirects": False})

    assert result["status_code"] == 302  # the raw redirect response itself, never followed
