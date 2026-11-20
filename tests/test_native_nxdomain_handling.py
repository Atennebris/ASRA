"""The shared NXDOMAIN-is-a-clean-negative-result treatment (_nxdomain_result, native.py), rolled
out beyond its original two call sites (http_request/web_fetch). Real, confirmed gaps this closes:
js_bundle_scan burned 34.6s + 4241 tokens on a doomed 1-Step Retry against a nonexistent bundle
host, and security_headers_audit had the identical gap -- neither could ever make a nonexistent
hostname resolve by "correcting" an argument, so escalating to status="error" (the 1-Step Retry's
own trigger) only ever wasted a full LLM round-trip. Modeled on test_http_request_retry.py's own
NXDOMAIN test: a real chained socket.gaierror (via `raise httpx.ConnectError(inner) from inner`),
the same shape real httpx/httpcore actually produce.
"""
import socket

import httpx

from agent.tools.native import js_bundle_scan, security_headers_audit

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _raise_chained_nxdomain(request: httpx.Request) -> httpx.Response:
    try:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    except socket.gaierror as inner:
        raise httpx.ConnectError(inner) from inner


def test_js_bundle_scan_treats_a_genuine_nxdomain_as_a_clean_negative_result_not_an_error(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_raise_chained_nxdomain))

    result = js_bundle_scan({"target": "https://this-host-does-not-exist.example.test/bundle.js"})

    assert result["status"] == "ok"
    assert result["resolved"] is False


def test_security_headers_audit_treats_a_genuine_nxdomain_as_a_clean_negative_result_not_an_error(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_raise_chained_nxdomain))

    result = security_headers_audit({"target": "https://this-host-does-not-exist.example.test/"})

    assert result["status"] == "ok"
    assert result["resolved"] is False


def test_js_bundle_scan_still_reports_a_real_error_for_a_non_dns_failure(monkeypatch):
    """A genuinely different failure (no gaierror anywhere in the chain) must still fall through to
    the generic, retryable status="error" branch -- the NXDOMAIN carve-out must never swallow a
    real, potentially-fixable error."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = js_bundle_scan({"target": "https://example.test/bundle.js"})

    assert result["status"] == "error"
