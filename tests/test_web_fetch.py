"""web_fetch: cve_lookup's own reference_urls field has always pointed at a real advisory/write-up
page, but nothing could actually open one before this tool -- Analyze/Exploit were stuck guessing
exploitability/technique from the bare CVE ID/title alone. Deliberately separate from http_request
(which targets the live scan target itself, not general research reading).
"""
import httpx

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import native
from agent.tools.native import _WEB_FETCH_MAX_TEXT_CHARS
from agent.tools.registry import get_tools_by_category

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def test_web_fetch_is_registered_for_scan_and_exploit_phases():
    scan_tools = {spec.name: spec for spec in get_tools_by_category("scan")}
    exploit_tools = {spec.name: spec for spec in get_tools_by_category("exploit")}
    assert "web_fetch" in scan_tools
    assert "web_fetch" in exploit_tools
    assert scan_tools["web_fetch"].requires_allowed_target is False


def test_extracts_title_and_readable_text_stripped_of_script_and_style(monkeypatch):
    page = """
    <html><head><title>CVE-2024-1234 Advisory</title>
    <style>body { color: red; }</style></head>
    <body>
    <script>var secret = "should not appear";</script>
    <p>Authentication is required before the affected endpoint can be reached.</p>
    </body></html>
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=page)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.web_fetch({"target": "https://example.com/advisory"})

    assert result["status"] == "ok"
    assert result["title"] == "CVE-2024-1234 Advisory"
    assert "Authentication is required" in result["text"]
    assert "should not appear" in page  # sanity: the script text really was in the source
    assert "should not appear" not in result["text"]
    assert "color: red" not in result["text"]
    assert result["truncated"] is False


def test_unescapes_html_entities_in_extracted_text(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<p>Bypass &amp; escalate privileges</p>")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.web_fetch({"target": "https://example.com/writeup"})

    assert "Bypass & escalate privileges" in result["text"]


def test_rejects_a_non_http_scheme_without_making_any_request(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should never be called for a rejected scheme")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.web_fetch({"target": "ftp://example.com/file.txt"})

    assert result["status"] == "error"
    assert "scheme" in result["error"].lower()


def test_truncates_an_oversized_page_instead_of_returning_it_fully(monkeypatch):
    huge_page = "<p>" + ("word " * (_WEB_FETCH_MAX_TEXT_CHARS // 5 + 1000)) + "</p>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=huge_page)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.web_fetch({"target": "https://example.com/long-writeup"})

    assert result["status"] == "ok"
    assert result["truncated"] is True
    assert len(result["text"]) == _WEB_FETCH_MAX_TEXT_CHARS


def test_a_network_error_is_reported_not_swallowed(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.web_fetch({"target": "https://example.com/advisory"})

    assert result["status"] == "error"
