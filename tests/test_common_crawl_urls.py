"""common_crawl_urls (agent/tools/native.py) -- a second, independent historical-URL archive
alongside wayback_urls, fully free with no API key/account at all. Two real quirks this covers:
Common Crawl's own crawl index id changes over time (resolved dynamically from collinfo.json,
never hardcoded) and its CDX response is newline-delimited JSON, not a single JSON array like
Wayback's own CDX API.
"""
import json

import httpx

from agent.tools import native
from agent.tools.native import common_crawl_urls

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


_COLLINFO = [{"id": "CC-MAIN-2026-30", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2026-30-index"}]


def _handler_with_results(request: httpx.Request) -> httpx.Response:
    if "collinfo.json" in str(request.url):
        return httpx.Response(200, json=_COLLINFO)
    body = "\n".join(json.dumps({"url": url}) for url in [
        "https://example.com/old-page", "https://example.com/forgotten-endpoint",
    ])
    return httpx.Response(200, text=body)


def _handler_no_captures(request: httpx.Request) -> httpx.Response:
    if "collinfo.json" in str(request.url):
        return httpx.Response(200, json=_COLLINFO)
    return httpx.Response(404, text="No Captures found for: example.com/*")


def _isolate_cache(monkeypatch):
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)


def test_common_crawl_urls_parses_newline_delimited_json(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_handler_with_results))

    result = common_crawl_urls({"domain": "example.com"})

    assert result["status"] == "ok"
    assert result["urls"] == ["https://example.com/forgotten-endpoint", "https://example.com/old-page"]


def test_common_crawl_urls_resolves_the_cdx_api_from_collinfo_dynamically(monkeypatch):
    """Real motivation this covers: Common Crawl retires its own crawl index id every few weeks --
    a hardcoded id would eventually 404 for every single call. Confirmed here by using an id
    ("CC-MAIN-2026-30") that doesn't exist anywhere in the source code, only in the mocked
    collinfo.json response, and checking the tool actually queried IT, not something hardcoded."""
    _isolate_cache(monkeypatch)
    seen_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return _handler_with_results(request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    common_crawl_urls({"domain": "example.com"})

    assert any("CC-MAIN-2026-30-index" in url for url in seen_urls)


def test_common_crawl_urls_treats_a_404_no_captures_as_a_genuine_empty_result(monkeypatch):
    """Common Crawl's own documented behavior for a domain with zero captures at all -- a plain
    HTTP 404, not a real error condition."""
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_handler_no_captures))

    result = common_crawl_urls({"domain": "example.com"})

    assert result["status"] == "ok"
    assert result["urls"] == []


def test_common_crawl_urls_skips_malformed_lines_without_failing_the_whole_call(monkeypatch):
    _isolate_cache(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        if "collinfo.json" in str(request.url):
            return httpx.Response(200, json=_COLLINFO)
        body = "not json at all\n" + json.dumps({"url": "https://example.com/real-page"}) + "\n" + json.dumps({"no_url_key": True})
        return httpx.Response(200, text=body)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = common_crawl_urls({"domain": "example.com"})

    assert result["status"] == "ok"
    assert result["urls"] == ["https://example.com/real-page"]


def test_common_crawl_urls_uses_the_default_timeout_when_none_given(monkeypatch):
    _isolate_cache(monkeypatch)
    captured = []

    def factory(**kwargs):
        captured.append(kwargs)
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(_handler_with_results), **kwargs)

    monkeypatch.setattr(httpx, "Client", factory)

    common_crawl_urls({"domain": "example.com"})

    assert captured[0]["timeout"] == 45.0


def test_common_crawl_urls_errors_when_collinfo_returns_nothing_usable(monkeypatch):
    _isolate_cache(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = common_crawl_urls({"domain": "example.com"})

    assert result["status"] == "error"


def test_common_crawl_urls_is_registered_with_recon_category():
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("common_crawl_urls")
    assert spec is not None
    assert spec.category == "recon"
    assert spec.requires_allowed_target is False
