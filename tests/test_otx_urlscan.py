"""otx_passive_dns / urlscan_search / github_code_search (agent/tools/native.py) -- three
free-tier OSINT sources. OTX and GitHub have no meaningful anonymous access (both disabled with a
clear error, not a raw 403/401, when no key is configured); urlscan's own search API works with no
key too, just on a lower/shared rate limit. All three read their API key from params["_api_key"],
the same generic injection every tool registered in agent/tools/tool_api_keys.py's
TOOL_API_KEY_SPECS gets from agent/core.py's _run_tool_with_retry -- see
tests/test_settings.py-adjacent tool-api-key tests for that injection mechanism itself; this file
only covers these three tools' own logic.
"""
import httpx

from agent.tools import native
from agent.tools.native import github_code_search, otx_passive_dns, urlscan_search
from agent.tools.tool_api_keys import TOOL_API_KEY_SPECS

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _isolate_cache(monkeypatch):
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)


# --- TOOL_API_KEY_SPECS registration -------------------------------------------------------------


def test_otx_urlscan_github_are_registered_tool_api_key_specs():
    assert TOOL_API_KEY_SPECS["otx_passive_dns"].env_var == "OTX_API_KEY"
    assert TOOL_API_KEY_SPECS["urlscan_search"].env_var == "URLSCAN_API_KEY"
    assert TOOL_API_KEY_SPECS["github_code_search"].env_var == "GITHUB_API_KEY"


def test_all_three_tools_are_registered_as_recon_category():
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    for name in ("otx_passive_dns", "urlscan_search", "github_code_search"):
        spec = get_tool(name)
        assert spec is not None, name
        assert spec.category == "recon"
        assert spec.requires_allowed_target is False


# --- otx_passive_dns -------------------------------------------------------------------------


def test_otx_passive_dns_errors_clearly_without_a_key(monkeypatch):
    _isolate_cache(monkeypatch)
    result = otx_passive_dns({"domain": "example.com"})
    assert result["status"] == "error"
    assert "OTX_API_KEY" in result["error"]


def test_otx_passive_dns_parses_real_records(monkeypatch):
    _isolate_cache(monkeypatch)
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"passive_dns": [
            {"hostname": "old.example.com", "address": "203.0.113.5", "record_type": "A", "first": "2020-01-01T00:00:00", "last": "2021-06-01T00:00:00"},
        ], "count": 1})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = otx_passive_dns({"domain": "example.com", "_api_key": "test-otx-key"})

    assert result["status"] == "ok"
    assert result["records"] == [{
        "hostname": "old.example.com", "address": "203.0.113.5", "record_type": "A",
        "first_seen": "2020-01-01T00:00:00", "last_seen": "2021-06-01T00:00:00",
    }]
    assert seen_headers[0]["x-otx-api-key"] == "test-otx-key"


def test_otx_passive_dns_reports_a_rejected_key_clearly(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(403)))

    result = otx_passive_dns({"domain": "example.com", "_api_key": "bad-key"})

    assert result["status"] == "error"
    assert "403" in result["error"]


def test_otx_passive_dns_handles_an_empty_result_set(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(200, json={"passive_dns": [], "count": 0})))

    result = otx_passive_dns({"domain": "example.com", "_api_key": "test-key"})

    assert result == {"status": "ok", "records": []}


# --- urlscan_search --------------------------------------------------------------------------


def test_urlscan_search_works_without_a_key(monkeypatch):
    _isolate_cache(monkeypatch)
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"total": 0, "results": []})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = urlscan_search({"domain": "example.com"})

    assert result["status"] == "ok"
    assert "api-key" not in seen_headers[0]


def test_urlscan_search_sends_the_key_when_configured(monkeypatch):
    _isolate_cache(monkeypatch)
    seen_headers = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"total": 0, "results": []})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    urlscan_search({"domain": "example.com", "_api_key": "test-urlscan-key"})

    assert seen_headers[0]["api-key"] == "test-urlscan-key"


def test_urlscan_search_parses_real_results(monkeypatch):
    _isolate_cache(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "total": 1,
            "results": [{
                "page": {"url": "https://forgotten.example.com/admin", "domain": "forgotten.example.com", "ip": "203.0.113.9", "asn": "AS64500", "server": "nginx"},
                "task": {"time": "2024-03-01T00:00:00.000Z"},
            }],
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = urlscan_search({"domain": "example.com"})

    assert result["status"] == "ok"
    assert result["total_found"] == 1
    assert result["scans"] == [{
        "url": "https://forgotten.example.com/admin", "domain": "forgotten.example.com",
        "ip": "203.0.113.9", "asn": "AS64500", "server": "nginx", "scanned_at": "2024-03-01T00:00:00.000Z",
    }]


def test_urlscan_search_tolerates_missing_page_or_task_fields(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(200, json={"total": 1, "results": [{}]})))

    result = urlscan_search({"domain": "example.com"})

    assert result["status"] == "ok"
    assert result["scans"] == [{"url": None, "domain": None, "ip": None, "asn": None, "server": None, "scanned_at": None}]


def test_urlscan_search_surfaces_a_real_http_error(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(500)))

    result = urlscan_search({"domain": "example.com"})

    assert result["status"] == "error"


# --- github_code_search ------------------------------------------------------------------------


def test_github_code_search_errors_clearly_without_a_key(monkeypatch):
    _isolate_cache(monkeypatch)
    result = github_code_search({"query": "target.com in:file"})
    assert result["status"] == "error"
    assert "GITHUB_API_KEY" in result["error"]


def test_github_code_search_sends_bearer_auth_and_parses_results(monkeypatch):
    _isolate_cache(monkeypatch)
    seen_headers = []
    seen_params = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        seen_params.append(dict(request.url.params))
        return httpx.Response(200, json={
            "total_count": 1,
            "items": [{
                "path": "config/.env",
                "html_url": "https://github.com/someuser/leaky-repo/blob/main/config/.env",
                "repository": {"full_name": "someuser/leaky-repo"},
            }],
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = github_code_search({"query": "target.com in:file", "_api_key": "ghp_test123"})

    assert result["status"] == "ok"
    assert result["total_count"] == 1
    assert result["results"] == [{
        "repository": "someuser/leaky-repo", "path": "config/.env",
        "url": "https://github.com/someuser/leaky-repo/blob/main/config/.env",
    }]
    assert seen_headers[0]["authorization"] == "Bearer ghp_test123"
    assert seen_params[0]["q"] == "target.com in:file"


def test_github_code_search_reports_an_invalid_token_clearly(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(401)))

    result = github_code_search({"query": "target.com", "_api_key": "bad-token"})

    assert result["status"] == "error"
    assert "401" in result["error"]


def test_github_code_search_reports_rate_limiting_clearly(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(403)))

    result = github_code_search({"query": "target.com", "_api_key": "test-token"})

    assert result["status"] == "error"
    assert "rate-limited" in result["error"].lower()


def test_github_code_search_reports_a_malformed_query_clearly(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(422, json={"message": "Validation Failed"})))

    result = github_code_search({"query": "a", "_api_key": "test-token"})

    assert result["status"] == "error"
    assert "Validation Failed" in result["error"]


def test_github_code_search_handles_an_empty_result_set(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda r: httpx.Response(200, json={"total_count": 0, "items": []})))

    result = github_code_search({"query": "target.com in:file", "_api_key": "test-token"})

    assert result == {"status": "ok", "total_count": 0, "results": []}


def test_interpret_github_code_search_permanent_failure_matches_401_and_403(monkeypatch):
    """Real fix this covers: an immediate 1-Step Retry on either an invalid token or a rate-limit
    hit is guaranteed to fail identically (a fresh request seconds later is still the same token,
    still inside the same 10/minute window) -- both must skip the doomed retry entirely."""
    from agent.core import _PERMANENT_ERROR_HINTS
    from agent.tools.native import interpret_github_code_search_permanent_failure

    assert _PERMANENT_ERROR_HINTS["github_code_search"] is interpret_github_code_search_permanent_failure

    unauthorized = {"status": "error", "error": "GitHub rejected the configured token (401) -- check it's still valid in Settings -> Tool API Keys."}
    rate_limited = {"status": "error", "error": "GitHub rate-limited this request (403) -- code search is capped at 10/minute regardless of token; wait and retry."}
    malformed_query = {"status": "error", "error": "GitHub rejected this query (Validation Failed) -- code search needs at least one search term plus a qualifier (e.g. in:file)."}

    assert interpret_github_code_search_permanent_failure(unauthorized) == unauthorized["error"]
    assert interpret_github_code_search_permanent_failure(rate_limited) == rate_limited["error"]
    assert interpret_github_code_search_permanent_failure(malformed_query) is None  # a corrected query CAN fix this
    assert interpret_github_code_search_permanent_failure({"status": "ok"}) is None
