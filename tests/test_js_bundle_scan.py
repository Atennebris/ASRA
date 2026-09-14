"""js_bundle_scan: view_source only ever links to a script_src URL, never reads it -- modern SPA
bundles hide real API routes, and occasionally live secrets, inside JS no HTML page ever shows as
text. Real gap this closes: no existing tool fetched JS file content at all before this.
"""
import httpx

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import native
from agent.tools.registry import get_tools_by_category

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def test_js_bundle_scan_is_registered_as_a_passive_scan_tool():
    scan_tools = {spec.name: spec for spec in get_tools_by_category("scan")}
    assert "js_bundle_scan" in scan_tools
    assert scan_tools["js_bundle_scan"].requires_allowed_target is False


def test_extracts_an_api_shaped_endpoint_literal_from_the_bundle(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".map"):
            return httpx.Response(404)
        return httpx.Response(200, text='fetch("/api/v2/users/profile").then(x=>x.json())')

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.js_bundle_scan({"target": "https://example.com/static/app.js"})

    assert result["status"] == "ok"
    assert "/api/v2/users/profile" in result["endpoint_like_strings"]
    assert result["sourcemap_exposed"] is False


def test_flags_a_matched_secret_pattern_by_name_only_never_the_raw_text(monkeypatch):
    fake_key = "AKIAABCDEFGHIJKLMNOP"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".map"):
            return httpx.Response(404)
        return httpx.Response(200, text=f'const cfg = {{key: "{fake_key}"}};')

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.js_bundle_scan({"target": "https://example.com/static/app.js"})

    assert result["secret_patterns_matched"] == ["aws_access_key_id"]
    # The actual guarantee this tool exists to make: the raw secret text never appears anywhere
    # in the result dict, only the pattern's name.
    import json
    assert fake_key not in json.dumps(result)


def test_reports_an_exposed_sourcemap(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".map"):
            return httpx.Response(200, text='{"version":3,"sources":["app.ts"]}')
        return httpx.Response(200, text="console.log('hi')")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.js_bundle_scan({"target": "https://example.com/static/app.js"})

    assert result["sourcemap_exposed"] is True
    assert result["sourcemap_secret_patterns_matched"] == []


def test_scans_an_exposed_sourcemaps_own_content_for_secrets(monkeypatch):
    """The bundle itself (minified) is usually clean; a real secret is far more likely to survive
    in the sourcemap's own reconstructed original source -- exactly the gap this closes."""
    fake_key = "AKIAABCDEFGHIJKLMNOP"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".map"):
            return httpx.Response(200, text=f'{{"sourcesContent":["const key = \\"{fake_key}\\";"]}}')
        return httpx.Response(200, text="console.log('hi')")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.js_bundle_scan({"target": "https://example.com/static/app.js"})

    assert result["sourcemap_exposed"] is True
    assert result["sourcemap_secret_patterns_matched"] == ["aws_access_key_id"]
    assert result["secret_patterns_matched"] == []  # the minified bundle itself has no match
    import json
    assert fake_key not in json.dumps(result)


def test_new_secret_pattern_formats_are_flagged_by_name_only(monkeypatch):
    fake_secrets = {
        "slack_token": "xoxb-1234567890-abcdefghijk",
        "github_token": "ghp_" + "a" * 36,
        "private_key_block": "-----BEGIN RSA PRIVATE KEY-----",
    }
    for pattern_name, fake_secret in fake_secrets.items():
        def handler(request: httpx.Request, _secret: str = fake_secret) -> httpx.Response:
            if request.url.path.endswith(".map"):
                return httpx.Response(404)
            return httpx.Response(200, text=f"const cfg = {{key: '{_secret}'}};")

        monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
        result = native.js_bundle_scan({"target": "https://example.com/static/app.js"})

        assert result["secret_patterns_matched"] == [pattern_name]
        import json
        assert fake_secret not in json.dumps(result)


def test_truncates_an_oversized_bundle_instead_of_reading_it_fully(monkeypatch):
    huge_body = ("x" * 100).encode() * 30_000  # 3,000,000 bytes > _JS_MAX_BYTES (2,000,000)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith(".map"):
            return httpx.Response(404)
        return httpx.Response(200, content=huge_body)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.js_bundle_scan({"target": "https://example.com/static/app.js"})

    assert result["status"] == "ok"
    assert result["truncated"] is True


def test_a_network_error_is_reported_not_swallowed(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.js_bundle_scan({"target": "https://example.com/static/app.js"})

    assert result["status"] == "error"
