"""agent/tools/dork_engine.py -- the dork catalog + build_dork_result/dork_search_native, and its
registration as the "dork_search" tool (agent/tools/__init__.py). Real HTTP calls are mocked at the
httpx transport boundary (same convention as tests/test_otx_urlscan.py), never the catalog's own
dispatch logic -- this file's job is proving build_dork_result routes to the right place with the
right params, not re-testing crt_sh_lookup/otx_passive_dns's own already-tested internals.
"""
import httpx

from agent.tools import dork_engine, native
from agent.tools.dork_engine import (
    DEFAULT_ENGINE,
    SEARCH_ENGINES,
    build_dork_result,
    get_dork_category,
    list_dork_categories,
    normalize_dork_target,
)

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _isolate_cache(monkeypatch):
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)


# --- catalog integrity -----------------------------------------------------------------------


def test_catalog_ids_are_unique():
    ids = [c.id for c in list_dork_categories()]
    assert len(ids) == len(set(ids))


def test_every_search_lead_category_has_a_query_template():
    for c in list_dork_categories():
        if c.kind == "search_lead":
            assert c.query_template and "{target}" in c.query_template, c.id


def test_every_external_link_and_direct_url_category_has_a_url_template():
    for c in list_dork_categories():
        if c.kind in ("external_link", "direct_url"):
            assert c.url_template, c.id


def test_every_native_tool_category_has_a_callable_and_param_key():
    for c in list_dork_categories():
        if c.kind == "native_tool":
            assert callable(c.native_fn), c.id
            assert c.native_param_key in ("domain", "target"), c.id
            assert c.native_tool_spec_name, c.id


def test_get_dork_category_unknown_id_returns_none():
    assert get_dork_category("does-not-exist") is None


# --- normalize_dork_target ---------------------------------------------------------------------


def test_normalize_target_bare_domain():
    assert normalize_dork_target("example.com") == ("example.com", "https://example.com")


def test_normalize_target_full_url_preserves_scheme_and_drops_path():
    assert normalize_dork_target("http://example.com/foo?x=1") == ("example.com", "http://example.com")


def test_normalize_target_strips_wildcard_prefix():
    assert normalize_dork_target("*.example.com") == ("example.com", "https://example.com")


def test_normalize_target_bare_ip():
    assert normalize_dork_target("10.0.0.5") == ("10.0.0.5", "https://10.0.0.5")


def test_normalize_target_unparseable_returns_none_pair():
    assert normalize_dork_target("") == (None, None)


# --- build_dork_result: errors -----------------------------------------------------------------


def test_build_dork_result_unknown_engine():
    result = build_dork_result(target="example.com", category_id="dir_listing", custom_dork=None, engine="altavista")
    assert result["status"] == "error"
    assert "altavista" in result["error"]


def test_build_dork_result_unknown_category():
    result = build_dork_result(target="example.com", category_id="not-a-real-category", custom_dork=None, engine=DEFAULT_ENGINE)
    assert result["status"] == "error"


def test_build_dork_result_nothing_given_at_all():
    result = build_dork_result(target=None, category_id=None, custom_dork=None, engine=DEFAULT_ENGINE)
    assert result["status"] == "error"


def test_build_dork_result_native_tool_category_requires_a_target():
    result = build_dork_result(target=None, category_id="crt_transparency", custom_dork=None, engine=DEFAULT_ENGINE)
    assert result["status"] == "error"


# --- build_dork_result: search_lead --------------------------------------------------------------


def test_build_dork_result_search_lead_from_category():
    result = build_dork_result(target="example.com", category_id="dir_listing", custom_dork=None, engine="google")
    assert result["status"] == "lead"
    assert result["kind"] == "search_lead"
    assert result["query"] == "site:example.com intitle:index.of"
    assert result["url"].startswith(SEARCH_ENGINES["google"].split("{query}")[0])
    assert "intitle%3Aindex.of" in result["url"]


def test_build_dork_result_custom_dork_only_no_target():
    result = build_dork_result(target=None, category_id=None, custom_dork='intext:"leaked"', engine="bing")
    assert result["status"] == "lead"
    assert result["query"] == 'intext:"leaked"'
    assert result["engine"] == "bing"


def test_build_dork_result_custom_dork_combined_with_target():
    result = build_dork_result(target="example.com", category_id=None, custom_dork="ext:sql", engine="duckduckgo")
    assert result["query"] == "site:example.com ext:sql"


# --- build_dork_result: direct_url / external_link ------------------------------------------------


def test_build_dork_result_direct_url_uses_origin_and_drops_path():
    result = build_dork_result(target="https://example.com/some/path", category_id="robots_txt", custom_dork=None, engine=DEFAULT_ENGINE)
    assert result["status"] == "lead"
    assert result["kind"] == "direct_url"
    assert result["url"] == "https://example.com/robots.txt"


def test_build_dork_result_direct_url_defaults_to_https_with_no_scheme_given():
    result = build_dork_result(target="example.com", category_id="crossdomain_xml", custom_dork=None, engine=DEFAULT_ENGINE)
    assert result["url"] == "https://example.com/crossdomain.xml"


def test_build_dork_result_external_link_quotes_the_host():
    result = build_dork_result(target="example.com", category_id="reverse_ip", custom_dork=None, engine=DEFAULT_ENGINE)
    assert result["status"] == "lead"
    assert result["kind"] == "external_link"
    assert result["url"] == "https://viewdns.info/reverseip/?host=example.com&t=1"


# --- build_dork_result: native_tool dispatch -----------------------------------------------------


def test_build_dork_result_native_tool_dispatches_and_tags_dork_category(monkeypatch):
    _isolate_cache(monkeypatch)
    monkeypatch.setattr(dork_engine, "get_tool_api_key", lambda name: None)

    def handler(request: httpx.Request) -> httpx.Response:
        assert "crt.sh" in str(request.url)
        return httpx.Response(200, json=[{"name_value": "sub.example.com"}])

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = build_dork_result(target="example.com", category_id="crt_transparency", custom_dork=None, engine=DEFAULT_ENGINE)

    assert result["status"] == "ok"
    assert result["dork_category"] == "crt_transparency"
    assert "sub.example.com" in result["subdomains"]


def test_build_dork_result_native_tool_uses_origin_for_security_headers(monkeypatch):
    """security_headers is the one native_tool category whose underlying tool wants a full URL
    under "target" (security_headers_audit does client.get(params["target"])), not a bare host
    under "domain" like every other native_tool category here -- confirms the full https:// origin
    (not the bare host) is what actually reaches it. DorkCategory is frozen and native_fn is a
    direct function-object reference captured at catalog-construction time, so the underlying HTTP
    call is mocked (same transport-level approach as the crt_transparency test above) rather than
    swapping out native_fn, which a frozen dataclass doesn't allow anyway."""
    monkeypatch.setattr(dork_engine, "get_tool_api_key", lambda name: None)
    seen_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, headers={})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = build_dork_result(target="example.com", category_id="security_headers", custom_dork=None, engine=DEFAULT_ENGINE)

    assert result["status"] == "ok"
    assert seen_urls == ["https://example.com"]


def test_build_dork_result_native_tool_injects_saved_api_key(monkeypatch):
    monkeypatch.setattr(dork_engine, "get_tool_api_key", lambda name: "fake-otx-key" if name == "otx_passive_dns" else None)
    seen_headers = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_headers.update(request.headers)
        return httpx.Response(200, json={"passive_dns": []})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = build_dork_result(target="example.com", category_id="passive_dns", custom_dork=None, engine=DEFAULT_ENGINE)

    assert result["status"] == "ok"
    assert seen_headers.get("x-otx-api-key") == "fake-otx-key"


def test_build_dork_result_native_tool_without_saved_api_key_reports_the_real_tools_own_error(monkeypatch):
    monkeypatch.setattr(dork_engine, "get_tool_api_key", lambda name: None)

    result = build_dork_result(target="example.com", category_id="passive_dns", custom_dork=None, engine=DEFAULT_ENGINE)

    assert result["status"] == "error"
    assert "OTX_API_KEY" in result["error"]
    assert result["dork_category"] == "passive_dns"


# --- registration: dork_search in TOOL_REGISTRY --------------------------------------------------


def test_dork_search_is_registered_as_recon_category():
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("dork_search")
    assert spec is not None
    assert spec.category == "recon"
    assert spec.tool_tier == 1
    assert spec.installed_by_default is True
    assert spec.requires_allowed_target is False


def test_dork_search_schema_category_enum_matches_the_catalog():
    import agent.tools  # noqa: F401
    from agent.tools.registry import get_tool

    spec = get_tool("dork_search")
    schema_ids = set(spec.parameters_schema["properties"]["category"]["enum"])
    catalog_ids = {c.id for c in list_dork_categories()}
    assert schema_ids == catalog_ids
