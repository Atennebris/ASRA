"""_update_ip_intel (agent/core.py): automatic, deterministic IP geolocation + role-classification
enrichment -- fires from the same universal per-tool-call dispatch site _track_host_health/
_update_asset_graph already use (agent/core.py's _run_tool_with_retry), so it covers Recon AND
Analyze alike, not just one phase's own local closure. Real motivation this whole feature exists
for: a domain's resolved IP is routinely mistaken for "the target's own server" when it's actually
a CDN/WAF edge or shared/cloud hosting -- session["recon_result"]["ip_intel"] makes that visible
automatically instead of depending on a human's own habit to catch it.
"""
import httpx
import pytest

from agent.core import RunContext, _update_ip_intel
from agent.tools import cache as cache_module
from agent.tools.registry import get_tool
from sessions import store

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _ctx(session):
    return RunContext(llm=object(), session=session, session_id=session["session_id"])


def _cloudflare_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={
        "status": "success", "country": "Australia", "countryCode": "AU",
        "regionName": "Queensland", "city": "South Brisbane", "lat": -27.4, "lon": 153.0,
        "isp": "Cloudflare, Inc", "org": "APNIC and Cloudflare DNS Resolver project",
        "as": "AS13335 Cloudflare, Inc.",
    })


def test_ip_intel_enriches_a_new_ip_revealed_by_dns_lookup(monkeypatch, tmp_path):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_cloudflare_handler))
    session = {
        "session_id": "usr_ip_intel_dns", "recon_result": {"dns_map": {"example.com": ["1.1.1.1"]}, "targets": []},
    }
    ctx = _ctx(session)

    _update_ip_intel(ctx, get_tool("dns_lookup"))

    intel = session["recon_result"]["ip_intel"]
    assert "1.1.1.1" in intel
    entry = intel["1.1.1.1"]
    assert entry["country_code"] == "AU"
    assert entry["role"] == "cdn_waf"
    assert entry["confidence"] == "high"
    assert entry["hostnames"] == ["example.com"]


def test_ip_intel_reuses_whatweb_protection_signal_when_present(monkeypatch):
    def generic_hosting_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "status": "success", "countryCode": "US", "isp": "Acme Dedicated Servers", "org": "Acme", "as": "AS999 Acme",
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(generic_hosting_handler))
    session = {
        "session_id": "usr_ip_intel_waf", "recon_result": {
            "dns_map": {"app.example.com": ["203.0.113.5"]},
            "targets": [], "protections": {"app.example.com": ["CloudFlare[nginx]"]},
        },
    }
    ctx = _ctx(session)

    _update_ip_intel(ctx, get_tool("record_target"))

    entry = session["recon_result"]["ip_intel"]["203.0.113.5"]
    assert entry["role"] == "cdn_waf"
    assert "CloudFlare[nginx]" in entry["reason"]


def test_ip_intel_ignores_a_target_ip_it_has_already_enriched(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _cloudflare_handler(request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    session = {
        "session_id": "usr_ip_intel_idempotent",
        "recon_result": {"dns_map": {"example.com": ["1.1.1.1"]}, "targets": [], "ip_intel": {"1.1.1.1": {"status": "ok", "role": "cdn_waf"}}},
    }
    ctx = _ctx(session)

    _update_ip_intel(ctx, get_tool("dns_lookup"))

    assert len(calls) == 0  # already enriched -- no new lookup fired


def test_ip_intel_ignores_tools_that_never_reveal_new_hosts(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return _cloudflare_handler(request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    session = {"session_id": "usr_ip_intel_unrelated", "recon_result": {"dns_map": {"example.com": ["1.1.1.1"]}, "targets": []}}
    ctx = _ctx(session)

    _update_ip_intel(ctx, get_tool("http_request"))

    assert len(calls) == 0
    assert "ip_intel" not in session["recon_result"] or session["recon_result"]["ip_intel"] == {}


def test_ip_intel_picks_up_a_bare_ip_target_host(monkeypatch):
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_cloudflare_handler))
    session = {
        "session_id": "usr_ip_intel_bare_ip",
        "recon_result": {"dns_map": {}, "targets": [{"host": "1.1.1.1", "port": 443, "service": "https"}]},
    }
    ctx = _ctx(session)

    _update_ip_intel(ctx, get_tool("nmap"))

    assert "1.1.1.1" in session["recon_result"]["ip_intel"]


def test_ip_intel_caps_lookups_per_call(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"status": "success", "countryCode": "US"})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    many_ips = [f"10.0.0.{i}" for i in range(1, 21)]  # 20 new IPs at once
    session = {
        "session_id": "usr_ip_intel_cap",
        "recon_result": {"dns_map": {"big.example.com": many_ips}, "targets": []},
    }
    ctx = _ctx(session)

    _update_ip_intel(ctx, get_tool("subdomain_enum"))

    assert len(session["recon_result"]["ip_intel"]) == 15  # _IP_INTEL_MAX_LOOKUPS_PER_CALL
    assert len(calls) == 15


def test_ip_intel_swallows_geoip_failures_gracefully(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    session = {"session_id": "usr_ip_intel_geoip_down", "recon_result": {"dns_map": {"example.com": ["1.1.1.1"]}, "targets": []}}
    ctx = _ctx(session)

    _update_ip_intel(ctx, get_tool("dns_lookup"))  # must not raise

    assert session["recon_result"].get("ip_intel", {}) == {}
