"""geoip_lookup / classify_ip_role (agent/tools/native.py): real IP geolocation + ASN/org
attribution, and the confidence-graded role guess built on top of it -- the deterministic backbone
of the Recon tab's Geopolitical Map. Same real-httpx.MockTransport approach as
test_web_self_register.py for geoip_lookup; classify_ip_role is pure and needs no mocking at all.
"""
import httpx
import pytest

from agent.tools import cache as cache_module
from agent.tools import native

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path / "cache")


# --- geoip_lookup ---


def test_geoip_lookup_missing_ip_is_an_error():
    result = native.geoip_lookup({})
    assert result["status"] == "error"


def test_geoip_lookup_returns_country_and_org(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "status": "success", "country": "United States", "countryCode": "US",
            "regionName": "Virginia", "city": "Ashburn", "lat": 39.03, "lon": -77.5,
            "isp": "Cloudflare, Inc", "org": "APNIC and Cloudflare DNS Resolver project",
            "as": "AS13335 Cloudflare, Inc.",
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.geoip_lookup({"ip": "1.1.1.1"})

    assert result["status"] == "ok"
    assert result["country_code"] == "US"
    assert result["lat"] == 39.03 and result["lon"] == -77.5
    assert "Cloudflare" in result["isp"]
    assert "AS13335" in result["asn"]


def test_geoip_lookup_upstream_failure_message_is_reported(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "fail", "message": "invalid query"})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.geoip_lookup({"ip": "not-an-ip"})

    assert result["status"] == "error"
    assert "invalid query" in result["error"]


def test_geoip_lookup_caches_by_ip(monkeypatch):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url)
        return httpx.Response(200, json={"status": "success", "countryCode": "US"})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    native.geoip_lookup({"ip": "8.8.8.8"})
    native.geoip_lookup({"ip": "8.8.8.8"})

    assert len(calls) == 1


def test_geoip_lookup_http_error_is_reported(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.geoip_lookup({"ip": "203.0.113.1"})

    assert result["status"] == "error"


# --- classify_ip_role ---


def test_classify_ip_role_detects_cloudflare_from_org_string():
    geo = {"isp": "Cloudflare, Inc", "org": "APNIC and Cloudflare DNS Resolver project", "asn": "AS13335 Cloudflare, Inc."}
    result = native.classify_ip_role(geo)
    assert result["role"] == "cdn_waf"
    assert result["confidence"] == "high"


def test_classify_ip_role_detects_cdn_from_whatweb_protection_first():
    geo = {"isp": "Some Random Hosting Co", "org": "Some Random Hosting Co", "asn": "AS1234 Random"}
    result = native.classify_ip_role(geo, detected_protection_products=["CloudFlare[nginx]"])
    assert result["role"] == "cdn_waf"
    assert result["confidence"] == "high"
    assert "CloudFlare[nginx]" in result["reason"]


def test_classify_ip_role_detects_generic_cloud_hosting():
    geo = {"isp": "Amazon.com, Inc.", "org": "AWS EC2", "asn": "AS16509 Amazon.com, Inc."}
    result = native.classify_ip_role(geo)
    assert result["role"] == "cloud_hosting"
    assert result["confidence"] == "medium"


def test_classify_ip_role_falls_back_to_likely_origin():
    geo = {"isp": "Acme Dedicated Servers LLC", "org": "Acme Dedicated Servers LLC", "asn": "AS99999 Acme"}
    result = native.classify_ip_role(geo)
    assert result["role"] == "likely_origin"
    assert result["confidence"] == "medium"
    assert "not proof" in result["reason"] or "not proven" in result["reason"] or "not certain" in result["reason"] or "confirm" in result["reason"].lower()


def test_classify_ip_role_never_claims_100_percent_certainty():
    """The whole point of this classifier -- never a bare "this IS the target" claim (the project's
    own anti-fabrication discipline, matching record_finding's verified/inferred distinction)."""
    for geo in [
        {"isp": "Cloudflare, Inc"},
        {"isp": "Amazon.com, Inc."},
        {"isp": "Acme Dedicated Servers LLC"},
    ]:
        result = native.classify_ip_role(geo)
        assert result["confidence"] in ("high", "medium", "low")
        assert "100%" not in result["reason"]
        assert "confirmed" not in result["reason"].lower()
