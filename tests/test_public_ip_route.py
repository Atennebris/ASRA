"""GET /api/public-ip (main.py) + the sidebar's hidden-by-default markup (base.html). The lookup
itself is unit-tested in tests/test_public_ip.py -- this file only proves route wiring: JSON shape,
no-store header, and that the server-rendered page never embeds the real IP at load time.
"""
from fastapi.testclient import TestClient

import main
from agent import public_ip


def _client():
    return TestClient(main.app)


def test_public_ip_route_returns_both_families_and_no_store(monkeypatch):
    async def fake_get_public_ips():
        return {
            "ipv4": public_ip.FamilyResult("203.0.113.9"),
            "ipv6": public_ip.FamilyResult(None, "timeout"),
        }

    monkeypatch.setattr(public_ip, "get_public_ips", fake_get_public_ips)
    resp = _client().get("/api/public-ip")

    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert body["ipv4"]["address"] == "203.0.113.9"
    assert body["ipv4"]["error"] is None
    assert body["ipv6"]["address"] is None
    assert body["ipv6"]["error"] == "timeout"


def test_public_ip_route_never_raises_on_total_failure(monkeypatch):
    async def fake_get_public_ips():
        return {
            "ipv4": public_ip.FamilyResult(None, "network_error"),
            "ipv6": public_ip.FamilyResult(None, "network_error"),
        }

    monkeypatch.setattr(public_ip, "get_public_ips", fake_get_public_ips)
    resp = _client().get("/api/public-ip")

    assert resp.status_code == 200
    body = resp.json()
    assert body["ipv4"]["address"] is None
    assert body["ipv6"]["address"] is None


def test_sidebar_hides_the_ip_block_by_default_with_no_address_in_the_page(monkeypatch):
    async def fake_get_public_ips():
        return {
            "ipv4": public_ip.FamilyResult("203.0.113.9"),
            "ipv6": public_ip.FamilyResult("2001:db8::9"),
        }

    # Even if a lookup ran during this request for some other reason, the home page itself must
    # never embed a real address -- the block is only ever populated client-side, on reveal.
    monkeypatch.setattr(public_ip, "get_public_ips", fake_get_public_ips)
    resp = _client().get("/")

    assert resp.status_code == 200
    html = resp.text
    assert "203.0.113.9" not in html
    assert "2001:db8::9" not in html
    assert 'id="asra-public-ip"' in html
    assert 'id="asra-public-ip-toggle"' in html
    assert 'aria-pressed="false"' in html
