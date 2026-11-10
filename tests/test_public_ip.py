"""agent/public_ip.py -- the sidebar "My IP" block's lookup logic. Never touches a real network:
every test drives lookup_public_ips()/get_public_ips() through a real httpx.AsyncClient backed by
httpx.MockTransport (same "real client, fake transport" convention as test_toolkit_repeater.py and
friends), not a crude monkeypatch of the whole function.
"""
import asyncio
import time

import httpx
import pytest

from agent import public_ip


def _run(coro):
    return asyncio.run(coro)


def _transport(handler):
    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _isolated_cache_and_env(monkeypatch):
    public_ip.reset_cache()
    monkeypatch.delenv("PUBLIC_IP_V4_URL", raising=False)
    monkeypatch.delenv("PUBLIC_IP_V6_URL", raising=False)
    monkeypatch.delenv("PUBLIC_IP_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("PUBLIC_IP_CACHE_SECONDS", raising=False)
    monkeypatch.delenv("PUBLIC_IP_AUTOHIDE_SECONDS", raising=False)
    yield
    public_ip.reset_cache()


# --- parse_address ----------------------------------------------------------------------------


def test_parse_address_accepts_a_real_ipv4():
    assert public_ip.parse_address("203.0.113.5\n", 4) == "203.0.113.5"


def test_parse_address_accepts_a_real_ipv6():
    assert public_ip.parse_address("2001:db8::1", 6) == "2001:db8::1"


def test_parse_address_rejects_wrong_family():
    assert public_ip.parse_address("203.0.113.5", 6) is None
    assert public_ip.parse_address("2001:db8::1", 4) is None


def test_parse_address_rejects_garbage():
    assert public_ip.parse_address("<html>not an ip</html>", 4) is None
    assert public_ip.parse_address("", 4) is None


def test_parse_address_rejects_an_oversized_body():
    assert public_ip.parse_address("1.2.3.4" + "x" * 200, 4) is None


# --- lookup_public_ips: both families ----------------------------------------------------------


def test_lookup_public_ips_returns_both_families_on_success(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_V4_URL", "https://v4.example/")
    monkeypatch.setenv("PUBLIC_IP_V6_URL", "https://v6.example/")

    def handler(request: httpx.Request) -> httpx.Response:
        if "v4" in str(request.url):
            return httpx.Response(200, text="203.0.113.7")
        return httpx.Response(200, text="2001:db8::7")

    result = _run(public_ip.lookup_public_ips(transport=_transport(handler)))
    assert result["ipv4"].address == "203.0.113.7"
    assert result["ipv4"].error is None
    assert result["ipv6"].address == "2001:db8::7"
    assert result["ipv6"].error is None


def test_lookup_public_ips_one_family_failing_does_not_affect_the_other(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_V4_URL", "https://v4.example/")
    monkeypatch.setenv("PUBLIC_IP_V6_URL", "https://v6.example/")

    def handler(request: httpx.Request) -> httpx.Response:
        if "v4" in str(request.url):
            return httpx.Response(200, text="203.0.113.7")
        return httpx.Response(503, text="no ipv6 on this network")

    result = _run(public_ip.lookup_public_ips(transport=_transport(handler)))
    assert result["ipv4"].address == "203.0.113.7"
    assert result["ipv6"].address is None
    assert result["ipv6"].error == "http_error"


def test_lookup_public_ips_invalid_response_body_is_reported_not_shown(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_V4_URL", "https://v4.example/")
    monkeypatch.setenv("PUBLIC_IP_V6_URL", "https://v6.example/")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>captive portal</html>")

    result = _run(public_ip.lookup_public_ips(transport=_transport(handler)))
    assert result["ipv4"].address is None
    assert result["ipv4"].error == "invalid_response"
    assert result["ipv6"].address is None
    assert result["ipv6"].error == "invalid_response"


def test_lookup_public_ips_timeout_is_reported_per_family(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_V4_URL", "https://v4.example/")
    monkeypatch.setenv("PUBLIC_IP_V6_URL", "https://v6.example/")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("timed out")

    result = _run(public_ip.lookup_public_ips(transport=_transport(handler)))
    assert result["ipv4"].address is None
    assert result["ipv4"].error == "timeout"
    assert result["ipv6"].error == "timeout"


# --- get_public_ips: cache TTL -----------------------------------------------------------------


def test_get_public_ips_caches_within_the_ttl(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_CACHE_SECONDS", "60")
    calls = {"n": 0}

    async def fake_lookup(*, transport=None):
        calls["n"] += 1
        return {"ipv4": public_ip.FamilyResult("203.0.113.1"), "ipv6": public_ip.FamilyResult(None, "timeout")}

    monkeypatch.setattr(public_ip, "lookup_public_ips", fake_lookup)

    first = _run(public_ip.get_public_ips())
    second = _run(public_ip.get_public_ips())
    assert calls["n"] == 1
    assert first == second


def test_get_public_ips_refreshes_once_the_ttl_elapses(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_CACHE_SECONDS", "0.01")
    calls = {"n": 0}

    async def fake_lookup(*, transport=None):
        calls["n"] += 1
        return {"ipv4": public_ip.FamilyResult(f"203.0.113.{calls['n']}"), "ipv6": public_ip.FamilyResult(None, "timeout")}

    monkeypatch.setattr(public_ip, "lookup_public_ips", fake_lookup)

    _run(public_ip.get_public_ips())
    time.sleep(0.03)
    _run(public_ip.get_public_ips())
    assert calls["n"] == 2


def test_get_public_ips_cache_disabled_when_ttl_is_zero(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_CACHE_SECONDS", "0")
    calls = {"n": 0}

    async def fake_lookup(*, transport=None):
        calls["n"] += 1
        return {"ipv4": public_ip.FamilyResult("203.0.113.1"), "ipv6": public_ip.FamilyResult(None, "timeout")}

    monkeypatch.setattr(public_ip, "lookup_public_ips", fake_lookup)

    _run(public_ip.get_public_ips())
    _run(public_ip.get_public_ips())
    assert calls["n"] == 2


# --- autohide_seconds ----------------------------------------------------------------------------


def test_autohide_seconds_defaults_to_30(monkeypatch):
    assert public_ip.autohide_seconds() == 30


def test_autohide_seconds_respects_env_override(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_AUTOHIDE_SECONDS", "45")
    assert public_ip.autohide_seconds() == 45


def test_autohide_seconds_rejects_a_bogus_value(monkeypatch):
    monkeypatch.setenv("PUBLIC_IP_AUTOHIDE_SECONDS", "not-a-number")
    assert public_ip.autohide_seconds() == 30
