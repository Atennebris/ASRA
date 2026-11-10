"""Live public (egress) IP lookup for the sidebar's "My IP" block (templates/base.html).

Why on-demand and not polled: the operator may flip a system-wide VPN/proxy at any moment, and a
bug bounty program may ask for the tester's own IP right then. So the lookup runs once per reveal
click (static/js/public_ip.js -> GET /api/public-ip) and never on a timer. The tiny TTL cache below
only absorbs a double-click; it is deliberately short so a VPN switch never looks stale for long.

The address is confidential: it is never persisted to disk and never written to any log line --
only that a lookup happened, per-family success/failure and duration are logged.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from dataclasses import dataclass

import httpx

from agent.utils.logger import get_logger

logger = get_logger("API")

DEFAULT_V4_URL = "https://api.ipify.org"
DEFAULT_V6_URL = "https://api6.ipify.org"
DEFAULT_TIMEOUT_SECONDS = 4.0
DEFAULT_CACHE_SECONDS = 5.0
DEFAULT_AUTOHIDE_SECONDS = 30

# A lookup service answering with a real address never needs more than this; anything longer is an
# HTML error page or a captive-portal body, not an IP.
_MAX_BODY_CHARS = 64


@dataclass(frozen=True)
class FamilyResult:
    address: str | None
    error: str | None = None


def _env_float(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, "").strip())
    except ValueError:
        return default
    return value if value >= 0 else default


def autohide_seconds() -> int:
    """How long a revealed IP stays on screen before the page hides it again (read by base.html)."""
    return max(1, int(_env_float("PUBLIC_IP_AUTOHIDE_SECONDS", DEFAULT_AUTOHIDE_SECONDS)))


def parse_address(text: str, version: int) -> str | None:
    """Returns the canonical address when `text` is a real IPv`version` address, else None."""
    candidate = text.strip()
    if not candidate or len(candidate) > _MAX_BODY_CHARS:
        return None
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return str(parsed) if parsed.version == version else None


async def _lookup_family(client: httpx.AsyncClient, url: str, version: int) -> FamilyResult:
    started = time.monotonic()
    try:
        response = await client.get(url)
        response.raise_for_status()
        address = parse_address(response.text, version)
        result = FamilyResult(address, None if address else "invalid_response")
    except httpx.TimeoutException:
        result = FamilyResult(None, "timeout")
    except httpx.HTTPStatusError:
        result = FamilyResult(None, "http_error")
    except httpx.HTTPError:
        result = FamilyResult(None, "network_error")
    logger.debug(
        "public-ip: ipv%d lookup %s in %.0fms",
        version,
        "ok" if result.address else f"failed ({result.error})",
        (time.monotonic() - started) * 1000,
    )
    return result


async def lookup_public_ips(*, transport: httpx.AsyncBaseTransport | None = None) -> dict[str, FamilyResult]:
    """Looks up IPv4 and IPv6 concurrently and independently -- one family failing (e.g. no IPv6 on
    this network) never affects the other. Never raises. `transport` exists so tests can mock the
    network layer."""
    v4_url = os.getenv("PUBLIC_IP_V4_URL", "").strip() or DEFAULT_V4_URL
    v6_url = os.getenv("PUBLIC_IP_V6_URL", "").strip() or DEFAULT_V6_URL
    timeout = _env_float("PUBLIC_IP_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS) or DEFAULT_TIMEOUT_SECONDS
    logger.debug("public-ip: lookup started (timeout=%.1fs)", timeout)
    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        v4, v6 = await asyncio.gather(_lookup_family(client, v4_url, 4), _lookup_family(client, v6_url, 6))
    return {"ipv4": v4, "ipv6": v6}


_cache: tuple[float, dict[str, FamilyResult]] | None = None


async def get_public_ips() -> dict[str, FamilyResult]:
    """Cached wrapper around lookup_public_ips(). The TTL is read per call so it can be tuned
    without a restart; 0 disables caching entirely."""
    global _cache
    ttl = _env_float("PUBLIC_IP_CACHE_SECONDS", DEFAULT_CACHE_SECONDS)
    now = time.monotonic()
    if _cache and ttl > 0 and now - _cache[0] < ttl:
        logger.debug("public-ip: served from cache")
        return _cache[1]
    result = await lookup_public_ips()
    _cache = (time.monotonic(), result)
    return result


def reset_cache() -> None:
    global _cache
    _cache = None
