"""Fail-closed egress kill-switch for the agent's own outbound tool calls.

Why this exists: on a real engagement the operator routes their traffic through a VPN/proxy so the
target never sees their real IP. If that channel silently drops, the OS falls back to the direct
route and the very next scanner/HTTP call leaks the operator's real address to the target. ASRA used
to only *show* the current public IP in the sidebar (agent/public_ip.py) -- a passive readout, no
enforcement. This module adds the enforcement: when the configured channel is down, network-touching
tool launches refuse to run and return an explicit reason instead of quietly going out the direct
route (the "fail-closed routing" principle -- a dropped channel blocks managed egress rather than
falling back).

What defines "the configured channel": ASRA_EGRESS_EXPECTED_IP -- the VPN/proxy's own public exit
IP(s), comma-separated. The probe looks up this machine's *current* public IP (the same lookup
service agent/public_ip.py uses) and compares. A mismatch means traffic is now exiting a different
route (the VPN dropped) -> blocked. A total lookup failure while a channel is configured means we
cannot confirm we are still on-channel -> blocked too (fail-closed). With no expected IP configured
there is no channel to measure against, so the probe reports reachability only and never blocks --
the operator must set ASRA_EGRESS_EXPECTED_IP for real protection, which the UI/status says plainly.

Enforcement is OFF by default (ASRA_EGRESS_ENFORCE=false). The resolution order for both settings is
the same GUI -> .env -> hardcoded-default order agent/reliability_settings.py uses, so the operator
tunes this from Settings without hand-editing .env, and .env stays the quiet default underneath.

Deliberately NOT a bundled proxy/VPN manager or a multi-protocol node vault -- the operator uses
their own system VPN. This is purely "configured channel down -> block", the simplest thing that
actually closes the IP-leak gap.

The probe is synchronous (httpx.Client) so the sync tool-launch points (agent/tools/runner.py's
subprocess dispatch, native.py's http_request) can call egress_block_reason() directly; the async
points (toolkit send_raw_request, browser_manager.navigate) wrap it in asyncio.to_thread. A short
TTL cache keeps the per-call gate cheap (one real network probe per cache window, shared by every
caller and by the sidebar's periodic status poll), while still noticing a dropped channel quickly.
"""
from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from dataclasses import dataclass, field

import httpx

from agent.public_ip import DEFAULT_V4_URL, DEFAULT_V6_URL, parse_address
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("EGRESS")

ENFORCE_KEY = "ASRA_EGRESS_ENFORCE"
EXPECTED_IP_KEY = "ASRA_EGRESS_EXPECTED_IP"

# Settings this store may hold (GUI-saved, overriding .env) -- any other key is rejected so the save
# route can't be coaxed into writing arbitrary data, same guard as reliability_settings.ALLOWED_KEYS.
ALLOWED_KEYS = frozenset({ENFORCE_KEY, EXPECTED_IP_KEY})

# Lives in the global app data dir (Documents/ASRA/data), never the repo's own data/ -- same
# convention and reasoning as agent/reliability_settings.py. Holds a flag + the expected exit IP
# (machine-specific operator config), nothing that belongs in git.
_SETTINGS_PATH = resolve_global_app_dir() / "data" / "egress_settings.json"

_DEFAULT_PROBE_TIMEOUT_SECONDS = 4.0
_DEFAULT_CACHE_SECONDS = 15.0

# A single public-IP answer is tiny; anything longer is an HTML error/captive-portal page, not an IP.
_MAX_BODY_CHARS = 64

# Egress states, deliberately a small set (the source project's off/starting/ready/degraded/blocked/
# error, pared down to what "configured channel down -> block" actually needs):
STATE_OFF = "off"  # enforcement disabled
STATE_OK = "ok"  # channel healthy (current IP matches the configured exit), or reachable-only when unconfigured
STATE_BLOCKED = "blocked"  # enforcement on and the channel is down -> network tools refuse to run


@dataclass(frozen=True)
class EgressStatus:
    state: str
    reason: str | None
    current_ip: str | None
    expected_ips: list[str] = field(default_factory=list)
    configured: bool = False  # whether an expected exit IP is set (i.e. a channel is actually defined)
    checked_at: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.state == STATE_BLOCKED


# --- settings store (GUI -> .env -> default), mirrors agent/reliability_settings.py --------------

_settings_cache: dict | None = None
_settings_lock = threading.Lock()


def _load_settings() -> dict:
    global _settings_cache
    with _settings_lock:
        if _settings_cache is not None:
            return dict(_settings_cache)
    data: dict = {}
    if _SETTINGS_PATH.exists():
        try:
            with _SETTINGS_PATH.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data = loaded
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("egress_guard: settings unreadable (%s) -- treating as unset", exc)
    with _settings_lock:
        _settings_cache = data
    return dict(data)


def save_setting(key: str, value: str) -> None:
    """Persist one egress setting, overriding its .env default on the next read. Rejects any key
    outside ALLOWED_KEYS."""
    if key not in ALLOWED_KEYS:
        raise ValueError(f"unknown egress setting {key!r}")
    global _settings_cache
    existing = _load_settings()
    existing[key] = str(value)
    _SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = _SETTINGS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)
    os.replace(tmp_path, _SETTINGS_PATH)
    with _settings_lock:
        _settings_cache = None
    reset_cache()  # a changed channel definition must be re-probed, not served from the old verdict
    logger.debug("egress_guard: setting saved %s=%r", key, value)


def _raw_setting(key: str) -> str | None:
    """Effective raw value for key: GUI-saved first, then the env var, then None."""
    saved = _load_settings().get(key)
    if saved is not None:
        return str(saved)
    return os.getenv(key)


def saved_raw(key: str) -> str | None:
    """The GUI-saved raw value only (None when never set in the GUI) -- for the Settings form."""
    value = _load_settings().get(key)
    return str(value) if value is not None else None


def configured_expected_ip_raw() -> str:
    """The effective expected-exit-IP string (GUI-saved, else .env, else empty) exactly as the
    operator typed it -- for pre-filling the Settings input. expected_exit_ips() above is the
    parsed/validated list the probe uses."""
    return _raw_setting(EXPECTED_IP_KEY) or ""


def _as_bool(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def enforcement_enabled() -> bool:
    return _as_bool(_raw_setting(ENFORCE_KEY))


def expected_exit_ips() -> list[str]:
    """The configured VPN/proxy exit IP(s) -- comma-separated, each validated as a real IP address.
    Garbage/partial entries are dropped rather than silently treated as a never-matching channel."""
    raw = _raw_setting(EXPECTED_IP_KEY) or ""
    out: list[str] = []
    for part in raw.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            out.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            logger.debug("egress_guard: ignoring malformed expected exit IP %r", candidate)
    return out


# --- the probe -----------------------------------------------------------------------------------


def _probe_timeout_seconds() -> float:
    try:
        value = float(os.getenv("ASRA_EGRESS_PROBE_TIMEOUT_SECONDS", "").strip())
        return value if value > 0 else _DEFAULT_PROBE_TIMEOUT_SECONDS
    except ValueError:
        return _DEFAULT_PROBE_TIMEOUT_SECONDS


def _cache_seconds() -> float:
    try:
        value = float(os.getenv("ASRA_EGRESS_PROBE_CACHE_SECONDS", "").strip())
        return value if value >= 0 else _DEFAULT_CACHE_SECONDS
    except ValueError:
        return _DEFAULT_CACHE_SECONDS


def _lookup_current_ip() -> tuple[str | None, str | None]:
    """This machine's current public IP, trying IPv4 then IPv6 (reusing the same lookup endpoints
    agent/public_ip.py uses). Returns (ip, error) -- (None, reason) when neither family answers."""
    v4_url = os.getenv("PUBLIC_IP_V4_URL", "").strip() or DEFAULT_V4_URL
    v6_url = os.getenv("PUBLIC_IP_V6_URL", "").strip() or DEFAULT_V6_URL
    timeout = _probe_timeout_seconds()
    last_error = "no response"
    with httpx.Client(timeout=timeout) as client:
        for url, version in ((v4_url, 4), (v6_url, 6)):
            try:
                response = client.get(url)
                response.raise_for_status()
                address = parse_address(response.text[:_MAX_BODY_CHARS], version)
                if address:
                    return address, None
                last_error = "invalid_response"
            except httpx.TimeoutException:
                last_error = "timeout"
            except httpx.HTTPError:
                last_error = "network_error"
    return None, last_error


_status_cache: EgressStatus | None = None
_status_cache_lock = threading.Lock()


def probe_egress(*, force: bool = False) -> EgressStatus:
    """Decide the current egress state. Cached for ASRA_EGRESS_PROBE_CACHE_SECONDS so the per-call
    gate and the sidebar poll share one real network probe per window. Never raises."""
    global _status_cache
    enforced = enforcement_enabled()
    if not enforced:
        # Nothing to probe when disabled -- cheap, and the sidebar poll must not hit the network
        # just to render an "off" dot.
        status = EgressStatus(STATE_OFF, None, None, [], False, time.time())
        with _status_cache_lock:
            _status_cache = status
        return status

    if not force:
        ttl = _cache_seconds()
        with _status_cache_lock:
            cached = _status_cache
        if cached is not None and cached.state != STATE_OFF and ttl > 0 and time.time() - cached.checked_at < ttl:
            return cached

    expected = expected_exit_ips()
    current_ip, error = _lookup_current_ip()
    configured = bool(expected)

    if not configured:
        # Enforcement is on but no channel is defined -- we can only report reachability, and must
        # NOT block (there is nothing to compare the current route against). The status says so, so
        # the operator sees the toggle is on-but-unconfigured rather than silently doing nothing.
        reason = (
            "egress enforcement is ON but no expected exit IP is configured (ASRA_EGRESS_EXPECTED_IP) "
            "-- a dropped VPN/proxy cannot be detected until you set it; not blocking"
        )
        status = EgressStatus(STATE_OK, reason, current_ip, [], False, time.time())
    elif current_ip is None:
        reason = (
            f"egress channel could not be verified: the public-IP probe failed ({error}). With an "
            "expected exit IP configured, an unverifiable channel is treated as down -- outbound "
            "network tool calls are blocked rather than risking the direct route."
        )
        status = EgressStatus(STATE_BLOCKED, reason, None, expected, True, time.time())
    elif current_ip not in expected:
        reason = (
            f"egress channel is DOWN: current public IP {current_ip} is not the configured VPN/proxy "
            f"exit ({', '.join(expected)}). Traffic would exit the direct route and leak the real IP, "
            "so outbound network tool calls are blocked until the channel is restored."
        )
        status = EgressStatus(STATE_BLOCKED, reason, current_ip, expected, True, time.time())
    else:
        status = EgressStatus(STATE_OK, None, current_ip, expected, True, time.time())

    with _status_cache_lock:
        _status_cache = status
    logger.debug(
        "egress_guard: probe state=%s configured=%s current_ip=%s expected=%s",
        status.state, configured, "set" if current_ip else "none", expected or "-",
    )
    return status


def egress_block_reason() -> str | None:
    """The one call every network tool-launch point makes before going outbound: returns a
    model-facing reason string when egress enforcement is ON and the configured channel is down
    (so the caller refuses the call), or None when it is clear to proceed. Safe from any thread."""
    if not enforcement_enabled():
        return None
    status = probe_egress()
    if status.blocked:
        logger.debug("egress_guard: blocking an outbound tool call -- %s", status.reason)
        return (
            "ASRA egress kill-switch: this outbound network tool call was refused because the "
            f"configured egress channel is down. {status.reason} This is an ASRA-side safety control "
            "(ASRA_EGRESS_ENFORCE), not a target-side block -- do not retry or try to work around it; "
            "restore the VPN/proxy channel (or disable egress enforcement in Settings) first."
        )
    return None


def reset_cache() -> None:
    """Drop the cached probe verdict -- used by tests and after a settings change."""
    global _status_cache
    with _status_cache_lock:
        _status_cache = None
