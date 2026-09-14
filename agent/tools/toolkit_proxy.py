"""In-process mitmproxy instance capturing the agent's own Playwright browser traffic into the
native toolkit's traffic store (agent/tools/toolkit_store.py) -- the Proxy half of ASRA's own
manual Proxy/Repeater/Decoder/Comparer toolkit.

One shared mitmproxy instance per ASRA process (not per session) -- browser_manager.py already
shares one Chromium Browser process across every session_id the same way, for the same reason
(avoid one more listening port per concurrent session). Traffic from different sessions is
demultiplexed back to the right session_id via HTTP proxy Basic-auth: each BrowserContext
authenticates to the proxy with its own session_id as the username (mitmproxy's built-in
`proxyauth` addon, mode "any" -- accepts any credentials, just records them on the flow).
Confirmed live (standalone smoke test against a real httpx client through a real mitmproxy
instance) that mitmproxy strips the Proxy-Authorization header before the request ever reaches
the real target -- nothing about this scheme is visible to the site under test.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from collections import OrderedDict

from agent.tools import toolkit_store
from agent.tools.allowed_targets import extract_hostname, registrable_domain
from agent.utils.logger import get_logger
from sessions.store import load_session

logger = get_logger("TOOLKIT")

_DEFAULT_PROXY_PORT = 8081
# Not a real secret -- proxyauth "any" mode accepts any username/password combination, this is
# just a fixed non-empty placeholder so Playwright's proxy config always has one.
_PROXY_AUTH_PASSWORD = "asra"
# Passive capture had no size ceiling at all before this -- confirmed live: one real, normal-scope
# session's traffic.jsonl reached 90MB / 508 entries, driven almost entirely by a 10.9MB video
# captured twice and ~20 recurring ~830KB Cloudflare Turnstile challenge bodies, none of it
# first-party target traffic worth keeping. Content-types that are essentially never useful for a
# web pentest AND can be large are dropped to metadata-only (status/headers/URL still captured,
# just not the payload); everything else is still capped so no single response can blow up the
# store. request_content_length/response_content_length still record the REAL original size either
# way, so the Site Map can show "10.9MB video, not captured" instead of silently looking empty.
_MAX_CAPTURED_BODY_BYTES = int(os.getenv("TOOLKIT_MAX_CAPTURED_BODY_BYTES", str(2_000_000)))
_SKIP_BODY_CONTENT_TYPE_PREFIXES = ("video/", "audio/", "font/")

# Second, independent source of the same disk-bloat problem the cap above fixed: off-scope
# third-party bodies (ad/analytics beacons, a payment widget's own JS, a bug-bounty platform page
# opened for reference), which the content-type filter above never touches because they're
# ordinary text/JS/JSON, not video/audio/font. Confirmed live (a real HackerOne session):
# 76.8MB of a 128MB traffic.jsonl came from hosts entirely outside the scanned target (js.stripe.com,
# hackerone.com, and other third-party asset hosts), including the exact same ~2MB JS bundle re-captured 5
# times byte-for-byte. Bodies for a host whose registrable domain isn't in the session's own scope
# are dropped to metadata-only (status/headers/URL/content-length still recorded, same as the
# content-type skip above) -- never the request/response shape itself, so the Site Map still shows
# every off-scope call was made, just without paying to store a payload nothing in this project
# ever reads back for a host it isn't testing.
_scope_cache: dict[str, tuple[float, frozenset[str]]] = {}


def _scope_filter_enabled() -> bool:
    return os.getenv("TOOLKIT_SCOPE_FILTER_ENABLED", "true").strip().lower() in ("1", "true", "yes")


def _scope_cache_ttl_seconds() -> float:
    return float(os.getenv("TOOLKIT_SCOPE_CACHE_TTL_SECONDS", "30"))


def _session_scope_apex_domains(session_id: str) -> frozenset[str]:
    """The session's own target(s), collapsed to registrable/apex domains -- e.g. session
    target "example.com" covers "trk.notify.example.com" (same apex) but not "js.stripe.com"
    or "hackerone.com" (different apex entirely). Includes recon_result["targets"] too, since a
    session's real in-scope host set grows as recon discovers legitimate sibling subdomains, not
    just whatever the operator originally typed. Cached per session_id with a short TTL (a fresh
    session.json read on every single proxied HTTP request would be its own new bottleneck) --
    30s default trades a small window of slightly-stale scope right after a brand new subdomain
    is discovered for not re-reading disk on every image/script/XHR request Chromium fires.

    An empty result (couldn't determine any scope at all -- e.g. an interactive-mode session with
    no "target" field in the shape this expects) means "don't filter", not "filter everything" --
    fails open, same posture as this module's pre-existing content-type filter, which never
    depended on scope at all.
    """
    cached = _scope_cache.get(session_id)
    now = time.monotonic()
    if cached is not None and cached[0] > now:
        return cached[1]
    session = load_session(session_id) or {}
    apexes: set[str] = set()
    target = session.get("target")
    if target:
        hostname = extract_hostname(target) or target
        apexes.add(registrable_domain(hostname))
    for entry in (session.get("recon_result") or {}).get("targets", []):
        host = entry.get("host")
        if host:
            apexes.add(registrable_domain(host))
    result = frozenset(apexes)
    _scope_cache[session_id] = (now + _scope_cache_ttl_seconds(), result)
    return result


def _is_in_scope(session_id: str, url: str) -> bool:
    if not _scope_filter_enabled():
        return True
    scope_apexes = _session_scope_apex_domains(session_id)
    if not scope_apexes:
        return True  # fail open -- see _session_scope_apex_domains' own docstring
    hostname = extract_hostname(url)
    if not hostname:
        return True
    return registrable_domain(hostname) in scope_apexes


# Third, independent source of the same disk-bloat problem: the SAME unchanging response body
# (identical bytes) fetched repeatedly within one session -- e.g. a vendor JS bundle Chromium
# re-requests on every page navigation. Confirmed live (a real HackerOne session): one
# ~2.04MB bundle alone was captured 5 times byte-for-byte (~10MB for one unchanging file).
# Deliberately body-hash based, not URL based -- a cache-busted query string on an otherwise
# byte-identical asset would defeat a URL-keyed dedup but not this one. Only applied to bodies
# already past a minimum size (small/tiny repeated bodies, e.g. a shared 204 or a repeated
# favicon, aren't the disk-bloat problem this exists for, and hashing every tiny body for no real
# savings is pure overhead). Bounded per-session (OrderedDict as a capped FIFO of hashes seen) so
# a very long-running session can't grow this cache without limit.
_DEDUP_MIN_BODY_BYTES = int(os.getenv("TOOLKIT_DEDUP_MIN_BODY_BYTES", "50000"))
_DEDUP_MAX_HASHES_PER_SESSION = int(os.getenv("TOOLKIT_DEDUP_MAX_HASHES_PER_SESSION", "2000"))
_seen_body_hashes: dict[str, "OrderedDict[str, None]"] = {}


def _is_duplicate_body(session_id: str, body: bytes) -> bool:
    if len(body) < _DEDUP_MIN_BODY_BYTES:
        return False
    digest = hashlib.sha256(body).hexdigest()
    seen = _seen_body_hashes.setdefault(session_id, OrderedDict())
    if digest in seen:
        seen.move_to_end(digest)
        return True
    seen[digest] = None
    if len(seen) > _DEDUP_MAX_HASHES_PER_SESSION:
        seen.popitem(last=False)
    return False


def _capture_body(raw: bytes, content_type: str, session_id: str, url: str) -> bytes:
    if any(content_type.lower().startswith(prefix) for prefix in _SKIP_BODY_CONTENT_TYPE_PREFIXES):
        return b""
    if not _is_in_scope(session_id, url):
        return b""
    captured = raw[:_MAX_CAPTURED_BODY_BYTES]
    if _is_duplicate_body(session_id, captured):
        return b""
    return captured


def _proxy_port() -> int:
    return int(os.getenv("TOOLKIT_PROXY_PORT", str(_DEFAULT_PROXY_PORT)))


def toolkit_enabled() -> bool:
    return os.getenv("TOOLKIT_ENABLED", "true").strip().lower() in ("1", "true", "yes")


class _TrafficCaptureAddon:
    """mitmproxy addon: one response() hook per completed request/response pair -- appends it to
    that flow's own session's traffic store. session_id comes from the proxy's own Basic-auth
    username (ToolkitProxyManager.proxy_config_for_session below), never from request
    headers/body, so the target site itself can never spoof/inject a session_id."""

    def response(self, flow) -> None:
        auth = flow.metadata.get("proxyauth")
        session_id = auth[0] if auth else None
        if not session_id:
            # Real, expected case, not an error: any connection that reaches this proxy without
            # going through ToolkitProxyManager.proxy_config_for_session (mitmproxy's own
            # bookkeeping traffic, a stray client) never carries proxyauth -- nothing to
            # attribute this flow to, so it's dropped rather than mis-attributed.
            return

        # .content (not .get_text()) -- the real, already-decompressed bytes regardless of
        # Content-Type, so _encode_body can make its own text-vs-binary decision instead of
        # get_text() silently force-decoding binary content as text first.
        request_content_type = flow.request.headers.get("content-type", "")
        response_content_type = flow.response.headers.get("content-type", "") if flow.response else ""
        request_raw_full = flow.request.content or b""
        response_raw_full = (flow.response.content or b"") if flow.response else b""
        url = flow.request.pretty_url
        request_body, request_encoding = toolkit_store.encode_body(
            request_content_type, _capture_body(request_raw_full, request_content_type, session_id, url),
        )
        response_body, response_encoding = toolkit_store.encode_body(
            response_content_type, _capture_body(response_raw_full, response_content_type, session_id, url),
        )

        entry = toolkit_store.build_traffic_entry(
            session_id=session_id,
            method=flow.request.method,
            url=url,
            request_headers=dict(flow.request.headers),
            request_body=request_body,
            request_body_encoding=request_encoding,
            request_content_length=len(request_raw_full),
            response_status=flow.response.status_code if flow.response else None,
            response_headers=dict(flow.response.headers) if flow.response else {},
            response_body=response_body,
            response_body_encoding=response_encoding,
            response_content_length=len(response_raw_full),
        )
        toolkit_store.append_traffic_entry(entry)


class ToolkitProxyManager:
    """Lazily starts the shared mitmproxy instance on first use -- a project that never opens the
    browser_* tools never pays for a proxy nobody uses, same lazy-launch posture as
    BrowserSessionManager's own shared Chromium (browser_manager.py)."""

    def __init__(self) -> None:
        self._master = None
        self._run_task: asyncio.Task | None = None
        self._start_lock = asyncio.Lock()

    async def ensure_started(self) -> bool:
        """Returns True once the proxy is listening (or already was), False if the feature is
        disabled (TOOLKIT_ENABLED=false) -- callers must treat False as "proceed without a
        proxy", not an error."""
        if not toolkit_enabled():
            return False
        if self._master is not None:
            return True
        async with self._start_lock:
            if self._master is not None:
                return True  # a concurrent first-caller may have already won the race
            from mitmproxy.options import Options
            from mitmproxy.tools.dump import DumpMaster

            port = _proxy_port()
            opts = Options(listen_host="127.0.0.1", listen_port=port)
            master = DumpMaster(opts, with_termlog=False, with_dumper=False)
            master.addons.add(_TrafficCaptureAddon())
            opts.update(proxyauth="any")
            self._run_task = asyncio.create_task(master.run())
            self._master = master
            logger.debug("toolkit_proxy: mitmproxy started on 127.0.0.1:%d", port)
            return True

    def proxy_config_for_session(self, session_id: str) -> dict[str, str]:
        """Playwright BrowserContext proxy= config -- session_id doubles as the Basic-auth
        username _TrafficCaptureAddon reads back off each flow (see its own docstring)."""
        return {
            "server": f"http://127.0.0.1:{_proxy_port()}",
            "username": session_id,
            "password": _PROXY_AUTH_PASSWORD,
        }

    async def shutdown(self) -> None:
        if self._master is None:
            return
        self._master.shutdown()
        if self._run_task is not None:
            try:
                await asyncio.wait_for(self._run_task, timeout=5)
            except (TimeoutError, asyncio.CancelledError):
                pass
        self._master = None
        self._run_task = None
        logger.debug("toolkit_proxy: mitmproxy shut down")


_manager = ToolkitProxyManager()


def get_toolkit_proxy_manager() -> ToolkitProxyManager:
    return _manager
