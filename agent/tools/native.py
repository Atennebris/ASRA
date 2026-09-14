"""Tier-1 native tools: plain Python functions — no subprocess/binary install, with one
deliberate exception (oob_generate/oob_poll, which shell out to the interactsh-client binary).

Every function takes a single params dict and returns a result dict shaped like run_tool()'s
tier-2 output ({"status": "ok"/"error", ...}) — run_tool() calls these directly for tool_tier=1
ToolSpecs and never wraps them in subprocess/health-check/timeout (each function owns its own
network timeout). oob_generate/oob_poll own a subprocess directly rather than going through the
shared tier-2 runner (agent/tools/runner.py) because interactsh-client needs a graceful SIGINT to
flush its session file/buffered output — confirmed live: the runner's generic hard-kill-on-timeout
drops both — a need specific enough to this one tool that it isn't worth adding to the runner
every other tool_tier=2 tool would inherit too.
"""
from __future__ import annotations

import base64
import csv
import functools
import hashlib
import html
import ipaddress
import json
import os
import plistlib
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
import mmh3
import pyevmasm
from curl_cffi import requests as curl_requests

from agent.tools import toolkit_store
from agent.tools.allowed_targets import collapse_cdn_edge_node_hosts, is_target_allowed
from agent.tools.background_jobs import check_background_job, start_background_job
from agent.tools.builders.re_target import _safe_extract_zip
from agent.tools.capability_paths import resolve_interpreter_path
from agent.tools import passive_detectors
from agent.tools.sandbox import run_sandboxed
from agent.tools import subagent_tasks
from agent.tools.builders.hydra import build_hydra_command, parse_hydra_result
from agent.tools.builders.validators import to_ascii_hostname, validate_header_pair, validate_safe_value, validate_target
from agent.tools.registry import get_tool
from agent.tools.builders.web_login_bruteforce import build_web_login_bruteforce_command, parse_web_login_bruteforce_result
from agent.tools.cache import cache_get, cache_set
from agent.tools.url_declutter import declutter_urls
from agent.tools.wordlist_store import get_assigned_wordlist
from agent.utils.errors import describe_exception
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir
from sessions.store import get_session_folder, reload_merge_save

logger = get_logger("TOOLS")

_HTTP_TIMEOUT = float(os.getenv("HTTP_REQUEST_TIMEOUT_SECONDS", "10"))
# A one-off DNS blip or connection reset self-heals almost immediately -- retrying fast and
# locally inside http_request itself, before ever reporting status=error, avoids the alternative:
# the LLM's own "1-Step Retry" (agent/core.py's _run_tool_with_retry) burning a full extra LLM
# round-trip (~15-30s) just to ask the model to try the identical URL again, for a failure that
# was never about the URL or its parameters. Real incident this fixes: a real bug-bounty scan
# against a wildcard scope saw the exact same hostname flip between resolving fine and
# "[Errno -5] No address associated with hostname" 17 times across one session -- a transient
# resolver hiccup, not a genuinely dead host (confirmed by other successful requests to that same
# name elsewhere in the same run), that cost a full LLM round-trip every single time.
#
# Bumped from 2 attempts/1.0s to 4 attempts/1.5s after a second real incident where the OLD budget
# (~2s of local retrying) still wasn't enough: the same target flip-flopped between resolving fine
# and "[Errno -5]" 9 times through http_request alone within one 4-minute window, and every single
# one exhausted the local retry loop and still escalated to the costly 1-Step Retry -- meaning the
# real resolver hiccup this session hit routinely outlasted the old ~2s window. tcp_port_check
# shares these same two knobs for its own local self-heal loop below (see _tcp_gaierror_retry) --
# not http_request-specific despite the env var names, kept as one shared, cache-friendly pair
# rather than a second near-duplicate env var pair for the exact same underlying phenomenon.
_HTTP_REQUEST_RETRY_ATTEMPTS = int(os.getenv("HTTP_REQUEST_RETRY_ATTEMPTS", "4"))
_HTTP_REQUEST_RETRY_DELAY_SECONDS = float(os.getenv("HTTP_REQUEST_RETRY_DELAY_SECONDS", "1.5"))


class _HardDeadlineExceeded(httpx.TimeoutException):
    """Raised by _with_hard_deadline when a call's own background thread hasn't returned within
    the deadline. A real subclass of httpx.TimeoutException (itself a httpx.HTTPError) so every
    existing `except httpx.HTTPError`/`except httpx.TimeoutException` call site in this file keeps
    catching it exactly like before with zero changes -- callers that specifically need to tell
    "this genuinely can't reach the host" apart from "httpx cleanly detected a slow response and
    raised its own TimeoutException" (see _with_hard_deadline's docstring) can catch this subclass
    on its own.
    """


def _with_hard_deadline(fn, deadline_seconds: float):
    """Runs fn() (an httpx call against the real scan target) with a real wall-clock deadline,
    independent of whatever httpx/httpcore/the OS resolver internally enforce.

    Real incident this fixes: a live bug-bounty session logged the SAME httpx.Client(timeout=10.0)
    single-request call taking ~20s (not ~10s) against an unreachable host, and ~61s for a 3-attempt
    retry loop around it -- confirmed 6 times across two tools (http_request, view_source,
    security_headers_audit) with near-identical timings each time. httpx's own `timeout=` only
    bounds each individual connect/read/write/pool phase; it does NOT bound the total time spent
    when a hostname resolves to more than one address (dual-stack A/AAAA, or plain round-robin A
    records) and one of them is unroutable from this environment (a broken/blackholed IPv6 route is
    the most likely cause in a WSL2 install) -- the stdlib connection machinery httpx/httpcore build
    on tries each candidate address in turn, each getting its OWN full connect-timeout budget, so
    the real wall-clock cost of one "unreachable host" call is (number of candidate addresses) x
    the configured timeout, not the configured timeout itself.

    Running the call on a background daemon thread and giving up at deadline_seconds regardless of
    what's still happening inside restores the bound the caller actually asked for. The thread
    itself is not (cannot safely be) killed if it's still blocked in a syscall past the deadline --
    it's abandoned to finish and be garbage-collected on its own; daemon=True only guarantees it can
    never block process shutdown while doing so.
    """
    result: dict = {}

    def _run():
        try:
            result["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 -- re-raised as-is in the caller's own thread below
            result["error"] = exc

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join(deadline_seconds)
    if thread.is_alive():
        raise _HardDeadlineExceeded(
            f"no response within {deadline_seconds:.0f}s hard deadline -- host is likely "
            "unreachable (a broken/blackholed route to one of its resolved addresses is the "
            "usual cause, not a slow server)"
        )
    if "error" in result:
        raise result["error"]
    return result["value"]


def _get_with_transient_retry(client: httpx.Client, url: str, deadline_seconds: float = _HTTP_TIMEOUT) -> httpx.Response:
    """Only retries connection/timeout-class errors -- never a real HTTP status, which httpx
    never raises for here in the first place (http_request doesn't call raise_for_status()).
    A _HardDeadlineExceeded is deliberately NOT retried like a normal ConnectError/TimeoutException
    -- it means the host is stuck well past its own configured timeout budget (see
    _with_hard_deadline), a condition three more full-budget attempts are extremely unlikely to
    self-heal from in the ~1s between attempts, unlike the fast-failing flip-flopping-DNS case this
    loop exists for.

    httpx.RemoteProtocolError ("Server disconnected without sending a response.") belongs in the
    same retried family as ConnectError/TimeoutException -- real, confirmed incident: a WAF
    (ddos-guard) rate-limiting a burst of requests from one egress dropped the TCP connection
    outright instead of returning a real HTTP status, and this specific exception class wasn't in
    the retried tuple. Every single occurrence (51 of them in one session) skipped this local,
    fast self-heal entirely and went straight to status="error", each one then costing a full
    15-30s LLM round-trip (the 1-Step Retry) just to resend the identical request -- which usually
    failed again too, since a ~1-2s LLM round-trip rarely outlasts a WAF's own rate-limit window.
    This was the single largest driver of that session's low tool-call efficiency score.
    """
    last_exc: httpx.HTTPError | None = None
    for attempt in range(_HTTP_REQUEST_RETRY_ATTEMPTS + 1):
        if attempt > 0:
            time.sleep(_HTTP_REQUEST_RETRY_DELAY_SECONDS)
        try:
            return _with_hard_deadline(lambda: client.get(url), deadline_seconds)
        except _HardDeadlineExceeded:
            raise
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as exc:
            last_exc = exc
    raise last_exc


# Real, confirmed incident this fixes: a WAF-fronted target (Telenor's api-app.telenor.se, while
# the model was correctly chasing a real Spring Boot Actuator hypothesis) rejected EVERY one of 7
# httpx-based http_request attempts with "Server disconnected without sending a response"
# (httpx.RemoteProtocolError) -- not rate-limiting like the ddos-guard incident
# _get_with_transient_retry's own docstring above already covers (that one self-heals with a plain
# retry), but a deterministic rejection of the connection itself on every single attempt, no matter
# how many times it's retried. httpx/OpenSSL's default TLS ClientHello (cipher suite order,
# extensions, ALPN, JA3/JA4 fingerprint) looks nothing like a real browser's, and an increasing
# number of WAFs (Cloudflare, Akamai, Imperva, and similar) fingerprint and drop connections from
# clients that don't look like one -- no amount of retrying with the SAME fingerprint could ever
# fix this, the same "permanent, not transient" family as is_target_allowed's own rejection reason
# (agent/tools/runner.py's _check_guardrail).
#
# curl_cffi wraps curl-impersonate, which replicates a real browser's actual TLS/HTTP2 fingerprint
# (not just its User-Agent header) at the wire level -- the only practical way to pass this class of
# check from plain Python without shipping a real browser. Configurable via env var since which
# impersonation profile currently blends in best can shift as browsers/WAF fingerprint databases
# both keep moving.
_IMPERSONATE_BROWSER = os.getenv("HTTP_IMPERSONATE_BROWSER", "chrome124")


def _browser_fingerprint_fallback_get(
    url: str, headers: dict[str, str], timeout: float, verify: bool, follow_redirects: bool
):
    """Last-resort fallback, tried only once http_request's own httpx.Client has already exhausted
    every local self-heal retry and still failed with httpx.RemoteProtocolError specifically --
    never for a genuinely unreachable host (_HardDeadlineExceeded) or a plain connect/read timeout,
    where a different TLS fingerprint changes nothing. Raises curl_cffi's own
    requests.exceptions.RequestException family on failure, left for the caller to turn into a
    normal {"status": "error", ...} result the same way httpx.HTTPError already is.
    """
    return curl_requests.get(
        url,
        headers=headers or None,
        timeout=timeout,
        verify=verify,
        impersonate=_IMPERSONATE_BROWSER,
        allow_redirects=follow_redirects,
    )


def _merged_target_headers(params: dict) -> dict[str, str]:
    """The project's own required extra headers for a call that hits the actual scan target (New
    Project form's "Custom User-Agent header" + "Custom HTTP Headers", injected server-side as
    params["_user_agent"]/params["_extra_headers"] by agent/core.py's _run_tool_with_retry) —
    some bug-bounty programs require these on all test traffic so their team can tell it apart from
    a real attack in their logs. User-Agent is applied first, then the generic extra headers on top
    (so an explicit "User-Agent" line in that field, unusual but not invalid, wins) — {} when
    neither is configured, same as today.
    """
    headers = dict(params.get("_extra_headers") or {})
    user_agent = params.get("_user_agent")
    if user_agent:
        headers = {"User-Agent": user_agent, **headers}
    return headers


def _target_client_kwargs(params: dict) -> dict:
    """Extra httpx.Client kwargs for a call that hits the actual scan target (never a third-party
    service like crt.sh/cve.circl.lu/exploit-db — those never see this).

    verify=False, always: a self-signed, expired, or hostname-mismatched certificate on a real
    in-scope host (a staging environment, an internal API) is the normal case in a pentest, not a
    rare edge case, and this is a human-authorized, explicitly in-scope target either way — never
    the confused-deputy/SSRF risk that trusting an arbitrary third party's cert would be. Real
    incident this fixes: httpx.Client's own stdlib default (verify=True) made every one of these
    call sites hard-fail with CERTIFICATE_VERIFY_FAILED against a real in-scope host with an
    incomplete cert chain; the model correctly reached for a verify_ssl/verify override to work
    around it, but no such parameter was ever wired to anything here, so even the corrected 1-Step
    Retry failed with the exact same error as the original call.
    """
    headers = _merged_target_headers(params)
    model_headers = params.get("headers")
    if isinstance(model_headers, dict):
        # Model-supplied headers (currently only http_request's schema exposes this) win over the
        # project's own injected extras -- needed so a model retargeting a request at a bare IP can
        # still set Host to the original domain instead of hitting a CDN/WAF's default vhost.
        headers = {**headers, **{str(k): str(v) for k, v in model_headers.items()}}
    return {"headers": headers, "verify": False} if headers else {"verify": False}


# --- recon, zero touch on the target (queries a third party, not the target itself) ---


def _crt_sh_subdomains(domain: str, client: httpx.Client) -> set[str]:
    resp = client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
    resp.raise_for_status()
    subdomains = set()
    for entry in resp.json():
        for name in entry.get("name_value", "").split("\n"):
            subdomains.add(name.strip().lower())
    return subdomains


def _certspotter_subdomains(domain: str, client: httpx.Client) -> set[str]:
    resp = client.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
    )
    resp.raise_for_status()
    subdomains = set()
    for entry in resp.json():
        for name in entry.get("dns_names", []):
            subdomains.add(name.strip().lower())
    return subdomains


def crt_sh_lookup(params: dict) -> dict:
    """Certificate Transparency subdomain lookup. crt.sh is the primary source; it's a free
    community service that's frequently slow/overloaded (confirmed by a real 40s+ non-response)
    or fully down (confirmed 3/3 attempts in one session) — on any error or timeout, falls back
    to api.certspotter.com (SSLMate, no key needed), which mirrors the same CT log data from a
    different, more reliable operator.
    """
    domain = params["domain"]
    cached = cache_get("crt_sh_lookup", domain)
    if cached is not None:
        return cached

    source = "crt.sh"
    try:
        with httpx.Client(timeout=45.0) as client:
            subdomains = _crt_sh_subdomains(domain, client)
    except (httpx.HTTPError, json.JSONDecodeError) as primary_exc:
        try:
            source = "certspotter"
            with httpx.Client(timeout=15.0) as client:
                subdomains = _certspotter_subdomains(domain, client)
        except (httpx.HTTPError, json.JSONDecodeError) as fallback_exc:
            return {"status": "error", "error": f"crt.sh: {primary_exc}; certspotter fallback: {fallback_exc}"}

    result = {"status": "ok", "source": source, "subdomains": collapse_cdn_edge_node_hosts(sorted(subdomains))}
    cache_set("crt_sh_lookup", domain, result)
    return result


def _persist_candidate_urls(session_id: str | None, result: dict) -> None:
    """Feeds wayback_urls/common_crawl_urls' own discovered-but-never-requested URLs into
    session["recon_result"]["candidate_urls"] so the Map tab's Site Map Tree (main.py's
    _build_site_map_tree) can show them as unconfirmed leaves, not just what actually got
    requested through the proxy or the agent's own browser automation. Real, confirmed gap this
    closes: before this, these URLs existed nowhere but a truncated JSON blob inside one
    session["logs"] entry (agent/core.py's own _append_log, capped at 8000 chars -- easily
    truncating a real domain's URL list), invisible to that tree entirely.

    Called on every successful call, cache hit or miss (both callers return early on a
    cache_get() hit, before any code after it would otherwise run) -- a second session querying
    the same domain within the shared cross-session URL cache's TTL must still get its OWN
    project's candidate_urls populated, since that cache is keyed by domain, not by session.

    reload_merge_save, not a blind save of a long-lived session snapshot -- same fix class as
    agent/tools/background_jobs.py's own saves (sessions/store.py's own docstring on why): this
    native function only ever receives a session_id (agent/core.py's own injection block), never
    the live session dict itself, specifically so it can't clobber whatever a concurrent phase/
    subagent/chat turn has already persisted in the meantime. append-only and deduped, so a plain
    length check is a sufficient "did this grow" signal for _SITE_MAP_TREE_CACHE (main.py) to
    bust its own cache on.
    """
    urls = result.get("urls") if result.get("status") == "ok" else None
    if not session_id or not urls:
        return

    def _apply(session: dict) -> None:
        existing = session.setdefault("recon_result", {}).setdefault("candidate_urls", [])
        existing_set = set(existing)
        existing.extend(u for u in urls if u not in existing_set)

    reload_merge_save(session_id, _apply)


def wayback_urls(params: dict) -> dict:
    domain = params["domain"]
    cached = cache_get("wayback_urls", domain)
    if cached is not None:
        _persist_candidate_urls(params.get("_session_id"), cached)
        return cached

    # Real, confirmed incident this fixes: the model passed timeout=60 to work around a slow/flaky
    # web.archive.org response, but the hardcoded 45.0 below silently ignored it — the override
    # wasn't wired to anything, so the same failure repeated regardless of what was asked for.
    timeout = float(params.get("timeout") or 45.0)
    query_params = {"url": f"{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": 500}
    # Same local self-heal loop as http_request's own _get_with_transient_retry, for the same
    # failure mode -- confirmed live: web.archive.org returned a transient 503 (it's overloaded,
    # not a real client error) or a read-timeout 4 separate times in one real session; this tool
    # had zero local retry at all before this, escalating straight to the costly LLM-driven 1-Step
    # Retry for something that resolved fine again a couple seconds later. A non-503 HTTP error or
    # a malformed JSON response still fails immediately below, same as before -- only the
    # connection-level/timeout/503-overload cases are worth a fast local retry.
    last_exc: Exception | None = None
    try:
        # web.archive.org's CDX API measured at ~38s for a real query — it succeeds, just slowly;
        # 15s was cutting it off before it could ever respond.
        with httpx.Client(timeout=timeout) as client:
            for attempt in range(_HTTP_REQUEST_RETRY_ATTEMPTS + 1):
                if attempt > 0:
                    time.sleep(_HTTP_REQUEST_RETRY_DELAY_SECONDS)
                try:
                    resp = client.get("https://web.archive.org/cdx/search/cdx", params=query_params)
                    if resp.status_code == 503:
                        last_exc = httpx.HTTPStatusError("503 Service Unavailable from web.archive.org", request=resp.request, response=resp)
                        continue
                    resp.raise_for_status()
                    rows = resp.json()
                    break
                except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError) as exc:
                    last_exc = exc
            else:
                raise last_exc
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    urls = [row[0] for row in rows[1:]] if rows else []  # first row is the column header
    result = {"status": "ok", **declutter_urls(urls)}
    logger.debug(
        "wayback_urls: domain=%s declutter %d -> %d urls (%d static asset, %d duplicate shape)",
        domain, result["raw_count"], result["kept_count"], result["removed_static_asset"], result["removed_duplicate_shape"],
    )
    cache_set("wayback_urls", domain, result)
    _persist_candidate_urls(params.get("_session_id"), result)
    return result


def _latest_common_crawl_cdx_api(client: httpx.Client) -> str | None:
    """Common Crawl publishes a NEW crawl (a new index id, e.g. "CC-MAIN-2024-42") every few
    weeks and eventually retires old ones -- collinfo.json is the public, unauthenticated listing
    of every currently-live index, newest first, so this never hardcodes an id that will
    eventually 404 once that crawl ages out. Cached like every other cache_get/cache_set tool
    result here (agent/tools/cache.py's default TTL), so a whole scan's worth of
    common_crawl_urls calls resolves this exactly once, not once per call.
    """
    cached = cache_get("common_crawl_collinfo", "latest")
    if cached is not None:
        return cached.get("cdx_api")
    resp = client.get("https://index.commoncrawl.org/collinfo.json")
    resp.raise_for_status()
    collections = resp.json()
    if not collections:
        return None
    cdx_api = collections[0].get("cdx-api")
    cache_set("common_crawl_collinfo", "latest", {"cdx_api": cdx_api})
    return cdx_api


def common_crawl_urls(params: dict) -> dict:
    """Common Crawl's own CDX index -- a second, independent historical-URL archive alongside
    wayback_urls, fully free with no API key or account at all (unlike a real Shodan/Censys/
    urlscan.io search, which all need at least a free signup -- this needs none). Real gap this
    closes: Wayback and Common Crawl each crawl the web independently on their own schedule, so a
    URL one archive missed the other sometimes still has, and neither one subsumes the other.

    The response format itself differs from wayback_urls' own CDX API too: Common Crawl's
    output=json is newline-delimited JSON (one JSON object per line), not a single JSON array with
    a header row -- parsed accordingly. A domain with zero captures at all returns a plain HTTP 404
    with a "No Captures found" body (Common Crawl's own documented signal for this, not a real
    error) -- treated as a genuine, empty ok result, not a failure.
    """
    domain = params["domain"]
    cached = cache_get("common_crawl_urls", domain)
    if cached is not None:
        _persist_candidate_urls(params.get("_session_id"), cached)
        return cached

    timeout = float(params.get("timeout") or 45.0)
    try:
        with httpx.Client(timeout=timeout) as client:
            cdx_api = _latest_common_crawl_cdx_api(client)
            if cdx_api is None:
                return {"status": "error", "error": "could not resolve Common Crawl's own current index (collinfo.json returned nothing usable)"}
            query_params = {"url": f"{domain}/*", "output": "json", "collapse": "urlkey", "limit": 500, "fl": "url"}
            resp = client.get(cdx_api, params=query_params)
            if resp.status_code == 404:
                result = {"status": "ok", **declutter_urls([])}
                cache_set("common_crawl_urls", domain, result)
                return result
            resp.raise_for_status()
            urls: list[str] = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    urls.append(json.loads(line)["url"])
                except (json.JSONDecodeError, KeyError):
                    continue
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    result = {"status": "ok", **declutter_urls(sorted(set(urls)))}
    logger.debug(
        "common_crawl_urls: domain=%s declutter %d -> %d urls (%d static asset, %d duplicate shape)",
        domain, result["raw_count"], result["kept_count"], result["removed_static_asset"], result["removed_duplicate_shape"],
    )
    cache_set("common_crawl_urls", domain, result)
    _persist_candidate_urls(params.get("_session_id"), result)
    return result


def shodan_internetdb_lookup(params: dict) -> dict:
    """Free, keyless recon: internetdb.shodan.io returns open ports, CPEs, hostnames, tags and
    known CVEs Shodan has observed for a single IPv4 -- no account, API key, or paid plan needed,
    unlike a real Shodan search (which requires a subscription for anything beyond a couple of
    manual point lookups). Data is refreshed weekly and carries no banners, so treat this as a
    passive enrichment signal, not a live scan -- a 404/empty result means Shodan has nothing on
    file for this IP, not that nothing is open.
    """
    ip = params["ip"]
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        return {"status": "error", "error": f"Not a valid IP address: {ip!r} ({exc})"}

    cached = cache_get("shodan_internetdb_lookup", ip)
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"https://internetdb.shodan.io/{ip}")
            if resp.status_code == 404:
                result = {
                    "status": "ok", "ip": ip, "found": False,
                    "note": "No InternetDB record for this IP -- Shodan hasn't observed it, not proof nothing is open.",
                }
                cache_set("shodan_internetdb_lookup", ip, result)
                return result
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    result = {
        "status": "ok",
        "ip": ip,
        "found": True,
        "ports": data.get("ports", []),
        "hostnames": data.get("hostnames", []),
        "cpes": data.get("cpes", []),
        "tags": data.get("tags", []),
        "vulns": data.get("vulns", []),
    }
    cache_set("shodan_internetdb_lookup", ip, result)
    return result


def otx_passive_dns(params: dict) -> dict:
    """AlienVault OTX (Open Threat Exchange) passive DNS -- every hostname/IP pairing OTX has ever
    observed for this domain, with first/last-seen timestamps. Real gap this closes: crt_sh_lookup/
    subfinder/wayback_urls/common_crawl_urls all surface a subdomain by finding some trace of it
    (a certificate, an archived page); passive DNS instead answers "what has this domain's own DNS
    actually resolved to, historically" -- can surface an old/decommissioned subdomain whose
    hostname was never captured by any of those other passive sources at all, or confirm which IPs
    a subdomain has moved across over time (useful for spotting a stale DNS record pointing at an
    IP the target no longer controls -- a real subdomain-takeover lead).

    Unlike urlscan_search below, OTX has no meaningful anonymous access -- every real endpoint
    requires X-OTX-API-Key, so this tool is simply disabled (a clear, explicit error, not a
    confusing 403 from the raw API) when no key is configured (Settings -> Tool API Keys, free to
    create). params["_api_key"] arrives via agent/core.py's own generic tool_api_keys injection --
    see agent/tools/tool_api_keys.py's TOOL_API_KEY_SPECS entry for this tool.
    """
    domain = params["domain"]
    api_key = params.get("_api_key")
    if not api_key:
        return {
            "status": "error",
            "error": "OTX_API_KEY not configured -- add a free AlienVault OTX API key in Settings -> Tool API Keys (https://otx.alienvault.com/api) to use this tool.",
        }

    cached = cache_get("otx_passive_dns", domain)
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers={"X-OTX-API-KEY": api_key},
            )
            if resp.status_code == 403:
                return {"status": "error", "error": "OTX rejected the configured API key (403) -- check it's still valid in Settings -> Tool API Keys."}
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    records = [
        {
            "hostname": entry.get("hostname"),
            "address": entry.get("address"),
            "record_type": entry.get("record_type"),
            "first_seen": entry.get("first"),
            "last_seen": entry.get("last"),
        }
        for entry in (data.get("passive_dns") or [])
    ]
    result = {"status": "ok", "records": records}
    cache_set("otx_passive_dns", domain, result)
    return result


def urlscan_search(params: dict) -> dict:
    """urlscan.io's own Search API -- every previously-submitted scan (by anyone, public scans
    only) of a page on this domain: the real URL scanned, its resolved IP/ASN, and when. A
    genuinely different signal than a certificate/archive-based subdomain source: this is actual
    live browser telemetry from a real visit to the page at scan time, so it can surface a page
    that never had its own certificate and was never archived, and confirms the domain/IP pairing
    was really live then, not just that a URL string exists somewhere.

    Works with no key at all (urlscan's own public search tier), just on a lower/shared rate limit
    -- unlike otx_passive_dns above, never disabled outright when unconfigured. params["_api_key"]
    (Settings -> Tool API Keys, agent/tools/tool_api_keys.py), when present, raises that limit and
    includes the operator's own private scans in results.
    """
    domain = params["domain"]
    api_key = params.get("_api_key")
    cached = cache_get("urlscan_search", domain)
    if cached is not None:
        return cached

    headers = {"API-Key": api_key} if api_key else {}
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 100},
                headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    scans = []
    for entry in (data.get("results") or []):
        page = entry.get("page") or {}
        task = entry.get("task") or {}
        scans.append({
            "url": page.get("url"),
            "domain": page.get("domain"),
            "ip": page.get("ip"),
            "asn": page.get("asn"),
            "server": page.get("server"),
            "scanned_at": task.get("time"),
        })
    result = {"status": "ok", "total_found": data.get("total"), "scans": scans}
    cache_set("urlscan_search", domain, result)
    return result


def github_code_search(params: dict) -> dict:
    """GitHub's own code-search API (GET /search/code) -- full-text search across every public
    repository's own file contents, not just repo names/descriptions. Real gap this closes: a
    target's own leaked API key/internal hostname/employee email sometimes sits in a public repo
    (a forgotten .env committed once, a config file in a fork) that neither a web search engine nor
    GitHub's own logged-out UI can find -- Google's own indexing of GitHub file CONTENT is
    inconsistent/incomplete, and GitHub gated its own code-search UI behind login years ago, so
    this is the one reliable way to search it at all, not just a convenience over browsing.

    Requires authentication -- GitHub rejects an anonymous /search/code call outright (unlike its
    general search), so this tool is disabled with a clear error when unconfigured. A classic
    Personal Access Token with ZERO scopes checked is enough: the token only proves "a real GitHub
    account", it grants no actual permissions and needs none for searching PUBLIC code. Rate-
    limited hard by GitHub itself: 10 requests/minute for code search specifically (far tighter
    than its own general 30/min search limit, let alone the 5000/hour core API) -- cached like
    every other lookup here so a repeated query within one scan doesn't burn that budget twice.

    `query` is the model's own real GitHub search syntax (qualifiers like `in:file`, `filename:`,
    `org:`, `extension:` all apply -- see GitHub's own code-search documentation), not just a bare
    keyword -- e.g. "target.com in:file" or "\"AKIA\" filename:.env".
    """
    query = params["query"]
    api_key = params.get("_api_key")
    if not api_key:
        return {
            "status": "error",
            "error": "GITHUB_API_KEY not configured -- add a GitHub personal access token (zero scopes needed, it only proves a real account) in Settings -> Tool API Keys to use this tool.",
        }

    cached = cache_get("github_code_search", query)
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": 30},
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if resp.status_code == 401:
                return {"status": "error", "error": "GitHub rejected the configured token (401) -- check it's still valid in Settings -> Tool API Keys."}
            if resp.status_code == 403:
                return {"status": "error", "error": "GitHub rate-limited this request (403) -- code search is capped at 10/minute regardless of token; wait and retry."}
            if resp.status_code == 422:
                error_data = resp.json()
                return {"status": "error", "error": f"GitHub rejected this query ({error_data.get('message') or 'validation failed'}) -- code search needs at least one search term plus a qualifier (e.g. in:file)."}
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    results = [
        {
            "repository": (item.get("repository") or {}).get("full_name"),
            "path": item.get("path"),
            "url": item.get("html_url"),
        }
        for item in (data.get("items") or [])
    ]
    result = {"status": "ok", "total_count": data.get("total_count"), "results": results}
    cache_set("github_code_search", query, result)
    return result


def _whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode(errors="replace")


_WHOIS_REGISTRAR_REFERRAL_PATTERN = re.compile(r"(?im)^\s*(?:Registrar WHOIS Server|ReferralServer|Whois Server)\s*:\s*(\S+)")
_WHOIS_MAX_REGISTRAR_HOPS = 3


def whois_lookup(params: dict) -> dict:
    domain = params["domain"]
    tld = domain.rsplit(".", 1)[-1]

    try:
        referral = _whois_query("whois.iana.org", tld)
        match = re.search(r"^refer:\s*(\S+)", referral, re.MULTILINE)
        server = match.group(1) if match else "whois.iana.org"
        raw = _whois_query(server, domain)

        # A thin gTLD-style registry (whois.nic.io and similar) only ever returns a stub record
        # pointing at the REGISTRAR's own whois server for the real registrant details -- following
        # only the first referral (IANA -> registry) stopped one hop short of that. Real incident
        # this fixes: a live recon pass against *.vimla.io got nothing but "TLD-registry data,
        # registrant details unavailable" for exactly this reason. A thick ccTLD registry
        # (whois.iis.se and similar) is usually already the final answer -- following a second hop
        # there is a safe no-op, since its response won't match this pattern at all.
        seen_servers = {server}
        for _ in range(_WHOIS_MAX_REGISTRAR_HOPS):
            registrar_match = _WHOIS_REGISTRAR_REFERRAL_PATTERN.search(raw)
            if not registrar_match:
                break
            next_server = registrar_match.group(1).strip().rstrip(".")
            if not next_server or next_server in seen_servers:
                break  # already visited -- a referral cycle, not real forward progress
            seen_servers.add(next_server)
            server = next_server
            raw = _whois_query(server, domain)
    except OSError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {"status": "ok", "server": server, "raw": raw}


# --- geoip_lookup / classify_ip_role: real IP geolocation + ASN/org attribution, and the
# deterministic role guess built on top of it -- the backbone of the Recon tab's Geopolitical Map
# and agent/core.py's automatic _update_ip_intel enrichment hook. Real motivation: a domain's
# resolved IP is routinely mistaken for "the target's own server" (a common, confirmed analyst
# habit: paste the domain into whois, treat whatever IP comes back as ground truth) when it's
# actually a CDN/WAF edge node, shared/cloud hosting, or something else entirely unrelated to the
# real origin. This makes that distinction visible automatically, as an honest, confidence-graded
# guess -- never a bare "this IS the target" claim a passive lookup alone can't support. ---

_GEOIP_HTTP_TIMEOUT = 15.0
_IP_API_FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"


def geoip_lookup(params: dict) -> dict:
    """Real IP geolocation + ASN/ISP/org attribution via ip-api.com's free, keyless API (a soft
    45 req/min-per-source-IP rate limit -- a failure here is reported honestly, never retried in a
    tight loop). The only source of country/ASN data anywhere in ASRA -- passive third-party
    enrichment, same posture as shodan_internetdb_lookup/otx_passive_dns (the IP itself leaves this
    box, nothing more sensitive than that).

    Cached (cache_get/cache_set) -- an IP's geolocation/ASN essentially never changes within one
    scan's lifetime, so a second lookup of the same address (agent/core.py's own automatic
    enrichment hook and a later manual model call both wanting it) costs nothing the second time.
    """
    ip = str(params.get("ip") or "").strip()
    if not ip:
        return {"status": "error", "error": "ip is required"}

    cached = cache_get("geoip_lookup", ip)
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=_GEOIP_HTTP_TIMEOUT) as client:
            resp = client.get(f"http://ip-api.com/json/{ip}", params={"fields": _IP_API_FIELDS})
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    if resp.status_code != 200:
        return {"status": "error", "error": f"ip-api.com returned HTTP {resp.status_code} -- likely rate-limited, try again shortly"}
    data = resp.json()
    if data.get("status") != "success":
        return {"status": "error", "error": data.get("message") or "ip-api.com lookup failed"}

    result = {
        "status": "ok", "ip": ip,
        "country": data.get("country", ""), "country_code": data.get("countryCode", ""),
        "region": data.get("regionName", ""), "city": data.get("city", ""),
        "lat": data.get("lat"), "lon": data.get("lon"),
        "isp": data.get("isp", ""), "org": data.get("org", ""), "asn": data.get("as", ""),
    }
    cache_set("geoip_lookup", ip, result)
    return result


# Substring matches against ip-api.com's own isp/org/as strings -- deliberately lowercase,
# case-insensitive (real observed org strings vary: "Cloudflare, Inc", "CLOUDFLARENET",
# "Amazon.com, Inc.", "AMAZON-02"). A CDN/WAF vendor match is the single strongest signal available
# here (that vendor's entire business model IS reverse-proxying someone else's origin) -- the only
# one graded "high" confidence below.
_KNOWN_CDN_WAF_VENDORS = (
    "cloudflare", "akamai", "fastly", "imperva", "incapsula", "sucuri", "stackpath",
    "keycdn", "bunnycdn", "cachefly", "section.io", "cloudinary", "edgecast", "limelight",
    "cdn77", "quic.cloud", "azion", "g-core",
)
# Generic cloud/VPS hosting -- deliberately graded "medium", not "not the target": a real origin
# server is routinely hosted on one of these too. This only means "not distinctively identifying"
# the way a dedicated CDN vendor match is, never "ruled out as the origin".
_KNOWN_CLOUD_HOSTING_VENDORS = (
    "amazon", "aws", "google cloud", "google llc", "microsoft", "azure", "digitalocean",
    "linode", "the constant company", "vultr", "choopa", "ovh", "hetzner", "contabo",
    "scaleway", "alibaba", "oracle cloud", "ionos", "godaddy", "namecheap", "hostinger",
    "bluehost", "dreamhost", "unified layer", "leaseweb", "psychz", "m247", "kamatera",
)


def classify_ip_role(geo: dict, detected_protection_products: list[str] | None = None) -> dict:
    """Confidence-graded guess at what a resolved IP actually IS -- a CDN/WAF edge node, generic
    cloud/VPS hosting, or (by elimination) a likely dedicated/origin server -- never a bare "this is
    the target" claim passive signals alone can prove. Same "verified vs inferred" honesty
    discipline this project already applies to findings (record_finding's own verification field):
    the only techniques that could actually PROVE an IP is the true origin are active ones (a
    direct connection that bypasses DNS/a CDN, a leaked origin IP) -- this stays a labeled guess.

    detected_protection_products is session["recon_result"]["protections"][host] for whichever
    hostname(s) resolve to this IP (agent/core.py's _hostnames_for_ip) -- a WhatWeb/nuclei
    application-layer fingerprint naming an actual CDN/WAF product is stronger evidence than an
    ASN-name guess alone, so it's checked first and cited by name in the reason.
    """
    for product in detected_protection_products or []:
        product_lower = product.lower()
        if any(vendor in product_lower for vendor in _KNOWN_CDN_WAF_VENDORS):
            return {
                "role": "cdn_waf", "confidence": "high",
                "reason": f"WhatWeb/nuclei fingerprinted {product} directly on this host -- a CDN/WAF product, almost certainly not the origin server.",
            }

    org_text = " ".join(filter(None, [geo.get("isp", ""), geo.get("org", ""), geo.get("asn", "")])).lower()
    for vendor in _KNOWN_CDN_WAF_VENDORS:
        if vendor in org_text:
            return {
                "role": "cdn_waf", "confidence": "high",
                "reason": f"IP is registered to {geo.get('isp') or geo.get('org')} -- a known CDN/WAF provider, almost certainly a reverse-proxy edge, not the origin.",
            }
    for vendor in _KNOWN_CLOUD_HOSTING_VENDORS:
        if vendor in org_text:
            return {
                "role": "cloud_hosting", "confidence": "medium",
                "reason": f"IP is registered to {geo.get('isp') or geo.get('org')} -- generic cloud/VPS hosting. Could be the real origin (many are), or could sit behind another layer you haven't found yet -- not distinctive either way.",
            }

    return {
        "role": "likely_origin", "confidence": "medium",
        "reason": "Not registered to any known CDN/WAF or major cloud-hosting provider -- the strongest passive signal available that this is a dedicated/on-prem server, not proof. Confirm with an active technique (e.g. a direct connection that bypasses DNS) before treating it as certain.",
    }


# --- recon/scan with light touch on the target ---


def _is_nxdomain_errno(errno_value: int | None) -> bool:
    """True for the two getaddrinfo() errno shapes this environment's resolver actually returns
    for "this hostname simply doesn't exist" (EAI_NONAME, and — confirmed live, three separate
    real bug-bounty sessions, dozens of occurrences — EAI_NODATA just as often). Neither is
    fixable by a corrected argument, so a caller treating this as True should return a clean,
    non-retryable negative result instead of status="error" (which the 1-Step Retry mechanism,
    agent/core.py's _RETRYABLE_STATUSES, would otherwise burn a full LLM round-trip resending).
    A real resolver-side hiccup (EAI_AGAIN, "Temporary failure in name resolution") is a
    genuinely different, still-worth-retrying case and must NOT match here.
    """
    eai_noname = getattr(socket, "EAI_NONAME", None)
    eai_nodata = getattr(socket, "EAI_NODATA", None)
    return errno_value is not None and errno_value in (eai_noname, eai_nodata)


def _dns_resolution_errno(exc: BaseException) -> int | None:
    """Walks an exception's own __cause__/__context__ chain looking for the real socket.gaierror
    underneath -- httpx.ConnectError/httpcore.ConnectError wrap DNS failures without exposing
    errno directly on themselves (confirmed live: httpcore.ConnectError's own sole args[0] IS the
    original socket.gaierror object, not a flattened string), so a bare str(exc) substring match
    would be fragile across httpx/httpcore versions. Returns None when no gaierror is found
    anywhere in the chain (a genuinely different failure, e.g. a real TCP-level refusal).
    """
    seen: BaseException | None = exc
    for _ in range(5):
        if isinstance(seen, socket.gaierror):
            return seen.errno
        args = getattr(seen, "args", None)
        if args and isinstance(args[0], socket.gaierror):
            return args[0].errno
        seen = getattr(seen, "__cause__", None) or getattr(seen, "__context__", None)
        if seen is None:
            break
    return None


def dns_lookup(params: dict) -> dict:
    domain = params["domain"]
    try:
        # to_ascii_hostname: a Cyrillic (or any other non-ASCII) domain must be converted to its
        # punycode form before the real resolver call -- confirmed live, socket.getaddrinfo()
        # raises EAI_NONAME on the raw Unicode form even for a real, live domain. `domain` itself
        # (not the converted form) is what error messages below still reference -- the operator
        # typed the Unicode form, that's what should read back to them.
        results = socket.getaddrinfo(to_ascii_hostname(domain), None)
    except socket.gaierror as exc:
        if _is_nxdomain_errno(exc.errno):
            return {
                "status": "ok", "ips": [], "resolved": False,
                "note": f"{domain} does not resolve (no such host) — a real, negative result, not a tool failure",
            }
        return {"status": "error", "error": describe_exception(exc)}
    return {"status": "ok", "ips": sorted({r[4][0] for r in results}), "resolved": True}


# A "*.example.com" wildcard-scope project (see validate_scope_entry()) needs more than crt_sh_
# lookup's passive certificate-transparency data — a subdomain that never got its own TLS cert
# (an internal tool, an old staging host) never shows up there. This is the active side of the
# same job: try a wordlist of the prefixes real orgs actually use, over plain DNS, no external
# API/rate limit involved. Deliberately not exhaustive (no brute-force-from-a-huge-wordlist mode)
# — this is meant to run in a few seconds as part of a normal recon pass, not as its own long job.
_COMMON_SUBDOMAIN_PREFIXES = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp",
    "api", "api-docs", "admin", "administrator", "portal", "dashboard", "panel",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "demo", "sandbox", "beta", "alpha", "preview", "old", "legacy", "backup",
    "app", "apps", "mobile", "m", "web",
    "vpn", "remote", "sso", "auth", "login", "secure", "id",
    "git", "gitlab", "github", "jenkins", "ci", "jira", "confluence", "wiki",
    "cdn", "static", "assets", "img", "images", "media", "files", "upload", "download",
    "blog", "shop", "store", "support", "help", "docs", "status", "forum", "community",
    "ns1", "ns2", "mx", "cpanel", "whm", "webdisk",
    "internal", "intranet", "corp", "office", "monitor", "grafana", "kibana",
]


# Bounds for subdomain_enum's own resolution pass. tool_tier=1 native functions own their own
# timeout (registry.py's ToolSpec docstring) -- runner.py enforces NO external kill switch here,
# unlike a tier-2 subprocess -- so a large assigned wordlist (see get_assigned_wordlist("subdomain_
# enum") below) resolved one hostname at a time could otherwise hang the whole agent loop for hours.
# Concurrency + a hard wall-clock deadline are what actually make a real SecLists-sized wordlist
# (thousands of prefixes) safe to point this at, not just a bigger default list.
_SUBDOMAIN_ENUM_MAX_PREFIXES = int(os.getenv("SUBDOMAIN_ENUM_MAX_PREFIXES", "5000"))
_SUBDOMAIN_ENUM_MAX_WORKERS = int(os.getenv("SUBDOMAIN_ENUM_MAX_WORKERS", "30"))
_SUBDOMAIN_ENUM_HARD_DEADLINE_SECONDS = float(os.getenv("SUBDOMAIN_ENUM_HARD_DEADLINE_SECONDS", "90"))


def _resolve_subdomain_candidate(hostname: str) -> set[str] | None:
    try:
        results = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, socket.timeout):
        return None
    return {r[4][0] for r in results}


def subdomain_enum(params: dict) -> dict:
    """Actively resolves a wordlist of subdomain prefixes against the given base domain -- the
    active counterpart to crt_sh_lookup/subfinder's passive discovery. Meant for a
    "*.example.com" wildcard-scope target, but works for any domain.

    Prefix source: an operator-assigned wordlist (Settings -> Wordlists, role "subdomain_enum" --
    e.g. setup_tools.sh's own installed SecLists subdomains-top1million-5000.txt) when one is
    configured, otherwise the small ~35-entry built-in list below. Real gap the assigned-wordlist
    path closes: subfinder's own docstring already documents that neither crt_sh_lookup (needs a
    TLS cert) nor this tool's old fixed prefix list ever surfaces a forgotten staging/internal host
    with neither -- a real, much larger wordlist is the only thing that finds one.

    Wildcard-DNS guard: resolves one random, near-certainly-nonexistent prefix first. If THAT
    resolves too, the domain answers every hostname the same way (a wildcard DNS record) and every
    other "found" result below would just be that same catch-all IP repeated, not a real distinct
    host -- filtered out rather than reported as noise.
    """
    domain = params["domain"]
    assigned_path = get_assigned_wordlist("subdomain_enum")
    source = "built-in"
    prefixes = _COMMON_SUBDOMAIN_PREFIXES
    if assigned_path:
        try:
            with open(assigned_path, encoding="utf-8", errors="ignore") as f:
                custom_prefixes = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if custom_prefixes:
                prefixes = custom_prefixes[:_SUBDOMAIN_ENUM_MAX_PREFIXES]
                source = assigned_path
        except OSError as exc:
            logger.debug("subdomain_enum: assigned wordlist %r unreadable (%s) -- falling back to built-in prefix list", assigned_path, exc)

    wildcard_probe = f"asra-wildcard-check-{uuid.uuid4().hex[:12]}.{domain}"
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    wildcard_ips = _resolve_subdomain_candidate(wildcard_probe)
    logger.debug("subdomain_enum: domain=%s source=%s prefixes=%d wildcard_dns=%s", domain, source, len(prefixes), bool(wildcard_ips))

    found = []
    deadline_hit = False
    start = time.monotonic()
    pool = ThreadPoolExecutor(max_workers=_SUBDOMAIN_ENUM_MAX_WORKERS)
    try:
        futures = {pool.submit(_resolve_subdomain_candidate, f"{prefix}.{domain}"): prefix for prefix in prefixes}
        for future in as_completed(futures):
            if time.monotonic() - start > _SUBDOMAIN_ENUM_HARD_DEADLINE_SECONDS:
                deadline_hit = True
                break
            prefix = futures[future]
            ips = future.result()
            if not ips or (wildcard_ips and ips == wildcard_ips):
                continue
            found.append({"host": f"{prefix}.{domain}", "ips": sorted(ips)})
    finally:
        socket.setdefaulttimeout(old_timeout)
        pool.shutdown(wait=False, cancel_futures=True)

    elapsed = round(time.monotonic() - start, 1)
    logger.debug("subdomain_enum: domain=%s tried=%d found=%d elapsed=%ss deadline_hit=%s", domain, len(prefixes), len(found), elapsed, deadline_hit)
    return {
        "status": "ok",
        "domain": domain,
        "source": source,
        "tried": len(prefixes),
        "found": found,
        "wildcard_dns": bool(wildcard_ips),
        "deadline_hit": deadline_hit,
    }


def http_request(params: dict) -> dict:
    url = params["target"]
    # Real, confirmed incident this fixes: the schema accepted (and a model correctly tried to
    # set) follow_redirects=False to test an open-redirect PoC against a deliberately
    # non-resolving redirect target, but the client below unconditionally hardcoded True — the
    # client actually tried to follow there and failed DNS before the redirect could even be
    # detected, and the override was silently ignored (this key wasn't even wired to anything).
    follow_redirects = params.get("follow_redirects", True)
    # Real, confirmed incident this fixes: a subagent's own OSINT legwork against web.archive.org's
    # CDX search API (broad wildcard queries there are known to genuinely take 20-60s, the exact
    # reason wayback_urls got this same override) hit this tool's fixed 10s hard deadline 9 times in
    # one session -- burning most of that subagent's whole time budget on doomed 1-Step Retries that
    # just resent the identical, still-too-slow query. Unlike wayback_urls (a fixed, known-slow
    # third-party endpoint), http_request also hits the real scan target, so the default here stays
    # the short, fast-failing 10s -- this is strictly an opt-in override for a call the model already
    # expects to be slow, never a silent behavior change for the common case.
    timeout = float(params.get("timeout") or _HTTP_TIMEOUT)
    client_kwargs = _target_client_kwargs(params)
    fingerprint_bypass_used = False
    try:
        with httpx.Client(timeout=timeout, follow_redirects=follow_redirects, **client_kwargs) as client:
            resp = _get_with_transient_retry(client, url, timeout)
    except httpx.RemoteProtocolError:
        # Every local self-heal retry inside _get_with_transient_retry already failed identically --
        # see _browser_fingerprint_fallback_get's own docstring for why this specific exception
        # (never a plain timeout/_HardDeadlineExceeded) is worth one more attempt with a real
        # browser's TLS/HTTP2 fingerprint before giving up entirely.
        logger.debug("native: http_request target=%r hit RemoteProtocolError after local retries, trying browser-fingerprint fallback (%s)", url, _IMPERSONATE_BROWSER)
        try:
            resp = _browser_fingerprint_fallback_get(
                url, client_kwargs.get("headers") or {}, timeout, client_kwargs.get("verify", False), follow_redirects,
            )
        except curl_requests.exceptions.RequestException as exc:
            logger.debug("native: http_request target=%r still blocked at the transport layer even with browser fingerprint: %s", url, exc)
            return {
                "status": "error",
                "error": (
                    "connection dropped by the target even with a real browser TLS/HTTP2 fingerprint "
                    f"(curl-impersonate {_IMPERSONATE_BROWSER}) -- this looks like a genuine WAF/network "
                    f"block on this target, not a client-fingerprint issue: {exc}"
                ),
            }
        logger.debug("native: http_request target=%r succeeded via browser-fingerprint fallback", url)
        fingerprint_bypass_used = True
    except httpx.HTTPError as exc:
        # Same non-retryable "ok, real negative result" treatment dns_lookup already gives a
        # genuine NXDOMAIN -- confirmed live, three real occurrences in one session
        # (three different nonexistent subdomains of the same target), each costing a doomed
        # 1-Step Retry (no corrected URL/argument makes a nonexistent hostname resolve) before this
        # fix; without it, http_request's DNS failures fell straight into the generic
        # status="error" branch below with no NXDOMAIN-awareness at all.
        if _is_nxdomain_errno(_dns_resolution_errno(exc)):
            return {
                "status": "ok", "resolved": False,
                "note": f"{url} does not resolve (no such host) — a real, negative result, not a tool failure",
            }
        return {"status": "error", "error": describe_exception(exc)}

    security_headers = {h: resp.headers.get(h) for h in _SECURITY_HEADERS_CHECKLIST if h in resp.headers}
    result = {
        "status": "ok",
        "status_code": resp.status_code,
        "security_headers": security_headers,
        "body_preview": resp.text[:2000],
    }
    if fingerprint_bypass_used:
        # Genuinely interesting recon signal in its own right (the target actively fingerprints and
        # blocks non-browser HTTP clients) -- surfaced in the result so the model can reason about
        # or record it, not just silently swallowed once the request itself succeeds.
        result["client_fingerprint_bypass_used"] = True

    detectors = {
        "reflected_payload_detected": passive_detectors.detect_reflected_payload(url, resp.text),
        "sql_error_detected": passive_detectors.detect_sql_error(url, resp.text),
        "open_redirect_detected": passive_detectors.detect_open_redirect(
            url, [(hop.status_code, dict(hop.headers)) for hop in resp.history],
        ),
        "command_injection_detected": passive_detectors.detect_command_injection(url, resp.text),
    }
    for field, value in detectors.items():
        if value is not None:
            result[field] = value
    return result


def tcp_port_check(params: dict) -> dict:
    host = params["target"]
    port = int(params["port"])
    timeout = float(params.get("timeout", 5))

    # Same local self-heal loop as http_request's own _get_with_transient_retry, for the identical
    # failure mode -- a socket.gaierror here is the same transient DNS flip-flop (this project's own
    # real incident: the same hostname alternating between resolving fine and "[Errno -5] No address
    # associated with hostname" several times within a few minutes), but this tool used to have zero
    # local retry at all -- a bare socket.connect_ex() with a single except, unlike http_request's
    # tuned loop. Every occurrence used to escalate straight to the costly LLM-driven 1-Step Retry
    # for something that resolved fine again moments later. Reuses http_request's own retry knobs
    # (_HTTP_REQUEST_RETRY_ATTEMPTS/_DELAY_SECONDS) rather than a second, near-duplicate pair of
    # constants for the same underlying phenomenon.
    last_exc: socket.gaierror | None = None
    for attempt in range(_HTTP_REQUEST_RETRY_ATTEMPTS + 1):
        if attempt > 0:
            time.sleep(_HTTP_REQUEST_RETRY_DELAY_SECONDS)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            return {"status": "ok", "port": port, "open": result == 0}
        except socket.gaierror as exc:
            last_exc = exc
        finally:
            sock.close()
    return {"status": "error", "error": str(last_exc)}


def ssl_cert_info(params: dict) -> dict:
    host = params["target"]
    port = int(params.get("port", 443))

    try:
        # ssl.get_server_certificate()'s own ca_certs=None default deliberately never validates
        # trust or hostname -- this tool's entire job is reporting what certificate a host is
        # presenting, which matters just as much (arguably more, for a pentest) when that
        # certificate is self-signed, expired, or hostname-mismatched. The previous
        # ssl.create_default_context()-based handshake couldn't even complete in that case, making
        # this tool structurally unable to inspect precisely the misconfigured certs an operator
        # most wants to see -- confirmed live: a real in-scope host with an incomplete cert chain
        # failed every ssl_cert_info attempt with CERTIFICATE_VERIFY_FAILED, and the model's own
        # verify=False override attempts had nothing to bind to.
        pem = ssl.get_server_certificate((host, port), timeout=10)
    except (OSError, ssl.SSLError) as exc:
        # "target" echoed back here (this tool has no other "command"-shaped field a native tier-1
        # function would normally carry) is what lets interpret_ssl_cert_info_failure below tell a
        # bare-IP handshake failure apart from a real hostname one -- see that function's docstring.
        return {"status": "error", "error": describe_exception(exc), "target": host}

    # SSLSocket.getpeercert()'s parsed-dict form is only ever populated for a certificate that was
    # actually validated -- Python's own ssl module returns {} otherwise, which is exactly the
    # trust-dependent behavior the fetch above exists to route around. ssl._test_decode_cert parses
    # the same PEM into that identical dict shape regardless of trust (live-verified against a real
    # expired-certificate host). Private API (leading underscore) -- the stdlib has no public
    # equivalent for decoding an unvalidated certificate into this shape -- but it has been stable
    # across Python versions for long enough that other real-world tools already rely on it for
    # this exact case.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
        f.write(pem)
        pem_path = f.name
    try:
        cert = ssl._ssl._test_decode_cert(pem_path)
    except (AttributeError, ssl.SSLError) as exc:
        return {"status": "error", "error": f"could not decode fetched certificate: {exc}"}
    finally:
        os.unlink(pem_path)

    return {
        "status": "ok",
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [v for k, v in cert.get("subjectAltName", [])],
    }


def interpret_ssl_cert_info_failure(result: dict) -> str | None:
    """ssl_cert_info against a bare IP address that's actually a CDN/proxy edge (Cloudflare and
    similar) reliably fails the TLS handshake -- the proxy relies on SNI (the hostname a client
    connects "as") to route to the right origin/certificate, and a bare IP has no meaningful SNI
    value to offer, so it rejects the handshake outright. Confirmed live: two separate ssl_cert_info
    calls against the same Cloudflare edge IP both failed with the identical
    SSLV3_ALERT_HANDSHAKE_FAILURE, deterministically -- a retry against the same IP can never fix
    this (it's not transient), and the raw OpenSSL error text gives the model no hint that the real
    fix is simply "use the hostname, not the IP". Same registration shape as this file's
    interpret_arjun_timeout / builders/wpscan.py's interpret_wpscan_timeout -- None whenever the
    failure isn't this specific, recognizable shape.
    """
    if result.get("status") != "error":
        return None
    error = str(result.get("error") or "")
    if "HANDSHAKE_FAILURE" not in error.upper():
        return None
    target = str(result.get("target") or "")
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return None  # a real hostname's own handshake failure has a different likely cause
    return (
        f"TLS handshake failed against the bare IP address {target!r}. If this address is a "
        "CDN/proxy edge (Cloudflare and similar), that's expected: the proxy relies on SNI (the "
        "hostname you connect as) to route to the right certificate/origin, and a bare IP offers no "
        "meaningful SNI value. Retrying this exact IP will fail the same way again -- retry against "
        "the real hostname that resolves to this IP instead, so the correct SNI is sent."
    )


_SENSITIVE_PATHS = [
    "/.git/config",
    "/.git/HEAD",
    "/.env",
    "/.DS_Store",
    "/backup.zip",
    "/.svn/entries",
    "/docker-compose.yml",
    "/.aws/credentials",
    "/wp-config.php.bak",
    "/config.php.bak",
]


def common_exposure_scan(params: dict) -> dict:
    base_url = params["target"].rstrip("/")

    exposed = []
    try:
        with httpx.Client(timeout=8.0, follow_redirects=False, **_target_client_kwargs(params)) as client:
            for path in _SENSITIVE_PATHS:
                try:
                    resp = _with_hard_deadline(lambda p=path: client.get(base_url + p), 8.0)
                except _HardDeadlineExceeded as exc:
                    # Host is unreachable -- every remaining path would hit the identical wall,
                    # so stop here instead of paying the same hard deadline N more times.
                    return {"status": "error", "error": f"target unreachable, stopped after 1 of {len(_SENSITIVE_PATHS)} paths: {exc}"}
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200:
                    exposed.append({"path": path, "status_code": resp.status_code, "content_length": len(resp.content)})
    except Exception as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {"status": "ok", "exposed_paths": exposed}


_GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]
# Read-only introspection query -- enough to prove introspection is enabled, preview the schema,
# AND name every real query/mutation field (one level of args each) so a later authz/batching probe
# has real material to build a targeted call from. Still deliberately bounded (one level of args,
# no recursive walk of each arg's own type) -- the same "prove + preview, not exhaustive" philosophy
# as before, just one level deeper; this project has no GraphQL client dependency and doesn't need
# one for this.
_GRAPHQL_INTROSPECTION_QUERY = {"query": "{__schema{queryType{name fields{name args{name}}} mutationType{fields{name args{name}}} types{name kind}}}"}
_OPENAPI_PATHS = ["/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs", "/swagger-ui/index.html"]


def api_schema_discovery(params: dict) -> dict:
    """A web API's whole surface is sometimes free: a live GraphQL introspection query or an
    exposed swagger/openapi spec leaks every real mutation/type/field/endpoint at once — turning
    "guess the routes" into "read the routes". Only ever reports a path that actually proved
    something (introspection genuinely returned schema data, or a spec file genuinely returned
    200) — a dead/404 path is silently skipped, same tolerance common_exposure_scan already has
    for the paths in its own list.

    Each graphql_endpoints entry's "queryable_fields"/"mutations" (name + one level of arg names)
    is the real material graphql_authz_probe/graphql_batching_probe need to build a targeted call
    from — a field-level authz check or a batching probe is only as good as the field name/args
    it's actually pointed at, never a guess.
    """
    base_url = params["target"].rstrip("/")
    graphql_endpoints = []
    openapi_specs = []

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params)) as client:
            for path in _GRAPHQL_PATHS:
                try:
                    resp = _with_hard_deadline(lambda p=path: client.post(base_url + p, json=_GRAPHQL_INTROSPECTION_QUERY), _HTTP_TIMEOUT)
                except _HardDeadlineExceeded as exc:
                    return {"status": "error", "error": f"target unreachable: {exc}"}
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                try:
                    body = resp.json()
                except ValueError:
                    continue
                schema = (body.get("data") or {}).get("__schema") if isinstance(body, dict) else None
                if schema:
                    query_type = schema.get("queryType") or {}
                    mutation_type = schema.get("mutationType") or {}

                    def _fields_of(type_obj: dict) -> list[dict]:
                        return [
                            {"name": f.get("name"), "args": [a.get("name") for a in (f.get("args") or []) if a.get("name")]}
                            for f in (type_obj.get("fields") or []) if f.get("name")
                        ][:_MAX_MATCHES]

                    graphql_endpoints.append(
                        {
                            "path": path,
                            "introspection_enabled": True,
                            "sample_types": [t.get("name") for t in schema.get("types", []) if t.get("name")][:_MAX_MATCHES],
                            # Real, name+arg material for graphql_authz_probe/graphql_batching_probe to
                            # build a targeted call from, instead of the model guessing field names by hand.
                            "queryable_fields": _fields_of(query_type),
                            "mutations": _fields_of(mutation_type),
                        }
                    )

            for path in _OPENAPI_PATHS:
                try:
                    resp = _with_hard_deadline(lambda p=path: client.get(base_url + p), _HTTP_TIMEOUT)
                except _HardDeadlineExceeded as exc:
                    return {"status": "error", "error": f"target unreachable: {exc}"}
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200:
                    openapi_specs.append({"path": path, "status_code": resp.status_code, "content_preview": resp.text[:2000]})
    except Exception as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {"status": "ok", "graphql_endpoints": graphql_endpoints, "openapi_specs": openapi_specs}


def favicon_hash(params: dict) -> dict:
    base_url = params["target"].rstrip("/")
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True, **_target_client_kwargs(params)) as client:
            resp = _with_hard_deadline(lambda: client.get(base_url + "/favicon.ico"), 8.0)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    if resp.status_code != 200 or not resp.content:
        return {"status": "ok", "favicon_found": False}

    # Shodan's http.favicon.hash recipe: base64-encode, then 32-bit murmur3.
    b64 = base64.encodebytes(resp.content)
    favicon_hash_value = mmh3.hash(b64)
    return {
        "status": "ok",
        "favicon_found": True,
        "mmh3_hash": favicon_hash_value,
        # Ready-to-follow Shodan dork for this exact hash -- the actual payoff of computing it at
        # all (hunting other infrastructure serving the same favicon, e.g. phishing clones or a
        # shared C2/tech stack) requires this precise query syntax; handing back the raw int alone
        # left that step for the model/operator to reconstruct from memory instead.
        "shodan_search_url": f"https://www.shodan.io/search?query=http.favicon.hash%3A{favicon_hash_value}",
    }


_SECURITY_HEADERS_CHECKLIST = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def security_headers_audit(params: dict) -> dict:
    url = params["target"]
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params)) as client:
            resp = _with_hard_deadline(lambda: client.get(url), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {
        "status": "ok",
        "headers_present": {header: header in resp.headers for header in _SECURITY_HEADERS_CHECKLIST},
    }


# Fixed, never-registered value — guaranteed to share nothing with any real target's own
# domain/scheme/structure. A real, observed incident: a model tested CORS reflection only with
# nuclei's cors-misconfig template, which generates a random label under the TARGET'S OWN domain
# (e.g. "https://<random>.vimla.se" for a target on vimla.se) — every one of those passing only
# proves the server trusts its own subdomains, a materially narrower and often-intentional
# pattern, but the model wrote it up as "reflects any arbitrary origin". This tool exists so that
# distinction is a real, deterministic fact from two real HTTP responses, not something a model
# has to remember to test itself.
_CORS_UNRELATED_TEST_ORIGIN = "https://asra-unrelated-origin-check.invalid"


def _cors_probe(target: str, origin: str, method: str, params: dict) -> tuple[bool | None, bool]:
    """One real request. Returns (reflected, allows_credentials).

    reflected: True/False is a definitive answer (the response did/didn't reflect this exact
    origin); None means the probe itself failed (network error, timeout, blocked) — NOT the same
    thing as a confirmed "no", and callers must never conflate the two: reading a failed probe as
    "confirmed not reflected" would silently narrow (or hide) a real wildcard CORS bug just
    because one request happened to not go through.

    allows_credentials: whether this SAME response also sent Access-Control-Allow-Credentials:
    true — a browser will only actually let cross-origin JS read a CREDENTIALED (cookie/session)
    response when BOTH that header AND an origin-reflecting ACAO are present; a reflected origin
    alone only exposes non-credentialed (public) data. Deliberately False (never True) when ACAO
    is the literal wildcard "*", even if the server also sent Access-Control-Allow-Credentials:
    true — real browsers hard-reject that exact combination for a credentialed request (the spec
    requires an EXACT origin echo, not "*", before credentials are ever honored), so reporting
    True there would overstate what a real attacker could actually do. Always a concrete bool
    (False, not None, when the probe itself failed or nothing was reflected) — meaningless on its
    own when reflected isn't True, but returned unconditionally so callers never have to
    special-case None-vs-False here on top of the reflected tri-state.
    """
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params)) as client:
            headers = {"Origin": origin}
            if method == "OPTIONS":
                headers["Access-Control-Request-Method"] = "GET"
            resp = _with_hard_deadline(lambda: client.request(method, target, headers=headers), _HTTP_TIMEOUT)
    except httpx.HTTPError:
        return None, False
    # A literal "*" counts as reflecting THIS origin too — real incident this fixes: a target
    # sending a static Access-Control-Allow-Origin: * (never echoing the actual Origin sent) came
    # back "no_origin_reflection_detected" from every probe (neither the same-suffix nor the
    # unrelated origin string ever equals the literal "*"), completely missing a real, live
    # wildcard CORS bug — the single most permissive answer possible, not the absence of one.
    acao = resp.headers.get("access-control-allow-origin")
    reflected = acao == origin or acao == "*"
    allows_credentials = acao == origin and resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    return reflected, allows_credentials


def _cors_reflected_origin(target: str, origin: str, params: dict) -> tuple[bool | None, bool]:
    """(reflected, allows_credentials) for this origin. reflected is True if EITHER a plain GET or
    an OPTIONS preflight (Access-Control-Request-Method: GET) reflects it — some servers only ever
    attach CORS headers to the preflight response, not to a simple GET, and only testing one shape
    can silently miss a real reflection. None only when BOTH probes failed outright (no answer
    from either); a real False needs at least one probe to have actually gotten a response that
    didn't reflect it. allows_credentials is taken from whichever probe actually reflected (GET
    checked first); if neither did, from whichever probe at least got a real answer — moot in that
    case since reflected isn't True, but never left ambiguous either.
    """
    get_reflected, get_credentials = _cors_probe(target, origin, "GET", params)
    if get_reflected:
        return True, get_credentials
    options_reflected, options_credentials = _cors_probe(target, origin, "OPTIONS", params)
    if options_reflected:
        return True, options_credentials
    if get_reflected is None and options_reflected is None:
        return None, False
    return False, (get_credentials or options_credentials)


def cors_check(params: dict) -> dict:
    """Deterministic CORS boundary test — fires the SAME request (GET and OPTIONS preflight, in
    case a server only reflects on one of them) twice over: once with an Origin that shares the
    target's own domain (a random label under it, same shape as nuclei's cors-misconfig
    template), once with an Origin that shares NOTHING with the target at all (a fixed, unrelated
    value). Reports which ones the server actually reflected back in Access-Control-Allow-Origin,
    as real fact from real responses — "inconclusive" (never a silent false negative) when a
    probe couldn't even get an answer, rather than reading a failed HTTP request as a confirmed
    "not reflected". Call this before ever describing a CORS finding as "reflects any origin" —
    reflecting only the same-suffix origin is a materially narrower, often-intentional "trusts
    its own subdomains" pattern, not a true wildcard bug, and record_finding will reject a
    "qualifying" verdict for a CORS finding on a host this tool has already shown that pattern
    for (unless real subdomain-takeover evidence is separately documented).

    Also reports allows_credentials — whether the response that reflected the unrelated Origin
    also sent Access-Control-Allow-Credentials: true, the SECOND, separate gate a real browser
    enforces before letting cross-origin JS actually read a credentialed (cookie/session)
    response — reflecting the origin alone only ever exposes non-authenticated/public data. None
    when unrelated_reflected isn't True (the question is moot — nothing is being exposed cross-
    origin at all in that case). If this project has identity credentials configured and
    allows_credentials is True here, cors_credentialed_check can attempt the real credentialed
    cross-origin read as concrete proof, not just an inference from these headers.
    """
    target = params["target"]
    hostname = urlsplit(target).hostname or ""
    same_suffix_origin = f"https://{uuid.uuid4().hex[:10]}.{hostname}"

    same_suffix_reflected, _same_suffix_allows_credentials = _cors_reflected_origin(target, same_suffix_origin, params)
    unrelated_reflected, unrelated_allows_credentials = _cors_reflected_origin(target, _CORS_UNRELATED_TEST_ORIGIN, params)

    if unrelated_reflected is True:
        verdict = "reflects_any_origin"
    elif unrelated_reflected is None or same_suffix_reflected is None:
        # At least one probe never got a real answer — report that honestly instead of guessing;
        # the record_finding gate must never treat this as a confirmed narrow/negative result.
        verdict = "inconclusive"
    elif same_suffix_reflected is True:
        verdict = "reflects_own_subdomains_only"
    else:
        verdict = "no_origin_reflection_detected"

    return {
        "status": "ok",
        "hostname": hostname,
        "verdict": verdict,
        "same_suffix_origin_tested": same_suffix_origin,
        "same_suffix_reflected": same_suffix_reflected,
        "unrelated_origin_tested": _CORS_UNRELATED_TEST_ORIGIN,
        "unrelated_reflected": unrelated_reflected,
        "allows_credentials": unrelated_allows_credentials if unrelated_reflected else None,
    }


def cors_credentialed_check(params: dict) -> dict:
    """The real, deterministic simulation of the actual CORS attack primitive -- not a guess, not
    a headless browser, just the exact request a victim's browser would make from a malicious page
    hosted at cors_check's own unrelated test origin, replayed with `identity`'s REAL logged-in
    session/cookies attached (the same credential store authenticated_request already uses), and
    the real response read back. No browser is needed to know whether it would expose this
    response to cross-origin JS -- that decision is a deterministic function of the response's own
    Access-Control-Allow-Origin/-Credentials headers versus the request's Origin, nothing more, so
    replicating the exact request server-side and checking those same headers on the real reply IS
    a faithful simulation of what a real victim's browser would do, not an approximation of it.

    Only call this once cors_check has already shown verdict="reflects_any_origin" AND
    allows_credentials=True for this same host -- calling it before that (or when either is false)
    can only ever end in confirmed_credentialed_cross_origin_read=False, since the anonymous
    prerequisite it depends on was never met; cors_check's own result already tells you whether
    it's worth calling this at all. `identity` must be one of this project's configured identities
    (see authenticated_request) -- returns an error naming the missing identity otherwise, same
    contract as authenticated_request's own credential-lookup failure.

    Gated exactly like authenticated_request (exploitation allowlist + human-approved session) --
    this is a real authenticated request against a live target using a real test account's actual
    session, not a read-only probe, and gets the exact same safety treatment.
    """
    target = params["target"]
    identity = params["identity"]
    hostname = urlsplit(target).hostname or ""
    session_id = params.get("_session_id")
    client = _get_authenticated_client(session_id, identity, params)
    if isinstance(client, dict):
        return client

    try:
        resp = _with_hard_deadline(lambda: client.get(target, headers={"Origin": _CORS_UNRELATED_TEST_ORIGIN}), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    acao = resp.headers.get("access-control-allow-origin")
    acac = resp.headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    # Same exact-origin-only rule as _cors_probe's own allows_credentials — a literal "*" ACAO
    # never grants a credentialed read in a real browser, no matter what ACAC says, so it must
    # never count as "confirmed" here either.
    confirmed = acao == _CORS_UNRELATED_TEST_ORIGIN and acac
    return {
        "status": "ok",
        "hostname": hostname,
        "identity": identity,
        "origin_used": _CORS_UNRELATED_TEST_ORIGIN,
        "status_code": resp.status_code,
        "confirmed_credentialed_cross_origin_read": confirmed,
        # Real evidence for the report only when the read is actually confirmed — same 2000-char
        # cap as authenticated_request's own body_preview, real PoC content without dumping an
        # unbounded response into session.json for a probe that didn't even prove anything.
        "body_preview": resp.text[:2000] if confirmed else None,
    }


def _b64url_json(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def jwt_decode(params: dict) -> dict:
    token = params["token"]
    parts = token.split(".")
    if len(parts) < 2:
        return {"status": "error", "error": "not a JWT-shaped token (expected at least header.payload)"}

    try:
        header = _b64url_json(parts[0])
        payload = _b64url_json(parts[1])
    except (ValueError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {"status": "ok", "header": header, "payload": payload}


_COMMENT_PATTERN = re.compile(r"<!--(.*?)-->", re.DOTALL)
_HIDDEN_INPUT_PATTERN = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
_SCRIPT_SRC_PATTERN = re.compile(r'<script[^>]*\bsrc=["\']([^"\']+)["\']', re.IGNORECASE)
_LINK_HREF_PATTERN = re.compile(r'<link[^>]*\bhref=["\']([^"\']+)["\']', re.IGNORECASE)
_META_TAG_PATTERN = re.compile(r"<meta[^>]*>", re.IGNORECASE)
_MAX_MATCHES = 50


def view_source(params: dict) -> dict:
    url = params["target"]
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params)) as client:
            resp = _with_hard_deadline(lambda: client.get(url), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    html = resp.text
    return {
        "status": "ok",
        "comments": [c.strip() for c in _COMMENT_PATTERN.findall(html)][:_MAX_MATCHES],
        "hidden_inputs": _HIDDEN_INPUT_PATTERN.findall(html)[:_MAX_MATCHES],
        "script_src": _SCRIPT_SRC_PATTERN.findall(html)[:_MAX_MATCHES],
        "link_href": _LINK_HREF_PATTERN.findall(html)[:_MAX_MATCHES],
        "meta_tags": _META_TAG_PATTERN.findall(html)[:_MAX_MATCHES],
    }


_JS_ENDPOINT_PATTERN = re.compile(r'["\'](/[a-zA-Z0-9_\-./]{0,100}api[a-zA-Z0-9_\-./]{0,100})["\']', re.IGNORECASE)
# Small and precise on purpose — every entry here is a well-known, low-false-positive prefix
# format; the point is a short, high-confidence list, not exhaustive coverage of every possible
# secret shape. Only the pattern NAME is ever returned to the caller (see js_bundle_scan below),
# never the matched text itself, same "never render credentials" rule identity creds already
# follow (save_identity_credentials below).
_SECRET_PATTERNS = {
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "google_oauth_token": re.compile(r"ya29\.[0-9A-Za-z\-_]+"),
    "stripe_live_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{10,}"),
    "slack_token": re.compile(r"xox[baprs]-[0-9A-Za-z-]+"),
    "slack_webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "github_pat": re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    "gcp_service_account": re.compile(r'"type"\s*:\s*"service_account"'),
    "firebase_cloud_msg_key": re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140,}"),
    "square_token": re.compile(r"sq0(atp|csp)-[0-9A-Za-z\-_]{22,}"),
    "twilio_sid": re.compile(r"\b(AC|SK)[a-f0-9]{32}\b"),
    "sendgrid_key": re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
    "mailgun_key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "npm_token": re.compile(r"npm_[A-Za-z0-9]{36}"),
    "basic_auth_url": re.compile(r"https?://[^/\s:@\"']+:[^/\s:@\"']+@[^/\s\"']+"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
}
_JS_MAX_BYTES = 2_000_000  # minified bundles can be multi-MB; cap before regexing, not after


def _scan_secret_patterns(text: str) -> dict[str, re.Match]:
    return {name: match for name, pattern in _SECRET_PATTERNS.items() if (match := pattern.search(text))}


def js_bundle_scan(params: dict) -> dict:
    """view_source only ever links to a script_src URL, never reads it — modern SPA bundles
    (React/Vue, exactly what a real target's front end usually is) hide real API routes, and
    occasionally live secrets, inside JS no HTML page ever shows as text. Reads the file (capped,
    truncated rather than fully downloaded past _JS_MAX_BYTES) for endpoint-shaped string literals
    and a small set of well-known secret-key formats, and separately fetches the matching ".map"
    sourcemap (same cap) if one is exposed — a sourcemap commonly contains the FULL original
    unminified source, exactly where a real secret is more likely to actually appear than in the
    minified bundle itself, so its content gets the same secret-pattern scan, not just an
    exposed/not-exposed boolean. Never returns the matched secret text itself, only which
    pattern(s) matched, by name -- plus each match's own character offset into the bundle/sourcemap
    text, so a follow-up fetch (e.g. an http_request/send_raw_request with a Range header) can be
    aimed at roughly the right place. Real incident this closes: a real bundle's matched
    private_key_block sat 97,175 bytes into a 647KB file -- far beyond what a follow-up fetch's own
    body-preview truncation could ever reach blindly -- and with no location hint the model gave up
    on a genuine, still-unresolved lead instead of ever confirming or ruling it out.
    """
    url = params["target"]

    def _read_capped(client: httpx.Client, target_url: str) -> tuple[bytes, bool, int]:
        data = b""
        trunc = False
        with client.stream("GET", target_url) as resp:
            status_code = resp.status_code
            for chunk in resp.iter_bytes():
                data += chunk
                if len(data) >= _JS_MAX_BYTES:
                    trunc = True
                    break
        return data, trunc, status_code

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params)) as client:
            body, truncated, _ = _with_hard_deadline(lambda: _read_capped(client, url), _HTTP_TIMEOUT)
            sourcemap_body, _, sourcemap_status = _with_hard_deadline(lambda: _read_capped(client, url + ".map"), _HTTP_TIMEOUT)
            sourcemap_exposed = sourcemap_status == 200
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    text = body.decode("utf-8", errors="replace")
    endpoints = sorted(set(_JS_ENDPOINT_PATTERN.findall(text)))[:_MAX_MATCHES]
    matched_secrets = _scan_secret_patterns(text)

    sourcemap_matched_secrets: dict[str, re.Match] = {}
    if sourcemap_exposed:
        sourcemap_text = sourcemap_body.decode("utf-8", errors="replace")
        sourcemap_matched_secrets = _scan_secret_patterns(sourcemap_text)

    return {
        "status": "ok",
        "truncated": truncated,
        "endpoint_like_strings": endpoints,
        "secret_patterns_matched": list(matched_secrets),
        "secret_pattern_offsets": {name: match.start() for name, match in matched_secrets.items()},
        "sourcemap_exposed": sourcemap_exposed,
        "sourcemap_secret_patterns_matched": list(sourcemap_matched_secrets),
        "sourcemap_secret_pattern_offsets": {name: match.start() for name, match in sourcemap_matched_secrets.items()},
    }


_WEB_FETCH_MAX_HTML_CHARS = 500_000  # cap raw HTML before regexing, same spirit as _JS_MAX_BYTES
_WEB_FETCH_MAX_TEXT_CHARS = int(os.getenv("WEB_FETCH_MAX_TEXT_CHARS", "8000"))
_SCRIPT_STYLE_PATTERN = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAG_PATTERN = re.compile(r"<[^>]+>")
_INLINE_WHITESPACE_PATTERN = re.compile(r"[ \t]+")
_EXCESS_BLANK_LINES_PATTERN = re.compile(r"\n{3,}")
_TITLE_TAG_PATTERN = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _html_to_readable_text(html_source: str) -> str:
    """Strips markup down to visible prose -- good enough for reading an advisory/blog/GitHub
    write-up (web_fetch's actual use case), not a general-purpose HTML renderer. Regex-based like
    the rest of this file's HTML handling (view_source, js_bundle_scan) rather than pulling in a
    new dependency (BeautifulSoup) for one tool.
    """
    without_scripts = _SCRIPT_STYLE_PATTERN.sub(" ", html_source)
    without_tags = _TAG_PATTERN.sub("\n", without_scripts)
    unescaped = html.unescape(without_tags)
    collapsed = _INLINE_WHITESPACE_PATTERN.sub(" ", unescaped)
    return _EXCESS_BLANK_LINES_PATTERN.sub("\n\n", collapsed).strip()


def web_fetch(params: dict) -> dict:
    """Reads a page from the general internet -- a CVE advisory, GitHub PoC/issue, vendor
    bulletin, security blog write-up -- as plain readable text. cve_lookup's own reference_urls
    field has always pointed at exactly this kind of page; before this tool nothing could actually
    open one, leaving Analyze/Exploit stuck guessing at exploitation preconditions/technique
    instead of reading the real source.

    Deliberately separate from http_request, not a duplicate of it: http_request is for probing
    the live scan target itself (target-scoped headers/verify=False via _target_client_kwargs, a
    raw 2000-char HTML preview, and SQLi/XSS/command-injection detectors meaningless against a
    third-party advisory page). web_fetch is a plain, honest client against a public third-party
    resource -- the same "third party, not the target" client shape as crt_sh_lookup/cve_lookup --
    that extracts actual readable prose instead of a raw markup fragment.

    Reuses the "target" argument name specifically so core.py's existing per-call guardrails
    (_out_of_scope_target, _loopback_or_link_local_target) fire on this tool exactly like every
    other URL-shaped tool -- an operator's out-of-scope exclusion list and the SSRF-relevant
    loopback/link-local block apply here for free, no separate mechanism to build or keep in sync.
    """
    url = params["target"]
    scheme = urlsplit(url).scheme.lower()
    if scheme not in ("http", "https"):
        return {"status": "error", "error": f"Unsupported scheme {scheme!r} -- only http/https URLs can be fetched."}

    timeout = float(params.get("timeout") or _HTTP_TIMEOUT)
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = _with_hard_deadline(lambda: client.get(url), timeout)
    except httpx.HTTPError as exc:
        # Same non-retryable "ok, real negative result" treatment http_request/dns_lookup already
        # give a genuine NXDOMAIN -- confirmed live (a real session, timetravel.mementoweb.org
        # lookup): without this, a nonexistent hostname fell into the generic status="error" branch
        # below and burned a full 1-Step Retry round-trip no corrected argument could ever fix.
        if _is_nxdomain_errno(_dns_resolution_errno(exc)):
            return {
                "status": "ok", "resolved": False,
                "note": f"{url} does not resolve (no such host) — a real, negative result, not a tool failure",
            }
        return {"status": "error", "error": describe_exception(exc)}

    raw = resp.text
    html_truncated = len(raw) > _WEB_FETCH_MAX_HTML_CHARS
    if html_truncated:
        raw = raw[:_WEB_FETCH_MAX_HTML_CHARS]

    title_match = _TITLE_TAG_PATTERN.search(raw)
    title = html.unescape(_TAG_PATTERN.sub("", title_match.group(1))).strip() if title_match else None

    text = _html_to_readable_text(raw)
    text_truncated = len(text) > _WEB_FETCH_MAX_TEXT_CHARS
    if text_truncated:
        text = text[:_WEB_FETCH_MAX_TEXT_CHARS]

    if html_truncated or text_truncated:
        logger.debug(
            "native: web_fetch target=%r truncated (html_truncated=%s text_truncated=%s)",
            url, html_truncated, text_truncated,
        )

    return {
        "status": "ok",
        "url": str(resp.url),
        "status_code": resp.status_code,
        "title": title,
        "text": text,
        "truncated": html_truncated or text_truncated,
    }


# --- Analyze -> Exploit bridge ---

# The GitHub mirror (offensive-security/exploitdb) was retired mid-2026 in favor of GitLab
# (confirmed by fetching its README, which now just points here) — found by an actual 404 on
# the old URL, not assumed.
_EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
_EXPLOITDB_CSV_PATH = resolve_global_app_dir() / "data" / "cache" / "exploitdb" / "files_exploits.csv"
_EXPLOITDB_CSV_TTL_SECONDS = 7 * 24 * 3600  # dataset changes slowly, a week-old copy is fine


def _ensure_exploitdb_csv() -> Path:
    if _EXPLOITDB_CSV_PATH.exists() and time.time() - _EXPLOITDB_CSV_PATH.stat().st_mtime < _EXPLOITDB_CSV_TTL_SECONDS:
        return _EXPLOITDB_CSV_PATH

    _EXPLOITDB_CSV_PATH.parent.mkdir(parents=True, exist_ok=True)
    with httpx.Client(timeout=30.0) as client:
        resp = client.get(_EXPLOITDB_CSV_URL)
        resp.raise_for_status()
    _EXPLOITDB_CSV_PATH.write_bytes(resp.content)
    return _EXPLOITDB_CSV_PATH


def exploit_db_lookup(params: dict) -> dict:
    query = params["query"]
    cached = cache_get("exploit_db_lookup", query)
    if cached is not None:
        return cached

    try:
        csv_path = _ensure_exploitdb_csv()
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    # Multi-term AND, not one whole-string substring match — same convention the real searchsploit
    # CLI uses against this identical CSV dataset. Real incident this fixes: a natural multi-word
    # query the LLM actually writes ("wordpress sql injection plugin") almost never appears as one
    # contiguous substring in a description, even when hundreds of real matching entries exist (this
    # exact query: 0 hits the old way, 328 with per-term matching) — every multi-word search was
    # silently starving the exploit phase of real, existing PoCs.
    query_terms = query.lower().split()
    matches = []
    total_matches = 0
    with csv_path.open("r", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            haystack = f"{row.get('description', '')} {row.get('codes', '')}".lower()
            if all(term in haystack for term in query_terms):
                total_matches += 1
                if len(matches) < 20:
                    matches.append(
                        {
                            "edb_id": row.get("id"),
                            "title": row.get("description"),
                            "cve": row.get("codes"),
                            "path": row.get("file"),
                        }
                    )

    result = {
        "status": "ok",
        "matches": matches,
        "total_matches": total_matches,
        "truncated": total_matches > len(matches),
    }
    cache_set("exploit_db_lookup", query, result)
    return result


def _find_exploitdb_file_path(edb_id: str) -> str | dict:
    """Looks up the repo-relative file path for one EDB-ID in the same CSV exploit_db_lookup
    already indexes — a dict return means an error (not found / couldn't fetch the index)."""
    try:
        csv_path = _ensure_exploitdb_csv()
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    with csv_path.open("r", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            if row.get("id") == edb_id:
                return row.get("file") or {"status": "error", "error": f"EDB-ID {edb_id} has no file path recorded"}
    return {"status": "error", "error": f"EDB-ID {edb_id} not found — search with exploit_db_lookup first"}


def _fetch_exploitdb_source(edb_id: str) -> dict:
    file_path = _find_exploitdb_file_path(edb_id)
    if isinstance(file_path, dict):
        return file_path

    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(f"https://gitlab.com/exploit-database/exploitdb/-/raw/main/{file_path}")
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {"status": "ok", "file_path": file_path, "source": resp.text}


# Only interpreted script types this tool will actually execute — no compiled-language PoC (.c,
# .cpp) gets auto-built, and no PoC without a recognized extension (.txt writeups, standalone
# binaries) gets guessed at. Anything outside this set comes back from exploit_db_run as a plain
# error telling the model to read it via exploit_db_fetch and reproduce it manually instead.
# ".py2" -> "python2": python2 is EOL and gone from most distro repos, but real, still-working PoCs
# that only run under it exist (a genuine case the operator has hit before) — not installed by
# default (agent/tools/capability_registry.py), only resolved on demand via capability_paths.
_EXPLOITDB_INTERPRETERS = {".py": "python3", ".py3": "python3", ".py2": "python2", ".sh": "bash", ".pl": "perl", ".rb": "ruby"}


def exploit_db_fetch(params: dict) -> dict:
    """Fetches the real PoC source code for one Exploit-DB entry (by EDB-ID, from
    exploit_db_lookup's results) WITHOUT running it. Read this first — every PoC has its own
    argument convention (there is no standard), so this is how to actually learn what
    exploit_db_run needs to be called with, and whether the PoC is even something worth running
    at all (some EDB entries are just a write-up, not a script)."""
    result = _fetch_exploitdb_source(str(params["edb_id"]))
    if result.get("status") != "ok":
        return result
    suffix = Path(result["file_path"]).suffix.lower()
    return {
        "status": "ok",
        "file_path": result["file_path"],
        "runnable_by_exploit_db_run": suffix in _EXPLOITDB_INTERPRETERS,
        "source": result["source"][:8000],
    }


def exploit_db_run(params: dict) -> dict:
    """Actually runs a real Exploit-DB PoC (by EDB-ID) with the given CLI arguments against the
    target — real, unreviewed third-party code from a public database, not written or vetted by
    this project. Call exploit_db_fetch first to read the script and work out its real argument
    order (every PoC has its own convention). "target" is only used for the allowlist/approval
    check — it must ALSO appear in "args" in whatever position/form the script itself expects.
    Same treatment as custom_exploit_run (agent/tools/sandbox.py's run_sandboxed, persisted into
    this session's own scripts/ folder rather than a throwaway tempfile) -- same risk class, real
    unreviewed code either way.
    """
    edb_id = str(params["edb_id"])
    result = _fetch_exploitdb_source(edb_id)
    if result.get("status") != "ok":
        return result

    file_path = result["file_path"]
    suffix = Path(file_path).suffix.lower()
    interpreter = _EXPLOITDB_INTERPRETERS.get(suffix)
    if interpreter is None:
        return {
            "status": "error",
            "error": f"{file_path} is a {suffix or 'unrecognized'} file, not a script this tool can run "
            "automatically — read it with exploit_db_fetch and reproduce/report it manually instead.",
        }
    capability_id = interpreter
    if interpreter == "python3":
        # sys.executable, not a bare "python3" resolved off PATH -- real incident: PATH resolves
        # to the system interpreter, which has none of this project's dependencies (httpx, mmh3,
        # ...) installed, so any fetched PoC that imports httpx failed every single time with an
        # opaque ModuleNotFoundError. sys.executable is this same process's own venv interpreter.
        interpreter = sys.executable
    else:
        # Checks a Settings-saved override path first (agent/tools/capability_paths.py) before
        # falling back to PATH -- a python2/etc install in a non-standard location actually gets
        # used, not just displayed as a Settings-page status.
        resolved = resolve_interpreter_path(interpreter)
        if resolved is None:
            return {
                "status": "tool_unavailable", "tool": "exploit_db_run",
                "capability": capability_id,
                "error": f"{interpreter!r} is not installed -- install it from Settings, or ask the "
                "operator to, then retry this finding/hypothesis.",
            }
        interpreter = resolved

    args = [str(a) for a in params.get("args", [])]
    timeout_seconds = int(os.getenv("EXPLOIT_TIMEOUT_SECONDS", "180"))

    scripts_dir = _exploit_scripts_dir(params.get("_session_id"))
    script_id = uuid.uuid4().hex[:12]
    script_path = scripts_dir / f"{script_id}{suffix}"
    script_path.write_text(result["source"], encoding="utf-8")

    try:
        proc = run_sandboxed([interpreter, str(script_path), *args], scripts_dir, timeout_seconds)
    except subprocess.TimeoutExpired:
        # Real, confirmed incident this fixes (fss-usr_d5b09a): a bare {"status": "timeout"} here
        # gave _run_tool_with_retry's own correction call (agent/core.py's f"Error: {_log_error(result)}")
        # nothing at all to react to, and left session["logs"]' own "error" field null forever --
        # the operator saw a completely empty result for a real 5-minute hang with no way to tell
        # what happened without going and reading debug.log by hand. An explicit reason (this
        # script's own configured timeout, plus the likely cause) gives both the correction call
        # and a human reading the log something real to act on.
        return {
            "status": "timeout", "edb_id": edb_id, "file_path": file_path,
            "error": (
                f"the PoC script exceeded its {timeout_seconds}s timeout and was killed -- it "
                "either hung (e.g. waiting on input, an infinite loop, a retry with no bound) or "
                "is genuinely too slow; check its own source (exploit_db_fetch) for a blocking "
                "call with no timeout of its own."
            ),
        }

    (scripts_dir / f"{script_id}.log").write_text(
        f"$ {interpreter} {script_path.name} {' '.join(args)}\n\n--- stdout ---\n{proc.stdout}\n\n--- stderr ---\n{proc.stderr}\n",
        encoding="utf-8",
    )

    result_dict = {
        "status": "ok" if proc.returncode == 0 else "error",
        "edb_id": edb_id,
        "file_path": file_path,
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:8000],
        "stderr": proc.stderr[:2000],
    }
    # Real, confirmed incident this fixes: a crashed PoC that produces genuinely no output on
    # EITHER stream leaves agent/core.py's _log_error fallback chain (error/stderr/reason) with
    # nothing at all to read -- a completely blank signal, worse than the documented low-signal
    # (but at least present) failure text nuclei/nikto/wpscan can produce, and worse for the model's
    # 1-Step Retry than a real error message would be. Only synthesized when both streams are truly
    # empty -- a PoC that DOES print something to stderr on failure keeps that real text untouched.
    if result_dict["status"] == "error" and not proc.stdout.strip() and not proc.stderr.strip():
        result_dict["error"] = (
            f"the PoC exited with code {proc.returncode} and produced no output on stdout or "
            "stderr -- it likely crashed before printing anything (e.g. an unhandled exception "
            "during argument parsing, a missing Python dependency, or an incompatible calling "
            "convention). Re-read the script with exploit_db_fetch to check its real expected "
            "argument order/format, or try running it with a verbose/debug flag if it has one."
        )
    return result_dict


def _exploit_scripts_dir(session_id: str | None) -> Path:
    """Session-scoped persistence for custom_exploit_run's own model-written scripts AND
    exploit_db_run's own fetched-PoC scripts -- same risk class (unvetted code neither written nor
    reviewed by this project), same treatment. Same "session's own project folder, else the global
    app dir" fallback background_jobs.py's own _job_dir() already uses. Also doubles as
    agent/tools/sandbox.py's one writable scratch root -- "persist the script" and "give the
    sandbox a writable directory" collapse into the same location instead of two separate
    mechanisms.
    """
    folder = get_session_folder(session_id) if session_id else None
    base = Path(folder) if folder else resolve_global_app_dir()
    scripts_dir = base / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    return scripts_dir


def custom_exploit_run(params: dict) -> dict:
    """Writes and runs a real, model-written Python script against the target — for a vulnerability
    class none of the purpose-built tools (msf/sqlmap/nikto/dalfox/wpscan/exploit_db_run) fit, e.g.
    a bespoke protocol interaction (raw FTP/SMTP/IMAP commands via ftplib/smtplib/imaplib/socket)
    or parsing a response format no other tool understands. Same execution shape as exploit_db_run
    (persisted script + subprocess + timeout + truncated output), except the source is written by
    the model itself instead of fetched from Exploit-DB — same risk class as that tool and
    msfconsole/sqlmap, not a new one. Runs under whatever platform-appropriate isolation
    agent/tools/sandbox.py's run_sandboxed can provide (bubblewrap on Linux -- covers Windows-via-
    WSL2 too, since the agent process itself always runs inside WSL2 there, see run.bat -- Seatbelt
    on native macOS, unsandboxed fallback otherwise) — filesystem/process isolation only, not a
    network allowlist: "target" is only used for the allowlist/approval check, the script itself still
    reaches the real target on its own (via socket/ssl/ftplib/smtplib/imaplib, httpx, or requests —
    httpx is the HTTP client this project actually depends on directly and the one to prefer;
    "requests" is only present at all as arjun's own transitive dependency, not a guarantee for
    every future venv). The script itself, and its real stdout/stderr, are persisted permanently in
    this session's own project folder (scripts/<id>.py, scripts/<id>.log) — not a throwaway tempfile
    deleted the moment the run ends, so a real PoC written this way survives to be reviewed later.

    dnspython (the "dns" module) is deliberately NOT in requirements.txt and so is NOT available
    here — real, confirmed incident: a model reasonably assuming a common security-scripting
    library would be present wrote `import dns.resolver` 4 times in one 8-minute stretch (and 7
    times combined across two sessions), each crashing with ModuleNotFoundError, each recovered
    only via a full 1-Step Retry round-trip that rewrote it to socket.getaddrinfo/subprocess+dig
    before the model reverted right back to the same mistake on its NEXT fresh call. The tool's own
    schema description (agent/tools/__init__.py) now states this explicitly rather than leaving it
    to be rediscovered by trial and error every time.
    """
    source = params["source"]
    args = [str(a) for a in params.get("args", [])]
    # Its OWN short knob, deliberately NOT EXPLOIT_TIMEOUT_SECONDS (which an operator commonly raises
    # to 600 for slow network exploit tools like msf/sqlmap). Real incident: an RE pass drove a
    # Windows crackme through wine but never fed/closed the process's stdin, so the binary sat at its
    # `operator>` prompt until the full 600s timeout killed it -- one hung script eating ten minutes,
    # unstoppable mid-run, and it happened across several calls in one session. 180s is plenty for a
    # real local PoC (a wine crackme run finishes in seconds); a genuinely long-running script can
    # raise this one knob without also lengthening every network exploit-tool timeout.
    timeout_seconds = int(os.getenv("CUSTOM_SCRIPT_TIMEOUT_SECONDS", "180"))

    # A plain compile() pre-flight, not a real execution -- catches the mechanical case (a stray
    # indent, an unclosed bracket) instantly instead of only after a real subprocess dispatch.
    # Real, confirmed incident this fixes: a model's own corrected 1-Step Retry (itself already
    # costing a ~3-minute round-trip after the original call's real network failure) had a single
    # stray leading space producing "IndentationError: unexpected indent" -- a purely mechanical
    # typo that burned the ONE retry chance this tool gets, discovered only after a real subprocess
    # had already been spawned. compile() can't catch every possible runtime failure (a real
    # NameError/logic bug still needs the actual run), but a SyntaxError-class defect is 100%
    # deterministic and free to catch before ever touching a tempfile or a subprocess.
    try:
        compile(source, "<custom_exploit_run>", "exec")
    except SyntaxError as exc:
        return {
            "status": "error",
            "error": f"SyntaxError at line {exc.lineno}, column {exc.offset}: {exc.msg} -- this script was never run (compile() caught it before the subprocess). Fix the syntax and resubmit.",
        }

    scripts_dir = _exploit_scripts_dir(params.get("_session_id"))
    script_id = uuid.uuid4().hex[:12]
    script_path = scripts_dir / f"{script_id}.py"
    script_path.write_text(source, encoding="utf-8")

    try:
        # sys.executable, not a bare "python3" resolved off PATH -- see exploit_db_run's matching
        # fix for the real incident this avoids (PATH's python3 has none of this project's
        # dependencies, so every httpx-based script failed on the first attempt, every time).
        proc = run_sandboxed([sys.executable, str(script_path), *args], scripts_dir, timeout_seconds)
    except subprocess.TimeoutExpired:
        # Real, confirmed incident this fixes (fss-usr_d5b09a): a real script had a busy-wait loop
        # that never advanced (`while ... and (p % 4 != 0): pass`), ran for the full CUSTOM_SCRIPT_
        # TIMEOUT_SECONDS, and the bare {"status": "timeout"} this used to return left BOTH
        # session["logs"]' own "error" field null AND _run_tool_with_retry's correction call
        # (f"Error: {_log_error(result)}") with nothing to react to -- the operator saw a
        # completely empty, unexplained failure for a genuine 5-minute hang. An explicit reason
        # (this tool's own configured timeout, plus the likely cause) gives both the correction
        # call and a human reading the log something real to act on.
        return {
            "status": "timeout",
            "error": (
                f"the script exceeded its {timeout_seconds}s timeout and was killed -- it either "
                "hung (e.g. a loop condition that never becomes false, waiting on input that never "
                "came) or is genuinely too slow for a local PoC/analysis script. Check the script's "
                "own loop conditions for one that never advances its own index/pointer, and add a "
                "real bound to any blocking call."
            ),
        }

    (scripts_dir / f"{script_id}.log").write_text(
        f"$ {sys.executable} {script_path.name} {' '.join(args)}\n\n--- stdout ---\n{proc.stdout}\n\n--- stderr ---\n{proc.stderr}\n",
        encoding="utf-8",
    )

    result = {
        "status": "ok" if proc.returncode == 0 else "error",
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:8000],
        "stderr": proc.stderr[:2000],
    }
    if proc.returncode != 0:
        # Sibling of the subprocess.TimeoutExpired branch's own explicit "error" above -- real,
        # confirmed incident this fixes (333-usr_fb4459): a real crash (exit_code=1,
        # AttributeError: module 'ssl' has no attribute 'PROTOCOL_TLSv1_3') left "error" entirely
        # absent from this dict. _log_error's own stderr fallback (agent/core.py) meant the
        # correction call itself wasn't actually blind, but the raw debug.log/session.json line
        # read as "error=None" with no diagnostic content, costing real time tracing the true cause
        # by hand during a log-review pass.
        result["error"] = (result["stderr"] or f"script exited with code {proc.returncode} and no stderr output").strip()
    return result


_ARJUN_VALID_METHODS = {"GET", "POST", "XML", "JSON"}
# Arjun's own default (5) is conservative; a real request pattern here is one request per CHUNK of
# candidate parameter names (not one per candidate, unlike ffuf), so this is still a modest,
# non-DoS-shaped concurrency bump, just enough to comfortably finish within the timeout budget
# below -- confirmed live against a real approved target with Arjun's own full default (large.txt,
# ~26k words) wordlist.
_ARJUN_DEFAULT_THREADS = 15


def interpret_arjun_timeout(result: dict) -> str | None:
    """Arjun's own --stable mode (an extra request-stability re-check pass, opt-in via params) is
    genuinely slower and routinely exceeds the subprocess timeout against a slow/WAF-fronted target
    -- confirmed live across 6+ real sessions:
    ~580-600s hangs, every one with --stable set, and each 1-Step Retry either resent it unchanged
    or guessed at an unrelated field-name fix, never dropping the one flag actually causing the
    hang, because nothing told the model that was the cause. Same registration shape as
    agent/tools/builders/wpscan.py's interpret_wpscan_timeout -- None for any status other than a
    genuine timeout, and only fires when --stable is actually present in the command that timed out.
    """
    if result.get("status") != "timeout":
        return None
    command = result.get("command") or []
    if "--stable" not in command:
        return None
    return (
        "Arjun timed out with --stable set -- that mode adds an extra request-stability re-check "
        "pass and routinely exceeds this budget against a slow or WAF-fronted target. Retrying "
        "with --stable still set will very likely time out the same way again. Drop --stable "
        "entirely for the retry (omit the \"stable\" parameter) -- Arjun's own default mode is "
        "meaningfully faster and still finds real hidden parameters, just without the extra "
        "stability re-checks."
    )


def interpret_arjun_crash(result: dict) -> str | None:
    """Arjun 2.2.7's own upstream bug (see arjun_probe's docstring: an AttributeError crash
    inside its own initialize() whenever the target's very first stability probe returns HTTP
    400/413/418/429/503) used to reach the model as a raw, unrecognized traceback in stderr, with
    nothing telling it this is a permanent, deterministic upstream limitation -- not something a
    corrected argument could ever fix. Confirmed live: the identical AttributeError fired on both
    the original call and its own 1-Step Retry (~44s wasted for zero possible gain), because
    the correction call had no way to know the same crash was coming again. Same registration
    shape as interpret_arjun_timeout right above -- None for anything that isn't this specific,
    recognizable crash signature.
    """
    if result.get("status") != "error":
        return None
    error_text = result.get("error") or ""
    if "initialize" not in error_text or "status_code" not in error_text:
        return None
    return (
        "Arjun crashed with a known upstream bug (AttributeError inside its own initialize() "
        "step) -- this happens whenever the target returns HTTP 400/413/418/429/503 on Arjun's "
        "very first stability probe, before any real parameter discovery begins. This is a "
        "permanent limitation of this Arjun version against this target's current response "
        "behavior, not something a corrected argument can fix -- retrying the same URL will "
        "crash identically every time. Try a different tool for hidden-parameter discovery "
        "against this target, or move on."
    )


def interpret_missing_identity(result: dict) -> str | None:
    """_get_authenticated_client's own "No credentials configured for identity ..." error (above)
    already spells out, in its own text, that this is permanent for the rest of the session -- but
    without this registration, a model reading it in isolation retried anyway across every
    credentialed tool that shares this same check (cors_credentialed_check/authenticated_request/
    authenticated_crawl/idor_probe/graphql_authz_probe/graphql_batching_probe/browser_navigate, the
    last via get_identity_browser_creds reusing the exact same function). Confirmed live
    (a real HackerOne rescan session): a project with zero configured identities still saw
    cors_credentialed_check retried 8 times across ~30 minutes, each time varying only the identity
    name or target URL -- neither of which could ever fix an empty credential store. Same family as
    interpret_arjun_crash right above: the error text already teaches the right lesson, it just
    was never wired into _PERMANENT_ERROR_HINTS to make retrying it unreachable in the first place.
    """
    if result.get("status") != "error":
        return None
    error_text = result.get("error") or ""
    if "permanent, deterministic condition for this project" not in error_text:
        return None
    return error_text


def interpret_permanent_connection_refusal(result: dict) -> str | None:
    """httpx.ConnectError wrapping a bare OS-level TCP refusal ("[Errno 111] Connection refused")
    or unreachable route ("[Errno 113] No route to host") -- unlike a DNS failure
    (_is_nxdomain_errno above) or a timeout, this means the OS/firewall itself rejected or dropped
    the TCP SYN before any HTTP-layer negotiation could even start; no corrected URL path/method/
    headers/body can ever change that outcome for the same host:port. Confirmed live
    (a real HackerOne session): 19 occurrences across one target's subdomain
    enumeration, every single 1-Step Retry resending the identical host:port and failing
    identically. Same family as interpret_missing_identity right above: the error text already
    teaches the right lesson, it just needs wiring into _PERMANENT_ERROR_HINTS to make the doomed
    retry itself unreachable.

    Also covers _with_hard_deadline's own _HardDeadlineExceeded text ("host is likely
    unreachable") -- a second, independent source of the exact same "no HTTP-layer negotiation
    ever started" outcome, just detected by this project's own wall-clock watchdog instead of a
    bare OS errno. Confirmed live (a real HackerOne session): 8 hard-deadline timeouts across
    distinct trk./link.inbox. subdomains in one phase, at least 4 of them triggering a 1-Step Retry
    that resent the identical host and failed identically ~14-15s later each time -- each host only
    ever tried once or twice, so _dead_host_blocked's own 3-of-8 repeat threshold never caught it.
    """
    if result.get("status") != "error":
        return None
    error_text = result.get("error") or ""
    if "Errno 111" in error_text or "Errno 113" in error_text:
        return (
            f"{error_text} -- this is an OS/network-level refusal (connection actively refused, or "
            "no route to this host/port), not an HTTP-layer or argument problem; retrying the same "
            "host:port will fail identically. Treat this as a genuine negative recon result, or try "
            "a different host/port instead."
        )
    if "host is likely unreachable" in error_text:
        return (
            f"{error_text} -- this wall-clock deadline was already hit once for this exact "
            "host:port; no corrected URL path/method/headers/body can make an unroutable address "
            "respond. Retrying the same host:port will fail identically. Treat this as a genuine "
            "negative recon result, or try a different host/port instead."
        )
    return None


def interpret_github_code_search_permanent_failure(result: dict) -> str | None:
    """github_code_search's own 401 (invalid/rejected token -- permanent for the rest of this
    session, no corrected argument can ever fix it) and 403 (rate-limited to 10/min -- an
    IMMEDIATE 1-Step Retry is guaranteed to still be inside the same rate-limit window and fail
    identically) errors are both already spelled out clearly in the error text itself (see that
    function's own status checks). Registered here so a correction round-trip is never wasted on
    either -- same family as interpret_arjun_crash/interpret_upx_not_packed above: the text already
    teaches the right lesson, it just needs wiring into _PERMANENT_ERROR_HINTS to make the doomed
    retry itself unreachable. A 422 (malformed query) is deliberately NOT covered here -- a
    genuinely corrected query can fix that one, so it stays a normal retryable error.
    """
    if result.get("status") != "error":
        return None
    error_text = result.get("error") or ""
    if "GitHub rejected the configured token" in error_text or "GitHub rate-limited this request" in error_text:
        return error_text
    return None


def interpret_arjun_failure(result: dict) -> str | None:
    """_ERROR_HINTS (agent/core.py) only allows one callable per tool name -- this dispatches to
    whichever of arjun's two known, distinct failure shapes (a --stable timeout, or the
    initialize() crash) actually matches this result, so both hints stay registered under the
    same "arjun" key instead of one silently shadowing the other.
    """
    return interpret_arjun_timeout(result) or interpret_arjun_crash(result)


def arjun_probe(params: dict) -> dict:
    """Runs Arjun (github.com/s0md3v/Arjun) against a single URL to discover hidden HTTP
    parameters — a real GET/POST/JSON field the target's own frontend never sends but its backend
    still accepts, exactly the surface many IDOR/SSRF/mass-assignment bugs live on. Complements
    ffuf (which discovers hidden PATHS, not parameters on a known one).

    A native tier-1 function rather than a generic tier-2 build_command+parser tool for one
    concrete reason, confirmed live: Arjun's own -oJ writer opens its output path in 'w+' mode,
    which fails outright ("File or stream is not seekable") the instant it's a pipe rather than a
    real file on disk -- exactly what -oJ /dev/stdout becomes once this project's own subprocess
    runner captures stdout (subprocess.run(..., capture_output=True)). There is no CLI flag around
    this; it needed a real temp file plus reading it back afterward, the same shape
    exploit_db_run/custom_exploit_run already use for their own tempfile-based execution, not the
    stdout-parsing convention every other tier-2 tool in this registry uses.

    Second, independent known limitation (also confirmed live, a genuine upstream bug, not this
    project's): Arjun 2.2.7 crashes with an unrelated AttributeError from inside its own
    initialize() whenever the target returns HTTP 400/413/418/429/503 on its very first stability
    probe -- common on WAF-protected or strict-validation endpoints. That crash (like the one this
    function's own tempfile handling works around) still only ever surfaces here as an ordinary
    {"status": "error"} result, never a crash of the agent's own session. Not worth patching the
    installed package in place: run.sh reinstalls requirements.txt on every hash change, which
    would silently discard any such patch.

    Third limitation: Arjun only ever writes its result once, at the very end of a run -- unlike
    nikto/ffuf (both have a -maxtime-equivalent to gracefully wrap up before a hard timeout kill),
    a run that hits the timeout below loses the ENTIRE result, not just whatever it hadn't reached
    yet. Mitigated by keeping the default thread count above Arjun's own conservative default, not
    by pretending a graceful-stop flag exists when it doesn't.
    """
    try:
        target = validate_target(params["target"])
    except ValueError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    method = str(params.get("method") or "GET").upper()
    if method not in _ARJUN_VALID_METHODS:
        method = "GET"
    threads = int(params.get("threads") or _ARJUN_DEFAULT_THREADS)
    timeout_seconds = int(os.getenv("TOOL_TIMEOUT_SECONDS", "120"))

    executable = shutil.which("arjun")
    if executable is None:
        return {"status": "tool_unavailable", "tool": "arjun"}

    json_fd, json_path = tempfile.mkstemp(suffix=".json")
    os.close(json_fd)
    # Start genuinely absent -- Arjun's own json_export() only ever writes this file at all once
    # it found something, so "the file exists after the run" is the one reliable signal that
    # something was actually found, not just a leftover empty placeholder from mkstemp() itself.
    Path(json_path).unlink()

    command = [executable, "-u", target, "-m", method, "-t", str(threads), "-oJ", json_path, "-q"]
    # Same precedence as ffuf's own wordlist resolution: explicit model choice first, then the
    # operator's Settings-UI assignment, then Arjun's own bundled parameter-name lists.
    wordlist = params.get("wordlist") or get_assigned_wordlist("arjun")
    if wordlist:
        command += ["-w", validate_safe_value(str(wordlist))]
    if params.get("stable"):
        command.append("--stable")
    # Server-side injected by agent/core.py's _run_tool_with_retry (New Project form's Custom
    # User-Agent + Custom HTTP Headers fields) — never part of this tool's own params schema, so
    # never model-supplied. Arjun's own --headers takes exactly one flag occurrence, multiple
    # headers separated by a literal "\n" inside that one string (confirmed against its own docs:
    # --headers "Accept-Language: en-US\nCookie: null"), not real newlines and not a repeated flag
    # the way nuclei/ffuf/dalfox's -H is.
    target_headers = _merged_target_headers(params)
    if target_headers:
        pairs = [validate_header_pair(name, value) for name, value in target_headers.items()]
        command += ["--headers", "\\n".join(f"{name}: {value}" for name, value in pairs)]

    try:
        # stdin=DEVNULL -- see runner.py's _run_tracked for the real incident (interactive-prompt
        # hang eating the whole subprocess timeout) this closes across every dispatch, not just one.
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        Path(json_path).unlink(missing_ok=True)
        # "command" echoed back here (unlike a bare tier-2 subprocess timeout, which already gets
        # this from _run_subprocess) is what lets agent/core.py's interpret_arjun_timeout hint
        # actually see whether --stable was set on this specific run -- see that function's own
        # docstring for the real incident this closes.
        return {"status": "timeout", "command": command}

    if proc.returncode != 0:
        Path(json_path).unlink(missing_ok=True)
        return {"status": "error", "exit_code": proc.returncode, "error": proc.stderr[-2000:]}

    if not Path(json_path).exists():
        return {"status": "ok", "hits": []}

    try:
        record = json.loads(Path(json_path).read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        record = {}
    finally:
        Path(json_path).unlink(missing_ok=True)

    hits = [
        {"url": url, "params": info.get("params", []), "method": info.get("method")}
        for url, info in record.items()
        if isinstance(info, dict)
    ]
    return {"status": "ok", "hits": hits}


# --- Hydra + web_login_bruteforce: real credential brute-forcing, network services and web login
# forms. A genuine multi-minute run, so unlike every other tool above this doesn't block the
# calling turn at all -- *_start fires it in the background (agent/tools/background_jobs.py) and
# returns a job_id immediately; background_job_check (shared, tool-agnostic) polls it. ---

_HYDRA_LOCKOUT_SIGNALS = (
    "captcha", "too many attempts", "too many failed", "account locked", "account is locked",
    "temporarily blocked", "temporarily locked", "rate limit", "try again later", "please wait before",
)


def _hydra_http_form_preflight(params: dict) -> str | None:
    """Real, empirical check for active brute-force defenses on an HTTP login form -- not a
    WAF-banner guess, an actual test: a few deliberately wrong login attempts, watching for a
    lockout/CAPTCHA/rate-limit signal in the real response. Returns a skip reason string if one
    fired, None if the form looks genuinely undefended (safe to proceed with the real run).
    Deliberately not implemented for network protocols (ssh/ftp/mysql/...) -- there is no single
    reliable, protocol-agnostic technique for it the way there is for an HTTP response; forcing a
    weak/unreliable version of this for those would give false confidence, worse than having none.
    """
    login_path = params.get("login_path")
    if not login_path:
        return None  # nothing to preflight without a login path -- build_hydra_command will
        # reject the call outright for missing login_path anyway
    target = str(params["target"]).rstrip("/")
    url = target + login_path
    username_field = str(params.get("username_field") or "username")
    password_field = str(params.get("password_field") or "password")
    headers = _merged_target_headers(params)

    durations: list[float] = []
    bodies: list[str] = []
    statuses: list[int] = []
    try:
        with httpx.Client(timeout=10.0, follow_redirects=True, headers=headers) as client:
            for attempt in range(3):
                start = time.monotonic()
                resp = _with_hard_deadline(
                    lambda a=attempt: client.post(url, data={username_field: "asra_preflight_probe", password_field: f"wrong_{a}_{uuid.uuid4().hex[:6]}"}),
                    10.0,
                )
                durations.append(time.monotonic() - start)
                bodies.append(resp.text.lower())
                statuses.append(resp.status_code)
    except httpx.HTTPError:
        return None  # can't reach it at all -- not a defense signal, the real run's own error handling reports this honestly instead

    if any(signal in body for body in bodies for signal in _HYDRA_LOCKOUT_SIGNALS):
        return "login form's response contained a lockout/CAPTCHA/rate-limit indicator during preflight probing"
    if statuses[0] not in (403, 429, 503) and statuses[-1] in (403, 429, 503):
        return f"login form started returning HTTP {statuses[-1]} after only {len(statuses)} preflight attempts — active rate limiting"
    if durations[-1] > durations[0] * 3 and durations[-1] > 2.0:
        return "login form's response time grew sharply across preflight attempts — possible progressive throttling"
    return None


def hydra_start(params: dict) -> dict:
    """Starts a real Hydra brute-force run in the background — returns a job_id immediately, call
    background_job_check with it to poll for the result (it's fine to check other findings/call
    other tools in between, same as oob_generate/oob_poll). See build_hydra_command for the full
    protocol/parameter shape (network services: ssh/ftp/telnet/mysql/postgres/rdp/smb; web login
    forms: http-post-form/http-get-form with structured login_path/username_field/password_field/
    failure_string fields — never raw Hydra module syntax).

    For http-post-form/http-get-form specifically, runs a real empirical preflight first (a
    handful of deliberately wrong login attempts, watching for a genuine lockout/CAPTCHA/
    rate-limit signal in the actual response) — if the target shows active brute-force defenses,
    this returns {"status": "skipped", "reason": ...} instead of ever starting the real run.

    Known, honest limitation carried over from Hydra itself: it cannot refresh a per-request CSRF
    token, so a login form that requires one will not work reliably here — use
    web_login_bruteforce instead for that case, which handles a real session/cookie jar and
    refetches the token on every attempt.
    """
    session_id = params.get("_session_id")
    session = params.get("_session")
    if not session_id or session is None:
        return {"status": "error", "error": "hydra_start requires session context"}

    protocol = str(params.get("protocol", "")).strip().lower()
    if protocol in ("http-post-form", "http-get-form"):
        skip_reason = _hydra_http_form_preflight(params)
        if skip_reason:
            return {"status": "skipped", "reason": skip_reason}

    max_concurrent = int(os.getenv("HYDRA_MAX_CONCURRENT_JOBS", "2"))
    timeout_seconds = int(os.getenv("HYDRA_TIMEOUT_SECONDS", "900"))

    def setup(job_id: str, job_dir: Path):
        command = build_hydra_command(params, job_id, job_dir)
        result_path = job_dir / f"{job_id}_result.json"
        return command, lambda _log_path: parse_hydra_result(result_path)

    try:
        # protocol stashed alongside target -- agent/core.py's _auto_record_cracked_credentials_finding
        # needs to know which Hydra module produced a "success" to weigh how much to trust it: the rdp
        # module specifically has a real, community-documented false-positive history (NLA/CredSSP
        # negotiation ambiguity can read as a successful login when it wasn't one) -- confirmed live in
        # this project (a real "successful" rdp crack that then failed every manual mstsc attempt with
        # the exact same credentials, no typos, no lockout, nothing else changed) -- while
        # ssh/ftp/mysql/postgres/smb complete a real protocol-level accept/reject and are treated as
        # reliable. Never recorded before this, so every prior hydra-sourced finding had no way to
        # carry this distinction.
        return start_background_job(session_id, session, "hydra", setup, max_concurrent, timeout_seconds, extra_metadata={"target": params.get("target"), "protocol": protocol})
    except ValueError as exc:
        return {"status": "error", "error": describe_exception(exc)}


def web_login_bruteforce_start(params: dict) -> dict:
    """Starts a real, CSRF-aware credential brute-force against a web login form in the
    background — returns a job_id immediately, call background_job_check with it to poll for the
    result. Unlike hydra_start's http-post-form/http-get-form (a static request body, rejected
    outright by any form requiring a per-request CSRF token), this maintains a real session/cookie
    jar and re-fetches the login page before every single attempt, extracting whatever CSRF-shaped
    hidden field it finds (the common framework conventions: csrf_token, csrfmiddlewaretoken,
    _token, authenticity_token, _csrf, __RequestVerificationToken, or a custom field name via
    csrf_field) — confirmed live against a real one-time-token login form that hydra's own
    http-post-form cannot get past at all.

    Same structured-fields contract as hydra_start's web-form mode (login_path/username_field/
    password_field/failure_string or success_string — never raw request-building), and the same
    real empirical preflight (a few deliberately wrong logins, checking for a genuine lockout/
    CAPTCHA/rate-limit signal) before ever starting the real run. Sequential, not multi-threaded
    (one attempt at a time, real cookies persisted throughout) — slower than Hydra for a form with
    no CSRF protection, but that's exactly the case hydra_start already covers; use this one
    specifically when a form needs a fresh token per request.
    """
    session_id = params.get("_session_id")
    session = params.get("_session")
    if not session_id or session is None:
        return {"status": "error", "error": "web_login_bruteforce_start requires session context"}

    skip_reason = _hydra_http_form_preflight(params)
    if skip_reason:
        return {"status": "skipped", "reason": skip_reason}

    max_concurrent = int(os.getenv("HYDRA_MAX_CONCURRENT_JOBS", "2"))
    timeout_seconds = int(os.getenv("HYDRA_TIMEOUT_SECONDS", "900"))

    def setup(job_id: str, job_dir: Path):
        command = build_web_login_bruteforce_command(params, job_id, job_dir)
        result_path = job_dir / f"{job_id}_result.json"
        return command, lambda _log_path: parse_web_login_bruteforce_result(result_path)

    try:
        return start_background_job(session_id, session, "web_login_bruteforce", setup, max_concurrent, timeout_seconds, extra_metadata={"target": params.get("target")})
    except ValueError as exc:
        return {"status": "error", "error": describe_exception(exc)}


def background_job_check(params: dict) -> dict:
    """Polls any *_start background job (hydra_start, web_login_bruteforce_start, ...) by its
    job_id — {"status": "running"} means genuinely still going (check again later), any other
    status ("ok"/"error"/"timeout"/"killed"/"interrupted") means it's actually done."""
    session_id = params.get("_session_id")
    session = params.get("_session")
    job_id = params.get("job_id")
    if not session_id or session is None:
        return {"status": "error", "error": "background_job_check requires session context"}
    if not job_id:
        return {"status": "error", "error": "job_id is required"}
    return check_background_job(session_id, session, job_id)


# --- AFL++ fuzzing (RE mode) -- reuses check_background_job above via job_id, no dedicated
# afl_fuzz_check needed. Fuzzing is inherently long-running (minutes, not the few seconds every
# other RE tool call here takes), the exact reason this goes through the SAME start-now/check-later
# background-job machinery hydra_start/web_login_bruteforce_start already use, not a plain
# synchronous subprocess call the rest of agent/tools/builders/*.py's RE tools are.
#
# Dumb/non-instrumented mode (-n), not QEMU mode (-Q) -- confirmed live this is the only mode that
# actually works with what setup_tools.sh's own install_afl installs: `-Q` needs a real
# afl-qemu-trace binary, which the apt afl++ package does NOT ship (only a static
# libAFLQemuDriver.a, confirmed by inspecting the package contents directly) -- building QEMU mode
# from source is a genuinely heavy, slow compile step, not something to silently claim works when
# it doesn't. Dumb mode has no coverage feedback (it can't tell a "new" execution path from an
# already-seen one, so it fuzzes less efficiently than instrumented AFL normally would), but it
# needs nothing beyond the target binary itself -- the honest, actually-working choice for a
# black-box RE target with no source to recompile.
def _afl_seed_corpus(job_dir: Path) -> Path:
    seed_dir = job_dir / "afl_input"
    seed_dir.mkdir(parents=True, exist_ok=True)
    seed_file = seed_dir / "seed1"
    if not seed_file.exists():
        seed_file.write_bytes(b"AAAAAAAA\n")
    return seed_dir


def _parse_afl_result(output_dir: Path) -> dict:
    # Confirmed live: a single fuzzer instance with no -M/-S name writes crashes/hangs/queue
    # DIRECTLY under the given -o directory, not into an "-o/default/" subdirectory the way some
    # AFL++ docs/examples (multi-instance -M/-S setups) might suggest.
    crashes_dir = output_dir / "crashes"
    hangs_dir = output_dir / "hangs"
    crashes = sorted(p.name for p in crashes_dir.glob("*") if p.is_file() and p.name != "README.txt") if crashes_dir.is_dir() else []
    hangs = sorted(p.name for p in hangs_dir.glob("*") if p.is_file() and p.name != "README.txt") if hangs_dir.is_dir() else []
    return {
        "crashes_found": len(crashes),
        "hangs_found": len(hangs),
        "crash_files": [str(crashes_dir / c) for c in crashes[:20]],
        "hang_files": [str(hangs_dir / h) for h in hangs[:20]],
        "output_dir": str(output_dir),
    }


def afl_fuzz_start(params: dict) -> dict:
    """Starts a real AFL++ dumb-mode (-n) fuzzing run against a local binary in the background --
    returns a job_id immediately, call background_job_check with it to poll for the result (crash/
    hang counts + file paths once it finishes). input_mode="file" (default) fuzzes a binary that
    takes a file argument (AFL's own @@ placeholder, substituted with the current test case's own
    path); input_mode="stdin" fuzzes a binary that reads its input from stdin instead (no @@, AFL
    feeds stdin directly). duration_seconds bounds the real fuzzing time (afl-fuzz's own -V flag,
    best-effort -- the background-job machinery's own hard deadline kill is the real, guaranteed
    backstop regardless of whether -V itself terminates cleanly). A trivial single-byte-string seed
    is auto-generated if the model doesn't need anything more specific -- AFL requires at least one
    non-empty seed file to start at all.
    """
    session_id = params.get("_session_id")
    session = params.get("_session")
    if not session_id or session is None:
        return {"status": "error", "error": "afl_fuzz_start requires session context"}

    file_path = str(params.get("file_path") or "").strip()
    if not file_path or not os.path.isfile(file_path):
        return {"status": "error", "error": f"file not found: {file_path!r}"}

    input_mode = params.get("input_mode", "file")
    if input_mode not in ("file", "stdin"):
        return {"status": "error", "error": "input_mode must be 'file' or 'stdin'"}

    duration_seconds = max(10, min(int(params.get("duration_seconds", 120)), 1800))
    max_concurrent = int(os.getenv("AFL_MAX_CONCURRENT_JOBS", "1"))
    # Real headroom over afl-fuzz's own -V budget before the job-level hard kill fires -- confirmed
    # live -V's own self-termination is NOT reliable in this project's own WSL2 dev environment at
    # all (a real -V 10 run never self-stopped even 115s past its own deadline; the hard kill below
    # is what actually ended it, right on schedule, at duration_seconds + this margin). Kept
    # deliberately small (not the much larger margin an initial guess used) precisely BECAUSE -V
    # is confirmed unreliable here -- the hard kill is doing the real work regardless, so a smaller
    # margin keeps the tool's own "duration_seconds bounds the real time" claim honest instead of
    # silently running ~2 extra minutes past what the caller actually asked for.
    timeout_seconds = duration_seconds + 30

    def setup(job_id: str, job_dir: Path):
        seed_dir = _afl_seed_corpus(job_dir)
        output_dir = job_dir / f"{job_id}_out"
        target_args = [file_path, "@@"] if input_mode == "file" else [file_path]
        command = ["afl-fuzz", "-i", str(seed_dir), "-o", str(output_dir), "-n", "-V", str(duration_seconds), "--", *target_args]
        return command, lambda _log_path: _parse_afl_result(output_dir)

    return start_background_job(
        session_id, session, "afl_fuzz", setup, max_concurrent, timeout_seconds,
        extra_metadata={"file_path": file_path},
        extra_env={"AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1"},
    )


# --- Authenticated identities: IDOR / broken access control testing. Real proof for the highest-
# value bug-bounty category none of the recon/scan tools above can ever reach at all — every one
# of them is unauthenticated by design. Credentials come from the New Project form (optional,
# per-project), stored in data/credentials/<session_id>.json — deliberately never rendered in any
# template, never included in Export Proof, and never passed as raw text into an LLM prompt: the
# model only ever sees an identity's NAME ("user_a"/"user_b"), agent/core.py injects the real
# session_id server-side right before dispatch (_run_tool_with_retry) so the model can't supply a
# different one and read another project's credentials. ---

# Global app data (Documents/ASRA/data, see projects/paths.py) -- real plaintext login credentials
# for a real target account, no business living inside the git checkout's own data/ folder.
_CREDENTIALS_DIR = resolve_global_app_dir() / "data" / "credentials"

# In-memory only, keyed by (session_id, identity) — the actual logged-in cookie jar/session is
# never written to disk (nothing here ever touches session.json), so a login only happens once per
# identity per server process, reused across every subsequent authenticated_request call.
_authenticated_clients: dict[tuple[str, str], httpx.Client] = {}


def _load_credentials(session_id: str) -> dict:
    path = _CREDENTIALS_DIR / f"{session_id}.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_identity_credentials(session_id: str, identities: dict) -> None:
    """Writes the New Project form's optional identity fields to this project's credential
    store — called once at project creation (main.py's start_scan), never updated afterward
    through this UI. Only identities that actually have at least one non-empty field get written,
    so a project with nothing configured has no file at all rather than an empty stub.
    """
    non_empty = {name: creds for name, creds in identities.items() if any(creds.values())}
    if not non_empty:
        return
    _CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
    path = _CREDENTIALS_DIR / f"{session_id}.json"
    path.write_text(json.dumps(non_empty, indent=2), encoding="utf-8")


def register_discovered_credential(
    session_id: str, identity_name: str, username: str, password: str, login_url: str | None,
    *, email: str | None = None, cookie: str | None = None, authorization_header: str | None = None,
) -> None:
    """Upserts one identity into this project's credential store (data/credentials/<session_id>.json)
    mid-session -- unlike save_identity_credentials above (write-once, only ever called from the New
    Project form at project-creation time), this is called by agent/core.py's deterministic
    asset-graph tracking (_update_asset_graph) whenever default_creds_check/web_self_register finds
    a real working web login pair, and by main.py's own manual "Add credential" route (Recon tab),
    so it becomes immediately usable via authenticated_request/idor_probe's own identity= lookup
    (_get_authenticated_client below) without the operator manually re-typing it into a form field
    mid-scan.

    login_url is optional here (unlike the original default_creds_check-only contract) --
    web_self_register can already have a real, live authenticated cookie jar in hand right after a
    successful registration (many signup flows auto-login), in which case there is no separate
    login step to replay later and login_url would only cause _get_authenticated_client to
    needlessly re-POST to it. email/cookie/authorization_header are optional, same "only write a
    field when a caller actually has one" posture as save_identity_credentials.
    """
    existing = _load_credentials(session_id)
    entry: dict = {"username": username, "password": password, "login_url": login_url}
    if email:
        entry["email"] = email
    if cookie:
        entry["cookie"] = cookie
    if authorization_header:
        entry["authorization_header"] = authorization_header
    existing[identity_name] = entry
    _CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
    path = _CREDENTIALS_DIR / f"{session_id}.json"
    path.write_text(json.dumps(existing, indent=2), encoding="utf-8")


# Fields ever written into a data/credentials/<session_id>.json entry (save_identity_credentials/
# register_discovered_credential above) -- the one place both list_identity_field_presence and
# reveal_identity_field below enumerate/validate against, so a new field added to one automatically
# shows up (masked) and becomes revealable in the other without a second list to keep in sync.
_IDENTITY_FIELD_NAMES = ("username", "email", "password", "login_url", "cookie", "authorization_header")


def list_identity_field_presence(session_id: str) -> dict[str, dict[str, bool]]:
    """Presence-only view of this project's credential store -- Recon tab's Credentials card
    (templates/partials/session_fragment.html) renders every configured identity's own fields
    masked by default (an eye button reveals one via reveal_identity_field below), so the initial
    page render needs to know WHICH fields exist for each identity to draw a mask placeholder for,
    without the real values ever entering the Jinja render context at all -- the standing
    "never shown again in this UI" contract these credentials were originally written under
    (save_identity_credentials's own docstring) only ever meant "never by default", not "no
    operator-owned reveal control can ever exist"; this keeps that same discipline (real secrets
    reach a rendered page only through the one dedicated, explicit-click reveal endpoint) rather
    than loosening it into passing the raw dict straight into a template.
    """
    return {
        identity_name: {field: bool(creds.get(field)) for field in _IDENTITY_FIELD_NAMES}
        for identity_name, creds in _load_credentials(session_id).items()
    }


def reveal_identity_field(session_id: str, identity_name: str, field: str) -> str | None:
    """The one place a real credential value is ever read back out for display -- backs the Recon
    tab's per-field eye-icon reveal (main.py's reveal_identity_field route). Returns None for an
    unknown identity/field or a field that's genuinely empty, which the route treats as a 404 rather
    than ever rendering a blank/placeholder value as if it were a real one.
    """
    if field not in _IDENTITY_FIELD_NAMES:
        return None
    value = _load_credentials(session_id).get(identity_name, {}).get(field)
    return value or None


def _get_authenticated_client(session_id: str, identity: str, params: dict | None = None) -> httpx.Client | dict:
    cache_key = (session_id, identity)
    if cache_key in _authenticated_clients:
        return _authenticated_clients[cache_key]

    creds = _load_credentials(session_id).get(identity)
    if not creds:
        # Real, confirmed incident this message wording fixes (same family as is_target_allowed's
        # own permanence wording, agent/tools/runner.py's _check_guardrail): a project with zero
        # configured identities got authenticated_request/authenticated_crawl/cors_credentialed_check
        # retried across a DIFFERENT identity name or a different URL each time, evading
        # _MAX_IDENTICAL_FAILURES_PER_PHASE's exact-signature dedup since the arguments genuinely
        # differed call to call -- but no identity name or URL could ever fix this: this project's
        # own credential store is empty, full stop, for the rest of the session.
        return {
            "status": "error",
            "error": (
                f"No credentials configured for identity {identity!r} on this project — this is a "
                "permanent, deterministic condition for this project for the rest of this session, "
                "not something a different identity name or a different target URL will fix (Settings "
                "has no retroactive way to add them; they can only be set on the New Project form at "
                "creation time). If this project genuinely has no configured identities at all, stop "
                "retrying credentialed tools against it and continue with unauthenticated checks instead."
            ),
        }

    target_headers = _merged_target_headers(params or {})
    client = httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, headers=target_headers or None)
    if creds.get("cookie"):
        client.headers["Cookie"] = creds["cookie"]
    if creds.get("authorization_header"):
        client.headers["Authorization"] = creds["authorization_header"]

    # username and email are separate New Project form fields (not one ambiguous "username or
    # email" box) because real login forms differ on which one they actually key off — some want
    # a handle, some specifically require an email address. Send whichever were actually given
    # (both, if both were): an extra field a login endpoint doesn't recognize is normally just
    # ignored, so this is strictly more likely to match the target's real field than guessing one.
    if creds.get("login_url") and creds.get("password") and (creds.get("username") or creds.get("email")):
        login_data = {creds.get("password_field") or "password": creds["password"]}
        if creds.get("username"):
            login_data[creds.get("username_field") or "username"] = creds["username"]
        if creds.get("email"):
            login_data[creds.get("email_field") or "email"] = creds["email"]
        try:
            _with_hard_deadline(lambda: client.post(creds["login_url"], data=login_data), _HTTP_TIMEOUT)
        except httpx.HTTPError as exc:
            client.close()
            return {"status": "error", "error": f"login request for identity {identity!r} failed: {exc}"}
        # No universal way to tell "login succeeded" from here (every app's success signal is
        # different) — the model judges that from the first real authenticated_request response
        # itself (its status code/body), not from a guess made at login time.

    _authenticated_clients[cache_key] = client
    return client


def get_identity_browser_creds(session_id: str, identity: str, params: dict | None = None) -> dict:
    """Playwright-side counterpart to _get_authenticated_client above -- reuses the SAME httpx
    login (including its cache, _authenticated_clients) and translates its cookie jar/Authorization
    header into the shapes Playwright's BrowserContext.add_cookies()/set_extra_http_headers()
    expect, so browser_navigate(identity=...) (agent/tools/browser_manager.py) can drive a real
    Chromium session as a configured identity. No login logic is duplicated here and no credential
    ever reaches the model -- browser_navigate's own JSON schema only ever takes an identity NAME,
    exactly the same posture authenticated_request/idor_probe already use.

    Two distinct sources of cookies must both be covered, not just one: a login_url flow's response
    Set-Cookie header lands in client.cookies.jar (httpx's normal cookie-jar handling), but a
    manually-pasted creds["cookie"] (_get_authenticated_client above) is set as a raw Cookie
    *header* instead, never touching the jar at all -- reading only the jar would silently produce
    zero cookies for that (very common: operator pastes a captured session cookie) identity shape.
    Forwarded as a literal Cookie extra-header instead of parsed into individual add_cookies()
    entries -- simpler, and correct either way since the target only ever sees the same raw string.
    """
    client = _get_authenticated_client(session_id, identity, params)
    if isinstance(client, dict):
        return client
    cookies = [
        {
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path or "/",
            "expires": cookie.expires if cookie.expires else -1,
            "secure": bool(cookie.secure),
        }
        for cookie in client.cookies.jar
    ]
    headers = {}
    auth_header = client.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header
    cookie_header = client.headers.get("Cookie")
    if cookie_header:
        headers["Cookie"] = cookie_header
    return {"status": "ok", "cookies": cookies, "headers": headers}


def authenticated_request(params: dict) -> dict:
    """Makes an HTTP request as one of this project's configured identities (user_a/user_b —
    whichever have credentials set), reusing the same logged-in session/cookie jar across calls.
    This is how to test authenticated endpoints and, specifically, IDOR/broken access control:
    act as one identity to create or note a resource's ID, then request that SAME id as the
    OTHER identity — if the second identity can read or modify it, that is real, confirmed,
    remote_direct proof, not an inference. Requires the target to be in the exploitation
    allowlist and the session to be human-approved, same as the exploit/sqlmap tools — but unlike
    those, calling this more than once for the same finding is expected and allowed (a real IDOR
    comparison needs at least two calls, one per identity).
    """
    session_id = params.get("_session_id")
    identity = params["identity"]
    client = _get_authenticated_client(session_id, identity, params)
    if isinstance(client, dict):
        return client

    # "target", not "url" — this is what the requires_allowed_target guardrail (run_tool()) reads
    # to check the allowlist, same convention every other gated tool (sqlmap, default_creds_check)
    # already uses; naming it something else here would silently skip that check.
    url = params["target"]
    method = params.get("method", "GET").upper()
    try:
        resp = _with_hard_deadline(lambda: client.request(method, url, data=params.get("data"), headers=params.get("headers")), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {
        "status": "ok",
        "identity": identity,
        "status_code": resp.status_code,
        "body_preview": resp.text[:2000],
        "headers": dict(resp.headers),
    }


_CRAWL_LINK_PATTERN = re.compile(r'''(?:href|src|action)=["']([^"'#][^"']*)["']''', re.IGNORECASE)


def authenticated_crawl(params: dict) -> dict:
    """Logs in as one of this project's configured identities (or crawls anonymously if no
    identity is given) and walks same-origin links/forms breadth-first from a starting URL,
    returning real observed endpoints with real status codes. Real incident this exists because
    of: live scans against bespoke web apps with identities configured never once discovered a
    real application endpoint on their own — Analyze only ever probed generic guessed paths
    (/admin, /api, /login), missing exactly the numeric-ID-bearing routes (an order, an inventory
    item, a user profile) that are the actual attack surface for IDOR/broken access control. Feed
    a discovered URL straight into authenticated_request or idor_probe next.
    """
    session_id = params.get("_session_id")
    identity = params.get("identity")
    start_url = params["start_url"]
    max_pages = max(1, min(int(params.get("max_pages", 20)), 40))

    if identity:
        client = _get_authenticated_client(session_id, identity, params)
        if isinstance(client, dict):
            return client
    else:
        client = httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params))

    origin_netloc = urlsplit(start_url).netloc
    visited: set[str] = set()
    queue: list[str] = [start_url]
    pages: list[dict] = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            resp = _with_hard_deadline(lambda u=url: client.get(u), _HTTP_TIMEOUT)
        except _HardDeadlineExceeded as exc:
            # Target unreachable -- every other queued page (same origin) would hit the same
            # wall, so stop crawling now instead of paying the hard deadline once per page.
            pages.append({"url": url, "error": describe_exception(exc)})
            break
        except httpx.HTTPError as exc:
            pages.append({"url": url, "error": describe_exception(exc)})
            continue

        pages.append({"url": url, "status_code": resp.status_code, "content_type": resp.headers.get("content-type", "")})

        if "text/html" not in resp.headers.get("content-type", ""):
            continue
        for link in _CRAWL_LINK_PATTERN.findall(resp.text):
            absolute = urljoin(url, link).split("#")[0]
            if urlsplit(absolute).netloc != origin_netloc:
                continue  # same-origin only — never follow the crawl off the target
            if absolute not in visited and absolute not in queue:
                queue.append(absolute)

    return {"status": "ok", "identity": identity or "unauthenticated", "pages_crawled": len(visited), "pages": pages}


def idor_probe(params: dict) -> dict:
    """Requests the exact same resource URL as two different identities (or one identity vs fully
    unauthenticated, when identity_b is omitted) and reports a deterministic, structured
    comparison — status codes, body length, and a body-similarity ratio — instead of requiring the
    model to eyeball two raw HTTP responses itself and judge whether they "look the same". A
    same-status-200 pair with a high similarity ratio is the actual shape of a confirmed IDOR;
    differing status codes (200 vs 401/403/404) is the actual shape of working access control.
    """
    session_id = params.get("_session_id")
    url = params["target"]
    identity_a = params["identity_a"]
    identity_b = params.get("identity_b")

    client_a = _get_authenticated_client(session_id, identity_a, params)
    if isinstance(client_a, dict):
        return client_a
    try:
        resp_a = _with_hard_deadline(lambda: client_a.get(url), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"identity_a request failed: {exc}"}

    if identity_b:
        client_b = _get_authenticated_client(session_id, identity_b, params)
        if isinstance(client_b, dict):
            return client_b
    else:
        client_b = httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params))
    try:
        resp_b = _with_hard_deadline(lambda: client_b.get(url), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"identity_b request failed: {exc}"}

    similarity = round(SequenceMatcher(None, resp_a.text[:5000], resp_b.text[:5000]).ratio(), 3)

    return {
        "status": "ok",
        "url": url,
        "identity_a": {"name": identity_a, "status_code": resp_a.status_code, "body_length": len(resp_a.text), "body_preview": resp_a.text[:1000]},
        "identity_b": {"name": identity_b or "unauthenticated", "status_code": resp_b.status_code, "body_length": len(resp_b.text), "body_preview": resp_b.text[:1000]},
        "body_similarity": similarity,
        "likely_idor": resp_a.status_code == 200 and resp_b.status_code == 200 and similarity > 0.8,
    }


_UUID_PATTERN = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_OBJECT_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{24}$")
_RESOURCE_ID_QUERY_PARAM_PATTERN = re.compile(r"(?:^|[?&])(?:[A-Za-z_]*id|uid)=([^&]+)", re.IGNORECASE)
# Bulk detail (a body_preview per swept entry) is capped independently of how many entries get
# replayed at all (authz_diff_sweep's own max_candidates) -- the whole reason max_candidates can
# default generously without risking a flooded context: raising how much gets CHECKED only grows
# the compact per-entry rows, never the expensive part, since that's capped here instead.
_AUTHZ_SWEEP_MAX_DETAILED_HITS = 15


def _looks_like_resource_identifier(segment: str) -> bool:
    return segment.isdigit() or bool(_UUID_PATTERN.match(segment)) or bool(_OBJECT_ID_PATTERN.match(segment))


def _url_addresses_a_specific_resource(url: str) -> bool:
    """True when `url`'s path or query string names one specific resource by a numeric/UUID/
    ObjectId identifier -- the actual shape an IDOR/broken-access-control bug lives on (an order, a
    profile, an inventory item), as opposed to a static asset or a collection-level endpoint with
    no single resource named at all. Used to filter authz_diff_sweep's candidates down to entries
    actually worth a replay, out of everything the Proxy happened to capture."""
    parsed = urlsplit(url)
    if any(_looks_like_resource_identifier(segment) for segment in parsed.path.split("/") if segment):
        return True
    return any(_looks_like_resource_identifier(value) for value in _RESOURCE_ID_QUERY_PARAM_PATTERN.findall(parsed.query))


def _decoded_request_body(entry: dict) -> str | bytes | None:
    body = entry.get("request_body")
    if not body:
        return None
    if entry.get("request_body_encoding") == "base64":
        return base64.b64decode(body)
    return body


def _authz_sweep_candidates(session_id: str | None, include_mutating: bool) -> tuple[list[dict], int]:
    """Every captured traffic entry (agent/tools/toolkit_store.py's Site Map -- everything the
    Proxy saw while the agent/operator actually browsed the real app, including a SPA's own
    fetch/XHR calls an HTML-link crawl never sees at all) worth an authz replay: a request that
    carried real auth (a Cookie or Authorization header) and addresses one specific resource by id.
    Deduplicated by (method, url), keeping the freshest capture of each -- the same endpoint is
    routinely hit many times in one browsing session (pagination, polling, repeat navigation).
    Second return value is how many candidates were skipped purely for being a non-GET/HEAD method
    while include_mutating is False -- surfaced to the caller so the sweep result can say WHY an
    endpoint it clearly saw wasn't swept, instead of silently dropping it.
    """
    candidates_by_key: dict[tuple[str, str], dict] = {}
    order: list[tuple[str, str]] = []
    mutating_skipped = 0
    for entry in toolkit_store.load_traffic_entries(session_id):
        url = entry.get("url") or ""
        if entry.get("response_status") is None or not url:
            continue
        if not _url_addresses_a_specific_resource(url):
            continue
        headers = entry.get("request_headers") or {}
        if not any(name.lower() in ("cookie", "authorization") for name in headers):
            continue
        method = (entry.get("method") or "GET").upper()
        if method not in ("GET", "HEAD"):
            if not include_mutating:
                mutating_skipped += 1
                continue
        key = (method, url)
        if key not in candidates_by_key:
            order.append(key)
        candidates_by_key[key] = entry  # last (freshest) capture for this method+url wins
    return [candidates_by_key[key] for key in order], mutating_skipped


def authz_diff_sweep(params: dict) -> dict:
    """Bulk broken-access-control/IDOR sweep over traffic ALREADY captured this session (the
    native Proxy's Site Map, agent/tools/toolkit_store.py) -- the batch counterpart to idor_probe.
    Instead of the model picking one URL at a time, this replays every already-observed,
    resource-shaped, authenticated request as `identity_b` in one call and diffs each against the
    response ALREADY captured for it (no second live request needed for the original identity --
    that traffic already happened when the app was actually browsed/crawled). Covers real endpoints
    an HTML-link crawl (authenticated_crawl) structurally cannot see -- a single-page app's own
    fetch/XHR calls only ever show up in real captured network traffic, never in server-rendered
    HTML.

    Only GET/HEAD requests are replayed automatically (include_mutating=True opts into replaying
    state-changing methods too) -- a bulk sweep silently re-firing a real POST/PUT/DELETE risks a
    duplicate real-world side effect (a second purchase, a second delete) the operator never asked
    for; use idor_probe/authenticated_request by hand for one specific mutating endpoint instead.

    Response size is decoupled from max_candidates by design: every swept entry gets one compact
    row (status codes + similarity + likely_idor, no body), but a full body_preview is only
    attached for entries flagged likely_idor (capped separately). Raising max_candidates to sweep
    more of a large site map costs replay time, not context -- it only grows the compact rows,
    never the expensive part.
    """
    session_id = params.get("_session_id")
    target = params.get("target")
    identity_b = params["identity_b"]
    include_mutating = bool(params.get("include_mutating", False))
    max_candidates = max(1, min(int(params.get("max_candidates", 50)), 150))

    client_b = _get_authenticated_client(session_id, identity_b, params)
    if isinstance(client_b, dict):
        return client_b

    candidates, mutating_skipped = _authz_sweep_candidates(session_id, include_mutating)
    in_scope = [entry for entry in candidates if is_target_allowed(entry["url"])]
    out_of_scope_skipped = len(candidates) - len(in_scope)
    swept = in_scope[:max_candidates]
    capped = len(in_scope) > max_candidates

    rows: list[dict] = []
    all_hits: list[dict] = []
    for entry in swept:
        method = (entry.get("method") or "GET").upper()
        request_body = None
        replay_headers: dict[str, str] = {}
        if method not in ("GET", "HEAD"):
            request_body = _decoded_request_body(entry)
            request_headers = entry.get("request_headers") or {}
            content_type = request_headers.get("Content-Type") or request_headers.get("content-type")
            if content_type:
                replay_headers["Content-Type"] = content_type

        try:
            resp = _with_hard_deadline(
                lambda e=entry, m=method, b=request_body, h=replay_headers: client_b.request(
                    m, e["url"],
                    content=b if isinstance(b, bytes) else None,
                    data=b if isinstance(b, str) else None,
                    headers=h or None,
                ),
                _HTTP_TIMEOUT,
            )
        except httpx.HTTPError as exc:
            rows.append({"url": entry["url"], "method": method, "status_a": entry.get("response_status"), "error": describe_exception(exc)})
            continue

        row = {"url": entry["url"], "method": method, "status_a": entry.get("response_status"), "status_b": resp.status_code}
        if entry.get("response_body_encoding") == "text" and entry.get("response_body"):
            original_body = entry["response_body"]
            similarity = round(SequenceMatcher(None, original_body[:5000], resp.text[:5000]).ratio(), 3)
            likely_idor = entry.get("response_status") == 200 and resp.status_code == 200 and similarity > 0.8
            row["body_similarity"] = similarity
            row["likely_idor"] = likely_idor
            if likely_idor:
                all_hits.append({**row, "original_body_preview": original_body[:1000], "identity_b_body_preview": resp.text[:1000]})
        else:
            row["body_similarity"] = None
            row["likely_idor"] = False
            row["note"] = "original captured response body wasn't text -- status-only comparison"
        rows.append(row)

    hits = all_hits[:_AUTHZ_SWEEP_MAX_DETAILED_HITS]

    logger.debug(
        "native: authz_diff_sweep session=%s target=%r identity_b=%s candidates=%d in_scope=%d swept=%d likely_idor=%d capped=%s",
        session_id, target, identity_b, len(candidates), len(in_scope), len(swept), len(all_hits), capped,
    )

    return {
        "status": "ok",
        "target": target,
        "identity_b": identity_b,
        "captured_traffic_candidates_found": len(candidates),
        "skipped_out_of_scope": out_of_scope_skipped,
        "skipped_mutating_methods": mutating_skipped,
        "swept_count": len(swept),
        "capped": capped,
        "likely_idor_count": len(all_hits),
        "results": rows,
        "likely_idor_hits": hits,
        "likely_idor_hits_truncated": len(all_hits) > len(hits),
    }


def _graphql_response_outcome(resp: httpx.Response) -> dict:
    """A GraphQL response is almost always HTTP 200 whether the operation actually succeeded or was
    denied -- the real success/denial signal lives in the JSON body's own "errors" array and
    whether "data" actually holds real (non-null) values, not the status code. Shared by
    graphql_authz_probe's own comparison below; never inferred from status code alone, unlike a
    REST-style check (idor_probe above).
    """
    try:
        body = resp.json()
    except ValueError:
        body = None
    errors = (body.get("errors") if isinstance(body, dict) else None) or []
    data = body.get("data") if isinstance(body, dict) else None
    has_real_data = isinstance(data, dict) and any(v is not None for v in data.values())
    return {"status_code": resp.status_code, "has_errors": bool(errors), "has_real_data": has_real_data, "body_preview": resp.text[:1000]}


def graphql_authz_probe(params: dict) -> dict:
    """Fires the SAME already-constructed GraphQL query/mutation as two different identities (or
    one identity vs fully unauthenticated, when identity_b is omitted) and reports a deterministic
    comparison -- exactly idor_probe's own approach, applied to a GraphQL POST body instead of a
    REST URL. Covers two real vulnerability classes with the same mechanism, distinguished only by
    which query the caller hands in: a mutation/query that should require an elevated role
    (field-level broken access control), or a query with a nested selection keyed by another
    identity's own ID, e.g. "user(id: 5) { orders { total } }" (nested-query IDOR). This tool never
    constructs the query itself -- api_schema_discovery's queryable_fields/mutations (name + arg
    names) is the real material to hand-write one from, the same way a manual REST endpoint would be.

    GraphQL-aware unlike idor_probe's raw status-code comparison: a 200 response with a populated
    "errors" array is a denial, not a success -- reading status code alone here would misread an
    access-denied error response as a working access-control bypass.
    """
    session_id = params.get("_session_id")
    url = params["target"]
    query = params["query"]
    variables = params.get("variables") or {}
    identity_a = params["identity_a"]
    identity_b = params.get("identity_b")
    payload = json.dumps({"query": query, "variables": variables})
    headers = {"Content-Type": "application/json"}

    client_a = _get_authenticated_client(session_id, identity_a, params)
    if isinstance(client_a, dict):
        return client_a
    try:
        resp_a = _with_hard_deadline(lambda: client_a.post(url, content=payload, headers=headers), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"identity_a request failed: {exc}"}

    if identity_b:
        client_b = _get_authenticated_client(session_id, identity_b, params)
        if isinstance(client_b, dict):
            return client_b
    else:
        client_b = httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params))
    try:
        resp_b = _with_hard_deadline(lambda: client_b.post(url, content=payload, headers=headers), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"identity_b request failed: {exc}"}

    outcome_a = _graphql_response_outcome(resp_a)
    outcome_b = _graphql_response_outcome(resp_b)
    similarity = round(SequenceMatcher(None, resp_a.text[:5000], resp_b.text[:5000]).ratio(), 3)

    return {
        "status": "ok",
        "url": url,
        "identity_a": {"name": identity_a, **outcome_a},
        "identity_b": {"name": identity_b or "unauthenticated", **outcome_b},
        "body_similarity": similarity,
        "likely_broken_access_control": (
            not outcome_a["has_errors"] and outcome_a["has_real_data"] and outcome_a["status_code"] == 200
            and not outcome_b["has_errors"] and outcome_b["status_code"] == 200
            and similarity > 0.8
        ),
    }


_MAX_BATCH_COUNT = 10  # same 2-10-real-requests DoS-safety cap EXPLOIT_PROMPT already establishes
# for concurrent-request race-condition tests (agent/prompts.py) -- never a bare, newly-invented
# number, and never a genuine flood: one real HTTP request either way, just with more operations
# aliased inside it.


def _graphql_arg_literal(value) -> str:
    """Serializes ONE Python scalar into GraphQL argument literal syntax. Deliberately scalar-only
    (str/int/float/bool/None) -- a real input OBJECT/list/enum value needs real schema-type
    awareness this project has no GraphQL client dependency for; this covers the overwhelmingly
    common case (a login/lookup mutation's own scalar arguments) without pretending to support more.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    # GraphQL string literals use the same escaping rules as JSON strings -- json.dumps on a plain
    # str gives correctly quoted+escaped output for free, no bespoke escaping logic needed.
    return json.dumps(str(value))


def graphql_batching_probe(params: dict) -> dict:
    """Builds ONE GraphQL request containing multiple ALIASED copies of the same query/mutation
    field call and fires it as a SINGLE HTTP request -- real evidence for whether a per-REQUEST rate
    limiter (a login form, coupon redemption, an OTP check) can be bypassed by batching many
    operations into one call instead of sending them as separate requests. Bounded at
    _MAX_BATCH_COUNT, same cap EXPLOIT_PROMPT already establishes for concurrent-request
    race-condition tests -- never a genuine flood, exactly one real HTTP request either way.

    Structured params (operation_type/field_name/arguments/selection), not a raw query string this
    tool would have to parse -- it builds the query itself, so a caller can never hand in something
    that fails to parse.
    """
    session_id = params.get("_session_id")
    url = params["target"]
    operation_type = params.get("operation_type", "mutation")
    if operation_type not in ("query", "mutation"):
        return {"status": "error", "error": f"operation_type must be 'query' or 'mutation', got {operation_type!r}"}
    field_name = params["field_name"]
    arguments = params.get("arguments") or {}
    selection = params.get("selection") or "__typename"
    count = max(1, min(int(params.get("count", 5)), _MAX_BATCH_COUNT))
    identity = params.get("identity")

    args_literal = ", ".join(f"{key}: {_graphql_arg_literal(value)}" for key, value in arguments.items())
    args_clause = f"({args_literal})" if args_literal else ""
    aliases = [f"a{i}" for i in range(count)]
    body = " ".join(f"{alias}: {field_name}{args_clause} {{ {selection} }}" for alias in aliases)
    query = f"{operation_type} {{ {body} }}"
    payload = json.dumps({"query": query})
    headers = {"Content-Type": "application/json"}

    if identity:
        client = _get_authenticated_client(session_id, identity, params)
        if isinstance(client, dict):
            return client
    else:
        client = httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params))

    try:
        resp = _with_hard_deadline(lambda: client.post(url, content=payload, headers=headers), _HTTP_TIMEOUT)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"batched request failed: {exc}"}

    try:
        body_json = resp.json()
    except ValueError:
        return {"status": "error", "error": "response was not valid JSON", "status_code": resp.status_code, "body_preview": resp.text[:1000]}

    data = body_json.get("data") if isinstance(body_json, dict) else None
    top_level_errors = body_json.get("errors") if isinstance(body_json, dict) else None

    # GraphQL error objects MAY carry a "path" pinpointing which aliased field they belong to --
    # used when present so a partial-failure batch shows exactly which alias(es) actually errored,
    # not just an undifferentiated top-level errors count.
    errors_by_alias: dict[str, list[str]] = {}
    for err in (top_level_errors or []):
        path = err.get("path") if isinstance(err, dict) else None
        if isinstance(path, list) and path and path[0] in aliases:
            errors_by_alias.setdefault(path[0], []).append(err.get("message", ""))

    per_alias = {}
    succeeded_count = 0
    for alias in aliases:
        alias_errors = errors_by_alias.get(alias, [])
        succeeded = (data or {}).get(alias) is not None and not alias_errors
        if succeeded:
            succeeded_count += 1
        per_alias[alias] = {"succeeded": succeeded, "errors": alias_errors}

    return {
        "status": "ok",
        "query_sent": query,
        "status_code": resp.status_code,
        "total_count": count,
        "succeeded_count": succeeded_count,
        "per_alias": per_alias,
        "top_level_errors_present": bool(top_level_errors),
    }


# --- OOB (out-of-band) interaction: real proof for the one class of finding no other tool here
# can confirm at all — blind SSRF, blind XSS, blind command/XXE injection, anything whose only
# observable effect happens server-side with nothing reflected back in the HTTP response. Backed
# by interactsh (github.com/projectdiscovery/interactsh, same maintainer as nuclei) — a unique
# throwaway domain that logs any DNS/HTTP interaction against it, decrypted and reported by the
# official client so this file never has to implement interactsh's crypto handshake itself. ---

# Global app data (Documents/ASRA/data, see projects/paths.py) -- a real RSA private key per
# session, no business living inside the git checkout's own data/ folder.
_OOB_SESSIONS_DIR = resolve_global_app_dir() / "data" / "oob_sessions"
_OOB_DOMAIN_PATTERN = re.compile(r"\b[a-z0-9]{15,45}\.oast\.[a-z]+\b")


def _interactsh_client_path() -> str | None:
    override = os.getenv("INTERACTSH_CLIENT_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    return shutil.which("interactsh-client")


def _run_interactsh(args: list[str], run_seconds: int) -> str:
    """Runs interactsh-client for a bounded window, ending it with SIGINT rather than a hard
    kill — confirmed live that only SIGINT reliably flushes the session file (oob_generate) and
    any buffered interaction JSONL already printed to stdout (oob_poll) before the process exits;
    a hard kill silently drops both.
    """
    # stdin=DEVNULL -- see runner.py's _run_tracked for the real incident (interactive-prompt hang
    # eating the whole subprocess timeout) this closes across every dispatch, not just one.
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True)
    try:
        stdout, _ = proc.communicate(timeout=run_seconds)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()
    return stdout or ""


def oob_generate(params: dict) -> dict:
    """Registers a new OOB interaction session and returns a real, unique domain — inject it
    into a payload wherever a target might fetch/resolve a URL server-side (an SSRF-shaped
    parameter, a blind-XSS sink, an XXE external entity, a blind command-injection probe like
    `curl <domain>`). Nothing is confirmed yet at this point; call oob_poll with the same token
    later, after whatever used the payload had a real chance to actually fire.
    """
    executable = _interactsh_client_path()
    if executable is None:
        return {"status": "tool_unavailable", "tool": "oob_generate"}

    token = uuid.uuid4().hex[:12]
    _OOB_SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    session_path = _OOB_SESSIONS_DIR / f"{token}.json"

    output = _run_interactsh(
        [executable, "-json", "-n", "1", "-disable-update-check", "-session-file", str(session_path)],
        run_seconds=6,
    )
    match = _OOB_DOMAIN_PATTERN.search(output)
    if not match:
        return {"status": "error", "error": "interactsh-client did not return a payload domain"}

    return {"status": "ok", "token": token, "domain": match.group(0)}


def oob_poll(params: dict) -> dict:
    """Checks a previously oob_generate'd session (by its token) for any real interaction logged
    since it was created. A non-empty "interactions" list is real proof something — a server, a
    victim's browser, whatever received the payload — actually reached out to the domain; an
    empty list just means nothing has happened yet (it's fine to poll more than once).
    """
    token = params["token"]
    session_path = _OOB_SESSIONS_DIR / f"{token}.json"
    if not session_path.exists():
        return {"status": "error", "error": f"unknown oob token {token!r} — call oob_generate first"}

    executable = _interactsh_client_path()
    if executable is None:
        return {"status": "tool_unavailable", "tool": "oob_poll"}

    output = _run_interactsh(
        [executable, "-json", "-disable-update-check", "-session-file", str(session_path), "-poll-interval", "1"],
        run_seconds=8,
    )

    interactions = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "protocol" in record:
            interactions.append(record)

    return {"status": "ok", "interaction_count": len(interactions), "interactions": interactions}


def _exploitation_scenario_from_cvss_vector(vector_string: str | None) -> str | None:
    """Derives the same remote_direct/mitm_active/victim_interaction/local_only classification
    record_finding asks the model for, but straight from the CVSS Attack Vector (AV) + User
    Interaction (UI) metrics — deterministic, no model judgment call needed for a CVE that
    already carries a real CVSS vector. mitm_passive has no CVSS equivalent (it's a config-hygiene
    judgment, e.g. "cookie sent unencrypted"), so it never comes from this path."""
    if not vector_string:
        return None
    parts = dict(segment.split(":", 1) for segment in vector_string.split("/") if ":" in segment)
    attack_vector, user_interaction = parts.get("AV"), parts.get("UI")
    if user_interaction == "R":
        return "victim_interaction"
    if attack_vector == "N":
        return "remote_direct"
    if attack_vector == "A":
        return "mitm_active"
    if attack_vector in ("L", "P"):
        return "local_only"
    return None


def _affected_version_range(cna: dict) -> str | None:
    """The concrete "which versions" a CVE record carries — a real card needs this to say more
    than a bare product name (a human can't tell if their install is affected otherwise). "n/a"
    is a real, common placeholder value in this dataset for records that never got a structured
    version filled in — treated as absent, not displayed as if it meant something.
    """
    for affected in cna.get("affected", []):
        for version_entry in affected.get("versions", []):
            if version_entry.get("status") != "affected":
                continue
            version = version_entry.get("version")
            if not version or version.lower() == "n/a":
                continue
            upper_bound = version_entry.get("lessThan") or version_entry.get("lessThanOrEqual")
            return f"{version} – {upper_bound}" if upper_bound else version
    return None


def _parse_dotted_version(text: str) -> tuple[int, ...] | None:
    """Pulls the first dotted-numeric version out of free text (e.g. "1.14.0" out of "nginx
    1.14.0 (Ubuntu)") as a comparable tuple of ints. None if nothing dotted-numeric is present.
    Deliberately simple — no pre-release/build-metadata handling — every version this project
    actually compares (a CVE record's version bound, a recon-reported service version) is a plain
    X.Y[.Z...] number; a real semver parser would be solving a problem nothing here has.
    """
    match = re.search(r"\d+(?:\.\d+)+", text)
    if not match:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


_VERSION_RANGE_OPERATOR_PATTERN = re.compile(r"(>=|<=|>|<)\s*(\d+(?:\.\d+)*)")


def _parse_combined_range_string(version_field: str) -> tuple[tuple[int, ...] | None, tuple[int, ...] | None, bool] | None:
    """Some CNAs — confirmed live on a real scan for GitHub-issued, GHSA-derived CVEs (Ghost CMS'
    own advisories) — cram an entire range into the single "version" field itself, e.g.
    ">= 3.24.0, < 6.19.1", instead of using the schema's own lessThan/lessThanOrEqual fields. Real
    incident this fixes: _affected_version_bounds only ever looked for lessThan/lessThanOrEqual,
    which this CNA never populates, so the upper bound (the fix version) was silently dropped —
    every installed version stayed "in range" forever, even a release patched years after the fix,
    because there was no upper edge left to compare against. None when the field has no range
    operator at all (a plain version string — the normal case for most other CNAs).
    """
    matches = _VERSION_RANGE_OPERATOR_PATTERN.findall(version_field)
    if not matches:
        return None
    lower = upper = None
    upper_inclusive = False
    for op, num in matches:
        parsed = _parse_dotted_version(num)
        if parsed is None:
            continue
        if op in (">=", ">"):
            lower = parsed
        else:
            upper = parsed
            upper_inclusive = op == "<="
    return lower, upper, upper_inclusive


def _cve_description(cna: dict) -> str | None:
    descriptions = cna.get("descriptions", [])
    description = next((d.get("value") for d in descriptions if d.get("lang") == "en"), None)
    if description is None and descriptions:
        description = descriptions[0].get("value")
    return description


# Real incident this fixes: CVE-2023-25136's own cna.affected[] array is empty (no structured
# range at all) — the ONLY place the fix version appears is prose in the description ("This is
# fixed in OpenSSH 9.2."). _affected_version_bounds used to return [] for this, meaning
# version_is_ruled_out could never say so even though the confirmed installed version (9.2p1) is
# unambiguously the patched one — costing a whole exploit-phase LLM round-trip to work out by hand
# what a plain substring match already answers for free. "fixed"/"patched"/"resolved" + "in" +
# a version number within the same short clause is common, formulaic CVE-description phrasing
# across many CNAs, not a one-off. The window is capped at 40 chars and stops at a sentence
# boundary so it can't accidentally reach into unrelated text further down the description.
_TEXT_FIXED_IN_PATTERN = re.compile(r"\b(?:fixed|patched|resolved)\s+in\b[^.\n]{0,40}?(\d+(?:\.\d+)+)", re.IGNORECASE)


def _affected_version_bounds(cna: dict) -> list[tuple[tuple[int, ...] | None, tuple[int, ...] | None, bool]]:
    """Every disjoint affected-version range a CVE record carries, as (lower_inclusive,
    upper_bound, upper_inclusive) tuples of parsed version numbers — unlike
    _affected_version_range() above (which stops at the first range for a short display string),
    this walks all of them, because a real CVE (e.g. one affecting nginx 0.x across several minor
    lines) commonly lists several. A None lower/upper means that side is unbounded. Used to
    deterministically rule a CVE in or out once a real installed version is known (agent/core.py's
    cve_lookup auto-record) — not for display.
    """
    bounds = []
    for affected in cna.get("affected", []):
        for entry in affected.get("versions", []):
            if entry.get("status") != "affected":
                continue
            version = entry.get("version")
            if not version or version.lower() == "n/a":
                continue
            combined_range = _parse_combined_range_string(version)
            if combined_range is not None:
                bounds.append(combined_range)
                continue
            less_than, less_eq = entry.get("lessThan"), entry.get("lessThanOrEqual")
            lower = _parse_dotted_version(version)
            # "version": "0" paired with lessThan/lessThanOrEqual is this dataset's convention for
            # "every version before the upper bound", not literally version 0.0 — treat it as an
            # unbounded lower edge so a real 0.x install still correctly matches.
            if lower == (0,):
                lower = None
            upper_raw = less_than or less_eq
            upper = _parse_dotted_version(upper_raw) if upper_raw else None
            bounds.append((lower, upper, bool(less_eq and not less_than)))
    if bounds:
        return bounds

    # No structured range anywhere in this record -- fall back to the description's own prose
    # before giving up entirely. Only ever adds an exclusive upper bound (never a lower one: "fixed
    # in X" says nothing about how far back the bug goes), so it can only ever rule a CVE OUT, on
    # the same "positive evidence only" discipline _version_definitely_not_affected already applies.
    description = _cve_description(cna)
    if description:
        match = _TEXT_FIXED_IN_PATTERN.search(description)
        if match:
            upper = _parse_dotted_version(match.group(1))
            if upper is not None:
                bounds.append((None, upper, False))
    return bounds


def _version_definitely_not_affected(version: tuple[int, ...], bounds: list[tuple]) -> bool:
    """True only when every known range EXPLICITLY excludes this version — i.e. we have positive
    proof the confirmed install isn't vulnerable, not just "we don't know". False (meaning "don't
    rule it out") whenever bounds is empty or any range is ambiguous/matches, so the caller only
    ever skips a finding on real evidence, never on absence of it.
    """
    if not bounds:
        return False
    for raw_lower, raw_upper, upper_inclusive in bounds:
        # cve_lookup's result round-trips through cache.py's JSON file cache (cache_get/cache_set)
        # once it's no longer a same-process fresh call — json.load turns every tuple this function
        # built into a plain list, and a bare list-vs-tuple "<" comparison raises TypeError. Real
        # incident this fixes: a cached CVE lookup crashed the whole Analyze phase outright the
        # first time this ran against a warm cache. Normalizing both sides to tuples here handles
        # a fresh call (already tuples, no-op) and a cached one (lists) identically.
        lower = tuple(raw_lower) if raw_lower is not None else None
        upper = tuple(raw_upper) if raw_upper is not None else None
        if lower is not None and version < lower:
            continue
        if upper is not None:
            if upper_inclusive and version > upper:
                continue
            if not upper_inclusive and version >= upper:
                continue
        return False  # this range doesn't exclude it — can't rule the CVE out
    return True


def version_is_ruled_out(confirmed_version_text: str, affected_version_bounds: list) -> bool:
    """Public entry point for agent/core.py's cve_lookup auto-record: True only when a real,
    confirmed installed-version string Recon already reported (e.g. "1.14.0" or "nginx 1.14.0
    (Ubuntu)") is proven outside every range in this CVE's affected_version_bounds (from
    _summarize_cve_record above) — positive evidence the CVE doesn't apply here, not a guess.
    False whenever no version can even be parsed out of the text, so a CVE is never ruled out for
    lack of data.
    """
    parsed = _parse_dotted_version(confirmed_version_text)
    if parsed is None:
        return False
    return _version_definitely_not_affected(parsed, affected_version_bounds or [])


def _reference_urls(cna: dict, limit: int = 3) -> list[str]:
    return [ref["url"] for ref in cna.get("references", []) if ref.get("url")][:limit]


def _summarize_cve_record(record: dict) -> dict:
    """Pulls a plain-language description, severity band, affected-version range, real reference
    links, and exploitation scenario out of one cve.circl.lu record — enough to auto-generate a
    real finding card from a bare CVE ID without an extra LLM round-trip (see agent/core.py's
    cve_lookup handling in _run_analyze)."""
    cna = record.get("containers", {}).get("cna", {})
    description = _cve_description(cna)

    severity, vector_string = None, None
    for container in (cna, *record.get("containers", {}).get("adp", [])):
        for metrics in container.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                cvss = metrics.get(key)
                if cvss and cvss.get("baseSeverity"):
                    severity = cvss["baseSeverity"].title()
                    vector_string = cvss.get("vectorString")
                    break
            if severity:
                break
        if severity:
            break

    return {
        "description": description,
        "severity": severity,
        "exploitation_scenario": _exploitation_scenario_from_cvss_vector(vector_string),
        # The real vector string itself, not just the scenario derived from it -- lets
        # agent/core.py's cve_lookup auto-record path put a real, NVD/CIRCL-sourced CVSS vector on
        # the finding card (record_finding's own cvss_vector field) instead of leaving it to the
        # model to reconstruct from memory, or omit it, for a CVE that already carries one.
        "cvss_vector": vector_string,
        "affected_versions": _affected_version_range(cna),
        # Structured, not just the display string above — lets agent/core.py's cve_lookup
        # auto-record deterministically rule a CVE out when Recon already confirmed an installed
        # version outside every range here (version_is_ruled_out below), instead of blindly
        # recording a finding for every CVE the product name has ever had regardless of version.
        "affected_version_bounds": _affected_version_bounds(cna),
        "references": _reference_urls(cna),
    }


def cve_lookup(params: dict) -> dict:
    """Searches cve.circl.lu's Vulnerability-Lookup API by vendor/product (vendor defaults to
    product — a common convention for this dataset, e.g. vendor=vsftpd, product=vsftpd)."""
    product = params["product"]
    vendor = params.get("vendor", product)
    cache_key = f"{vendor}/{product}"
    cached = cache_get("cve_lookup", cache_key)
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"https://cve.circl.lu/api/vulnerability/search/{vendor}/{product}")
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    records_by_id: dict[str, dict] = {}
    for source_results in data.get("results", {}).values():
        for entry in source_results:
            cve_id = entry[0].upper()
            records_by_id.setdefault(cve_id, entry[1] if len(entry) > 1 else {})

    cve_ids = sorted(records_by_id)
    details = {cve_id: _summarize_cve_record(records_by_id[cve_id]) for cve_id in cve_ids}

    result = {"status": "ok", "cve_ids": cve_ids, "details": details}
    cache_set("cve_lookup", cache_key, result)
    return result


# --- reverse-engineering mode: pyevmasm is a pure-Python EVM disassembler, no subprocess/binary
# install at all -- tier-1 like every other function in this file, unlike radare2/gdb/slither/
# heimdall (agent/tools/builders/), which really are external binaries. ---


def disassemble_evm_bytecode(params: dict) -> dict:
    """Disassembles raw EVM bytecode into its opcode sequence -- for a smart contract with no
    available Solidity source (see agent/tools/builders/slither.py for the source-available case,
    agent/tools/builders/heimdall.py for a higher-level pseudocode decompile of the same
    bytecode-only case). Accepts either a literal hex bytecode string (with or without a leading
    "0x") or a path to a local file containing one -- same bytecode_or_path shape heimdall's own
    tool takes, for a consistent interface between the two bytecode-only tools."""
    raw_input = str(params.get("bytecode_or_path") or "").strip()
    if not raw_input:
        return {"status": "error", "error": "bytecode_or_path is required."}

    candidate_path = Path(raw_input)
    bytecode = candidate_path.read_text(encoding="utf-8").strip() if candidate_path.is_file() else raw_input
    if bytecode.startswith(("0x", "0X")):
        bytecode = bytecode[2:]

    try:
        raw_bytes = bytes.fromhex(bytecode)
    except ValueError as exc:
        return {"status": "error", "error": f"Not valid hex bytecode: {exc}"}

    try:
        instructions = pyevmasm.disassemble_all(raw_bytes)
    except Exception as exc:  # pyevmasm's own assortment of errors on malformed/truncated bytecode
        return {"status": "error", "error": describe_exception(exc)}

    return {
        "status": "ok",
        "instructions": [
            {
                "address": ins.pc,
                "opcode": ins.name,
                "operand": hex(ins.operand) if ins.operand is not None else None,
            }
            for ins in instructions
        ],
    }


# --- forge_poc_run: real, executed proof for a contract finding, not just a static pattern match --
# slither/mythril/heimdall all stop at "this pattern/symbolic-execution path looks exploitable";
# nothing in the arsenal before this could actually COMPILE and RUN a PoC transaction against real
# chain state to settle whether it genuinely is. forge test (Foundry) does exactly that, and
# forge-std's own vm.createSelectFork(rpcUrl[, blockNumber]) cheatcode -- called from WITHIN the
# model's own Solidity source, never a CLI flag here -- forks a REAL chain's state into a local,
# throwaway EVM simulation: reads (balances, storage, other contracts' code) see the real,
# live/historical chain; nothing written back ever reaches the real network. `forge test`
# (never `forge script --broadcast`, which this tool deliberately never runs) cannot broadcast a
# real transaction under any circumstances -- the same "confirmed by real evidence, never real
# damage" posture this project's own exploitation tooling already holds elsewhere.
_FOUNDRY_POC_TIMEOUT_SECONDS_DEFAULT = 300


def _foundry_scaffold_dir() -> Path:
    """The ONE shared, global forge-std vendor copy every session's own PoC reuses via an absolute-
    path remapping -- vendored once (setup_tools.sh's install_foundry, real network access
    guaranteed at install time), never re-fetched per session/call.

    Deliberately Path.home() (~/.foundry-asra-scaffold), NOT resolve_global_app_dir() (Documents/
    ASRA/data, where every other piece of runtime state in this project lives) -- resolve_global_app_dir()
    resolves to the WINDOWS Documents folder under WSL2 (a real cmd.exe round-trip,
    projects/paths.py's _resolve_documents_dir), which setup_tools.sh cannot cheaply replicate in
    bash at install time (it runs before requirements.txt's own python-dotenv/etc. are even
    installed, so it can't just shell out to the real Python resolver either). Foundry's own
    installer already puts forge/cast/anvil themselves under $HOME/.foundry/bin regardless of
    platform -- Path.home() here lands the vendored forge-std dependency in that exact same
    filesystem namespace bash's own $HOME resolves to inside the SAME WSL2/Linux/macOS process this
    agent always runs in, no path-translation needed on either side. Arguably more correct anyway:
    vendored dependency source is toolchain cache, not user-browsable project data.
    """
    return Path.home() / ".foundry-asra-scaffold"


def parse_forge_poc_output(stdout: str) -> dict:
    """`forge test --json` prints one JSON report keyed by "<path>:<ContractName>", each value
    holding "test_results": {"<testSignature>": {"status": "Success"|"Failure", "reason": ...,
    "decoded_logs": [...]}}  -- Foundry's own documented --json schema. Falls back to raw_output
    for anything that doesn't parse as that shape -- overwhelmingly a Solidity COMPILE error
    (a bad PoC, or a genuine typo), which forge prints as plain text before any JSON is ever
    produced, so json.loads() itself fails outright; forge_poc_run below treats an empty "tests"
    result as a real execution problem, not a clean/failed PoC verdict, for exactly this reason.
    """
    try:
        report = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {"raw_output": stdout.strip()}
    if not isinstance(report, dict):
        return {"raw_output": stdout.strip()}

    tests = []
    for suite_name, suite in report.items():
        if not isinstance(suite, dict):
            continue
        for test_name, result in (suite.get("test_results") or {}).items():
            if not isinstance(result, dict):
                continue
            tests.append({
                "suite": suite_name,
                "test": test_name,
                "status": result.get("status"),
                "reason": result.get("reason"),
                "logs": result.get("decoded_logs") or [],
            })
    if not tests:
        return {"raw_output": stdout.strip()}
    return {"tests": tests}


def forge_poc_run(params: dict) -> dict:
    """Compiles and runs a real, model-written Foundry test (source: the full .t.sol file content,
    extending forge-std's `Test` contract) as an actually-executed PoC -- the dynamic complement to
    slither/mythril's static contract analysis. Fork real chain state from WITHIN the Solidity
    source itself via forge-std's vm.createSelectFork(rpcUrl[, blockNumber]) cheatcode (no separate
    fork_rpc_url/block_number parameters here -- same "the model writes the whole script" shape
    custom_exploit_run/custom_re_script already use); assert the exploit's real effect (a drained
    balance, a bypassed check, an unauthorized state change) with a normal Solidity `assert`/
    `require` -- a passing test is real, executed proof, not a pattern match. `forge test` alone is
    run here, never `forge script --broadcast` -- no real transaction can ever reach the actual
    network through this tool, only a local fork simulation.

    Same persisted-script discipline as custom_exploit_run: the source and forge's own log survive
    in this session's own project folder (scripts/foundry_poc/), not a throwaway tempfile. Unlike
    that tool, this one needs a real, separately-installed toolchain (forge itself, plus a shared
    vendored forge-std) -- both checked explicitly here with an actionable error message, since a
    tier-1 native tool gets no automatic "is this installed" gate the way a tier-2 build_command
    tool does (agent/tools/tool_inventory.py).
    """
    source = params.get("source")
    if not source or not str(source).strip():
        return {"status": "error", "error": "source is required -- the full Solidity test file, extending forge-std's Test contract."}

    if shutil.which("forge") is None:
        return {
            "status": "error",
            "error": (
                "forge (Foundry) is not installed on this machine -- run setup_tools.sh to install "
                "it, or see https://getfoundry.sh for a manual install."
            ),
        }

    forge_std_src = _foundry_scaffold_dir() / "lib" / "forge-std" / "src"
    if not (forge_std_src / "Test.sol").is_file():
        return {
            "status": "error",
            "error": (
                "forge is installed, but the shared forge-std scaffold (the Test base contract/"
                "cheatcodes every PoC needs) is missing -- run setup_tools.sh again to vendor it, "
                f"or manually run `forge install foundry-rs/forge-std --no-git` inside {_foundry_scaffold_dir()}."
            ),
        }

    # Real, confirmed-live incident this specific layout fixes: `forge test --match-path` only
    # filters which tests RUN -- forge still COMPILES every .sol file under the project's own
    # configured test dir regardless, every single call. A shared test/ directory across calls (an
    # earlier version of this function) meant ONE broken/leftover PoC from a previous call broke
    # EVERY later call in the same session with an unrelated compile error, forever, even a call
    # whose own new source was perfectly valid. Each call therefore gets its own fully separate
    # mini Foundry project (own test/, own foundry.toml, own out/cache) under a script_id
    # subdirectory -- persisted for review same as custom_exploit_run's scripts, just never sharing
    # a compilation unit with any sibling call.
    script_id = uuid.uuid4().hex[:12]
    project_dir = _exploit_scripts_dir(params.get("_session_id")) / "foundry_poc" / script_id
    (project_dir / "test").mkdir(parents=True, exist_ok=True)

    (project_dir / "foundry.toml").write_text(
        "[profile.default]\n"
        "src = \"test\"\n"
        "test = \"test\"\n"
        "out = \"out\"\n"
        "libs = []\n"
        f"remappings = [\"forge-std/={forge_std_src}/\"]\n",
        encoding="utf-8",
    )
    sol_path = project_dir / "test" / "PoC.t.sol"
    sol_path.write_text(str(source), encoding="utf-8")

    timeout_seconds = int(os.getenv("FORGE_POC_TIMEOUT_SECONDS", str(_FOUNDRY_POC_TIMEOUT_SECONDS_DEFAULT)))

    try:
        proc = run_sandboxed(["forge", "test", "--json"], project_dir, timeout_seconds)
    except subprocess.TimeoutExpired:
        # Same bare-timeout gap fixed for custom_exploit_run/exploit_db_run just above (real
        # incident: fss-usr_d5b09a) -- an explicit reason instead of a silent {"status": "timeout"}
        # with nothing for a human or the correction call to react to.
        return {
            "status": "timeout",
            "error": (
                f"forge test exceeded its {timeout_seconds}s timeout and was killed -- the PoC "
                "either hangs (an unbounded loop/external call inside the test) or the Foundry "
                "fork/RPC it depends on is genuinely slow to respond."
            ),
        }

    (project_dir / "run.log").write_text(
        f"$ forge test --json\n\n--- stdout ---\n{proc.stdout}\n\n--- stderr ---\n{proc.stderr}\n",
        encoding="utf-8",
    )

    parsed = parse_forge_poc_output(proc.stdout)
    if "tests" not in parsed:
        # No structured test result at all -- overwhelmingly a Solidity compile error or a real
        # forge/environment problem, never a legitimate "the PoC's own assertion failed" verdict
        # (that DOES come back as structured "tests" data, status="Failure", a real result to
        # report, not a tool malfunction). Reported as error so the model fixes and retries the
        # source, the same "compile problem, not a verdict" treatment a Python SyntaxError gets in
        # custom_exploit_run.
        return {"status": "error", "error": parsed.get("raw_output") or proc.stderr.strip() or f"forge exited {proc.returncode} with no usable output."}

    return {"status": "ok", "exit_code": proc.returncode, **parsed}


# --- ipa_extract: iOS's own preparation step, mirroring apktool/jadx's role for Android ---------
# A .ipa is a plain ZIP archive under the hood (Payload/<AppName>.app/... + metadata) -- no special
# Apple tooling is needed just to unpack one. What IS genuinely Apple-only is the REST of the usual
# iOS RE toolchain (Xcode, otool, codesign, class-dump) -- all macOS-native, none of it runs on this
# project's own Linux/WSL2 runtime. Rather than
# a full second, macOS-shaped iOS toolchain this project could never actually run, this extracts the
# real embedded Mach-O executable + Info.plist metadata and hands the executable straight to the
# arsenal that ALREADY handles Mach-O -- radare2/gdb/r2ghidra/frida_trace are all format-agnostic,
# already confirmed to cover ELF/PE/Mach-O alike, nothing iOS-specific needed there at all. The one
# real gap this does NOT close is a dedicated Objective-C/Swift class-dump -- radare2's own `ic`/
# `izz` commands surface __objc_classlist class/method names, a real but less polished substitute
# for class-dump proper, and that limitation is stated plainly in this tool's own result, not hidden.
def _ipa_output_dir(ipa_path: str) -> str:
    p = Path(ipa_path)
    return str(p.parent / f"{p.stem}_ipa")


def ipa_extract(params: dict) -> dict:
    """Extracts a local .ipa (iOS app archive) and reports the embedded app's real Info.plist
    metadata (bundle id, version, main executable name) plus the extracted Mach-O executable's own
    path -- run radare2/gdb/r2ghidra/frida_trace directly against executable_path afterward, exactly
    as you would any other local binary. A preparation step, not a finding-producing scanner itself,
    same role apktool/jadx play for Android."""
    ipa_path_raw = params.get("file_path")
    if not ipa_path_raw:
        return {"status": "error", "error": "file_path is required."}
    ipa_path = Path(str(ipa_path_raw).strip())
    if not ipa_path.is_file():
        return {"status": "error", "error": f"File not found: {ipa_path}"}

    output_dir = Path(_ipa_output_dir(str(ipa_path)))
    try:
        with zipfile.ZipFile(ipa_path) as archive:
            _safe_extract_zip(archive, output_dir)
    except (zipfile.BadZipFile, ValueError) as exc:
        return {"status": "error", "error": f"Not a valid .ipa (zip) archive, or unsafe archive contents: {exc}"}

    payload_dir = output_dir / "Payload"
    app_dirs = sorted(payload_dir.glob("*.app")) if payload_dir.is_dir() else []
    if not app_dirs:
        return {"status": "error", "error": f"No Payload/*.app directory found after extraction into {output_dir} -- this may not be a real iOS .ipa."}
    app_dir = app_dirs[0]

    metadata: dict = {}
    info_plist_path = app_dir / "Info.plist"
    if info_plist_path.is_file():
        try:
            with info_plist_path.open("rb") as f:
                # plistlib handles BOTH binary and XML plist formats transparently (Apple ships
                # Info.plist as binary by default in a real build) -- no format detection needed.
                plist = plistlib.load(f)
        except (plistlib.InvalidFileException, ValueError) as exc:
            metadata = {"parse_error": f"Could not parse Info.plist: {exc}"}
        else:
            metadata = {
                "bundle_id": plist.get("CFBundleIdentifier"),
                "bundle_name": plist.get("CFBundleName") or plist.get("CFBundleDisplayName"),
                "version": plist.get("CFBundleShortVersionString"),
                "build": plist.get("CFBundleVersion"),
                "executable_name": plist.get("CFBundleExecutable"),
            }

    executable_name = metadata.get("executable_name")
    executable_path = str(app_dir / executable_name) if executable_name and (app_dir / executable_name).is_file() else None

    return {
        "status": "ok",
        "app_dir": str(app_dir),
        "executable_path": executable_path,
        "metadata": metadata,
        "note": (
            "Mach-O executable extracted -- run radare2/gdb/r2ghidra/frida_trace directly against "
            "executable_path, the same as any other local binary. No dedicated Objective-C/Swift "
            "class-dump tool exists here; radare2's own `ic`/`izz` commands surface class/method "
            "names from __objc_classlist as a real, if less polished, substitute."
            if executable_path else
            "Could not determine the main executable from Info.plist -- inspect app_dir directly "
            "to find it (the file matching Info.plist's CFBundleExecutable, or the one real Mach-O "
            "file at the top level of the .app directory)."
        ),
    }


# --- exploit-tier, not tier-1 by risk: same guardrail as Metasploit ---

_DEFAULT_CREDENTIAL_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("admin", ""),
    ("test", "test"),
]

# Vendor-keyed default-credential lookup, backed by cirt.net's own public Default Password Database
# (https://cirt.net/passwords/, 531 vendors / ~2100 entries at harvest time) -- the same source
# github.com/Viralmaniar/Passhunt reads live via a plain HTTP request. cirt.net now sits behind
# Cloudflare Bot Management, which rejects a bare HTTP client outright (confirmed: a plain httpx/curl
# GET returns HTTP 403 "Attention Required! | Cloudflare"), so this repo bundles a real, one-time
# harvest instead of querying it live on every call -- scripts/harvest_cirt_default_passwords.py
# (real Playwright + this repo's own browser stealth patches, confirmed live to pass Cloudflare
# cleanly) writes it to cirt_default_passwords.json below. Re-run that script whenever a refresh is
# wanted; this file is source-controlled, fully public security-research reference data, not runtime
# state.
_CIRT_DEFAULT_PASSWORDS_PATH = Path(__file__).resolve().parent / "data" / "cirt_default_passwords.json"


@functools.lru_cache(maxsize=1)
def _load_cirt_default_passwords() -> dict[str, list[dict]]:
    if not _CIRT_DEFAULT_PASSWORDS_PATH.exists():
        return {}
    try:
        return json.loads(_CIRT_DEFAULT_PASSWORDS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _normalize_vendor_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


_VENDOR_SUBSTRING_MATCH_MIN_LEN = 4  # see _resolve_vendor_credential_pairs' own docstring


def _resolve_vendor_credential_pairs(vendor_query: str) -> tuple[list[tuple[str, str]], str] | None:
    """Matches `vendor_query` against cirt.net's own real vendor names, in three passes, each only
    tried once the previous one found nothing:

    1. Exact match, case/punctuation-insensitive (e.g. "hikvision" -> their real "Hikvision", if it
       were in the database -- confirmed live it currently is NOT: cirt.net's own list skews toward
       legacy network/router/camera hardware, several modern self-hosted web-dashboard names this
       tool was originally hand-seeded with, e.g. Jenkins/Grafana/Hikvision/TP-Link, genuinely have
       no entry there at all -- MISSING here is an honest, correct answer for those, not a bug).
    2. Whole-WORD match against the query split on non-alphanumeric characters (e.g. "hp printer" ->
       word "hp" -> real vendor "HP"), so a short real vendor name can still match a longer
       descriptive query without resorting to raw substring matching.
    3. Raw substring match, but ONLY for names at least _VENDOR_SUBSTRING_MATCH_MIN_LEN characters
       long. Real, confirmed bug this guards against: querying "elasticsearch" raw-substring-matched
       the completely unrelated real vendor "AST" (its normalized name "ast" sits inside
       "el-AST-icsearch") and would have silently tried AST's own passwords against an Elasticsearch
       target -- a short name is exactly the case raw substring matching produces false positives
       for, and pass 2 already covers the legitimate short-name case (an exact whole word) safely.

    Returns (deduplicated (user, password) pairs, the real matched vendor name), or None if nothing
    matches at all or the matched vendor has no usable pairs.

    "(none)" (cirt.net's own convention for an empty field) is normalized to "" -- a real value a
    login form actually expects for a blank username/password -- and an entry with BOTH fields
    blank (nothing to actually submit) is dropped.
    """
    database = _load_cirt_default_passwords()
    if not database:
        return None

    normalized_query = _normalize_vendor_name(vendor_query)
    normalized_index = {_normalize_vendor_name(name): name for name in database}

    matched_name = normalized_index.get(normalized_query)
    if matched_name is None:
        query_words = {_normalize_vendor_name(word) for word in re.split(r"[^A-Za-z0-9]+", vendor_query) if word}
        word_candidates = [name for norm, name in normalized_index.items() if norm in query_words]
        if word_candidates:
            matched_name = min(word_candidates, key=len)
    if matched_name is None:
        candidates = [
            name for norm, name in normalized_index.items()
            if len(norm) >= _VENDOR_SUBSTRING_MATCH_MIN_LEN and len(normalized_query) >= _VENDOR_SUBSTRING_MATCH_MIN_LEN
            and (normalized_query in norm or norm in normalized_query)
        ]
        if candidates:
            matched_name = min(candidates, key=len)
    if matched_name is None:
        return None

    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in database[matched_name]:
        username = entry.get("user", "").strip()
        password = entry.get("password", "").strip()
        if username.lower() == "(none)":
            username = ""
        if password.lower() == "(none)":
            password = ""
        if not username and not password:
            continue
        pair = (username, password)
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)
    return (pairs, matched_name) if pairs else None


_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_VALID_VERIFICATIONS = {"verified", "inferred", "needs_verification"}
_VALID_EXPLOITATION_SCENARIOS = {"remote_direct", "mitm_active", "mitm_passive", "victim_interaction", "local_only"}
# Accepted only by record_exploit_decision, and only for a skip action -- real incident: the
# schema's "genuine re-check, not a copy" wording is right for a real exploit_attempted, but
# nonsensical for a skip (nothing new was learned about HOW this would be exploited). The model's
# honest "nothing to add" instinct got rejected outright as an invalid enum value, burning a
# correction round-trip, and the guess it fell back to on retry then silently overwrote the
# finding's already-correct exploitation_scenario from Analyze (deliberately excluded from
# _VALID_EXPLOITATION_SCENARIOS so _apply_skip_outcome's existing "only overwrite with a real
# value" check already treats it as "leave the finding's own value alone", no extra logic needed).
_EXPLOITATION_SCENARIO_UNCHANGED = "unchanged"
# Only meaningful when the project's own scope rules (session["scope_rules"], New Project form)
# were actually given — the model is told to only set this when a finding clearly matches one of
# those lists (agent/prompts.py's ANALYZE_PROMPT), so most findings on a scope-rules-less project
# simply omit it (None), same as today.
_VALID_BOUNTY_RELEVANCE = {"qualifying", "non_qualifying", "unclear"}


# --- session recording: the LLM calls these the instant it identifies something, not batched
# into a final answer — the caller (agent/core.py's execute_tool closure in _run_recon/
# _run_analyze) persists the returned "recorded" dict into the session immediately. These
# functions only validate/normalize the model's input; they know nothing about sessions. ---


def record_finding(params: dict) -> dict:
    # Errors are collected across every field and returned together, not one-at-a-time --
    # a model that gets back only the first bad field re-submits and routinely trips the next
    # one, burning a whole extra round-trip per field (confirmed live: three consecutive
    # single-field rejections on one record_finding call).
    errors = []

    title = params.get("title")
    if not title:
        # Real incident this fixes: the model omitted "title" entirely on a live scan, and this
        # used to be a bare params["title"] subscript -- an unhandled KeyError that reached the
        # model as a bare "'title'" error message (agent/tools/runner.py's last-resort catch-all),
        # costing an extra guessing round-trip instead of the clear message every other field here
        # already gives.
        errors.append("title is required")
    severity_raw = params.get("severity")
    # Case-insensitive: a real-world model reply routinely sends "low"/"medium" instead of the
    # exact capitalized enum value -- unambiguously the same value, not worth a whole retry
    # round-trip over. Same "accept a real-world variant" discipline as record_exploit_decision's
    # reason/reasoning alias below.
    severity = next(
        (candidate for candidate in _VALID_SEVERITIES if isinstance(severity_raw, str) and candidate.lower() == severity_raw.lower()),
        severity_raw,
    )
    if severity not in _VALID_SEVERITIES:
        errors.append(f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {severity_raw!r}")
    verification = params.get("verification", "needs_verification")
    if verification not in _VALID_VERIFICATIONS:
        errors.append(f"verification must be one of {sorted(_VALID_VERIFICATIONS)}, got {verification!r}")
    exploitation_scenario = params.get("exploitation_scenario")
    if exploitation_scenario not in _VALID_EXPLOITATION_SCENARIOS:
        errors.append(
            f"exploitation_scenario must be one of {sorted(_VALID_EXPLOITATION_SCENARIOS)}, got {exploitation_scenario!r}"
        )
    qualifies_for_bounty = params.get("qualifies_for_bounty")
    if qualifies_for_bounty is not None and qualifies_for_bounty not in _VALID_BOUNTY_RELEVANCE:
        errors.append(
            f"qualifies_for_bounty must be one of {sorted(_VALID_BOUNTY_RELEVANCE)}, got {qualifies_for_bounty!r}"
        )
    # Optional, loosely validated -- this is a report-facing convenience field, not a security gate
    # like severity/qualifies_for_bounty above, so it only rejects something that clearly isn't a
    # CVSS vector at all (free text pasted in the wrong field) rather than policing the exact
    # metric set, which legitimately differs between CVSS 3.x and 4.0.
    cvss_vector = params.get("cvss_vector")
    if cvss_vector is not None and not (isinstance(cvss_vector, str) and cvss_vector.startswith("CVSS:")):
        errors.append(
            f"cvss_vector must be a real CVSS vector string starting with 'CVSS:' (e.g. "
            f"'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N'), got {cvss_vector!r} -- omit the field "
            "entirely if you can't confidently derive one from what you actually observed"
        )
    # exploited/evidence/remediation_advice: optional, and absent from `recorded` entirely unless
    # the model actually set them -- _normalize_findings' {**_FINDING_DEFAULTS, **finding} merge
    # (agent/core.py) then leaves the normal Recon/Analyze case (exploited unset here, confirmed
    # later by Exploit) byte-for-byte unchanged. Exists for exactly one real gap: a finding
    # record_finding'd during the Chain phase (agent/core.py's _run_chain) has no LATER phase that
    # will ever confirm it — Chain runs after Exploit — so without a way to set these at record
    # time, a fully-proven Chain finding (real evidence, a real tool-call replay) permanently
    # stayed exploited=False/evidence=None, and both finding-card templates render NOTHING in that
    # case (neither the exploited nor the "not exploitable" block), silently losing the strongest
    # evidence a session produced. Confirmed live: a fully-proven account-takeover finding recorded
    # this way had its real evidence sitting only in evidence_ref, which no template ever renders.
    exploited = params.get("exploited")
    if exploited is not None and not isinstance(exploited, bool):
        errors.append(f"exploited must be a boolean, got {exploited!r}")
    evidence = params.get("evidence")
    if exploited is True and not evidence:
        errors.append(
            "evidence is required when exploited=true — quote the real proof (request/response, command output) "
            "that backs this claim, never an unbacked assertion"
        )
    # Optional: the id of a specific captured-traffic entry (list_captured_traffic/toolkit Site
    # Map) this finding's evidence actually came from -- a precise, clickable link to the exact
    # request/response byte-for-byte, alongside (never instead of) the free-text evidence/
    # evidence_ref quote above. Deliberately NOT cross-checked against toolkit_store here (this
    # whole function "only validates/normalize the model's input; it knows nothing about sessions",
    # see this section's own header comment) -- a hallucinated/stale id degrades softly (the UI's
    # own "View captured request" link 404s inside its dialog), never a hard failure.
    evidence_entry_id = params.get("evidence_entry_id")

    if errors:
        return {"status": "error", "error": "; ".join(errors)}

    recorded = {
        "title": title,
        "severity": severity,
        "description": params.get("description", ""),
        "technology": params.get("technology"),
        "reproduction_steps": params.get("reproduction_steps"),
        "verification": verification,
        "evidence_ref": params.get("evidence_ref"),
        "exploitation_scenario": exploitation_scenario,
        "qualifies_for_bounty": qualifies_for_bounty,
        # Optional, set by the model itself (ANALYZE_PROMPT) or deterministically by
        # agent/core.py's cve_lookup auto-record (version_is_ruled_out above) when there's real
        # evidence this finding isn't actually exploitable/applicable here — kept in the report
        # for audit trail (due diligence was done) rather than silently dropped, but flagged
        # distinctly in the UI (templates/macros/ui.html's false_positive_badge) so a human
        # skimming findings knows not to spend time chasing or submitting it.
        "false_positive_reason": params.get("false_positive_reason"),
    }
    if exploited is not None:
        recorded["exploited"] = exploited
    if evidence:
        recorded["evidence"] = evidence
    if evidence_entry_id:
        recorded["evidence_entry_id"] = evidence_entry_id
    remediation_advice = params.get("remediation_advice")
    if remediation_advice:
        recorded["remediation_advice"] = remediation_advice
    discovery_tool = params.get("discovery_tool")
    if discovery_tool:
        recorded["discovery_tool"] = discovery_tool
    if cvss_vector:
        recorded["cvss_vector"] = cvss_vector
    host = params.get("host")
    if host:
        recorded["host"] = host
    return {"status": "ok", "recorded": recorded}


_VALID_EXPLOIT_ACTIONS = {"exploit_attempted", "skipped_needs_verification", "skipped_no_suitable_tool"}


def record_exploit_decision(params: dict) -> dict:
    """Exploit phase's final answer for one finding, submitted as a real tool call instead of
    free-text JSON — same reliability reasoning as record_finding: native/prompt-mode tool-calling
    is a provider-enforced contract, "reply in this JSON shape as plain text" is not. Called via
    agent/core.py's _run_llm_tool_loop terminal_tool mechanism, which ends the exploit loop the
    instant this returns status "ok" and treats the rest of this dict (minus "status") as the
    phase's answer.
    """
    action = params.get("action")
    if action not in _VALID_EXPLOIT_ACTIONS:
        return {"status": "error", "error": f"action must be one of {sorted(_VALID_EXPLOIT_ACTIONS)}, got {action!r}"}
    exploitation_scenario = params.get("exploitation_scenario")
    # "unchanged" only makes sense for a skip -- exploit_attempted always has a real new attempt to
    # base a genuine re-check on, so it still must give one of the five real values.
    scenario_ok = exploitation_scenario in _VALID_EXPLOITATION_SCENARIOS or (
        exploitation_scenario == _EXPLOITATION_SCENARIO_UNCHANGED and action != "exploit_attempted"
    )
    if not scenario_ok:
        allowed = sorted(_VALID_EXPLOITATION_SCENARIOS) + (
            [] if action == "exploit_attempted" else [_EXPLOITATION_SCENARIO_UNCHANGED]
        )
        return {
            "status": "error",
            "error": f"exploitation_scenario must be one of {allowed}, got {exploitation_scenario!r}",
        }
    # "reason" is a real-world variant spelling the model reaches for constantly (confirmed live:
    # one exploit-phase turn burned 8 consecutive failed calls over exactly this, never getting
    # past the field name) — normalize it here, the single validation entry point, rather than
    # rejecting a spelling that unambiguously means the same thing.
    reasoning = params.get("reasoning") or params.get("reason")
    if not reasoning:
        return {"status": "error", "error": "reasoning is required — explain concretely what was actually achieved, or why nothing more could be"}
    result = {
        "status": "ok",
        "action": action,
        "tool": params.get("tool"),
        "exploitation_scenario": exploitation_scenario,
        "reasoning": reasoning,
    }
    # Optional: a durable fact about the target's actual software identity/version this pass
    # established, worth sharing with other findings on the same stack (agent/core.py's
    # _record_confirmed_tech_fact / _confirmed_tech_facts_task_addendum) rather than making each
    # one independently re-discover it. Never required — most findings have nothing reusable to
    # report here, and that's the normal case.
    confirmed_tech_fact = params.get("confirmed_tech_fact")
    if confirmed_tech_fact:
        result["confirmed_tech_fact"] = confirmed_tech_fact
    # Optional, primarily for a skip: agent/core.py's _apply_skip_outcome applies these the same
    # way _confirm_exploit_result's own corrected_severity/corrected_qualifies_for_bounty already
    # get applied for exploit_attempted (_apply_corrected_qualification) -- a skip previously had
    # no way to correct Analyze's first-guess qualification at all, even when this call's own
    # "reasoning" concludes real impact can't be demonstrated (real incident: a High/"qualifying"
    # CORS finding stayed that way through a skipped_no_suitable_tool decision whose own reasoning
    # said impact was undemonstrable -- the finding never had anywhere to write that down).
    corrected_severity = params.get("corrected_severity")
    if corrected_severity:
        result["corrected_severity"] = corrected_severity
    corrected_qualifies_for_bounty = params.get("corrected_qualifies_for_bounty")
    if corrected_qualifies_for_bounty:
        result["corrected_qualifies_for_bounty"] = corrected_qualifies_for_bounty
    # Optional, same family as the two corrected_* fields above: a skip whose own reasoning
    # concludes the finding isn't real at all (an out-of-range CVE, a condition that doesn't
    # actually hold) previously had no way to retroactively flag it as a false positive the way
    # Analyze's own auto-CVE-record path can at record_finding time — agent/core.py's
    # _apply_skip_outcome applies this the same way it already applies corrected_severity/
    # corrected_qualifies_for_bounty.
    corrected_false_positive_reason = params.get("corrected_false_positive_reason")
    if corrected_false_positive_reason:
        result["corrected_false_positive_reason"] = corrected_false_positive_reason
    # Optional, meaningful for EVERY action (attempted or skipped alike — unlike the corrected_*
    # fields above, this isn't about revising Analyze's first guess, it's the operator-facing "what
    # do I actually do about this" a human reading the finished report needs regardless of whether
    # exploitation itself succeeded). Concrete and actionable, not a restatement of the description.
    remediation_advice = params.get("remediation_advice")
    if remediation_advice:
        result["remediation_advice"] = remediation_advice
    return result


_VALID_CHAIN_ACTIONS = {"chain_confirmed", "no_chain_found"}


def record_chain_result(params: dict) -> dict:
    """Chain phase's final answer, submitted as a real tool call instead of free-text JSON — same
    reliability reasoning and terminal_tool contract as record_exploit_decision. chain_confirmed
    requires real proof (which findings, the actual evidence quoted from each, and which tool call
    demonstrated the combination) — a narrated-only claim is rejected here, deterministically,
    rather than trusted on the model's word alone (same discipline as the CVE-existence rule in
    EXPLOIT_PROMPT: an unsupported assertion isn't evidence, in either direction).

    reverified_findings (optional) is the write-back path for a different real gap: this phase
    routinely re-tests an EXISTING finding's own vulnerability while looking for chains (it has
    every finding's evidence_ref in context, and the exact same tools) — a fresh, real re-check
    with no mechanism to update that finding's own record. agent/core.py's _apply_chain_reverifications
    is what actually applies these to session["findings"] once this call returns "ok"; this
    function only validates the shape (each entry needs a real title + fresh evidence_ref) since it
    has no access to the findings list itself to check the title actually exists.
    """
    action = params.get("action")
    if action not in _VALID_CHAIN_ACTIONS:
        return {"status": "error", "error": f"action must be one of {sorted(_VALID_CHAIN_ACTIONS)}, got {action!r}"}
    reasoning = params.get("reasoning") or params.get("reason")
    if not reasoning:
        return {"status": "error", "error": "reasoning is required — explain what you checked and why you reached this conclusion"}

    finding_titles = params.get("finding_titles")
    evidence_quotes = params.get("evidence_quotes")
    tool_call_proof = params.get("tool_call_proof")
    impact_scenario = params.get("impact_scenario")
    if action == "chain_confirmed":
        if not isinstance(finding_titles, list) or len(finding_titles) < 2:
            return {"status": "error", "error": "finding_titles must list at least the two findings being chained, by their real title"}
        if not isinstance(evidence_quotes, list) or len(evidence_quotes) < 2:
            return {"status": "error", "error": "evidence_quotes must quote the real evidence_ref/evidence value of each finding named in finding_titles — not a paraphrase"}
        if not tool_call_proof:
            return {
                "status": "error",
                "error": "tool_call_proof is required for chain_confirmed — describe the real tool call (and its actual result) "
                "that proved these findings combine; a narrated claim alone is not accepted",
            }
        if not impact_scenario or not isinstance(impact_scenario, str):
            return {
                "status": "error",
                "error": "impact_scenario is required for chain_confirmed — a concrete, submission-ready paragraph describing "
                "what an attacker can now actually do (not a restatement of reasoning/tool_call_proof)",
            }

    reverified_findings = params.get("reverified_findings")
    if reverified_findings is not None:
        if not isinstance(reverified_findings, list):
            return {"status": "error", "error": "reverified_findings must be a list of {title, evidence_ref} objects"}
        for entry in reverified_findings:
            if not isinstance(entry, dict) or not entry.get("title") or not entry.get("evidence_ref"):
                return {
                    "status": "error",
                    "error": "each reverified_findings entry needs a real title (matching an existing finding) and "
                    "evidence_ref quoting the fresh tool call result that re-confirmed/changed it — not a paraphrase",
                }

    return {
        "status": "ok",
        "action": action,
        "finding_titles": finding_titles,
        "evidence_quotes": evidence_quotes,
        "tool_call_proof": tool_call_proof,
        "impact_scenario": impact_scenario,
        "reasoning": reasoning,
        "reverified_findings": reverified_findings,
    }


def record_host_relationship(params: dict) -> dict:
    """Explicit, agent-authored "I proved a real pivot from host A to host B" assertion — the
    high-fidelity sibling of the Map tab's own chain_attempts-derived attack_path edges
    (main.py's _build_attack_surface_graph, agent/core.py's _persist_chain_attempt): those are
    reconstructed AFTER THE FACT by scanning a whole Chain pass's own reasoning text for which
    hosts its finding_titles touched, which only ever fires once an entire Chain pass concludes and
    only carries a short auto-extracted note. This tool lets the model record the same kind of fact
    directly, the moment it actually proves it (from Exploit as well as Chain — see this tool's own
    category="exploit" registration), with a real mechanism label and evidence attached — the
    closest thing this app has to Cobalt Strike's own beacon-to-beacon pivot event, and something
    an operator can trust precisely because it's gated on the same "real evidence, not a narrated
    claim" discipline every other record_* tool in this registry already enforces.

    Deliberately NOT gated behind a terminal_tool contract like record_chain_result/
    record_exploit_decision -- a real pivot can be proven mid-investigation, well before the model
    is ready to submit ITS turn's own final answer, and this only ever adds one extra line to the
    Map, never ends a phase.
    """
    source_host = params.get("source_host")
    target_host = params.get("target_host")
    mechanism = params.get("mechanism")
    evidence = params.get("evidence")
    if not source_host or not isinstance(source_host, str):
        return {"status": "error", "error": "source_host is required -- the real host/IP you pivoted FROM"}
    if not target_host or not isinstance(target_host, str):
        return {"status": "error", "error": "target_host is required -- the real host/IP you reached"}
    if source_host == target_host:
        return {"status": "error", "error": "source_host and target_host must be two different hosts"}
    if not mechanism or not isinstance(mechanism, str):
        return {
            "status": "error",
            "error": "mechanism is required -- a short, concrete label for HOW (e.g. 'leaked credentials', "
            "'SSRF', 'internal redirect', 'shared session token'), not a restatement of evidence",
        }
    if not evidence or not isinstance(evidence, str):
        return {
            "status": "error",
            "error": "evidence is required -- the real tool call and its actual result that proves this pivot, "
            "not a narrated claim",
        }
    return {
        "status": "ok",
        "source_host": source_host,
        "target_host": target_host,
        "mechanism": mechanism,
        "evidence": evidence,
    }


_VALID_VERIFICATION_OUTCOMES = {"confirmed_present", "confirmed_fixed", "inconclusive"}
_VALID_SKEPTICAL_VERDICTS = {"confirmed", "refuted", "inconclusive"}


def record_reverification_result(params: dict) -> dict:
    """A rescanned project's final answer for one carried-over finding from the prior scan — same
    terminal_tool contract shape as record_exploit_decision, ends agent/core.py's _run_reverify
    tool loop for this one finding the instant this returns status "ok". verification_outcome is a
    real three-way answer, not a boolean — confirmed_present/confirmed_fixed both require a real
    tool call this turn behind them, and inconclusive exists specifically so a model that genuinely
    couldn't reach either (WAF-blocked, timed out) has somewhere honest to put that instead of being
    forced to guess confirmed_fixed. Real, confirmed incident this fixes: a bare boolean gave the
    model no way to report "I couldn't verify" even though REVERIFY_PROMPT explicitly asked it to
    say so — it said so in reasoning but had to code still_present=false anyway, and agent/core.py's
    _run_reverify silently dropped the finding from the report as if it had been proven fixed.
    evidence_ref is required exactly for confirmed_present because that's the one case where an
    unverified rubber-stamp would carry the old finding's stale confidence forward without anyone
    having actually re-checked anything.
    """
    outcome = params.get("verification_outcome")
    if outcome not in _VALID_VERIFICATION_OUTCOMES:
        return {"status": "error", "error": f"verification_outcome must be one of {sorted(_VALID_VERIFICATION_OUTCOMES)}, got {outcome!r}"}
    # Same "reason" spelling variant accepted here as record_exploit_decision — same tool-calling
    # model, same slip, no reason to relearn the lesson twice.
    reasoning = params.get("reasoning") or params.get("reason")
    if not reasoning:
        return {"status": "error", "error": "reasoning is required — explain concretely what you actually checked and what it showed"}
    evidence_ref = params.get("evidence_ref")
    if outcome == "confirmed_present" and not evidence_ref:
        return {"status": "error", "error": "evidence_ref is required when verification_outcome is confirmed_present — quote the fresh proof from a tool call made just now, not a copy of the old finding's evidence"}
    return {
        "status": "ok",
        "verification_outcome": outcome,
        "reasoning": reasoning,
        "evidence_ref": evidence_ref,
        "corrected_severity": params.get("corrected_severity"),
        "corrected_qualifies_for_bounty": params.get("corrected_qualifies_for_bounty"),
        "corrected_false_positive_reason": params.get("corrected_false_positive_reason"),
        "escalation_justification": params.get("escalation_justification"),
    }


def record_skeptical_verification_result(params: dict) -> dict:
    """The Skeptical Verifier's own final answer -- ends agent/core.py's _run_skeptical_verification
    tool loop for this one finding the instant this returns status "ok". Same three-way-verdict
    shape as record_reverification_result, for the identical reason: "confirmed"/"refuted" both
    require a real tool call this turn behind them (evidence_ref), and "inconclusive" exists
    specifically so a model that genuinely couldn't reach either (blocked, no suitable tool) has
    somewhere honest to put that instead of being forced to guess. Unlike record_reverification_result
    (re-checking a PRIOR scan's finding, target may have been patched since), this verifier is
    checking a claim from the SAME scan it never saw the original investigation of -- "refuted" here
    means the claim doesn't hold up under independent re-checking, not that the target changed.
    """
    verdict = params.get("verdict")
    if verdict not in _VALID_SKEPTICAL_VERDICTS:
        return {"status": "error", "error": f"verdict must be one of {sorted(_VALID_SKEPTICAL_VERDICTS)}, got {verdict!r}"}
    reasoning = params.get("reasoning") or params.get("reason")
    if not reasoning:
        return {"status": "error", "error": "reasoning is required — explain concretely what you actually checked and what it showed"}
    evidence_ref = params.get("evidence_ref")
    if verdict in ("confirmed", "refuted") and not evidence_ref:
        return {"status": "error", "error": f"evidence_ref is required when verdict is {verdict!r} — quote the fresh proof from a tool call made just now, not a copy of the recipe you were given"}
    return {
        "status": "ok",
        "verdict": verdict,
        "reasoning": reasoning,
        "evidence_ref": evidence_ref,
        "corrected_severity": params.get("corrected_severity"),
        "corrected_qualifies_for_bounty": params.get("corrected_qualifies_for_bounty"),
        "corrected_false_positive_reason": params.get("corrected_false_positive_reason"),
    }


def report_subagent_result(params: dict) -> dict:
    """A delegated Subagent's own final answer — the terminal_tool that ends its
    _run_llm_tool_loop conversation (agent/core.py's _start_subagent_task), same "call this real
    tool with your final answer instead of free-text" contract as record_exploit_decision/
    record_reverification_result. summary is what the main agent actually sees once this pushes
    through the auto-delivery queue — concrete and specific, not a vague "task complete".
    """
    summary = params.get("summary")
    if not summary:
        return {"status": "error", "error": "summary is required — a concrete, specific account of what you actually found/did, not a vague 'task complete'"}
    return {"status": "ok", "summary": summary, "details": params.get("details")}


def check_subagent_task(params: dict) -> dict:
    """The explicit fallback poll for a delegated subagent task -- delegate_to_subagent's own
    primary delivery is the auto-push queue (agent/core.py's _push_subagent_result/
    _drain_subagent_results), not this; this is only for when that push somehow didn't happen, or
    the model wants to check earlier than the next natural drain point. A normal tier-1
    native_function (unlike delegate_to_subagent) -- it only inspects an already-tracked
    asyncio.Task's state (.done()/.result()/.exception() are plain, thread-safe reads), no running
    event loop required, so it needs no special-cased dispatch bypass the way spawning one does.
    """
    task_id = params.get("task_id")
    if not task_id:
        return {"status": "error", "error": "task_id is required"}
    return subagent_tasks.check_subagent_task(params.get("_session_id"), params.get("_session"), task_id)


def record_target(params: dict) -> dict:
    host = params.get("host")
    if not host:
        return {"status": "error", "error": "host is required"}
    port = params.get("port")
    recorded = {
        "host": host,
        "port": int(port) if port is not None else None,
        "service": params.get("service"),
        "version": params.get("version"),
    }
    return {"status": "ok", "recorded": recorded}


_VALID_HYPOTHESIS_STATUSES = {"confirmed", "ruled_out"}


def record_hypothesis(params: dict) -> dict:
    """A hypothesis is deliberately weaker than a finding (record_finding) and stronger than a bare
    fact (record_target) -- it names a SUSPECTED vulnerability/attack angle worth someone else's
    attention later, from raw evidence that doesn't yet prove anything on its own (an open,
    unauthenticated-looking admin path; a version string that rings a bell for a CVE family; a
    service exposed on a port that's unusual for it). The whole point is to let recon's own raw
    observations survive into Analyze/Exploit's hands as a real, structured lead instead of only
    living in that one turn's own reasoning text, gone the moment the conversation moves on.
    """
    text = params.get("text")
    if not text:
        return {"status": "error", "error": "text is required"}
    recorded = {"text": text, "evidence": params.get("evidence") or ""}
    source_tool = params.get("source_tool")
    if source_tool:
        recorded["source_tool"] = source_tool
    host = params.get("host")
    if host:
        recorded["host"] = host
    return {"status": "ok", "recorded": recorded}


def resolve_hypothesis(params: dict) -> dict:
    """Closes out an earlier record_hypothesis once it's actually been investigated -- "confirmed"
    (a real record_finding should also exist for it by now; this just marks the LEAD itself settled,
    it doesn't create the finding) or "ruled_out" (checked and it doesn't hold up -- note should say
    why, the same "don't just say 'unclear', explain the actual check" discipline record_finding's
    own false_positive_reason already follows). hypothesis_text is matched loosely against existing
    hypotheses (agent/core.py's own matching, not here) -- validation here is only about shape.
    """
    hypothesis_text = params.get("hypothesis_text")
    if not hypothesis_text:
        return {"status": "error", "error": "hypothesis_text is required"}
    status = params.get("status")
    if not isinstance(status, str) or status.strip().lower() not in _VALID_HYPOTHESIS_STATUSES:
        return {"status": "error", "error": f"status must be one of {sorted(_VALID_HYPOTHESIS_STATUSES)}, got {status!r}"}
    resolved = {
        "hypothesis_text": hypothesis_text,
        "status": status.strip().lower(),
        "note": params.get("note") or "",
    }
    resolving_tool = params.get("resolving_tool")
    if resolving_tool:
        resolved["resolving_tool"] = resolving_tool
    return {"status": "ok", "resolved": resolved}


_VALID_PLAN_PHASES = {"recon", "analyze", "exploit"}
_VALID_PLAN_TASK_STATUSES = {"pending", "active", "done", "blocked"}


def _derive_plan_status(child_statuses: list[str]) -> str:
    """A task's own status is never set directly by the model -- it's derived from its subtasks
    (done only once every subtask is done, active once any subtask is active/done, otherwise still
    pending), and a phase's status is derived the exact same way one level up, from its tasks' own
    (already-derived) statuses. Same reasoning as _auto_delegate_recon_overflow's own "a soft
    convention the model has to remember to keep in sync turned out unreliable" lesson, applied one
    level earlier: a model that marks every subtask done but forgets to also flag the parent task
    is a real, easy way to get stuck-looking inconsistent state if the parent had its own
    independent status field -- deriving it instead makes that whole class of drift structurally
    impossible, not just less likely.

    "blocked" (added after a real incident: a model correctly tried to report several subtasks as
    genuinely blocked -- "the Heroku dyno is crash-looping, every request 503s" -- via a status
    value the schema didn't recognize at the time, which silently downgraded to "pending",
    indistinguishable from "never even attempted"; the phase then stayed rendered as perpetually
    "active"/spinning long after it had genuinely concluded) rolls up specially: a parent whose
    children are ALL either "done" or "blocked" (nothing left pending/active) is itself "blocked"
    if any child is, else "done" -- honestly reflecting "this concluded, but not everything in it
    actually succeeded" instead of collapsing that distinction into a bare "done". A parent with a
    genuine MIX of blocked and still-open (pending/active) children still shows "active", same as
    before -- there's real remaining work, "blocked" hasn't taken over the whole thing.
    """
    if not child_statuses:
        return "pending"
    if all(status in ("done", "blocked") for status in child_statuses):
        return "blocked" if any(status == "blocked" for status in child_statuses) else "done"
    if any(status in ("active", "done", "blocked") for status in child_statuses):
        return "active"
    return "pending"


def _attempt_json_truncation_repair(raw: str) -> str | None:
    """Best-effort recovery for a JSON string cut off exactly at its own end -- missing only
    trailing closing brackets/braces, not a value truncated mid-way. Confirmed live
    (a real HackerOne rescan session): 8 of 9 update_plan "phases was sent as a string but is not
    valid JSON" errors in one real session had json.JSONDecodeError's own error position land
    exactly at len(original string) -- the provider's own function-call argument encoding
    (opencode-zen/nemotron) reliably dropped exactly the LAST character (always one closing `]`),
    not a random mid-string truncation. Walks the string tracking bracket/brace depth (respecting
    string literals and escape sequences) and, if it ends still inside an open array/object with no
    unterminated string, appends exactly the missing closing characters in the right order. Returns
    None (no repair attempted) when the string is already balanced or genuinely ends mid-string/
    mid-escape -- those aren't "missing one closing bracket", they're a different, non-recoverable
    shape this helper deliberately leaves to the normal error path below.
    """
    stack: list[str] = []
    in_string = False
    escape = False
    for ch in raw:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if not stack:
                return None
            stack.pop()
    if in_string or not stack:
        return None
    closing = {"{": "}", "[": "]"}
    return raw + "".join(closing[ch] for ch in reversed(stack))


def update_plan(params: dict) -> dict:
    """Validates and shapes a plan submission -- same "validate here, persist in agent/core.py's
    own execute() closure" split as record_target/record_finding above (this function never
    touches session state itself). A real, structural shape error (phases missing/not a list, a
    phase entry missing "phase" or "tasks" not a list, a task with no subtasks at all) is a real
    error the model should see and correct -- a phase's "tasks" list is allowed to be genuinely
    empty though (a legitimate draft-only forward-seed, rationale but nothing confirmed yet to build
    real tasks from -- see the comment at this function's own phases_raw normalization above). A
    subtask's own recommended_tools entry that names a tool that
    doesn't exist in this registry at all is silently dropped (never rejected outright), same
    "don't fail the whole call over one bad sub-field" tolerance record_finding's own
    case-insensitive severity aliasing already applies elsewhere; agent/core.py's
    _apply_plan_recommendations only ever reorders tools that are actually offered this phase
    anyway, so a dropped or out-of-phase name costs nothing either way.

    Three levels, not two: phase -> task -> subtask. A task is a real, concrete unit of work (e.g.
    "Enumerate the attack surface"); its subtasks are the actual steps that realize it (e.g. "WHOIS
    lookup", "DNS resolution"), each one the thing recommended_tools is actually about -- a task
    itself never carries tools or an independent status, only its subtasks do (see
    _derive_plan_status above for why status specifically is never independently settable above the
    leaf level).
    """
    # Real incident this covers: RECON_PROMPT explicitly asks the model to forward-seed a "genuine
    # best-effort sketch for analyze and exploit too, even though you can't act on those yet" in the
    # SAME call as recon's own real, fully broken-down plan — a legitimate draft-only phase can
    # honestly have nothing but a rationale yet (nothing confirmed to build real tasks/subtasks
    # from). Confirmed live: a real session's very first update_plan call failed outright with
    # "phase 'analyze' needs a non-empty tasks list" because analyze's own entry was exactly this —
    # rationale-only, tasks: [] — which didn't just reject analyze's own (legitimately empty) entry,
    # it discarded recon's own real, fully-detailed plan in the SAME call too, since this used to be
    # a whole-call rejection. Forced the model's retry to invent filler placeholder tasks just to
    # pass validation, which then got fully thrown away anyway once analyze itself later submitted
    # its own real plan. A phase's tasks list is now allowed to be empty (still must be a real list,
    # not missing/wrong-typed) — a task, once present, still must have real text and subtasks (see
    # below), so this only tolerates "nothing yet", never a half-written task.
    phases_raw = params.get("phases")
    phases_was_json_encoded_string = False
    if isinstance(phases_raw, str):
        # A native tool-calling model occasionally double-encodes this nested array parameter as
        # its own JSON string instead of sending a real array -- confirmed live: one real
        # provider+model pair did this on every single update_plan call across a whole session,
        # failing the first attempt 100% of the time and only succeeding via the 1-Step Retry that
        # resent the identical data as a real list. Recovering it here removes an entirely
        # avoidable extra LLM round-trip on every update_plan call, not just an occasional one --
        # same "accept a real-world variant shape" tolerance already applied to nuclei's tags
        # (accepts a JSON array where a comma-separated string is expected, the mirror image of
        # this case).
        #
        # phases_was_json_encoded_string (used below, once parsing succeeds) is what actually
        # teaches the model NOT to keep doing this: real, confirmed incident (rev-retest-rescan-
        # usr_8ba29f) — the SAME real provider+model pair sent phases as a JSON string 8 separate
        # times across one ~13-minute recon phase, each one silently self-healed by this same
        # recovery with zero lasting effect, because the 1-Step Retry's own correction exchange is
        # a fully isolated side-conversation the model never sees again — it has no memory of the
        # correction by the time it makes its NEXT independent update_plan call. Putting a reminder
        # directly in THIS call's own "recorded" result (below) instead reaches the model through
        # the one channel that actually persists: the tool-result message every future turn in this
        # same phase can still see in its own conversation history.
        original_phases_str = phases_raw
        try:
            phases_raw = json.loads(phases_raw)
            phases_was_json_encoded_string = True
        except (json.JSONDecodeError, TypeError) as exc:
            # Real, confirmed incident: this same double-encoding also showed up genuinely
            # malformed -- truncated mid-string (missing closing brackets), not just validly
            # double-encoded -- and json.loads() raising here used to be silently swallowed,
            # falling through to the generic "phases is required and must be a non-empty list"
            # message below. That's misleading: phases was NOT missing, it was present but broken,
            # and the message gave the model no hint what was actually wrong with it (a parse
            # error at a specific position), just that it looked empty. The normal 1-Step Retry
            # still recovered every time in practice (the schema hint reminds the model phases
            # must be a real list), but the wrong error message cost a needless extra guess.
            #
            # Before giving up, try the targeted truncation repair above -- it only ever fires for
            # the specific "missing trailing closing bracket(s)" shape, never for a genuinely
            # different malformation, so falling through to the same error message below when it
            # returns None (or still fails to parse) costs nothing extra.
            repaired = _attempt_json_truncation_repair(original_phases_str)
            if repaired is not None:
                try:
                    phases_raw = json.loads(repaired)
                    phases_was_json_encoded_string = True
                except json.JSONDecodeError:
                    repaired = None
            if repaired is None:
                preview = original_phases_str[:200] + ("..." if len(original_phases_str) > 200 else "")
                return {
                    "status": "error",
                    "error": (
                        f"phases was sent as a string but is not valid JSON ({exc}) -- send phases as "
                        f"a native JSON array/object, not a string. Original value: {preview!r}"
                    ),
                }
    if not isinstance(phases_raw, list) or not phases_raw:
        return {"status": "error", "error": "phases is required and must be a non-empty list"}

    phases: list[dict] = []
    dropped_tool_names: list[str] = []
    for phase_entry in phases_raw:
        if not isinstance(phase_entry, dict):
            return {"status": "error", "error": f"each phase entry must be an object, got {phase_entry!r}"}
        phase_name = phase_entry.get("phase")
        if phase_name not in _VALID_PLAN_PHASES:
            return {"status": "error", "error": f"phase must be one of {sorted(_VALID_PLAN_PHASES)}, got {phase_name!r}"}
        # Default to [] when the key is simply absent -- the error message below promises tasks
        # "can be empty for a draft-only forward-seed", so an omitted key must mean the same thing
        # as an explicit empty list, not a rejection. Real, confirmed incident: a model sent a
        # forward-seed phase with just a rationale and no "tasks" key at all, got rejected by this
        # check, and burned an extra correction round-trip discovering it had to spell out [].
        tasks_raw = phase_entry.get("tasks", [])
        if not isinstance(tasks_raw, list):
            return {"status": "error", "error": f"phase {phase_name!r} tasks must be a list (can be empty for a draft-only forward-seed with just a rationale)"}

        tasks: list[dict] = []
        for task_entry in tasks_raw:
            if not isinstance(task_entry, dict) or not task_entry.get("text"):
                return {"status": "error", "error": f"each task in phase {phase_name!r} needs a non-empty 'text'"}
            subtasks_raw = task_entry.get("subtasks")
            if not isinstance(subtasks_raw, list) or not subtasks_raw:
                return {
                    "status": "error",
                    "error": f"task {task_entry['text']!r} needs a non-empty 'subtasks' list — break it into the real concrete steps, even if there's only one",
                }

            subtasks: list[dict] = []
            for subtask_entry in subtasks_raw:
                if not isinstance(subtask_entry, dict) or not subtask_entry.get("text"):
                    return {"status": "error", "error": f"each subtask of {task_entry['text']!r} needs a non-empty 'text'"}
                status = subtask_entry.get("status") or "pending"
                if status not in _VALID_PLAN_TASK_STATUSES:
                    status = "pending"  # tolerate a real-world variant rather than failing the whole call
                recommended_tools = []
                for tool_name in subtask_entry.get("recommended_tools") or []:
                    if get_tool(tool_name) is not None:
                        recommended_tools.append(tool_name)
                    else:
                        dropped_tool_names.append(tool_name)
                subtasks.append({"text": subtask_entry["text"], "status": status, "recommended_tools": recommended_tools})

            task_status = _derive_plan_status([subtask["status"] for subtask in subtasks])
            tasks.append({"text": task_entry["text"], "status": task_status, "subtasks": subtasks})

        phase_status = _derive_plan_status([task["status"] for task in tasks])
        phases.append({"phase": phase_name, "rationale": phase_entry.get("rationale") or "", "status": phase_status, "tasks": tasks})

    recorded = {"phases": phases}
    if dropped_tool_names:
        # Not part of "recorded" -- agent/core.py's execute() closure logs this at debug level
        # (get_logger("AGENT")) so a silently-dropped, non-existent tool name is never truly
        # invisible, just not loud enough to fail the whole plan update over.
        recorded["_dropped_tool_names"] = dropped_tool_names
    if phases_was_json_encoded_string:
        # See phases_was_json_encoded_string's own comment above for why this lives HERE (inside
        # the real "ok" result every future turn's own conversation history still carries) rather
        # than in the 1-Step Retry's isolated correction exchange, which the model never sees again.
        recorded["reminder"] = (
            "Your 'phases' argument arrived as a JSON-encoded STRING this time, not a native array "
            "— it was tolerantly parsed and applied, but pass it as a real nested array/object "
            "directly in the tool call's own arguments for every update_plan call from now on, not "
            "as a string."
        )
    return {"status": "ok", "recorded": recorded}


# --- web_self_register: a real, single-shot account-creation attempt against a target's own
# signup/registration form -- for the case where NO account exists yet on this target at all and
# the program's own rules allow creating one (a real, common bug-bounty authenticated-testing
# path, distinct from default_creds_check's "try known default logins" and hydra/
# web_login_bruteforce's "crack an existing account's password"). Exploit-tier gating (creates a
# real, persistent account on the target's own infrastructure, not passive recon), same class as
# default_creds_check. Deliberately no CAPTCHA/email-verification/OTP handling -- a signup flow
# gated behind any of those genuinely cannot be completed this way; this reports an honest
# match/no-match result either way (never a guess), same "say what actually happened" discipline as
# web_login_bruteforce's own success/failure_string contract. ---

_SELF_REGISTER_CSRF_FIELD_NAMES = (
    "csrf_token", "csrfmiddlewaretoken", "_token", "authenticity_token", "_csrf", "csrf",
    "__RequestVerificationToken",
)


def _extract_self_register_csrf_token(html_text: str, custom_field: str | None) -> tuple[str, str] | None:
    """Same hidden-field-shaped CSRF-token sniff as web_login_bruteforce's own subprocess script
    (agent/tools/builders/web_login_bruteforce.py's _SCRIPT) -- duplicated rather than shared/
    imported since that one lives inside a static string executed as a standalone subprocess (no
    sensible import path back into this file for it), while this tool runs in-process for a single
    GET+POST(+POST) sequence with no subprocess of its own to hand a script file to.
    """
    names = ([custom_field] if custom_field else []) + list(_SELF_REGISTER_CSRF_FIELD_NAMES)
    for name in names:
        escaped = re.escape(name)
        pattern_a = r'name=["\']' + escaped + r'["\'][^>]*value=["\']([^"\']*)["\']'
        match = re.search(pattern_a, html_text, re.IGNORECASE)
        if not match:
            pattern_b = r'value=["\']([^"\']*)["\'][^>]*name=["\']' + escaped + r'["\']'
            match = re.search(pattern_b, html_text, re.IGNORECASE)
        if match:
            return name, match.group(1)
    return None


def _self_register_submit(client: httpx.Client, url: str, data: dict, csrf_field: str | None) -> httpx.Response:
    """One GET (fresh cookies/CSRF token) + POST cycle against `url` -- shared by both the
    registration submission itself and the optional post-registration login step below, so a
    CSRF-protected form is handled identically either way, on the SAME client (persistent cookies).
    """
    get_resp = _with_hard_deadline(lambda: client.get(url), _HTTP_TIMEOUT)
    token = _extract_self_register_csrf_token(get_resp.text, csrf_field)
    body = dict(data)
    if token:
        body[token[0]] = token[1]
    return _with_hard_deadline(lambda: client.post(url, data=body), _HTTP_TIMEOUT)


# --- temp_email_create / temp_email_check_inbox: real, working disposable-inbox automation for a
# signup flow (web_self_register above) that requires a receivable email address to complete
# verification, when no configured identity/real address is available. Tries several independent
# free, key-free, documented JSON-API providers in order, not just one -- any of these can go
# down/block requests on its own schedule with zero warning, confirmed live during this exact
# feature's own development: 1secmail returned a bare "403 Forbidden ... Server unable to read
# htaccess file" from its own host while mail.tm and guerrillamail both worked fine at the same
# moment. A single-provider implementation would make this whole capability only as reliable as
# whichever one host happens to be up right now. No browser/scraping involved for any of the
# three -- each is a real, documented, key-free JSON API, exactly as deterministic as any other
# third-party lookup tool here (crt_sh_lookup, whois_lookup). If every provider fails, the result
# says so explicitly and names the browser-driven fallback (open a temp-mail site's own web UI via
# browser_navigate) instead of silently giving up with no path forward. ---

_TEMP_MAIL_HTTP_TIMEOUT = 20.0


def _strip_html_tags(raw_html: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", " ", raw_html)).strip()


def _mailtm_create(client: httpx.Client) -> dict:
    domains_resp = client.get("https://api.mail.tm/domains")
    domains_resp.raise_for_status()
    domains = [d["domain"] for d in domains_resp.json().get("hydra:member", []) if d.get("isActive")]
    if not domains:
        raise ValueError("mail.tm: no active domain available")
    address = f"asra{uuid.uuid4().hex[:10]}@{domains[0]}"
    password = uuid.uuid4().hex
    create_resp = client.post("https://api.mail.tm/accounts", json={"address": address, "password": password})
    if create_resp.status_code not in (200, 201):
        raise ValueError(f"mail.tm: account creation failed, HTTP {create_resp.status_code}")
    token_resp = client.post("https://api.mail.tm/token", json={"address": address, "password": password})
    token_resp.raise_for_status()
    token = token_resp.json().get("token")
    if not token:
        raise ValueError("mail.tm: no auth token returned")
    return {"address": address, "token": token}


def _mailtm_check(client: httpx.Client, account: dict) -> list[dict]:
    headers = {"Authorization": f"Bearer {account['token']}"}
    list_resp = client.get("https://api.mail.tm/messages", headers=headers)
    list_resp.raise_for_status()
    messages = []
    for summary in list_resp.json().get("hydra:member", [])[:10]:
        detail_resp = client.get(f"https://api.mail.tm/messages/{summary['id']}", headers=headers)
        if detail_resp.status_code != 200:
            continue
        detail = detail_resp.json()
        html_body = detail.get("html")
        html_text = html_body[0] if isinstance(html_body, list) and html_body else (html_body or "")
        body = detail.get("text") or _strip_html_tags(html_text)
        messages.append({
            "from": (detail.get("from") or {}).get("address", ""),
            "subject": detail.get("subject", ""),
            "text": body[:4000],
            "received_at": detail.get("createdAt", ""),
        })
    return messages


def _onesecmail_create(client: httpx.Client) -> dict:
    resp = client.get("https://www.1secmail.com/api/v1/", params={"action": "genRandomMailbox", "count": 1})
    resp.raise_for_status()
    addresses = resp.json()
    if not addresses:
        raise ValueError("1secmail: no mailbox returned")
    address = addresses[0]
    login, domain = address.split("@", 1)
    return {"address": address, "login": login, "domain": domain}


def _onesecmail_check(client: httpx.Client, account: dict) -> list[dict]:
    params = {"login": account["login"], "domain": account["domain"]}
    resp = client.get("https://www.1secmail.com/api/v1/", params={**params, "action": "getMessages"})
    resp.raise_for_status()
    messages = []
    for summary in resp.json()[:10]:
        detail_resp = client.get("https://www.1secmail.com/api/v1/", params={**params, "action": "readMessage", "id": summary["id"]})
        if detail_resp.status_code != 200:
            continue
        detail = detail_resp.json()
        body = detail.get("textBody") or _strip_html_tags(detail.get("htmlBody") or "")
        messages.append({
            "from": detail.get("from", ""),
            "subject": detail.get("subject", ""),
            "text": body[:4000],
            "received_at": detail.get("date", ""),
        })
    return messages


def _guerrillamail_create(client: httpx.Client) -> dict:
    resp = client.get("https://api.guerrillamail.com/ajax.php", params={"f": "get_email_address"})
    resp.raise_for_status()
    data = resp.json()
    address, sid_token = data.get("email_addr"), data.get("sid_token")
    if not address or not sid_token:
        raise ValueError("guerrillamail: no mailbox/session token returned")
    return {"address": address, "sid_token": sid_token}


def _guerrillamail_check(client: httpx.Client, account: dict) -> list[dict]:
    resp = client.get("https://api.guerrillamail.com/ajax.php", params={"f": "check_email", "seq": 0, "sid_token": account["sid_token"]})
    resp.raise_for_status()
    messages = []
    for summary in resp.json().get("list", [])[:10]:
        body = summary.get("mail_body") or summary.get("mail_excerpt") or ""
        messages.append({
            "from": summary.get("mail_from", ""),
            "subject": summary.get("mail_subject", ""),
            "text": _strip_html_tags(body)[:4000],
            "received_at": summary.get("mail_date", ""),
        })
    return messages


# Order matters -- tried top to bottom, first success wins. mail.tm first (richest API, own
# per-account auth token); the other two are fully anonymous (no signup step at all) and serve as
# real, independent fallbacks, not just theoretical ones -- see this section's own module comment
# for the confirmed-live incident that motivated having more than one.
_TEMP_MAIL_PROVIDERS = [
    ("mail.tm", _mailtm_create, _mailtm_check),
    ("1secmail", _onesecmail_create, _onesecmail_check),
    ("guerrillamail", _guerrillamail_create, _guerrillamail_check),
]
_TEMP_MAIL_CHECKERS = {name: check for name, _, check in _TEMP_MAIL_PROVIDERS}

# In-memory only (never written to disk/session.json) -- a throwaway mailbox's own auth token/
# session-id is a real secret for that mailbox, but it's disposable and process-lifetime scoped
# anyway, same "authenticated client cache" posture as _authenticated_clients above. Keyed by
# session_id -> {address: {**provider-specific fields, "provider": name}}.
_temp_email_accounts: dict[str, dict[str, dict]] = {}


def temp_email_create(params: dict) -> dict:
    """Creates a real, receivable disposable email inbox -- for a signup flow (web_self_register)
    that requires a working email address to complete verification, when no configured identity/
    real address is available. Tries several independent free API providers in order (see this
    section's own module comment) and returns the first one that actually works; poll
    temp_email_check_inbox(email=...) afterward for the verification message it actually receives.

    Not gated by the exploitation allowlist -- every provider here is a third-party mail service,
    never the assessment target itself, same posture as crt_sh_lookup/hibp_breach_check. If every
    provider fails, the result names a browser_navigate-driven fallback instead of a dead end.
    """
    session_id = params.get("_session_id")
    if not session_id:
        return {"status": "error", "error": "temp_email_create requires session context"}

    errors = []
    with httpx.Client(timeout=_TEMP_MAIL_HTTP_TIMEOUT) as client:
        for name, create_fn, _check_fn in _TEMP_MAIL_PROVIDERS:
            try:
                account = create_fn(client)
            except (httpx.HTTPError, ValueError, KeyError, json.JSONDecodeError) as exc:
                errors.append(f"{name}: {describe_exception(exc)}")
                continue
            account["provider"] = name
            _temp_email_accounts.setdefault(session_id, {})[account["address"]] = account
            logger.debug("native: temp_email_create session=%s provider=%s address=%s", session_id, name, account["address"])
            return {"status": "ok", "email": account["address"], "provider": name}

    return {
        "status": "error",
        "error": f"All known API-based temp-mail providers failed right now: {'; '.join(errors)}",
        # Deliberately no fixed site list here -- any one of those can itself go down/block/change
        # layout, the exact failure mode this whole fallback exists to route around one level up.
        # dork_search's own custom_dork branch needs no target at all (see that tool's own
        # build_dork_result: `elif custom_dork: query = custom_dork`), so this is a genuinely open
        # search, not a hardcoded shortlist -- whichever real, currently-live provider search
        # actually turns up gets used, the same way a human would just search for one.
        "browser_fallback_hint": (
            "Every API-based provider failed (each can go down/block requests independently of the "
            "others). Search for a live one instead of guessing a name: dork_search(custom_dork="
            "'free temporary email inbox', engine='google') builds a real search-engine query URL, "
            "browser_navigate to it, then browser_snapshot to read the results and pick any "
            "currently-working provider -- never limited to a fixed list, same for the case where "
            "your first pick also turns out to be broken/CAPTCHA-gated: search again."
        ),
    }


def temp_email_check_inbox(params: dict) -> dict:
    """Polls a disposable inbox created by temp_email_create for real received messages -- returns
    each one's real sender/subject/plain-text body so the model can find and quote a verification
    link/code directly from actual evidence, never invent one. It's fine to call this more than
    once while waiting for a signup's verification email to arrive (mail delivery isn't instant).
    Defaults to the most recently created address for this session when "email" is omitted.
    """
    session_id = params.get("_session_id")
    email = params.get("email")
    accounts = _temp_email_accounts.get(session_id) or {}
    if not email:
        if not accounts:
            return {"status": "error", "error": "no temp_email_create address for this session yet -- call it first"}
        email = next(reversed(accounts))  # most recently created -- dicts preserve insertion order
    account = accounts.get(email)
    if account is None:
        return {"status": "error", "error": f"no temp_email_create address {email!r} for this session -- call temp_email_create first"}

    try:
        with httpx.Client(timeout=_TEMP_MAIL_HTTP_TIMEOUT) as client:
            messages = _TEMP_MAIL_CHECKERS[account["provider"]](client, account)
    except (httpx.HTTPError, ValueError, KeyError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {"status": "ok", "email": email, "provider": account["provider"], "messages": messages}


def web_self_register(params: dict) -> dict:
    """Attempts a real, single-shot self-registration against a target's own signup/registration
    form. On success, the new account's username/password become immediately usable via
    authenticated_request/idor_probe's own identity= lookup (agent/core.py's _update_asset_graph
    registers it, same as a default_creds_check hit) — check identity_name in this call's own
    result (or the "credential_identity_names" field _update_asset_graph attaches) rather than
    re-typing the username/password into another tool. Check the program's own scope rules before
    calling this — some bug-bounty programs explicitly permit or even require self-registration for
    authenticated testing, others restrict or forbid automated account creation.

    username/password/email are auto-generated (asra_<random>) when omitted — pass explicit values
    only when the target's own rules require a specific shape (e.g. email must be from an allowed
    domain). login_path is optional: when the signup flow doesn't auto-login the new account (the
    common case), pass the real login endpoint and this performs one real login POST right after a
    successful registration so the returned identity is immediately authenticated, not just
    created — registration succeeding but this follow-up login failing does NOT undo the
    registration result, since the account still exists either way.
    """
    target = str(params["target"])
    registration_path = params.get("registration_path")
    if not registration_path:
        return {"status": "error", "error": "registration_path is required"}

    failure_string = params.get("failure_string")
    success_string = params.get("success_string")
    if not failure_string and not success_string:
        return {"status": "error", "error": "failure_string or success_string is required"}

    username = str(params.get("username") or f"asra_{uuid.uuid4().hex[:8]}")
    password = str(params.get("password") or f"Asra!{uuid.uuid4().hex[:10]}9")
    username_field = str(params.get("username_field") or "username")
    password_field = str(params.get("password_field") or "password")
    confirm_password_field = params.get("confirm_password_field")
    email_field = params.get("email_field")
    email = str(params["email"]) if params.get("email") else (f"asra.{uuid.uuid4().hex[:10]}@example.com" if email_field else None)
    csrf_field = params.get("csrf_field")
    extra_fields = params.get("extra_fields") or {}

    registration_url = target.rstrip("/") + str(registration_path)
    data = {username_field: username, password_field: password}
    if confirm_password_field:
        data[str(confirm_password_field)] = password
    if email_field and email:
        data[str(email_field)] = email
    for key, value in extra_fields.items():
        data[str(key)] = value

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True, **_target_client_kwargs(params)) as client:
            resp = _self_register_submit(client, registration_url, data, csrf_field)
            body = resp.text
            matched = (
                success_string.lower() in body.lower() if success_string
                else failure_string.lower() not in body.lower()
            )
            if not matched:
                return {
                    "status": "error",
                    "error": "registration did not match success_string/failure_string -- treat this account as NOT created",
                    "status_code": resp.status_code,
                    "body_preview": body[:2000],
                }

            login_url = None
            login_path = params.get("login_path")
            if login_path:
                candidate_login_url = target.rstrip("/") + str(login_path)
                login_data = {username_field: username, password_field: password}
                if email_field and email:
                    login_data[str(email_field)] = email
                try:
                    _self_register_submit(client, candidate_login_url, login_data, csrf_field)
                    login_url = candidate_login_url
                except httpx.HTTPError:
                    pass  # registration itself still succeeded -- just couldn't confirm a fresh login
            cookie = "; ".join(f"{c.name}={c.value}" for c in client.cookies.jar) or None
    except httpx.HTTPError as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {
        "status": "ok",
        "successful_credentials": [{"username": username, "password": password}],
        "registration_url": registration_url,
        "email": email,
        "login_url": login_url,
        "cookie": cookie,
    }


def default_creds_check(params: dict) -> dict:
    """Tries default username/password pairs against a login endpoint (POST JSON).

    An optional "vendor" param looks up that product/vendor's own real known-default pairs from
    cirt.net's Default Password Database (_load_cirt_default_passwords above -- 531 real vendors,
    harvested by scripts/harvest_cirt_default_passwords.py) and tries THOSE first, then falls
    through to the generic list -- pass this whenever nmap -sV/whatweb/a CVE lookup has already
    identified what's actually running (e.g. "Server: Hikvision IP Camera httpd" ->
    vendor="hikvision"; matched case/punctuation-insensitively against cirt.net's real names, with a
    substring fallback, so an approximate slug still resolves). Omitting "vendor" keeps the exact
    original behavior: only the six generic pairs, tried once each.
    """
    login_url = params["target"]
    username_field = params.get("username_field", "email")
    password_field = params.get("password_field", "password")
    vendor_query = (params.get("vendor") or "").strip()

    pairs = _DEFAULT_CREDENTIAL_PAIRS
    matched_vendor = None
    if vendor_query:
        resolved = _resolve_vendor_credential_pairs(vendor_query)
        if resolved is None:
            hint = (
                "run scripts/harvest_cirt_default_passwords.py first -- it hasn't been run yet"
                if not _load_cirt_default_passwords()
                else (
                    "check the spelling, or it may genuinely not be in cirt.net's database (it skews "
                    "toward legacy network/router/camera hardware, not modern self-hosted web "
                    "dashboards) -- omit 'vendor' to fall back to the six generic pairs either way"
                )
            )
            return {
                "status": "error",
                "error": f"No default-credential entry found for vendor {vendor_query!r} in cirt.net's database -- {hint}.",
            }
        vendor_pairs, matched_vendor = resolved
        # Vendor-specific pairs first (most likely to actually hit) -- generic list still tried
        # after, deduplicated so an already-tried vendor pair never fires twice.
        pairs = vendor_pairs + [pair for pair in _DEFAULT_CREDENTIAL_PAIRS if pair not in vendor_pairs]

    successes = []
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, **_target_client_kwargs(params)) as client:
            for username, password in pairs:
                try:
                    resp = _with_hard_deadline(
                        lambda u=username, p=password: client.post(login_url, json={username_field: u, password_field: p}),
                        _HTTP_TIMEOUT,
                    )
                except _HardDeadlineExceeded as exc:
                    return {
                        "status": "error",
                        "error": f"target unreachable, stopped after 1 of {len(pairs)} credential pairs: {exc}",
                    }
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200:
                    successes.append({"username": username, "password": password})
    except Exception as exc:
        return {"status": "error", "error": describe_exception(exc)}

    return {
        "status": "ok",
        "successful_credentials": successes,
        "attempted": len(pairs),
        "vendor": matched_vendor,
    }


# --- active cloud-storage permission probe (CloudSpecter-style: anonymous read/write test against
# a real bucket/container endpoint) -- exploit-tier gating, same reasoning as default_creds_check
# above: an anonymous PUT is a real write against the target's own infrastructure, not passive
# recon. Deliberately anonymous-only (no AWS/GCP/Azure SDK, no credential wiring) -- this answers
# "is this bucket exposed to the whole internet", the actual bug-bounty-relevant question; testing
# WITH credentials would need real cloud SDKs and a place to keep those secrets, out of scope for
# what this tool is for. ---

_CLOUD_BUCKET_TEST_OBJECT_PREFIX = "asra-cloud-bucket-scan-test-"


def _cloud_bucket_severity(readable: bool, writable: bool | None) -> str:
    if writable:
        return "CRITICAL"
    if readable:
        return "HIGH"
    return "INFO"


def _cloud_bucket_check_s3_compatible(base_url: str, test_write: bool, client: httpx.Client, provider: str) -> dict:
    """AWS S3 and GCS's own XML API (storage.googleapis.com) both speak the identical S3-style
    bucket-listing/PUT-object protocol -- one implementation covers both providers."""
    base = base_url.rstrip("/")
    result: dict = {"provider": provider, "readable": False, "writable": None, "cleanup_ok": None}
    try:
        resp = client.get(base + "/")
    except httpx.HTTPError as exc:
        result["error"] = f"read check failed: {describe_exception(exc)}"
        return result
    result["read_status_code"] = resp.status_code
    result["readable"] = resp.status_code == 200 and "<ListBucketResult" in resp.text
    if not test_write:
        return result

    key = _CLOUD_BUCKET_TEST_OBJECT_PREFIX + uuid.uuid4().hex[:8] + ".txt"
    put_url = f"{base}/{key}"
    body = b"ASRA cloud_bucket_scan write-permission test file -- safe to delete."
    try:
        put_resp = client.put(put_url, content=body)
    except httpx.HTTPError as exc:
        result["writable"] = False
        result["write_error"] = describe_exception(exc)
        return result
    result["write_status_code"] = put_resp.status_code
    result["writable"] = put_resp.status_code in (200, 204)
    if result["writable"]:
        try:
            del_resp = client.delete(put_url)
            result["cleanup_ok"] = del_resp.status_code in (200, 204, 404)
        except httpx.HTTPError as exc:
            result["cleanup_ok"] = False
            result["cleanup_error"] = describe_exception(exc)
    return result


def _cloud_bucket_check_azure(container_url: str, client: httpx.Client) -> dict:
    """Azure Blob Storage never allows anonymous write regardless of container ACL -- a real
    platform limitation, not something a misconfiguration could ever grant -- so only the read
    (list) check is meaningful here; write is always reported untested."""
    base = container_url.rstrip("/")
    separator = "&" if "?" in base else "?"
    list_url = f"{base}{separator}restype=container&comp=list"
    result: dict = {
        "provider": "azure",
        "readable": False,
        "writable": False,
        "cleanup_ok": None,
        "write_note": "Azure Blob Storage has no anonymous-write capability at the platform level -- never tested.",
    }
    try:
        resp = client.get(list_url)
    except httpx.HTTPError as exc:
        result["error"] = f"read check failed: {describe_exception(exc)}"
        return result
    result["read_status_code"] = resp.status_code
    result["readable"] = resp.status_code == 200 and "<EnumerationResults" in resp.text
    return result


def cloud_bucket_scan(params: dict) -> dict:
    """Active anonymous read/write permission probe for a single AWS S3 / GCS / Azure Blob bucket
    or container -- same technique as CloudSpecter (github.com/Viralmaniar/CloudSpecter): actually
    connects and tests, rather than just noting a bucket's URL was mentioned somewhere (that's what
    dork_search's s3_buckets/digitalocean_spaces categories do). A public, anonymously-writable
    bucket is a common, well-paid bug-bounty finding class on its own.

    "target" is the bucket's own full https URL (virtual-hosted or path style both work for AWS):
    https://<bucket>.s3.amazonaws.com, https://s3.amazonaws.com/<bucket>,
    https://storage.googleapis.com/<bucket>, or https://<account>.blob.core.windows.net/<container>.
    "test_write" (default False) additionally uploads a small, clearly-labeled test object and
    immediately deletes it to confirm anonymous write access -- only set this when you actually need
    write-permission proof; the read-only check alone already answers "is this bucket public".

    Severity, same rating CloudSpecter itself reports: CRITICAL (anonymous read+write), HIGH
    (anonymous read only), INFO (not readable -- proves nothing either way about write, since a
    write-only bucket policy, while rare, is possible and only test_write=True can reveal it).
    """
    raw_target = params["target"].strip()
    test_write = bool(params.get("test_write", False))
    target = raw_target if "://" in raw_target else f"https://{raw_target}"
    host = (urlsplit(target).hostname or "").lower()

    if host == "s3.amazonaws.com" or host.endswith(".s3.amazonaws.com"):
        provider = "aws"
    elif host == "storage.googleapis.com":
        provider = "gcp"
    elif host.endswith(".blob.core.windows.net"):
        provider = "azure"
    else:
        return {
            "status": "error",
            "error": (
                f"target host {host!r} isn't a recognized AWS S3 / GCS / Azure Blob endpoint -- pass "
                "the bucket's own https URL, e.g. https://<bucket>.s3.amazonaws.com, "
                "https://storage.googleapis.com/<bucket>, or https://<account>.blob.core.windows.net/<container>."
            ),
        }

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, **_target_client_kwargs(params)) as client:
            if provider == "azure":
                check = _cloud_bucket_check_azure(target, client)
            else:
                check = _cloud_bucket_check_s3_compatible(target, test_write, client, provider)
    except Exception as exc:
        return {"status": "error", "error": describe_exception(exc)}

    severity = _cloud_bucket_severity(check.get("readable", False), check.get("writable"))
    return {"status": "ok", "target": target, "severity": severity, **check}


# --- breach/leaked-credential OSINT lookups: third-party services, zero touch on the target ---


def xposedornot_check(params: dict) -> dict:
    """Free, keyless breach-exposure lookup for a single email address via XposedOrNot's public API
    (github.com/Viralmaniar/XposedOrNot, api.xposedornot.com) -- an independently-maintained
    aggregation of real data breaches (Collection #1, Yahoo, and others), same category of service
    as Have I Been Pwned but with no account/key required at all. A hit on an employee's corporate
    email is a real credential-stuffing/password-reuse risk signal during a pentest, not proof of a
    live vulnerability by itself -- hibp_breach_check (if a key is configured) is a second,
    independently-sourced confirmation worth pairing this with. Rate-limited by the service itself
    (2 req/sec, 25/hour, 100/day on its free tier) -- a 429 means "wait", not "broken".
    """
    email = params["email"].strip()
    cached = cache_get("xposedornot_check", email)
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(f"https://api.xposedornot.com/v1/check-email/{email}")
            if resp.status_code == 404:
                result = {"status": "ok", "email": email, "exposed": False, "breaches": []}
                cache_set("xposedornot_check", email, result)
                return result
            if resp.status_code == 429:
                return {"status": "error", "error": "XposedOrNot rate limit hit (2/sec, 25/hour, 100/day on the free tier) -- wait before retrying."}
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    if data.get("Error") == "Not found":
        result = {"status": "ok", "email": email, "exposed": False, "breaches": []}
    else:
        breach_groups = data.get("breaches") or []
        breaches = sorted({name for group in breach_groups for name in group})
        result = {"status": "ok", "email": email, "exposed": bool(breaches), "breaches": breaches}
    cache_set("xposedornot_check", email, result)
    return result


def hibp_breach_check(params: dict) -> dict:
    """Have I Been Pwned breach-exposure lookup for a single email address
    (haveibeenpwned.com/api/v3/breachedaccount) -- the industry-reference breach-notification
    service; a hit here carries more external credibility in a bug-bounty report than a lesser-known
    aggregator alone. Requires a paid HIBP API key (Settings -> Tool API Keys) -- HIBP has no
    anonymous email-search access at all, unlike its own free k-anonymity Pwned Passwords endpoint
    (see hibp_password_check). Use the fully free xposedornot_check first/instead when no key is
    configured. params["_api_key"] arrives via agent/core.py's generic tool_api_keys injection --
    see agent/tools/tool_api_keys.py's TOOL_API_KEY_SPECS entry for this tool.
    """
    email = params["email"].strip()
    api_key = params.get("_api_key")
    if not api_key:
        return {
            "status": "error",
            "error": (
                "HIBP_API_KEY not configured -- add a Have I Been Pwned API key in Settings -> Tool "
                "API Keys (https://haveibeenpwned.com/API/Key, paid) to use this tool. Free "
                "alternative for the same kind of check: xposedornot_check."
            ),
        }

    cached = cache_get("hibp_breach_check", email)
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                params={"truncateResponse": "false"},
                headers={"hibp-api-key": api_key, "user-agent": "ASRA-pentest-agent"},
            )
            if resp.status_code == 404:
                result = {"status": "ok", "email": email, "exposed": False, "breaches": []}
                cache_set("hibp_breach_check", email, result)
                return result
            if resp.status_code == 401:
                return {"status": "error", "error": "HIBP rejected the configured API key (401) -- check it's still valid in Settings -> Tool API Keys."}
            if resp.status_code == 429:
                return {"status": "error", "error": "HIBP rate limit hit -- wait before retrying."}
            resp.raise_for_status()
            data = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": describe_exception(exc)}

    breaches = [
        {
            "name": entry.get("Name"),
            "domain": entry.get("Domain"),
            "breach_date": entry.get("BreachDate"),
            "data_classes": entry.get("DataClasses"),
            "is_verified": entry.get("IsVerified"),
        }
        for entry in data
    ]
    result = {"status": "ok", "email": email, "exposed": bool(breaches), "breaches": breaches}
    cache_set("hibp_breach_check", email, result)
    return result


def hibp_password_check(params: dict) -> dict:
    """Free, keyless check of whether a password has appeared in a known breach corpus, via HIBP's
    k-anonymity Pwned Passwords range API -- only the first 5 hex characters of the password's own
    SHA-1 hash are ever sent over the network, the full password/hash never leaves this machine.
    Real use during a pentest: strengthen a weak/default-credential finding by showing the exact
    password is a KNOWN breached password (not merely guessable), or vet a proposed test password
    before use. Not a target-facing check at all -- this queries pwnedpasswords.com, never the
    assessment target -- and the result deliberately never echoes the password itself back.
    """
    password = params["password"]
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    cached = cache_get("hibp_password_check", prefix)
    if cached is not None:
        body = cached["body"]
    else:
        try:
            with httpx.Client(timeout=15.0) as client:
                resp = client.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"user-agent": "ASRA-pentest-agent"})
                resp.raise_for_status()
        except httpx.HTTPError as exc:
            return {"status": "error", "error": describe_exception(exc)}
        body = resp.text
        cache_set("hibp_password_check", prefix, {"body": body})

    for line in body.splitlines():
        line_suffix, _, count = line.partition(":")
        if line_suffix.strip().upper() == suffix:
            return {"status": "ok", "pwned": True, "times_seen": int(count.strip() or 0)}
    return {"status": "ok", "pwned": False, "times_seen": 0}
