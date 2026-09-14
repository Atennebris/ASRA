"""Live threat-intelligence enrichment for playbook techniques: CISA KEV (Known Exploited
Vulnerabilities) + FIRST.org EPSS (Exploit Prediction Scoring System). Ties a technique's CVEs to
what's ACTUALLY being exploited in the wild right now, so the agent prioritizes proven-and-hot over
theoretical.

Everything here is best-effort and offline-tolerant: feeds are fetched once and cached to the global
app dir with a TTL; a fetch failure (no network, a feed down) falls back to whatever's cached, or to
"unknown" (never an exception into the caller). The two fetch functions are the only network touch
and are deliberately isolated so tests can mock them.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("PLAYBOOK")

_KEV_CACHE_PATH = resolve_global_app_dir() / "data" / "playbook" / "kev_cache.json"
_EPSS_CACHE_PATH = resolve_global_app_dir() / "data" / "playbook" / "epss_cache.json"

_KEV_FEED_URL = os.getenv("THREAT_INTEL_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
_EPSS_API_URL = os.getenv("THREAT_INTEL_EPSS_URL", "https://api.first.org/data/v1/epss")


def _ttl_seconds() -> int:
    """How long cached feed data stays fresh before a re-fetch is attempted. 0 disables network
    entirely (cache-only) -- useful for a fully offline run."""
    return int(os.getenv("THREAT_INTEL_TTL_SECONDS", "86400"))


def _fetch_timeout() -> float:
    return float(os.getenv("THREAT_INTEL_FETCH_TIMEOUT_SECONDS", "8"))


def threat_intel_enabled() -> bool:
    return os.getenv("THREAT_INTEL_ENABLED", "true").strip().lower() == "true"


def _load_cache(path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError as exc:
        logger.debug("threat_intel: cache write failed (%s) -- ignored", exc)


def _http_get_json(url: str) -> dict | None:
    """The single network primitive (isolated so tests mock it). Returns parsed JSON, or None on ANY
    failure -- network down, timeout, non-JSON, HTTP error."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ASRA-threat-intel"})
        with urllib.request.urlopen(req, timeout=_fetch_timeout()) as resp:  # noqa: S310 (fixed, non-user URL)
            return json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.debug("threat_intel: fetch failed for %s (%s)", url, exc)
        return None


def kev_cve_ids() -> set[str]:
    """The set of CVE ids in CISA's Known Exploited Vulnerabilities catalog. Cached with a TTL;
    refreshed from the feed only when stale AND reachable, else the cached set is used (empty if
    never fetched and currently offline)."""
    cache = _load_cache(_KEV_CACHE_PATH)
    fresh = cache.get("fetched_at", 0) + _ttl_seconds() > time.time()
    if fresh or _ttl_seconds() == 0:
        return set(cache.get("cves", []))
    data = _http_get_json(_KEV_FEED_URL)
    if data and isinstance(data.get("vulnerabilities"), list):
        cves = sorted({v.get("cveID") for v in data["vulnerabilities"] if v.get("cveID")})
        _save_cache(_KEV_CACHE_PATH, {"fetched_at": int(time.time()), "cves": cves})
        logger.debug("threat_intel: refreshed KEV catalog (%d CVEs)", len(cves))
        return set(cves)
    return set(cache.get("cves", []))  # fetch failed -> fall back to cache


def epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """EPSS probabilities (0..1, "how likely this CVE is exploited in the wild") for the given CVEs.
    Per-CVE cached with a TTL; only the stale/unknown ones are (batch) re-fetched, and a fetch
    failure leaves the cached/omitted values untouched."""
    if not cve_ids:
        return {}
    cache = _load_cache(_EPSS_CACHE_PATH)
    now = time.time()
    out: dict[str, float] = {}
    to_fetch: list[str] = []
    for cve in cve_ids:
        entry = cache.get(cve)
        if entry and entry.get("fetched_at", 0) + _ttl_seconds() > now:
            out[cve] = entry["score"]
        elif _ttl_seconds() == 0:
            if entry:
                out[cve] = entry["score"]
        else:
            to_fetch.append(cve)
    if to_fetch:
        data = _http_get_json(f"{_EPSS_API_URL}?cve={','.join(to_fetch)}")
        if data and isinstance(data.get("data"), list):
            for row in data["data"]:
                cve = row.get("cve")
                try:
                    score = float(row.get("epss"))
                except (TypeError, ValueError):
                    continue
                if cve:
                    out[cve] = score
                    cache[cve] = {"score": score, "fetched_at": int(now)}
            _save_cache(_EPSS_CACHE_PATH, cache)
            logger.debug("threat_intel: refreshed EPSS for %d CVE(s)", len(to_fetch))
    return out


def enrich_cves(cve_ids: list[str]) -> dict[str, dict]:
    """Per-CVE {"kev": bool, "epss": float|None} for a technique's CVEs -- the shape the UI and the
    addendum both read. Best-effort: whatever the caches/feeds can supply, never an error."""
    if not cve_ids or not threat_intel_enabled():
        return {}
    kev = kev_cve_ids()
    epss = epss_scores(cve_ids)
    return {cve: {"kev": cve in kev, "epss": epss.get(cve)} for cve in cve_ids}
