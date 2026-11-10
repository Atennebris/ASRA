"""Live threat-intelligence enrichment for playbook techniques: CISA KEV (Known Exploited
Vulnerabilities) + FIRST.org EPSS (Exploit Prediction Scoring System) + CVE Program cvelistV5
(description/CVSS/affected products) + poc-in-github (public PoC-repo availability). Ties a
technique's CVEs to what's ACTUALLY being exploited in the wild right now, what it actually IS
(not just an id), and whether exploit code is already public -- so the agent prioritizes
proven-and-hot over theoretical, and has real context on hand instead of a bare CVE id.

Everything here is best-effort and offline-tolerant: feeds are fetched once and cached to the global
app dir with a TTL; a fetch failure (no network, a feed down) falls back to whatever's cached, or to
"unknown" (never an exception into the caller). The fetch functions are the only network touch and
are deliberately isolated so tests can mock them.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.request

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("PLAYBOOK")

_KEV_CACHE_PATH = resolve_global_app_dir() / "data" / "playbook" / "kev_cache.json"
_EPSS_CACHE_PATH = resolve_global_app_dir() / "data" / "playbook" / "epss_cache.json"
_CVE_METADATA_CACHE_PATH = resolve_global_app_dir() / "data" / "playbook" / "cve_metadata_cache.json"
_POC_CACHE_PATH = resolve_global_app_dir() / "data" / "playbook" / "poc_cache.json"

_KEV_FEED_URL = os.getenv("THREAT_INTEL_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
_EPSS_API_URL = os.getenv("THREAT_INTEL_EPSS_URL", "https://api.first.org/data/v1/epss")
# The CVE Program's own record repo, raw-fetched one file per CVE (no clone -- the full repo is
# several GB). This is the same source SploitScan itself switched to in its v0.9 after hitting
# NVD's API rate limits -- confirmed against the live repo: cves/<year>/<N>xxx/CVE-<year>-<n>.json,
# <N>xxx being the CVE number's thousands bucket (e.g. CVE-2024-1709 -> cves/2024/1xxx/...).
_CVELISTV5_RAW_BASE = os.getenv("THREAT_INTEL_CVELISTV5_BASE_URL", "https://raw.githubusercontent.com/CVEProject/cvelistV5/main")
# Unofficial, alpha-quality mirror of nomi-sec/PoC-in-GitHub -- "does a public PoC repo exist for
# this CVE" is a real lead for the exploit phase, but no auth/rate-limit policy is documented and a
# live check turned up plenty of near-duplicate, zero-star, non-PoC noise alongside real hits.
_POC_API_URL = os.getenv("THREAT_INTEL_POC_URL", "https://poc-in-github.motikan2010.net/api/v1/")

_CVE_ID_PATTERN = re.compile(r"^CVE-(\d{4})-(\d+)$", re.IGNORECASE)


def _ttl_seconds() -> int:
    """How long cached feed data stays fresh before a re-fetch is attempted. 0 disables network
    entirely (cache-only) -- useful for a fully offline run."""
    return int(os.getenv("THREAT_INTEL_TTL_SECONDS", "86400"))


def _fetch_timeout() -> float:
    return float(os.getenv("THREAT_INTEL_FETCH_TIMEOUT_SECONDS", "8"))


def threat_intel_enabled() -> bool:
    return os.getenv("THREAT_INTEL_ENABLED", "true").strip().lower() == "true"


def threat_intel_poc_lookup_enabled() -> bool:
    """Separate from threat_intel_enabled(): poc-in-github is a third-party, undocumented-rate-limit
    "alpha" source whose hits need a manual look (never treat a hit as proof of a working exploit) --
    lets an operator turn off just this noisier signal without losing KEV/EPSS/CVE-metadata too."""
    return os.getenv("THREAT_INTEL_POC_LOOKUP_ENABLED", "true").strip().lower() == "true"


def _poc_result_limit() -> int:
    return int(os.getenv("THREAT_INTEL_POC_RESULT_LIMIT", "5"))


def _safe_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


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


def _cvelistv5_path(cve_id: str) -> str | None:
    """CVE id -> its path inside the cvelistV5 repo, or None if cve_id doesn't even look like a
    real CVE id (never raises -- a caller handing in garbage just gets skipped)."""
    match = _CVE_ID_PATTERN.match(cve_id.strip())
    if not match:
        return None
    year, number = match.group(1), match.group(2)
    bucket = f"{int(number) // 1000}xxx"
    return f"cves/{year}/{bucket}/CVE-{year}-{number}.json"


def _first_cvss_from_metrics(metrics: list) -> tuple:
    """A record can carry several CVSS versions (v2/v3.0/v3.1/v4.0) as separate metrics entries --
    the first one found wins; which version that is varies per CVE and isn't worth picking over."""
    for metric in metrics or []:
        for key, value in metric.items():
            if key.lower().startswith("cvssv") and isinstance(value, dict):
                return value.get("baseScore"), value.get("vectorString"), value.get("baseSeverity")
    return None, None, None


def _extract_cve_metadata(record: dict) -> dict:
    """Pulls the fields an operator/agent actually act on (description, CVSS, affected products,
    references) out of a CVE JSON 5.x record. Everything CNA-submitted lives under
    containers.cna -- there's no flat top-level shortcut for any of it.

    CVSS falls back from the CNA's own submission to containers.adp (CISA's "Vulnrichment"
    enrichment) when the CNA didn't submit a structured score -- confirmed live against a real
    record: CVE-2021-41773's Apache-submitted CNA entry only has a free-text "critical" severity
    string, no cvssV3_1 block at all, while CISA's own ADP container for that same CVE (a KEV
    entry, so plausibly one CISA specifically backfilled) carries a real CVSSv3.1 7.5/HIGH score.
    Skipping ADP would silently lose CVSS for exactly the older, under-scored CVEs most likely to
    matter."""
    containers = (record or {}).get("containers") or {}
    cna = containers.get("cna") or {}
    description = next(
        (d.get("value") for d in (cna.get("descriptions") or []) if d.get("lang") == "en" and d.get("value")),
        None,
    )
    cvss_score, cvss_vector, severity = _first_cvss_from_metrics(cna.get("metrics"))
    if cvss_score is None:
        for adp_entry in containers.get("adp") or []:
            cvss_score, cvss_vector, severity = _first_cvss_from_metrics(adp_entry.get("metrics"))
            if cvss_score is not None:
                break
    affected = [
        {"vendor": a.get("vendor"), "product": a.get("product")}
        for a in (cna.get("affected") or [])
        if a.get("vendor") or a.get("product")
    ]
    references = [r.get("url") for r in (cna.get("references") or []) if r.get("url")]
    return {
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "affected": affected[:10],
        "references": references[:10],
    }


def cve_metadata(cve_ids: list[str]) -> dict[str, dict]:
    """Description + CVSS + affected products for each CVE, from the CVE Program's own cvelistV5
    repo -- real content about what the CVE actually IS, not just whether it's hot (that's KEV/
    EPSS's job). Unlike KEV/EPSS there's no batch endpoint here, so this is one raw-file fetch per
    CVE -- slower on a cold cache, but the per-CVE TTL cache below (same pattern as epss_scores)
    makes every refresh after the first one fast and still offline-tolerant. A fetch failure for one
    CVE just leaves it out of the result (and out of the cache, so it's retried next time) -- never
    an exception, never a cached false negative."""
    if not cve_ids:
        return {}
    cache = _load_cache(_CVE_METADATA_CACHE_PATH)
    now = time.time()
    out: dict[str, dict] = {}
    to_fetch: list[str] = []
    for cve in cve_ids:
        entry = cache.get(cve)
        if entry and entry.get("fetched_at", 0) + _ttl_seconds() > now:
            out[cve] = entry["data"]
        elif _ttl_seconds() == 0:
            if entry:
                out[cve] = entry["data"]
        else:
            to_fetch.append(cve)
    fetched = 0
    for cve in to_fetch:
        path = _cvelistv5_path(cve)
        if not path:
            continue
        record = _http_get_json(f"{_CVELISTV5_RAW_BASE}/{path}")
        if record is None:
            continue  # fetch failed -- leave uncached, retried on the next refresh
        data = _extract_cve_metadata(record)
        out[cve] = data
        cache[cve] = {"data": data, "fetched_at": int(now)}
        fetched += 1
    if fetched:
        _save_cache(_CVE_METADATA_CACHE_PATH, cache)
        logger.debug("threat_intel: refreshed CVE metadata for %d CVE(s)", fetched)
    return out


def poc_availability(cve_ids: list[str]) -> dict[str, list[dict]]:
    """Public GitHub repos referencing each CVE (poc-in-github.motikan2010.net, an unofficial
    mirror of nomi-sec/PoC-in-GitHub). A THIRD signal, distinct from KEV (confirmed exploited in
    the wild) and EPSS (statistical probability): whether exploit CODE is already public -- a real
    lead for the exploit phase, never proof it works (confirmed live: a popular CVE's results
    included plenty of near-duplicate, zero-star, non-PoC repos alongside real ones -- always worth
    a manual look before trusting one). Gated by its own threat_intel_poc_lookup_enabled(), separate
    from KEV/EPSS/CVE-metadata, for exactly that noise reason. Capped to the top
    THREAT_INTEL_POC_RESULT_LIMIT repos by star count; empty (not missing) means a real "no hits",
    same fetch-failure handling as cve_metadata."""
    if not cve_ids or not threat_intel_poc_lookup_enabled():
        return {}
    cache = _load_cache(_POC_CACHE_PATH)
    now = time.time()
    out: dict[str, list[dict]] = {}
    to_fetch: list[str] = []
    for cve in cve_ids:
        entry = cache.get(cve)
        if entry and entry.get("fetched_at", 0) + _ttl_seconds() > now:
            out[cve] = entry["repos"]
        elif _ttl_seconds() == 0:
            if entry:
                out[cve] = entry["repos"]
        else:
            to_fetch.append(cve)
    fetched = 0
    limit = _poc_result_limit()
    for cve in to_fetch:
        data = _http_get_json(f"{_POC_API_URL}?cve_id={cve.lower()}")
        if data is None or not isinstance(data.get("pocs"), list):
            continue  # fetch failed -- leave uncached, retried on the next refresh
        repos = []
        for poc in data["pocs"]:
            full_name = poc.get("full_name")
            if not full_name:
                continue
            repos.append({
                "repo": full_name,
                "url": poc.get("html_url"),
                "stars": _safe_int(poc.get("stargazers_count")),
            })
        repos.sort(key=lambda r: r["stars"], reverse=True)
        repos = repos[:limit]
        out[cve] = repos
        cache[cve] = {"repos": repos, "fetched_at": int(now)}
        fetched += 1
    if fetched:
        _save_cache(_POC_CACHE_PATH, cache)
        logger.debug("threat_intel: refreshed PoC availability for %d CVE(s)", fetched)
    return out


def enrich_cves(cve_ids: list[str]) -> dict[str, dict]:
    """Per-CVE {"kev": bool, "epss": float|None} for a technique's CVEs -- the shape the UI and the
    addendum both read. Best-effort: whatever the caches/feeds can supply, never an error."""
    if not cve_ids or not threat_intel_enabled():
        return {}
    kev = kev_cve_ids()
    epss = epss_scores(cve_ids)
    return {cve: {"kev": cve in kev, "epss": epss.get(cve)} for cve in cve_ids}
