"""Persistent, cross-session store of confirmed exploitation techniques, keyed by a target
fingerprint (WAF vendor + technology keywords) -- the "accumulating edge" mechanism: a technique
proven against one target's stack gets surfaced as a lead the next time a similarly fingerprinted
stack shows up, instead of every session rediscovering the same bypass from scratch. Same on-disk
convention as agent/tools/wordlist_store.py (load/_write pair, atomic tmp-file + os.replace,
empty/corrupt file treated as "nothing stored yet" rather than an error) -- app-level state that
spans every session/project, not tied to one session_id the way credentials/oob_sessions are.

Shape: {fingerprint_key: [entry, ...]}. fingerprint_key is a deterministic JSON string built by
agent/core.py's _finding_fingerprint (sorted tech_keywords + sorted waf_vendors) -- this module
treats it as an opaque string, it doesn't know how it was built.
"""
from __future__ import annotations

import json
import math
import os
import re
import uuid
from datetime import datetime, timezone

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# A payload template is a proven payload with its target-specific bits lifted out into {{placeholder}}
# slots (e.g. {{target}}, {{param}}, {{host}}), so it drops straight onto the next similar target.
_TEMPLATE_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def render_payload_template(template: str, values: dict) -> str:
    """Fills a technique's {{placeholder}} slots from `values`; leaves any slot with no supplied value
    intact (so a half-filled template still shows the operator exactly what's missing). Empty in ->
    empty out."""
    if not template:
        return ""
    return _TEMPLATE_VAR_RE.sub(lambda m: str(values.get(m.group(1), m.group(0))), template)

logger = get_logger("PLAYBOOK")

# Global app data (Documents/ASRA/data, see projects/paths.py) -- real exploitation
# techniques/payloads confirmed against real bug-bounty/pentest targets, no business living
# inside the git checkout's own data/ folder.
PLAYBOOK_STORE_PATH = resolve_global_app_dir() / "data" / "playbook" / "techniques.json"
# Semantic-search vectors live in their OWN file, keyed by technique id, so the main techniques.json
# stays small/human-readable instead of carrying a ~1.5KB float array per entry. Shape:
# {"_model": "<embedding model>", "<id>": [floats], ...}. The model is stamped so a later model
# change can invalidate cleanly (a vector embedded with model A can't be compared to a query
# embedded with model B).
PLAYBOOK_EMBEDDINGS_PATH = resolve_global_app_dir() / "data" / "playbook" / "embeddings.json"
# How much a perfect semantic match (cosine 1.0) is worth relative to the keyword score (whose strong
# matches land around 5-8) -- high enough that a genuine meaning-match surfaces a technique the
# keywords miss, not so high it drowns an exact-stack keyword hit.
_SEMANTIC_WEIGHT = 4.0


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def load_embeddings() -> dict:
    if not PLAYBOOK_EMBEDDINGS_PATH.exists():
        return {}
    try:
        with PLAYBOOK_EMBEDDINGS_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("playbook embeddings.json unreadable (%s) -- treating as none stored", exc)
        return {}


def _write_embeddings(data: dict) -> None:
    PLAYBOOK_EMBEDDINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = PLAYBOOK_EMBEDDINGS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp_path, PLAYBOOK_EMBEDDINGS_PATH)


def store_embeddings(vectors: dict[str, list[float]], model: str) -> None:
    """Merges id->vector pairs into the embeddings file under the given model. If the stored model
    differs from `model`, the old vectors are dropped first (they can't be compared to queries
    embedded with a different model) -- a clean re-embed on a model switch, never a silent mix."""
    if not vectors:
        return
    data = load_embeddings()
    if data.get("_model") not in (None, model):
        logger.debug("playbook: embedding model changed %r -> %r, dropping stale vectors", data.get("_model"), model)
        data = {}
    data["_model"] = model
    for tid, vec in vectors.items():
        data[tid] = vec
    _write_embeddings(data)
    logger.debug("playbook: stored %d embedding vector(s) under model=%s", len(vectors), model)


def embedding_model() -> str:
    """The embedding model name -- the ONE place it's resolved, shared by the provider's embed()
    call and the vector store's model stamp so they can never drift. Env-overridable; the connection
    is always the active provider's (agent/core.py / agent/chat.py), only the model is defaulted."""
    return os.getenv("PLAYBOOK_EMBEDDING_MODEL", "text-embedding-3-small")


def build_embedding_text(entry: dict) -> str:
    """The text a technique is embedded from -- its own description plus the payload, vuln class and
    stack tokens, so a semantic query matches on the whole meaning, not just the title."""
    parts = [
        str(entry.get("technique") or ""),
        str(entry.get("vuln_class") or ""),
        str(entry.get("payload_or_command") or ""),
        " ".join(entry.get("tech_keywords") or []),
        " ".join(entry.get("waf_vendors") or []),
    ]
    return " ".join(p for p in parts if p).strip()


def embeddings_count() -> int:
    """How many technique vectors are stored (excludes the _model marker) -- the Playbook UI shows
    this over the total so the operator can see whether semantic search is actually active."""
    return sum(1 for k in load_embeddings() if k != "_model")


def technique_ids_missing_embeddings() -> list[str]:
    """Ids of stored techniques that have no vector yet -- used to backfill (main.py's re-embed
    action) so legacy/imported entries become semantically searchable too."""
    have = set(load_embeddings().keys())
    return [
        e.get("id") for entries in load_playbook_store().values() for e in entries
        if e.get("id") and e.get("id") not in have
    ]


def load_playbook_store() -> dict:
    if not PLAYBOOK_STORE_PATH.exists():
        return {}

    try:
        with PLAYBOOK_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("techniques.json unreadable (%s) — treating as empty store", exc)
        return {}

    if not isinstance(data, dict):
        logger.debug("techniques.json does not contain an object — treating as empty store")
        return {}

    return {
        key: entries for key, entries in data.items()
        if isinstance(key, str) and isinstance(entries, list)
    }


def _write_playbook_store(store: dict) -> None:
    PLAYBOOK_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = PLAYBOOK_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, PLAYBOOK_STORE_PATH)


def extract_cves(*texts: str) -> list[str]:
    """CVE ids mentioned anywhere in the given text(s), upper-cased and deduped (order-stable) --
    lets a captured/added technique auto-carry the CVEs its description names, no manual entry
    needed, so threat-intel enrichment has something to key on."""
    seen: list[str] = []
    for text in texts:
        for m in _CVE_RE.findall(text or ""):
            cid = m.upper()
            if cid not in seen:
                seen.append(cid)
    return seen


def refresh_threat_intel() -> int:
    """Enriches every technique that names CVEs with live KEV/EPSS signals and STAMPS the result onto
    the entry (kev: bool, epss_max: float) so scoring + the addendum can read it without any network
    at search time. Network happens only here (the explicit refresh action), behind threat_intel's
    own TTL cache. Returns how many techniques were updated."""
    from agent.tools import threat_intel
    if not threat_intel.threat_intel_enabled():
        return 0
    store = load_playbook_store()
    all_cves = sorted({c for entries in store.values() for e in entries for c in (e.get("cves") or [])})
    if not all_cves:
        return 0
    enriched = threat_intel.enrich_cves(all_cves)
    updated = 0
    for entries in store.values():
        for entry in entries:
            cves = entry.get("cves") or []
            if not cves:
                continue
            kev = any(enriched.get(c, {}).get("kev") for c in cves)
            epss_values = [enriched.get(c, {}).get("epss") for c in cves if enriched.get(c, {}).get("epss") is not None]
            epss_max = max(epss_values) if epss_values else None
            if entry.get("kev") != kev or entry.get("epss_max") != epss_max:
                entry["kev"] = kev
                entry["epss_max"] = epss_max
                updated += 1
    if updated:
        _write_playbook_store(store)
    logger.debug("playbook: threat-intel refresh stamped %d technique(s)", updated)
    return updated


def count_techniques() -> int:
    """Total number of stored technique entries across every fingerprint key -- the running "how
    many are in the playbook" number the chat's storage-reward notifications show (agent/chat.py /
    agent/core.py). Cheap enough to recompute on each capture: the store is small operator-curated
    knowledge, not a high-write log."""
    return sum(len(entries) for entries in load_playbook_store().values())


def record_technique(fingerprint_key: str, entry: dict) -> str | None:
    """Appends entry under fingerprint_key, or -- if an existing entry under that same key has the
    identical technique text already -- bumps that entry's times_confirmed/last_seen/
    source_session_ids instead of piling up a near-duplicate. This dedup runs on every deterministic
    write (not just the periodic LLM distillation pass) so the store stays reasonably clean even for
    an operator who disables PLAYBOOK_DISTILL_ENABLED entirely.

    Returns the id of the entry that now represents this technique (the existing one on a dedup, the
    new one otherwise) -- callers use it to build kill-chain links (chained_from_ids): a technique
    recorded right after another one in the same session records the previous entry's id as its
    predecessor.
    """
    store = load_playbook_store()
    entries = store.setdefault(fingerprint_key, [])
    existing = next(
        (e for e in entries if str(e.get("technique", "")).strip().lower() == str(entry.get("technique", "")).strip().lower()),
        None,
    )
    if existing is not None:
        existing["times_confirmed"] = int(existing.get("times_confirmed", 1)) + 1
        existing["last_seen"] = entry.get("last_seen") or datetime.now(timezone.utc).isoformat()
        # Re-confirming a working technique refreshes its staleness clock (it still works TODAY).
        if existing.get("outcome") != "failed" and entry.get("last_confirmed_at"):
            existing["last_confirmed_at"] = entry["last_confirmed_at"]
        source_sessions = existing.setdefault("source_session_ids", [])
        for session_id in entry.get("source_session_ids") or []:
            if session_id not in source_sessions:
                source_sessions.append(session_id)
        # Automatic review: a real field capture (source_type="live" -- an actually-exploited
        # finding or an operator-vouched chat/manual entry) landing on the exact same technique
        # text as a still-unreviewed library-extracted one IS the proof that was missing --
        # flips it to "confirmed" without waiting on a manual click. Never flips the other
        # direction (a later extracted match never demotes an already-confirmed entry).
        if existing.get("confidence") == "unreviewed" and entry.get("source_type") == "live":
            existing["confidence"] = "confirmed"
            logger.debug("record_technique: auto-confirmed previously-unreviewed entry id=%s via live capture", existing.get("id"))
        logger.debug("record_technique: bumped existing entry under key=%r (times_confirmed=%d)", fingerprint_key, existing["times_confirmed"])
        _write_playbook_store(store)
        return existing.get("id")
    entries.append(entry)
    logger.debug("record_technique: new entry under key=%r technique=%r", fingerprint_key, entry.get("technique"))
    _write_playbook_store(store)
    return entry.get("id")


def _chain_ordered(by_id: dict[str, dict], technique_id: str) -> list[dict]:
    """Walks chained_from_ids backward from technique_id to the chain's root, returning the ordered
    [root, ..., technique_id] entry list -- the full multi-step recipe that produced this technique.
    Follows the first predecessor (auto-chaining records a single predecessor, so chains are linear)
    and is cycle-safe via a visited set (a hand-imported/edited store could carry a loop)."""
    stack: list[dict] = []
    seen: set[str] = set()
    cur = by_id.get(technique_id)
    while cur is not None and cur.get("id") not in seen:
        seen.add(cur.get("id"))
        stack.append(cur)
        preds = cur.get("chained_from_ids") or []
        cur = by_id.get(preds[0]) if preds else None
    return list(reversed(stack))


def get_technique_chains(technique_ids: list[str]) -> dict[str, list[dict]]:
    """Full recipe chains for several techniques at once, in ONE store load -- the addendum
    (agent/core.py) reconstructs the multi-step kill-chain behind each surfaced technique with this."""
    if not technique_ids:
        return {}
    by_id = {e.get("id"): e for entries in load_playbook_store().values() for e in entries}
    return {tid: _chain_ordered(by_id, tid) for tid in technique_ids}


def resolve_technique_texts(technique_ids: set[str]) -> dict[str, str]:
    """Maps technique ids to their short technique text -- used to render kill-chain links
    (chained_from_ids) as readable "chains from: <prev technique>" lines in the addendum
    (agent/core.py) instead of opaque ids. Unknown ids are simply absent from the result."""
    if not technique_ids:
        return {}
    out: dict[str, str] = {}
    for entries in load_playbook_store().values():
        for entry in entries:
            eid = entry.get("id")
            if eid in technique_ids:
                out[eid] = str(entry.get("technique", ""))
    return out


def replace_technique_entries(fingerprint_key: str, entries: list[dict]) -> None:
    """Overwrites the entry list under fingerprint_key wholesale -- used by agent/core.py's
    periodic LLM distillation pass after it merges near-duplicate entries, unlike record_technique
    (which only ever appends or bumps one entry at a time). An empty entries list removes the key
    entirely rather than leaving a dangling empty list around.
    """
    store = load_playbook_store()
    if entries:
        store[fingerprint_key] = entries
    else:
        store.pop(fingerprint_key, None)
    _write_playbook_store(store)
    logger.debug("replace_technique_entries: key=%r now has %d entry(ies)", fingerprint_key, len(entries))


def _decay_halflife_days() -> float:
    """Confidence half-life in days: a technique's "how proven" weight halves every this-many days
    since it last worked (WAF bypasses rot fast). 0 disables decay."""
    return float(os.getenv("PLAYBOOK_DECAY_HALFLIFE_DAYS", "365"))


def _stale_days() -> int:
    """A worked technique not confirmed in this many days is flagged 'stale — re-verify'. 0 disables."""
    return int(os.getenv("PLAYBOOK_STALE_DAYS", "180"))


def _age_days(entry: dict) -> float | None:
    ts = entry.get("last_confirmed_at") or entry.get("last_seen")
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(str(ts))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0)


def _staleness_decay(entry: dict) -> float:
    """Multiplier (0.2..1.0) on the confidence part of the score -- older = lower, floored at 0.2 so a
    proven-but-old technique still ranks above an untested one. Relevance (keyword/semantic) and
    exploitability (KEV/EPSS) are NOT decayed -- those don't rot the way "did it still work" does."""
    hl = _decay_halflife_days()
    if hl <= 0:
        return 1.0
    age = _age_days(entry)
    if age is None:
        return 1.0
    return max(0.2, 0.5 ** (age / hl))


def is_stale(entry: dict) -> bool:
    """A worked technique whose last confirmation is older than PLAYBOOK_STALE_DAYS -- surfaced with a
    'stale, re-verify' flag (dead-ends never go stale; a confirmed dead-end stays a dead-end)."""
    sd = _stale_days()
    if sd <= 0 or entry.get("outcome") == "failed":
        return False
    age = _age_days(entry)
    return age is not None and age > sd


def _confidence_score(entry: dict) -> float:
    """How proven a technique is, on its own, independent of any particular target: times_confirmed,
    how many DISTINCT sessions/targets proved it (far stronger than the same one confirmed N times),
    the real success_rate from attribution (led_to_finding / injected) once that data exists, decayed
    by staleness (WAF bypasses rot -- only this "how proven" part decays), then boosted if
    threat-intel (KEV/EPSS, stamped by refresh_threat_intel, no network here) says it's actively
    exploited in the wild. Shared by _relevance_score (search ranking against a query target) and
    technique_rank (the playbook UI's absolute, query-independent rank tier) so "how good is this
    technique" is computed exactly once."""
    times = int(entry.get("times_confirmed", 1) or 1)
    distinct_targets = len(entry.get("source_session_ids") or []) or 1
    injected = int(entry.get("injected_count", 0) or 0)
    led = int(entry.get("led_to_finding_count", 0) or 0)
    success_rate = (led / injected) if injected > 0 else 0.0
    confidence = min(times, 10) * 0.1 + min(distinct_targets, 10) * 0.15 + success_rate * 1.0
    confidence *= _staleness_decay(entry)
    if entry.get("kev"):
        confidence += 1.5
    epss_max = entry.get("epss_max")
    if isinstance(epss_max, (int, float)):
        confidence += float(epss_max)
    return confidence


def _relevance_score(
    query_tech: set[str], query_waf: set[str], query_vuln_class: str | None,
    key_tech: set[str], key_waf: set[str], entry: dict,
) -> float:
    """Weighted similarity of one stored entry to the current target (0.0 == not a candidate).
    Replaces the old "overlap COUNT, exact key first" ranking, which surfaced too little: an entry
    keyed to "cloudflare+php+wordpress" never matched a "cloudflare+php" target at all unless the
    keyword sets overlapped by raw count in the right way, and a WAF-bypass proven on the exact same
    WAF but a different CMS ranked no higher than an unrelated tech match.

    Dimensions, most decisive first:
    - keyword Jaccard (|A n B| / |A u B|) -- partial-stack similarity, the backbone. Zero overlap
      means not a candidate at all (returns 0.0), same "must share some tech" floor as before.
    - WAF vendor match -- a WAF bypass is the single most reusable cross-target knowledge, so a
      shared WAF vendor is a strong, near-keyword-weight boost even when the CMS/language differs.
    - vulnerability-class match -- lets "how I got XSS past this stack" rank up when the current
      work is also about XSS, not just when the tech tokens line up.
    - confidence (_confidence_score) -- all bounded so a popular-but-generic entry can't drown out a
      precise stack match.
    """
    union = query_tech | key_tech
    jaccard = len(query_tech & key_tech) / len(union) if union else 0.0
    if jaccard == 0.0:
        return 0.0

    score = jaccard * 3.0
    if query_waf and key_waf and (query_waf & key_waf):
        score += 2.0
    if query_vuln_class and entry.get("vuln_class") and str(entry["vuln_class"]).lower() == query_vuln_class.lower():
        score += 1.5
    score += _confidence_score(entry)
    return score


# Weak-to-legendary rank tiers, ordered ascending -- the playbook UI's colored rank badge/filter/sort.
# Score thresholds are calibrated off _confidence_score's own range: a freshly-added, once-confirmed
# entry lands at ~0.25 (Bronze); a technique confirmed 10x across 10 distinct targets with a perfect
# attributed success rate tops out at 3.5 (times*0.1 capped 1.0 + targets*0.15 capped 1.5 +
# success_rate*1.0) with NO threat-intel needed -- Legendary's 3.0 threshold sits comfortably below
# that ceiling, not AT it, so a technique confirmed only microseconds ago (real, nonzero staleness
# decay even then) still clears it instead of being knocked down a tier by floating-point noise.
# Legendary is earned by real cross-target proof, not gated behind having a CVE -- KEV/EPSS just
# gets there faster. Dead-ends (outcome == "failed") are never ranked: a confirmed dead-end isn't
# "weak", it's a different kind of knowledge (see is_stale's same distinction), so technique_rank
# returns None for them.
RANK_TIERS: list[tuple[str, float]] = [
    ("bronze", 0.0),
    ("silver", 0.5),
    ("gold", 1.2),
    ("platinum", 2.0),
    ("legendary", 3.0),
]
RANK_ORDER: list[str] = [name for name, _ in RANK_TIERS]


def technique_rank(entry: dict) -> str | None:
    """The rank tier name ('bronze'..'legendary') for a worked technique, or None for a dead-end
    (outcome == 'failed'), which isn't ranked on the weak-to-legendary scale at all."""
    if entry.get("outcome") == "failed":
        return None
    score = _confidence_score(entry)
    rank = RANK_TIERS[0][0]
    for name, threshold in RANK_TIERS:
        if score >= threshold:
            rank = name
        else:
            break
    return rank


_EDITABLE_TECHNIQUE_FIELDS = ("technique", "payload_or_command", "vuln_class", "outcome")


def make_fingerprint_key(tech_keywords, waf_vendors) -> str:
    """The canonical fingerprint key for a (tech, waf) pair -- the single source of truth for how an
    entry is keyed, so the manager's re-key path (update_technique) and agent/core.py's own
    _playbook_fingerprint_key stay byte-for-byte identical (sorted, deduped, order-independent)."""
    return json.dumps({"tech": sorted(set(tech_keywords)), "waf": sorted(set(waf_vendors))}, sort_keys=True)


def _seed_entry(eid: str, tech: list[str], waf: list[str], technique: str, vuln_class: str, payload: str = "") -> tuple[str, dict]:
    key = json.dumps({"tech": sorted(tech), "waf": sorted(waf)}, sort_keys=True)
    return key, {
        "id": eid, "technique": technique, "vuln_class": vuln_class, "payload_or_command": payload or None,
        "evidence_ref": "", "tech_keywords": sorted(tech), "waf_vendors": sorted(waf), "outcome": "worked",
        "times_confirmed": 1, "injected_count": 0, "led_to_finding_count": 0, "chained_from_ids": [],
        "last_seen": "", "source_session_ids": ["seed"],
    }


def _build_seed_pack() -> dict:
    """A small starter set of well-known, PUBLIC, target-agnostic WAF/CDN-bypass patterns an operator
    can one-click import to prime an empty playbook (main.py's seed route). Deliberately generic
    leads-to-check, not target-specific exploits -- the real accumulating edge still comes from the
    operator's own confirmed captures. Stable ids so re-importing dedups instead of duplicating."""
    pack: dict = {}
    for key, entry in [
        _seed_entry("seed_cf_origin", [], ["cloudflare"], "Recover the origin IP behind Cloudflare via historical/stale DNS records, forgotten subdomains, or SSL-cert transparency logs, then hit the origin directly to bypass the CDN/WAF entirely.", "waf_bypass"),
        _seed_entry("seed_hpp", [], [], "HTTP Parameter Pollution: send the same parameter twice; some WAFs inspect the first occurrence while the app uses the last (or vice versa), letting a clean value hide a payload.", "waf_bypass", "?id=1&id=1'--"),
        _seed_entry("seed_mixed_encoding", [], [], "Mixed / double URL-encoding of injection payloads (e.g. %2527 for a quote): the WAF normalizes once and sees benign input, the app decodes again and executes it.", "waf_bypass", "%2527%2520OR%25201%3D1"),
        _seed_entry("seed_ct_swap", [], [], "Content-Type swap: resend a blocked form/body as application/json (or vice versa); WAF rules scoped to one content type often don't inspect the other.", "waf_bypass"),
        _seed_entry("seed_sqli_comment", ["mysql"], [], "SQLi WAF evasion via inline comments + case variation (e.g. /*!50000UNION*/ /*!SELECT*/) to break signature matching on keyword patterns.", "sqli", "/*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- -"),
    ]:
        pack.setdefault(key, []).append(entry)
    return pack


def import_seed_pack() -> int:
    return import_entries(_build_seed_pack(), source_label="seed")


def add_manual_technique(technique: str, payload_or_command: str = "", tech_keywords: list[str] | None = None,
                         waf_vendors: list[str] | None = None, vuln_class: str = "", worked: bool = True,
                         cves: str = "") -> str | None:
    """Builds and records a single operator-authored technique -- the Playbook manager's own "add"
    action (main.py). Same entry shape (attribution counters, chain refs, keying) as an
    agent/chat-captured one, so a hand-added technique ranks and surfaces exactly like the rest.
    Returns the new entry's id, or None if the technique text was empty."""
    technique = (technique or "").strip()
    if not technique:
        return None
    tech = sorted({str(t).strip().lower() for t in (tech_keywords or []) if str(t).strip()})
    waf = sorted({str(w).strip().lower() for w in (waf_vendors or []) if str(w).strip()})
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": uuid.uuid4().hex[:12],
        "technique": technique,
        "vuln_class": (vuln_class or "").strip() or None,
        "payload_or_command": (payload_or_command or "").strip() or None,
        # Auto-extracted from the text PLUS any the operator typed explicitly.
        "cves": extract_cves(technique, payload_or_command or "", cves or ""),
        "evidence_ref": "",
        "tech_keywords": tech,
        "waf_vendors": waf,
        "outcome": "worked" if worked else "failed",
        "times_confirmed": 1,
        "injected_count": 0,
        "led_to_finding_count": 0,
        "chained_from_ids": [],
        "last_seen": now,
        "last_confirmed_at": now if worked else None,
        "source_session_ids": ["manual"],
        # An operator typing this in by hand IS a human vouching for it -- same standing as a
        # live-captured finding, distinct from an LLM's own unreviewed guess at what a book says.
        "source_type": "live",
        "confidence": "confirmed",
    }
    record_technique(make_fingerprint_key(tech, waf), entry)
    logger.debug("playbook: manually added technique id=%s outcome=%s", entry["id"], entry["outcome"])
    return entry["id"]


def seed_pack_imported() -> bool:
    """Whether the built-in seed pack is already present (any of its stable ids in the store) -- lets
    the manager UI (main.py) tell the operator the pack is optional and, once imported, not re-offer
    it as if the playbook were empty."""
    seed_ids = {e.get("id") for entries in _build_seed_pack().values() for e in entries}
    store_ids = {e.get("id") for entries in load_playbook_store().values() for e in entries}
    return bool(seed_ids & store_ids)


def list_all_techniques() -> list[dict]:
    """Every stored technique flattened across all fingerprint keys, each annotated with its own key
    (`_key`) and a derived `success_rate` -- the Playbook manager UI (main.py) reads this. Newest
    first. A read-only view: edits/deletes go through update_technique/delete_technique by id."""
    store = load_playbook_store()
    by_id = {e.get("id"): e for entries in store.values() for e in entries}
    out: list[dict] = []
    for key, entries in store.items():
        for entry in entries:
            injected = int(entry.get("injected_count", 0) or 0)
            led = int(entry.get("led_to_finding_count", 0) or 0)
            # The full recipe chain (root-first technique texts) when this entry is part of one --
            # the manager renders it as a "Recipe" block. length 1 == no predecessors, so no recipe.
            chain = _chain_ordered(by_id, entry.get("id")) if entry.get("chained_from_ids") else []
            out.append({
                **entry,
                "_key": key,
                "success_rate": (led / injected) if injected > 0 else None,
                "distinct_targets": len(entry.get("source_session_ids") or []),
                "chain": [c.get("technique") for c in chain] if len(chain) > 1 else [],
                "stale": is_stale(entry),
                "rank": technique_rank(entry),
                "rank_score": _confidence_score(entry),
                # Normalized here (not left to the template's own default() calls) so every
                # existing entry from before this field existed reads as "live/confirmed" --
                # the same thing it always implicitly was, never a silent behavior change.
                "source_type": entry.get("source_type") or "live",
                "confidence": entry.get("confidence") or "confirmed",
            })
    out.sort(key=lambda e: e.get("last_seen", ""), reverse=True)
    return out


def list_techniques_for_session(session_id: str) -> list[dict]:
    """Every playbook entry actually captured (or re-confirmed) during this one specific session --
    the per-project "what technique got applied here, with what evidence, when, and against what
    vuln class" view (session_fragment.html's own Techniques tab), as opposed to list_all_techniques'
    global, cross-session manager view. A session_id lands in an entry's source_session_ids either
    at the moment it's first captured (_maybe_capture_playbook_entry/re_record_technique) or later,
    if this same session re-confirms a technique another session captured first (record_technique's
    own dedup branch) -- either way it counts as "applied in this session". Newest first, same
    ordering as list_all_techniques."""
    if not session_id:
        return []
    return [e for e in list_all_techniques() if session_id in (e.get("source_session_ids") or [])]


def update_technique(technique_id: str, updates: dict, tech_keywords: list[str] | None = None, waf_vendors: list[str] | None = None, cves: list[str] | None = None) -> bool:
    """Edits an entry by id: the soft fields (technique text, payload, vuln_class, outcome) in place,
    plus -- when tech_keywords and/or waf_vendors are supplied and actually differ -- RE-KEYS it,
    moving the entry to the fingerprint key its new stack implies (dropping its old key if it becomes
    empty). Re-keying is a real move, not a delete+recreate: the entry keeps its own id and
    attribution history. Returns True if an entry was found and changed."""
    store = load_playbook_store()
    found_key = found_entry = None
    for key, entries in store.items():
        for entry in entries:
            if entry.get("id") == technique_id:
                found_key, found_entry = key, entry
                break
        if found_entry is not None:
            break
    if found_entry is None:
        return False

    for field in _EDITABLE_TECHNIQUE_FIELDS:
        if field in updates:
            found_entry[field] = updates[field]

    if cves is not None:
        # Editing CVEs clears any stamped KEV/EPSS so a stale flag from the old CVE set can't linger
        # until the next refresh-intel.
        found_entry["cves"] = extract_cves(*cves)
        found_entry.pop("kev", None)
        found_entry.pop("epss_max", None)

    if tech_keywords is not None or waf_vendors is not None:
        new_tech = tech_keywords if tech_keywords is not None else (found_entry.get("tech_keywords") or [])
        new_waf = waf_vendors if waf_vendors is not None else (found_entry.get("waf_vendors") or [])
        found_entry["tech_keywords"] = sorted(set(new_tech))
        found_entry["waf_vendors"] = sorted(set(new_waf))
        new_key = make_fingerprint_key(new_tech, new_waf)
        if new_key != found_key:
            store[found_key] = [e for e in store[found_key] if e.get("id") != technique_id]
            if not store[found_key]:
                del store[found_key]
            store.setdefault(new_key, []).append(found_entry)
            logger.debug("playbook: re-keyed entry id=%s from %r to %r", technique_id, found_key, new_key)

    _write_playbook_store(store)
    logger.debug("playbook: updated entry id=%s", technique_id)
    return True


def delete_technique(technique_id: str) -> bool:
    """Removes one entry by id (empties + drops its key if it was the last under it). Returns True if
    something was actually removed."""
    store = load_playbook_store()
    for key in list(store.keys()):
        before = len(store[key])
        store[key] = [e for e in store[key] if e.get("id") != technique_id]
        if len(store[key]) != before:
            if not store[key]:
                del store[key]
            _write_playbook_store(store)
            logger.debug("playbook: deleted entry id=%s", technique_id)
            return True
    return False


def mark_reviewed(technique_id: str, confirmed: bool) -> bool:
    """The manual half of reviewing a library-extracted entry (Playbook UI's own "Confirm"/
    "Reject" buttons on an unreviewed card) -- the other, automatic half lives in
    record_technique's own dedup branch above (a real field capture proving the same technique).
    confirmed=True flips confidence -> "confirmed" in place (same entry, same id, keeps its
    times_confirmed/source history). confirmed=False rejects it outright -- an operator-reviewed
    "no, this book's advice doesn't hold up" is a real verdict, not something to leave lingering
    as a still-technically-present but never-surfaced record, so this deletes it via
    delete_technique rather than inventing a third confidence state. Returns True if an entry was
    found and acted on."""
    if not confirmed:
        return delete_technique(technique_id)
    store = load_playbook_store()
    for entries in store.values():
        for entry in entries:
            if entry.get("id") == technique_id:
                entry["confidence"] = "confirmed"
                _write_playbook_store(store)
                logger.debug("playbook: manually reviewed+confirmed entry id=%s", technique_id)
                return True
    return False


def bulk_mark_reviewed(source_id: str, confirmed: bool) -> int:
    """Bulk counterpart to mark_reviewed -- the Playbook UI's own "Reviewing from X" banner
    (main.py's playbook_bulk_review), scoped to exactly one Library source's own still-unreviewed
    entries so it can never be mistaken for (or misused as) a global "confirm everything" action.
    One store load/write for the whole batch, not N of them (looping mark_reviewed would reload
    and rewrite the entire store once per entry). Same confirmed=True-flips-confidence,
    confirmed=False-deletes-outright semantics as the single-entry version. Returns how many
    entries were affected."""
    store = load_playbook_store()
    affected = 0
    for key in list(store.keys()):
        kept = []
        for entry in store[key]:
            if entry.get("source_id") == source_id and entry.get("confidence") == "unreviewed":
                affected += 1
                if confirmed:
                    entry["confidence"] = "confirmed"
                    kept.append(entry)
                # confirmed=False -- reject outright, same as mark_reviewed's own delete_technique
                # path; simply not re-appending it to `kept` removes it.
            else:
                kept.append(entry)
        store[key] = kept
    if affected:
        for key in list(store.keys()):
            if not store[key]:
                del store[key]
        _write_playbook_store(store)
        logger.debug("playbook: bulk review source=%s confirmed=%s affected=%d", source_id, confirmed, affected)
    return affected


def import_entries(incoming: dict, source_label: str = "import") -> int:
    """Merges an exported/seed playbook ({fingerprint_key: [entry, ...]}) into the store, appending
    entries not already present (dedup by id, then by identical technique text under the same key via
    record_technique). Returns how many were actually added. Malformed shapes are skipped, never
    raised -- an operator's own upload shouldn't be able to crash the app."""
    if not isinstance(incoming, dict):
        return 0
    existing_ids = {e.get("id") for entries in load_playbook_store().values() for e in entries}
    added = 0
    for key, entries in incoming.items():
        if not isinstance(key, str) or not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not str(entry.get("technique", "")).strip():
                continue
            if entry.get("id") in existing_ids:
                continue
            entry.setdefault("source_session_ids", [source_label])
            record_technique(key, entry)
            added += 1
    logger.debug("playbook: imported %d entr(y/ies) from %s", added, source_label)
    return added


def dedupe_all_techniques() -> int:
    """Manual cleanup for merging in someone else's playbook export (main.py's dedupe route) --
    import_entries/record_technique already dedup an incoming entry against an existing one that
    shares IDENTICAL technique text UNDER THE SAME fingerprint key, but two operators scanning the
    same target can still end up with the same confirmed technique keyed slightly differently (their
    sessions' own tech-keyword extraction isn't guaranteed byte-identical even for the same stack) --
    that case survives import untouched. This widens the exact-text-match rule from "within one key"
    to the WHOLE store: every entry sharing identical technique text (case/whitespace-normalized),
    regardless of which fingerprint key it lives under, is folded into one. "Leave the new one": the
    entry with the most recent last_confirmed_at/last_seen is kept (under its own original key), the
    rest are removed after their attribution (times_confirmed/injected_count/led_to_finding_count,
    source_session_ids) is folded into it -- same fields record_technique's own same-key bump
    already merges, just summed across more than one entry at once. Returns how many entries were
    removed. Entries with empty technique text are left alone (nothing to key a match on).
    """
    store = load_playbook_store()
    groups: dict[str, list[tuple[str, dict]]] = {}
    for key, entries in store.items():
        for entry in entries:
            norm = str(entry.get("technique", "")).strip().lower()
            if norm:
                groups.setdefault(norm, []).append((key, entry))

    removed = 0
    for occurrences in groups.values():
        if len(occurrences) < 2:
            continue
        occurrences.sort(key=lambda pair: pair[1].get("last_confirmed_at") or pair[1].get("last_seen") or "", reverse=True)
        _keep_key, keep_entry = occurrences[0]
        for key, entry in occurrences[1:]:
            if entry.get("id") == keep_entry.get("id"):
                continue
            keep_entry["times_confirmed"] = int(keep_entry.get("times_confirmed", 1) or 1) + int(entry.get("times_confirmed", 1) or 1)
            keep_entry["injected_count"] = int(keep_entry.get("injected_count", 0) or 0) + int(entry.get("injected_count", 0) or 0)
            keep_entry["led_to_finding_count"] = int(keep_entry.get("led_to_finding_count", 0) or 0) + int(entry.get("led_to_finding_count", 0) or 0)
            source_sessions = keep_entry.setdefault("source_session_ids", [])
            for sid in entry.get("source_session_ids") or []:
                if sid not in source_sessions:
                    source_sessions.append(sid)
            store[key] = [e for e in store[key] if e.get("id") != entry.get("id")]
            removed += 1

    if removed:
        for key in list(store.keys()):
            if not store[key]:
                del store[key]
        _write_playbook_store(store)
        logger.debug("playbook: dedupe_all_techniques removed %d duplicate entr(y/ies)", removed)
    return removed


def find_duplicate_groups() -> list[list[dict]]:
    """Read-only preview for the Playbook UI's own "Check duplicates" button (main.py) -- real,
    direct operator ask: the old button ran dedupe_all_techniques's own blind auto-merge-
    keep-newest straight on click, with nothing shown beforehand except a static confirm-dialog
    warning. This groups by the exact same rule (identical technique text, case/whitespace-
    normalized, regardless of fingerprint key) WITHOUT writing anything, so the operator can see
    every group and pick which copy to keep per group (merge_duplicate_group below) instead.
    Returns each duplicate group as a list of entries (only groups with 2+ members), newest-first
    within a group and groups themselves newest-first."""
    store = load_playbook_store()
    groups: dict[str, list[dict]] = {}
    for entries in store.values():
        for entry in entries:
            norm = str(entry.get("technique", "")).strip().lower()
            if norm:
                groups.setdefault(norm, []).append(entry)
    ordered_groups = [
        sorted(entries, key=lambda e: e.get("last_confirmed_at") or e.get("last_seen") or "", reverse=True)
        for entries in groups.values() if len(entries) > 1
    ]
    ordered_groups.sort(key=lambda g: g[0].get("last_confirmed_at") or g[0].get("last_seen") or "", reverse=True)
    return ordered_groups


def merge_duplicate_group(keep_id: str, other_ids: list[str]) -> int:
    """Manual, operator-chosen counterpart to dedupe_all_techniques's own auto-merge -- folds each
    of other_ids' own attribution (times_confirmed/injected_count/led_to_finding_count/
    source_session_ids, same fields that function already sums) into keep_id's entry, then removes
    them. keep_id is whichever copy the operator picked in the "Check duplicates" dialog, not
    necessarily the most-recently-confirmed one dedupe_all_techniques itself would have chosen.
    Returns how many entries were actually merged away and removed (0 if keep_id wasn't found)."""
    store = load_playbook_store()
    keep_entry = next((e for entries in store.values() for e in entries if e.get("id") == keep_id), None)
    if keep_entry is None:
        return 0
    other_id_set = set(other_ids)
    removed = 0
    for key in list(store.keys()):
        remaining = []
        for entry in store[key]:
            if entry.get("id") in other_id_set:
                keep_entry["times_confirmed"] = int(keep_entry.get("times_confirmed", 1) or 1) + int(entry.get("times_confirmed", 1) or 1)
                keep_entry["injected_count"] = int(keep_entry.get("injected_count", 0) or 0) + int(entry.get("injected_count", 0) or 0)
                keep_entry["led_to_finding_count"] = int(keep_entry.get("led_to_finding_count", 0) or 0) + int(entry.get("led_to_finding_count", 0) or 0)
                source_sessions = keep_entry.setdefault("source_session_ids", [])
                for sid in entry.get("source_session_ids") or []:
                    if sid not in source_sessions:
                        source_sessions.append(sid)
                removed += 1
            else:
                remaining.append(entry)
        store[key] = remaining
    if removed:
        for key in list(store.keys()):
            if not store[key]:
                del store[key]
        _write_playbook_store(store)
        logger.debug("playbook: merged %d duplicate(s) into operator-chosen keep_id=%s", removed, keep_id)
    return removed


def _bump_counter_for_ids(technique_ids: set[str], field: str) -> None:
    """Increments `field` on every entry whose id is in technique_ids, in ONE load-update-write over
    the whole store. Shared by bump_injected/bump_led_to_finding below -- the attribution feedback
    loop (agent/core.py): injected_count counts how often an entry was surfaced as a lead,
    led_to_finding_count how often a real finding followed. success_rate = led / injected then ranks
    proven techniques up and feeds pruning. Unknown ids are silently skipped (an entry can be
    distilled/pruned away between being injected and being credited)."""
    if not technique_ids:
        return
    store = load_playbook_store()
    changed = False
    for entries in store.values():
        for entry in entries:
            if entry.get("id") in technique_ids:
                entry[field] = int(entry.get(field, 0) or 0) + 1
                changed = True
    if changed:
        _write_playbook_store(store)
        logger.debug("playbook: bumped %s on %d id(s)", field, len(technique_ids))


def bump_injected(technique_ids: set[str]) -> None:
    _bump_counter_for_ids(technique_ids, "injected_count")


def bump_led_to_finding(technique_ids: set[str]) -> None:
    _bump_counter_for_ids(technique_ids, "led_to_finding_count")


def prune_low_value(min_injections: int) -> int:
    """Removes entries that were surfaced as a lead at least `min_injections` times yet NEVER once
    preceded a confirmed finding (led_to_finding_count == 0) -- proven noise, actively costing prompt
    budget and crowding out useful leads every time it's injected. Dead-ends (outcome=="failed") are
    deliberately NEVER pruned: a confirmed dead-end is valuable precisely because it keeps the agent
    from re-trying it, and it's not expected to "lead to a finding" in the first place. Returns how
    many were removed. min_injections <= 0 disables pruning entirely (returns 0)."""
    if min_injections <= 0:
        return 0
    store = load_playbook_store()
    removed = 0
    for key in list(store.keys()):
        kept = [
            e for e in store[key]
            if e.get("outcome") == "failed"
            or int(e.get("injected_count", 0) or 0) < min_injections
            or int(e.get("led_to_finding_count", 0) or 0) > 0
        ]
        removed += len(store[key]) - len(kept)
        if kept:
            store[key] = kept
        else:
            del store[key]
    if removed:
        _write_playbook_store(store)
        logger.debug("playbook: pruned %d low-value entr(y/ies) (min_injections=%d)", removed, min_injections)
    return removed


def find_similar_techniques(tech_keywords: set[str], waf_vendors: set[str], limit: int, vuln_class: str | None = None, query_embedding: list[float] | None = None) -> list[dict]:
    """Every stored entry scored against the current target and ranked by (score, recency), top
    `limit` returned. HYBRID: the keyword score (_relevance_score -- partial stack overlap, shared
    WAF, matching vuln class, confidence) PLUS, when query_embedding is supplied, a semantic score
    (cosine of the query vector against the entry's stored embedding, weighted by _SEMANTIC_WEIGHT).
    Semantic is what surfaces a technique whose WORDS don't overlap the query but whose MEANING does
    -- the whole point of the RAG upgrade -- while keyword keeps exact-stack matches sharp. With no
    query_embedding (the provider has no embeddings / it wasn't computed) this degrades to the exact
    prior keyword behavior. Returns [] when nothing scores and there's no semantic query to lean on.
    The store is small operator-curated knowledge, so scoring every entry each call is cheap.
    """
    if limit <= 0:
        return []
    if not tech_keywords and query_embedding is None:
        return []
    store = load_playbook_store()
    embeddings = load_embeddings() if query_embedding is not None else {}
    scored: list[tuple[float, dict]] = []
    for key, entries in store.items():
        try:
            parsed_key = json.loads(key)
            key_tech = set(parsed_key.get("tech") or [])
            key_waf = set(parsed_key.get("waf") or [])
        except (json.JSONDecodeError, AttributeError, TypeError):
            continue
        for entry in entries:
            keyword_score = _relevance_score(tech_keywords, waf_vendors, vuln_class, key_tech, key_waf, entry) if tech_keywords else 0.0
            semantic_score = 0.0
            if query_embedding is not None:
                vec = embeddings.get(entry.get("id"))
                if isinstance(vec, list):
                    semantic_score = _cosine(query_embedding, vec) * _SEMANTIC_WEIGHT
            total = keyword_score + semantic_score
            if total > 0.0:
                scored.append((total, entry))

    scored.sort(key=lambda pair: (pair[0], pair[1].get("last_seen", "")), reverse=True)
    return [entry for _, entry in scored[:limit]]
