"""Sequencer: entropy/predictability analysis of a token (session id, CSRF token, reset token, ...)
across several real samples. A minimally useful analysis, deliberately not a full FIPS 140-2 test
battery (monobit/poker/runs/long-runs tests, the kind a commercial token analyzer runs) --
per-character-position Shannon entropy plus exact-duplicate detection is enough to catch the two
failure modes that actually matter in practice: a token whose characters aren't uniformly
distributed at some position (a weak PRNG, a predictable prefix/suffix like a timestamp), and a
token generator that flat-out repeats a value.

Two ways to collect samples: pull them out of ALREADY-captured traffic (toolkit_store) by
header/cookie name, or fire fresh repeated requests through the SAME send engine Repeater/Intruder
use (toolkit_repeater.send_raw_request) and extract the value from each fresh response --
collect_stored_samples and collect_live_samples respectively, both feeding the same
analyze_samples.
"""
from __future__ import annotations

import asyncio
import math
import os
import re
from collections import Counter

from agent.tools import toolkit_store
from agent.tools.toolkit_repeater import send_raw_request
from agent.utils.logger import get_logger

logger = get_logger("TOOLKIT")

_DEFAULT_MAX_CONCURRENT = 5
_MAX_ALLOWED_CONCURRENT = 20
# Sequencer needs enough samples for the entropy estimate to mean anything (a commercial token
# analyzer's own default is 100) but this is a live-fire action against a real target -- capped
# well below Intruder's own
# _MAX_ATTEMPTS (agent/tools/toolkit_intruder.py) since a token-collection run has no legitimate
# reason to need hundreds of samples the way a payload sweep does.
_MAX_LIVE_SAMPLES = 200
_MAX_STORED_SAMPLES = 200
_MIN_SAMPLES_FOR_ANALYSIS = 2

_SET_COOKIE_VALUE_PATTERN = re.compile(r"([^=\s;]+)=([^;]*)")


def _max_concurrent_default() -> int:
    return int(os.getenv("INTRUDER_MAX_CONCURRENT_REQUESTS", str(_DEFAULT_MAX_CONCURRENT)))


def extract_value(headers: dict[str, str], header_name: str) -> str | None:
    """Pulls one token value out of a response's headers -- either a plain header
    ("X-CSRF-Token") or, prefixed "cookie:NAME", one specific cookie's value out of a Set-Cookie
    header (Set-Cookie itself can carry attributes like Path/HttpOnly alongside the real value,
    so a plain header-name match would return the whole "name=value; Path=/; HttpOnly" string,
    not the token itself)."""
    if header_name.lower().startswith("cookie:"):
        cookie_name = header_name.split(":", 1)[1].strip()
        set_cookie = None
        for name, value in headers.items():
            if name.lower() == "set-cookie":
                set_cookie = value
                break
        if not set_cookie:
            return None
        match = re.search(rf"(?:^|;\s*){re.escape(cookie_name)}=([^;]*)", set_cookie)
        return match.group(1) if match else None
    for name, value in headers.items():
        if name.lower() == header_name.lower():
            return value
    return None


def collect_stored_samples(session_id: str | None, header_name: str, limit: int = _MAX_STORED_SAMPLES) -> list[str]:
    """Every already-captured traffic entry's own response, newest first, with header_name
    extracted from each -- no live network call at all, works entirely off the Proxy's own capture
    history. Entries with no matching header/cookie are silently skipped (not every captured
    request necessarily set the token being analyzed).

    Uses load_recent_traffic_entries (tail-read, doesn't parse the whole file) rather than
    load_traffic_entries()[:limit] -- confirmed live (a real HackerOne rescan session, 18h with
    proxy/repeater active): traffic.jsonl had grown to ~136MB, and toolkit_store's own docstring
    already documents an even worse real incident (384MB, 8.6s full-file parse) for exactly this
    "only wanted the last N entries" shape. load_recent_traffic_entries returns them
    oldest-of-the-batch first; reversing that (a `limit`-sized list, not the whole file) restores
    the newest-first order this function has always promised.
    """
    entries = list(reversed(toolkit_store.load_recent_traffic_entries(session_id, limit)))
    samples = []
    for entry in entries:
        value = extract_value(entry["response_headers"], header_name)
        if value:
            samples.append(value)
    return samples


async def collect_live_samples(
    *, session_id: str | None, method: str, url: str, headers_text: str, body: str,
    header_name: str, count: int, max_concurrent: int | None = None,
) -> dict:
    """Fires `count` real, concurrent, identical requests (the same template every time -- no
    §...§ substitution, unlike Intruder) through send_raw_request (source="repeater", so each
    attempt is visible in the Site Map like any other manual send), then extracts header_name from
    each real response. Returns {"status": "ok", "samples": [...], "requested": N, "collected": M}
    -- M can be less than N when some responses didn't carry the header/cookie at all, or the
    request itself failed to connect."""
    count = max(1, min(int(count), _MAX_LIVE_SAMPLES))
    limit = max(1, min(int(max_concurrent or _max_concurrent_default()), _MAX_ALLOWED_CONCURRENT))
    semaphore = asyncio.Semaphore(limit)
    headers = toolkit_store.parse_header_lines(headers_text)

    async def _fire() -> dict:
        async with semaphore:
            return await send_raw_request(session_id=session_id, method=method, url=url, headers=headers, body=body)

    results = await asyncio.gather(*(_fire() for _ in range(count)))
    samples = []
    for result in results:
        if result["status"] != "ok":
            continue
        value = extract_value(result["entry"]["response_headers"], header_name)
        if value:
            samples.append(value)
    logger.debug(
        "toolkit_sequencer: session=%s url=%s header=%s requested=%d collected=%d",
        session_id, url, header_name, count, len(samples),
    )
    return {"status": "ok", "samples": samples, "requested": count, "collected": len(samples)}


def _shannon_entropy_bits(counter: Counter, total: int) -> float:
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def _verdict(duplicate_count: int, total_entropy_bits: float, sample_count: int) -> str:
    # Thresholds are a defensible, minimally-useful heuristic, not a formal cryptographic
    # standard -- NIST-style guidance commonly cites ~64 bits as a reasonable floor for a session
    # identifier; below ~32 bits is squarely brute-forceable with commodity hardware.
    if duplicate_count > 0:
        return f"weak — {duplicate_count} exact duplicate value(s) among {sample_count} samples"
    if total_entropy_bits < 32:
        return f"weak — only ~{total_entropy_bits:.0f} bits of estimated entropy, brute-forceable"
    if total_entropy_bits < 64:
        return f"borderline — ~{total_entropy_bits:.0f} bits of estimated entropy"
    return f"looks strong — ~{total_entropy_bits:.0f} bits of estimated entropy"


def analyze_samples(samples: list[str]) -> dict:
    """Per-position Shannon entropy (bits) across every sample, plus exact-duplicate detection --
    see this module's own docstring for why these two, not the full FIPS battery. Comparing
    positions only up to the SHORTEST sample's length -- a position that doesn't exist in every
    sample can't be fairly compared across all of them. Returns {"status": "ok", ...} or
    {"status": "error", "error": "..."} (too few samples to say anything meaningful)."""
    clean = [s for s in samples if s]
    if len(clean) < _MIN_SAMPLES_FOR_ANALYSIS:
        return {"status": "error", "error": f"need at least {_MIN_SAMPLES_FOR_ANALYSIS} non-empty samples to analyze, got {len(clean)}"}

    lengths = [len(s) for s in clean]
    min_len = min(lengths)
    max_len = max(lengths)
    duplicate_count = len(clean) - len(set(clean))

    position_entropies = []
    for i in range(min_len):
        counter = Counter(s[i] for s in clean)
        position_entropies.append(round(_shannon_entropy_bits(counter, len(clean)), 3))

    overall_counter = Counter("".join(clean))
    overall_charset_size = len(overall_counter)
    overall_entropy_per_char = _shannon_entropy_bits(overall_counter, sum(overall_counter.values()))
    total_entropy_estimate = sum(position_entropies)

    return {
        "status": "ok",
        "sample_count": len(clean),
        "duplicate_count": duplicate_count,
        "min_length": min_len,
        "max_length": max_len,
        "length_varies": min_len != max_len,
        "charset_size": overall_charset_size,
        "overall_entropy_per_char_bits": round(overall_entropy_per_char, 3),
        "total_entropy_estimate_bits": round(total_entropy_estimate, 2),
        "position_entropies": position_entropies,
        "verdict": _verdict(duplicate_count, total_entropy_estimate, len(clean)),
    }
