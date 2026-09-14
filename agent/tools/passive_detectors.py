"""Deterministic, signature-based passive detectors for common web-vuln signals -- narrow, gated
checks (never a heuristic guess at what "looks like" a finding) shared by two callers:

- agent/tools/native.py's http_request -- checked against ONE fully-resolved request/response,
  including whatever redirect chain httpx.Client(follow_redirects=True) actually followed. This is
  where these detectors originally lived; moved out here unchanged in behavior so a second caller
  can use them without native.py and agent/tools/toolkit_store.py importing each other.
- agent/tools/toolkit_store.py's build_traffic_entry -- checked against EVERY traffic entry this
  project ever builds (Proxy capture from the agent's own browser, Repeater sends, Intruder
  attempts), closing a real gap: before this module existed, a SQL error or open redirect surfacing
  during ordinary browser-driven recon (never routed through http_request) went completely
  unflagged unless the model separately decided to re-check that exact URL with http_request itself.

Every detector takes plain values (url, status, headers, body text) rather than an httpx.Response,
so neither caller depends on httpx's own response type.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

# Chars that only matter here if they'd actually change how the response is parsed (break out of
# an HTML attribute/tag/string) — flags real injection probes, not benign echoed search terms.
_HTML_BREAKOUT_CHARS = ('<', '>', '"', "'")

# Query-param names that conventionally hold a redirect target — checked against the Location
# header of an actual redirect response, not just present-in-URL.
_REDIRECT_PARAM_NAMES = frozenset({"url", "redirect", "redirect_uri", "next", "return", "continue", "dest", "destination"})

# Real, narrow signatures for actual DB error output — not a heuristic "looks like an error".
_SQL_ERROR_PATTERNS = (
    ("mysql", re.compile(r"you have an error in your sql syntax", re.IGNORECASE)),
    ("mysql", re.compile(r"warning:\s*mysqli?_", re.IGNORECASE)),
    ("postgresql", re.compile(r"pg_query\(\)|pg_exec\(\)", re.IGNORECASE)),
    ("postgresql", re.compile(r"syntax error at or near", re.IGNORECASE)),
    ("mssql", re.compile(r"unclosed quotation mark after the character string", re.IGNORECASE)),
    ("mssql", re.compile(r"microsoft ole db provider for sql server", re.IGNORECASE)),
    ("oracle", re.compile(r"ora-\d{5}", re.IGNORECASE)),
    ("sqlite", re.compile(r"sqlite3?\.OperationalError|sqlite_(step|prepare)", re.IGNORECASE)),
)

# Output signatures for a real command/path-injection result — the effect, not the payload echoed
# back (which would just be detect_reflected_payload's job).
_COMMAND_INJECTION_OUTPUT_PATTERNS = (
    ("etc_passwd", re.compile(r"root:.*:0:0:")),
    ("shell_id_output", re.compile(r"uid=\d+\([^)]*\)\s*gid=\d+")),
)
# Chars/sequences that mark a query value as an actual command/path-injection probe, not benign
# input — gates the output-pattern check so a coincidental match on an unrelated response doesn't
# get attributed to an injection that was never attempted.
_COMMAND_INJECTION_PROBE_MARKERS = (';', '|', '&&', '`', '$(', '../')


def _query_params(url: str) -> list[tuple[str, str]]:
    return parse_qsl(urlsplit(url).query)


def detect_reflected_payload(url: str, body: str) -> dict | None:
    """Deterministic check for whether a query-param value came back unescaped in the response —
    the exact signal that confirms reflected XSS/injection, catching it whether or not the model
    itself thinks to compare its own payload against the response body (it doesn't always).
    """
    for name, value in _query_params(url):
        if len(value) < 4 or not any(c in value for c in _HTML_BREAKOUT_CHARS):
            continue
        if value in body:
            return {"param": name, "value": value}
    return None


def detect_sql_error(url: str, body: str) -> dict | None:
    """Deterministic check for a real DB error signature appearing after a request that actually
    carried a SQLi-shaped probe (a quote character in some query value) — narrow signature bank,
    not a heuristic guess at what "looks like" an error.
    """
    if not any("'" in value or '"' in value for _, value in _query_params(url)):
        return None
    for engine, pattern in _SQL_ERROR_PATTERNS:
        match = pattern.search(body)
        if match:
            return {"engine": engine, "matched": match.group(0)}
    return None


def detect_open_redirect(url: str, hops: list[tuple[int, dict]]) -> dict | None:
    """Deterministic check: did a query param that looks like a redirect target actually end up as
    the Location header of a real redirect response? `hops` is every (status_code, headers) pair
    actually observed as a 3xx along the way — native.py's http_request passes
    [(h.status_code, dict(h.headers)) for h in response.history] (the intermediate hops httpx's own
    follow_redirects=True already recorded); a single traffic entry that IS itself a 3xx (Proxy/
    Repeater, which never auto-follows) passes its own single (status, headers) as a one-item list.
    """
    for name, value in _query_params(url):
        if name.lower() not in _REDIRECT_PARAM_NAMES or not value:
            continue
        for _status, headers in hops:
            location = headers.get("location") or headers.get("Location") or ""
            if value == location or (value in location and len(value) > 8):
                return {"param": name, "value": value, "location": location}
    return None


def detect_command_injection(url: str, body: str) -> dict | None:
    """Deterministic check for real command/path-injection *output* (an /etc/passwd dump, a shell
    id/whoami result) after a request that carried an actual injection-shaped probe — gated the
    same way as detect_sql_error, to avoid attributing a coincidental match to nothing.
    """
    if not any(
        any(marker in value for marker in _COMMAND_INJECTION_PROBE_MARKERS)
        for _, value in _query_params(url)
    ):
        return None
    for name, pattern in _COMMAND_INJECTION_OUTPUT_PATTERNS:
        match = pattern.search(body)
        if match:
            return {"signature": name, "matched": match.group(0)}
    return None


def detect_flags(url: str, status: int | None, headers: dict, body: str) -> list[str]:
    """Convenience wrapper for a caller that only wants flag NAMES (agent/tools/toolkit_store.py's
    build_traffic_entry) rather than each detector's own detail dict -- runs all four, in a fixed
    order, against one entry's own single request/response (no multi-hop redirect chain available
    at this level, so detect_open_redirect only ever sees this one response as its own hop, exactly
    the "a single traffic entry that IS itself a 3xx" case its own docstring describes)."""
    flags: list[str] = []
    if detect_reflected_payload(url, body):
        flags.append("reflected_payload")
    if detect_sql_error(url, body):
        flags.append("sql_error")
    hops = [(status, headers)] if status is not None and 300 <= status < 400 else []
    if detect_open_redirect(url, hops):
        flags.append("open_redirect")
    if detect_command_injection(url, body):
        flags.append("command_injection")
    return flags
