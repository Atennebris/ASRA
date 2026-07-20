"""Tier-1 native tools: plain Python functions, no subprocess/binary install.

Every function takes a single params dict and returns a result dict shaped like run_tool()'s
tier-2 output ({"status": "ok"/"error", ...}) — run_tool() calls these directly for tool_tier=1
ToolSpecs and never wraps them in subprocess/health-check/timeout (each function owns its own
network timeout).
"""
from __future__ import annotations

import base64
import csv
import json
import re
import socket
import ssl
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx
import mmh3

from agent.tools.cache import cache_get, cache_set

_HTTP_TIMEOUT = 10.0


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

    result = {"status": "ok", "source": source, "subdomains": sorted(subdomains)}
    cache_set("crt_sh_lookup", domain, result)
    return result


def wayback_urls(params: dict) -> dict:
    domain = params["domain"]
    cached = cache_get("wayback_urls", domain)
    if cached is not None:
        return cached

    try:
        # web.archive.org's CDX API measured at ~38s for a real query — it succeeds, just slowly;
        # 15s was cutting it off before it could ever respond.
        with httpx.Client(timeout=45.0) as client:
            resp = client.get(
                "https://web.archive.org/cdx/search/cdx",
                params={"url": f"{domain}/*", "output": "json", "fl": "original", "collapse": "urlkey", "limit": 500},
            )
            resp.raise_for_status()
            rows = resp.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        return {"status": "error", "error": str(exc)}

    urls = [row[0] for row in rows[1:]] if rows else []  # first row is the column header
    result = {"status": "ok", "urls": urls}
    cache_set("wayback_urls", domain, result)
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


def whois_lookup(params: dict) -> dict:
    domain = params["domain"]
    tld = domain.rsplit(".", 1)[-1]

    try:
        referral = _whois_query("whois.iana.org", tld)
        match = re.search(r"^refer:\s*(\S+)", referral, re.MULTILINE)
        server = match.group(1) if match else "whois.iana.org"
        raw = _whois_query(server, domain)
    except OSError as exc:
        return {"status": "error", "error": str(exc)}

    return {"status": "ok", "server": server, "raw": raw}


# --- recon/scan with light touch on the target ---


def dns_lookup(params: dict) -> dict:
    domain = params["domain"]
    try:
        results = socket.getaddrinfo(domain, None)
    except socket.gaierror as exc:
        return {"status": "error", "error": str(exc)}
    return {"status": "ok", "ips": sorted({r[4][0] for r in results})}


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
    ("oracle", re.compile(r"ora-\d{5}")),
    ("sqlite", re.compile(r"sqlite3?\.OperationalError|sqlite_(step|prepare)", re.IGNORECASE)),
)

# Output signatures for a real command/path-injection result — the effect, not the payload echoed
# back (which would just be _detect_reflected_payload's job).
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


def _detect_reflected_payload(url: str, body: str) -> dict | None:
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


def _detect_sql_error(url: str, body: str) -> dict | None:
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


def _detect_open_redirect(url: str, response: httpx.Response) -> dict | None:
    """Deterministic check: did a query param that looks like a redirect target actually end up as
    the Location header of a real redirect response? Checked against resp.history (the
    intermediate 3xx hops httpx.Client(follow_redirects=True) still records), not the body.
    """
    if not response.history:
        return None
    for name, value in _query_params(url):
        if name.lower() not in _REDIRECT_PARAM_NAMES or not value:
            continue
        for hop in response.history:
            location = hop.headers.get("location", "")
            if value == location or (value in location and len(value) > 8):
                return {"param": name, "value": value, "location": location}
    return None


def _detect_command_injection(url: str, body: str) -> dict | None:
    """Deterministic check for real command/path-injection *output* (an /etc/passwd dump, a shell
    id/whoami result) after a request that carried an actual injection-shaped probe — gated the
    same way as _detect_sql_error, to avoid attributing a coincidental match to nothing.
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


def http_request(params: dict) -> dict:
    url = params["target"]
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": str(exc)}

    security_headers = {h: resp.headers.get(h) for h in _SECURITY_HEADERS_CHECKLIST if h in resp.headers}
    result = {
        "status": "ok",
        "status_code": resp.status_code,
        "security_headers": security_headers,
        "body_preview": resp.text[:2000],
    }

    detectors = {
        "reflected_payload_detected": _detect_reflected_payload(url, resp.text),
        "sql_error_detected": _detect_sql_error(url, resp.text),
        "open_redirect_detected": _detect_open_redirect(url, resp),
        "command_injection_detected": _detect_command_injection(url, resp.text),
    }
    for field, value in detectors.items():
        if value is not None:
            result[field] = value
    return result


def tcp_port_check(params: dict) -> dict:
    host = params["target"]
    port = int(params["port"])
    timeout = float(params.get("timeout", 5))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
    except socket.gaierror as exc:
        return {"status": "error", "error": str(exc)}
    finally:
        sock.close()

    return {"status": "ok", "port": port, "open": result == 0}


def ssl_cert_info(params: dict) -> dict:
    host = params["target"]
    port = int(params.get("port", 443))

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError) as exc:
        return {"status": "error", "error": str(exc)}

    return {
        "status": "ok",
        "subject": dict(x[0] for x in cert.get("subject", [])),
        "issuer": dict(x[0] for x in cert.get("issuer", [])),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [v for k, v in cert.get("subjectAltName", [])],
    }


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
        with httpx.Client(timeout=8.0, follow_redirects=False) as client:
            for path in _SENSITIVE_PATHS:
                try:
                    resp = client.get(base_url + path)
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200:
                    exposed.append({"path": path, "status_code": resp.status_code, "content_length": len(resp.content)})
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    return {"status": "ok", "exposed_paths": exposed}


def favicon_hash(params: dict) -> dict:
    base_url = params["target"].rstrip("/")
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True) as client:
            resp = client.get(base_url + "/favicon.ico")
    except httpx.HTTPError as exc:
        return {"status": "error", "error": str(exc)}

    if resp.status_code != 200 or not resp.content:
        return {"status": "ok", "favicon_found": False}

    # Shodan's http.favicon.hash recipe: base64-encode, then 32-bit murmur3.
    b64 = base64.encodebytes(resp.content)
    return {"status": "ok", "favicon_found": True, "mmh3_hash": mmh3.hash(b64)}


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
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": str(exc)}

    return {
        "status": "ok",
        "headers_present": {header: header in resp.headers for header in _SECURITY_HEADERS_CHECKLIST},
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
        return {"status": "error", "error": str(exc)}

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
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": str(exc)}

    html = resp.text
    return {
        "status": "ok",
        "comments": [c.strip() for c in _COMMENT_PATTERN.findall(html)][:_MAX_MATCHES],
        "hidden_inputs": _HIDDEN_INPUT_PATTERN.findall(html)[:_MAX_MATCHES],
        "script_src": _SCRIPT_SRC_PATTERN.findall(html)[:_MAX_MATCHES],
        "link_href": _LINK_HREF_PATTERN.findall(html)[:_MAX_MATCHES],
        "meta_tags": _META_TAG_PATTERN.findall(html)[:_MAX_MATCHES],
    }


# --- Analyze -> Exploit bridge ---

# The GitHub mirror (offensive-security/exploitdb) was retired mid-2026 in favor of GitLab
# (confirmed by fetching its README, which now just points here) — found by an actual 404 on
# the old URL, not assumed.
_EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
_EXPLOITDB_CSV_PATH = Path("data/cache/exploitdb/files_exploits.csv")
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
        return {"status": "error", "error": str(exc)}

    query_lower = query.lower()
    matches = []
    with csv_path.open("r", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            haystack = f"{row.get('description', '')} {row.get('codes', '')}".lower()
            if query_lower in haystack:
                matches.append(
                    {
                        "edb_id": row.get("id"),
                        "title": row.get("description"),
                        "cve": row.get("codes"),
                        "path": row.get("file"),
                    }
                )
                if len(matches) >= 20:
                    break

    result = {"status": "ok", "matches": matches}
    cache_set("exploit_db_lookup", query, result)
    return result


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
        return {"status": "error", "error": str(exc)}

    cve_ids = sorted(
        {
            entry[0].upper()
            for source_results in data.get("results", {}).values()
            for entry in source_results
        }
    )

    result = {"status": "ok", "cve_ids": cve_ids}
    cache_set("cve_lookup", cache_key, result)
    return result


# --- exploit-tier, not tier-1 by risk: same guardrail as Metasploit ---

_DEFAULT_CREDENTIAL_PAIRS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("admin", ""),
    ("test", "test"),
]


_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}
_VALID_VERIFICATIONS = {"verified", "inferred", "needs_verification"}


# --- session recording: the LLM calls these the instant it identifies something, not batched
# into a final answer — the caller (agent/core.py's execute_tool closure in _run_recon/
# _run_analyze) persists the returned "recorded" dict into the session immediately. These
# functions only validate/normalize the model's input; they know nothing about sessions. ---


def record_finding(params: dict) -> dict:
    severity = params["severity"]
    if severity not in _VALID_SEVERITIES:
        return {"status": "error", "error": f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}"}
    verification = params.get("verification", "needs_verification")
    if verification not in _VALID_VERIFICATIONS:
        return {"status": "error", "error": f"verification must be one of {sorted(_VALID_VERIFICATIONS)}, got {verification!r}"}

    recorded = {
        "title": params["title"],
        "severity": severity,
        "description": params.get("description", ""),
        "technology": params.get("technology"),
        "reproduction_steps": params.get("reproduction_steps"),
        "verification": verification,
        "evidence_ref": params.get("evidence_ref"),
    }
    return {"status": "ok", "recorded": recorded}


def record_target(params: dict) -> dict:
    port = params.get("port")
    recorded = {
        "host": params["host"],
        "port": int(port) if port is not None else None,
        "service": params.get("service"),
        "version": params.get("version"),
    }
    return {"status": "ok", "recorded": recorded}


def default_creds_check(params: dict) -> dict:
    login_url = params["target"]
    username_field = params.get("username_field", "email")
    password_field = params.get("password_field", "password")

    successes = []
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
            for username, password in _DEFAULT_CREDENTIAL_PAIRS:
                try:
                    resp = client.post(login_url, json={username_field: username, password_field: password})
                except httpx.HTTPError:
                    continue
                if resp.status_code == 200:
                    successes.append({"username": username, "password": password})
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    return {
        "status": "ok",
        "successful_credentials": successes,
        "attempted": len(_DEFAULT_CREDENTIAL_PAIRS),
    }
