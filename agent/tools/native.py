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


def http_request(params: dict) -> dict:
    url = params["target"]
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(url)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": str(exc)}

    security_headers = {h: resp.headers.get(h) for h in _SECURITY_HEADERS_CHECKLIST if h in resp.headers}
    return {
        "status": "ok",
        "status_code": resp.status_code,
        "security_headers": security_headers,
        "body_preview": resp.text[:2000],
    }


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
