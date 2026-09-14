"""Exploitation allowlist storage, plus the shared hostname-matching logic behind both the
positive allowlist (is_target_allowed) and the negative out-of-scope exclusion list
(is_target_out_of_scope, agent/core.py's per-tool-call guard).

is_target_allowed backs the run_tool() guardrail for requires_allowed_target tools (Metasploit,
sqlmap, default_creds_check). Deliberately NOT sourced from .env, and never implied by just
submitting a scan target: the list is empty by default and only grows through an explicit,
off-by-default opt-in — the "authorize exploitation" checkbox on the New Project form. Recon/scan
tools are unaffected by this allowlist; only exploitation is gated by it — see README.md
"Test scope / Legal notice" for why.

is_target_out_of_scope is the opposite direction and applies to every tool call, recon included —
the New Project form's optional "Out of scope" field (session["out_of_scope"], sessions/store.py's
create_session), an operator-specified exclusion list checked deterministically before any tool
call, not just something mentioned to the model in a prompt.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import os
import re
from contextvars import ContextVar, Token
from urllib.parse import urlparse

import tldextract

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
ALLOWED_TARGETS_PATH = resolve_global_app_dir() / "data" / "allowed_targets.json"

# suffix_list_urls=() disables tldextract's live network fetch on first use -- it falls back to
# its own bundled Public Suffix List snapshot instead, so building the exploitation allowlist
# never grows a surprise network dependency (or first-call latency) of its own.
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

# When True for the current async context, is_target_allowed() returns True for EVERY target,
# wholesale — the per-project exploitation allowlist check is satisfied without any target ever
# being written to allowed_targets.json. This is how the Interactive mode session view works: it's
# the operator's own manual execution console (a CTF-style "here's the target, here's the task"
# console, agent/chat.py), and deliberately choosing that mode IS the exploitation authorization,
# so no separate "authorize this target" step exists there. Set for the duration of an interactive
# chat turn (agent/chat.py's run_chat_turn_background) and, because asyncio.create_task copies the
# current context, inherited by any Subagent task that turn spawns — so a subagent's own sqlmap/
# metasploit calls are authorized too, without the global list ever being touched. Never set on the
# autonomous agent path (run_session), so ordinary projects keep the exact off-by-default allowlist
# behavior they always had. One shared switch checked in is_target_allowed() below covers every
# call site of it at once (runner.py's guardrail, toolkit_agent_tools.py's live-mode manual check).
_full_exploitation_authorized: ContextVar[bool] = ContextVar("asra_full_exploitation_authorized", default=False)


def authorize_all_targets_for_context() -> Token:
    """Turns on wholesale exploitation authorization for the current async context (see
    _full_exploitation_authorized above). Returns the reset token the caller must hand back to
    deauthorize_all_targets_for_context() in its own finally, exactly like ContextVar.set()."""
    logger.debug("allowed_targets: wholesale exploitation authorization enabled for this context (interactive mode)")
    return _full_exploitation_authorized.set(True)


def deauthorize_all_targets_for_context(token: Token) -> None:
    _full_exploitation_authorized.reset(token)

_IP_RANGE_PATTERN = re.compile(r"^([^\s-]+)\s*-\s*([^\s-]+)$")


def parse_ip_range_or_cidr(value: str) -> str | None:
    """Recognizes two IP-block scope-entry shapes beyond a plain host/wildcard: CIDR
    ("10.0.0.0/24") and an explicit "start - end" range ("192.168.1.1 - 192.168.1.254", a common
    bug-bounty scope-table format for a pool of addresses). Returns the canonical, whitespace-free
    stored form (a real ipaddress network string, or "start-end" with no spaces) -- which also
    always passes validate_target()'s shape check downstream, so nmap and friends can receive it
    directly as a real target argument (nmap understands CIDR, and a same-prefix last-octet range,
    natively on its own). None means `value` isn't shaped like either at all -- the normal case for
    a plain hostname/URL/wildcard entry, which the caller should validate/match as it always has.
    A bare single IP with no "/" (e.g. "10.0.0.5") deliberately does NOT go through ip_network()
    here even though it would technically parse as a /32 -- that already works today as a plain
    exact-string match, and silently rewriting it to "10.0.0.5/32" would be a surprising, needless
    behavior change for the overwhelmingly common single-host case.
    """
    if "/" in value:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            pass

    match = _IP_RANGE_PATTERN.match(value)
    if not match:
        return None
    try:
        start = ipaddress.ip_address(match.group(1))
        end = ipaddress.ip_address(match.group(2))
    except ValueError:
        return None
    if start.version != end.version or int(start) > int(end):
        return None
    return f"{start}-{end}"


def _cidr_or_range_contains(entry: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """False (never raises) when `entry` isn't a CIDR/range at all -- the caller's existing
    exact-string/wildcard matching already covers that case."""
    canonical = parse_ip_range_or_cidr(entry)
    if canonical is None:
        return False
    if "/" in canonical:
        return ip in ipaddress.ip_network(canonical, strict=False)
    start_text, end_text = canonical.split("-", 1)
    start, end = ipaddress.ip_address(start_text), ipaddress.ip_address(end_text)
    return start.version == ip.version and int(start) <= int(ip) <= int(end)


def load_allowed_targets() -> list[str]:
    if not ALLOWED_TARGETS_PATH.exists():
        return []

    try:
        with ALLOWED_TARGETS_PATH.open("r", encoding="utf-8") as f:
            targets = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("allowed_targets.json unreadable (%s) — treating as empty allowlist", exc)
        return []

    if not isinstance(targets, list):
        logger.debug("allowed_targets.json does not contain a list — treating as empty allowlist")
        return []

    return [str(t) for t in targets]


def _write_allowed_targets(targets: list[str]) -> None:
    ALLOWED_TARGETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = ALLOWED_TARGETS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(targets, f, indent=2)
    os.replace(tmp_path, ALLOWED_TARGETS_PATH)


def add_allowed_target(target: str) -> list[str]:
    targets = load_allowed_targets()
    if target not in targets:
        targets.append(target)
        _write_allowed_targets(targets)
        logger.debug("allowed_targets: added %r (total=%d)", target, len(targets))
    return targets


def extract_hostname(target: str) -> str | None:
    """Pulls the hostname out of a full URL or a bare host/IP token. A bare (unbracketed) IPv6
    literal is checked first and returned directly, before ever reaching urlparse -- real bug this
    fixes: urlparse("2001:db8::1") misreads "2001" as a URL *scheme* (nothing here has "//" or
    brackets to disambiguate it), so .hostname came back as just "2001", silently breaking any
    bare-IPv6 CIDR/range/allowlist match. urlparse only populates .hostname for a "scheme://..." or
    "//..." string otherwise -- a bare IPv4/hostname with no scheme (the common case for a
    Metasploit-style RHOSTS-shaped target) parses as a path with no netloc at all, giving
    hostname=None; the "//" retry covers exactly that case without disturbing a real full URL,
    which already parses correctly on the first try.
    """
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    return urlparse(target).hostname or urlparse(f"//{target}").hostname


def registrable_domain(hostname: str) -> str:
    """Apex/registrable domain for `hostname` via tldextract (e.g. "trk.notify.example.com" ->
    "example.com") -- the same extractor instance authorize_exploit_targets already uses for its
    own wildcard-scope apex calculation, exposed here so other modules needing an apex-domain
    comparison (e.g. toolkit_proxy's passive-capture scope filter) don't need a second tldextract
    instance/suffix-list snapshot of their own."""
    return _TLD_EXTRACTOR(hostname).top_domain_under_public_suffix or hostname


def _matches_scope_entries(target: str, entries: list[str]) -> bool:
    """Matches by hostname, not exact string — sqlmap targets are full URLs (with path/query)
    while a scope entry stores a bare host (as Metasploit's RHOSTS expects), e.g. an entry
    "juice-shop.herokuapp.com" must also cover "https://juice-shop.herokuapp.com/rest/...".

    A "*.example.com" entry (the New Project form's wildcard-scope syntax, see
    validate_scope_entry()) additionally covers any subdomain of example.com — and example.com
    itself, matching how bug-bounty programs typically mean it: "the whole tree is in scope",
    a superset of the bare domain, not a replacement that excludes it. This exact form is checked
    first and separately (not folded into the general glob check below) specifically to preserve
    that "also covers the bare domain" behavior, which a plain glob match on "*.example.com" would
    NOT give (fnmatch's "*" still requires the literal "." after it to be present in the matched
    string, so "example.com" itself wouldn't match "*.example.com" under plain fnmatch).

    Any OTHER placement of "*" in an entry (validate_scope_entry() accepts this too) is matched as
    a real glob pattern against the hostname — "prod-*.example.com" (a wildcard filling out part
    of one label, matching prod-us1.example.com/prod-eu2.example.com/...) and "*-eu.example.com"
    (a wildcard as a label's own prefix, matching api-eu.example.com/web-eu.example.com/...) are
    both real, commonly-seen scope-table conventions, not hypothetical — confirmed live, entries in
    exactly these shapes were accepted as valid scope input but never actually matched anything
    downstream before this. fnmatchcase (not fnmatch) on lower-cased strings, deliberately: DNS
    hostnames are case-insensitive, and fnmatch's own case-sensitivity is platform-dependent (case-
    insensitive on Windows, case-sensitive on POSIX) — a security-relevant scope check must behave
    identically regardless of which OS this happens to run on.

    A CIDR ("10.0.0.0/24") or "start-end" IP-range entry additionally covers any literal IP address
    falling inside it (only ever checked against the target's own literal IP -- a hostname is never
    resolved just to test this, same as the wildcard checks above never do a DNS lookup either).
    Shared by both is_target_allowed (positive list) and is_target_out_of_scope (negative list) —
    same matching rules apply either direction, only which list gets checked differs.
    """
    hostname = extract_hostname(target)
    candidates = {target}
    if hostname:
        candidates.add(hostname)

    target_ip = None
    if hostname:
        try:
            target_ip = ipaddress.ip_address(hostname)
        except ValueError:
            target_ip = None

    for entry in entries:
        if entry in candidates:
            return True
        if entry.startswith("*.") and hostname:
            base = entry[2:]
            if hostname == base or hostname.endswith("." + base):
                return True
        elif "*" in entry and hostname and fnmatch.fnmatchcase(hostname.lower(), entry.lower()):
            return True
        if target_ip is not None and _cidr_or_range_contains(entry, target_ip):
            return True
    return False


def is_target_allowed(target: str) -> bool:
    # Interactive mode authorizes every target wholesale (see _full_exploitation_authorized) — the
    # operator's own manual console, where choosing the mode is the authorization. Checked before
    # the on-disk allowlist so it applies to every gated tool uniformly, including a subagent's own.
    if _full_exploitation_authorized.get():
        return True
    return _matches_scope_entries(target, load_allowed_targets())


def is_target_out_of_scope(target: str, out_of_scope_entries: list[str]) -> bool:
    """out_of_scope_entries comes straight from session["out_of_scope"] (agent/core.py's caller) —
    unlike is_target_allowed's allowlist, this is never persisted to disk on its own; it's
    per-session operator input, not a standing global list."""
    return _matches_scope_entries(target, out_of_scope_entries)


def authorize_exploit_targets(clean_targets: list[str], enumerate_subdomains: bool) -> None:
    """Widens the (global) exploitation allowlist for every target in scope — shared by main.py's
    start_scan/rescan routes AND agent/core.py's mid-session "operator added a new target" path, so
    this logic exists exactly once rather than being duplicated across the web layer and the agent
    layer. "Enumerate subdomains" is documented on the New Project form itself as having "the same
    effect as writing each one as *.example.com" — that promise has to reach the exploitation
    allowlist too, not just recon's active subdomain search. Real incident this fixes: a real scan
    with this box checked found a real, verified finding on a legitimately-discovered subdomain, and
    default_creds_check still refused to run against it because only the literal typed host had been
    authorized — the checkbox's own documented behavior was silently not honored past the recon
    phase. add_allowed_target is idempotent (dedups on exact string), so calling this more than once
    for the same targets (e.g. a project rescanned twice, or a target added mid-session that was
    already in scope) is always safe.

    The wildcard base is the target's own APEX/registrable domain (via tldextract), not its literal
    hostname — real, confirmed incident this fixes: target "crossfire.z8games.com" (itself already
    a subdomain, not an apex domain) with this box checked used to authorize only
    "*.crossfire.z8games.com", while recon's own grounding logic (agent/core.py's
    _is_recon_target_grounded, via crt_sh_lookup/subdomain_enum/dns_lookup) is deliberately allowed
    to range across the whole registrable domain once a real discovery tool surfaces a sibling host
    (e.g. "support.z8games.com"). That mismatch meant Exploit found and could not act on a real,
    verified finding on a legitimately in-scope, legitimately-discovered host for the entire rest of
    that session. Using the apex domain here keeps exploitation's allowlist as wide as what recon is
    already allowed to discover and report on.
    """
    for one_target in clean_targets:
        if enumerate_subdomains and not one_target.startswith("*."):
            hostname = extract_hostname(one_target) or one_target
            add_allowed_target(f"*.{_TLD_EXTRACTOR(hostname).top_domain_under_public_suffix or hostname}")
        else:
            add_allowed_target(one_target)


# Real, confirmed incident this fixes (a real HackerOne session): subfinder against a domain
# backed by a large CDN can return thousands of interchangeable edge-node hostnames (e.g.
# "ipv4-c017-ord003-ix.1.oca.example-cdn.net") that differ from each other ONLY in numeric/code
# segments -- one subagent handed this raw list correctly improvised "filter out CDN node
# patterns" as an ad-hoc plan step, another one didn't and burned several whatweb calls against
# hosts that don't even resolve (NXDOMAIN). Filtering this was previously only ever a per-turn
# model judgment call, never a structural guarantee -- unbounded on a large-enough CDN estate.
_CDN_EDGE_NODE_COLLAPSE_THRESHOLD = 5
_CDN_EDGE_NODE_SAMPLE_COUNT = 2
_DIGIT_RUN_PATTERN = re.compile(r"\d+")


def collapse_cdn_edge_node_hosts(hosts: list[str]) -> list[str]:
    """Collapses runs of hostnames that are structurally identical except for digit segments
    (the classic CDN/edge-node/load-balancer-pool naming shape) down to a couple of representative
    samples plus a count, instead of handing a discovery tool's full list straight to the model —
    same "don't drown the caller in a flood of indistinguishable results" principle already applied
    to `_dedupe_hosts_by_dns_identity` elsewhere in this project, just for a different kind of
    duplication (naming-pattern fan-out, not the same physical host under two identifiers).

    Groups hosts by a "skeleton" (every run of digits replaced with '#') and collapses any group
    bigger than `_CDN_EDGE_NODE_COLLAPSE_THRESHOLD` — deliberately not a low bar like 2-3, which
    would also swallow a handful of genuinely distinct hosts (www1/www2, ns1/ns2/ns3) that just
    happen to share a numbered naming scheme; real CDN edge-node fan-out shows up in the hundreds
    or thousands, not single digits. Groups at or under the threshold are returned untouched, in
    their original relative order. Generic by construction — no CDN/provider name is hardcoded
    anywhere in this function, it reacts purely to the shape of the hostnames it's given.
    """
    if len(hosts) <= _CDN_EDGE_NODE_COLLAPSE_THRESHOLD:
        return list(hosts)

    groups: dict[str, list[str]] = {}
    order: list[str] = []
    for host in hosts:
        skeleton = _DIGIT_RUN_PATTERN.sub("#", host)
        if skeleton not in groups:
            groups[skeleton] = []
            order.append(skeleton)
        groups[skeleton].append(host)

    collapsed: list[str] = []
    for skeleton in order:
        members = groups[skeleton]
        if len(members) > _CDN_EDGE_NODE_COLLAPSE_THRESHOLD:
            samples = sorted(members)[:_CDN_EDGE_NODE_SAMPLE_COUNT]
            collapsed.extend(samples)
            collapsed.append(
                f"... {len(members) - len(samples)} more hosts matching pattern {skeleton!r} "
                "collapsed (looks like CDN/edge-node fan-out, not distinct attack surface) — "
                "the samples above are representative, not exhaustive"
            )
        else:
            collapsed.extend(members)
    return collapsed
