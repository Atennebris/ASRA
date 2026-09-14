"""Shared parameter validation for build_command() functions — defense against command injection.

By design, protection stops at "can't escape this token into a new shell command"
(no control chars / newlines / null bytes in any single argv element). It never restricts *which*
flags a tool is allowed to receive — every build_command() passes argv as a list[str] to subprocess
(never shell=True), so injection characters inside a value can't be reinterpreted as a new command.
"""
from __future__ import annotations

import ipaddress
import itertools
import re

from agent.tools.allowed_targets import parse_ip_range_or_cidr

_CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f]")

# Loose hostname/IP/URL shape check — just enough to reject obviously malformed input
# (empty string, whitespace-only, shell metacharacters). Allows query strings (?, =, &, %)
# since sqlmap targets are full URLs with an injectable parameter, not just a hostname. [ and ]
# cover bracketed IPv6 host literals in a URL (http://[2001:db8::1]:8080/); bare IPv6 (no
# brackets) already fits the existing hex-digit + ":" set. Ѐ-ӿ/Ԁ-ԯ (Cyrillic +
# Cyrillic Supplement) cover real internationalized domains — a Cyrillic-script hostname/URL
# (e.g. банк.рф) is a real target/scope shape some bug-bounty programs actually use, not a
# hypothetical, and was flatly rejected here before with no way around it. Not a general "any
# script" allowance (that would need Unicode category matching the stdlib `re` module can't do at
# all without the third-party `regex` package) — scoped to the one script actually asked for.
# Not a strict RFC validator — real injection protection is the argv-list barrier (subprocess
# calls take a list, never a shell string), this only rejects shapes that couldn't be a
# legitimate target/URL in the first place.
_TARGET_SHAPE_PATTERN = re.compile(r"^[A-Za-z0-9.\-:_/?=&%\[\]Ѐ-ӿԀ-ԯ]+$")
# Same allowlist as above, plus "*" — only for validate_scope_entry() below, never validate_target()
# itself (a real tool dispatch must keep rejecting a literal "*" outright; this is exclusively for
# the New Project form's own scope field, which is matched against, never sent to a subprocess/HTTP
# call as-is).
_WILDCARD_TARGET_SHAPE_PATTERN = re.compile(r"^[A-Za-z0-9.\-:_/?=&%\[\]*Ѐ-ӿԀ-ԯ]+$")


def validate_safe_value(value: str) -> str:
    """Rejects control characters, newlines, and null bytes in a single argv token."""
    if _CONTROL_CHAR_PATTERN.search(value):
        raise ValueError(f"Value contains control/newline/null characters: {value!r}")
    return value


def to_ascii_hostname(hostname: str) -> str:
    """Punycode/IDNA form of a bare (non-URL) hostname -- confirmed live that this matters, not
    just a theoretical concern: socket.getaddrinfo() raises EAI_NONAME on a raw Cyrillic hostname
    like "банк.рф" (glibc's resolver needs the wire-format ASCII label, not the Unicode display
    form), while the exact same domain resolves correctly once converted here first. Only for a
    BARE hostname/domain string (dns_lookup's own "domain" param) -- never a full URL, since the
    stdlib "idna" codec has no concept of scheme/path and would mangle one if given it whole; a URL
    target doesn't need this at all, httpx (agent/tools/native.py's http_request) already applies
    the equivalent conversion itself when it actually sends a request. An already-ASCII hostname
    passes through unchanged (str.isascii() short-circuit), so this is always safe to call
    regardless of whether the input needed conversion in the first place. Falls back to the
    original string on a genuinely malformed label (UnicodeError) rather than raising -- letting
    the real DNS lookup's own error surface normally is more useful than a confusing encode failure
    on top of it.
    """
    if hostname.isascii():
        return hostname
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def strip_flag_with_value(extra_args: list[str], flag_prefixes: tuple[str, ...]) -> list[str]:
    """Drops a model-supplied flag (matching one of flag_prefixes exactly) AND the value token
    right after it from extra_args -- for a builder that always places its own target flag
    unconditionally (nikto's -host, ffuf's -u), so a model-supplied duplicate of that same flag
    can't survive into the real command. Same fix class already applied to wpscan's --url/-u and
    whatweb's aggression/user-agent dedup (both of which only skip ADDING their own default when
    already present); this one is for builders with no "already present" branch to skip at all,
    where the duplicate has to be actively removed instead. A trailing flag with no following
    value (a model mistake on its own) is dropped by itself, not left dangling.
    """
    cleaned: list[str] = []
    skip_next = False
    for arg in extra_args:
        if skip_next:
            skip_next = False
            continue
        if arg in flag_prefixes:
            skip_next = True
            continue
        cleaned.append(arg)
    return cleaned


def validate_header_pair(name: str, value: str) -> tuple[str, str]:
    """Same control/newline/null-byte barrier as validate_safe_value, applied to both halves of a
    single HTTP header (agent/core.py's _parse_custom_headers -- the New Project form's "Custom
    HTTP Headers" field) before it reaches any tool's own header flag."""
    return validate_safe_value(str(name).strip()), validate_safe_value(str(value).strip())


def validate_target(target: str) -> str:
    """Validates a target string is a plausible hostname/IP/URL token, free of injection characters."""
    # Tool-calling models frequently send a single-item JSON array instead of a bare string
    # for a "target" argument (the same shape mismatch already handled for nuclei's tags) —
    # accepting it here avoids a hard crash (AttributeError on .strip()) that silently drops
    # that tool call's result for the rest of the phase.
    if isinstance(target, list):
        target = target[0] if target else ""
    target = str(target).strip()
    if not target:
        raise ValueError("Target must not be empty.")

    validate_safe_value(target)

    if not _TARGET_SHAPE_PATTERN.match(target):
        raise ValueError(f"Target does not look like a hostname/IP/URL: {target!r}")

    return target


_SCHEME_PREFIXED_WILDCARD_PATTERN = re.compile(r"^https?://\*\.", re.IGNORECASE)

# Matches one non-nested "(...)" group at a time -- deliberately excludes "(" and ")" from the
# captured content (not just "does not contain another full group") so a genuinely malformed/
# unbalanced paren in free text (e.g. an Out-of-scope note like "example.com (see notes)") never
# gets swallowed into a neighboring group by accident; it just falls through as literal text.
_ALTERNATION_GROUP_PATTERN = re.compile(r"\(([^()]*)\)")
# A single scope-table entry realistically expands to at most a few dozen TLDs/subdomains, not
# thousands -- caps a pathological paste (e.g. several multi-option groups multiplied together)
# from silently generating an enormous target list the rest of the pipeline never expected.
_MAX_ALTERNATION_EXPANSIONS = 500


def expand_target_alternation(target: str) -> list[str]:
    """Expands a bug-bounty-style pipe-alternation scope entry -- e.g.
    "https://www.vidaxl.(at|be|bg|com|de|...)" (one company, one domain, every ccTLD it operates
    under -- a real, commonly-seen scope-table shape, not hypothetical) -- into one concrete target
    per alternative. Returns [target] unchanged when no "(a|b)" group is present at all, the
    overwhelmingly common case of a plain host/URL with no parens.

    More than one group in the same entry (e.g. "(www|shop).example.(com|de)") is cartesian-
    producted across all of them, not just the first. A parenthesized segment with no "|" inside
    (e.g. a stray "(see notes)" in a free-text Out-of-scope entry) is left exactly as it was,
    parens included -- it isn't an alternation, so it must not be torn apart or dropped.

    Must run BEFORE validate_scope_entry()/validate_target() on each result, never instead of it --
    this only reshapes the input into concrete candidates, none of the real shape/injection
    validation happens here, and the "(" "|" ")" characters themselves must never reach a real
    tool call.
    """
    segments = _ALTERNATION_GROUP_PATTERN.split(target)
    if len(segments) == 1:
        return [target]

    literals = segments[0::2]
    raw_groups = segments[1::2]
    options_per_group: list[list[str]] = []
    for group in raw_groups:
        if "|" in group:
            options_per_group.append(group.split("|"))
        else:
            options_per_group.append([f"({group})"])

    total = 1
    for options in options_per_group:
        total *= len(options)
    if total > _MAX_ALTERNATION_EXPANSIONS:
        raise ValueError(
            f"Target alternation expands to too many combinations (>{_MAX_ALTERNATION_EXPANSIONS}): {target!r}"
        )

    expanded = []
    for combo in itertools.product(*options_per_group):
        pieces = [literals[0]]
        for value, literal in zip(combo, literals[1:]):
            pieces.append(value)
            pieces.append(literal)
        expanded.append("".join(pieces))
    return expanded


def validate_scope_entry(value: str) -> str:
    """Same shape check as validate_target(), plus tolerance for a "*" wildcard anywhere in the
    hostname — bug-bounty scope tables use this in several real, commonly-seen shapes, not just
    one:
      - "*.example.com": the whole subdomain tree is in scope (the original, most common form).
      - "prod-*.example.com": a wildcard filling out part of one specific label (matches
        prod-us1.example.com, prod-eu2.example.com, ...).
      - "*-eu.example.com": a wildcard as a label's own prefix (matches api-eu.example.com,
        web-eu.example.com, ...).
    Only the New Project form's scope field should ever see this (a real tool call still goes
    through plain validate_target(), which must keep rejecting "*" outright — nothing downstream
    may pass a literal wildcard to a subprocess/HTTP call). The wildcard is preserved verbatim on
    the returned value so the rest of the pipeline (recon prompt, allowlist matching —
    allowed_targets.py's _matches_scope_entries) can act on it deliberately instead of it silently
    vanishing into a plain hostname.

    A scope table just as commonly writes the leading form as "https://*.example.com" or
    "http://*.example.com" (a real, seen-in-the-wild variant, not hypothetical) — the scheme
    carries no extra meaning for a whole-subdomain-tree scope (recon discovers both HTTP and HTTPS
    on whatever it finds regardless), so it's stripped here rather than taught to every downstream
    consumer of the "*." marker (agent/core.py's _has_wildcard_scope, allowed_targets.py's
    is_target_allowed, RECON_PROMPT) — they all keep expecting exactly the bare "*.example.com"
    form they already handle, this is the one normalization point.

    A CIDR block ("10.0.0.0/24") or an explicit "start - end" IP-range ("192.168.1.1 -
    192.168.1.254", a common scope-table format for a pool of addresses) is recognized here too —
    canonicalized to a whitespace-free form (allowed_targets.parse_ip_range_or_cidr) that still
    passes the shape check below on its own, and matched for real (not just accepted as a shape)
    by allowed_targets.py's _matches_scope_entries.
    """
    if not isinstance(value, str):
        return validate_target(value)
    stripped = value.strip()

    ip_block = parse_ip_range_or_cidr(stripped)
    if ip_block is not None:
        return ip_block

    stripped = _SCHEME_PREFIXED_WILDCARD_PATTERN.sub("*.", stripped)
    if "*" not in stripped:
        return validate_target(value)

    validate_safe_value(stripped)
    if not _WILDCARD_TARGET_SHAPE_PATTERN.match(stripped):
        raise ValueError(f"Target does not look like a hostname/IP/URL: {stripped!r}")
    return stripped


def classify_target_type(value: str) -> str:
    """Informational-only classification (UI label, never a validation/routing decision) of one
    already-validated target/scope entry into "ip" | "subnet" | "wildcard" | "url" | "domain" |
    "host". Deliberately does not distinguish a bracketed IPv6 literal with an explicit port
    (`[::1]:8443`) or a domain with a port (`example.com:8443`) from a plain host/domain -- both
    fall through to "host"/"domain" respectively, which is an acceptable minor mislabel for a
    display-only chip, not worth a heavier parser. Piligrim's own "Repo"/"Code" target types are
    deliberately absent -- they don't apply to ASRA's network-scan target model (RE mode's local
    file targets are a separate flow with no comparable type concept today).
    """
    stripped = (value or "").strip()
    if parse_ip_range_or_cidr(stripped) is not None:
        return "subnet"
    try:
        ipaddress.ip_address(stripped.strip("[]"))
        return "ip"
    except ValueError:
        pass
    if "*" in stripped:
        return "wildcard"
    if "://" in stripped or "/" in stripped:
        return "url"
    if "." in stripped:
        return "domain"
    return "host"
