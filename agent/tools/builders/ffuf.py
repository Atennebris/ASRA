"""build_command() and output parser for ffuf (github.com/ffuf/ffuf) — content/endpoint discovery.

Real gap this closes: nothing in this registry actively brute-forces hidden paths with a real
wordlist. common_exposure_scan only checks a short fixed list of known-sensitive files,
authenticated_crawl only finds what's already linked in HTML/forms, js_bundle_scan only finds
endpoint-shaped strings already embedded in JS. None of them can ever surface an unlinked backup
file, a forgotten debug endpoint, or an old API version with a non-guessable name — exactly the
class of finding real directory fuzzing exists for.
"""
from __future__ import annotations

import json
import os
from collections import Counter

from agent.tools.builders.validators import (
    strip_flag_with_value,
    validate_header_pair,
    validate_safe_value,
    validate_target,
)
from agent.tools.wordlist_store import get_assigned_wordlist

# A single, modest, always-installed wordlist (setup_tools.sh's install_ffuf_wordlist) -- not the
# same as the opt-in rockyou.txt/full-SecLists set (install_large_wordlists), which is sized for
# password guessing, not path discovery, and gated behind an explicit flag. ffuf is useless with no
# wordlist at all, so this one ships unconditionally; env-overridable for a bigger/custom list
# without touching code, same reasoning as every other path/timeout knob in this project.
_DEFAULT_WORDLIST_ENV = "FFUF_WORDLIST_PATH"
_DEFAULT_WORDLIST_PATH = "/usr/share/wordlists/ffuf/common.txt"

# ffuf's own reaction to a -w path it can't open is to print its ENTIRE help/usage text (~7KB,
# every flag it supports) to stdout and exit 1 -- no "wordlist not found" message anywhere in it.
# Confirmed live: a session guessed 4 different plausible-sounding-but-not-actually-installed
# wordlist paths (SecLists/dirb paths that exist on a full Kali install but not in this project's
# own WSL provisioning, see setup_tools.sh's install_ffuf_wordlist) across 7 wasted 1-Step Retry
# round-trips before stumbling onto the one path that's actually guaranteed to exist. Same
# "low-signal tool failure" pattern as nuclei's interpret_nuclei_failure right above this file's
# sibling module -- this marker is stable across ffuf versions since it's a literal section header
# from the help text itself, not something tied to one specific version string.
_USAGE_DUMP_MARKER = "HTTP OPTIONS:"


def interpret_ffuf_failure(result: dict) -> str | None:
    """None when the failure isn't this specific one (a real network/target error still needs its
    own real message, not this hint bolted on regardless of cause)."""
    stdout = result.get("stdout") or ""
    if _USAGE_DUMP_MARKER not in stdout:
        return None
    return (
        f"ffuf couldn't open the wordlist file (it printed its full help text instead of a clear "
        f"error) -- the 'wordlist' path you gave almost certainly doesn't exist in this "
        f"environment. Only {_DEFAULT_WORDLIST_PATH} is guaranteed to be installed here; omit the "
        f"'wordlist' argument entirely to use it, rather than guessing another SecLists/dirb-style "
        f"path that may not be provisioned on this machine."
    )

# Broad enough to catch real hidden content (401/403 on an admin path is itself a signal, not
# noise) without matching literally everything -- 404 is deliberately excluded, that's the "not
# found" case ffuf's wordlist run produces thousands of times per scan.
_DEFAULT_MATCH_CODES = "200,204,301,302,307,401,403,405,500"
# Real, unrelated incident this mirrors (nikto's build_nikto_command): a wordlist run against a
# slow target can run well past this project's own TOOL_TIMEOUT_SECONDS, and the subprocess
# runner's hard kill on timeout loses every result ffuf had already found, not just the ones it
# hadn't reached yet. -maxtime makes ffuf wrap up and print whatever it has before that kill lands.
_TIMEOUT_SAFETY_MARGIN_SECONDS = 30
_MIN_MAXTIME_SECONDS = 30
_DEFAULT_EXTERNAL_TIMEOUT_SECONDS = 120
# Moderate concurrency, not a DoS-shaped hammering -- this project already treats "more than a
# handful of concurrent requests" as a DoS risk bounty programs explicitly exclude (see
# EXPLOIT_PROMPT's race-condition guidance, capped at 2-10). Directory fuzzing is a different
# shape of traffic (one request per candidate path, not concurrent hits on the same endpoint) but
# still deserves a sane, non-aggressive default rather than ffuf's own out-of-the-box maximum.
_DEFAULT_THREADS = 40
# See build_ffuf_command's own -ac default below for why this list exists.
_FILTER_FLAG_PREFIXES = ("-ac", "-fc", "-fs", "-fw", "-fl", "-fr", "-fmode")
# ffuf's own -u is its only target flag (confirmed against its own --help, no long-form alias).
# This builder always places -u itself unconditionally below, so a model-supplied duplicate via
# extra_args has to be stripped, not just detected -- same "duplicate target flag" bug class
# already confirmed live for wpscan's --url/-u.
_URL_FLAG_PREFIXES = ("-u",)

# Backstop for parse_ffuf_output's own WAF-flood collapse below, independent of whether -ac's own
# runtime calibration actually worked for a given target -- see _collapse_dominant_response_shape's
# own docstring for the real incident this closes.
_WAF_FLOOD_MIN_HITS = 20
_WAF_FLOOD_DOMINANT_FRACTION = 0.9


def build_ffuf_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    if "FUZZ" not in target:
        # The model naturally supplies a bare URL ("https://example.com/api") far more often than
        # one with the FUZZ marker already placed -- appending it to a trailing-slash-normalized
        # path is the common case (directory/endpoint discovery under this path), same tolerance
        # nuclei's tags-as-list handling already extends to a natural-but-not-exact input shape.
        target = target.rstrip("/") + "/FUZZ"

    # Precedence: an explicit model-supplied wordlist always wins (it may have picked one for a
    # deliberate reason) -- otherwise the operator's own Settings-UI assignment (agent/tools/
    # wordlist_store.py), then the env override, then the small always-installed default.
    wordlist = validate_safe_value(str(
        params.get("wordlist") or get_assigned_wordlist("ffuf") or os.getenv(_DEFAULT_WORDLIST_ENV, _DEFAULT_WORDLIST_PATH)
    ))
    match_codes = validate_safe_value(str(params.get("match_status_codes") or _DEFAULT_MATCH_CODES))
    threads = int(params.get("threads") or _DEFAULT_THREADS)
    extra_args = strip_flag_with_value(
        [validate_safe_value(str(arg)) for arg in params.get("extra_args", [])], _URL_FLAG_PREFIXES
    )

    command = ["ffuf", "-u", target, "-w", wordlist, "-mc", match_codes, "-t", str(threads), "-of", "json", "-o", "/dev/stdout", "-s"]

    extensions = params.get("extensions")
    if extensions:
        if isinstance(extensions, str):
            extensions = [extensions]
        command += ["-e", ",".join(validate_safe_value(str(ext)) for ext in extensions)]

    # Never added when the model already picked its own -maxtime via extra_args -- ffuf doesn't
    # reliably merge two occurrences of the same flag, same reasoning as nikto's build_command.
    if not any(arg.startswith("-maxtime") for arg in extra_args):
        configured_timeout = int(os.getenv("TOOL_TIMEOUT_SECONDS", str(_DEFAULT_EXTERNAL_TIMEOUT_SECONDS)))
        maxtime_seconds = max(configured_timeout - _TIMEOUT_SAFETY_MARGIN_SECONDS, _MIN_MAXTIME_SECONDS)
        command += ["-maxtime", str(maxtime_seconds)]

    # ffuf's own auto-calibration probes a few random non-existent paths first and derives a
    # filter from their shared response shape (size/words/lines) -- without it, a WAF/catch-all-403
    # host burns this tool's FULL -maxtime budget producing thousands of near-identical "hits"
    # instead of the handful of real ones. Real, confirmed incident this fixes: a real scan ran its
    # complete 570s -maxtime budget producing a 532KB+ dump of catch-all 403s, even though the
    # model's own reasoning mid-scan had already recognized "drowning in identical catch-all 403s"
    # -- there was no flag telling ffuf to filter them out on its own. Never added when the model
    # already picked its own filtering (-ac itself, or any of -fc/-fs/-fw/-fl/-fr/-fmode) -- an
    # explicit model choice has to win outright, not get silently doubled up with this default,
    # same discipline as every other builder default in this file.
    if not any(arg.startswith(_FILTER_FLAG_PREFIXES) for arg in extra_args):
        command.append("-ac")

    command += extra_args

    # Server-side injected by agent/core.py's _run_tool_with_retry (New Project form's Custom
    # User-Agent + Custom HTTP Headers fields) — never part of this tool's own params schema, so
    # never model-supplied. ffuf's own -H is a real repeatable flag, one occurrence per header.
    user_agent = params.get("_user_agent")
    if user_agent:
        command += ["-H", f"User-Agent: {validate_safe_value(user_agent)}"]
    for name, value in (params.get("_extra_headers") or {}).items():
        name, value = validate_header_pair(name, value)
        command += ["-H", f"{name}: {value}"]

    return command


def parse_ffuf_output(stdout: str) -> list[dict]:
    """Extracts hits from ffuf's -of json output -- confirmed live against a real scan: even with
    -s and -o /dev/stdout, ffuf still writes its normal live per-match "found" notifications
    (plain hostname/path text, one per line) to stdout throughout the run; -s only suppresses the
    banner/progress bar, not those. The one line that's actually the full JSON report is written
    last, after every plain-text match line, so json.loads(stdout) on the whole blob reliably
    fails -- this scans from the end for that one line instead of trusting the whole stream to be
    JSON. The plain-text lines carry no information the JSON's own "results" array doesn't already
    have, so skipping them loses nothing.
    """
    record = None
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "results" in candidate:
            record = candidate
            break
    if record is None:
        return []

    hits = []
    for item in record.get("results", []):
        hits.append(
            {
                "url": item.get("url"),
                "path": (item.get("input") or {}).get("FUZZ"),
                "status": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
                "redirect_location": item.get("redirectlocation") or None,
            }
        )
    return _collapse_dominant_response_shape(hits)


def _collapse_dominant_response_shape(hits: list[dict]) -> list[dict]:
    """Backstop for a WAF/catch-all-block flood that build_ffuf_command's own -ac auto-calibration
    was specifically added to prevent (see that flag's own comment above) but doesn't always
    actually catch -- confirmed live (a real YesWeHack session, usr_45dd32): a real scan against a
    Cloudflare-fronted host returned 9,570 of 9,570 "hits", every single one status=403 with the
    IDENTICAL (length, words, lines) shape -- one uniform block page for every fuzzed word, zero
    real signal, -ac present in the executed command but evidently unable to establish a working
    filter against this specific target. The most likely mechanism: -mc's own default explicitly
    includes 403/401/405/500 as "interesting" (deliberately, since a real admin path returning 401/
    403 IS itself a signal) -- exactly the status codes a WAF's own block page commonly also
    returns, so -ac's derived filter and -mc's own match list can end up fighting over the same
    status code with no guarantee -ac wins for every target/ffuf-version combination.

    Rather than depend on understanding (or fixing) -ac's own runtime behavior for every possible
    WAF, this is a deterministic downstream backstop, same "synthesize signal instead of dumping
    raw noise" principle nuclei's own -omit-raw fix already applies one layer over: when an
    overwhelming majority of hits (_WAF_FLOOD_DOMINANT_FRACTION) share the exact same
    (status, length, words) shape, collapse them to ONE clearly-labeled summary entry instead of
    handing the model thousands of near-identical records. Every hit that DOESN'T match the
    dominant shape (the real signal, if any) is kept byte-for-byte unchanged -- this only ever
    removes duplicate noise, never a genuinely distinct result. Below _WAF_FLOOD_MIN_HITS this
    never fires at all -- a small, real batch of same-shaped hits (a site with a handful of
    identically-sized 404-alternative pages) is exactly the ambiguous case not worth collapsing.
    """
    if len(hits) < _WAF_FLOOD_MIN_HITS:
        return hits

    shape_counts = Counter((h["status"], h["length"], h["words"]) for h in hits)
    dominant_shape, dominant_count = shape_counts.most_common(1)[0]
    if dominant_count / len(hits) < _WAF_FLOOD_DOMINANT_FRACTION:
        return hits

    status, length, words = dominant_shape
    kept = [h for h in hits if (h["status"], h["length"], h["words"]) != dominant_shape]
    kept.append({
        "url": None, "path": None, "status": status, "length": length, "words": words,
        "redirect_location": None,
        "note": (
            f"{dominant_count} of {len(hits)} fuzzed paths returned an identical response "
            f"(status={status}, length={length}, words={words}) -- almost certainly a WAF/"
            "catch-all block page, not real content, and collapsed to this one summary entry. "
            "Do not treat this as a real finding."
        ),
    })
    return kept
