"""build_command() and output parser for WPScan — WordPress core/plugin/theme version enumeration.

Only ever reachable once agent/core.py's wpscan gate has let the call through (a real WordPress
detection already exists for this host, from WhatWeb — see agent/tools/builders/whatweb.py) —
this module itself has no opinion on that, it just builds/parses the command.
"""
from __future__ import annotations

import re

from agent.tools.builders.validators import validate_header_pair, validate_safe_value, validate_target

_WP_VERSION_PATTERN = re.compile(r"WordPress version ([\d.]+)")
_PLUGIN_NAME_PATTERN = re.compile(r"^\[\+\]\s+([a-z0-9][a-z0-9_\-]+)$", re.IGNORECASE)
_PLUGIN_VERSION_PATTERN = re.compile(r"^\s*\|\s*Version:\s*([\d.]+)")


def interpret_wpscan_timeout(result: dict) -> str | None:
    """Two distinct, confirmed-live causes for a WPScan timeout, each needing its own specific
    correction -- a generic "it timed out, try again" leaves the model re-sending the exact same
    slow command, wasting a full second timeout budget for zero new information:

    1. --plugins-detection aggressive (the model's own choice via extra_args -- never this
       builder's default) brute-forces the full plugin signature database, often thousands of
       requests -- against a WAF/CDN-fronted target this routinely exceeds the subprocess timeout
       outright. Confirmed live: the same call, and its own near-identical 1-Step Retry, both timed
       out with the exact same aggressive flag.
    2. --update (this builder's own default, see _UPDATE_FLAGS below) makes WPScan refresh its
       local vulnerability database before scanning, in the same invocation -- confirmed live
       twice in one real session, each burning the entire subprocess timeout on the database
       update alone, without ever reaching the actual scan. Retrying with --update still set
       will very likely time out the same way again.

    None for any status other than a genuine timeout (a real error needs its own real message,
    not this hint bolted on regardless of cause).
    """
    if result.get("status") != "timeout":
        return None
    command = result.get("command") or []
    if "aggressive" in command:
        return (
            "WPScan timed out with --plugins-detection aggressive -- that mode brute-forces "
            "the full plugin signature database (often thousands of requests) and routinely exceeds "
            "this budget against a WAF/CDN-fronted target. Retrying with the identical aggressive flag "
            "will very likely time out the same way again. Drop --plugins-detection entirely (WPScan's "
            "own default, passive mode, is far faster and still confirms the WordPress core version) "
            "or use --plugins-detection mixed for a lighter, faster plugin sweep."
        )
    if "--update" in command:
        return (
            "WPScan timed out while --update was set (this tool's own default -- refreshes the "
            "local vulnerability database before scanning, in the same invocation) -- that database "
            "update alone can consume the entire timeout budget on a first run or slow connection, "
            "leaving zero time for the actual scan. Retrying with --update still set will very "
            "likely time out the same way again with no new information. Add --no-update to this "
            "retry (extra_args) to scan immediately against whatever database is already present, "
            "trading database freshness for actually getting results this run."
        )
    return None


# Real, confirmed incident this fixes: extra_args carrying the short alias "-u" (WPScan accepts
# both --url and -u for the same option, confirmed against its own --help) wasn't recognized by
# this dedup check -- the executed command ended up with the target TWICE ("--url X -u X"),
# which WPScan rejects outright ("url option must be unique"), exit_code=1, no useful stdout.
_URL_FLAG_PREFIXES = ("--url", "-u")
_UPDATE_FLAGS = ("--update", "--no-update")


def build_wpscan_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    extra_args = [validate_safe_value(str(arg)) for arg in params.get("extra_args", [])]
    # Real, confirmed incident this fixes: extra_args also carrying "--url" duplicated the flag
    # ("--url X --url X") in the real executed command four separate times -- same class of bug
    # already fixed for whatweb's own aggression/user-agent/target dedup (build_whatweb_command),
    # just never applied here. An explicit model choice has to win outright, not get silently
    # doubled up with this builder's own default.
    command = ["wpscan", "--no-banner"]
    if not any(arg in _URL_FLAG_PREFIXES for arg in extra_args):
        command += ["--url", target]
    # Real, confirmed incident this fixes: WPScan's local vulnerability database going stale makes
    # it print "It seems like you have not updated the database for some time. Do you want to
    # update now? [Y]es [N]o, default: [N]" and block reading an answer from stdin -- confirmed
    # live to eat ~9 real minutes (nearly the entire 600s subprocess timeout) before the outer
    # timeout finally killed it, reading to the operator as the whole session silently stuck for
    # no visible reason. agent/tools/runner.py's stdin=DEVNULL fix means this can no longer HANG
    # (an EOF answer defaults to "No" immediately) -- but that still leaves every scan running
    # against a database that might be missing recently-disclosed vulnerabilities. --update
    # (confirmed live: runs the update non-interactively, then proceeds straight into the actual
    # scan in the SAME invocation, no separate step) is a better default than --no-update for
    # that reason -- always keep results as accurate as possible rather than just suppressing the
    # question. Skipped when the model already picked a choice itself (either flag), same
    # "explicit model choice wins outright" discipline as every other builder default in this file.
    if not any(arg in _UPDATE_FLAGS for arg in extra_args):
        command.append("--update")
    command += extra_args
    # Server-side injected by agent/core.py's _run_tool_with_retry (New Project form's Custom
    # User-Agent + Custom HTTP Headers fields) — never part of this tool's own params schema, so
    # never model-supplied. WPScan's own --headers takes exactly one flag occurrence, multiple
    # headers separated by "; " inside that one string (confirmed against its own docs, e.g.
    # "X-Forwarded-For: 127.0.0.1; Another: aaa"), not a repeated flag.
    user_agent = params.get("_user_agent")
    if user_agent:
        command += ["--user-agent", validate_safe_value(user_agent)]
    extra_headers = params.get("_extra_headers") or {}
    if extra_headers:
        pairs = [validate_header_pair(name, value) for name, value in extra_headers.items()]
        command += ["--headers", "; ".join(f"{name}: {value}" for name, value in pairs)]
    # Settings -> Tool API Keys (agent/tools/tool_api_keys.py) -- server-side injected exactly like
    # _user_agent/_extra_headers above, never part of this tool's own params schema, so never
    # model-supplied. Unlocks WPScan's vulnerability-database cross-reference (core/plugin/theme
    # versions still get enumerated without it). Skipped when the model already passed its own
    # --api-token, same "explicit model choice wins outright" rule the --url/--update dedup above
    # follows -- extra_args is never populated with the real key anyway, but a duplicate --api-token
    # would still make WPScan reject the call outright ("api-token option must be unique").
    api_key = params.get("_api_key")
    if api_key and "--api-token" not in extra_args:
        command += ["--api-token", validate_safe_value(api_key)]
    return command


def parse_wpscan_output(stdout: str) -> dict:
    """Extracts the confirmed WordPress core version and any enumerated plugin name+version
    pairs from WPScan's real CLI text output. A plugin header line looks like "[+] contact-form-7"
    followed by "| Version: 5.4 (80% confidence)" a few lines below it — matched here as a
    name/version pair, not a guess.
    """
    wp_version_match = _WP_VERSION_PATTERN.search(stdout)
    wordpress_version = wp_version_match.group(1) if wp_version_match else None

    plugins = []
    current_name: str | None = None
    for line in stdout.splitlines():
        name_match = _PLUGIN_NAME_PATTERN.match(line.strip())
        if name_match:
            current_name = name_match.group(1)
            continue
        version_match = _PLUGIN_VERSION_PATTERN.match(line)
        if version_match and current_name:
            plugins.append({"name": current_name, "version": version_match.group(1)})
            current_name = None

    return {"wordpress_version": wordpress_version, "plugins": plugins}
