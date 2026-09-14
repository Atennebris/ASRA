"""build_command() and output parser for Nuclei."""
from __future__ import annotations

import json

from agent.tools.builders.validators import validate_header_pair, validate_safe_value, validate_target
from agent.tools.nuclei_template_packs import installed_template_args, recon_triggered_tags, update_template_dir_args

# An earlier plan called for tags "exploits,vulnerabilities,cves" — those tags don't exist
# in Nuclei's real taxonomy (confirmed against an actual template run: 0 templates matched, hard
# failure "no templates provided for scan"). Real, populated active-check tags used instead — each
# one below re-verified live (nuclei -tl -tags <tag>) to actually have real templates before being
# added, same discipline. takeover/default-login/xss/ssrf added on top of the original set because
# they're exactly the classes an automated agent CAN confirm directly (remote_direct, no victim or
# MITM position needed) — a dangling CNAME, a working default login, a firing XSS payload, or a
# real OOB SSRF hit are all real proof, unlike the hygiene-class findings (missing headers, TLS
# config) nuclei's original tag set mostly surfaces instead. waf-detect added the same way, same
# discipline (re-verified live: exactly one real template under it, http/global-matchers/
# global-waf-detect.yaml) -- unlike every other tag here it isn't a vulnerability class, it's what
# lets a WAF/CDN protecting a host get identified BY NAME (its match's own "matcher-name" field,
# e.g. "cloudflare"/"fortigate"/"zscaler") instead of only ever showing up as an unlabeled
# "technology" token or a wall of blocked/403 responses nobody explained. See agent/core.py's
# _merge_protection_detection for where that match actually gets turned into recon_result
# ["protections"].
_DEFAULT_TAGS = "cve,vuln,exposure,rce,misconfig,takeover,default-login,xss,ssrf,waf-detect"

_NO_TEMPLATES_MARKER = "no templates provided for scan"


def interpret_nuclei_failure(result: dict) -> str | None:
    """Nuclei's own failure message for an invalid -tags value ("Could not run nuclei: no
    templates provided for scan") gives the model nothing to work with beyond a raw ANSI-colored
    banner -- confirmed live: a session guessed at 6+ plausible-sounding-but-nonexistent tag
    combinations (e.g. "cookies-without-httponly,cookies-without-secure", "cookie-security") across
    many separate 1-Step Retry round-trips before stumbling onto one that happened to work. Real
    nuclei tags are almost always a single generic word (a template's own "tags:" YAML field), not
    a descriptive compound phrase -- this steers the model there instead of more blind guessing.
    None when the failure isn't this specific one (a real target/network error still needs its own
    real message, not this hint bolted on regardless of cause).
    """
    stderr = result.get("stderr") or ""
    if _NO_TEMPLATES_MARKER not in stderr:
        return None
    return (
        "0 templates matched -- nuclei's -tags value must exactly match a real template's own tag, "
        "not a descriptive phrase you invent. Real tags are almost always one simple, generic word "
        "(e.g. \"cookie\", \"tls\", \"redirect\", \"cors\"), never a compound phrase like "
        f"\"cookies-without-httponly\". Already-verified real tags for this project: {_DEFAULT_TAGS}. "
        "For anything else, try ONE simple generic word for that specific check, not several "
        "combined into one made-up tag."
    )


def build_nuclei_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    tags = params.get("tags", _DEFAULT_TAGS)
    # The schema asks for a comma-separated string, but tool-calling models frequently send a
    # JSON array of tags instead (a very natural way to represent "multiple tags") — accepting
    # both avoids burning a full retry round-trip on a shape mismatch that isn't a real error.
    if isinstance(tags, list):
        tags = ",".join(str(tag) for tag in tags)
    tags = validate_safe_value(tags)
    # -silent: banner/progress ("[INF] Templates loaded...", version info) goes to stderr by
    # default, not stdout -- confirmed live, it's tiny (under 1KB) and already captured separately
    # in result["stderr"], so -silent isn't the fix for a huge stdout. -omit-raw is: nuclei embeds
    # a full request/response pair in EVERY JSONL match by default (-include-rr, deprecated but
    # still the live default), and parse_nuclei_output below never reads either field -- only
    # template_id/name/severity/matched_at. Real incident this fixes: two real nuclei calls in one
    # session (two regional subdomains of the same target, both behind a WAF that made many templates "match" its generic
    # challenge page) returned 2.27MB/1.73MB of raw stdout each, dominated by embedded
    # request/response bodies never used downstream -- confirmed live against an approved test
    # target (ginandjuice.shop, full default tag set): -omit-raw cut identical-match output from
    # 278KB to 39KB, a ~7x reduction, with the exact same set of matched template-ids.
    command = ["nuclei", "-u", target, "-jsonl", "-silent", "-omit-raw"]
    # Always pinned to a fixed, ASRA-controlled directory (agent/tools/nuclei_template_packs.py),
    # never left at nuclei's own $HOME-relative default -- the desktop launcher's "Run the agent as
    # root" toggle means this same project runs as different OS users across launches,
    # and Path.home() silently differs between them. Without this, official templates
    # AND the github/<repo> shorthand below would each resolve against whichever user happened to
    # launch THIS run, invisibly diverging from a previous run's own template state.
    command += update_template_dir_args()
    # A heavy pack (e.g. wordfence-cve) activates on the tags the model explicitly asked for, PLUS
    # whatever real recon evidence already exists for this exact target (recon_triggered_tags reads
    # recon_result["technologies"][target] -- e.g. a literal "WordPress" WhatWeb token) -- so a scan
    # doesn't silently skip an actually-relevant pack just because the model didn't think to name it.
    # This only widens which packs get INCLUDED in -t below, never the model's own -tags filter
    # (still exactly `tags`, unmodified) -- recon evidence unlocks availability, it doesn't override
    # what the model actually chose to run.
    gating_tags = tags
    session = params.get("_session")
    if session is not None:
        recon_tags = recon_triggered_tags(session, target)
        if recon_tags:
            gating_tags = ",".join(filter(None, [tags, *sorted(recon_tags)]))
    # Empty unless the operator installed extra template packs from the Tools tab AND (for a heavy
    # pack) gating_tags actually trigger it -- omitting -t entirely here (the default) is byte-
    # identical to this project's nuclei behavior before that module existed.
    command += installed_template_args(gating_tags)
    command += ["-tags", tags]
    # Server-side injected by agent/core.py's _run_tool_with_retry (New Project form's Custom
    # User-Agent + Custom HTTP Headers fields) — never part of this tool's own params schema, so
    # never model-supplied. Nuclei's own -H is a real repeatable flag, one occurrence per header.
    user_agent = params.get("_user_agent")
    if user_agent:
        command += ["-H", f"User-Agent: {validate_safe_value(user_agent)}"]
    for name, value in (params.get("_extra_headers") or {}).items():
        name, value = validate_header_pair(name, value)
        command += ["-H", f"{name}: {value}"]
    return command


def parse_nuclei_output(stdout: str) -> list[dict]:
    """Extracts findings from Nuclei's -jsonl output (one JSON object per line)."""
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = record.get("info", {})
        findings.append(
            {
                "template_id": record.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": record.get("matched-at") or record.get("host"),
                # Only ever populated for a global-matchers template (global-waf-detect is the one
                # real case in this project's own tag set) -- nuclei's own per-matcher label (e.g.
                # "cloudflare"/"fortigate"), the actual product name a template-id/name pair alone
                # can't give (those two are the same generic "Global WAF Detect Matchers" string
                # for every WAF it can recognize). None for every other, non-global-matcher template.
                "matcher_name": record.get("matcher-name"),
            }
        )
    return findings
