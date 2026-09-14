"""build_command() and output parser for Dalfox (github.com/hahwul/dalfox) — the one tool in this
registry that actually confirms XSS execution instead of just reflection-text matching. Real
incident this exists because of: the only XSS signal available before this was nuclei's reflected-
payload-in-response-text check, which cannot tell "the payload text is in the HTML" apart from
"the payload actually ran as JavaScript" — the difference between a maybe and a screenshot of
alert(). type_by_code below maps Dalfox's own three-way classification (verified DOM execution,
reflected-only, or AST-detected DOM sink) onto that exact distinction.
"""
from __future__ import annotations

import json

from agent.tools.builders.validators import validate_header_pair, validate_safe_value, validate_target

# Dalfox's own finding "type" field, one letter, lowercased by parse_dalfox_output below.
# v = payload confirmed executed in a real parsed DOM (headless-browser-grade proof, the
#     strongest evidence this registry can produce for XSS at all).
# r = payload reflected in the raw response text, execution not independently confirmed —
#     exactly the old nuclei-only signal, now explicitly labeled as the weaker one instead of
#     being indistinguishable from a verified hit.
# a = found via static AST analysis of same-origin JavaScript — a real DOM-XSS source/sink pair,
#     not a runtime confirmation, but a different (and often more actionable) class of evidence
#     than a request/response reflection.
_XSS_TYPE_BY_CODE = {"v": "verified_dom_execution", "r": "reflected_unconfirmed", "a": "dom_based_ast"}


def build_dalfox_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    command = ["dalfox", "scan", target, "-f", "json", "--silence"]

    # Stored XSS needs a genuinely different scan mode (submit the payload at `target`, then
    # re-check a DIFFERENT url for it to fire) — not just a flag on top of the normal reflected/
    # DOM scan, which only ever looks at the immediate response to its own request.
    if params.get("mode") == "stored":
        command.append("--sxss")
        sxss_url = params.get("sxss_url")
        if sxss_url:
            command += ["--sxss-url", validate_target(sxss_url)]

    param_names = params.get("param")
    if param_names:
        if isinstance(param_names, str):
            param_names = [param_names]
        for name in param_names:
            command += ["-p", validate_safe_value(str(name))]

    cookie = params.get("cookie")
    if cookie:
        command += ["--cookies", validate_safe_value(cookie)]

    # Server-side injected by agent/core.py's _run_tool_with_retry (New Project form's Custom
    # User-Agent + Custom HTTP Headers fields) — never part of this tool's own params schema, so
    # never model-supplied. Dalfox's own -H is a real repeatable stringArray flag, one occurrence
    # per header (confirmed against its own usage docs).
    user_agent = params.get("_user_agent")
    if user_agent:
        command += ["--user-agent", validate_safe_value(user_agent)]
    for name, value in (params.get("_extra_headers") or {}).items():
        name, value = validate_header_pair(name, value)
        command += ["-H", f"{name}: {value}"]

    return command


def parse_dalfox_output(stdout: str) -> list[dict]:
    """Extracts findings from Dalfox's -f json output — one JSON object (not JSONL like nuclei),
    findings under the top-level "findings" key, confirmed live against a real scan."""
    try:
        record = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    findings = []
    for item in record.get("findings", []):
        type_code = str(item.get("type", "")).lower()
        findings.append(
            {
                "xss_type": _XSS_TYPE_BY_CODE.get(type_code, item.get("type")),
                "severity": item.get("severity"),
                "param": item.get("param"),
                "payload": item.get("payload"),
                "poc_url": item.get("data"),
                "evidence": item.get("evidence"),
                "inject_type": item.get("inject_type"),
                "cwe": item.get("cwe"),
            }
        )
    return findings
