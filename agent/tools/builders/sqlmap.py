"""build_command() and output parser for sqlmap."""
from __future__ import annotations

import re

from agent.tools.builders.validators import validate_header_pair, validate_safe_value, validate_target

# Real sqlmap source (lib/controller/controller.py: _formatInjection/_showInjections) confirmed
# by reading the installed package: a confirmed injection is printed as "Parameter: <name> (<GET/
# POST/...>)" on its own line — it never actually says "is vulnerable" on that line. The original
# regex here (`Parameter:.*is vulnerable`) was based on a paraphrase, not the real tool's output,
# and would never have matched a genuine positive result. Found by re-deriving from source, then
# confirmed against a real detected injection on a local test target.
_VULNERABLE_PARAM_PATTERN = re.compile(r"^Parameter:\s+(?P<name>.+?)\s+\((?P<place>\w+)\)$", re.MULTILINE)
_DATABASE_LIST_PATTERN = re.compile(r"^\[\*\]\s+(\S+)$", re.MULTILINE)  # confirmed against lib/core/dump.py: lister()


def build_sqlmap_command(params: dict) -> list[str]:
    """First pass confirms the injection and lists databases (--dbs); a second call with
    dump_table/database can target a specific table (--dump) once a finding is confirmed —
    same one-attempt-per-finding rule as Metasploit, just two possible calls.
    """
    target = validate_target(params["target"])
    command = ["sqlmap", "-u", target, "--batch"]

    if params.get("data"):
        # POST body (e.g. JSON login payload) — not passed through validate_target's hostname/URL
        # shape check since it's arbitrary request data, not a target; validate_safe_value still
        # blocks control/newline/null bytes, the actual injection barrier is argv-list (2.1.5).
        command += ["--data", validate_safe_value(params["data"])]
        # A login endpoint legitimately answers wrong-credentials probes with 401/403 — sqlmap
        # otherwise hard-stops on the first non-2xx response instead of testing the payload
        # (confirmed against a real run against Juice Shop's /rest/user/login).
        command += ["--ignore-code", "401,403"]
    # sqlmap's own --headers takes exactly one flag occurrence, multiple headers separated by a
    # literal "\n" inside that one string (its own --help: "X-Forwarded-For: 127.0.0.1\nX-
    # Forwarded-For: 127.0.0.2") — a real newline is already rejected by validate_safe_value below,
    # so the model-supplied "headers" param has to follow that same convention today regardless.
    # The New Project form's Custom HTTP Headers field (server-side injected as
    # params["_extra_headers"] by agent/core.py's _run_tool_with_retry, never model-supplied) is
    # merged into this SAME one flag rather than a second --headers occurrence, which sqlmap would
    # not merge -- the second would silently win and drop the first entirely.
    header_parts = []
    if params.get("headers"):
        header_parts.append(validate_safe_value(params["headers"]))
    for name, value in (params.get("_extra_headers") or {}).items():
        name, value = validate_header_pair(name, value)
        header_parts.append(f"{name}: {value}")
    if header_parts:
        command += ["--headers", "\\n".join(header_parts)]
    if params.get("test_parameter"):
        command += ["-p", validate_safe_value(params["test_parameter"])]
    if params.get("level"):
        command += ["--level", validate_safe_value(str(params["level"]))]
    if params.get("risk"):
        command += ["--risk", validate_safe_value(str(params["risk"]))]
    if params.get("tamper"):
        # A comma-separated list of sqlmap's own tamper script names (e.g.
        # "space2comment,charencode") -- sqlmap parses/validates these itself at runtime, so no
        # allowlist here: it ships ~140 of them, and duplicating that catalog would only drift out
        # of sync with it. Real motivation: a real session (usr_136b4c) hit a WAF that
        # blocked every injection attempt outright, and nothing anywhere tried a bypass before
        # giving up -- this is the mechanism for sqlmap's own share of that fix.
        command += ["--tamper", validate_safe_value(params["tamper"])]
    # Server-side injected by agent/core.py's _run_tool_with_retry (New Project form's Custom
    # User-Agent field) — never part of this tool's own params schema, so never model-supplied.
    if params.get("_user_agent"):
        command += ["--user-agent", validate_safe_value(params["_user_agent"])]

    if params.get("dump_table"):
        database = validate_safe_value(params["database"])
        table = validate_safe_value(params["dump_table"])
        command += ["-D", database, "-T", table, "--dump"]
    else:
        command.append("--dbs")

    return command


def parse_sqlmap_output(stdout: str) -> dict:
    """Extracts injection confirmation and discovered databases/tables as evidence."""
    vulnerable_params = [
        {"parameter": m.group("name"), "place": m.group("place")}
        for m in _VULNERABLE_PARAM_PATTERN.finditer(stdout)
    ]
    databases = _DATABASE_LIST_PATTERN.findall(stdout) if "available databases" in stdout else []

    return {
        "injection_confirmed": bool(vulnerable_params),
        "vulnerable_parameters": vulnerable_params,
        "databases": databases,
    }
