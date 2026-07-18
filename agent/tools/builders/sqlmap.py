"""build_command() and output parser for sqlmap."""
from __future__ import annotations

import re

from agent.tools.builders.validators import validate_safe_value, validate_target

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
    if params.get("headers"):
        command += ["--headers", validate_safe_value(params["headers"])]
    if params.get("test_parameter"):
        command += ["-p", validate_safe_value(params["test_parameter"])]
    if params.get("level"):
        command += ["--level", validate_safe_value(str(params["level"]))]
    if params.get("risk"):
        command += ["--risk", validate_safe_value(str(params["risk"]))]

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
