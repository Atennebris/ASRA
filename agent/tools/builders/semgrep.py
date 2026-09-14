"""build_command() and output parser for semgrep -- SAST over an available source tree (the
reverse-engineering mode's "source-code audit" capability, deliberately separate from the
disassembly/decompilation chain: no binary involved at all)."""
from __future__ import annotations

import json

from agent.tools.builders.validators import validate_safe_value


def build_semgrep_command(params: dict) -> list[str]:
    target = validate_safe_value(str(params["path"]).strip())
    return ["semgrep", "--config", "auto", "--json", target]


def parse_semgrep_output(stdout: str) -> dict:
    try:
        report = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {"raw_output": stdout.strip()}

    results = report.get("results") or []
    findings = [
        {
            "check_id": item.get("check_id"),
            "path": item.get("path"),
            "line": (item.get("start") or {}).get("line"),
            "message": (item.get("extra") or {}).get("message"),
            "severity": (item.get("extra") or {}).get("severity"),
        }
        for item in results
    ]
    return {"findings": findings}
