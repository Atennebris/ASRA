"""build_command() and output parser for Slither -- Solidity static analysis. Requires source
(a .sol file or a project directory containing one); for a contract with no available source, see
heimdall.py (decompile bytecode) or native.py's disassemble_evm_bytecode (raw disassembly)."""
from __future__ import annotations

import json

from agent.tools.builders.validators import validate_safe_value


def build_slither_command(params: dict) -> list[str]:
    target = validate_safe_value(str(params["path"]).strip())
    return ["slither", target, "--json", "-"]


def parse_slither_output(stdout: str) -> dict:
    """Slither's `--json -` prints its full report to stdout -- pass through just the detector
    findings the model actually needs (results.detectors), not the whole report (which also
    repeats slither's own version/compilation metadata on every call)."""
    try:
        report = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {"raw_output": stdout.strip()}

    detectors = ((report.get("results") or {}).get("detectors")) or []
    findings = [
        {
            "check": item.get("check"),
            "impact": item.get("impact"),
            "confidence": item.get("confidence"),
            "description": item.get("description"),
        }
        for item in detectors
    ]
    return {"findings": findings}
