"""build_command() and output parser for Slither -- Solidity static analysis. Requires source
(a .sol file or a project directory containing one); for a contract with no available source, see
heimdall.py (decompile bytecode) or native.py's disassemble_evm_bytecode (raw disassembly).

Output goes through agent/tools/re_evidence.py's evidence_result() -- deliberately chosen as one
of the FIRST two builders retrofitted to it (alongside mythril.py), since a detector "finding" is
itself a pattern-match judgment (slither's own `impact`/`confidence` fields already admit this),
not a confirmed vulnerability -- the exact class of result
[[dont_treat_a_security_tools_raw_result_as_proof]] warns about. The finding COUNT is `observed`
(a hard fact about what slither actually reported); the findings' own content is `inferred`
(slither's own detector judgment, carrying real false-positive risk, same as mythril.py's).
"""
from __future__ import annotations

import json

from agent.tools.builders.validators import validate_safe_value
from agent.tools.re_evidence import evidence_result

_CONFIDENCE_CAVEAT = (
    "Slither's own findings are static pattern-match judgments against known detector rules "
    "(each already carries its own impact/confidence from slither itself) -- a real lead worth "
    "checking, never a confirmed vulnerability on their own. Verify each against the actual "
    "contract logic before treating it as a real vulnerability."
)


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
        return {
            **evidence_result({}, unknown={"findings": "slither's own output was not valid JSON -- see raw_output"}),
            "raw_output": stdout.strip(),
        }

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
    return evidence_result(
        {"total_findings": len(findings)},
        inferred={"findings": findings, "confidence_caveat": _CONFIDENCE_CAVEAT},
    )
