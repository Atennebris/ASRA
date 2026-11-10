"""build_command() and output parser for Mythril -- symbolic-execution analysis of a smart
contract, the RE toolset's second, genuinely different analysis technique for contracts alongside
slither's pattern-based detectors (finds real bug classes slither's own static patterns can miss,
at the cost of being slower). Works on EITHER a Solidity source file OR raw EVM bytecode -- same
bytecode_or_path shape agent/tools/builders/heimdall.py and agent/tools/native.py's
disassemble_evm_bytecode already use, for a consistent interface across every contract-analysis
tool that can take either form.

Output goes through agent/tools/re_evidence.py's evidence_result() -- deliberately chosen as one
of the FIRST two builders retrofitted to it (alongside slither.py), since a symbolic-execution
"finding" is itself already a judgment call (a reachable-state heuristic, not a confirmed
exploit), the exact class of result [[dont_treat_a_security_tools_raw_result_as_proof]] warns
about. The finding COUNT is `observed` (a hard fact about what mythril actually reported, true
regardless of whether any individual finding holds up); the findings' own content is `inferred`
(mythril's own symbolic-execution judgment, carrying real false-positive risk) -- never the
reverse, which would silently read a heuristic pattern-match as a measured fact.
"""
from __future__ import annotations

import json
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.re_evidence import evidence_result


def build_mythril_command(params: dict) -> list[str]:
    target = validate_safe_value(str(params["bytecode_or_path"]).strip())
    if Path(target).is_file():
        return ["myth", "analyze", target, "-o", "json"]
    # Not a local file -- treat it as raw hex bytecode (mythril's own -c flag), same "with or
    # without a leading 0x" tolerance the sibling bytecode-only tools already have.
    bytecode = target[2:] if target.lower().startswith("0x") else target
    return ["myth", "analyze", "-c", bytecode, "-o", "json"]


_CONFIDENCE_CAVEAT = (
    "Mythril's own findings are symbolic-execution-reachability judgments against known bug "
    "classes (SWC IDs) -- a real lead worth checking, never a confirmed exploit on their own. "
    "Verify each against the actual contract logic before treating it as a real vulnerability."
)


def parse_mythril_output(stdout: str) -> dict:
    try:
        report = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {
            **evidence_result({}, unknown={"findings": "mythril's own output was not valid JSON -- see raw_output"}),
            "raw_output": stdout.strip(),
        }

    issues = report.get("issues") if isinstance(report, dict) else None
    if issues is None and isinstance(report, list):
        issues = report
    findings = [
        {
            "title": issue.get("title"),
            "severity": issue.get("severity"),
            "swc_id": issue.get("swc-id") or issue.get("swc_id"),
            "description": issue.get("description") or issue.get("description_head"),
            "function": issue.get("function"),
        }
        for issue in (issues or [])
    ]
    return evidence_result(
        {"total_findings": len(findings)},
        inferred={"findings": findings, "confidence_caveat": _CONFIDENCE_CAVEAT},
    )
