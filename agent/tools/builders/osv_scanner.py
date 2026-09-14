"""build_command() and output parser for osv-scanner -- software composition analysis (SCA) over
a source tree's own dependency lockfiles (package-lock.json, requirements.txt, Cargo.lock, go.sum,
...), matched against the OSV (Open Source Vulnerabilities) database. One tool, many ecosystems --
scans whatever lockfiles it actually finds under the given path, no per-language tool needed, and
no install/resolve step first (reads lockfiles directly, doesn't need `npm install`/`pip install`
to have already run)."""
from __future__ import annotations

import json

from agent.tools.builders.validators import validate_safe_value


def build_osv_scanner_command(params: dict) -> list[str]:
    target = validate_safe_value(str(params["path"]).strip())
    return ["osv-scanner", "scan", "source", "--format", "json", target]


def parse_osv_scanner_output(stdout: str) -> dict:
    try:
        report = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return {"raw_output": stdout.strip()}

    findings = []
    for result in report.get("results") or []:
        source = (result.get("source") or {}).get("path")
        for package in result.get("packages") or []:
            pkg_info = package.get("package") or {}
            for vuln in package.get("vulnerabilities") or []:
                findings.append({
                    "source": source,
                    "package": pkg_info.get("name"),
                    "version": pkg_info.get("version"),
                    "ecosystem": pkg_info.get("ecosystem"),
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary"),
                })
    return {"findings": findings}
