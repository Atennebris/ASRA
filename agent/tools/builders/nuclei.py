"""build_command() and output parser for Nuclei."""
from __future__ import annotations

import json

from agent.tools.builders.validators import validate_safe_value, validate_target

# An earlier plan called for tags "exploits,vulnerabilities,cves" — those tags don't exist
# in Nuclei's real taxonomy (confirmed against an actual template run: 0 templates matched, hard
# failure "no templates provided for scan"). Real, populated active-check tags used instead.
_DEFAULT_TAGS = "cve,vuln,exposure,rce,misconfig"


def build_nuclei_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    tags = params.get("tags", _DEFAULT_TAGS)
    # The schema asks for a comma-separated string, but tool-calling models frequently send a
    # JSON array of tags instead (a very natural way to represent "multiple tags") — accepting
    # both avoids burning a full retry round-trip on a shape mismatch that isn't a real error.
    if isinstance(tags, list):
        tags = ",".join(str(tag) for tag in tags)
    tags = validate_safe_value(tags)
    return ["nuclei", "-u", target, "-jsonl", "-tags", tags]


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
            }
        )
    return findings
