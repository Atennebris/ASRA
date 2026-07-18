"""build_command() and output parser for Nmap."""
from __future__ import annotations

import re

from agent.tools.builders.validators import validate_target

_PORT_LINE_PATTERN = re.compile(
    r"^(?P<port>\d+)/(?P<protocol>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)\s*(?P<version>.*)$"
)


def build_nmap_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    return ["nmap", "-F", "-sV", target]


def parse_nmap_output(stdout: str) -> list[dict]:
    """Extracts {port, service, version} entries from Nmap's default text output."""
    findings = []
    for line in stdout.splitlines():
        match = _PORT_LINE_PATTERN.match(line.strip())
        if not match:
            continue
        if match.group("state") != "open":
            continue
        findings.append(
            {
                "port": int(match.group("port")),
                "service": match.group("service"),
                "version": match.group("version").strip(),
            }
        )
    return findings
