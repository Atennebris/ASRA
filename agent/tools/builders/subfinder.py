"""build_command() and output parser for Subfinder (github.com/projectdiscovery/subfinder) —
passive subdomain enumeration from many aggregated OSINT sources at once.

Real gap this closes: crt_sh_lookup only ever sees a subdomain that has its own TLS certificate
(nothing else) and subdomain_enum only resolves a short, fixed ~50-word prefix list -- a real
forgotten staging/internal host with neither its own cert nor a common name never surfaces from
either. Subfinder aggregates dozens of independent passive sources (its own default set, no API
keys required for the free ones) in a single pass, same "discover more, without hammering the
target with active requests" spirit as crt_sh_lookup, just far broader.
"""
from __future__ import annotations

from agent.tools.allowed_targets import collapse_cdn_edge_node_hosts
from agent.tools.builders.validators import validate_safe_value


def build_subfinder_command(params: dict) -> list[str]:
    domain = validate_safe_value(str(params["domain"]).strip())
    if not domain:
        raise ValueError("domain must not be empty.")
    command = ["subfinder", "-d", domain, "-silent"]
    extra_args = [validate_safe_value(str(arg)) for arg in params.get("extra_args", [])]
    command += extra_args
    return command


def parse_subfinder_output(stdout: str) -> dict:
    """One hostname per line in -silent mode -- same flat-list shape as crt_sh_lookup's own
    "subdomains" field, deliberately, so both passive-discovery tools read identically to the
    model and to anything downstream that already expects that shape."""
    subdomains = sorted({line.strip() for line in stdout.splitlines() if line.strip()})
    return {"subdomains": collapse_cdn_edge_node_hosts(subdomains)}
