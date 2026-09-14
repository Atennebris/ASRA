"""Read-only "what's worth looking at next, and why" tool over THIS session's own already-collected
recon data -- never calls out to a target itself, purely re-reads what recon_result/findings
already hold in memory. A genuinely explainable heuristic (every point comes with its own reason
string the model can quote directly), not a black-box score -- the goal is to give the model a
faster way to prioritize a large host list itself, not to make the prioritization decision for it;
nothing in the agent loop calls this automatically or gates on its output, it's exactly as optional
as any other read-only recon tool (cve_lookup, whois, ...).

Deliberately scoped to structured, reliable fields only -- recon_result["technologies"] (host ->
tech tokens, populated by _run_analyze) and recon_result["host_health"]/["protections"] all key
cleanly by host. session["findings"] does NOT carry a clean structured host field across every
finding-creation site in agent/core.py (host info often lives inside free-text technology/
description strings instead) -- rather than guess at a schema change there, a finding's relevance
to a given host is matched here as an explicit BEST-EFFORT substring check, always labeled as such
in its own reason string so the model can weigh it accordingly rather than trust it blindly.
"""
from __future__ import annotations

import re

_HOSTNAME_KEYWORDS = (
    "admin", "staging", "dev", "test", "internal", "vpn", "jenkins", "gitlab", "grafana",
    "kibana", "jira", "confluence", "graphql", "swagger", "phpmyadmin", "portainer", "sonarqube",
)
_TECH_KEYWORDS = (
    "wordpress", "jenkins", "grafana", "kibana", "elasticsearch", "phpmyadmin", "jira",
    "confluence", "tomcat", "weblogic", "jboss", "struts", "drupal", "joomla", "magento",
    "gitlab", "portainer", "sonarqube", "graphql",
)
_SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}
_MAX_KEYWORD_HITS_COUNTED = 4  # caps runaway scores from one host matching many keywords at once
_HOSTNAME_KEYWORD_POINTS = 8
_TECH_KEYWORD_POINTS = 6
_HEALTHY_HOST_POINTS = 5
_PROTECTION_POINTS = 3
_DEFAULT_LIMIT = 15


def _collect_hosts(recon: dict) -> set[str]:
    hosts: set[str] = set()
    for target in recon.get("targets") or []:
        if isinstance(target, str) and target.strip():
            hosts.add(target.strip())
    hosts.update((recon.get("technologies") or {}).keys())
    hosts.update((recon.get("host_health") or {}).keys())
    hosts.update((recon.get("protections") or {}).keys())
    return hosts


def _score_host(host: str, recon: dict, findings: list[dict]) -> dict:
    score = 0
    reasons: list[str] = []

    health = (recon.get("host_health") or {}).get(host)
    if health and health.get("successes", 0) > 0:
        score += _HEALTHY_HOST_POINTS
        reasons.append("responded successfully to at least one tool call this session")

    host_lower = host.lower()
    hostname_hits = [kw for kw in _HOSTNAME_KEYWORDS if kw in host_lower][:_MAX_KEYWORD_HITS_COUNTED]
    for kw in hostname_hits:
        score += _HOSTNAME_KEYWORD_POINTS
        reasons.append(f"hostname contains '{kw}'")

    techs = [str(t).lower() for t in (recon.get("technologies") or {}).get(host) or []]
    tech_hits = [kw for kw in _TECH_KEYWORDS if any(kw in t for t in techs)][:_MAX_KEYWORD_HITS_COUNTED]
    for kw in tech_hits:
        score += _TECH_KEYWORD_POINTS
        reasons.append(f"detected technology matches '{kw}'")

    protection = (recon.get("protections") or {}).get(host)
    if protection:
        score += _PROTECTION_POINTS
        reasons.append(f"sits behind an identified protection ({protection}) — confirms real infrastructure")

    # Best-effort only -- see module docstring. A finding whose free-text fields happen to mention
    # this host's own string gets counted; anything genuinely unattributable is silently skipped
    # rather than guessed at.
    host_pattern = re.compile(re.escape(host), re.IGNORECASE) if host else None
    if host_pattern is not None:
        for finding in findings:
            haystack = " ".join(str(finding.get(field) or "") for field in ("technology", "description", "title"))
            if host_pattern.search(haystack):
                weight = _SEVERITY_WEIGHT.get(str(finding.get("severity", "")).lower(), 0)
                if weight:
                    score += weight
                    reasons.append(
                        f"possible related finding (best-effort host match, not authoritative): "
                        f"\"{finding.get('title')}\" ({finding.get('severity')})"
                    )

    return {"host": host, "score": score, "reasons": reasons}


def rank_attack_surface(params: dict) -> dict:
    session = params.get("_session") or {}
    recon = session.get("recon_result") or {}
    findings = session.get("findings") or []
    limit = params.get("limit") or _DEFAULT_LIMIT

    hosts = _collect_hosts(recon)
    if not hosts:
        return {"status": "ok", "ranked_hosts": [],
                "note": "No hosts recorded in recon_result yet — run recon first."}

    ranked = sorted((_score_host(host, recon, findings) for host in hosts), key=lambda e: -e["score"])
    return {"status": "ok", "ranked_hosts": ranked[:limit], "total_hosts_considered": len(hosts)}
