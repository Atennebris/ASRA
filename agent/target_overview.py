"""A live, continuously-rebuilt overview of what we know about the target right now.

The session already accumulates every fact an operator cares about -- recon_result (surface, stack,
protections), findings (with their derived verification status), hypotheses, target_profile.
What it lacked was one consolidated "state of knowledge" read, rebuilt as facts arrive rather than a
static end-of-scan dump. This is that read, COMPUTED from session on every render -- never a second
stored blob that could drift from the fields it summarizes (DRY), the same discipline the finding
verification status (agent/verification_status.py) already follows.

Pure and session-shape-only: no LLM, no I/O, no mutation. The session dict is the single source of
truth; this just aggregates it, so the live SSE re-render of the session fragment picks up a fresh
overview for free with no extra trigger.
"""
from __future__ import annotations

from agent.verification_status import (
    derive_verification_status,
    latest_reverify_outcome_by_title,
)

# Keep the surfaced lists short -- an overview is a glance, not the full Recon tab. A real engagement
# can run 20-50+ hosts / dozens of tech tokens; the card shows the first N and a "+M more" count.
_MAX_LISTED = 12


def build_target_overview(session: dict) -> dict:
    """Aggregate the session into one overview dict. `has_data` is False for a brand-new project
    with nothing recorded yet, so the template can skip the whole card rather than render empty
    sections."""
    recon = session.get("recon_result") or {}
    findings = session.get("findings") or []
    hypotheses = session.get("hypotheses") or []

    surface = _surface(recon)
    stack = _stack(recon)
    finding_summary = _findings(findings, session.get("reverification_history"))
    hypothesis_summary = _hypotheses(hypotheses)
    knowledge = _knowledge(surface, stack, finding_summary, hypothesis_summary)

    has_data = bool(
        surface["host_count"]
        or stack["technologies"]["shown"]
        or finding_summary["total"]
        or hypothesis_summary["total"]
        or (session.get("target_profile") or [])
    )

    return {
        "surface": surface,
        "stack": stack,
        "findings": finding_summary,
        "hypotheses": hypothesis_summary,
        "profile_facts": session.get("target_profile") or [],
        "knowledge": knowledge,
        "has_data": has_data,
    }


def _capped(items: list) -> dict:
    """{"shown": first N, "more": how many were hidden} -- one shape the template renders the same
    way everywhere it lists something that can run long."""
    unique = list(dict.fromkeys(items))  # de-dup, preserve first-seen order
    return {"shown": unique[:_MAX_LISTED], "more": max(0, len(unique) - _MAX_LISTED)}


def _surface(recon: dict) -> dict:
    targets = recon.get("targets") or []
    hosts = [t.get("host") for t in targets if t.get("host")]
    # Scanned targets only -- deliberately NOT every dns_map A-record. A hostname that merely
    # resolved (but was never probed) belongs on the Map tab's own node list, not in the overview's
    # "surface we're actually assessing" count; folding it in both inflates the count and surfaces
    # unrelated resolved hostnames here.
    unique_hosts = list(dict.fromkeys(hosts))
    ports = {(t.get("host"), t.get("port")) for t in targets if t.get("port") is not None}
    return {
        "host_count": len(unique_hosts),
        "hosts": _capped(unique_hosts),
        "port_count": len(ports),
    }


def _stack(recon: dict) -> dict:
    tech_tokens: list[str] = []
    for tokens in (recon.get("technologies") or {}).values():
        tech_tokens.extend(tokens or [])
    protections: list[str] = []
    for labels in (recon.get("protections") or {}).values():
        protections.extend(labels or [])
    os_guesses: list[str] = []
    for guesses in (recon.get("os_guesses") or {}).values():
        if isinstance(guesses, list):
            os_guesses.extend(guesses)
        elif guesses:
            os_guesses.append(guesses)
    return {
        "technologies": _capped(tech_tokens),
        "protections": _capped(protections),
        "os_guesses": _capped(os_guesses),
    }


def _findings(findings: list[dict], reverification_history: list[dict] | None) -> dict:
    reverify_outcomes = latest_reverify_outcome_by_title(reverification_history)
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    exploited = 0
    for finding in findings:
        status = derive_verification_status(finding, reverify_outcomes.get(finding.get("title")))["status"]
        by_status[status] = by_status.get(status, 0) + 1
        severity = finding.get("severity") or "Low"
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if finding.get("exploited"):
            exploited += 1
    return {
        "total": len(findings),
        "by_status": by_status,
        "by_severity": by_severity,
        "verified": by_status.get("verified", 0),
        "disputed": by_status.get("disputed", 0),
        "exploited": exploited,
    }


def _hypotheses(hypotheses: list[dict]) -> dict:
    counts = {"unconfirmed": 0, "confirmed": 0, "ruled_out": 0}
    for hypothesis in hypotheses:
        status = hypothesis.get("status")
        if status in counts:
            counts[status] += 1
    return {
        "total": len(hypotheses),
        "open": counts["unconfirmed"],
        "confirmed": counts["confirmed"],
        "ruled_out": counts["ruled_out"],
    }


def _knowledge(surface: dict, stack: dict, finding_summary: dict, hypothesis_summary: dict) -> dict:
    """Honest knowledge boundaries, in the same observed/inferred/unknown spirit as the RE evidence
    contract (agent/tools/re_evidence.py): what's directly measured vs suspected vs genuinely not
    determined yet -- so the overview reads as "here's the edge of what we know", never implying an
    empty field means an absence of risk. Derived straight from the counts above, no new state."""
    return {
        # Directly measured this engagement.
        "verified_findings": finding_summary["verified"],
        "hosts_known": surface["host_count"],
        # Suspected but not actively confirmed yet.
        "inferred_findings": finding_summary["by_status"].get("inferred", 0)
        + finding_summary["by_status"].get("needs_verification", 0),
        "open_hypotheses": hypothesis_summary["open"],
        # Flagged for a human: two independent providers split on these.
        "disputed_findings": finding_summary["disputed"],
    }
