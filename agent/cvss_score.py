"""Compute a CVSS base score + severity rating from a vector string.

A finding can carry a CVSS vector set two ways: the agent's own assessment of a confirmed finding
(record_finding's cvss_vector) or one lifted from a CVE record. Until now the vector rendered only as
a raw string -- an operator still had to score it in their head. This turns the vector into the
number and label a triager actually reads ("9.8 Critical"), deterministically and offline.

Scope: CVSS v3.0 and v3.1 base scores, whose formula is fully specified and compact. v4.0 scoring
depends on large published lookup tables; rather than ship a half-correct reimplementation that could
quietly misrank a real finding, a v4.0 vector returns its version with score=None -- the UI then
shows the honest vector without a fabricated number. This module scores the BASE metrics only;
temporal/environmental modifiers are intentionally out of scope (nothing here produces them).
"""
from __future__ import annotations

import math

# Base-metric weights, straight from the CVSS v3.1 specification (v3.0 shares these; only the
# Roundup step below differs between the two versions).
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}
# Privileges Required is the one metric whose weight depends on Scope (a changed scope makes a
# low/high privilege requirement matter less), so it is a nested lookup keyed on scope first.
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.5},
}


def severity_rating(score: float) -> str:
    """The standard CVSS v3 qualitative band for a base score -- the same thresholds NVD uses, so a
    computed 9.8 reads "Critical" exactly as a CVE page would."""
    if score <= 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def cvss_base_score(vector_string: str | None) -> dict | None:
    """Parse a CVSS vector and return {"score", "severity", "version"}, or None when the string is
    not a CVSS vector at all. For a v4.0 vector, "score"/"severity" are None (see module docstring):
    the caller still gets the version so it can show the raw vector honestly rather than a made-up
    number. A v3.x vector missing any required base metric also returns score=None rather than
    guessing an absent metric's weight."""
    if not vector_string or not isinstance(vector_string, str) or not vector_string.startswith("CVSS:"):
        return None

    parts = dict(segment.split(":", 1) for segment in vector_string.split("/") if ":" in segment)
    version = parts.get("CVSS")
    if not version:
        return None
    if version.startswith("4"):
        return {"score": None, "severity": None, "version": version}
    if not version.startswith("3"):
        # An unrecognized major version -- surface the version, don't fabricate a score for a
        # formula this module doesn't implement.
        return {"score": None, "severity": None, "version": version}

    scope = parts.get("S")
    try:
        av = _AV[parts["AV"]]
        ac = _AC[parts["AC"]]
        ui = _UI[parts["UI"]]
        pr = _PR[scope][parts["PR"]]
        conf = _IMPACT[parts["C"]]
        integ = _IMPACT[parts["I"]]
        avail = _IMPACT[parts["A"]]
    except KeyError:
        # A required base metric is absent or carries a value this formula doesn't know -- honest
        # None beats a score computed from a guessed weight.
        return {"score": None, "severity": None, "version": version}

    iss = 1.0 - ((1.0 - conf) * (1.0 - integ) * (1.0 - avail))
    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = _roundup(min(impact + exploitability, 10.0), version)
    else:
        score = _roundup(min(1.08 * (impact + exploitability), 10.0), version)

    return {"score": score, "severity": severity_rating(score), "version": version}


def _roundup(value: float, version: str) -> float:
    """CVSS v3.1 defines Roundup precisely (to avoid floating-point rounding disputes between
    scorers); v3.0 only says "round up to one decimal". Use each version's own rule so a score here
    matches what an official calculator prints for that version."""
    if version == "3.1":
        scaled = round(value * 100000)
        if scaled % 10000 == 0:
            return scaled / 100000.0
        return (math.floor(scaled / 10000) + 1) / 10.0
    return math.ceil(value * 10) / 10.0
