"""record_finding/record_exploit_decision/record_target used to access a required field via a bare
params["x"] subscript -- an unhandled KeyError on a real scan (the model omitted "title" AND
"severity" in one call) that agent/tools/runner.py's last-resort catch-all turned into a bare
"'severity'" error message fed back to the model, instead of the clear "X is required" message
every OTHER validation failure in these same functions already gives. Cost a wasted extra
correction round-trip before the model even understood what was missing. Fixed to validate with
.get() + a real message, same as their other fields already do.
"""
from agent.tools.native import record_exploit_decision, record_finding, record_hypothesis, record_target, resolve_hypothesis


def test_record_finding_missing_title_gives_a_clear_error_not_a_keyerror():
    result = record_finding({"severity": "Low", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "error"
    assert "title" in result["error"]


def test_record_finding_missing_severity_gives_a_clear_error_not_a_keyerror():
    result = record_finding({"title": "X", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "error"
    assert "severity" in result["error"]


def test_record_finding_normalizes_lowercase_severity():
    """Real incident this fixes: the model's own correction retry sent "low" instead of "Low" and
    got rejected, burning yet another round-trip before finally sending the exact capitalization."""
    result = record_finding({"title": "X", "severity": "low", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert result["recorded"]["severity"] == "Low"


def test_record_finding_accepts_info_severity():
    """Info is a real 5th severity tier (a notable observation with no security impact of its own,
    e.g. an exposed banner or discovered endpoint) -- not a vulnerability, but distinct from an
    invalid/unrecognized severity string."""
    result = record_finding({"title": "X", "severity": "Info", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert result["recorded"]["severity"] == "Info"


def test_record_finding_still_rejects_a_genuinely_invalid_severity():
    result = record_finding({"title": "X", "severity": "extremely-critical", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "error"
    assert "extremely-critical" in result["error"]


def test_record_finding_accepts_a_well_formed_call():
    result = record_finding({"title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert result["recorded"]["title"] == "X"
    assert result["recorded"]["severity"] == "High"


def test_record_finding_omits_exploited_and_evidence_when_not_given():
    """The normal Recon/Analyze case -- Exploit confirms these fields later, so record_finding
    must not inject false defaults that would shadow _FINDING_DEFAULTS' own exploited=False/
    evidence=None once agent/core.py's _normalize_findings merges them in."""
    result = record_finding({"title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert "exploited" not in result["recorded"]
    assert "evidence" not in result["recorded"]
    assert "remediation_advice" not in result["recorded"]
    assert "discovery_tool" not in result["recorded"]


def test_record_finding_passes_through_discovery_tool_when_given():
    result = record_finding({
        "title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct",
        "discovery_tool": "nuclei_scan",
    })
    assert result["status"] == "ok"
    assert result["recorded"]["discovery_tool"] == "nuclei_scan"


def test_record_hypothesis_passes_through_source_tool_when_given():
    result = record_hypothesis({"text": "admin panel reachable", "source_tool": "whatweb"})
    assert result["status"] == "ok"
    assert result["recorded"]["source_tool"] == "whatweb"


def test_record_hypothesis_omits_source_tool_when_not_given():
    result = record_hypothesis({"text": "admin panel reachable"})
    assert result["status"] == "ok"
    assert "source_tool" not in result["recorded"]


def test_record_finding_passes_through_host_when_given():
    """main.py's _build_attack_surface_graph (Map tab) places a finding on its host node by this
    field -- omitted entirely (not None) when the model doesn't set it, same "only add the key if
    present" discipline discovery_tool/cvss_vector above already follow."""
    result = record_finding({
        "title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct",
        "host": "api.example.com",
    })
    assert result["status"] == "ok"
    assert result["recorded"]["host"] == "api.example.com"


def test_record_finding_omits_host_when_not_given():
    result = record_finding({"title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert "host" not in result["recorded"]


def test_record_hypothesis_passes_through_host_when_given():
    result = record_hypothesis({"text": "admin panel reachable", "host": "admin.example.com"})
    assert result["status"] == "ok"
    assert result["recorded"]["host"] == "admin.example.com"


def test_record_hypothesis_omits_host_when_not_given():
    result = record_hypothesis({"text": "admin panel reachable"})
    assert result["status"] == "ok"
    assert "host" not in result["recorded"]


def test_resolve_hypothesis_passes_through_resolving_tool_when_given():
    result = resolve_hypothesis({"hypothesis_text": "admin panel reachable", "status": "confirmed", "note": "checked", "resolving_tool": "sqlmap"})
    assert result["status"] == "ok"
    assert result["resolved"]["resolving_tool"] == "sqlmap"


def test_resolve_hypothesis_omits_resolving_tool_when_not_given():
    result = resolve_hypothesis({"hypothesis_text": "admin panel reachable", "status": "confirmed", "note": "checked"})
    assert result["status"] == "ok"
    assert "resolving_tool" not in result["resolved"]


def test_record_finding_exploited_true_requires_evidence():
    """Real gap this closes: a Chain-phase finding (agent/core.py's _run_chain, which runs AFTER
    Exploit, so no later phase will ever confirm it) needs a way to claim exploited=true at record
    time -- but only ever backed by real, quoted proof, same "quote real evidence, never fabricate"
    discipline as corrected_severity/corrected_qualifies_for_bounty elsewhere in this project."""
    result = record_finding({
        "title": "X", "severity": "Critical", "description": "d",
        "exploitation_scenario": "remote_direct", "exploited": True,
    })
    assert result["status"] == "error"
    assert "evidence" in result["error"]


def test_record_finding_accepts_exploited_true_with_evidence():
    result = record_finding({
        "title": "X", "severity": "Critical", "description": "d",
        "exploitation_scenario": "remote_direct", "exploited": True,
        "evidence": "real cookie replay: 200 OK, 269980 bytes vs 50-byte anonymous redirect",
        "remediation_advice": "invalidate sessions on logout, set HttpOnly+Secure on the cookie",
    })
    assert result["status"] == "ok"
    assert result["recorded"]["exploited"] is True
    assert "cookie replay" in result["recorded"]["evidence"]
    assert "HttpOnly" in result["recorded"]["remediation_advice"]


def test_record_finding_rejects_non_boolean_exploited():
    result = record_finding({
        "title": "X", "severity": "Low", "description": "d",
        "exploitation_scenario": "remote_direct", "exploited": "yes",
    })
    assert result["status"] == "error"
    assert "exploited" in result["error"]


def test_record_finding_passes_through_evidence_entry_id_when_given():
    result = record_finding({
        "title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct",
        "evidence_entry_id": "abc123def456",
    })
    assert result["status"] == "ok"
    assert result["recorded"]["evidence_entry_id"] == "abc123def456"


def test_record_finding_omits_evidence_entry_id_when_not_given():
    result = record_finding({"title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert "evidence_entry_id" not in result["recorded"]


def test_record_exploit_decision_missing_action_gives_a_clear_error_not_a_keyerror():
    result = record_exploit_decision({"exploitation_scenario": "remote_direct", "reasoning": "x"})
    assert result["status"] == "error"
    assert "action" in result["error"]


def test_record_finding_passes_through_cvss_vector_when_given():
    result = record_finding({
        "title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    })
    assert result["status"] == "ok"
    assert result["recorded"]["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"


def test_record_finding_omits_cvss_vector_when_not_given():
    result = record_finding({"title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert "cvss_vector" not in result["recorded"]


def test_record_finding_rejects_a_cvss_vector_that_isnt_one():
    result = record_finding({
        "title": "X", "severity": "High", "description": "d", "exploitation_scenario": "remote_direct",
        "cvss_vector": "pretty bad, 8/10",
    })
    assert result["status"] == "error"
    assert "cvss_vector" in result["error"]


def test_record_target_missing_host_gives_a_clear_error_not_a_keyerror():
    result = record_target({"port": 443, "service": "https"})
    assert result["status"] == "error"
    assert "host" in result["error"]


def test_record_target_accepts_a_well_formed_call():
    result = record_target({"host": "example.com", "port": 443, "service": "https"})
    assert result["status"] == "ok"
    assert result["recorded"]["host"] == "example.com"
