"""_run_chain / record_chain_result: the final pass across every finding a session recorded,
looking for a real attack chain (a credential one finding leaked unlocking an endpoint another
finding named) -- structurally impossible during Exploit itself, since _run_exploit_for_finding
hands the model only ONE finding at a time. Same anti-fabrication discipline as the CVE-existence
fix made to EXPLOIT_PROMPT: a claimed chain must quote real evidence and be proven by an actual
tool call, enforced deterministically in record_chain_result, not just requested in the prompt.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _finding_needs_escalation, _run_chain
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.native import record_chain_result
from agent.tools.registry import get_tools_by_category
from sessions import store


def _run(coro):
    return asyncio.run(coro)


# --- native function: validation ---


def test_record_chain_result_requires_a_valid_action():
    result = record_chain_result({"action": "made_it_up", "reasoning": "x"})
    assert result["status"] == "error"
    assert "action" in result["error"]


def test_record_chain_result_requires_reasoning():
    result = record_chain_result({"action": "no_chain_found"})
    assert result["status"] == "error"
    assert "reasoning" in result["error"]


def test_record_chain_result_accepts_a_well_formed_no_chain_found():
    result = record_chain_result({"action": "no_chain_found", "reasoning": "no two findings share any reusable evidence"})
    assert result["status"] == "ok"
    assert result["action"] == "no_chain_found"


def test_record_chain_result_rejects_chain_confirmed_without_finding_titles():
    result = record_chain_result({
        "action": "chain_confirmed", "reasoning": "x",
        "evidence_quotes": ["a", "b"], "tool_call_proof": "authenticated_request(...) -> 200",
    })
    assert result["status"] == "error"
    assert "finding_titles" in result["error"]


def test_record_chain_result_rejects_chain_confirmed_without_evidence_quotes():
    result = record_chain_result({
        "action": "chain_confirmed", "reasoning": "x",
        "finding_titles": ["Leaked credential", "Admin endpoint"], "tool_call_proof": "authenticated_request(...) -> 200",
    })
    assert result["status"] == "error"
    assert "evidence_quotes" in result["error"]


def test_record_chain_result_rejects_chain_confirmed_without_tool_call_proof():
    """The anti-fabrication guardrail this whole tool exists for: a narrated-only claim, with no
    real tool call behind it, must never be accepted as chain_confirmed."""
    result = record_chain_result({
        "action": "chain_confirmed", "reasoning": "x",
        "finding_titles": ["Leaked credential", "Admin endpoint"], "evidence_quotes": ["a", "b"],
    })
    assert result["status"] == "error"
    assert "tool_call_proof" in result["error"]


def test_record_chain_result_rejects_a_non_list_reverified_findings():
    result = record_chain_result({"action": "no_chain_found", "reasoning": "x", "reverified_findings": "not a list"})
    assert result["status"] == "error"
    assert "reverified_findings" in result["error"]


def test_record_chain_result_rejects_a_reverified_finding_missing_evidence_ref():
    result = record_chain_result({
        "action": "no_chain_found", "reasoning": "x",
        "reverified_findings": [{"title": "Reflected XSS"}],
    })
    assert result["status"] == "error"
    assert "evidence_ref" in result["error"]


def test_record_chain_result_accepts_well_formed_reverified_findings():
    result = record_chain_result({
        "action": "no_chain_found", "reasoning": "x",
        "reverified_findings": [{"title": "Reflected XSS", "evidence_ref": "dalfox verified_dom_execution again", "exploited": True}],
    })
    assert result["status"] == "ok"
    assert result["reverified_findings"] == [{"title": "Reflected XSS", "evidence_ref": "dalfox verified_dom_execution again", "exploited": True}]


def test_record_chain_result_rejects_chain_confirmed_without_impact_scenario():
    """The bounty-payability guardrail this field exists for: a proven chain with no concrete,
    submission-ready statement of what an attacker can now actually DO is exactly the "real bypass,
    no demonstrated impact" gap this project's own escalation work is meant to close."""
    result = record_chain_result({
        "action": "chain_confirmed", "reasoning": "x",
        "finding_titles": ["Leaked credential", "Admin endpoint"], "evidence_quotes": ["a", "b"],
        "tool_call_proof": "authenticated_request(...) -> 200",
    })
    assert result["status"] == "error"
    assert "impact_scenario" in result["error"]


def test_record_chain_result_accepts_a_well_formed_chain_confirmed():
    result = record_chain_result({
        "action": "chain_confirmed",
        "reasoning": "the leaked FTP password unlocked the admin panel",
        "finding_titles": ["Leaked credential", "Admin endpoint"],
        "evidence_quotes": ["password=hunter2 in .git/config", "https://x.example.com/admin returns 200"],
        "tool_call_proof": "authenticated_request(target='https://x.example.com/admin', ...) -> status 200",
        "impact_scenario": "An unauthenticated attacker reuses the leaked .git credential to log into "
        "the live admin panel at https://x.example.com/admin, gaining full administrative access.",
    })
    assert result["status"] == "ok"
    assert result["action"] == "chain_confirmed"
    assert result["finding_titles"] == ["Leaked credential", "Admin endpoint"]
    assert "admin panel" in result["impact_scenario"]


# --- registration: post_exploit only, never leaked into another phase's toolset ---


def test_record_chain_result_is_not_leaked_into_exploit_or_scan_toolsets():
    """Same reasoning as record_reverification_result: category="post_exploit" is the one value
    no phase's get_tools_by_category(...) call queries, so _run_chain has to add it by name
    (get_tool("record_chain_result")) rather than relying on category-based assembly alone --
    otherwise it would show up as a dead-end tool call in every normal Exploit-phase finding.
    """
    assert "record_chain_result" not in {s.name for s in get_tools_by_category("exploit")}
    assert "record_chain_result" not in {s.name for s in get_tools_by_category("scan")}


# --- _run_chain: orchestration ---


def _make_session(findings):
    return {
        "session_id": "usr_chain_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": findings, "approvals": [], "chat": {"summary": "", "messages": []},
    }


def test_run_chain_is_a_no_op_only_with_zero_findings():
    ctx = RunContext(llm=object(), session=_make_session([]), session_id="usr_chain_test")
    result = _run(_run_chain(ctx))
    assert result == []  # no LLM call needed -- object() would blow up if .complete() were ever called


def test_run_chain_now_runs_with_exactly_one_finding(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes: a session with exactly one Low finding (scim.openai.com
    info-disclosure) never got a Chain pass at all under the old `<= 1` bail-out, even though a
    single finding can still genuinely escalate against recon facts/hypotheses that were never
    findings of their own. One finding is now enough for Chain to actually run."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    one_finding = [{"title": "Only Finding", "severity": "Low", "evidence_ref": "sourcemap discloses op-scim 2.3.0"}]
    llm = _ScriptedLLM([("record_chain_result", {"action": "no_chain_found", "reasoning": "no in-range CVE found for op-scim 2.3.0"})])
    session = _make_session(one_finding)
    session["recon_result"] = {"technologies": {"scim.example.com": "op-scim 2.3.0"}, "cves": [], "targets": []}
    session["hypotheses"] = [{"text": "session file might be readable directly", "evidence": "", "status": "ruled_out"}]
    ctx = RunContext(llm=llm, session=session, session_id="usr_chain_test")

    result = _run(_run_chain(ctx))

    assert llm.calls_made == 1  # it actually ran, not skipped
    assert result == one_finding
    task_sent = llm.tasks_seen[0]
    assert "op-scim 2.3.0" in task_sent
    assert "session file might be readable directly" in task_sent


def test_run_chain_marks_its_own_phase_timing_even_as_a_no_op():
    """Real gap this fixes: Chain (and Validate) run for real time after Exploit but weren't
    tracked in session["phase_timings"] at all, so Session time (session.started_at ->
    finished_at) came out visibly bigger than Recon+Analyze+Exploit's own shown durations added
    together, with no explanation. Marked even in the instant no-op case for a consistent contract
    -- "this phase ran" is true regardless of how much real work it found to do."""
    ctx = RunContext(llm=object(), session=_make_session([]), session_id="usr_chain_test")
    _run(_run_chain(ctx))
    timing = ctx.session["phase_timings"]["chain"]
    assert timing["started_at"] is not None
    assert timing["finished_at"] is not None


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0
        self.tasks_seen = []

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        self.tasks_seen.append(messages[-1]["content"])
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def test_run_chain_gives_the_model_full_evidence_not_a_slim_summary(tmp_path, monkeypatch):
    """A chain claim must quote real evidence_ref/evidence values -- the model needs them in
    context to quote from at all, unlike _run_validate's slim title/severity-only summary."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "Leaked credential", "severity": "High", "evidence_ref": "password=hunter2 in .git/config", "evidence": None},
        {"title": "Admin endpoint", "severity": "Medium", "evidence_ref": "https://x.example.com/admin returns 200", "evidence": None},
    ]
    llm = _ScriptedLLM([("record_chain_result", {"action": "no_chain_found", "reasoning": "nothing reusable"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    _run(_run_chain(ctx))

    task_sent = llm.tasks_seen[0]
    assert "password=hunter2 in .git/config" in task_sent
    assert "https://x.example.com/admin returns 200" in task_sent


def test_run_chain_ends_on_a_real_record_chain_result_tool_call(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "A", "severity": "High", "evidence_ref": "ref-a"},
        {"title": "B", "severity": "Medium", "evidence_ref": "ref-b"},
    ]
    llm = _ScriptedLLM([("record_chain_result", {"action": "no_chain_found", "reasoning": "no shared evidence"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    result = _run(_run_chain(ctx))

    assert llm.calls_made == 1  # ended on the first turn, no repair round-trip needed
    assert result == findings  # no_chain_found records nothing new


def test_run_chain_persists_a_new_finding_recorded_via_record_finding_before_the_terminal_call(tmp_path, monkeypatch):
    """The confirmed-chain path: the model calls record_finding for the genuinely new finding a
    chain produced, THEN calls record_chain_result -- both must land, same as deep-dive's
    record_finding handling in _run_exploit_for_finding.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "Leaked credential", "severity": "High", "evidence_ref": "password=hunter2 in .git/config"},
        {"title": "Admin endpoint", "severity": "Medium", "evidence_ref": "https://x.example.com/admin returns 200"},
    ]
    new_finding_args = {
        "title": "Leaked .git credential unlocks admin panel",
        "severity": "Critical",
        "description": "The leaked FTP password also works as the admin panel login.",
        "verification": "verified",
        "evidence_ref": "authenticated_request with password=hunter2 against /admin -> 200",
        "exploitation_scenario": "remote_direct",
    }
    llm = _ScriptedLLM([
        ("record_finding", new_finding_args),
        ("record_chain_result", {
            "action": "chain_confirmed",
            "reasoning": "the leaked credential authenticated against the admin panel",
            "finding_titles": ["Leaked credential", "Admin endpoint"],
            "evidence_quotes": ["password=hunter2 in .git/config", "https://x.example.com/admin returns 200"],
            "tool_call_proof": "authenticated_request(...) -> status 200",
            "impact_scenario": "An unauthenticated attacker reuses the leaked credential to log into the live admin panel.",
        }),
    ])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    result = _run(_run_chain(ctx))

    titles = {f["title"] for f in result}
    assert "Leaked .git credential unlocks admin panel" in titles
    assert len(result) == 3  # the two originals plus the new chained finding


def test_run_chain_marks_a_freshly_recorded_finding_as_reverified_this_pass(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes: Chain built a genuinely proven attack chain (a
    reflected XSS -> cookie read -> OOB-confirmed exfiltration) and recorded it via record_finding
    in this same pass -- Validate, running immediately after, kept an older and strictly weaker
    duplicate instead, because only reverified_findings' pre-existing-title path ever set the
    _reverified_this_pass freshness marker _run_validate's own dedup summary reads, never a
    finding record_finding created mid-pass. A finding created THIS pass is by definition at least
    as fresh as anything reverified this pass, so it must carry the exact same marker.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "Leaked credential", "severity": "High", "evidence_ref": "password=hunter2 in .git/config"},
        {"title": "Admin endpoint", "severity": "Medium", "evidence_ref": "https://x.example.com/admin returns 200"},
    ]
    new_finding_args = {
        "title": "Leaked .git credential unlocks admin panel",
        "severity": "Critical",
        "description": "The leaked FTP password also works as the admin panel login.",
        "verification": "verified",
        "evidence_ref": "authenticated_request with password=hunter2 against /admin -> 200",
        "exploitation_scenario": "remote_direct",
    }
    llm = _ScriptedLLM([
        ("record_finding", new_finding_args),
        ("record_chain_result", {
            "action": "chain_confirmed",
            "reasoning": "the leaked credential authenticated against the admin panel",
            "finding_titles": ["Leaked credential", "Admin endpoint"],
            "evidence_quotes": ["password=hunter2 in .git/config", "https://x.example.com/admin returns 200"],
            "tool_call_proof": "authenticated_request(...) -> status 200",
            "impact_scenario": "An unauthenticated attacker reuses the leaked credential to log into the live admin panel.",
        }),
    ])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    result = _run(_run_chain(ctx))

    new_finding = next(f for f in result if f["title"] == "Leaked .git credential unlocks admin panel")
    assert new_finding["_reverified_this_pass"] is True
    # The two untouched originals were never reverified or freshly created this pass.
    assert "_reverified_this_pass" not in next(f for f in result if f["title"] == "Leaked credential")


def test_run_chain_applies_reverified_findings_back_onto_the_original_finding(tmp_path, monkeypatch):
    """Real incident this fixes: the chain phase re-ran Dalfox against an XSS finding's own
    endpoint (not a new chain -- the exact same bug, checked again), got a fresh
    verified_dom_execution result, but that confirmation never reached the finding's own
    exploited/evidence_ref/advisory_note fields -- the final report kept telling the operator to
    re-run Dalfox to confirm, even though this pass had already done exactly that."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {
            "title": "Reflected XSS in group_id", "severity": "Medium", "evidence_ref": "old, unconfirmed evidence",
            "exploited": False, "advisory_note": "no real Dalfox call backed this claim -- re-run it to confirm",
        },
        {"title": "Missing X-Frame-Options", "severity": "Low", "evidence_ref": "header absent"},
    ]
    llm = _ScriptedLLM([
        ("record_chain_result", {
            "action": "no_chain_found",
            "reasoning": "no shared evidence between findings, but re-tested the XSS while looking",
            "reverified_findings": [{
                "title": "Reflected XSS in group_id",
                "evidence_ref": "dalfox: DOM verification successful for param group_id (DOM marker)",
                "exploited": True,
                "note": "Re-ran Dalfox during the chain pass and got verified_dom_execution again.",
            }],
        }),
    ])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    result = _run(_run_chain(ctx))

    reverified = next(f for f in result if f["title"] == "Reflected XSS in group_id")
    assert reverified["exploited"] is True
    assert reverified["evidence_ref"] == "dalfox: DOM verification successful for param group_id (DOM marker)"
    assert reverified["advisory_note"] == "Re-ran Dalfox during the chain pass and got verified_dom_execution again."
    untouched = next(f for f in result if f["title"] == "Missing X-Frame-Options")
    assert untouched["evidence_ref"] == "header absent"  # the other finding is left completely alone


def test_run_chain_persists_a_chain_attempt_record_for_no_chain_found(tmp_path, monkeypatch):
    """session["chain_attempts"] must record EVERY real pass, "no_chain_found" included -- without
    this, an operator can't tell "Chain ran and genuinely found nothing" apart from "Chain never
    ran at all" (both otherwise look identical: no new finding appeared)."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "A", "severity": "High", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([("record_chain_result", {"action": "no_chain_found", "reasoning": "nothing to escalate with"})])
    session = _make_session(findings)
    ctx = RunContext(llm=llm, session=session, session_id="usr_chain_test")

    _run(_run_chain(ctx))

    attempts = ctx.session["chain_attempts"]
    assert len(attempts) == 1
    assert attempts[0]["outcome"] == "no_chain_found"
    assert attempts[0]["reasoning"] == "nothing to escalate with"
    assert attempts[0]["material_considered"] == {"findings": 1, "recon_technologies": 0, "hypotheses": 0}
    assert attempts[0]["ran_at"]


def test_run_chain_persists_a_chain_attempt_record_for_chain_confirmed(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "Leaked credential", "severity": "High", "evidence_ref": "password=hunter2 in .git/config"},
        {"title": "Admin endpoint", "severity": "Medium", "evidence_ref": "https://x.example.com/admin returns 200"},
    ]
    llm = _ScriptedLLM([("record_chain_result", {
        "action": "chain_confirmed",
        "reasoning": "the leaked credential authenticated against the admin panel",
        "finding_titles": ["Leaked credential", "Admin endpoint"],
        "evidence_quotes": ["password=hunter2 in .git/config", "https://x.example.com/admin returns 200"],
        "tool_call_proof": "authenticated_request(...) -> status 200",
        "impact_scenario": "An unauthenticated attacker reuses the leaked credential to log into the live admin panel.",
    })])
    session = _make_session(findings)
    ctx = RunContext(llm=llm, session=session, session_id="usr_chain_test")

    _run(_run_chain(ctx))

    attempts = ctx.session["chain_attempts"]
    assert len(attempts) == 1
    assert attempts[0]["outcome"] == "chain_confirmed"
    assert attempts[0]["hop"] == 1
    assert attempts[0]["finding_titles"] == ["Leaked credential", "Admin endpoint"]
    assert attempts[0]["tool_call_proof"] == "authenticated_request(...) -> status 200"
    assert "admin panel" in attempts[0]["impact_scenario"]


# --- _finding_needs_escalation: the prioritization/hop-continuation signal ---


def test_finding_needs_escalation_true_for_low_and_medium_severity():
    assert _finding_needs_escalation({"severity": "Low"}) is True
    assert _finding_needs_escalation({"severity": "Medium"}) is True


def test_finding_needs_escalation_true_when_severity_missing():
    assert _finding_needs_escalation({}) is True


def test_finding_needs_escalation_true_for_non_qualifying_or_unclear_regardless_of_severity():
    assert _finding_needs_escalation({"severity": "Critical", "qualifies_for_bounty": "non_qualifying"}) is True
    assert _finding_needs_escalation({"severity": "High", "qualifies_for_bounty": "unclear"}) is True


def test_finding_needs_escalation_false_once_severity_and_bounty_status_both_stand_on_their_own():
    assert _finding_needs_escalation({"severity": "Critical"}) is False
    assert _finding_needs_escalation({"severity": "High", "qualifies_for_bounty": "qualifying"}) is False


# --- _run_chain: prioritization signal reaches the model ---


def test_run_chain_flags_findings_needing_escalation_in_the_task(tmp_path, monkeypatch):
    """The needs_escalation flag (CHAIN_PROMPT's own prioritization signal) must actually reach the
    model's task text, distinguishing a real-but-unpaid finding from one that already stands on its
    own -- otherwise the prompt's instruction to prioritize has nothing real to act on."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "WAF bypass", "severity": "Low", "evidence_ref": "ref-a"},
        {"title": "Confirmed RCE", "severity": "Critical", "qualifies_for_bounty": "qualifying", "evidence_ref": "ref-b"},
    ]
    llm = _ScriptedLLM([("record_chain_result", {"action": "no_chain_found", "reasoning": "nothing reusable"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    _run(_run_chain(ctx))

    task_sent = llm.tasks_seen[0]
    assert '"needs_escalation": true' in task_sent
    assert '"needs_escalation": false' in task_sent


# --- _run_chain: automatic multi-hop escalation ---


def test_run_chain_runs_a_second_hop_when_the_new_finding_still_needs_escalation(tmp_path, monkeypatch):
    """The whole point of hopping: a chain that only produces a Medium, non-qualifying finding (a
    WAF bypass reaching a reachable-but-not-yet-valuable endpoint) still isn't payable on its own --
    Chain must automatically try again against the finding it just created, not stop the instant it
    proves ONE connection."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "WAF bypass on /api", "severity": "Low", "evidence_ref": "waf_evasion_probe bypassed the filter"}]
    new_finding_args = {
        "title": "Bypass reaches internal status endpoint",
        "severity": "Medium",
        "description": "The WAF bypass reaches /internal/status, which returns build metadata.",
        "verification": "verified",
        "evidence_ref": "GET /internal/status via the bypass payload -> 200, build metadata in response",
        "exploitation_scenario": "remote_direct",
    }
    llm = _ScriptedLLM([
        ("record_finding", new_finding_args),
        ("record_chain_result", {
            "action": "chain_confirmed",
            "reasoning": "the WAF bypass reaches an internal endpoint the filter should have blocked",
            "finding_titles": ["WAF bypass on /api", "Bypass reaches internal status endpoint"],
            "evidence_quotes": ["waf_evasion_probe bypassed the filter", "GET /internal/status via the bypass payload -> 200, build metadata in response"],
            "tool_call_proof": "http_request(url='/internal/status', headers=<bypass payload>) -> 200",
            "impact_scenario": "An unauthenticated attacker uses the WAF bypass to reach the normally-blocked /internal/status endpoint and read build metadata.",
        }),
        ("record_chain_result", {
            "action": "no_chain_found",
            "reasoning": "the internal status endpoint's own metadata doesn't unlock anything further",
        }),
    ])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    result = _run(_run_chain(ctx))

    assert llm.calls_made == 3  # hop 1: record_finding + record_chain_result, hop 2: record_chain_result
    attempts = ctx.session["chain_attempts"]
    assert [a["hop"] for a in attempts] == [1, 2]
    assert attempts[0]["outcome"] == "chain_confirmed"
    assert attempts[1]["outcome"] == "no_chain_found"
    assert len(result) == 2  # the original plus the one new chained finding


def test_run_chain_stops_hopping_once_a_pass_creates_nothing_new_bounty_worthy(tmp_path, monkeypatch):
    """A chain_confirmed pass that only re-links EXISTING findings (no new finding created) has
    nothing fresh to build a further hop on -- must not spin up a pointless extra pass."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "Leaked credential", "severity": "High", "evidence_ref": "password=hunter2 in .git/config"},
        {"title": "Admin endpoint", "severity": "Medium", "evidence_ref": "https://x.example.com/admin returns 200"},
    ]
    llm = _ScriptedLLM([("record_chain_result", {
        "action": "chain_confirmed",
        "reasoning": "the leaked credential authenticated against the admin panel",
        "finding_titles": ["Leaked credential", "Admin endpoint"],
        "evidence_quotes": ["password=hunter2 in .git/config", "https://x.example.com/admin returns 200"],
        "tool_call_proof": "authenticated_request(...) -> status 200",
        "impact_scenario": "An unauthenticated attacker reuses the leaked credential to log into the live admin panel.",
    })])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    _run(_run_chain(ctx))

    assert llm.calls_made == 1
    assert len(ctx.session["chain_attempts"]) == 1


def test_run_chain_stops_at_chain_max_hops_even_if_still_escalatable(tmp_path, monkeypatch):
    """CHAIN_MAX_HOPS is a real cap, not just a soft target -- even a finding that still
    needs_escalation must not push the pass count past it."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "_CHAIN_MAX_HOPS", 1)

    findings = [{"title": "WAF bypass on /api", "severity": "Low", "evidence_ref": "waf_evasion_probe bypassed the filter"}]
    new_finding_args = {
        "title": "Bypass reaches internal status endpoint", "severity": "Medium",
        "description": "The WAF bypass reaches an internal endpoint.", "verification": "verified",
        "evidence_ref": "GET /internal/status -> 200", "exploitation_scenario": "remote_direct",
    }
    llm = _ScriptedLLM([
        ("record_finding", new_finding_args),
        ("record_chain_result", {
            "action": "chain_confirmed",
            "reasoning": "the WAF bypass reaches an internal endpoint",
            "finding_titles": ["WAF bypass on /api", "Bypass reaches internal status endpoint"],
            "evidence_quotes": ["a", "b"],
            "tool_call_proof": "http_request(...) -> 200",
            "impact_scenario": "Reaches an internal endpoint via the bypass.",
        }),
    ])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    _run(_run_chain(ctx))

    assert llm.calls_made == 2  # capped at one hop even though the new finding still needs_escalation
    assert len(ctx.session["chain_attempts"]) == 1


def test_run_chain_tells_a_later_hop_which_finding_to_push_further(tmp_path, monkeypatch):
    """hop_index > 0's task text must actually name the finding the prior hop just produced, not
    just silently include it among the rest of the findings list -- otherwise the model has no
    signal that this pass is a continuation rather than a fresh look at everything."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "WAF bypass on /api", "severity": "Low", "evidence_ref": "waf_evasion_probe bypassed the filter"}]
    new_finding_args = {
        "title": "Bypass reaches internal status endpoint", "severity": "Medium",
        "description": "x", "verification": "verified",
        "evidence_ref": "GET /internal/status -> 200", "exploitation_scenario": "remote_direct",
    }
    llm = _ScriptedLLM([
        ("record_finding", new_finding_args),
        ("record_chain_result", {
            "action": "chain_confirmed", "reasoning": "x",
            "finding_titles": ["WAF bypass on /api", "Bypass reaches internal status endpoint"],
            "evidence_quotes": ["a", "b"], "tool_call_proof": "http_request(...) -> 200",
            "impact_scenario": "Reaches an internal endpoint via the bypass.",
        }),
        ("record_chain_result", {"action": "no_chain_found", "reasoning": "nothing further"}),
    ])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    _run(_run_chain(ctx))

    hop_2_task = llm.tasks_seen[2]
    assert "hop 2" in hop_2_task
    assert "Bypass reaches internal status endpoint" in hop_2_task


def test_run_chain_ignores_a_reverified_finding_naming_an_unknown_title(tmp_path, monkeypatch):
    """A title typo/mismatch must not error the whole chain result -- it's silently skipped, same
    as any other best-effort write-back in this codebase."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "A", "severity": "High", "evidence_ref": "ref-a"},
        {"title": "B", "severity": "Medium", "evidence_ref": "ref-b"},
    ]
    llm = _ScriptedLLM([
        ("record_chain_result", {
            "action": "no_chain_found", "reasoning": "no shared evidence",
            "reverified_findings": [{"title": "Nonexistent Finding", "evidence_ref": "some fresh evidence"}],
        }),
    ])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_chain_test")

    result = _run(_run_chain(ctx))

    assert result == findings  # completely untouched -- no matching title, nothing to apply
