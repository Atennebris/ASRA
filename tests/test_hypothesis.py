"""record_hypothesis/resolve_hypothesis (agent/tools/native.py) + their persistence
(agent/core.py's _persist_new_hypothesis/_resolve_hypothesis/_open_hypotheses_task_addendum).

A hypothesis is deliberately weaker than a finding (record_finding — no proof yet) and stronger
than a passing thought (record_target-shaped structured data, not just reasoning text) — a
suspected attack angle Recon/Analyze notices from raw evidence that Analyze/Exploit can actually
follow up on, instead of it only ever living in one turn's own conversation.
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _MAX_PAST_HYPOTHESIS_OUTCOMES_PER_TEXT,
    _append_tool_timeline,
    _extract_tool_timeline_entries,
    _open_hypotheses_task_addendum,
    _persist_new_hypothesis,
    _previously_resolved_hypotheses_task_addendum,
    _resolve_hypothesis,
)
from agent.tools.native import record_hypothesis, resolve_hypothesis
from sessions import store


# --- record_hypothesis / resolve_hypothesis: pure validation ---


def test_record_hypothesis_requires_text():
    result = record_hypothesis({})
    assert result["status"] == "error"
    assert "text" in result["error"]


def test_record_hypothesis_accepts_text_and_optional_evidence():
    result = record_hypothesis({"text": "Admin panel might be reachable", "evidence": "GET /admin returned 200"})
    assert result["status"] == "ok"
    assert result["recorded"] == {"text": "Admin panel might be reachable", "evidence": "GET /admin returned 200"}


def test_record_hypothesis_defaults_evidence_to_empty_string():
    result = record_hypothesis({"text": "x"})
    assert result["recorded"]["evidence"] == ""


def test_resolve_hypothesis_requires_hypothesis_text():
    result = resolve_hypothesis({"status": "confirmed"})
    assert result["status"] == "error"
    assert "hypothesis_text" in result["error"]


def test_resolve_hypothesis_rejects_an_invalid_status():
    result = resolve_hypothesis({"hypothesis_text": "x", "status": "maybe"})
    assert result["status"] == "error"
    assert "status" in result["error"]


def test_resolve_hypothesis_accepts_confirmed_and_ruled_out():
    for status in ("confirmed", "ruled_out"):
        result = resolve_hypothesis({"hypothesis_text": "x", "status": status, "note": "checked it"})
        assert result["status"] == "ok"
        assert result["resolved"]["status"] == status


def test_resolve_hypothesis_normalizes_status_case():
    result = resolve_hypothesis({"hypothesis_text": "x", "status": "Confirmed"})
    assert result["status"] == "ok"
    assert result["resolved"]["status"] == "confirmed"


# --- persistence: _persist_new_hypothesis / _resolve_hypothesis ---


def _session(session_id):
    return {"session_id": session_id, "target": "example.com", "status": "processing", "logs": [], "findings": [], "hypotheses": []}


def test_persist_new_hypothesis_appends_with_unconfirmed_status(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_persist")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "GET /admin -> 200"}, "recon")

    assert len(session["hypotheses"]) == 1
    entry = session["hypotheses"][0]
    assert entry["text"] == "Odd admin path"
    assert entry["evidence"] == "GET /admin -> 200"
    assert entry["source_phase"] == "recon"
    assert entry["status"] == "unconfirmed"
    assert entry["resolution_note"] is None
    assert entry["resolved_at"] is None
    assert entry["id"]


def test_persist_new_hypothesis_records_source_tool_as_a_discovery_timeline_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_source_tool")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "x", "source_tool": "whatweb"}, "recon")

    assert session["hypotheses"][0]["tool_timeline"] == [{"tool": "whatweb", "stage": "discovery"}]


def test_persist_new_hypothesis_has_an_empty_timeline_when_no_source_tool_given(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_no_source_tool")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "x"}, "recon")

    assert "tool_timeline" not in session["hypotheses"][0]  # never set at all, not an empty list -- same absence-means-empty contract as findings


def test_resolve_hypothesis_records_resolving_tool_as_a_verification_timeline_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_resolve_tool")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "x"}, "recon")

    _resolve_hypothesis(ctx, {"hypothesis_text": "Odd admin path", "status": "confirmed", "note": "checked", "resolving_tool": "sqlmap"}, "exploit")

    assert session["hypotheses"][0]["tool_timeline"] == [{"tool": "sqlmap", "stage": "verification"}]


def test_extract_tool_timeline_entries_dedupes_and_excludes_bookkeeping_tools():
    trace = [
        {"tool": "nuclei_scan", "arguments": {}, "result": {}},
        {"tool": "nuclei_scan", "arguments": {}, "result": {}},  # repeated -- only the first counts
        {"tool": "record_finding", "arguments": {}, "result": {}},  # bookkeeping -- excluded
        {"tool": "sqlmap", "arguments": {}, "result": {}},
    ]
    entries = _extract_tool_timeline_entries(trace, "exploitation")
    assert entries == [
        {"tool": "nuclei_scan", "stage": "exploitation"},
        {"tool": "sqlmap", "stage": "exploitation"},
    ]


def test_append_tool_timeline_does_not_duplicate_entries_across_repeated_calls():
    """Real risk this guards against: a re-run deep dive extending the same finding's timeline a
    second time must not double up entries already there from the first pass."""
    finding = {"title": "X"}
    _append_tool_timeline(finding, [{"tool": "nmap_scan", "stage": "exploitation"}])
    _append_tool_timeline(finding, [{"tool": "nmap_scan", "stage": "exploitation"}, {"tool": "sqlmap", "stage": "exploitation"}])
    assert finding["tool_timeline"] == [
        {"tool": "nmap_scan", "stage": "exploitation"},
        {"tool": "sqlmap", "stage": "exploitation"},
    ]


def test_append_tool_timeline_never_shares_a_list_across_findings():
    """Regression guard for the exact mutable-default trap this feature deliberately avoided --
    tool_timeline is NOT a key in _FINDING_DEFAULTS specifically so two independent findings never
    end up sharing (and silently polluting) the same list object."""
    finding_a, finding_b = {"title": "A"}, {"title": "B"}
    _append_tool_timeline(finding_a, [{"tool": "nmap_scan", "stage": "exploitation"}])
    assert finding_b.get("tool_timeline") is None


def test_persist_new_hypothesis_defaults_source_to_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_source_default")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "x"}, "recon")

    assert session["hypotheses"][0]["source"] == "agent"


def test_persist_new_hypothesis_accepts_user_source():
    """An operator-submitted hint (New Project form pre-scan hints, a live submission, or a
    post-completion verification request) is tagged source="user" so the UI can distinguish it
    from a lead the agent found on its own."""
    session = _session("usr_hyp_source_user")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _persist_new_hypothesis(ctx, {"text": "Check for exposed .git", "evidence": ""}, "pre_scan", source="user")

    assert session["hypotheses"][0]["source"] == "user"
    assert session["hypotheses"][0]["source_phase"] == "pre_scan"


def test_resolve_hypothesis_matches_by_loose_text_and_updates_status(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_resolve")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    _persist_new_hypothesis(ctx, {"text": "Odd admin path at /admin might be unauthenticated", "evidence": "GET /admin -> 200"}, "recon")

    _resolve_hypothesis(ctx, {"hypothesis_text": "Odd admin path", "status": "confirmed", "note": "Confirmed via unauth GET"}, "analyze")

    entry = session["hypotheses"][0]
    assert entry["status"] == "confirmed"
    assert entry["resolution_note"] == "Confirmed via unauth GET"
    assert entry["resolved_at"] is not None


# --- past_hypothesis_outcomes ledger: _resolve_hypothesis / _previously_resolved_hypotheses_task_addendum ---


def test_resolve_hypothesis_appends_to_past_hypothesis_outcomes_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_ledger")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "x"}, "recon")

    _resolve_hypothesis(ctx, {"hypothesis_text": "Odd admin path", "status": "ruled_out", "note": "requires auth"}, "analyze")

    ledger = session["past_hypothesis_outcomes"]
    assert len(ledger) == 1
    assert ledger[0]["text"] == "Odd admin path"
    assert ledger[0]["status"] == "ruled_out"
    assert ledger[0]["resolution_note"] == "requires auth"
    assert ledger[0]["resolved_at"] is not None


def test_resolve_hypothesis_caps_past_hypothesis_outcomes_per_text(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_ledger_cap")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    for i in range(_MAX_PAST_HYPOTHESIS_OUTCOMES_PER_TEXT + 2):
        session["hypotheses"] = [{
            "id": f"h{i}", "text": "Odd admin path", "evidence": "x", "status": "unconfirmed",
            "resolution_note": None, "resolved_at": None, "source_phase": "recon", "source": "agent",
        }]
        _resolve_hypothesis(ctx, {"hypothesis_text": "Odd admin path", "status": "ruled_out", "note": f"pass {i + 1}"}, "analyze")

    ledger = [e for e in session["past_hypothesis_outcomes"] if e["text"] == "Odd admin path"]
    assert len(ledger) == _MAX_PAST_HYPOTHESIS_OUTCOMES_PER_TEXT
    assert ledger[-1]["resolution_note"] == f"pass {_MAX_PAST_HYPOTHESIS_OUTCOMES_PER_TEXT + 2}"


def test_previously_resolved_hypotheses_task_addendum_is_empty_when_no_history():
    assert _previously_resolved_hypotheses_task_addendum({}) == ""
    assert _previously_resolved_hypotheses_task_addendum({"past_hypothesis_outcomes": []}) == ""


def test_previously_resolved_hypotheses_task_addendum_lists_ruled_out_and_confirmed_text():
    session = {"past_hypothesis_outcomes": [
        {"text": "Admin panel reachable unauthenticated", "status": "ruled_out", "resolution_note": "requires auth"},
        {"text": "Debug endpoint leaks stack traces", "status": "confirmed", "resolution_note": None},
    ]}
    addendum = _previously_resolved_hypotheses_task_addendum(session)
    assert "Admin panel reachable unauthenticated" in addendum
    assert "ruled_out" in addendum
    assert "requires auth" in addendum
    assert "Debug endpoint leaks stack traces" in addendum
    assert "confirmed" in addendum
    assert "skip" not in addendum.lower()  # calibration only, never an instruction to skip


def test_previously_resolved_hypotheses_task_addendum_ignores_still_unconfirmed_entries():
    """Defensive -- the ledger should only ever contain resolved entries, but this must never
    surface an unconfirmed one as if it were settled history."""
    session = {"past_hypothesis_outcomes": [{"text": "x", "status": "unconfirmed", "resolution_note": None}]}
    assert _previously_resolved_hypotheses_task_addendum(session) == ""


def test_resolve_hypothesis_is_a_silent_no_op_when_nothing_matches(tmp_path, monkeypatch):
    """A typo'd/paraphrased hypothesis_text with no real match must not crash the whole tool call —
    same "don't fail over one bad sub-field" tolerance this project applies elsewhere."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_no_match")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "x"}, "recon")

    _resolve_hypothesis(ctx, {"hypothesis_text": "Completely unrelated text", "status": "ruled_out"}, "analyze")

    assert session["hypotheses"][0]["status"] == "unconfirmed"  # untouched


def test_resolve_hypothesis_never_reopens_an_already_resolved_one(tmp_path, monkeypatch):
    """The first still-open match wins -- a hypothesis already resolved must not be re-resolved by
    a second, looser match against the same text."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _session("usr_hyp_no_reopen")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    _persist_new_hypothesis(ctx, {"text": "Odd admin path", "evidence": "x"}, "recon")
    _resolve_hypothesis(ctx, {"hypothesis_text": "Odd admin path", "status": "ruled_out", "note": "first check"}, "analyze")

    _resolve_hypothesis(ctx, {"hypothesis_text": "Odd admin path", "status": "confirmed", "note": "second, wrong re-check"}, "exploit")

    entry = session["hypotheses"][0]
    assert entry["status"] == "ruled_out"  # the first resolution stands
    assert entry["resolution_note"] == "first check"


# --- _open_hypotheses_task_addendum ---


def test_open_hypotheses_addendum_is_empty_with_none_recorded():
    assert _open_hypotheses_task_addendum({}) == ""
    assert _open_hypotheses_task_addendum({"hypotheses": []}) == ""


def test_open_hypotheses_addendum_lists_only_unconfirmed_ones():
    session = {
        "hypotheses": [
            {"text": "Still open lead", "evidence": "raw fact", "status": "unconfirmed"},
            {"text": "Already confirmed lead", "evidence": "", "status": "confirmed"},
            {"text": "Already ruled out lead", "evidence": "", "status": "ruled_out"},
        ]
    }
    addendum = _open_hypotheses_task_addendum(session)
    assert "Still open lead" in addendum
    assert "raw fact" in addendum
    assert "Already confirmed lead" not in addendum
    assert "Already ruled out lead" not in addendum
