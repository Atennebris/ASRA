"""_run_reverify (agent/core.py): re-checks a rescanned project's carried-over findings against the
current target state with real tool calls, rather than trusting the old verification forward. Real
incident this guards against: findings accidentally deleted during an unrelated cleanup earlier in
this project's history -- the same "the data existed and then quietly didn't" risk this phase's own
persistence (via the shared _persist_new_finding helper) must never reproduce.
"""
import asyncio
import time

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _MAX_PAST_REVERIFICATION_ENTRIES_PER_TITLE,
    _REVERIFY_CALIBRATED_MAX_TOOL_CALLS,
    _REVERIFY_STABLE_TREND_MIN_STREAK,
    _previously_ruled_out_task_addendum,
    _run_reverify,
    _stable_outcome_streak,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from sessions import store


def _run(coro):
    return asyncio.run(coro)


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0
        self.offered_tool_names: list[str] | None = None

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self.offered_tool_names is None and tools is not None:
            self.offered_tool_names = [t["function"]["name"] for t in tools]
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def _base_session(**overrides):
    session = {
        "session_id": "usr_reverify_test", "findings": [], "logs": [],
        "approvals": [], "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


def _old_finding(**overrides):
    finding = {
        "title": "XSS on /search", "severity": "High", "description": "reflected XSS",
        "technology": "PHP", "exploitation_scenario": "remote_direct", "qualifies_for_bounty": "qualifying",
        "reproduction_steps": "steps", "evidence_ref": "old evidence from prior scan",
        "found_at": "2026-01-01T00:00:00+00:00", "verification": "verified",
    }
    finding.update(overrides)
    return finding


def test_run_reverify_is_a_true_noop_when_no_carried_over_findings(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([])
    session = _base_session()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert llm.calls_made == 0
    assert session["findings"] == []
    assert "reverification_history" not in session
    # A normal, non-rescan session must never grow a "reverify" phase card — it categorically
    # doesn't apply here, and phase_timings drives the Plan tab's own phase display.
    assert "reverify" not in session.get("phase_timings", {})


def test_run_reverify_tracks_phase_timings_for_real_work(tmp_path, monkeypatch):
    """Real, confirmed gap this closes: a genuine 52m47s block of real reverify work was
    completely invisible in session["phase_timings"] (unlike recon/analyze/exploit/chain/validate,
    which were already tracked) -- Session time (started_at -> finished_at) came out visibly
    bigger than every other phase's own shown duration added together, with nothing in the UI
    explaining the gap."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_reverification_result", {"verification_outcome": "confirmed_fixed", "reasoning": "fixed"}),
    ])
    session = _base_session(carried_over_findings=[_old_finding()])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    timing = session["phase_timings"]["reverify"]
    assert timing["started_at"] is not None
    assert timing["finished_at"] is not None


def test_run_reverify_reconfirmed_finding_is_persisted_with_provenance(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_reverification_result", {
            "verification_outcome": "confirmed_present", "reasoning": "re-fired the same payload, it still executes",
            "evidence_ref": "fresh curl output showing the unescaped payload",
        }),
    ])
    old = _old_finding()
    # Non-blank on purpose: this test checks that qualifies_for_bounty is carried verbatim, which
    # requires this project to actually have scope rules configured -- agent/core.py's
    # _persist_new_finding strips the field to None otherwise (a separate guardrail, not what this
    # test is about).
    session = _base_session(
        rescanned_from="usr_old_session", carried_over_findings=[old],
        scope_rules={"qualifying": "XSS, SQLi", "non_qualifying": ""},
    )
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert len(session["findings"]) == 1
    new_finding = session["findings"][0]
    assert new_finding["title"] == old["title"]
    assert new_finding["verification"] == "verified"
    assert new_finding["carried_over_from"] == "usr_old_session"
    assert new_finding["first_found_at"] == old["found_at"]
    assert new_finding["evidence_ref"] == "fresh curl output showing the unescaped payload"
    # Severity/scope carried verbatim, not re-litigated by this phase
    assert new_finding["severity"] == "High"
    assert new_finding["qualifies_for_bounty"] == "qualifying"

    assert len(session["reverification_history"]) == 1
    assert session["reverification_history"][0] == {
        "title": old["title"], "verification_outcome": "confirmed_present",
        "reasoning": "re-fired the same payload, it still executes",
        "checked_at": session["reverification_history"][0]["checked_at"],
    }


def test_run_reverify_resolved_finding_is_not_persisted_but_is_recorded_in_history(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_reverification_result", {"verification_outcome": "confirmed_fixed", "reasoning": "the page now returns 404, bug is fixed"}),
    ])
    old = _old_finding(title="Old fixed bug")
    session = _base_session(carried_over_findings=[old])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    # Re-reporting a fixed bug as active would be misleading -- must never land in findings.
    assert session["findings"] == []
    assert len(session["reverification_history"]) == 1
    assert session["reverification_history"][0]["verification_outcome"] == "confirmed_fixed"
    assert session["reverification_history"][0]["title"] == "Old fixed bug"
    assert "404" in session["reverification_history"][0]["reasoning"]


def test_run_reverify_inconclusive_finding_is_carried_forward_flagged_needs_verification(tmp_path, monkeypatch):
    """Real, confirmed incident this guards against: a finding the model explicitly said it
    "cannot verify either way" (WAF-blocked every attempt) used to vanish from the report with no
    trace at all, because the old still_present boolean forced a false verdict. It must now survive
    into session["findings"], flagged for a human to re-check, not silently dropped."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_reverification_result", {
            "verification_outcome": "inconclusive",
            "reasoning": "every attempt hit the same Cloudflare challenge, could not verify either way",
        }),
    ])
    old = _old_finding(title="Blocked-by-WAF finding")
    session = _base_session(rescanned_from="usr_old_session", carried_over_findings=[old])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert len(session["findings"]) == 1
    carried = session["findings"][0]
    assert carried["title"] == "Blocked-by-WAF finding"
    assert carried["verification"] == "needs_verification"
    assert "Cloudflare challenge" in carried["advisory_note"]
    assert carried["carried_over_from"] == "usr_old_session"

    assert len(session["reverification_history"]) == 1
    assert session["reverification_history"][0]["verification_outcome"] == "inconclusive"


def test_run_reverify_treats_a_no_verdict_pass_as_inconclusive_not_confirmed_fixed(tmp_path, monkeypatch):
    """A loop that never calls the terminal tool at all (budget exhausted, stalled) must not be
    silently treated the same as an explicit "confirmed fixed" -- both used to collapse into the
    same bool(None) == False path before this fix."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([])  # never calls record_reverification_result -- immediate "done"
    old = _old_finding(title="Never got a verdict")
    session = _base_session(carried_over_findings=[old])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert len(session["findings"]) == 1
    assert session["findings"][0]["verification"] == "needs_verification"
    assert session["reverification_history"][0]["verification_outcome"] == "inconclusive"


def test_run_reverify_is_idempotent_a_second_call_does_nothing_more(tmp_path, monkeypatch):
    """The resumability fix: an interrupted/resumed rescan calls _run_reverify more than once per
    run_session() invocation (see run_session's sequencing) -- it must be a cheap no-op once
    everything pending has already been processed, not re-process (and duplicate) everything."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_reverification_result", {"verification_outcome": "confirmed_present", "reasoning": "confirmed", "evidence_ref": "e"}),
    ])
    old = _old_finding()
    session = _base_session(carried_over_findings=[old])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))
    calls_after_first = llm.calls_made
    assert calls_after_first > 0

    finished_at_after_first = session["phase_timings"]["reverify"]["finished_at"]

    _run(_run_reverify(ctx))

    assert llm.calls_made == calls_after_first  # no new LLM calls made
    assert len(session["findings"]) == 1  # not duplicated
    assert len(session["reverification_history"]) == 1  # not duplicated
    # A second, idempotent no-op call (nothing pending) must never push finished_at forward — it
    # did no new work, so it must not look like the phase finished again just now.
    assert session["phase_timings"]["reverify"]["finished_at"] == finished_at_after_first


def test_run_reverify_persists_a_genuinely_new_finding_reported_via_record_finding(tmp_path, monkeypatch):
    """The design review's sharpest catch: reverify's toolset includes record_finding (it's
    "scan"-category) -- if the execute closure didn't persist it the same way Analyze/deep-dive do
    (agent/core.py's shared _persist_new_finding helper), a genuinely new finding the model spots
    while re-checking the old claim would be silently dropped."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_finding", {
            "title": "Unrelated new bug spotted while checking", "severity": "Low", "description": "d",
            "exploitation_scenario": "remote_direct", "verification": "needs_verification", "evidence_ref": "e",
        }),
        ("record_reverification_result", {"verification_outcome": "confirmed_fixed", "reasoning": "original bug is gone"}),
    ])
    old = _old_finding(title="Original old bug")
    session = _base_session(carried_over_findings=[old])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    titles = {f["title"] for f in session["findings"]}
    assert "Unrelated new bug spotted while checking" in titles
    # The reconfirmation verdict (false) is independent -- the original bug still isn't re-added.
    assert "Original old bug" not in titles


def test_run_reverify_upgrades_a_stall_forced_inconclusive_once_the_subagent_result_actually_arrives(tmp_path, monkeypatch):
    """Real bug this guards against: a reverify pass that polls check_subagent_task identically
    _STALL_REPEAT_THRESHOLD times in a row gets its final answer FORCED to "inconclusive" before it
    ever sees the subagent's real result — but _run_llm_tool_loop's own wrapper then unconditionally
    waits for that exact same subagent task to resolve anyway, right before returning to
    _run_reverify. The phase pays that wait's full cost either way; before this fix, the answer it
    waited for was simply thrown away instead of upgrading the premature "inconclusive" it forced
    moments earlier. This reproduces the whole stall -> forced-answer -> late-arrival sequence for
    real (through _run_reverify itself, not just the new helper in isolation) and asserts the report
    ends up with the real, resolved verdict instead of the stale forced one."""
    from agent.tools import subagent_tasks

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    task_id = "task_terrapin_check"

    class _FakeSubagentTask:
        """Duck-types only what subagent_tasks._reap actually calls (.done/.cancelled/.exception/
        .result) — check_subagent_task's own dispatch is plain sync code, no real asyncio
        concurrency is needed to control exactly when this "task" appears to finish."""
        def __init__(self):
            self.done_flag = False

        def done(self):
            return self.done_flag

        def cancelled(self):
            return False

        def exception(self):
            return None

        def result(self):
            return ({"summary": "OpenSSH 9.6, Terrapin patched — not vulnerable"}, [])

    fake_task = _FakeSubagentTask()
    subagent_tasks._RUNNING_SUBAGENT_TASKS[task_id] = fake_task
    try:
        # Simulates the subagent genuinely finishing right as _run_llm_tool_loop's wrapper starts
        # its own unconditional post-loop wait — i.e. AFTER the stall-forced "inconclusive" answer
        # has already been computed from the 6 identical (and, until now, honestly "running") polls.
        real_await_all = subagent_tasks.await_all_running_subagent_tasks

        async def fake_await_all(session_id, session, stop_check=None):
            fake_task.done_flag = True
            await real_await_all(session_id, session, stop_check=stop_check)

        monkeypatch.setattr(subagent_tasks, "await_all_running_subagent_tasks", fake_await_all)

        llm = _ScriptedLLM([
            *([("check_subagent_task", {"task_id": task_id})] * 6),  # trips back-to-back stall detection
            ("record_reverification_result", {  # the stall-forced final answer, before the real result exists yet
                "verification_outcome": "inconclusive",
                "reasoning": "the subagent task hasn't reported back yet, so I can't confirm either way",
            }),
            ("record_reverification_result", {  # the upgrade pass, now armed with the real, resolved result
                "verification_outcome": "confirmed_present",
                "reasoning": "the subagent's real result confirms the outdated, vulnerable OpenSSH banner",
                "evidence_ref": "subagent task result: OpenSSH 8.9p1, Terrapin-vulnerable",
            }),
        ])
        old = _old_finding(title="SSH Terrapin vulnerability")
        session = _base_session(rescanned_from="usr_old_session", carried_over_findings=[old])
        session["subagent_tasks"] = {
            task_id: {
                "profile_name": "recon-helper", "status": "running", "started_at": 0.0,
                "deadline": time.time() + 900, "result": None, "triggered_by": "model",
                "chat_thread_id": None, "delivered": False,
            },
        }
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_reverify(ctx))
    finally:
        subagent_tasks._RUNNING_SUBAGENT_TASKS.pop(task_id, None)

    # The forced "inconclusive" pass alone would have carried the OLD finding forward flagged
    # needs_verification (see the sibling inconclusive test above) — the upgrade must have replaced
    # it with the real, resolved verdict instead.
    assert len(session["reverification_history"]) == 1
    assert session["reverification_history"][0]["verification_outcome"] == "confirmed_present"
    assert len(session["findings"]) == 1
    reconfirmed = session["findings"][0]
    assert reconfirmed["title"] == "SSH Terrapin vulnerability"
    assert reconfirmed["verification"] == "verified"
    assert reconfirmed["evidence_ref"] == "subagent task result: OpenSSH 8.9p1, Terrapin-vulnerable"
    # The real subagent task must have actually been reaped/resolved by the mandatory wait — proof
    # this test exercised the genuine wait-then-upgrade sequence, not a shortcut around it.
    assert session["subagent_tasks"][task_id]["status"] == "done"


def test_run_reverify_withholds_severity_escalation_on_reproduction_alone(tmp_path, monkeypatch):
    """Real bug this guards against: a reverify pass reproducing an already-known finding could
    freely raise its severity/qualification with nothing behind that but the same reproduction
    already captured in evidence_ref/reasoning -- record_reverification_result's schema never
    forbade it and _apply_corrected_qualification has no concept of "old vs new evidence". Without
    the guard in _apply_reverify_correction, this would land severity="Medium"/qualifies_for_bounty
    ="qualifying" with no escalation_justification behind it at all."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_reverification_result", {
            "verification_outcome": "confirmed_present", "reasoning": "re-fired the same payload, it still executes",
            "evidence_ref": "fresh curl output showing the unescaped payload",
            "corrected_severity": "Medium",  # up from the old finding's Low
            "corrected_qualifies_for_bounty": "qualifying",  # up from the old finding's "unclear"
            # No escalation_justification -- reproduction alone is not new evidence.
        }),
    ])
    old = _old_finding(severity="Low", qualifies_for_bounty="unclear")
    session = _base_session(
        rescanned_from="usr_old_session", carried_over_findings=[old],
        scope_rules={"qualifying": "XSS, SQLi", "non_qualifying": ""},
    )
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert len(session["findings"]) == 1
    reconfirmed = session["findings"][0]
    # Escalation withheld -- kept at the prior scan's own values.
    assert reconfirmed["severity"] == "Low"
    assert reconfirmed["qualifies_for_bounty"] == "unclear"
    assert "original_severity" not in reconfirmed
    assert "original_qualifies_for_bounty" not in reconfirmed
    assert "no new evidence" in reconfirmed["escalation_withheld_note"]


def test_run_reverify_applies_severity_escalation_with_a_real_justification(tmp_path, monkeypatch):
    """The guard must never block a LEGITIMATE escalation that does have genuine new evidence
    behind it -- only reproduction-alone gets withheld."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([
        ("record_reverification_result", {
            "verification_outcome": "confirmed_present", "reasoning": "now also reachable unauthenticated",
            "evidence_ref": "fresh curl output showing the bug now works with no auth token at all",
            "corrected_severity": "Critical",
            "escalation_justification": "Unlike the prior scan, this now reproduces with zero authentication "
            "required -- a materially broader, unauthenticated attack surface the original finding never showed.",
        }),
    ])
    old = _old_finding(severity="High")
    session = _base_session(rescanned_from="usr_old_session", carried_over_findings=[old])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    reconfirmed = session["findings"][0]
    assert reconfirmed["severity"] == "Critical"
    assert reconfirmed["original_severity"] == "High"
    assert "escalation_withheld_note" not in reconfirmed


def test_run_reverify_accumulates_past_reverification_outcomes_across_rescans(tmp_path, monkeypatch):
    """Real, confirmed operator complaint this closes: a finding re-proven "still there"/"fixed"
    rescan after rescan with zero cross-rescan memory reads as pointless repeated churn. Unlike
    reverification_history (reset every rescan for its own within-rescan idempotency, simulated
    here by clearing it and re-seeding carried_over_findings the way main.py's rescan routes do
    between separate rescans), past_reverification_outcomes must keep growing."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    old = _old_finding(title="Recurring finding")
    session = _base_session(carried_over_findings=[old])

    async def two_separate_rescans():
        # Both calls share ONE event loop (asyncio.run below), matching how run_session() actually
        # drives this in production -- one long-lived server-process loop, never a fresh loop per
        # rescan. get_stop_event's per-session asyncio.Event isn't safe to reuse across two
        # DIFFERENT event loops, which two separate top-level asyncio.run() calls here would do.
        llm = _ScriptedLLM([("record_reverification_result", {"verification_outcome": "confirmed_present", "reasoning": "still there, first rescan", "evidence_ref": "e1"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
        await _run_reverify(ctx)
        assert len(session["past_reverification_outcomes"]) == 1

        # A second, separate rescan of the same lineage: main.py resets reverification_history and
        # re-seeds carried_over_findings, but never touches past_reverification_outcomes.
        session["reverification_history"] = []
        session["carried_over_findings"] = [old]
        llm2 = _ScriptedLLM([("record_reverification_result", {"verification_outcome": "confirmed_fixed", "reasoning": "gone on second rescan"})])
        ctx2 = RunContext(llm=llm2, session=session, session_id=session["session_id"])
        await _run_reverify(ctx2)

    _run(two_separate_rescans())

    ledger = session["past_reverification_outcomes"]
    assert len(ledger) == 2
    assert [e["verification_outcome"] for e in ledger] == ["confirmed_present", "confirmed_fixed"]
    assert all(e["title"] == "Recurring finding" for e in ledger)


def test_run_reverify_caps_past_reverification_outcomes_per_title(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    old = _old_finding(title="Repeatedly checked finding")
    session = _base_session(carried_over_findings=[old])

    async def many_separate_rescans():
        for i in range(_MAX_PAST_REVERIFICATION_ENTRIES_PER_TITLE + 2):
            session["reverification_history"] = []
            session["carried_over_findings"] = [old]
            llm = _ScriptedLLM([("record_reverification_result", {"verification_outcome": "confirmed_present", "reasoning": f"pass {i}", "evidence_ref": "e"})])
            ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
            await _run_reverify(ctx)

    _run(many_separate_rescans())

    ledger = session["past_reverification_outcomes"]
    assert len(ledger) == _MAX_PAST_REVERIFICATION_ENTRIES_PER_TITLE
    # Oldest entries are the ones dropped, not the newest.
    assert ledger[-1]["reasoning"] == f"pass {_MAX_PAST_REVERIFICATION_ENTRIES_PER_TITLE + 1}"


def test_previously_ruled_out_task_addendum_is_empty_when_no_fixed_history():
    assert _previously_ruled_out_task_addendum({}) == ""
    assert _previously_ruled_out_task_addendum({"past_reverification_outcomes": []}) == ""
    # A still-present or inconclusive history doesn't belong in this addendum -- only fixed ones.
    still_present_only = {"past_reverification_outcomes": [{"title": "X", "verification_outcome": "confirmed_present"}]}
    assert _previously_ruled_out_task_addendum(still_present_only) == ""


def test_previously_ruled_out_task_addendum_lists_confirmed_fixed_titles():
    session = {
        "past_reverification_outcomes": [
            {"title": "Old fixed bug", "verification_outcome": "confirmed_fixed"},
            {"title": "Still present bug", "verification_outcome": "confirmed_present"},
        ],
    }
    addendum = _previously_ruled_out_task_addendum(session)
    assert "Old fixed bug" in addendum
    assert "Still present bug" not in addendum


def test_run_reverify_toolset_excludes_exploit_category_tools_but_includes_its_terminal_tool(tmp_path, monkeypatch):
    """Reverify only re-checks EXISTENCE, never runs a real exploitation attempt itself -- that
    happens naturally afterward in the normal Exploit phase if the finding is reconfirmed. Its own
    terminal tool must still be reachable despite living in the unqueried "post_exploit" category
    (agent/tools/__init__.py's registration comment explains why that category specifically)."""
    from agent.tools.registry import get_tools_by_category

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    llm = _ScriptedLLM([("record_reverification_result", {"verification_outcome": "confirmed_fixed", "reasoning": "gone"})])
    old = _old_finding()
    session = _base_session(carried_over_findings=[old])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert llm.offered_tool_names is not None
    exploit_only_tool_names = {s.name for s in get_tools_by_category("exploit")} - {s.name for s in get_tools_by_category("scan")}
    assert exploit_only_tool_names, "sanity: exploit and scan categories must actually differ for this check to mean anything"
    assert not (exploit_only_tool_names & set(llm.offered_tool_names))


# --- _stable_outcome_streak: pure unit tests ---


def test_stable_outcome_streak_is_none_when_shorter_than_the_minimum():
    outcomes = [{"verification_outcome": "confirmed_fixed"}] * (_REVERIFY_STABLE_TREND_MIN_STREAK - 1)
    assert _stable_outcome_streak(outcomes) is None


def test_stable_outcome_streak_is_none_for_a_mixed_trend():
    outcomes = (
        [{"verification_outcome": "confirmed_present"}] +
        [{"verification_outcome": "confirmed_fixed"}] * (_REVERIFY_STABLE_TREND_MIN_STREAK - 1)
    )
    assert _stable_outcome_streak(outcomes) is None


def test_stable_outcome_streak_detects_a_stable_trailing_run():
    outcomes = [{"verification_outcome": "confirmed_fixed"}] * _REVERIFY_STABLE_TREND_MIN_STREAK
    assert _stable_outcome_streak(outcomes) == ("confirmed_fixed", _REVERIFY_STABLE_TREND_MIN_STREAK)


def test_stable_outcome_streak_counts_the_full_run_past_the_minimum():
    outcomes = (
        [{"verification_outcome": "confirmed_present"}] +
        [{"verification_outcome": "confirmed_fixed"}] * (_REVERIFY_STABLE_TREND_MIN_STREAK + 2)
    )
    assert _stable_outcome_streak(outcomes) == ("confirmed_fixed", _REVERIFY_STABLE_TREND_MIN_STREAK + 2)


# --- _run_reverify: effort calibration for a stable trend ---


def _stable_ledger(title, outcome, count):
    return [{"title": title, "verification_outcome": outcome, "checked_at": f"2026-01-0{i + 1}T00:00:00+00:00"} for i in range(count)]


def test_run_reverify_calibrates_max_tool_calls_after_a_stable_confirmed_fixed_streak(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    captured = {}

    async def fake_loop(ctx, system_prompt, task, tool_specs, phase, execute_tool=None, terminal_tool=None, plan_phase=None, max_tool_calls=None, **kwargs):
        captured["max_tool_calls"] = max_tool_calls
        captured["task"] = task
        return {"verification_outcome": "confirmed_fixed", "reasoning": "still fixed"}, []

    monkeypatch.setattr("agent.core._run_llm_tool_loop", fake_loop)

    old = _old_finding()
    session = _base_session(
        carried_over_findings=[old],
        past_reverification_outcomes=_stable_ledger(old["title"], "confirmed_fixed", _REVERIFY_STABLE_TREND_MIN_STREAK),
    )
    ctx = RunContext(llm=_ScriptedLLM([]), session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert captured["max_tool_calls"] == _REVERIFY_CALIBRATED_MAX_TOOL_CALLS
    assert "consecutive rescans" in captured["task"]
    assert "must still make a real tool call" in captured["task"]


def test_run_reverify_does_not_calibrate_when_streak_is_mixed(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    captured = {}

    async def fake_loop(ctx, system_prompt, task, tool_specs, phase, execute_tool=None, terminal_tool=None, plan_phase=None, max_tool_calls=None, **kwargs):
        captured["max_tool_calls"] = max_tool_calls
        return {"verification_outcome": "confirmed_present", "reasoning": "still there"}, []

    monkeypatch.setattr("agent.core._run_llm_tool_loop", fake_loop)

    old = _old_finding()
    mixed_ledger = [
        {"title": old["title"], "verification_outcome": "confirmed_present", "checked_at": "2026-01-01T00:00:00+00:00"},
        {"title": old["title"], "verification_outcome": "confirmed_fixed", "checked_at": "2026-01-02T00:00:00+00:00"},
        {"title": old["title"], "verification_outcome": "confirmed_present", "checked_at": "2026-01-03T00:00:00+00:00"},
    ]
    session = _base_session(carried_over_findings=[old], past_reverification_outcomes=mixed_ledger)
    ctx = RunContext(llm=_ScriptedLLM([]), session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert captured["max_tool_calls"] is None


def test_run_reverify_never_fabricates_a_verdict_when_the_calibrated_budget_runs_out(tmp_path, monkeypatch):
    """Calibration must only tighten the ceiling, never grant a skip or fabricate a result: if the
    calibrated budget is exhausted before the model ever reaches record_reverification_result (the
    terminal tool), the pass must fall back to the same honest "inconclusive" every other budget-
    exhausted/stalled reverify pass already gets -- never silently reuse the stable trend's own
    outcome as if it had been freshly re-proven.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    async def fake_loop(ctx, system_prompt, task, tool_specs, phase, execute_tool=None, terminal_tool=None, plan_phase=None, max_tool_calls=None, **kwargs):
        assert max_tool_calls == _REVERIFY_CALIBRATED_MAX_TOOL_CALLS
        return None, []  # budget exhausted without ever reaching the terminal tool -- no verdict

    monkeypatch.setattr("agent.core._run_llm_tool_loop", fake_loop)

    old = _old_finding()
    session = _base_session(
        carried_over_findings=[old],
        past_reverification_outcomes=_stable_ledger(old["title"], "confirmed_fixed", _REVERIFY_STABLE_TREND_MIN_STREAK + 3),
    )
    ctx = RunContext(llm=_ScriptedLLM([]), session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    assert session["reverification_history"][0]["verification_outcome"] == "inconclusive"
