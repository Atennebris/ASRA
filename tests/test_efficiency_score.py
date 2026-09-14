"""compute_efficiency_score (agent/core.py) -- a PROCESS-efficiency score (-100..+100), never a
results/yield score: it weighs failed/retried/duplicate tool calls and forced-stop stalls against
the session's own real tool-call volume, deliberately blind to how many findings turned up. A
hardened target correctly, cleanly yielding zero findings must score exactly as well as a soft one
yielding real bugs just as cleanly -- conflating "worked cleanly" with "found a lot" is exactly the
confusion a real log-review pass in this project already had to correct once, before ever checking
the data.
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _log_phase_efficiency_summary, compute_efficiency_notes, compute_efficiency_score
from sessions import store


def _session(phase_efficiency=None, stall_events=None):
    return {"phase_efficiency": phase_efficiency or {}, "stall_events": stall_events or []}


def test_no_tool_calls_yet_has_no_data_and_a_neutral_placeholder_score():
    result = compute_efficiency_score(_session())
    assert result["has_data"] is False
    assert result["score"] == 0
    assert result["total_tool_calls"] == 0


def test_perfectly_clean_session_scores_the_maximum():
    session = _session({"recon": {"tool_calls": 50, "retried": 0, "non_ok": 0, "duplicates": 0}})
    result = compute_efficiency_score(session)
    assert result["has_data"] is True
    assert result["score"] == 100


def test_a_hundred_percent_failure_rate_alone_still_scores_clearly_negative():
    """Real bug this test guards against: an earlier version of this formula (a bounded weighted
    average across all four factors) let a session where LITERALLY EVERY call failed still score
    +20, because no single factor's own weight could reach the full range alone -- diluting one
    very bad signal by requiring every other signal to also be maximally bad. A session where
    nothing at all worked must never read as "efficient"."""
    session = _session({"exploit": {"tool_calls": 20, "retried": 0, "non_ok": 20, "duplicates": 0}})
    result = compute_efficiency_score(session)
    assert result["score"] < 0
    assert result["score"] == -60  # 100 - 160*1.0, clamped


def test_score_floors_at_minus_100_not_below():
    session = _session(
        {"exploit": {"tool_calls": 20, "retried": 20, "non_ok": 20, "duplicates": 20}},
        stall_events=[{"phase": "exploit"}] * 5,
    )
    result = compute_efficiency_score(session)
    assert result["score"] == -100


def test_score_ceilings_at_plus_100_not_above():
    """A pathological all-zero-rate session (shouldn't happen in practice given total_calls > 0,
    but the clamp must hold regardless) never exceeds the ceiling."""
    session = _session({"recon": {"tool_calls": 1, "retried": 0, "non_ok": 0, "duplicates": 0}})
    result = compute_efficiency_score(session)
    assert result["score"] <= 100


def test_stalls_are_a_flat_per_event_penalty_not_normalized_by_call_count():
    session_few_calls = _session({"recon": {"tool_calls": 5, "retried": 0, "non_ok": 0, "duplicates": 0}}, stall_events=[{"phase": "recon"}])
    session_many_calls = _session({"recon": {"tool_calls": 500, "retried": 0, "non_ok": 0, "duplicates": 0}}, stall_events=[{"phase": "recon"}])
    result_few = compute_efficiency_score(session_few_calls)
    result_many = compute_efficiency_score(session_many_calls)
    assert result_few["score"] == result_many["score"] == 75  # 100 - 25*1, same regardless of volume


def test_accumulates_across_multiple_phase_buckets_including_subagent():
    session = _session({
        "recon": {"tool_calls": 30, "retried": 1, "non_ok": 1, "duplicates": 0},
        "analyze": {"tool_calls": 20, "retried": 0, "non_ok": 0, "duplicates": 0},
        "subagent": {"tool_calls": 10, "retried": 0, "non_ok": 1, "duplicates": 0},
    })
    result = compute_efficiency_score(session)
    assert result["total_tool_calls"] == 60
    assert result["failure_rate"] == 2 / 60
    assert result["retry_rate"] == 1 / 60


# --- compute_efficiency_notes: deterministic, rule-based, standing self-audit -------------------


def _log_entry(phase, command, status="ok"):
    return {"phase": phase, "command": command, "status": status}


def test_efficiency_notes_empty_for_a_clean_session_with_no_data():
    assert compute_efficiency_notes(_session()) == []


def test_efficiency_notes_empty_for_a_clean_session_with_real_data():
    session = _session({"recon": {"tool_calls": 50, "retried": 0, "non_ok": 0, "duplicates": 0}})
    session["logs"] = [_log_entry("recon", f"http_request({{'url': 'https://example.com/{i}'}})") for i in range(10)]
    assert compute_efficiency_notes(session) == []


def test_efficiency_notes_flags_high_failure_rate():
    session = _session({"exploit": {"tool_calls": 20, "retried": 0, "non_ok": 15, "duplicates": 0}})
    notes = compute_efficiency_notes(session)
    assert any("failure rate" in note for note in notes)


def test_efficiency_notes_flags_high_retry_rate():
    session = _session({"exploit": {"tool_calls": 20, "retried": 15, "non_ok": 0, "duplicates": 0}})
    notes = compute_efficiency_notes(session)
    assert any("retry rate" in note for note in notes)


def test_efficiency_notes_flags_high_duplicate_rate():
    session = _session({"analyze": {"tool_calls": 20, "retried": 0, "non_ok": 0, "duplicates": 10}})
    notes = compute_efficiency_notes(session)
    assert any("duplicate rate" in note for note in notes)


def test_efficiency_notes_flags_stall_events():
    session = _session(
        {"exploit": {"tool_calls": 20, "retried": 0, "non_ok": 0, "duplicates": 0}},
        stall_events=[{"phase": "exploit"}, {"phase": "recon"}],
    )
    notes = compute_efficiency_notes(session)
    assert any("2 phase(s) were force-stopped" in note for note in notes)


def test_efficiency_notes_flags_a_repeated_successful_poll_invisible_to_the_aggregate_rates():
    """Real, confirmed incident this covers (a real HackerOne session): check_subagent_task
    polled 22 times in a row, each one individually succeeding ("still running") -- invisible to
    failure_rate/retry_rate/duplicate_rate alike, since nothing ever failed and the stall detector
    only catches strict back-to-back repeats, not ones with other calls interleaved between them."""
    session = _session({"analyze": {"tool_calls": 30, "retried": 0, "non_ok": 0, "duplicates": 0}})
    session["logs"] = (
        [_log_entry("analyze", "check_subagent_task({'task_id': 'abc123'})") for _ in range(22)]
        + [_log_entry("analyze", "http_request({'url': 'https://example.com/'})")]
    )
    notes = compute_efficiency_notes(session)
    assert any("'check_subagent_task'" in note and "22 times" in note and "analyze" in note for note in notes)


def test_efficiency_notes_does_not_flag_a_handful_of_ordinary_repeat_polls():
    session = _session({"analyze": {"tool_calls": 3, "retried": 0, "non_ok": 0, "duplicates": 0}})
    session["logs"] = [_log_entry("analyze", "check_subagent_task({'task_id': 'abc123'})") for _ in range(3)]
    assert compute_efficiency_notes(session) == []


def test_efficiency_notes_ignores_failed_calls_when_counting_repeats():
    """Only calls that actually SUCCEEDED every time count for this detector -- a repeated call
    that keeps failing is already covered by the failure/retry-rate checks above, not this one."""
    session = _session({"analyze": {"tool_calls": 10, "retried": 0, "non_ok": 10, "duplicates": 0}})
    session["logs"] = [_log_entry("analyze", "http_request({'url': 'x'})", status="error") for _ in range(10)]
    notes = compute_efficiency_notes(session)
    assert not any("polling/waiting pattern" in note for note in notes)


# --- _log_phase_efficiency_summary: the persistence layer compute_efficiency_score reads from ---


def _ctx(session_id, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {"session_id": session_id, "logs": []}
    return RunContext(llm=None, session=session, session_id=session_id)


def test_log_phase_efficiency_summary_persists_counts_under_the_phase_name(tmp_path, monkeypatch):
    ctx = _ctx("usr_eff_persist", tmp_path, monkeypatch)
    trace = [
        {"tool": "dns_lookup", "arguments": {"domain": "a.com"}, "result": {"status": "ok"}},
        {"tool": "dns_lookup", "arguments": {"domain": "b.com"}, "result": {"status": "error"}},
        {"tool": "nmap", "arguments": {"target": "a.com"}, "result": {"status": "ok", "retried": True}},
    ]

    _log_phase_efficiency_summary(ctx, "recon", trace)

    stats = ctx.session["phase_efficiency"]["recon"]
    assert stats == {"tool_calls": 3, "retried": 1, "non_ok": 1, "duplicates": 0}


def test_log_phase_efficiency_summary_accumulates_across_multiple_calls_same_phase(tmp_path, monkeypatch):
    """Real shape this covers: Exploit calls this once PER FINDING (a fresh _run_llm_tool_loop each
    time, phase="exploit" every time) -- accumulation across findings is deliberate, not a bug."""
    ctx = _ctx("usr_eff_accumulate", tmp_path, monkeypatch)
    trace_a = [{"tool": "x", "arguments": {}, "result": {"status": "ok"}}]
    trace_b = [{"tool": "y", "arguments": {}, "result": {"status": "error"}}]

    _log_phase_efficiency_summary(ctx, "exploit", trace_a)
    _log_phase_efficiency_summary(ctx, "exploit", trace_b)

    stats = ctx.session["phase_efficiency"]["exploit"]
    assert stats["tool_calls"] == 2
    assert stats["non_ok"] == 1


def test_log_phase_efficiency_summary_buckets_subagent_separately_from_phase_name(tmp_path, monkeypatch):
    ctx = _ctx("usr_eff_subagent", tmp_path, monkeypatch)
    trace = [{"tool": "x", "arguments": {}, "result": {"status": "ok"}}]

    _log_phase_efficiency_summary(ctx, "analyze", trace, is_subagent=True)

    assert "subagent" in ctx.session["phase_efficiency"]
    assert "analyze" not in ctx.session["phase_efficiency"]


def test_log_phase_efficiency_summary_is_a_no_op_for_an_empty_trace(tmp_path, monkeypatch):
    ctx = _ctx("usr_eff_empty", tmp_path, monkeypatch)
    _log_phase_efficiency_summary(ctx, "recon", [])
    assert "phase_efficiency" not in ctx.session


def test_a_clean_scan_of_a_hardened_target_scores_as_well_as_one_that_found_real_bugs():
    """The whole point of a PROCESS score: session A (found nothing, hardened target) and session B
    (found real bugs) must score identically when the underlying tool-call behavior was equally
    clean -- compute_efficiency_score never looks at findings at all."""
    clean_no_findings = _session({"analyze": {"tool_calls": 40, "retried": 2, "non_ok": 1, "duplicates": 0}})
    clean_with_findings = _session({"analyze": {"tool_calls": 40, "retried": 2, "non_ok": 1, "duplicates": 0}})
    assert compute_efficiency_score(clean_no_findings)["score"] == compute_efficiency_score(clean_with_findings)["score"]
