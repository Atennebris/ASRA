"""Live-ticking durations (static/js/live_duration.js): session/phase/task/subtask durations used
to only visibly change on the next real SSE update, not with the actual passage of time -- real
operator complaint: "the numbers should be dynamic, changing in real time." A still-in-progress
duration (no finished_at yet) gets data-live-duration + data-started-at so the client-side ticker
can take over between real page renders; an already-finished one renders as plain static text,
correctly frozen -- nothing to tick.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _log_entry(step, phase):
    return {
        "step": step, "phase": phase, "thought": None, "command": "dns_lookup({})",
        "status": "success", "error": None, "finding_title": None, "duration_ms": 120.0,
        "subagent_task_id": None, "subagent_name": None, "at": "2026-01-01T00:00:00+00:00",
    }


def _base_session(session_id, status):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


def test_session_time_is_live_while_still_running(tmp_path, monkeypatch):
    session_id = "usr_live_duration_session_running_test"
    session = _base_session(session_id, "processing")
    session["started_at"] = "2026-01-01T00:00:00+00:00"
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert 'data-live-duration data-started-at="2026-01-01T00:00:00+00:00"' in resp.text


def test_session_time_is_static_once_finished(tmp_path, monkeypatch):
    session_id = "usr_live_duration_session_finished_test"
    session = _base_session(session_id, "completed")
    session["started_at"] = "2026-01-01T00:00:00+00:00"
    session["finished_at"] = "2026-01-01T00:05:00+00:00"
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "data-live-duration" not in resp.text


def test_phase_duration_is_live_while_the_phase_has_no_finished_at(tmp_path, monkeypatch):
    session_id = "usr_live_duration_phase_running_test"
    session = _base_session(session_id, "processing")
    session["logs"] = [_log_entry(0, "recon")]
    session["phase_timings"] = {"recon": {"started_at": "2026-01-01T00:00:00+00:00"}}
    session["plan"] = {"phases": [{
        "phase": "recon", "rationale": "", "status": "active",
        "tasks": [{"text": "T", "status": "active", "subtasks": [{"text": "S", "status": "active", "recommended_tools": []}]}],
    }], "version": 1, "updated_at": "now"}
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert 'data-live-duration data-started-at="2026-01-01T00:00:00+00:00"' in resp.text


def test_phase_duration_is_static_once_the_phase_has_finished_at(tmp_path, monkeypatch):
    session_id = "usr_live_duration_phase_finished_test"
    session = _base_session(session_id, "processing")
    session["logs"] = [_log_entry(0, "analyze")]
    session["phase_timings"] = {"recon": {"started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:05:00+00:00"}}
    session["plan"] = {"phases": [{
        "phase": "recon", "rationale": "", "status": "done",
        "tasks": [{"text": "T", "status": "done", "subtasks": [{"text": "S", "status": "done", "recommended_tools": []}]}],
    }], "version": 1, "updated_at": "now"}
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "data-live-duration" not in resp.text


def test_phase_duration_is_static_once_the_session_has_concluded_even_without_its_own_finished_at(tmp_path, monkeypatch):
    """Real, confirmed gap: a phase that crashed mid-run (LLM provider exhausted) and was never
    re-entered on resume (findings already durable, so run_session skipped straight past it) never
    reaches _mark_phase_finished -- phase_timings[phase] stays {started_at only} forever, even
    though the phase, and the whole session, are definitively over (session.status=="completed").
    Before this fix, format_duration_between fell back to "now" whenever finished_at was missing,
    so this phase's own header kept ticking upward on every page load, days after the session
    actually finished. Once the session itself has concluded, freeze at session.finished_at."""
    session_id = "usr_live_duration_phase_crashed_no_finished_at_test"
    session = _base_session(session_id, "completed")
    session["started_at"] = "2026-01-01T00:00:00+00:00"
    session["finished_at"] = "2026-01-01T00:10:00+00:00"
    session["logs"] = [_log_entry(0, "exploit")]
    session["phase_timings"] = {"analyze": {"started_at": "2026-01-01T00:01:00+00:00"}}
    session["plan"] = {"phases": [{
        "phase": "analyze", "rationale": "", "status": "active",
        "tasks": [{"text": "T", "status": "active", "subtasks": [{"text": "S", "status": "active", "recommended_tools": []}]}],
    }], "version": 1, "updated_at": "now"}
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "data-live-duration" not in resp.text
    assert "9m" in resp.text  # 00:01:00 -> session.finished_at 00:10:00 = 9 minutes


def test_task_and_subtask_durations_are_live_while_still_running(tmp_path, monkeypatch):
    session_id = "usr_live_duration_task_running_test"
    session = _base_session(session_id, "processing")
    session["logs"] = [_log_entry(0, "recon")]
    session["plan"] = {"phases": [{
        "phase": "recon", "rationale": "", "status": "active",
        "tasks": [{
            "text": "T", "status": "active", "started_at": "2026-01-01T00:01:00+00:00",
            "subtasks": [{
                "text": "S", "status": "active", "recommended_tools": [],
                "started_at": "2026-01-01T00:02:00+00:00",
            }],
        }],
    }], "version": 1, "updated_at": "now"}
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert 'data-live-duration data-started-at="2026-01-01T00:01:00+00:00"' in resp.text
    assert 'data-live-duration data-started-at="2026-01-01T00:02:00+00:00"' in resp.text


def test_task_duration_is_static_once_finished_at_is_set(tmp_path, monkeypatch):
    session_id = "usr_live_duration_task_finished_test"
    session = _base_session(session_id, "processing")
    session["logs"] = [_log_entry(0, "analyze")]
    session["plan"] = {"phases": [{
        "phase": "recon", "rationale": "", "status": "done",
        "tasks": [{
            "text": "T", "status": "done",
            "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:03:00+00:00",
            "subtasks": [{"text": "S", "status": "done", "recommended_tools": []}],
        }],
    }], "version": 1, "updated_at": "now"}
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "data-live-duration" not in resp.text


def test_other_processing_line_shows_chain_plus_validate_span(tmp_path, monkeypatch):
    """Real operator complaint this answers: Session time (session.started_at -> finished_at) came
    out bigger than Recon+Analyze+Exploit's own shown durations added together, with nothing
    telling the operator why -- Chain and Validate run for real time after Exploit but had no
    display of their own at all. chain.started_at -> validate.finished_at is that whole span
    (they run back-to-back)."""
    session_id = "usr_live_duration_other_processing_test"
    session = _base_session(session_id, "completed")
    session["started_at"] = "2026-01-01T00:00:00+00:00"
    session["finished_at"] = "2026-01-01T00:10:00+00:00"
    session["phase_timings"] = {
        "chain": {"started_at": "2026-01-01T00:07:00+00:00", "finished_at": "2026-01-01T00:07:30+00:00"},
        "validate": {"started_at": "2026-01-01T00:07:30+00:00", "finished_at": "2026-01-01T00:08:00+00:00"},
    }
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Other processing" in resp.text
    assert "1m" in resp.text  # 00:07:00 -> 00:08:00 = 1 minute


def test_other_processing_line_is_absent_when_chain_never_ran(tmp_path, monkeypatch):
    session_id = "usr_live_duration_no_other_processing_test"
    session = _base_session(session_id, "completed")
    session["started_at"] = "2026-01-01T00:00:00+00:00"
    session["finished_at"] = "2026-01-01T00:10:00+00:00"
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Other processing" not in resp.text


def test_other_processing_line_shows_reverify_span(tmp_path, monkeypatch):
    """Same reconciliation gap as chain+validate, different position in the pipeline: a rescan's
    reverify pass runs BEFORE Analyze, so it needs its own line, not folded into chain+validate's.
    Real, confirmed gap this closes: a genuine 52m47s block of real reverify work was completely
    invisible here, with nothing explaining why Session time ran well past what
    Recon/Analyze/Exploit's own shown durations added up to."""
    session_id = "usr_live_duration_reverify_processing_test"
    session = _base_session(session_id, "completed")
    session["started_at"] = "2026-01-01T00:00:00+00:00"
    session["finished_at"] = "2026-01-01T00:10:00+00:00"
    session["phase_timings"] = {
        "reverify": {"started_at": "2026-01-01T00:01:00+00:00", "finished_at": "2026-01-01T00:03:00+00:00"},
    }
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Other processing (reverify)" in resp.text
    assert "2m" in resp.text  # 00:01:00 -> 00:03:00 = 2 minutes
