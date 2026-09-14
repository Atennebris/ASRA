"""Plan tab: two real operator-reported issues from a real session (tttt-usr_93a383) --

1. A phase that genuinely concluded (phase_timings[phase].finished_at set) but whose own derived
   status wasn't "done" (a task never resolved, whether reported "blocked" or left as stale
   "pending") used to render as a permanent "active" spinner, indefinitely, long after the session
   moved on and completed. Fixed by overriding the phase-level icon to "blocked" once
   phase_timings confirms real conclusion, unless the phase's own status is genuinely "done".

2. A task/subtask whose started_at == finished_at (only ever observed already resolved, never seen
   "active" first) rendered as a misleading "0s" duration, reading as "this took zero time" when
   it likely took real minutes. Fixed by omitting the duration in that specific case.
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


def _session(session_id, status, logs, plan_phases, phase_timings=None):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": logs, "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "plan": {"phases": plan_phases, "version": 1, "updated_at": "now"},
        "phase_timings": phase_timings or {},
    }


def test_a_concluded_phase_with_an_unresolved_task_shows_blocked_not_a_forever_spinner(tmp_path, monkeypatch):
    session_id = "usr_plan_concluded_blocked_test"
    plan_phases = [{
        "phase": "analyze", "rationale": "", "status": "active",
        "tasks": [
            {"text": "Confirm vuln classes", "status": "done", "subtasks": [{"text": "S1", "status": "done", "recommended_tools": []}]},
            {"text": "Check remaining endpoints", "status": "pending", "subtasks": [{"text": "S2", "status": "pending", "recommended_tools": []}]},
        ],
    }]
    session = _session(
        session_id, "completed", logs=[_log_entry(0, "exploit")], plan_phases=plan_phases,
        phase_timings={"analyze": {"started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:08:00+00:00"}},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Blocked" in resp.text  # the plan_status_icon's own title attribute


def test_a_concluded_phases_own_unresolved_task_and_subtask_also_show_blocked_not_pending(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes: the phase-level "blocked" fallback above was applied
    one level up only -- a concluded phase's own icon correctly showed "blocked", but the task and
    subtask underneath it (never explicitly marked done/blocked by the model) fell all the way
    through to "pending", directly contradicting the phase icon right next to them and the real
    started_at/duration text already shown for that same task. Session here has ONE phase, one
    unresolved task, one unresolved subtask -- exactly 3 "Blocked" icons once all three levels
    agree, not just the phase's own.
    """
    session_id = "usr_plan_concluded_task_subtask_blocked_test"
    plan_phases = [{
        "phase": "analyze", "rationale": "", "status": "active",
        "tasks": [
            {"text": "Check remaining endpoints", "status": "pending", "started_at": "2026-01-01T00:01:00+00:00", "subtasks": [
                {"text": "S2", "status": "pending", "started_at": "2026-01-01T00:01:00+00:00", "recommended_tools": []},
            ]},
        ],
    }]
    session = _session(
        session_id, "completed", logs=[_log_entry(0, "exploit")], plan_phases=plan_phases,
        phase_timings={"analyze": {"started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:08:00+00:00"}},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert resp.text.count("title=\"Blocked") == 3  # phase + task + subtask, all in agreement


def test_a_phase_that_crashed_mid_way_shows_blocked_not_a_forever_spinner(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (dexonline-usr_58a900): the session crashed INSIDE
    Recon itself (every configured LLM provider exhausted) -- phase_timings["recon"] has a real
    started_at but NO finished_at at all (_mark_phase_finished never runs for a phase that
    crashed instead of completing), so the original finished_at-only phase_concluded check never
    fired. session.status is "failed" and nothing is running, yet the Plan tab kept showing a
    live spinner on the task the model's last update_plan call had left "active" -- the same
    misleading "still working" read the finished_at fix already exists to prevent, just via a
    crash path that fix didn't cover.
    """
    session_id = "usr_plan_crashed_mid_phase_test"
    plan_phases = [{
        "phase": "recon", "rationale": "", "status": "active",
        "tasks": [
            {"text": "Done task", "status": "done", "subtasks": [{"text": "S1", "status": "done", "recommended_tools": []}]},
            {"text": "Gather historical URLs via Wayback", "status": "active", "subtasks": [
                {"text": "Run wayback_urls", "status": "active", "started_at": "2026-08-06T21:35:10+00:00", "recommended_tools": []},
            ]},
        ],
    }]
    session = _session(
        session_id, "failed", logs=[_log_entry(0, "recon")], plan_phases=plan_phases,
        # started_at only -- no finished_at, exactly what a mid-phase crash leaves behind.
        phase_timings={"recon": {"started_at": "2026-08-06T21:08:07+00:00"}},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "title=\"Blocked" in resp.text
    # The actual rendered element, not a bare substring -- the chat panel's own inline script
    # (chat_panel.html, present on every session page regardless of status) legitimately contains
    # the literal text "asra-spinner" as a CSS-selector string (querySelector(".asra-spinner")),
    # which a bare substring check would misread as a live spinner being rendered.
    assert 'class="asra-spinner"' not in resp.text  # no live spinner element anywhere once the session has ended


def test_a_still_running_phase_is_never_shown_blocked_even_if_a_task_is_pending(tmp_path, monkeypatch):
    session_id = "usr_plan_still_running_not_blocked_test"
    plan_phases = [{
        "phase": "analyze", "rationale": "", "status": "active",
        "tasks": [{"text": "T", "status": "pending", "subtasks": [{"text": "S", "status": "pending", "recommended_tools": []}]}],
    }]
    session = _session(
        session_id, "processing", logs=[_log_entry(0, "analyze")], plan_phases=plan_phases,
        phase_timings={"analyze": {"started_at": "2026-01-01T00:00:00+00:00"}},  # no finished_at -- still running
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "In progress" in resp.text
    assert "title=\"Blocked" not in resp.text


def test_a_fully_done_phase_still_shows_done_not_blocked(tmp_path, monkeypatch):
    session_id = "usr_plan_fully_done_test"
    plan_phases = [{
        "phase": "recon", "rationale": "", "status": "done",
        "tasks": [{"text": "T", "status": "done", "subtasks": [{"text": "S", "status": "done", "recommended_tools": []}]}],
    }]
    session = _session(
        session_id, "completed", logs=[_log_entry(0, "exploit")], plan_phases=plan_phases,
        phase_timings={"recon": {"started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:05:00+00:00"}},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "title=\"Blocked" not in resp.text


def test_a_literal_blocked_subtask_renders_the_blocked_icon(tmp_path, monkeypatch):
    session_id = "usr_plan_literal_blocked_subtask_test"
    plan_phases = [{
        "phase": "exploit", "rationale": "", "status": "blocked",
        "tasks": [{"text": "T", "status": "blocked", "subtasks": [
            {"text": "S", "status": "blocked", "recommended_tools": []},
        ]}],
    }]
    session = _session(
        session_id, "completed", logs=[_log_entry(0, "exploit")], plan_phases=plan_phases,
        phase_timings={"exploit": {"started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:05:00+00:00"}},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.text.count("title=\"Blocked") >= 1


def test_same_instant_started_and_finished_at_omits_the_misleading_0s(tmp_path, monkeypatch):
    session_id = "usr_plan_same_instant_duration_test"
    same_ts = "2026-01-01T00:00:00+00:00"
    plan_phases = [{
        "phase": "recon", "rationale": "", "status": "done",
        "tasks": [{
            "text": "T", "status": "done", "started_at": same_ts, "finished_at": same_ts,
            "subtasks": [{"text": "S", "status": "done", "started_at": same_ts, "finished_at": same_ts, "recommended_tools": []}],
        }],
    }]
    session = _session(session_id, "completed", logs=[_log_entry(0, "exploit")], plan_phases=plan_phases)
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert ">0s<" not in resp.text
    assert "Task duration" not in resp.text
    assert "Subtask duration" not in resp.text


def test_a_real_measured_duration_still_renders_normally(tmp_path, monkeypatch):
    """Regression guard for the 0s fix above -- a genuinely different started_at/finished_at pair
    must still show its real duration, not get accidentally suppressed too."""
    session_id = "usr_plan_real_duration_test"
    plan_phases = [{
        "phase": "recon", "rationale": "", "status": "done",
        "tasks": [{
            "text": "T", "status": "done",
            "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:03:00+00:00",
            "subtasks": [{"text": "S", "status": "done", "recommended_tools": []}],
        }],
    }]
    session = _session(session_id, "completed", logs=[_log_entry(0, "exploit")], plan_phases=plan_phases)
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "3m" in resp.text
