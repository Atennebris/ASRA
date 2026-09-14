"""session["time_budget_seconds"] (New Project form's Time budget field, sessions/store.py's
create_session): agent/core.py's run_session keeps looping additional full recon->analyze->exploit
->chain->validate passes for as long as real time remains instead of stopping at the first natural
completion, folding each pass's own findings into the next as carried_over_findings for real
re-verification (the same in-place-rescan data shape main.py's rescan_session_in_place already
uses). None (the default) is byte-for-byte the original, unlimited, single-pass behavior.
"""
import asyncio
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.core import (
    _prepare_next_time_budget_pass,
    _time_budget_deadline_timestamp,
    _time_budget_pass_is_a_repeat,
    _time_budget_remaining,
    run_session,
)
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


def _run(coro):
    return asyncio.run(coro)


def _base_session(session_id, **overrides):
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


# --- _time_budget_deadline_timestamp / _time_budget_remaining -----------------------------------


def test_deadline_is_none_when_no_budget_was_ever_set():
    session = {"started_at": datetime.now(timezone.utc).isoformat()}
    assert _time_budget_deadline_timestamp(session) is None
    assert _time_budget_remaining(session) is False


def test_deadline_is_none_for_a_budget_below_the_minimum():
    session = {"started_at": datetime.now(timezone.utc).isoformat(), "time_budget_seconds": 30}
    assert _time_budget_deadline_timestamp(session) is None


def test_deadline_is_none_without_a_started_at():
    assert _time_budget_deadline_timestamp({"time_budget_seconds": 3600}) is None


def test_remaining_is_true_when_the_deadline_is_still_in_the_future():
    started = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    session = {"started_at": started, "time_budget_seconds": 3600}
    assert _time_budget_remaining(session) is True


def test_remaining_is_false_once_the_deadline_has_passed():
    started = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    session = {"started_at": started, "time_budget_seconds": 3600}
    assert _time_budget_remaining(session) is False


# --- _time_budget_pass_is_a_repeat ---------------------------------------------------------------


def test_first_pass_is_never_a_repeat():
    """The very first pass has nothing to compare against — even an empty finding set must not be
    treated as a repeat immediately, or a time-budgeted session would never even get a SECOND pass."""
    session = {"findings": [{"title": "A"}]}
    assert _time_budget_pass_is_a_repeat(session) is False


def test_second_pass_with_the_same_titles_is_a_repeat():
    session = {"findings": [{"title": "A"}, {"title": "B"}]}
    _time_budget_pass_is_a_repeat(session)  # seeds the "previous" snapshot
    session["findings"] = [{"title": "B"}, {"title": "A"}]  # same set, different order
    assert _time_budget_pass_is_a_repeat(session) is True


def test_second_pass_with_a_different_title_is_not_a_repeat():
    session = {"findings": [{"title": "A"}]}
    _time_budget_pass_is_a_repeat(session)
    session["findings"] = [{"title": "A"}, {"title": "B"}]
    assert _time_budget_pass_is_a_repeat(session) is False


# --- _prepare_next_time_budget_pass --------------------------------------------------------------


def test_prepare_next_pass_moves_findings_into_carried_over_findings():
    session = {"findings": [{"title": "A"}], "reverification_history": [{"title": "old"}]}
    _prepare_next_time_budget_pass(session)
    assert session["carried_over_findings"] == [{"title": "A"}]
    # findings must stay visible across the pass boundary (as pending-reverify placeholders), not
    # vanish to [] until the next pass's own Reverify phase gets around to each one -- see
    # _prepare_next_time_budget_pass's own docstring for the real incident this covers.
    assert session["findings"] == [{"title": "A", "_carried_over_pending_reverify": True}]
    assert session["reverification_history"] == []
    assert session["time_budget_passes"] == 2


def test_prepare_next_pass_increments_across_repeated_calls():
    session = {"findings": []}
    _prepare_next_time_budget_pass(session)
    _prepare_next_time_budget_pass(session)
    assert session["time_budget_passes"] == 3


# --- run_session: full end-to-end looping behavior -----------------------------------------------


def _wire_common_noops(monkeypatch):
    async def _noop(*args, **kwargs):
        return None

    async def _no_running_jobs(session_id, session):
        return None

    monkeypatch.setattr(core, "_run_reverify", _noop)
    monkeypatch.setattr(core, "_run_exploit", _noop)
    monkeypatch.setattr(core, "await_all_running_jobs", _no_running_jobs)


def test_run_session_without_a_time_budget_runs_exactly_one_pass(tmp_path, monkeypatch):
    """The existing, unlimited behavior must be completely unchanged when time_budget_seconds was
    never set — the exact scenario every OTHER run_session test in this project already covers,
    reconfirmed here as this new mechanism's own explicit baseline."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())
    _wire_common_noops(monkeypatch)

    recon_calls = {"n": 0}

    async def _empty_recon(ctx, target):
        recon_calls["n"] += 1
        return {"targets": []}

    async def _findings_passthrough(ctx):
        return ctx.session["findings"]

    monkeypatch.setattr(core, "_run_recon", _empty_recon)
    async def _noop_analyze(ctx, target, recon_result):
        return None

    monkeypatch.setattr(core, "_run_analyze", _noop_analyze)
    monkeypatch.setattr(core, "_run_chain", _findings_passthrough)
    monkeypatch.setattr(core, "_run_validate", _findings_passthrough)

    session_id = "usr_no_time_budget_test"
    store.save_session(session_id, _base_session(session_id, status="pending"))

    _run(run_session(session_id))

    assert recon_calls["n"] == 1
    saved = store.load_session(session_id)
    assert saved["status"] == "completed"
    assert saved.get("time_budget_passes") is None


def test_run_session_keeps_looping_while_time_budget_remains_then_stops_on_repeat(tmp_path, monkeypatch):
    """Real behavior this proves end-to-end: with a generous time budget still remaining, the
    pipeline runs MULTIPLE full passes automatically — each finding a genuinely different result at
    first (simulating "dig deeper, find more") — and only stops once two consecutive passes produce
    the identical finding set, not because the budget ran out."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())
    _wire_common_noops(monkeypatch)

    async def _empty_recon(ctx, target):
        return {"targets": []}

    # Pass 1 finds "A", pass 2 finds "A"+"B" (real new progress), pass 3 finds "A"+"B" again
    # (nothing new) -- the stall guard must fire on pass 3, stopping a 4th pass from ever running.
    pass_findings = [
        [{"title": "A", "severity": "Medium"}],
        [{"title": "A", "severity": "Medium"}, {"title": "B", "severity": "Medium"}],
        [{"title": "A", "severity": "Medium"}, {"title": "B", "severity": "Medium"}],
        [{"title": "A", "severity": "Medium"}, {"title": "B", "severity": "Medium"}],
    ]
    call_count = {"n": 0}

    async def _analyze_adds_this_passes_findings(ctx, target, recon_result):
        idx = min(call_count["n"], len(pass_findings) - 1)
        call_count["n"] += 1
        ctx.session["findings"] = list(pass_findings[idx])

    async def _findings_passthrough(ctx):
        return ctx.session["findings"]

    monkeypatch.setattr(core, "_run_recon", _empty_recon)
    monkeypatch.setattr(core, "_run_analyze", _analyze_adds_this_passes_findings)
    monkeypatch.setattr(core, "_run_chain", _findings_passthrough)
    monkeypatch.setattr(core, "_run_validate", _findings_passthrough)

    session_id = "usr_time_budget_loops_test"
    started_at = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    store.save_session(session_id, _base_session(
        session_id, status="pending", started_at=started_at, time_budget_seconds=3600,  # 1h, generous
    ))

    _run(run_session(session_id))

    # Exactly 3 real passes: pass 1 (finds A), pass 2 (finds A+B, genuinely new), pass 3 (finds
    # A+B again, identical to pass 2 -- the repeat that stops a 4th pass from ever starting).
    assert call_count["n"] == 3
    saved = store.load_session(session_id)
    assert saved["status"] == "completed"
    assert saved["time_budget_passes"] == 3
    assert {f["title"] for f in saved["findings"]} == {"A", "B"}


def test_run_session_stops_immediately_when_the_budget_has_already_expired(tmp_path, monkeypatch):
    """A session resumed long after its own deadline already passed (started_at far enough in the
    past) must run exactly one pass and stop — same as having no budget at all, not an unbounded
    catch-up loop."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())
    _wire_common_noops(monkeypatch)

    recon_calls = {"n": 0}

    async def _empty_recon(ctx, target):
        recon_calls["n"] += 1
        return {"targets": []}

    async def _findings_passthrough(ctx):
        return ctx.session["findings"]

    async def _noop_analyze(ctx, target, recon_result):
        return None

    monkeypatch.setattr(core, "_run_recon", _empty_recon)
    monkeypatch.setattr(core, "_run_analyze", _noop_analyze)
    monkeypatch.setattr(core, "_run_chain", _findings_passthrough)
    monkeypatch.setattr(core, "_run_validate", _findings_passthrough)

    session_id = "usr_time_budget_expired_test"
    started_at = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat()
    store.save_session(session_id, _base_session(
        session_id, status="pending", started_at=started_at, time_budget_seconds=3600,  # already over
    ))

    _run(run_session(session_id))

    assert recon_calls["n"] == 1
    saved = store.load_session(session_id)
    assert saved["status"] == "completed"
    assert saved.get("time_budget_passes") is None  # never even entered a second pass


# --- POST /api/scan: New Project form's Time budget field (preset / custom) ----------------------


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def _isolate_routes(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)


def test_start_scan_with_no_time_budget_selected_leaves_it_unset(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post("/api/scan", data={"name": "No Budget Project", "target": "example.com"}, follow_redirects=False)
        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert load_session(session_id)["time_budget_seconds"] is None
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_start_scan_with_a_fixed_preset_sets_the_matching_seconds(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post(
            "/api/scan",
            data={"name": "2h Budget Project", "target": "example.com", "time_budget_preset": "7200"},
            follow_redirects=False,
        )
        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert load_session(session_id)["time_budget_seconds"] == 7200
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_start_scan_with_a_custom_value_converts_minutes_to_seconds(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post(
            "/api/scan",
            data={
                "name": "Custom Budget Project", "target": "example.com",
                "time_budget_preset": "custom", "time_budget_custom_minutes": "90",
            },
            follow_redirects=False,
        )
        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert load_session(session_id)["time_budget_seconds"] == 5400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_start_scan_with_a_malformed_custom_value_tolerates_down_to_no_budget(tmp_path, monkeypatch):
    """Same "don't fail the whole form over one bad sub-field" discipline this route already applies
    to initial_hypotheses/out_of_scope_notes -- a blank or non-numeric custom field with "custom"
    selected must not 400 the whole project creation."""
    _isolate_routes(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post(
            "/api/scan",
            data={"name": "Bad Custom Budget", "target": "example.com", "time_budget_preset": "custom", "time_budget_custom_minutes": "not a number"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert load_session(session_id)["time_budget_seconds"] is None
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


# --- POST /api/session/{id}/extend-time-budget ----------------------------------------------------


def _make_time_budgeted_session(name="Budgeted project", target="example.com", **overrides):
    session_id = create_session(target, name=name, time_budget_seconds=3600)
    session = load_session(session_id)
    session["status"] = "completed"
    # create_session() alone never sets started_at (only a real run_session() call does, once it
    # actually starts) -- a session this helper builds must look like a real, already-run one, not
    # a still-"created"/never-started shell, or extend_time_budget's own real "has this ever
    # actually started" guard would reject it for the wrong reason.
    session["started_at"] = "2026-08-14T10:00:00+00:00"
    session.update(overrides)
    store.save_session(session_id, session)
    return session_id


def test_extend_time_budget_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post("/api/session/usr_does_not_exist/extend-time-budget", data={"time_budget_preset": "3600"})
        assert resp.status_code == 404
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_extend_time_budget_rejects_a_currently_running_session(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        session_id = _make_time_budgeted_session(status="processing")
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/extend-time-budget", data={"time_budget_preset": "3600"})
        assert resp.status_code == 400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_extend_time_budget_rejects_no_real_additional_time(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        session_id = _make_time_budgeted_session()
        client = TestClient(main.app)
        resp = client.post(f"/api/session/{session_id}/extend-time-budget", data={})
        assert resp.status_code == 400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_extend_time_budget_adds_to_the_existing_budget_and_resumes(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        session_id = _make_time_budgeted_session()  # starts at 3600s
        client = TestClient(main.app)
        resp = client.post(
            f"/api/session/{session_id}/extend-time-budget",
            data={"time_budget_preset": "3600"}, follow_redirects=False,
        )
        assert resp.status_code == 303
        # Same session, never a new project.
        assert resp.headers["location"].rstrip("/").rsplit("/", 1)[-1] == session_id

        saved = load_session(session_id)
        assert saved["time_budget_seconds"] == 7200  # 3600 (original) + 3600 (added), additive
        assert saved["status"] == "processing"
        assert saved["findings"] == []
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_extend_time_budget_moves_existing_findings_into_carried_over_findings(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        finding = {
            "title": "Old Finding", "severity": "High", "description": "d", "technology": "PHP",
            "exploitation_scenario": "remote_direct", "qualifies_for_bounty": "qualifying",
            "reproduction_steps": "steps", "evidence_ref": "old evidence",
            "found_at": "2026-01-01T00:00:00+00:00", "verification": "verified",
        }
        session_id = _make_time_budgeted_session(findings=[finding])
        client = TestClient(main.app)
        client.post(f"/api/session/{session_id}/extend-time-budget", data={"time_budget_preset": "3600"}, follow_redirects=False)

        saved = load_session(session_id)
        # Same pending-reverify placeholder as rescan_session_in_place uses -- findings must stay
        # visible (not [] ) until Reverify actually re-checks each one.
        assert len(saved["findings"]) == 1
        assert saved["findings"][0]["title"] == "Old Finding"
        assert saved["findings"][0]["_carried_over_pending_reverify"] is True
        assert saved["carried_over_findings"][0]["title"] == "Old Finding"
        assert "_carried_over_pending_reverify" not in saved["carried_over_findings"][0]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_extend_time_budget_supports_a_custom_value(tmp_path, monkeypatch):
    _isolate_routes(tmp_path, monkeypatch)
    try:
        session_id = _make_time_budgeted_session()  # starts at 3600s
        client = TestClient(main.app)
        client.post(
            f"/api/session/{session_id}/extend-time-budget",
            data={"time_budget_preset": "custom", "time_budget_custom_minutes": "15"},
            follow_redirects=False,
        )
        assert load_session(session_id)["time_budget_seconds"] == 4500  # 3600 + 15*60
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
