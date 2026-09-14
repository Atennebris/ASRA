"""Total session time (session_fragment.html's "Session time:" line, main.py's session_duration
filter): agent/core.py's run_session/run_focused_exploit set session["started_at"] exactly once
(never reset by a later resume) and session["finished_at"] only on a real "completed" outcome --
an "interrupted"/"failed" session is still not-done, so the duration keeps counting against the
current time instead of freezing at the moment it happened to pause. This is what lets the
displayed duration span an operator-triggered interruption + Resume without resetting to zero or
double-counting.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import request_session_stop, run_focused_exploit, run_session
from sessions import store

import main


def _base_session(session_id, **overrides):
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


class _NeverCalledLLM:
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        raise AssertionError("LLM should never be called once a stop was already requested")


def test_session_duration_filter_formats_a_finished_session():
    session = {"started_at": "2026-07-27T10:00:00+00:00", "finished_at": "2026-07-27T11:30:05+00:00"}
    assert main.format_session_duration(session) == "1h 30m"


def test_session_duration_filter_falls_back_to_now_when_not_yet_finished():
    from datetime import datetime, timedelta, timezone

    started = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    session = {"started_at": started}
    # Still-open session (no finished_at) -- must measure against "now", not blank out.
    assert main.format_session_duration(session) in ("4m 59s", "5m 0s", "5m 1s")


def test_session_duration_filter_blank_without_started_at():
    assert main.format_session_duration({}) == ""


def test_run_session_sets_started_at_once_and_preserves_it_across_a_resume(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _NeverCalledLLM())

    session_id = "usr_duration_resume_test"
    original_started_at = "2026-07-20T08:00:00+00:00"
    store.save_session(session_id, _base_session(session_id, status="failed", started_at=original_started_at))

    request_session_stop(session_id)
    asyncio.run(run_session(session_id))  # stops immediately at the first LLM checkpoint

    saved = store.load_session(session_id)
    assert saved["status"] == "interrupted"
    # Resuming a previously-failed run must not reset the clock back to "now".
    assert saved["started_at"] == original_started_at
    # Not done yet -- must not freeze the duration at this pause.
    assert "finished_at" not in saved


def test_run_session_sets_started_at_on_a_brand_new_run(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _NeverCalledLLM())

    session_id = "usr_duration_fresh_test"
    store.save_session(session_id, _base_session(session_id, status="pending"))

    request_session_stop(session_id)
    asyncio.run(run_session(session_id))

    saved = store.load_session(session_id)
    assert saved.get("started_at")
    assert "finished_at" not in saved


def test_run_session_sets_finished_at_only_when_it_actually_completes(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())

    async def _empty_recon(ctx, target):
        return {"targets": []}

    async def _noop(*args, **kwargs):
        return None

    async def _findings_passthrough(ctx):
        return ctx.session["findings"]

    async def _no_running_jobs(session_id, session):
        return None

    monkeypatch.setattr(core, "_run_recon", _empty_recon)
    monkeypatch.setattr(core, "_run_reverify", _noop)
    monkeypatch.setattr(core, "_run_analyze", _noop)
    monkeypatch.setattr(core, "_run_exploit", _noop)
    monkeypatch.setattr(core, "_run_chain", _findings_passthrough)
    monkeypatch.setattr(core, "_run_validate", _findings_passthrough)
    monkeypatch.setattr(core, "await_all_running_jobs", _no_running_jobs)

    session_id = "usr_duration_completed_test"
    store.save_session(session_id, _base_session(session_id, status="pending"))

    asyncio.run(run_session(session_id))

    saved = store.load_session(session_id)
    assert saved["status"] == "completed"
    assert saved.get("started_at")
    assert saved.get("finished_at")
    assert saved["finished_at"] >= saved["started_at"]


def test_run_session_logs_the_total_duration_exactly_once_on_completion(tmp_path, monkeypatch):
    """Real gap this closes: the total elapsed wall-clock time for a run was only ever
    reconstructable by a human manually subtracting session["started_at"] from
    session["finished_at"] in session.json -- nothing ever wrote it to debug.log. run_session's
    own top-level finally now logs it exactly once regardless of which exit path was taken."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())

    async def _empty_recon(ctx, target):
        return {"targets": []}

    async def _noop(*args, **kwargs):
        return None

    async def _findings_passthrough(ctx):
        return ctx.session["findings"]

    async def _no_running_jobs(session_id, session):
        return None

    monkeypatch.setattr(core, "_run_recon", _empty_recon)
    monkeypatch.setattr(core, "_run_reverify", _noop)
    monkeypatch.setattr(core, "_run_analyze", _noop)
    monkeypatch.setattr(core, "_run_exploit", _noop)
    monkeypatch.setattr(core, "_run_chain", _findings_passthrough)
    monkeypatch.setattr(core, "_run_validate", _findings_passthrough)
    monkeypatch.setattr(core, "await_all_running_jobs", _no_running_jobs)

    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))

    session_id = "usr_duration_log_test"
    store.save_session(session_id, _base_session(session_id, status="pending"))

    asyncio.run(run_session(session_id))

    duration_calls = [a for a in logged if "total duration" in a[0]]
    assert len(duration_calls) == 1
    assert duration_calls[0][1] == session_id
    assert duration_calls[0][2] == "completed"


def test_run_session_attributes_a_crash_to_the_phase_that_actually_failed(tmp_path, monkeypatch):
    """Real incident this covers: Analyze crashed mid-phase (an LLM provider outage) after already
    recording findings via record_finding. compute_resume_entry_point correctly says "resume from
    exploit" (there ARE findings now) -- but the crash's own failure log entry used to be logged
    under phase=resumable_from too, which misattributed an Analyze-phase crash as
    "[exploit] failed: ..." even though Exploit had never even started. The failure log entry must
    reflect the phase _mark_phase_started actually left "started but not finished", not wherever a
    resume would begin."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())

    async def _empty_recon(ctx, target):
        core._mark_phase_started(ctx.session, "recon")
        core._mark_phase_finished(ctx.session, "recon")
        return {"targets": []}

    async def _noop(*args, **kwargs):
        return None

    async def _crashing_analyze(ctx, target, recon_result):
        core._mark_phase_started(ctx.session, "analyze")
        ctx.session["findings"] = [{"title": "Some Finding", "severity": "Medium"}]
        raise RuntimeError("LLM API unreachable")

    monkeypatch.setattr(core, "_run_recon", _empty_recon)
    monkeypatch.setattr(core, "_run_reverify", _noop)
    monkeypatch.setattr(core, "_run_analyze", _crashing_analyze)

    session_id = "usr_phase_attribution_test"
    store.save_session(session_id, _base_session(session_id, status="pending"))

    try:
        asyncio.run(run_session(session_id))
    except RuntimeError:
        pass

    saved = store.load_session(session_id)
    assert saved["status"] == "failed"
    assert saved["resumable_from"] == "exploit"  # findings exist, so THIS is where a resume should start
    failure_entries = [entry for entry in saved["logs"] if entry.get("status") == "failed"]
    assert len(failure_entries) == 1
    assert failure_entries[0]["phase"] == "analyze"  # not "exploit" -- that's not where the crash happened


def test_run_session_freezes_the_chain_validate_reconciliation_span_once(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (a real session, usr_194956): session_fragment.html's "Other
    processing (chain + validate)" line read chain.started_at -> validate.finished_at directly.
    run_focused_exploit/run_hypothesis_verification both legitimately re-call _run_validate later
    (a dedup pass after fresh deep-dive/hypothesis work), which correctly pushes
    phase_timings["validate"]["finished_at"] forward for whatever else reads it live -- but the SAME
    overwrite made that reconciliation line balloon to "2h 46m" in a real session where the actual
    chain+validate work took ~10 minutes. reconciled_at must be set once, right after the pipeline's
    own original run, and never move again even when validate's own finished_at moves later."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())

    async def _empty_recon(ctx, target):
        return {"targets": []}

    async def _noop(*args, **kwargs):
        return None

    async def _real_chain(ctx):
        core._mark_phase_started(ctx.session, "chain")
        core._mark_phase_finished(ctx.session, "chain")
        return ctx.session["findings"]

    async def _real_validate(ctx):
        core._mark_phase_started(ctx.session, "validate")
        core._mark_phase_finished(ctx.session, "validate")
        return ctx.session["findings"]

    async def _no_running_jobs(session_id, session):
        return None

    monkeypatch.setattr(core, "_run_recon", _empty_recon)
    monkeypatch.setattr(core, "_run_reverify", _noop)
    monkeypatch.setattr(core, "_run_analyze", _noop)
    monkeypatch.setattr(core, "_run_exploit", _noop)
    monkeypatch.setattr(core, "_run_chain", _real_chain)
    monkeypatch.setattr(core, "_run_validate", _real_validate)
    monkeypatch.setattr(core, "await_all_running_jobs", _no_running_jobs)

    session_id = "usr_reconciliation_freeze_test"
    store.save_session(session_id, _base_session(session_id, status="pending"))

    asyncio.run(run_session(session_id))

    saved = store.load_session(session_id)
    original_finished_at = saved["phase_timings"]["validate"]["finished_at"]
    original_reconciled_at = saved["phase_timings"]["validate"]["reconciled_at"]
    assert original_reconciled_at == original_finished_at

    # Simulate a later, unrelated re-entry (a deep-dive/hypothesis-verification pass hours
    # afterward, calling _run_validate again) -- finished_at moves forward for live consumers...
    core._mark_phase_finished(saved, "validate")
    assert saved["phase_timings"]["validate"]["finished_at"] != original_finished_at
    # ...but the frozen reconciliation snapshot must never move again.
    assert saved["phase_timings"]["validate"]["reconciled_at"] == original_reconciled_at


def test_run_focused_exploit_sets_finished_at_only_when_it_actually_completes(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: object())

    async def _fake_exploit_for_finding(ctx, target, finding, exploit_tools, deep_dive=False):
        return {"action": "skipped_no_suitable_tool", "tool": None, "reasoning": "no fitting tool"}, []

    monkeypatch.setattr(core, "_run_exploit_for_finding", _fake_exploit_for_finding)

    session_id = "usr_duration_deep_dive_test"
    finding = {"title": "Some Finding", "severity": "Medium", "verification": "verified"}
    old_finished_at = "2026-07-01T00:00:00+00:00"
    store.save_session(
        session_id,
        _base_session(session_id, status="completed", findings=[finding], started_at="2026-07-01T00:00:00+00:00", finished_at=old_finished_at),
    )

    asyncio.run(run_focused_exploit(session_id, "Some Finding"))

    saved = store.load_session(session_id)
    assert saved["status"] == "completed"
    # A later deep dive that itself completes must push finished_at forward, not leave the
    # original scan's stale timestamp in place -- the deep dive itself took real time too.
    assert saved["finished_at"] != old_finished_at
    assert saved["finished_at"] >= saved["started_at"]
