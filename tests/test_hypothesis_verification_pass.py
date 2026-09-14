"""run_hypothesis_verification: the idle-session path for investigating one hypothesis, triggered
by main.py's /api/session/{id}/hypotheses route once a session is no longer live -- either a fresh
operator-submitted paste (hypothesis_id absent, structured into {text, evidence} via
_structure_hypothesis_text -- a real LLM call, mocked here, own dedicated tests in
tests/test_hypothesis_structuring.py) or an "Investigate now"/"Prioritize now" re-check of an
already-open hypothesis (hypothesis_id given, no structuring needed). Mirrors run_focused_exploit's
own orchestration tests (tests/test_exploit_deep_dive.py) -- _run_llm_tool_loop/_run_validate are
mocked directly rather than driving a real LLM loop, per that file's own stated rationale.
"""
import asyncio

import agent.core as core
from agent.core import run_hypothesis_verification
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _make_idle_session(session_id, hypotheses=None, findings=None):
    return {
        "session_id": session_id,
        "target": "example.com",
        "status": "completed",
        "logs": [],
        "findings": findings or [],
        "hypotheses": hypotheses or [],
        "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


async def _fake_llm_tool_loop_noop(ctx, prompt, task, tool_specs, phase, **kwargs):
    return None, []


async def _fake_structure_passthrough(ctx, raw_text):
    """Stands in for the real LLM structuring call -- splits nothing, just wraps the raw text as
    {text: raw_text, evidence: ""}, since these tests care about run_hypothesis_verification's own
    orchestration, not the structuring behavior itself."""
    return {"text": raw_text, "evidence": ""}


def test_run_hypothesis_verification_structures_and_persists_a_fresh_hint_before_running(monkeypatch):
    session_id = "usr_hyp_verify_fresh"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", _fake_llm_tool_loop_noop)

    async def fake_structure(ctx, raw_text):
        assert raw_text == "confirmed on a different scan: exposed .git"
        return {"text": "check for exposed .git", "evidence": "saw a 403 on /.git/config"}

    monkeypatch.setattr(core, "_structure_hypothesis_text", fake_structure)

    _run(run_hypothesis_verification(session_id, raw_text="confirmed on a different scan: exposed .git"))

    reloaded = store.load_session(session_id)
    assert len(reloaded["hypotheses"]) == 1
    entry = reloaded["hypotheses"][0]
    assert entry["text"] == "check for exposed .git"
    assert entry["evidence"] == "saw a 403 on /.git/config"
    assert entry["source"] == "user"
    assert entry["source_phase"] == "post_completion"
    assert reloaded["status"] == "completed"


def test_run_hypothesis_verification_survives_a_pass_that_never_resolves_it(monkeypatch):
    """Real requirement this closes: if the pass times out/crashes before ever calling
    resolve_hypothesis, the operator's own submitted lead must still be a real, visible, still-open
    hypothesis afterward -- not silently lost just because nothing got around to confirming it."""
    session_id = "usr_hyp_verify_survives"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", _fake_llm_tool_loop_noop)
    monkeypatch.setattr(core, "_structure_hypothesis_text", _fake_structure_passthrough)

    _run(run_hypothesis_verification(session_id, raw_text="check for exposed .git"))

    assert store.load_session(session_id)["hypotheses"][0]["status"] == "unconfirmed"


def test_run_hypothesis_verification_leaves_a_note_when_no_verdict_is_reached(monkeypatch):
    """Real, confirmed operator complaint this closes: resolve_hypothesis can only ever move a
    hypothesis to "confirmed"/"ruled_out" (agent/tools/__init__.py's _VALID_HYPOTHESIS_STATUSES) --
    a pass that genuinely investigated (real tool calls happened) but never called it left the card
    showing nothing but the bare "Unconfirmed" badge, with no way to tell "actually looked at, still
    unclear" apart from "never looked at yet". A completed pass that didn't resolve it must now
    leave a resolution_note explaining that, even though status itself correctly stays unconfirmed."""
    session_id = "usr_hyp_verify_inconclusive_note"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", _fake_llm_tool_loop_noop)
    monkeypatch.setattr(core, "_structure_hypothesis_text", _fake_structure_passthrough)

    _run(run_hypothesis_verification(session_id, raw_text="check for exposed .git"))

    entry = store.load_session(session_id)["hypotheses"][0]
    assert entry["status"] == "unconfirmed"
    assert entry["resolution_note"]


def test_run_hypothesis_verification_re_investigates_an_existing_entry_without_duplicating(monkeypatch):
    session_id = "usr_hyp_verify_existing"
    existing = {
        "id": "abc123def456", "text": "old lead", "evidence": "", "source_phase": "recon", "source": "agent",
        "status": "unconfirmed", "resolution_note": None, "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
    }
    session = _make_idle_session(session_id, hypotheses=[existing])
    store.save_session(session_id, session)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", _fake_llm_tool_loop_noop)

    _run(run_hypothesis_verification(session_id, hypothesis_id="abc123def456"))

    reloaded = store.load_session(session_id)
    assert len(reloaded["hypotheses"]) == 1  # no duplicate created
    assert reloaded["hypotheses"][0]["id"] == "abc123def456"


def test_run_hypothesis_verification_unknown_id_is_ignored_not_fatal(monkeypatch):
    session_id = "usr_hyp_verify_unknown_id"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())

    _run(run_hypothesis_verification(session_id, hypothesis_id="doesnotexist"))

    reloaded = store.load_session(session_id)
    assert reloaded["status"] == "completed"  # untouched, never flipped to processing
    assert reloaded["hypotheses"] == []


def test_run_hypothesis_verification_runs_validate_when_a_new_finding_is_recorded(monkeypatch):
    session_id = "usr_hyp_verify_new_finding"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)

    async def fake_llm_tool_loop(ctx, prompt, task, tool_specs, phase, **kwargs):
        ctx.session["findings"].append({"title": "Exposed .git directory", "severity": "Medium", "verification": "verified"})
        return None, []

    validate_calls = []

    async def fake_run_validate(ctx):
        validate_calls.append(len(ctx.session["findings"]))
        return ctx.session["findings"]

    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", fake_llm_tool_loop)
    monkeypatch.setattr(core, "_run_validate", fake_run_validate)
    monkeypatch.setattr(core, "_structure_hypothesis_text", _fake_structure_passthrough)

    _run(run_hypothesis_verification(session_id, raw_text="check for exposed .git"))

    assert validate_calls == [1]


def test_run_hypothesis_verification_skips_validate_when_nothing_new_recorded(monkeypatch):
    session_id = "usr_hyp_verify_no_new_finding"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)
    validate_called = []

    async def fake_run_validate(ctx):
        validate_called.append(True)
        return ctx.session["findings"]

    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", _fake_llm_tool_loop_noop)
    monkeypatch.setattr(core, "_run_validate", fake_run_validate)
    monkeypatch.setattr(core, "_structure_hypothesis_text", _fake_structure_passthrough)

    _run(run_hypothesis_verification(session_id, raw_text="check for exposed .git"))

    assert validate_called == []


def test_run_hypothesis_verification_marks_interrupted_on_stop(monkeypatch):
    session_id = "usr_hyp_verify_stopped"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)

    async def fake_llm_tool_loop_raises(ctx, prompt, task, tool_specs, phase, **kwargs):
        raise core.SessionStopRequested()

    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", fake_llm_tool_loop_raises)
    monkeypatch.setattr(core, "_structure_hypothesis_text", _fake_structure_passthrough)

    _run(run_hypothesis_verification(session_id, raw_text="check for exposed .git"))

    reloaded = store.load_session(session_id)
    assert reloaded["status"] == "interrupted"
    assert "resumable_from" in reloaded


def test_run_hypothesis_verification_unknown_session_is_a_noop(monkeypatch):
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    _run(run_hypothesis_verification("usr_does_not_exist", raw_text="anything"))  # must not raise


def test_run_hypothesis_verification_accumulates_real_pass_time_not_a_naive_span(monkeypatch):
    """Real, confirmed gap this closes: this phase can run several separate passes hours apart (one
    per operator-submitted hunch) -- _mark_phase_started's own setdefault keeps started_at pinned at
    the FIRST pass forever, so a naive started_at->finished_at span would silently count all the
    idle time between passes as if it were real work. accumulated_seconds must instead grow by each
    pass's own real elapsed time, and keep growing (not reset) across multiple separate calls."""
    session_id = "usr_hyp_verify_accumulates"
    session = _make_idle_session(session_id)
    store.save_session(session_id, session)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())
    monkeypatch.setattr(core, "_run_llm_tool_loop", _fake_llm_tool_loop_noop)
    monkeypatch.setattr(core, "_structure_hypothesis_text", _fake_structure_passthrough)

    _run(run_hypothesis_verification(session_id, raw_text="first hunch"))
    after_first = store.load_session(session_id)["phase_timings"]["hypothesis_verification"]["accumulated_seconds"]
    assert after_first > 0

    _run(run_hypothesis_verification(session_id, raw_text="second hunch, a while later"))
    after_second = store.load_session(session_id)["phase_timings"]["hypothesis_verification"]["accumulated_seconds"]

    # Strictly grew (a second real pass happened) -- never reset back to just this pass's own time.
    assert after_second > after_first
