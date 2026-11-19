"""A weak primary model with no secondary verification provider configured gets one recommendation
to enable it at session start. This is a hint only -- it writes a single session-log entry and never
enables verification or touches the verification machinery, so an operator who never set it up sees
exactly the same run behavior as before, just with the recommendation visible in the log.
"""
from types import SimpleNamespace

import agent.core as core
from agent.core import RunContext, _maybe_recommend_secondary_verification


def _ctx(weak: bool) -> RunContext:
    session = {"session_id": "usr_hint_test", "logs": []}
    return RunContext(llm=SimpleNamespace(weak_profile=weak), session=session, session_id=session["session_id"])


def test_hint_shown_when_weak_and_no_secondary(monkeypatch):
    monkeypatch.setenv("WEAK_MODEL_VERIFICATION_HINT", "true")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: None)
    ctx = _ctx(weak=True)

    _maybe_recommend_secondary_verification(ctx, "recon")

    logs = ctx.session["logs"]
    assert len(logs) == 1
    assert logs[0]["status"] == "warning"
    assert "secondary verification" in (logs[0]["thought"] or "").lower()


def test_no_hint_when_secondary_already_configured(monkeypatch):
    monkeypatch.setenv("WEAK_MODEL_VERIFICATION_HINT", "true")
    monkeypatch.setattr(core, "get_secondary_verification_provider",
                        lambda: {"provider": "openai", "model": "gpt-x", "free_only": False})
    ctx = _ctx(weak=True)

    _maybe_recommend_secondary_verification(ctx, "recon")

    assert ctx.session["logs"] == []


def test_no_hint_when_model_not_weak(monkeypatch):
    monkeypatch.setenv("WEAK_MODEL_VERIFICATION_HINT", "true")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: None)
    ctx = _ctx(weak=False)

    _maybe_recommend_secondary_verification(ctx, "recon")

    assert ctx.session["logs"] == []


def test_no_hint_when_disabled_by_env(monkeypatch):
    monkeypatch.setenv("WEAK_MODEL_VERIFICATION_HINT", "false")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: None)
    ctx = _ctx(weak=True)

    _maybe_recommend_secondary_verification(ctx, "recon")

    assert ctx.session["logs"] == []


def test_hint_is_a_single_entry_per_run(monkeypatch):
    # run_session calls the recommendation once, before the pipeline loop, so one run yields at most
    # one hint entry (the call site -- not a latch -- is what bounds it; this guards the single append).
    monkeypatch.setenv("WEAK_MODEL_VERIFICATION_HINT", "true")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: None)
    ctx = _ctx(weak=True)

    _maybe_recommend_secondary_verification(ctx, "recon")

    assert len(ctx.session["logs"]) == 1


def test_missing_weak_profile_attribute_is_treated_as_not_weak(monkeypatch):
    # A provider with no weak_profile attribute at all (e.g. a codex/opencode-local client) must not
    # raise and must be treated as "not weak" -- same getattr-default contract the phase loop uses.
    monkeypatch.setenv("WEAK_MODEL_VERIFICATION_HINT", "true")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: None)
    session = {"session_id": "usr_hint_test", "logs": []}
    ctx = RunContext(llm=object(), session=session, session_id=session["session_id"])

    _maybe_recommend_secondary_verification(ctx, "recon")

    assert ctx.session["logs"] == []
