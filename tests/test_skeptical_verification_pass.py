"""_run_skeptical_verification / record_skeptical_verification_result: the last check before a
finding ships as "verified" -- a genuinely blind second opinion (never shown the original
reasoning/trace, only the claim + reproduction recipe) that must independently reproduce or
explicitly refute, real motivation being that the existing anti-fabrication guard only checks
structure ("was a real tool call made") and cannot catch "a real tool call was made, but the model
misread its own output."
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_skeptical_verification
from agent.llm_client import LLMResponse, ToolCallRequest
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _make_session(findings):
    return {
        "session_id": "usr_skeptical_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": findings, "approvals": [], "chat": {"summary": "", "messages": []},
    }


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


def test_no_op_when_no_finding_is_verified(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "A", "severity": "Low", "verification": "inferred"},
        {"title": "B", "severity": "Medium", "verification": "needs_verification"},
    ]
    ctx = RunContext(llm=object(), session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))  # object() would blow up if .complete() were ever called

    assert "phase_timings" not in ctx.session or "skeptical_verification" not in ctx.session.get("phase_timings", {})
    assert findings[0].get("skeptical_verification") is None


def test_only_verified_findings_are_visited(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "Verified one", "severity": "High", "verification": "verified", "evidence_ref": "ref-a"},
        {"title": "Inferred one", "severity": "Medium", "verification": "inferred"},
    ]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "reproduced it", "evidence_ref": "fresh proof"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert llm.calls_made == 1  # only the verified finding triggered a pass
    assert findings[0]["skeptical_verification"] == "confirmed"
    assert findings[1].get("skeptical_verification") is None


def test_confirmed_verdict_leaves_verification_untouched(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "Real XSS", "severity": "High", "verification": "verified", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "same payload still fires", "evidence_ref": "fresh reflected output"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert findings[0]["verification"] == "verified"
    assert findings[0]["skeptical_verification"] == "confirmed"
    assert findings[0]["skeptical_verification_note"] == "same payload still fires"


def test_refuted_verdict_downgrades_verification_but_keeps_the_finding(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "Misread finding", "severity": "Critical", "verification": "verified", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {
        "verdict": "refuted", "reasoning": "re-ran the exact same login, got 401 not 200",
        "evidence_ref": "authenticated_request returned status_code=401",
    })])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert len(ctx.session["findings"]) == 1  # never silently dropped
    assert findings[0]["verification"] == "needs_verification"  # downgraded
    assert findings[0]["skeptical_verification"] == "refuted"
    assert findings[0]["skeptical_verification_note"] == "re-ran the exact same login, got 401 not 200"


def test_inconclusive_verdict_leaves_verification_untouched(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "Blocked check", "severity": "Medium", "verification": "verified", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "inconclusive", "reasoning": "hit a Cloudflare challenge every attempt"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert findings[0]["verification"] == "verified"  # untouched -- inconclusive is not a negative result
    assert findings[0]["skeptical_verification"] == "inconclusive"


def test_task_content_never_includes_the_original_narrative(tmp_path, monkeypatch):
    """The whole point is blindness -- advisory_note/reasoning from the original pass must never
    reach the verifier, only the claim + its reproduction recipe."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{
        "title": "Sensitive finding", "severity": "High", "verification": "verified",
        "description": "A real description", "technology": "nginx 1.14", "evidence_ref": "ref-a",
        "evidence": "raw evidence text", "reproduction_steps": "curl -X POST ...", "poc_command": "curl -X POST ... final",
        "advisory_note": "THIS SHOULD NEVER LEAK: original exploit reasoning was sloppy here",
        "remediation_advice": "THIS SHOULD ALSO NEVER LEAK",
    }]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "ok", "evidence_ref": "x"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    task_sent = llm.tasks_seen[0]
    assert "ref-a" in task_sent
    assert "raw evidence text" in task_sent
    assert "curl -X POST ... final" in task_sent
    assert "THIS SHOULD NEVER LEAK" not in task_sent
    assert "THIS SHOULD ALSO NEVER LEAK" not in task_sent


def test_no_verdict_reached_is_treated_as_inconclusive(tmp_path, monkeypatch):
    """A stall/exhausted-budget pass (terminal tool never called) must get the same honest
    treatment as a model-reported inconclusive, never silently treated as a pass."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "Stalled check", "severity": "Medium", "verification": "verified", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([])  # never calls the terminal tool -- immediately replies "done" with no tool calls
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert findings[0]["skeptical_verification"] == "inconclusive"
    assert findings[0]["verification"] == "verified"  # not treated as a refutation


# --- Ensemble second opinion (Settings -> Secondary verification provider) ----------------------


def test_ensemble_check_skipped_without_a_configured_secondary_provider(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: None)

    findings = [{"title": "Real XSS", "severity": "Critical", "verification": "verified", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "ok", "evidence_ref": "x"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert "ensemble_disagreement" not in findings[0]


def test_ensemble_check_skipped_for_medium_and_low_severity(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    findings = [{"title": "Minor issue", "severity": "Medium", "verification": "verified", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "ok", "evidence_ref": "x"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert "ensemble_disagreement" not in findings[0]


def test_ensemble_check_skipped_when_primary_verdict_is_inconclusive(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    def _fail_if_called(provider_id, model=None):
        raise AssertionError("secondary provider must never be resolved when primary is inconclusive")
    monkeypatch.setattr(core, "get_provider", _fail_if_called)

    findings = [{"title": "Blocked check", "severity": "Critical", "verification": "verified", "evidence_ref": "ref-a"}]
    llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "inconclusive", "reasoning": "blocked"})])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))  # must not raise

    assert "ensemble_disagreement" not in findings[0]


def test_ensemble_check_agreeing_verdicts_are_not_flagged_as_disagreement(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    secondary_llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "also reproduced it", "evidence_ref": "y"})])
    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: secondary_llm)

    findings = [{"title": "Real XSS", "severity": "Critical", "verification": "verified", "evidence_ref": "ref-a"}]
    primary_llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "reproduced it", "evidence_ref": "x"})])
    ctx = RunContext(llm=primary_llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert findings[0]["ensemble_secondary_verdict"] == "confirmed"
    assert findings[0]["ensemble_disagreement"] is False
    assert findings[0]["ensemble_secondary_provider"] == "secondary/secondary-model"
    assert secondary_llm.calls_made == 1  # the secondary model was genuinely, independently called


def test_ensemble_check_flags_a_genuine_disagreement(tmp_path, monkeypatch):
    """Real motivation this covers: this session's own log-review audit found the default
    skeptical pass nearly downgrade a real, twice-confirmed Critical finding to a false positive
    over a client-side TLS quirk the same model didn't know to account for -- disagreement must
    surface explicitly, never be silently resolved by trusting either side."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    secondary_llm = _ScriptedLLM([("record_skeptical_verification_result", {
        "verdict": "refuted", "reasoning": "could not reproduce with a default client", "evidence_ref": "y",
    })])
    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: secondary_llm)

    findings = [{"title": "Deprecated TLS 1.0/1.1 Support", "severity": "High", "verification": "verified", "evidence_ref": "ref-a"}]
    primary_llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "reproduced with SECLEVEL=0", "evidence_ref": "x"})])
    ctx = RunContext(llm=primary_llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))

    assert findings[0]["skeptical_verification"] == "confirmed"  # primary verdict, never overridden
    assert findings[0]["ensemble_secondary_verdict"] == "refuted"
    assert findings[0]["ensemble_disagreement"] is True


def test_ensemble_check_crash_does_not_break_the_phase(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    class _CrashingLLM:
        provider_id = "secondary"
        model = "secondary-model"
        def complete(self, messages, tools=None, stop_check=None):
            raise RuntimeError("secondary provider unreachable")

    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: _CrashingLLM())

    findings = [{"title": "Real XSS", "severity": "Critical", "verification": "verified", "evidence_ref": "ref-a"}]
    primary_llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "ok", "evidence_ref": "x"})])
    ctx = RunContext(llm=primary_llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))  # must not raise

    assert findings[0]["skeptical_verification"] == "confirmed"  # primary result still applied
    assert findings[0]["ensemble_secondary_verdict"] == "inconclusive"  # crash treated as inconclusive
    assert findings[0]["ensemble_disagreement"] is False


def test_ensemble_check_skips_gracefully_when_secondary_provider_is_not_configured_on_this_machine(tmp_path, monkeypatch):
    """get_provider raises ValueError for an unresolvable (provider, model) pair (e.g. a saved
    secondary choice whose API key was since removed) -- same recoverability contract
    get_next_chain_step already relies on, not a hard crash."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    def _raise_value_error(provider_id, model=None):
        raise ValueError("not configured")
    monkeypatch.setattr(core, "get_provider", _raise_value_error)

    findings = [{"title": "Real XSS", "severity": "Critical", "verification": "verified", "evidence_ref": "ref-a"}]
    primary_llm = _ScriptedLLM([("record_skeptical_verification_result", {"verdict": "confirmed", "reasoning": "ok", "evidence_ref": "x"})])
    ctx = RunContext(llm=primary_llm, session=_make_session(findings), session_id="usr_skeptical_test")

    _run(_run_skeptical_verification(ctx))  # must not raise

    assert findings[0]["skeptical_verification"] == "confirmed"
    assert "ensemble_disagreement" not in findings[0]
