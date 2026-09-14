"""_run_detection_second_opinion (agent/core.py): a genuine second opinion on DETECTION itself,
not just on an already-confirmed finding's reproduction (that's _run_skeptical_verification's own
ensemble check). Gated on the same Settings -> Secondary verification provider setting (None by
default -- a no-op unless the operator explicitly configured one), review-only (no scan/exploit
tool access -- only record_finding/record_hypothesis), and forbids verification="verified" since
this pass never makes a real tool call of its own.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_analyze, _run_detection_second_opinion
from agent.llm_client import LLMResponse, ToolCallRequest
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _make_session(findings=None):
    return {
        "session_id": "usr_second_opinion_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": findings or [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": [], "cves": [], "dns_map": {}, "technologies": {}},
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


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def test_no_op_without_a_configured_secondary_provider(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: None)

    ctx = RunContext(llm=object(), session=_make_session(), session_id="usr_second_opinion_test")

    _run(_run_detection_second_opinion(ctx, "example.com", ctx.session["recon_result"]))  # object() would blow up if .complete() were ever called

    assert ctx.session["findings"] == []


def test_skips_gracefully_when_secondary_provider_is_not_usable(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    def _raise_value_error(provider_id, model=None):
        raise ValueError("not configured")
    monkeypatch.setattr(core, "get_provider", _raise_value_error)

    ctx = RunContext(llm=object(), session=_make_session(), session_id="usr_second_opinion_test")

    _run(_run_detection_second_opinion(ctx, "example.com", ctx.session["recon_result"]))  # must not raise

    assert ctx.session["findings"] == []


def test_secondary_provider_flags_a_missed_finding(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    secondary_llm = _ScriptedLLM([("record_finding", {
        "title": "Exposed .git directory", "severity": "High", "description": "d",
        "exploitation_scenario": "remote_direct", "verification": "inferred", "evidence_ref": "e",
    })])
    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: secondary_llm)

    ctx = RunContext(llm=object(), session=_make_session(), session_id="usr_second_opinion_test")

    _run(_run_detection_second_opinion(ctx, "example.com", ctx.session["recon_result"]))

    assert secondary_llm.calls_made == 2  # the record_finding call, then one more turn to end the loop (no terminal_tool)
    findings = ctx.session["findings"]
    assert len(findings) == 1
    assert findings[0]["title"] == "Exposed .git directory"
    assert findings[0]["detected_by_secondary_opinion"] is True
    assert findings[0]["ensemble_secondary_provider"] == "secondary/secondary-model"


def test_secondary_provider_claiming_verified_is_downgraded(tmp_path, monkeypatch):
    """This pass never makes a real tool call of its own -- a "verified" self-claim has nothing
    real behind it and must never reach the report as if it did."""
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    secondary_llm = _ScriptedLLM([("record_finding", {
        "title": "Claims verified with no tool access", "severity": "High", "description": "d",
        "exploitation_scenario": "remote_direct", "verification": "verified", "evidence_ref": "e",
    })])
    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: secondary_llm)

    ctx = RunContext(llm=object(), session=_make_session(), session_id="usr_second_opinion_test")

    _run(_run_detection_second_opinion(ctx, "example.com", ctx.session["recon_result"]))

    assert ctx.session["findings"][0]["verification"] == "needs_verification"


def test_secondary_provider_records_a_hypothesis_instead_of_a_finding(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    secondary_llm = _ScriptedLLM([("record_hypothesis", {
        "text": "The login form may be vulnerable to timing-based user enumeration",
        "evidence": "Response times differed slightly for valid vs invalid usernames in the recon transcript",
    })])
    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: secondary_llm)

    ctx = RunContext(llm=object(), session=_make_session(), session_id="usr_second_opinion_test")

    _run(_run_detection_second_opinion(ctx, "example.com", ctx.session["recon_result"]))

    assert ctx.session["findings"] == []
    hypotheses = ctx.session.get("hypotheses", [])
    assert len(hypotheses) == 1
    assert hypotheses[0]["source_phase"] == "detection_second_opinion"


def test_already_found_findings_are_shown_to_the_secondary_pass(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    secondary_llm = _ScriptedLLM([])  # no tool calls at all -- "nothing new" is a legitimate outcome
    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: secondary_llm)

    findings = [{"title": "Already found XSS", "severity": "Medium", "technology": "PHP", "verification": "verified"}]
    ctx = RunContext(llm=object(), session=_make_session(findings), session_id="usr_second_opinion_test")

    _run(_run_detection_second_opinion(ctx, "example.com", ctx.session["recon_result"]))

    assert secondary_llm.calls_made == 1
    assert "Already found XSS" in secondary_llm.tasks_seen[0]
    assert ctx.session["findings"] == findings  # unchanged, nothing new was flagged


def test_secondary_pass_crash_does_not_break_analyze(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(core, "get_secondary_verification_provider", lambda: {"provider": "secondary", "model": "secondary-model"})

    class _CrashingLLM:
        provider_id = "secondary"
        model = "secondary-model"
        def complete(self, messages, tools=None, stop_check=None):
            raise RuntimeError("secondary provider unreachable")

    monkeypatch.setattr(core, "get_provider", lambda provider_id, model=None: _CrashingLLM())

    ctx = RunContext(llm=object(), session=_make_session(), session_id="usr_second_opinion_test")

    _run(_run_detection_second_opinion(ctx, "example.com", ctx.session["recon_result"]))  # must not raise

    assert ctx.session["findings"] == []


def test_run_analyze_invokes_the_second_opinion_pass_after_the_primary_pass(tmp_path, monkeypatch):
    """Wiring check: _run_analyze must actually call _run_detection_second_opinion once its own
    primary pass is done, with the session's real (possibly primary-pass-updated) recon_result --
    not just have the function exist unused."""
    _isolate(tmp_path, monkeypatch)

    calls = []

    async def _fake_second_opinion(ctx, target, recon_result):
        calls.append((target, recon_result))
    monkeypatch.setattr(core, "_run_detection_second_opinion", _fake_second_opinion)

    session = {
        "session_id": "usr_second_opinion_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": [], "cves": [], "dns_map": {}, "technologies": {}},
    }
    llm = _ScriptedLLM([])  # primary Analyze pass finds nothing and ends immediately
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", session["recon_result"]))

    assert len(calls) == 1
    assert calls[0][0] == "example.com"
