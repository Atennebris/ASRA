"""_run_hypothesis_resolution_gate: run_session's own deterministic "hard block" before a session
can complete -- every still-open hypothesis (agent's own, or an operator's) must get a real
resolve_hypothesis call backed by an actual investigative tool call, not just be left unconfirmed
because nobody got around to checking it. Also covers _make_hypothesis_verification_executor's
shared execute() closure and its anti-fabrication guard directly.
"""
import asyncio
import dataclasses

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _hypothesis_resolved_without_real_investigation,
    _make_hypothesis_verification_executor,
    _run_hypothesis_resolution_gate,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import TOOL_REGISTRY, ToolSpec


def _run(coro):
    return asyncio.run(coro)


def _session(hypotheses=None, findings=None):
    return {
        "session_id": "usr_hyp_gate_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": findings or [], "hypotheses": hypotheses or [], "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


def _open_hypothesis(text="staging debug mode might be on", **overrides):
    entry = {
        "id": "hyp001", "text": text, "evidence": "", "source_phase": "recon", "source": "agent",
        "status": "unconfirmed", "resolution_note": None, "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
    }
    entry.update(overrides)
    return entry


class _CountingNoOpLLM:
    """Should never actually be called when there's nothing open to resolve."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self.calls = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls += 1
        return LLMResponse(content="nothing to do", tool_calls=[])


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


# --- _hypothesis_resolved_without_real_investigation: pure function ---


def test_no_investigation_is_true_for_empty_trace():
    assert _hypothesis_resolved_without_real_investigation([]) is True


def test_no_investigation_is_true_for_bookkeeping_only_trace():
    trace = [{"tool": "record_hypothesis", "arguments": {}, "result": {}}]
    assert _hypothesis_resolved_without_real_investigation(trace) is True


def test_no_investigation_is_false_once_a_real_tool_ran():
    trace = [{"tool": "http_request", "arguments": {}, "result": {}}]
    assert _hypothesis_resolved_without_real_investigation(trace) is False


# --- _make_hypothesis_verification_executor: the execute() closure directly ---


def test_executor_dispatches_record_finding_and_persists_it():
    session = _session()
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = ToolSpec(name="record_finding", category="scan", tool_tier=1, executable="", build_command=None, requires_allowed_target=False, installed_by_default=True, native_function=lambda p: {"status": "ok", "recorded": {"title": p["title"], "severity": "Low", "description": "d"}})
    execute = _make_hypothesis_verification_executor(ctx)

    result = _run(execute(spec, {"title": "Exposed .git directory"}))

    assert result["status"] == "ok"
    assert len(ctx.session["findings"]) == 1
    assert ctx.session["findings"][0]["title"] == "Exposed .git directory"


def test_executor_dispatches_resolve_hypothesis_and_persists_it():
    session = _session(hypotheses=[_open_hypothesis()])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = ToolSpec(name="resolve_hypothesis", category="post_exploit", tool_tier=1, executable="", build_command=None, requires_allowed_target=False, installed_by_default=True, native_function=lambda p: {"status": "ok", "resolved": {"hypothesis_text": p["hypothesis_text"], "status": p["status"], "note": p.get("note", "")}})
    execute = _make_hypothesis_verification_executor(ctx)  # no trace -> guard disabled

    result = _run(execute(spec, {"hypothesis_text": "staging debug mode might be on", "status": "ruled_out", "note": "checked, not present"}))

    assert result["status"] == "ok"
    assert ctx.session["hypotheses"][0]["status"] == "ruled_out"


def test_executor_rejects_resolve_hypothesis_with_zero_prior_investigation_when_trace_given():
    session = _session(hypotheses=[_open_hypothesis()])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = ToolSpec(name="resolve_hypothesis", category="post_exploit", tool_tier=1, executable="", build_command=None, requires_allowed_target=False, installed_by_default=True, native_function=lambda p: {"status": "ok", "resolved": {"hypothesis_text": p["hypothesis_text"], "status": p["status"], "note": p.get("note", "")}})
    empty_trace: list[dict] = []
    execute = _make_hypothesis_verification_executor(ctx, trace=empty_trace)

    result = _run(execute(spec, {"hypothesis_text": "staging debug mode might be on", "status": "ruled_out", "note": "trust me"}))

    assert result["status"] == "error"
    assert ctx.session["hypotheses"][0]["status"] == "unconfirmed"  # untouched, rejected before persisting


def test_executor_with_target_id_can_re_resolve_an_already_resolved_hypothesis():
    """Real gap this closes: without target_hypothesis_id, _resolve_hypothesis's own fuzzy match
    only ever considers "unconfirmed" hypotheses, so a re-check of one that's already
    confirmed/ruled-out (run_all_hypotheses_verification's whole point, or a future single-item
    "recheck" action) would silently no-op instead of actually applying the new verdict."""
    session = _session(hypotheses=[_open_hypothesis(status="ruled_out", resolution_note="stale, wrong conclusion")])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = ToolSpec(name="resolve_hypothesis", category="post_exploit", tool_tier=1, executable="", build_command=None, requires_allowed_target=False, installed_by_default=True, native_function=lambda p: {"status": "ok", "resolved": {"hypothesis_text": p["hypothesis_text"], "status": p["status"], "note": p.get("note", "")}})
    execute = _make_hypothesis_verification_executor(ctx, target_hypothesis_id="hyp001")

    result = _run(execute(spec, {"hypothesis_text": "staging debug mode might be on", "status": "confirmed", "note": "actually present, re-checked and confirmed"}))

    assert result["status"] == "ok"
    assert ctx.session["hypotheses"][0]["status"] == "confirmed"
    assert ctx.session["hypotheses"][0]["resolution_note"] == "actually present, re-checked and confirmed"


def test_executor_without_target_id_ignores_an_already_resolved_hypothesis():
    """Unchanged existing behavior for the gate's own multi-hypothesis pass (no single target) --
    only ever matches a still-"unconfirmed" hypothesis, silent no-op otherwise."""
    session = _session(hypotheses=[_open_hypothesis(status="ruled_out")])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = ToolSpec(name="resolve_hypothesis", category="post_exploit", tool_tier=1, executable="", build_command=None, requires_allowed_target=False, installed_by_default=True, native_function=lambda p: {"status": "ok", "resolved": {"hypothesis_text": p["hypothesis_text"], "status": p["status"], "note": p.get("note", "")}})
    execute = _make_hypothesis_verification_executor(ctx)  # no target_hypothesis_id

    result = _run(execute(spec, {"hypothesis_text": "staging debug mode might be on", "status": "confirmed", "note": "should not apply"}))

    assert result["status"] == "ok"  # tool call itself still "succeeds"...
    assert ctx.session["hypotheses"][0]["status"] == "ruled_out"  # ...but nothing was actually re-matched


def test_executor_allows_resolve_hypothesis_after_a_real_tool_call_in_trace():
    session = _session(hypotheses=[_open_hypothesis()])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = ToolSpec(name="resolve_hypothesis", category="post_exploit", tool_tier=1, executable="", build_command=None, requires_allowed_target=False, installed_by_default=True, native_function=lambda p: {"status": "ok", "resolved": {"hypothesis_text": p["hypothesis_text"], "status": p["status"], "note": p.get("note", "")}})
    trace_with_real_call = [{"tool": "http_request", "arguments": {"target": "https://example.com/debug"}, "result": {"status": "ok"}}]
    execute = _make_hypothesis_verification_executor(ctx, trace=trace_with_real_call)

    result = _run(execute(spec, {"hypothesis_text": "staging debug mode might be on", "status": "ruled_out", "note": "probed /debug, got a clean 404"}))

    assert result["status"] == "ok"
    assert ctx.session["hypotheses"][0]["status"] == "ruled_out"


# --- _run_hypothesis_resolution_gate: the full pass ---


def test_gate_is_a_zero_cost_noop_with_no_open_hypotheses():
    session = _session(hypotheses=[_open_hypothesis(status="confirmed")])
    llm = _CountingNoOpLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_hypothesis_resolution_gate(ctx))

    assert llm.calls == 0
    assert "hypothesis_gate" not in ctx.session.get("phase_timings", {})


def test_gate_resolves_an_open_hypothesis_via_a_real_tool_call_then_resolve_hypothesis():
    # http_request is a real registered tool _hypothesis_verification_tool_specs() offers (recon+
    # scan+exploit categories) -- swap its native_function for a fake one so this test never makes
    # a real network call, same save/restore pattern as test_analyze_cve_capture.py.
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "http_request")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, native_function=lambda p: {"status": "ok", "status_code": 404})
    try:
        session = _session(hypotheses=[_open_hypothesis()])
        llm = _ScriptedLLM([
            ("http_request", {"target": "https://staging.example.com/debug"}),
            ("resolve_hypothesis", {"hypothesis_text": "staging debug mode might be on", "status": "ruled_out", "note": "probed /debug, got a clean 404, not present"}),
        ])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_hypothesis_resolution_gate(ctx))

        assert ctx.session["hypotheses"][0]["status"] == "ruled_out"
        assert ctx.session["phase_timings"]["hypothesis_gate"]["started_at"]
        assert ctx.session["phase_timings"]["hypothesis_gate"]["finished_at"]
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_gate_leaves_a_hypothesis_open_if_the_pass_never_resolves_it():
    """Bounded, not an infinite block -- a pass that runs out of ideas (or budget) still lets the
    session complete, just with the hypothesis honestly left unconfirmed rather than fabricated."""
    session = _session(hypotheses=[_open_hypothesis()])
    llm = _ScriptedLLM([])  # immediately says "done" with no tool calls at all
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_hypothesis_resolution_gate(ctx))

    assert ctx.session["hypotheses"][0]["status"] == "unconfirmed"
