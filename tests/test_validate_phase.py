"""_run_validate's dedup pass and its "reverified_this_pass" freshness signal.

Real incident this covers: _apply_chain_reverifications (agent/core.py) correctly refreshes an
existing finding's evidence_ref/exploited/advisory_note when the chain phase re-tests it — but
_run_validate runs IMMEDIATELY after chain and used to send the model a summary with no evidence
freshness signal at all (just index/title/severity/verification/technology/found_at/description
preview). Confirmed live: a finding chain had just reverified with fresher, more complete evidence
got deduped away by Validate moments later in favor of an older/less-evidenced duplicate, silently
discarding the fresh evidence along with the finding it belonged to. reverified_this_pass on the
summary, plus VALIDATE_PROMPT's own instruction to prefer keeping it, closes that gap.
"""
import asyncio
import json

from agent.core import RunContext, _run_validate
from agent.llm_client import LLMResponse
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _make_session(findings):
    return {
        "session_id": "usr_validate_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": findings, "approvals": [], "chat": {"summary": "", "messages": []},
    }


class _KeepIndicesLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, keep_indices):
        self._keep_indices = keep_indices
        self.last_task_sent = None

    def complete(self, messages, tools=None, stop_check=None):
        self.last_task_sent = messages[-1]["content"]
        return LLMResponse(content=json.dumps({"keep": self._keep_indices}), tool_calls=[])


def test_run_validate_marks_its_own_phase_timing_even_as_a_no_op():
    """Same gap as _run_chain's own version of this test: Validate runs for real time after Chain
    but wasn't tracked in session["phase_timings"] at all, contributing to Session time coming out
    bigger than the sum of every phase shown on the Plan tab with no explanation."""
    ctx = RunContext(llm=object(), session=_make_session([]), session_id="usr_validate_test")
    _run(_run_validate(ctx))
    timing = ctx.session["phase_timings"]["validate"]
    assert timing["started_at"] is not None
    assert timing["finished_at"] is not None


def test_summary_sent_to_the_model_includes_reverified_this_pass(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "A", "severity": "High", "_reverified_this_pass": True},
        {"title": "B", "severity": "Medium"},
    ]
    llm = _KeepIndicesLLM([0, 1])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_validate_test")

    _run(_run_validate(ctx))

    sent = json.loads(llm.last_task_sent.split("Findings:\n", 1)[1])
    assert sent[0]["reverified_this_pass"] is True
    assert sent[1]["reverified_this_pass"] is False  # absent marker reads as False, not omitted


def test_reverified_marker_is_stripped_from_kept_findings(tmp_path, monkeypatch):
    """The marker is transient bookkeeping for this one pass's own dedup decision -- it must never
    survive into the findings that get persisted to session.json."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "A", "severity": "High", "_reverified_this_pass": True},
        {"title": "B", "severity": "Medium"},
    ]
    llm = _KeepIndicesLLM([0, 1])
    ctx = RunContext(llm=llm, session=_make_session(findings), session_id="usr_validate_test")

    result = _run(_run_validate(ctx))

    assert all("_reverified_this_pass" not in f for f in result)


def test_reverified_marker_is_stripped_even_when_the_model_response_is_unparseable(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [
        {"title": "A", "severity": "High", "_reverified_this_pass": True},
        {"title": "B", "severity": "Medium"},
    ]

    class _GarbageLLM:
        provider_id = "test-provider"
        model = "test-model"
        def complete(self, messages, tools=None, stop_check=None):
            return LLMResponse(content="not json at all", tool_calls=[])

    ctx = RunContext(llm=_GarbageLLM(), session=_make_session(findings), session_id="usr_validate_test")

    result = _run(_run_validate(ctx))

    assert result == findings  # pre-dedup findings kept, unparseable model response
    assert all("_reverified_this_pass" not in f for f in result)


def test_reverified_marker_is_stripped_with_a_single_finding_no_dedup_needed(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    findings = [{"title": "Only One", "severity": "Low", "_reverified_this_pass": True}]
    ctx = RunContext(llm=object(), session=_make_session(findings), session_id="usr_validate_test")

    result = _run(_run_validate(ctx))

    assert "_reverified_this_pass" not in result[0]  # cleaned up even on the early no-op return
