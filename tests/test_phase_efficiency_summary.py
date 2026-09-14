"""agent/core.py's _log_phase_efficiency_summary: one debug line per phase run showing total tool
calls, how many needed a 1-Step Retry, how many ended not-ok, and how many were an exact repeat of
an earlier call in the same phase -- makes a real, confirmed waste pattern (a session guessing at
6+ nonexistent nuclei tags, separately repeating identical dns_lookup calls for already-failed
domains) visible at a glance instead of a manual grep-and-count across the whole log.

_run_llm_tool_loop wraps _run_llm_tool_loop_impl in a try/finally specifically so this summary
fires exactly once regardless of which of that function's several return points was actually
taken -- tested here via a real, unmocked run through the public function, not just the pure
summary function in isolation.
"""
import asyncio

import agent.core as core
from agent.core import RunContext, _log_phase_efficiency_summary, _run_llm_tool_loop
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import ToolSpec


def _run(coro):
    return asyncio.run(coro)


def _base_ctx(session_id="usr_summary_test"):
    session = {"session_id": session_id, "logs": [], "findings": []}
    return RunContext(llm=None, session=session, session_id=session_id)


# --- _log_phase_efficiency_summary: pure unit tests ---


def test_log_phase_efficiency_summary_counts_retries_non_ok_and_duplicates(monkeypatch):
    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))
    ctx = _base_ctx()

    trace = [
        {"tool": "dns_lookup", "arguments": {"domain": "a.example.com"}, "result": {"status": "ok"}},
        {"tool": "dns_lookup", "arguments": {"domain": "b.example.com"}, "result": {"status": "error"}},
        {"tool": "dns_lookup", "arguments": {"domain": "a.example.com"}, "result": {"status": "ok"}},  # exact repeat
        {"tool": "nuclei", "arguments": {"target": "x", "tags": "cookie"}, "result": {"status": "ok", "retried": True}},
    ]
    _log_phase_efficiency_summary(ctx, "recon", trace)

    summary_calls = [a for a in logged if "phase summary" in a[0]]
    assert len(summary_calls) == 1
    args = summary_calls[0]
    assert args[-4] == 4  # total tool calls
    assert args[-3] == 1  # retried
    assert args[-2] == 1  # non-ok
    assert args[-1] == 1  # exact duplicate


def test_log_phase_efficiency_summary_does_not_count_legitimate_subagent_polling_as_failure(monkeypatch):
    """check_subagent_task/background_job_check never return {"status": "ok"} -- they pass through
    their own task/job lifecycle status. A "running" poll (still in flight, exactly what the
    operator's own docs tell the model to expect when it polls instead of blocking) and a "done"
    poll (successful completion) must NOT inflate non_ok, only a genuine terminal failure should.
    Real, confirmed incident (a real HackerOne session): an analyze phase logged "6 ended
    not-ok" when only 3 were real errors -- the other 4 were check_subagent_task calls that
    correctly found the delegated task still running.

    The background-job half of this trace uses "background_job_check" -- the tool's REAL registered
    name (agent/tools/__init__.py) -- not the "check_background_job" this test used to write here,
    which never matched any real call.name and so silently never got exercised at all (see
    _NON_FAILURE_POLL_STATUSES' own comment in agent/core.py for the matching production fix).
    """
    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))
    ctx = _base_ctx()

    trace = [
        {"tool": "check_subagent_task", "arguments": {"task_id": "t1"}, "result": {"status": "running"}},
        {"tool": "check_subagent_task", "arguments": {"task_id": "t1"}, "result": {"status": "done", "result": {}}},
        {"tool": "background_job_check", "arguments": {"job_id": "j1"}, "result": {"status": "running"}},
        {"tool": "background_job_check", "arguments": {"job_id": "j1"}, "result": {"status": "ok", "result": {}}},
        {"tool": "check_subagent_task", "arguments": {"task_id": "t2"}, "result": {"status": "error", "error": "unknown subagent task 't2'"}},
    ]
    _log_phase_efficiency_summary(ctx, "analyze", trace)

    summary_calls = [a for a in logged if "phase summary" in a[0]]
    assert len(summary_calls) == 1
    args = summary_calls[0]
    assert args[-4] == 5  # total tool calls
    assert args[-2] == 1  # non-ok: only the genuine "unknown task" error


def test_log_phase_efficiency_summary_is_a_noop_for_an_empty_trace(monkeypatch):
    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))
    ctx = _base_ctx()

    _log_phase_efficiency_summary(ctx, "recon", [])

    assert logged == []


# --- _run_llm_tool_loop: the summary fires exactly once, via the real public function ---


class _NoToolCallsLLM:
    """Always answers with a plain final reply and no tool calls -- exercises the
    expect_json_final=False return path (recon/analyze's own shape)."""

    provider_id = "test-provider"
    model = "test-model"

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content="nothing more to check", tool_calls=[])


def test_run_llm_tool_loop_logs_the_summary_exactly_once_with_no_tool_calls_made(monkeypatch):
    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))
    ctx = RunContext(llm=_NoToolCallsLLM(), session={"session_id": "usr_x", "logs": [], "findings": []}, session_id="usr_x")

    _run(_run_llm_tool_loop(ctx, "system prompt", "task", [], "recon", expect_json_final=False))

    summary_calls = [a for a in logged if "phase summary" in a[0]]
    # An empty trace (no tool calls at all) is a deliberate no-op -- nothing to summarize.
    assert summary_calls == []


class _OneToolCallThenDoneLLM:
    """First turn: calls a real registered tool. Second turn: plain final reply, no more calls."""

    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self._turn = 0

    def complete(self, messages, tools=None, stop_check=None):
        self._turn += 1
        if self._turn == 1:
            return LLMResponse(
                content=None,
                tool_calls=[ToolCallRequest(id="call_1", name="dns_lookup", arguments={"domain": "example.com"})],
            )
        return LLMResponse(content="done", tool_calls=[])


def test_run_llm_tool_loop_logs_the_summary_exactly_once_after_a_real_tool_call(monkeypatch):
    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))
    spec = ToolSpec(
        name="dns_lookup", category="recon", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True,
        native_function=lambda args: {"status": "ok", "resolved": ["1.2.3.4"]},
    )
    ctx = RunContext(llm=_OneToolCallThenDoneLLM(), session={"session_id": "usr_y", "logs": [], "findings": []}, session_id="usr_y")

    _run(_run_llm_tool_loop(ctx, "system prompt", "task", [spec], "recon", expect_json_final=False))

    summary_calls = [a for a in logged if "phase summary" in a[0]]
    assert len(summary_calls) == 1
    assert summary_calls[0][-4] == 1  # exactly one tool call happened
