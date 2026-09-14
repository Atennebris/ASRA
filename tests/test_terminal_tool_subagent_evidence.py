"""Terminal-tool guardrails around an unresolved subagent task delegated within THIS same trace.

Two related, but distinct, incidents fixed here:

1. Citing an unresolved task as settled evidence (rev-retest-rescan-usr_94eb6d): the model polled
   check_subagent_task, saw status="running" every single time, then called
   record_reverification_result claiming the subagent "has now reported back" a specific SSH
   version and Terrapin verdict — evidence it had never actually observed, since the task never
   resolved in this same conversation. The real result, once it eventually arrived, was different.

2. Concluding an HONEST "inconclusive"/give-up verdict while a subagent delegated THIS SAME pass
   is still genuinely running, without waiting for it (rev-retest-rescan-usr_8ba29f): reverify
   delegated a subagent for an SSH banner, then concluded verification_outcome="inconclusive" only
   26 seconds / 5 polls later, reasoning "the subagent has been running for several minutes" —
   false at the time. The subagent's real answer arrived 6m45s later, well within its own bounded
   SUBAGENT_TASK_TIMEOUT_SECONDS budget — this never risks hanging forever, since that task is
   guaranteed to reach a resolved status (done/timeout/error) on its own regardless of what this
   loop does.

_unresolved_subagent_task_ids/_cited_unresolved_subagent_task (agent/core.py) reject a terminal
call that either cites an unresolved task_id as evidence, OR concludes at all while ANY task
delegated in this same trace is still unresolved — and accept it once every such task has actually
resolved (done/timeout/error) in this same conversation.
"""
import asyncio

import pytest

from agent.core import RunContext, _run_llm_tool_loop
from agent.tools import native as native_tools
from agent.tools.registry import ToolSpec
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _make_tool(name: str) -> ToolSpec:
    return ToolSpec(
        name=name, category="recon", tool_tier=2, executable="true",
        build_command=lambda args: ["true"], requires_allowed_target=False, installed_by_default=True,
    )


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
            return _Response(name, arguments, self.calls_made)
        return _Response(None, None, self.calls_made)


class _ToolCall:
    def __init__(self, id, name, arguments):
        self.id, self.name, self.arguments = id, name, arguments


class _Response:
    def __init__(self, name, arguments, call_index):
        self.content_was_malformed = False
        self.usage = None
        if name is None:
            self.content, self.tool_calls = "done", []
        else:
            self.content = None
            self.tool_calls = [_ToolCall(f"call_{call_index}", name, arguments)]


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_subagent_evidence_test")


def _make_execute(check_statuses):
    """check_statuses: list of statuses returned by successive check_subagent_task calls, in
    order — mirrors the real tool's own shape ({"status": ..., "result": ...})."""
    call_count = {"n": 0}

    async def execute(spec, arguments):
        if spec.name == "check_subagent_task":
            idx = min(call_count["n"], len(check_statuses) - 1)
            call_count["n"] += 1
            status = check_statuses[idx]
            result = {"summary": "OpenSSH 8.9p1, Terrapin not vulnerable"} if status == "done" else None
            return {"status": status, "result": result}
        if spec.name == "record_reverification_result":
            return native_tools.record_reverification_result(arguments)
        return {"status": "ok"}

    return execute


def test_terminal_call_citing_a_still_running_subagent_task_is_rejected():
    llm = _ScriptedLLM([
        ("check_subagent_task", {"task_id": "abc123"}),
        (
            "record_reverification_result",
            {
                "verification_outcome": "confirmed_fixed",
                "reasoning": "subagent task abc123 has now reported back: OpenSSH 8.9p1, no longer vulnerable",
                "evidence_ref": "subagent task abc123 confirmed patched",
            },
        ),
        # If the first attempt were (wrongly) accepted as terminal, this call would never run —
        # its presence alone doesn't prove rejection, but combined with the assertions below it does.
        ("check_subagent_task", {"task_id": "abc123"}),
    ])
    ctx = _make_ctx(llm)
    execute = _make_execute(check_statuses=["running", "running"])

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("check_subagent_task"), _make_tool("record_reverification_result")],
        "reverify", execute_tool=execute, expect_json_final=False, terminal_tool="record_reverification_result",
    ))

    # The premature terminal call must have been rejected (turned into an error), not accepted —
    # the loop should still be running (script exhausted → generic stop), never having returned
    # a terminal_result built from unverified evidence.
    assert result is None
    reverify_results = [entry["result"] for entry in trace if entry["tool"] == "record_reverification_result"]
    assert len(reverify_results) == 1
    assert reverify_results[0]["status"] == "error"
    assert "abc123" in reverify_results[0]["error"]
    assert "running" in reverify_results[0]["error"]


def test_terminal_call_citing_a_resolved_subagent_task_is_accepted():
    llm = _ScriptedLLM([
        ("check_subagent_task", {"task_id": "abc123"}),
        (
            "record_reverification_result",
            {
                "verification_outcome": "confirmed_fixed",
                "reasoning": "subagent task abc123 finished and confirmed the finding no longer reproduces",
                "evidence_ref": "subagent task abc123: OpenSSH 8.9p1, Terrapin not vulnerable",
            },
        ),
    ])
    ctx = _make_ctx(llm)
    execute = _make_execute(check_statuses=["done"])

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("check_subagent_task"), _make_tool("record_reverification_result")],
        "reverify", execute_tool=execute, expect_json_final=False, terminal_tool="record_reverification_result",
    ))

    assert result is not None
    assert result["verification_outcome"] == "confirmed_fixed"


def test_terminal_call_is_blocked_while_an_uncited_subagent_task_from_this_pass_is_still_running():
    """Real, confirmed incident (rev-retest-rescan-usr_8ba29f): the model didn't fabricate/cite
    anything — it honestly said "inconclusive, the subagent hasn't answered yet" — but that
    subagent (delegated earlier in this exact pass) was still genuinely running, and its own real
    answer arrived less than 7 minutes later. Concluding this early short-changes a lead that was
    only a few more minutes from a real answer, even though the reply itself is technically honest
    about not having evidence yet."""
    llm = _ScriptedLLM([
        ("check_subagent_task", {"task_id": "abc123"}),
        (
            "record_reverification_result",
            {
                "verification_outcome": "inconclusive",
                "reasoning": "the subagent task hasn't reported back yet, so I can't confirm either way",
            },
        ),
        # If the first attempt were (wrongly) accepted as terminal, this call would never run.
        ("check_subagent_task", {"task_id": "abc123"}),
    ])
    ctx = _make_ctx(llm)
    execute = _make_execute(check_statuses=["running", "running"])

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("check_subagent_task"), _make_tool("record_reverification_result")],
        "reverify", execute_tool=execute, expect_json_final=False, terminal_tool="record_reverification_result",
    ))

    assert result is None
    reverify_results = [entry["result"] for entry in trace if entry["tool"] == "record_reverification_result"]
    assert len(reverify_results) == 1
    assert reverify_results[0]["status"] == "error"
    assert "abc123" in reverify_results[0]["error"]
    assert "still running" in reverify_results[0]["error"]


def test_terminal_call_is_accepted_once_every_delegated_task_has_actually_resolved():
    llm = _ScriptedLLM([
        ("check_subagent_task", {"task_id": "abc123"}),
        (
            "record_reverification_result",
            {
                "verification_outcome": "confirmed_fixed",
                "reasoning": "I directly re-ran the CVE check myself with cve_lookup and it no longer applies",
                "evidence_ref": "cve_lookup confirmed the installed version is out of the affected range",
            },
        ),
    ])
    ctx = _make_ctx(llm)
    execute = _make_execute(check_statuses=["timeout"])

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("check_subagent_task"), _make_tool("record_reverification_result")],
        "reverify", execute_tool=execute, expect_json_final=False, terminal_tool="record_reverification_result",
    ))

    assert result is not None
    assert result["verification_outcome"] == "confirmed_fixed"


def test_terminal_call_with_no_subagent_delegation_at_all_is_unaffected():
    llm = _ScriptedLLM([
        (
            "record_reverification_result",
            {
                "verification_outcome": "confirmed_fixed",
                "reasoning": "I directly re-ran the CVE check myself with cve_lookup and it no longer applies",
                "evidence_ref": "cve_lookup confirmed the installed version is out of the affected range",
            },
        ),
    ])
    ctx = _make_ctx(llm)
    execute = _make_execute(check_statuses=[])

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("check_subagent_task"), _make_tool("record_reverification_result")],
        "reverify", execute_tool=execute, expect_json_final=False, terminal_tool="record_reverification_result",
    ))

    assert result is not None
    assert result["verification_outcome"] == "confirmed_fixed"
