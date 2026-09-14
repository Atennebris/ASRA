"""Two related additions to session.json's logs[] entries (agent/core.py's _append_log):

1. duration_ms -- real wall-clock time measured around the actual tool dispatch
   (execute_tool/_run_tool_with_retry), not the previous "eyeball the gap between two consecutive
   log timestamps by hand" approximation (which also included the next LLM turn's own thinking
   time, so it was never more than a guess).
2. subagent_task_id/subagent_name -- tag every log entry a delegated subagent's own RunContext
   produces (RunContext.subagent_task_id/.subagent_name, set for the whole lifetime of one
   delegation) so main.py's _group_subagent_logs can group a subagent's own steps into one block
   instead of a flat stream interleaved by wall-clock time with the main agent's own entries.
"""
import asyncio

import pytest

from agent.core import RunContext, _run_llm_tool_loop
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import ToolSpec
from main import _group_subagent_logs
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
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def _make_ctx(llm, **kwargs) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_duration_test", **kwargs)


def test_duration_ms_reflects_the_real_measured_dispatch_time():
    async def _slow_execute(spec, arguments):
        await asyncio.sleep(0.05)
        return {"status": "ok", "tool": spec.name}

    llm = _ScriptedLLM([("dns_lookup", {"domain": "example.com"})])
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_slow_execute, expect_json_final=False,
    ))

    entry = ctx.session["logs"][0]
    assert entry["duration_ms"] is not None
    assert entry["duration_ms"] >= 40  # real measured delay (~50ms), not a stub zero


def test_duration_ms_is_none_for_a_same_turn_duplicate_skip():
    # The duplicate branch never actually dispatches (see the same-turn dedup guard) -- there is
    # no real work to time, so duration_ms must stay None rather than implying a fake 0ms.
    async def _execute(spec, arguments):
        return {"status": "ok", "tool": spec.name}

    # _ScriptedLLM only ever puts ONE tool call per turn -- a real same-turn batch (several
    # ToolCallRequest at once) needs its own tiny stand-in instead.
    class _BatchLLM:
        provider_id = "test-provider"
        model = "test-model"
        def __init__(self):
            self.calls_made = 0

        def complete(self, messages, tools=None, stop_check=None):
            self.calls_made += 1
            if self.calls_made == 1:
                return LLMResponse(content=None, tool_calls=[
                    ToolCallRequest(id="c1", name="http_request", arguments={"target": "https://old.example.com"}),
                    ToolCallRequest(id="c2", name="http_request", arguments={"target": "https://old.example.com"}),
                ])
            return LLMResponse(content="done", tool_calls=[])

    ctx = _make_ctx(_BatchLLM())

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("http_request")], "analyze",
        execute_tool=_execute, expect_json_final=False,
    ))

    entries = ctx.session["logs"]
    assert entries[0]["duration_ms"] is not None
    assert entries[1]["status"] == "skipped"
    assert entries[1]["duration_ms"] is None


def test_subagent_run_context_tags_its_own_log_entries():
    async def _execute(spec, arguments):
        return {"status": "ok", "tool": spec.name}

    llm = _ScriptedLLM([("dns_lookup", {"domain": "example.com"})])
    ctx = _make_ctx(llm, subagent_task_id="task123", subagent_name="OSINT Bot")

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "subagent",
        execute_tool=_execute, expect_json_final=False,
    ))

    entry = ctx.session["logs"][0]
    assert entry["subagent_task_id"] == "task123"
    assert entry["subagent_name"] == "OSINT Bot"


def test_main_phase_entries_have_no_subagent_tag():
    async def _execute(spec, arguments):
        return {"status": "ok", "tool": spec.name}

    llm = _ScriptedLLM([("dns_lookup", {"domain": "example.com"})])
    ctx = _make_ctx(llm)  # no subagent_task_id/name -- a normal main-phase RunContext

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_execute, expect_json_final=False,
    ))

    entry = ctx.session["logs"][0]
    assert entry["subagent_task_id"] is None
    assert entry["subagent_name"] is None


def _log_entry(step, subagent_task_id=None, subagent_name=None):
    return {
        "step": step, "phase": "subagent", "command": "dns_lookup({})", "status": "success",
        "error": None, "thought": None, "duration_ms": 10, "finding_title": None,
        "subagent_task_id": subagent_task_id, "subagent_name": subagent_name, "at": "2026-01-01T00:00:00+00:00",
    }


def test_group_subagent_logs_groups_by_task_and_pulls_status_from_subagent_tasks():
    session = {
        "logs": [
            {"step": 1, "phase": "recon", "subagent_task_id": None, "subagent_name": None},
            _log_entry(2, subagent_task_id="task_a", subagent_name="Recon Bot"),
            _log_entry(3, subagent_task_id="task_a", subagent_name="Recon Bot"),
            _log_entry(4, subagent_task_id="task_b", subagent_name="OSINT Bot"),
        ],
        "subagent_tasks": {
            "task_a": {"profile_name": "Recon Bot", "status": "done"},
            "task_b": {"profile_name": "OSINT Bot", "status": "running"},
        },
    }

    groups = _group_subagent_logs(session)

    assert [g["task_id"] for g in groups] == ["task_a", "task_b"]
    assert groups[0]["profile_name"] == "Recon Bot"
    assert groups[0]["status"] == "done"
    assert len(groups[0]["entries"]) == 2
    assert groups[1]["status"] == "running"


def test_group_subagent_logs_tolerates_entries_from_before_this_field_existed():
    # An old session's phase="subagent" entries predate subagent_task_id entirely -- must not
    # crash, must still render, grouped under a fallback key instead of a raw KeyError.
    session = {
        "logs": [
            {"step": 1, "phase": "subagent", "command": "whatweb(...)", "status": "success", "subagent_name": "Legacy Bot"},
        ],
        "subagent_tasks": {},
    }

    groups = _group_subagent_logs(session)

    assert len(groups) == 1
    assert groups[0]["task_id"] == "unknown"
    assert groups[0]["profile_name"] == "Legacy Bot"


def test_group_subagent_logs_empty_when_no_subagent_activity():
    session = {"logs": [{"step": 1, "phase": "recon"}], "subagent_tasks": {}}
    assert _group_subagent_logs(session) == []
