"""Same-turn duplicate tool-call guard in _run_llm_tool_loop -- a model batching several tool
calls into one turn occasionally repeats the exact same name+arguments two or more times (real
incident: a live session issued the identical http_request four times within under a second, all
in one turn). The pre-existing cross-turn stall detector (_STALL_REPEAT_THRESHOLD, see
test_tool_loop_stall.py) only stops a genuine stuck loop at that many repeats in a row -- a
same-turn burst of 2-5 slips under it and just burns tool budget for zero new information. This
guard is a separate, narrower fix: only the FIRST occurrence of a given call within one turn's own
batch actually dispatches; every later identical call in that same batch is a costless no-op.
"""
import asyncio

import pytest

from agent.core import RunContext, _run_llm_tool_loop
from agent.llm_client import LLMResponse, ToolCallRequest
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


class _ScriptedBatchLLM:
    """Feeds back one canned BATCH of tool calls per turn (several ToolCallRequest at once, same
    as a real model's parallel tool-calling turn), then a plain text final reply once the script
    runs out."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, batches):
        self._script = list(batches)
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self._script:
            batch = self._script.pop(0)
            return LLMResponse(
                content=None,
                tool_calls=[
                    ToolCallRequest(id=f"call_{self.calls_made}_{i}", name=name, arguments=arguments)
                    for i, (name, arguments) in enumerate(batch)
                ],
            )
        return LLMResponse(content="done", tool_calls=[])


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_dedup_test")


def test_identical_calls_in_the_same_turn_dispatch_only_once():
    dispatched = []

    async def _execute(spec, arguments):
        dispatched.append((spec.name, arguments))
        return {"status": "ok", "tool": spec.name}

    batch = [("http_request", {"target": "https://old.example.com"})] * 4
    llm = _ScriptedBatchLLM([batch])
    ctx = _make_ctx(llm)

    _, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("http_request")], "analyze",
        execute_tool=_execute, expect_json_final=False,
    ))

    assert len(dispatched) == 1  # only the first of the 4 identical calls actually ran
    assert len(trace) == 4  # all 4 still show up in the trace, so nothing is silently dropped
    statuses = [entry["result"]["status"] for entry in trace]
    assert statuses == ["ok", "skipped", "skipped", "skipped"]
    assert "duplicate of an earlier" in trace[1]["result"]["reason"]


def test_distinct_calls_in_the_same_turn_all_dispatch():
    dispatched = []

    async def _execute(spec, arguments):
        dispatched.append((spec.name, arguments))
        return {"status": "ok", "tool": spec.name}

    batch = [("dns_lookup", {"domain": f"host{i}.example.com"}) for i in range(4)]
    llm = _ScriptedBatchLLM([batch])
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_execute, expect_json_final=False,
    ))

    assert len(dispatched) == 4  # genuinely different arguments must never be treated as dupes


def test_same_call_repeated_across_separate_turns_still_dispatches_each_time():
    # The dedup guard only applies WITHIN one turn's own batch -- a repeat across separate turns
    # is exactly what the pre-existing cross-turn stall detector (a different mechanism) handles.
    dispatched = []

    async def _execute(spec, arguments):
        dispatched.append((spec.name, arguments))
        return {"status": "ok", "tool": spec.name}

    batches = [[("dns_lookup", {"domain": "example.com"})]] * 3
    llm = _ScriptedBatchLLM(batches)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_execute, expect_json_final=False,
    ))

    assert len(dispatched) == 3
