"""_run_llm_tool_loop's terminal_tool repair path (agent/core.py's _repair_terminal_tool_reply).

Real incident this guards against: a reverify-phase turn where the model stopped calling tools
with empty content (no tool call, no text at all). The old fallback (_repair_json_reply) stripped
the tool schema away entirely (tools=None) and asked the model to "resend ONLY the JSON object" —
but a terminal_tool's shape was never given as text anywhere in the conversation, only as a
structured tool schema, so a model with no native recall of that schema fell back to a completely
different, unparseable function-call syntax it remembered from its own training. Two calls were
burned, and a carried-over finding's reverify verdict silently defaulted to "no longer present"
even though it was never actually re-checked at all. The fix retries WITH the real tool schema
still attached, giving the model a genuine second chance at a proper tool call.
"""
import asyncio

from agent.core import RunContext, _run_llm_tool_loop
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import ToolSpec
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_terminal_tool_repair_test")


def _terminal_tool_spec() -> ToolSpec:
    return ToolSpec(
        name="record_reverification_result", category="post_exploit", tool_tier=1,
        executable="", build_command=None,
        native_function=lambda params: {"status": "ok", **params},
        requires_allowed_target=False, installed_by_default=True,
    )


async def _execute(spec, arguments):
    return spec.native_function(arguments)


class _GarbledThenProperLLM:
    """First reply: no tool call, no parseable content at all (the exact real failure — an empty
    stop). Second reply (the repair attempt): records whether a tool schema was actually offered,
    then answers with a real, matching terminal_tool call."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self.calls_made = 0
        self.tools_offered_on_repair_call: list | None = None

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self.calls_made == 1:
            return LLMResponse(content="", tool_calls=[])
        self.tools_offered_on_repair_call = tools
        return LLMResponse(
            content=None,
            tool_calls=[ToolCallRequest(
                id="call_repair", name="record_reverification_result",
                arguments={"verification_outcome": "confirmed_present", "reasoning": "confirmed on the retry"},
            )],
        )


def test_terminal_tool_repair_retries_with_the_real_schema_not_tools_none(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    llm = _GarbledThenProperLLM()
    ctx = _make_ctx(llm)

    parsed, _trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_terminal_tool_spec()], "reverify",
        execute_tool=_execute, expect_json_final=False, terminal_tool="record_reverification_result",
    ))

    # The repair call must have been given the real tool schema, not tools=None -- that's the
    # entire fix: a model with no schema to recall from has nothing to construct a real call from.
    assert llm.tools_offered_on_repair_call
    assert any(t["function"]["name"] == "record_reverification_result" for t in llm.tools_offered_on_repair_call)
    # And with the schema actually offered, the model's real tool call is honored as the phase's
    # final answer instead of silently defaulting to "no verdict reached".
    assert parsed == {"verification_outcome": "confirmed_present", "reasoning": "confirmed on the retry"}


class _NeverRecoversLLM:
    """Every call (initial + repair) replies with neither a tool call nor parseable content --
    proves the repair path fails closed (returns None) rather than fabricating a result when the
    model genuinely never manages a real answer."""
    provider_id = "test-provider"
    model = "test-model"

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content="", tool_calls=[])


def test_terminal_tool_repair_returns_none_when_the_model_never_recovers(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    ctx = _make_ctx(_NeverRecoversLLM())

    parsed, _trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_terminal_tool_spec()], "reverify",
        execute_tool=_execute, expect_json_final=False, terminal_tool="record_reverification_result",
    ))

    assert parsed is None
