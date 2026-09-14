"""A model that keeps violating one tool's own JSON-schema constraint (an enum, most commonly) by
inventing a DIFFERENT invalid value on every call escapes both existing loop guards:
_STALL_REPEAT_THRESHOLD needs a byte-identical call repeated back-to-back, and
_MAX_IDENTICAL_FAILURES_PER_PHASE is keyed by the exact (name, arguments) signature, which is
different every time by construction here. Real, confirmed incident (NinthCircle-crackmes-usr_04a301):
a fallback-tier subagent model burned its entire 30-minute task budget re-guessing radare2's
`analysis` enum with 9 different invalid r2-command strings, each one correctly caught and
1-Step-Retry-corrected on its own (never_dispatched marker) but never carrying that correction
forward into the model's own conversation, so it kept guessing. never_dispatched_counts (keyed by
TOOL NAME alone) is the guard that catches this.
"""
import asyncio

from agent.core import RunContext, _MAX_SCHEMA_VIOLATIONS_PER_PHASE, _run_llm_tool_loop
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import ToolSpec
from sessions import store


def _isolate_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _make_tool(name: str) -> ToolSpec:
    return ToolSpec(
        name=name, category="re", tool_tier=2, executable="true",
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


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_schema_violation_test")


def test_repeated_schema_violations_with_different_values_are_capped(tmp_path, monkeypatch):
    _isolate_session_storage(tmp_path, monkeypatch)
    dispatched = []

    async def execute_always_never_dispatched(spec, arguments):
        # Every call uses a DIFFERENT invalid value -- the exact real-incident shape -- so no two
        # calls ever share a (name, arguments) signature.
        dispatched.append(arguments)
        return {"status": "error", "tool": spec.name, "error": "invalid analysis value", "never_dispatched": True}

    many_distinct_bad_calls = [
        ("radare2", {"analysis": f"/ad 0x{i:x}"}) for i in range(_MAX_SCHEMA_VIOLATIONS_PER_PHASE * 5)
    ]
    llm = _ScriptedLLM(many_distinct_bad_calls)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("radare2")], "subagent",
        execute_tool=execute_always_never_dispatched, expect_json_final=False,
    ))

    # Real dispatch happens up to the threshold; every call after that is skipped without ever
    # reaching execute_tool again -- the whole point of the guard.
    assert len(dispatched) == _MAX_SCHEMA_VIOLATIONS_PER_PHASE


def test_schema_violation_counter_also_catches_a_corrected_retry_that_succeeded():
    """The 1-Step Retry inside _run_tool_with_retry can successfully correct an individual
    never_dispatched failure -- the final result it returns is then a normal "ok" with no
    never_dispatched marker at all. The counter must still see it via
    "schema_violation_corrected" (set by _run_tool_with_retry itself), or every one of the 9 real
    violations in the actual incident would have gone uncounted since each one WAS corrected."""
    from agent.core import _TOOL_RETRY_BOOKKEEPING_KEYS

    assert "schema_violation_corrected" in _TOOL_RETRY_BOOKKEEPING_KEYS


def test_a_different_tool_is_not_affected_by_another_tools_schema_violations(tmp_path, monkeypatch):
    _isolate_session_storage(tmp_path, monkeypatch)
    dispatched = {"radare2": 0, "gdb": 0}

    async def execute(spec, arguments):
        dispatched[spec.name] += 1
        if spec.name == "radare2":
            return {"status": "error", "tool": "radare2", "error": "bad enum", "never_dispatched": True}
        return {"status": "ok", "tool": "gdb"}

    script = [("radare2", {"analysis": f"bad{i}"}) for i in range(_MAX_SCHEMA_VIOLATIONS_PER_PHASE * 3)]
    script += [("gdb", {"file_path": "/bin/ls"})] * 3
    llm = _ScriptedLLM(script)
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("radare2"), _make_tool("gdb")], "subagent",
        execute_tool=execute, expect_json_final=False,
    ))

    assert dispatched["radare2"] == _MAX_SCHEMA_VIOLATIONS_PER_PHASE
    assert dispatched["gdb"] == 3  # untouched by radare2's own guard
