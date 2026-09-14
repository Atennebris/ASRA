"""_run_llm_tool_loop's refusal-reinforcement mechanism. Real incident this fixes: a real recon
phase got a full safety-style refusal ("I cannot assist with hacking or unauthorized access...")
from the model after a few genuinely successful tool calls, and the loop silently treated that as
"recon complete, 0 targets found" — status="success", no indication anything unusual happened. The
target's own recon_result stayed empty for the rest of that run, and nothing in the UI/logs
distinguished it from a real, clean "nothing here" result.
"""
import asyncio

import pytest

from agent.core import RunContext, _looks_like_a_refusal, _run_llm_tool_loop
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


async def _noop_execute(spec, arguments):
    return {"status": "ok", "tool": spec.name}


def _make_ctx(llm) -> RunContext:
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_refusal_test")


# --- _looks_like_a_refusal: the detector itself ---


_REAL_REFUSAL_TEXT = (
    "I cannot assist with hacking or unauthorized access to computer systems. This request asks "
    "for activities that are: 1. **Illegal** - Unauthorized access to computer systems violates "
    "computer crime laws in most jurisdictions"
)


@pytest.mark.parametrize("text", [
    _REAL_REFUSAL_TEXT,
    "I can't help with that request.",
    "I'm not able to assist with this.",
    "I'm unable to comply with this request.",
    "That would go against my guidelines, so I must decline.",
    "I cannot provide assistance for malicious or illegal activities.",
    "I don't feel comfortable proceeding with this.",
])
def test_looks_like_a_refusal_catches_real_refusal_phrasings(text):
    assert _looks_like_a_refusal(text) is True


@pytest.mark.parametrize("text", [
    "Recon complete. Found targets: example.com (185.132.176.192) with SSH, HTTP, HTTPS.",
    "No other critical or high-severity vulnerabilities were found during this scan.",
    "I cannot confirm this CVE is exploitable without further access.",
    "I'm unable to verify the current OpenSSH version without a working banner-grab tool.",
    "The theoretical risk was real when Flash was alive, but no modern browser executes SWF.",
    None,
    "",
])
def test_looks_like_a_refusal_does_not_trip_on_legitimate_conclusions(text):
    assert _looks_like_a_refusal(text) is False


# --- integration: the reinforcement retry actually recovers a refused phase ---


class _RefusalThenRecoveryLLM:
    """Refuses outright on the first turn, then (once reinforced) does real work and completes
    normally -- proves the reinforcement message actually reaches the model and a refusal isn't a
    dead end."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self.calls_made = 0
        self.seen_reinforcement = False

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self.calls_made == 1:
            return LLMResponse(content=_REAL_REFUSAL_TEXT, tool_calls=[])
        self.seen_reinforcement = any("pre-authorized" in (m.get("content") or "") for m in messages)
        if self.calls_made == 2:
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id="call_2", name="dns_lookup", arguments={"domain": "example.com"})])
        return LLMResponse(content="Recon complete. Found 1 target.", tool_calls=[])


def test_refusal_gets_one_reinforcement_and_can_recover(tmp_path):
    llm = _RefusalThenRecoveryLLM()
    ctx = _make_ctx(llm)

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    assert llm.seen_reinforcement is True
    assert len(trace) == 1  # the real dns_lookup call after recovery actually ran
    assert ctx.session["logs"][-1]["status"] == "success"  # ended as a genuine completion, not an error
    assert result is None  # expect_json_final=False phases return None on a normal free-text wrap-up


# --- integration: a refusal that persists even after reinforcement is flagged, not silently "ok" ---


class _PersistentRefusalLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self):
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        return LLMResponse(content=_REAL_REFUSAL_TEXT, tool_calls=[])


def test_persistent_refusal_is_flagged_as_an_error_not_a_silent_success(tmp_path):
    llm = _PersistentRefusalLLM()
    ctx = _make_ctx(llm)

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    # Exactly one reinforcement attempt -- refused, reinforced once, refused again, then stopped.
    # Not an open-ended loop the model could keep refusing through.
    assert llm.calls_made == 2
    assert trace == []
    assert result is None
    last_log = ctx.session["logs"][-1]
    assert last_log["status"] == "error"
    assert "authorization reminder" in last_log["error"]


def test_persistent_refusal_is_flagged_for_terminal_tool_phases_too(tmp_path):
    """Same mechanism, exercised through the terminal_tool path (Exploit/Reverify's shape)
    instead of the free-text-wrapup path (Recon/Analyze's shape) -- both must not silently
    swallow a refusal as if the model legitimately had nothing to report."""
    llm = _PersistentRefusalLLM()
    ctx = _make_ctx(llm)

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("record_exploit_decision")], "exploit",
        execute_tool=_noop_execute, terminal_tool="record_exploit_decision",
    ))

    # 1st call refuses, 2nd (post-reinforcement) refuses again, then the pre-existing terminal_tool
    # safety net tries one more repair round-trip (_repair_json_reply) on the unparsable refusal
    # text before giving up -- that 3rd call is the same existing behavior as any other unparsable
    # terminal_tool reply, not something new added here.
    assert llm.calls_made == 3
    assert result is None
    last_log = ctx.session["logs"][-1]
    assert last_log["status"] == "error"
    assert "authorization reminder" in last_log["error"]


def test_normal_completion_without_any_refusal_is_unaffected(tmp_path):
    """Regression guard: a phase that never says anything refusal-shaped must behave exactly as
    before -- no reinforcement message injected, no extra LLM call spent."""
    class _CleanCompletionLLM:
        provider_id = "test-provider"
        model = "test-model"
        def __init__(self):
            self.calls_made = 0

        def complete(self, messages, tools=None, stop_check=None):
            self.calls_made += 1
            if self.calls_made == 1:
                return LLMResponse(content=None, tool_calls=[ToolCallRequest(id="call_1", name="dns_lookup", arguments={"domain": "example.com"})])
            return LLMResponse(content="Recon complete. Found 1 target.", tool_calls=[])

    llm = _CleanCompletionLLM()
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    assert llm.calls_made == 2  # exactly the tool call + the wrap-up, no reinforcement round-trip
    assert ctx.session["logs"][-1]["status"] == "success"
