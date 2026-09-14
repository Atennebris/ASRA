"""_run_llm_tool_loop's garbled-output-reinforcement mechanism. Real incident this fixes
(a real HackerOne session, usr_b0f9b9, nemotron-3.5-lightning-free via opencode-zen): a phase-ending
turn came back with tool_calls=0 and content=`"There\\t\\n\\n, -չêubyt (, bildete"` -- a normal,
well-typed Python str (so llm_client.py's own content_was_malformed structural check never fires)
with no refusal phrasing either (so _looks_like_a_refusal never fires) -- and got silently treated
as this phase's real "nothing found" final answer, cascading the whole session straight through
exploit/validate to completed in under a second. Neither existing detector catches a reply that's
syntactically a normal string but linguistically incoherent -- tokenizer-level corruption from a
free-tier model under load.
"""
import asyncio

import pytest

from agent.core import RunContext, _looks_like_garbled_output, _run_llm_tool_loop
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
    return RunContext(llm=llm, session={"logs": []}, session_id="usr_garbled_test")


# --- _looks_like_garbled_output: the detector itself ---


_REAL_GARBLED_TEXT = "There\t\n\n, -չêubyt (, bildete"


@pytest.mark.parametrize("text", [
    _REAL_GARBLED_TEXT,
    "asdf ゾ的 -ubyte(, present",  # short burst mixing an unexpected script into otherwise-plain text
    "х" + "ա" * 3 + "yz",  # Armenian letters mixed into an otherwise short Cyrillic/Latin string
])
def test_looks_like_garbled_output_catches_real_corrupted_replies(text):
    assert _looks_like_garbled_output(text) is True


@pytest.mark.parametrize("text", [
    "Recon complete. Found targets: example.com (203.0.113.42) with SSH, HTTP, HTTPS.",
    "No other critical or high-severity vulnerabilities were found during this scan.",
    "Хорошо, давай разберёмся что за зверь. Запущу несколько анализов параллельно.",  # legitimate Russian reply
    "Nothing qualifies for the bounty here.",
    None,
    "",
    "   ",
    # Long legitimate English text past the length gate must never trip it, even if it happened to
    # contain a stray non-Latin/Cyrillic character somewhere in a URL/path/technical token.
    "A" * 250,
])
def test_looks_like_garbled_output_does_not_trip_on_legitimate_replies(text):
    assert _looks_like_garbled_output(text) is False


# --- integration: the reinforcement retry actually recovers a corrupted phase ---


class _GarbledThenRecoveryLLM:
    """Returns corrupted garbage on the first turn, then (once reinforced) does real work and
    completes normally -- proves the reinforcement message actually reaches the model and a
    corrupted reply isn't a dead end."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self.calls_made = 0
        self.seen_reinforcement = False

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self.calls_made == 1:
            return LLMResponse(content=_REAL_GARBLED_TEXT, tool_calls=[])
        self.seen_reinforcement = any("garbled" in (m.get("content") or "") for m in messages)
        if self.calls_made == 2:
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id="call_2", name="dns_lookup", arguments={"domain": "example.com"})])
        return LLMResponse(content="Recon complete. Found 1 target.", tool_calls=[])


def test_garbled_output_gets_one_reinforcement_and_can_recover():
    llm = _GarbledThenRecoveryLLM()
    ctx = _make_ctx(llm)

    result, trace = _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    assert llm.seen_reinforcement is True
    assert len(trace) == 1  # the real dns_lookup call after recovery actually ran
    assert ctx.session["logs"][-1]["status"] == "success"
    assert result is None


def test_persistent_garbled_output_is_still_accepted_after_the_one_reinforcement():
    """Same bounded shape as the refusal/malformed-content mechanisms: exactly one reinforcement
    attempt, not an open-ended loop -- a model that stays corrupted even after the nudge falls
    through to the normal free-text final-answer handling instead of retrying forever."""
    class _PersistentlyGarbledLLM:
        provider_id = "test-provider"
        model = "test-model"
        def __init__(self):
            self.calls_made = 0

        def complete(self, messages, tools=None, stop_check=None):
            self.calls_made += 1
            return LLMResponse(content=_REAL_GARBLED_TEXT, tool_calls=[])

    llm = _PersistentlyGarbledLLM()
    ctx = _make_ctx(llm)

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "recon",
        execute_tool=_noop_execute, expect_json_final=False,
    ))

    # Exactly one reinforcement attempt -- garbled, reinforced once, still garbled, then accepted
    # as-is (same fallback every other zero-tool-calls final reply gets), not retried forever.
    assert llm.calls_made == 2


def test_normal_completion_without_any_garbled_output_is_unaffected():
    """Regression guard: a phase that never says anything corrupted must behave exactly as before
    -- no reinforcement message injected, no extra LLM call spent."""
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
