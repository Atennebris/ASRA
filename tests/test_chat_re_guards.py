"""Targeted tests for agent/chat.py's RE-focused chat guards:
- the decoder-loop guard's result-based "progress" redefinition (RC#2),
- the deterministic radare2 -> target_profile auto-record wiring (RC#1),
- the anti-fabrication final-verdict guard (B3),
- the terminal-RE-success -> record_finding next-turn nudge (RC#4).

Network/LLM and tool dispatch are mocked at the exact call site (llm.complete,
load_session/save_session/reload_merge_save, _run_tool_with_retry) -- the same pattern test_chat.py
uses. Deliberately does NOT depend on the sibling-owned symbols auto_record_target_profile_from_tool
(agent.core) or build_re_chat_prompt (agent.prompts): where one is involved it is patched/spied in
this module's namespace, so these tests stand on their own regardless of concurrent edits elsewhere.
"""
import asyncio
import contextlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import agent.chat as chat
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY for get_tool below)
from agent.chat import (
    _consume_carryover_notes,
    _is_secret_shaped,
    _looks_like_re_success,
    _new_thread,
    _result_progress_signature,
    _run_chat_tool_loop,
    _unconfirmed_secret_assertions,
)
from agent.core import RunContext
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import get_tool


def _run(coro):
    return asyncio.run(coro)


def _ctx(session_id="usr_guard"):
    session = {"session_id": session_id, "target": "x", "status": "completed", "findings": [], "logs": [], "out_of_scope": []}
    return RunContext(llm=None, session=session, session_id=session_id)


def _msg(role, text, at="t"):
    return {"role": role, "at": at, "segments": [{"type": "text", "content": text}]}


def _session_with_thread(session_id, thread_id="thread_1", **thread_overrides):
    thread = {**_new_thread(), "id": thread_id, "messages": [_msg("user", "go")], **thread_overrides}
    return {
        "session_id": session_id, "target": "x", "status": "completed", "findings": [], "logs": [],
        "chat_threads": [thread], "active_chat_thread_id": thread_id,
    }


@contextlib.contextmanager
def _patches(session, *extra):
    """Routes agent.chat's own persistence (load/save and reload_merge_save) at the in-memory
    `session`, plus any extra patch objects passed in, so these loop tests need no real store on
    disk. reload_merge_save lives in sessions.store (not agent.chat), so patching load/save alone
    would miss it -- it is patched explicitly here to apply against the same in-memory session."""
    def fake_reload_merge_save(session_id, apply):
        apply(session)
        return session

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch("agent.chat.load_session", side_effect=lambda sid: session))
        stack.enter_context(patch("agent.chat.save_session", side_effect=lambda sid, data: None))
        stack.enter_context(patch("agent.chat.reload_merge_save", side_effect=fake_reload_merge_save))
        for extra_patch in extra:
            stack.enter_context(extra_patch)
        yield


# --- pure helpers -----------------------------------------------------------------------------


def test_result_progress_signature_differs_when_output_changes():
    a = _result_progress_signature({"status": "ok", "stdout": "parsed header MZ"})
    b = _result_progress_signature({"status": "ok", "stdout": "parsed section .text"})
    assert a != b


def test_result_progress_signature_ignores_volatile_metadata():
    a = _result_progress_signature({"status": "ok", "stdout": "same", "started_at": "t1", "llm": "p1"})
    b = _result_progress_signature({"status": "ok", "stdout": "same", "started_at": "t2", "llm": "p2"})
    assert a == b  # only the real output counts, not timing/which provider answered


def test_result_progress_signature_falls_back_but_stays_stable_for_identical_results():
    # No output-bearing field at all -> the fallback must still be identical call-to-call (so a
    # genuinely repeated empty result still reads as "no new output"), and status is excluded so a
    # retryable->ok flip alone doesn't look like progress.
    assert _result_progress_signature({"status": "ok"}) == _result_progress_signature({"status": "ok"})


@pytest.mark.parametrize("literal", ["super_secret_password_123", "FLAG{w0w}", "AB12-CD34-EF56", "9e3779b97f4a7c15"])
def test_is_secret_shaped_accepts_real_secrets(literal):
    assert _is_secret_shaped(literal) is True


@pytest.mark.parametrize("word", ["unknown", "MinGW", "the", "unclear", "password"])
def test_is_secret_shaped_rejects_plain_words(word):
    assert _is_secret_shaped(word) is False


def test_unconfirmed_secret_assertions_flags_a_literal_absent_from_tool_output():
    text = "The password is super_secret_password_123 and there is no crypto."
    assert _unconfirmed_secret_assertions(text, haystack="splitmix64 fmix64 digest bytes") == ["super_secret_password_123"]


def test_unconfirmed_secret_assertions_accepts_a_literal_present_in_tool_output():
    text = "The password is super_secret_password_123."
    assert _unconfirmed_secret_assertions(text, haystack="ACCESS GRANTED: super_secret_password_123") == []


def test_unconfirmed_secret_assertions_ignores_generic_prose():
    # "the compiler is unknown" must never trip the guard -- "unknown" is not secret-shaped.
    assert _unconfirmed_secret_assertions("The compiler is unknown.", haystack="") == []


def test_looks_like_re_success_detects_a_crack_marker_in_output():
    assert _looks_like_re_success({"status": "ok", "stdout": "Congratulations! Access granted."}) is True


def test_looks_like_re_success_false_on_ordinary_output():
    assert _looks_like_re_success({"status": "ok", "stdout": "disassembled 42 functions"}) is False


# --- RC#2: decoder-loop guard now measures progress by whether the OUTPUT changed ----------------


_PRODUCTIVE_OUTPUTS = [
    "found function sub_401000 at entry",
    "decrypted header: MZ, PE32+ executable for MS Windows",
    "located splitmix64 constant 0x9e3779b97f4a7c15 in .rdata",
    "loop runs 64 rounds, fmix64 accumulates the digest",
    "comparison against stored digest at 0x404050",
    "strcmp branch taken only when input matches the hash",
]


def test_decoder_loop_does_not_stop_a_productive_free_form_turn(monkeypatch):
    """RC#2: varied custom_re_script calls that each return materially NEW output are real
    incremental progress and must NOT be hard-stopped (the win-framework solve), even though the
    OLD guard counted every non-record call toward the hard stop regardless of output."""
    monkeypatch.setattr(chat, "_CHAT_DECODER_LOOP_NUDGE_THRESHOLD", 2)
    monkeypatch.setattr(chat, "_CHAT_DECODER_LOOP_HARD_STOP_THRESHOLD", 4)
    ctx = _ctx("usr_productive")
    spec = get_tool("custom_re_script")
    tool_calls = [
        LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{i}", name="custom_re_script", arguments={"source": f"step {i}"})])
        for i in range(6)
    ]
    final = LLMResponse(content="Recovered the parser logic, still finishing the decode.")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=tool_calls + [final]))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "keep decoding"}]
    session = _session_with_thread("usr_productive")

    results = [{"status": "ok", "stdout": out} for out in _PRODUCTIVE_OUTPUTS]
    with _patches(session, patch("agent.chat._run_tool_with_retry", new=AsyncMock(side_effect=results))):
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [spec], mode="reverse_engineering"))

    assert reply == final.content  # a natural finish -- never the forced-stop summary
    assert ctx.llm.complete.call_count == 7  # 6 real tool turns + 1 natural final answer
    tool_messages = [m for m in messages if m.get("role") == "tool"]
    assert all("playbook_hint" not in m["content"] for m in tool_messages)  # never even nudged


def test_decoder_loop_still_hard_stops_when_output_barely_changes(monkeypatch):
    """The guard's real protection stays intact: the same dead variation producing near-identical
    output call after call (the 70-minute incident) still reaches the hard stop."""
    monkeypatch.setattr(chat, "_CHAT_DECODER_LOOP_NUDGE_THRESHOLD", 2)
    monkeypatch.setattr(chat, "_CHAT_DECODER_LOOP_HARD_STOP_THRESHOLD", 4)
    ctx = _ctx("usr_dead")
    spec = get_tool("custom_re_script")
    # Exactly the number of calls the hard stop (threshold 4) allows before cutting in -- a 5th
    # leftover tool response would be what the forced-summary call returns instead of the summary.
    tool_calls = [
        LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{i}", name="custom_re_script", arguments={"source": f"variation {i}"})])
        for i in range(4)
    ]
    forced_summary = LLMResponse(content="I kept trying the same decode and it never worked.")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=tool_calls + [forced_summary]))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "keep decoding"}]
    session = _session_with_thread("usr_dead")

    dead = {"status": "ok", "stdout": "wine: command not found"}
    with _patches(session, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value=dead))):
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [spec], mode="reverse_engineering"))

    assert reply == forced_summary.content
    assert ctx.llm.complete.call_count == 5  # 4 tool turns to the hard stop + 1 forced summary
    assert session["chat_threads"][0].get("decoder_loop_cut") is True  # next turn will be warned


# --- RC#1: deterministic radare2 -> target_profile auto-record ----------------------------------


def test_radare2_call_triggers_auto_record_target_profile():
    """RC#1 (chat half): the chat RE loop must feed a radare2 result through
    auto_record_target_profile_from_tool so durable facts land even if the model never calls
    record_target_profile. The helper itself is sibling-owned; here it is spied, not exercised."""
    ctx = _ctx("usr_autorecord")
    spec = get_tool("radare2")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="radare2", arguments={"action": "info"})]),
        LLMResponse(content="That binary is a 64-bit PE."),
    ]))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what is this binary"}]
    session = _session_with_thread("usr_autorecord")
    radare_result = {"status": "ok", "stdout": "arch x86, bits 64, format pe"}
    spy = MagicMock()

    with _patches(
        session,
        patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value=radare_result)),
        patch("agent.chat.auto_record_target_profile_from_tool", spy),
    ):
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [spec], mode="reverse_engineering"))

    spy.assert_called_once()
    assert spy.call_args.args[1] == "radare2"
    assert spy.call_args.args[2]["stdout"] == "arch x86, bits 64, format pe"


# --- B3: anti-fabrication final-verdict guard ---------------------------------------------------


def test_final_re_verdict_asserting_an_unconfirmed_secret_gets_a_caveat():
    ctx = _ctx("usr_verdict_unconfirmed")
    spec = get_tool("custom_re_script")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="custom_re_script", arguments={"source": "run it"})]),
        LLMResponse(content="Solved it: the password is super_secret_password_123, there is no crypto."),
    ]))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "crack it"}]
    session = _session_with_thread("usr_verdict_unconfirmed")
    # The recorded tool output never contains that password -- exactly the crypto_crackme incident.
    result = {"status": "ok", "stdout": "msvc build, splitmix64/fmix64 hash, no plaintext password seen"}

    with _patches(session, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value=result))):
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [spec], mode="reverse_engineering"))

    assert "не подтверждено инструментами" in reply
    segment = session["chat_threads"][0]["messages"][-1]["segments"][-1]
    assert segment.get("unconfirmed_verdict") is True
    assert "super_secret_password_123" in segment["content"]


def test_final_re_verdict_asserting_a_tool_confirmed_secret_is_left_alone():
    ctx = _ctx("usr_verdict_confirmed")
    spec = get_tool("custom_re_script")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="custom_re_script", arguments={"source": "run it"})]),
        LLMResponse(content="The password is Sup3rKey_2024 (confirmed by running it)."),
    ]))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "crack it"}]
    session = _session_with_thread("usr_verdict_confirmed")
    result = {"status": "ok", "stdout": "wine run printed: password accepted -> Sup3rKey_2024"}

    with _patches(session, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value=result))):
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [spec], mode="reverse_engineering"))

    assert "не подтверждено инструментами" not in reply
    segment = session["chat_threads"][0]["messages"][-1]["segments"][-1]
    assert "unconfirmed_verdict" not in segment


def test_non_re_mode_verdict_is_never_caveated():
    ctx = _ctx("usr_verdict_agent")
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="The password is hunter2_abc999.", tool_calls=[])))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    session = _session_with_thread("usr_verdict_agent")

    with _patches(session, patch("agent.chat._run_tool_with_retry", new=AsyncMock())):
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="agent"))

    assert reply == "The password is hunter2_abc999."  # untouched in non-RE chat


# --- RC#4: terminal RE success -> record_finding next-turn nudge --------------------------------


def test_terminal_re_success_without_record_finding_flags_the_next_turn():
    ctx = _ctx("usr_success_unrecorded")
    spec = get_tool("custom_re_script")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="custom_re_script", arguments={"source": "run it"})]),
        LLMResponse(content="Done -- it printed the success banner."),
    ]))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "solve it"}]
    session = _session_with_thread("usr_success_unrecorded")
    result = {"status": "ok", "stdout": "Congratulations, you win! flag{abc}"}

    with _patches(session, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value=result))):
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [spec], mode="reverse_engineering"))

    assert session["chat_threads"][0].get("re_success_unrecorded") is True


def test_consume_carryover_notes_emits_and_clears_both_flags():
    session = _session_with_thread("usr_carryover", decoder_loop_cut=True, re_success_unrecorded=True)
    thread = session["chat_threads"][0]

    def fake_reload_merge_save(session_id, apply):
        apply(session)
        return session

    with patch("agent.chat.reload_merge_save", side_effect=fake_reload_merge_save):
        notes = _consume_carryover_notes("usr_carryover", "thread_1", thread)

    assert "cut short" in notes
    assert "record_finding" in notes
    # Fired exactly once -- the flags must be cleared so the turn after this one stays silent.
    assert "decoder_loop_cut" not in thread
    assert "re_success_unrecorded" not in thread


def test_consume_carryover_notes_is_empty_when_nothing_pending():
    session = _session_with_thread("usr_carryover_none")
    thread = session["chat_threads"][0]
    with patch("agent.chat.reload_merge_save", side_effect=AssertionError("must not write when nothing pending")):
        assert _consume_carryover_notes("usr_carryover_none", "thread_1", thread) == ""
