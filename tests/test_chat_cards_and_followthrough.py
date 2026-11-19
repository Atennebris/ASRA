"""BUG1 (suggestion cards must ALWAYS show) and BUG2 ("promises then cuts off" follow-through)
enforcement in agent/chat.py's interactive/RE chat loop. LLM calls are mocked at llm.complete and
chat's own load_session/save_session (same pattern as test_chat.py) -- the suite never hits a real
model.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import agent.chat as chat
from agent.chat import (
    _proposes_next_steps_in_prose,
    _run_chat_tool_loop,
    _states_imminent_self_action,
    _trailing_list_steps,
)
from agent.core import RunContext
from agent.llm_client import LLMResponse, ToolCallRequest


def _run(coro):
    return asyncio.run(coro)


def _ctx(session_id="usr_followthrough"):
    session = {"session_id": session_id, "target": "x", "status": "completed", "findings": [], "logs": [], "out_of_scope": []}
    return RunContext(llm=None, session=session, session_id=session_id)


def _session_with_thread(session_id, thread_id="thread_1"):
    return {
        "session_id": session_id, "target": "x", "status": "completed", "findings": [], "logs": [],
        "chat_threads": [{"id": thread_id, "title": "t", "summary": "", "messages": [
            {"role": "user", "at": "t", "segments": [{"type": "text", "content": "go"}]},
        ], "updated_at": "t"}],
        "active_chat_thread_id": thread_id,
    }


def _patch_persistence(session):
    return (
        patch("agent.chat.load_session", side_effect=lambda sid: session),
        patch("agent.chat.save_session", side_effect=lambda sid, data: None),
    )


def _segments(session, thread_id="thread_1"):
    return session["chat_threads"][0]["messages"][-1]["segments"]


# --- pure detector helpers ---


def test_states_imminent_self_action_true_for_clear_english_and_russian_self_intent():
    assert _states_imminent_self_action("I'll run strings now to extract the symbols.") is True
    assert _states_imminent_self_action("Let me decompile main() and check the auth path.") is True
    assert _states_imminent_self_action("Сейчас запущу strings по бинарнику.") is True
    assert _states_imminent_self_action("Далее проверю, как устроена проверка лицензии.") is True


def test_states_imminent_self_action_false_for_questions_offers_and_plain_text():
    # A question to the operator -- asking, not committing.
    assert _states_imminent_self_action("Should I run strings to extract the symbols?") is False
    assert _states_imminent_self_action("Хотите, чтобы я запустил strings?") is False
    # Offering options / describing what the OPERATOR could do.
    assert _states_imminent_self_action("You can run strings, or you could decompile main().") is False
    assert _states_imminent_self_action("Вы можете запустить strings, если хотите.") is False
    # "I'll" with no action verb -- not a commitment to act.
    assert _states_imminent_self_action("Let me know if you want me to keep going.") is False
    assert _states_imminent_self_action("I'll be happy to help once you share the binary.") is False
    # Plain informational answer.
    assert _states_imminent_self_action("The binary is a 64-bit MSVC build with no obfuscation.") is False


def test_trailing_list_steps_parses_last_numbered_or_bulleted_block():
    text = (
        "Here's what I found: the login form reflects input.\n\n"
        "1. Check whether the login form is vulnerable to SQLi\n"
        "2. Decompile main() to inspect the auth check\n"
    )
    assert _trailing_list_steps(text) == [
        "Check whether the login form is vulnerable to SQLi",
        "Decompile main() to inspect the auth check",
    ]
    # A closing remark after the list must not hide it; the LAST contiguous run wins.
    text2 = "Intro.\n- do A\n- do B\n\nLet me know which one.\n"
    assert _trailing_list_steps(text2) == ["do A", "do B"]
    # No list -> nothing.
    assert _trailing_list_steps("Just a plain sentence.") == []


def test_proposes_next_steps_in_prose_detects_handoff_markers():
    assert _proposes_next_steps_in_prose("Next steps: verify the redirect and check the cookie flags.") is True
    assert _proposes_next_steps_in_prose("Дальше можно проверить загрузку файлов.") is True
    assert _proposes_next_steps_in_prose("The scan is complete and nothing else is left.") is False


# --- BUG1: cards must always show ---


def test_prose_list_turn_ends_with_synthesized_suggested_actions_segment():
    """A turn that proposes next steps only as a trailing numbered list (no suggest_next_steps call)
    must still end with a suggested_actions segment -- synthesized from the list, with NO extra LLM
    call (path a)."""
    ctx = _ctx("usr_bug1_prose")
    text = (
        "The login form reflects input unescaped.\n\n"
        "1. Check whether the login form is vulnerable to SQLi\n"
        "2. Decompile main() to inspect the auth check\n"
    )
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content=text, tool_calls=[])))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what next?"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="interactive"))

    ctx.llm.complete.assert_called_once()  # path (a): no second model step
    actions = next(s for s in _segments(session) if s["type"] == "suggested_actions")
    assert actions["actions"] == [
        "Check whether the login form is vulnerable to SQLi",
        "Decompile main() to inspect the auth check",
    ]


def test_prose_proposal_without_a_clean_list_falls_back_to_one_forced_model_step():
    """When the proposal is prose without a parseable list, BUG1 issues ONE bounded model step whose
    only allowed action is suggest_next_steps -- and renders its cards."""
    ctx = _ctx("usr_bug1_forced")
    forced = ToolCallRequest(id="c1", name="suggest_next_steps", arguments={"steps": ["Verify the open redirect", "Check cookie flags"]})
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content="Next steps you could take: verify the redirect, then look at the cookies.", tool_calls=[]),
        LLMResponse(content="", tool_calls=[forced]),
    ]))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what next?"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="interactive"))

    assert ctx.llm.complete.call_count == 2  # one bounded forced suggestion step
    actions = next(s for s in _segments(session) if s["type"] == "suggested_actions")
    assert actions["actions"] == ["Verify the open redirect", "Check cookie flags"]


def test_plain_answer_with_no_proposed_steps_produces_no_cards():
    """BUG1 must not fabricate cards: a fully-closed answer proposing nothing gets no suggested_actions
    segment and no extra model step."""
    ctx = _ctx("usr_bug1_none")
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="The target is fully patched; nothing exploitable remains.", tool_calls=[])))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "anything left?"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="interactive"))

    ctx.llm.complete.assert_called_once()
    assert all(s["type"] != "suggested_actions" for s in _segments(session))


def test_agent_mode_does_not_synthesize_cards():
    """Cards are an interactive/RE affordance only -- Agent mode never gets a synthesized menu."""
    ctx = _ctx("usr_bug1_agentmode")
    text = "Findings:\n1. First\n2. Second\n"
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content=text, tool_calls=[])))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "report"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="agent"))

    ctx.llm.complete.assert_called_once()
    assert all(s["type"] != "suggested_actions" for s in _segments(session))


# --- BUG2: promises then cuts off -> auto-continue ---


def test_unfulfilled_self_intent_triggers_exactly_one_auto_continue():
    """A turn ending with a clear 'I'll run X' self-intent but NO tool call auto-continues one more
    turn so the agent actually acts, instead of handing control back mid-promise."""
    ctx = _ctx("usr_bug2_continue")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content="Сейчас запущу strings по бинарнику, чтобы вытащить строки.", tool_calls=[]),
        LLMResponse(content="Готово: strings отработал, нашёл отладочную строку.", tool_calls=[]),
    ]))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "вытащи строки"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="reverse_engineering"))

    assert ctx.llm.complete.call_count == 2  # initial + exactly one auto-continue
    assert reply == "Готово: strings отработал, нашёл отладочную строку."
    assert any(m.get("content") == chat._AUTO_CONTINUE_INSTRUCTION for m in messages)


def test_question_to_operator_does_not_auto_continue():
    """Asking the operator a question is not an unfulfilled self-action -- no auto-continue."""
    ctx = _ctx("usr_bug2_question")
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="Хотите, чтобы я запустил strings по бинарнику?", tool_calls=[])))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "что дальше?"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="reverse_engineering"))

    ctx.llm.complete.assert_called_once()  # no auto-continue
    assert reply == "Хотите, чтобы я запустил strings по бинарнику?"
    assert all(m.get("content") != chat._AUTO_CONTINUE_INSTRUCTION for m in messages)


def test_options_offer_does_not_auto_continue():
    """Offering the operator options ('you could...') is not a self-commitment -- no auto-continue."""
    ctx = _ctx("usr_bug2_options")
    # A forced suggestion step may follow (prose proposal) but an auto-continue nudge must never be issued.
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content="You can run strings, or you could decompile main() to inspect the check.", tool_calls=[]),
        LLMResponse(content="", tool_calls=[ToolCallRequest(id="c1", name="suggest_next_steps", arguments={"steps": ["Run strings", "Decompile main()"]})]),
    ]))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what next?"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="interactive"))

    assert all(m.get("content") != chat._AUTO_CONTINUE_INSTRUCTION for m in messages)


def test_auto_continue_respects_cap_and_surfaces_an_honest_note_when_exhausted():
    """When the cap is used up and the promised action still hasn't landed, the turn stops with a
    visible honest note (no silent drop) and still emits suggestion cards."""
    ctx = _ctx("usr_bug2_cap")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content="I'll run strings now to pull the symbols.", tool_calls=[]),
        LLMResponse(content="Let me decode the firmware image next.\n\n1. Dump the flash with the debugger\n2. Decode the recovered image\n", tool_calls=[]),
    ]))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "extract it"}]

    p1, p2 = _patch_persistence(session)
    with patch.object(chat, "_CHAT_MAX_AUTO_CONTINUE", 1), p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="interactive"))

    assert ctx.llm.complete.call_count == 2  # initial + one auto-continue, then exhausted (no further model step here)
    segs = _segments(session)
    note = next(s for s in segs if s["type"] == "text" and s.get("error") and s["content"] == chat._AUTO_CONTINUE_EXHAUSTED_NOTE)
    assert note is not None
    actions = next(s for s in segs if s["type"] == "suggested_actions")
    assert actions["actions"] == ["Dump the flash with the debugger", "Decode the recovered image"]


def test_repeated_identical_promise_stops_auto_continuing_early():
    """A near-identical promise repeated with no progress stops the auto-continue immediately (reusing
    the decoder-loop similarity threshold), before the cap would otherwise allow another."""
    ctx = _ctx("usr_bug2_repeat")
    same = "Сейчас запущу strings по бинарнику, чтобы вытащить строки."
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content=same, tool_calls=[]),
        LLMResponse(content=same, tool_calls=[]),
    ]))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "вытащи строки"}]

    p1, p2 = _patch_persistence(session)
    with patch.object(chat, "_CHAT_MAX_AUTO_CONTINUE", 3), p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="reverse_engineering"))

    # Only one auto-continue happened (2 calls), not three: the repeated identical promise tripped the
    # early-stop, and the exhausted note was surfaced.
    assert ctx.llm.complete.call_count == 2
    assert any(s["type"] == "text" and s.get("error") and s["content"] == chat._AUTO_CONTINUE_EXHAUSTED_NOTE for s in _segments(session))
