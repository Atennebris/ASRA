"""suggest_next_steps must be TERMINAL: once the chat loop shows the operator a card menu, the turn
ends -- no further LLM call, no tool runs after the cards. Real complaint: the agent offered cards
and then kept working (another decompile, a browser_navigate that 404'd) while still "thinking", so
clicking a card would interrupt a half-finished action.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent.chat import _run_chat_tool_loop
from agent.core import RunContext
from agent.llm_client import LLMResponse, ToolCallRequest


def _run(coro):
    return asyncio.run(coro)


def _ctx(session_id="usr_cards_terminal"):
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


def test_cards_end_the_turn_second_response_never_consumed():
    ctx = _ctx()
    # If the loop WRONGLY kept going after the cards, it would consume this second response and try a
    # real tool call. The assertion that complete is called exactly once is what proves cards are terminal.
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[
        LLMResponse(content="Here is what I found so far.", tool_calls=[
            ToolCallRequest(id="c1", name="suggest_next_steps", arguments={"steps": ["Decompile main()", "Grep for license"]}),
        ]),
        LLMResponse(content="", tool_calls=[ToolCallRequest(id="c2", name="radare2", arguments={})]),
    ]))
    session = _session_with_thread(ctx.session_id)
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what next?"}]

    p1, p2 = _patch_persistence(session)
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="reverse_engineering"))

    assert ctx.llm.complete.call_count == 1
    seg_types = [s["type"] for s in session["chat_threads"][0]["messages"][-1]["segments"]]
    assert "suggested_actions" in seg_types
