"""Unit tests for agent/chat.py. Network/LLM calls mocked via unittest.mock.patch on the
exact call site (llm.complete, load_session/save_session) — same pattern as test_llm_client.py.
"""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from agent.chat import (
    _compact_if_needed,
    _estimate_tokens,
    _handle_tool_calls,
    _session_snapshot,
    run_chat_turn,
)
from agent.core import get_instruction_queue
from agent.llm_client import LLMResponse, ToolCallRequest


def _run(coro):
    return asyncio.run(coro)


# --- pure functions ---


def test_session_snapshot_includes_target_status_findings_recent_logs():
    session = {
        "target": "example.com",
        "status": "processing",
        "recon_result": {"targets": [{"host": "example.com", "port": 443}]},
        "findings": [{"title": "XSS", "severity": "High", "verification": "verified", "exploited": False}],
        "logs": [{"phase": "recon", "command": "dns_lookup(...)", "status": "success"}] * 10,
    }
    snapshot = json.loads(_session_snapshot(session))
    assert snapshot["target"] == "example.com"
    assert snapshot["status"] == "processing"
    assert snapshot["findings"] == [{"title": "XSS", "severity": "High", "verification": "verified", "exploited": False}]
    assert len(snapshot["recent_activity"]) == 5  # trimmed to the last N, not all 10


def test_session_snapshot_handles_missing_optional_fields():
    snapshot = json.loads(_session_snapshot({"target": "x", "status": "pending"}))
    assert snapshot["recon_targets"] == []
    assert snapshot["findings"] == []
    assert snapshot["recent_activity"] == []


def test_estimate_tokens_is_roughly_chars_over_four():
    assert _estimate_tokens("a" * 400) == 100


# --- _handle_tool_calls: queues directives, doesn't touch the session file itself ---


def test_handle_tool_calls_skip_finding_queues_instruction():
    session_id = "usr_test_chat_1"
    call = ToolCallRequest(id="call_1", name="skip_finding", arguments={"finding_title": "Reflected XSS"})

    reply = _handle_tool_calls(session_id, [call])

    queue = get_instruction_queue(session_id)
    assert queue.get_nowait() == {"type": "skip_finding", "finding_title": "Reflected XSS"}
    assert "Reflected XSS" in reply


def test_handle_tool_calls_add_guidance_queues_instruction():
    session_id = "usr_test_chat_2"
    call = ToolCallRequest(id="call_1", name="add_guidance", arguments={"text": "focus on the login form"})

    reply = _handle_tool_calls(session_id, [call])

    queue = get_instruction_queue(session_id)
    assert queue.get_nowait() == {"type": "add_guidance", "text": "focus on the login form"}
    assert "focus on the login form" in reply


def test_handle_tool_calls_multiple_calls_all_queued():
    session_id = "usr_test_chat_3"
    calls = [
        ToolCallRequest(id="call_1", name="skip_finding", arguments={"finding_title": "A"}),
        ToolCallRequest(id="call_2", name="add_guidance", arguments={"text": "hint"}),
    ]

    _handle_tool_calls(session_id, calls)

    queue = get_instruction_queue(session_id)
    assert queue.qsize() == 2


# --- _compact_if_needed: triggers only over budget, produces a shorter combined summary ---


def test_compact_if_needed_skips_when_under_budget():
    llm = SimpleNamespace(context_limit=128000, complete=MagicMock())
    chat = {"summary": "", "messages": [{"role": "user", "content": "hi", "at": "t"}]}

    _run(_compact_if_needed(llm, chat, "usr_x"))

    llm.complete.assert_not_called()
    assert chat["messages"] == [{"role": "user", "content": "hi", "at": "t"}]


def test_compact_if_needed_triggers_and_replaces_summary_when_over_budget():
    # Tiny context_limit forces the budget well below the size of the synthetic history below.
    llm = SimpleNamespace(context_limit=100, complete=MagicMock(return_value=LLMResponse(content="Condensed summary.")))
    messages = [{"role": "user", "content": "message " * 50, "at": str(i)} for i in range(10)]
    chat = {"summary": "old summary", "messages": messages}

    _run(_compact_if_needed(llm, chat, "usr_y"))

    llm.complete.assert_called_once()
    assert chat["summary"] == "Condensed summary."
    assert len(chat["messages"]) == 4  # only the most recent kept verbatim


def test_compact_if_needed_noop_when_too_few_messages_to_retire():
    llm = SimpleNamespace(context_limit=1, complete=MagicMock())  # budget always exceeded
    chat = {"summary": "", "messages": [{"role": "user", "content": "hi", "at": "t"}]}

    _run(_compact_if_needed(llm, chat, "usr_z"))

    llm.complete.assert_not_called()


# --- run_chat_turn: end-to-end with load_session/save_session/get_provider mocked ---


def test_run_chat_turn_plain_reply_persists_exchange():
    session = {"session_id": "usr_e2e_1", "target": "x", "status": "completed", "findings": [], "logs": []}
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(return_value=LLMResponse(content="It found nothing.")))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save, patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        reply = _run(run_chat_turn("usr_e2e_1", "what did the scan find?"))

    assert reply == "It found nothing."
    mock_save.assert_called_once()
    saved_session = mock_save.call_args[0][1]
    assert saved_session["chat"]["messages"][-2] == {"role": "user", "content": "what did the scan find?", "at": saved_session["chat"]["messages"][-2]["at"]}
    assert saved_session["chat"]["messages"][-1]["content"] == "It found nothing."


def test_run_chat_turn_tool_call_reply_queues_and_confirms():
    session = {"session_id": "usr_e2e_2", "target": "x", "status": "processing", "findings": [], "logs": []}
    tool_call = ToolCallRequest(id="call_1", name="add_guidance", arguments={"text": "check the API"})
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(return_value=LLMResponse(content=None, tool_calls=[tool_call])))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"), patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        reply = _run(run_chat_turn("usr_e2e_2", "please check the API"))

    assert "check the API" in reply
    queue = get_instruction_queue("usr_e2e_2")
    assert queue.get_nowait() == {"type": "add_guidance", "text": "check the API"}


def test_run_chat_turn_unknown_session_raises():
    with patch("agent.chat.load_session", return_value=None):
        with pytest.raises(ValueError, match="Unknown session"):
            _run(run_chat_turn("usr_does_not_exist", "hi"))
