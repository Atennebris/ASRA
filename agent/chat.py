"""Chat panel: a separate, persisted conversation about a session — not the same LLM
conversation as the autonomous ReAct loop (agent/core.py). This module never reads the agent's
raw tool-call trace and the agent never reads chat history; the only link between them is a
short, structured directive (skip_finding/add_guidance) queued via agent.core's instruction
queue, applied at the loop's own natural iteration boundaries — never a shared context, never a
live interrupt of an in-flight LLM call.

Storage: session["chat"] = {"summary": str, "messages": [{"role", "content", "at"}, ...]} — the
same session JSON file everything else lives in (sessions/store.py), no new persistence layer.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from agent.core import get_instruction_queue
from agent.llm_client import LLMProvider, ToolCallRequest, get_provider
from agent.prompts import CHAT_COMPACTION_PROMPT, CHAT_PROMPT
from agent.utils.logger import get_logger
from sessions.store import load_session, save_session

logger = get_logger("CHAT")

_CHARS_PER_TOKEN = 4  # same rough estimate used elsewhere in this codebase (agent/utils/debug.py)
# Keep chat history within this fraction of the model's real context window — the rest is
# reserved for the session snapshot, the system prompt, and the model's own reply.
_COMPACTION_BUDGET_FRACTION = 0.3
_DEFAULT_CONTEXT_LIMIT = 32000  # fallback when the provider's context_limit is unknown
_RECENT_MESSAGES_KEPT_VERBATIM = 4
_RECENT_LOG_ENTRIES_IN_SNAPSHOT = 5

_CHAT_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "skip_finding",
            "description": "Mark one specific, not-yet-exploited finding to be skipped instead of attempted.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_title": {"type": "string", "description": "Exact finding title, as shown in the session snapshot"},
                },
                "required": ["finding_title"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_guidance",
            "description": "Queue a short steering hint for the scan phase currently running, if any.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "The hint, a sentence or two"},
                },
                "required": ["text"],
            },
        },
    },
]


def _session_snapshot(session: dict) -> str:
    """Fresh facts about the session, rebuilt every turn — never accumulated into chat history
    (that would defeat the whole point of compacting the history separately, see module docstring).
    Findings/log fields are trimmed to what a human would actually need to discuss, not the full
    raw record.
    """
    findings = session.get("findings", [])
    recent_logs = session.get("logs", [])[-_RECENT_LOG_ENTRIES_IN_SNAPSHOT:]
    snapshot = {
        "target": session.get("target"),
        "status": session.get("status"),
        "recon_targets": session.get("recon_result", {}).get("targets", []),
        "findings": [
            {
                "title": f.get("title"),
                "severity": f.get("severity"),
                "verification": f.get("verification"),
                "exploited": f.get("exploited"),
            }
            for f in findings
        ],
        "recent_activity": [
            {"phase": entry.get("phase"), "command": entry.get("command"), "status": entry.get("status")}
            for entry in recent_logs
        ],
    }
    return json.dumps(snapshot)


def _estimate_tokens(text: str) -> int:
    return len(text) // _CHARS_PER_TOKEN


async def _compact_if_needed(llm: LLMProvider, chat: dict, session_id: str) -> None:
    budget = int((llm.context_limit or _DEFAULT_CONTEXT_LIMIT) * _COMPACTION_BUDGET_FRACTION)
    history_size = _estimate_tokens(chat["summary"] + json.dumps(chat["messages"]))
    if history_size <= budget:
        return

    messages = chat["messages"]
    if len(messages) <= _RECENT_MESSAGES_KEPT_VERBATIM:
        return  # nothing old enough to retire yet, budget pressure comes from the snapshot itself
    to_retire = messages[:-_RECENT_MESSAGES_KEPT_VERBATIM]

    logger.debug(
        "chat: session=%s history ~%d tokens over budget (%d) — compacting %d message(s)",
        session_id, history_size, budget, len(to_retire),
    )
    compaction_messages = [
        {"role": "system", "content": CHAT_COMPACTION_PROMPT},
        {
            "role": "user",
            "content": f"Existing summary:\n{chat['summary'] or '(none yet)'}\n\nMessages to fold in:\n{json.dumps(to_retire)}",
        },
    ]
    response = await asyncio.to_thread(llm.complete, compaction_messages, None)
    chat["summary"] = response.content or chat["summary"]
    chat["messages"] = messages[-_RECENT_MESSAGES_KEPT_VERBATIM:]
    logger.debug("chat: session=%s compaction done, new summary is %d chars", session_id, len(chat["summary"]))


def _handle_tool_calls(session_id: str, tool_calls: list[ToolCallRequest]) -> str:
    queue = get_instruction_queue(session_id)
    confirmations = []
    for call in tool_calls:
        if call.name == "skip_finding":
            title = call.arguments.get("finding_title", "")
            queue.put_nowait({"type": "skip_finding", "finding_title": title})
            logger.debug("chat: session=%s queued skip_finding(%r)", session_id, title)
            confirmations.append(f'Got it — I\'ll make sure "{title}" is skipped.')
        elif call.name == "add_guidance":
            text = call.arguments.get("text", "")
            queue.put_nowait({"type": "add_guidance", "text": text})
            logger.debug("chat: session=%s queued add_guidance(%r)", session_id, text)
            confirmations.append(f'Noted — passed along to the running scan: "{text}".')
        else:
            logger.debug("chat: session=%s ignoring unknown chat tool call %r", session_id, call.name)
    return " ".join(confirmations) if confirmations else "Okay."


async def run_chat_turn(session_id: str, user_message: str) -> str:
    """Runs one chat turn: loads the session, builds a fresh snapshot + compacted history,
    calls the LLM (same provider/model as the scan, separate conversation), applies any tool
    call as a queued directive, persists the exchange, and returns the reply text.
    """
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")

    chat = session.setdefault("chat", {"summary": "", "messages": []})
    llm = get_provider()

    logger.debug("chat: session=%s user message received (%d chars)", session_id, len(user_message))
    await _compact_if_needed(llm, chat, session_id)

    messages = [
        {"role": "system", "content": CHAT_PROMPT},
        {"role": "user", "content": f"Current session state:\n{_session_snapshot(session)}"},
    ]
    if chat["summary"]:
        messages.append({"role": "assistant", "content": f"(summary of earlier conversation) {chat['summary']}"})
    for past in chat["messages"]:
        messages.append({"role": past["role"], "content": past["content"]})
    messages.append({"role": "user", "content": user_message})

    response = await asyncio.to_thread(llm.complete, messages, _CHAT_TOOLS_SCHEMA)
    reply_text = _handle_tool_calls(session_id, response.tool_calls) if response.tool_calls else (response.content or "")

    now = datetime.now(timezone.utc).isoformat()
    chat["messages"].append({"role": "user", "content": user_message, "at": now})
    chat["messages"].append({"role": "assistant", "content": reply_text, "at": now})
    save_session(session_id, session)
    logger.debug("chat: session=%s reply sent (%d chars)", session_id, len(reply_text))
    return reply_text
