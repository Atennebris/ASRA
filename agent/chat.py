"""Chat panel: separate, persisted conversations about a session — not the same LLM conversation
as the autonomous ReAct loop (agent/core.py). This module never reads the agent's raw tool-call
trace and the agent never reads chat history; the only link between them is a short, structured
directive (skip_finding/add_guidance) queued via agent.core's instruction queue, applied at the
loop's own natural iteration boundaries — never a shared context, never a live interrupt of an
in-flight LLM call. The one deliberate exception is read-only: chat's own system prompt gets the
same cross-session technique-playbook addendum Analyze/Exploit already use
(agent.core._playbook_task_addendum) — a lead to consider, never something chat can write to.

Storage: session["chat_threads"] = [thread, ...], session["active_chat_thread_id"] = str — several
independent, named conversations per project (Umbra-Agent-style /new /resume), not one that grows
forever. Each thread:
{
  "id": str, "title": str, "summary": str,
  "messages": [{"role": "user"|"assistant", "at": iso, "segments": [...]}],
  "provider": str | None, "model": str | None, "pending": bool,
  "created_at": iso, "updated_at": iso, "color": str | None,
}
"color" (added later, absent on an older thread until touched -- see thread.setdefault below) is a
"#rrggbb" string or None, the Quick Chat tab strip's own per-tab customization (real, explicit
operator ask: parity with the Terminal tab strip's own color picker, static/js/terminal.js's
setTabColor) -- persisted here rather than the Terminal's own per-browser localStorage, since a
thread already lives in session.json and this way the color survives across devices/reloads the
same way its title/messages already do. set_chat_thread_color() is the one writer.
A message's own "segments" is an ORDERED list of {"type": "text", "content": str},
{"type": "tool_call", "id", "name", "arguments", "output", "error", "done"}, and/or
{"type": "suggested_actions", "actions": [str, ...]} entries — one interleaved sequence per turn,
in the order they actually happened (Piligrim's own chat model, adapted here), not a flat text blob
with tool calls thrown away once the turn ends. The "suggested_actions" kind is UI-only, appended by
the suggest_next_steps bookkeeping tool (Interactive/Reverse-Engineering modes only) — the operator
sees each action as a clickable button (chat_messages.html) that fills their input box on click,
instead of the model writing a numbered list into its own prose. Persisted
INCREMENTALLY as a turn runs (_append_segment_and_save / _update_last_tool_call_segment_and_save),
not batched at the end, so the existing chat SSE stream (main.py's /chat/stream, already re-pushes
on any session["chat_threads"] change) shows a tool card go from pending to done live, the same
"real data, persisted the instant it's known" discipline this codebase already applies to
findings/logs elsewhere.

provider/model/pending are per-thread (each thread can use a different provider, and only ITS OWN
turn shows "thinking"). A session created before this shipped has session["chat"] (the old flat
single-conversation schema) instead — migrated into a one-thread chat_threads list the first time
_ensure_chat_threads runs (see its own docstring), same "upgrade in place on read" convention this
module already used for provider/model/pending before threads existed.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os
import re
import uuid
from datetime import datetime, timezone


from agent.core import (
    _apply_corrected_false_positive_reason,
    _apply_corrected_qualification,
    _apply_corrected_title,
    _BROWSER_TOOL_NAMES,
    _embed_playbook_entries,
    _embed_playbook_query,
    _playbook_fingerprint_key,
    _goal_task_addendum,
    _playbook_task_addendum,
    _re_experience_level_addendum,
    _run_tool_with_retry,
    _scope_rules_task_addendum,
    _technology_keywords,
    _TOOL_RESULT_CHAR_LIMIT,
    _tool_to_openai_schema,
    _TOOLKIT_TOOL_TOGGLE_KEYS,
    _VALID_SEVERITIES,
    get_instruction_queue,
    RunContext,
)
from agent.llm_client import LLMCallAborted, LLMProvider, ToolCallRequest, get_provider
from agent.prompts import CHAT_COMPACTION_PROMPT, CHAT_PROMPT, INTERACTIVE_CHAT_PROMPT, PLAYBOOK_STRATEGY_PROMPT, RE_CHAT_PROMPT, STANDALONE_CHAT_PROMPT
from agent.tools import chat_settings_store, playbook_store
from agent.tools.allowed_targets import authorize_all_targets_for_context, deauthorize_all_targets_for_context
from agent.tools.registry import ToolSpec, get_tool, get_tools_by_category
from agent.tools.subagent_store import get_enabled_profiles
from agent.tools.toolkit_settings_store import load_toolkit_agent_settings
from agent.utils.debug import current_session_id
from agent.utils.lazy_openai import openai
from agent.utils.logger import get_logger
from sessions.store import load_session, reload_merge_save, save_session

logger = get_logger("CHAT")

_CHARS_PER_TOKEN = 4  # same rough estimate used elsewhere in this codebase (agent/utils/debug.py)
# Keep chat history within this fraction of the model's real context window — the rest is
# reserved for the session snapshot, the system prompt, and the model's own reply.
_COMPACTION_BUDGET_FRACTION = 0.3
_DEFAULT_CONTEXT_LIMIT = 32000  # fallback when the provider's context_limit is unknown
_RECENT_MESSAGES_KEPT_VERBATIM = 4
_RECENT_LOG_ENTRIES_IN_SNAPSHOT = 5
# Real, confirmed operator complaint: a hardcoded cap (6, then 20) kept cutting off genuine
# interactive browser investigations (navigate, snapshot, fill, click, evaluate, go_back is already
# several real actions for ONE simple verification) partway through, landing on the "try again in
# smaller steps" fallback below with nothing actually verified. Unlimited by default (0) -- an
# operator running a heavier real-browser-testing workflow shouldn't need a code change just to keep
# going. Env-configurable (same shape as SUBAGENT_MAX_CONCURRENT_TASKS/WEB_FETCH_MAX_TEXT_CHARS) for
# anyone who wants a hard ceiling back.
_CHAT_MAX_TOOL_ITERATIONS = int(os.getenv("CHAT_MAX_TOOL_ITERATIONS", "0"))  # 0/unset = unlimited
# Handled directly inside _run_chat_tool_loop (queue a directive) rather than dispatched through
# _run_tool_with_retry -- they're not real registered ToolSpecs, just chat's own bookkeeping.
_CHAT_BOOKKEEPING_TOOL_NAMES = {"skip_finding", "add_guidance", "correct_finding"}
_DEFAULT_THREAD_TITLE = "New chat"
_TITLE_MAX_CHARS = 40


class ChatStopRequested(Exception):
    """Raised at _run_chat_tool_loop's own checkpoints once the operator clicks Stop on a live
    chat turn (main.py's /chat/stop route) -- mirrors agent/core.py's SessionStopRequested, but
    scoped to one chat turn instead of the whole autonomous scan: a chat conversation is a
    genuinely separate thing from the scan loop (see this module's own docstring), so stopping one
    must never touch the other. Caught in _run_one_chat_turn, which persists the outcome."""


# Same in-memory, keyed, non-file-writing pattern as agent/core.py's own _stop_events/
# get_stop_event/request_session_stop -- an HTTP route can't safely flip a signal by writing
# session.json directly while a live turn's own read-modify-write cycle (_append_segment_and_save
# et al.) is also writing that same file. Keyed by (session_id, thread_id), not just session_id --
# more than one thread can be pending at once (the operator can switch away from a still-running
# thread and start a turn on a different one, see append_pending_chat_message below), so a Stop
# click must only ever interrupt the exact turn it was clicked on.
_chat_stop_events: dict[tuple[str, str], asyncio.Event] = {}


def get_chat_stop_event(session_id: str, thread_id: str) -> asyncio.Event:
    return _chat_stop_events.setdefault((session_id, thread_id), asyncio.Event())


def request_chat_stop(session_id: str, thread_id: str) -> None:
    """main.py's /chat/stop route calls this once the operator clicks Stop on a live turn's own
    "thinking…" indicator. Only flips the in-memory signal above -- _run_chat_tool_loop's own
    checkpoints notice it and _run_one_chat_turn persists status/notice, same division of
    responsibility as request_session_stop/run_session in agent/core.py."""
    get_chat_stop_event(session_id, thread_id).set()


# The three tool names _CHAT_TOOLS_SCHEMA below already provides for every mode -- used to
# exclude agent/core.py's own category="re" ToolSpec registrations of the identical names
# (registered there for run_re_triage/run_re_reverify's benefit, not for chat) from ever also
# landing in an RE-mode chat turn's own tools_schema. See _chat_tool_specs's own comment.
_PLAYBOOK_TOOL_NAMES = frozenset({"query_playbook", "playbook_strategy", "record_technique"})

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
    # Reuses agent/core.py's own _apply_corrected_title/_apply_corrected_qualification/
    # _apply_corrected_false_positive_reason -- the EXACT functions the main agent's own exploit
    # confirmation already uses (record_exploit_decision's corrected_title/corrected_severity/
    # corrected_qualifies_for_bounty/corrected_false_positive_reason) -- so a chat-driven correction
    # and an agent-driven one are structurally identical: the original value is always kept
    # (original_title/original_severity/original_qualifies_for_bounty), never silently overwritten.
    {
        "type": "function",
        "function": {
            "name": "correct_finding",
            "description": (
                "Correct one specific finding's title/severity/bounty-qualification/false-positive "
                "status -- only once you've actually verified the current value is wrong (your own "
                "web_fetch/browser check, or the operator citing a specific fact), never on a guess "
                "or the operator's unconfirmed suspicion alone. The original value is always kept "
                "for audit, never silently lost. At least one corrected_* field is required."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_ref": {"type": "string", "description": "The finding's own [F#] id (e.g. 'F3') from the snapshot, or its exact title"},
                    "corrected_title": {"type": "string", "description": "Only if the title itself named the wrong host/target"},
                    "corrected_severity": {"type": "string", "enum": sorted(_VALID_SEVERITIES)},
                    "corrected_qualifies_for_bounty": {"type": "string", "enum": ["qualifying", "non_qualifying", "unclear"]},
                    "corrected_false_positive_reason": {"type": "string", "description": "Only fills a gap -- never overwrites an already-set reason"},
                    "reasoning": {"type": "string", "description": "What evidence actually changed -- required, shown to the operator and kept on the finding's own audit trail"},
                },
                "required": ["finding_ref", "reasoning"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "record_technique",
            "description": (
                "Save a reusable exploitation technique (or a confirmed DEAD-END) into the "
                "cross-session playbook -- the accumulating knowledge that surfaces as a lead the next "
                "time a similarly fingerprinted stack shows up, so future sessions don't re-derive it "
                "from scratch. Call this the moment you actually CONFIRM something reusable: a WAF "
                "bypass that worked, a payload that landed, a misconfiguration pattern, an auth "
                "weakness -- OR, just as valuable, that a plausible approach definitively did NOT work "
                "against this stack (worked=false), so it's not retried later. Key it to the tech "
                "stack it applies to (tech_keywords / waf_vendors) so it's findable again. Only record "
                "genuinely confirmed, generalizable knowledge -- not a guess or a one-off note."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "technique": {"type": "string", "description": "The reusable insight, in one or two sentences (what to do / what was observed)"},
                    "payload_or_command": {"type": "string", "description": "The concrete payload, request, or command, if there is one"},
                    "tech_keywords": {"type": "array", "items": {"type": "string"}, "description": "The tech stack it applies to, e.g. [\"nginx\",\"php\",\"wordpress\"] -- used to key + retrieve it. Include at least one."},
                    "waf_vendors": {"type": "array", "items": {"type": "string"}, "description": "WAF/CDN vendors it applies to, e.g. [\"cloudflare\"] -- optional"},
                    "vuln_class": {"type": "string", "description": "Vulnerability class, e.g. sqli / xss / ssrf / rce / auth_bypass -- optional"},
                    "worked": {"type": "boolean", "description": "true = it worked (a lead for next time); false = a confirmed dead-end (skip it next time). Defaults to true."},
                },
                "required": ["technique"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_playbook",
            "description": (
                "Search the cross-session playbook for reusable techniques relevant to what you're "
                "about to try -- a natural-language question ('how did we get past Cloudflare for "
                "SSRF?', 'stored XSS in a profile field') matches by MEANING, not just keywords, so "
                "it surfaces prior wins (and dead-ends to avoid) even when worded differently. Use it "
                "on demand when you're deciding how to attack something and want to reuse what's "
                "already been proven, instead of re-deriving from scratch."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What you're looking for, in plain language"},
                    "tech_keywords": {"type": "array", "items": {"type": "string"}, "description": "Optional: narrow to a stack, e.g. [\"nginx\",\"php\"]"},
                    "waf_vendors": {"type": "array", "items": {"type": "string"}, "description": "Optional: narrow to a WAF/CDN, e.g. [\"cloudflare\"]"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "playbook_strategy",
            "description": (
                "Compose a concrete, ordered ATTACK PLAN for a target out of the cross-session "
                "playbook, instead of just listing matches. Describe the target (stack, WAF, and what "
                "you want to achieve) and it retrieves the relevant proven techniques -- recipes, "
                "payload templates, dead-ends to avoid, stale ones to re-verify -- then synthesizes "
                "them into step-by-step guidance you can act on. Use it when you're planning HOW to "
                "attack something end-to-end; use query_playbook instead for a quick lookup."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The target and goal, in plain language, e.g. 'Cloudflare-fronted WordPress, want RCE'"},
                    "tech_keywords": {"type": "array", "items": {"type": "string"}, "description": "Optional: the target's stack, e.g. [\"nginx\",\"php\"]"},
                    "waf_vendors": {"type": "array", "items": {"type": "string"}, "description": "Optional: the target's WAF/CDN, e.g. [\"cloudflare\"]"},
                },
                "required": ["query"],
            },
        },
    },
]

# Interactive/Reverse-Engineering-mode-only bookkeeping tools -- offered whenever session["mode"]
# is "interactive" or "reverse_engineering" (agent/chat.py's _run_chat_tool_loop builds the schema
# per turn; "agent" and "standalone" mode chat never get these). record_finding here is the
# situational counterpart to the autonomous agent's own record_finding: an Interactive-mode session
# has no scan pipeline producing findings, so the ONLY way something the operator asked for becomes
# a durable, visible, exportable finding card is the chat agent recording it here once it actually
# succeeds. Deliberately not in agent-mode chat (that mode's findings come from the scan; a
# chat-recorded one there would just muddy them) and not in standalone Quick Chat either (no
# session/project of its own to attach a finding card to at all).
_INTERACTIVE_CHAT_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "record_finding",
            "description": (
                "Record a situational finding -- call this ONLY once you have genuinely, successfully "
                "delivered what the operator actually asked for in this session: obtained the value "
                "they needed, confirmed the specific thing, found the flag/endpoint/credential, proved "
                "the misconfiguration. A failed, partial, or inconclusive attempt is NOT a finding -- "
                "just keep working in the conversation, record nothing. This creates a finding card "
                "the operator can see and export, so make the title and detail concrete and factual."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short, concrete name of what was achieved/obtained (e.g. 'Origin IP behind Cloudflare recovered')"},
                    "detail": {"type": "string", "description": "What was found/achieved and how it was confirmed -- the real, factual result the operator needed"},
                    "severity": {"type": "string", "enum": sorted(_VALID_SEVERITIES), "description": "Optional impact rating; omit for a neutral/informational result"},
                    "artifact": {"type": "string", "description": "The concrete obtained value itself, if any -- a flag, an IP, an endpoint, a credential, a token"},
                },
                "required": ["title", "detail"],
            },
        },
    },
    # Real, confirmed operator complaint this fixes: a novice-mode RE session's own suggested next
    # steps (RE_EXPERIENCE_LEVEL_ADDENDA["novice"], agent/prompts.py) only ever landed as a plain
    # numbered list buried inside the model's own reply text -- something a newcomer, by definition
    # unsure of the right vocabulary, had to read carefully and then retype by hand. This tool lets
    # the model hand the SAME idea over structurally instead, so chat_messages.html can render it as
    # real clickable buttons (see this module's own docstring for the "suggested_actions" segment
    # shape) that just fill the input box on click -- faster and less intimidating than free text.
    {
        "type": "function",
        "function": {
            "name": "suggest_next_steps",
            "description": (
                "Offer the operator a short menu of concrete next things to try, as clickable "
                "options instead of writing a numbered list inside your own reply. Call this only "
                "when you're genuinely WRAPPING UP this turn's work and handing control back -- "
                "after your own text reply already reports what you found/did across the turn, not "
                "right after a single small action (e.g. right after recording one finding, before "
                "you've actually looked into anything else). If there's more of the same thread "
                "left to investigate, keep going instead of stopping early to offer a menu. Each "
                "option's text is inserted into the operator's own message box when they click it "
                "(not sent automatically), so phrase each one as if the operator were typing it "
                "themselves (\"Check whether the login form is vulnerable to SQLi\", not \"SQLi\")."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "steps": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "2-4 short, concrete next actions, each phrased as the operator's own next message",
                    },
                },
                "required": ["steps"],
            },
        },
    },
]


def _session_snapshot(session: dict) -> str:
    """Fresh facts about the session, rebuilt every turn — never accumulated into chat history
    (that would defeat the whole point of compacting the history separately, see module docstring).
    Findings/log fields are trimmed to what a human would actually need to discuss, not the full
    raw record.

    Every field here mirrors one of the badges/status lines session_fragment.html actually renders
    on a finding/hypothesis card (macros/ui.html's bounty_badge/false_positive_badge/exploited_badge/
    hypothesis_status_badge) — the operator can only sensibly ask chat about what they can SEE on
    screen, so a field the UI shows but the snapshot omits is a guaranteed "the chat doesn't know
    what I'm looking at" gap. Real, confirmed gap this closes: the old snapshot had only severity/
    verification/exploited — no qualifies_for_bounty (the bounty_badge), no advisory_note (the
    ONLY thing that actually drives exploited_badge's "Not exploitable" text — exploited=False alone
    means "not yet attempted", not "confirmed unexploitable", a distinction the operator can't ask
    about at all if the field backing it is invisible), no false_positive_reason, no skeptical
    verification's own second-opinion note, no remediation advice, and no hypotheses at all.

    Each finding/hypothesis/recon-target entry also carries a short "id" (F1/H2/R3, 1-indexed in
    the exact order session_fragment.html itself renders that list) — session_fragment.html shows
    the identical id next to each card's own "Discuss in chat" button, so the operator can point at
    one or more specific records (by clicking that button on several cards in a row, which inserts
    a "[F3] " tag at wherever their cursor was, or by just typing them itself) instead of the chat
    having to guess which of several similarly-named findings a vague description means.
    CHAT_PROMPT/INTERACTIVE_CHAT_PROMPT/RE_CHAT_PROMPT each tell the model how to read the tag(s),
    including a message that carries more than one, anywhere in the text.
    """
    findings = session.get("findings", [])
    hypotheses = session.get("hypotheses", [])
    recon_targets = session.get("recon_result", {}).get("targets", [])
    recent_logs = session.get("logs", [])[-_RECENT_LOG_ENTRIES_IN_SNAPSHOT:]
    snapshot = {
        "target": session.get("target"),
        "status": session.get("status"),
        # RE mode's own accumulating target facts (agent/core.py's record_target_profile) --
        # language, compiler, obfuscator, platform, version, whatever's actually been established.
        # Included unconditionally (empty list costs nothing) rather than gated on session mode, so
        # this needs no special-casing here if a future mode ever starts using the same tool.
        "target_profile": session.get("target_profile", []),
        "recon_targets": [
            {"id": f"R{i}", "host": t.get("host"), "port": t.get("port"), "service": t.get("service"), "version": t.get("version")}
            for i, t in enumerate(recon_targets, start=1)
        ],
        "findings": [
            {
                "id": f"F{i}",
                "title": f.get("title"),
                "severity": f.get("severity"),
                "description": f.get("description"),
                "technology": f.get("technology"),
                "reproduction_steps": f.get("reproduction_steps"),
                "exploitation_scenario": f.get("exploitation_scenario"),
                "verification": f.get("verification"),
                "exploited": f.get("exploited"),
                "evidence": f.get("evidence"),
                "evidence_ref": f.get("evidence_ref"),
                "poc_command": f.get("poc_command"),
                "advisory_note": f.get("advisory_note"),
                "qualifies_for_bounty": f.get("qualifies_for_bounty"),
                "false_positive_reason": f.get("false_positive_reason"),
                "skeptical_verification": f.get("skeptical_verification"),
                "skeptical_verification_note": f.get("skeptical_verification_note"),
                "remediation_advice": f.get("remediation_advice"),
                "extracted_artifact": f.get("extracted_artifact"),
                "artifact_usage_hint": f.get("artifact_usage_hint"),
                "found_at": f.get("found_at"),
                "carried_over_from": f.get("carried_over_from"),
                "original_title": f.get("original_title"),
                "original_severity": f.get("original_severity"),
                "original_qualifies_for_bounty": f.get("original_qualifies_for_bounty"),
                "tool_timeline": f.get("tool_timeline") or [],
            }
            for i, f in enumerate(findings, start=1)
        ],
        "hypotheses": [
            {
                "id": f"H{i}",
                "text": h.get("text"),
                "status": h.get("status"),
                "evidence": h.get("evidence"),
                "resolution_note": h.get("resolution_note"),
                "source": h.get("source"),
                "source_phase": h.get("source_phase"),
                "created_at": h.get("created_at"),
                "resolved_at": h.get("resolved_at"),
                "tool_timeline": h.get("tool_timeline") or [],
            }
            for i, h in enumerate(hypotheses, start=1)
        ],
        "recent_activity": [
            {"phase": entry.get("phase"), "command": entry.get("command"), "status": entry.get("status")}
            for entry in recent_logs
        ],
    }
    return json.dumps(snapshot)


def _estimate_tokens(text: str) -> int:
    return len(text) // _CHARS_PER_TOKEN


def _chat_tool_arg_summary(name: str, arguments: dict) -> str:
    """A short, human-readable one-line summary of a tool call's arguments -- for the collapsed
    tool-call card's header (chat_messages.html) and for replaying a past turn's tool use into LLM
    history (_segments_to_text) -- never the raw JSON. A small per-tool-name table for the common
    cases, falling back to the first argument's own value for anything not specially handled (same
    "readable synopsis, not a dump" idea Piligrim's own toolSummary() uses).
    """
    if name == "web_fetch":
        return str(arguments.get("target", ""))
    if name in _BROWSER_TOOL_NAMES:
        return str(arguments.get("target") or arguments.get("expression") or arguments.get("ref") or "")
    if name == "skip_finding":
        return str(arguments.get("finding_title", ""))
    if name == "add_guidance":
        return str(arguments.get("text", ""))
    if name == "suggest_next_steps":
        count = len(arguments.get("steps") or [])
        return f"{count} option{'s' if count != 1 else ''}"
    if arguments:
        return str(next(iter(arguments.values())))
    return ""


def _segments_to_text(segments: list[dict]) -> str:
    """Flattens a message's segments into plain text for replay as LLM conversation history -- a
    text segment contributes its own content, a tool_call segment becomes a short bracketed note
    ("[used web_fetch(https://example.com) -> ok]") so the model still sees THAT it used a tool and
    roughly what happened, without replaying the exact provider-specific tool_call/tool wire format
    turn after turn (which would grow unboundedly and doesn't survive compaction or a
    provider/model switch cleanly). Only used for PAST turns/history replay and compaction input —
    the CURRENT, still-live turn builds real tool_calls/tool-role messages instead (see
    _run_chat_tool_loop), since that one still needs the real multi-turn tool-calling contract.
    """
    parts = []
    for seg in segments:
        if seg["type"] == "text":
            # A turn-level failure notice (run_chat_turn_background's except branch -- a provider
            # rate-limit/connection error, never a real answer) is deliberately excluded from what
            # gets replayed back to the model as its own conversation history. Real, confirmed
            # incident this fixes: once a rate-limit notice landed in history as an ordinary
            # assistant text segment, EVERY later turn in that same thread saw it as if it were the
            # model's own considered claim ("I can't delegate right now due to the rate-limit
            # error") and kept refusing to even attempt delegate_to_subagent turn after turn, long
            # after the transient provider error had nothing to do with the current attempt (a
            # different provider, sometimes not even the same tool being available). The operator
            # still sees it in the UI (chat_messages.html renders it regardless) -- only the
            # model's own next-turn context is spared it.
            if seg["content"] and not seg.get("error"):
                parts.append(seg["content"])
        elif seg["type"] == "tool_call":
            status = "error" if seg.get("error") else "ok" if seg.get("done") else "pending"
            summary = _chat_tool_arg_summary(seg["name"], seg.get("arguments") or {})
            parts.append(f"[used {seg['name']}({summary}) -> {status}]")
        elif seg["type"] == "suggested_actions":
            parts.append(f"[offered next-step options: {', '.join(seg.get('actions') or [])}]")
    return "\n".join(parts)


async def _run_compaction(llm: LLMProvider, thread: dict, session_id: str, instructions: str = "") -> bool:
    """The actual distillation call, shared by automatic (_compact_if_needed, budget-triggered) and
    manual (compact_chat_thread, always runs regardless of size) compaction. Returns True if it did
    something (there was enough history to retire), False if it was a no-op (too short a
    conversation to compact yet) -- the manual path uses this to give honest feedback instead of
    silently doing nothing. Only the RETIRED messages are flattened via _segments_to_text (cheaper,
    and tool-call minutiae from turns nobody will re-read aren't worth the tokens); the kept
    verbatim tail stays in its real segment shape so its tool cards keep rendering normally.
    """
    messages = thread["messages"]
    if len(messages) <= _RECENT_MESSAGES_KEPT_VERBATIM:
        return False
    # role="reward" messages (deliver_storage_reward_to_chat) carry a "reward" dict, no "segments" --
    # they're UI-only gamified markers, skipped here (nothing to summarize) rather than crashing the
    # comprehension. A retired reward simply drops out of history on compaction, which is fine.
    to_retire = [
        {"role": m["role"], "content": _segments_to_text(m["segments"])}
        for m in messages[:-_RECENT_MESSAGES_KEPT_VERBATIM] if m.get("segments") is not None
    ]

    logger.debug(
        "chat: session=%s compacting %d message(s)%s", session_id, len(to_retire), " (manual)" if instructions else "",
    )
    user_content = f"Existing summary:\n{thread['summary'] or '(none yet)'}\n\nMessages to fold in:\n{json.dumps(to_retire)}"
    if instructions:
        user_content += f"\n\nOperator's own instructions for this compaction: {instructions}"
    compaction_messages = [
        {"role": "system", "content": CHAT_COMPACTION_PROMPT},
        {"role": "user", "content": user_content},
    ]
    response = await asyncio.to_thread(llm.complete, compaction_messages, None)
    thread["summary"] = response.content or thread["summary"]
    # A persisted "system" note, not a one-off flash -- the operator asked specifically to be able
    # to SEE that a compaction actually happened (not just infer it from a shorter history), and a
    # flash only shows once, right after the request that triggered it; a real note in the log
    # stays visible on scrollback and survives the automatic (budget-triggered, otherwise silent)
    # path too, where there's no request/response round-trip to hang a flash off at all.
    now = datetime.now(timezone.utc).isoformat()
    note = f"History compacted — {len(to_retire)} earlier message{'s' if len(to_retire) != 1 else ''} summarized."
    thread["messages"] = messages[-_RECENT_MESSAGES_KEPT_VERBATIM:] + [
        {"role": "system", "at": now, "segments": [{"type": "text", "content": note}]},
    ]
    logger.debug("chat: session=%s compaction done, new summary is %d chars", session_id, len(thread["summary"]))
    return True


async def _compact_if_needed(llm: LLMProvider, thread: dict, session_id: str) -> None:
    budget = int((llm.context_limit or _DEFAULT_CONTEXT_LIMIT) * _COMPACTION_BUDGET_FRACTION)
    flattened = [_segments_to_text(m["segments"]) for m in thread["messages"] if m.get("segments") is not None]
    history_size = _estimate_tokens(thread["summary"] + json.dumps(flattened))
    if history_size <= budget:
        return
    await _run_compaction(llm, thread, session_id)


def _new_thread(title: str = _DEFAULT_THREAD_TITLE) -> dict:
    """provider/model default to whatever the operator last explicitly picked in the chat panel's
    own picker (chat_settings_store's last_provider/last_model, persisted on disk -- survives both
    /new and a server restart), not a hardcoded None every time. A caller migrating real old history
    (_ensure_chat_threads) overwrites these right after with that thread's own saved values anyway."""
    now = datetime.now(timezone.utc).isoformat()
    last = chat_settings_store.load_chat_settings()
    return {
        "id": f"thread_{uuid.uuid4().hex[:12]}",
        "title": title,
        "summary": "",
        "messages": [],
        "provider": last["last_provider"],
        "model": last["last_model"],
        "pending": False,
        "queued_messages": [],
        "created_at": now,
        "updated_at": now,
        "color": None,
    }


def _ensure_chat_threads(session: dict) -> tuple[list[dict], str | None]:
    """Returns (threads, active_thread_id). Migrates an old session["chat"] (the pre-thread flat
    single-conversation schema) into a one-thread chat_threads list the first time this runs on a
    given session, and backfills any per-thread field an older chat_threads-schema session might
    still be missing -- same "upgrade in place on read" convention this module already used for
    chat["provider"]/["model"]/["pending"] before threads existed.
    """
    threads = session.get("chat_threads")
    if threads is None:
        old_chat = session.pop("chat", None)
        # sessions/store.py's create_session pre-seeds every new session with an EMPTY
        # {"summary": "", "messages": []} -- a real, confirmed bug this specific check fixes: that
        # dict is truthy (it has keys) even though there's no actual history in it, so a bare
        # `if old_chat:` took the "real migration" branch for every brand-new session, permanently
        # title-locking its very first thread to "Chat" and defeating auto-titling below. Checking
        # for actual messages is what distinguishes "real old history to migrate" from "just the
        # empty placeholder every session already carries".
        if old_chat and old_chat.get("messages"):
            thread = _new_thread(title="Chat")
            thread["summary"] = old_chat.get("summary") or ""
            thread["provider"] = old_chat.get("provider")
            thread["model"] = old_chat.get("model")
            thread["pending"] = bool(old_chat.get("pending"))
            thread["messages"] = [
                {"role": m.get("role", "user"), "at": m.get("at"), "segments": [{"type": "text", "content": m.get("content", "")}]}
                for m in old_chat.get("messages", [])
            ]
            if thread["messages"]:
                thread["updated_at"] = thread["messages"][-1].get("at") or thread["updated_at"]
        else:
            # A genuinely brand-new session (never had any chat at all) gets the default title,
            # NOT "Chat" -- append_pending_chat_message's own auto-titling only fires when the
            # title is still the default, so a truly fresh thread can pick up a real title from
            # its first message. "Chat" is reserved for the migrated-old-history case above, where
            # real content already exists and auto-retitling would be wrong (see that function's
            # own docstring).
            thread = _new_thread()
        threads = [thread]
        session["chat_threads"] = threads
        session["active_chat_thread_id"] = thread["id"]

    for thread in threads:
        thread.setdefault("title", _DEFAULT_THREAD_TITLE)
        thread.setdefault("summary", "")
        thread.setdefault("messages", [])
        thread.setdefault("provider", None)
        thread.setdefault("model", None)
        thread.setdefault("pending", False)
        thread.setdefault("queued_messages", [])
        thread.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        thread.setdefault("updated_at", thread["created_at"])
        thread.setdefault("color", None)

    active_id = session.get("active_chat_thread_id")
    if not active_id or not any(t["id"] == active_id for t in threads):
        active_id = threads[-1]["id"] if threads else None
        session["active_chat_thread_id"] = active_id
    return threads, active_id


def _find_thread(session: dict, thread_id: str) -> dict | None:
    threads, _ = _ensure_chat_threads(session)
    return next((t for t in threads if t["id"] == thread_id), None)


def _get_active_thread(session: dict) -> dict:
    threads, active_id = _ensure_chat_threads(session)
    if not threads:
        thread = _new_thread(title="Chat")
        threads.append(thread)
        session["chat_threads"] = threads
        session["active_chat_thread_id"] = thread["id"]
        return thread
    return next(t for t in threads if t["id"] == active_id)


_FINDING_REF_RE = re.compile(r"^F(\d+)$", re.IGNORECASE)


def _resolve_finding_ref(session: dict, ref: str) -> dict | None:
    """correct_finding's own lookup -- accepts either the snapshot's own [F#] id (1-indexed
    position in session["findings"], the EXACT same numbering _session_snapshot stamps onto each
    entry and session_fragment.html's chat_ref macro shows on the card) or an exact title, mirroring
    skip_finding's own "exact title" convention for a model that didn't have (or didn't use) the id.
    """
    findings = session.get("findings", [])
    match = _FINDING_REF_RE.match(ref.strip())
    if match:
        index = int(match.group(1)) - 1
        return findings[index] if 0 <= index < len(findings) else None
    return next((f for f in findings if f.get("title") == ref), None)


def _apply_chat_finding_correction(session_id: str, arguments: dict) -> str:
    """correct_finding's real work -- fresh reload immediately before mutating/saving, same
    discipline _append_segment_and_save already applies, since a scan phase can be writing to this
    same session concurrently. Reuses agent/core.py's own _apply_corrected_* functions unchanged
    (see _CHAT_TOOLS_SCHEMA's own comment for why that matters) -- this function's only job is
    resolving the finding, calling them, and describing what actually changed back to the operator.
    """
    session = load_session(session_id)
    if session is None:
        return "That session no longer exists."

    finding_ref = (arguments.get("finding_ref") or "").strip()
    finding = _resolve_finding_ref(session, finding_ref)
    if finding is None:
        return f"Couldn't find a finding matching {finding_ref!r} in the current snapshot — nothing changed."

    reasoning = (arguments.get("reasoning") or "").strip()
    if not reasoning:
        return "A correction needs your own reasoning/evidence for what changed — nothing applied."

    changes = []
    before_title = finding.get("title")
    _apply_corrected_title(finding, arguments.get("corrected_title"))
    if finding.get("title") != before_title:
        changes.append(f'title → "{finding["title"]}"')

    before_severity, before_qualifies = finding.get("severity"), finding.get("qualifies_for_bounty")
    _apply_corrected_qualification(finding, arguments.get("corrected_severity"), arguments.get("corrected_qualifies_for_bounty"))
    if finding.get("severity") != before_severity:
        changes.append(f'severity → {finding["severity"]}')
    if finding.get("qualifies_for_bounty") != before_qualifies:
        changes.append(f'qualifies_for_bounty → {finding["qualifies_for_bounty"]}')

    before_fp_reason = finding.get("false_positive_reason")
    _apply_corrected_false_positive_reason(finding, arguments.get("corrected_false_positive_reason"))
    if finding.get("false_positive_reason") != before_fp_reason:
        changes.append("false_positive_reason set")

    if not changes:
        return "Nothing actually changed — the value(s) given already match what's on record, or weren't recognized."

    # Kept for anyone auditing session.json directly -- not yet rendered anywhere in the UI, same
    # "the change itself is visible (original_title/false_positive_reason already render), the WHY
    # behind it is one layer deeper" tradeoff record_exploit_decision's own reasoning field already
    # accepts without a dedicated display surface of its own.
    finding.setdefault("chat_correction_notes", []).append({
        "note": reasoning, "changes": changes, "at": datetime.now(timezone.utc).isoformat(),
    })
    save_session(session_id, session)
    logger.debug("chat: session=%s corrected finding %r: %s", session_id, finding.get("title"), ", ".join(changes))
    return f'Updated "{finding.get("title")}": ' + ", ".join(changes) + "."


def _apply_chat_record_technique(session_id: str, arguments: dict, llm=None) -> tuple[str, dict | None]:
    """Writes a chat-discovered technique (or dead-end) into the cross-session playbook -- the write
    path the autonomous agent has always had (agent/core.py's _maybe_capture_playbook_entry) but the
    chat never did, so an interactive-mode session's own confirmed knowledge now accumulates too.
    Returns (confirmation_for_the_model, reward_or_None); the reward is delivered AFTER the turn ends
    (run_chat_turn_background), never mid-turn, so it can't disturb the in-progress assistant
    message's own segment writes. Keyed the same way as the autonomous capture (tech_keywords +
    waf_vendors -> _playbook_fingerprint_key), so a chat-recorded entry and an agent-recorded one are
    retrievable through the exact same find_similar_techniques lookup.
    """
    technique = (arguments.get("technique") or "").strip()
    if not technique:
        return "I couldn't record that — the technique text was empty, so nothing was saved.", None

    raw_keywords = arguments.get("tech_keywords") or []
    tech_keywords = frozenset(_technology_keywords(" ".join(str(t) for t in raw_keywords)))
    if not tech_keywords:
        # No explicit stack given -- fall back to whatever tech tokens the technique text itself
        # carries, so the entry is still findable rather than stored under an empty, never-matched key.
        tech_keywords = frozenset(_technology_keywords(technique))
    waf_vendors = frozenset(str(w).strip().lower() for w in (arguments.get("waf_vendors") or []) if str(w).strip())

    worked = arguments.get("worked", True)
    outcome = "worked" if worked else "failed"
    key = _playbook_fingerprint_key(tech_keywords, waf_vendors)
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": uuid.uuid4().hex[:12],
        "technique": technique,
        "vuln_class": (arguments.get("vuln_class") or "").strip() or None,
        "payload_or_command": (arguments.get("payload_or_command") or "").strip() or None,
        "cves": playbook_store.extract_cves(technique, str(arguments.get("payload_or_command") or "")),
        "evidence_ref": "",
        "tech_keywords": sorted(tech_keywords),
        "waf_vendors": sorted(waf_vendors),
        "outcome": outcome,
        "times_confirmed": 1,
        # Attribution counters -- see agent/core.py's _maybe_capture_playbook_entry for what drives
        # them; 0 here so a chat-recorded entry ranks the same way an agent-recorded one does.
        "injected_count": 0,
        "led_to_finding_count": 0,
        # Kill-chain links are only auto-built on the autonomous path (sequential captures against one
        # target); a chat-recorded technique stands on its own -- empty, same schema shape.
        "chained_from_ids": [],
        "last_seen": now,
        # Staleness anchor -- only a technique that WORKED has a "last confirmed working" time.
        "last_confirmed_at": now if worked else None,
        "source_session_ids": [session_id],
        # An operator/agent asserting this from a real chat session -- field-vouched, same
        # standing as an autonomously-captured finding, not an LLM's own unreviewed guess at
        # what some uploaded document says (agent/tools/library_store.py's separate path).
        "source_type": "live",
        "confidence": "confirmed",
    }
    recorded_id = playbook_store.record_technique(key, entry)
    if llm is not None and recorded_id:
        _embed_playbook_entries(llm, [{**entry, "id": recorded_id}])
    total = playbook_store.count_techniques()
    logger.debug("chat: session=%s recorded playbook technique outcome=%s key=%r total=%d", session_id, outcome, key, total)

    verb = "technique" if worked else "dead-end"
    confirmation = (
        f'Saved a {"working technique" if worked else "dead-end"} to the playbook — it\'ll surface as '
        f'a lead on similarly fingerprinted stacks in future sessions. {total} technique(s) stored now.'
    )
    reward = {
        "kind": "technique", "label": f"New {verb} captured", "delta": 1,
        "total": total, "total_label": "in playbook", "detail": technique,
    }
    return confirmation, reward


def _apply_chat_record_finding(session_id: str, arguments: dict) -> tuple[str, dict | None]:
    """Records a situational Interactive-mode finding into session["findings"] once the chat agent
    has actually delivered what the operator asked for. Reload-merge-save (sessions.store.
    reload_merge_save), not a blind load/append/save -- this exact call site is the one
    reload_merge_save's own docstring names as where that pattern originated: a background task
    (e.g. a subagent) saving its own reload_merge_save'd changes in between this call's load and
    save used to get silently clobbered by this function's stale in-memory snapshot. Real,
    confirmed incident: a chat-recorded finding was visibly confirmed to the operator ("N recorded
    this session") but never made it into the saved session.json, wiped out by a concurrent
    background task's save. Returns (confirmation, reward); the reward is flushed after the turn
    like record_technique's. Stored with a compatible-enough shape (title/description/severity/
    found_at) that it renders as a real finding card (templates/partials/interactive_findings.html)
    and would even survive an export, plus source="interactive" so it's never mistaken for a scan
    finding."""
    title = (arguments.get("title") or "").strip()
    detail = (arguments.get("detail") or "").strip()
    if not title or not detail:
        return "I couldn't record that finding — both a title and a concrete detail are required.", None

    severity = (arguments.get("severity") or "").strip().lower() or None
    if severity is not None and severity not in _VALID_SEVERITIES:
        severity = None
    finding = {
        "id": uuid.uuid4().hex[:12],
        "title": title,
        "description": detail,
        "severity": severity,
        "extracted_artifact": (arguments.get("artifact") or "").strip() or None,
        "found_at": datetime.now(timezone.utc).isoformat(),
        "source": "interactive",
    }
    session = reload_merge_save(session_id, lambda s: s.setdefault("findings", []).append(finding))
    if session is None:
        return "I couldn't record that finding — the session is no longer available.", None
    total = len(session["findings"])
    logger.debug("chat: session=%s recorded interactive finding=%r (total=%d)", session_id, title, total)

    confirmation = f'Recorded "{title}" as a finding — it\'s on the Findings panel now (collapse the chat to see it). {total} recorded this session.'
    reward = {
        "kind": "finding", "label": "New finding recorded", "delta": 1,
        "total": total, "total_label": "this session", "detail": title,
    }
    return confirmation, reward


_MAX_SUGGESTED_STEPS = 4


def _sanitize_suggested_steps(arguments: dict) -> list[str]:
    """suggest_next_steps' own input cleanup -- trims blanks, drops empties, and caps the count so a
    model that ignores its own tool description (2-4 short options) can't flood the chat with a wall
    of buttons instead of the numbered-list wall of text this tool exists to replace."""
    raw = arguments.get("steps") or []
    steps = [str(s).strip() for s in raw if str(s).strip()]
    return steps[:_MAX_SUGGESTED_STEPS]


def _retrieve_playbook_matches(arguments: dict, llm, limit: int) -> tuple[list[dict], str, str]:
    """Shared RAG retrieval for query_playbook and playbook_strategy: embeds the query via the active
    provider for semantic search, falling back to keyword matching on tokens pulled from the query
    itself when no embeddings are available. Returns (matches, mode, query). Read-only."""
    query = (arguments.get("query") or "").strip()
    if not query:
        return [], "", ""
    tech = frozenset(_technology_keywords(" ".join(str(t) for t in (arguments.get("tech_keywords") or []))))
    waf = frozenset(str(w).strip().lower() for w in (arguments.get("waf_vendors") or []) if str(w).strip())
    vec = _embed_playbook_query(llm, query)
    if vec is None and not tech:
        # No embeddings available -- derive tech tokens from the query text so keyword search still runs.
        tech = frozenset(_technology_keywords(query))
    matches = playbook_store.find_similar_techniques(set(tech), set(waf), limit, query_embedding=vec)
    return matches, ("semantic" if vec is not None else "keyword"), query


def _apply_chat_query_playbook(arguments: dict, llm=None) -> str:
    """The query_playbook tool: a natural-language, on-demand search over the cross-session playbook
    (the RAG "ask the accumulated edge" path). Always returns SOMETHING useful via the semantic ->
    keyword fallback. Read-only -- never writes."""
    matches, mode, query = _retrieve_playbook_matches(arguments, llm, 6)
    if not query:
        return "Give me something to look for and I'll search the playbook."
    if not matches:
        return f"No matching techniques in the playbook for that ({mode} search)."
    lines = []
    for m in matches:
        # Library-extracted, not yet reviewed (agent/tools/library_store.py) -- its own label,
        # never "works"/"DEAD-END" which would read as field-tested when it's only an LLM's own
        # reading of an uploaded document.
        unreviewed = m.get("confidence") == "unreviewed"
        label = "UNVERIFIED" if unreviewed else ("DEAD-END" if m.get("outcome") == "failed" else "works")
        line = f"- [{label}] {m.get('technique')}"
        if m.get("payload_or_command"):
            line += f" (payload/command: {m['payload_or_command']})"
        if m.get("payload_template"):
            line += f" [template: {m['payload_template']}]"
        if unreviewed:
            source = m.get("source_title") or "an uploaded source"
            if m.get("source_ref"):
                source += f", {m['source_ref']}"
            line += f" (from {source} — try it, but not yet confirmed working)"
        else:
            line += f" — seen {m.get('times_confirmed', 1)}x"
        lines.append(line)
    return f"Playbook matches ({mode} search):\n" + "\n".join(lines)


def _strategy_technique_block(matches: list[dict]) -> str:
    """Renders retrieved techniques (with outcome/stale flags, payload, template) for the strategy
    synthesizer's context -- everything it's allowed to build a plan from, nothing else."""
    lines = []
    for m in matches:
        unreviewed = m.get("confidence") == "unreviewed"
        if unreviewed:
            flags = ["UNVERIFIED"]
        else:
            flags = ["DEAD-END"] if m.get("outcome") == "failed" else ["works"]
            if m.get("outcome") != "failed" and playbook_store.is_stale(m):
                flags.append("STALE")
        line = f"- [{', '.join(flags)}] {m.get('technique')}"
        if unreviewed:
            source = m.get("source_title") or "an uploaded source"
            if m.get("source_ref"):
                source += f", {m['source_ref']}"
            line += f" (from {source} — extracted by LLM, never field-tested)"
        if m.get("payload_or_command"):
            line += f"\n    payload/command: {m['payload_or_command']}"
        if m.get("payload_template"):
            line += f"\n    reusable template: {m['payload_template']}"
        lines.append(line)
    return "\n".join(lines)


async def _apply_chat_playbook_strategy(arguments: dict, llm) -> str:
    """The playbook_strategy tool: retrieves techniques for a described target, then composes them
    into ONE concrete, ordered attack plan via a focused LLM pass (LLM strategy synthesis). Falls back
    gracefully -- no matches means an honest "nothing stored", a failed synthesis call returns the raw
    retrieved list rather than nothing. Read-only."""
    matches, mode, query = _retrieve_playbook_matches(arguments, llm, 8)
    if not query:
        return "Describe the target (stack, WAF, goal) and I'll compose a strategy from the playbook."
    if not matches:
        logger.debug("chat: playbook_strategy found no matches (%s search) for query=%r", mode, query[:80])
        return f"No stored techniques match that target ({mode} search) — nothing to build a strategy from yet."
    logger.debug("chat: playbook_strategy composing from %d match(es) (%s search)", len(matches), mode)
    task = f"Target:\n{query}\n\nRetrieved techniques ({mode} search):\n{_strategy_technique_block(matches)}"
    messages = [
        {"role": "system", "content": PLAYBOOK_STRATEGY_PROMPT},
        {"role": "user", "content": task},
    ]
    try:
        response = await asyncio.to_thread(llm.complete, messages, None)
        strategy = (response.content or "").strip()
    except Exception as exc:
        logger.debug("chat: playbook_strategy synthesis failed (%s) -- returning raw matches", exc)
        strategy = ""
    if not strategy:
        return f"Retrieved techniques ({mode} search), couldn't compose a plan:\n{_strategy_technique_block(matches)}"
    return f"Attack strategy composed from {len(matches)} playbook technique(s):\n\n{strategy}"


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
        elif call.name == "correct_finding":
            confirmations.append(_apply_chat_finding_correction(session_id, call.arguments))
        else:
            logger.debug("chat: session=%s ignoring unknown chat tool call %r", session_id, call.name)
    return " ".join(confirmations) if confirmations else "Okay."


def _chat_tool_specs(mode: str = "agent", allowed_subagent_ids: list[str] | None = None) -> list[ToolSpec]:
    """Chat's own curated, safe read/research tool set -- deliberately NOT the full installed-tool
    catalog a subagent profile can pick from (agent/tools/subagent_store.py); only what
    data/chat_settings.json's capability toggles actually enable (agent/tools/
    chat_settings_store.py, managed via the /chat-settings UI). A tool name that resolves to
    nothing (get_tool returns None -- not installed on this machine) is silently skipped, same
    tolerance _subagent_context's own tool-filtering already has.

    subagents_enabled additionally requires at least one enabled Subagent profile to mean
    anything -- same gate agent/core.py's own _subagent_delegation_extras applies to the main
    agent's phases, so chat never offers delegate_to_subagent when there's genuinely nothing
    configured to delegate to.

    mode in ("interactive", "reverse_engineering") (main.py's start_interactive/start_re) makes
    Subagent delegation always available regardless of the chat_settings toggle -- it's the
    backbone of those modes (the operator reaches the heavy arsenal -- nmap/sqlmap/ffuf/... -- only
    by delegating to a Subagent that carries those tools), so silently leaving it off would cripple
    the whole console. Still requires at least one enabled Subagent profile to actually exist; the
    per-profile tool choices stay entirely the operator's own (Subagents tab), so this is one
    sensible default, not a hardcoded toolset. mode == "standalone" (the top-level, project-less
    Quick Chat) deliberately behaves like "agent" here instead -- it has no scan of its own to be
    the backbone of, so it stays opt-in via the toggle, same safe-by-default posture as an ordinary
    project's own chat.

    mode == "reverse_engineering" additionally appends every category="re" tool (radare2/gdb/
    slither/heimdall_decompile/disassemble_evm_bytecode/semgrep/memscan_*/...) -- these are never
    offered to an "agent"/"interactive" session (registry.py's own Category comment: "re" is never
    queried by an ordinary web-pentest phase), so the follow-up chat is the only place they need
    appending explicitly, same pattern as the toolkit tools just below. memscan_* specifically is
    deliberately available ONLY here, never in run_re_triage/run_re_reverify's own tool lists
    (agent/core.py's _MEMSCAN_TOOL_NAMES exclusion) -- its live-process attach workflow needs a
    human in the loop between scans, which only this turn-by-turn chat can provide.

    The native toolkit's six tools (send_raw_request/list_captured_traffic/decode_value/
    diff_requests/intruder_run/sequencer_analyze) are gated by a SEPARATE settings store,
    data/toolkit_agent_settings.json (agent/tools/toolkit_settings_store.py) -- not
    chat_settings.json, since those same six toggles also gate the main agent's own phases and
    subagent delegation (agent/core.py's _toolkit_tool_extras/_delegate_to_subagent_impl), not just
    chat.
    """
    settings = chat_settings_store.load_chat_settings()
    names: list[str] = []
    if settings["web_fetch_enabled"]:
        names.append("web_fetch")
    if settings["browser_enabled"]:
        names.extend(sorted(_BROWSER_TOOL_NAMES))
    if settings["dork_engine_enabled"]:
        names.append("dork_search")
    if (mode in ("interactive", "reverse_engineering") or settings["subagents_enabled"]) and get_enabled_profiles(allowed_subagent_ids):
        names.extend(["delegate_to_subagent", "check_subagent_task"])
    toolkit_settings = load_toolkit_agent_settings()
    names.extend(name for name, toggle_key in _TOOLKIT_TOOL_TOGGLE_KEYS.items() if toolkit_settings[toggle_key])
    specs = [spec for spec in (get_tool(name) for name in names) if spec is not None]
    if mode == "reverse_engineering":
        # query_playbook/playbook_strategy/record_technique are registered under category="re"
        # too (agent/core.py, for run_re_triage/run_re_reverify's own benefit, which have no other
        # way to reach chat.py's own versions of these) -- excluded here specifically, since chat
        # already provides all three under those exact same names via _CHAT_TOOLS_SCHEMA below
        # (always included, every mode). Including both would put two same-named tool definitions
        # in the schema sent to the model for one turn.
        specs.extend(spec for spec in get_tools_by_category("re") if spec.name not in _PLAYBOOK_TOOL_NAMES)
        # background_job_check is category="exploit" (the main Agent pipeline's own hydra/
        # web_login_bruteforce poll tool), invisible to the category="re" sweep just above --
        # appended explicitly so afl_fuzz_start (genuinely category="re", offered by that sweep)
        # can actually be checked on from chat too, not just from run_re_triage/run_re_reverify.
        job_check_spec = get_tool("background_job_check")
        if job_check_spec is not None:
            specs.append(job_check_spec)
    return specs


def _chat_subagent_addendum(mode: str = "agent", allowed_subagent_ids: list[str] | None = None) -> str:
    """Tells the chat LLM the actual enabled Subagent profile name(s) it must pass as
    subagent_name -- without this, delegate_to_subagent's own tool description only says "an
    enabled Subagent profile" with no concrete name anywhere in the conversation, so the model
    has nothing to go on but a guess (e.g. picking a tool name like "subfinder" out of a
    profile's own allowed_tools list instead of the profile's own name), which always fails
    get_profile_by_name's lookup. Mirrors the same real-names-not-just-a-description discipline
    agent/core.py's own _subagent_delegation_extras already applies for the main agent, and uses
    the exact same enabled-check _chat_tool_specs gates delegate_to_subagent's own availability
    on, so this never names a profile the model isn't actually offered the tool for.
    """
    settings = chat_settings_store.load_chat_settings()
    # Interactive/Reverse-Engineering modes offer delegation regardless of the chat_settings
    # toggle (see _chat_tool_specs) -- name the real profiles in that case too, or the model gets
    # the tool with no concrete subagent_name to pass. "standalone" (Quick Chat) follows the same
    # opt-in-only rule "agent" mode does (see _chat_tool_specs's own mode check), so it's grouped
    # with "agent" here too -- naming profiles when the toggle is off would describe a tool the
    # model was never actually given.
    if mode not in ("interactive", "reverse_engineering") and not settings["subagents_enabled"]:
        return ""
    profiles = get_enabled_profiles(allowed_subagent_ids)
    if not profiles:
        return ""
    names = ", ".join(f"'{p['name']}'" for p in profiles)
    return f"\n\nEnabled Subagent profile(s) you can pass as subagent_name to delegate_to_subagent right now: {names}."


# Mirrors the real statuses subagent_tasks.py's own _reap/reconcile_orphaned_subagent_tasks ever
# set (see that module) -- an unrecognized one (should never happen, kept only as a real backstop)
# falls back to a plain "(status: X)" instead of silently mislabeling it as one of these.
_SUBAGENT_OUTCOME_VERBS = {
    "done": "finished",
    "error": "failed",
    "timeout": "timed out",
    "stopped": "was stopped",
    "killed": "was killed (the operator stopped the session)",
    "orphaned": "was orphaned (the server restarted mid-task)",
}


def _format_subagent_result_for_chat(profile_name: str, outcome: str, result: dict | None) -> str:
    """Turns a subagent's raw result dict into plain, human-readable chat prose instead of a raw
    JSON blob. Real, confirmed operator complaint this fixes: the very first version of
    deliver_subagent_result_to_chat just json.dumps()'d the whole result dict straight into the
    chat bubble -- {"summary": "...", "details": null, "tool": "report_subagent_result"} rendered
    as one unformatted line of raw JSON, unreadable next to every other plain-prose message in the
    thread. report_subagent_result's own "summary" (agent/tools/native.py) is the subagent's real,
    deliberately-written final answer -- showing it as prose, not as a dict value, is what makes
    this actually readable. "details" (optional, often null) is appended only when the subagent
    provided one. An "error"/timeout-with-no-summary/genuinely unexpected shape falls back to a
    capped raw dump rather than silently dropping real data the operator should still see.
    """
    verb = _SUBAGENT_OUTCOME_VERBS.get(outcome, f"ended (status: {outcome})")
    header = f"Subagent '{profile_name}' {verb}."
    if not result:
        return header
    error = result.get("error")
    if error:
        return f"{header}\n\n{error}"
    summary = result.get("summary")
    if summary:
        details = result.get("details")
        body = summary if not details else f"{summary}\n\n{details}"
        return f"{header}\n\n{body}"
    return f"{header}\n\n{json.dumps(result, ensure_ascii=False)[:_TOOL_RESULT_CHAR_LIMIT]}"


def deliver_subagent_result_to_chat(session_id: str, thread_id: str, profile_name: str, result: dict) -> None:
    """Called from agent/core.py's _on_subagent_task_done, straight off a delegated subagent's own
    asyncio.Task done-callback -- this IS delegate_to_subagent's real delivery path for a
    chat-triggered task. Chat has no continuous loop the way a live scan phase does to inject a
    "next turn" message into (run_chat_turn_background runs exactly one turn and returns); this
    writes the result directly into the thread it came from instead, whether or not that thread is
    still the active one by the time the subagent actually finishes.

    Fresh-reload-before-save, same discipline as _reload_active_message/_append_segment_and_save --
    this runs on its own, asynchronously, well after the chat turn that triggered the delegation has
    already finished and returned, so it can never assume its own stale in-memory session is still
    current.

    Appended as role="assistant", not "user": a "user"-role message renders right-aligned as if the
    operator had typed it (templates/partials/chat_messages.html), which this plainly isn't --
    role="assistant" both reads correctly in the UI (left-aligned, matching the "was delegated"
    acknowledgment the model itself already sent for this same delegation) and gets replayed into
    the model's own context on its next real turn (unlike role="system", which
    run_chat_turn_background's own history loop deliberately strips before replay — see that
    function's own comment).

    A thread that's gone by the time this fires (deleted, or a session that vanished entirely) is
    a real, expected possibility for an async push arriving well after the fact — logged and
    dropped, never an exception a done-callback has no one to report to anyway.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("chat: session=%s deliver_subagent_result_to_chat: session vanished before delivery could land", session_id)
        return
    thread = _find_thread(session, thread_id)
    if thread is None:
        logger.debug("chat: session=%s thread=%s deliver_subagent_result_to_chat: thread no longer exists (deleted?)", session_id, thread_id)
        return
    outcome = result.get("outcome", "unknown")
    content = _format_subagent_result_for_chat(profile_name, outcome, result.get("result"))
    now = datetime.now(timezone.utc).isoformat()
    thread["messages"].append({"role": "assistant", "at": now, "segments": [{"type": "text", "content": content}]})
    thread["updated_at"] = now
    save_session(session_id, session)
    logger.debug("chat: session=%s thread=%s subagent %r result delivered (outcome=%s)", session_id, thread_id, profile_name, outcome)


def deliver_storage_reward_to_chat(session_id: str, *, kind: str, label: str, delta: int, total: int, total_label: str, detail: str) -> None:
    """Appends a gamified "+N" reward marker into the session's ACTIVE chat thread whenever something
    worth remembering lands in storage (a new finding, a captured playbook technique). Delivered as
    its own message with role="reward" -- a UI-only event (chat_messages.html renders the pop card),
    never replayed to the model as conversation (run_chat_turn_background's history loop + _segments_
    to_text both skip it, same as a role="system" compaction note). Fresh-reload-before-save, same
    discipline as deliver_subagent_result_to_chat: agent/core.py's autonomous scan loop calls this
    (via _notify_storage_reward) from its own long-lived in-memory session, so this must never assume
    that copy is current -- and the chat_threads merge (sessions/store.py's _preserve_newer_chat_
    threads, keyed on updated_at) keeps the reward even if that stale scan-loop copy saves later.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("chat: session=%s deliver_storage_reward_to_chat: session vanished before delivery", session_id)
        return
    thread = _get_active_thread(session)
    now = datetime.now(timezone.utc).isoformat()
    thread["messages"].append({
        "role": "reward", "at": now,
        "reward": {"kind": kind, "label": label, "delta": delta, "total": total, "total_label": total_label, "detail": (detail or "")[:200]},
    })
    thread["updated_at"] = now
    save_session(session_id, session)
    logger.debug("chat: session=%s reward delivered kind=%s delta=+%d total=%d", session_id, kind, delta, total)


def _reload_active_message(session_id: str, thread_id: str) -> tuple[dict, dict, dict] | None:
    """Fresh reload + find thread + find its own in-progress assistant message -- the shared first
    half of every incremental persistence step during a live tool loop (_append_segment_and_save /
    _update_last_tool_call_segment_and_save). Re-loading fresh on every single step, not just once
    at turn start, is what actually protects a multi-second turn's own segments from a concurrent
    scan-loop save landing mid-turn (sessions/store.py's _preserve_newer_chat_threads is the other,
    complementary half of this same protection -- see that function's own docstring for the real,
    already-confirmed incident this whole discipline exists because of).
    """
    session = load_session(session_id)
    if session is None:
        return None
    thread = _find_thread(session, thread_id)
    if thread is None:
        return None
    if not thread["messages"] or thread["messages"][-1]["role"] != "assistant":
        thread["messages"].append({"role": "assistant", "at": datetime.now(timezone.utc).isoformat(), "segments": []})
    return session, thread, thread["messages"][-1]


def _append_segment_and_save(session_id: str, thread_id: str, segment: dict) -> None:
    found = _reload_active_message(session_id, thread_id)
    if found is None:
        return
    session, thread, last_message = found
    last_message["segments"].append(segment)
    thread["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_session(session_id, session)


def _update_last_tool_call_segment_and_save(session_id: str, thread_id: str, call_id: str, **fields) -> None:
    found = _reload_active_message(session_id, thread_id)
    if found is None:
        return
    session, thread, last_message = found
    for seg in reversed(last_message["segments"]):
        if seg.get("type") == "tool_call" and seg.get("id") == call_id:
            seg.update(fields)
            break
    thread["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_session(session_id, session)


# Abandoned LLM calls (the worker thread keeps running after a Stop click wins the race in
# _complete_or_stop below -- Python cannot forcibly kill a blocking call already running in a
# thread) are kept referenced here purely so asyncio doesn't garbage-collect a still-pending Task
# and warn about it; discarded via the task's own done-callback the moment the background thread
# actually finishes. Nothing ever reads their result -- the turn that started them has already
# moved on by then.
_abandoned_llm_calls: set[asyncio.Task] = set()

# Same keepalive purpose as _abandoned_llm_calls just above, for a tool call abandoned by
# _run_tool_or_stop below instead of an LLM completion abandoned by _complete_or_stop.
_abandoned_tool_calls: set[asyncio.Task] = set()


async def _complete_or_stop(ctx: RunContext, thread_id: str, messages: list[dict], tools: list[dict] | None):
    """Runs ctx.llm.complete(...), racing it against the operator's own Stop signal so a click
    actually aborts THIS in-flight call -- not just noticed the next time _run_chat_tool_loop
    happens to check between calls (the checkpoint agent/core.py's own SessionStopRequested uses,
    fine for a scan step that runs minutes at a time, see ChatStopRequested's own docstring).

    Real, confirmed incident this fixes: a typical chat reply finishes in 2-10 seconds -- often
    faster than an operator can even register that "thinking…" appeared and click Stop, let alone
    have that click land before the call was going to finish anyway. Every recorded live test
    (`123-usr_dbd8cd`, 2026-08-18) showed the SAME shape: the Stop click posted successfully, but
    the in-flight LLM call had already been running long enough that it simply finished normally a
    few seconds later, `stopped=False` -- the between-call-only checkpoint never got a chance to
    fire because there was no NEXT call left to check before. A click that lands once nothing is
    pending anymore (400, "not currently running") reads identically to the operator as "Stop
    didn't do anything", even though it's technically correct given nothing was left to stop.

    The underlying network call itself is never forcibly killed -- Python has no way to preempt a
    blocking call already running in a worker thread -- it keeps running to completion in the
    background regardless; only the CALLER stops waiting on it the instant Stop wins the race,
    which is what actually makes the button feel responsive. Its eventual result (or error) is
    simply never read once nothing is awaiting it (see _abandoned_llm_calls above).
    """
    stop_event = get_chat_stop_event(ctx.session_id, thread_id)
    if stop_event.is_set():
        raise ChatStopRequested()
    stop_check = lambda: stop_event.is_set()  # noqa: E731
    call_task = asyncio.ensure_future(asyncio.to_thread(ctx.llm.complete, messages, tools, stop_check=stop_check))
    stop_task = asyncio.ensure_future(stop_event.wait())
    try:
        done, _pending = await asyncio.wait({call_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        if call_task in done:
            try:
                return call_task.result()
            except LLMCallAborted:
                raise ChatStopRequested()
        _abandoned_llm_calls.add(call_task)
        call_task.add_done_callback(lambda t: (_abandoned_llm_calls.discard(t), t.exception()))
        raise ChatStopRequested()
    finally:
        stop_task.cancel()


async def _run_tool_or_stop(ctx: RunContext, thread_id: str, spec: ToolSpec, arguments: dict):
    """Same race-against-Stop shape as _complete_or_stop above, applied to a real tool dispatch
    (_run_tool_with_retry) instead of an LLM completion -- confirmed live this was the actual gap
    behind "Stop doesn't react instantly": _complete_or_stop already made the LLM-thinking phase of
    a turn interruptible, but a tool call itself (radare2's own `aaa` full-analysis pass measured at
    ~2m30s on a real binary, or a `wine`/custom_re_script invocation blocking on its own internal
    timeout) was only ever checked for Stop BEFORE it started (the `if stop_check(): raise
    ChatStopRequested()` immediately above where this is called) -- once dispatched, a click had no
    effect until that one tool call finished on its own, however long that took. Same underlying
    constraint and same accepted tradeoff as the LLM case: the real subprocess/thread this kicks off
    is never forcibly killed (Python can't preempt a blocking call already running in a worker
    thread), it keeps running to completion in the background regardless; only the CALLER stops
    waiting on it the instant Stop wins the race, which is what actually makes the button feel
    responsive. Its eventual result is simply never read once nothing is awaiting it (see
    _abandoned_tool_calls above).
    """
    stop_event = get_chat_stop_event(ctx.session_id, thread_id)
    if stop_event.is_set():
        raise ChatStopRequested()
    call_task = asyncio.ensure_future(_run_tool_with_retry(ctx, spec, arguments))
    stop_task = asyncio.ensure_future(stop_event.wait())
    try:
        done, _pending = await asyncio.wait({call_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        if call_task in done:
            return call_task.result()
        _abandoned_tool_calls.add(call_task)
        call_task.add_done_callback(lambda t: (_abandoned_tool_calls.discard(t), t.exception()))
        raise ChatStopRequested()
    finally:
        stop_task.cancel()


# A model that supports native tool-calling can still, on a given turn, just narrate a fake
# invocation in plain prose instead of actually emitting one -- confirmed live (opencode-zen's
# "big-pickle" free-tier model, session hcm-usr_15eee7): a turn's `response.tool_calls` came back
# genuinely empty from the provider, yet `response.content` read "Запущу крекми через wine...
# [used custom_re_script(<a full pasted script>) -> ok]\nWine не установлен..." -- narration
# describing a tool call AND its output, with no real tool ever dispatched. This is a different
# failure mode from the DSML/prompt-mode parsing quirks agent/llm_client.py already has fallback
# regexes for (those fire when the model DOES attempt a real structured call, just in a
# differently-spelled wrapper) -- here there is nothing to parse, the provider's own tool_calls
# field is empty, so there is no structured call to recover. The only honest fix at this layer is
# detection + a visible warning, not silent trust: an operator reading "Wine не установлен" right
# after this pattern has no way to tell that's the MODEL'S OWN GUESS, not a real subprocess result,
# unless it's flagged. chat_messages.html renders seg.suspected_fake_tool_call as a warning banner.
#
# Second real incident, same underlying disease, a genuinely different textual shape (orrery-
# usr_38e422, same model): `response.tool_calls` empty again, but this time `response.content` was
# `<tool_call>\n<function=record_finding>\n<parameter=title>\n...` -- a different fine-tune-specific
# XML-ish tool-call dialect (no "[used ... -> ...]" narration at all, so the pattern above never
# matched), correctly guessing record_finding's own real parameter names yet never dispatching it --
# a genuine, concrete finding (a partially-recovered key algorithm) silently vanished with
# suspected_fake_tool_call staying unset, no warning shown anywhere. One single regex can't be
# expected to anticipate every fine-tune's own invented syntax, but this specific `<tool_call>`/
# `<function=`/`<parameter=` shape is common enough across Hermes/Qwen-style function-calling
# dialects that it's worth its own explicit branch rather than waiting for a third incident.
_FAKE_TOOL_CALL_PATTERN = re.compile(
    r"\[used\s+\w[\w.]*\s*\(.*?\)\s*(?:->|-&gt;)\s*\w+\s*\]"
    r"|<tool_call>"
    r"|<function\s*="
    r"|<parameter\s*=",
    re.DOTALL | re.IGNORECASE,
)


def _looks_like_narrated_fake_tool_call(text: str) -> bool:
    return bool(text) and bool(_FAKE_TOOL_CALL_PATTERN.search(text))


async def _run_chat_tool_loop(ctx: RunContext, thread_id: str, messages: list[dict], real_tool_specs: list[ToolSpec], pending_rewards: list[dict] | None = None, mode: str = "agent") -> str:
    """The actual LLM<->tools conversation for one chat turn — bounded, small, and deliberately its
    own thing rather than agent/core.py's _run_llm_tool_loop_impl: that function unconditionally
    writes every turn into session["logs"] (this module's own docstring promises chat will never
    touch that shared scan log), and its own free-text-final exit path (terminal_tool=None,
    expect_json_final=False) discards response.content entirely instead of returning it — no way
    to get a plain conversational reply back out of it. Bolting an incompatible return/logging mode
    onto that already-large function would add a permanent branch every other caller has to reason
    around, for a genuinely different use case.

    Every text/tool_call segment is persisted the instant it's known (_append_segment_and_save /
    _update_last_tool_call_segment_and_save) — a live SSE viewer sees a tool card go pending->done
    in real time, not just the final reply once the whole turn ends.

    real_tool_specs is whatever _chat_tool_specs() resolved this turn (web_fetch/browser_*, per the
    operator's own Chat settings toggles). Dispatched via _run_tool_with_retry — the exact same
    function the main agent's own loop uses — so scope/allowlist/out-of-scope checks and the
    browser tools' own session-injection (agent/core.py:1736-1750) all apply identically; there is
    no separate, weaker safety path for chat. skip_finding/add_guidance are still handled directly
    here via _handle_tool_calls (unchanged behavior).
    """
    if pending_rewards is None:
        pending_rewards = []
    specs_by_name = {spec.name: spec for spec in real_tool_specs}
    # mode == "standalone" (the top-level, project-less Quick Chat) has no session findings to
    # skip/correct and no scan phase to steer -- skip_finding/add_guidance/correct_finding stay
    # excluded there (query_playbook/playbook_strategy/record_technique, the OTHER three names in
    # _CHAT_TOOLS_SCHEMA, are cross-session and stay available in every mode including this one).
    bookkeeping_schema = [t for t in _CHAT_TOOLS_SCHEMA if mode != "standalone" or t["function"]["name"] not in _CHAT_BOOKKEEPING_TOOL_NAMES]
    bookkeeping_schema += _INTERACTIVE_CHAT_TOOLS_SCHEMA if mode in ("interactive", "reverse_engineering") else []
    tools_schema = bookkeeping_schema + [_tool_to_openai_schema(spec) for spec in real_tool_specs]

    # Checked directly at each tool-dispatch boundary below (the actual LLM call itself races the
    # Stop signal via _complete_or_stop instead -- see that function's own docstring for why a
    # plain between-call check alone isn't responsive enough for a typical few-second chat reply).
    stop_check = lambda: get_chat_stop_event(ctx.session_id, thread_id).is_set()  # noqa: E731

    iteration_budget = itertools.count() if _CHAT_MAX_TOOL_ITERATIONS <= 0 else range(_CHAT_MAX_TOOL_ITERATIONS)
    for _ in iteration_budget:
        response = await _complete_or_stop(ctx, thread_id, messages, tools_schema)
        if not response.tool_calls:
            text = response.content or ""
            segment = {"type": "text", "content": text}
            if _looks_like_narrated_fake_tool_call(text):
                segment["suspected_fake_tool_call"] = True
                logger.debug(
                    "chat: session=%s thread=%s reply narrates what looks like a tool call but tool_calls was empty -- flagging, not trusting",
                    ctx.session_id, thread_id,
                )
            _append_segment_and_save(ctx.session_id, thread_id, segment)
            return text

        # A model occasionally emits reasoning text alongside a tool call in the same turn --
        # surfaced as its own text segment, interleaved BEFORE the tool call(s) that followed it,
        # same ordering Piligrim's own segment model uses.
        if response.content:
            _append_segment_and_save(ctx.session_id, thread_id, {"type": "text", "content": response.content})

        messages.append({
            "role": "assistant",
            "content": response.content or "",
            "tool_calls": [
                {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                for c in response.tool_calls
            ],
        })
        for call in response.tool_calls:
            if stop_check():
                raise ChatStopRequested()
            _append_segment_and_save(ctx.session_id, thread_id, {
                "type": "tool_call", "id": call.id, "name": call.name, "arguments": call.arguments,
                # Computed once here, not in the template -- chat_messages.html just reads this
                # field directly, no Jinja-side tool-name-dispatch logic needed.
                "arg_summary": _chat_tool_arg_summary(call.name, call.arguments),
                "output": None, "error": False, "done": False,
            })
            try:
                if call.name == "record_technique":
                    # The reward it produces is collected, NOT delivered here -- appending a reward
                    # message mid-turn would land between this assistant message and the pending
                    # tool_call segment's own done-update just below, breaking _reload_active_
                    # message's "last message is the active assistant message" assumption. Flushed
                    # by run_chat_turn_background once the whole turn has finished persisting.
                    confirmation, reward = _apply_chat_record_technique(ctx.session_id, call.arguments, ctx.llm)
                    if reward is not None:
                        pending_rewards.append(reward)
                    result = {"status": "ok", "confirmation": confirmation}
                elif call.name == "query_playbook":
                    result = {"status": "ok", "confirmation": _apply_chat_query_playbook(call.arguments, ctx.llm)}
                elif call.name == "playbook_strategy":
                    result = {"status": "ok", "confirmation": await _apply_chat_playbook_strategy(call.arguments, ctx.llm)}
                elif call.name == "record_finding" and mode in ("interactive", "reverse_engineering"):
                    # Interactive/Reverse-Engineering-only situational finding -- same deferred-reward discipline as
                    # record_technique above (never delivered mid-turn).
                    confirmation, reward = _apply_chat_record_finding(ctx.session_id, call.arguments)
                    if reward is not None:
                        pending_rewards.append(reward)
                    result = {"status": "ok", "confirmation": confirmation}
                elif call.name == "suggest_next_steps" and mode in ("interactive", "reverse_engineering"):
                    # A real, separate segment (not folded into this tool_call's own output) --
                    # chat_messages.html renders "suggested_actions" as its own row of buttons, not
                    # tucked inside the collapsed tool-call card nobody would think to expand.
                    steps = _sanitize_suggested_steps(call.arguments)
                    if steps:
                        _append_segment_and_save(ctx.session_id, thread_id, {"type": "suggested_actions", "actions": steps})
                        logger.debug("chat: session=%s thread=%s offered %d suggested next step(s)", ctx.session_id, thread_id, len(steps))
                        result = {"status": "ok", "confirmation": "Shown to the operator as clickable options."}
                    else:
                        result = {"status": "error", "error": "no usable steps given -- nothing shown"}
                elif call.name in _CHAT_BOOKKEEPING_TOOL_NAMES and mode != "standalone":
                    # mode == "standalone" (Quick Chat) has none of these offered in its own
                    # tools_schema (bookkeeping_schema's own filter above) -- guarded here too so a
                    # model that calls one anyway (leaked in from stale history, or a provider that
                    # doesn't strictly honor the offered schema) falls through to the same "unknown
                    # tool" branch below instead of silently queuing a skip/guidance instruction
                    # nothing will ever drain, or "correcting" a finding that doesn't exist.
                    result = {"status": "ok", "confirmation": _handle_tool_calls(ctx.session_id, [call])}
                else:
                    spec = specs_by_name.get(call.name)
                    if spec is None:
                        result = {"status": "error", "error": f"unknown tool {call.name!r} (not currently enabled in Chat settings)"}
                    else:
                        arguments = call.arguments
                        if call.name == "delegate_to_subagent":
                            # Tags the eventual result with the thread it must land back in --
                            # agent/core.py's _on_subagent_task_done reads this (via
                            # subagent_tasks.register_task) to deliver the finished subagent's
                            # result straight into THIS chat thread (deliver_subagent_result_to_chat
                            # below) instead of the shared instruction queue only a live scan's own
                            # phase loop drains, which chat never does. A new dict, not a mutation of
                            # call.arguments in place -- that same dict object is already referenced
                            # by the tool_call segment appended above; mutating it here would leak
                            # this internal field into what the operator sees in that segment's own
                            # "arguments" display.
                            arguments = {**arguments, "_chat_thread_id": thread_id}
                        result = await _run_tool_or_stop(ctx, thread_id, spec, arguments)
            except Exception as exc:
                # Real, confirmed incident this fixes: _run_tool_with_retry's own 1-Step-Retry
                # correction call (agent/core.py) can itself raise (a provider outage/context-limit
                # error on ITS OWN nested LLM call, unrelated to this tool's own dispatch) -- that
                # exception used to propagate straight out of this loop, skipping the
                # done=True/error=True update below entirely. The tool_call segment was then
                # permanently stuck mid-spinner (chat_messages.html's own "not seg.done" check never
                # flips), which also meant syncChatState's own spinner-detection kept the whole chat
                # form disabled forever, even once the turn had genuinely ended (the outer except in
                # run_chat_turn_background still appends its own separate failure notice). Always
                # resolve this segment first, THEN let the real error keep propagating up to that
                # outer handler exactly as before -- the operator still needs to see the real cause.
                # ChatStopRequested specifically (_run_tool_or_stop above, once a Stop click wins
                # its race against this exact tool call) carries no message of its own -- str(exc)
                # would render as an empty, misleadingly red "failed" card for what was actually a
                # deliberate abandon, not a real tool failure.
                if isinstance(exc, ChatStopRequested):
                    _update_last_tool_call_segment_and_save(ctx.session_id, thread_id, call.id, output="Stopped by the operator.", error=False, done=True)
                else:
                    _update_last_tool_call_segment_and_save(ctx.session_id, thread_id, call.id, output=str(exc), error=True, done=True)
                raise
            logger.debug("chat: session=%s tool call %s -> status=%s", ctx.session_id, call.name, result.get("status"))
            is_error = result.get("status") in ("error", "failed")
            output_text = result.get("confirmation") or json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT]
            _update_last_tool_call_segment_and_save(ctx.session_id, thread_id, call.id, output=output_text, error=is_error, done=True)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT]})

        # Real, confirmed operator complaint this fixes: append_pending_chat_message's own
        # queued_messages path (this file's docstring above) only ever got drained by
        # run_chat_turn_background AFTER the entire turn returned -- for a turn that keeps calling
        # tools (a real session hit 100+ tool calls in one turn before this existed), a message the
        # operator typed and sent while that turn was still running sat untouched, invisible to the
        # model, the whole time. Checked once per outer iteration (after a full batch of tool
        # calls, not once per turn) -- reloaded fresh from disk each time, since
        # append_pending_chat_message's own write happens from a completely separate request that
        # can land at any point mid-turn. Appended as a real, new top-level "user" message in
        # thread["messages"] (not another segment on the in-progress assistant message) -- the next
        # _append_segment_and_save call sees a non-assistant message now sits last and correctly
        # starts a fresh assistant message right after it, so the queued message renders as its own
        # bubble exactly where it landed chronologically, with the turn's own reply continuing
        # underneath in a new bubble, not silently merged into the middle of the previous one.
        fresh_session = load_session(ctx.session_id)
        fresh_thread = _find_thread(fresh_session, thread_id) if fresh_session is not None else None
        queued = (fresh_thread or {}).get("queued_messages") or []
        if queued:
            next_item = queued.pop(0)
            fresh_thread["queued_messages"] = queued
            fresh_thread["messages"].append({
                "role": "user", "at": next_item["at"],
                "segments": [{"type": "text", "content": next_item["text"]}],
            })
            fresh_thread["updated_at"] = datetime.now(timezone.utc).isoformat()
            save_session(ctx.session_id, fresh_session)
            messages.append({"role": "user", "content": next_item["text"]})
            logger.debug(
                "chat: session=%s thread=%s injected queued message mid-turn (%d chars, %d still queued)",
                ctx.session_id, thread_id, len(next_item["text"]), len(queued),
            )

    logger.debug("chat: session=%s tool loop exhausted its %d-iteration budget without a final answer", ctx.session_id, _CHAT_MAX_TOOL_ITERATIONS)
    # Real, confirmed operator complaint: this used to just give up with a flat "try again in
    # smaller steps" the instant the budget ran out -- discarding every real tool result already
    # sitting in `messages` (a press_key failure diagnosed, a click confirmed, a page navigated) and
    # making a genuinely multi-step investigation look like it accomplished nothing at all. One more
    # LLM call with NO tools (tools=None forces free-text content, the model can't try to squeeze in
    # a 21st tool call) asks it to actually summarize what it already found from that same message
    # history, instead of the operator having to re-read the raw tool-call cards themselves to
    # reconstruct it. Still falls back to the plain apology if even this call fails outright (a
    # provider outage, not just "ran out of budget") -- never let a summary attempt's own failure
    # replace a real error with a misleadingly generic one.
    # Real, confirmed operator complaint this half fixes: with tools=None here, a turn that got cut
    # off by the budget mid-investigation could NEVER offer a suggest_next_steps menu on the way
    # out, even in Interactive/RE mode where it's otherwise the normal way to hand control back --
    # the model was structurally blocked from it. Allowing exactly that one tool back in (nothing
    # else -- no 21st real tool call) lets the forced summary still end with a real menu grounded in
    # whatever got done before the budget cut it off, instead of silently downgrading to plain text.
    forced_tools = [t for t in bookkeeping_schema if t["function"]["name"] == "suggest_next_steps"] or None
    messages.append({
        "role": "user",
        "content": "You've used up your tool budget for this turn. Stop here -- do not attempt another "
                   "tool call except suggest_next_steps. Summarize plainly what you actually "
                   "found/did/confirmed so far, and what (if anything) is still unresolved. If it's a "
                   "genuine, natural point to hand back a menu of next moves, you may also call "
                   "suggest_next_steps once alongside your summary.",
    })
    response = None
    try:
        response = await _complete_or_stop(ctx, thread_id, messages, forced_tools)
        fallback = response.content or ""
    except ChatStopRequested:
        raise
    except Exception as exc:
        logger.debug("chat: session=%s budget-exhausted summary call itself failed (%s)", ctx.session_id, exc)
        fallback = ""
    if not fallback.strip():
        fallback = "I wasn't able to finish looking into that within my tool budget — try asking again with a narrower question, or in smaller steps."
    _append_segment_and_save(ctx.session_id, thread_id, {"type": "text", "content": fallback})
    if response is not None and response.tool_calls:
        for call in response.tool_calls:
            if call.name != "suggest_next_steps":
                continue
            steps = _sanitize_suggested_steps(call.arguments)
            if steps:
                _append_segment_and_save(ctx.session_id, thread_id, {"type": "suggested_actions", "actions": steps})
                logger.debug("chat: session=%s thread=%s offered %d suggested next step(s) on budget-exhausted exit", ctx.session_id, thread_id, len(steps))
    return fallback


def append_pending_chat_message(
    session_id: str, user_message: str, provider: str | None, model: str | None,
) -> tuple[dict, bool]:
    """The fast, synchronous half of a chat turn — appends the operator's message (to the currently
    ACTIVE thread) and flips that thread's pending=True immediately, so the panel can render it as
    sent (plus a "thinking" indicator) before the LLM has even been asked, instead of the whole
    exchange only appearing once the reply comes back. Returns (session, started).

    started=False (queued behind an in-flight turn, Claude Code CLI-style) when this thread's own
    previous turn is still pending — the message is appended to thread["queued_messages"] instead
    of thread["messages"], rendered as its own "queued" bubble (chat_messages.html), and dispatched
    automatically by run_chat_turn_background once the current turn (and any queued ahead of it)
    finishes — never a silent no-op or a dropped message the operator has to notice and retype.
    main.py's own route only schedules a NEW run_chat_turn_background BackgroundTask when
    started=True; the turn already running is what drains the queue for started=False.

    provider/model are only overwritten when explicitly given (not None) — a bare "resend" call
    site that doesn't know about the picker fields can still call this without accidentally
    resetting a previously chosen provider back to "same as main agent". A brand-new thread's own
    title is auto-derived from this first message (truncated) — never re-derived for a thread that
    already has history (a migrated old conversation, or one already past its first message).

    Whenever the picker fields ARE explicitly given, they're also persisted to
    chat_settings_store's last_provider/last_model (see _new_thread's own docstring) — the operator
    just used them for real, so the next brand-new thread should start from the same place instead
    of resetting to whatever Settings' own main-agent provider happens to be.
    """
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")

    thread = _get_active_thread(session)
    now = datetime.now(timezone.utc).isoformat()

    if thread["pending"]:
        thread.setdefault("queued_messages", []).append({"id": uuid.uuid4().hex[:12], "text": user_message, "at": now})
        thread["updated_at"] = now
        save_session(session_id, session)
        logger.debug(
            "chat: session=%s thread=%s queued message (%d chars) behind an in-flight turn (%d now queued)",
            session_id, thread["id"], len(user_message), len(thread["queued_messages"]),
        )
        return session, False

    if provider is not None or model is not None:
        if provider is not None:
            thread["provider"] = provider or None
        if model is not None:
            thread["model"] = model or None
        chat_settings_store.save_last_chat_llm(thread["provider"], thread["model"])

    thread["messages"].append({"role": "user", "at": now, "segments": [{"type": "text", "content": user_message}]})
    thread["pending"] = True
    thread["updated_at"] = now
    if thread["title"] == _DEFAULT_THREAD_TITLE and len(thread["messages"]) == 1:
        thread["title"] = user_message[:_TITLE_MAX_CHARS] + ("…" if len(user_message) > _TITLE_MAX_CHARS else "")
    save_session(session_id, session)
    logger.debug("chat: session=%s thread=%s user message accepted (%d chars), pending=True", session_id, thread["id"], len(user_message))
    return session, True


def cancel_queued_chat_message(session_id: str, thread_id: str, message_id: str) -> dict | None:
    """Removes one not-yet-dispatched queued message (chat_messages.html's own "x" on a queued
    bubble) — the operator changed their mind before it was actually sent. Returns None (main.py's
    route 404s) only when the thread itself doesn't exist; an already-gone message_id (already
    dispatched, or already cancelled by an earlier click racing this one) is a harmless no-op
    rather than an error, same tolerance delete_chat_thread already gives a stale thread_id.
    """
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")
    thread = _find_thread(session, thread_id)
    if thread is None:
        return None
    queued = thread.get("queued_messages") or []
    remaining = [m for m in queued if m["id"] != message_id]
    if len(remaining) != len(queued):
        thread["queued_messages"] = remaining
        thread["updated_at"] = datetime.now(timezone.utc).isoformat()
        save_session(session_id, session)
        logger.debug("chat: session=%s thread=%s cancelled queued message id=%s", session_id, thread_id, message_id)
    return session


# HTTP status -> what it actually means, so the operator can tell "the provider is throttling
# free-tier usage" from "your API key is wrong" from "the provider is down" at a glance, instead of
# every failure looking identical. Real incident this fixes: a live 429 from opencode-zen's
# big-pickle model surfaced as the raw stringified exception -- openai.APIStatusError.__str__
# produces exactly "Error code: 429 - {raw json body}" -- with nothing telling the operator this
# was an external rate limit, not an ASRA bug, or what to actually do about it.
_LLM_ERROR_EXPLANATIONS = {
    429: "rate limited — this model's usage quota is currently exhausted (often a shared free-tier cap, not specific to your account)",
    401: "authentication failed — the API key configured for this provider is missing or invalid",
    403: "access denied — the configured API key doesn't have access to this model",
    400: "bad request — the provider rejected this request (e.g. an option this specific model doesn't support)",
    404: "not found — this model/endpoint doesn't exist on this provider (check the model name in Settings)",
}


def _provider_error_detail(exc: "openai.APIStatusError") -> str:
    """The provider's OWN human-readable error message, pulled out of the response body -- the
    single most useful, least-guessed thing to show the operator. HTTP status codes lie: opencode-
    zen returns 401 for a plain unsupported-model error (body {'error': {'type': 'ModelError',
    'message': 'Model is not supported'}}), so keying only on the code and printing "your API key
    is invalid" sends the operator fixing the wrong thing. The body's own message is trusted over
    the code whenever present. Returns "" when nothing usable can be recovered.

    Any key-shaped token in the message is redacted first: some providers echo the submitted API
    key back inside a malformed-auth error body, and this string is rendered straight onto the
    Settings page -- the exact leak the key-masking there exists to prevent (same reasoning as
    _test_provider_credentials' own "never forward exc's raw text").
    """
    body = getattr(exc, "body", None)
    message: object = None
    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            message = err.get("message")
        elif isinstance(err, str):
            message = err
        if not message:
            message = body.get("message")
    elif isinstance(body, str):
        message = body
    if not isinstance(message, str) or not message.strip():
        return ""
    # Collapse the stray double spaces some providers emit (opencode-zen's "Model  is not
    # supported") so the surfaced text reads cleanly.
    cleaned = " ".join(message.split())
    cleaned = re.sub(r"sk-[A-Za-z0-9_\-]{10,}", "***", cleaned)
    cleaned = re.sub(r"\b[A-Za-z0-9_\-]{32,}\b", "***", cleaned)
    return cleaned[:300]


def _format_llm_error(exc: Exception, provider: str | None, model: str | None) -> str:
    """Turns a raw provider exception into something the operator can actually act on: what the
    status code means, and that it's the PROVIDER at fault, not ASRA -- switch provider/model or
    wait, rather than reporting it as a bug. Falls back to the plain str(exc) for anything that
    isn't a recognized openai-SDK exception shape, same as before this existed.

    Reused as-is by main.py's Settings "Test" button (POST /api/settings/test-llm) -- that route
    used to dump the exact same raw str(exc) this was originally built to fix for chat, just in a
    different feature (confirmed live: a real opencode-zen free-tier 429 on the Test button showed
    the operator a bare "Error code: 429 - {'type': 'error', ...}" dict repr with no explanation).
    Deliberately worded generically ("this provider", not "chat's own provider") so both callers'
    own text reads correctly -- both are dropdown-driven forms, so "the dropdowns above" fits either.
    """
    provider_label = f"{provider or '(main agent default)'}/{model or '(default)'}"
    if isinstance(exc, openai.APIStatusError):
        status = exc.status_code
        # The provider's own message (when the body carries one) is trusted over the status-code
        # guess -- a code like 401 can mean something entirely non-auth (opencode-zen returns 401
        # for an unsupported model), and the code-only explanation then actively misleads. Lead
        # with the real message; keep the "provider's side, not an ASRA bug" framing either way.
        detail = _provider_error_detail(exc)
        if detail:
            return (
                f"This provider ({provider_label}) returned HTTP {status} and rejected the "
                f"request: \"{detail}\". This is on the provider's side, not an ASRA bug — switch "
                "provider/model in the dropdowns above, or wait and try again."
            )
        if status in _LLM_ERROR_EXPLANATIONS:
            reason = _LLM_ERROR_EXPLANATIONS[status]
        elif status >= 500:
            reason = "the provider's own servers are having trouble right now"
        else:
            reason = "the provider rejected this request"
        return (
            f"This provider ({provider_label}) returned HTTP {status}: {reason}. This is on "
            "the provider's side, not an ASRA bug — switch provider/model in the dropdowns above, "
            "or wait and try again."
        )
    if isinstance(exc, openai.APIConnectionError):
        return (
            f"Couldn't reach this provider ({provider_label}) — a network/connection issue, "
            "not an ASRA bug. Try again in a moment."
        )
    return f"Something went wrong — {exc}"


async def _run_one_chat_turn(session_id: str, thread_id: str, mode: str) -> bool:
    """One real LLM<->tools turn against thread_id's own already-pending user message, then hands
    off to the NEXT queued message (if any) — run_chat_turn_background's own queue-drain loop below
    calls this repeatedly until it returns False. Returns True when a queued message was dequeued
    and left pending for the next iteration, False once the queue is empty or the operator stopped
    the turn (see below).

    Builds the fresh snapshot + playbook addendum + compacted history, then runs _run_chat_tool_loop
    (this thread's OWN provider/model — "same as main agent" via get_provider's own None-means-
    default resolution when neither was ever picked) — a real, bounded LLM<->tools conversation
    persisting its own progress as it goes (see _run_chat_tool_loop), not a single call.

    Fresh-reloads the session/thread at the very start (a /new or thread-switch, or another
    already-drained queue item, could have landed since the caller last touched it) — every
    subsequent write goes through _append_segment_and_save/_update_last_tool_call_segment_and_save,
    which each do their own fresh reload immediately before saving (see _reload_active_message's own
    docstring for why this matters).

    Never lets an LLM/network failure, or an operator Stop, leave the panel stuck showing
    "thinking…" forever, or lose the operator's own already-persisted message — pending is always
    cleared and SOME reply (a real one, a stop notice, or a plain failure notice, appended as its
    own text segment) is always produced, even on an unhandled exception from the provider call
    itself.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("chat: session=%s _run_one_chat_turn: session vanished before it could run", session_id)
        return False
    thread = _find_thread(session, thread_id)
    if thread is None:
        logger.debug("chat: session=%s thread=%s _run_one_chat_turn: thread no longer exists", session_id, thread_id)
        return False
    last_message = thread["messages"][-1] if thread["messages"] else None
    pending_user_message = last_message if last_message and last_message["role"] == "user" else None
    user_message = _segments_to_text(pending_user_message["segments"]) if pending_user_message else ""

    # Collected during the turn (agent/chat.py's record_technique handler), flushed as gamified "+N"
    # reward messages only AFTER the turn's own assistant message is fully persisted below -- never
    # mid-turn, so a reward append can't split the in-progress assistant message's segment writes.
    pending_rewards: list[dict] = []
    stopped = False
    try:
        llm = get_provider(thread["provider"], thread["model"])
        logger.debug(
            "chat: session=%s thread=%s background turn starting (provider=%s model=%s mode=%s)",
            session_id, thread_id, thread["provider"] or "(main agent default)", thread["model"] or "(default)", mode,
        )
        await _compact_if_needed(llm, thread, session_id)

        system_prompt = {
            "interactive": INTERACTIVE_CHAT_PROMPT,
            "reverse_engineering": RE_CHAT_PROMPT,
            "standalone": STANDALONE_CHAT_PROMPT,
        }.get(mode, CHAT_PROMPT)
        # Only for RE mode -- Agent-mode's own chat sidebar has never surfaced session["scope_rules"]/
        # ["goal"]/["re_experience_level"] either (a pre-existing gap for the first two, and simply
        # not applicable for the third, neither something this touches), so these stay scoped to the
        # one mode that actually has a real way to set them (main.py's start_re route).
        re_addenda = ""
        if mode == "reverse_engineering":
            re_addenda = _re_experience_level_addendum(session) + _scope_rules_task_addendum(session) + _goal_task_addendum(session)
        messages = [
            {"role": "system", "content": system_prompt + re_addenda + _playbook_task_addendum(session, llm=llm) + _chat_subagent_addendum(mode, session.get("enabled_subagent_ids"))},
            {"role": "user", "content": f"Current session state:\n{_session_snapshot(session)}"},
        ]
        if thread["summary"]:
            messages.append({"role": "assistant", "content": f"(summary of earlier conversation) {thread['summary']}"})
        # Every earlier message EXCEPT the just-appended pending one -- append_pending_chat_message
        # already put it last in thread["messages"] (that's the whole point, for immediate
        # visibility), so it's added back explicitly as this turn's own final message below instead
        # of being replayed twice. Matched by object identity, not position -- _compact_if_needed
        # (just above) can slice+reassign thread["messages"] and append its own trailing "system"
        # note, which can leave the pending message anywhere but last; identity survives that slice
        # (Python list slicing keeps the same element references) regardless of where it lands.
        # Past turns are flattened (_segments_to_text), not replayed with their real tool_calls/
        # tool-role shape -- see that function's own docstring for why.
        for past in thread["messages"]:
            if past is pending_user_message:
                continue
            # A "system" entry is a compaction note; a "reward" entry is a UI-only gamified
            # "+N" storage marker (deliver_storage_reward_to_chat) with no "segments" at all --
            # neither is anything either party actually said, so both are stripped before replay.
            if past["role"] in ("system", "reward"):
                continue
            messages.append({"role": past["role"], "content": _segments_to_text(past["segments"])})
        messages.append({"role": "user", "content": user_message})

        ctx = RunContext(llm=llm, session=session, session_id=session_id)
        await _run_chat_tool_loop(ctx, thread_id, messages, _chat_tool_specs(mode, session.get("enabled_subagent_ids")), pending_rewards, mode)
    except ChatStopRequested:
        stopped = True
        logger.debug("chat: session=%s thread=%s turn stopped by the operator", session_id, thread_id)
        _append_segment_and_save(session_id, thread_id, {"type": "text", "content": "Stopped by the operator.", "error": True})
    except Exception as exc:
        logger.debug("chat: session=%s thread=%s background turn failed (%s)", session_id, thread_id, exc)
        error_message = _format_llm_error(exc, thread["provider"], thread["model"])
        try:
            # error=True -- shown to the operator like any other reply, but _segments_to_text
            # excludes it from what gets replayed to the model as ITS OWN past conversation on
            # later turns (see that function's own docstring for the real incident this closes).
            _append_segment_and_save(session_id, thread_id, {"type": "text", "content": error_message, "error": True})
        except Exception as save_exc:
            # Real, confirmed incident this guards against: this recovery save can itself hit the
            # same transient disk/OSError class that crashed the turn in the first place (a
            # double-fault) -- left unguarded, that second exception escaped uncaught, silently
            # killing the whole background task with thread["pending"] never cleared. The reload
            # below still runs and forces pending=False even though the error text never made it
            # to disk this time, instead of leaving the thread stranded until the next server start.
            logger.debug("chat: session=%s thread=%s recovery save also failed (%s)", session_id, thread_id, save_exc)

    dequeued_next = False
    found = _reload_active_message(session_id, thread_id)
    if found is not None:
        fresh_session, fresh_thread, _ = found
        fresh_thread["pending"] = False
        if stopped:
            # A deliberate Stop means "stop the chat", not just this one reply -- clears whatever
            # else the operator queued up behind it too, rather than silently ploughing on into a
            # follow-up they never got a chance to reconsider once the interrupted turn actually
            # landed.
            fresh_thread["queued_messages"] = []
        else:
            queued = fresh_thread.get("queued_messages") or []
            if queued:
                next_item = queued.pop(0)
                now = datetime.now(timezone.utc).isoformat()
                fresh_thread["messages"].append({"role": "user", "at": now, "segments": [{"type": "text", "content": next_item["text"]}]})
                fresh_thread["pending"] = True
                fresh_thread["updated_at"] = now
                dequeued_next = True
        save_session(session_id, fresh_session)
    # The single owner of clearing this turn's own stop signal, mirroring agent/core.py's own
    # run_session/run_focused_exploit -- see ChatStopRequested's docstring for why _run_chat_tool_
    # loop's own checkpoints must never clear it themselves.
    get_chat_stop_event(session_id, thread_id).clear()

    # Flush any storage rewards this turn earned (record_technique) NOW -- the turn's own assistant
    # message is fully persisted, so appending reward messages is safe. Each is its own
    # fresh-reload-append-save (deliver_storage_reward_to_chat), landing after the reply.
    for reward in pending_rewards:
        deliver_storage_reward_to_chat(session_id, **reward)
    logger.debug(
        "chat: session=%s thread=%s background turn finished (rewards=%d, stopped=%s, next_queued=%s)",
        session_id, thread_id, len(pending_rewards), stopped, dequeued_next,
    )
    return dequeued_next


async def run_chat_turn_background(session_id: str) -> None:
    """Runs as a FastAPI BackgroundTask after append_pending_chat_message has already made the
    operator's message and pending=True durable on the active thread. Drains that thread's own
    message queue (Claude Code CLI-style "type ahead while it's still working") by repeatedly
    calling _run_one_chat_turn until nothing's left queued -- each iteration is a fully independent
    turn (its own fresh snapshot/history/tool loop), chained here rather than inside
    _run_one_chat_turn itself so a single turn's own logic stays a single turn's own logic.

    thread_id is resolved ONCE, from whichever thread was active at the moment this task actually
    starts (a /new or thread-switch could have landed between append_pending_chat_message's own
    save and this background task starting) -- every queued follow-up dispatched by this same loop
    stays pinned to that SAME thread, never wherever the operator happens to have navigated to by
    the time a later queue item's turn begins.

    current_session_id/exploit_auth_token are scoped to the WHOLE drain loop, not per-turn -- same
    session, same interactive-mode status, for every queued turn this loop runs; re-setting them on
    every iteration would be pure overhead for no behavioral difference. current_session_id: without
    it every chat debug line, tool call included, landed only in the global app log even though the
    operator is looking at one specific session's own project-folder debug.log (agent/utils/debug.py
    routes purely off this ContextVar; agent/chat.py never set it before, unlike agent/core.py's
    run_session/run_focused_exploit). Reset in finally so a later, unrelated turn sharing this
    process never inherits a stale value.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("chat: session=%s run_chat_turn_background: session vanished before it could run", session_id)
        return
    thread_id = _get_active_thread(session)["id"]

    # Interactive/Reverse-Engineering-mode sessions (session["mode"], main.py's start_interactive/
    # start_re) are the operator's own manual console: a different system prompt (execute concrete
    # tasks / ask when unclear, rather than the observer role CHAT_PROMPT frames), Subagent
    # delegation always offered, and exploitation authorized wholesale for the duration of this
    # turn -- authorize_all_targets_for_context() is inherited by any Subagent task this turn
    # spawns (asyncio.create_task copies the context), so a subagent's own gated tools are
    # authorized too without touching the global list. "agent" is the default for every
    # pre-existing session missing the field entirely, matching sessions/store.py's own default.
    # "standalone" (the top-level, project-less Quick Chat) deliberately does NOT get this: it has
    # no target/scope of its own, so wholesale-authorizing exploitation there would turn "ask a
    # quick security question" into a silent blanket authorization to attack whatever host happens
    # to come up in conversation -- it keeps the exact same off-by-default posture "agent" mode has.
    mode = session.get("mode", "agent")

    session_context_token = current_session_id.set(session_id)
    exploit_auth_token = authorize_all_targets_for_context() if mode in ("interactive", "reverse_engineering") else None
    try:
        while await _run_one_chat_turn(session_id, thread_id, mode):
            pass
    finally:
        current_session_id.reset(session_context_token)
        # Only this turn's own context loses the authorization -- a Subagent task spawned during it
        # copied the context at create_task time, so its own (separate) copy keeps the authorization
        # for its whole run and is unaffected by this reset.
        if exploit_auth_token is not None:
            deauthorize_all_targets_for_context(exploit_auth_token)


async def compact_chat_thread(session_id: str, instructions: str = "") -> bool:
    """The manual /compact entry point (button or slash command, main.py's own route) -- runs
    _run_compaction unconditionally (no size-budget check, unlike the automatic path) against the
    currently active thread. A genuinely synchronous, single quick LLM call (unlike a full chat
    turn's own multi-tool loop), so this runs to completion within its own request instead of
    needing a pending/background-task handoff — same reasoning
    _structure_hypothesis_text (agent/core.py) already applies to its own single, quick,
    tool-less LLM call. Returns False (a no-op, nothing to compact yet) when the thread is too
    short — main.py's own route turns that into an honest "nothing to compact yet" message instead
    of silently doing nothing.
    """
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")
    thread = _get_active_thread(session)
    # Same current_session_id wiring as run_chat_turn_background above -- see that function's own
    # docstring for why this is needed at all (agent/chat.py never set it before this).
    session_context_token = current_session_id.set(session_id)
    try:
        llm = get_provider(thread["provider"], thread["model"])
        did_compact = await _run_compaction(llm, thread, session_id, instructions)
        if did_compact:
            thread["updated_at"] = datetime.now(timezone.utc).isoformat()
            save_session(session_id, session)
        return did_compact
    finally:
        current_session_id.reset(session_context_token)


def start_new_chat_thread(session_id: str) -> dict:
    """/new (button or slash command) -- old threads are never destroyed, just no longer active
    (Umbra's own "old threads become browsable, never deleted" behavior)."""
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")
    _ensure_chat_threads(session)
    thread = _new_thread()
    session["chat_threads"].append(thread)
    session["active_chat_thread_id"] = thread["id"]
    save_session(session_id, session)
    logger.debug("chat: session=%s started new thread id=%s", session_id, thread["id"])
    return session


def switch_chat_thread(session_id: str, thread_id: str) -> dict | None:
    """/resume's own picker, once an entry is clicked -- returns None (main.py's route 404s) when
    thread_id doesn't exist. Switching to a thread that's still mid-turn (pending=True) is allowed
    -- the panel just shows that thread's own live "thinking" state, same as if the operator had
    simply never navigated away from it."""
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")
    thread = _find_thread(session, thread_id)
    if thread is None:
        return None
    session["active_chat_thread_id"] = thread_id
    save_session(session_id, session)
    logger.debug("chat: session=%s switched active thread to id=%s", session_id, thread_id)
    return session


def list_chat_threads(session_id: str) -> list[dict]:
    """Newest-first -- the /resume picker's own data source (main.py's route)."""
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")
    threads, _ = _ensure_chat_threads(session)
    return sorted(threads, key=lambda t: t["updated_at"], reverse=True)


def delete_chat_thread(session_id: str, thread_id: str) -> dict | None:
    """The /resume picker's own delete control (main.py's route requires the operator to confirm
    via the same asraConfirm dialog every other destructive action in this app uses, before this
    ever runs) -- unlike /new's "old threads become browsable, never deleted" default, this is the
    one explicit way to actually remove one. Deleting the currently active thread switches to
    whichever OTHER thread was updated most recently, or creates a fresh one if that was the last
    thread left -- the thread list must never end up empty. Returns None (main.py's route 404s)
    when thread_id doesn't exist.
    """
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")
    threads, active_id = _ensure_chat_threads(session)
    if not any(t["id"] == thread_id for t in threads):
        return None

    remaining = [t for t in threads if t["id"] != thread_id]
    if not remaining:
        remaining = [_new_thread()]
    session["chat_threads"] = remaining
    if active_id == thread_id:
        newest = max(remaining, key=lambda t: t["updated_at"])
        session["active_chat_thread_id"] = newest["id"]
    # A deliberate delete looks IDENTICAL, to sessions/store.py's own merge logic, to a stale
    # caller's session snapshot simply predating a thread that was created after it loaded (the
    # exact case that merge's own "never drop a thread that exists only on one side" rule exists
    # to protect) -- both are "on-disk has this thread id, incoming doesn't". Without an explicit
    # tombstone, that protection silently resurrects a thread the operator just deleted the next
    # time any stale in-memory session (the scan loop's own long-lived copy) saves. See that
    # function's own docstring for how this list is consumed.
    session.setdefault("deleted_chat_thread_ids", []).append(thread_id)
    save_session(session_id, session)
    logger.debug("chat: session=%s deleted thread id=%s", session_id, thread_id)
    return session


def rename_chat_thread(session_id: str, thread_id: str, title: str) -> dict | None:
    """Chat tab strip's inline rename (real, explicit operator ask: parity with the Terminal tab
    strip's own dblclick-to-rename, static/js/terminal.js's wireRename). A blank/whitespace-only
    title is a no-op (keeps whatever the thread already had) rather than ever saving an empty
    name -- mirrors terminal.js's own commit() falling back to tab.defaultLabel the same way.

    Setting a real title here is exactly what already stops _run_chat_tool_loop's own
    auto-title-from-first-message logic (this file's own "thread['title'] == _DEFAULT_THREAD_TITLE
    and len(thread['messages']) == 1" check) from ever overwriting it again -- that condition
    requires the title to STILL be the literal default, so no separate "locked" flag is needed for
    the two to coexist.
    """
    session = load_session(session_id)
    if session is None:
        return None
    threads, _ = _ensure_chat_threads(session)
    thread = next((t for t in threads if t["id"] == thread_id), None)
    if thread is None:
        return None
    title = title.strip()
    if title:
        thread["title"] = title[:_TITLE_MAX_CHARS]
        thread["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_session(session_id, session)
    logger.debug("chat: session=%s renamed thread id=%s title=%r", session_id, thread_id, thread["title"])
    return session


_HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


def set_chat_thread_color(session_id: str, thread_id: str, color: str | None) -> dict | None:
    """Chat tab strip's per-tab color (real, explicit operator ask: parity with the Terminal tab
    strip's own color picker, static/js/terminal.js's setTabColor) -- see this module's own
    top-of-file schema comment for why this is persisted on the thread itself rather than
    client-side localStorage the way the Terminal tab strip does it.

    A value that isn't a real "#rrggbb" (a stray/malformed client value -- the real picker is
    always a native <input type="color">, which can't produce anything else, but this never trusts
    that alone) is silently treated as "clear the color" rather than saving garbage that would
    otherwise land straight in an inline CSS custom property.
    """
    session = load_session(session_id)
    if session is None:
        return None
    threads, _ = _ensure_chat_threads(session)
    thread = next((t for t in threads if t["id"] == thread_id), None)
    if thread is None:
        return None
    thread["color"] = color if color and _HEX_COLOR_RE.match(color) else None
    save_session(session_id, session)
    logger.debug("chat: session=%s thread id=%s color=%r", session_id, thread_id, thread["color"])
    return session


def reconcile_orphaned_chat_threads(session_id: str, data: dict) -> None:
    """Called from main.py's startup orphaned-session sweep, on the raw dict just loaded from
    disk -- a chat turn's own run_chat_turn_background coroutine cannot survive the process that
    was running it, same reasoning agent/tools/subagent_tasks.py's reconcile_orphaned_subagent_
    tasks already documents for a delegated Subagent's own asyncio.Task: this process has no live
    handle for ANY turn from a previous process's run, so a thread still marked pending=True here
    has nothing left alive anywhere to ever clear it, notice a Stop click, or drain its queue.

    Real, confirmed incident this fixes: an operator's Stop click and two resent follow-ups all
    silently piled up against a thread stuck pending from a previous server run -- the Stop event
    got set and the follow-ups got queued exactly as designed, but there was no live
    _run_chat_tool_loop left anywhere to ever check either one, so nothing visibly happened and the
    thread stayed stuck. Clearing pending here (mirroring what a Stop click itself already does to
    a real live turn: a notice, pending cleared, the queue dropped too) is what actually unsticks
    it -- the operator can just send a fresh message afterward.

    Mutates data["chat_threads"] in place; the caller (already saving the session for its own
    reasons, or specifically for this) persists it via its own save_session.
    """
    now = datetime.now(timezone.utc).isoformat()
    for thread in data.get("chat_threads") or []:
        if not thread.get("pending"):
            continue
        queued_count = len(thread.get("queued_messages") or [])
        thread.setdefault("messages", []).append({
            "role": "assistant", "at": now,
            "segments": [{
                "type": "text", "error": True,
                # Deliberately doesn't assert *why* -- this sweep also catches a turn whose
                # background task already died silently well before this restart (e.g. an
                # unguarded save-time exception), not only one genuinely still in flight when the
                # process stopped, so naming "the server restarted" as the cause is sometimes wrong.
                "content": "Interrupted — this reply never completed. Send your message again.",
            }],
        })
        thread["pending"] = False
        thread["queued_messages"] = []
        thread["updated_at"] = now
        logger.debug(
            "chat: session=%s thread=%s reconciled a stuck pending turn from a previous process (%d queued message(s) dropped)",
            session_id, thread["id"], queued_count,
        )
