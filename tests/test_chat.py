"""Unit tests for agent/chat.py. Network/LLM calls mocked via unittest.mock.patch on the
exact call site (llm.complete, load_session/save_session) — same pattern as test_llm_client.py.
"""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import openai
import pytest

import agent.chat as chat  # used to monkeypatch _CHAT_MAX_TOOL_ITERATIONS in budget-exhaustion tests
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY, needed for get_tool below)
from agent.chat import (
    ChatStopRequested,
    _TITLE_MAX_CHARS,
    _append_segment_and_save,
    _apply_chat_finding_correction,
    _chat_subagent_addendum,
    _chat_tool_arg_summary,
    _chat_tool_specs,
    _compact_if_needed,
    _complete_or_stop,
    _ensure_chat_threads,
    _estimate_tokens,
    _find_thread,
    _format_llm_error,
    _format_subagent_result_for_chat,
    _get_active_thread,
    _handle_tool_calls,
    _new_thread,
    _resolve_finding_ref,
    _run_chat_tool_loop,
    _run_compaction,
    _sanitize_suggested_steps,
    _segments_to_text,
    _session_snapshot,
    _update_last_tool_call_segment_and_save,
    append_pending_chat_message,
    cancel_queued_chat_message,
    compact_chat_thread,
    delete_chat_thread,
    deliver_subagent_result_to_chat,
    get_chat_stop_event,
    list_chat_threads,
    reconcile_orphaned_chat_threads,
    rename_chat_thread,
    request_chat_stop,
    run_chat_turn_background,
    set_chat_thread_color,
    start_new_chat_thread,
    switch_chat_thread,
)
from agent.core import RunContext, get_instruction_queue
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import get_tool


def _run(coro):
    return asyncio.run(coro)


def _session(session_id, **overrides):
    session = {"session_id": session_id, "target": "x", "status": "completed", "findings": [], "logs": []}
    session.update(overrides)
    return session


# --- pure functions ---


def test_session_snapshot_includes_target_status_findings_recent_logs():
    session = {
        "target": "example.com",
        "status": "processing",
        "recon_result": {"targets": [{"host": "example.com", "port": 443}]},
        "findings": [{
            "title": "XSS", "severity": "High", "verification": "verified", "exploited": False,
            "advisory_note": "no real session to hijack", "qualifies_for_bounty": "unclear",
            "false_positive_reason": None, "skeptical_verification": "confirmed",
            "skeptical_verification_note": "reproduced independently", "remediation_advice": "escape output",
            "tool_timeline": [{"tool": "nuclei_scan", "stage": "discovery"}, {"tool": "sqlmap", "stage": "exploitation"}],
        }],
        "hypotheses": [{
            "text": "admin panel reachable", "status": "confirmed", "evidence": "200 OK on /admin", "resolution_note": None,
            "source": "agent", "source_phase": "recon", "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
        }],
        "logs": [{"phase": "recon", "command": "dns_lookup(...)", "status": "success"}] * 10,
    }
    snapshot = json.loads(_session_snapshot(session))
    assert snapshot["target"] == "example.com"
    assert snapshot["status"] == "processing"
    # Every field a finding/hypothesis card's own badges are actually driven by (macros/ui.html's
    # bounty_badge/false_positive_badge/exploited_badge/hypothesis_status_badge) must survive into
    # the snapshot -- the operator can only ask chat about what they can see on screen. Each entry
    # also carries a short F#/H#/R# id (1-indexed, session_fragment.html's own "Discuss in chat"
    # buttons insert the identical tag) so the operator can point chat at one specific record.
    finding_snapshot = snapshot["findings"][0]
    assert finding_snapshot["id"] == "F1"
    assert finding_snapshot["title"] == "XSS"
    assert finding_snapshot["advisory_note"] == "no real session to hijack"
    assert finding_snapshot["qualifies_for_bounty"] == "unclear"
    assert finding_snapshot["skeptical_verification_note"] == "reproduced independently"
    assert finding_snapshot["remediation_advice"] == "escape output"
    assert finding_snapshot["tool_timeline"] == [{"tool": "nuclei_scan", "stage": "discovery"}, {"tool": "sqlmap", "stage": "exploitation"}]
    hypothesis_snapshot = snapshot["hypotheses"][0]
    assert hypothesis_snapshot["id"] == "H1"
    assert hypothesis_snapshot["text"] == "admin panel reachable"
    assert hypothesis_snapshot["source"] == "agent"
    assert hypothesis_snapshot["source_phase"] == "recon"
    assert hypothesis_snapshot["tool_timeline"] == []
    assert snapshot["recon_targets"] == [{"id": "R1", "host": "example.com", "port": 443, "service": None, "version": None}]
    assert len(snapshot["recent_activity"]) == 5  # trimmed to the last N, not all 10


def test_session_snapshot_handles_missing_optional_fields():
    snapshot = json.loads(_session_snapshot({"target": "x", "status": "pending"}))
    assert snapshot["recon_targets"] == []
    assert snapshot["findings"] == []
    assert snapshot["hypotheses"] == []
    assert snapshot["recent_activity"] == []


def test_session_snapshot_never_leaks_operator_notes_or_pinned_refs():
    # operator_notes (main.py's collapsed-chat side panel scratchpad) and pinned_refs (the same
    # panel's Pinned rail) are the one piece of state in this app deliberately never shown to the
    # model -- _session_snapshot builds an explicit whitelisted dict, never **session, so simply
    # never adding these two keys there is the whole guarantee. This test is the regression guard:
    # even if a future edit accidentally starts spreading extra session fields into the snapshot,
    # this still fails loudly.
    session = {
        "target": "x", "status": "pending",
        "operator_notes": "a secret lead the operator doesn't want the model to see",
        "pinned_refs": ["F1", "H2"],
    }
    snapshot = json.loads(_session_snapshot(session))
    assert "operator_notes" not in snapshot
    assert "pinned_refs" not in snapshot
    assert "secret lead" not in _session_snapshot(session)


def test_estimate_tokens_is_roughly_chars_over_four():
    assert _estimate_tokens("a" * 400) == 100


def test_chat_tool_arg_summary_web_fetch_uses_target():
    assert _chat_tool_arg_summary("web_fetch", {"target": "https://example.com"}) == "https://example.com"


def test_chat_tool_arg_summary_browser_tool_uses_target_or_ref():
    assert _chat_tool_arg_summary("browser_navigate", {"target": "https://example.com"}) == "https://example.com"
    assert _chat_tool_arg_summary("browser_click", {"ref": "e12"}) == "e12"


def test_chat_tool_arg_summary_falls_back_to_first_argument_value():
    assert _chat_tool_arg_summary("some_unknown_tool", {"query": "openssh"}) == "openssh"


def test_chat_tool_arg_summary_empty_when_no_arguments():
    assert _chat_tool_arg_summary("some_unknown_tool", {}) == ""


def test_chat_tool_arg_summary_suggest_next_steps_shows_option_count():
    assert _chat_tool_arg_summary("suggest_next_steps", {"steps": ["a", "b", "c"]}) == "3 options"
    assert _chat_tool_arg_summary("suggest_next_steps", {"steps": ["a"]}) == "1 option"


def test_sanitize_suggested_steps_trims_and_drops_blanks():
    assert _sanitize_suggested_steps({"steps": [" Check the login form ", "", "  ", "Decompile main()"]}) == [
        "Check the login form", "Decompile main()",
    ]


def test_sanitize_suggested_steps_caps_at_four():
    assert _sanitize_suggested_steps({"steps": ["a", "b", "c", "d", "e", "f"]}) == ["a", "b", "c", "d"]


def test_sanitize_suggested_steps_empty_when_no_steps_given():
    assert _sanitize_suggested_steps({}) == []


def test_segments_to_text_flattens_text_and_tool_call_segments():
    segments = [
        {"type": "text", "content": "Let me check that."},
        {"type": "tool_call", "id": "c1", "name": "web_fetch", "arguments": {"target": "https://example.com"}, "done": True, "error": False},
        {"type": "text", "content": "The page says hello."},
    ]
    text = _segments_to_text(segments)
    assert "Let me check that." in text
    assert "[used web_fetch(https://example.com) -> ok]" in text
    assert "The page says hello." in text


def test_segments_to_text_marks_a_pending_tool_call_as_pending():
    segments = [{"type": "tool_call", "id": "c1", "name": "web_fetch", "arguments": {}, "done": False, "error": False}]
    assert "-> pending]" in _segments_to_text(segments)


def test_segments_to_text_marks_a_failed_tool_call_as_error():
    segments = [{"type": "tool_call", "id": "c1", "name": "web_fetch", "arguments": {}, "done": True, "error": True}]
    assert "-> error]" in _segments_to_text(segments)


def test_segments_to_text_skips_empty_text_segments():
    assert _segments_to_text([{"type": "text", "content": ""}]) == ""


def test_segments_to_text_flattens_suggested_actions_segment():
    segments = [{"type": "suggested_actions", "actions": ["Check the login form", "Decompile main()"]}]
    assert _segments_to_text(segments) == "[offered next-step options: Check the login form, Decompile main()]"


def test_segments_to_text_excludes_a_turn_failure_notice_from_replay():
    """Real, confirmed incident this fixes: a rate-limit failure notice persisted as an ordinary
    text segment, then got replayed as the model's OWN past conversation history on every later
    turn -- the model kept refusing to even attempt delegate_to_subagent, citing "the rate-limit
    error" long after it was over, because its own visible history looked like it had already
    concluded things were broken."""
    segments = [{"type": "text", "content": "Chat's own provider (opencode-zen/big-pickle) returned HTTP 429: rate limited...", "error": True}]
    assert _segments_to_text(segments) == ""


def test_segments_to_text_keeps_a_normal_reply_alongside_an_excluded_failure_notice():
    segments = [
        {"type": "text", "content": "A failure notice from an earlier attempt.", "error": True},
        {"type": "text", "content": "A real answer."},
    ]
    assert _segments_to_text(segments) == "A real answer."


# --- thread model: _new_thread / _ensure_chat_threads / _find_thread / _get_active_thread ---


def test_new_thread_has_the_full_expected_shape(tmp_path, monkeypatch):
    _isolate_chat_settings(tmp_path, monkeypatch)
    thread = _new_thread()
    assert thread["id"].startswith("thread_")
    assert thread["title"] == "New chat"
    assert thread["summary"] == ""
    assert thread["messages"] == []
    assert thread["provider"] is None
    assert thread["model"] is None
    assert thread["pending"] is False
    assert thread["created_at"] == thread["updated_at"]


def test_new_thread_prefills_provider_and_model_from_the_last_explicit_chat_pick(tmp_path, monkeypatch):
    """Real, confirmed operator complaint: /new (and a server restart) used to reset the chat
    picker to blank ("same as main agent") every time, even after the operator had explicitly
    picked a different provider/model in chat -- see agent/tools/chat_settings_store.py's own
    last_provider/last_model docstring."""
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_last_chat_llm("ollama", "big-pickle")

    thread = _new_thread()

    assert thread["provider"] == "ollama"
    assert thread["model"] == "big-pickle"


def test_ensure_chat_threads_creates_a_default_thread_when_nothing_exists():
    session = _session("usr_t1")
    threads, active_id = _ensure_chat_threads(session)
    assert len(threads) == 1
    assert active_id == threads[0]["id"]
    assert session["chat_threads"] is threads
    assert session["active_chat_thread_id"] == active_id


def test_ensure_chat_threads_migrates_an_old_flat_chat_into_one_thread():
    session = _session("usr_t2", chat={
        "summary": "old summary", "messages": [{"role": "user", "content": "hi", "at": "t1"}, {"role": "assistant", "content": "hello", "at": "t2"}],
        "provider": "qwen", "model": "qwen-max", "pending": False,
    })

    threads, active_id = _ensure_chat_threads(session)

    assert "chat" not in session  # old key dropped
    assert len(threads) == 1
    thread = threads[0]
    assert thread["id"] == active_id
    assert thread["title"] == "Chat"
    assert thread["summary"] == "old summary"
    assert thread["provider"] == "qwen"
    assert thread["model"] == "qwen-max"
    assert len(thread["messages"]) == 2
    assert thread["messages"][0] == {"role": "user", "at": "t1", "segments": [{"type": "text", "content": "hi"}]}
    assert thread["messages"][1]["segments"] == [{"type": "text", "content": "hello"}]


def test_ensure_chat_threads_backfills_missing_fields_on_an_old_thread():
    session = {"chat_threads": [{"id": "thread_old", "messages": []}]}
    threads, active_id = _ensure_chat_threads(session)
    thread = threads[0]
    assert thread["title"] == "New chat"
    assert thread["summary"] == ""
    assert thread["provider"] is None
    assert thread["pending"] is False
    assert "created_at" in thread and "updated_at" in thread


def test_ensure_chat_threads_resets_active_id_when_it_points_nowhere():
    session = {"chat_threads": [{"id": "thread_a", "messages": []}], "active_chat_thread_id": "thread_gone"}
    threads, active_id = _ensure_chat_threads(session)
    assert active_id == "thread_a"
    assert session["active_chat_thread_id"] == "thread_a"


def test_ensure_chat_threads_is_idempotent_on_a_second_call():
    session = _session("usr_t3")
    threads1, active1 = _ensure_chat_threads(session)
    threads2, active2 = _ensure_chat_threads(session)
    assert threads1 is threads2
    assert active1 == active2


def test_find_thread_returns_none_for_unknown_id():
    session = _session("usr_t4")
    _ensure_chat_threads(session)
    assert _find_thread(session, "does-not-exist") is None


def test_get_active_thread_creates_one_if_the_list_is_somehow_empty():
    session = {"chat_threads": [], "active_chat_thread_id": None}
    thread = _get_active_thread(session)
    assert thread is not None
    assert session["chat_threads"] == [thread]


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


# --- correct_finding: _resolve_finding_ref + _apply_chat_finding_correction ---


def _finding(**overrides):
    finding = {"title": "Reflected XSS", "severity": "Medium", "qualifies_for_bounty": "unclear", "false_positive_reason": None}
    finding.update(overrides)
    return finding


def test_resolve_finding_ref_by_snapshot_id_matches_session_snapshots_own_numbering():
    # Must stay 1-indexed in list order -- the exact same rule _session_snapshot uses to stamp
    # "id": "F1"/"F2" onto each entry, and chat_ref (macros/ui.html) uses to label each card.
    session = _session("usr1", findings=[_finding(title="A"), _finding(title="B")])
    assert _resolve_finding_ref(session, "F1")["title"] == "A"
    assert _resolve_finding_ref(session, "f2")["title"] == "B"  # case-insensitive
    assert _resolve_finding_ref(session, "F3") is None  # out of range


def test_resolve_finding_ref_falls_back_to_exact_title():
    session = _session("usr1", findings=[_finding(title="Reflected XSS")])
    assert _resolve_finding_ref(session, "Reflected XSS") is not None
    assert _resolve_finding_ref(session, "reflected xss") is None  # exact match only, unlike F#


def test_apply_chat_finding_correction_updates_severity_and_keeps_the_original():
    session = _session("usr1", findings=[_finding(severity="Medium")])
    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        reply = _apply_chat_finding_correction("usr1", {
            "finding_ref": "F1", "corrected_severity": "high",
            "reasoning": "Confirmed a real credentialed session is reachable via the reflected payload.",
        })
    finding = session["findings"][0]
    assert finding["severity"] == "High"
    assert finding["original_severity"] == "Medium"  # never silently lost
    assert "severity" in reply
    mock_save.assert_called_once_with("usr1", session)


def test_apply_chat_finding_correction_requires_reasoning():
    session = _session("usr1", findings=[_finding()])
    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        reply = _apply_chat_finding_correction("usr1", {"finding_ref": "F1", "corrected_severity": "High"})
    assert "reasoning" in reply.lower()
    assert session["findings"][0]["severity"] == "Medium"  # untouched
    mock_save.assert_not_called()


def test_apply_chat_finding_correction_reports_unknown_ref_without_saving():
    session = _session("usr1", findings=[_finding()])
    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        reply = _apply_chat_finding_correction("usr1", {"finding_ref": "F9", "reasoning": "typo'd the ref"})
    assert "F9" in reply
    mock_save.assert_not_called()


def test_apply_chat_finding_correction_noop_when_nothing_actually_changes():
    session = _session("usr1", findings=[_finding(severity="High")])
    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        reply = _apply_chat_finding_correction("usr1", {
            "finding_ref": "F1", "corrected_severity": "High", "reasoning": "already correct",
        })
    assert "nothing" in reply.lower()
    mock_save.assert_not_called()


def test_handle_tool_calls_correct_finding_routes_through_to_the_session():
    session = _session("usr1", findings=[_finding()])
    call = ToolCallRequest(id="call_1", name="correct_finding", arguments={
        "finding_ref": "F1", "corrected_qualifies_for_bounty": "qualifying",
        "reasoning": "Operator confirmed a live PoC against production.",
    })
    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        reply = _handle_tool_calls("usr1", [call])
    assert session["findings"][0]["qualifies_for_bounty"] == "qualifying"
    assert "qualifies_for_bounty" in reply


# --- _chat_tool_specs: resolves data/chat_settings.json's two toggles into real ToolSpecs ---


def _isolate_chat_settings(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store
    monkeypatch.setattr(chat_settings_store, "CHAT_SETTINGS_STORE_PATH", tmp_path / "chat_settings.json")


def test_chat_tool_specs_both_enabled_includes_web_fetch_and_every_browser_tool(tmp_path, monkeypatch):
    from agent.core import _BROWSER_TOOL_NAMES
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(True, True)

    names = {spec.name for spec in _chat_tool_specs()}

    assert "web_fetch" in names
    assert _BROWSER_TOOL_NAMES <= names


def test_chat_tool_specs_both_disabled_is_empty(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, False, False)

    assert _chat_tool_specs() == []


def test_chat_tool_specs_includes_dork_search_when_enabled(tmp_path, monkeypatch):
    """dork_engine_enabled defaults True (a low-risk, read-mostly capability, same posture as
    web_fetch/browser) -- so an explicit save with it on offers dork_search, same shape as
    test_chat_tool_specs_both_enabled_includes_web_fetch_and_every_browser_tool above."""
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, False, True)

    names = {spec.name for spec in _chat_tool_specs()}

    assert names == {"dork_search"}


def test_chat_tool_specs_subagents_enabled_but_no_profile_configured_omits_delegation(tmp_path, monkeypatch):
    """subagents_enabled alone isn't enough -- delegate_to_subagent is meaningless with zero
    enabled Subagent profiles, same gate agent/core.py's own _subagent_delegation_extras applies."""
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, True, False)
    monkeypatch.setattr("agent.chat.get_enabled_profiles", lambda *a, **k: [])

    assert _chat_tool_specs() == []


def test_chat_tool_specs_subagents_enabled_with_a_profile_includes_delegation_tools(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, True, False)
    monkeypatch.setattr("agent.chat.get_enabled_profiles", lambda *a, **k: [{"name": "recon-helper"}])

    names = {spec.name for spec in _chat_tool_specs()}

    assert names == {"delegate_to_subagent", "check_subagent_task"}


def test_chat_tool_specs_interactive_mode_forces_delegation_regardless_of_toggle(tmp_path, monkeypatch):
    """Interactive/Reverse-Engineering mode is the backbone use case for delegate_to_subagent (the
    only way those consoles reach the heavy nmap/sqlmap/ffuf arsenal) -- offered even with the
    chat_settings toggle off, unlike plain "agent" mode chat just above."""
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, False, False)
    monkeypatch.setattr("agent.chat.get_enabled_profiles", lambda *a, **k: [{"name": "recon-helper"}])

    names = {spec.name for spec in _chat_tool_specs(mode="interactive")}

    assert names == {"delegate_to_subagent", "check_subagent_task"}


def test_chat_tool_specs_standalone_mode_respects_the_toggle_like_agent_mode(tmp_path, monkeypatch):
    """mode="standalone" (the top-level, project-less Quick Chat) has no scan of its own to be the
    backbone of, unlike interactive/reverse_engineering just above -- it stays opt-in via the
    chat_settings toggle, same safe-by-default posture as an ordinary project's own "agent" mode
    chat, even with a Subagent profile enabled."""
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, False, False)
    monkeypatch.setattr("agent.chat.get_enabled_profiles", lambda: [{"name": "recon-helper"}])

    assert _chat_tool_specs(mode="standalone") == []


# --- _chat_tool_specs: the native toolkit's own four tools, gated by a SEPARATE settings store
# (data/toolkit_agent_settings.json, agent/tools/toolkit_settings_store.py) -- not chat_settings.json,
# since the same four toggles also gate the main agent's phases and subagent delegation. ---


def _isolate_toolkit_settings(tmp_path, monkeypatch):
    from agent.tools import toolkit_settings_store
    monkeypatch.setattr(toolkit_settings_store, "TOOLKIT_AGENT_SETTINGS_STORE_PATH", tmp_path / "toolkit_agent_settings.json")


def test_chat_tool_specs_omits_toolkit_tools_when_every_toggle_is_off(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    _isolate_toolkit_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, False, False)

    assert _chat_tool_specs() == []


def test_chat_tool_specs_includes_only_the_enabled_toolkit_tool(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store, toolkit_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    _isolate_toolkit_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, False, False)
    toolkit_settings_store.save_toolkit_agent_settings({"toolkit_decoder_enabled": True})

    names = {spec.name for spec in _chat_tool_specs()}

    assert names == {"decode_value"}


def test_chat_tool_specs_includes_every_enabled_toolkit_tool_alongside_web_fetch(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store, toolkit_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    _isolate_toolkit_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(True, False, False, False)
    toolkit_settings_store.save_toolkit_agent_settings({
        "toolkit_proxy_enabled": True, "toolkit_repeater_enabled": True,
        "toolkit_decoder_enabled": True, "toolkit_comparer_enabled": True, "toolkit_intruder_enabled": True,
        "toolkit_sequencer_enabled": True,
    })

    names = {spec.name for spec in _chat_tool_specs()}

    assert names == {
        "web_fetch", "list_captured_traffic", "send_raw_request", "decode_value", "diff_requests",
        "intruder_run", "sequencer_analyze",
    }


def test_chat_subagent_addendum_empty_when_subagents_disabled(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, False)
    monkeypatch.setattr("agent.chat.get_enabled_profiles", lambda: [{"name": "Default Subagent - helper"}])

    assert _chat_subagent_addendum() == ""


def test_chat_subagent_addendum_empty_when_no_profile_enabled(tmp_path, monkeypatch):
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, True)
    monkeypatch.setattr("agent.chat.get_enabled_profiles", lambda *a, **k: [])

    assert _chat_subagent_addendum() == ""


def test_chat_subagent_addendum_names_the_real_enabled_profile(tmp_path, monkeypatch):
    """Regression: delegate_to_subagent's tool description only ever said "an enabled Subagent
    profile" with no concrete name in the conversation, so the chat model had nothing to go on
    but a guess (e.g. "subfinder", a tool name sitting inside a profile's own allowed_tools list)
    instead of the profile's real name ("Default Subagent - helper"), and every such guess failed
    get_profile_by_name's lookup with "no enabled subagent named ...". The addendum must name the
    real, enabled profile so the model has something concrete to pass as subagent_name."""
    from agent.tools import chat_settings_store
    _isolate_chat_settings(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(False, False, True)
    monkeypatch.setattr("agent.chat.get_enabled_profiles", lambda *a, **k: [{"name": "Default Subagent - helper"}])

    addendum = _chat_subagent_addendum()

    assert "Default Subagent - helper" in addendum
    assert "subagent_name" in addendum


# --- _compact_if_needed / _run_compaction: automatic (size-triggered) and manual (unconditional) ---


def _thread(messages=None, **overrides):
    thread = {
        "id": "thread_x", "title": "New chat", "summary": "", "messages": messages or [],
        "provider": None, "model": None, "pending": False, "created_at": "t0", "updated_at": "t0",
    }
    thread.update(overrides)
    return thread


def _msg(role, text, at="t"):
    return {"role": role, "at": at, "segments": [{"type": "text", "content": text}]}


def test_compact_if_needed_skips_when_under_budget():
    llm = SimpleNamespace(context_limit=128000, complete=MagicMock())
    thread = _thread(messages=[_msg("user", "hi")])

    _run(_compact_if_needed(llm, thread, "usr_x"))

    llm.complete.assert_not_called()
    assert len(thread["messages"]) == 1


def test_compact_if_needed_triggers_and_replaces_summary_when_over_budget():
    llm = SimpleNamespace(context_limit=100, complete=MagicMock(return_value=LLMResponse(content="Condensed summary.")))
    messages = [_msg("user", "message " * 50, at=str(i)) for i in range(10)]
    thread = _thread(messages=messages, summary="old summary")

    _run(_compact_if_needed(llm, thread, "usr_y"))

    llm.complete.assert_called_once()
    assert thread["summary"] == "Condensed summary."
    # 4 most recent kept verbatim, in their real segment shape, plus a persisted "this happened"
    # system note (chat_messages.html renders it centered/muted, like the one-off compact flash).
    assert len(thread["messages"]) == 5
    assert thread["messages"][-2]["segments"] == messages[-1]["segments"]
    assert thread["messages"][-1]["role"] == "system"
    assert "compacted" in thread["messages"][-1]["segments"][0]["content"].lower()


def test_compact_if_needed_noop_when_too_few_messages_to_retire():
    llm = SimpleNamespace(context_limit=1, complete=MagicMock())  # budget always exceeded
    thread = _thread(messages=[_msg("user", "hi")])

    _run(_compact_if_needed(llm, thread, "usr_z"))

    llm.complete.assert_not_called()


def test_run_compaction_returns_false_when_too_short():
    llm = SimpleNamespace(complete=MagicMock())
    thread = _thread(messages=[_msg("user", "hi")])

    did = _run(_run_compaction(llm, thread, "usr_short"))

    assert did is False
    llm.complete.assert_not_called()


def test_run_compaction_includes_manual_instructions_in_the_prompt():
    llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="Summary.")))
    messages = [_msg("user", f"message {i}", at=str(i)) for i in range(6)]
    thread = _thread(messages=messages)

    did = _run(_run_compaction(llm, thread, "usr_manual", instructions="focus on the login flow"))

    assert did is True
    sent_content = llm.complete.call_args[0][0][1]["content"]
    assert "focus on the login flow" in sent_content


# --- append_pending_chat_message: the fast, synchronous half of a chat turn ---


def test_append_pending_chat_message_appends_to_active_thread_and_sets_pending():
    session = _session("usr_ap1")

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result_session, started = append_pending_chat_message("usr_ap1", "hello", None, None)

    assert result_session is session
    assert started is True
    thread = session["chat_threads"][0]
    assert thread["pending"] is True
    assert thread["messages"][-1]["role"] == "user"
    assert thread["messages"][-1]["segments"] == [{"type": "text", "content": "hello"}]
    mock_save.assert_called_once()


def test_append_pending_chat_message_auto_titles_a_brand_new_thread():
    session = _session("usr_ap_title")

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        append_pending_chat_message("usr_ap_title", "what did the scan find?", None, None)

    assert session["chat_threads"][0]["title"] == "what did the scan find?"


def test_append_pending_chat_message_truncates_a_long_title():
    session = _session("usr_ap_title_long")
    long_message = "a" * 80

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        append_pending_chat_message("usr_ap_title_long", long_message, None, None)

    title = session["chat_threads"][0]["title"]
    assert title.endswith("…")
    assert len(title) == 41  # 40 chars + the ellipsis marker


def test_append_pending_chat_message_never_retitles_a_thread_with_existing_history():
    session = _session("usr_ap_notitle")
    _ensure_chat_threads(session)
    session["chat_threads"][0]["title"] = "Chat"  # simulates a migrated thread with real history
    session["chat_threads"][0]["messages"] = [_msg("user", "old message")]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        append_pending_chat_message("usr_ap_notitle", "a brand new question", None, None)

    assert session["chat_threads"][0]["title"] == "Chat"


def test_append_pending_chat_message_queues_when_already_pending():
    """A second message while the thread's own previous turn is still pending is no longer a
    silent no-op -- it's queued (Claude Code CLI-style, agent/chat.py's thread["queued_messages"]),
    dispatched automatically once the in-flight turn (and anything queued ahead of it) finishes --
    see run_chat_turn_background's own queue-drain loop."""
    session = _session("usr_ap2")
    _ensure_chat_threads(session)
    session["chat_threads"][0]["pending"] = True

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result_session, started = append_pending_chat_message("usr_ap2", "second message while first is in flight", None, None)

    assert result_session is session
    assert started is False
    mock_save.assert_called_once()
    assert session["chat_threads"][0]["messages"] == []
    queued = session["chat_threads"][0]["queued_messages"]
    assert len(queued) == 1
    assert queued[0]["text"] == "second message while first is in flight"


def test_cancel_queued_chat_message_removes_only_the_matching_entry():
    session = _session("usr_cancel_q")
    _ensure_chat_threads(session)
    thread_id = session["active_chat_thread_id"]
    session["chat_threads"][0]["queued_messages"] = [
        {"id": "q1", "text": "keep this one queued", "at": "2026-01-01T00:00:00+00:00"},
        {"id": "q2", "text": "cancel this one", "at": "2026-01-01T00:00:01+00:00"},
    ]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result = cancel_queued_chat_message("usr_cancel_q", thread_id, "q2")

    assert result is session
    mock_save.assert_called_once()
    remaining = session["chat_threads"][0]["queued_messages"]
    assert [m["id"] for m in remaining] == ["q1"]


def test_cancel_queued_chat_message_unknown_thread_returns_none():
    session = _session("usr_cancel_q_missing")
    _ensure_chat_threads(session)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result = cancel_queued_chat_message("usr_cancel_q_missing", "thread_does_not_exist", "q1")

    assert result is None
    mock_save.assert_not_called()


def test_append_pending_chat_message_persists_provider_and_model_when_given():
    session = _session("usr_ap3")

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        append_pending_chat_message("usr_ap3", "hi", "qwen", "qwen-max")

    thread = session["chat_threads"][0]
    assert thread["provider"] == "qwen"
    assert thread["model"] == "qwen-max"


def test_append_pending_chat_message_remembers_the_explicit_pick_for_the_next_new_thread():
    """The other half of the /new-reset-to-blank fix: an explicit pick made while sending a message
    must be readable back via chat_settings_store, not just stored on this one thread."""
    from agent.tools import chat_settings_store
    session = _session("usr_ap_remember")

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        append_pending_chat_message("usr_ap_remember", "hi", "ollama", "big-pickle")

    settings = chat_settings_store.load_chat_settings()
    assert settings["last_provider"] == "ollama"
    assert settings["last_model"] == "big-pickle"


def test_append_pending_chat_message_leaves_the_remembered_pick_untouched_when_omitted():
    """A bare "resend" call site (provider=model=None, per this function's own docstring) must not
    reset chat_settings_store's remembered pick back to blank."""
    from agent.tools import chat_settings_store
    chat_settings_store.save_last_chat_llm("ollama", "big-pickle")
    session = _session("usr_ap_no_reset")

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        append_pending_chat_message("usr_ap_no_reset", "hi", None, None)

    settings = chat_settings_store.load_chat_settings()
    assert settings["last_provider"] == "ollama"
    assert settings["last_model"] == "big-pickle"


def test_append_pending_chat_message_unknown_session_raises():
    with patch("agent.chat.load_session", return_value=None):
        with pytest.raises(ValueError, match="Unknown session"):
            append_pending_chat_message("usr_missing", "hi", None, None)


# --- thread management: new / switch / list ---


def test_start_new_chat_thread_appends_and_activates_a_fresh_thread():
    session = _session("usr_new")
    _ensure_chat_threads(session)
    first_id = session["active_chat_thread_id"]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = start_new_chat_thread("usr_new")

    assert len(result["chat_threads"]) == 2
    assert result["active_chat_thread_id"] != first_id


def test_switch_chat_thread_activates_the_requested_thread():
    session = _session("usr_switch")
    _ensure_chat_threads(session)
    session["chat_threads"].append({**_new_thread(), "id": "thread_other"})

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = switch_chat_thread("usr_switch", "thread_other")

    assert result["active_chat_thread_id"] == "thread_other"


def test_switch_chat_thread_returns_none_for_unknown_thread():
    session = _session("usr_switch2")
    _ensure_chat_threads(session)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result = switch_chat_thread("usr_switch2", "does-not-exist")

    assert result is None
    mock_save.assert_not_called()


def test_list_chat_threads_returns_newest_first():
    session = _session("usr_list")
    session["chat_threads"] = [
        {**_new_thread(), "id": "thread_old", "updated_at": "2026-01-01T00:00:00+00:00"},
        {**_new_thread(), "id": "thread_new", "updated_at": "2026-06-01T00:00:00+00:00"},
    ]
    session["active_chat_thread_id"] = "thread_new"

    with patch("agent.chat.load_session", return_value=session):
        threads = list_chat_threads("usr_list")

    assert [t["id"] for t in threads] == ["thread_new", "thread_old"]


def test_delete_chat_thread_removes_a_non_active_thread():
    session = _session("usr_del1")
    _ensure_chat_threads(session)
    active_id = session["active_chat_thread_id"]
    session["chat_threads"].append({**_new_thread(), "id": "thread_other"})

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = delete_chat_thread("usr_del1", "thread_other")

    assert {t["id"] for t in result["chat_threads"]} == {active_id}
    assert result["active_chat_thread_id"] == active_id  # untouched, the deleted thread wasn't active
    assert result["deleted_chat_thread_ids"] == ["thread_other"]


def test_delete_chat_thread_switches_active_when_deleting_the_active_one():
    session = _session("usr_del2")
    session["chat_threads"] = [
        {**_new_thread(), "id": "thread_a", "updated_at": "2026-01-01T00:00:00+00:00"},
        {**_new_thread(), "id": "thread_b", "updated_at": "2026-06-01T00:00:00+00:00"},
    ]
    session["active_chat_thread_id"] = "thread_a"

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = delete_chat_thread("usr_del2", "thread_a")

    assert {t["id"] for t in result["chat_threads"]} == {"thread_b"}
    assert result["active_chat_thread_id"] == "thread_b"  # the most recently updated survivor


def test_delete_chat_thread_creates_a_fresh_thread_when_deleting_the_last_one():
    session = _session("usr_del3")
    _ensure_chat_threads(session)
    only_id = session["active_chat_thread_id"]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = delete_chat_thread("usr_del3", only_id)

    assert len(result["chat_threads"]) == 1
    assert result["chat_threads"][0]["id"] != only_id
    assert result["active_chat_thread_id"] == result["chat_threads"][0]["id"]


def test_delete_chat_thread_returns_none_for_unknown_thread():
    session = _session("usr_del4")
    _ensure_chat_threads(session)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result = delete_chat_thread("usr_del4", "does-not-exist")

    assert result is None
    mock_save.assert_not_called()


# --- rename_chat_thread / set_chat_thread_color: chat tab strip parity with the Terminal tab strip ---


def test_rename_chat_thread_sets_a_new_title():
    session = _session("usr_rename1")
    _ensure_chat_threads(session)
    thread_id = session["active_chat_thread_id"]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = rename_chat_thread("usr_rename1", thread_id, "Bug bounty notes")

    assert result["chat_threads"][0]["title"] == "Bug bounty notes"


def test_rename_chat_thread_ignores_a_blank_title():
    session = _session("usr_rename2")
    _ensure_chat_threads(session)
    thread_id = session["active_chat_thread_id"]
    session["chat_threads"][0]["title"] = "Kept as-is"

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = rename_chat_thread("usr_rename2", thread_id, "   ")

    assert result["chat_threads"][0]["title"] == "Kept as-is"


def test_rename_chat_thread_truncates_to_the_same_max_length_as_auto_titling():
    session = _session("usr_rename3")
    _ensure_chat_threads(session)
    thread_id = session["active_chat_thread_id"]
    long_title = "x" * 100

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = rename_chat_thread("usr_rename3", thread_id, long_title)

    assert len(result["chat_threads"][0]["title"]) == _TITLE_MAX_CHARS


def test_rename_chat_thread_returns_none_for_unknown_thread():
    session = _session("usr_rename4")
    _ensure_chat_threads(session)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result = rename_chat_thread("usr_rename4", "does-not-exist", "New title")

    assert result is None
    mock_save.assert_not_called()


def test_set_chat_thread_color_stores_a_valid_hex_value():
    session = _session("usr_color1")
    _ensure_chat_threads(session)
    thread_id = session["active_chat_thread_id"]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = set_chat_thread_color("usr_color1", thread_id, "#a50303")

    assert result["chat_threads"][0]["color"] == "#a50303"


def test_set_chat_thread_color_none_clears_it():
    session = _session("usr_color2")
    _ensure_chat_threads(session)
    thread_id = session["active_chat_thread_id"]
    session["chat_threads"][0]["color"] = "#a50303"

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = set_chat_thread_color("usr_color2", thread_id, None)

    assert result["chat_threads"][0]["color"] is None


def test_set_chat_thread_color_rejects_a_malformed_value_instead_of_storing_garbage():
    # The real picker is always a native <input type="color">, which can't produce anything else --
    # this is the defensive backstop for a stray/malformed client value, never trusting it blindly.
    session = _session("usr_color3")
    _ensure_chat_threads(session)
    thread_id = session["active_chat_thread_id"]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        result = set_chat_thread_color("usr_color3", thread_id, "javascript:alert(1)")

    assert result["chat_threads"][0]["color"] is None


def test_set_chat_thread_color_returns_none_for_unknown_thread():
    session = _session("usr_color4")
    _ensure_chat_threads(session)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        result = set_chat_thread_color("usr_color4", "does-not-exist", "#a50303")

    assert result is None
    mock_save.assert_not_called()


# --- reconcile_orphaned_chat_threads: startup recovery for a thread stuck pending from a dead process ---


def test_reconcile_orphaned_chat_threads_clears_pending_and_the_queue():
    data = {
        "chat_threads": [{
            **_new_thread(), "id": "thread_1", "pending": True,
            "queued_messages": [{"id": "q1", "text": "still there?", "at": "2026-01-01T00:00:00+00:00"}],
            "messages": [_msg("user", "hi")],
        }],
    }

    reconcile_orphaned_chat_threads("usr_orphan", data)

    thread = data["chat_threads"][0]
    assert thread["pending"] is False
    assert thread["queued_messages"] == []
    last_segment = thread["messages"][-1]["segments"][-1]
    assert last_segment["error"] is True
    assert "Interrupted" in last_segment["content"]


def test_reconcile_orphaned_chat_threads_leaves_a_non_pending_thread_untouched():
    original_messages = [_msg("user", "hi"), _msg("assistant", "done")]
    data = {"chat_threads": [{**_new_thread(), "id": "thread_1", "pending": False, "messages": original_messages}]}

    reconcile_orphaned_chat_threads("usr_not_stuck", data)

    assert data["chat_threads"][0]["messages"] == original_messages


def test_reconcile_orphaned_chat_threads_handles_a_session_with_no_chat_threads_at_all():
    data = {"target": "example.com"}
    reconcile_orphaned_chat_threads("usr_no_chat", data)  # must not raise
    assert "chat_threads" not in data


# --- incremental persistence: _reload_active_message / _append_segment_and_save / _update_last_tool_call_segment_and_save ---


def test_append_segment_and_save_creates_the_assistant_message_stub_on_first_segment():
    thread_id = "thread_seg1"
    session = _session("usr_seg1", chat_threads=[{**_new_thread(), "id": thread_id, "messages": [_msg("user", "hi")]}], active_chat_thread_id=thread_id)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        _append_segment_and_save("usr_seg1", thread_id, {"type": "text", "content": "partial reply"})

    thread = session["chat_threads"][0]
    assert thread["messages"][-1]["role"] == "assistant"
    assert thread["messages"][-1]["segments"] == [{"type": "text", "content": "partial reply"}]
    mock_save.assert_called_once()


def test_append_segment_and_save_appends_to_the_same_in_progress_assistant_message():
    thread_id = "thread_seg2"
    session = _session("usr_seg2", chat_threads=[{**_new_thread(), "id": thread_id, "messages": [_msg("user", "hi")]}], active_chat_thread_id=thread_id)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        _append_segment_and_save("usr_seg2", thread_id, {"type": "text", "content": "first"})
        _append_segment_and_save("usr_seg2", thread_id, {"type": "tool_call", "id": "c1", "name": "web_fetch"})

    thread = session["chat_threads"][0]
    assert len(thread["messages"]) == 2  # one user, one assistant -- not a new assistant message per segment
    assert len(thread["messages"][-1]["segments"]) == 2


def test_append_segment_and_save_is_a_noop_when_thread_vanished():
    with patch("agent.chat.load_session", return_value=_session("usr_seg_gone")), patch("agent.chat.save_session") as mock_save:
        _append_segment_and_save("usr_seg_gone", "does-not-exist", {"type": "text", "content": "x"})
    mock_save.assert_not_called()


def test_update_last_tool_call_segment_and_save_mutates_the_matching_segment():
    thread_id = "thread_seg3"
    session = _session("usr_seg3", chat_threads=[{
        **_new_thread(), "id": thread_id,
        "messages": [_msg("user", "hi"), {"role": "assistant", "at": "t", "segments": [
            {"type": "tool_call", "id": "c1", "name": "web_fetch", "arguments": {}, "output": None, "error": False, "done": False},
        ]}],
    }], active_chat_thread_id=thread_id)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"):
        _update_last_tool_call_segment_and_save("usr_seg3", thread_id, "c1", output="ok result", error=False, done=True)

    seg = session["chat_threads"][0]["messages"][-1]["segments"][0]
    assert seg["output"] == "ok result"
    assert seg["done"] is True


def test_deliver_subagent_result_to_chat_appends_an_assistant_message_and_saves():
    thread_id = "thread_subagent_deliver"
    session = _session("usr_subagent_deliver", chat_threads=[{**_new_thread(), "id": thread_id, "messages": [_msg("user", "use a subagent")]}], active_chat_thread_id=thread_id)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        deliver_subagent_result_to_chat("usr_subagent_deliver", thread_id, "Recon Bot", {"outcome": "done", "result": {"summary": "found 3 subdomains"}})

    thread = session["chat_threads"][0]
    delivered = thread["messages"][-1]
    # role="assistant", not "user" -- a "user"-role message renders right-aligned as if the
    # operator had typed it (chat_messages.html), and role="system" would be stripped before
    # ever being replayed into the model's own context on its next turn (run_chat_turn_background).
    assert delivered["role"] == "assistant"
    text = delivered["segments"][0]["content"]
    assert "Recon Bot" in text
    assert "found 3 subdomains" in text
    # Regression: this used to be a raw json.dumps() of the whole result dict -- plain prose only,
    # no leftover JSON punctuation from the wrapper shape.
    assert '"summary"' not in text
    assert "{" not in text
    mock_save.assert_called_once()


def test_format_subagent_result_for_chat_renders_summary_and_details_as_prose():
    text = _format_subagent_result_for_chat("Recon Bot", "done", {"summary": "Found one subdomain: api.openai.com.", "details": "Seen via crt.sh.", "tool": "report_subagent_result"})

    assert text == "Subagent 'Recon Bot' finished.\n\nFound one subdomain: api.openai.com.\n\nSeen via crt.sh."


def test_format_subagent_result_for_chat_omits_details_when_absent():
    text = _format_subagent_result_for_chat("Recon Bot", "done", {"summary": "Found one subdomain.", "details": None, "tool": "report_subagent_result"})

    assert text == "Subagent 'Recon Bot' finished.\n\nFound one subdomain."


def test_format_subagent_result_for_chat_surfaces_an_error_outcome_plainly():
    text = _format_subagent_result_for_chat("Recon Bot", "error", {"error": "provider outage"})

    assert text == "Subagent 'Recon Bot' failed.\n\nprovider outage"


def test_format_subagent_result_for_chat_handles_a_bare_status_with_no_result():
    text = _format_subagent_result_for_chat("Recon Bot", "killed", None)

    assert text == "Subagent 'Recon Bot' was killed (the operator stopped the session)."


def test_deliver_subagent_result_to_chat_is_a_noop_when_session_vanished():
    with patch("agent.chat.load_session", return_value=None), patch("agent.chat.save_session") as mock_save:
        deliver_subagent_result_to_chat("usr_gone", "thread1", "Recon Bot", {"outcome": "done", "result": {}})
    mock_save.assert_not_called()


def test_deliver_subagent_result_to_chat_is_a_noop_when_thread_vanished():
    """The originating thread can be deleted (agent/chat.py's delete_chat_thread) in the window
    between delegation and the subagent's own async completion -- an expected, real possibility
    for a push arriving well after the fact, not an error condition."""
    session = _session("usr_thread_gone", chat_threads=[])
    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save:
        deliver_subagent_result_to_chat("usr_thread_gone", "does-not-exist", "Recon Bot", {"outcome": "done", "result": {}})
    mock_save.assert_not_called()


def test_append_segment_and_save_reloads_fresh_so_concurrent_scan_writes_survive():
    """The real race this guards against (same class of bug as the whole-thread version this
    generalizes): the live scan loop persists a new finding somewhere BETWEEN two incremental
    chat saves (e.g. right after a tool_call-pending segment is saved, before its own done=True
    update lands). Each incremental save does exactly one fresh load immediately before its own
    one save -- modeled here by having load_session already reflect the scan's own concurrent
    write by the time THIS call runs (i.e. it landed on disk before this call started, the
    realistic case for two genuinely separate save_session calls racing on the filesystem).
    """
    thread_id = "thread_race"
    session_with_scan_write = _session(
        "usr_seg_race", findings=[{"title": "New finding from the live scan loop"}],
        chat_threads=[{**_new_thread(), "id": thread_id, "messages": [_msg("user", "hi")]}], active_chat_thread_id=thread_id,
    )
    saved = {}

    def fake_save_session(session_id, data):
        saved["data"] = data

    with patch("agent.chat.load_session", return_value=session_with_scan_write), patch("agent.chat.save_session", side_effect=fake_save_session):
        _append_segment_and_save("usr_seg_race", thread_id, {"type": "tool_call", "id": "c1", "name": "web_fetch", "arguments": {}, "output": None, "error": False, "done": False})

    assert saved["data"]["findings"] == [{"title": "New finding from the live scan loop"}]
    thread = next(t for t in saved["data"]["chat_threads"] if t["id"] == thread_id)
    assert thread["messages"][-1]["segments"][-1]["name"] == "web_fetch"


# --- _run_chat_tool_loop: the real, bounded LLM<->tools conversation for one chat turn ---


def _ctx(session_id="usr_loop"):
    session = {"session_id": session_id, "target": "x", "status": "completed", "findings": [], "logs": [], "out_of_scope": []}
    return RunContext(llm=None, session=session, session_id=session_id)


def _patch_chat_persistence(session, thread_id):
    """Routes _append_segment_and_save/_update_last_tool_call_segment_and_save's own internal
    load_session/save_session calls at the in-memory `session`/its thread directly, so
    _run_chat_tool_loop tests can assert on the final segment shape without a real store."""
    def fake_load(session_id):
        return session

    def fake_save(session_id, data):
        pass

    return patch("agent.chat.load_session", side_effect=fake_load), patch("agent.chat.save_session", side_effect=fake_save)


def test_run_chat_tool_loop_returns_content_immediately_when_no_tool_calls():
    ctx = _ctx()
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="Plain answer, no tools needed.")))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "hi")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, []))

    assert reply == "Plain answer, no tools needed."
    ctx.llm.complete.assert_called_once()
    assert session["chat_threads"][0]["messages"][-1]["segments"] == [{"type": "text", "content": "Plain answer, no tools needed."}]


def test_run_chat_tool_loop_flags_a_narrated_fake_tool_call():
    """Real, confirmed incident (session hcm-usr_15eee7): the provider's own tool_calls came back
    empty, yet the reply narrated "[used custom_re_script(...) -> ok]" plus fabricated-looking
    output as if a real tool had actually run. _looks_like_narrated_fake_tool_call must catch this
    and mark the segment, not silently persist it as an ordinary trusted reply."""
    ctx = _ctx("usr_loop_fake_tool")
    narrated = (
        "Запущу крекми через wine с вводом `debugCall32`.\n"
        '[used custom_re_script(import subprocess\nresult = subprocess.run(["wine", "x.exe"])) -> ok]\n'
        "Wine не установлен в этой среде."
    )
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content=narrated, tool_calls=[])))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "try debugCall32"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "try it")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, []))

    assert reply == narrated
    segment = session["chat_threads"][0]["messages"][-1]["segments"][0]
    assert segment["suspected_fake_tool_call"] is True


def test_run_chat_tool_loop_does_not_flag_an_ordinary_reply():
    ctx = _ctx("usr_loop_ordinary")
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="I recommend checking the login form next.", tool_calls=[])))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what next?"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "what next?")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, []))

    segment = session["chat_threads"][0]["messages"][-1]["segments"][0]
    assert "suspected_fake_tool_call" not in segment


def test_run_chat_tool_loop_still_handles_skip_finding_via_the_instruction_queue():
    ctx = _ctx("usr_loop_skip")
    tool_call = ToolCallRequest(id="c1", name="skip_finding", arguments={"finding_title": "Reflected XSS"})
    responses = [
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="Done, marked it skipped.", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "skip the XSS finding"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "skip it")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, []))

    assert reply == "Done, marked it skipped."
    queue = get_instruction_queue("usr_loop_skip")
    assert queue.get_nowait() == {"type": "skip_finding", "finding_title": "Reflected XSS"}


def test_run_chat_tool_loop_suggest_next_steps_appends_a_suggested_actions_segment():
    ctx = _ctx("usr_loop_suggest")
    tool_call = ToolCallRequest(id="c1", name="suggest_next_steps", arguments={"steps": ["Check the login form for SQLi", "Decompile main()"]})
    responses = [
        LLMResponse(content="Here's what I found.", tool_calls=[tool_call]),
        LLMResponse(content="", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what next?"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "what next?")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="interactive"))

    segments = session["chat_threads"][0]["messages"][-1]["segments"]
    actions_segment = next(s for s in segments if s["type"] == "suggested_actions")
    assert actions_segment["actions"] == ["Check the login form for SQLi", "Decompile main()"]


def test_run_chat_tool_loop_suggest_next_steps_unavailable_in_agent_mode():
    """suggest_next_steps is only offered when mode != "agent" (_INTERACTIVE_CHAT_TOOLS_SCHEMA's own
    gate) -- if a model calls it anyway (e.g. it leaked in from earlier history), the dispatch falls
    through to "unknown tool" exactly like any other tool that isn't actually in this turn's schema,
    rather than silently honoring it in a mode with no Findings panel or novice-onboarding UX to
    justify it."""
    ctx = _ctx("usr_loop_suggest_agent")
    tool_call = ToolCallRequest(id="c1", name="suggest_next_steps", arguments={"steps": ["Check the login form"]})
    responses = [
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="Okay.", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "what next?"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "what next?")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="agent"))

    segments = session["chat_threads"][0]["messages"][-1]["segments"]
    assert not any(s["type"] == "suggested_actions" for s in segments)
    tool_segment = next(s for s in segments if s["type"] == "tool_call")
    assert tool_segment["error"] is True
    assert "unknown tool" in tool_segment["output"]


def test_run_chat_tool_loop_skip_finding_unavailable_in_standalone_mode():
    """mode="standalone" (the top-level, project-less Quick Chat) has no session findings to
    skip/correct and no running scan phase to steer -- skip_finding/add_guidance/correct_finding
    stay excluded there (this module's own bookkeeping_schema filter), and even a model that calls
    one anyway falls through to "unknown tool" instead of silently queuing an instruction nothing
    will ever drain."""
    ctx = _ctx("usr_loop_skip_standalone")
    tool_call = ToolCallRequest(id="c1", name="skip_finding", arguments={"finding_title": "Reflected XSS"})
    responses = [
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="Okay.", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "skip the XSS finding"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "skip it")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [], mode="standalone"))

    segments = session["chat_threads"][0]["messages"][-1]["segments"]
    tool_segment = next(s for s in segments if s["type"] == "tool_call")
    assert tool_segment["error"] is True
    assert "unknown tool" in tool_segment["output"]


def test_run_chat_tool_loop_dispatches_a_real_tool_and_persists_segments_incrementally():
    ctx = _ctx("usr_loop_fetch")
    web_fetch_spec = get_tool("web_fetch")
    tool_call = ToolCallRequest(id="c1", name="web_fetch", arguments={"target": "https://example.com"})
    responses = [
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="The page says hello.", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "read https://example.com"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "read it")]}], active_chat_thread_id="thread_1")
    fake_result = {"status": "ok", "url": "https://example.com", "text": "hello"}

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value=fake_result)) as mock_dispatch:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [web_fetch_spec]))

    assert reply == "The page says hello."
    mock_dispatch.assert_called_once_with(ctx, web_fetch_spec, {"target": "https://example.com"})
    segments = session["chat_threads"][0]["messages"][-1]["segments"]
    tool_segment = next(s for s in segments if s["type"] == "tool_call")
    assert tool_segment["done"] is True
    assert tool_segment["error"] is False
    assert tool_segment["arg_summary"] == "https://example.com"
    assert json.loads(tool_segment["output"]) == fake_result
    assert segments[-1] == {"type": "text", "content": "The page says hello."}


def test_run_chat_tool_loop_tags_delegate_to_subagent_calls_with_the_chat_thread_id():
    """Regression: agent/core.py's _on_subagent_task_done had no way to tell a chat-triggered
    delegation apart from an ordinary scan-phase one, so a finished chat-delegated subagent's
    result was pushed into the shared instruction queue only a live scan's own phase loop ever
    drains -- chat never drained it, so the result was never seen again anywhere (visible in
    debug.log as a real, completed run; invisible in the chat panel). The fix threads the
    originating thread_id through as "_chat_thread_id" so it can be delivered back to THIS thread
    instead. Also confirms call.arguments itself is never mutated in place -- that same dict
    object is already referenced by the persisted tool_call segment appended just before dispatch,
    and this internal field must never leak into what the operator sees there."""
    ctx = _ctx("usr_loop_delegate")
    delegate_spec = get_tool("delegate_to_subagent")
    original_arguments = {"subagent_name": "Recon Bot", "task_description": "check subdomains"}
    tool_call = ToolCallRequest(id="c1", name="delegate_to_subagent", arguments=original_arguments)
    responses = [
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="Delegated it.", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "use a subagent"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "use a subagent")]}], active_chat_thread_id="thread_1")
    fake_result = {"status": "ok", "task_id": "abc123"}

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value=fake_result)) as mock_dispatch:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [delegate_spec]))

    assert reply == "Delegated it."
    mock_dispatch.assert_called_once_with(ctx, delegate_spec, {**original_arguments, "_chat_thread_id": "thread_1"})
    # The original arguments dict (already captured in the persisted tool_call segment) was never
    # mutated in place -- a NEW dict was passed to _run_tool_with_retry instead.
    assert original_arguments == {"subagent_name": "Recon Bot", "task_description": "check subdomains"}


def test_run_chat_tool_loop_marks_a_failed_tool_call_as_error():
    ctx = _ctx("usr_loop_fail")
    web_fetch_spec = get_tool("web_fetch")
    tool_call = ToolCallRequest(id="c1", name="web_fetch", arguments={"target": "https://example.com"})
    responses = [
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="That failed.", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "read it"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "read it")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value={"status": "error", "error": "boom"})):
        _run(_run_chat_tool_loop(ctx, "thread_1", messages, [web_fetch_spec]))

    tool_segment = next(s for s in session["chat_threads"][0]["messages"][-1]["segments"] if s["type"] == "tool_call")
    assert tool_segment["error"] is True
    assert tool_segment["done"] is True


def test_run_chat_tool_loop_resolves_the_segment_even_when_dispatch_itself_raises():
    """Real, confirmed incident this fixes (live session Safety-Bug-Bounty-usr_158b31):
    _run_tool_with_retry's own 1-Step-Retry correction call can itself raise (its own nested LLM
    call hit a provider outage/context-limit error, unrelated to this tool's own dispatch) -- that
    exception used to propagate straight out of the loop, skipping the done=True update entirely.
    The tool_call segment stayed stuck mid-spinner forever (chat_messages.html gates the spinner on
    "not seg.done"), which also meant the chat form's own pending-detection (a spinner still
    present) kept it disabled long after the turn had actually ended. The segment must resolve
    first, THEN the real exception still propagates -- the operator still needs to see the real
    cause via run_chat_turn_background's own outer handler.
    """
    ctx = _ctx("usr_loop_dispatch_raises")
    web_fetch_spec = get_tool("web_fetch")
    tool_call = ToolCallRequest(id="c1", name="web_fetch", arguments={"target": "https://example.com"})
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content=None, tool_calls=[tool_call])))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "read it"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "read it")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2, patch("agent.chat._run_tool_with_retry", new=AsyncMock(side_effect=RuntimeError("nested correction call blew up"))):
        with pytest.raises(RuntimeError, match="nested correction call blew up"):
            _run(_run_chat_tool_loop(ctx, "thread_1", messages, [web_fetch_spec]))

    tool_segment = next(s for s in session["chat_threads"][0]["messages"][-1]["segments"] if s["type"] == "tool_call")
    assert tool_segment["done"] is True
    assert tool_segment["error"] is True
    assert "nested correction call blew up" in tool_segment["output"]


def test_run_chat_tool_loop_reports_an_unknown_tool_without_crashing():
    ctx = _ctx("usr_loop_unknown")
    tool_call = ToolCallRequest(id="c1", name="nmap_scan", arguments={"target": "example.com"})
    responses = [
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="I can't run that.", tool_calls=[]),
    ]
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=responses))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "run nmap"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "run nmap")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, []))  # nmap_scan not in the enabled tool set

    assert reply == "I can't run that."
    tool_segment = next(s for s in session["chat_threads"][0]["messages"][-1]["segments"] if s["type"] == "tool_call")
    assert "unknown tool" in tool_segment["output"]


def test_run_chat_tool_loop_falls_back_to_the_generic_message_when_even_the_summary_call_fails(monkeypatch):
    # The mock here always returns a tool_calls response, including for the post-budget summary
    # call (tools=None is a request-shape hint, not something a mock respects on its own) -- content
    # comes back None every time, so the summary attempt itself produces nothing usable and this
    # correctly falls back to the plain apology rather than silently returning an empty reply.
    # Default budget is unlimited (0) -- give this test a finite one so it actually exhausts instead
    # of looping forever against a MagicMock that never returns a final answer.
    monkeypatch.setattr(chat, "_CHAT_MAX_TOOL_ITERATIONS", 3)
    ctx = _ctx("usr_loop_budget")
    web_fetch_spec = get_tool("web_fetch")
    ctx.llm = SimpleNamespace(complete=MagicMock(
        return_value=LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="web_fetch", arguments={"target": "https://example.com"})])
    ))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "keep looking"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "keep looking")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value={"status": "ok"})):
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [web_fetch_spec]))

    assert "tool budget" in reply


def test_run_chat_tool_loop_summarizes_real_progress_once_the_budget_runs_out(monkeypatch):
    """Real, confirmed operator complaint this fixes: exhausting the budget used to discard every
    real tool result already sitting in the conversation and return a flat "try again in smaller
    steps" apology -- a genuinely multi-step browser investigation (several real, useful actions)
    looked like it had accomplished nothing at all. Now one final no-tools call asks the model to
    summarize what it actually found from that same history instead of just giving up."""
    # Default budget is unlimited (0) -- give this test a finite one so there's an actual budget to
    # exhaust; a real operator who wants this ceiling back sets CHAT_MAX_TOOL_ITERATIONS themselves.
    monkeypatch.setattr(chat, "_CHAT_MAX_TOOL_ITERATIONS", 3)
    ctx = _ctx("usr_loop_budget2")
    web_fetch_spec = get_tool("web_fetch")
    tool_call_response = LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="web_fetch", arguments={"target": "https://example.com"})])
    summary_response = LLMResponse(content="Confirmed the login form is reachable; could not finish checking the CSRF token before running out of budget.")
    ctx.llm = SimpleNamespace(complete=MagicMock(side_effect=[tool_call_response] * chat._CHAT_MAX_TOOL_ITERATIONS + [summary_response]))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "keep looking"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "keep looking")]}], active_chat_thread_id="thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2, patch("agent.chat._run_tool_with_retry", new=AsyncMock(return_value={"status": "ok"})):
        reply = _run(_run_chat_tool_loop(ctx, "thread_1", messages, [web_fetch_spec]))

    assert reply == summary_response.content
    # The final call must have been made WITHOUT tools -- otherwise the model could just try (and
    # fail) a 21st tool call instead of actually answering.
    final_call_args = ctx.llm.complete.call_args_list[-1]
    assert final_call_args.args[1] is None


def test_run_chat_tool_loop_raises_chat_stop_requested_when_the_operator_stops_it():
    """The Stop button's own checkpoint (main.py's /chat/stop route -> request_chat_stop) -- must
    be noticed BEFORE the loop's first LLM call even runs, mirroring agent/core.py's own pre-call
    stop check in _llm_complete."""
    ctx = _ctx("usr_loop_stop")
    ctx.llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="should never be reached")))
    messages = [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}]
    session = _session(ctx.session_id, chat_threads=[{**_new_thread(), "id": "thread_1", "messages": [_msg("user", "hi")]}], active_chat_thread_id="thread_1")
    request_chat_stop(ctx.session_id, "thread_1")

    p1, p2 = _patch_chat_persistence(session, "thread_1")
    with p1, p2:
        with pytest.raises(ChatStopRequested):
            _run(_run_chat_tool_loop(ctx, "thread_1", messages, []))

    ctx.llm.complete.assert_not_called()


def test_complete_or_stop_aborts_while_the_llm_call_is_still_running():
    """Real, confirmed incident this fixes: a between-call-only checkpoint (the version above) can
    never interrupt a call already IN FLIGHT, no matter how long it still has left to run — and a
    typical chat reply finishes in 2-10 seconds, often faster than an operator can even register
    "thinking…" and click Stop, let alone have that click land before the call was going to finish
    on its own anyway (confirmed live, `123-usr_dbd8cd`, 2026-08-18: every recorded Stop click
    landed on a call that simply finished normally a few seconds later, `stopped=False`).
    _complete_or_stop must actually stop WAITING on the call the instant Stop fires, not just note
    the flag for whenever the next call happens to start."""
    import time as time_module

    ctx = _ctx("usr_complete_or_stop")

    def slow_complete(messages, tools=None, stop_check=None):
        time_module.sleep(0.3)
        return LLMResponse(content="finished too late to matter")

    ctx.llm = SimpleNamespace(complete=slow_complete)

    async def _run_and_time():
        stop_event = get_chat_stop_event(ctx.session_id, "thread_1")

        async def _stop_soon():
            await asyncio.sleep(0.05)
            stop_event.set()

        asyncio.ensure_future(_stop_soon())
        start = asyncio.get_event_loop().time()
        with pytest.raises(ChatStopRequested):
            await _complete_or_stop(ctx, "thread_1", [], None)
        return asyncio.get_event_loop().time() - start

    elapsed = _run(_run_and_time())
    assert elapsed < 0.2  # raised well before the 0.3s "network call" itself finished


# --- _format_llm_error: raw provider exception -> an operator-actionable message ---


def _api_status_error(status_code: int, message: str = "error") -> openai.APIStatusError:
    request = SimpleNamespace(method="POST", url="https://example.test/v1/chat/completions")
    response = SimpleNamespace(status_code=status_code, headers={}, request=request)
    return openai.APIStatusError(message, response=response, body=None)


def test_format_llm_error_429_names_it_a_rate_limit_and_names_the_provider_at_fault():
    message = _format_llm_error(_api_status_error(429), "opencode-zen", "big-pickle")
    assert "opencode-zen/big-pickle" in message
    assert "429" in message
    assert "rate limit" in message.lower()
    assert "not an ASRA bug" in message


def test_format_llm_error_401_names_it_an_auth_failure():
    message = _format_llm_error(_api_status_error(401), "openai", "gpt-4o")
    assert "authentication failed" in message.lower()


def _api_status_error_with_body(status_code: int, body: object) -> openai.APIStatusError:
    request = SimpleNamespace(method="POST", url="https://example.test/v1/chat/completions")
    response = SimpleNamespace(status_code=status_code, headers={}, request=request)
    return openai.APIStatusError("error", response=response, body=body)


def test_format_llm_error_401_with_a_model_error_body_shows_the_real_reason_not_an_auth_claim():
    """Real, confirmed incident (debug.log, opencode-zen): the provider returned HTTP 401 with body
    {'error': {'type': 'ModelError', 'message': 'Model  is not supported'}} -- a plain unsupported-
    model error dressed up as a 401. The code-only path called it "authentication failed — the API
    key is missing or invalid", sending the operator to fix a key that was never the problem. The
    body's own message must win, cleaned of the stray double space."""
    body = {"type": "error", "error": {"type": "ModelError", "message": "Model  is not supported"}}
    message = _format_llm_error(_api_status_error_with_body(401, body), "opencode-zen", "nemotron-3.5-lightning-free")
    assert "Model is not supported" in message  # double space collapsed
    assert "authentication failed" not in message.lower()
    assert "api key" not in message.lower()
    assert "not an ASRA bug" in message
    assert "opencode-zen/nemotron-3.5-lightning-free" in message


def test_format_llm_error_prefers_a_top_level_body_message_too():
    message = _format_llm_error(_api_status_error_with_body(400, {"message": "context length exceeded"}), "qwen", "qwen-plus")
    assert "context length exceeded" in message


def test_format_llm_error_redacts_a_key_echoed_back_in_the_body():
    """Some providers echo the submitted key back inside a malformed-auth error body; this string
    lands straight on the Settings page, so any key-shaped token must be redacted before display --
    the same leak the key-masking there exists to prevent."""
    leaked = "Incorrect API key provided: sk-abcdef0123456789ABCDEFxyz. Check your key."
    message = _format_llm_error(_api_status_error_with_body(401, {"error": {"message": leaked}}), "openai", "gpt-4o")
    assert "sk-abcdef0123456789ABCDEFxyz" not in message
    assert "***" in message


def test_format_llm_error_401_with_no_body_still_falls_back_to_the_auth_explanation():
    """A genuine 401 with an empty body keeps the old, correct code-based explanation -- the body
    message only overrides it when there actually is one."""
    message = _format_llm_error(_api_status_error(401), "openai", "gpt-4o")
    assert "authentication failed" in message.lower()


def test_format_llm_error_5xx_names_it_a_provider_outage():
    message = _format_llm_error(_api_status_error(503), "openai", "gpt-4o")
    assert "servers are having trouble" in message


def test_format_llm_error_unrecognized_status_still_names_the_provider():
    message = _format_llm_error(_api_status_error(418), "openai", "gpt-4o")
    assert "418" in message
    assert "openai/gpt-4o" in message


def test_format_llm_error_connection_failure_is_not_reported_as_a_bug():
    exc = openai.APIConnectionError(request=SimpleNamespace(method="POST", url="https://example.test/v1/chat/completions"))
    message = _format_llm_error(exc, "openai", "gpt-4o")
    assert "not an ASRA bug" in message
    assert "openai/gpt-4o" in message


def test_format_llm_error_falls_back_to_the_plain_exception_for_unrecognized_error_types():
    message = _format_llm_error(RuntimeError("boom"), "openai", "gpt-4o")
    assert "boom" in message


def test_format_llm_error_labels_missing_provider_model_as_defaults():
    message = _format_llm_error(_api_status_error(429), None, None)
    assert "(main agent default)/(default)" in message


# --- run_chat_turn_background: the LLM half, run as a FastAPI BackgroundTask ---


def _pending_session(session_id: str, user_message: str = "what did the scan find?", **thread_overrides) -> dict:
    thread = {**_new_thread(), "id": "thread_1", "messages": [_msg("user", user_message)], "pending": True}
    thread.update(thread_overrides)
    return _session(session_id, chat_threads=[thread], active_chat_thread_id="thread_1")


def test_run_chat_turn_background_plain_reply_persists_exchange_and_clears_pending():
    session = _pending_session("usr_bg1")
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(return_value=LLMResponse(content="It found nothing.")))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save, patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        _run(run_chat_turn_background("usr_bg1"))

    assert mock_save.call_count >= 1
    saved_session = mock_save.call_args[0][1]
    thread = saved_session["chat_threads"][0]
    assert thread["messages"][-1]["segments"] == [{"type": "text", "content": "It found nothing."}]
    assert thread["messages"][-1]["role"] == "assistant"
    assert thread["pending"] is False


def test_run_chat_turn_background_does_not_duplicate_pending_message_when_compaction_runs_mid_turn():
    """Real regression caught in the same turn the compaction system-note was added: _run_compaction
    slices+reassigns thread["messages"] and appends its own trailing "system" note BEFORE the
    pending user message is re-added as this turn's own final message -- if that pending message
    were matched by POSITION ("the last element") instead of object identity, it would get replayed
    twice the moment a compaction note becomes the new actual last element mid-turn."""
    prior = [_msg("user" if i % 2 == 0 else "assistant", "message " * 50, at=str(i)) for i in range(10)]
    pending_text = "what did the scan find?"
    pending = _msg("user", pending_text, at="pending")
    session = _pending_session("usr_bg_dup", user_message=pending_text, messages=prior + [pending])
    fake_llm = SimpleNamespace(
        context_limit=100,  # forces _compact_if_needed to actually run this turn
        complete=MagicMock(side_effect=[LLMResponse(content="Condensed summary."), LLMResponse(content="Final answer.")]),
    )

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"), patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        _run(run_chat_turn_background("usr_bg_dup"))

    # First complete() call is the compaction's own; the second is the real turn's own opening call.
    assert fake_llm.complete.call_count == 2
    real_turn_messages = fake_llm.complete.call_args_list[1][0][0]
    occurrences = sum(1 for m in real_turn_messages if m.get("content") == pending_text)
    assert occurrences == 1


def test_run_chat_turn_background_tool_call_reply_queues_and_confirms():
    # side_effect (not return_value): the loop's budget is unlimited by default, so a mock that
    # always returns a tool call and never a final answer would spin forever here instead of
    # exercising the one real call this test cares about.
    tool_call = ToolCallRequest(id="call_1", name="add_guidance", arguments={"text": "check the API"})
    session = _pending_session("usr_bg2", user_message="please check the API")
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(side_effect=[
        LLMResponse(content=None, tool_calls=[tool_call]),
        LLMResponse(content="Noted, I'll check the API.", tool_calls=[]),
    ]))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"), patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        _run(run_chat_turn_background("usr_bg2"))

    queue = get_instruction_queue("usr_bg2")
    assert queue.get_nowait() == {"type": "add_guidance", "text": "check the API"}


def test_run_chat_turn_background_does_not_replay_a_past_failure_notice_to_a_later_turn():
    """Real, confirmed incident: a rate-limit error from one turn used to get replayed as the
    model's OWN past conversation history on the NEXT turn -- it then kept refusing to even
    attempt delegate_to_subagent, citing "the rate-limit error" from a turn that had nothing to do
    with the current one. Two real turns in the SAME thread here: the first fails, the second
    succeeds -- the second call's own message history must not contain the first turn's error text.
    """
    session = _pending_session("usr_bg_history", provider="opencode-zen", model="big-pickle", user_message="use a subagent")
    failing_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(side_effect=_api_status_error(429, "FreeUsageLimitError")))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"), patch(
        "agent.chat.get_provider", return_value=failing_llm
    ):
        _run(run_chat_turn_background("usr_bg_history"))

    thread = session["chat_threads"][0]
    assert thread["messages"][-1]["segments"][-1]["error"] is True
    # A second, real user message -- same shape append_pending_chat_message itself would produce.
    thread["messages"].append({"role": "user", "at": "2026-01-01T00:00:01+00:00", "segments": [{"type": "text", "content": "use a subagent"}]})
    thread["pending"] = True

    succeeding_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(return_value=LLMResponse(content="Delegated it.", tool_calls=[])))
    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"), patch(
        "agent.chat.get_provider", return_value=succeeding_llm
    ):
        _run(run_chat_turn_background("usr_bg_history"))

    sent_messages = succeeding_llm.complete.call_args.args[0]
    # Excludes the system message -- CHAT_PROMPT itself legitimately mentions "rate limit" as a
    # general example; what must never appear is the CONVERSATION HISTORY replaying the actual
    # formatted failure notice from the earlier turn.
    history_content = " ".join(m.get("content", "") for m in sent_messages if m["role"] != "system")
    assert "returned HTTP 429" not in history_content
    assert "FreeUsageLimitError" not in history_content
    assert "opencode-zen/big-pickle" not in history_content


def test_run_chat_turn_background_passes_threads_own_provider_and_model_to_get_provider():
    session = _pending_session("usr_bg3", provider="qwen", model="qwen-max")
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(return_value=LLMResponse(content="ok")))
    fake_get_provider = MagicMock(return_value=fake_llm)

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"), patch(
        "agent.chat.get_provider", fake_get_provider
    ):
        _run(run_chat_turn_background("usr_bg3"))

    fake_get_provider.assert_called_once_with("qwen", "qwen-max")


def test_run_chat_turn_background_missing_session_is_a_noop():
    with patch("agent.chat.load_session", return_value=None), patch("agent.chat.save_session") as mock_save:
        _run(run_chat_turn_background("usr_gone"))

    mock_save.assert_not_called()


def test_run_chat_turn_background_recovers_gracefully_from_a_failed_llm_call():
    session = _pending_session("usr_bg_fail")
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(side_effect=RuntimeError("boom")))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save, patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        _run(run_chat_turn_background("usr_bg_fail"))

    saved_session = mock_save.call_args[0][1]
    thread = saved_session["chat_threads"][0]
    assert thread["pending"] is False
    assert "boom" in thread["messages"][-1]["segments"][-1]["content"]


def test_run_chat_turn_background_formats_a_provider_rate_limit_error_readably():
    """Real, confirmed operator complaint this fixes: a live 429 from opencode-zen's big-pickle
    model reached the operator as the raw stringified openai.APIStatusError -- a Python dict repr
    with no indication this was an external rate limit, not an ASRA bug."""
    session = _pending_session("usr_bg_429", provider="opencode-zen", model="big-pickle")
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(side_effect=_api_status_error(429, "FreeUsageLimitError")))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save, patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        _run(run_chat_turn_background("usr_bg_429"))

    saved_session = mock_save.call_args[0][1]
    reply = saved_session["chat_threads"][0]["messages"][-1]["segments"][-1]["content"]
    assert "opencode-zen/big-pickle" in reply
    assert "rate limit" in reply.lower()
    assert "{'type': 'error'" not in reply  # never the raw dict repr again


def test_run_chat_turn_background_reloads_fresh_before_final_pending_clear_so_concurrent_scan_writes_survive():
    """The real race this guards against: the live scan loop persists a new finding/log entry
    somewhere DURING this chat turn's own LLM call. save_session is a full-dict overwrite, not a
    merge -- if this function saved a stale snapshot, that concurrent write would be silently
    reverted. Simulated by having load_session return a different, "fresher" session on later
    calls than on its first.
    """
    stale_session = _pending_session("usr_race")
    fresh_session = {**stale_session, "findings": [{"title": "New finding from the live scan loop"}], "chat_threads": [dict(t) for t in stale_session["chat_threads"]]}
    load_calls = {"n": 0}

    def fake_load_session(session_id):
        load_calls["n"] += 1
        return stale_session if load_calls["n"] == 1 else fresh_session

    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(return_value=LLMResponse(content="ok")))
    saved = {}

    def fake_save_session(session_id, data):
        saved["data"] = data

    with patch("agent.chat.load_session", side_effect=fake_load_session), patch(
        "agent.chat.save_session", side_effect=fake_save_session
    ), patch("agent.chat.get_provider", return_value=fake_llm):
        _run(run_chat_turn_background("usr_race"))

    assert load_calls["n"] >= 2
    assert saved["data"]["findings"] == [{"title": "New finding from the live scan loop"}]
    thread = saved["data"]["chat_threads"][0]
    assert thread["messages"][-1]["segments"][-1]["content"] == "ok"
    assert thread["pending"] is False


def test_run_chat_turn_background_persists_a_stop_notice_and_clears_the_queue_on_stop():
    """A Stop click (main.py's /chat/stop route -> request_chat_stop) means "stop the chat", not
    just this one reply -- run_chat_turn_background must persist a distinct notice, clear pending,
    and drop anything the operator had queued behind it too (see run_chat_turn_background's own
    docstring for why), never silently ploughing on into a queued follow-up."""
    session = _pending_session(
        "usr_bg_stop", queued_messages=[{"id": "q1", "text": "a follow-up", "at": "2026-01-01T00:00:01+00:00"}],
    )
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(return_value=LLMResponse(content="should never be reached")))
    request_chat_stop("usr_bg_stop", "thread_1")

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save, patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        _run(run_chat_turn_background("usr_bg_stop"))

    fake_llm.complete.assert_not_called()
    saved_session = mock_save.call_args[0][1]
    thread = saved_session["chat_threads"][0]
    assert thread["pending"] is False
    assert thread["queued_messages"] == []
    last_segment = thread["messages"][-1]["segments"][-1]
    assert last_segment["content"] == "Stopped by the operator."
    assert last_segment["error"] is True
    # The single owner of clearing the signal, once the turn it belonged to has genuinely ended --
    # a later resumed turn on this same thread must not immediately re-trigger stop on its very
    # first LLM call just because a stale flag was left set (same guarantee agent/core.py's own
    # get_stop_event gives run_session).
    assert get_chat_stop_event("usr_bg_stop", "thread_1").is_set() is False


def test_run_chat_turn_background_drains_the_queue_after_a_turn_finishes():
    """Claude Code CLI-style message queue: a follow-up typed and sent while the first turn was
    still pending (agent/chat.py's append_pending_chat_message queuing it, thread["queued_
    messages"]) must be dispatched as its own real turn automatically once the first one finishes
    -- no operator action needed to "unstick" it."""
    session = _pending_session(
        "usr_bg_queue", user_message="first message",
        queued_messages=[{"id": "q1", "text": "second message", "at": "2026-01-01T00:00:01+00:00"}],
    )
    fake_llm = SimpleNamespace(context_limit=128000, complete=MagicMock(side_effect=[
        LLMResponse(content="first reply"),
        LLMResponse(content="second reply"),
    ]))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session"), patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        _run(run_chat_turn_background("usr_bg_queue"))

    assert fake_llm.complete.call_count == 2
    thread = session["chat_threads"][0]
    assert thread["pending"] is False
    assert thread["queued_messages"] == []
    user_texts = [_segments_to_text(m["segments"]) for m in thread["messages"] if m["role"] == "user"]
    assistant_texts = [_segments_to_text(m["segments"]) for m in thread["messages"] if m["role"] == "assistant"]
    assert user_texts == ["first message", "second message"]
    assert assistant_texts == ["first reply", "second reply"]


# --- compact_chat_thread: the manual /compact entry point ---


def test_compact_chat_thread_returns_false_and_does_not_save_when_too_short():
    session = _session("usr_compact_short")
    _ensure_chat_threads(session)
    session["chat_threads"][0]["messages"] = [_msg("user", "hi")]

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save, patch(
        "agent.chat.get_provider", return_value=SimpleNamespace(complete=MagicMock())
    ):
        did = _run(compact_chat_thread("usr_compact_short"))

    assert did is False
    mock_save.assert_not_called()


def test_compact_chat_thread_saves_when_it_actually_compacts():
    session = _session("usr_compact_real")
    _ensure_chat_threads(session)
    session["chat_threads"][0]["messages"] = [_msg("user", f"m{i}") for i in range(6)]
    fake_llm = SimpleNamespace(complete=MagicMock(return_value=LLMResponse(content="Summary.")))

    with patch("agent.chat.load_session", return_value=session), patch("agent.chat.save_session") as mock_save, patch(
        "agent.chat.get_provider", return_value=fake_llm
    ):
        did = _run(compact_chat_thread("usr_compact_real"))

    assert did is True
    mock_save.assert_called_once()
    assert session["chat_threads"][0]["summary"] == "Summary."
    # The operator asked to actually SEE that a manual /compact did something, not just infer it
    # from a shorter history -- a persisted system note, not just a one-off route-level flash.
    last_message = session["chat_threads"][0]["messages"][-1]
    assert last_message["role"] == "system"
    assert "compacted" in last_message["segments"][0]["content"].lower()


def test_compact_chat_thread_unknown_session_raises():
    with patch("agent.chat.load_session", return_value=None):
        with pytest.raises(ValueError, match="Unknown session"):
            _run(compact_chat_thread("usr_missing"))
