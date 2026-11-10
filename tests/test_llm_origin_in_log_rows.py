"""Every tool-activity row (Agent Logs card, Interactive/RE activity log, chat tool-call card) shows
which provider/model produced it and how long that LLM request took."""
from __future__ import annotations

import time
from types import SimpleNamespace

import main
from agent import core
from agent.llm_client import LLMResponse, describe_response_origin, stamp_response_origin


def _llm(provider_id="opencode-zen", model="big-pickle-2"):
    return SimpleNamespace(provider_id=provider_id, model=model)


def test_stamp_sets_origin_and_elapsed():
    started = time.monotonic() - 3.25
    stamped = stamp_response_origin(LLMResponse(content="hi"), _llm(), started)
    assert (stamped.provider_id, stamped.model) == ("opencode-zen", "big-pickle-2")
    assert 3.2 <= stamped.elapsed_seconds < 3.6
    assert stamped.content == "hi"  # nothing else about the response changes


def test_stamp_tolerates_an_llm_double_without_provider_attrs():
    stamped = stamp_response_origin(LLMResponse(content="x"), SimpleNamespace(), time.monotonic())
    assert describe_response_origin(stamped) is None  # unstamped -> no label, never a crash


def test_describe_origin_is_json_shaped():
    stamped = stamp_response_origin(LLMResponse(content="x"), _llm(), time.monotonic() - 1)
    origin = describe_response_origin(stamped)
    assert origin["provider"] == "opencode-zen" and origin["model"] == "big-pickle-2"
    assert isinstance(origin["elapsed_s"], float)


def test_append_log_persists_llm_origin(monkeypatch):
    monkeypatch.setattr(core, "save_session", lambda *_a, **_k: None)
    ctx = SimpleNamespace(
        session={"logs": []}, session_id="s", current_finding_title=None, subagent_task_id=None, subagent_name=None,
    )
    origin = {"provider": "p", "model": "m", "elapsed_s": 2.5}
    core._append_log(ctx, "recon", None, "nmap", "success", None, 10, "out", origin)
    core._append_log(ctx, "recon", None, None, "failed", "boom")
    assert ctx.session["logs"][0]["llm"] == origin
    assert ctx.session["logs"][1]["llm"] is None


def test_interactive_log_entries_carry_llm_from_chat_segments_and_re_logs():
    origin = {"provider": "openrouter", "model": "qwen3-coder", "elapsed_s": 4.0}
    session = {
        "chat_threads": [{"messages": [{"role": "assistant", "at": "2026-01-01T00:00:01+00:00",
                                        "segments": [{"type": "tool_call", "name": "web_fetch", "llm": origin}]}]}],
        "logs": [{"at": "2026-01-01T00:00:02+00:00", "command": "/usr/local/bin/radare2 -q", "status": "success", "llm": origin}],
    }
    entries = main._interactive_log_entries(session)
    assert [e["llm"] for e in entries] == [origin, origin]


def _render(template_name, **context):
    return main.templates.get_template(template_name).render(**context)


def test_interactive_log_row_shows_provider_model_and_seconds():
    entry = {"idx": 0, "at": "2026-11-09T19:45:00+00:00", "name": "/usr/local/bin/radare2", "arg_summary": "-q",
             "output": "x", "error": False, "done": True,
             "llm": {"provider": "opencode-zen", "model": "big-pickle-2", "elapsed_s": 3.24}}
    html = _render("partials/interactive_log.html", entries=[entry])
    assert "opencode-zen/big-pickle-2 &middot; LLM 3.2s" in html


def test_interactive_log_row_without_llm_renders_no_label():
    entry = {"idx": 0, "at": "2026-11-09T19:45:00+00:00", "name": "t", "arg_summary": "a",
             "output": "x", "error": False, "done": True, "llm": None}
    assert "&middot;" not in _render("partials/interactive_log.html", entries=[entry]).split("</summary>")[0]


def test_chat_tool_card_shows_origin():
    seg = {"type": "tool_call", "id": "c1", "name": "web_fetch", "arg_summary": "https://x", "output": "o",
           "error": False, "done": True, "llm": {"provider": "codex", "model": "gpt-5.1", "elapsed_s": 12.0}}
    message = {"role": "assistant", "at": "2026-11-09T19:45:00+00:00", "segments": [seg]}
    html = _render("partials/chat_messages.html", session={"session_id": "s", "mode": "interactive"},
                   thread={"messages": [message], "pending": False}, messages=[message])
    assert "codex/gpt-5.1 &middot; LLM 12.0s" in html


def test_agent_log_card_shows_origin():
    """Agent-mode's shared log_entry_card macro (Logs tab, per-phase tabs, subagent group)."""
    template = main.templates.get_template("partials/session_fragment.html")
    module = template.make_module({"session": {"status": "done", "findings": [], "logs": []}})
    entry = {"step": 1, "phase": "recon", "command": "nmap({})", "thought": None, "status": "success", "error": None,
             "output": None, "duration_ms": 1500, "at": "2026-11-09T19:45:00+00:00",
             "llm": {"provider": "nvidia", "model": "nemotron-70b", "elapsed_s": 7.84}}
    assert "nvidia/nemotron-70b &middot; LLM 7.8s" in str(module.log_entry_card(entry, "text-accent"))
    del entry["llm"]  # an entry written before this field existed must still render
    assert "nemotron" not in str(module.log_entry_card(entry, "text-accent"))


def test_human_duration_reads_long_waits_as_minutes():
    f = main._human_duration
    assert (f(None), f(850), f(8800), f(581_000), f(3_720_000)) == ("", "850ms", "8.8s", "9m 41s", "1h 02m")


def test_interactive_log_shows_the_finish_time_of_the_result_not_the_reply_creation_time():
    """Real incident: every tool call in one model reply showed the reply's creation time (23:30) even
    though a slow strace_run only finished at 23:42 -- the time read as 'in advance'."""
    session = {"chat_threads": [{"messages": [{"role": "assistant", "at": "2026-01-01T21:30:29+00:00", "segments": [
        {"type": "tool_call", "name": "strace_run", "done": True, "started_at": "2026-01-01T21:32:52+00:00",
         "finished_at": "2026-01-01T21:42:58+00:00", "duration_ms": 606000},
        {"type": "tool_call", "name": "old_row_without_new_fields", "done": True},
        {"type": "tool_call", "name": "still_running", "done": False, "started_at": "2026-01-01T21:43:00+00:00"},
    ]}]}]}
    by_name = {e["name"]: e for e in main._interactive_log_entries(session)}
    assert by_name["strace_run"]["at"] == "2026-01-01T21:42:58+00:00"
    assert by_name["strace_run"]["duration_ms"] == 606000
    assert by_name["old_row_without_new_fields"]["at"] == "2026-01-01T21:30:29+00:00"  # graceful fallback
    assert by_name["still_running"]["at"] is None  # no result yet -> no time claimed
    assert by_name["still_running"]["started_at"] == "2026-01-01T21:43:00+00:00"


def test_running_row_has_live_timer_and_no_time_or_llm_seconds_in_advance():
    entry = {"idx": 0, "at": None, "started_at": "2026-11-09T21:43:00+00:00", "duration_ms": None, "name": "strace_run",
             "arg_summary": "x", "output": None, "error": False, "done": False,
             "llm": {"provider": "openrouter", "model": "nemotron", "elapsed_s": 20.9}}
    summary = _render("partials/interactive_log.html", entries=[entry]).split("</summary>")[0]
    assert 'data-asra-elapsed-since="2026-11-09T21:43:00+00:00"' in summary
    assert "LLM 20.9s" not in summary and "openrouter/nemotron" in summary
    assert "2026" not in summary.replace("2026-11-09T21:43:00+00:00", "")  # no human timestamp yet


def test_finished_row_shows_llm_time_tool_time_and_finish_time_separately():
    entry = {"idx": 0, "at": "2026-11-09T21:42:58+00:00", "started_at": "x", "duration_ms": 581_000, "name": "strace_run",
             "arg_summary": "x", "output": "o", "error": False, "done": True,
             "llm": {"provider": "openrouter", "model": "nemotron", "elapsed_s": 20.9}}
    summary = _render("partials/interactive_log.html", entries=[entry]).split("</summary>")[0]
    assert "LLM 20.9s" in summary and "9m 41s" in summary and "09 Nov 2026" in summary


def _chat_html(seg, pending):
    message = {"role": "assistant", "at": "2026-11-09T19:45:00+00:00", "segments": [seg]}
    return _render("partials/chat_messages.html", session={"session_id": "s", "mode": "interactive"},
                   thread={"messages": [message], "pending": pending})


def test_chat_card_spinner_only_while_the_turn_is_really_running():
    seg = {"type": "tool_call", "id": "c1", "name": "radare2", "arg_summary": "x", "output": None,
           "error": False, "done": False, "started_at": "2026-11-09T21:43:00+00:00"}
    live = _chat_html(seg, pending=True)
    assert 'id="chat-tool-ind-c1-running"' in live and "(running" in live and "data-asra-elapsed-since" in live
    orphan = _chat_html(seg, pending=False)  # turn died before the result landed
    assert "asra-spinner" not in orphan.split("</summary>")[0] and "Interrupted" in orphan
    assert "(no output recorded)" in orphan


def test_chat_card_indicator_id_changes_with_state_so_morph_replaces_a_stale_spinner():
    failed = {"type": "tool_call", "id": "c1", "name": "radare2", "arg_summary": "x", "output": "{}", "error": True, "done": True}
    html = _chat_html(failed, pending=True)
    assert 'id="chat-tool-ind-c1-failed"' in html and "asra-spinner" not in html.split("</summary>")[0]
