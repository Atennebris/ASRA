"""_reload_merge_save (agent/core.py) and its use in _persist_new_finding / run_re_triage's own
finally block / run_re_reverify: a long-lived in-memory session snapshot (an entire RE triage pass,
a re-verify loop) must never blind-save itself over whatever a CONCURRENT writer already landed on
disk in the meantime -- e.g. the session's own chat panel recording a finding mid-pass via a fresh
load-append-save. Real, confirmed incident this fixes: a chat-recorded record_finding call fired its
storage-reward toast, then the RE triage pass it ran alongside ended and its own stale-snapshot save
silently wiped it back to session["findings"] == [] -- empty on the Findings tab, still empty after
a page reload, because it was genuinely never on disk by the time the pass finished.
"""
import asyncio

import agent.core as core
from agent.core import RunContext, _persist_new_finding, _reload_merge_save
from sessions import store

import pytest


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _base_session(session_id: str) -> dict:
    return {"session_id": session_id, "mode": "reverse_engineering", "logs": [], "findings": [],
            "target_profile": [], "hypotheses": [], "status": "processing"}


# --- _reload_merge_save: the shared primitive ---


def test_reload_merge_save_does_not_clobber_a_concurrent_write():
    session_id = "usr_race_test"
    store.save_session(session_id, _base_session(session_id))

    # Simulate a concurrent writer (e.g. the chat panel's own fresh-load-append-save) landing a
    # real change on disk AFTER our in-memory snapshot would have been taken.
    fresh = store.load_session(session_id)
    fresh["findings"].append({"title": "concurrently recorded finding"})
    store.save_session(session_id, fresh)

    # Our own call only wants to add ITS OWN field -- it must not see, and must not need to see,
    # the concurrent write above; _reload_merge_save reloads fresh on its own.
    _reload_merge_save(session_id, lambda s: s.__setitem__("status", "completed"))

    result = store.load_session(session_id)
    assert result["status"] == "completed"
    assert result["findings"] == [{"title": "concurrently recorded finding"}]


def test_reload_merge_save_returns_none_for_a_vanished_session():
    assert _reload_merge_save("usr_never_existed", lambda s: None) is None


# --- _persist_new_finding: the real call site this bug lived in ---


def test_persist_new_finding_preserves_a_finding_recorded_concurrently_on_disk():
    session_id = "usr_re_triage_test"
    session = _base_session(session_id)
    store.save_session(session_id, session)

    # ctx.session is what run_re_triage holds in memory for the whole pass -- loaded once, same
    # object identity throughout. It does NOT yet know about the finding the chat panel is about
    # to record concurrently.
    ctx = RunContext(llm=None, session=session, session_id=session_id)

    # The chat panel (a totally separate code path, agent/chat.py's _apply_chat_record_finding)
    # does its own fresh load-append-save while ctx.session above sits unaware in memory.
    concurrent = store.load_session(session_id)
    concurrent["findings"].append({"title": "chat-recorded finding", "source": "interactive"})
    store.save_session(session_id, concurrent)

    # Now the triage pass itself records ITS OWN finding via the normal path.
    result = asyncio.run(_persist_new_finding(ctx, {"title": "triage-recorded finding", "severity": "high"}))
    assert result is None  # no CORS conflict -- success

    on_disk = store.load_session(session_id)
    titles = {f["title"] for f in on_disk["findings"]}
    # Both findings must survive -- the chat-recorded one from the concurrent writer, and the one
    # this call itself just recorded. Before the fix, the concurrent one was silently wiped.
    assert titles == {"chat-recorded finding", "triage-recorded finding"}


def test_persist_new_finding_still_updates_ctx_session_in_memory():
    # The in-memory ctx.session must still reflect the new finding immediately -- same-pass logic
    # (e.g. a later CORS-conflict check against session["findings"]) reads ctx.session directly,
    # not a fresh reload, so the fix must not regress that.
    session_id = "usr_in_memory_test"
    session = _base_session(session_id)
    store.save_session(session_id, session)
    ctx = RunContext(llm=None, session=session, session_id=session_id)

    asyncio.run(_persist_new_finding(ctx, {"title": "in-memory check", "severity": "low"}))

    assert any(f["title"] == "in-memory check" for f in ctx.session["findings"])


# --- real-time notification on a Critical/High finding (agent/tools/notifications.py) -----------
# _persist_new_finding is the ONE real choke point every record_finding persistence path (Analyze,
# a deep dive, Reverify's carry-over/reconfirmation, Chain) already funnels through -- covers all
# of them from a single call site, real, confirmed by grepping every _persist_new_finding call
# site in agent/core.py, not eight separate notification hooks.


def test_persist_new_finding_notifies_on_a_critical_finding(monkeypatch):
    session_id = "usr_notify_critical"
    session = _base_session(session_id)
    session["name"] = "My Project"
    session["target"] = "example.com"
    store.save_session(session_id, session)
    ctx = RunContext(llm=None, session=session, session_id=session_id)
    notified = []
    monkeypatch.setattr(core, "notify_high_severity_finding", lambda *a: notified.append(a))

    asyncio.run(_persist_new_finding(ctx, {"title": "Remote Code Execution", "severity": "Critical"}))

    assert notified == [("My Project", "example.com", "Remote Code Execution", "Critical")]


def test_persist_new_finding_notifies_on_a_high_finding(monkeypatch):
    session_id = "usr_notify_high"
    session = _base_session(session_id)
    store.save_session(session_id, session)
    ctx = RunContext(llm=None, session=session, session_id=session_id)
    notified = []
    monkeypatch.setattr(core, "notify_high_severity_finding", lambda *a: notified.append(a))

    asyncio.run(_persist_new_finding(ctx, {"title": "SQL Injection", "severity": "High"}))

    assert len(notified) == 1


def test_persist_new_finding_does_not_notify_on_medium_or_low(monkeypatch):
    session_id = "usr_notify_medium_low"
    session = _base_session(session_id)
    store.save_session(session_id, session)
    ctx = RunContext(llm=None, session=session, session_id=session_id)
    notified = []
    monkeypatch.setattr(core, "notify_high_severity_finding", lambda *a: notified.append(a))

    asyncio.run(_persist_new_finding(ctx, {"title": "Missing header", "severity": "Medium"}))
    asyncio.run(_persist_new_finding(ctx, {"title": "Info disclosure", "severity": "Low"}))

    assert notified == []


def test_persist_new_finding_falls_back_to_session_id_without_a_name(monkeypatch):
    session_id = "usr_notify_no_name"
    session = _base_session(session_id)
    store.save_session(session_id, session)
    ctx = RunContext(llm=None, session=session, session_id=session_id)
    notified = []
    monkeypatch.setattr(core, "notify_high_severity_finding", lambda *a: notified.append(a))

    asyncio.run(_persist_new_finding(ctx, {"title": "Critical bug", "severity": "Critical"}))

    assert notified[0][0] == session_id
