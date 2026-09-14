"""Smoke tests: starting a session creates a real file, and its JSON structure is valid.

Every session now gets its own project folder (sessions/store.py + projects/paths.py) instead of
a flat data/sessions/<id>.json — these tests redirect all three storage knobs (legacy dir, index
file, and the PROJECTS_DIR a new folder is created under) into tmp_path, so a test run never
touches the real data/sessions/ or the user's actual Documents folder.
"""
import json
import re

import pytest

from projects import paths as project_paths
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    """Every test gets its own throwaway directories — never touches real storage."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    return tmp_path


def _project_session_file(base, session_id, target="example.com"):
    folder = f"{store._sanitize_folder_name(target)}-{session_id}"
    return base / "projects" / folder / "session.json"


def test_create_session_creates_its_own_project_folder(_isolated_storage):
    session_id = store.create_session("example.com")
    assert _project_session_file(_isolated_storage, session_id).exists()


def test_create_session_authorize_exploit_defaults_false(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["authorize_exploit"] is False


def test_create_session_stores_authorize_exploit_true(_isolated_storage):
    session_id = store.create_session("example.com", authorize_exploit=True)
    assert store.load_session(session_id)["authorize_exploit"] is True


def test_create_session_mode_defaults_to_agent(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["mode"] == "agent"


def test_create_session_stores_interactive_mode(_isolated_storage):
    # main.py's start_interactive passes an empty target (named in chat later) + mode="interactive".
    session_id = store.create_session("", name="CTF box", mode="interactive", initial_status="interactive")
    session = store.load_session(session_id)
    assert session["mode"] == "interactive"
    assert session["target"] == ""
    assert session["status"] == "interactive"


def test_create_session_assigns_a_random_valid_icon_and_color(_isolated_storage):
    from projects import icons
    session = store.load_session(store.create_session("example.com"))
    assert session["icon"] in icons.ICON_NAMES
    assert session["icon_color"] in icons.ICON_COLORS


def test_create_session_keeps_a_chosen_icon_and_color(_isolated_storage):
    from projects import icons
    session = store.load_session(store.create_session("example.com", icon=icons.ICON_NAMES[2], icon_color=icons.ICON_COLORS[3]))
    assert session["icon"] == icons.ICON_NAMES[2]
    assert session["icon_color"] == icons.ICON_COLORS[3]


def test_create_session_random_defaults_on_invalid_icon_and_color(_isolated_storage):
    from projects import icons
    session = store.load_session(store.create_session("example.com", icon="not-a-real-icon", icon_color="notacolor"))
    assert session["icon"] in icons.ICON_NAMES
    assert session["icon_color"] in icons.ICON_COLORS


def test_create_session_keeps_any_valid_hex_color(_isolated_storage):
    # The picker is a full-spectrum color input now -- any #rrggbb is kept, not just the palette.
    session = store.load_session(store.create_session("example.com", icon="bug", icon_color="#0aB3cD"))
    assert session["icon_color"] == "#0aB3cD"


def test_create_session_black_color_default_is_treated_as_unchosen(_isolated_storage):
    # Black is the picker's neutral default -- it must never stick (invisible on the dark UI); a
    # random visible color is assigned instead.
    from projects import icons
    session = store.load_session(store.create_session("example.com", icon="bug", icon_color="#000000"))
    assert session["icon_color"] != "#000000"
    assert session["icon_color"] in icons.ICON_COLORS


def test_build_summary_reports_mode(_isolated_storage):
    session_id = store.create_session("", name="CTF box", mode="interactive", initial_status="interactive")
    summary = next(s for s in store.list_session_summaries() if s["session_id"] == session_id)
    assert summary["mode"] == "interactive"


def test_build_summary_reports_has_pending_chat(_isolated_storage):
    """main.py's own startup reconciliation sweep (agent/chat.py's reconcile_orphaned_chat_threads)
    needs this cheap, cached flag to find a stuck chat thread without a full load_session() on
    every session -- see sessions/store.py's own _build_summary docstring for the real "364 MB
    session file" incident this discipline already exists to avoid at scale."""
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)
    session["chat_threads"] = [{"id": "thread_1", "pending": False}]
    store.save_session(session_id, session)
    summary = next(s for s in store.list_session_summaries() if s["session_id"] == session_id)
    assert summary["has_pending_chat"] is False

    session["chat_threads"][0]["pending"] = True
    store.save_session(session_id, session)
    summary = next(s for s in store.list_session_summaries() if s["session_id"] == session_id)
    assert summary["has_pending_chat"] is True


def test_create_session_hypotheses_defaults_to_empty(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["hypotheses"] == []


def test_create_session_pre_seeds_hypotheses_from_initial_hypotheses(_isolated_storage):
    session_id = store.create_session("example.com", initial_hypotheses=["staging debug mode might be on", "old /api/v1 might still be reachable"])
    hypotheses = store.load_session(session_id)["hypotheses"]

    assert len(hypotheses) == 2
    assert hypotheses[0]["text"] == "staging debug mode might be on"
    assert hypotheses[0]["source"] == "user"
    assert hypotheses[0]["source_phase"] == "pre_scan"
    assert hypotheses[0]["status"] == "unconfirmed"
    assert hypotheses[0]["id"] != hypotheses[1]["id"]


def test_create_session_status_defaults_to_pending(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["status"] == "pending"


def test_create_session_initial_status_overrides_the_default(_isolated_storage):
    """main.py's start_scan (the New Project form's "Create" button) passes initial_status=
    "created" so a freshly created project doesn't look "live" until its own later "Start" click
    -- every other caller (rescan_session, resume_session, the CLI entrypoint, every other test in
    this file) keeps relying on the "pending" default above, unaffected by this opt-in override."""
    session_id = store.create_session("example.com", initial_status="created")
    assert store.load_session(session_id)["status"] == "created"


def test_create_session_llm_provider_defaults_to_none(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["llm_provider"] is None


def test_create_session_stores_the_llm_provider_choice(_isolated_storage):
    session_id = store.create_session("example.com", llm_provider="qwen")
    assert store.load_session(session_id)["llm_provider"] == "qwen"


def test_create_session_identity_flags_default_false(_isolated_storage):
    session = store.load_session(store.create_session("example.com"))
    assert session["identity_a_configured"] is False
    assert session["identity_b_configured"] is False


def test_create_session_stores_identity_flags(_isolated_storage):
    session_id = store.create_session("example.com", identity_a_configured=True, identity_b_configured=True)
    session = store.load_session(session_id)
    assert session["identity_a_configured"] is True
    assert session["identity_b_configured"] is True


def test_save_session_retries_past_a_transient_permission_error(_isolated_storage, monkeypatch):
    """Real incident this fixes: os.replace() on a project folder's real path (a Windows-mounted
    DrvFs path even from inside WSL2) raced with something else briefly holding session.json open
    (the session page's own SSE stream re-reading it) and raised PermissionError, crashing
    run_session outright with no retry at all."""
    monkeypatch.setattr(store, "_REPLACE_RETRY_DELAY_SECONDS", 0)
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)

    real_replace = store.os.replace
    calls = {"count": 0}

    def flaky_replace(src, dst):
        calls["count"] += 1
        if calls["count"] < 3:
            raise PermissionError("simulated transient Windows file lock")
        return real_replace(src, dst)

    monkeypatch.setattr(store.os, "replace", flaky_replace)

    store.save_session(session_id, session)  # must not raise

    # 3 calls for session.json's own retry loop (2 simulated failures + the 3rd succeeding), plus
    # 1 more for save_session's own summary-cache update (sessions/store.py's _save_summary_index,
    # also os.replace()-based since it needs the same atomic-write guarantee as reload_merge_save)
    # -- by call 4 flaky_replace's own `< 3` condition no longer fires, so this one
    # just succeeds for real, same as the session.json write's own 3rd attempt did.
    assert calls["count"] == 4
    assert store.load_session(session_id) == session


def test_save_session_falls_back_to_a_direct_write_once_retries_are_exhausted(_isolated_storage, monkeypatch):
    """Real incident this fixes: os.replace() kept failing on one specific session's file across
    three separate server restarts, hours apart -- the block was specifically on the RENAME
    (something else held a handle without FILE_SHARE_DELETE), confirmed live by a plain in-place
    write to that same path succeeding instantly even while os.replace() kept failing. Losing the
    save outright after exhausting retries (the previous behavior) once left a session stuck
    showing status="processing" for hours with no way to resume/rescan it and a Stop button that
    did nothing real."""
    monkeypatch.setattr(store, "_REPLACE_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(store, "_REPLACE_RETRY_ATTEMPTS", 3)
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)
    session["status"] = "interrupted"

    def always_locked(src, dst):
        raise PermissionError("simulated persistent rename-only Windows file lock")

    monkeypatch.setattr(store.os, "replace", always_locked)

    store.save_session(session_id, session)  # must not raise

    assert store.load_session(session_id)["status"] == "interrupted"
    # No leftover .json.tmp artifact from the abandoned rename attempts.
    assert not store._session_path(session_id).with_suffix(".json.tmp").exists()


def test_save_session_skips_the_full_retry_budget_once_a_path_is_known_blocked(_isolated_storage, monkeypatch):
    """Real incident this fixes: a session left open in a browser tab (its SSE stream re-reading
    session.json for as long as the tab stays open) held the rename-blocking lock for the file's
    entire remaining lifetime, so every single subsequent save that whole run paid the full
    ~6s retry budget before falling back anyway -- minutes of pure wasted wall-clock time over a
    long session. Once a path has already needed the fallback once, a later save to that SAME path
    should try only once more (not the full budget) before falling back again."""
    monkeypatch.setattr(store, "_REPLACE_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(store, "_REPLACE_RETRY_ATTEMPTS", 30)
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)
    session["status"] = "interrupted"

    calls = {"count": 0}

    def always_locked(src, dst):
        calls["count"] += 1
        raise PermissionError("simulated persistent rename-only Windows file lock")

    monkeypatch.setattr(store.os, "replace", always_locked)

    store.save_session(session_id, session)
    # 30 for session.json's own retry loop (exhausted, learns the path is blocked), +1 more for
    # save_session's own summary-cache update (sessions/store.py's _save_summary_index, also
    # os.replace()-based for the same atomic-write reason as the main session write) -- that
    # extra call also hits this same always-failing monkeypatch,
    # caught by save_session's own try/except around the summary-cache update (a derived cache,
    # never worth failing the real save over).
    assert calls["count"] == 31  # first save: pays the full retry budget, learns the path is blocked

    calls["count"] = 0
    store.save_session(session_id, session)
    # 1 quick check for the now-known-blocked session.json path, +1 more for the summary-cache
    # update above (which has no "known blocked" fast path of its own -- it's a small, cheap write
    # every time, not worth the same tracking machinery session.json's real data needs).
    assert calls["count"] == 2  # second save to the same path: one quick check, straight to fallback
    assert store.load_session(session_id)["status"] == "interrupted"


def test_save_session_known_blocked_path_clears_once_the_lock_is_gone(_isolated_storage, monkeypatch):
    """The known-blocked fast path must self-heal -- once os.replace() actually succeeds again for a
    path (the browser tab was closed, the antivirus/indexer moved on), a later save must go back to
    paying the full retry budget rather than being permanently stuck on the direct-write fallback."""
    monkeypatch.setattr(store, "_REPLACE_RETRY_DELAY_SECONDS", 0)
    monkeypatch.setattr(store, "_REPLACE_RETRY_ATTEMPTS", 30)
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)

    real_replace = store.os.replace

    def always_locked(src, dst):
        raise PermissionError("simulated persistent rename-only Windows file lock")

    monkeypatch.setattr(store.os, "replace", always_locked)
    store.save_session(session_id, session)  # learns the path is blocked

    monkeypatch.setattr(store.os, "replace", real_replace)  # lock has cleared
    store.save_session(session_id, session)

    path = store._session_path(session_id)
    assert path not in store._KNOWN_BLOCKED_PATHS


def test_delete_session_removes_matching_credentials_file(_isolated_storage, monkeypatch):
    monkeypatch.setattr(store, "_CREDENTIALS_DIR", _isolated_storage / "credentials")
    session_id = store.create_session("example.com")
    credentials_path = store._CREDENTIALS_DIR / f"{session_id}.json"
    credentials_path.parent.mkdir(parents=True, exist_ok=True)
    credentials_path.write_text("{}", encoding="utf-8")

    assert store.delete_session(session_id) is True
    assert not credentials_path.exists()


def test_delete_session_is_harmless_when_no_credentials_file_exists(_isolated_storage, monkeypatch):
    monkeypatch.setattr(store, "_CREDENTIALS_DIR", _isolated_storage / "credentials")
    session_id = store.create_session("example.com")
    assert store.delete_session(session_id) is True


def test_delete_all_sessions_removes_every_project_and_returns_the_count(_isolated_storage):
    ids = [store.create_session(f"example{i}.com") for i in range(3)]

    deleted = store.delete_all_sessions()

    assert deleted == 3
    for session_id in ids:
        assert store.load_session(session_id) is None
    assert store.list_session_summaries() == []


def test_delete_all_sessions_survives_one_bad_entry(_isolated_storage, monkeypatch):
    """A single locked/undeletable project (Windows file-locking, this project's own documented
    WSL2/DrvFs rename-only lesson) must not stop the rest of the batch from being cleaned up."""
    good_id_1 = store.create_session("first.example.com")
    bad_id = store.create_session("second.example.com")
    good_id_2 = store.create_session("third.example.com")

    real_delete_session = store.delete_session

    def flaky_delete(session_id):
        if session_id == bad_id:
            raise OSError("simulated: file is in use by another process")
        return real_delete_session(session_id)

    monkeypatch.setattr(store, "delete_session", flaky_delete)

    deleted = store.delete_all_sessions()

    assert deleted == 2
    assert store.load_session(good_id_1) is None
    assert store.load_session(good_id_2) is None
    # The bad one is still around -- delete_all_sessions logged and moved on rather than losing
    # track of it or crashing the whole batch.
    remaining_ids = {s["session_id"] for s in store.list_session_summaries()}
    assert remaining_ids == {bad_id}


def test_create_session_id_shape(_isolated_storage):
    session_id = store.create_session("example.com")
    assert re.fullmatch(r"usr_[0-9a-f]{6}", session_id)


def test_create_session_json_structure_is_valid(_isolated_storage):
    session_id = store.create_session("example.com")
    with _project_session_file(_isolated_storage, session_id).open() as f:
        data = json.load(f)

    assert data == {
        "session_id": session_id,
        "name": "example.com",
        "target": "example.com",
        "icon": data["icon"],  # random per project -- validity asserted in its own test below
        "icon_color": data["icon_color"],
        "mode": "agent",
        "re_experience_level": "hobbyist",
        "status": "pending",
        "created_at": data["created_at"],  # presence/format checked separately below
        "logs": [],
        "findings": [],
        "approvals": [],
        "missing_capabilities": [],
        "hypotheses": [],
        "phase_efficiency": {},
        "stall_events": [],
        "llm_usage": [],
        "chat": {"summary": "", "messages": []},
        "enumerate_subdomains": False,
        "scope_rules": {"qualifying": "", "non_qualifying": ""},
        "custom_instructions": "",
        "goal": "",
        "custom_user_agent": "",
        "custom_headers": "",
        "out_of_scope": [],
        "out_of_scope_notes": [],
        "program_url": "",
        "program_check": {"last_checked": None, "last_error": None, "disclosed_reports_text": "", "disclosed_reports_checked_at": None},
        "authorize_exploit": False,
        "llm_provider": None,
        "identity_a_configured": False,
        "identity_b_configured": False,
        "extra_identities_configured": 0,
        "time_budget_seconds": None,
        "plan": {"phases": [], "version": 0, "updated_at": None},
        "chain_attempts": [],
        "asset_graph": {"credentials": []},
        "enabled_subagent_ids": None,
    }
    # ISO 8601 with timezone — datetime.fromisoformat round-trips it without raising.
    from datetime import datetime

    datetime.fromisoformat(data["created_at"])


def test_load_session_returns_none_for_unknown_id():
    assert store.load_session("usr_ffffff") is None


def test_load_session_round_trips_after_save():
    session_id = store.create_session("example.com")
    store.save_session(session_id, {**store.load_session(session_id), "status": "completed"})

    reloaded = store.load_session(session_id)
    assert reloaded["status"] == "completed"
    assert reloaded["session_id"] == session_id


def test_save_session_leaves_no_temp_file_behind(_isolated_storage):
    session_id = store.create_session("example.com")
    store.save_session(session_id, store.load_session(session_id))

    project_dir = _project_session_file(_isolated_storage, session_id).parent
    assert list(project_dir.glob("*.json.tmp")) == []


# --- save_session preserving a newer "chat" against a stale in-memory caller ---
#
# Real, confirmed-live incident this guards against: agent/chat.py maintains session["chat"]
# through its own independent load/save pair per turn, while the main scan loop (agent/core.py's
# run_session) can hold ONE long-lived in-memory session copy for an entire multi-hour run,
# repeatedly saving that copy's own (never updated) "chat" snapshot -- silently reverting/deleting
# a chat reply within seconds of it being persisted, every time the scan saves anything.


def test_save_session_keeps_the_longer_on_disk_chat_over_a_stale_incoming_one(_isolated_storage):
    session_id = store.create_session("example.com")
    # Simulates chat's own independent write landing first (more messages on disk)...
    on_disk_chat = {"summary": "", "messages": [{"role": "user", "content": "hi", "at": "t"}], "provider": None, "model": None, "pending": False}
    store.save_session(session_id, {**store.load_session(session_id), "chat": on_disk_chat})

    # ...then the scan loop's own long-lived, chat-blind in-memory copy (still the empty chat it
    # was loaded with at scan start) saves something unrelated (a new finding).
    stale_scan_session = store.load_session(session_id)
    stale_scan_session_before_chat_existed = {**stale_scan_session, "chat": {"summary": "", "messages": []}, "findings": [{"title": "New finding"}]}
    store.save_session(session_id, stale_scan_session_before_chat_existed)

    reloaded = store.load_session(session_id)
    assert reloaded["chat"] == on_disk_chat  # not reverted to the scan's own stale empty chat
    assert reloaded["findings"] == [{"title": "New finding"}]  # the scan's own real write still landed


def test_save_session_keeps_the_incoming_chat_when_it_is_not_shorter(_isolated_storage):
    session_id = store.create_session("example.com")
    on_disk_chat = {"summary": "", "messages": [{"role": "user", "content": "hi", "at": "t"}], "provider": None, "model": None, "pending": False}
    store.save_session(session_id, {**store.load_session(session_id), "chat": on_disk_chat})

    # A same-length (or longer) incoming chat is trusted as the more deliberate write -- e.g.
    # chat's own turn correctly building on what it just loaded, not a stale, unrelated caller.
    newer_chat = {"summary": "", "messages": [{"role": "user", "content": "hi", "at": "t"}], "provider": "qwen", "model": None, "pending": False}
    store.save_session(session_id, {**store.load_session(session_id), "chat": newer_chat})

    assert store.load_session(session_id)["chat"] == newer_chat


def test_save_session_chat_merge_is_a_noop_when_caller_has_no_chat_field_at_all(_isolated_storage):
    """A caller (or a session predating the chat feature) that never mentions "chat" at all must
    not crash the merge logic -- on_disk_chat exists, incoming has none, on-disk (longer) wins."""
    session_id = store.create_session("example.com")
    on_disk_chat = {"summary": "", "messages": [{"role": "user", "content": "hi", "at": "t"}], "provider": None, "model": None, "pending": False}
    store.save_session(session_id, {**store.load_session(session_id), "chat": on_disk_chat})

    bare_session = {k: v for k, v in store.load_session(session_id).items() if k != "chat"}
    store.save_session(session_id, bare_session)

    assert store.load_session(session_id)["chat"] == on_disk_chat


# --- save_session preserving newer chat_threads (per-thread), the generalized version of the
# above for the multi-thread chat model (agent/chat.py's session["chat_threads"]) ---


def _chat_thread(thread_id, num_messages, updated_at="t0"):
    return {
        "id": thread_id, "title": "T", "summary": "", "provider": None, "model": None, "pending": False,
        "created_at": "t0", "updated_at": updated_at,
        "messages": [{"role": "user", "at": str(i), "segments": [{"type": "text", "content": f"m{i}"}]} for i in range(num_messages)],
    }


def test_save_session_keeps_the_more_recently_updated_on_disk_thread_over_a_stale_incoming_one(_isolated_storage):
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 2, updated_at="t1")
    store.save_session(session_id, {**store.load_session(session_id), "chat_threads": [thread_a], "active_chat_thread_id": "thread_a"})

    # The scan loop's own long-lived, chat-blind in-memory copy (still the empty thread_a it was
    # loaded with at scan start, so an OLDER updated_at) saves something unrelated (a new finding).
    stale_scan_session = store.load_session(session_id)
    stale_scan_session["chat_threads"] = [_chat_thread("thread_a", 0, updated_at="t0")]
    stale_scan_session["findings"] = [{"title": "New finding"}]
    store.save_session(session_id, stale_scan_session)

    reloaded = store.load_session(session_id)
    assert len(reloaded["chat_threads"][0]["messages"]) == 2  # not reverted to the scan's own stale empty thread
    assert reloaded["findings"] == [{"title": "New finding"}]  # the scan's own real write still landed


def test_save_session_keeps_the_more_recently_updated_thread_even_with_tied_message_count(_isolated_storage):
    """The exact real, confirmed-live incident this merge rule exists for: an in-place segment
    mutation (agent/chat.py's _update_last_tool_call_segment_and_save flipping an existing
    tool_call segment's own done/output fields once a tool finishes) changes NO message count at
    all -- a count-only merge (this function's earlier version) ties on this and silently hands
    the win to a stale concurrent write, reverting a completed tool call's card back to a
    permanent "(running...)" spinner. updated_at must break the tie correctly even when both
    sides' message counts are identical."""
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 1, updated_at="t0")
    store.save_session(session_id, {**store.load_session(session_id), "chat_threads": [thread_a], "active_chat_thread_id": "thread_a"})

    # Chat's own real write: same message count, but the tool_call segment inside it just
    # transitioned done=False -> True -- updated_at moves, the messages list length does not.
    fresh_session = store.load_session(session_id)
    fresh_thread = fresh_session["chat_threads"][0]
    fresh_thread["messages"][0]["segments"] = [{"type": "tool_call", "id": "c1", "done": True, "output": "real result"}]
    fresh_thread["updated_at"] = "t1"
    store.save_session(session_id, fresh_session)

    # The scan loop's stale in-memory copy, loaded BEFORE that update (still done=False), saves
    # something unrelated -- same message count as what's now on disk, but genuinely older content.
    stale_scan_session = store.load_session(session_id)
    stale_thread = _chat_thread("thread_a", 1, updated_at="t0")
    stale_thread["messages"][0]["segments"] = [{"type": "tool_call", "id": "c1", "done": False, "output": None}]
    stale_scan_session["chat_threads"] = [stale_thread]
    stale_scan_session["findings"] = [{"title": "unrelated"}]
    store.save_session(session_id, stale_scan_session)

    reloaded = store.load_session(session_id)
    segment = reloaded["chat_threads"][0]["messages"][0]["segments"][0]
    assert segment["done"] is True  # not reverted to the stale copy's still-pending state
    assert segment["output"] == "real result"


def test_save_session_keeps_a_thread_id_that_exists_only_on_one_side(_isolated_storage):
    """Real scenario: the operator starts a NEW thread (thread_b) while the scan loop's own stale
    in-memory copy still only knows about thread_a -- thread_b must survive the scan's next save,
    not get silently dropped just because that caller never saw it exist."""
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 1)
    store.save_session(session_id, {**store.load_session(session_id), "chat_threads": [thread_a], "active_chat_thread_id": "thread_a"})

    thread_b = _chat_thread("thread_b", 1)
    session_with_new_thread = store.load_session(session_id)
    session_with_new_thread["chat_threads"].append(thread_b)
    session_with_new_thread["active_chat_thread_id"] = "thread_b"
    store.save_session(session_id, session_with_new_thread)

    # Scan's stale copy only knows thread_a, saves something unrelated.
    stale_scan_session = store.load_session(session_id)
    stale_scan_session["chat_threads"] = [_chat_thread("thread_a", 1)]
    stale_scan_session["logs"] = [{"x": 1}]
    store.save_session(session_id, stale_scan_session)

    reloaded = store.load_session(session_id)
    assert {t["id"] for t in reloaded["chat_threads"]} == {"thread_a", "thread_b"}
    assert reloaded["logs"] == [{"x": 1}]


def test_save_session_keeps_a_deleted_thread_deleted_despite_a_stale_incoming_copy(_isolated_storage):
    """Real, confirmed-live regression found in the SAME turn delete_chat_thread (agent/chat.py)
    was added: a deliberate delete looks IDENTICAL to the per-thread merge above as the exact
    "stale caller predates a new thread" scenario the previous test covers -- both are "on-disk has
    this id, incoming doesn't" -- so without an explicit tombstone
    (session["deleted_chat_thread_ids"]), that same protection silently resurrected a thread the
    operator had just deleted the instant any other, unrelated save landed. The tombstone must
    survive even when the OTHER caller's own snapshot predates the delete and still carries the
    now-deleted thread."""
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 1)
    thread_b = _chat_thread("thread_b", 1)
    store.save_session(session_id, {**store.load_session(session_id), "chat_threads": [thread_a, thread_b], "active_chat_thread_id": "thread_a"})

    # delete_chat_thread's own real shape: shrink chat_threads AND record the tombstone in the
    # same save.
    after_delete = store.load_session(session_id)
    after_delete["chat_threads"] = [thread_a]
    after_delete["deleted_chat_thread_ids"] = ["thread_b"]
    store.save_session(session_id, after_delete)

    # A stale caller, loaded BEFORE the delete -- still thinks thread_b exists, knows nothing
    # about the tombstone at all -- saves something unrelated.
    stale = store.load_session(session_id)
    del stale["deleted_chat_thread_ids"]
    stale["chat_threads"] = [thread_a, thread_b]
    stale["logs"] = [{"x": 1}]
    store.save_session(session_id, stale)

    reloaded = store.load_session(session_id)
    assert {t["id"] for t in reloaded["chat_threads"]} == {"thread_a"}  # thread_b stays deleted
    assert reloaded["logs"] == [{"x": 1}]


def test_save_session_restores_chat_threads_entirely_when_caller_has_none(_isolated_storage):
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 3)
    store.save_session(session_id, {**store.load_session(session_id), "chat_threads": [thread_a], "active_chat_thread_id": "thread_a"})

    bare_session = {k: v for k, v in store.load_session(session_id).items() if k not in ("chat_threads", "active_chat_thread_id")}
    store.save_session(session_id, bare_session)

    reloaded = store.load_session(session_id)
    assert len(reloaded["chat_threads"]) == 1
    assert len(reloaded["chat_threads"][0]["messages"]) == 3
    assert reloaded["active_chat_thread_id"] == "thread_a"


def test_save_session_falls_back_to_legacy_chat_merge_when_neither_side_has_threads(_isolated_storage):
    """Old-schema sessions (pre chat_threads) must keep working exactly as before via the
    legacy _preserve_newer_chat fallback -- this is the same scenario
    test_save_session_keeps_the_longer_on_disk_chat_over_a_stale_incoming_one already covers via
    save_session directly, re-asserted here as the explicit "no chat_threads anywhere" case."""
    session_id = store.create_session("example.com")
    on_disk_chat = {"summary": "", "messages": [{"role": "user", "content": "hi", "at": "t"}]}
    store.save_session(session_id, {**store.load_session(session_id), "chat": on_disk_chat})

    stale = store.load_session(session_id)
    stale["chat"] = {"summary": "", "messages": []}
    stale["findings"] = [{"title": "New finding"}]
    store.save_session(session_id, stale)

    reloaded = store.load_session(session_id)
    assert reloaded["chat"] == on_disk_chat
    assert reloaded["findings"] == [{"title": "New finding"}]


# --- Per-thread message files: session.json itself only ever stores thread METADATA; each
# thread's own messages/queued_messages live in their own file under chat_threads/. Real, confirmed
# incident this fixes: session.json was re-serialized and rewritten IN FULL (every OTHER thread's
# entire history included) on every single save, with no ceiling for a session meant to accumulate
# real history for months (the standalone, project-less Quick Chat specifically). ---


def _thread_file(base, session_id, thread_id, target="example.com"):
    folder = f"{store._sanitize_folder_name(target)}-{session_id}"
    return base / "projects" / folder / "chat_threads" / f"{thread_id}.json"


def test_save_session_moves_thread_messages_into_their_own_file(_isolated_storage):
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 3)
    store.save_session(session_id, {**store.load_session(session_id), "chat_threads": [thread_a], "active_chat_thread_id": "thread_a"})

    thread_file = _thread_file(_isolated_storage, session_id, "thread_a")
    assert thread_file.exists()
    on_disk_body = json.loads(thread_file.read_text(encoding="utf-8"))
    assert len(on_disk_body["messages"]) == 3

    # session.json itself must never carry the messages inline once they've been split out.
    session_file = _project_session_file(_isolated_storage, session_id)
    raw_session = json.loads(session_file.read_text(encoding="utf-8"))
    assert "messages" not in raw_session["chat_threads"][0]


def test_load_session_hydrates_messages_back_from_the_threads_own_file(_isolated_storage):
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 3)
    store.save_session(session_id, {**store.load_session(session_id), "chat_threads": [thread_a], "active_chat_thread_id": "thread_a"})

    reloaded = store.load_session(session_id)

    assert len(reloaded["chat_threads"][0]["messages"]) == 3
    assert reloaded["chat_threads"][0]["messages"][0]["segments"][0]["content"] == "m0"


def test_save_session_skips_rewriting_an_unchanged_threads_own_file(_isolated_storage, monkeypatch):
    """The actual point of the whole design: a message sent in the session's currently-active
    thread must never also rewrite every OTHER, untouched thread's own (already large, unrelated)
    history file on that same save."""
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 5, updated_at="t0")
    thread_b = _chat_thread("thread_b", 1, updated_at="t0")
    store.save_session(session_id, {
        **store.load_session(session_id), "chat_threads": [thread_a, thread_b], "active_chat_thread_id": "thread_a",
    })

    write_calls = []
    real_save_thread_body = store._save_thread_body

    def _tracking_save_thread_body(threads_dir, thread_id, messages, queued_messages):
        write_calls.append(thread_id)
        return real_save_thread_body(threads_dir, thread_id, messages, queued_messages)

    monkeypatch.setattr(store, "_save_thread_body", _tracking_save_thread_body)

    # Only thread_a actually changes (a new message, updated_at moves) -- thread_b is untouched.
    session = store.load_session(session_id)
    session["chat_threads"][0]["messages"].append({"role": "user", "at": "5", "segments": [{"type": "text", "content": "m5"}]})
    session["chat_threads"][0]["updated_at"] = "t1"
    store.save_session(session_id, session)

    assert write_calls == ["thread_a"]  # thread_b's own file was never rewritten


def test_save_session_removes_a_deleted_threads_own_file(_isolated_storage):
    session_id = store.create_session("example.com")
    thread_a = _chat_thread("thread_a", 1)
    thread_b = _chat_thread("thread_b", 1)
    store.save_session(session_id, {
        **store.load_session(session_id), "chat_threads": [thread_a, thread_b], "active_chat_thread_id": "thread_a",
    })
    thread_b_file = _thread_file(_isolated_storage, session_id, "thread_b")
    assert thread_b_file.exists()

    # delete_chat_thread's own real shape (agent/chat.py): shrink chat_threads AND record the
    # tombstone, same as the existing merge tests above use.
    session = store.load_session(session_id)
    session["chat_threads"] = [t for t in session["chat_threads"] if t["id"] != "thread_b"]
    session["deleted_chat_thread_ids"] = ["thread_b"]
    store.save_session(session_id, session)

    assert not thread_b_file.exists()


def test_load_session_is_a_noop_hydration_for_an_old_style_session_still_embedding_messages_inline(_isolated_storage):
    """A session.json that predates this feature (messages still embedded directly in
    chat_threads, never split out) must keep loading exactly as before -- no file read attempted,
    no data lost, until it's next saved (which then migrates it automatically)."""
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)
    session["chat_threads"] = [_chat_thread("thread_a", 2)]
    session["active_chat_thread_id"] = "thread_a"
    # Write the OLD-style raw JSON directly, bypassing save_session's own split-on-write entirely.
    session_file = _project_session_file(_isolated_storage, session_id)
    session_file.write_text(json.dumps(session), encoding="utf-8")

    reloaded = store.load_session(session_id)

    assert len(reloaded["chat_threads"][0]["messages"]) == 2
    # Never touched the filesystem for a thread file that was never split out in the first place.
    assert not _thread_file(_isolated_storage, session_id, "thread_a").exists()


def test_save_session_auto_migrates_an_old_style_session_to_the_split_format(_isolated_storage):
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)
    session["chat_threads"] = [_chat_thread("thread_a", 2)]
    session["active_chat_thread_id"] = "thread_a"
    session_file = _project_session_file(_isolated_storage, session_id)
    session_file.write_text(json.dumps(session), encoding="utf-8")

    # The very next ordinary save (e.g. an unrelated field changing) migrates it, with no explicit
    # migration step anywhere.
    reloaded = store.load_session(session_id)
    reloaded["goal"] = "test goal"
    store.save_session(session_id, reloaded)

    raw_session = json.loads(session_file.read_text(encoding="utf-8"))
    assert "messages" not in raw_session["chat_threads"][0]
    assert _thread_file(_isolated_storage, session_id, "thread_a").exists()
    assert len(store.load_session(session_id)["chat_threads"][0]["messages"]) == 2


def test_create_session_falls_back_to_legacy_dir_when_project_folder_unwritable(_isolated_storage, monkeypatch):
    # Point PROJECTS_DIR at a path that can't be created (its parent is a file, not a dir) —
    # the exact kind of real-world failure (permissions, a broken override) create_session must
    # survive without losing the session entirely.
    blocked = _isolated_storage / "blocked-file"
    blocked.write_text("not a directory")
    monkeypatch.setenv("PROJECTS_DIR", str(blocked / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()

    session_id = store.create_session("example.com")

    legacy_path = (_isolated_storage / "legacy") / f"{session_id}.json"
    assert legacy_path.exists()
    assert store.load_session(session_id)["target"] == "example.com"


def test_create_session_stores_explicit_name(_isolated_storage):
    session_id = store.create_session("example.com", name="acme-pentest")
    assert store.load_session(session_id)["name"] == "acme-pentest"


def test_create_session_uses_target_as_name_when_omitted(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["name"] == "example.com"


def test_create_session_enumerate_subdomains_defaults_off(_isolated_storage):
    session_id = store.create_session("example.com")
    assert store.load_session(session_id)["enumerate_subdomains"] is False


def test_create_session_stores_enumerate_subdomains_when_enabled(_isolated_storage):
    session_id = store.create_session("example.com", enumerate_subdomains=True)
    assert store.load_session(session_id)["enumerate_subdomains"] is True


def test_name_exists_is_case_insensitive(_isolated_storage):
    store.create_session("example.com", name="Acme Pentest")
    assert store.name_exists("acme pentest") is True
    assert store.name_exists("ACME PENTEST") is True


def test_name_exists_false_for_unused_name(_isolated_storage):
    store.create_session("example.com", name="Acme Pentest")
    assert store.name_exists("Someone Else's Project") is False


# --- list_session_summaries(): the cheap-fields cache that replaced main.py's own full
# json.load()-every-session-file loop for _load_all_sessions()/_mark_orphaned_sessions_interrupted().
# Real incident this fixes: one real session.json had grown to 364 MB (a since-fixed logging bug),
# and every one of the three separate 5s UI polls (sidebar, home page, Projects page) plus server
# startup re-parsed it in full, every single time -- "жутко долго" tab switching and slow startup. ---


def test_list_session_summaries_returns_the_expected_shape(_isolated_storage):
    session_id = store.create_session("example.com", name="Acme Pentest")

    summaries = store.list_session_summaries()

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["session_id"] == session_id
    assert summary["name"] == "Acme Pentest"
    assert summary["target"] == "example.com"
    assert summary["status"] == "pending"
    assert summary["findings_count"] == 0
    assert summary["resumable_from"] is None
    assert summary["phase"] is None
    assert summary["rescanned_from_name"] is None
    assert summary["folder"] is not None


def test_list_session_summaries_reflects_a_save_without_needing_a_fresh_process(_isolated_storage):
    session_id = store.create_session("example.com")
    session = store.load_session(session_id)
    session["status"] = "completed"
    session["findings"] = [{"title": "SQLi"}]
    store.save_session(session_id, session)

    summary = next(s for s in store.list_session_summaries() if s["session_id"] == session_id)
    assert summary["status"] == "completed"
    assert summary["findings_count"] == 1


def test_list_session_summaries_does_not_reparse_a_session_already_in_the_cache(_isolated_storage, monkeypatch):
    """Proves the fix actually breaks the "every poll re-parses every file" feedback loop, not just
    that a small example happens to look right -- same rigor as test_describe_command_stays_bounded_
    even_with_a_huge_injected_session for the earlier logging-bloat fix this one is paired with."""
    session_id = store.create_session("example.com")
    store.list_session_summaries()  # first call: cache miss, backfills the summary index

    real_open = store.Path.open
    opened_session_files = []

    def tracking_open(self, *args, **kwargs):
        if self.name == "session.json":
            opened_session_files.append(self)
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(store.Path, "open", tracking_open)

    summaries = store.list_session_summaries()

    assert opened_session_files == []
    assert summaries[0]["session_id"] == session_id


def test_list_session_summaries_backfills_a_legacy_session_missing_from_the_cache(_isolated_storage):
    """A session written before this cache existed (or the cache file itself is missing/corrupt)
    must still show up correctly -- read once, then cached, not silently dropped from the list."""
    legacy_dir = _isolated_storage / "legacy"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "usr_legacy.json").write_text(json.dumps({
        "session_id": "usr_legacy", "name": "Legacy Project", "target": "old.example.com",
        "status": "completed", "created_at": "2020-01-01T00:00:00+00:00",
        "logs": [], "findings": [{"title": "XSS"}], "approvals": [],
    }))

    summaries = store.list_session_summaries()

    assert len(summaries) == 1
    assert summaries[0]["session_id"] == "usr_legacy"
    assert summaries[0]["name"] == "Legacy Project"
    assert summaries[0]["findings_count"] == 1
    assert summaries[0]["folder"] is None
    # Backfilled into the on-disk cache too, not just returned once and forgotten.
    assert "usr_legacy" in store._load_summary_index()


def test_list_session_summaries_computes_resumable_from_for_a_legacy_failed_session(_isolated_storage):
    """Same lazy-computation rule as the pre-cache code: a session with no stored resumable_from
    that's already interrupted/failed gets one computed on the fly, not left null."""
    legacy_dir = _isolated_storage / "legacy"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "usr_legacy.json").write_text(json.dumps({
        "session_id": "usr_legacy", "target": "old.example.com", "status": "failed",
        "created_at": "2020-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "recon_result": {"targets": ["old.example.com"]},
    }))

    summary = store.list_session_summaries()[0]
    assert summary["resumable_from"] == "analyze"


def test_delete_session_removes_it_from_the_summary_cache(_isolated_storage):
    session_id = store.create_session("example.com")
    store.list_session_summaries()
    assert session_id in store._load_summary_index()

    store.delete_session(session_id)

    assert session_id not in store._load_summary_index()
    assert session_id not in {s["session_id"] for s in store.list_session_summaries()}


def test_name_exists_uses_the_summary_cache_and_still_works_correctly(_isolated_storage):
    store.create_session("example.com", name="Acme Pentest")
    assert store.name_exists("acme pentest") is True
    assert store.name_exists("someone else's project") is False


def test_iter_all_session_paths_finds_legacy_and_project_sessions(_isolated_storage):
    new_id = store.create_session("example.com")

    legacy_dir = _isolated_storage / "legacy"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "usr_legacy.json").write_text(json.dumps({
        "session_id": "usr_legacy", "target": "old.example.com", "status": "completed",
        "created_at": "2020-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
    }))

    found_ids = {p.parent.name if p.name == "session.json" else p.stem for p in store.iter_all_session_paths()}
    assert new_id in found_ids or f"{store._sanitize_folder_name('example.com')}-{new_id}" in found_ids
    assert "usr_legacy" in found_ids


# --- mode="standalone": the top-level, project-less Quick Chat (main.py's GET /chat) -- a real
# session like any other on disk, just kept out of every project listing at this one source. ---


def test_list_session_summaries_excludes_a_standalone_mode_session(_isolated_storage):
    quick_chat_id = store.create_session("", name="Quick Chat", mode="standalone")
    store.create_session("example.com", name="Acme Pentest")

    summaries = store.list_session_summaries()

    assert quick_chat_id not in {s["session_id"] for s in summaries}
    assert len(summaries) == 1
    assert summaries[0]["name"] == "Acme Pentest"


def test_list_session_summaries_excludes_a_legacy_standalone_mode_session(_isolated_storage):
    """Same exclusion for a session living in the legacy flat data/sessions/ glob, not just the
    indexed-project-folder loop above -- both loops in list_session_summaries carry the filter."""
    legacy_dir = _isolated_storage / "legacy"
    legacy_dir.mkdir(parents=True, exist_ok=True)
    (legacy_dir / "usr_legacy_standalone.json").write_text(json.dumps({
        "session_id": "usr_legacy_standalone", "target": "", "status": "completed", "mode": "standalone",
        "created_at": "2020-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
    }))

    assert store.list_session_summaries() == []


def test_delete_session_refuses_a_standalone_mode_session(_isolated_storage):
    quick_chat_id = store.create_session("", name="Quick Chat", mode="standalone")

    deleted = store.delete_session(quick_chat_id)

    assert deleted is False
    assert store.load_session(quick_chat_id) is not None


def test_delete_all_sessions_never_touches_a_standalone_mode_session(_isolated_storage):
    """delete_all_sessions sources its ids from list_session_summaries -- the exclusion above is
    enough on its own to keep "Delete all" from ever reaching the Quick Chat session, with no
    separate check needed in delete_all_sessions itself."""
    quick_chat_id = store.create_session("", name="Quick Chat", mode="standalone")
    store.create_session("example.com")

    deleted_count = store.delete_all_sessions()

    assert deleted_count == 1
    assert store.load_session(quick_chat_id) is not None
