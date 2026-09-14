"""Route-level tests for the chat panel's live-send/receive redesign (main.py): the markdown
sanitization filter, the fast+backgrounded POST /api/session/{id}/chat route, and the
pending-guard no-op. The chat_stream SSE endpoint's own generator loop is deliberately not
exercised here at the streaming level — the pre-existing, structurally identical stream_session
route has no test coverage of its generator either; _render_chat_messages producing genuinely
different output for genuinely different chat state (covered below) is what that endpoint's own
hash-diff actually depends on being correct.
"""
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import main
import projects.paths as project_paths
from agent.chat import get_chat_stop_event
from agent.tools import chat_settings_store
from sessions import store
from sessions.store import load_session


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)
    monkeypatch.setattr(chat_settings_store, "CHAT_SETTINGS_STORE_PATH", tmp_path / "chat_settings.json")


def _create_session(client: TestClient, name: str) -> str:
    resp = client.post("/api/scan", data={"name": name, "target": "example.com"}, follow_redirects=False)
    assert resp.status_code == 303, resp.text
    return resp.headers["location"].rsplit("/", 1)[-1]


# --- _render_chat_markdown: safe markdown -> HTML ---


def test_render_chat_markdown_renders_bold_and_lists():
    html = str(main._render_chat_markdown("**bold** and\n\n- one\n- two"))
    assert "<strong>bold</strong>" in html
    assert "<li>one</li>" in html
    assert "<li>two</li>" in html


def test_render_chat_markdown_strips_script_tags_but_keeps_inert_text():
    html = str(main._render_chat_markdown("before <script>alert(1)</script> after"))
    assert "<script" not in html
    assert "alert(1)" in html  # inert text survives, just never as an executable tag


def test_render_chat_markdown_strips_event_handler_attributes():
    html = str(main._render_chat_markdown('<a href="https://example.com" onclick="alert(1)">link</a>'))
    assert "onclick" not in html
    assert 'href="https://example.com"' in html


def test_render_chat_markdown_strips_javascript_uri():
    html = str(main._render_chat_markdown('<a href="javascript:alert(1)">click</a>'))
    assert "javascript:" not in html


def test_render_chat_markdown_handles_empty_content():
    assert str(main._render_chat_markdown("")) == ""
    assert str(main._render_chat_markdown(None)) == ""


# --- _render_chat_markdown: [F#]/[H#]/[R#] card-reference and slash-command highlighting ---
# Real, confirmed operator complaint: chat_panel.html's own asraDiscussInChat inserts a "[F3] "
# tag, and a message starting with it rendered as flat, unstyled text -- indistinguishable from
# any other bracketed text, with nothing marking it as a real pointer to a specific card.


def test_render_chat_markdown_highlights_a_finding_reference_tag():
    html = str(main._render_chat_markdown("[F17] что думаешь? Есть шанс повысить опасность?"))
    assert '<span class="' in html
    assert ">[F17]</span>" in html
    assert "что думаешь" in html


def test_render_chat_markdown_highlights_hypothesis_and_recon_reference_tags():
    html = str(main._render_chat_markdown("about [H2] and also [R5]"))
    assert ">[H2]</span>" in html
    assert ">[R5]</span>" in html


def test_render_chat_markdown_does_not_highlight_an_unrelated_bracket():
    # Only the F/H/R + digits shape counts -- a plain "[note]" is real operator text, not a
    # generated reference tag, and must not be mistaken for one.
    html = str(main._render_chat_markdown("[note] see below"))
    assert "<span" not in html


def test_render_chat_markdown_highlights_a_slash_command_anywhere_in_the_message():
    # chat_panel.html's own client-side interception only catches /new, /resume, /compact as the
    # message's first word -- a mention mid-sentence still gets sent as a normal message and
    # deserves the same visual treatment once it's in history.
    html = str(main._render_chat_markdown("I typed /compact but nothing happened"))
    assert ">/compact</span>" in html


def test_render_chat_markdown_does_not_highlight_a_slash_inside_a_url_path():
    html = str(main._render_chat_markdown("see a/compact/b for details"))
    assert "<span" not in html


# --- POST /api/session/{id}/chat: fast response, background task, pending-guard ---


def test_chat_post_returns_immediately_with_user_message_and_pending_indicator(tmp_path, monkeypatch):
    """The actual bug this whole redesign fixes: the response must show the user's own message
    (and a "thinking" indicator) WITHOUT waiting for the LLM — verified here by making
    run_chat_turn_background a no-op that never resolves the pending state, so a response
    containing the spinner is only possible if the fast path already rendered before that
    background task's own (mocked-away) work would ever matter.
    """
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Fast Path")

    resp = client.post(f"/api/session/{session_id}/chat", data={"message": "what did the scan find?"})

    assert resp.status_code == 200
    assert "what did the scan find?" in resp.text
    assert "asra-spinner" in resp.text  # the "thinking" indicator, since pending=True
    main.run_chat_turn_background.assert_called_once_with(session_id)


def test_chat_post_rejects_empty_message(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Empty Message")

    resp = client.post(f"/api/session/{session_id}/chat", data={"message": "   "})

    assert resp.status_code == 400


def test_chat_post_unknown_session_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_does_not_exist/chat", data={"message": "hi"})

    assert resp.status_code == 404


def test_chat_post_queues_while_a_turn_is_already_pending(tmp_path, monkeypatch):
    """Server-side reaction to append_pending_chat_message's own started=False return -- a second
    send while the first is still in flight must not double-fire a second background LLM call for
    the same conversation (the already-running turn drains the queue itself once it finishes; see
    test_chat.py's own queuing tests for append_pending_chat_message's side of this).
    """
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Pending Guard")
    stub_session = load_session(session_id)
    monkeypatch.setattr(main, "append_pending_chat_message", lambda *a, **k: (stub_session, False))
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())

    resp = client.post(f"/api/session/{session_id}/chat", data={"message": "second message"})

    assert resp.status_code == 200
    main.run_chat_turn_background.assert_not_called()


def test_chat_stop_route_flips_the_stop_event_for_a_pending_thread(tmp_path, monkeypatch):
    """The "thinking…" indicator's own Stop button (chat_messages.html) -- only flips the
    in-memory signal agent/chat.py's _run_chat_tool_loop checkpoints poll; run_chat_turn_background
    is mocked out here so the thread just stays pending, the same setup the queuing test above uses.
    """
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Stop Flip")
    client.post(f"/api/session/{session_id}/chat", data={"message": "hi"})
    thread_id = load_session(session_id)["active_chat_thread_id"]

    resp = client.post(f"/api/session/{session_id}/chat/stop", data={"thread_id": thread_id})

    assert resp.status_code == 200
    assert get_chat_stop_event(session_id, thread_id).is_set() is True


def test_chat_stop_route_requires_a_pending_turn(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Stop Not Pending")
    client.post(f"/api/session/{session_id}/chat", data={"message": "hi"})
    session = load_session(session_id)
    thread_id = session["active_chat_thread_id"]
    thread = next(t for t in session["chat_threads"] if t["id"] == thread_id)
    thread["pending"] = False
    store.save_session(session_id, session)

    resp = client.post(f"/api/session/{session_id}/chat/stop", data={"thread_id": thread_id})

    assert resp.status_code == 400


def test_chat_stop_route_404s_for_an_unknown_thread(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Stop Unknown Thread")

    resp = client.post(f"/api/session/{session_id}/chat/stop", data={"thread_id": "thread_does_not_exist"})

    assert resp.status_code == 404


def test_cancel_queued_chat_message_route_removes_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Cancel Queued")
    client.post(f"/api/session/{session_id}/chat", data={"message": "hi"})
    session = load_session(session_id)
    thread_id = session["active_chat_thread_id"]
    thread = next(t for t in session["chat_threads"] if t["id"] == thread_id)
    thread["queued_messages"] = [{"id": "q1", "text": "queued follow-up", "at": "2026-01-01T00:00:00+00:00"}]
    store.save_session(session_id, session)

    resp = client.post(f"/api/session/{session_id}/chat/queued/cancel", data={"thread_id": thread_id, "message_id": "q1"})

    assert resp.status_code == 200
    assert load_session(session_id)["chat_threads"][0]["queued_messages"] == []


def test_chat_post_persists_provider_and_model_choice(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Provider Choice")

    client.post(f"/api/session/{session_id}/chat", data={"message": "hi", "provider": "qwen", "model": "qwen-max"})

    session = load_session(session_id)
    thread = session["chat_threads"][0]
    assert thread["provider"] == "qwen"
    assert thread["model"] == "qwen-max"


# --- _render_chat_messages: the source of truth chat_stream's own hash-diff depends on ---


def test_render_chat_messages_output_differs_for_genuinely_different_chat_state():
    from starlette.requests import Request

    scope = {"type": "http", "method": "GET", "path": "/", "headers": [], "query_string": b""}
    request = Request(scope)

    empty = main._render_chat_messages(request, {"session_id": "usr_a"})
    with_message = main._render_chat_messages(request, {
        "session_id": "usr_b",
        "chat_threads": [{"id": "thread_1", "title": "T", "summary": "", "provider": None, "model": None, "pending": False,
                           "created_at": "t", "updated_at": "t",
                           "messages": [{"role": "user", "at": "t", "segments": [{"type": "text", "content": "hi"}]}]}],
        "active_chat_thread_id": "thread_1",
    })
    assert empty != with_message
    assert "hi" in with_message


# --- /chat-settings: moved into Settings' own "Chat" tab -- this route now only redirects an old
# bookmark/muscle-memory visit there instead of 404ing. The toggles' own render is covered under
# "Settings -> Chat tab" below; the POST endpoints they post to are unchanged. ---


def test_chat_settings_page_redirects_to_settings_chat_tab(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/chat-settings", follow_redirects=False)

    assert resp.status_code == 301
    assert resp.headers["location"] == "/settings#general/settings-chat-section"


def test_settings_page_chat_tab_renders_the_capability_toggles(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert 'id="settings-chat-section"' in resp.text
    assert "Web fetch" in resp.text
    assert "Browser" in resp.text
    assert "Dork Engine" in resp.text
    assert "Subagent delegation" in resp.text
    assert 'href="/chat"' in resp.text  # points at Quick Chat, not the removed /chat-settings page


def test_chat_settings_post_toggles_one_field_on(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/chat-settings/subagents_enabled", data={"enabled": "on"})

    assert resp.status_code == 204
    settings = chat_settings_store.load_chat_settings()
    assert settings["web_fetch_enabled"] is True
    assert settings["browser_enabled"] is True
    assert settings["subagents_enabled"] is True


def test_chat_settings_post_toggles_one_field_off_without_touching_the_others(tmp_path, monkeypatch):
    """Real, confirmed operator complaint this fixes: the old shared-<form> version resubmitted
    ALL THREE checkboxes' client-side state together on every toggle click -- a page left open
    since before another field changed elsewhere would silently revert that other field back to
    its own stale snapshot the instant any toggle on it was clicked. Each field is now its own
    independent request that only ever touches the one field named in the URL; the other two must
    come out exactly as they already were on disk, never reset to some client-supplied default."""
    _isolate(tmp_path, monkeypatch)
    chat_settings_store.save_chat_settings(True, True, True)
    client = TestClient(main.app)

    resp = client.post("/api/chat-settings/subagents_enabled", data={})

    assert resp.status_code == 204
    settings = chat_settings_store.load_chat_settings()
    assert settings["web_fetch_enabled"] is True
    assert settings["browser_enabled"] is True
    assert settings["subagents_enabled"] is False


def test_chat_settings_post_rejects_an_unknown_field(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/chat-settings/not_a_real_field", data={"enabled": "on"})

    assert resp.status_code == 404


# --- chat_panel.html's own Subagents button/dialog (partials/chat_subagents_panel.html):
# QUICK CHAT ONLY -- a real project already picked its own Subagents once, up front, on its New
# Project form (partials/new_project_form.html's subagent_project_checklist()); Quick Chat has no
# such form at all, so this live, in-chat control is the only way to narrow it, ever. The backing
# routes (get_session_subagents_panel/save_session_enabled_subagents) stay plain and session-id-
# generic -- only this ONE button's own visibility is restricted to mode == "standalone". ---


def _isolate_subagents(tmp_path, monkeypatch):
    from agent.tools import subagent_store
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    return subagent_store


def test_chat_panel_never_shows_the_subagents_button_for_a_real_project(tmp_path, monkeypatch):
    """Real project already chose its own Subagents once at creation -- this button must never
    appear on its chat sidebar regardless of the chat_settings subagents_enabled toggle, since
    showing it there would just be a second, redundant control over the same already-made choice."""
    subagent_store = _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    subagent_store.update_profile(subagent_store.add_profile("Recon Helper", [], "", None, None)["profiles"][-1]["id"], enabled=True)
    chat_settings_store.save_chat_settings(False, False, True, False)  # subagents_enabled ON
    client = TestClient(main.app)
    session_id = _create_session(client, "Real Project")

    resp = client.get(f"/session/{session_id}")

    assert 'id="chat-subagents-btn"' not in resp.text


def test_chat_panel_hides_the_subagents_button_on_quick_chat_when_no_profile_is_enabled(tmp_path, monkeypatch):
    _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/chat")

    assert 'id="chat-subagents-btn"' not in resp.text


def test_chat_panel_hides_the_subagents_button_on_quick_chat_when_the_toggle_is_off(tmp_path, monkeypatch):
    subagent_store = _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    subagent_store.update_profile(subagent_store.add_profile("Recon Helper", [], "", None, None)["profiles"][-1]["id"], enabled=True)
    chat_settings_store.save_chat_settings(False, False, False, False)  # subagents_enabled off
    client = TestClient(main.app)

    resp = client.get("/chat")

    assert 'id="chat-subagents-btn"' not in resp.text


def test_chat_panel_shows_the_subagents_button_on_quick_chat_when_enabled(tmp_path, monkeypatch):
    subagent_store = _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    subagent_store.update_profile(subagent_store.add_profile("Recon Helper", [], "", None, None)["profiles"][-1]["id"], enabled=True)
    chat_settings_store.save_chat_settings(False, False, True, False)
    client = TestClient(main.app)

    resp = client.get("/chat")

    assert 'id="chat-subagents-btn"' in resp.text


def test_subagents_panel_route_renders_a_checked_box_per_enabled_profile_by_default(tmp_path, monkeypatch):
    subagent_store = _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    profile_id = subagent_store.add_profile("Recon Helper", [], "", None, None)["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)
    client = TestClient(main.app)
    # Created directly (not via /api/scan's own New Project checklist parsing) -- represents an
    # existing project with no restriction (enabled_subagent_ids=None), same as any project
    # created before this feature existed.
    session_id = store.create_session("example.com", name="Panel Render Project")

    resp = client.get(f"/api/session/{session_id}/subagents-panel")

    assert resp.status_code == 200
    assert "Recon Helper" in resp.text
    tag_start = resp.text.index(f'value="{profile_id}"')
    tag_end = resp.text.index(">", tag_start)
    assert "checked" in resp.text[tag_start:tag_end]


def test_subagents_panel_route_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/api/session/usr_does_not_exist/subagents-panel")

    assert resp.status_code == 404


def test_save_enabled_subagents_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_does_not_exist/enabled-subagents", data={})

    assert resp.status_code == 404


def test_save_enabled_subagents_narrows_only_the_given_session(tmp_path, monkeypatch):
    subagent_store = _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    kept_id = subagent_store.add_profile("Recon Helper", [], "", None, None)["profiles"][-1]["id"]
    subagent_store.update_profile(kept_id, enabled=True)
    unchecked_id = subagent_store.add_profile("Bruteforce Helper", [], "", None, None)["profiles"][-1]["id"]
    subagent_store.update_profile(unchecked_id, enabled=True)
    client = TestClient(main.app)
    session_id = _create_session(client, "Narrowed Chat Project")
    # Created directly, not via /api/scan -- represents a completely unrelated, pre-existing
    # project with no restriction of its own (enabled_subagent_ids=None).
    other_session_id = store.create_session("example.org", name="Unaffected Chat Project")

    resp = client.post(f"/api/session/{session_id}/enabled-subagents", data={"enabled_subagent_ids": [kept_id]})

    assert resp.status_code == 204
    assert load_session(session_id)["enabled_subagent_ids"] == [kept_id]
    # A completely different session must never be touched by narrowing this one's checklist.
    assert load_session(other_session_id)["enabled_subagent_ids"] is None


def test_save_enabled_subagents_leaving_every_box_checked_stores_no_restriction(tmp_path, monkeypatch):
    subagent_store = _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    profile_id = subagent_store.add_profile("Recon Helper", [], "", None, None)["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)
    client = TestClient(main.app)
    session_id = _create_session(client, "All Checked Project")

    resp = client.post(f"/api/session/{session_id}/enabled-subagents", data={"enabled_subagent_ids": [profile_id]})

    assert resp.status_code == 204
    assert load_session(session_id)["enabled_subagent_ids"] is None


def test_save_enabled_subagents_also_works_for_the_quick_chat_session(tmp_path, monkeypatch):
    """The exact same route/mechanism, unmodified, since Quick Chat is a real session with the
    same enabled_subagent_ids field -- no special-casing needed for it anywhere."""
    subagent_store = _isolate_subagents(tmp_path, monkeypatch)
    _isolate(tmp_path, monkeypatch)
    profile_id = subagent_store.add_profile("Recon Helper", [], "", None, None)["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)
    client = TestClient(main.app)
    client.get("/chat")  # lazily creates the real Quick Chat session
    quick_chat_session_id = chat_settings_store.load_chat_settings()["quick_chat_session_id"]

    resp = client.post(f"/api/session/{quick_chat_session_id}/enabled-subagents", data={"enabled_subagent_ids": []})

    assert resp.status_code == 204
    assert load_session(quick_chat_session_id)["enabled_subagent_ids"] == []


# --- _render_chat_markdown: tables + Cyrillic/UTF-8 ---


def test_render_chat_markdown_renders_a_real_table():
    html = str(main._render_chat_markdown("| A | B |\n|---|---|\n| 1 | 2 |"))
    assert "<table>" in html
    assert "<th>A</th>" in html
    assert "<td>1</td>" in html


def test_render_chat_markdown_handles_cyrillic_text():
    html = str(main._render_chat_markdown("**Привет** — это находка на сайте."))
    assert "Привет" in html
    assert "<strong>Привет</strong>" in html
    assert "находка" in html


# --- thread routes: /new-thread, /threads (picker), /switch-thread, /compact ---


def test_new_chat_thread_route_creates_and_activates_a_fresh_thread(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "New Thread Route")
    client.post(f"/api/session/{session_id}/chat", data={"message": "first thread's own message"})
    first_thread_id = load_session(session_id)["active_chat_thread_id"]

    resp = client.post(f"/api/session/{session_id}/chat/new-thread")

    assert resp.status_code == 200
    session = load_session(session_id)
    assert len(session["chat_threads"]) == 2
    assert session["active_chat_thread_id"] != first_thread_id
    # The response is the new, empty thread's own message stream PLUS an out-of-band refresh of the
    # Quick Chat tab strip (main.py's _render_chat_thread_tabs_oob) -- the old thread's own title
    # (its first message, truncated) legitimately appears there now, so scope this assertion to the
    # actual message-stream portion, not the whole response.
    stream_part = resp.text.split('id="chat-thread-tabs"')[0]
    assert "first thread's own message" not in stream_part
    assert "first thread&#39;s own message" not in stream_part
    # The old thread must still show up as a switchable tab, not vanish just because it's inactive
    # (Jinja auto-escapes the apostrophe in a thread's own title, unlike a plain chat bubble).
    assert "first thread&#39;s own message" in resp.text


def test_new_chat_thread_route_unknown_session_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_does_not_exist/chat/new-thread")

    assert resp.status_code == 404


def test_get_chat_threads_route_lists_threads_newest_first(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Threads Picker")
    client.post(f"/api/session/{session_id}/chat", data={"message": "older thread message"})
    client.post(f"/api/session/{session_id}/chat/new-thread")
    client.post(f"/api/session/{session_id}/chat", data={"message": "newer thread message"})

    resp = client.get(f"/api/session/{session_id}/chat/threads")

    assert resp.status_code == 200
    assert "Chat history" in resp.text
    # Newest first -- the newer thread's own title appears before the older one's in the raw HTML.
    assert resp.text.index("newer thread message") < resp.text.index("older thread message")


def test_switch_chat_thread_route_activates_the_requested_thread_and_shows_its_history(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Switch Thread Route")
    client.post(f"/api/session/{session_id}/chat", data={"message": "thread one's own message"})
    first_thread_id = load_session(session_id)["active_chat_thread_id"]
    client.post(f"/api/session/{session_id}/chat/new-thread")

    resp = client.post(f"/api/session/{session_id}/chat/switch-thread", data={"thread_id": first_thread_id})

    assert resp.status_code == 200
    assert "thread one's own message" in resp.text
    assert load_session(session_id)["active_chat_thread_id"] == first_thread_id


def test_switch_chat_thread_route_unknown_thread_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "Switch Thread 404")

    resp = client.post(f"/api/session/{session_id}/chat/switch-thread", data={"thread_id": "does-not-exist"})

    assert resp.status_code == 404


def test_delete_chat_thread_route_removes_it_and_updates_the_picker(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Delete Thread Route")
    client.post(f"/api/session/{session_id}/chat", data={"message": "thread one's own message"})
    first_thread_id = load_session(session_id)["active_chat_thread_id"]
    client.post(f"/api/session/{session_id}/chat/new-thread")

    resp = client.post(f"/api/session/{session_id}/chat/delete-thread", data={"thread_id": first_thread_id})

    assert resp.status_code == 200
    session = load_session(session_id)
    assert first_thread_id not in {t["id"] for t in session["chat_threads"]}
    assert session["deleted_chat_thread_ids"] == [first_thread_id]
    # The picker's own re-rendered list must no longer mention the deleted thread's message.
    assert "thread one's own message" not in resp.text


def test_delete_chat_thread_route_unknown_thread_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "Delete Thread 404")

    resp = client.post(f"/api/session/{session_id}/chat/delete-thread", data={"thread_id": "does-not-exist"})

    assert resp.status_code == 404


def test_delete_chat_thread_route_unknown_session_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_does_not_exist/chat/delete-thread", data={"thread_id": "x"})

    assert resp.status_code == 404


def test_rename_chat_thread_route_persists_the_new_title(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Rename Thread Route")
    client.post(f"/api/session/{session_id}/chat", data={"message": "hi"})
    thread_id = load_session(session_id)["active_chat_thread_id"]

    resp = client.post(f"/api/session/{session_id}/chat/rename-thread", data={"thread_id": thread_id, "title": "Bug bounty notes"})

    assert resp.status_code == 200
    threads = load_session(session_id)["chat_threads"]
    assert next(t["title"] for t in threads if t["id"] == thread_id) == "Bug bounty notes"


def test_rename_chat_thread_route_unknown_thread_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "Rename Thread 404")

    resp = client.post(f"/api/session/{session_id}/chat/rename-thread", data={"thread_id": "does-not-exist", "title": "x"})

    assert resp.status_code == 404


def test_set_chat_thread_color_route_persists_the_color(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Thread Color Route")
    client.post(f"/api/session/{session_id}/chat", data={"message": "hi"})
    thread_id = load_session(session_id)["active_chat_thread_id"]

    resp = client.post(f"/api/session/{session_id}/chat/thread-color", data={"thread_id": thread_id, "color": "#a50303"})

    assert resp.status_code == 200
    threads = load_session(session_id)["chat_threads"]
    assert next(t["color"] for t in threads if t["id"] == thread_id) == "#a50303"


def test_set_chat_thread_color_route_unknown_thread_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "Chat Thread Color 404")

    resp = client.post(f"/api/session/{session_id}/chat/thread-color", data={"thread_id": "does-not-exist", "color": "#a50303"})

    assert resp.status_code == 404


def test_compact_chat_thread_route_reports_when_nothing_to_compact(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    session_id = _create_session(client, "Compact Too Short")
    client.post(f"/api/session/{session_id}/chat", data={"message": "just one message so far"})

    resp = client.post(f"/api/session/{session_id}/chat/compact")

    assert resp.status_code == 200
    assert "Nothing to compact yet" in resp.text


def test_compact_chat_thread_route_unknown_session_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/session/usr_does_not_exist/chat/compact")

    assert resp.status_code == 404


# --- Interactive mode: chat-only console (start_interactive + session.html's interactive branch) ---


def test_start_interactive_creates_a_chat_only_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/scan/interactive", data={"name": "CTF Box"}, follow_redirects=False)

    assert resp.status_code == 303, resp.text
    session_id = resp.headers["location"].rsplit("/", 1)[-1]
    session = load_session(session_id)
    assert session["mode"] == "interactive"
    assert session["target"] == ""  # named in chat, not up front
    assert session["status"] == "interactive"  # never runs the scan pipeline
    assert session["authorize_exploit"] is True


def test_start_interactive_hx_returns_redirect_header(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/scan/interactive", data={"name": "CTF HX"}, headers={"HX-Request": "true"})

    assert resp.status_code == 200
    assert resp.headers["HX-Redirect"].startswith("/session/")


def test_start_interactive_requires_a_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/scan/interactive", data={"name": "  "}, headers={"HX-Request": "true"})

    assert resp.status_code == 200
    assert "Project name is required" in resp.text
    # Re-rendered on the fields step with the Interactive mode kept selected, so the error shows
    # where the operator actually was (not bounced back to the mode picker).
    assert 'data-np-step="fields"' in resp.text
    assert 'data-np-mode="interactive"' in resp.text
    assert 'id="np-mode-interactive" class="sr-only" checked' in resp.text


def test_interactive_session_page_renders_chat_only(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/scan/interactive", data={"name": "CTF Page"}, follow_redirects=False)
    session_id = resp.headers["location"].rsplit("/", 1)[-1]

    page = client.get(f"/session/{session_id}")

    assert page.status_code == 200
    assert "Interactive mode" in page.text
    assert 'id="chat-panel"' in page.text  # the chat console is present
    assert 'id="session-stream"' not in page.text  # the scan log / SSE stream is NOT rendered


def test_new_project_form_has_the_icon_picker(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    page = client.get("/")
    assert page.status_code == 200
    assert "project-icon-picker" in page.text
    assert 'name="icon"' in page.text
    assert 'name="icon_color"' in page.text


def test_validation_error_preserves_chosen_icon_and_color(tmp_path, monkeypatch):
    from projects import icons
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "summary.json")
    client = TestClient(main.app)
    _create_session(client, "dup")  # so the next create hits the duplicate-name error

    resp = client.post(
        "/api/scan",
        data={"name": "dup", "target": "example.com", "icon": "skull", "icon_color": "#f472b6"},
        headers={"HX-Request": "true"},
    )
    assert resp.status_code == 200
    assert "already exists" in resp.text
    # the chosen icon stays selected and the color is carried back, not reset -- id is prefixed
    # "agent-" (icon_picker's id_prefix) since this same picker is now also rendered once per
    # other New Project wizard panel (Interactive, Reverse Engineering) in the same page, and ids
    # must stay unique across all of them.
    assert 'id="agent-icon-skull" value="skull" class="sr-only" checked' in resp.text
    assert 'value="#f472b6"' in resp.text
    assert icons.ICON_NAMES  # sanity: the pools loaded


def test_created_project_row_renders_its_chosen_icon_color(tmp_path, monkeypatch):
    from projects import icons
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "summary.json")
    client = TestClient(main.app)
    client.post("/api/scan", data={"name": "IconProj", "target": "example.com", "icon": "bug", "icon_color": icons.ICON_COLORS[0]}, follow_redirects=False)

    listing = client.get("/sessions")
    assert listing.status_code == 200
    assert icons.ICON_COLORS[0] in listing.text  # the chosen color is applied to the row's icon


def test_new_project_form_opens_on_the_mode_picker(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    page = client.get("/")

    assert page.status_code == 200
    # A fresh open starts on step 1 (the mode picker), with neither mode pre-selected.
    assert 'data-np-step="mode"' in page.text
    assert "How do you want to work?" in page.text
    assert 'id="np-mode-agent" class="sr-only" >' in page.text or 'id="np-mode-agent" class="sr-only">' in page.text
    # Both modes and the interactive route are present in the (hidden-until-chosen) fields step.
    assert "Agent mode" in page.text
    assert "Interactive mode" in page.text
    assert 'action="/api/scan/interactive"' in page.text


# --- Interactive mode: activity log (interactive_log route + partial) ---


def test_interactive_log_empty_state(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/scan/interactive", data={"name": "Log Empty"}, follow_redirects=False)
    session_id = resp.headers["location"].rsplit("/", 1)[-1]

    page = client.get(f"/api/session/{session_id}/interactive-log")

    assert page.status_code == 200
    assert "No tool activity yet" in page.text


def test_interactive_log_lists_tool_calls_chronologically(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/scan/interactive", data={"name": "Log Filled"}, follow_redirects=False)
    session_id = resp.headers["location"].rsplit("/", 1)[-1]

    session = load_session(session_id)
    session["chat_threads"] = [{
        "id": "t1", "title": "T", "summary": "", "provider": None, "model": None, "pending": False,
        "created_at": "2026-01-01T00:00:00+00:00", "updated_at": "2026-01-01T00:00:05+00:00",
        "messages": [{
            "role": "assistant", "at": "2026-01-01T00:00:03+00:00",
            "segments": [
                {"type": "text", "content": "working"},
                {"type": "tool_call", "id": "c1", "name": "web_fetch", "arg_summary": "https://example.test",
                 "output": '{"status": "ok"}', "error": False, "done": True},
            ],
        }],
    }]
    session["active_chat_thread_id"] = "t1"
    from sessions.store import save_session
    save_session(session_id, session)

    page = client.get(f"/api/session/{session_id}/interactive-log")

    assert page.status_code == 200
    assert "web_fetch" in page.text
    assert "https://example.test" in page.text
    assert "1 tool call this session" in page.text


def test_interactive_log_flatten_helper_orders_across_threads():
    session = {"chat_threads": [
        {"messages": [{"role": "assistant", "at": "2026-01-01T00:00:10+00:00",
                       "segments": [{"type": "tool_call", "name": "second", "done": True}]}]},
        {"messages": [{"role": "assistant", "at": "2026-01-01T00:00:01+00:00",
                       "segments": [{"type": "tool_call", "name": "first", "done": True}]}]},
    ]}
    entries = main._interactive_log_entries(session)
    assert [e["name"] for e in entries] == ["first", "second"]  # sorted by timestamp, not thread order


def test_interactive_log_unknown_session_404s(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/api/session/usr_missing/interactive-log")

    assert resp.status_code == 404


def test_interactive_log_entries_get_stable_position_based_idx():
    session = {"chat_threads": [
        {"messages": [{"role": "assistant", "at": "2026-01-01T00:00:01+00:00",
                       "segments": [{"type": "tool_call", "name": "first", "done": True}]}]},
        {"messages": [{"role": "assistant", "at": "2026-01-01T00:00:10+00:00",
                       "segments": [{"type": "tool_call", "name": "second", "done": True}]}]},
    ]}
    entries = main._interactive_log_entries(session)
    assert [e["idx"] for e in entries] == [0, 1]
    # A later entry appended after the two above must not renumber them -- idiomorph (re_triage_
    # tab.html's morph-swap poll) keys each <details id="interactive-log-N"> off this exact number
    # to match it to its own previous render; if an earlier entry's idx ever shifted, morph would
    # match the wrong card and either lose or misplace its open/closed state.
    session["chat_threads"].append(
        {"messages": [{"role": "assistant", "at": "2026-01-01T00:00:20+00:00",
                       "segments": [{"type": "tool_call", "name": "third", "done": True}]}]},
    )
    entries_after = main._interactive_log_entries(session)
    assert [e["idx"] for e in entries_after] == [0, 1, 2]
    assert [e["name"] for e in entries_after] == ["first", "second", "third"]


# --- RE mode: baseline-triage node graph (main.py's _re_triage_graph_context) ---


def test_re_triage_graph_context_edges_stop_at_reticle_and_pill_boundaries_not_centers():
    # A single tool call places its one node dead at the top (angle -90deg): x=200, y=200-145=55.
    session = {"logs": [
        {"command": "/usr/local/bin/radare2 -q -c aaa /mnt/c/target.exe", "at": "2026-01-01T00:00:00+00:00", "status": "ok"},
    ]}
    node = main._re_triage_graph_context(session)["graph_nodes"][0]
    assert node["name"] == "radare2"
    assert (node["x"], node["y"]) == (200.0, 55.0)
    # Edge starts on the TARGET reticle's own boundary (r=34 from center, straight up from it),
    # never the reticle's center -- the real fix for lines running invisibly underneath the reticle.
    assert (node["edge_x1"], node["edge_y1"]) == (200.0, 166.0)
    # Edge ends on the pill's own rectangular boundary (its bottom edge, 13px above the pill's own
    # center y=55), never the pill's center -- the real fix for the old center-to-center line that
    # only ever "looked" right because the pill happened to be painted on top of it afterward.
    assert (node["edge_x2"], node["edge_y2"]) == (200.0, 68.0)
    assert node["edge_y2"] != node["y"]


def test_re_triage_graph_context_orders_by_first_use_and_flags_failed_tools():
    session = {"logs": [
        {"command": "/usr/local/bin/radare2 -q -c aaa", "at": "2026-01-01T00:00:00+00:00", "status": "ok"},
        {"command": 'custom_re_script({"source": "x"})', "at": "2026-01-01T00:00:01+00:00", "status": "error"},
        {"command": "/usr/local/bin/radare2 -q -c iij", "at": "2026-01-01T00:00:02+00:00", "status": "ok"},
    ]}
    ctx = main._re_triage_graph_context(session)
    by_name = {n["name"]: n for n in ctx["graph_nodes"]}

    assert by_name["radare2"]["order"] == 1
    assert by_name["custom_re_script"]["order"] == 2
    assert by_name["radare2"]["count"] == 2
    assert by_name["radare2"]["has_error"] is False
    assert by_name["custom_re_script"]["has_error"] is True
    # The most recent LOG entry (radare2's 2nd call) is latest, even though custom_re_script was
    # called more recently in wall-clock order than radare2's FIRST call -- "latest" tracks the
    # actual last-resolved entry, not first-use order.
    assert by_name["radare2"]["is_latest"] is True
    assert by_name["custom_re_script"]["is_latest"] is False
    assert ctx["graph_last_activity_at"] == "2026-01-01T00:00:02+00:00"


def test_re_triage_graph_context_stage_strip_marks_next_untouched_stage_after_the_furthest_one_reached():
    # Only "static" (radare2) has been touched -- Profiling was skipped entirely. The honest "next"
    # stage is the first untouched one AFTER static (dynamic), not "profile" (which is untouched
    # too, but already behind where the operator actually is).
    session = {"logs": [
        {"command": "/usr/local/bin/radare2 -q -c aaa", "at": "2026-01-01T00:00:00+00:00", "status": "ok"},
    ]}
    stages = {s["key"]: s for s in main._re_triage_graph_context(session)["graph_stages"]}

    assert stages["static"]["active"] is True
    assert stages["profile"]["active"] is False
    assert stages["profile"]["is_next"] is False
    assert stages["dynamic"]["is_next"] is True
    assert stages["automation"]["is_next"] is False


def test_re_triage_graph_context_first_stage_is_next_before_anything_has_run():
    ctx = main._re_triage_graph_context({"logs": []})
    assert ctx["graph_nodes"] == []
    assert ctx["graph_last_activity_at"] is None
    # Nothing has run yet, so the furthest-touched stage is "none" -- the first stage in sequence
    # (Profiling) is correctly the one awaiting. re_triage_tab_content.html never actually shows
    # this strip in this state (it's nested inside the {% if graph_nodes %} branch, graph_nodes is
    # empty here), but the underlying data should still be honest on its own terms.
    stages = {s["key"]: s for s in ctx["graph_stages"]}
    assert stages["profile"]["is_next"] is True
    assert sum(s["is_next"] for s in ctx["graph_stages"]) == 1


def test_re_triage_tab_route_returns_bare_content_not_a_nested_polling_shell(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client, "RE Graph Route")
    session = load_session(session_id)
    session["mode"] = "reverse_engineering"
    session["status"] = "processing"
    session["logs"] = [
        {"command": "/usr/local/bin/gdb --batch /mnt/c/target.exe", "at": "2026-01-01T00:00:00+00:00", "status": "ok"},
    ]
    store.save_session(session_id, session)

    page = client.get(f"/api/session/{session_id}/re-triage-tab")

    assert page.status_code == 200
    # This response fills #re-triage-tab's own innerHTML (hx-swap="morph:innerHTML" in
    # partials/re_triage_tab.html) -- it must be the bare content, never a second copy of that same
    # id, or morph would nest a duplicate polling shell inside the real one on every single poll.
    assert 'id="re-triage-tab"' not in page.text
    assert 'id="re-info-panel-graph"' in page.text
    assert 'id="re-info-panel-triage"' in page.text
    assert 'id="interactive-log-0"' in page.text
    assert "gdb" in page.text


# --- Quick Chat: the top-level, project-less chat (GET /chat, get_or_create_quick_chat_session) ---


def test_quick_chat_page_lazily_creates_a_standalone_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/chat")

    assert resp.status_code == 200
    assert 'id="chat-panel"' in resp.text
    session_id = chat_settings_store.load_chat_settings()["quick_chat_session_id"]
    assert session_id is not None
    session = load_session(session_id)
    assert session["mode"] == "standalone"
    assert session["name"] == "Quick Chat"


def test_quick_chat_page_shows_a_tab_strip_project_chat_does_not(tmp_path, monkeypatch):
    """Real, explicit operator ask: browser-style tabs for switching between recent threads on the
    standalone Quick Chat page specifically (templates/chat.html's show_chat_tabs) -- a project's
    own compact sidebar chat keeps just the history-icon dialog, unchanged."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    quick_chat_resp = client.get("/chat")
    project_session_id = _create_session(client, "Tabs Regression Project")
    project_resp = client.get(f"/session/{project_session_id}")

    assert 'id="chat-thread-tabs"' in quick_chat_resp.text
    assert 'id="chat-thread-tabs"' not in project_resp.text


def test_quick_chat_page_reuses_the_same_session_on_a_later_visit(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    client.get("/chat")
    first_id = chat_settings_store.load_chat_settings()["quick_chat_session_id"]

    client.get("/chat")

    assert chat_settings_store.load_chat_settings()["quick_chat_session_id"] == first_id


def test_quick_chat_session_never_appears_in_the_projects_list(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    client.get("/chat")
    _create_session(client, "A Real Project")

    listing = client.get("/sessions")

    assert listing.status_code == 200
    assert "Quick Chat" not in listing.text
    assert "A Real Project" in listing.text


def test_quick_chat_session_page_redirects_to_chat(tmp_path, monkeypatch):
    """A stale bookmark or manually-typed /session/<id> for the Quick Chat's own real session id
    must not render session.html (which assumes a real project's full field set) -- it sends the
    operator back to the actual page instead."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    client.get("/chat")
    session_id = chat_settings_store.load_chat_settings()["quick_chat_session_id"]

    resp = client.get(f"/session/{session_id}", follow_redirects=False)

    assert resp.status_code == 302
    assert resp.headers["location"] == "/chat"


def test_quick_chat_can_send_a_message(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "run_chat_turn_background", MagicMock())
    client = TestClient(main.app)
    client.get("/chat")
    session_id = chat_settings_store.load_chat_settings()["quick_chat_session_id"]

    resp = client.post(f"/api/session/{session_id}/chat", data={"message": "what's the difference between XSS and CSRF?"})

    assert resp.status_code == 200
    assert "what&#39;s the difference between XSS and CSRF?" in resp.text or "what's the difference between XSS and CSRF?" in resp.text
    main.run_chat_turn_background.assert_called_once_with(session_id)
