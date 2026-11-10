"""Regression tests for a batch of operator-reported UI bugs:
- page action buttons sitting ON the decorative header banner (Projects, Subagents, Playbook);
- the chat panel's provider/model pick snapping back after a page refresh (it was only saved on Send);
- the chat tab strip's doubled "dot dot" (now laid out like the Terminal tabs);
- Settings reloading to its first tab on every wordlist pick / plain form save.
"""
import re

from fastapi.testclient import TestClient

import main
import projects.paths as project_paths
from agent.chat import save_chat_picker
from agent.tools import chat_settings_store
from sessions import store
from sessions.store import load_session


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(chat_settings_store, "CHAT_SETTINGS_STORE_PATH", tmp_path / "chat_settings.json")

    async def _noop(session_id, provider_id=None, entry_point="recon"):
        return None

    monkeypatch.setattr(main, "run_session", _noop)


def _create_session(client: TestClient) -> str:
    resp = client.post("/api/scan", data={"name": "picker-test", "target": "example.com"}, follow_redirects=False)
    assert resp.status_code == 303, resp.text
    return resp.headers["location"].rsplit("/", 1)[-1]


# --- header banners carry only the title -----------------------------------------------------------


def test_projects_new_project_button_is_in_a_toolbar_below_the_header_not_on_the_banner():
    html = TestClient(main.app).get("/sessions").text
    assert re.search(r'<div class="flex items-center justify-end mb-4">\s*<button[^>]*new-project-modal', html)
    assert "justify-between py-3.5" not in html  # the old title+button header shape is gone


def test_subagents_export_import_are_in_a_toolbar_below_the_header():
    html = TestClient(main.app).get("/subagents").text
    assert re.search(r'<div class="flex items-center justify-end gap-2 mb-4">\s*<a href="/api/subagents/export"', html)
    header = html[html.index("<h1"): html.index('<div class="flex items-center justify-end gap-2 mb-4">')]
    assert "/api/subagents/export" not in header and "subagent-import" not in header


def test_playbook_action_buttons_are_in_a_toolbar_below_the_header():
    html = TestClient(main.app).get("/playbook").text
    toolbar = re.search(r'<div class="flex items-center justify-end gap-2 flex-wrap mb-4">(.*?)</div>\s*\n\s*(?:<|\{)', html, re.S)
    assert toolbar is not None
    assert "asraToggleLibraryPanel" in html[html.index('justify-end gap-2 flex-wrap mb-4'):]
    banner = html[html.index("<h1"): html.index('justify-end gap-2 flex-wrap mb-4')]
    assert "asraToggleLibraryPanel" not in banner and "playbook-add" not in banner


# --- chat provider/model pick is remembered the moment it changes ----------------------------------


def test_picking_a_provider_in_chat_survives_a_reload_without_sending_anything(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client)

    resp = client.post(f"/api/session/{session_id}/chat/picker", data={"provider": "openrouter", "model": "some/model", "free_only": "true"})
    assert resp.status_code == 200

    thread = next(t for t in load_session(session_id)["chat_threads"] if t["id"] == load_session(session_id)["active_chat_thread_id"])
    assert (thread["provider"], thread["model"]) == ("openrouter", "some/model")
    last = chat_settings_store.load_chat_settings()
    assert (last["last_provider"], last["last_model"], last["last_free_only"]) == ("openrouter", "some/model", True)


def test_picker_save_does_not_rewrite_the_session_when_nothing_changed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client)
    client.post(f"/api/session/{session_id}/chat/picker", data={"provider": "openrouter", "model": "m"})

    writes = []
    real_save = main.save_chat_picker.__globals__["save_session"]
    monkeypatch.setattr("agent.chat.save_session", lambda *a, **k: (writes.append(1), real_save(*a, **k))[1])
    save_chat_picker(session_id, "openrouter", "m")
    assert writes == []  # a no-op change must not touch a session file a running turn may also be writing


def test_picker_route_404s_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert TestClient(main.app).post("/api/session/nope/chat/picker", data={"provider": "x", "model": "y"}).status_code == 404


def test_blank_picker_values_mean_same_as_main_agent(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    session_id = _create_session(client)
    client.post(f"/api/session/{session_id}/chat/picker", data={"provider": "openrouter", "model": "m"})
    client.post(f"/api/session/{session_id}/chat/picker", data={"provider": "", "model": ""})
    session = load_session(session_id)
    thread = next(t for t in session["chat_threads"] if t["id"] == session["active_chat_thread_id"])
    assert thread["provider"] is None and thread["model"] is None


def test_chat_panel_wires_the_picker_to_save_on_user_changes_only():
    html = TestClient(main.app).get("/chat").text
    assert "/chat/picker" in html
    assert "providerPicked" in html  # automatic model-list reloads must not overwrite a saved model


# --- chat tab strip: same layout as the Terminal tabs ----------------------------------------------


def test_chat_tab_order_is_dot_label_color_close_like_the_terminal_tabs():
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader("templates"), autoescape=True)
    html = env.get_template("partials/chat_thread_tabs.html").render(
        threads=[{"id": "t1", "title": "New chat", "pending": False, "color": ""}],
        session={"session_id": "s1", "active_chat_thread_id": "t1"}, oob=False,
    )
    order = [html.index(marker) for marker in ('class="chat-tab-dot', 'class="chat-tab-label', 'class="chat-tab-color-btn', 'class="chat-tab-close')]
    assert order == sorted(order), "dot must come BEFORE the label, never beside the color swatch"
    assert "group-hover" not in html  # visibility is CSS-driven now, same as the Terminal's tabs


# --- Settings keeps its tab -------------------------------------------------------------------------


def test_wordlist_assign_via_htmx_answers_204_and_does_not_redirect(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "set_assignment", lambda role, path: None)
    role = sorted(main.ASSIGNABLE_ROLES)[0]
    client = TestClient(main.app)
    htmx = client.post("/api/settings/wordlists/assign", data={"role": role, "path": ""}, headers={"HX-Request": "true"}, follow_redirects=False)
    assert htmx.status_code == 204
    plain = client.post("/api/settings/wordlists/assign", data={"role": role, "path": ""}, follow_redirects=False)
    assert plain.status_code == 303  # no-JS fallback unchanged


def test_settings_page_carries_the_tab_hash_on_plain_form_posts():
    html = TestClient(main.app).get("/settings").text
    assert 'addEventListener("submit"' in html and "url.hash = location.hash" in html
    assert 'hx-post="/api/settings/wordlists/assign"' not in html or 'hx-trigger="change"' in html
