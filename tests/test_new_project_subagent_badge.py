"""templates/partials/new_project_form.html's per-project Subagent picker: a checkbox per
globally-ENABLED Subagent profile, shared by all three New Project modes (Agent/Interactive/
Reverse Engineering) via the subagent_project_checklist() macro. get_enabled_subagent_profiles is
registered as a CALLABLE Jinja global (main.py) rather than injected by a specific route's context,
since this form is {% include %}'d straight into base.html's own always-present New Project modal,
reachable from every page -- there's no single route handler to inject it into.

Every checkbox defaults to CHECKED; main.py's _resolve_enabled_subagent_ids resolves an
all-checked submission to None (session["enabled_subagent_ids"], no restriction at all) and an
actual narrowing to a real, explicit id list -- see sessions/store.py's create_session docstring.
"""
from fastapi.testclient import TestClient

import main
from agent.tools import subagent_store
from projects import paths as project_paths
from sessions import store
from sessions.store import load_session


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")


def _isolate_with_real_sessions(tmp_path, monkeypatch):
    """Full isolation for tests that actually POST to /api/scan and create a real session/project
    folder on disk -- same pattern as tests/test_rescan_route.py's own _isolate. Callers must
    `project_paths.resolve_projects_base_dir.cache_clear()` again in a finally block once done,
    same discipline every other test using this pattern already follows."""
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()


def test_badge_shows_no_subagents_by_default(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/")

    assert "No subagents enabled" in resp.text


def test_badge_reflects_a_live_enabled_profile_without_a_restart(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    store = subagent_store.add_profile("Recon Helper", ["dns_lookup"], "", None, None)
    profile_id = store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)

    resp = client.get("/")

    assert "1 subagent" in resp.text
    assert "Recon Helper" in resp.text
    assert "No subagents enabled" not in resp.text


def test_badge_pluralizes_correctly_for_multiple_enabled_profiles(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    for name in ("Bot One", "Bot Two"):
        store = subagent_store.add_profile(name, [], "", None, None)
        subagent_store.update_profile(store["profiles"][-1]["id"], enabled=True)

    resp = client.get("/")

    assert "2 subagents" in resp.text
    assert "Bot One" in resp.text
    assert "Bot Two" in resp.text


def test_badge_ignores_disabled_profiles():
    resp = TestClient(main.app).get("/")
    # The seeded default profile ships disabled -- must not be counted as "enabled".
    assert "Default Subagent" not in resp.text or "No subagents enabled" in resp.text


def test_badge_appears_on_the_sessions_page_too_via_the_shared_base_modal(tmp_path, monkeypatch):
    """The form lives inside base.html's own New Project modal, present on every page -- not
    just the home page's own direct inclusion."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/sessions")

    assert "subagent" in resp.text.lower()


def test_checklist_renders_one_checked_checkbox_per_enabled_profile(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    store = subagent_store.add_profile("Recon Helper", ["dns_lookup"], "", None, None)
    profile_id = store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)

    resp = client.get("/")

    assert 'name="enabled_subagent_ids"' in resp.text
    assert f'value="{profile_id}"' in resp.text
    # The checkbox for this profile must be checked by default -- find its own <input ...> tag
    # and confirm "checked" sits inside it, rather than just anywhere on the page.
    tag_start = resp.text.index(f'value="{profile_id}"')
    tag_end = resp.text.index(">", tag_start)
    assert "checked" in resp.text[tag_start:tag_end]


def test_leaving_every_checkbox_checked_stores_no_restriction(tmp_path, monkeypatch):
    """The common, default posture (every profile stays checked) must resolve to None -- no
    restriction at all -- not a frozen snapshot of whatever happened to be enabled at creation."""
    _isolate_with_real_sessions(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        profile_store = subagent_store.add_profile("Recon Helper", [], "", None, None)
        profile_id = profile_store["profiles"][-1]["id"]
        subagent_store.update_profile(profile_id, enabled=True)

        resp = client.post("/api/scan", data={
            "name": "All subagents project", "target": "example.com",
            "enabled_subagent_ids": [profile_id],  # every box left checked
        }, follow_redirects=False)

        assert resp.status_code == 303
        session_id = resp.headers["location"].split("/")[-1]
        session = load_session(session_id)
        assert session["enabled_subagent_ids"] is None
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_unchecking_a_profile_narrows_the_new_projects_own_allowlist(tmp_path, monkeypatch):
    _isolate_with_real_sessions(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        profile_store = subagent_store.add_profile("Recon Helper", [], "", None, None)
        kept_id = profile_store["profiles"][-1]["id"]
        subagent_store.update_profile(kept_id, enabled=True)
        profile_store = subagent_store.add_profile("Bruteforce Helper", [], "", None, None)
        unchecked_id = profile_store["profiles"][-1]["id"]
        subagent_store.update_profile(unchecked_id, enabled=True)

        resp = client.post("/api/scan", data={
            "name": "Narrowed project", "target": "example.com",
            "enabled_subagent_ids": [kept_id],  # unchecked_id deliberately left out
        }, follow_redirects=False)

        assert resp.status_code == 303
        session_id = resp.headers["location"].split("/")[-1]
        session = load_session(session_id)
        assert session["enabled_subagent_ids"] == [kept_id]
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_unchecking_every_profile_stores_an_explicit_empty_allowlist(tmp_path, monkeypatch):
    _isolate_with_real_sessions(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        profile_store = subagent_store.add_profile("Recon Helper", [], "", None, None)
        subagent_store.update_profile(profile_store["profiles"][-1]["id"], enabled=True)

        resp = client.post("/api/scan", data={
            "name": "Zero subagents project", "target": "example.com",
            # enabled_subagent_ids omitted entirely -- every box unchecked client-side.
        }, follow_redirects=False)

        assert resp.status_code == 303
        session_id = resp.headers["location"].split("/")[-1]
        session = load_session(session_id)
        assert session["enabled_subagent_ids"] == []
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
