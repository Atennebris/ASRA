"""main.py's Subagents/Tools settings pages: GET /subagents and GET /tools render, and the full
CRUD flow (create/edit/toggle/delete) for a subagent profile actually persists through
agent/tools/subagent_store.py -- same isolation discipline as test_wordlist_settings_routes.py.
"""
import json

from fastapi.testclient import TestClient

import main
from agent.tools import subagent_store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")


def test_get_subagents_renders(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/subagents")

    assert resp.status_code == 200
    assert "Subagents" in resp.text
    assert "New subagent" in resp.text
    assert "Default Subagent" in resp.text  # the seeded default profile


def test_edit_dialog_is_not_nested_inside_the_subagents_table(tmp_path, monkeypatch):
    """Real, confirmed bug this fixes: each profile's Edit <dialog> (and its own <form>, holding
    the Provider & Model picker's new Test button) used to render INLINE inside the table's
    <tbody>, as a direct sibling of each <tr>. <dialog> is not valid <tbody> content, so Chrome's
    HTML parser silently "foster parents" it out of the table at parse time -- and the dialog's own
    <form> tag got dropped entirely in the process (a live browser reproduction confirmed
    document.querySelector("...Test button...").closest("form") returned null), breaking anything
    inside relying on real DOM form-ancestry (hx-include="closest form"). Every <dialog> must now
    render after the closing </table>, never between <tbody> and </tbody>."""
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/subagents")

    assert resp.status_code == 200
    tbody_start = resp.text.index("<tbody>")
    tbody_end = resp.text.index("</tbody>")
    assert "<dialog" not in resp.text[tbody_start:tbody_end]
    assert "<dialog" in resp.text  # the dialogs still render, just hoisted outside the table


def test_get_tools_renders_with_real_tool_availability(tmp_path, monkeypatch):
    client = TestClient(main.app)

    resp = client.get("/tools")

    assert resp.status_code == 200
    assert "Tools" in resp.text
    assert "nmap" in resp.text  # a real registered tool name


def test_subagent_context_never_offers_record_finding_or_record_target(tmp_path, monkeypatch):
    # Real, confirmed incident: a subagent's own allowed_tools could include record_finding,
    # the tool would return "status": "ok" every time it was called, and none of those recorded
    # findings ever actually reached session["findings"] (persistence only happens inside each
    # phase's own execute() closure, which a subagent's loop never gets — see agent/core.py's
    # _delegate_to_subagent_impl). Checking the box was silently pointless; it must not be offered.
    _isolate(tmp_path, monkeypatch)
    ctx = main._subagent_context()

    assert "record_finding" not in ctx["available_tools"]
    assert "record_target" not in ctx["available_tools"]
    # Same-family exclusions from the recursive-delegation fix must still hold too.
    assert "delegate_to_subagent" not in ctx["available_tools"]
    assert "check_subagent_task" not in ctx["available_tools"]
    # Their six terminal/recording siblings (each phase's own terminal_tool or a live-recording
    # tool, all only actually applied inside that phase's own execute() closure a subagent never
    # gets) share the identical gap and must be excluded the same way.
    for tool_name in (
        "record_hypothesis", "resolve_hypothesis", "record_exploit_decision",
        "record_chain_result", "record_reverification_result", "record_skeptical_verification_result",
    ):
        assert tool_name not in ctx["available_tools"]


def test_create_subagent_route_persists_a_real_profile(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post(
        "/api/subagents",
        data={"name": "OSINT Bot", "allowed_tools": ["dns_lookup"], "instructions": "Passive recon only.", "provider": "", "model": ""},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/subagents"
    store = subagent_store.load_subagent_profiles()
    created = next(p for p in store["profiles"] if p["name"] == "OSINT Bot")
    assert created["allowed_tools"] == ["dns_lookup"]
    assert created["instructions"] == "Passive recon only."
    assert created["enabled"] is False


def test_create_subagent_route_rejects_a_blank_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/subagents", data={"name": "   "})

    assert resp.status_code == 400
    assert "Name this subagent" in resp.text


def test_toggle_subagent_route_flips_enabled_state(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    store = subagent_store.add_profile("Toggle Bot", [], "", None, None)
    profile_id = store["profiles"][-1]["id"]
    assert subagent_store.load_subagent_profiles()["profiles"][-1]["enabled"] is False

    resp = client.post(f"/api/subagents/{profile_id}/toggle", follow_redirects=False)

    assert resp.status_code == 303
    updated = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == profile_id)
    assert updated["enabled"] is True

    client.post(f"/api/subagents/{profile_id}/toggle")
    updated = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == profile_id)
    assert updated["enabled"] is False


def test_toggle_subagent_route_404s_for_an_unknown_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/subagents/does-not-exist/toggle")

    assert resp.status_code == 404


def test_update_subagent_route_persists_changed_fields(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    store = subagent_store.add_profile("Original Name", [], "", None, None)
    profile_id = store["profiles"][-1]["id"]

    resp = client.post(
        f"/api/subagents/{profile_id}",
        data={"name": "Renamed Bot", "allowed_tools": ["nmap", "dns_lookup"], "instructions": "New instructions.", "provider": "opencode-zen", "model": "big-pickle"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    updated = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == profile_id)
    assert updated["name"] == "Renamed Bot"
    assert updated["allowed_tools"] == ["nmap", "dns_lookup"]
    assert updated["provider"] == "opencode-zen"
    assert updated["model"] == "big-pickle"


def test_delete_subagent_route_removes_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    store = subagent_store.add_profile("Delete Me", [], "", None, None)
    profile_id = store["profiles"][-1]["id"]

    resp = client.post(f"/api/subagents/{profile_id}/delete", follow_redirects=False)

    assert resp.status_code == 303
    remaining_ids = {p["id"] for p in subagent_store.load_subagent_profiles()["profiles"]}
    assert profile_id not in remaining_ids


def test_export_subagents_route_downloads_the_whole_store_as_json(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    subagent_store.add_profile("Export Me", ["dns_lookup"], "recon only", "opencode-zen", "big-pickle")

    resp = client.get("/api/subagents/export")

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/json"
    assert "asra_subagents.json" in resp.headers["content-disposition"]
    body = resp.json()
    assert any(p["name"] == "Export Me" for p in body["profiles"])


def test_import_subagents_route_merges_new_profiles_and_reports_the_count(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    payload = {"profiles": [
        {"id": "imported-1", "name": "Imported Bot", "enabled": True, "allowed_tools": ["nmap"],
         "instructions": "", "provider": None, "model": None},
    ]}

    resp = client.post("/api/subagents/import", data={"data": json.dumps(payload)})

    assert resp.status_code == 200
    assert "Added 1 new profile" in resp.text
    imported = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == "imported-1")
    assert imported["enabled"] is False  # imported profiles always land disabled for review


def test_import_subagents_route_skips_duplicates_already_present(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    payload = {"profiles": [{"id": "imported-1", "name": "Imported Bot", "allowed_tools": []}]}
    data = json.dumps(payload)
    client.post("/api/subagents/import", data={"data": data})

    resp = client.post("/api/subagents/import", data={"data": data})

    assert resp.status_code == 200
    assert "skipped 1 already configured" in resp.text


def test_import_subagents_route_reports_invalid_json_without_crashing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/subagents/import", data={"data": "{not valid json"})

    assert resp.status_code == 200
    assert "not valid JSON" in resp.text
