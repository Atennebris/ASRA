"""main.py's Settings -> Tools -> "Custom tools" routes: add/toggle/update/delete. Same category
as tests/test_custom_tools_root_routes.py -- only the operator clicking the Tools tab can reach
these, never the LLM agent (no ToolSpec registration for any of them)."""
from fastapi.testclient import TestClient

import main
from agent.tools import custom_tools_root, custom_tools_store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(custom_tools_store, "CUSTOM_TOOLS_STORE_PATH", tmp_path / "custom_tools.json")


def test_get_settings_renders_registered_custom_tools(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    custom_tools_store.add_custom_tool(name="mytool", path="/opt/a/mytool", description="does a thing", requires_target=True, category="recon")
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "mytool" in resp.text
    assert "(custom)" in resp.text


def test_add_route_registers_and_redirects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "capture_usage_hint", lambda path: "autofilled usage text")
    client = TestClient(main.app)

    resp = client.post("/api/tools/custom-tools/add", data={"name": "mytool", "path": "/opt/a/mytool"}, follow_redirects=False)

    assert resp.status_code == 303
    records = custom_tools_store.load_custom_tools()
    assert len(records) == 1
    assert records[0]["name"] == "mytool"
    assert records[0]["description"] == "autofilled usage text"
    assert records[0]["enabled"] is True
    assert records[0]["requires_target"] is True  # safe default


def test_toggle_route_persists_and_returns_no_content(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = custom_tools_store.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="recon")
    client = TestClient(main.app)

    resp = client.post(f"/api/tools/custom-tools/{record['id']}/toggle", data={})  # unchecked -> no "enabled" field at all

    assert resp.status_code == 204
    assert custom_tools_store.get_custom_tool(record["id"])["enabled"] is False


def test_toggle_route_rejects_an_unknown_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/tools/custom-tools/not-a-real-id/toggle", data={"enabled": "on"})

    assert resp.status_code == 404


def test_update_route_saves_description_category_and_requires_target(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = custom_tools_store.add_custom_tool(name="mytool", path="/opt/a/mytool", description="old", requires_target=True, category="recon")
    client = TestClient(main.app)

    resp = client.post(
        f"/api/tools/custom-tools/{record['id']}/update",
        data={"description": "new description", "category": "scan", "requires_target": ""},  # unchecked
        follow_redirects=False,
    )

    assert resp.status_code == 303
    updated = custom_tools_store.get_custom_tool(record["id"])
    assert updated["description"] == "new description"
    assert updated["category"] == "scan"
    assert updated["requires_target"] is False


def test_delete_route_removes_and_redirects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    record = custom_tools_store.add_custom_tool(name="mytool", path="/opt/a/mytool", description="", requires_target=True, category="recon")
    client = TestClient(main.app)

    resp = client.post(f"/api/tools/custom-tools/{record['id']}/delete", follow_redirects=False)

    assert resp.status_code == 303
    assert custom_tools_store.load_custom_tools() == []


def test_delete_route_rejects_an_unknown_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/tools/custom-tools/not-a-real-id/delete")

    assert resp.status_code == 404


def test_test_path_route_includes_custom_candidates(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: [])
    binary = tmp_path / "mystery_tool"
    binary.write_text("#!/bin/sh\n")
    import stat
    binary.chmod(binary.stat().st_mode | stat.S_IEXEC)
    client = TestClient(main.app)

    resp = client.post("/api/tools/custom-root/test", data={"path": str(tmp_path)})

    assert resp.status_code == 200
    assert "mystery_tool" in resp.text
    assert "/api/tools/custom-tools/add" in resp.text
