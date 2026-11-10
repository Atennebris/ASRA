"""main.py's Settings -> Tools -> "Custom tools path" routes: GET /settings' own status line, and
the two human-triggered POST actions (live "Test path", persisting "Save path"). Neither has a
ToolSpec registration -- only the operator clicking the Tools tab can reach them, same category as
the sibling capability-path/sudo-password routes (tests/test_capability_settings_routes.py).
"""
from fastapi.testclient import TestClient

import main
from agent.tools import custom_tools_root


def _isolate(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("")
    monkeypatch.setattr(custom_tools_root, "_ENV_PATH", str(env_path))
    monkeypatch.delenv("TOOLS_CUSTOM_ROOT", raising=False)


def test_get_settings_renders_the_custom_tools_path_block(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "Custom tools path" in resp.text
    assert "No custom tools path saved" in resp.text


def test_get_settings_shows_the_saved_value(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    custom_tools_root.save_custom_tools_root("/mnt/e/tools")
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert "/mnt/e/tools" in resp.text


def test_test_route_translates_and_reports_found_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: ["nmap", "nuclei"])
    (tmp_path / "nmap").write_text("#!/bin/sh\n")
    client = TestClient(main.app)

    resp = client.post("/api/tools/custom-root/test", data={"path": str(tmp_path)})

    assert resp.status_code == 200
    assert "nmap" in resp.text
    assert "nuclei" in resp.text
    assert "Save path" in resp.text  # the follow-up save form is always offered


def test_save_route_persists_and_redirects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/tools/custom-root/save", data={"path": "E:\\tools"}, follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/settings"
    assert custom_tools_root.get_custom_tools_root() == "/mnt/e/tools"


def test_save_route_with_blank_clears_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    custom_tools_root.save_custom_tools_root("/mnt/e/tools")
    client = TestClient(main.app)

    client.post("/api/tools/custom-root/save", data={"path": ""})

    assert custom_tools_root.get_custom_tools_root() is None
