"""main.py's Tools -> "Install (heavy)" routes: the same confirm/start/status mechanism as the base
"Install" button, parameterized by `heavy=True` rather than a second set of near-duplicate
templates/routes. Mocks the underlying arsenal_install.py calls -- these tests must never actually
spawn setup_tools_heavy.sh (a real, slow, system-modifying subprocess), only verify main.py's own
routing/template wiring.
"""
from fastapi.testclient import TestClient

import main


def test_settings_tools_tab_shows_the_heavy_install_button():
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "Install (heavy)" in resp.text


def test_heavy_install_confirm_route_shows_heavy_copy_and_omits_the_wordlists_checkbox(monkeypatch):
    monkeypatch.setattr(main, "heavy_can_autostart", lambda: {"ok": True, "reason": "root", "command": "bash setup_tools_heavy.sh"})
    client = TestClient(main.app)

    resp = client.get("/api/tools/arsenal/heavy-install/confirm")

    assert resp.status_code == 200
    assert "setup_tools_heavy.sh" in resp.text
    assert "Ghidra" in resp.text
    assert "include_wordlists" not in resp.text  # that opt-in checkbox is the base-arsenal-only
    assert '/api/tools/arsenal/heavy-install/start' in resp.text


def test_heavy_install_start_blocked_shows_the_manual_command(monkeypatch):
    monkeypatch.setattr(main, "start_heavy_arsenal_install", lambda: {
        "status": "manual", "message": "sudo needs a password", "command": "sudo bash setup_tools_heavy.sh",
    })
    client = TestClient(main.app)

    resp = client.post("/api/tools/arsenal/heavy-install/start")

    assert resp.status_code == 200
    assert "sudo needs a password" in resp.text
    assert "setup_tools_heavy.sh" in resp.text


def test_heavy_install_start_success_polls_the_heavy_status_endpoint_not_the_base_one(monkeypatch):
    monkeypatch.setattr(main, "start_heavy_arsenal_install", lambda: {"status": "started"})
    monkeypatch.setattr(main, "heavy_arsenal_install_status", lambda: {
        "state": "running", "running": True, "returncode": None, "succeeded": None,
        "command": "bash setup_tools_heavy.sh", "wordlists": False, "started_at": 0.0,
        "log": "installing...", "log_path": "/tmp/arsenal-heavy-install.log",
    })
    client = TestClient(main.app)

    resp = client.post("/api/tools/arsenal/heavy-install/start")

    assert resp.status_code == 200
    assert "Installing the heavy arsenal" in resp.text
    assert "/api/tools/arsenal/heavy-install/status" in resp.text
    assert "/api/tools/arsenal/install/status" not in resp.text  # never the base installer's endpoint


def test_heavy_install_status_route_renders_idle(monkeypatch):
    monkeypatch.setattr(main, "heavy_arsenal_install_status", lambda: {
        "state": "idle", "running": False, "returncode": None, "succeeded": None,
        "command": None, "wordlists": False, "started_at": None, "log": "", "log_path": "/tmp/x.log",
    })
    client = TestClient(main.app)

    resp = client.get("/api/tools/arsenal/heavy-install/status")

    assert resp.status_code == 200
    assert "hasn" in resp.text.lower()  # "Install hasn't run yet."
