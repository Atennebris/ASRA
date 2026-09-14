"""main.py's Settings-page capability routes: GET /settings' "Optional interpreters/compilers"
context, and the three human-triggered POST actions (install, save a path override, save/clear the
sudo password). None of these have a ToolSpec registration -- the LLM agent can never reach them,
only the operator clicking the Settings UI, same category as the wordlist download/assign routes.
"""
import subprocess

from fastapi.testclient import TestClient

import main
from agent.tools import capability_install, capability_paths


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(capability_paths, "TOOL_PATHS_PATH", tmp_path / "tool_paths.json")
    env_path = tmp_path / ".env"
    env_path.write_text("")
    monkeypatch.setattr(capability_install, "_ENV_PATH", str(env_path))
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)


def test_get_settings_renders_the_optional_capabilities_section(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.get("/settings")

    assert resp.status_code == 200
    assert "Optional interpreters/compilers" in resp.text
    assert "Python 2" in resp.text


def test_install_route_rejects_an_unknown_capability(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/capabilities/not-a-real-capability/install")

    assert resp.status_code == 404


def test_install_route_succeeds_and_redirects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        capability_install.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "ok", ""),
    )
    client = TestClient(main.app)

    resp = client.post("/api/settings/capabilities/python2/install", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/settings"


def test_install_route_shows_the_fallback_command_inline_on_failure(tmp_path, monkeypatch):
    """Real guarantee this protects: a failed automatic install must never just vanish -- the
    operator needs the exact command to run themselves, right there on the page."""
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        capability_install.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, "", "sudo: a password is required\n"),
    )
    client = TestClient(main.app)

    resp = client.post("/api/settings/capabilities/python2/install")

    assert resp.status_code == 400
    assert "sudo apt-get install -y python2" in resp.text
    assert "Optional interpreters/compilers" in resp.text  # rest of the page still renders


def test_path_route_rejects_an_unknown_capability(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/capabilities/not-a-real-capability/path", data={"path": "/opt/x"})

    assert resp.status_code == 404


def test_path_route_persists_and_clears(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/capabilities/python2/path", data={"path": "/opt/python2.7/bin/python2"}, follow_redirects=False)
    assert resp.status_code == 303
    assert capability_paths.load_tool_paths()["python2"] == "/opt/python2.7/bin/python2"

    client.post("/api/settings/capabilities/python2/path", data={"path": ""})
    assert "python2" not in capability_paths.load_tool_paths()


def test_sudo_password_route_saves_and_is_reflected_in_settings_status(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)

    resp = client.post("/api/settings/sudo-password", data={"password": "hunter2"}, follow_redirects=False)

    assert resp.status_code == 303
    assert capability_install.has_sudo_password() is True
    page = client.get("/settings")
    assert "Sudo password saved" in page.text
    assert "hunter2" not in page.text  # never echoed back


def test_sudo_password_route_clears_with_a_blank_submit(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    capability_install.save_sudo_password("hunter2")
    client = TestClient(main.app)

    client.post("/api/settings/sudo-password", data={"password": ""})

    assert capability_install.has_sudo_password() is False
