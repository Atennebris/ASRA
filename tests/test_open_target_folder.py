"""RE mode's "Open target folder" button (main.py's open_target_folder route) -- opens, or (under
WSL2) surfaces a copyable path for, the local file/folder session["target"] resolved to. Real
Explorer/xdg-open launches are covered at the projects.paths.resolve_open_target level
(tests/test_projects_paths.py); these tests only check the route wires session["target"] through
correctly and renders the right partial for each outcome.
"""
from fastapi.testclient import TestClient

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()


def _re_session(target):
    session_id = create_session(target, name="RE open-folder project", mode="reverse_engineering")
    session = load_session(session_id)
    session["target"] = target
    store.save_session(session_id, session)
    return session_id


def test_open_target_folder_route_reports_missing_target(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = _re_session(str(tmp_path / "does-not-exist"))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/open-target-folder")
    assert resp.status_code == 200
    assert "Not found on disk" in resp.text


def test_open_target_folder_route_handles_a_real_local_target(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(project_paths, "_is_wsl", lambda: False)
    monkeypatch.setattr(project_paths.sys, "platform", "linux")
    launched = {}
    monkeypatch.setattr(project_paths.subprocess, "Popen", lambda args, **kw: launched.update(args=args))

    target_dir = tmp_path / "re_target"
    target_dir.mkdir()
    session_id = _re_session(str(target_dir))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/open-target-folder")
    assert resp.status_code == 200
    assert "Opened" in resp.text
    assert launched["args"] == ["xdg-open", str(target_dir)]


def test_open_target_folder_route_under_wsl2_never_launches_and_shows_copyable_path(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(project_paths, "_is_wsl", lambda: True)
    popen_calls = []
    monkeypatch.setattr(project_paths.subprocess, "Popen", lambda *a, **kw: popen_calls.append((a, kw)))

    target_dir = tmp_path / "re_target"
    target_dir.mkdir()
    session_id = _re_session(str(target_dir))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/open-target-folder")
    assert resp.status_code == 200
    assert popen_calls == []
    assert "isn't safe from inside WSL2" in resp.text


def test_open_target_folder_route_handles_multiple_comma_separated_targets(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(project_paths, "_is_wsl", lambda: False)
    monkeypatch.setattr(project_paths.sys, "platform", "linux")
    monkeypatch.setattr(project_paths.subprocess, "Popen", lambda *a, **kw: None)

    first = tmp_path / "1"
    second = tmp_path / "2"
    first.mkdir()
    second.mkdir()
    session_id = _re_session(f"{first}, {second}")
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/open-target-folder")
    assert resp.status_code == 200
    assert resp.text.count("Opened") == 2


def test_open_target_folder_route_missing_session_404s():
    client = TestClient(main.app)
    resp = client.post("/api/session/does-not-exist/open-target-folder")
    assert resp.status_code == 404
