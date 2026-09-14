"""projects/paths.py: where new project folders get created, per-OS + WSL2-aware, overridable."""
from pathlib import Path

import pytest

from projects import paths


@pytest.fixture(autouse=True)
def _clear_cache():
    paths.resolve_projects_base_dir.cache_clear()
    yield
    paths.resolve_projects_base_dir.cache_clear()


def test_projects_dir_override_wins_over_everything(monkeypatch, tmp_path):
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "custom"))
    assert paths.resolve_projects_base_dir() == tmp_path / "custom"


def test_projects_dir_override_expands_user(monkeypatch):
    monkeypatch.setenv("PROJECTS_DIR", "~/somewhere")
    assert paths.resolve_projects_base_dir() == Path("~/somewhere").expanduser()


def test_windows_path_to_wsl_conversion():
    assert paths._windows_path_to_wsl("C:\\Users\\user\\Documents") == Path("/mnt/c/Users/user/Documents")


def test_windows_path_to_wsl_lowercases_drive_letter():
    assert str(paths._windows_path_to_wsl("D:\\Data")).startswith("/mnt/d")


def test_is_wsl_true_when_env_var_set(monkeypatch):
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    assert paths._is_wsl() is True


def test_wsl_windows_documents_dir_returns_none_on_interop_failure(monkeypatch):
    def _boom(*args, **kwargs):
        raise OSError("cmd.exe not found")

    monkeypatch.setattr(paths.subprocess, "run", _boom)
    assert paths._wsl_windows_documents_dir() is None


def test_resolve_falls_back_to_home_documents_when_wsl_interop_fails(monkeypatch):
    monkeypatch.delenv("PROJECTS_DIR", raising=False)
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    monkeypatch.setattr(paths, "_wsl_windows_documents_dir", lambda: None)

    base = paths.resolve_projects_base_dir()
    assert base == Path.home() / "Documents" / paths._PROJECTS_SUBDIR


# resolve_open_target -- the RE-mode "Open target folder" button's backend. WSL2 must NEVER spawn
# explorer.exe from this process (a real, confirmed incident already hit that exact interop hop
# elsewhere in this project); native Linux/macOS is safe to launch directly.
def test_resolve_open_target_missing_path_is_an_error(tmp_path):
    result = paths.resolve_open_target(tmp_path / "does-not-exist")
    assert result == {"kind": "error", "message": f"Not found on disk: {tmp_path / 'does-not-exist'}"}


def test_resolve_open_target_file_resolves_to_its_parent_folder(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "_is_wsl", lambda: False)
    monkeypatch.setattr(paths.sys, "platform", "linux")
    launched = {}
    monkeypatch.setattr(paths.subprocess, "Popen", lambda args, **kw: launched.update(args=args, kw=kw))

    target_file = tmp_path / "crackme.exe"
    target_file.write_bytes(b"\x00")
    result = paths.resolve_open_target(target_file)

    assert result == {"kind": "opened", "folder": str(tmp_path)}
    assert launched["args"] == ["xdg-open", str(tmp_path)]
    assert launched["kw"]["start_new_session"] is True


def test_resolve_open_target_directory_used_as_is(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "_is_wsl", lambda: False)
    monkeypatch.setattr(paths.sys, "platform", "darwin")
    launched = {}
    monkeypatch.setattr(paths.subprocess, "Popen", lambda args, **kw: launched.update(args=args))

    result = paths.resolve_open_target(tmp_path)
    assert result == {"kind": "opened", "folder": str(tmp_path)}
    assert launched["args"] == ["open", str(tmp_path)]


def test_resolve_open_target_never_spawns_a_process_under_wsl2(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "_is_wsl", lambda: True)
    popen_calls = []
    monkeypatch.setattr(paths.subprocess, "Popen", lambda *a, **kw: popen_calls.append((a, kw)))

    result = paths.resolve_open_target(tmp_path)
    assert result["kind"] == "windows_path"
    assert popen_calls == []


def test_resolve_open_target_wsl2_converts_mnt_drive_path(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "_is_wsl", lambda: True)
    monkeypatch.setattr(paths, "_wsl_folder_to_windows_path", lambda folder: "C:\\fake\\path")

    result = paths.resolve_open_target(tmp_path)
    assert result == {"kind": "windows_path", "path": "C:\\fake\\path", "folder": str(tmp_path)}


def test_wsl_folder_to_windows_path_converts_mnt_mount():
    assert paths._wsl_folder_to_windows_path(Path("/mnt/c/Users/user/Desktop/ASRA")) == "C:\\Users\\user\\Desktop\\ASRA"


def test_wsl_folder_to_windows_path_falls_back_to_wsl_unc(monkeypatch):
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    assert paths._wsl_folder_to_windows_path(Path("/home/user/re_target")) == "\\\\wsl$\\Ubuntu-24.04\\home\\user\\re_target"


def test_wsl_folder_to_windows_path_bare_fallback_without_distro_name(monkeypatch):
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    assert paths._wsl_folder_to_windows_path(Path("/home/user/re_target")) == "/home/user/re_target"


def test_resolve_open_target_unknown_platform_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "_is_wsl", lambda: False)
    monkeypatch.setattr(paths.sys, "platform", "freebsd")
    result = paths.resolve_open_target(tmp_path)
    assert result["kind"] == "error"
