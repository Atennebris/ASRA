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
