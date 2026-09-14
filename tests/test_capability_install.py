"""agent/tools/capability_registry.py, capability_paths.py, capability_install.py: the Settings ->
Optional interpreters/compilers table + real path resolution + real (but safely-degrading) install
execution. install_capability's three sudo modes (already root / SUDO_PASSWORD set -> sudo -S /
nothing set -> sudo -n) are the part worth real coverage -- a web request has no TTY, so the
non-interactive paths must never hang and must always hand back a plain, human-runnable fallback
command on any failure.
"""
import subprocess

from agent.tools import capability_install, capability_paths
from agent.tools.capability_registry import OPTIONAL_CAPABILITIES, get_capability


def test_registry_has_python2_and_c_cpp_compilers():
    ids = {c["id"] for c in OPTIONAL_CAPABILITIES}
    assert {"python2", "gcc", "g++"} <= ids


def test_get_capability_returns_none_for_unknown_id():
    assert get_capability("not-a-real-capability") is None


# --- capability_paths ---------------------------------------------------------------------------


def _isolate_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(capability_paths, "TOOL_PATHS_PATH", tmp_path / "tool_paths.json")


def test_resolve_interpreter_path_falls_back_to_path_when_no_override(tmp_path, monkeypatch):
    _isolate_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(capability_paths.shutil, "which", lambda name: "/usr/bin/python2" if name == "python2" else None)

    assert capability_paths.resolve_interpreter_path("python2") == "/usr/bin/python2"


def test_resolve_interpreter_path_prefers_a_saved_override_that_still_exists(tmp_path, monkeypatch):
    _isolate_paths(tmp_path, monkeypatch)
    real_binary = tmp_path / "python2.7"
    real_binary.write_text("#!/bin/sh\n")
    capability_paths.save_tool_path("python2", str(real_binary))
    monkeypatch.setattr(capability_paths.shutil, "which", lambda name: "/usr/bin/python2")

    assert capability_paths.resolve_interpreter_path("python2") == str(real_binary)


def test_resolve_interpreter_path_ignores_a_stale_override(tmp_path, monkeypatch):
    """The operator moved/removed the binary since saving the override -- falls back to PATH rather
    than failing outright, same "don't trust stale config blindly" instinct as agent/settings.py's
    own fallback when a saved provider/model has since disappeared."""
    _isolate_paths(tmp_path, monkeypatch)
    capability_paths.save_tool_path("python2", str(tmp_path / "does-not-exist"))
    monkeypatch.setattr(capability_paths.shutil, "which", lambda name: "/usr/bin/python2")

    assert capability_paths.resolve_interpreter_path("python2") == "/usr/bin/python2"


def test_save_tool_path_with_blank_clears_it(tmp_path, monkeypatch):
    _isolate_paths(tmp_path, monkeypatch)
    real_binary = tmp_path / "python2.7"
    real_binary.write_text("#!/bin/sh\n")
    capability_paths.save_tool_path("python2", str(real_binary))

    capability_paths.save_tool_path("python2", "")

    assert capability_paths.load_tool_paths() == {}


def test_get_capability_status_reports_not_installed(tmp_path, monkeypatch):
    _isolate_paths(tmp_path, monkeypatch)
    monkeypatch.setattr(capability_paths.shutil, "which", lambda name: None)

    status = capability_paths.get_capability_status("python2")

    assert status == {"installed": False, "path": None, "source": None}


# --- capability_install: build_install_command ---------------------------------------------------


def test_build_install_command_returns_none_for_unknown_capability(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    assert capability_install.build_install_command("not-a-real-capability") is None


def test_build_install_command_returns_none_without_a_package_manager(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: None)
    assert capability_install.build_install_command("python2") is None


def test_build_install_command_uses_the_right_package_name_per_manager(monkeypatch):
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: False)

    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "dnf")
    assert capability_install.build_install_command("g++") == ["sudo", "-n", "dnf", "install", "-y", "gcc-c++"]

    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "pacman")
    assert capability_install.build_install_command("g++") == ["sudo", "-n", "pacman", "-S", "--noconfirm", "--needed", "gcc"]


def test_build_install_command_omits_sudo_when_already_root(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 0)

    assert capability_install.build_install_command("python2") == ["apt-get", "install", "-y", "python2"]


def test_build_install_command_fallback_form_never_has_n_or_capital_s_flag(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: True)

    fallback = capability_install.build_install_command("python2", with_sudo_flag=False)

    assert fallback == ["sudo", "apt-get", "install", "-y", "python2"]


def test_build_install_command_uses_sudo_capital_s_when_a_password_is_saved(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: True)

    assert capability_install.build_install_command("python2") == ["sudo", "-S", "apt-get", "install", "-y", "python2"]


def test_build_install_command_uses_sudo_lowercase_n_without_a_saved_password(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: False)

    assert capability_install.build_install_command("python2") == ["sudo", "-n", "apt-get", "install", "-y", "python2"]


# --- capability_install: install_capability --------------------------------------------------


def test_install_capability_reports_unsupported_without_a_package_manager(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: None)

    result = capability_install.install_capability("python2")

    assert result["status"] == "unsupported"
    assert result["command"] is None


def test_install_capability_success(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: False)
    monkeypatch.setattr(
        capability_install.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "Setting up python2 ...\n", ""),
    )

    result = capability_install.install_capability("python2")

    assert result["status"] == "ok"
    assert result["command"] == "sudo apt-get install -y python2"


def test_install_capability_without_a_saved_password_uses_devnull_stdin_and_fails_fast(monkeypatch):
    """The core guarantee: no saved password -> sudo -n -> a required password fails immediately
    (never hangs the request thread waiting for a TTY prompt that will never come)."""
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: False)
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 1, "", "sudo: a password is required\n")

    monkeypatch.setattr(capability_install.subprocess, "run", _fake_run)

    result = capability_install.install_capability("python2")

    assert result["status"] == "error"
    assert captured["argv"] == ["sudo", "-n", "apt-get", "install", "-y", "python2"]
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL
    assert result["command"] == "sudo apt-get install -y python2"
    assert "run this yourself" in result["message"].lower()


def test_install_capability_with_a_saved_password_pipes_it_via_stdin_not_argv(monkeypatch):
    """The password must never appear in argv (visible to anyone running `ps aux` on this
    machine) -- only ever piped through stdin via sudo -S's own input= mechanism."""
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: True)
    monkeypatch.setenv("SUDO_PASSWORD", "hunter2")
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(capability_install.subprocess, "run", _fake_run)

    result = capability_install.install_capability("python2")

    assert result["status"] == "ok"
    assert captured["argv"] == ["sudo", "-S", "apt-get", "install", "-y", "python2"]
    assert "hunter2" not in captured["argv"]
    assert captured["kwargs"]["input"] == "hunter2\n"
    assert "stdin" not in captured["kwargs"]


def test_install_capability_with_a_wrong_saved_password_reports_it_specifically(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: True)
    monkeypatch.setenv("SUDO_PASSWORD", "wrong-password")
    monkeypatch.setattr(
        capability_install.subprocess, "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], 1, "", "Sorry, try again.\n"),
    )

    result = capability_install.install_capability("python2")

    assert result["status"] == "error"
    assert "saved sudo password" in result["message"].lower()


def test_install_capability_timeout(monkeypatch):
    monkeypatch.setattr(capability_install, "detect_package_manager", lambda: "apt")
    monkeypatch.setattr(capability_install.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(capability_install, "has_sudo_password", lambda: False)

    def _raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd=a[0], timeout=1)

    monkeypatch.setattr(capability_install.subprocess, "run", _raise_timeout)

    result = capability_install.install_capability("python2")

    assert result["status"] == "error"
    assert "timed out" in result["message"].lower()


# --- capability_install: sudo password storage ----------------------------------------------


def _isolate_env(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("")
    monkeypatch.setattr(capability_install, "_ENV_PATH", str(env_path))
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)
    return env_path


def test_has_sudo_password_false_by_default(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    assert capability_install.has_sudo_password() is False


def test_save_sudo_password_round_trips(tmp_path, monkeypatch):
    env_path = _isolate_env(tmp_path, monkeypatch)

    capability_install.save_sudo_password("hunter2")

    assert capability_install.has_sudo_password() is True
    assert "hunter2" in env_path.read_text()


def test_save_sudo_password_with_blank_clears_it(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    capability_install.save_sudo_password("hunter2")

    capability_install.save_sudo_password("   ")

    assert capability_install.has_sudo_password() is False


def test_clear_sudo_password(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    capability_install.save_sudo_password("hunter2")

    capability_install.clear_sudo_password()

    assert capability_install.has_sudo_password() is False
