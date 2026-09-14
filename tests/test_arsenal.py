"""agent/tools/arsenal.py + agent/tools/arsenal_install.py: the Tools-page arsenal readiness
summary and its install runner's pre-flight/command resolution."""
from agent.tools import arsenal, arsenal_install


def _entry(name, *, tier, installed, categories):
    return {"name": name, "categories": tuple(categories), "tier": tier,
            "installed": installed, "description": ""}


def _fake_inventory(entries):
    def _inner():
        return entries
    return _inner


def test_verdict_none_when_no_external_installed(monkeypatch):
    monkeypatch.setattr(arsenal, "list_tool_availability", _fake_inventory([
        _entry("nmap", tier=2, installed=False, categories=["scan"]),
        _entry("nuclei", tier=2, installed=False, categories=["scan"]),
        _entry("http_get", tier=1, installed=True, categories=["recon"]),  # native never moves it
    ]))
    summary = arsenal.summarize_arsenal()
    assert summary["verdict"] == "none"
    assert summary["external_total"] == 2
    assert summary["external_installed"] == 0
    assert summary["percent"] == 0
    assert summary["missing"] == ["nmap", "nuclei"]


def test_verdict_full_when_all_external_installed(monkeypatch):
    monkeypatch.setattr(arsenal, "list_tool_availability", _fake_inventory([
        _entry("nmap", tier=2, installed=True, categories=["scan"]),
        _entry("radare2", tier=2, installed=True, categories=["re"]),
    ]))
    summary = arsenal.summarize_arsenal()
    assert summary["verdict"] == "full"
    assert summary["percent"] == 100
    assert summary["missing"] == []


def test_verdict_partial_and_per_mode_breakdown(monkeypatch):
    monkeypatch.setattr(arsenal, "list_tool_availability", _fake_inventory([
        _entry("nmap", tier=2, installed=True, categories=["scan"]),
        _entry("nuclei", tier=2, installed=False, categories=["scan"]),
        _entry("radare2", tier=2, installed=False, categories=["re"]),
        _entry("gdb", tier=2, installed=False, categories=["re"]),
    ]))
    summary = arsenal.summarize_arsenal()
    assert summary["verdict"] == "partial"
    assert summary["external_installed"] == 1
    assert summary["external_total"] == 4

    modes = {m["key"]: m for m in summary["modes"]}
    assert modes["web"]["installed"] == 1 and modes["web"]["total"] == 2
    assert modes["web"]["available"] is True
    # Every RE tool missing -> that whole mode reports unavailable, the operator-facing signal.
    assert modes["re"]["available"] is False
    assert modes["re"]["installed"] == 0 and modes["re"]["total"] == 2


def test_modes_omit_buckets_with_no_external_tools(monkeypatch):
    monkeypatch.setattr(arsenal, "list_tool_availability", _fake_inventory([
        _entry("nmap", tier=2, installed=True, categories=["scan"]),
    ]))
    summary = arsenal.summarize_arsenal()
    assert [m["key"] for m in summary["modes"]] == ["web"]  # no re/toolkit externals -> not shown


def test_can_autostart_unsupported_off_linux(monkeypatch):
    monkeypatch.setattr(arsenal_install.sys, "platform", "win32")
    result = arsenal_install.can_autostart()
    assert result["ok"] is False
    assert result["reason"] == "unsupported"


def test_resolve_command_root_needs_no_sudo(monkeypatch):
    monkeypatch.setattr(arsenal_install.os, "geteuid", lambda: 0, raising=False)
    argv, password, display = arsenal_install._resolve_command()
    assert argv[0] == "bash"
    assert password is None


def test_resolve_command_uses_saved_sudo_password(monkeypatch):
    monkeypatch.setattr(arsenal_install.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(arsenal_install, "has_sudo_password", lambda: True)
    monkeypatch.setenv("SUDO_PASSWORD", "hunter2")
    argv, password, display = arsenal_install._resolve_command()
    assert argv[:3] == ["sudo", "-S", "bash"]
    assert password == "hunter2"


def test_resolve_command_manual_when_no_sudo_path(monkeypatch):
    monkeypatch.setattr(arsenal_install.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(arsenal_install, "has_sudo_password", lambda: False)
    monkeypatch.setattr(arsenal_install, "_passwordless_sudo_available", lambda: False)
    argv, password, display = arsenal_install._resolve_command()
    assert argv is None
    assert "setup_tools.sh" in display


def test_status_idle_before_any_install(monkeypatch, tmp_path):
    # Point the log path at an empty temp dir so a real prior run's log can't leak into this test.
    monkeypatch.setattr(arsenal_install, "resolve_global_app_dir", lambda: tmp_path)
    monkeypatch.setitem(arsenal_install._STATE, "proc", None)
    monkeypatch.setitem(arsenal_install._STATE, "log_path", None)
    status = arsenal_install.arsenal_install_status()
    assert status["state"] == "idle"
    assert status["running"] is False
