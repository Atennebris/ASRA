"""build_strace_command's own behavior -- RE mode's previously-missing "what does it actually touch
when it runs" behavioral-triage step (see agent/tools/builders/strace.py's own module docstring for
why this was added: a ProcMon/Process Hacker-style sandbox pass nothing else in the RE toolset
covered). Pins the default trace categories, the via_wine wrapping, and the injection-safety
allowlist on trace_categories.

run_strace's own tests below cover the offscreen-display wiring specifically -- real, confirmed
incident: a via_wine=true call used to spawn `wine` through runner.py's generic tier-2 dispatch,
which never touches DISPLAY/WAYLAND_DISPLAY, so wine inherited the host agent process's own real
(WSLg-forwarded) display and popped a genuine, visible window on the operator's desktop. Same
pattern as tests/test_sandbox.py's own run_sandboxed tests.
"""
import subprocess

import pytest

import agent.tools.builders.strace as strace_module
from agent.tools.builders.strace import build_strace_command, run_strace


def test_default_command_shape():
    command = build_strace_command({"file_path": "/tmp/target"})
    assert command == [
        "strace", "-f", "-tt", "-s", "200", "-e", "trace=file,network,process", "/tmp/target",
    ]


def test_via_wine_wraps_the_target():
    command = build_strace_command({"file_path": "/tmp/target.exe", "via_wine": True})
    assert command[-2:] == ["wine", "/tmp/target.exe"]


def test_run_args_appended_after_the_target():
    command = build_strace_command({"file_path": "/tmp/target", "run_args": ["--flag", "value"]})
    assert command[-3:] == ["/tmp/target", "--flag", "value"]


def test_run_args_appended_after_wine_and_target():
    command = build_strace_command({"file_path": "/tmp/target.exe", "via_wine": True, "run_args": ["OP-1234"]})
    assert command[-3:] == ["wine", "/tmp/target.exe", "OP-1234"]


def test_custom_trace_categories():
    command = build_strace_command({"file_path": "/tmp/target", "trace_categories": "signal,desc"})
    assert "trace=signal,desc" in command


def test_unknown_trace_category_rejected():
    with pytest.raises(ValueError, match="unknown categories"):
        build_strace_command({"file_path": "/tmp/target", "trace_categories": "file,shell"})


@pytest.mark.parametrize("bad_categories", [
    "file;shell rm -rf /",
    "File",  # uppercase not allowed by the pattern -- keeps the allowlist check itself trustworthy
    "file, network",  # a space breaks the strict comma-list shape
])
def test_malformed_trace_categories_rejected(bad_categories):
    with pytest.raises(ValueError):
        build_strace_command({"file_path": "/tmp/target", "trace_categories": bad_categories})


def test_empty_trace_categories_falls_back_to_default():
    # Same "empty string means not specified" convention as every other optional string param in
    # this codebase (e.g. radare2.py's hex_view length) -- not a rejection case.
    command = build_strace_command({"file_path": "/tmp/target", "trace_categories": ""})
    assert "trace=file,network,process" in command


def test_run_args_must_be_a_list():
    with pytest.raises(ValueError, match="run_args"):
        build_strace_command({"file_path": "/tmp/target", "run_args": "not-a-list"})


def test_run_args_rejects_control_characters():
    with pytest.raises(ValueError):
        build_strace_command({"file_path": "/tmp/target", "run_args": ["ok\nnot-ok"]})


# --- run_strace: offscreen-display wiring -- only when via_wine, never for a plain native target --

def test_run_strace_without_via_wine_never_touches_the_display(monkeypatch):
    monkeypatch.setattr(strace_module.os, "environ", {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "PATH": "/usr/bin"})
    called = {"start_offscreen_display": False}
    monkeypatch.setattr(strace_module, "start_offscreen_display", lambda: called.__setitem__("start_offscreen_display", True) or (None, None))
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(argv, 0, "out", "trace")

    monkeypatch.setattr(strace_module.subprocess, "run", _fake_run)

    result = run_strace({"file_path": "/tmp/target"})

    assert result["status"] == "ok"
    assert called["start_offscreen_display"] is False
    # A native (non-wine) target's env is left completely alone -- DISPLAY still present, exactly
    # what a plain native ELF/Mach-O binary being strace'd (no GUI risk at all) actually needs.
    assert captured["env"]["DISPLAY"] == ":0"


def test_run_strace_via_wine_strips_display_and_uses_the_started_xvfb(monkeypatch):
    monkeypatch.setattr(strace_module.os, "environ", {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "PATH": "/usr/bin"})

    class _FakeXvfbProcess:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    fake_xvfb = _FakeXvfbProcess()
    monkeypatch.setattr(strace_module, "start_offscreen_display", lambda: (fake_xvfb, ":42"))
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "out", "trace")

    monkeypatch.setattr(strace_module.subprocess, "run", _fake_run)

    result = run_strace({"file_path": "/tmp/target.exe", "via_wine": True})

    assert result["status"] == "ok"
    assert captured["env"]["DISPLAY"] == ":42"
    assert "wine" in captured["argv"]
    assert fake_xvfb.terminated is True


def test_run_strace_via_wine_with_no_xvfb_available_leaves_display_stripped(monkeypatch):
    """No Xvfb installed (start_offscreen_display returns (None, None)) -- must NOT silently fall
    back to the host's own real DISPLAY, which is exactly the leak this whole module exists to
    close; better a program that can't show a window at all than one popping up on the real desktop."""
    monkeypatch.setattr(strace_module.os, "environ", {"DISPLAY": ":0", "PATH": "/usr/bin"})
    monkeypatch.setattr(strace_module, "start_offscreen_display", lambda: (None, None))
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(argv, 0, "out", "trace")

    monkeypatch.setattr(strace_module.subprocess, "run", _fake_run)

    run_strace({"file_path": "/tmp/target.exe", "via_wine": True})

    assert "DISPLAY" not in captured["env"]


def test_run_strace_invalid_params_never_reaches_subprocess(monkeypatch):
    called = {"run": False}
    monkeypatch.setattr(strace_module.subprocess, "run", lambda *a, **k: called.__setitem__("run", True))

    result = run_strace({"file_path": "/tmp/target", "trace_categories": "not-a-real-category"})

    assert result["status"] == "error"
    assert called["run"] is False


def test_run_strace_timeout(monkeypatch):
    def _raise_timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd=["strace"], timeout=1)

    monkeypatch.setattr(strace_module.subprocess, "run", _raise_timeout)
    result = run_strace({"file_path": "/tmp/target"})
    assert result["status"] == "timeout"


def test_run_strace_tool_missing(monkeypatch):
    def _raise_not_found(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(strace_module.subprocess, "run", _raise_not_found)
    result = run_strace({"file_path": "/tmp/target"})
    assert result["status"] == "tool_unavailable"


# --- run_strace: status classification must reflect strace ITSELF, not the traced program's own
# exit code -- real, confirmed incident (orrery-usr_38e422): a via_wine=true call against a target
# that exits 1 with no arguments got classified "error" purely because of the traced program's own
# exit code, which triggered a 1-Step-Retry correction path that embedded strace's own large, real
# stderr uncapped and produced a single 1M+-token LLM call that exhausted the entire fallback chain.

def test_run_strace_nonzero_target_exit_with_real_trace_is_ok(monkeypatch):
    def _fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "23:46:53.186127 execve(...) = 0\n...")

    monkeypatch.setattr(strace_module.subprocess, "run", _fake_run)

    result = run_strace({"file_path": "/tmp/target"})

    assert result["status"] == "ok"
    assert result["exit_code"] == 1


def test_run_strace_nonzero_exit_with_no_trace_at_all_is_error(monkeypatch):
    def _fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "")

    monkeypatch.setattr(strace_module.subprocess, "run", _fake_run)

    result = run_strace({"file_path": "/tmp/target"})

    assert result["status"] == "error"
    assert result["exit_code"] == 1
