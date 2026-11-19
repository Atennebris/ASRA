"""Regression tests for ToolSpec.working_dir_factory -> runner subprocess cwd.

Why this exists: frida-trace writes its generated handlers into `cwd/__handlers__`, which crashes
with a read-only install-dir CWD. The fix threads a per-tool working directory from
ToolSpec.working_dir_factory through runner._run_subprocess into subprocess.Popen(cwd=...). These
tests pin that wiring so it can't silently regress back to the inherited (possibly read-only) CWD.
"""
from unittest import mock

import agent.tools  # noqa: F401 - ensures the registry is populated
from agent.tools.builders.frida import frida_trace_working_dir
from agent.tools.registry import get_tool
from agent.tools import runner


def test_frida_trace_spec_declares_working_dir_factory():
    spec = get_tool("frida_trace")
    assert spec is not None
    assert spec.working_dir_factory is frida_trace_working_dir


def test_run_tracked_passes_cwd_to_popen():
    captured = {}

    class _FakeProc:
        returncode = 0

        def communicate(self, input=None, timeout=None):
            return ("out", "err")

    def _fake_popen(command, **kwargs):
        captured["cwd"] = kwargs.get("cwd")
        return _FakeProc()

    with mock.patch("agent.tools.runner.subprocess.Popen", _fake_popen):
        runner._run_tracked(["echo", "hi"], timeout_seconds=5, cwd="/tmp/some_writable_dir")

    assert captured["cwd"] == "/tmp/some_writable_dir"


def test_run_tracked_defaults_cwd_none():
    captured = {}

    class _FakeProc:
        returncode = 0

        def communicate(self, input=None, timeout=None):
            return ("out", "err")

    def _fake_popen(command, **kwargs):
        captured["cwd"] = kwargs.get("cwd", "MISSING")
        return _FakeProc()

    with mock.patch("agent.tools.runner.subprocess.Popen", _fake_popen):
        runner._run_tracked(["echo", "hi"], timeout_seconds=5)

    # With no cwd, the kwarg is omitted entirely (sentinel stays "MISSING"), so Popen keeps its
    # inherited-CWD default for every tool that sets no working_dir_factory -- and the historical
    # Popen call signature is unchanged for the test doubles that mock it.
    assert captured["cwd"] == "MISSING"
