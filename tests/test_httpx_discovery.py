"""agent/tools/discovery.py's httpx-specific liveness check. Real incident this exists for: a
whole recon phase burned 9 targets x (1 call + 1 wasted 1-Step Retry) because discover_known_tools()
registered whatever binary `shutil.which("httpx")` found on PATH with no liveness check at all --
this project's own `httpx` Python dependency (requirements.txt) installs a console-script shim of
the identical name that always fails with "pip install 'httpx[cli]'" when actually run, and it can
shadow the real ProjectDiscovery recon tool on PATH (confirmed live in this project's own dev
environment: activating venv/ puts the broken shim ahead of the real /usr/local/bin/httpx).
"""
import subprocess

import agent.tools.discovery as discovery


class _FakeCompleted:
    def __init__(self, returncode):
        self.returncode = returncode


def test_httpx_binary_is_real_false_when_nothing_is_on_path(monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda name: None)
    monkeypatch.delenv("HTTPX_PATH", raising=False)
    assert discovery._httpx_binary_is_real() is False


def test_httpx_binary_is_real_false_for_the_broken_pip_shim(monkeypatch):
    """The exact real failure mode: a binary exists on PATH but exits non-zero on -version --
    confirmed live to be what the broken httpx[cli] shim actually does."""
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/some/path/httpx")
    monkeypatch.delenv("HTTPX_PATH", raising=False)
    monkeypatch.setattr(discovery.subprocess, "run", lambda *a, **k: _FakeCompleted(returncode=1))
    assert discovery._httpx_binary_is_real() is False


def test_httpx_binary_is_real_false_when_the_call_itself_raises(monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/some/path/httpx")
    monkeypatch.delenv("HTTPX_PATH", raising=False)

    def _raise(*a, **k):
        raise subprocess.TimeoutExpired(cmd="httpx", timeout=5)

    monkeypatch.setattr(discovery.subprocess, "run", _raise)
    assert discovery._httpx_binary_is_real() is False


def test_httpx_binary_is_real_true_for_a_working_binary(monkeypatch):
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/local/bin/httpx")
    monkeypatch.delenv("HTTPX_PATH", raising=False)
    monkeypatch.setattr(discovery.subprocess, "run", lambda *a, **k: _FakeCompleted(returncode=0))
    assert discovery._httpx_binary_is_real() is True


def test_httpx_path_override_takes_priority_over_which(monkeypatch, tmp_path):
    """Real incident this covers: the liveness check must resolve the SAME path real dispatch
    (runner.py's _resolve_executable) will actually use, or an operator's HTTPX_PATH override
    (set specifically to bypass a venv shadowing the real binary) would be silently ignored here
    while still being honored at dispatch time -- or vice versa."""
    override_path = tmp_path / "real-httpx"
    override_path.write_text("#!/bin/sh\necho fake\n")
    monkeypatch.setenv("HTTPX_PATH", str(override_path))
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/venv/bin/httpx" if name == "httpx" else None)
    seen_paths = []

    def _fake_run(cmd, **kwargs):
        seen_paths.append(cmd[0])
        return _FakeCompleted(returncode=0)

    monkeypatch.setattr(discovery.subprocess, "run", _fake_run)
    assert discovery._httpx_binary_is_real() is True
    assert seen_paths == [str(override_path)]  # the override, never the PATH-found one


def test_discover_known_tools_skips_httpx_when_the_liveness_check_fails(monkeypatch):
    monkeypatch.setattr(discovery, "_httpx_binary_is_real", lambda: False)
    monkeypatch.setattr(discovery.shutil, "which", lambda name: "/usr/bin/" + name if name in ("dnsx", "gobuster") else None)
    names = {spec.name for spec in discovery.discover_known_tools()}
    assert "httpx" not in names
    assert "dnsx" in names  # unrelated tools are unaffected by httpx's own liveness check


def test_discover_known_tools_includes_httpx_when_the_liveness_check_passes(monkeypatch):
    monkeypatch.setattr(discovery, "_httpx_binary_is_real", lambda: True)
    monkeypatch.setattr(discovery.shutil, "which", lambda name: None)  # dnsx/gobuster genuinely absent
    names = {spec.name for spec in discovery.discover_known_tools()}
    assert "httpx" in names


def test_interpret_httpx_failure_recognizes_the_broken_shim_marker():
    hint = discovery.interpret_httpx_failure({
        "stdout": "The httpx command line client could not run because the required dependencies "
        "were not installed.\nMake sure you've installed everything with: pip install 'httpx[cli]'",
    })
    assert hint is not None
    assert "not a real argument" in hint


def test_interpret_httpx_failure_is_none_for_an_unrelated_error():
    hint = discovery.interpret_httpx_failure({"stdout": "", "stderr": "connection refused"})
    assert hint is None
