"""Every subprocess this project spawns must get stdin=subprocess.DEVNULL, never the parent
server's own inherited stdin. Real, confirmed incident this fixes: with no stdin= argument, a
child process inherits whatever this SERVER process's own stdin is connected to -- in the real
production launch (run.bat opens a genuine console window, not a redirected /dev/null-style
launch), that's a live, interactive-capable terminal nobody is typing into. `wpscan` hit exactly
this: its local vulnerability database was stale, it printed "Do you want to update now? [Y]es
[N]o, default: [N]" and blocked reading stdin for an answer that was never coming -- a real
~9-minute hang eating almost the entire 600s subprocess timeout, which read to the operator as
the whole session silently stuck for no visible reason. DEVNULL gives any tool that ever prompts
interactively an immediate EOF instead, closing the whole class of bug (not just wpscan) across
every real subprocess dispatch point in this project.
"""
import shutil
import subprocess as subprocess_module

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import background_jobs as bg
from agent.tools import discovery, native
from agent.tools.builders import discovered
from agent.tools.registry import ToolSpec
from agent.tools.runner import run_tool
from projects import paths as project_paths
from sessions import store


def test_run_tool_passes_stdin_devnull_to_the_real_subprocess(monkeypatch):
    """The primary tier-2 dispatch path (agent/tools/runner.py's _run_tracked) every ordinary
    external tool (nmap, whatweb, wpscan, ffuf, ...) goes through."""
    captured = {}
    real_popen = subprocess_module.Popen

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess_module, "Popen", fake_popen)
    spec = ToolSpec(
        name="fake_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", "pass"],
        requires_allowed_target=False, installed_by_default=True,
    )

    run_tool(spec, {})

    assert captured.get("stdin") is subprocess_module.DEVNULL


def test_custom_exploit_run_passes_stdin_devnull(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        native.subprocess, "run",
        lambda *a, **k: captured.update(k) or subprocess_module.CompletedProcess(a, 0, "ok", ""),
    )

    native.custom_exploit_run({"source": "print('ok')", "target": "example.com"})

    assert captured.get("stdin") is subprocess_module.DEVNULL


def test_exploit_db_run_passes_stdin_devnull(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        native, "_fetch_exploitdb_source",
        lambda edb_id: {"status": "ok", "file_path": "exploits/multiple/remote/5257.py", "source": "print('ok')"},
    )
    monkeypatch.setattr(
        native.subprocess, "run",
        lambda *a, **k: captured.update(k) or subprocess_module.CompletedProcess(a, 0, "ok", ""),
    )

    native.exploit_db_run({"edb_id": "5257", "target": "example.com"})

    assert captured.get("stdin") is subprocess_module.DEVNULL


def test_arjun_probe_passes_stdin_devnull(monkeypatch):
    captured = {}
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/bin/arjun" if name == "arjun" else shutil.which(name))
    monkeypatch.setattr(
        native.subprocess, "run",
        lambda *a, **k: captured.update(k) or subprocess_module.CompletedProcess(a, 0, "", ""),
    )

    result = native.arjun_probe({"target": "https://example.com"})

    assert captured.get("stdin") is subprocess_module.DEVNULL
    assert result["status"] == "ok"


def test_run_interactsh_passes_stdin_devnull(monkeypatch):
    captured = {}
    real_popen = subprocess_module.Popen

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(native.subprocess, "Popen", fake_popen)

    native._run_interactsh(["python3", "-c", "pass"], run_seconds=5)

    assert captured.get("stdin") is subprocess_module.DEVNULL


def test_background_job_launch_passes_stdin_devnull(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()

    captured = {}
    real_popen = subprocess_module.Popen

    def fake_popen(*args, **kwargs):
        captured.update(kwargs)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(bg.subprocess, "Popen", fake_popen)

    def setup(job_id, job_dir):
        return ["python3", "-c", "pass"], lambda log_path: {"parsed": True}

    session = {"session_id": "usr_stdin_devnull_test", "background_jobs": {}}
    try:
        bg.start_background_job("usr_stdin_devnull_test", session, "fake-tool", setup, max_concurrent=2, timeout_seconds=10)
        assert captured.get("stdin") is subprocess_module.DEVNULL
    finally:
        bg._RUNNING_PROCESSES.clear()
        bg._PARSERS.clear()
        project_paths.resolve_projects_base_dir.cache_clear()


def test_httpx_liveness_check_passes_stdin_devnull(monkeypatch):
    captured = {}
    monkeypatch.setattr(discovery, "_resolve_httpx_candidate", lambda: "/usr/local/bin/httpx")
    monkeypatch.setattr(
        discovery.subprocess, "run",
        lambda *a, **k: captured.update(k) or subprocess_module.CompletedProcess(a, 0, "", ""),
    )

    discovery._httpx_binary_is_real()

    assert captured.get("stdin") is subprocess_module.DEVNULL


def test_get_tool_help_probe_passes_stdin_devnull(monkeypatch, tmp_path):
    captured = {}
    monkeypatch.setattr(discovered, "TOOL_HELP_CACHE_DIR", tmp_path)
    monkeypatch.setattr(
        discovered.subprocess, "run",
        lambda *a, **k: captured.update(k) or subprocess_module.CompletedProcess(a, 0, "help text", ""),
    )

    discovered.get_tool_help("fake-tool", "/usr/bin/fake-tool")

    assert captured.get("stdin") is subprocess_module.DEVNULL
