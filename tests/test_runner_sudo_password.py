"""agent/tools/runner.py's _run_tracked: the one deliberate exception to its own "always
stdin=DEVNULL" rule (see that function's own long comment) -- a command a tool builder itself
prefixed with ["sudo", "-S", ...] (nmap's own -O, so far the only real case) gets SUDO_PASSWORD
piped via stdin instead, when one is saved (Settings -> Optional interpreters/compilers). No saved
password still hits DEVNULL, so sudo -S fails fast on its own EOF rather than hanging -- same
guarantee capability_install.py's sudo -n path already has, just reached a different way.

Real subprocess.Popen is mocked throughout -- these tests must never invoke an actual `sudo`
binary (side effects, real auth attempts, unpredictable behavior depending on this machine's own
sudo/PAM config are all wrong for a unit test).
"""
import subprocess

import agent.tools.runner as runner


class _FakePopen:
    def __init__(self, command, stdout=None, stderr=None, stdin=None, text=None, errors=None):
        _FakePopen.last_kwargs = {"stdin": stdin}
        self.returncode = 0

    def communicate(self, input=None, timeout=None):
        _FakePopen.last_communicate_input = input
        return "ok", ""


def test_normal_command_still_uses_devnull_stdin(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "Popen", _FakePopen)
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)

    runner._run_tracked(["nmap", "-F", "-sV", "example.com"], 10)

    assert _FakePopen.last_kwargs["stdin"] == subprocess.DEVNULL
    assert _FakePopen.last_communicate_input is None


def test_sudo_s_prefixed_command_pipes_the_saved_password_via_stdin(monkeypatch):
    monkeypatch.setattr(runner.subprocess, "Popen", _FakePopen)
    monkeypatch.setenv("SUDO_PASSWORD", "hunter2")

    runner._run_tracked(["sudo", "-S", "nmap", "-F", "-sV", "example.com", "-O", "--osscan-guess"], 10)

    assert _FakePopen.last_kwargs["stdin"] == subprocess.PIPE
    assert _FakePopen.last_communicate_input == "hunter2\n"


def test_sudo_s_prefixed_command_without_a_saved_password_falls_back_to_devnull(monkeypatch):
    """No SUDO_PASSWORD set -- sudo -S must still fail fast (EOF on stdin), never hang waiting for
    a TTY prompt that will never come, same guarantee as every other tool call already has."""
    monkeypatch.setattr(runner.subprocess, "Popen", _FakePopen)
    monkeypatch.delenv("SUDO_PASSWORD", raising=False)

    runner._run_tracked(["sudo", "-S", "nmap", "-F", "-sV", "example.com"], 10)

    assert _FakePopen.last_kwargs["stdin"] == subprocess.DEVNULL
    assert _FakePopen.last_communicate_input is None


def test_a_bare_sudo_command_without_capital_s_is_not_treated_as_the_password_case(monkeypatch):
    """Only the exact ["sudo", "-S", ...] shape this project's own builders opt into (nmap.py) is
    special-cased -- a plain ["sudo", ...] (not this project's convention) must not silently start
    reading SUDO_PASSWORD into some other command's stdin."""
    monkeypatch.setattr(runner.subprocess, "Popen", _FakePopen)
    monkeypatch.setenv("SUDO_PASSWORD", "hunter2")

    runner._run_tracked(["sudo", "apt-get", "update"], 10)

    assert _FakePopen.last_kwargs["stdin"] == subprocess.DEVNULL
    assert _FakePopen.last_communicate_input is None


# --- _run_subprocess: the {TOOL}_PATH-override substitution must land at the right index ---------


def test_run_subprocess_substitutes_the_resolved_executable_after_a_sudo_s_prefix(monkeypatch):
    """Real bug this guards against: run_tool's own command[0] = resolved_executable substitution
    (agent/tools/runner.py, the HTTPX_PATH incident) would otherwise overwrite "sudo" itself with
    nmap's resolved path, corrupting the whole privileged invocation."""
    from agent.tools.registry import ToolSpec

    captured = {}

    def _fake_run_tracked(command, timeout_seconds):
        captured["command"] = list(command)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(runner, "_run_tracked", _fake_run_tracked)
    monkeypatch.setattr(runner, "_resolve_executable", lambda spec: "/usr/bin/nmap")

    spec = ToolSpec(
        name="nmap", category="scan", tool_tier=2, executable="nmap",
        build_command=lambda params: ["sudo", "-S", "nmap", "-F", "-sV", "example.com", "-O", "--osscan-guess"],
        requires_allowed_target=False, installed_by_default=True,
    )
    result = runner.run_tool(spec, {"target": "example.com"})

    assert result["status"] == "ok"
    assert captured["command"] == ["sudo", "-S", "/usr/bin/nmap", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


def test_run_subprocess_substitutes_at_index_0_when_no_sudo_prefix(monkeypatch):
    from agent.tools.registry import ToolSpec

    captured = {}

    def _fake_run_tracked(command, timeout_seconds):
        captured["command"] = list(command)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(runner, "_run_tracked", _fake_run_tracked)
    monkeypatch.setattr(runner, "_resolve_executable", lambda spec: "/usr/bin/nmap")

    spec = ToolSpec(
        name="nmap", category="scan", tool_tier=2, executable="nmap",
        build_command=lambda params: ["nmap", "-F", "-sV", "example.com"],
        requires_allowed_target=False, installed_by_default=True,
    )
    runner.run_tool(spec, {"target": "example.com"})

    assert captured["command"] == ["/usr/bin/nmap", "-F", "-sV", "example.com"]
