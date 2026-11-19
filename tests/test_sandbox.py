"""agent/tools/sandbox.py: cross-platform process isolation for custom_exploit_run/exploit_db_run's
own unvetted scripts -- bubblewrap on Linux (covers Windows-via-WSL2 too, since the agent process
itself always runs inside WSL2 there, confirmed via run.bat), Seatbelt (sandbox-exec) on native
macOS, graceful unsandboxed fallback otherwise (bwrap missing on Linux, or a genuinely unhandled
platform). Filesystem/process isolation only ("Tier 1") -- network egress restriction was
considered and explicitly rejected, not restricted on any platform.
"""
import subprocess
import sys
from pathlib import Path

import pytest

from agent.tools import sandbox


# --- _bwrap_command: pure argv construction ---


def test_bwrap_command_binds_scratch_dir_writable(tmp_path):
    argv = sandbox._bwrap_command(["echo", "hi"], tmp_path)

    assert "bwrap" == argv[0]
    assert "--bind" in argv
    bind_index = argv.index("--bind")
    assert argv[bind_index + 1] == str(tmp_path.resolve())
    assert argv[bind_index + 2] == str(tmp_path.resolve())


def test_bwrap_command_root_is_read_only():
    argv = sandbox._bwrap_command(["echo", "hi"], __import__("pathlib").Path("/tmp"))

    assert "--ro-bind" in argv
    ro_index = argv.index("--ro-bind")
    assert argv[ro_index + 1] == "/"
    assert argv[ro_index + 2] == "/"


def test_bwrap_command_unshares_user_and_pid_but_not_network(tmp_path):
    argv = sandbox._bwrap_command(["echo", "hi"], tmp_path)

    assert "--unshare-user" in argv
    assert "--unshare-pid" in argv
    # Deliberately NOT restricting network in this pass -- the script still has to reach the real
    # target; see the module's own docstring for why this is a documented scope boundary, not an
    # oversight.
    assert "--unshare-net" not in argv


def test_bwrap_command_appends_the_real_command_at_the_end(tmp_path):
    argv = sandbox._bwrap_command(["python3", "script.py", "arg1"], tmp_path)

    assert argv[-3:] == ["python3", "script.py", "arg1"]


def test_bwrap_command_masks_sensitive_paths_that_actually_exist(tmp_path, monkeypatch):
    # credentials/allowed_targets.json resolve through resolve_global_app_dir() (Documents/ASRA by
    # default), NOT a repo-relative path -- real bug this test now guards against: the old
    # _SENSITIVE_PATHS tuple was a bare "data/credentials" string, which only ever matched an
    # always-empty decoy directory in the repo itself, never the real credentials store.
    fake_repo = tmp_path / "repo"
    (fake_repo / "data" / "credentials").mkdir(parents=True)
    (fake_repo / "data" / "credentials" / "usr_x.json").write_text("{}")
    (fake_repo / ".env").write_text("SECRET=1")
    monkeypatch.chdir(fake_repo)
    monkeypatch.setattr(sandbox, "resolve_global_app_dir", lambda: fake_repo)

    argv = sandbox._bwrap_command(["echo"], fake_repo)

    # data/credentials exists and is a directory -> masked via --tmpfs. Not simply the FIRST
    # --tmpfs in argv any more -- _bwrap_command now also masks /run/user/<uid> (a writable tmpfs
    # for RE mode's dynamic-analysis path, e.g. wine's own runtime socket dir) ahead of these
    # sensitive-path entries, so find the one whose own value is the credentials path specifically.
    credentials_path = str((fake_repo / "data" / "credentials").resolve())
    tmpfs_targets = [argv[i + 1] for i, v in enumerate(argv) if v == "--tmpfs"]
    assert credentials_path in tmpfs_targets
    # .env exists and is a file -> masked via --ro-bind /dev/null
    env_ro_binds = [i for i, v in enumerate(argv) if v == "--ro-bind" and argv[i + 1] == "/dev/null"]
    assert len(env_ro_binds) == 1
    assert argv[env_ro_binds[0] + 2] == str((fake_repo / ".env").resolve())
    # data/allowed_targets.json doesn't exist in this fake repo -> not referenced at all
    assert str((fake_repo / "data" / "allowed_targets.json").resolve()) not in argv


# --- run_sandboxed: platform dispatch ---


def test_dispatches_to_linux_branch_when_bwrap_is_available(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/bwrap" if name == "bwrap" else None)
    called = {}
    monkeypatch.setattr(sandbox, "_run_sandboxed_linux", lambda command, scratch_dir, timeout_seconds: called.setdefault("hit", True))

    sandbox.run_sandboxed(["echo"], tmp_path, 10)

    assert called.get("hit") is True


def test_falls_back_to_unsandboxed_when_bwrap_is_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    called = {}

    def _fail_if_called(*a, **k):
        raise AssertionError("_run_sandboxed_linux must not be called when bwrap is missing")

    monkeypatch.setattr(sandbox, "_run_sandboxed_linux", _fail_if_called)
    # The unsandboxed tail now goes through run_with_process_group_timeout (process-group cleanup
    # + an explicit WINEPREFIX/Xvfb setup -- see run_sandboxed's own comment for the real incident
    # this closes), not a bare subprocess.run -- that's what actually runs the command now.
    monkeypatch.setattr(sandbox, "run_with_process_group_timeout", lambda *a, **k: called.setdefault("fallback", True))

    sandbox.run_sandboxed(["echo", "hi"], tmp_path, 10)

    assert called.get("fallback") is True


def test_falls_back_to_unsandboxed_on_an_unhandled_platform(monkeypatch, tmp_path):
    """win32 specifically: the documented/supported Windows launch path (run.bat) always runs the
    agent inside WSL2 (sys.platform == "linux" there, confirmed via run.bat's own real behavior),
    so this platform value only occurs if someone runs main.py with a native Windows Python
    bypassing run.bat/WSL2 entirely -- not a case with its own sandbox implementation, same honest
    unsandboxed-with-a-log-line fallback as any other unhandled platform."""
    monkeypatch.setattr(sandbox.sys, "platform", "win32")
    # Also stubbed here, not just subprocess -- the unsandboxed tail now calls
    # start_offscreen_display() too, whose own shutil.which("Xvfb") otherwise hits a real stdlib
    # win32-only code path (_winapi) that doesn't exist on this (real Linux) test runner once
    # sys.platform is faked to "win32" -- unrelated to what this test is actually checking.
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    called = {}
    monkeypatch.setattr(sandbox, "run_with_process_group_timeout", lambda *a, **k: called.setdefault("fallback", True))

    sandbox.run_sandboxed(["echo", "hi"], tmp_path, 10)

    assert called.get("fallback") is True


def test_real_execution_actually_runs_the_command(tmp_path):
    """No mocking -- exercises the real dispatch on whatever this test suite is actually running
    on (bwrap-sandboxed if bubblewrap is installed here, unsandboxed fallback otherwise -- either
    way it must actually execute the command and return real output)."""
    result = sandbox.run_sandboxed([sys.executable, "-c", "print('hello from sandbox')"], tmp_path, 30)
    assert result.returncode == 0
    assert "hello from sandbox" in result.stdout


# --- _run_sandboxed_linux: WSLg DISPLAY leakage fix (real, confirmed incident -- see that
# function's own comment: without this, a GUI-capable program a sandboxed script spawns, e.g. wine,
# popped a real, visible window on the operator's own Windows desktop every time). NOT xvfb-run --
# real, confirmed incident: that script's own `"$@" 2>&1` unconditionally merges the wrapped
# command's stderr into stdout, which silently broke custom_exploit_run's/exploit_db_run's own
# stderr-capturing error path. start_offscreen_display manages Xvfb directly instead. ---


def test_run_sandboxed_linux_strips_display_and_wayland_display_from_env(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.os, "environ", {"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0", "PATH": "/usr/bin"})
    monkeypatch.setattr(sandbox, "start_offscreen_display", lambda: (None, None))
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run)

    sandbox._run_sandboxed_linux(["echo", "hi"], tmp_path, 10)

    assert "DISPLAY" not in captured["env"]
    assert "WAYLAND_DISPLAY" not in captured["env"]


def test_run_sandboxed_linux_pins_writable_home_and_dotnet_state_under_scratch(monkeypatch, tmp_path):
    """The .NET SDK fix: $HOME inside `--ro-bind / /` is read-only, so dotnet/csc/nuget's own
    $HOME-relative writes ($HOME/.dotnet sentinel, $HOME/.nuget restore) die with "Read-only file
    system". HOME (and the dotnet/nuget state dirs) must be pinned at the one writable bind the
    sandbox grants, same treatment TMPDIR/WINEPREFIX already get."""
    monkeypatch.setattr(sandbox.os, "environ", {"HOME": "/root", "PATH": "/usr/bin"})
    monkeypatch.setattr(sandbox, "start_offscreen_display", lambda: (None, None))
    # Keep the sensitive-path masking off the simulated read-only /root (an inaccessible path on the
    # test runner) -- this test is only about the env dict, not the bind masking.
    monkeypatch.setattr(sandbox, "resolve_global_app_dir", lambda: tmp_path / "app")
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run)

    sandbox._run_sandboxed_linux(["dotnet", "build"], tmp_path, 10)

    scratch = str(tmp_path.resolve())
    env = captured["env"]
    assert env["HOME"] == scratch  # no longer the read-only ambient /root
    assert env["DOTNET_CLI_HOME"] == scratch
    assert env["NUGET_PACKAGES"].startswith(scratch)
    assert env["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
    assert env["DOTNET_NOLOGO"] == "1"


def test_run_sandboxed_linux_sets_display_from_the_started_xvfb(monkeypatch, tmp_path):
    class _FakeXvfbProcess:
        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    fake_xvfb_process = _FakeXvfbProcess()
    monkeypatch.setattr(sandbox, "start_offscreen_display", lambda: (fake_xvfb_process, ":42"))
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["env"] = kwargs.get("env")
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run)

    sandbox._run_sandboxed_linux(["wine", "target.exe"], tmp_path, 10)

    assert captured["env"]["DISPLAY"] == ":42"
    # The real command runs through plain bwrap -- never wrapped in a third-party script that could
    # touch its stdout/stderr streams.
    assert captured["argv"][0] == "bwrap"
    assert captured["argv"][-2:] == ["wine", "target.exe"]


def test_run_sandboxed_linux_terminates_the_xvfb_process_after_running(monkeypatch, tmp_path):
    class _FakeXvfbProcess:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    fake_xvfb_process = _FakeXvfbProcess()
    monkeypatch.setattr(sandbox, "start_offscreen_display", lambda: (fake_xvfb_process, ":42"))
    monkeypatch.setattr(sandbox.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 0, "ok", ""))

    sandbox._run_sandboxed_linux(["wine", "target.exe"], tmp_path, 10)

    assert fake_xvfb_process.terminated is True


def test_run_sandboxed_linux_degrades_gracefully_without_xvfb(monkeypatch, tmp_path):
    """Xvfb missing/failed to start (e.g. install_wine's own xvfb install step failed/was skipped)
    must not block the sandboxed command from running at all -- it just loses the offscreen-display
    protection, same "log it, don't silently break" degradation bwrap's own missing-binary fallback
    already follows."""
    monkeypatch.setattr(sandbox, "start_offscreen_display", lambda: (None, None))
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs.get("env")
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run)

    sandbox._run_sandboxed_linux(["wine", "target.exe"], tmp_path, 10)

    assert captured["argv"][0] == "bwrap"
    assert "DISPLAY" not in captured["env"]


# --- start_offscreen_display: real Xvfb process management, no third-party wrapper script -------


def teststart_offscreen_display_returns_none_when_xvfb_is_not_installed(monkeypatch):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)

    process, display = sandbox.start_offscreen_display()

    assert (process, display) == (None, None)


def teststart_offscreen_display_returns_a_process_and_display_once_the_lock_file_appears(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None)
    monkeypatch.setattr(sandbox.random, "randint", lambda a, b: 4242)

    class _FakeProcess:
        def poll(self):
            return None  # still running

    captured_argv = {}

    def _fake_popen(argv, **kwargs):
        captured_argv["argv"] = argv
        # Simulate Xvfb becoming ready by creating the real lock file it would create itself.
        Path("/tmp/.X4242-lock").write_text("")
        return _FakeProcess()

    monkeypatch.setattr(sandbox.subprocess, "Popen", _fake_popen)
    try:
        process, display = sandbox.start_offscreen_display()
        assert display == ":4242"
        assert process is not None
        assert captured_argv["argv"][0] == "/usr/bin/Xvfb"
        assert captured_argv["argv"][1] == ":4242"
    finally:
        Path("/tmp/.X4242-lock").unlink(missing_ok=True)


def teststart_offscreen_display_gives_up_after_a_few_failed_attempts(monkeypatch):
    """Xvfb never becomes ready (lock file never appears) on every attempt -- must not hang or
    retry forever, and must report (None, None) rather than a display nothing is actually serving."""
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: "/usr/bin/Xvfb" if name == "Xvfb" else None)
    monkeypatch.setattr(sandbox, "_XVFB_READY_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(sandbox, "_XVFB_READY_POLL_INTERVAL_SECONDS", 0.01)
    monkeypatch.setattr(sandbox, "_XVFB_START_ATTEMPTS", 2)

    class _FakeProcessThatNeverBecomesReady:
        def poll(self):
            return None  # still running, but its lock file never appears

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda argv, **k: _FakeProcessThatNeverBecomesReady())

    process, display = sandbox.start_offscreen_display()

    assert (process, display) == (None, None)


# --- macOS Seatbelt branch: only meaningful on macOS to actually run, but the SBPL-generation
# and dispatch logic are pure/mockable and worth testing everywhere ---


def test_macos_sandbox_profile_allows_broad_read_and_scratch_dir_write(tmp_path):
    profile = sandbox._macos_sandbox_profile(tmp_path)

    assert "(deny default)" in profile
    assert "(allow file-read*)" in profile
    assert f'(allow file-write* (subpath "{tmp_path.resolve()}"))' in profile


def test_macos_sandbox_profile_allows_network_tier_1_scope(tmp_path):
    profile = sandbox._macos_sandbox_profile(tmp_path)

    assert "(allow network*)" in profile


def test_macos_sandbox_profile_masks_sensitive_paths_that_exist(tmp_path, monkeypatch):
    fake_repo = tmp_path / "repo"
    (fake_repo / "data" / "credentials").mkdir(parents=True)
    (fake_repo / ".env").write_text("SECRET=1")
    monkeypatch.chdir(fake_repo)
    monkeypatch.setattr(sandbox, "resolve_global_app_dir", lambda: fake_repo)

    profile = sandbox._macos_sandbox_profile(fake_repo)

    assert "(deny file-read*" in profile
    assert str((fake_repo / "data" / "credentials").resolve()) in profile
    assert str((fake_repo / ".env").resolve()) in profile
    # data/allowed_targets.json doesn't exist in this fake repo -- never referenced at all
    assert str((fake_repo / "data" / "allowed_targets.json").resolve()) not in profile


def test_macos_sandbox_profile_omits_deny_clause_when_nothing_sensitive_exists(tmp_path, monkeypatch):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    monkeypatch.chdir(empty_dir)
    monkeypatch.setattr(sandbox, "resolve_global_app_dir", lambda: empty_dir)

    profile = sandbox._macos_sandbox_profile(empty_dir)

    assert "(deny file-read*" not in profile


def test_dispatches_to_macos_branch(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.sys, "platform", "darwin")
    called = {}
    monkeypatch.setattr(sandbox, "_run_sandboxed_macos", lambda command, scratch_dir, timeout_seconds: called.setdefault("hit", True))

    sandbox.run_sandboxed(["echo"], tmp_path, 10)

    assert called.get("hit") is True


def test_macos_branch_invokes_sandbox_exec_with_the_profile_and_real_command(monkeypatch, tmp_path):
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(sandbox.subprocess, "run", _fake_run)

    sandbox._run_sandboxed_macos(["python3", "script.py", "arg1"], tmp_path, 10)

    argv = captured["argv"]
    assert argv[0] == "sandbox-exec"
    assert argv[1] == "-p"
    assert "(version 1)" in argv[2]
    assert argv[3:] == ["python3", "script.py", "arg1"]


# --- wine_prefix_dir: a WINEPREFIX wine will actually accept, never under a Windows-mounted drive
# (see its own docstring for the real incident this fixes: CM-usr_b416f2) ---


def test_wine_prefix_dir_is_stable_and_creates_the_directory():
    path_1 = sandbox.wine_prefix_dir("/mnt/c/Users/user/Desktop/crackme/crackme.exe")
    path_2 = sandbox.wine_prefix_dir("/mnt/c/Users/user/Desktop/crackme/crackme.exe")

    assert path_1 == path_2
    assert path_1.is_dir()
    # The whole point is sidestepping drvfs's ownership check on a /mnt/c/... path -- the prefix
    # itself must never land back under one.
    assert "/mnt/" not in str(path_1)


def test_wine_prefix_dir_differs_for_different_keys():
    assert sandbox.wine_prefix_dir("target-a") != sandbox.wine_prefix_dir("target-b")


# --- run_with_process_group_timeout: kills the WHOLE process group on timeout, not just the one
# direct child (see its own docstring for the real incident: a `wine`-spawned wineserver surviving
# a bare SIGKILL and holding a mutex that hung every subsequent attempt identically) ---


def test_run_with_process_group_timeout_returns_completed_process_on_success():
    result = sandbox.run_with_process_group_timeout(
        [sys.executable, "-c", "print('ok')"], timeout_seconds=10,
    )
    assert result.returncode == 0
    assert "ok" in result.stdout


def test_run_with_process_group_timeout_kills_group_and_returns_partial_output_on_timeout(monkeypatch):
    killed = {}

    class _FakeProc:
        pid = 4321
        args = ["sleep", "100"]

        def __init__(self):
            self._calls = 0

        def communicate(self, timeout=None):
            self._calls += 1
            if self._calls == 1:
                raise subprocess.TimeoutExpired(cmd=self.args, timeout=timeout)
            return ("partial-out", "partial-err")  # the drain after the kill

    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda *a, **k: _FakeProc())
    monkeypatch.setattr(sandbox.os, "killpg", lambda pid, sig: killed.setdefault("killpg", (pid, sig)))

    with pytest.raises(subprocess.TimeoutExpired) as excinfo:
        sandbox.run_with_process_group_timeout(["sleep", "100"], timeout_seconds=1)

    assert killed["killpg"] == (4321, sandbox.signal.SIGKILL)
    # Partial output drained from the killed group and attached to the exception, not discarded.
    assert excinfo.value.stdout == "partial-out"
    assert excinfo.value.stderr == "partial-err"


def test_run_with_process_group_timeout_without_stop_check_does_not_poll(monkeypatch):
    """Default (stop_check=None) stays a single blocking communicate(timeout=...), no polling loop
    -- behavior byte-identical to before stop_check existed."""
    calls = {"n": 0}

    class _FakeProc:
        pid = 1
        args = ["echo"]
        returncode = 0

        def communicate(self, timeout=None):
            calls["n"] += 1
            return ("ok", "")

    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda *a, **k: _FakeProc())

    result = sandbox.run_with_process_group_timeout(["echo"], timeout_seconds=5)

    assert result.stdout == "ok"
    assert calls["n"] == 1


def test_run_with_process_group_timeout_honors_stop_check_and_kills_the_group(monkeypatch):
    """A stop_check that flips to True mid-run must kill the whole group promptly (not wait out the
    full timeout) -- the shared-symbol contract Agent A threads a live-session stop callback through."""
    monkeypatch.setattr(sandbox, "_STOP_CHECK_POLL_INTERVAL_SECONDS", 0.01)
    killed = {}
    stop_calls = {"n": 0}

    def _stop_check():
        stop_calls["n"] += 1
        return stop_calls["n"] >= 2  # not stopped on the first poll, stopped on the second

    class _FakeProc:
        pid = 777
        args = ["sleep", "100"]

        def communicate(self, timeout=None):
            if timeout is not None:
                raise subprocess.TimeoutExpired(cmd=self.args, timeout=timeout)  # a per-slice poll
            return ("partial", "")  # the drain after the kill

    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda *a, **k: _FakeProc())
    monkeypatch.setattr(sandbox.os, "killpg", lambda pid, sig: killed.setdefault("killpg", (pid, sig)))

    with pytest.raises(subprocess.TimeoutExpired) as excinfo:
        sandbox.run_with_process_group_timeout(["sleep", "100"], timeout_seconds=100, stop_check=_stop_check)

    assert killed["killpg"] == (777, sandbox.signal.SIGKILL)
    assert stop_calls["n"] >= 2
    assert excinfo.value.stdout == "partial"


# --- run_sandboxed's unsandboxed fallback: same WINEPREFIX/Xvfb protection as _run_sandboxed_linux
# (real, confirmed incident this fixes -- this branch had neither before, see run_sandboxed's own
# comment) ---


def test_unsandboxed_fallback_sets_wineprefix_and_strips_display(monkeypatch, tmp_path):
    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)  # no bwrap, no Xvfb either
    monkeypatch.setattr(sandbox.os, "environ", {"DISPLAY": ":0", "PATH": "/usr/bin"})
    captured = {}

    def _fake_run_with_timeout(command, *, cwd=None, env=None, timeout_seconds=None):
        captured["env"] = env
        return subprocess.CompletedProcess(command, 0, "ok", "")

    monkeypatch.setattr(sandbox, "run_with_process_group_timeout", _fake_run_with_timeout)

    sandbox.run_sandboxed(["wine", "target.exe"], tmp_path, 10)

    assert "DISPLAY" not in captured["env"]
    assert "WINEPREFIX" in captured["env"]
