"""Standalone Terminal tab's real PTY backend (agent/tools/terminal_manager.py) -- a genuine login
shell, not a mocked one: these tests spawn a real /bin/bash child process (same as the app does at
runtime) and drive it through actual stdin/stdout bytes, the same way a real WebSocket client would.
tests/conftest.py's autouse fixture already isolates APP_DATA_DIR (so resolve_global_app_dir(),
which console-logs/ sits under, never touches a real Documents/ASRA on the machine running these
tests) -- no extra isolation needed here for that part.
"""
from __future__ import annotations

import asyncio
import builtins
import os
import re
import time
from pathlib import Path

import pytest

from agent.tools import terminal_manager


@pytest.fixture(autouse=True)
def _cleanup_terminals():
    """Real OS child processes -- never let one survive past its own test, regardless of whether
    the test itself remembered to close it (same "own background processes until they're
    stopped" discipline this project applies everywhere else)."""
    yield
    terminal_manager.shutdown_all()


def _wait_for(session, needle: bytes, timeout: float = 3.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in session.get_scrollback():
            return True
        time.sleep(0.05)
    return False


_DSR_QUERY = re.compile(rb"\x1b\[6n")


async def _await_windows_shell(session, needle: bytes, timeout: float = 8.0) -> bool:
    """Like _wait_for, but ASYNC (await asyncio.sleep, not time.sleep) and also answers a
    ConPTY-hosted Windows program's own cursor-position query (the \\x1b[6n a fresh
    windows-pty-bridge/ session always opens with) the way a real terminal emulator (xterm.js, in
    the real browser-facing path) already does automatically. Confirmed live: without SOME
    response to this, PowerShell never produces its own banner/prompt at all -- our test harness
    has no real terminal emulator in the loop the way production does, so it has to fake this one
    specific response itself.

    MUST be awaited from inside the SAME asyncio.run() call that created the session, never
    called synchronously after that call has already returned -- confirmed live, a real bug in an
    earlier draft of these tests, not a hypothetical: asyncio.run()'s own cleanup phase
    (_cancel_all_tasks + a couple of run_until_complete calls for shutdown_asyncgens/
    shutdown_default_executor) keeps the loop alive JUST long enough to explain why a plain
    synchronous time.sleep() poll after it returns happens to work for a fast, near-instant bash
    echo (the reader callback gets one last real chance to fire during that brief window) but
    never for something slower like a real PowerShell startup + DSR round-trip -- past that short
    window the loop is genuinely closed and terminal_manager's own loop.add_reader callback never
    fires again, so scrollback simply stops updating no matter how long a synchronous caller waits."""
    deadline = time.time() + timeout
    answered = 0
    while time.time() < deadline:
        data = session.get_scrollback()
        if needle in data:
            return True
        queries = len(_DSR_QUERY.findall(data))
        if queries > answered:
            for _ in range(queries - answered):
                session.write_input(b"\x1b[24;1R")  # a plausible, fake "row 24, col 1"
            answered = queries
        await asyncio.sleep(0.05)
    return needle in session.get_scrollback()


async def _spawn_and_echo(cwd, phrase: bytes):
    session = await terminal_manager.create_terminal(cwd)
    session.write_input(b"echo " + phrase + b"\n")
    return session


def test_create_terminal_spawns_a_real_shell_that_echoes_input(tmp_path):
    session = asyncio.run(_spawn_and_echo(str(tmp_path), b"hello_terminal_test"))
    try:
        assert _wait_for(session, b"hello_terminal_test")
        assert session.cwd == str(tmp_path)
        assert session.pid is not None
        assert terminal_manager.get_terminal(session.id) is session
    finally:
        terminal_manager.close_terminal(session.id)


def test_create_terminal_falls_back_to_home_when_cwd_is_not_a_real_directory(tmp_path):
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path / "does-not-exist"))

    session = asyncio.run(scenario())
    try:
        from pathlib import Path
        assert session.cwd == str(Path.home())
    finally:
        terminal_manager.close_terminal(session.id)


def test_transcript_log_file_is_written_under_console_logs_dir(tmp_path):
    session = asyncio.run(_spawn_and_echo(str(tmp_path), b"transcript_marker_xyz"))
    try:
        assert _wait_for(session, b"transcript_marker_xyz")
        assert session.log_path is not None
        assert session.log_path.parent.name == "console-logs"
        assert session.log_path.exists()
        assert b"transcript_marker_xyz" in session.log_path.read_bytes()
    finally:
        terminal_manager.close_terminal(session.id)


def test_resize_does_not_raise_and_is_a_noop_after_exit(tmp_path):
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(scenario())
    session.resize(120, 40)  # must not raise while alive
    terminal_manager.close_terminal(session.id)
    session.resize(120, 40)  # must not raise once the master fd is already gone


def test_write_input_after_close_is_a_silent_noop(tmp_path):
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(scenario())
    terminal_manager.close_terminal(session.id)
    session.write_input(b"echo should-not-crash\n")  # must not raise


def test_close_terminal_removes_it_from_the_registry_and_kills_the_process(tmp_path):
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(scenario())
    pid = session.pid
    assert terminal_manager.close_terminal(session.id) is True
    assert terminal_manager.get_terminal(session.id) is None
    # Closing an already-closed id is a safe no-op, not an error.
    assert terminal_manager.close_terminal(session.id) is False

    deadline = time.time() + 3
    dead = False
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            dead = True
            break
        time.sleep(0.05)
    assert dead, "child shell process outlived close_terminal()"


def test_shutdown_all_clears_the_registry_and_kills_every_session(tmp_path):
    async def scenario():
        a = await terminal_manager.create_terminal(str(tmp_path))
        b = await terminal_manager.create_terminal(str(tmp_path))
        return a, b

    session_a, session_b = asyncio.run(scenario())
    terminal_manager.shutdown_all()
    assert terminal_manager.get_terminal(session_a.id) is None
    assert terminal_manager.get_terminal(session_b.id) is None


class _FakeWebSocket:
    """Minimal stand-in for fastapi.WebSocket -- just enough surface (async send_bytes/send_json/
    close) for attach()/detach() to exercise their own logic without a real network connection."""

    def __init__(self):
        self.sent_bytes: list[bytes] = []
        self.sent_json: list[dict] = []
        self.closed = False

    async def send_bytes(self, data: bytes) -> None:
        self.sent_bytes.append(data)

    async def send_json(self, payload: dict) -> None:
        self.sent_json.append(payload)

    async def close(self, code: int = 1000) -> None:
        self.closed = True


def test_attach_returns_none_for_an_unknown_terminal_id():
    assert asyncio.run(terminal_manager.attach("does-not-exist", _FakeWebSocket())) is None


def test_second_attach_disconnects_the_first_viewer(tmp_path):
    async def scenario():
        session = await terminal_manager.create_terminal(str(tmp_path))
        first = _FakeWebSocket()
        second = _FakeWebSocket()
        await terminal_manager.attach(session.id, first)
        await terminal_manager.attach(session.id, second)
        return session, first, second

    session, first, second = asyncio.run(scenario())
    try:
        assert first.closed is True
        assert second.closed is False
        assert session._viewer is second
    finally:
        terminal_manager.close_terminal(session.id)


def test_detect_available_shells_only_lists_real_executable_paths():
    shells = terminal_manager.detect_available_shells()
    assert shells, "expected at least one real shell to be detected on this machine"
    for entry in shells:
        assert os.path.isfile(entry["path"])
        # kind="windows" entries are checked with isfile() alone (DrvFs's own executable-bit
        # emulation for a mounted .exe isn't reliably queryable via os.access) -- only the
        # kind="wsl" (real Linux) entries are also required to carry a real executable bit.
        if entry["kind"] == "wsl":
            assert os.access(entry["path"], os.X_OK)
            assert entry["name"] == os.path.basename(entry["path"])
        assert entry["kind"] in ("wsl", "windows")
    # No duplicates even if a path appears in both /etc/shells and the fallback candidate list.
    paths = [entry["path"] for entry in shells]
    assert len(paths) == len(set(paths))


def test_detect_available_shells_falls_back_to_candidates_when_etc_shells_is_missing(monkeypatch):
    real_open = builtins.open

    def _raise_for_etc_shells(path, *args, **kwargs):
        if path == "/etc/shells":
            raise OSError("simulated missing /etc/shells")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(terminal_manager, "open", _raise_for_etc_shells, raising=False)
    shells = terminal_manager.detect_available_shells()
    paths = [entry["path"] for entry in shells]
    assert "/bin/bash" in paths or "/usr/bin/bash" in paths


def test_create_terminal_honors_a_shell_from_the_detected_list(tmp_path):
    detected = terminal_manager.detect_available_shells()
    # Prefer a non-default WSL entry if there's more than one, so this actually proves the
    # override took effect rather than coincidentally matching the default anyway -- deliberately
    # never picks a kind="windows" entry here (that's its own dedicated, slower test below).
    non_default = [s["path"] for s in detected if s["path"] != terminal_manager.default_shell_path() and s["kind"] == "wsl"]
    chosen = non_default[0] if non_default else detected[0]["path"]

    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path), chosen)

    session = asyncio.run(scenario())
    try:
        assert session.shell == chosen
    finally:
        terminal_manager.close_terminal(session.id)


def test_create_terminal_ignores_an_unknown_shell_path_and_falls_back_to_default(tmp_path):
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path), "/not/a/real/shell")

    session = asyncio.run(scenario())
    try:
        assert session.shell == terminal_manager.default_shell_path()
    finally:
        terminal_manager.close_terminal(session.id)


class _FakeProcVersionPath:
    """Stand-in for pathlib.Path("/proc/version") -- rebinds only terminal_manager's own module-
    level `Path` name, never the real pathlib.Path class, so this can't leak into anything else
    that happens to construct a Path during the same test."""

    def __init__(self, *args, **kwargs):
        pass

    def read_text(self, **kwargs):
        return "Linux version 6.1.0-generic (buildd@lcy02-amd64-119) ...\n"


def test_is_wsl_host_reads_the_distro_env_var(monkeypatch):
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    assert terminal_manager._is_wsl_host() is True


def test_is_wsl_host_false_when_neither_signal_is_present(monkeypatch):
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(terminal_manager, "Path", _FakeProcVersionPath)
    assert terminal_manager._is_wsl_host() is False


def test_windows_shells_are_only_offered_when_wsl_host_is_detected(monkeypatch):
    monkeypatch.setattr(terminal_manager, "_is_wsl_host", lambda: False)
    shells = terminal_manager.detect_available_shells()
    assert all(s["kind"] != "windows" for s in shells)


def test_windows_shells_are_offered_when_wsl_host_is_detected_and_present(monkeypatch):
    monkeypatch.setattr(terminal_manager, "_is_wsl_host", lambda: True)
    monkeypatch.setattr(terminal_manager, "_WINDOWS_SHELL_CANDIDATES", [("/fake/path/pwsh.exe", "Fake PowerShell")])
    monkeypatch.setattr(terminal_manager, "_bridge_binary_path", lambda: Path(__file__))
    real_isfile = os.path.isfile
    monkeypatch.setattr(terminal_manager.os.path, "isfile", lambda path: path == "/fake/path/pwsh.exe" or real_isfile(path))
    shells = terminal_manager.detect_available_shells()
    windows_entries = [s for s in shells if s["kind"] == "windows"]
    assert windows_entries == [{"path": "/fake/path/pwsh.exe", "name": "Fake PowerShell", "kind": "windows"}]


def test_windows_shells_are_not_offered_without_a_built_bridge_binary(monkeypatch):
    """Real requirement, not an edge case: the bridge is a separately-built artifact (a native
    Windows `cargo build --release`, not something the WSL2-side Python venv can produce) -- a
    fresh clone or a machine where that one-time build step was never run must never offer a
    Windows shell option that would immediately fail to launch."""
    monkeypatch.setattr(terminal_manager, "_is_wsl_host", lambda: True)
    monkeypatch.setattr(terminal_manager, "_WINDOWS_SHELL_CANDIDATES", [("/fake/path/pwsh.exe", "Fake PowerShell")])
    monkeypatch.setattr(terminal_manager, "_bridge_binary_path", lambda: Path("/definitely/does/not/exist.exe"))
    real_isfile = os.path.isfile
    monkeypatch.setattr(terminal_manager.os.path, "isfile", lambda path: path == "/fake/path/pwsh.exe" or real_isfile(path))
    shells = terminal_manager.detect_available_shells()
    assert all(s["kind"] != "windows" for s in shells)


@pytest.mark.skipif(
    not terminal_manager._is_wsl_host()
    or not any(s["kind"] == "windows" for s in terminal_manager.detect_available_shells()),
    reason="no native Windows shell reachable via WSL interop on this machine",
)
def test_create_terminal_can_spawn_a_real_windows_shell_via_wsl_interop(tmp_path):
    """The highest-risk part of this feature: launching a real Windows .exe from inside WSL2 --
    now via windows-pty-bridge/'s own real ConPTY, not a direct exec onto the Linux pty (the
    earlier direct-exec approach was replaced for exactly this reason).
    Confirmed live (manual probe, not just this test) that this survives cleanly -- the calling
    Python process stays alive throughout, unlike a separate, unrelated explorer.exe-from-WSL
    incident elsewhere in this project (that process wasn't isolated the way _spawn_pty already
    isolates every terminal here: its own session via os.setsid(), its own PTY as controlling
    terminal, no shared console with ASRA's own process)."""
    windows_shell = next(s for s in terminal_manager.detect_available_shells() if s["kind"] == "windows")

    async def scenario():
        session = await terminal_manager.create_terminal(str(tmp_path), windows_shell["path"])
        session.write_input(b"echo WINDOWS_SHELL_PROBE_MARKER\r\n")
        found = await _await_windows_shell(session, b"WINDOWS_SHELL_PROBE_MARKER")
        return session, found

    session, found = asyncio.run(scenario())
    try:
        assert session.shell == windows_shell["path"]
        assert found
    finally:
        terminal_manager.close_terminal(session.id)
        # The real point of this test: the interpreter running it (and, in the real app, the
        # whole ASRA server) must still be alive and responsive after spawning+killing a real
        # Windows process via WSL interop -- if it weren't, pytest itself would never get here.
        assert os.getpid() > 0


@pytest.mark.skipif(
    not terminal_manager._is_wsl_host()
    or not any(s["kind"] == "windows" and "PowerShell" in s["name"] for s in terminal_manager.detect_available_shells()),
    reason="no native PowerShell reachable via WSL interop on this machine",
)
def test_windows_pty_bridge_gives_powershell_real_tab_completion():
    """THE actual bug this whole bridge exists to fix -- confirmed live (this exact scenario, via
    an isolated probe, before being turned into a permanent test): PowerShell's own PSReadLine
    (real interactive line-editing -- syntax highlighting, tab-completion, history) only works
    when the target shell has a genuine Win32 ConPTY of its own, which is exactly what
    windows-pty-bridge/ now gives it. The OLD (pre-bridge) direct-exec approach either crashed
    PowerShell outright on a bare Tab keypress, or (cmd.exe) silently failed to complete anything
    at all."""
    windows_shell = next(
        s for s in terminal_manager.detect_available_shells()
        if s["kind"] == "windows" and "PowerShell" in s["name"]
    )

    async def scenario():
        session = await terminal_manager.create_terminal("/mnt/c/Users/Public", windows_shell["path"])
        still_alive_after_create = not session.exited
        session.write_input(b"cd C:\\Us")
        await asyncio.sleep(0.4)
        session.write_input(b"\t")  # the exact keystroke that used to crash PowerShell outright
        await asyncio.sleep(1.0)
        still_alive_after_tab = not session.exited  # the crash this bridge fixes
        completed = await _await_windows_shell(session, b"C:\\Users\\")  # PSReadLine actually completed it
        return session, still_alive_after_create, still_alive_after_tab, completed

    session, still_alive_after_create, still_alive_after_tab, completed = asyncio.run(scenario())
    try:
        assert still_alive_after_create
        assert still_alive_after_tab
        assert completed
    finally:
        terminal_manager.close_terminal(session.id)


def test_write_input_wraps_bytes_in_the_bridge_frame_for_windows_kind_sessions(tmp_path, monkeypatch):
    """windows-pty-bridge/ (a real Win32 ConPTY host, replacing the earlier direct-exec approach
    that left Tab/PSReadLine broken) speaks a length-
    framed protocol on its own stdin, not raw passthrough: a plain redirected pipe has no message
    boundaries of its own the way a WebSocket frame does, so the length has to be explicit. Real,
    confirmed incident this shape fixes: without this framing (and without the pty's own raw mode,
    see the sibling test below), the KERNEL's own default cooked-mode line-echo put literal
    garbage control bytes into the terminal output -- verified live, not just reasoning about it.
    Exercises the framing in isolation (flip .kind on a real, cheap /bin/sh session rather than
    needing a real Windows binary) by capturing what os.write actually receives."""
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(scenario())
    try:
        session.kind = "windows"
        written = []
        monkeypatch.setattr(terminal_manager.os, "write", lambda fd, data: written.append(data) or len(data))
        session.write_input(b"foo\tbar")
        assert written == [b"\x00\x00\x00\x00\x07foo\tbar"]  # tag 0x00 + u32 length(7) + payload
    finally:
        terminal_manager.close_terminal(session.id)


def test_write_input_passes_bytes_through_unframed_for_wsl_sessions(tmp_path, monkeypatch):
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(scenario())
    try:
        written = []
        monkeypatch.setattr(terminal_manager.os, "write", lambda fd, data: written.append(data) or len(data))
        session.write_input(b"foo\tbar")
        assert written == [b"foo\tbar"]
    finally:
        terminal_manager.close_terminal(session.id)


def test_resize_sends_a_framed_message_for_windows_kind_instead_of_ioctl(tmp_path, monkeypatch):
    """The bridge owns a SEPARATE ConPTY of its own -- TIOCSWINSZ on our own Linux pty would only
    change metadata the bridge itself never reads, so a windows-kind resize has to go through the
    same explicit framed protocol write_input's own sibling test above documents."""
    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(scenario())
    try:
        session.kind = "windows"
        written = []
        monkeypatch.setattr(terminal_manager.os, "write", lambda fd, data: written.append(data) or len(data))
        session.resize(120, 40)
        assert written == [b"\x01\x00\x78\x00\x28"]  # tag 0x01 + u16 cols(120) + u16 rows(40)
    finally:
        terminal_manager.close_terminal(session.id)


def test_windows_safe_cwd_fallback_returns_first_existing_candidate(monkeypatch):
    # A real username lookup would otherwise take priority (correctly -- see the sibling tests
    # below) and mask what this test is actually checking: the CANDIDATE-LIST fallback behavior
    # for when no real username can be determined at all.
    monkeypatch.setattr(terminal_manager, "_detect_windows_username", lambda: None)
    monkeypatch.setattr(terminal_manager, "_WINDOWS_SAFE_CWD_CANDIDATES", ["/does/not/exist/at/all", "/tmp"])
    assert terminal_manager._windows_safe_cwd_fallback() == "/tmp"


def test_windows_safe_cwd_fallback_prefers_the_real_operators_own_profile(tmp_path, monkeypatch):
    """Real, confirmed operator complaint this fixes: every Windows shell opened with no explicit
    cwd used to default straight to C:\\Users\\Public -- a mostly-empty, rarely-used SHARED system
    profile, not the operator's own actual Desktop/Documents/files -- which read as "the terminal
    is broken, I don't recognize most of these folders and the rest are empty" when it was really
    just never looking at the right user's own home directory at all."""
    monkeypatch.setattr(terminal_manager, "_detect_windows_username", lambda: "realoperator")
    fake_profile = tmp_path / "mnt_c_Users_realoperator"
    fake_profile.mkdir()
    monkeypatch.setattr(terminal_manager.os.path, "isdir", lambda p: p == "/mnt/c/Users/realoperator" or os.path.isdir(p))
    assert terminal_manager._windows_safe_cwd_fallback() == "/mnt/c/Users/realoperator"


def test_windows_safe_cwd_fallback_falls_back_when_the_detected_profile_does_not_exist(monkeypatch):
    """A detected username whose own profile folder doesn't actually exist (a stale/renamed
    account, an edge case, whatever) must never be trusted blindly -- falls through to the same
    candidate list the "no username at all" case uses."""
    monkeypatch.setattr(terminal_manager, "_detect_windows_username", lambda: "nonexistent-user")
    monkeypatch.setattr(terminal_manager, "_WINDOWS_SAFE_CWD_CANDIDATES", ["/does/not/exist/at/all", "/tmp"])
    assert terminal_manager._windows_safe_cwd_fallback() == "/tmp"


def test_detect_windows_username_parses_cmd_exe_output(monkeypatch):
    terminal_manager._windows_username_lookup_attempted = False
    terminal_manager._windows_username_cache = None
    monkeypatch.setattr(terminal_manager.os.path, "isfile", lambda p: True)

    class _FakeResult:
        stdout = "realoperator\r\n"

    monkeypatch.setattr(terminal_manager.subprocess, "run", lambda *a, **kw: _FakeResult())
    try:
        assert terminal_manager._detect_windows_username() == "realoperator"
        # Cached -- a second call must not re-invoke subprocess.run at all.
        monkeypatch.setattr(
            terminal_manager.subprocess, "run",
            lambda *a, **kw: (_ for _ in ()).throw(AssertionError("should not be called again")),
        )
        assert terminal_manager._detect_windows_username() == "realoperator"
    finally:
        terminal_manager._windows_username_lookup_attempted = False
        terminal_manager._windows_username_cache = None


def test_detect_windows_username_returns_none_when_cmd_exe_is_missing(monkeypatch):
    terminal_manager._windows_username_lookup_attempted = False
    terminal_manager._windows_username_cache = None
    monkeypatch.setattr(terminal_manager.os.path, "isfile", lambda p: False)
    try:
        assert terminal_manager._detect_windows_username() is None
    finally:
        terminal_manager._windows_username_lookup_attempted = False
        terminal_manager._windows_username_cache = None


@pytest.mark.skipif(not os.path.isfile("/mnt/c/Windows/System32/cmd.exe"), reason="no real cmd.exe reachable via WSL interop on this machine")
def test_detect_windows_username_returns_a_real_value_on_this_machine(monkeypatch):
    """Confirmed live (this exact call, not a mock) on the actual dev machine this was built and
    fixed on -- resolved to the machine's own real logged-in Windows username, and that user's own
    profile folder genuinely exists at /mnt/c/Users/<that name>."""
    terminal_manager._windows_username_lookup_attempted = False
    terminal_manager._windows_username_cache = None
    try:
        username = terminal_manager._detect_windows_username()
        assert username
        assert os.path.isdir(f"/mnt/c/Users/{username}")
    finally:
        terminal_manager._windows_username_lookup_attempted = False
        terminal_manager._windows_username_cache = None


def test_create_terminal_redirects_windows_kind_away_from_a_non_windows_cwd(tmp_path, monkeypatch):
    """A WSL-internal path (not under /mnt/) has no real Windows drive letter behind it -- WSL2
    only exposes it to a Windows process as a \\\\wsl.localhost\\... UNC path, and a real probe
    confirmed live that PowerShell itself gets denied read access there ("Access to the path
    ... is denied" on a plain `ls`). Must be redirected to somewhere a Windows shell can actually
    read, never silently left somewhere that looks entered but can't be listed."""
    monkeypatch.setattr(terminal_manager, "_is_wsl_host", lambda: True)
    monkeypatch.setattr(terminal_manager, "_WINDOWS_SHELL_CANDIDATES", [("/fake/pwsh.exe", "Fake PowerShell")])
    monkeypatch.setattr(terminal_manager, "_bridge_binary_path", lambda: Path(__file__))
    real_isfile = os.path.isfile
    monkeypatch.setattr(terminal_manager.os.path, "isfile", lambda path: path == "/fake/pwsh.exe" or real_isfile(path))
    real_spawn_pty = terminal_manager._spawn_pty

    def fake_spawn(shell, argv, cwd, env, raw=False):
        return real_spawn_pty("/bin/sh", ["/bin/sh"], cwd, env)

    monkeypatch.setattr(terminal_manager, "_spawn_pty", fake_spawn)
    monkeypatch.setattr(terminal_manager, "_windows_safe_cwd_fallback", lambda: str(tmp_path))

    not_windows_backed = tmp_path / "somewhere"
    not_windows_backed.mkdir()

    async def scenario():
        return await terminal_manager.create_terminal(str(not_windows_backed), "/fake/pwsh.exe")

    session = asyncio.run(scenario())
    try:
        assert session.kind == "windows"
        assert session.cwd == str(tmp_path)  # redirected, not the WSL-internal path we asked for
    finally:
        terminal_manager.close_terminal(session.id)


@pytest.mark.skipif(not os.path.isdir("/mnt/c"), reason="not running under WSL2 with a real C: mount")
def test_create_terminal_keeps_a_windows_drive_backed_cwd_for_windows_kind(monkeypatch):
    monkeypatch.setattr(terminal_manager, "_is_wsl_host", lambda: True)
    monkeypatch.setattr(terminal_manager, "_WINDOWS_SHELL_CANDIDATES", [("/fake/pwsh.exe", "Fake PowerShell")])
    monkeypatch.setattr(terminal_manager, "_bridge_binary_path", lambda: Path(__file__))
    real_isfile = os.path.isfile
    monkeypatch.setattr(terminal_manager.os.path, "isfile", lambda path: path == "/fake/pwsh.exe" or real_isfile(path))
    real_spawn_pty = terminal_manager._spawn_pty

    def fake_spawn(shell, argv, cwd, env, raw=False):
        return real_spawn_pty("/bin/sh", ["/bin/sh"], cwd, env)

    monkeypatch.setattr(terminal_manager, "_spawn_pty", fake_spawn)

    async def scenario():
        return await terminal_manager.create_terminal("/mnt/c", "/fake/pwsh.exe")

    session = asyncio.run(scenario())
    try:
        assert session.cwd == "/mnt/c"  # already Windows-drive-backed -- left alone, not redirected
    finally:
        terminal_manager.close_terminal(session.id)


def test_create_terminal_routes_windows_kind_through_the_bridge_with_translated_paths(tmp_path, monkeypatch):
    """The bridge (windows-pty-bridge/'s own compiled binary) -- not the target shell -- is what
    actually gets exec'd for a kind="windows" entry: argv is [bridge_path, translated_shell_path,
    translated_cwd], both paths translated from their /mnt/c/... WSL form to a real Windows-shaped
    one first. Real, confirmed bug this guards against: a native Windows process (the bridge)
    can't resolve a /mnt/c/... path via CreateProcessW at all. Also confirms the pty is opened
    in raw mode for this kind (see _spawn_pty's own
    docstring for why: without it, the kernel's own cooked-mode local echo corrupts the bridge's
    binary framing). Captures the real argv without needing a real Windows binary OR a real built
    bridge to exist on this test machine (a real /bin/sh is spawned underneath instead via the
    mocked _spawn_pty, so session bookkeeping/cleanup stays realistic; _bridge_binary_path points
    at this very test file, which is guaranteed to exist, purely so detect_available_shells' own
    is_file() gate passes)."""
    real_spawn_pty = terminal_manager._spawn_pty
    captured = {}

    def fake_spawn(shell, argv, cwd, env, raw=False):
        captured["shell"] = shell
        captured["argv"] = list(argv)
        captured["raw"] = raw
        return real_spawn_pty("/bin/sh", ["/bin/sh"], cwd, env)

    monkeypatch.setattr(terminal_manager, "_spawn_pty", fake_spawn)
    monkeypatch.setattr(terminal_manager, "_is_wsl_host", lambda: True)
    monkeypatch.setattr(terminal_manager, "_WINDOWS_SHELL_CANDIDATES", [("/mnt/c/fake/pwsh.exe", "Fake PowerShell")])
    monkeypatch.setattr(terminal_manager, "_bridge_binary_path", lambda: Path(__file__))
    real_isfile = os.path.isfile
    monkeypatch.setattr(terminal_manager.os.path, "isfile", lambda path: path == "/mnt/c/fake/pwsh.exe" or real_isfile(path))

    async def scenario():
        return await terminal_manager.create_terminal("/mnt/c/Users/Public", "/mnt/c/fake/pwsh.exe")

    session = asyncio.run(scenario())
    try:
        assert captured["shell"] == str(Path(__file__))
        assert captured["argv"][0] == str(Path(__file__))
        assert captured["argv"][1] == "C:\\fake\\pwsh.exe"
        assert captured["argv"][2] == "C:\\Users\\Public"
        assert captured["raw"] is True
    finally:
        terminal_manager.close_terminal(session.id)


def test_create_terminal_still_uses_login_flag_for_a_wsl_shell(tmp_path, monkeypatch):
    real_spawn_pty = terminal_manager._spawn_pty
    captured = {}

    def fake_spawn(shell, argv, cwd, env, raw=False):
        captured["argv"] = list(argv)
        captured["raw"] = raw
        return real_spawn_pty(shell, argv, cwd, env, raw=raw)

    monkeypatch.setattr(terminal_manager, "_spawn_pty", fake_spawn)

    async def scenario():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(scenario())
    try:
        assert captured["argv"] == [terminal_manager.default_shell_path(), "-l"]
        assert captured["raw"] is False  # only a kind="windows" session opens its pty in raw mode
    finally:
        terminal_manager.close_terminal(session.id)


def test_detach_only_clears_the_matching_viewer(tmp_path):
    async def scenario():
        session = await terminal_manager.create_terminal(str(tmp_path))
        ws = _FakeWebSocket()
        await terminal_manager.attach(session.id, ws)
        # A stale detach for a viewer that's no longer attached must not clear the real one.
        terminal_manager.detach(session.id, _FakeWebSocket())
        assert session._viewer is ws
        terminal_manager.detach(session.id, ws)
        return session

    session = asyncio.run(scenario())
    try:
        assert session._viewer is None
    finally:
        terminal_manager.close_terminal(session.id)
