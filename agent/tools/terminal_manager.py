"""Real interactive PTY-backed terminal sessions for the standalone Terminal tab (main.py's
GET /terminal page + WS /ws/terminal/{terminal_id}) -- a genuine login shell, not an agent-mediated
sandboxed command runner: whatever runs in a real terminal on this machine (another CLI tool, an
interactive REPL, a TUI program) must behave identically here, the same way VS Code's own
integrated terminal does, because that's the whole point of this feature for the operator.

Runs only inside a POSIX process -- confirmed by this project's own "Runtime architecture" notes:
ASRA's Python process is always Linux under the hood (WSL2 on Windows, native on Linux/macOS),
sys.platform is never "win32" in the supported launch path. So this uses the stdlib `pty` module
directly (openpty + a plain os.fork/os.execvpe child, the same shape ptyprocess/pexpect use
internally) -- no ConPTY/pywinpty branch of our own on the Python side, no cross-platform PTY
abstraction needed here at all. The one real exception is detect_available_shells()'s own optional
native-Windows shells (cmd.exe/powershell.exe), offered only when this process is itself running
under WSL2 AND windows-pty-bridge/'s own compiled binary is present -- that binary (a separate
Rust crate, built natively on Windows, NOT something this Python module builds or runs itself) is
what actually hosts a real Win32 ConPTY for the target shell to attach to; see
detect_available_shells's own docstring for the full "why" and create_terminal's for how it's
actually invoked.

Deliberately NOT gated by agent/tools/allowed_targets.py's exploitation allowlist -- same reasoning
that module's own docstring already gives for Interactive mode (agent/chat.py): this is the
operator's own manual console, choosing to open it IS the authorization, and a raw shell has no
single "target" argument to scope-check in the first place.

Lifecycle: a terminal's real PTY process lives for as long as this server process is alive --
closing/reloading the browser tab does NOT kill it (a reconnect to the same terminal_id re-attaches
and replays the in-memory scrollback buffer), but a full ASRA server restart does not try to adopt
it either (an explicit, discussed trade-off -- no tmux/screen backing process, kept simple). Every
session's raw output is also appended to its own timestamped transcript file under this machine's
global app dir (Documents/ASRA/console-logs/, see resolve_global_app_dir) -- an operational log for
the operator to look back on, the same spirit as debug.log, not something the debug-category
logger itself should carry (see TERMINAL category usage below: lifecycle events only, never raw
keystrokes/output -- that's exactly the kind of thing that can carry a password the operator typed).
"""
from __future__ import annotations

import asyncio
import fcntl
import os
import pty
import signal
import struct
import subprocess
import termios
import time
import tty
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

# _wsl_folder_to_windows_path is projects/paths.py's own private "/mnt/<drive>/... -> <drive>:\..."
# converter (regex-based, already tested there) -- imported directly rather than duplicated here,
# unlike this module's own tiny _is_wsl_host (a genuine 2-line check, cheaper to duplicate than to
# couple across modules). A native Windows process (windows-pty-bridge/'s own asra-pty-bridge.exe)
# needs a REAL Windows-shaped path for both the shell it hosts and its own starting directory --
# passing it a /mnt/c/... Linux-side path directly is a real, confirmed bug (CreateProcessW simply
# can't resolve that path shape at all).
from projects.paths import _wsl_folder_to_windows_path

logger = get_logger("TERMINAL")

# Total bytes of PTY output kept in memory per terminal for a reconnect's own scrollback replay --
# not the on-disk transcript (unbounded, see _open_log_file), just what a freshly (re)attached
# xterm.js instance needs to redraw its own scrollback without a server restart. Overridable since
# a heavier operator workflow (a long `less`/log-tail session) may want more replay depth.
_SCROLLBACK_BYTES = int(os.environ.get("TERMINAL_SCROLLBACK_KB", "200")) * 1024

# Login shell by default (matches run.sh's own `bash -l` convention) so PATH picks up everything
# setup_tools.sh installed -- a plain non-login shell can silently miss PATH entries sourced only
# from .bash_profile/.profile. TERMINAL_SHELL lets an operator opt into zsh/fish/etc. instead.
_DEFAULT_SHELL = os.environ.get("TERMINAL_SHELL") or os.environ.get("SHELL") or "/bin/bash"

_CONSOLE_LOG_SUBDIR = "console-logs"

# One PTY read at a time -- generous enough that a fast `cat` of a large file or a chatty nmap
# run doesn't fragment into hundreds of tiny WebSocket frames, small enough to stay a bounded,
# predictable per-callback cost.
_READ_CHUNK_BYTES = 65536


class TerminalSession:
    """One real PTY + child shell process, plus the bookkeeping needed to reattach to it later.
    Created only via create_terminal() below -- never instantiate directly, the constructor alone
    doesn't spawn anything."""

    def __init__(self, terminal_id: str, cwd: str, shell: str, kind: str = "wsl") -> None:
        self.id = terminal_id
        self.cwd = cwd
        self.shell = shell
        self.kind = kind  # "wsl" (real POSIX shell) or "windows" (native .exe via WSL interop)
        self.pid: int | None = None
        self.master_fd: int | None = None
        self.created_at = time.time()
        self.exited = False
        self.exit_code: int | None = None
        self.log_path: Path | None = None
        self._log_file = None  # binary file handle, unbuffered
        self._scrollback: deque[bytes] = deque()
        self._scrollback_size = 0
        self._viewer = None  # the one attached WebSocket (fastapi.WebSocket), or None
        self._loop: asyncio.AbstractEventLoop | None = None

    def get_scrollback(self) -> bytes:
        return b"".join(self._scrollback)

    def write_input(self, data: bytes) -> None:
        if self.master_fd is None or self.exited or not data:
            return
        if self.kind == "windows":
            # windows-pty-bridge/ (a real Win32 ConPTY host, launched instead of the target shell
            # directly -- see create_terminal's own comment) speaks its own length-framed protocol
            # on stdin, not raw passthrough: a plain redirected pipe has no message boundaries of
            # its own the way a WebSocket frame does, so the length has to be explicit. This is
            # what makes Tab/PSReadLine/history genuinely WORK for a Windows shell here, instead of
            # the previous direct-exec approach's own Tab-strip workaround (removed once this
            # bridge existed -- the crash it guarded against can't happen anymore, the target shell
            # now gets a real native console, never a translated Linux pty directly).
            data = b"\x00" + struct.pack(">I", len(data)) + data
        try:
            os.write(self.master_fd, data)
        except OSError as exc:
            logger.debug("terminal write failed id=%s (%s)", self.id, exc)

    def resize(self, cols: int, rows: int) -> None:
        if self.master_fd is None or cols <= 0 or rows <= 0:
            return
        try:
            if self.kind == "windows":
                # The bridge owns a SEPARATE ConPTY of its own -- TIOCSWINSZ on our Linux pty
                # would only change metadata the bridge itself never reads. Told explicitly
                # instead, via the same framed protocol write_input's own comment describes.
                os.write(self.master_fd, b"\x01" + struct.pack(">HH", cols, rows))
            else:
                # Setting the master's own window size is enough -- the kernel delivers SIGWINCH
                # to the slave's foreground process group on its own, no manual signal needed.
                fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError as exc:
            logger.debug("terminal resize failed id=%s (%s)", self.id, exc)

    def _append_scrollback(self, data: bytes) -> None:
        self._scrollback.append(data)
        self._scrollback_size += len(data)
        while self._scrollback_size > _SCROLLBACK_BYTES and len(self._scrollback) > 1:
            removed = self._scrollback.popleft()
            self._scrollback_size -= len(removed)

    def _on_readable(self) -> None:
        try:
            data = os.read(self.master_fd, _READ_CHUNK_BYTES)
        except OSError:
            data = b""
        if not data:
            self._handle_exit()
            return
        self._append_scrollback(data)
        if self._log_file is not None:
            try:
                self._log_file.write(data)
            except OSError as exc:
                logger.debug("terminal transcript write failed id=%s (%s)", self.id, exc)
        viewer = self._viewer
        if viewer is not None:
            asyncio.create_task(_safe_send_bytes(viewer, data))

    def _handle_exit(self) -> None:
        self._stop_reading()
        exit_code = None
        if self.pid is not None:
            try:
                _, status = os.waitpid(self.pid, 0)
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
            except ChildProcessError:
                pass
        self.exit_code = exit_code
        self.exited = True
        self._close_log_file()
        logger.debug("terminal exited id=%s exit_code=%s", self.id, self.exit_code)
        viewer = self._viewer
        if viewer is not None:
            asyncio.create_task(_safe_send_json(viewer, {"type": "exited", "code": self.exit_code}))

    def _stop_reading(self) -> None:
        if self.master_fd is None:
            return
        if self._loop is not None:
            try:
                self._loop.remove_reader(self.master_fd)
            except (ValueError, OSError):
                pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        self.master_fd = None

    def _close_log_file(self) -> None:
        if self._log_file is not None:
            try:
                self._log_file.close()
            except OSError:
                pass
            self._log_file = None

    def kill(self) -> None:
        """Best-effort, synchronous teardown -- used both for an explicit operator "close tab" and
        for the whole-server shutdown backstop (main.py's _lifespan), so a terminal's real child
        process never survives past whichever of those actually happens."""
        self._stop_reading()
        if self.pid is not None:
            try:
                # The child called os.setsid() at spawn (_spawn_pty below), so its own pgid equals
                # its pid -- killing that whole group takes out anything IT spawned too (a Ctrl+C-
                # resistant background job left running inside the shell), not just the shell itself.
                os.killpg(self.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                pass
            else:
                # Without this, the shell becomes a zombie forever -- SIGTERM alone doesn't reap
                # it, only waitpid() does, and nothing else in this process ever calls waitpid()
                # for a session killed this way (only the natural-EOF path in _handle_exit does).
                # A real, confirmed bug this fixes: os.kill(pid, 0) still succeeds against an
                # unreaped zombie, so the child looked "still alive" indefinitely after close().
                # Bounded and safe to block on -- bash has no SIGTERM trap of its own, so this
                # returns almost immediately in the overwhelmingly common case; a child that
                # somehow ignores SIGTERM would block this call, so give it a hard ceiling and
                # fall back to SIGKILL rather than hang the caller (close_terminal, or a whole-
                # server shutdown) on one stuck process.
                deadline = time.time() + 3
                reaped = False
                while time.time() < deadline:
                    try:
                        reaped_pid, _ = os.waitpid(self.pid, os.WNOHANG)
                    except ChildProcessError:
                        reaped = True
                        break
                    if reaped_pid == self.pid:
                        reaped = True
                        break
                    time.sleep(0.05)
                if not reaped:
                    try:
                        os.killpg(self.pid, signal.SIGKILL)
                        os.waitpid(self.pid, 0)
                    except (ProcessLookupError, ChildProcessError, PermissionError, OSError):
                        pass
        self._close_log_file()
        self.exited = True


_TERMINALS: dict[str, TerminalSession] = {}


async def _safe_send_bytes(ws, data: bytes) -> None:
    try:
        await ws.send_bytes(data)
    except Exception:
        pass  # viewer already disconnected -- detach() will clean up the registry side


async def _safe_send_json(ws, payload: dict) -> None:
    try:
        await ws.send_json(payload)
    except Exception:
        pass


def _spawn_pty(shell: str, argv: list[str], cwd: str, env: dict[str, str], raw: bool = False) -> tuple[int, int]:
    """Forks a real child process attached to a fresh PTY slave as its controlling terminal.
    Plain os.fork()+os.execvpe(), not subprocess.Popen -- Popen's preexec_fn runs before it
    redirects stdin/stdout/stderr to the given fds, so there's no clean hook to call
    ioctl(TIOCSCTTY) on the slave at the right moment; a manual fork here is the same handful of
    syscalls pexpect/ptyprocess use internally, and the child does nothing but
    setsid/ioctl/dup2/close/exec (all async-signal-safe) before immediately exec'ing, so there's no
    real fork-in-a-threaded-process risk. `argv` is caller-supplied (not always [shell, "-l"]) --
    see create_terminal's own argv shaping for why a Windows shell needs a different shape.

    `raw`=True (only ever set for the windows-pty-bridge target -- create_terminal's own caller)
    puts the pty into raw mode (no kernel-level ECHO/canonical line buffering) before the child
    ever runs. Every WSL/Linux shell here relies on the pty starting in normal cooked mode and
    switching itself into raw mode via its own readline/termios setup the moment it starts an
    interactive session (completely standard bash/zsh/etc. behavior) -- so this is never set for
    those. The bridge does no termios configuration of its own at all (it's a Windows program;
    POSIX termios doesn't mean anything on that side), so left at the pty's own cooked-mode
    default, the KERNEL's own local-echo line discipline echoes back everything written to the
    master -- confirmed live, real, and completely protocol-breaking: the bridge's own binary
    length-prefixed framing (write_input's own comment) showed up as literal garbage characters in
    the terminal output, because the kernel echoed it before -- and regardless of -- whatever the
    bridge itself did with those bytes once it actually read them.
    Returns (child_pid, master_fd) -- the caller owns master_fd from here on."""
    master_fd, slave_fd = pty.openpty()
    if raw:
        tty.setraw(slave_fd)
    pid = os.fork()
    if pid == 0:
        # Child: never returns past execvpe on success. Any failure here calls os._exit directly
        # (never raises back into the parent's own exception handling, which would be nonsense in
        # a forked child sharing the parent's file descriptors/state).
        try:
            os.close(master_fd)
            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if slave_fd > 2:
                os.close(slave_fd)
            os.chdir(cwd)
            os.execvpe(shell, argv, env)
        except Exception:
            os._exit(1)
    os.close(slave_fd)
    return pid, master_fd


# Consulted only when /etc/shells is missing/empty (some minimal container base images ship
# without it) -- common install paths across mainstream distros, so a fresh machine still offers
# at least whatever's really present instead of an empty picker.
_FALLBACK_SHELL_CANDIDATES = [
    "/bin/bash", "/usr/bin/bash", "/bin/zsh", "/usr/bin/zsh", "/bin/fish", "/usr/bin/fish",
    "/bin/dash", "/bin/sh", "/bin/ksh", "/usr/bin/ksh", "/bin/tcsh", "/bin/csh",
]

# Native Windows shells, reachable only when this process is itself running inside WSL2 (see
# _is_wsl_host below) -- launched through WSL2's own binfmt_misc interop, which lets a Linux
# process exec a real Windows .exe directly. Absolute /mnt/c/... paths, not bare names on PATH:
# WSL2's default interop.appendWindowsPath setting would usually make "cmd.exe"/"powershell.exe"
# resolve via PATH too, but that setting is a per-machine opt-out, and an absolute path check
# here doesn't depend on it being left at its default. kind="windows" tags every entry so
# create_terminal knows to build Windows-shaped argv (no "-l", meaningless there) and the frontend
# knows to group/label these separately from the WSL(Linux) shells above them.
_WINDOWS_SHELL_CANDIDATES = [
    ("/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "PowerShell"),
    ("/mnt/c/Program Files/PowerShell/7/pwsh.exe", "PowerShell 7"),
    ("/mnt/c/Windows/System32/cmd.exe", "Command Prompt"),
]


def _bridge_binary_path() -> Path:
    """windows-pty-bridge/bin/asra-pty-bridge.exe -- a real Win32 ConPTY host (see that crate's own
    Cargo.toml description), built with a native Windows `cargo build --release` (same "Desktop
    shell changes" rebuild discipline this project already applies to desktop/src-tauri, not
    something the WSL2-side Python venv can build itself). Resolved relative to this file's own
    location (three parents up: agent/tools/ -> agent/ -> repo root) rather than the process's
    current working directory, so this is correct regardless of where ASRA was launched from."""
    return Path(__file__).resolve().parents[2] / "windows-pty-bridge" / "bin" / "asra-pty-bridge.exe"


def _is_wsl_host() -> bool:
    """True when THIS process is itself running inside WSL2 -- the "dual system" case (a real
    Windows host underneath, reachable via interop) as opposed to native Linux/macOS, where there
    is no separate "Windows side" to offer at all. Same two-signal check projects/paths.py's own
    _is_wsl() already uses (WSL_DISTRO_NAME env var, else /proc/version mentioning "microsoft") --
    duplicated here rather than imported since it's two lines and importing a private, underscore-
    prefixed helper across modules would be the wrong kind of coupling for something this small."""
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def detect_available_shells() -> list[dict]:
    """Real shells actually present and executable on THIS machine. Always includes the POSIX/
    Linux side ASRA's own process runs on (WSL2 on Windows, native on Linux/macOS; see this
    module's own docstring) -- reads /etc/shells first (the canonical POSIX registry of installed
    login shells), then checks _FALLBACK_SHELL_CANDIDATES for anything not already listed there.
    Every Linux entry is verified to actually exist AND be executable before being returned --
    nothing here is taken on faith, so a stale /etc/shells entry (a shell since uninstalled) never
    shows up as a false option.

    When this process is itself running under WSL2 (a real Windows host underneath -- a "dual
    system") AND windows-pty-bridge/'s own compiled binary is actually present (_bridge_binary_path
    -- an optional, separately-built component; see that crate's own Cargo.toml), also probes
    _WINDOWS_SHELL_CANDIDATES and includes whichever actually exist, tagged kind="windows". No
    bridge binary means no Windows entries offered at all -- never a choice that would silently
    fall back to something broken.

    Earlier revision of this feature (before the bridge existed) launched cmd.exe/powershell.exe
    directly via WSL2's own interop, attached straight to the same Linux PTY every WSL shell here
    uses -- confirmed live, real, and bad: PowerShell's own PSReadLine (interactive line-editor,
    owns tab-completion/history) crashed outright on a single Tab keypress, and cmd.exe's own path
    completion never worked at all even without crashing (WSL2's console translation for a directly
    interop-launched Windows console app doesn't fully emulate what either program actually needs).
    windows-pty-bridge is the real fix, not a workaround: it launches AS the interop-exec'd process
    (same isolation _spawn_pty already gives every terminal here -- os.setsid() into a fresh
    session, a real PTY as its own controlling terminal, no shared console with ASRA's own process),
    then creates a genuine Win32 ConPTY of its OWN and attaches the real target shell to THAT --
    so PSReadLine/tab-completion/history all work exactly as they would in a real Windows Terminal
    window, because the target shell never touches the translated Linux pty at all. The frontend
    still labels these entries "experimental": the bridge is new, exercised far less than the WSL
    shells above it, and still depends on WSL2's interop launch mechanism for its own I/O plumbing.
    NTFS-via-DrvFs's own executable-bit emulation for a mounted .exe isn't reliably queryable via
    os.access(X_OK) the way a real Linux executable bit is, so these are checked with a plain
    os.path.isfile() instead -- the extension alone (.exe, always present in the candidate list
    above) is what actually matters for WSL2's own binfmt_misc dispatch.

    Recomputed fresh on every call -- cheap (a handful of stat() calls), and this only ever runs
    when an operator opens the shell picker, not on any hot path.
    """
    candidates: list[str] = []
    try:
        with open("/etc/shells", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    candidates.append(line)
    except OSError:
        pass
    for path in _FALLBACK_SHELL_CANDIDATES:
        if path not in candidates:
            candidates.append(path)

    seen: set[str] = set()
    shells: list[dict] = []
    for path in candidates:
        if path in seen or not os.path.isfile(path) or not os.access(path, os.X_OK):
            continue
        seen.add(path)
        shells.append({"path": path, "name": os.path.basename(path), "kind": "wsl"})

    if _is_wsl_host() and _bridge_binary_path().is_file():
        for path, name in _WINDOWS_SHELL_CANDIDATES:
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            shells.append({"path": path, "name": name, "kind": "windows"})

    return shells


def default_shell_path() -> str:
    return _DEFAULT_SHELL


# Fallbacks ONLY -- _windows_safe_cwd_fallback() below always tries the operator's own real
# Windows profile first (_detect_windows_username). These are what's left if that lookup can't
# resolve a real username, or that user's own profile folder somehow doesn't exist. "Public" is a
# standard, always-present, always-world-readable Windows profile folder; the raw drive root is
# the last-resort fallback if even that were somehow missing.
_WINDOWS_SAFE_CWD_CANDIDATES = ["/mnt/c/Users/Public", "/mnt/c/"]

_windows_username_cache: str | None = None
_windows_username_lookup_attempted = False


def _detect_windows_username() -> str | None:
    """The real, currently logged-in Windows username -- WSL2 does NOT expose this as an ambient
    environment variable on its own, so the only reliable way to get it is to ask Windows
    directly, via the same interop mechanism this whole feature already uses to launch cmd.exe/
    powershell.exe (a plain one-shot `cmd.exe /c echo %USERNAME%`, not anything PTY-related).
    Cached after the first lookup (the answer can't change mid-process, and launching cmd.exe just
    to ask isn't worth paying for on every single terminal creation)."""
    global _windows_username_cache, _windows_username_lookup_attempted
    if _windows_username_lookup_attempted:
        return _windows_username_cache
    _windows_username_lookup_attempted = True
    cmd_path = "/mnt/c/Windows/System32/cmd.exe"
    if not os.path.isfile(cmd_path):
        return None
    try:
        result = subprocess.run(
            [cmd_path, "/c", "echo %USERNAME%"],
            capture_output=True, text=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("terminal: windows username lookup failed (%s)", exc)
        return None
    username = result.stdout.strip()
    if not username or username == "%USERNAME%":
        return None
    _windows_username_cache = username
    return username


def _windows_safe_cwd_fallback() -> str:
    """A real, accessible starting directory for a Windows-kind terminal with no cwd of its own
    to use -- the operator's own real Windows profile folder whenever that can be determined, NOT
    a generic shared system profile. Real, confirmed operator complaint this fixes: every plain
    "+"-opened Windows shell used to default straight to C:\\Users\\Public -- a mostly-empty,
    rarely-used SHARED system profile, not the operator's own actual Desktop/Documents/files --
    which read as "the terminal is broken, half these folders are empty and I don't recognize the
    others" when it was really just never looking at the right user's own home directory at all."""
    username = _detect_windows_username()
    if username:
        real_profile = f"/mnt/c/Users/{username}"
        if os.path.isdir(real_profile):
            return real_profile
    for candidate in _WINDOWS_SAFE_CWD_CANDIDATES:
        if os.path.isdir(candidate):
            return candidate
    return "/"


def _open_log_file(session: TerminalSession) -> Path:
    """One timestamped transcript file per terminal session under the global app dir's own
    console-logs/ subfolder (Documents/ASRA/console-logs/ -- sibling to debug.log, never this
    repo's own data/ directory, same "operator's real Documents, not the install folder" rule
    agent/utils/debug.py already follows). Deliberately outside git entirely (resolve_global_app_dir
    already lives outside the repo), so this needs no .gitignore entry of its own. Raw PTY bytes,
    unbuffered append -- same shape the Unix `script` command captures, so a saved file replays
    with its original formatting/colors intact if ever opened in a real terminal later."""
    base = resolve_global_app_dir() / _CONSOLE_LOG_SUBDIR
    base.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = base / f"{stamp}_{session.id}.log"
    session._log_file = open(path, "ab", buffering=0)
    return path


async def create_terminal(cwd: str | None = None, shell: str | None = None) -> TerminalSession:
    """Spawns a brand-new real shell. `cwd` is used as-is when it's a real, existing directory
    (the per-project "open terminal here" quick-launch); falls back to the operator's own home
    directory otherwise (the global sidebar tab's default -- a normal fresh terminal's own
    expectation, not this project's own repo/install folder). `shell` (the terminal-type picker,
    main.py's /api/terminal/new) is only ever honored when it exactly matches one of
    detect_available_shells()'s own paths -- never an arbitrary client-supplied exec path -- and
    silently falls back to the configured default otherwise, same forgiving-body-parsing spirit as
    the rest of this route family rather than a hard 400 for what's realistically an operator's own
    now-stale picker selection (a shell that was uninstalled between page load and click)."""
    terminal_id = uuid.uuid4().hex[:12]
    resolved_cwd = cwd if cwd and Path(cwd).is_dir() else str(Path.home())
    detected = detect_available_shells()
    shell_kind_by_path = {entry["path"]: entry["kind"] for entry in detected}
    resolved_shell = shell if shell in shell_kind_by_path else _DEFAULT_SHELL
    resolved_kind = shell_kind_by_path.get(resolved_shell, "wsl")
    if resolved_kind == "windows" and not resolved_cwd.startswith("/mnt/"):
        # A WSL-internal path (e.g. /root, /home/user) has no real Windows drive letter behind
        # it -- WSL2 exposes it to a Windows process only as a \\wsl.localhost\... UNC path, which
        # Windows console apps don't reliably get read access to (confirmed live: PowerShell
        # itself denied "Access to the path '\\wsl.localhost\...\root' is denied" on a plain `ls`
        # started there). Redirected to a real, always-present, always-accessible Windows
        # directory instead -- never silently left somewhere that looks entered but can't be read.
        resolved_cwd = _windows_safe_cwd_fallback()

    if resolved_kind == "windows":
        # The bridge, not the target shell, is what actually gets exec'd -- it creates its own
        # real ConPTY and attaches the target shell to THAT (see windows-pty-bridge/src/main.rs
        # and this module's own top-of-file docstring). argv[1]/argv[2] are the real shell path
        # and starting directory, both translated to real Windows-shaped paths first -- the
        # bridge is a native Windows process (CreateProcessW underneath), and handing it a
        # /mnt/c/... Linux-side path for either one is a real, confirmed bug (CreateProcessW
        # can't resolve that path shape, and relying on WSL2 interop's own ambient cwd
        # translation for the bridge process itself was confirmed live to land somewhere OTHER
        # than the cwd this function actually resolved -- passing it explicitly removes that
        # guesswork entirely). The bridge never receives a login-shell "-l" flag either way (it's
        # not a shell itself, and neither cmd.exe/powershell.exe would understand it).
        exec_target = str(_bridge_binary_path())
        windows_shell = _wsl_folder_to_windows_path(Path(resolved_shell))
        windows_cwd = _wsl_folder_to_windows_path(Path(resolved_cwd))
        argv = [exec_target, windows_shell, windows_cwd]
    else:
        exec_target = resolved_shell
        argv = [resolved_shell, "-l"]

    env = dict(os.environ)
    env["TERM"] = "xterm-256color"

    pid, master_fd = _spawn_pty(exec_target, argv, resolved_cwd, env, raw=(resolved_kind == "windows"))
    os.set_blocking(master_fd, False)

    session = TerminalSession(terminal_id, resolved_cwd, resolved_shell, resolved_kind)
    session.pid = pid
    session.master_fd = master_fd
    session.log_path = _open_log_file(session)

    loop = asyncio.get_running_loop()
    session._loop = loop
    loop.add_reader(master_fd, session._on_readable)

    _TERMINALS[terminal_id] = session
    logger.debug(
        "terminal created id=%s shell=%s kind=%s cwd=%s pid=%s log=%s",
        terminal_id, resolved_shell, resolved_kind, resolved_cwd, pid, session.log_path,
    )
    return session


def get_terminal(terminal_id: str) -> TerminalSession | None:
    return _TERMINALS.get(terminal_id)


def list_terminals() -> list[dict]:
    """Every terminal session still tracked in this process (alive or exited-but-not-yet-closed) --
    backs the frontend's own reattach-after-reload flow (static/js/terminal.js's restoreTabs()).
    A real PTY here lives for the server process's whole lifetime regardless of what the browser
    does (this module's own top-of-file docstring), but until this existed the frontend had no way
    to discover that: a full page reload/navigation always called /api/terminal/new instead,
    leaving every previously-open tab's real shell process running invisibly forever (a genuine,
    confirmed leak, not just a UI annoyance) while the operator saw their terminal wiped clean.
    Includes exited sessions too -- an operator reattaching to one should still see its final
    scrollback and exit message, exactly like a real terminal window left open after its shell died."""
    return [
        {"terminal_id": s.id, "cwd": s.cwd, "shell": s.shell, "kind": s.kind, "exited": s.exited}
        for s in _TERMINALS.values()
    ]


async def attach(terminal_id: str, ws) -> TerminalSession | None:
    """Attaches `ws` as the terminal's one live viewer -- a second attach on the same terminal_id
    (e.g. the same tab reopened in another browser window) politely disconnects whoever was
    already attached first, the same "one active viewer" model `tmux attach -d` uses, so input
    from two sockets can never race on the same PTY."""
    session = _TERMINALS.get(terminal_id)
    if session is None:
        return None
    previous = session._viewer
    session._viewer = ws
    if previous is not None and previous is not ws:
        try:
            await previous.close(code=1000)
        except Exception:
            pass
    logger.debug("terminal attached id=%s", terminal_id)
    return session


def detach(terminal_id: str, ws) -> None:
    session = _TERMINALS.get(terminal_id)
    if session is not None and session._viewer is ws:
        session._viewer = None
        logger.debug("terminal detached id=%s", terminal_id)


def close_terminal(terminal_id: str) -> bool:
    session = _TERMINALS.pop(terminal_id, None)
    if session is None:
        return False
    session.kill()
    logger.debug("terminal closed id=%s", terminal_id)
    return True


def shutdown_all() -> None:
    """Whole-server-shutdown backstop (main.py's _lifespan) -- kills every still-running terminal
    child process so a server restart never leaves an orphaned shell behind, the same "background
    processes are something I own until stopped" discipline this project already applies to
    browser_manager/memscan_manager's own shutdown hooks."""
    if not _TERMINALS:
        return
    for session in list(_TERMINALS.values()):
        session.kill()
    _TERMINALS.clear()
    logger.debug("terminal_manager: shutdown_all killed all remaining sessions")
