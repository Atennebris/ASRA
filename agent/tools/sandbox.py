"""Cross-platform process isolation for custom_exploit_run/exploit_db_run's own unvetted scripts --
model-written code, or a fetched public PoC never reviewed by this project -- previously with zero
isolation at all ("no sandboxing here or anywhere else in this project," the real gap this file
closes).

Scope is deliberately filesystem/process isolation only ("Tier 1"), not network egress restriction
(considered and explicitly rejected -- the script still has to reach the real pentest target, and
real IP-level network allowlisting was judged not worth the added complexity/risk for this
project). What IS closed: a buggy or runaway script can no longer touch host files outside its own
scratch directory, interfere with unrelated processes, survive past its own timeout as an orphaned
process tree, or (on Linux, via a private Xvfb display -- see _run_sandboxed_linux's/
start_offscreen_display's own comments) pop a real, visible window on the operator's own desktop
through WSLg's automatic GUI forwarding -- any GUI-capable program the script spawns (wine being the
confirmed, recurring case) runs against a private, offscreen X server instead.

Real, confirmed runtime reality (not assumption -- see this project's own run.bat, `git show
HEAD:run.bat`): on Windows, the agent process itself always runs INSIDE WSL2 (run.bat is a thin
bridge that shells out via `wsl.exe`; the real main.py process is a Linux Python the whole time),
so `sys.platform` inside the running agent is "linux" on Windows too, never "win32" -- there is no
Windows-specific branch here, bubblewrap covers Windows-via-WSL2 the same as native Linux. macOS
(a real, separate native launch path via run.sh, no WSL involved at all there) gets its own
Seatbelt (`sandbox-exec`) branch.
"""
from __future__ import annotations

import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")


def _sensitive_paths() -> tuple[str, ...]:
    """Re-masked (unreadable) even though the Linux sandbox's own broad `--ro-bind / /` would
    otherwise make them readable inside the sandbox -- a model-written exploit script has no
    legitimate reason to ever read this project's own stored credentials, exploitation allowlist,
    or .env, and a compromised/buggy script reading them would be a real information leak even
    though it can't (in this Tier-1 scope) write anywhere outside its own scratch directory.
    Live-confirmed exact failure mode can vary by filesystem: a directory masked via --tmpfs reads
    back as a genuinely empty listing on every filesystem tested; a single file masked via
    --ro-bind /dev/null reads as empty on a native Linux filesystem but raised PermissionError
    instead on a WSL2 Windows-drive (drvfs) mount in real testing -- either way the real content is
    never exposed, just via a different real error than "successfully read zero bytes".

    Real, confirmed bug this fixes: this used to be a module-level tuple of bare repo-relative
    strings ("data/credentials", "data/allowed_targets.json") -- but neither of those actually
    lives in the repo's own data/ folder; both are written under resolve_global_app_dir()
    (Documents/ASRA/data/... by default, or APP_DATA_DIR), same as
    agent/tools/native.py's _CREDENTIALS_DIR and agent/tools/allowed_targets.py's
    ALLOWED_TARGETS_PATH already resolve them. The repo-relative path is always empty (just an
    empty .gitkeep'd placeholder directory), so path.exists() below was masking a decoy every
    time -- the REAL credentials and REAL exploitation allowlist, sitting under Documents/ASRA,
    were never actually covered by either the Linux bubblewrap or macOS Seatbelt branch, defeating
    exactly the information-leak this function's own docstring describes. Only .env is genuinely
    repo-relative (loaded from the project root, same place `cp .env.example .env` puts it) and
    stays a bare string; the other two now resolve through the same function every other real
    consumer of these paths already uses, computed fresh (not cached at import time) so an
    APP_DATA_DIR set after this module first loads is still honored.
    """
    app_dir = resolve_global_app_dir()
    return (str(app_dir / "data" / "credentials"), str(app_dir / "data" / "allowed_targets.json"), ".env")


def _bwrap_command(command: list[str], scratch_dir: Path) -> list[str]:
    scratch = str(scratch_dir.resolve())
    argv = [
        "bwrap",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        # `--ro-bind / /` makes /run/user/<uid> visible (read-only) whenever it's a real directory
        # on the HOST -- confirmed live on this exact WSL2 machine (a normal logged-in user session
        # already has one, `/run/user/1000` populated with a real D-Bus socket etc.). A program that
        # needs a real per-user runtime directory (XDG basedir convention -- confirmed live this
        # actually matters for `wine`, added for RE mode's dynamic-analysis path) checks whether
        # /run/user/<uid> EXISTS first and prefers it over any custom XDG_RUNTIME_DIR override once
        # it does, so the read-only host copy wins and every write fails ("Read-only file system")
        # regardless of what XDG_RUNTIME_DIR is set to. Masking the WHOLE /run tree with one broad
        # `--tmpfs /run` looked like the obvious fix but isn't safe -- confirmed live it makes wine
        # itself crash (`free(): invalid pointer`, SIGABRT), presumably from some other /run path
        # (D-Bus, systemd) it also expects to still be there. Masking ONLY the one specific
        # `/run/user/<uid>` subpath with a fresh, real, writable tmpfs is what actually works: wine
        # ran the real target end-to-end against this exact mount in live testing, and every other
        # real path under /run stays intact (read-only, same as before) for whatever else needs it.
        "--tmpfs", f"/run/user/{os.getuid()}",
        "--bind", scratch, scratch,
        "--unshare-user", "--unshare-pid",
        "--die-with-parent", "--new-session",
    ]
    for rel in _sensitive_paths():
        path = Path(rel)
        if not path.exists():
            continue
        resolved = str(path.resolve())
        if path.is_dir():
            argv += ["--tmpfs", resolved]
        else:
            # Binding /dev/null over a single file is the standard bwrap trick for masking one
            # file read-only-empty -- --tmpfs only works on directories.
            argv += ["--ro-bind", os.devnull, resolved]
    argv += command
    return argv


def _run_sandboxed_linux(command: list[str], scratch_dir: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    # --unshare-pid makes bwrap PID 1 inside its own PID namespace -- when subprocess.run's own
    # timeout SIGKILLs that one process, the kernel itself tears down every other process still in
    # that namespace (standard Linux PID-namespace behavior, nothing bwrap has to implement), so
    # the whole tree dies, not just the direct child. No cgroups here -- bwrap itself doesn't cap
    # memory/CPU; a real gap, not silently pretended away.
    #
    # `--ro-bind / /` makes EVERY path read-only inside the sandbox except scratch_dir and the
    # freshly-tmpfs'd /run/user/<uid> above -- including /tmp, which a plain subprocess.run outside
    # a sandbox would always find writable. Confirmed live: a model-written script's own
    # `open('/tmp/...')` raised "Read-only file system" before this. Every well-behaved Linux
    # program already respects TMPDIR for exactly this "give me a real scratch directory" purpose,
    # so pointing it at the one directory the sandbox grants write access to fixes the whole class
    # at once. XDG_RUNTIME_DIR is pointed at the tmpfs `_bwrap_command` mounted above (the real,
    # canonical path a program expects, not a substitute elsewhere) -- WINEPREFIX needs its own
    # separate writable directory too, confirmed live: wine's prefix (its per-target "fake Windows
    # install", defaults to $HOME/.wine) is a distinct need from the runtime socket, and $HOME
    # inside the sandbox has no `.wine` of its own to fall back to.
    scratch_path = str(scratch_dir.resolve())
    env = {
        **os.environ,
        "TMPDIR": scratch_path,
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
        "WINEPREFIX": f"{scratch_path}/.wine",
    }
    # Real, confirmed incident (WSLg -- this project's own actual Windows-hosted runtime): the host
    # process's own DISPLAY/WAYLAND_DISPLAY point at the REAL Windows-forwarded compositor, not a
    # headless surface. custom_re_script's own docstring/setup_tools.sh's install_wine both already
    # claimed a "headless use case" for driving a Windows PE target through wine -- that claim was
    # never actually true: any GUI-capable program the script spawns (wine being the confirmed,
    # recurring case -- an RE session can invoke custom_re_script hundreds of times) popped a REAL,
    # VISIBLE window on the operator's own Windows desktop every single time. Stripped here, and a
    # private Xvfb display started below so anything the script launches gets its own offscreen X
    # server instead -- confirmed live end-to-end: wine's own X11 disconnect message on exit ("X
    # connection to :NN broken") named the private Xvfb display, never the real one.
    #
    # Deliberately NOT the `xvfb-run` wrapper script (the obvious first choice) -- real, confirmed
    # incident: xvfb-run's own script runs the wrapped command as `"$@" 2>&1`, unconditionally
    # merging its stderr into stdout before this function ever sees either stream. That silently
    # broke custom_exploit_run's/exploit_db_run's own stderr-capturing error path (a real regression
    # caught by this project's own full pytest suite, not found by manual testing) -- managing Xvfb
    # directly here keeps subprocess.run's normal capture_output=True stdout/stderr separation intact.
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    xvfb_process, display = start_offscreen_display()
    if display is not None:
        env["DISPLAY"] = display
    else:
        logger.debug("run_sandboxed: Xvfb not installed/failed to start -- a GUI-capable program the script spawns (e.g. wine) may show a real window on the host desktop")
    try:
        return subprocess.run(
            _bwrap_command(command, scratch_dir), cwd=scratch_dir, capture_output=True, text=True,
            timeout=timeout_seconds, stdin=subprocess.DEVNULL, env=env,
        )
    finally:
        if xvfb_process is not None:
            xvfb_process.terminate()
            try:
                xvfb_process.wait(timeout=3)
            except Exception:
                xvfb_process.kill()


_XVFB_SCREEN_ARGS = ["-screen", "0", "1280x1024x24", "-nolisten", "tcp"]
_XVFB_READY_TIMEOUT_SECONDS = 3.0
_XVFB_READY_POLL_INTERVAL_SECONDS = 0.05
_XVFB_DISPLAY_NUM_RANGE = (100, 9999)
_XVFB_START_ATTEMPTS = 5


def start_offscreen_display() -> tuple[subprocess.Popen | None, str | None]:
    """Starts a private Xvfb virtual X server on a free display number and waits for it to actually
    be ready (the real X11 lock file, /tmp/.X<N>-lock, existing -- the same real-world signal
    xvfb-run's own script relies on internally, just polled here directly instead of trusting that
    script's own stdout/stderr handling). Returns (None, None) if Xvfb isn't installed, or if it
    genuinely couldn't start after a few attempts (a random display number colliding with another
    concurrent sandboxed run is retried; a real Xvfb failure is not).

    A random display number, not a fixed one -- two custom_exploit_run/custom_re_script calls can
    run concurrently (this project has no global lock serializing them), so a fixed number would let
    one steal/corrupt the other's virtual display.
    """
    xvfb_bin = shutil.which("Xvfb")
    if xvfb_bin is None:
        return None, None
    for _ in range(_XVFB_START_ATTEMPTS):
        display_num = random.randint(*_XVFB_DISPLAY_NUM_RANGE)
        lock_path = Path(f"/tmp/.X{display_num}-lock")
        if lock_path.exists():
            continue
        try:
            process = subprocess.Popen(
                [xvfb_bin, f":{display_num}", *_XVFB_SCREEN_ARGS],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
            )
        except OSError as exc:
            logger.debug("run_sandboxed: failed to spawn Xvfb (%s)", exc)
            return None, None
        deadline = time.monotonic() + _XVFB_READY_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break  # exited already -- this display number lost a race, try a different one
            if lock_path.exists():
                return process, f":{display_num}"
            time.sleep(_XVFB_READY_POLL_INTERVAL_SECONDS)
        # Never became ready (or exited) within the deadline -- clean up and try again.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except Exception:
                process.kill()
    logger.debug("run_sandboxed: Xvfb did not become ready after %d attempt(s)", _XVFB_START_ATTEMPTS)
    return None, None


def _macos_sandbox_profile(scratch_dir: Path) -> str:
    """Seatbelt Sandbox Profile Language (SBPL) -- the same real mechanism Codex CLI's own macOS
    sandboxing uses (sandbox-exec, confirmed via their own docs). Same shape as the Linux bwrap
    profile so all three platforms share one mental model: broad read access, one writable scratch
    directory, sensitive project paths explicitly denied even though the broad read rule would
    otherwise cover them, network left open (Tier-1 scope, same as the Linux branch).

    Honesty note, not silently glossed over: written from well-established public SBPL patterns,
    but neither this session nor its author has real macOS hardware to confirm the exact syntax
    launches cleanly, unlike the Linux branch (live-tested this session, confirmed actually
    blocking writes and masking sensitive paths for real). A real Mac run is the only way to fully
    confirm this profile is correct.
    """
    scratch = str(scratch_dir.resolve())
    sensitive_subpaths = [Path(p).resolve() for p in _sensitive_paths() if Path(p).exists()]
    deny_sensitive = ""
    if sensitive_subpaths:
        clauses = " ".join(f'(subpath "{p}")' for p in sensitive_subpaths)
        deny_sensitive = f"(deny file-read* {clauses})\n"
    return (
        "(version 1)\n"
        "(deny default)\n"
        "(allow process-fork)\n"
        "(allow process-exec*)\n"
        "(allow file-read*)\n"
        f"{deny_sensitive}"
        f'(allow file-write* (subpath "{scratch}"))\n'
        # Tier-1 scope, same as the Linux branch -- the script still has to reach the real target;
        # real IP-level egress restriction was considered and explicitly rejected as not worth the
        # added complexity/risk for this project.
        "(allow network*)\n"
        "(allow sysctl-read)\n"
        "(allow mach-lookup)\n"
        "(allow iokit-open)\n"
    )


def _run_sandboxed_macos(command: list[str], scratch_dir: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    # sandbox-exec is a stock macOS system binary (/usr/bin/sandbox-exec), always present -- no
    # availability_check/install step needed, unlike bubblewrap on Linux. "-p <profile>" (inline
    # SBPL text) rather than "-f <file>", so there's no separate profile-tempfile to clean up.
    profile = _macos_sandbox_profile(scratch_dir)
    return subprocess.run(
        ["sandbox-exec", "-p", profile, *command], cwd=scratch_dir, capture_output=True, text=True,
        timeout=timeout_seconds, stdin=subprocess.DEVNULL,
    )


def run_sandboxed(command: list[str], scratch_dir: Path, timeout_seconds: int) -> subprocess.CompletedProcess:
    """Runs command with cwd=scratch_dir under whatever platform-appropriate isolation is actually
    available, raising subprocess.TimeoutExpired on timeout the same way plain subprocess.run
    always has -- callers keep the exact same except/timeout handling regardless of which branch
    actually ran. Falls back to a plain, unsandboxed subprocess.run (today's pre-existing behavior)
    when bubblewrap isn't installed on Linux, or on any platform neither branch below covers --
    logged explicitly so "no sandboxing happened this run" is a real, visible fact, not a silent
    downgrade.
    """
    if sys.platform == "darwin":
        return _run_sandboxed_macos(command, scratch_dir, timeout_seconds)
    if sys.platform.startswith("linux"):
        if shutil.which("bwrap"):
            return _run_sandboxed_linux(command, scratch_dir, timeout_seconds)
        logger.debug("run_sandboxed: bubblewrap not installed, running unsandboxed")
    else:
        logger.debug("run_sandboxed: no sandbox implementation for platform=%r, running unsandboxed", sys.platform)
    return subprocess.run(
        command, cwd=scratch_dir, capture_output=True, text=True, timeout=timeout_seconds, stdin=subprocess.DEVNULL,
    )
