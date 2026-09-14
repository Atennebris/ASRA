"""wine_debug_run -- attempted real dynamic debugging of a Windows PE (.exe/.dll) target, via
wine's own `winedbg --gdb` proxy mode instead of gdb attaching directly.

STATUS: built but NOT registered as a live tool (agent/tools/__init__.py) -- see that file's own
comment at the wine_debug_run call site for the full status. Confirmed live, working: connect
(`target remote localhost:<port>`), read real state, detach -- a real gdb client stopped cleanly at
`DbgBreakPoint()` in ntdll.dll with correct Windows-DLL symbol resolution, proving winedbg's proxy
genuinely understands the wine-hosted PE process, unlike plain gdb attaching directly (which cannot
attach to or resolve a Windows PE under wine at all -- confirmed separately, see
agent/tools/builders/gdb.py's own module docstring). Confirmed live, BROKEN: `continue` (resuming
the debuggee past that initial stop) hangs indefinitely -- reproduced with a bare `continue` and NO
breakpoint at all, generous 90s budget, still hung. Tried granting wineserver64 cap_sys_ptrace
(setup_tools.sh's install_wine -- the same fix agent/tools/memscan_manager.py's own module docstring
documents for scanmem under this same WSL2 environment's Yama ptrace_scope=1) -- did not resolve it.
Root cause not found. Since a breakpoint the model actually cares about is somewhere in the PE's OWN
code (which isn't mapped/reachable until AFTER that initial ntdll stop is resumed), the tool cannot
currently do the one thing it exists for.

Why this exists, once continue is fixed: gdb is a native-Linux tracer and, confirmed live, genuinely
cannot attach to or resolve symbols in a Windows PE running under wine at all -- RE_TRIAGE_PROMPT/
RE_CHAT_PROMPT both warn the model away from even trying. winedbg's `--gdb` mode (`man winedbg`) is
built for exactly this gap: it launches the PE through wine's own loader and exposes a real GDB
remote-serial-protocol server a plain `gdb` client can connect to. Once `continue` genuinely works,
breakpoints/reads are meant to work exactly like agent/tools/builders/gdb.py's own batch-mode gdb --
this module already reuses that file's own break_at/stops/reads validation (validate_break_targets/
validate_stops/build_read_commands) so the two tools would present an identical, consistent shape.

Two cooperating subprocesses, not one batch command -- this is why it's shaped as a tier-1
native_function (were it registered) rather than a build_command()-based tier-2 tool the way gdb.py
is: (1) `winedbg --gdb --no-start --port <port> <exe> [args]` runs in the BACKGROUND as its own
long-lived process (it has to stay alive for step 2 to connect to), and (2) a real `gdb --batch`
client connects to it and does the actual debugging, its own output being what the model reads.
runner.py's own generic subprocess timeout (tier-2 tools only) doesn't apply here -- this module
enforces its OWN overall wall-clock budget (WINE_DEBUG_TIMEOUT_SECONDS) and unconditionally kills
the winedbg proxy in a `finally`, so a wine/wineserver process can never outlive this one call.
"""
from __future__ import annotations

import fcntl
import os
import socket
import subprocess
import time

from agent.tools.builders.gdb import build_read_commands, validate_break_targets, validate_stops
from agent.tools.builders.validators import validate_safe_value
from agent.tools.sandbox import start_offscreen_display
from agent.utils.debug import truncate_for_log
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_DEFAULT_TIMEOUT_SECONDS = 180
# How much of the overall budget is spent waiting for winedbg's own proxy server to come up
# (wineserver startup + PE load) before giving up -- wine's own first-run prefix initialization can
# genuinely take several real seconds, confirmed live; the remainder of the budget is left for the
# real gdb client round trip.
_PORT_WAIT_FRACTION = 0.4
_PORT_POLL_INTERVAL_SECONDS = 0.3


def _timeout_seconds() -> int:
    return int(os.getenv("WINE_DEBUG_TIMEOUT_SECONDS", str(_DEFAULT_TIMEOUT_SECONDS)))


def _free_tcp_port() -> int:
    """Binds an ephemeral port and immediately releases it so winedbg can bind the same number --
    a small, accepted TOCTOU race (another process could grab it in between) rather than a real
    problem: this project's own tools are single-operator/local, and a genuine collision just
    surfaces as a clear "port already in use" error from winedbg, not a silent wrong result."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _drain_nonblocking(proc: subprocess.Popen) -> str:
    """Reads whatever winedbg has already printed without blocking -- diagnostic text only (its
    "target remote localhost:<port>" hint is NOT used as the readiness signal, see _port_is_listening
    below for why), captured here purely so a genuine startup failure (a crash, a missing wine
    prefix) has real output attached to the error this function returns."""
    if proc.stdout is None:
        return ""
    fd = proc.stdout.fileno()
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    chunks = []
    try:
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        pass
    return b"".join(chunks).decode("utf-8", errors="replace")


def _port_is_listening(port: int) -> bool:
    """Checks readiness via `ss` (does something already have this port in LISTEN state), never by
    opening a real connection to it ourselves.

    Real, confirmed incident this fixes: an earlier version of this function polled readiness by
    opening a real socket.connect() to the port and immediately closing it -- winedbg's own gdb
    proxy accepts exactly ONE client connection ever ("winedbg will quit after the first connection
    is hung up", `man winedbg`), so that probe connection WAS the one real connection winedbg was
    waiting for; it hung up instantly, and the actual gdb client's later connection attempt then
    timed out against an already-finished proxy. `ss` reads kernel socket state directly and never
    touches the port itself, so it can't consume the one connection winedbg is waiting for.
    """
    try:
        result = subprocess.run(
            ["ss", "-tln", f"( sport = :{port} )"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
    # First line is always ss's own column header -- a real listening socket adds a second line.
    return result.stdout.count("\n") > 1


def _wait_until_ready(proc: subprocess.Popen, deadline: float, port: int) -> tuple[bool, str]:
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            # winedbg exited before its proxy ever started listening -- a real crash (a corrupt/
            # unsupported PE, a missing wine prefix), not a timing issue a longer wait would fix.
            return False, _drain_nonblocking(proc)
        if _port_is_listening(port):
            return True, ""
        time.sleep(_PORT_POLL_INTERVAL_SECONDS)
    return False, _drain_nonblocking(proc)


def wine_debug_run(params: dict) -> dict:
    file_path = validate_safe_value(str(params["file_path"]).strip())

    try:
        break_targets = validate_break_targets(params.get("break_at"))
        stops = validate_stops(params.get("stops"))
        read_commands = build_read_commands(params.get("reads"))
    except ValueError as exc:
        return {"status": "error", "tool": "wine_debug_run", "error": str(exc)}

    run_args_raw = params.get("run_args") or []
    if not isinstance(run_args_raw, list):
        return {"status": "error", "tool": "wine_debug_run", "error": "'run_args' must be a list of strings"}
    try:
        run_args = [validate_safe_value(str(arg)) for arg in run_args_raw]
    except ValueError as exc:
        return {"status": "error", "tool": "wine_debug_run", "error": str(exc)}

    total_budget = _timeout_seconds()
    started = time.monotonic()
    port = _free_tcp_port()

    winedbg_proc: subprocess.Popen | None = None
    xvfb_proc: subprocess.Popen | None = None
    try:
        # Real, confirmed incident this closes (agent/tools/sandbox.py's own run_sandboxed already
        # does the identical thing for custom_re_script's wine invocations, and documents the exact
        # same failure this fixes): the host process's own DISPLAY/WAYLAND_DISPLAY point at WSLg's
        # REAL Windows-forwarded compositor, not a headless surface -- any GUI-capable program a
        # wine-driven call spawns (winedbg's own crash/attach dialogs included) pops a real, visible
        # window on the operator's own Windows desktop otherwise. Stripped here and a private Xvfb
        # display started, same as run_sandboxed's own start_offscreen_display -- this module can't
        # reuse run_sandboxed() itself (that function wraps ONE subprocess.run call inside bubblewrap
        # for model-written-script isolation; this is a two-process orchestration with its own
        # timeout/lifecycle, a different shape), but the offscreen-display half is the exact same
        # need and reuses that exact helper rather than re-implementing it.
        env = dict(os.environ)
        env.pop("DISPLAY", None)
        env.pop("WAYLAND_DISPLAY", None)
        xvfb_proc, display = start_offscreen_display()
        if display is not None:
            env["DISPLAY"] = display
        else:
            logger.debug("run_tool: wine_debug_run Xvfb not installed/failed to start -- winedbg may show a real window on the host desktop")

        try:
            winedbg_proc = subprocess.Popen(
                ["winedbg", "--gdb", "--no-start", "--port", str(port), file_path, *run_args],
                # stdin=PIPE and deliberately never closed/written to -- NOT DEVNULL. Real, confirmed
                # incident: with stdin=DEVNULL, a target that reads from stdin (any interactive
                # prompt -- e.g. a crackme's own "enter operator ID") gets an instant EOF and can run
                # to completion/exit before winedbg's own proxy ever finishes starting, racing past
                # the breakpoint this call exists to hit. An open, never-EOF'd pipe leaves it blocked
                # on that first read exactly like it would be if the operator had launched it by hand.
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=False,
                env=env,
            )
        except FileNotFoundError:
            return {"status": "error", "tool": "wine_debug_run", "error": "wine is not installed -- run ./setup_tools.sh first"}

        port_deadline = started + total_budget * _PORT_WAIT_FRACTION
        ready, wine_output = _wait_until_ready(winedbg_proc, port_deadline, port)
        if not ready:
            logger.debug("run_tool: wine_debug_run winedbg proxy never announced readiness; output=%s", truncate_for_log(wine_output))
            return {
                "status": "error", "tool": "wine_debug_run",
                "error": "winedbg's own gdb-proxy server never announced readiness in time -- it may have crashed on this target; see wine_stderr",
                "wine_stderr": wine_output.strip(),
            }

        commands = [f"target remote localhost:{port}"]
        commands += [f"break {target}" for target in break_targets]
        per_stop = ["continue", "info registers", "backtrace", "x/10i $pc", *read_commands]
        for _ in range(stops):
            commands.extend(per_stop)
        commands += ["detach", "quit"]

        gdb_command = ["gdb", "--batch"]
        for cmd in commands:
            gdb_command += ["-ex", cmd]

        remaining = max(5, total_budget - (time.monotonic() - started))
        try:
            gdb_result = subprocess.run(
                gdb_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=remaining,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "tool": "wine_debug_run", "command": gdb_command}

        return {
            "status": "ok", "tool": "wine_debug_run",
            "exit_code": gdb_result.returncode,
            "raw_output": gdb_result.stdout.strip(),
            "command": gdb_command,
        }
    finally:
        # Never leave a wine/wineserver process running past this one call -- see this module's own
        # docstring for why runner.py's usual tier-2 subprocess timeout doesn't cover this path.
        if winedbg_proc is not None and winedbg_proc.poll() is None:
            winedbg_proc.terminate()
            try:
                winedbg_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                winedbg_proc.kill()
        if xvfb_proc is not None:
            xvfb_proc.terminate()
            try:
                xvfb_proc.wait(timeout=3)
            except Exception:
                xvfb_proc.kill()
