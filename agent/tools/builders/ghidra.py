"""Native (tier-1) runner for Ghidra's headless decompiler (analyzeHeadless) -- static analysis/
decompilation of a local binary (ELF/PE/Mach-O), complementing radare2's own r2ghidra-based
decompile_function with Ghidra's own, generally higher-quality decompiler for complex binaries.

Why tier-1 (native_function), not tier-2 (build_command/parse_output) like radare2.py/gdb.py:
the real result doesn't come back as plain subprocess stdout the generic tier-2 pipeline expects
(agent/core.py's _OUTPUT_PARSERS, `Callable[[str], object]`) -- it comes over a Unix domain socket
(see below), and whether to start a fresh server process or reuse an already-running one depends on
real filesystem/process state decided before any command can even be built -- more than a pure
function of params alone, which is all build_command() ever sees. Same reasoning
agent/tools/custom_tool_runtime.py's run_registered_custom_tool is tier-1 for.

Plain subprocess.Popen, not run_sandboxed (agent/tools/sandbox.py) -- that sandbox exists
specifically for UNVETTED code (a model-written custom_exploit_run/custom_re_script script, or an
operator-supplied custom-tool binary this project never reviewed). The analyzeHeadless invocation
built here is a fixed, ASRA-authored command running ASRA's own reviewed postScript -- the same
trust tier as radare2/gdb's own tier-2 dispatch, which also runs unsandboxed.

Persistent server process, not a fresh `analyzeHeadless` subprocess per call: real, confirmed cost
class (JVM + Ghidra's own plugin framework startup, paid again on EVERY call even with
`-process -noanalysis` already skipping the heavier full-analysis step) made this worth closing --
ported after comparing against `morluto/rea`'s own equivalent bridge once its source became
available for this project to actually read, not invented from nothing. One persistent
`analyzeHeadless` process per (file_path, mtime) project (see _project_dir_for) runs the bundled
`agent/tools/ghidra_scripts/AsraExtract.java` in its own `--server <socket> <idle_timeout>` mode
(read that file's own header comment for the full wire protocol) -- Ghidra's own headless framework
keeps the whole process (JVM, loaded Program, analysis database) resident for as long as that
script's own run() method hasn't returned, which it deliberately never does except on an explicit
shutdown request or its own idle timeout. The FIRST call for a given binary starts that server with
`-import <file>` (a real, full auto-analysis, paid once); every later call against the SAME
unchanged binary reuses the already-running server (or starts a fresh one with
`-process <name> -noanalysis` if the earlier one already exited) -- confirmed live (2026-11-09):
`-process` alone still re-runs full analysis by default, `-noanalysis` is what actually skips it,
with no loss of decompiler accuracy (the program was already analyzed once, at import time).
Modifying the binary (a different mtime) gets a fresh project directory, and therefore a fresh
server, automatically.

Socket file permissions are 0600 (owner-only) -- this project's own single-operator trust model
doesn't need a multi-client auth/identity layer the way exposing this mechanism to a different,
less-trusted client eventually would (see AsraExtract.java's own header comment for the explicit
note to revisit this before that day, e.g. a future MCP-server/CLI surface). A stale socket left
over from a process that's no longer actually alive is distinguished from a genuinely-reusable one
via a real liveness probe (mode="ping") before ANY call trusts it, not by just checking the file's
own existence -- an existing-but-dead socket file is common (a killed/crashed server, a stale
leftover across an ASRA restart) and must not be silently treated as "already running."

The socket file itself lives under a NATIVE-filesystem path (Path.home()/.cache/asra/ghidra_sockets,
see _native_scratch_dir_for), deliberately NOT inside the Ghidra project directory
(resolve_global_app_dir(), which resolves to the Windows-side Documents folder under WSL2's own
drvfs mount). Real, confirmed-live failure this avoids: `ServerSocketChannel.bind()` on a Unix
domain socket path under /mnt/c/... raises `SocketException: Operation not supported` -- drvfs
(the 9P-based filesystem WSL2 uses to reach a Windows drive) does not support Unix domain socket
files at all, only a native Linux filesystem does. Same root cause class setup_tools.sh's own
install_radare2 already documents for a DIFFERENT reason (a drvfs build failing with a raw
"OSError: [Errno 22] Invalid argument" under concurrent file I/O) and already works around the
same way: stage the thing that genuinely needs a native filesystem under $HOME, which is always
native under WSL2's own default layout. Bare $HOME-relative is normally avoided in this project
($HOME differs between root/non-root launches) --
the deliberate exception here is the same one that section's own install_radare2 precedent already
carves out: this is ephemeral, PROCESS-lifetime-scoped state (a currently-running server's own
socket), never meant to be found again by a future call running under a DIFFERENT $HOME (a
root-mode and non-root-mode launch are different OS users entirely under WSL2, so a socket one of
them created was never going to be reusable by the other regardless of where it lived) -- not
durable data a later differently-launched call needs to locate, the actual failure class that rule
exists to prevent.

Known, honestly-documented limitation: a server that dies mid-request (killed, OOM) leaves its
client-side caller with a clear, real socket error (surfaced as status="error"), not a silent hang
-- the NEXT call against the same project detects the dead socket via the same liveness probe and
starts a fresh server automatically. A server killed while holding Ghidra's own project lock can
still leave that lock behind (Ghidra's own locking mechanism, not something this module manages) --
deleting that one project's own cache directory (logged on every call, see _project_dir_for)
self-heals it on the next call via a fresh -import, same as before this rework.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import socket as socket_module
import subprocess
import time
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.custom_tools_root import resolve_via_custom_root
from agent.tools.re_evidence import evidence_result
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "ghidra_scripts"
_POSTSCRIPT_NAME = "AsraExtract.java"
_PROJECT_NAME = "asra"

_VALID_MODES = {
    "info", "functions", "decompile_function", "disassemble_function", "xrefs_to", "cfg", "pcode_def_use",
    "value_flow", "inspect_native_data_type", "set_address_name", "annotate_native_function", "fix_no_return_flags",
    "fix_mips_soft_float",
}
_MODES_REQUIRING_TARGET = {
    "decompile_function", "disassemble_function", "xrefs_to", "cfg", "pcode_def_use",
    "value_flow", "inspect_native_data_type", "set_address_name", "annotate_native_function",
}
# The two write-capability modes additionally require a `value` payload (the new name / comment
# text to write) -- fix_no_return_flags/fix_mips_soft_float mutate the database too, but take no
# caller-supplied value at all (fix_no_return_flags has its own fixed KNOWN_RETURNING_IMPORTS
# allowlist plus a genuine RETURN-opcode scan; fix_mips_soft_float derives everything from the
# program's own default calling convention -- see "dry_run" below for its own write-gating param),
# so neither is a "write mode" in this param-validation sense.
_MODES_REQUIRING_VALUE = {"set_address_name", "annotate_native_function"}

# How long to wait for the SERVER to become ready (covers a first-time `-import`'s full auto-
# analysis, the same real cost class radare2.py's own `aaa` already documents at ~2m30s on a large
# obfuscated binary) -- NOT the per-request budget once the server is already confirmed alive, see
# _SOCKET_REQUEST_TIMEOUT_SECONDS below for that.
_SERVER_START_TIMEOUT_SECONDS = int(os.getenv("GHIDRA_ANALYSIS_TIMEOUT_SECONDS", "600"))
# How long ONE already-connected request/response round trip may take -- short relative to the
# server-start budget above since the expensive part (full analysis) is already done by the time
# a request is actually sent; still generous enough for a slow decompile_function/pcode_def_use on
# a large function rather than the generic tier-2 default.
_SOCKET_REQUEST_TIMEOUT_SECONDS = int(os.getenv("GHIDRA_SOCKET_REQUEST_TIMEOUT_SECONDS", "120"))
# How long the Java server itself waits with no new connection before self-terminating -- passed
# straight through as a script arg (AsraExtract.java's own --server mode reads it). Real, deliberate
# safety net: an ASRA process that crashes/gets killed must not leave an orphaned Ghidra JVM running
# forever; this bounds that regardless of what the Python side does or fails to do on exit.
_SERVER_IDLE_TIMEOUT_SECONDS = int(os.getenv("GHIDRA_SERVER_IDLE_TIMEOUT_SECONDS", "900"))
# A quick, short-timeout probe (mode="ping") before trusting any socket file's own existence as
# proof a server is actually alive and responsive -- a stale socket left over from a killed/crashed
# server, or across an ASRA restart, is a real, common case, not a hypothetical one.
_PING_TIMEOUT_SECONDS = 3


def _resolve_analyzeheadless() -> str | None:
    # Same {TOOL}_PATH-then-PATH-then-custom-root convention as agent/tools/runner.py's own
    # _resolve_executable, kept independent of that tier-2-only helper (same reasoning
    # agent/tools/amass_runner.py's own _resolve_amass_path already gives -- this tool dispatches
    # its own subprocess directly rather than going through run_tool()). Unlike amass_runner.py's
    # version, this DOES include the custom-root fallback (resolve_via_custom_root) -- a real,
    # confirmed need: an operator's own pre-existing Ghidra install is routinely nested several
    # directories deep under a custom root (<root>/ghidra_<version>/support/analyzeHeadless),
    # exactly the layout that recursive search exists to find.
    override = os.getenv("ANALYZEHEADLESS_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    found_on_path = shutil.which("analyzeHeadless")
    if found_on_path:
        return found_on_path
    return resolve_via_custom_root("analyzeHeadless")


def ghidra_available() -> bool:
    """ToolSpec.availability_check -- same reasoning as amass_enum's own amass_available: a tier-1
    native tool whose real dependency is an external binary the Python code doesn't itself carry
    must not report "always installed" the way an ordinary tier-1 tool would."""
    return _resolve_analyzeheadless() is not None


def _project_key_for(file_path: str) -> str:
    """One deterministic key per (file_path, mtime) -- same mtime-busting identity
    radare2_result_cache_key already uses, so an edited binary gets a fresh project (and therefore
    a fresh server) automatically instead of silently reusing a stale analysis."""
    try:
        mtime = os.path.getmtime(file_path)
    except OSError:
        mtime = 0.0
    return hashlib.sha1(f"{file_path}:{mtime}".encode()).hexdigest()[:20]


def _project_dir_for(key: str) -> Path:
    """The Ghidra project's own directory -- plain file I/O only, never a socket, so the Windows-
    side Documents folder (resolve_global_app_dir(), under WSL2's own drvfs mount) is fine here;
    see this module's own docstring for why the SOCKET specifically cannot live here. Never
    $HOME-relative/repo-relative ($HOME differs
    between root/non-root launches)."""
    project_dir = resolve_global_app_dir() / "data" / "ghidra_projects" / key
    project_dir.mkdir(parents=True, exist_ok=True)
    return project_dir


def _native_scratch_dir_for(key: str) -> Path:
    """Native-filesystem-only scratch space for the socket + its starting-lock -- see this
    module's own docstring for the real, confirmed-live reason a Unix domain socket cannot live
    under resolve_global_app_dir()'s own Documents-folder (drvfs) path."""
    native_dir = Path.home() / ".cache" / "asra" / "ghidra_sockets" / key
    native_dir.mkdir(parents=True, exist_ok=True)
    return native_dir


def _socket_path_for(native_dir: Path) -> Path:
    return native_dir / "asra.sock"


def _read_line(sock: socket_module.socket) -> str:
    """Reads bytes until a newline (the server's own one-response-per-line protocol,
    AsraExtract.java's own writeLine) or the connection closes -- a bounded accumulation, not an
    unbounded read, since a single JSON response line is never large enough to need streaming."""
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf.decode("utf-8", errors="replace")


def _ping_server(socket_path: Path) -> bool:
    """A real liveness probe, not just `socket_path.exists()` -- a socket FILE can outlive the
    process that created it (killed/crashed server, a stale leftover across an ASRA restart), and
    treating a dead socket's own file as proof of a live server would make every call against it
    hang/fail instead of self-healing."""
    if not socket_path.exists():
        return False
    try:
        with socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM) as sock:
            sock.settimeout(_PING_TIMEOUT_SECONDS)
            sock.connect(str(socket_path))
            sock.sendall(b'{"mode":"ping"}\n')
            response = json.loads(_read_line(sock))
            return response.get("status") == "ok"
    except (OSError, ValueError, json.JSONDecodeError):
        return False


def _start_server(executable: str, project_dir: Path, gpr_exists: bool, program_name: str, file_path: str, socket_path: Path) -> None:
    action_args = ["-process", program_name, "-noanalysis"] if gpr_exists else ["-import", file_path]
    command = [
        executable, str(project_dir), _PROJECT_NAME,
        *action_args,
        "-scriptPath", str(_SCRIPTS_DIR),
        "-postScript", _POSTSCRIPT_NAME, "--server", str(socket_path), str(_SERVER_IDLE_TIMEOUT_SECONDS),
    ]
    logger.debug(
        "ghidra: starting server project_dir=%s reused_project=%s command=%s",
        project_dir, gpr_exists, command,
    )
    # A real detached background process -- deliberately outlives this one Python call, serving
    # every future call against the same project until its own idle timeout or a shutdown request.
    # start_new_session=True keeps it from being killed by a signal sent to ASRA's own process
    # group (e.g. Ctrl-C in the terminal ASRA itself runs in).
    proc = subprocess.Popen(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        start_new_session=True,
    )

    deadline = time.monotonic() + _SERVER_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if _ping_server(socket_path):
            return
        if proc.poll() is not None:
            raise RuntimeError(f"the Ghidra server process exited early (exit code {proc.returncode}) before becoming ready")
        time.sleep(0.5)
    raise TimeoutError(f"the Ghidra server did not become ready within {_SERVER_START_TIMEOUT_SECONDS}s")


def _ensure_server_running(executable: str, project_dir: Path, native_dir: Path, gpr_path: Path, program_name: str, file_path: str) -> Path:
    socket_path = _socket_path_for(native_dir)
    if _ping_server(socket_path):
        return socket_path

    # A real, confirmed-possible race: two calls against the SAME brand-new binary arriving close
    # together (e.g. the main agent and a subagent both reaching for it) could otherwise both see
    # "no server yet" and both try to -import the same project simultaneously -- Ghidra's own
    # project locking would make the second one fail outright rather than cleanly queueing. A
    # dedicated lock file (not the project itself) serializes just the "check, then maybe start"
    # decision: whoever gets the lock first actually starts the server; everyone else blocks here,
    # then re-checks (inside the lock) and finds it already running, same as the fast path above.
    # Lives in the same native scratch dir as the socket, not the (possibly drvfs) project dir --
    # no reason to risk a second drvfs quirk on flock() when a native path is already right there.
    lock_path = native_dir / "starting.lock"
    lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if _ping_server(socket_path):
            return socket_path
        socket_path.unlink(missing_ok=True)  # a dead/stale socket file -- confirmed not alive above
        try:
            _start_server(executable, project_dir, gpr_path.exists(), program_name, file_path, socket_path)
        except RuntimeError:
            # Confirmed live (2026-11-09): a server killed abruptly (SIGKILL) while it had the
            # project open can leave Ghidra's own project file registry corrupted -- the next
            # `-process` attempt against that same project fails fast with a real Ghidra error
            # ("Requested project program file(s) not found: <name>"), distinct from a normal
            # startup failure. This was an accepted, honestly-documented limitation for the old
            # one-shot design ("not handled automatically... rare enough"); it stops being rare
            # once a server can be killed at ANY point while actively serving, not just during one
            # brief one-shot call, so it gets real self-healing now: one retry, with the whole
            # project directory wiped and rebuilt via a fresh -import, never looped further (a
            # SECOND failure in a row is a real, different problem worth surfacing, not retrying
            # blindly). Only worth attempting when `-process` (an existing project) was the one
            # that just failed -- a fresh `-import` failing has no stale project to blame.
            if not gpr_path.exists():
                raise
            logger.debug("ghidra: -process failed against project_dir=%s, retrying once with a fresh -import", project_dir)
            shutil.rmtree(project_dir, ignore_errors=True)
            project_dir.mkdir(parents=True, exist_ok=True)
            _start_server(executable, project_dir, False, program_name, file_path, socket_path)
        return socket_path
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _send_request(socket_path: Path, request: dict) -> dict:
    with socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM) as sock:
        sock.settimeout(_SOCKET_REQUEST_TIMEOUT_SECONDS)
        sock.connect(str(socket_path))
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        response = _read_line(sock)
    return json.loads(response)


def run_ghidra(params: dict) -> dict:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    path_obj = Path(file_path)
    if path_obj.is_dir():
        raise ValueError(f"file_path is a directory, not a binary: {file_path!r}")
    if not path_obj.is_file():
        raise ValueError(f"file_path does not exist: {file_path!r}")

    mode = params.get("mode", "info")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown ghidra mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")

    target = str(params.get("target") or "").strip()
    if mode in _MODES_REQUIRING_TARGET and not target:
        raise ValueError(f"mode={mode!r} requires a 'target' parameter (a function name or address).")
    if target:
        target = validate_safe_value(target)

    value = str(params.get("value") or "").strip()
    if mode in _MODES_REQUIRING_VALUE and not value:
        raise ValueError(f"mode={mode!r} requires a 'value' parameter (the new name / comment text to write).")
    if value:
        value = validate_safe_value(value)

    # Only fix_mips_soft_float ever reads this (the server ignores it for every other mode) --
    # defaults to True deliberately: this mode's own XML/calling-convention surgery is the
    # riskiest write this server performs, so the model/operator must see the full candidate list
    # and explicitly repeat the call with dry_run=False before anything actually gets mutated.
    dry_run_param = params.get("dry_run")
    dry_run = True if dry_run_param is None else bool(dry_run_param)

    executable = _resolve_analyzeheadless()
    if executable is None:
        return {"status": "tool_unavailable", "tool": "ghidra"}

    key = _project_key_for(file_path)
    project_dir = _project_dir_for(key)
    native_dir = _native_scratch_dir_for(key)
    gpr_path = project_dir / f"{_PROJECT_NAME}.gpr"
    program_name = path_obj.name

    try:
        socket_path = _ensure_server_running(executable, project_dir, native_dir, gpr_path, program_name, file_path)
    except (RuntimeError, TimeoutError) as exc:
        logger.debug("ghidra: could not start/reach the server for project_dir=%s (%s)", project_dir, exc)
        return {"status": "error", "tool": "ghidra", "error": f"could not start the Ghidra server process: {exc}"}

    logger.debug("ghidra: dispatching mode=%s target=%r project_dir=%s socket=%s", mode, target, project_dir, socket_path)

    try:
        raw = _send_request(socket_path, {"mode": mode, "target": target, "value": value, "dry_run": dry_run})
    except socket_module.timeout:
        logger.debug("ghidra: request timed out after %ss mode=%s", _SOCKET_REQUEST_TIMEOUT_SECONDS, mode)
        return {"status": "timeout", "tool": "ghidra"}
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logger.debug("ghidra: could not communicate with the server (%s)", exc)
        return {"status": "error", "tool": "ghidra", "error": f"could not communicate with the Ghidra server: {exc}"}

    if "observed" not in raw:
        # The server's own malformed-request-shaped error (handleOneConnection's JSON-parse-failure
        # branch) -- never actually reached dispatchRequest(), so there's no observed/unknown pair.
        error = raw.get("error", "unknown server error")
        logger.debug("ghidra: server reported a request-level error: %s", error)
        return {"status": "error", "tool": "ghidra", "error": error}

    logger.debug("ghidra: finished mode=%s status=ok", mode)
    return {"status": "ok", "tool": "ghidra", **evidence_result(raw.get("observed", {}), unknown=raw.get("unknown", {}))}
