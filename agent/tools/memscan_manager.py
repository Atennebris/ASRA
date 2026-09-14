"""Stateful scanmem sessions backing the memscan_* tools (registered in agent/tools/__init__.py) --
the classic "Cheat Engine" workflow (attach to a running process, scan memory for a value, narrow
across repeated scans as the value visibly changes, list candidate addresses, patch one to confirm
it's the real address) applied here for RE research: proving how a live process actually stores a
value (anti-cheat/licensing research, confirming a decompiled guess against real runtime state), the
same technique used to build game trainers/cheats, studied from the defensive side.

A scanmem session must persist ACROSS separate LLM tool calls -- attach now, scan again later once
the operator reports the value changed, sometimes minutes apart -- the same reason
agent/tools/browser_manager.py needs a stateful manager instead of a plain one-shot subprocess
tool. Simpler than that module though: scanmem speaks a plain line-based stdin/stdout protocol, no
event loop involved, so this stays synchronous (module-level dict + threading.Lock, dispatched as an
ordinary tier-1 native_function via asyncio.to_thread, no agent/core.py _dispatch_tool special-casing
needed the way Playwright's event-loop-pinned API requires for the browser_* tools).

CRITICAL SAFETY PROPERTY, confirmed by actually running `help` inside a real scanmem session (not
assumed from documentation): scanmem's own REPL includes a `shell` command ("execute a shell command
without leaving scanmem") -- its command language is exactly as dangerous as GDB's/radare2's own
scripting languages, which agent/tools/builders/gdb.py's and radare2.py's own module docstrings
already warn about. Every value this module sends to a live scanmem process is therefore run through
_validate_numeric() first -- a strict, anchored regex accepting ONLY a plain decimal/hex/float
literal, control characters included in what it rejects -- never free text from the model, and
memscan_write only ever writes via `set <list-index>=<value>` (a match-id scanmem itself already
tracks internally from this session's own most recent memscan_list, never a raw address string the
model could type/guess), never the address-taking `write <type> <addr> <value>` form. This is the
single most important safety property of this whole module.

Confirmed live (WSL2, this project's actual runtime): a fresh Linux install's default Yama
ptrace_scope=1 blocks scanmem from attaching even to a same-uid process it didn't itself fork --
`error: failed to attach to <pid>, Operation not permitted`. Granting the scanmem BINARY
cap_sys_ptrace via setcap once at install time (setup_tools.sh's install_scanmem(), the standard
fix scanmem/GameConqueror's own docs recommend as the alternative to running everything as root)
resolves this without any runtime sudo escalation -- confirmed live end-to-end afterward: attach,
scan, narrow, list, and a real `write`/`set` landing in a live target process's actual memory,
observed via that process's own subsequent output.
"""
from __future__ import annotations

import os
import re
import subprocess
import threading
import time
import uuid
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_DEFAULT_IDLE_TIMEOUT_SECONDS = 600
_DEFAULT_MAX_CONCURRENT_SESSIONS = 2
_IDLE_REAPER_POLL_SECONDS = 30

# How long to let scanmem finish responding before reading back whatever it's produced so far --
# a plain command (option/list/set) settles fast; a real memory scan (a bare value, or an operator
# comparison) walks every mapped region of the target process, confirmed live to meaningfully
# outlast a plain command on anything but a tiny test binary.
_COMMAND_SETTLE_SECONDS = 1.5
_SCAN_SETTLE_SECONDS = 3.0

# radare2's own list-shaped tool outputs (xrefs_to/functions/strings) cap at 50 entries with an
# honest total-count note (agent/tools/__init__.py's parse_radare2_output) -- same precedent here,
# a real scan can return far more matches than are useful to hand an LLM in one turn.
_MAX_LIST_ENTRIES = 50

# Not underscore-prefixed -- agent/tools/__init__.py's own ToolSpec registration imports these
# directly for the memscan_attach/memscan_scan schemas' own enum lists, so the model-facing choices
# can never drift out of sync with what this module actually accepts.
#
# "string"/"bytearray" added after being confirmed live (a real scanmem 0.17 session, not assumed
# from docs) as genuine, working scanmem `option scan_data_type` values -- this module used to
# expose ONLY the six numeric types, arbitrarily narrower than scanmem's own real capability.
# Real, confirmed incident this fixes: NinthCircle-crackmes-usr_573a1e needed exactly this (finding
# a decrypted verdict string, e.g. "ACCESS GRANTED", in a live process's memory) and had no way to
# do it through this tool -- the model fell back to a hand-rolled /proc/pid/mem parser via
# custom_re_script instead, which failed twice on wrong offsets before working. See _STRING_TOKEN
# and _BYTEARRAY_PATTERN below for how each type's own value gets validated/formatted.
VALUE_TYPES = frozenset({"int8", "int16", "int32", "int64", "float32", "float64", "string", "bytearray"})
# Types with no real ordering -- "increased"/"decreased" (scanmem's own `+`/`-` tokens) are
# meaningless for these and rejected outright in scan() below, rather than silently sent to scanmem
# and left to fail in some scanmem-internal way that's harder for the model to diagnose.
_NON_ORDERED_VALUE_TYPES = frozenset({"string", "bytearray"})
SCAN_MODES = frozenset({"exact", "unknown", "increased", "decreased", "changed", "unchanged"})
# mode -> the literal scanmem token for a bare (no explicit value) comparison against the LAST
# scan/snapshot -- confirmed live via `help` inside a real scanmem session, not assumed from docs.
_SCAN_MODE_TOKENS = {"increased": "+", "decreased": "-", "changed": "!=", "unchanged": "="}

# Anchored, nothing-but-a-number -- see the module docstring's CRITICAL SAFETY PROPERTY above.
# Accepts standard C notation scanmem itself documents (leading 0x for hex, a plain decimal, or a
# float) -- never anything containing a space/semicolon/newline that could smuggle a second scanmem
# command (e.g. a bare "shell ...") into the same line.
_NUMERIC_PATTERN = re.compile(r"^-?(0x[0-9a-fA-F]+|\d+(\.\d+)?)$")

_LIST_LINE_PATTERN = re.compile(
    r"^\[\s*(?P<index>\d+)\]\s*(?P<address>[0-9a-fA-F]+),.*?,\s*(?P<region>\S+),\s*"
    r"(?P<value>[^,]+),\s*\[(?P<type>[^\]]+)\]\s*$"
)
_MATCH_COUNT_PATTERN = re.compile(r"we currently have (\d+) match")


def _idle_timeout_seconds() -> int:
    return int(os.getenv("MEMSCAN_SESSION_IDLE_TIMEOUT_SECONDS", str(_DEFAULT_IDLE_TIMEOUT_SECONDS)))


def _max_concurrent_sessions() -> int:
    return int(os.getenv("MEMSCAN_MAX_CONCURRENT_SESSIONS", str(_DEFAULT_MAX_CONCURRENT_SESSIONS)))


def _validate_numeric(value: object) -> str:
    text = str(value).strip()
    if not _NUMERIC_PATTERN.match(text):
        raise ValueError(f"value must be a plain decimal/hex/float number, got {value!r}")
    return text


# scanmem's own bytearray syntax, confirmed live: hex-pair tokens (or "??" as a per-byte wildcard)
# separated by single spaces, e.g. "FF ?? EE ?? 02 01" -- anchored so nothing else can ride along on
# the same line. A LITERAL space only, never Python's `\s` -- `\s` also matches `\n`/`\r`/`\t`, and
# this value reaches scanmem's own stdin as one line (session.send() appends exactly one trailing
# "\n"); an embedded newline that `\s` let through would land as a genuinely SEPARATE line there,
# able to smuggle a real second scanmem command (its own `shell` command included) in behind an
# innocent-looking byte pattern -- the exact same injection class already fixed once for
# agent/tools/builders/radare2.py's own `hex_patch_asm` instruction regex, caught here by the
# tests below before this ever shipped rather than after a live incident.
_BYTEARRAY_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}|\?\?)( ([0-9A-Fa-f]{2}|\?\?))*$")


def _validate_bytearray(value: object) -> str:
    text = str(value).strip()
    if not _BYTEARRAY_PATTERN.match(text):
        raise ValueError(
            f"value must be space-separated hex byte pairs (wildcards allowed as \"??\"), e.g. "
            f"\"FF ?? EE ?? 02 01\", got {value!r}"
        )
    return text


def _validate_string_value(value: object) -> str:
    """Same control/newline/null-byte barrier as agent/tools/builders/validators.py's own
    validate_safe_value, reused here rather than re-implemented -- see this module's own CRITICAL
    SAFETY PROPERTY docstring at the top: a value containing a newline would land as a genuinely
    SEPARATE line on scanmem's own stdin (this session's live protocol, one command per line), which
    could smuggle a real second scanmem command (its own `shell` command included) in behind an
    innocent-looking string search -- the exact same injection class agent/tools/builders/radare2.py's
    own module docstring documents a real, confirmed incident of, for a completely different tool.
    """
    text = str(value)
    if not text:
        raise ValueError("value must not be empty for a string scan")
    return validate_safe_value(text)


class _ScanSession:
    """One live `scanmem -p <pid>` process, stdin/stdout kept open across separate tool calls --
    the one deliberate exception to agent/tools/runner.py's usual stdin=DEVNULL convention (same
    precedent as that module's own `sudo -S` password-piping special case). A dedicated reader
    thread continuously drains stdout into an in-memory buffer so no output is ever dropped between
    tool calls waiting on a fixed sleep -- only ever read LATE (on the next call), never lost,
    unlike the select()-polling approach this module's own live protocol testing confirmed is
    genuinely racy against scanmem's real output timing.
    """

    def __init__(self, popen: subprocess.Popen, pid: int, scan_data_type: str) -> None:
        self.popen = popen
        self.pid = pid
        self.scan_data_type = scan_data_type
        self.last_activity = time.time()
        self.lock = threading.Lock()
        self._buffer: list[str] = []
        self._buffer_lock = threading.Lock()
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self) -> None:
        try:
            for line in self.popen.stdout:  # type: ignore[union-attr]
                with self._buffer_lock:
                    self._buffer.append(line)
        except Exception:
            pass  # process died / pipe closed -- nothing left to read, thread just exits

    def send(self, command: str) -> None:
        self.popen.stdin.write(command + "\n")  # type: ignore[union-attr]
        self.popen.stdin.flush()  # type: ignore[union-attr]

    def drain(self, settle_seconds: float) -> str:
        time.sleep(settle_seconds)
        with self._buffer_lock:
            lines, self._buffer = self._buffer, []
        return "".join(lines)

    def is_alive(self) -> bool:
        return self.popen.poll() is None


# session_id -> scan_id -> _ScanSession. In-memory only, like agent/tools/background_jobs.py's own
# _RUNNING_PROCESSES -- unlike that module's session["background_jobs"] JSON metadata, nothing here
# needs restart reconciliation (a scan session dying with the server is a correct outcome, not a
# leak: there is no multi-minute unattended job to lose track of, and detaching is always one
# memscan_detach call away).
_SESSIONS: dict[str, dict[str, _ScanSession]] = {}
_SESSIONS_LOCK = threading.Lock()

_reaper_thread: threading.Thread | None = None
_reaper_stop_event: threading.Event | None = None


def _ensure_reaper_started() -> None:
    global _reaper_thread, _reaper_stop_event
    if _reaper_thread is not None and _reaper_thread.is_alive():
        return
    _reaper_stop_event = threading.Event()
    _reaper_thread = threading.Thread(target=_reaper_loop, args=(_reaper_stop_event,), daemon=True)
    _reaper_thread.start()


def _reaper_loop(stop_event: threading.Event) -> None:
    """Crash/cancel safety net, not the primary cleanup path -- the primary path is an explicit
    memscan_detach call. Mirrors browser_manager.py's own _idle_reaper_loop exactly: this exists
    for the session that genuinely got forgotten (a long chat conversation moved on to something
    else and never detached), not for the normal case."""
    while not stop_event.wait(_IDLE_REAPER_POLL_SECONDS):
        for session in _sweep_idle_sessions():
            _terminate(session)


def _sweep_idle_sessions() -> list[_ScanSession]:
    """Pops every session idle for longer than MEMSCAN_SESSION_IDLE_TIMEOUT_SECONDS out of
    _SESSIONS and returns them for the caller to _terminate() -- split out from _reaper_loop so the
    actual staleness logic is directly unit-testable without spinning a real thread or waiting out
    real wall-clock time."""
    timeout = _idle_timeout_seconds()
    now = time.time()
    stale: list[_ScanSession] = []
    with _SESSIONS_LOCK:
        for session_id, sessions in list(_SESSIONS.items()):
            for scan_id, session in list(sessions.items()):
                if now - session.last_activity > timeout:
                    logger.debug("memscan_manager: session=%s scan_id=%s idle for >%ds -- closing", session_id, scan_id, timeout)
                    stale.append(sessions.pop(scan_id))
            if not sessions:
                _SESSIONS.pop(session_id, None)
    return stale


def _terminate(session: _ScanSession) -> None:
    try:
        session.send("exit")
        session.drain(0.3)
    except Exception:
        pass
    try:
        session.popen.terminate()
        session.popen.wait(timeout=3)
    except Exception:
        try:
            session.popen.kill()
        except Exception:
            pass


def _get_session(session_id: str, scan_id: str) -> _ScanSession | None:
    with _SESSIONS_LOCK:
        session = _SESSIONS.get(session_id, {}).get(scan_id)
    if session is not None and not session.is_alive():
        # scanmem exited on its own (crashed, or the target process it was watching exited) --
        # drop the stale entry instead of handing the caller a dead handle that will only ever
        # time out on send()/drain().
        with _SESSIONS_LOCK:
            _SESSIONS.get(session_id, {}).pop(scan_id, None)
        return None
    return session


def _capacity_error(session_id: str) -> dict | None:
    """Must be called with _SESSIONS_LOCK already held. Returns a model-facing {"status":
    "skipped", ...} dict if this project is already at MEMSCAN_MAX_CONCURRENT_SESSIONS, else None.
    Called twice by attach() below (an early check before the /proc existence check, then again
    right before actually spawning) -- see that function's own comments for why."""
    existing = _SESSIONS.setdefault(session_id, {})
    max_sessions = _max_concurrent_sessions()
    if len(existing) >= max_sessions:
        return {
            "status": "skipped",
            "reason": f"{len(existing)} memscan session(s) already open for this project (max {max_sessions}) -- call memscan_detach on one first",
        }
    return None


def attach(session_id: str, pid: object, scan_data_type: str) -> dict:
    if scan_data_type not in VALUE_TYPES:
        return {"status": "error", "error": f"scan_data_type must be one of {sorted(VALUE_TYPES)}, got {scan_data_type!r}"}
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return {"status": "error", "error": f"pid must be an integer, got {pid!r}"}
    # Refuses to attach to this agent's own process, its parent, or a low-numbered system/init
    # process -- a live-memory-write primitive is real capability this project has never granted
    # before (gdb/frida are read-only diagnostics), so it gets its own explicit guard against
    # pointing at anything host-critical, the same instinct behind sandbox.py's own _SENSITIVE_PATHS.
    if pid_int == os.getpid() or pid_int == os.getppid() or pid_int < 10:
        return {"status": "error", "error": f"refusing to attach to pid {pid_int} -- this agent's own/parent process or a low-numbered system process"}

    # Capacity checked before the /proc existence check below -- no point validating a candidate
    # target this project has no room left to actually attach to.
    with _SESSIONS_LOCK:
        early_capacity_error = _capacity_error(session_id)
    if early_capacity_error is not None:
        return early_capacity_error

    if not Path(f"/proc/{pid_int}").is_dir():
        return {"status": "error", "error": f"no such process: pid {pid_int}"}

    with _SESSIONS_LOCK:
        # Re-checked under the lock -- a concurrent attach() for the same session_id could have
        # filled the last slot between the early check above and here.
        capacity_error = _capacity_error(session_id)
        if capacity_error is not None:
            return capacity_error
        existing = _SESSIONS[session_id]
        try:
            popen = subprocess.Popen(
                ["scanmem", "-p", str(pid_int)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except FileNotFoundError:
            return {"status": "error", "error": "scanmem is not installed -- run ./setup_tools.sh first"}
        session = _ScanSession(popen, pid_int, scan_data_type)
        session.drain(_COMMAND_SETTLE_SECONDS)  # swallow the startup banner/region-count info lines
        session.send(f"option scan_data_type {scan_data_type}")
        session.drain(0.3)
        scan_id = uuid.uuid4().hex[:12]
        existing[scan_id] = session
    _ensure_reaper_started()
    logger.debug("memscan_manager: session=%s scan_id=%s attached pid=%s scan_data_type=%s", session_id, scan_id, pid_int, scan_data_type)
    return {"status": "ok", "scan_id": scan_id, "pid": pid_int, "scan_data_type": scan_data_type}


def scan(session_id: str, scan_id: str, mode: str, value: object = None) -> dict:
    session = _get_session(session_id, scan_id)
    if session is None:
        return {"status": "error", "error": f"no active memscan session {scan_id!r} -- call memscan_attach first"}
    if mode not in SCAN_MODES:
        return {"status": "error", "error": f"mode must be one of {sorted(SCAN_MODES)}, got {mode!r}"}
    if mode in ("increased", "decreased") and session.scan_data_type in _NON_ORDERED_VALUE_TYPES:
        return {
            "status": "error",
            "error": (
                f'mode={mode!r} means "greater/less than before", which has no meaning for '
                f'scan_data_type={session.scan_data_type!r} -- use "changed"/"unchanged" (did it '
                f'differ from the last scan at all) or "exact" (search for a specific value) instead'
            ),
        }
    try:
        if mode == "exact":
            if value is None:
                return {"status": "error", "error": 'mode="exact" requires a value'}
            if session.scan_data_type == "string":
                command = f'" {_validate_string_value(value)}'
            elif session.scan_data_type == "bytearray":
                command = _validate_bytearray(value)
            else:
                command = _validate_numeric(value)
        elif mode == "unknown":
            # A true CE-style "unknown initial value" scan -- captures the ENTIRE process state as
            # candidates (confirmed live via scanmem's own `help snapshot`), narrowed afterward by
            # a later increased/decreased/changed/unchanged call once the operator reports the
            # value actually changed in the running target.
            command = "snapshot"
        else:
            token = _SCAN_MODE_TOKENS[mode]
            # "changed"/"unchanged" WITH an explicit value only ever means "changed to this specific
            # NUMBER" here -- scanmem's own `"`/bytearray-literal syntax is exact-match-shaped
            # (search fresh, not "compare this value against what was already found"), so a
            # string/bytearray value alongside changed/unchanged isn't a scanmem shape at all, only
            # the bare structural comparison (no value) is supported for those two types.
            if value is not None and session.scan_data_type in _NON_ORDERED_VALUE_TYPES:
                return {
                    "status": "error",
                    "error": (
                        f'mode={mode!r} with an explicit value is only meaningful for a numeric '
                        f'scan_data_type -- call it with no value for scan_data_type={session.scan_data_type!r} '
                        f'(compares against the last scan/snapshot as-is), or use mode="exact" to '
                        f'search for a specific string/byte pattern'
                    ),
                }
            command = f"{token} {_validate_numeric(value)}" if value is not None else token
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    with session.lock:
        session.send(command)
        output = session.drain(_SCAN_SETTLE_SECONDS)
    session.last_activity = time.time()
    match_count_m = _MATCH_COUNT_PATTERN.search(output)
    match_count = int(match_count_m.group(1)) if match_count_m else (1 if "match identified" in output else None)
    logger.debug("memscan_manager: session=%s scan_id=%s scan mode=%s value=%s -> match_count=%s", session_id, scan_id, mode, value, match_count)
    return {"status": "ok", "match_count": match_count, "raw_output": output[-2000:]}


def list_matches(session_id: str, scan_id: str, limit: int = _MAX_LIST_ENTRIES) -> dict:
    session = _get_session(session_id, scan_id)
    if session is None:
        return {"status": "error", "error": f"no active memscan session {scan_id!r} -- call memscan_attach first"}
    with session.lock:
        # `update` refreshes every known match to its CURRENT live value first -- without this,
        # `list` would show whatever value each match had at the time of the last scan/narrow, not
        # what the process actually holds right now (confirmed live via `help update`).
        session.send("update")
        session.drain(_COMMAND_SETTLE_SECONDS)
        session.send("list")
        output = session.drain(_COMMAND_SETTLE_SECONDS)
    session.last_activity = time.time()
    matches = []
    for line in output.splitlines():
        m = _LIST_LINE_PATTERN.match(line.strip())
        if m:
            matches.append({
                "index": int(m.group("index")),
                "address": m.group("address"),
                "region": m.group("region"),
                "value": m.group("value").strip(),
                "type": m.group("type").strip(),
            })
    truncated = len(matches) > limit
    logger.debug("memscan_manager: session=%s scan_id=%s list -> %d match(es)%s", session_id, scan_id, len(matches), " (truncated)" if truncated else "")
    return {"status": "ok", "matches": matches[:limit], "total_count": len(matches), "truncated": truncated}


def write(session_id: str, scan_id: str, list_index: object, value: object) -> dict:
    session = _get_session(session_id, scan_id)
    if session is None:
        return {"status": "error", "error": f"no active memscan session {scan_id!r} -- call memscan_attach first"}
    try:
        index_int = int(list_index)
    except (TypeError, ValueError):
        return {"status": "error", "error": f"list_index must be an integer, got {list_index!r}"}
    if index_int < 0:
        return {"status": "error", "error": "list_index must be >= 0"}
    try:
        numeric_value = _validate_numeric(value)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    # `set <index>=<value>` (confirmed live via `help set`) writes by MATCH-ID -- an index scanmem
    # itself already tracks internally from this session's own most recent memscan_list, never a
    # raw address string. Deliberately NOT the address-taking `write <type> <addr> <value>` form --
    # see the module docstring's CRITICAL SAFETY PROPERTY.
    with session.lock:
        session.send(f"set {index_int}={numeric_value}")
        output = session.drain(_COMMAND_SETTLE_SECONDS)
    session.last_activity = time.time()
    logger.debug("memscan_manager: session=%s scan_id=%s write list_index=%s value=%s", session_id, scan_id, index_int, value)
    return {"status": "ok", "raw_output": output[-1000:]}


def detach(session_id: str, scan_id: str) -> dict:
    with _SESSIONS_LOCK:
        session = _SESSIONS.get(session_id, {}).pop(scan_id, None)
        if session_id in _SESSIONS and not _SESSIONS[session_id]:
            _SESSIONS.pop(session_id, None)
    if session is None:
        return {"status": "error", "error": f"no active memscan session {scan_id!r}"}
    _terminate(session)
    logger.debug("memscan_manager: session=%s scan_id=%s detached", session_id, scan_id)
    return {"status": "ok"}


def kill_all(session_id: str) -> None:
    """Detaches every memscan session for one ASRA project -- not currently wired into any
    finally-block (memscan_* is exposed in RE chat only, never run_re_triage/run_re_reverify, and
    chat itself relies on the idle reaper the same way browser_* sessions do, confirmed via
    agent/chat.py having no explicit browser_manager.close_session call either), kept as a public
    function so a future caller (or a session-delete route) has a real, tested way to force-clean
    a project's own sessions without waiting out the idle timeout."""
    with _SESSIONS_LOCK:
        sessions = _SESSIONS.pop(session_id, {})
    for session in sessions.values():
        _terminate(session)
    if sessions:
        logger.debug("memscan_manager: session=%s killed %d leftover memscan session(s)", session_id, len(sessions))


def shutdown_all() -> None:
    """Called once from main.py's app-shutdown hook, mirroring get_browser_manager().shutdown() --
    the process-wide backstop that terminates every remaining scanmem process so none survive a
    server restart."""
    global _reaper_stop_event
    if _reaper_stop_event is not None:
        _reaper_stop_event.set()
    with _SESSIONS_LOCK:
        all_sessions = list(_SESSIONS.values())
        _SESSIONS.clear()
    for sessions in all_sessions:
        for session in sessions.values():
            _terminate(session)


# --- native_function wrappers, registered as ToolSpecs (agent/tools/__init__.py) -----------------
# Each pulls _session_id from params (server-injected, hidden from the model's schema -- see
# agent/core.py's own "injected" dict, same pattern afl_fuzz_start/record_target_profile use).

def memscan_attach(params: dict) -> dict:
    session_id = params.get("_session_id")
    if not session_id:
        return {"status": "error", "error": "memscan_attach requires session context"}
    scan_data_type = str(params.get("scan_data_type") or "int32").strip()
    return attach(session_id, params.get("pid"), scan_data_type)


def memscan_scan(params: dict) -> dict:
    session_id = params.get("_session_id")
    if not session_id:
        return {"status": "error", "error": "memscan_scan requires session context"}
    scan_id = str(params.get("scan_id") or "").strip()
    mode = str(params.get("mode") or "").strip()
    return scan(session_id, scan_id, mode, params.get("value"))


def memscan_list(params: dict) -> dict:
    session_id = params.get("_session_id")
    if not session_id:
        return {"status": "error", "error": "memscan_list requires session context"}
    scan_id = str(params.get("scan_id") or "").strip()
    return list_matches(session_id, scan_id)


def memscan_write(params: dict) -> dict:
    session_id = params.get("_session_id")
    if not session_id:
        return {"status": "error", "error": "memscan_write requires session context"}
    scan_id = str(params.get("scan_id") or "").strip()
    return write(session_id, scan_id, params.get("list_index"), params.get("value"))


def memscan_detach(params: dict) -> dict:
    session_id = params.get("_session_id")
    if not session_id:
        return {"status": "error", "error": "memscan_detach requires session context"}
    scan_id = str(params.get("scan_id") or "").strip()
    return detach(session_id, scan_id)
