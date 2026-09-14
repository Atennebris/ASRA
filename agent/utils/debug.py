"""DEBUG=true wiring: CATEGORY_COLORS, two destinations per log line, two-tier logging for large
payloads.

Every debug-level record goes to exactly ONE of two places (_SessionAwareFileHandler.emit below —
never both, see that class's own docstring for the real incident this split fixes):
1. The global app log, resolve_global_app_dir()/debug.log (Documents/ASRA on Windows/macOS, the
   equivalent on Linux — projects/paths.py) — activity that isn't tied to one specific pentest
   project: server startup, UI clicks before/between scans, anything with no active session_id.
   This is the file run.bat's separate debug window tails live.
2. That session's own project folder (Documents/ASRA Projects/<project>/debug.log) — a clean,
   portable per-engagement debug trail sitting right next to that project's session.json, not
   mixed in with every other engagement ever run. Written instead of (not in addition to) the
   global log whenever current_session_id has an active value (set by agent/core.py's
   run_session/run_focused_exploit for the duration of a run). The server's own console handler
   (build_console_handler, wired up alongside this one in logger.py's _configure) still shows
   every line live regardless of this routing.

Nothing here writes into this repo's own data/ directory anymore — debug output is something the
user reads (this session's own request, after `data/debug.log` growing forever in the app's own
install folder was flagged as clutter), so it lives in Documents like project folders already did.
"""
import contextvars
import logging
import os
import re
import threading
import time
from pathlib import Path

from projects.paths import resolve_global_app_dir

# debug.log intentionally uses the machine's own local clock (this file's module docstring: "a
# real timestamp from the machine's own clock... never something synthetic/relative") -- an
# operator tailing the separate debug console window (run.bat) wants to read it against their own
# wall clock, not mentally convert from UTC. session.json's own timestamps (started_at,
# phase_timings, logs[].at -- agent/core.py) are all datetime.now(timezone.utc), on the other hand,
# specifically so duration math never depends on the host machine's timezone/DST. Cross-referencing
# the two without knowing which is which produces a silently wrong elapsed time -- confirmed live
# during a real session review: a debug.log timestamp read against a session.json UTC timestamp
# looked like a 4.5-hour session that was actually 1.5 hours, purely from the unlabeled 3-hour
# offset. Rather than switching debug.log to UTC (which would be a straight regression for the
# live-tailing use case this format was deliberately built for), every debug.log line now carries
# its own explicit UTC offset so it's self-describing wherever it ends up read. Computed once at
# import time, not per record -- a log timestamp's offset drifting by an hour across a rare
# mid-run DST transition is an acceptable trade against recomputing this on every single log call.
_LOCAL_UTC_OFFSET = time.strftime("%z") or "+0000"

# Matches LOG_CATEGORIES in logger.py — extend both together when a new module starts logging.
CATEGORY_COLORS: dict[str, str] = {
    "TOOLS": "\033[36m",  # cyan
    "SESSION": "\033[35m",  # magenta
    "LLM": "\033[33m",  # yellow
    "AGENT": "\033[32m",  # green
    "API": "\033[34m",  # blue
    "CHAT": "\033[31m",  # red
    "PROJECTS": "\033[92m",  # bright green
    "UI": "\033[95m",  # bright magenta — the browser side (agent/static/js/debug_events.js + main.py's /api/debug/client-event)
    "SUBAGENT": "\033[96m",  # bright cyan — deliberately distinct from AGENT's green and TOOLS' plain cyan, so a delegated subagent's own activity stands out from the main agent's much larger volume of console output
    "PLAYBOOK": "\033[93m",  # bright yellow — distinct from LLM's plain yellow, for cross-session technique capture/lookup/distillation activity
    "TOOLKIT": "\033[94m",  # bright blue — distinct from API's plain blue, for native Proxy/Repeater/Decoder/Comparer traffic capture
    "UPDATE": "\033[91m",  # bright red — distinct from CHAT's plain red, for git update checks/apply
    "TERMINAL": "\033[38;5;208m",  # orange — distinct from every other category, standalone PTY
    # terminal tab lifecycle (agent/tools/terminal_manager.py)
    "DESKTOP": "\033[90m",  # bright black/gray — the Tauri desktop shell's own Rust-side lines
    # (desktop/src-tauri/src/main.rs's append_desktop_log_line), written directly to this same file
    # format rather than through get_logger() -- distinct color since these happen BEFORE any
    # Python process/session exists (WSL distro discovery, waiting for the backend's port).
    "LIBRARY": "\033[38;5;141m",  # light purple — distinct from every other category, source
    # upload/normalization/LLM-extraction activity (agent/tools/library_store.py)
}
_RESET = "\033[0m"
_FALLBACK_COLOR = "\033[37m"  # white, for a category missing from CATEGORY_COLORS

# Chars kept inline in the log before a large payload is truncated and dumped to its own file
# (nmap/nuclei output can be huge) — see dump_large_payload/truncate_for_log below.
_INLINE_PREVIEW_CHARS = 500

# Which session (if any) the current call stack is working on behalf of — set by
# agent/core.py's run_session()/run_focused_exploit() for the duration of that run, read here to
# decide whether a log record also belongs in that session's own project folder. A ContextVar
# (not a plain module global) so concurrent sessions in the same process never bleed into each
# other's logs, and asyncio.to_thread calls still see the value set on their originating task.
current_session_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_session_id", default=None)

# Which delegated subagent (if any) the current call stack is running on behalf of -- set by
# agent/core.py's own subagent-spawn point (_delegate_to_subagent_impl's inner _run()) for the
# duration of that subagent's own conversation, including every tool call/subprocess it makes via
# asyncio.to_thread (same context-copy mechanism current_session_id above, and
# agent/tools/runner.py's own current_subprocess_registry, already rely on). None for the main
# phase loop. Read by runner.py's own TOOLS-category debug lines (that module has no RunContext
# to read the way agent/core.py's _log_agent_debug does, only spec/params) so a concurrent
# subagent's tool call is never visually indistinguishable from the main loop's own in debug.log.
current_subagent_label: contextvars.ContextVar[str | None] = contextvars.ContextVar("current_subagent_label", default=None)


def is_debug_enabled() -> bool:
    return os.getenv("DEBUG", "false").strip().lower() in ("1", "true", "yes")


def _session_folder() -> Path | None:
    session_id = current_session_id.get()
    if not session_id:
        return None
    # Local import: sessions.store -> agent.utils.logger -> (lazily) agent.utils.debug is an
    # existing cycle logger.py already avoids by importing debug.py lazily inside a function —
    # matching that same convention here instead of pulling sessions.store in at module level.
    from sessions.store import get_session_folder

    folder = get_session_folder(session_id)
    return Path(folder) if folder else None


class _CategoryConsoleFormatter(logging.Formatter):
    def __init__(self, category: str):
        # _LOCAL_UTC_OFFSET appended to the template string itself (not datefmt) so this keeps its
        # existing compact, msec-free "%H:%M:%S" time -- see this module's own docstring for why.
        super().__init__(f"%(asctime)s {_LOCAL_UTC_OFFSET} %(message)s", datefmt="%H:%M:%S")
        self._color = CATEGORY_COLORS.get(category, _FALLBACK_COLOR)
        self._category = category

    def format(self, record: logging.LogRecord) -> str:
        return f"{self._color}[{self._category}]{_RESET} {super().format(record)}"


def build_console_handler(category: str) -> logging.StreamHandler:
    handler = logging.StreamHandler()
    handler.setFormatter(_CategoryConsoleFormatter(category))
    return handler


_ACTIVE_SESSION_LOG_POINTER_NAME = "active_session_debug_log.txt"
# Last path written to the pointer file -- avoids a redundant disk write on every single
# session-scoped log line (there can be many in a row from the same session), only rewriting when
# the active project actually changes.
_last_pointer_target: str | None = None

# WSL2's own drive-mount convention (/mnt/c/, /mnt/d/, ...) -- see _to_windows_path_if_wsl_mount's
# own docstring for why this needs converting before it reaches scripts/debug_console.ps1.
_WSL_MOUNT_PATH_PATTERN = re.compile(r"^/mnt/([A-Za-z])(/.*)?$")


def _to_windows_path_if_wsl_mount(path: str) -> str:
    """On the documented Windows launch path, this
    whole process runs INSIDE WSL2 (run.bat is a thin `wsl.exe -- bash -lc "... run.sh"` bridge),
    so a real Path computed here for the Windows drive naturally comes out shaped like
    `/mnt/c/Users/...` -- WSL2's own mount convention, not a bug on its own. But
    scripts/debug_console.ps1 (the SEPARATE debug console window run.bat opens) is a genuine
    native Win32 PowerShell process with no WSL hop in it at all (its own docstring is explicit
    about this, specifically to keep normal console copy/paste working) -- its `Test-Path`/file-open
    calls on a bare `/mnt/c/...` string silently resolve to "doesn't exist" (confirmed live), so the
    window's own "also follow the active project's own log" feature never activates, with nothing
    telling the operator why; the pointer file itself just looks like it's pointing somewhere odd.

    Only rewrites a path that actually matches WSL's own `/mnt/<letter>/` shape -- genuine native
    Linux/macOS (run.sh, no WSL involved, scripts/debug_console.py reads this exact same pointer
    file expecting an ordinary native path) never produces a path shaped like this for its own
    app-data dir, so this is a silent no-op there, never mis-rewriting a real Linux `/mnt/...`
    mount an operator happens to have unrelated to WSL... which this app's own resolve_global_app_dir()
    never produces anyway (that possibility is purely theoretical, not something this app can hit).

    """
    match = _WSL_MOUNT_PATH_PATTERN.match(path)
    if not match:
        return path
    drive = match.group(1).upper()
    rest = (match.group(2) or "").replace("/", "\\")
    return f"{drive}:{rest}"


def _update_active_session_log_pointer(project_debug_log_path: Path) -> None:
    """Best-effort: writes project_debug_log_path into a small pointer file in the global app dir
    so run.bat's separate debug console window (scripts/debug_console.ps1, which only ever tails
    the GLOBAL log by design -- see this module's own docstring for why session-scoped lines are
    deliberately kept OUT of that file) can still find and additionally tail whichever project's
    log is actually active right now, without that project's own data ever mixing into the global
    FILE itself. Real incident this fixes: an operator watching that window during a real, active
    scan saw almost nothing (global-scope activity only -- server startup, toolkit traffic), and
    reasonably read that as the console being broken, when the session's own rich AGENT/LLM/TOOLS
    activity was simply routed to a file that window never looked at.

    "Most recently logged" is a pragmatic proxy for "the one the operator cares about right now",
    not a strict guarantee under genuine concurrent sessions in the same process -- acceptable for
    a live-viewing convenience, since the actual FILE separation this function sits next to stays
    exactly as correct as before regardless.

    Routed through _to_windows_path_if_wsl_mount first -- see that function's own docstring for why
    the raw path this process sees isn't always what the reader on the other end needs.
    """
    global _last_pointer_target
    target = _to_windows_path_if_wsl_mount(str(project_debug_log_path))
    if target == _last_pointer_target:
        return
    try:
        pointer_path = resolve_global_app_dir() / _ACTIVE_SESSION_LOG_POINTER_NAME
        pointer_path.parent.mkdir(parents=True, exist_ok=True)
        pointer_path.write_text(target, encoding="utf-8")
        _last_pointer_target = target
    except OSError:
        pass  # same best-effort spirit as the rest of this handler -- never crash logging over this


# Every LOG_CATEGORIES entry (logger.py) gets its OWN _SessionAwareFileHandler instance -- and
# therefore its own logging.Handler.lock -- even though every one of them can end up writing to
# the exact same physical debug.log path (global or a given session's). Handler.lock only
# serializes emit() calls made through that ONE instance; it does nothing to stop two DIFFERENT
# instances (e.g. the TOOLS handler and the LLM handler) from writing to the same file at the same
# moment from different threads (a subagent's own asyncio.to_thread worker running alongside the
# main loop). Real, confirmed incident: exactly that produced literal line corruption in a real
# session's debug.log -- one category's line lost its own timestamp/category prefix, glued onto
# the tail of a different category's line instead, twice in the same session. Keyed by resolved
# path (not one single global lock) so writes to two different sessions' own project-folder logs
# still never block each other.
_file_write_locks: dict[str, threading.Lock] = {}
_file_write_locks_guard = threading.Lock()


def _lock_for_path(path: Path) -> threading.Lock:
    key = str(path)
    with _file_write_locks_guard:
        lock = _file_write_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _file_write_locks[key] = lock
        return lock


class _SessionAwareFileHandler(logging.FileHandler):
    """Routes each record to exactly ONE of two files, never both — see the module docstring for
    the two destinations. A record with no active session_id goes to the global app log (server
    startup, UI clicks before/between scans). A record WITH an active session_id goes only to that
    session's own project-folder log, never the global one — the global log is meant to hold
    activity that isn't tied to one specific pentest project, not a duplicate copy of every
    session's own trace. The server's own console (build_console_handler, a separate handler on
    the same logger) already shows every line live regardless of this routing, so nothing about
    live visibility during an active scan is lost by keeping session-scoped lines out of the
    global FILE.

    Real incident this fixes: before this split, EVERY session-scoped line also landed in the
    global file unconditionally, so Documents/ASRA/debug.log grew to 249MB/256k lines across normal
    use — a full duplicate copy of every project's own debug.log, forever, defeating the entire
    point of a separate per-project log ("not mixed in with every other session ever run" — the
    global file was exactly that mix).
    """

    def emit(self, record: logging.LogRecord) -> None:
        folder = _session_folder()
        if folder is None:
            # no active session — this belongs in the global file, shared across every category's
            # own handler instance, hence the shared per-path lock (see _lock_for_path above).
            with _lock_for_path(Path(self.baseFilename)):
                super().emit(record)
            return
        try:
            folder.mkdir(parents=True, exist_ok=True)
            project_log_path = folder / "debug.log"
            with _lock_for_path(project_log_path), project_log_path.open("a", encoding="utf-8") as f:
                f.write(self.format(record) + "\n")
        except OSError:
            return  # a session's own folder being briefly unwritable must never crash logging
        _update_active_session_log_pointer(project_log_path)


def build_file_handler() -> logging.FileHandler:
    global_log_path = resolve_global_app_dir() / "debug.log"
    global_log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = _SessionAwareFileHandler(global_log_path, encoding="utf-8")
    # _LOCAL_UTC_OFFSET appended to the template string itself (not datefmt) so this keeps its
    # existing default datefmt (None), which is what gives it millisecond precision -- passing an
    # explicit datefmt here to embed %z would silently drop that (logging.Formatter only appends
    # msecs when datefmt is None) -- see this module's own docstring for why the offset matters.
    handler.setFormatter(logging.Formatter(f"%(asctime)s {_LOCAL_UTC_OFFSET} [%(name)s] %(message)s"))
    return handler


def dump_large_payload(step_id: str, content: str) -> str:
    """Writes full content to a "-tool-calls" dump directory next to wherever this log line is
    landing (the active session's own project folder if there is one, else the global app dir),
    returns the path as a string."""
    folder = _session_folder() or resolve_global_app_dir()
    dump_dir = folder / "debug-tool-calls"
    dump_dir.mkdir(parents=True, exist_ok=True)
    dump_path = dump_dir / f"{step_id}.txt"
    dump_path.write_text(content, encoding="utf-8")
    return str(dump_path)


def truncate_for_log(content: str, step_id: str | None = None) -> str:
    """Compact preview for a debug log line; if content is large and step_id is given, also dumps the full text to disk."""
    if len(content) <= _INLINE_PREVIEW_CHARS:
        return content

    remainder = len(content) - _INLINE_PREVIEW_CHARS
    suffix = f"... (+{remainder} chars)"

    if step_id:
        dump_path = dump_large_payload(step_id, content)
        suffix += f", full dump: {dump_path}"

    return content[:_INLINE_PREVIEW_CHARS] + suffix
