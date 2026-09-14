#!/usr/bin/env python3
"""Cross-platform tail of the ASRA global debug log with per-category colors -- the actual work
behind the separate debug window run.bat (Windows, inside a cmd window) and run.sh (native macOS/
Linux, in a new terminal window) open when DEBUG=true. The launcher script picks which real
terminal/console the window runs in per OS; this script does the identical tailing/coloring work
on every OS, so that logic exists in exactly one place.

Why Python and not native shell/batch: none of cmd.exe, bash, or a Windows batch file has a
built-in "wait for new lines appended to a growing file, with per-category ANSI color" primitive.
Python is already a hard requirement for ASRA itself (this project's own venv), so reusing it here
avoids reimplementing file-tailing three times in three different shell dialects.

Colors are the exact same CATEGORY_COLORS mapping the main server console already uses
(agent/utils/debug.py) -- one source of truth, not a second color table to keep in sync by hand.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent.utils.debug import CATEGORY_COLORS  # noqa: E402

_RESET = "\033[0m"
_HEADER_COLOR = "\033[36m"
_DIM = "\033[90m"
# ASCII banner so the window is instantly recognizable at a glance -- same art as
# scripts/debug_console.ps1's Windows counterpart, kept in sync by hand since one's PowerShell and
# the other's Python (no shared template between the two languages).
_BANNER = (
    "    _     ____  ____      _    ",
    "   / \\   / ___||  _ \\    / \\   ",
    "  / _ \\  \\___ \\| |_) |  / _ \\  ",
    " / ___ \\  ___) |  _ <  / ___ \\ ",
    "/_/   \\_\\|____/|_| \\_\\/_/   \\_\\",
)
# Matches agent/utils/logger.py's get_logger() naming convention (logging.getLogger(f"asra.
# {category}")) -- a real log line reads "... [asra.TOOLS] ..." not "... [TOOLS] ...", so matching
# on the bare category name would never actually hit. (The PowerShell version this replaced had
# exactly this bug in a different shape: `-like "*[$category]*"` treats `[...]` as a wildcard
# character CLASS in PowerShell, not literal brackets, so it matched almost every line on whichever
# category happened to be checked first, not the line's real category.)
_LOGGER_NAME_PREFIX = "asra."


def _enable_windows_ansi() -> None:
    """cmd.exe's console host only renders ANSI/VT escape codes when a process explicitly turns
    that mode on via SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING) -- unlike PowerShell,
    which has supported it by default since Windows 10. A no-op on every other OS/console.
    """
    if sys.platform != "win32":
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
    mode = ctypes.c_uint32()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING


def _colorize(line: str) -> str:
    for category, color in CATEGORY_COLORS.items():
        if f"[{_LOGGER_NAME_PREFIX}{category}]" in line:
            return f"{color}{line}{_RESET}"
    return line


def _running_in_a_windows_console() -> bool:
    """True both for a real native Windows process (sys.platform == "win32") AND for this process
    running inside WSL2 while the actually-visible window is a native Windows console (run.bat's
    cmd window) -- on Windows, ASRA's Python always runs inside WSL2 (see run.bat), so sys.platform
    alone reports "linux" even though the window the user is looking at, and its copy/paste
    conventions, are 100% native Windows cmd.exe.
    """
    if sys.platform == "win32":
        return True
    import os

    return bool(os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"))


def _copy_hint() -> str:
    if _running_in_a_windows_console():
        return "Select with the mouse + Enter to copy (QuickEdit Mode) -- right-click title bar > Properties to check it's on."
    if sys.platform == "darwin":
        return "Select with the mouse, then Cmd+C to copy."
    return "Select with the mouse to copy (or Ctrl+Shift+C, depending on your terminal)."


def main() -> None:
    parser = argparse.ArgumentParser(description="Tail the ASRA global debug log with per-category colors.")
    parser.add_argument("--log-path", required=True, help="Path to debug.log")
    args = parser.parse_args()

    _enable_windows_ansi()
    # Console codepages that aren't already UTF-8 (the common cmd.exe default) turn correctly
    # UTF-8-encoded bytes into mojibake on display even once ANSI color codes work -- reconfiguring
    # here covers the write side; run.bat also switches the console's own codepage (chcp 65001) so
    # both sides agree on what a byte sequence means. line_buffering=True: Python otherwise
    # fully-buffers stdout whenever it isn't attached to a real terminal (a real risk here, since
    # some terminal emulators launch their shell through an intermediate pipe) -- without this, log
    # lines could sit in a buffer instead of appearing live, defeating the entire point of a tail.
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)

    log_path = Path(args.log_path)
    for banner_line in _BANNER:
        print(f"{_HEADER_COLOR}{banner_line}{_RESET}")
    debug_label = "D E B U G   C O N S O L E"
    banner_width = len(_BANNER[0])
    label_padding = max(0, (banner_width - len(debug_label)) // 2)
    print(f"{_DIM}{' ' * label_padding}{debug_label}{_RESET}")
    print()
    print(f"{_HEADER_COLOR}ASRA debug log -- {log_path}{_RESET}")
    print(f"{_DIM}{_copy_hint()}{_RESET}")
    print()

    # Wait for the file to exist -- the launcher creates it up front, but this must never crash on
    # a race (server hasn't written its first line yet).
    while not log_path.exists():
        time.sleep(0.2)

    # Global log only shows server startup / UI-clicks-between-scans / native toolkit traffic by
    # design (agent/utils/debug.py's own module docstring) -- an active scan's own AGENT/LLM/TOOLS
    # activity is routed to that project's own debug.log instead, so this window additionally
    # follows a small pointer file (agent/utils/debug.py's _update_active_session_log_pointer) that
    # names whichever project log was written to most recently, switching over live the moment a
    # new session starts logging.
    pointer_path = log_path.parent / "active_session_debug_log.txt"
    project_file = None
    project_log_path: Path | None = None

    def maybe_switch_project_log() -> None:
        nonlocal project_file, project_log_path
        if not pointer_path.exists():
            return
        try:
            target = pointer_path.read_text(encoding="utf-8").strip()
        except OSError:
            return
        if not target or Path(target) == project_log_path:
            return
        target_path = Path(target)
        if not target_path.exists():
            return  # pointer written but the file itself isn't there yet -- try again next poll
        if project_file is not None:
            project_file.close()
        project_file = target_path.open("r", encoding="utf-8", errors="replace")
        project_file.seek(0, 2)
        project_log_path = target_path
        print(f"{_DIM}-- now also following the active project's own log: {target_path}{_RESET}")

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        # Start with none of the file's existing content, only what gets appended from this point
        # on -- anything already in the file is history from a previous run (possibly hours old),
        # and replaying it on every startup reads as live activity that isn't actually happening
        # right now (the exact confusion a fixed-tail-length read used to cause here).
        f.seek(0, 2)
        try:
            while True:
                saw_line = False

                line = f.readline()
                if line:
                    saw_line = True
                    print(_colorize(line.rstrip("\n")))

                maybe_switch_project_log()
                if project_file is not None:
                    project_line = project_file.readline()
                    if project_line:
                        saw_line = True
                        print(_colorize(project_line.rstrip("\n")))

                if not saw_line:
                    time.sleep(0.2)
        except KeyboardInterrupt:
            pass
        finally:
            if project_file is not None:
                project_file.close()


if __name__ == "__main__":
    main()
