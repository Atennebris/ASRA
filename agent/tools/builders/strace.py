"""build_strace_command()/run_strace() for strace -- behavioral triage of a local binary: run it
under strace and report which real syscalls it makes (files opened/read/written, sockets/
connections, processes spawned, signals) as it actually executes, rather than reasoning about
behavior from static code alone.

This is RE mode's missing "sandbox/monitoring" stage -- the ProcMon/Process Hacker step a competent
reverse engineer always runs before or alongside static analysis (what does this thing actually
touch when it runs), which nothing else in this project's RE toolset covers: tshark_capture already
covers network traffic at the packet level, but nothing surfaces file/registry/process-level
behavior before this. A Windows PE run through `wine` shows wine's OWN translation of Windows API
calls into real host syscalls (e.g. a registry read becomes a real open() under ~/.wine/...) -- an
honest, useful proxy for "what does it touch," not a perfectly faithful Windows-native trace (the
same class of limitation qiling_emulate's own docstring/description is upfront about).

A tier-1 native_function (run_strace, agent/tools/__init__.py's own ToolSpec), NOT a plain
build_command()-based tier-2 tool routed through runner.py's generic dispatch -- real, confirmed
incident this fixes: a via_wine=true call spawns `wine` directly, and runner.py's generic subprocess
path never touches DISPLAY/WAYLAND_DISPLAY, so wine inherits the host agent process's own real
(WSLg-forwarded) display and pops a genuine, visible window on the operator's own Windows desktop --
the exact same class of leak agent/tools/sandbox.py's run_sandboxed already exists to prevent for
custom_re_script's own wine invocations, and agent/tools/wine_debug.py's own module docstring
documents a real, confirmed instance of. run_strace reuses that exact same start_offscreen_display
helper, conditionally (only when via_wine is set -- a native Linux/Mach-O target has no GUI risk at
all, no need to pay Xvfb's startup cost for it).

Never raw strace command text from the model -- trace_categories is restricted to strace's own
built-in `-e trace=` category keywords (a fixed allowlist), and run_args are plain argv elements
(validated, never shell-interpolated) appended after the target -- the same "validate at the
boundary" discipline every other builder in this project applies.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

from agent.tools.builders.validators import validate_safe_value
from agent.tools.sandbox import start_offscreen_display

# strace's own built-in `-e trace=` category keywords -- deliberately not every one strace supports
# (e.g. %clock/%creds/%pure are real but rarely useful for RE triage), just the ones that actually
# answer "what does this thing touch": file opens/reads/writes, network connections, process/thread
# spawning, signals received, and raw file-descriptor operations. A fixed allowlist, not a denylist,
# for the same reason agent/tools/builders/radare2.py's own free-text params are -- this becomes a
# real `-e` argv element, so anything not in this set is rejected outright rather than passed through.
_ALLOWED_TRACE_CATEGORIES = frozenset({"file", "network", "process", "signal", "memory", "desc", "ipc"})
_CATEGORY_LIST_PATTERN = re.compile(r"^[a-z]+(,[a-z]+)*$")

_DEFAULT_TRACE_CATEGORIES = "file,network,process"

# String-argument print length -- strace's own default (32 chars) truncates exactly the kind of
# thing this tool exists to see (a real file path, a registry-translated path under ~/.wine/...).
# 200 is generous without risking a single syscall line dominating the whole output on a binary that
# touches something with a very long path.
_MAX_STRING_LENGTH = 200


def build_strace_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())

    trace_categories = str(params.get("trace_categories") or _DEFAULT_TRACE_CATEGORIES).strip()
    if not _CATEGORY_LIST_PATTERN.match(trace_categories):
        raise ValueError(
            f"trace_categories must be a comma-separated list of lowercase category names, got {trace_categories!r}"
        )
    categories = trace_categories.split(",")
    unknown = [c for c in categories if c not in _ALLOWED_TRACE_CATEGORIES]
    if unknown:
        raise ValueError(f"trace_categories has unknown categories {unknown} -- must each be one of {sorted(_ALLOWED_TRACE_CATEGORIES)}")

    run_args_raw = params.get("run_args") or []
    if not isinstance(run_args_raw, list):
        raise ValueError("'run_args' must be a list of strings")
    run_args = [validate_safe_value(str(arg)) for arg in run_args_raw]

    # A Windows PE (.exe) has no real syscalls of its own to trace directly on this Linux host --
    # `wine` translates its Windows API calls into real host syscalls (file opens under its own
    # prefix, real sockets, ...), the same reason RE_TRIAGE_PROMPT already routes a PE through wine
    # for every other dynamic path (custom_re_script, gdb). Explicit boolean, not auto-detected here
    # -- build_command() has no access to the file's own contents/target_profile, only the model
    # (which already established the target's shape earlier in the pass) knows which this is.
    via_wine = bool(params.get("via_wine", False))
    target_command = ["wine", file_path] if via_wine else [file_path]

    return [
        "strace",
        "-f",  # follow forked/spawned child processes -- wine and many real targets spawn one
        "-tt",  # microsecond timestamps, so events can be correlated against other observations
        "-s", str(_MAX_STRING_LENGTH),
        "-e", f"trace={trace_categories}",
        *target_command,
        *run_args,
    ]


def strace_available() -> bool:
    """run_strace is tier-1 (native_function) -- runner.py's tool_is_installed treats every tier-1
    ToolSpec as always-available UNLESS it names its own availability_check (see that function's own
    docstring), since a tier-1 tool has no `executable` field for the generic check to resolve. This
    is that check, so the Tools tab / subagent tool-checklist still show the REAL, honest state of
    whether the strace binary this tool actually shells out to is present, not a false "installed"."""
    return shutil.which("strace") is not None


def _timeout_seconds() -> int:
    # Same env var/default every other subprocess-backed RE tool honors (agent/tools/runner.py's
    # own _timeout_for) -- run_strace bypasses that generic dispatch (see this module's own
    # docstring for why), so it re-reads the same knob directly rather than inventing a separate one.
    return int(os.getenv("TOOL_TIMEOUT_SECONDS", "600"))


def run_strace(params: dict) -> dict:
    try:
        command = build_strace_command(params)
    except ValueError as exc:
        return {"status": "error", "tool": "strace_run", "error": str(exc)}
    via_wine = bool(params.get("via_wine", False))

    env = dict(os.environ)
    xvfb_proc: subprocess.Popen | None = None
    try:
        if via_wine:
            # See this module's own docstring for the real incident this closes -- only started
            # when actually needed (a native Linux/Mach-O target has no GUI risk, no reason to pay
            # Xvfb's startup cost for it).
            env.pop("DISPLAY", None)
            env.pop("WAYLAND_DISPLAY", None)
            xvfb_proc, display = start_offscreen_display()
            if display is not None:
                env["DISPLAY"] = display

        try:
            result = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=_timeout_seconds(), env=env,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "tool": "strace_run", "command": command}
        except FileNotFoundError:
            return {"status": "tool_unavailable", "tool": "strace_run"}

        # strace's own exit code is the TRACED PROGRAM's exit code (standard strace behavior, not a
        # bug) -- unlike radare2/gdb's own exit code (which reflects only whether THAT analysis
        # tool itself ran to completion), so `returncode == 0` is the wrong ok/error signal here: a
        # traced target legitimately exiting nonzero (a usage error, a rejected argument, anything)
        # is real, useful RE behavioral information, not a tool failure. Real, confirmed incident
        # this fixes (orrery-usr_38e422): a via_wine=true call against a target that exits 1 with no
        # valid arguments got classified "error", which triggered _run_tool_with_retry's own 1-Step-
        # Retry correction path -- and strace's own (genuinely large, real trace) stderr, embedded
        # raw into that correction prompt with no cap at the time, produced a single LLM call of
        # 1,063,415 tokens that exhausted the entire 8-model fallback chain and failed the whole
        # chat turn. Treated as a real strace-level failure only when nothing was actually traced at
        # all (a nonzero exit with empty stderr -- e.g. strace couldn't even exec the target file);
        # any real captured trace, regardless of what the traced program's own exit code was, is ok.
        status = "ok" if (result.returncode == 0 or result.stderr) else "error"
        return {
            "status": status,
            "tool": "strace_run",
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "command": command,
        }
    finally:
        if xvfb_proc is not None:
            xvfb_proc.terminate()
            try:
                xvfb_proc.wait(timeout=3)
            except Exception:
                xvfb_proc.kill()
