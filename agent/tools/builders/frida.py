"""build_command() and output parser for Frida -- dynamic instrumentation, RE mode's own runtime
complement to radare2/gdb's static-only analysis. Real gap this closes: Mobile RE (apktool/jadx)
and binary analysis (radare2/gdb) were both purely static before this -- neither can watch what a
process actually DOES at runtime (which functions get called, with what arguments, in what order),
which is often the fastest way to find a serial-check/licensing routine or a certificate-pinning
check without reading disassembly line by line at all.

frida-trace -i (include-by-name-pattern) is the safe entry point used here, not raw JS injection --
same "never let the model supply arbitrary scripting/command text" discipline
agent/tools/builders/radare2.py's own module docstring already established for r2's command
language and agent/tools/builders/gdb.py for GDB's scripting language: Frida's own JS API can do
arbitrary process manipulation, so accepting model-authored JS here would be equivalent to a raw
code-execution tool with no allowlist at all. -i matches by function name glob (e.g. "open*",
"*licence*", a specific export) -- frida-trace auto-generates its own safe, read-only logging
handler for every match, no custom code involved.

frida-trace naturally exits once the traced (spawned) process exits on its own -- confirmed live: a
short-lived CLI target (the common RE case: a crackme, a CLI tool, not a long-running server)
finishes tracing and returns well within a normal subprocess timeout, fitting this project's
synchronous "run command, capture full output" tool convention. A genuinely long-running/server-
shaped target would hit the timeout and lose its output entirely (agent/tools/runner.py discards
stdout/stderr on TimeoutExpired) -- an honest limitation of fitting a live-tracing tool into a
bounded synchronous call, not something this builder can paper over.
"""
from __future__ import annotations

from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")


def frida_trace_working_dir() -> Path:
    """The writable, ASRA-controlled directory frida-trace MUST be launched from.

    frida-trace auto-generates one logging handler script per matched function into
    `Path.cwd() / "__handlers__"` -- it reads the CURRENT WORKING DIRECTORY directly (confirmed in
    frida_tools/tracer.py: FileRepository._repo_dir and its handler_dir.mkdir) and offers NO CLI
    flag or env var to relocate it (`-o` only redirects the trace MESSAGES to a file, and worse,
    diverts them off stdout where parse_frida_trace_output reads them). Real, confirmed incident:
    with ASRA's own cwd on a read-only path, that mkdir raised
    `OSError: Read-only file system: '/mnt/e/ASRA/__handlers__/...'` and the whole trace died.

    So the only real fix is to run frida-trace from a guaranteed-writable directory. This returns
    one under resolve_global_app_dir() (Documents/ASRA/data, writable in both the operator's
    root-mode and non-root launches -- NOT a drvfs-unsupported thing like a unix socket, just plain
    .js text files, so the Documents path is fine), never the repo tree or an ambient $HOME-relative
    path. The tier-2 runner must pass this as the subprocess cwd for frida_trace (reported
    separately -- a builder returns argv only and cannot set its own cwd)."""
    working_dir = resolve_global_app_dir() / "data" / "frida_trace"
    working_dir.mkdir(parents=True, exist_ok=True)
    return working_dir


def build_frida_trace_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    function_pattern = validate_safe_value(str(params["function_pattern"]).strip())
    args = [validate_safe_value(str(a)) for a in (params.get("args") or [])]
    # Make sure the writable working directory frida-trace has to run in actually exists before the
    # runner launches it there -- see frida_trace_working_dir() for the read-only-CWD crash this
    # prevents. Best-effort: a builder can't set its own subprocess cwd, so never fail the build if
    # this one preparatory step can't be done; worst case is the pre-existing CWD behavior.
    try:
        logger.debug("frida_trace: writable working directory ready at %s", frida_trace_working_dir())
    except OSError as exc:
        logger.debug("frida_trace: could not prepare the writable working directory (%s)", exc)
    # -f spawns the target fresh (not attach-by-name/pid) -- the common RE case is "run this local
    # binary while watching it", not instrumenting something already running. "--" separates
    # frida-trace's own flags from the target's own argv, same convention every CLI tool here uses.
    command = ["frida-trace", "-f", file_path, "-i", function_pattern]
    if args:
        command += ["--", *args]
    return command


def build_frida_ps_command(params: dict) -> list[str]:
    return ["frida-ps"]


def parse_frida_trace_output(stdout: str) -> dict:
    """frida-trace has no structured/JSON output mode -- its own trace lines (one per intercepted
    call, e.g. '   322 ms  opendir(name="/tmp")') are genuinely meant to be read as text, in order,
    not as discrete structured records the way radare2's -j commands are. Passed through as-is
    (bounded by the generic _TOOL_RESULT_CHAR_LIMIT downstream, same as any other tool)."""
    return {"trace_output": stdout.strip()}


def parse_frida_ps_output(stdout: str) -> dict:
    """frida-ps's own plain 'PID  Name' table -- confirmed against a real run, no --json flag
    exists for the local-process-list case this builder uses."""
    processes = []
    for line in stdout.strip().splitlines()[2:]:  # skip the header + dashed-line rows
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            processes.append({"pid": int(parts[0]), "name": parts[1].strip()})
    return {"processes": processes} if processes else {"raw_output": stdout.strip()}
