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

from agent.tools.builders.validators import validate_safe_value


def build_frida_trace_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    function_pattern = validate_safe_value(str(params["function_pattern"]).strip())
    args = [validate_safe_value(str(a)) for a in (params.get("args") or [])]
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
