"""build_command() and output parser for gdb -- batch-mode dynamic triage of a local binary: set
one or more breakpoints (by function name or address), run, and inspect registers/backtrace/
disassembly/arbitrary memory at each stop, optionally continuing to the next breakpoint hit.

Never a real interactive session -- runner.py's subprocess dispatch always sets stdin=DEVNULL, which
would instantly EOF a real interactive gdb prompt -- every invocation here is
`gdb --batch -ex <cmd> -ex <cmd> ... <binary>`, a single run, one exit.

The generated command list is built entirely from a fixed template plus a small allowlisted set of
per-stop inspection commands (never raw GDB command text from the model) -- GDB's own scripting
language can shell out (`shell <cmd>`, `call system(...)`), and its expression evaluator (used by
both `print` and `x`'s own address argument) can invoke arbitrary inferior functions given
call syntax (`x/s foo()`) -- so `reads[].address` is restricted to a strict allowlist (a bare
register, a hex/decimal address, or one of those +/- a simple offset), never free-form GDB
expression text, the same "validate at the boundary" discipline agent/tools/builders/radare2.py
applies to its own free-text-ish parameters.

Real, confirmed incident this rewrite fixes: the previous version supported exactly ONE breakpoint,
no `continue`, and no way to read memory at any address other than `x/10i $pc` (10 instructions at
the current PC) -- effectively a single snapshot, not real debugging. Confirmed live
(NinthCircle-crackmes-usr_573a1e, a garble-obfuscated Go crackme): needing to read a decrypted
verdict string ("ACCESS GRANTED") from a live process's memory at a specific point, the model never
touched gdb at all -- it had no way to set a breakpoint at the right call site and dump the string
actually sitting at a register/address there -- and instead hand-rolled a raw /proc/pid/mem parser
from scratch via custom_re_script, which failed twice on wrong offsets before working. Real
step-through debugging (multiple stops, arbitrary memory reads) is exactly what that class of task
needs; this file now provides it within the same allowlisted-command safety model.
"""
from __future__ import annotations

import re

from agent.tools.builders.validators import validate_safe_value

# A bare identifier (function name) or a hex/decimal/`*`-prefixed address -- deliberately narrow so
# this can only ever become a GDB "break <this>" argument, never a way to smuggle another GDB
# command in via the break target itself.
_BREAK_TARGET_PATTERN = re.compile(r"^(0x[0-9a-fA-F]+|\*0x[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]*)$")

# reads[].address's own shape -- a bare register ($rax, $pc, $rip, ...), a hex/decimal address, or
# one of those plus/minus a simple hex/decimal offset (e.g. "$rax+0x8", "0x401000-16"). Deliberately
# excludes parentheses/function-call syntax entirely (GDB's expression evaluator can invoke an
# inferior function given one, e.g. "x/s foo()" -- the same class of risk agent/tools/builders/
# radare2.py's own free-text allowlists guard against, just GDB's own version of it) -- a strict
# allowlist, not a denylist.
_GDB_ADDR_EXPR_PATTERN = re.compile(r"^(\$[A-Za-z][A-Za-z0-9]*|0x[0-9a-fA-F]+|[0-9]+)([+-](0x[0-9a-fA-F]+|[0-9]+))?$")

# reads[].type -- the GDB `x` command's own unit-format letter. "string" (s) reads a NUL-terminated
# string, "hex" (xb) reads raw bytes as hex, "instructions" (i) disassembles -- the same instruction
# reader the fixed `x/10i $pc` below already uses, just at an address the model can choose instead
# of only ever the current PC.
_READ_TYPES = {"string": "s", "hex": "xb", "instructions": "i"}

# Real, practical ceilings -- not arbitrary: more breakpoints/stops than this mostly means the model
# is trying to trace a loop iteration-by-iteration, which gdb's own batch mode (no live judgment
# between stops) is the wrong tool for; a real fixed cap keeps one call's output bounded and finishes
# in reasonable time even against a binary that's slow to reach its first breakpoint.
_MAX_BREAKPOINTS = 5
_MAX_STOPS = 5
_MAX_READ_COUNT = 64


def validate_break_targets(break_at_raw: object) -> list[str]:
    """Shared with agent/tools/wine_debug.py -- the same break_at shape (a bare function name or
    address, or a list of up to _MAX_BREAKPOINTS of them) is valid for a real `break` command
    whether the batch is running gdb directly against a local ELF/Mach-O or through winedbg's own
    gdb-proxy mode against a Windows PE."""
    break_targets = break_at_raw if isinstance(break_at_raw, list) else [break_at_raw or "main"]
    break_targets = [str(t).strip() for t in break_targets if str(t).strip()]
    if not break_targets:
        break_targets = ["main"]
    if len(break_targets) > _MAX_BREAKPOINTS:
        raise ValueError(f"break_at accepts at most {_MAX_BREAKPOINTS} targets, got {len(break_targets)}")
    for target in break_targets:
        if not _BREAK_TARGET_PATTERN.match(target):
            raise ValueError(f"break_at entries must each be a bare function name or address, got {target!r}")
    return break_targets


def validate_stops(stops_raw: object) -> int:
    """Shared with agent/tools/wine_debug.py -- see validate_break_targets's own docstring."""
    stops = stops_raw or 1
    try:
        stops = int(stops)
    except (TypeError, ValueError):
        raise ValueError(f"'stops' must be an integer, got {stops_raw!r}") from None
    if not 1 <= stops <= _MAX_STOPS:
        raise ValueError(f"'stops' must be between 1 and {_MAX_STOPS}, got {stops}")
    return stops


def build_read_commands(reads_raw: object) -> list[str]:
    """Shared with agent/tools/wine_debug.py -- see validate_break_targets's own docstring. Turns
    the model-facing {address, type, count} shape into real, safe `x/<count><unit> <address>`
    commands."""
    reads = reads_raw or []
    if not isinstance(reads, list):
        raise ValueError("'reads' must be a list of {address, type, count} objects")
    read_commands: list[str] = []
    for i, read in enumerate(reads):
        if not isinstance(read, dict):
            raise ValueError(f"reads[{i}] must be an object with address/type/count")
        address = str(read.get("address") or "").strip()
        if not _GDB_ADDR_EXPR_PATTERN.match(address):
            raise ValueError(
                f"reads[{i}].address must be a bare register (e.g. \"$rax\", \"$pc\"), a hex/decimal "
                f"address, or one of those plus/minus a simple offset (e.g. \"$rax+0x8\") -- no "
                f"parentheses or function-call syntax, got {address!r}"
            )
        read_type = str(read.get("type") or "hex").strip()
        if read_type not in _READ_TYPES:
            raise ValueError(f"reads[{i}].type must be one of {sorted(_READ_TYPES)}, got {read_type!r}")
        count = read.get("count") or 8
        try:
            count = int(count)
        except (TypeError, ValueError):
            raise ValueError(f"reads[{i}].count must be an integer, got {count!r}") from None
        if not 1 <= count <= _MAX_READ_COUNT:
            raise ValueError(f"reads[{i}].count must be between 1 and {_MAX_READ_COUNT}, got {count}")
        read_commands.append(f"x/{count}{_READ_TYPES[read_type]} {address}")
    return read_commands


def build_gdb_command(params: dict) -> list[str]:
    binary_path = validate_safe_value(str(params["file_path"]).strip())
    break_targets = validate_break_targets(params.get("break_at"))
    run_args = validate_safe_value(str(params.get("run_args") or "").strip())
    stops = validate_stops(params.get("stops"))
    read_commands = build_read_commands(params.get("reads"))

    commands = [f"break {target}" for target in break_targets]
    commands.append(f"run {run_args}".strip())
    # Same fixed baseline every stop got before this rewrite (registers/backtrace/10 instructions at
    # PC) -- always included so a call with no `reads` at all still behaves exactly like the old
    # single-breakpoint version; read_commands are additive, not a replacement.
    per_stop = ["info registers", "backtrace", "x/10i $pc", *read_commands]
    for i in range(stops):
        commands.extend(per_stop)
        if i < stops - 1:
            commands.append("continue")
    commands.append("quit")

    command = ["gdb", "--batch"]
    for cmd in commands:
        command += ["-ex", cmd]
    command.append(binary_path)
    return command


def parse_gdb_output(stdout: str) -> dict:
    """No structured GDB output mode exists for this command mix (unlike radare2's `j`-suffixed
    JSON commands) -- the raw batch-mode transcript (register dump, backtrace, disassembly, any
    requested memory reads, repeated once per stop) is already what the model needs to read
    directly."""
    return {"raw_output": stdout.strip()}
