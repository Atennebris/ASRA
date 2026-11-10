"""Native (tier-1) wrapper over WABT (the WebAssembly Binary Toolkit) -- ASRA's static analysis
path for a compiled .wasm module, the same role radare2 plays for a native binary. A browser/
web-client RE target increasingly ships compiled WASM (a game's physics/crypto core, an anti-bot
check, a licensing routine) instead of, or alongside, JS -- before this module nothing in ASRA's
toolset could read a .wasm file at all.

Four independent WABT binaries, one per mode, resolved the same {TOOL}_PATH-then-PATH-then-custom-
root way go_buildinfo.py resolves `go` -- there is no single "wabt" executable to health-check
against, so this is tier-1 (its own resolution/error handling per binary) rather than tier-2 (one
fixed `executable` name):

- mode="validate" (`wasm-validate`): the cheapest possible check -- is this even a well-formed wasm
  module at all. Worth running first; every other mode's output is meaningless on an invalid file.
- mode="info" (`wasm-objdump -h -x`): headers + full section inventory -- imports/exports/
  functions/memory/tables/globals by name and signature, no disassembly. The actual "what does
  this do" cheap-inventory step, same philosophy as radare2's info/imports/exports before ever
  decompiling: an unusual import name (e.g. a crypto or network host-function import) or an export
  list often answers the question outright.
- mode="disassemble" (`wasm-objdump -d`): per-function WASM instruction listing -- the closest
  analogue to radare2's own disassemble_function, one level below full decompilation.
- mode="decompile_wat" (`wasm2wat`): the WHOLE module re-encoded as WebAssembly Text format (WAT)
  -- readable structured text (named/numbered locals, explicit control-flow blocks), as close to
  "decompiled" as a stack-machine bytecode with no variable/type erasure problem actually needs;
  unlike a native decompiler there is no pseudocode-vs-real-code gap to flag, WAT is a lossless,
  standard textual encoding of the exact same module.

All four results are "observed"/method="static" -- WABT's own parse of the real binary, not an
inference. A large module's "info"/"disassemble"/"decompile_wat" text can genuinely be sizable (a
big emscripten-compiled app); rather than inventing new pagination machinery for this one builder,
this reuses the project's own existing truncate_for_log (agent/utils/debug.py) -- same mechanism
nmap/nuclei's own large stdout already goes through: an inline preview plus a full dump written to
disk, not pagination's offset/next_offset contract (the module's own text is one coherent artifact
to read, not a list of independent entries the way radare2's functions/xrefs are -- the
pagination model fits a list, not a block of text, so this deliberately doesn't force it).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.custom_tools_root import resolve_via_custom_root
from agent.tools.re_evidence import evidence_result
from agent.utils.debug import truncate_for_log
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_TIMEOUT_SECONDS = int(os.getenv("WASM_ANALYZE_TIMEOUT_SECONDS", "60"))

_VALID_MODES = frozenset({"validate", "info", "disassemble", "decompile_wat"})

_MODE_TO_BINARY = {
    "validate": "wasm-validate",
    "info": "wasm-objdump",
    "disassemble": "wasm-objdump",
    "decompile_wat": "wasm2wat",
}

# wasm-objdump's own section-header lines look like "Import[3]:" / "Export[2]:" / "Custom:" -- used
# to split mode="info"'s -x output into named sections without hardcoding each section's own
# internal bullet-line shape (which genuinely differs: an Import line and a Memory line don't share
# a column layout) -- each section's bullet lines are kept as literal text, one list entry per
# line, rather than over-parsing a format that already reads fine as short text lines.
_SECTION_HEADER_PATTERN = re.compile(r"^([A-Za-z]+)(?:\[\d+\])?:$")

# wasm-objdump -d's own per-function header line, e.g. "000029 func[2] <add>:" or
# "000029 func[2]:" (unnamed/unexported function -- no <name> suffix at all).
_FUNCTION_HEADER_PATTERN = re.compile(r"^[0-9a-f]+\s+func\[(\d+)\](?:\s+<([^>]*)>)?:$")


def _resolve_binary(binary_name: str) -> str | None:
    # Same {TOOL}_PATH-then-PATH-then-custom-root convention as go_buildinfo.py's _resolve_go /
    # unblob.py's _resolve_unblob -- one shared override env var for the whole WABT toolkit
    # (WABT_PATH, a directory) rather than one per binary, since all four ship together as one
    # Debian/apt/brew package and an operator who overrides one almost certainly overrides all.
    override_dir = os.getenv("WABT_PATH")
    if override_dir:
        candidate = os.path.join(override_dir, binary_name)
        if shutil.which(candidate) or os.path.isfile(candidate):
            return candidate
    found_on_path = shutil.which(binary_name)
    if found_on_path:
        return found_on_path
    return resolve_via_custom_root(binary_name)


def wasm_analyze_available() -> bool:
    """ToolSpec.availability_check -- same reasoning as ghidra_available/unblob_available: a
    tier-1 native tool whose real dependency is an external binary the Python code doesn't itself
    carry must not report "always installed" the way an ordinary tier-1 tool would. Checking
    `wasm-objdump` alone (rather than all four) is consistent with those two precedents -- all
    four WABT binaries ship together as one package, so one present implies the rest are too."""
    return _resolve_binary("wasm-objdump") is not None


def _run_binary(executable: str, args: list[str]) -> subprocess.CompletedProcess:
    command = [executable, *args]
    logger.debug("wasm_analyze: dispatching command=%s", command)
    return subprocess.run(
        command, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
    )


def _run_validate(executable: str, file_path: str) -> dict:
    try:
        proc = _run_binary(executable, [file_path])
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "wasm_analyze"}

    is_valid = proc.returncode == 0
    observed = {"is_valid_wasm": is_valid}
    unknown = {} if is_valid else {}
    if not is_valid:
        observed["validation_error"] = (proc.stderr or proc.stdout or "").strip()[-2000:]
    logger.debug("wasm_analyze: validate finished is_valid_wasm=%s", is_valid)
    return {"status": "ok", "tool": "wasm_analyze", **evidence_result(observed, unknown=unknown, method="static")}


def _parse_objdump_sections(stdout: str) -> dict[str, list[str]]:
    """Splits wasm-objdump -x's own "Section[N]:\\n - bullet\\n - bullet" shape into
    {section_name: [bullet lines]} -- each bullet line kept verbatim (stripped of its leading
    "- "), since the per-section column layout genuinely differs and isn't worth re-parsing."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        header_match = _SECTION_HEADER_PATTERN.match(stripped)
        if header_match:
            current = header_match.group(1)
            sections.setdefault(current, [])
            continue
        if current is not None and stripped.startswith("-"):
            sections[current].append(stripped[1:].strip())
    # Drop sections with no bullet lines at all -- wasm-objdump's own "-h" header summary block
    # ("Sections:" followed by one line per section, no leading "-") matches the same
    # Section[N]:-style header regex but never has any bullet lines under it; keeping it here
    # would surface a confusing, empty "Sections": [] entry alongside the real per-section detail.
    return {name: entries for name, entries in sections.items() if entries}


def _run_info(executable: str, file_path: str) -> dict:
    try:
        proc = _run_binary(executable, ["-h", "-x", file_path])
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "wasm_analyze"}

    if proc.returncode != 0:
        error = (proc.stderr or proc.stdout or "").strip()
        logger.debug("wasm_analyze: info failed exit_code=%s stderr_preview=%s", proc.returncode, error[:500])
        return {"status": "error", "tool": "wasm_analyze", "exit_code": proc.returncode, "error": error[-2000:]}

    sections = _parse_objdump_sections(proc.stdout or "")
    observed = {"sections": sections, "section_names": sorted(sections.keys())}
    logger.debug("wasm_analyze: info finished section_names=%s", observed["section_names"])
    return {"status": "ok", "tool": "wasm_analyze", **evidence_result(observed, method="static")}


def _parse_objdump_disassembly(stdout: str) -> list[dict]:
    """Splits wasm-objdump -d's own "offset func[N] <name>:\\n offset: hex bytes | instr\\n..."
    shape into one entry per function. Each instruction line's own byte-offset/raw-hex-bytes
    columns are dropped -- the "| " separator wasm-objdump itself always prints right before the
    actual mnemonic+operands text is what's kept, rather than assuming a fixed column width."""
    functions: list[dict] = []
    current: dict | None = None
    for raw_line in stdout.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        header_match = _FUNCTION_HEADER_PATTERN.match(stripped)
        if header_match:
            current = {"index": int(header_match.group(1)), "name": header_match.group(2), "instructions": []}
            functions.append(current)
            continue
        if current is not None and "|" in stripped:
            instruction = stripped.rsplit("|", 1)[1].strip()
            if instruction:
                current["instructions"].append(instruction)
    return functions


def _run_disassemble(executable: str, file_path: str) -> dict:
    try:
        proc = _run_binary(executable, ["-d", file_path])
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "wasm_analyze"}

    if proc.returncode != 0:
        error = (proc.stderr or proc.stdout or "").strip()
        logger.debug("wasm_analyze: disassemble failed exit_code=%s stderr_preview=%s", proc.returncode, error[:500])
        return {"status": "error", "tool": "wasm_analyze", "exit_code": proc.returncode, "error": error[-2000:]}

    functions = _parse_objdump_disassembly(proc.stdout or "")
    step_id = f"wasm_disassemble_{int(time.time() * 1000)}"
    observed = {
        "functions": functions,
        "total_functions": len(functions),
        "raw_output": truncate_for_log(proc.stdout or "", step_id),
    }
    logger.debug("wasm_analyze: disassemble finished total_functions=%d", len(functions))
    return {"status": "ok", "tool": "wasm_analyze", **evidence_result(observed, method="static")}


def _run_decompile_wat(executable: str, file_path: str) -> dict:
    try:
        proc = _run_binary(executable, [file_path])
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "wasm_analyze"}

    if proc.returncode != 0:
        error = (proc.stderr or proc.stdout or "").strip()
        logger.debug("wasm_analyze: decompile_wat failed exit_code=%s stderr_preview=%s", proc.returncode, error[:500])
        return {"status": "error", "tool": "wasm_analyze", "exit_code": proc.returncode, "error": error[-2000:]}

    step_id = f"wasm_decompile_wat_{int(time.time() * 1000)}"
    observed = {"wat": truncate_for_log(proc.stdout or "", step_id)}
    logger.debug("wasm_analyze: decompile_wat finished output_chars=%d", len(proc.stdout or ""))
    return {"status": "ok", "tool": "wasm_analyze", **evidence_result(observed, method="static")}


def run_wasm_analyze(params: dict) -> dict:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    # Real, confirmed behavior (not assumed): every WABT binary tested here (wasm-validate,
    # wasm-objdump) exits 0 even for a nonexistent file -- the "No such file or directory" message
    # only ever lands on stderr, never reflected in the exit code. Without this upfront check,
    # mode="validate" against a missing path would silently report is_valid_wasm=True (empty
    # stdout, returncode 0 looks identical to "no problems found"), and mode="info"/"disassemble"
    # would silently report an empty, error-free section/function list -- both false positives,
    # not an honest tool_unavailable/error. Checked here once, before resolving/running anything.
    path_obj = Path(file_path)
    if path_obj.is_dir():
        raise ValueError(f"file_path is a directory, not a file: {file_path!r}")
    if not path_obj.is_file():
        raise ValueError(f"file_path does not exist: {file_path!r}")

    mode = str(params.get("mode") or "info").strip()
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(_VALID_MODES)}, got {mode!r}")

    binary_name = _MODE_TO_BINARY[mode]
    executable = _resolve_binary(binary_name)
    if executable is None:
        return {
            "status": "tool_unavailable",
            "tool": "wasm_analyze",
            "error": (
                f"mode={mode!r} requires '{binary_name}' (part of the WABT toolkit) -- none found "
                "on PATH/WABT_PATH/custom tools root. Install WABT (e.g. `apt install wabt`, "
                "`brew install wabt`) to use this mode."
            ),
        }

    if mode == "validate":
        return _run_validate(executable, file_path)
    if mode == "info":
        return _run_info(executable, file_path)
    if mode == "disassemble":
        return _run_disassemble(executable, file_path)
    return _run_decompile_wat(executable, file_path)
