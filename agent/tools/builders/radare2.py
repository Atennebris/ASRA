"""build_command() and output parser for radare2 -- batch-mode static analysis/decompilation of a
local binary (ELF/PE/Mach-O). Never launches r2's own interactive shell: runner.py's subprocess
dispatch always sets stdin=DEVNULL, so every invocation here is a single non-interactive
`-q -c "<commands>"` batch run, one exit.

The analysis surface is a fixed allowlist of r2 command strings, never raw r2-command passthrough
from the model -- r2's own command language can shell out (`!<cmd>`, `#!pipe`), so letting the
model supply arbitrary command text here would be equivalent to a raw shell tool (same reasoning
agent/tools/builders/gdb.py applies to GDB's own scripting language).
"""
from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value

# wx/hex_search's own argument shape -- a bare hex string, no 0x prefix, even-length (whole
# bytes). Rejected outright here rather than letting r2's own parser deal with something malformed
# -- same "validate at the boundary, don't rely on the tool's own error message" discipline every
# other builder in this project already applies. Deliberately no wildcard support (r2's own `/x`
# accepts `.` as a per-nibble "any" mask) -- YAGNI until a real need for masked search shows up;
# a plain literal byte sequence is already the common case (a magic number, a known signature).
_HEX_BYTES_RE = re.compile(r"^[0-9a-fA-F]+$")

# wa's own argument shape -- a free-text assembly mnemonic (e.g. "jmp 0x401050", "mov eax, 1",
# "nop"), NOT run through validate_safe_value alone the way `address` is just below (that's
# deliberately permissive because a malformed address just makes r2 report "invalid address" --
# see that param's own comment). An instruction string reaches r2's own command interpreter as
# free text glued into the SAME `-c "<command>"` string every other analysis command already goes
# through, so anything from r2's own meta-character set (`;` chains a second command, `` ` `` /
# `$()` substitutes, `!`/`#!pipe` shells out -- exactly what this file's own module docstring warns
# about) would be a real command-injection path if it reached r2 verbatim. Assembly mnemonics never
# legitimately need any of those characters, so this is a strict allowlist (letters/digits/
# a plain space/`,+-*[]:.`), not a denylist -- confirmed against real r2 output live (`wa nop`, `wa
# mov eax, 1`) that this covers ordinary Intel-syntax instructions with immediates/registers/
# memory operands.
#
# A literal space only, NOT Python's `\s` -- a real, confirmed gap in this exact regex's first
# version: `\s` also matches `\n`/`\r`/`\t`, and radare2's own `-c "<command>"` parser treats an
# EMBEDDED NEWLINE as a command separator, exactly like `;` -- confirmed live: a raw r2 invocation
# with `-c "nop\n!id"` (only reachable in the first place because `\s` let a literal `\n` character
# through this exact regex) executed `!id` as a REAL shell command, printing genuine `uid=...`
# output, despite `!`/`;`/backtick/`$`/`|`/`#` all being individually blocked -- the newline itself
# was the injection vector, entirely separate from every other meta-character already excluded.
# Assembly mnemonics never legitimately need a tab/CR/LF between tokens, so a bare space is both
# sufficient and the only whitespace this pattern now accepts.
_ASM_INSTRUCTION_RE = re.compile(r"^[A-Za-z0-9 ,+\-*\[\]:.]+$")

# analysis names whose r2 command actually mutates the file on disk -- see the -w branch and the
# one-time-backup logic in build_radare2_command below, and radare2_result_cache_key's own
# "-w" in command check (which already generalizes to any command built for one of these).
_WRITE_ANALYSES = {"hex_patch", "hex_patch_asm"}

# `aaa` (analyze all, auto-detect functions) runs first wherever a command needs function/xref
# awareness -- radare2 does no analysis at all by default, only raw disassembly would work
# without it. `pdgj` is r2ghidra's own JSON decompile output (only present once
# `r2pm -i r2ghidra` has been provisioned by setup_tools.sh) -- falls back to a plain
# "unknown command" error from r2 itself if the plugin isn't installed, surfaced to the model via
# parse_radare2_output's raw_output fallback.
#
# A per-target radare2 PROJECT cache (`aaa; Ps <name>` once, `P <name>` to reopen on later calls)
# was tried here and reverted -- confirmed live that `aaa` alone costs ~2m30s on a real 3.6MB
# obfuscated Go binary, so repeated calls against the same target are genuinely this expensive, but
# reopening a saved project does NOT reliably restore name-based `@ <name>` addressing: `afl~?`
# proves the function list itself comes back intact after `P <name>` (1764/1764 functions, same as a
# fresh aaa), yet `pdgj @ main`/`s main` right after that same reopen fails to resolve the `main`
# flag at all (falls through to the current seek position, decompiling the wrong function, or errors
# outright with "Invalid tmpseek address"), even with an explicit `fs *` flagspace refresh first --
# project reopen restores the analysis database but not, apparently, the same flag bindings a fresh
# `aaa` creates inline. Not chased further (would need a name->address resolution step built on
# `aflj`'s own output rather than r2's own `@ name` addressing, real added complexity for a caching
# layer, not core correctness) -- left as a known limitation rather than chased further for now.
_ALLOWED_ANALYSIS_COMMANDS = {
    "info": "iIj",
    "imports": "iij",
    "exports": "iEj",
    "strings": "izzj",
    "symbols": "isj",
    # Section/segment table (`iSj`) and entrypoint list (`iej`) -- both read-only, structured-JSON,
    # no `aaa` needed and no address argument, the same shape as info/imports/strings above. Added
    # because they're part of the baseline a reverse engineer always looks at (where is the code,
    # where does execution start) and, without them here, a model that wanted sections/entry had no
    # allowlisted way to get them and would route around this tool via a raw subprocess instead.
    "sections": "iSj",
    "entrypoint": "iej",
    "functions": "aaa; aflj",
    "disassemble_function": "aaa; pdfj @ {address}",
    "decompile_function": "aaa; e r2ghidra.pdg=true; pdgj @ {address}",
    "xrefs_to": "aaa; axtj @ {address}",
    # Read-only hex+ASCII dump (pxj -- same j-suffixed structured-JSON convention every other entry
    # above already uses). {length} defaults to 256 bytes when the model omits it -- enough to
    # actually see something without the model needing to guess a number for a first look.
    "hex_view": "pxj {length} @ {address}",
    # A WRITE action -- see the -w branch and the one-time-backup logic in build_radare2_command
    # below, and _WRITE_ANALYSES above. wx takes a bare hex-byte string (no 0x prefix), validated
    # by _HEX_BYTES_RE before it ever reaches r2.
    "hex_patch": "wx {hex_bytes} @ {address}",
    # Read-only byte-pattern search across the WHOLE file (r2's own `/x`, confirmed live to emit
    # real JSON via the `j` suffix -- `[{"addr":0,"type":"hexpair","data":"7f454c46"}]` searching
    # for ELF magic bytes in a real binary) -- the one thing hex_view/hex_patch alone never covered:
    # neither can find WHERE a known byte sequence (a magic number, a signature, a known bad opcode)
    # occurs without the operator already knowing an address to look at. No `aaa` prefix needed --
    # this is a raw byte scan over the file's own contents, independent of function analysis, so it
    # stays fast even on a large binary unlike every `aaa`-prefixed entry above.
    "hex_search": "/xj {hex_pattern}",
    # A WRITE action -- same -w/backup handling as hex_patch (_WRITE_ANALYSES), but takes a real
    # assembly MNEMONIC (r2's own `wa`, confirmed live: "wa nop" and "wa mov eax, 1" both correctly
    # assembled and wrote the right bytes for the target architecture) instead of a hand-computed
    # hex_bytes string -- hex_patch alone made anything past a trivial NOP/no-op-style edit
    # (redirecting a jump, changing an immediate, patching a call target) require the model to
    # compute raw machine code itself, an error-prone task no LLM is well-suited to; this lets r2's
    # own assembler do that instead, verified against its own disassembler by construction.
    # {instruction} is validated by _ASM_INSTRUCTION_RE (a strict character allowlist, not a
    # denylist) before it ever reaches r2's own command interpreter -- see that pattern's own
    # comment for why this needs to be stricter than the plain validate_safe_value every other
    # free-text-ish param here gets.
    "hex_patch_asm": "wa {instruction} @ {address}",
}

def build_radare2_command(params: dict) -> list[str]:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    # Real, confirmed incident this fixes: a model passed a DIRECTORY path here by mistake. r2
    # doesn't error on that -- it just opens an empty/no-file session, so every read command
    # (info/functions/strings/...) came back exit_code=0 with silently empty results, and the
    # model burned several tool calls before writing its own diagnostic script to find the real
    # cause. Same "validate at the boundary, don't rely on the tool's own error message" discipline
    # every other check in this function already applies. Deliberately is_dir(), not "not
    # is_file()" -- a genuinely MISSING path (never existed at all) already gets a clear error
    # straight from r2 itself once dispatched, and radare2_result_cache_key's own mtime-lookup
    # already handles that case gracefully (never caches it); only a directory silently "succeeds"
    # with nothing to show for it, so only that case needs catching here.
    if Path(file_path).is_dir():
        raise ValueError(f"file_path is a directory, not a binary: {file_path!r} (radare2 opens it silently empty instead of erroring)")
    analysis = params.get("analysis", "info")
    if analysis not in _ALLOWED_ANALYSIS_COMMANDS:
        raise ValueError(f"Unknown radare2 analysis={analysis!r} -- must be one of {sorted(_ALLOWED_ANALYSIS_COMMANDS)}")

    r2_command = _ALLOWED_ANALYSIS_COMMANDS[analysis]
    format_kwargs: dict[str, str] = {}

    if "{address}" in r2_command:
        address = params.get("address")
        if not address and analysis == "hex_view":
            # hex_view is the one address-needing analysis with an obvious sane default: the
            # program's own entry point (r2's "entry0" flag) -- a reasonable place to start a raw
            # byte dump when the model hasn't picked a specific address yet. Real, confirmed
            # incident this fixes: the previous hard-required address forced an avoidable
            # corrected-retry round-trip on hex_view's own most common first call. Every other
            # {address} analysis (disassemble_function/decompile_function/xrefs_to/hex_patch/
            # hex_patch_asm) still requires an explicit target -- there's no equivalently sane
            # default for "which function", so those keep the hard requirement below.
            address = "entry0"
        if not address:
            raise ValueError(f"analysis={analysis!r} requires an 'address' parameter (a function name or address).")
        # r2's own @ operand accepts a bare function name or a hex/decimal address -- passed
        # through validate_safe_value only (control-char/injection barrier), not further
        # restricted to a stricter shape, since r2 itself rejects anything it can't resolve as a
        # flag/address rather than silently doing something else with it.
        format_kwargs["address"] = validate_safe_value(str(address).strip())

    if "{length}" in r2_command:
        length = params.get("length") or 256
        try:
            length = int(length)
        except (TypeError, ValueError):
            raise ValueError(f"hex_view's 'length' parameter must be an integer, got {length!r}") from None
        if length <= 0:
            raise ValueError("hex_view's 'length' parameter must be a positive number of bytes")
        format_kwargs["length"] = str(length)

    if "{hex_bytes}" in r2_command:
        hex_bytes = str(params.get("hex_bytes") or "").strip()
        if not hex_bytes:
            raise ValueError("hex_patch requires a 'hex_bytes' parameter (a hex string, e.g. \"9090\" for two NOPs).")
        if not _HEX_BYTES_RE.match(hex_bytes) or len(hex_bytes) % 2 != 0:
            raise ValueError(f"hex_patch's 'hex_bytes' must be an even-length hex string (0-9/a-f only), got {hex_bytes!r}")
        format_kwargs["hex_bytes"] = hex_bytes

    if "{hex_pattern}" in r2_command:
        hex_pattern = str(params.get("hex_pattern") or "").strip()
        if not hex_pattern:
            raise ValueError("hex_search requires a 'hex_pattern' parameter (a hex byte string to search for, e.g. \"4d5a\" for the MZ magic).")
        if not _HEX_BYTES_RE.match(hex_pattern) or len(hex_pattern) % 2 != 0:
            raise ValueError(f"hex_search's 'hex_pattern' must be an even-length hex string (0-9/a-f only), got {hex_pattern!r}")
        format_kwargs["hex_pattern"] = hex_pattern

    if "{instruction}" in r2_command:
        instruction = str(params.get("instruction") or "").strip()
        if not instruction:
            raise ValueError("hex_patch_asm requires an 'instruction' parameter (an assembly mnemonic, e.g. \"jmp 0x401050\", \"nop\", \"mov eax, 1\").")
        if not _ASM_INSTRUCTION_RE.match(instruction):
            raise ValueError(
                f"hex_patch_asm's 'instruction' contains characters no real assembly mnemonic needs "
                f"(only letters/digits/a plain space/,+-*[]:. are allowed -- no tabs/newlines), got {instruction!r}"
            )
        format_kwargs["instruction"] = instruction

    r2_command = r2_command.format(**format_kwargs)

    if analysis in _WRITE_ANALYSES:
        # Real, hard-to-reverse action: this writes to the file ON DISK, in place. A cheap,
        # reversible safety net -- back the file up ONCE, the first time this session patches it
        # (a plain sibling file, never overwritten once it exists, so it always reflects the file's
        # state before ANY patch this session made, not just the most recent one).
        backup_path = Path(file_path).with_suffix(Path(file_path).suffix + ".asra-bak")
        if not backup_path.exists():
            shutil.copy2(file_path, backup_path)
        return ["radare2", "-q", "-w", "-c", r2_command, file_path]

    return ["radare2", "-q", "-c", r2_command, file_path]


def radare2_result_cache_key(command: list[str], params: dict) -> str | None:
    """Memoization key for build_radare2_command's output (see ToolSpec.result_cache_key).

    radare2 runs in batch mode -- one process, a fixed allowlist of read commands, deterministic
    output -- so the same command on the same unmodified file is byte-identical, yet each call pays
    a full `aaa` re-analysis (~2m30s on a large obfuscated binary). The key embeds the input file's
    mtime so any edit to the target busts it automatically. Returns None (never cache, never serve
    from cache) for the one write action: a `-w` hex_patch mutates the file, and its result must
    always reflect a real dispatch, not a stale read.
    """
    if "-w" in command:
        return None
    file_path = str(params.get("file_path") or "").strip()
    if not file_path:
        return None
    try:
        mtime = os.path.getmtime(file_path)
    except OSError:
        # Can't stat the file -> can't prove it's unchanged -> don't risk a stale hit; run fresh.
        return None
    return f"{mtime}:{' '.join(command)}"


# xrefs_to (axtj) and functions (aflj) on a heavily-called function/a large binary routinely
# return hundreds of entries of radare2's own verbose per-entry JSON shape -- confirmed live: one
# real xrefs_to call against a ~2400-byte function returned a raw JSON array long enough that even
# AFTER _TOOL_RESULT_CHAR_LIMIT's generic 8000-char cap (agent/core.py), what reached the chat
# transcript was still an unreadable multi-screen wall of `{"addr":...,"type":"CALL","at":...}`
# repeated dozens of times -- truncating the STRING doesn't fix an unsummarized LIST, it just cuts
# it off mid-structure. Capped at the entry level instead, with an honest total count kept so the
# model (and the operator reading the same chat transcript) knows entries were dropped, not that
# the function only has 50 callers.
_MAX_LIST_ENTRIES = 50


def parse_radare2_output(stdout: str) -> dict:
    """Every allowed analysis command above ends in a `j` (radare2's own JSON-output suffix) --
    pass it through structured when it parses. Falls back to raw text (still useful to the model)
    when it doesn't -- e.g. r2ghidra isn't installed and pdgj printed a plain error line instead
    of JSON."""
    stripped = stdout.strip()
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return {"raw_output": stripped}

    if isinstance(parsed, list) and len(parsed) > _MAX_LIST_ENTRIES:
        return {
            "result": parsed[:_MAX_LIST_ENTRIES],
            "total_entries": len(parsed),
            # Deliberately doesn't suggest "narrow via a more specific address" -- confirmed live
            # (NinthCircle-crackmes-usr_04a301) that advice is actively wrong for every command that
            # can actually land here: strings/symbols/imports/exports/functions take no address
            # parameter at all (build_radare2_command silently ignores one if sent, so "narrowing"
            # this way just reruns the identical, still-truncated command), and xrefs_to's address is
            # already a required single target, not an optional narrowing knob. The total count is
            # the only real signal this tool can offer once the cap is hit.
            "note": f"{len(parsed)} entries found, showing the first {_MAX_LIST_ENTRIES} -- there is no narrower filter for this analysis command; the total count above is the rest of the signal.",
        }
    return {"result": parsed}
