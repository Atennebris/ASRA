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

import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.utils.debug import dump_large_payload
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

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
# was tried TWICE here. First attempt: confirmed live that `aaa` alone costs ~2m30s on a real
# 3.6MB obfuscated Go binary, so repeated calls against the same target are genuinely this
# expensive, but reopening a saved project does NOT reliably restore name-based `@ <name>`
# addressing: `afl~?` proves the function list itself comes back intact after `P <name>`
# (1764/1764 functions, same as a fresh aaa), yet `pdgj @ main`/`s main` right after that same
# reopen fails to resolve the `main` flag at all (falls through to the current seek position,
# decompiling the wrong function, or errors outright with "Invalid tmpseek address"). Second
# attempt (2026-11-09), on this project's real installed radare2 6.2.1: confirmed live and
# reproducible (3/3 runs) that `P <name>` project reopen doesn't just mis-resolve names, it
# SEGFAULTS the whole process outright on this exact version (`Ps <name>` itself succeeds and
# writes a real project directory -- newer r2 stores a project as `<dir.projects>/<name>/rc.r2`
# plus an embedded git repo, not the old single-file format -- but `P <name>` to reopen it crashes
# every time). Building a cache on top of a mechanism that crashes the analysis engine would
# directly contradict this phase's own "never let something break" mandate, so project save/reopen
# is NOT used at all, by either attempt's design.
#
# What's actually implemented instead (see _WARM_CACHEABLE_ANALYSES and _read_warm_cache/
# _write_warm_cache below): never reopen anything r2-native. Instead, avoid the EXPENSIVE PART of
# `aaa` -- analyzing every function in the whole binary -- by running `af @ <address>` (analyze
# just the one function being asked about) when we already know a valid address for it, backed by
# OUR OWN name->address map built from a prior cold `aaa; aflj` run on this exact (path, mtime) and
# persisted as a small JSON sidecar (never a raw address the model supplied unverified -- a
# NON-numeric address string is only ever trusted if it's an exact key in that map; anything else
# falls back to the full, proven-safe cold `aaa` path, never a guess). Confirmed live, end to end,
# on a real compiled-with-debug-info ELF (4 functions, one calling the other three): decompiling
# the SAME function (`main`) once cold (full `aaa`) and once warm (`af` plus a full `afn` replay of
# every cached name, below) produced byte-identical decompiled code -- same call targets, same
# DWARF-sourced names for both the function itself and its callees, same local variable names, same
# control flow. An earlier, narrower hand-probe (replaying `afn` for only ONE function instead of
# the full cached map) DID show a cosmetic divergence in one unused local variable's display name --
# confirming it's the full-map replay that closes this, not an accident of a small test binary.
# This is still a residual risk in principle on some binary this one live check didn't happen to
# exercise, which is exactly why an unresolved name always forces the untouched cold path rather
# than ever trusting the narrow path to be "close enough."
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
    # These two templates deliberately do NOT hardcode an "aaa;" prefix here -- build_radare2_command
    # picks the prefix dynamically (a cheap single-function `af @ <address>` plus `afn` name-replay
    # when a valid warm cache resolves the address, the full `aaa` otherwise) -- see
    # _WARM_CACHEABLE_ANALYSES and the long design-history comment above this dict for why.
    "disassemble_function": "pdfj @ {address}",
    "decompile_function": "e r2ghidra.pdg=true; pdgj @ {address}",
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

# The only two analyses that take a FUNCTION address and can meaningfully run on just that one
# function instead of the whole binary -- see the long comment above _ALLOWED_ANALYSIS_COMMANDS
# for why this exists and why `xrefs_to` is deliberately NOT included: xrefs_to is a genuinely
# global query (who, anywhere in the binary, references this address) and a single function's own
# narrow analysis cannot answer that -- it keeps paying the full `aaa` cost every time, unchanged.
_WARM_CACHEABLE_ANALYSES = {"disassemble_function", "decompile_function"}

# A plain numeric address (hex or decimal) is always safe to use as-is, cold or warm -- r2 proved
# live (see the long comment above) that ADDRESS-based seeking survives everything that broke; only
# NAME/flag resolution is the fragile part. Anything that doesn't match this is treated as a
# function NAME, only trusted via our own cache below, never guessed.
_NUMERIC_ADDRESS_RE = re.compile(r"^(0[xX][0-9a-fA-F]+|-?[0-9]+)$")


def _address_as_int(value: str) -> int | None:
    """Normalizes a numeric address string (hex "0x..." or plain decimal) to an int for equality
    comparison -- the warm-cache's own dict always stores hex() strings (_write_warm_cache), but a
    numeric address a caller passed straight through (the _NUMERIC_ADDRESS_RE branch above) can be
    decimal, so a plain string == would wrongly treat "0x1400015e0" and "5368713696" (the same
    address) as different. None (never raises) for anything that isn't a plain address -- callers
    only use this for an equality check, where None just never matches."""
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except (TypeError, ValueError):
        return None

# Sentinel marking the boundary, in a cold-path command's own stdout, between the real requested
# analysis (always first) and the trailing `aflj` priming call used to (re)build the warm cache for
# next time. A `echo`'d literal line -- cheap, unambiguous, and -- confirmed live -- never collides
# with any `j`-suffixed command's own JSON output (which is always a single line with no embedded
# literal newlines of its own).
_WARM_CACHE_SENTINEL = "__ASRA_R2_WARM_PRIME__"


def _warm_cache_enabled() -> bool:
    return os.getenv("RADARE2_WARM_PROJECT_CACHE", "true").strip().lower() != "false"


def _warm_cache_dir() -> Path:
    """Plain JSON sidecar files only -- never an r2 project (see the design-history comment above
    _ALLOWED_ANALYSIS_COMMANDS for why r2's own project format is not used at all here), so, unlike
    Ghidra's own socket file, there is no drvfs incompatibility to work around; this can live right
    under the project's normal app-data directory. Never $HOME-relative ($HOME differs
    between root/non-root launches of the same install)."""
    cache_dir = resolve_global_app_dir() / "data" / "radare2_warm_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _warm_cache_key(file_path: str) -> str:
    """Deterministic from the absolute path alone -- staleness is handled separately via the
    sidecar's own stored mtime, the same split already used by radare2_result_cache_key below."""
    return "asra_" + hashlib.sha256(str(Path(file_path).resolve()).encode()).hexdigest()[:20]


def _warm_cache_path(file_path: str) -> Path:
    return _warm_cache_dir() / f"{_warm_cache_key(file_path)}.json"


def _read_warm_cache(file_path: str) -> dict | None:
    """None means "cold" -- caller always falls back to the existing, already-correct full-`aaa`
    path. Every failure mode here (missing file, unreadable JSON, stale mtime) degrades to that
    same cold path rather than ever raising or guessing -- this function must never be the reason a
    tool call fails."""
    if not _warm_cache_enabled():
        return None
    try:
        current_mtime = os.path.getmtime(file_path)
    except OSError:
        return None
    try:
        cached = json.loads(_warm_cache_path(file_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(cached, dict) or cached.get("mtime") != current_mtime:
        return None
    names = cached.get("names")
    if not isinstance(names, dict) or not names:
        return None
    return cached


def _write_warm_cache(file_path: str, functions: list) -> None:
    """Called only with an ALREADY-parsed, already-verified-non-empty `aflj` list (see
    parse_radare2_output's own priming-text handling below) -- never persists a cache entry for a
    prime that didn't clearly succeed, so a half-finished/garbled prime simply never gets cached
    (next call just primes again) rather than poisoning future calls with bad data. Any I/O failure
    here is swallowed -- this is a pure side effect for NEXT time, it must never affect the result
    of THIS call."""
    if not _warm_cache_enabled():
        return
    try:
        names: dict[str, str] = {}
        for entry in functions:
            name = entry.get("name")
            addr = entry.get("addr")
            if isinstance(name, str) and name and isinstance(addr, int):
                names[name] = hex(addr)
        if not names:
            return
        mtime = os.path.getmtime(file_path)
        payload = {"mtime": mtime, "names": names}
        _warm_cache_path(file_path).write_text(json.dumps(payload), encoding="utf-8")
    except Exception:
        logger.debug("radare2 warm cache: failed to persist cache for %s", file_path, exc_info=True)


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

    if analysis in _WARM_CACHEABLE_ANALYSES and _warm_cache_enabled():
        # Decide BEFORE formatting: a name address only ever gets translated to a real hex value
        # when it's an exact match in a cache we've actually verified is fresh for THIS file (see
        # _read_warm_cache) -- anything else (no cache yet, or a name the cache doesn't recognize)
        # falls straight through to the existing, already-correct, already-tested full-`aaa` cold
        # path below, exactly as if this whole feature didn't exist. Numeric addresses are always
        # safe either way (see _NUMERIC_ADDRESS_RE's own comment) and still get the speed benefit
        # whenever a cache happens to already be warm.
        raw_address = format_kwargs["address"]
        cache = _read_warm_cache(file_path)
        if cache is not None and not _NUMERIC_ADDRESS_RE.match(raw_address):
            resolved = cache["names"].get(raw_address)
            if resolved is None:
                cache = None  # unrecognized name -- never guess, force the cold path
            else:
                format_kwargs["address"] = resolved

        r2_command = r2_command.format(**format_kwargs)
        if cache is not None:
            # Narrow, single-function analysis instead of the whole-binary `aaa` -- then replay
            # every cached (name, address) pair so call targets inside the real command's own
            # output are named exactly as a full `aaa` run would have named them (verified live,
            # see the design-history comment above _ALLOWED_ANALYSIS_COMMANDS).
            #
            # Real, confirmed regression this fixes (Supratest_RE_a-usr_ff40fb): every cached name
            # OTHER than the one actually `af`'d was replayed via `afn <name> @ <addr>` -- r2's own
            # `afn` RENAMES an already-analyzed function, it does not create one, and the narrow
            # `af @ <address>` above only ever defines a function at that ONE address. Every other
            # cached address was never analyzed this call, so every one of those `afn` replays
            # failed with r2's own `Cannot find function at <addr>` -- confirmed live, the exact
            # same 5 addresses, identically, on every single warm-cache hit for this binary. The
            # errors never broke the real requested command (chained with `;`, r2 keeps going), but
            # they polluted every warm decompile/disassemble result with repeated noise the model
            # had no way to explain. Fixed by only using `afn` (rename) for the one address that
            # really was just `af`'d; every other cached name only needs to LABEL that address for
            # call-target display in pdf/pdg output, which r2's own flag command (`f <name> @
            # <addr>`) does without requiring the address to already be an analyzed function.
            target_addr_int = _address_as_int(format_kwargs["address"])
            afn_replay = "; ".join(
                (f"afn {name} @ {addr}" if _address_as_int(addr) == target_addr_int else f"f {name} @ {addr}")
                for name, addr in cache["names"].items()
            )
            prefix = f"af @ {format_kwargs['address']}"
            if afn_replay:
                prefix += f"; {afn_replay}"
            r2_command = f"{prefix}; {r2_command}"
        else:
            # Cold: full `aaa` exactly like before this phase, plus a trailing, sentinel-delimited
            # `aflj` call that (re)builds the warm cache for next time -- see
            # parse_radare2_output's own sentinel-splitting for the other half of this.
            r2_command = f"aaa; {r2_command}; echo {_WARM_CACHE_SENTINEL}; aflj"
    elif analysis in _WARM_CACHEABLE_ANALYSES:
        # Feature disabled via RADARE2_WARM_PROJECT_CACHE=false -- byte-identical to this phase
        # never having existed: always the full `aaa`, never a cache read/write of any kind.
        r2_command = f"aaa; {r2_command.format(**format_kwargs)}"
    else:
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


# Sentinel for retry_radare2_write_on_permission_denied below -- same "echo a literal marker line,
# split it off in parse_radare2_output" convention _WARM_CACHE_SENTINEL already uses, so the model
# (and a human reading session.json later) can never mistake a scratch-copy patch for an in-place
# one -- the real path actually written is always named explicitly, never left implicit in `command`
# alone (which a correction/retry call upstream could otherwise silently drop or paraphrase).
_PATCH_FALLBACK_SENTINEL = "__ASRA_R2_PATCHED_COPY__"

# Real stderr text r2 emits for both root causes this fallback covers -- a Windows-side DOS
# read-only attribute on the file itself, and another process (confirmed live: a zombie `wine`
# process left over from an earlier failed live-interaction script) still holding an exclusive
# handle on it -- neither of which `chmod` from the Linux/WSL2 side can fix, and neither of which a
# model's own "corrected retry" (agent/core.py) has any argument to change its way out of.
_PERMISSION_DENIED_MARKERS = ("Permission denied", "Read-only file system")


def retry_radare2_write_on_permission_denied(command: list[str], result: dict) -> list[str] | None:
    """ToolSpec.retry_command_on_result -- a deterministic, code-level fallback for a `-w` write
    (hex_patch/hex_patch_asm) that failed with a plain OS-level permission error, same shape and
    same reasoning as nmap's own retry_nmap_with_pn_if_host_seemed_down: the fix is already fully
    determined by what actually went wrong, so there is nothing for the model to usefully reason
    about -- let alone spend its one "corrected retry" chance on.

    Real, confirmed incident this fixes (Supratest_RE_a-usr_ff40fb): `wx 90 @ <addr>` against a
    real target under WSL2's /mnt/c/... drvfs mount failed twice, identically, with `Permission
    denied` / `Cannot open ... for writing` -- never an argument problem (the address and hex_bytes
    were both correct). Left to agent/core.py's generic corrected-retry, a weak model's only
    "fixes" were guessing an unrelated `/tmp/<basename>` path that was never actually created there,
    and -- on the NEXT top-level attempt -- silently swapping `analysis` from `"hex_patch"` to
    `"disasm"` entirely, i.e. corrupting the one call that mattered most in the whole session. This
    closes the dead end outright: copy the real target into ASRA's own always-writable app-data
    scratch dir ONCE, force it writable (shutil.copy2 can carry over the very read-only mode bit
    that caused this), and patch the copy there -- made unambiguous via _PATCH_FALLBACK_SENTINEL
    (see parse_radare2_output) rather than ever silently claiming the original in-place file changed.
    """
    if "-w" not in command:
        return None
    stderr = result.get("stderr") or ""
    if not any(marker in stderr for marker in _PERMISSION_DENIED_MARKERS):
        return None
    file_path = command[-1]
    scratch_dir = resolve_global_app_dir() / "data" / "radare2_patch_scratch"
    if Path(file_path).parent == scratch_dir:
        return None  # already retried once against the scratch copy -- never loop further
    try:
        scratch_dir.mkdir(parents=True, exist_ok=True)
        scratch_path = scratch_dir / Path(file_path).name
        shutil.copy2(file_path, scratch_path)
        os.chmod(scratch_path, 0o644)
    except OSError:
        logger.debug("radare2 permission-denied fallback: could not stage a writable copy of %s", file_path, exc_info=True)
        return None
    c_index = command.index("-c")
    new_command = list(command)
    new_command[c_index + 1] = f"{command[c_index + 1]}; echo {_PATCH_FALLBACK_SENTINEL}:{scratch_path}"
    new_command[-1] = str(scratch_path)
    return new_command


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


def parse_radare2_output(stdout: str, arguments: dict | None = None) -> dict:
    """Every allowed analysis command above ends in a `j` (radare2's own JSON-output suffix) --
    pass it through structured when it parses. Falls back to raw text (still useful to the model)
    when it doesn't -- e.g. r2ghidra isn't installed and pdgj printed a plain error line instead
    of JSON.

    A result list longer than _MAX_LIST_ENTRIES used to be silently cut to the first page forever
    -- real signal loss on a large/obfuscated binary (hundreds of functions/xrefs, only the first
    50 ever visible). Paged instead: `arguments["offset"]` (the model's own tool-call
    argument, threaded through by agent/core.py's _apply_output_parser -- see
    _PAGINATED_OUTPUT_PARSERS there) picks which slice comes back, `next_offset` tells the model
    the exact argument to call again with for the next page (None once there isn't one), and the
    FULL untruncated list is written once, on the first page, to disk via dump_large_payload --
    reusing the project's existing debug-dump infrastructure (agent/utils/debug.py) rather than
    building a second artifact-storage mechanism for the same job.

    A cold warm-cache priming call (see build_radare2_command's own _WARM_CACHE_SENTINEL) appends
    an `aflj` call after the real one, separated by a literal echo'd sentinel line -- detected and
    split off here BEFORE any of the logic above runs, so the model always sees exactly the real
    command's own result, byte-identical to a run with warm-caching disabled entirely. The priming
    half is used ONLY to refresh the on-disk warm cache for next time (_write_warm_cache) -- never
    surfaced to the model, and any failure to parse it is silently ignored (see _write_warm_cache's
    own "never poison the cache with a bad prime" guard).
    """
    stdout, patched_copy_path = _split_patch_fallback_marker(stdout)
    stdout, primed_functions = _split_warm_cache_priming(stdout)
    if primed_functions is not None and arguments:
        file_path = str(arguments.get("file_path") or "").strip()
        if file_path:
            _write_warm_cache(file_path, primed_functions)

    stripped = stdout.strip()
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        result: dict = {"raw_output": stripped}
    else:
        if not isinstance(parsed, list) or len(parsed) <= _MAX_LIST_ENTRIES:
            result = {"result": parsed}
        else:
            result = None  # paginated below -- patched_copy_path still applies either way

    if result is not None:
        if patched_copy_path:
            result["patched_copy_path"] = patched_copy_path
            result["note"] = (
                f"The original file could not be opened for writing (OS-level permission error, "
                f"not an argument mistake) -- the patch was written to a writable COPY instead: "
                f"{patched_copy_path}. The original target file was NOT modified."
            )
        return result

    offset = _coerce_offset(arguments.get("offset") if arguments else None)
    total_entries = len(parsed)
    page = parsed[offset:offset + _MAX_LIST_ENTRIES]
    next_offset = offset + _MAX_LIST_ENTRIES if offset + _MAX_LIST_ENTRIES < total_entries else None

    response: dict = {
        "result": page,
        "total_entries": total_entries,
        "offset": offset,
        "next_offset": next_offset,
    }
    if offset >= total_entries:
        response["note"] = (
            f"offset={offset} is past the end -- only {total_entries} entries exist in total "
            f"(valid offsets run from 0 to {total_entries - 1})."
        )
    else:
        shown_through = offset + len(page)
        more_hint = f"call again with offset={next_offset} for the next page" if next_offset is not None else "this was the last page"
        response["note"] = (
            f"{total_entries} entries found, showing {offset}-{shown_through - 1} -- {more_hint}. "
            # Deliberately doesn't suggest "narrow via a more specific address" -- confirmed live
            # (NinthCircle-crackmes-usr_04a301) that advice is actively wrong for every command
            # that can land here: strings/symbols/imports/exports/functions take no address
            # parameter at all (build_radare2_command silently ignores one if sent), and xrefs_to's
            # address is already a required single target, not an optional narrowing knob.
            "There is no narrower filter for this analysis command."
        )
    if offset == 0:
        step_id = f"radare2_{int(time.time() * 1000)}"
        response["full_dump_path"] = dump_large_payload(step_id, json.dumps(parsed, indent=2))
        response["note"] += f" The complete, untruncated list ({total_entries} entries) was also written to {response['full_dump_path']}."
    return response


def _split_warm_cache_priming(stdout: str) -> tuple[str, list | None]:
    """Splits a cold-path priming call's stdout on _WARM_CACHE_SENTINEL: (real_text,
    parsed_aflj_list_or_None). Returns (stdout, None) unchanged when the sentinel isn't present at
    all -- every non-priming call (an ineligible analysis, a warm-path narrow `af` call, or warm-
    caching disabled outright) takes this branch and is completely untouched by any of this.
    """
    marker_line = f"\n{_WARM_CACHE_SENTINEL}\n"
    if marker_line not in stdout:
        # Also handle it landing at the very start/end without a surrounding blank line either side.
        if stdout.strip() == _WARM_CACHE_SENTINEL or _WARM_CACHE_SENTINEL not in stdout:
            return stdout, None
        marker_line = _WARM_CACHE_SENTINEL
    real_text, _, priming_text = stdout.partition(marker_line)
    try:
        parsed = json.loads(priming_text.strip())
    except (json.JSONDecodeError, ValueError):
        return real_text, None
    if not isinstance(parsed, list) or not parsed:
        return real_text, None
    return real_text, parsed


def _split_patch_fallback_marker(stdout: str) -> tuple[str, str | None]:
    """Splits retry_radare2_write_on_permission_denied's own echo'd marker line out of stdout:
    (real_text, scratch_path_or_None). Returns (stdout, None) unchanged for the overwhelming
    majority of write calls -- the ones that succeeded in place on the first try and never went
    through that fallback at all."""
    prefix = f"{_PATCH_FALLBACK_SENTINEL}:"
    for line in stdout.splitlines():
        if line.startswith(prefix):
            scratch_path = line[len(prefix):].strip()
            return stdout.replace(line, "", 1), (scratch_path or None)
    return stdout, None


def _coerce_offset(raw_offset: object) -> int:
    """A malformed offset (missing, a string, negative) degrades to the first page rather than
    raising -- same "never let a bad argument crash the tool call" discipline as every other
    builder in this file."""
    try:
        offset = int(raw_offset) if raw_offset is not None else 0
    except (TypeError, ValueError):
        return 0
    return offset if offset >= 0 else 0
