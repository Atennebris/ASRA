"""Native (tier-1) runner for pwntools' own crash/exploit-primitive analysis -- a pure-Python
library (no subprocess, no external binary) already a standing project dependency
(requirements.txt), so this needs no install step of its own and has no command-injection surface
at all (nothing here ever shells out).

Three modes, deliberately NOT overlapping with what gdb.py's own live-breakpoint debugging already
covers -- this is post-mortem/offline analysis, not a live session:
- "cyclic_pattern": generates a De Bruijn-based pattern (pwntools' own `cyclic()`) to feed a
  target as input -- the standard technique for finding exactly where in a buffer overflow a
  crash's control data (return address, saved RBP, ...) actually comes from.
- "cyclic_offset": given a value captured from a REAL crash (e.g. the corrupted return address
  cyclic_pattern's own output eventually produced), finds its exact byte offset into that pattern
  (`cyclic_find()`) -- confirmed live: the offset found this way exactly matches where that value
  sits in the original pattern.
- "parse_corefile": structured facts from a real core dump (pwntools' own `Corefile` -- confirmed
  live against a real SIGSEGV core generated via `gdb ... generate-core-file`): crash signal,
  program counter, stack pointer, fault address, a short raw stack dump, and the crashed binary's
  own path. Genuinely new data gdb.py's own live-breakpoint flow has no equivalent for (a POST-
  MORTEM dump, not a live inferior) -- complements it rather than duplicating it. Hardened against
  a malformed/truncated/corrupted core dump (a real file the target itself influenced, not
  necessarily trustworthy) -- a deliberate adversarial-input pass (2026-11-09: a 0-byte file, a
  truncated stub, a file cut right after its own program headers, randomly-flipped bytes, a
  corrupted ELF identification, and a forged program-header count) confirmed pwntools' own
  Corefile always either raises a clean exception or leaves every field as None for malformed
  input -- never a hang, never a silently-wrong value -- so each field is read independently
  (one bad field degrades to its own explicit `unknown` entry instead of losing every other field
  or the whole call), and an early magic-byte check gives a fast, specific error for the most
  common real case ("this isn't a core file at all") before handing it to pwntools at all.
  Considered REA's own route instead (a full hand-rolled, byte-range-validated ELF/core parser,
  `morluto/rea`'s own bridge/pwntools/recorded_crash_impl.py) and decided against it here -- it
  solves a materially bigger problem (full per-segment/per-note structural introspection with
  exact byte provenance) than this builder's own narrow scope (a handful of scalar facts plus one
  short read) actually needs, and the live adversarial testing above found no case it would have
  caught that per-field error handling doesn't already handle just as safely.

pwndbg itself (the OTHER half of what `morluto/rea`'s own pwntools/pwndbg bridge wraps) is
deliberately NOT a second tool here -- once installed (setup_tools_heavy.sh's own install_pwndbg,
wired into the invoking user's ~/.gdbinit), it transparently enriches gdb's own OUTPUT the next
time the already-registered `gdb` tool runs a batch session; there is no separate pwndbg-specific
capability to call, only gdb's own behavior getting better once pwndbg is present on the machine.

pwnlib.update.disabled is set before importing pwn -- confirmed live: importing `pwn` normally
triggers a real network call ("Checking for new versions of pwntools") and writes a cache file
under the invoking user's own ~/.cache -- neither belongs in a security tool's tool-call path
(an unexpected outbound request, and $HOME-relative state this project's own "Runtime architecture"
rule already warns against relying on).
"""
from __future__ import annotations

import re

import pwnlib.update

pwnlib.update.disabled = True

from pwn import Corefile, context, cyclic, cyclic_find  # noqa: E402 -- must follow the disabled= line above

from agent.tools.re_evidence import evidence_result  # noqa: E402
from agent.utils.logger import get_logger  # noqa: E402

logger = get_logger("TOOLS")

context.log_level = "error"  # pwntools' own startup banner/info lines -- noise in a tool result, not signal

_VALID_MODES = {"cyclic_pattern", "cyclic_offset", "parse_corefile"}

# Real, practical ceilings -- a model asking for an absurdly long pattern (or supplying garbage
# length) gets a clear rejection instead of silently generating megabytes of pattern text.
_MIN_PATTERN_LENGTH = 4
_MAX_PATTERN_LENGTH = 100_000
# How many raw stack bytes parse_corefile reads/reports -- enough to see several saved return
# addresses/pointers past the crash site without dumping the whole (often multi-KB) stack region.
_STACK_DUMP_BYTES = 256

_HEX_VALUE_RE = re.compile(r"^(0[xX])?[0-9a-fA-F]+$")


def _parse_int_value(raw: object) -> int:
    """cyclic_offset's own 'value' param -- a hex string ("0x6161616c"), a bare hex string with no
    0x prefix, or a plain decimal integer. Rejects anything else outright rather than letting a
    malformed value silently parse as 0 or raise a confusing error deep inside pwntools."""
    text = str(raw).strip()
    if not text:
        raise ValueError("'value' must not be empty.")
    if text.lower().startswith("0x"):
        return int(text, 16)
    if _HEX_VALUE_RE.match(text) and not text.isdigit():
        return int(text, 16)
    return int(text, 10)


def run_pwntools_analysis(params: dict) -> dict:
    mode = params.get("mode")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown pwntools_analysis mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")

    if mode == "cyclic_pattern":
        return _cyclic_pattern(params)
    if mode == "cyclic_offset":
        return _cyclic_offset(params)
    return _parse_corefile(params)


def _cyclic_pattern(params: dict) -> dict:
    length = params.get("length", 200)
    try:
        length = int(length)
    except (TypeError, ValueError):
        raise ValueError(f"'length' must be an integer, got {length!r}") from None
    if not _MIN_PATTERN_LENGTH <= length <= _MAX_PATTERN_LENGTH:
        raise ValueError(f"'length' must be between {_MIN_PATTERN_LENGTH} and {_MAX_PATTERN_LENGTH}, got {length}")

    pattern = cyclic(length)
    logger.debug("pwntools_analysis: generated a %d-byte cyclic pattern", length)
    return {
        "status": "ok",
        "tool": "pwntools_analysis",
        # Pwntools' default alphabet is plain lowercase/uppercase ASCII letters -- always safely
        # representable as text, never binary noise, so a plain string (not base64/hex) is the
        # most directly usable form for the model to hand straight to a target as input.
        "pattern": pattern.decode("ascii"),
        "length": length,
    }


def _cyclic_offset(params: dict) -> dict:
    value = _parse_int_value(params.get("value"))
    n = params.get("n")
    if n is not None:
        try:
            n = int(n)
        except (TypeError, ValueError):
            raise ValueError(f"'n' must be an integer (the subsequence/value width in bytes), got {n!r}") from None

    offset = cyclic_find(value, n=n)
    logger.debug("pwntools_analysis: cyclic_find(%#x, n=%s) -> %s", value, n, offset)
    if offset == -1:
        return {
            "status": "ok",
            "tool": "pwntools_analysis",
            "found": False,
            "note": f"{value:#x} does not occur anywhere in pwntools' own default cyclic sequence for n={n or 'auto'} -- it isn't a value this pattern ever produces at any offset.",
        }
    return {"status": "ok", "tool": "pwntools_analysis", "found": True, "offset": offset}


def _parse_corefile(params: dict) -> dict:
    path = str(params.get("file_path") or params.get("core_path") or "").strip()
    if not path:
        raise ValueError("parse_corefile requires a 'file_path' parameter (path to a real core dump file).")

    # A cheap, specific check BEFORE handing the file to pwntools at all -- confirmed live
    # (2026-11-09, a deliberate adversarial-input pass: a 0-byte file, a 100-byte truncated stub,
    # a file truncated to half/to right-after-its-own-program-headers, a file with every byte in a
    # 50-byte window flipped, a corrupted ELF identification field, and a forged e_phnum claiming
    # far more program headers than the file could hold) that pwntools' own Corefile already
    # raises a clean, catchable exception (never hangs, never silently returns a plausible-but-
    # wrong value) for every one of those -- this earlier check only exists to give a faster,
    # more specific message for the single most common real case ("this isn't a core file at
    # all") rather than whatever exception type pwntools happens to raise for it.
    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except OSError as exc:
        return {"status": "error", "tool": "pwntools_analysis", "error": f"could not open {path!r}: {exc}"}
    if len(header) < 16 or header[:4] != b"\x7fELF":
        return {"status": "error", "tool": "pwntools_analysis", "error": f"{path!r} does not start with a valid ELF core header -- not a real core dump file."}

    try:
        core = Corefile(path)
    except Exception as exc:
        return {"status": "error", "tool": "pwntools_analysis", "error": f"could not parse {path!r} as an ELF core dump: {exc}"}

    # Each field read independently, deliberately -- confirmed live that a malformed-enough input
    # can make pwntools' own Corefile construction itself succeed while EVERY field silently comes
    # back None (a forged, absurdly large program-header count was enough to reproduce this) --
    # a single shared try/except around the whole block would be fine for that specific case, but
    # a DIFFERENT malformation that raises on, say, `.exe` while `.pc`/`.sp` are still genuinely
    # readable would otherwise lose fields that were never actually in question. One bad field
    # degrades to its own `unknown` entry; it never costs the others.
    observed: dict = {}
    unknown: dict[str, str] = {}

    def _safe_field(name: str, getter):
        try:
            observed[name] = getter()
        except Exception as exc:
            unknown[name] = f"could not read this field from the core dump: {exc}"

    _safe_field("executable", lambda: core.exe.path if core.exe else None)
    _safe_field("pid", lambda: core.pid)
    _safe_field("signal_number", lambda: core.signal)

    import signal as _signal

    def _signal_name():
        if not core.signal:
            return None
        try:
            return _signal.Signals(core.signal).name
        except ValueError:
            return None

    _safe_field("signal_name", _signal_name)
    _safe_field("pc", lambda: hex(core.pc) if core.pc else None)
    _safe_field("sp", lambda: hex(core.sp) if core.sp else None)
    _safe_field("fault_address", lambda: hex(core.fault_addr) if core.fault_addr else None)

    sp = observed.get("sp")
    if sp is None:
        unknown["stack_dump_hex"] = "no valid stack pointer was recovered from this core dump -- nothing to read a stack dump from"
    else:
        try:
            stack_bytes = core.read(int(sp, 16), _STACK_DUMP_BYTES)
        except Exception as exc:
            stack_bytes = b""
            unknown["stack_dump_hex"] = f"could not read stack memory at the crash's own stack pointer: {exc}"
        if stack_bytes:
            observed["stack_dump_hex"] = stack_bytes.hex()
            observed["stack_dump_from"] = sp

    logger.debug("pwntools_analysis: parsed corefile %s -- signal=%s pc=%s", path, observed.get("signal_name"), observed.get("pc"))
    return {"status": "ok", "tool": "pwntools_analysis", **evidence_result(observed, unknown=unknown, method="dynamic")}
