"""Native (tier-1) semantic cross-version diff of two local binaries -- what actually changed
between two builds of the same program/library, not a byte-level diff (radiff2.py already covers
that: similarity score / raw byte changes, with no notion of "this is the same function, just
edited" at all).

Two-step design, cheapest signal first, matching this project's own recorded design principle for
this exact capability (diff cheap inventory before paying for expensive decompilation):

1. **Cheap inventory diff** (always runs): radare2's own `isj`/`iij`/`iEj`/`iIj` (symbols/imports/
   exports/file info -- the same read-only, no-`aaa`-needed commands radare2.py's own
   `_ALLOWED_ANALYSIS_COMMANDS` already exposes to the model one at a time) on both files, filtered
   to GLOBAL, non-imported FUNC symbols -- the symbols a human reverse engineer actually cares about
   when asking "what changed," not every LOCAL crt-internal label a real ELF carries. A symbol
   present in only one file is added/removed; a symbol present in both is "changed" (by size, a
   genuinely cheap signal -- a same-named function whose body grew/shrank did NOT stay identical)
   or "same size" (cheap inventory alone cannot prove the body is unchanged from size matching
   alone, only that it did not grow/shrink -- this is reported honestly as an ambiguous case for
   the deep step below to resolve, never claimed as a confirmed match on its own).
2. **Deep content-digest diff** (optional, bounded, only for functions present in both files):
   decompiles each such function with Ghidra's own persistent-server builder
   (agent/tools/builders/ghidra.py's `run_ghidra`, called as a plain in-process function -- the
   same trust tier as this module's own direct radare2 subprocess call below, not routed back
   through agent/tools/runner.py's generic dispatch/guardrail path, which exists for externally
   triggered tool calls, not one already-trusted tier-1 module calling another) and hashes a
   normalized form of the resulting pseudocode text. Two functions whose normalized digests match
   are reported as "same" with real (if limited) confidence; a mismatch is reported as "changed" --
   this is a genuine content digest, the strongest tier this project's own cross-version design
   note calls for, but it is NOT the full REA-style identity hierarchy (content digest -> module/
   source digest -> node identity -> source-map -> structural CFG fingerprint -> semantic key) --
   only the first (content digest, via normalized decompiled text) and last (name match, used here
   only as a cheap heuristic for WHICH pairs to even compare, never asserted as identity by itself)
   tiers are implemented. The middle tiers (a real structural CFG-shape fingerprint independent of
   decompiler-assigned local names, a source-map-aware match) are deliberately NOT built here --
   real added complexity with no concrete ASRA consumer yet asking for them, the same YAGNI
   reasoning this project's own evidence-contract module (re_evidence.py) already documents for its
   own deliberately-skipped pieces. Revisit if a real case shows the content-digest tier alone isn't
   enough (e.g. two functions whose decompiled text differs only in decompiler-assigned local names
   even after normalization, falsely reported "changed").

Deep-diffing is capped (BINARY_DIFF_MAX_DEEP_FUNCTIONS) and prioritizes functions the cheap pass
could NOT already resolve (same name, same size -- genuinely ambiguous) over ones it already
reported "changed" by size (deep-diffing those only adds confirmation, not new information, so
they're deep-diffed last, if the cap allows). If Ghidra isn't available on this host at all
(ghidra_available() returns False), the deep step is skipped outright with a clear `unknown` entry
explaining why -- the cheap-inventory diff above is still returned in full; this tool never fails
outright just because the heavier half of its own design isn't available.

Calling `run_ghidra` directly (not through a `build_command`/tier-2 subprocess, and not by
re-dispatching through runner.py) mirrors how agent/tools/builders/pwntools_analysis.py calls
pwntools' own `Corefile` directly and how ghidra.py itself shells out to `analyzeHeadless` directly
-- all tier-1 native code running inside the already-trusted agent process, not a boundary a second
guardrail/allowlist layer needs to sit on.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from agent.tools.builders.ghidra import ghidra_available, run_ghidra
from agent.tools.builders.validators import validate_safe_value
from agent.tools.custom_tools_root import resolve_via_custom_root
from agent.tools.re_evidence import evidence_result
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Same reasoning as agent/tools/builders/radare2.py's own _MAX_LIST_ENTRIES: an added/removed/
# changed list can genuinely run into the hundreds on two unrelated binaries -- capped at the entry
# level with an honest total-count note, never silently handed to the generic char-limit truncation.
_MAX_LIST_ENTRIES = int(os.getenv("BINARY_DIFF_MAX_LIST_ENTRIES", "50"))

# How many common-by-name functions get the expensive Ghidra-decompile-and-hash treatment per call.
# A real cost ceiling -- each one pays Ghidra's own per-request decompile cost (see ghidra.py's own
# _SOCKET_REQUEST_TIMEOUT_SECONDS), and a large shared binary can have hundreds of common functions.
_MAX_DEEP_FUNCTIONS = int(os.getenv("BINARY_DIFF_MAX_DEEP_FUNCTIONS", "10"))

# Ghidra's own decompiler assigns synthetic local-variable/label names deterministically from a
# function's internal structure (local_28, iVar1, uStack_18, ...) -- confirmed live against two
# independently-decompiled copies of an IDENTICAL function body that these never collide with real
# user-chosen identifiers in ordinary C, so blanking them out before hashing avoids two genuinely
# identical function bodies being falsely reported "changed" purely because Ghidra's own numbering
# happened to land differently across two separate analysis runs.
_GHIDRA_SYNTHETIC_NAME_RE = re.compile(
    r"\b(?:local|uStack|iStack|aStack|puStack|pcStack|auStack|cStack)_[0-9a-fA-F]+\b"
    r"|\b[a-z]Var\d+\b"
)
_WHITESPACE_RE = re.compile(r"\s+")


def _resolve_radare2() -> str | None:
    """Same {TOOL}_PATH -> PATH -> custom-root convention as agent/tools/runner.py's own
    _resolve_executable and ghidra.py's own _resolve_analyzeheadless -- kept independent of the
    tier-2-only helper since, like those two, this tool dispatches its own subprocess directly."""
    override = os.getenv("RADARE2_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    found_on_path = shutil.which("radare2")
    if found_on_path:
        return found_on_path
    return resolve_via_custom_root("radare2")


def binary_semantic_diff_available() -> bool:
    """ToolSpec.availability_check -- the cheap-inventory half of this tool needs radare2 itself;
    the deep half degrades gracefully without Ghidra (see module docstring), so radare2 alone is
    the real hard dependency."""
    return _resolve_radare2() is not None


def _run_r2_json(executable: str, file_path: str, r2_flag: str) -> object:
    result = subprocess.run(
        [executable, "-q", "-c", r2_flag, file_path],
        capture_output=True, text=True, timeout=60, check=False,
    )
    try:
        return json.loads(result.stdout.strip())
    except (json.JSONDecodeError, ValueError):
        return None


def _cheap_inventory(executable: str, file_path: str) -> dict:
    info = _run_r2_json(executable, file_path, "iIj") or {}
    symbols_raw = _run_r2_json(executable, file_path, "isj") or []
    imports_raw = _run_r2_json(executable, file_path, "iij") or []

    # GLOBAL, non-imported FUNC symbols only -- see module docstring for why LOCAL crt-internal
    # labels (deregister_tm_clones, frame_dummy, ...) are deliberately excluded from this diff.
    functions = {
        entry["name"]: entry
        for entry in symbols_raw
        if isinstance(entry, dict)
        and entry.get("type") == "FUNC"
        and entry.get("bind") == "GLOBAL"
        and not entry.get("is_imported")
        and entry.get("name")
    }
    imports = {entry["name"] for entry in imports_raw if isinstance(entry, dict) and entry.get("name")}
    return {"info": info, "functions": functions, "imports": imports}


def _cap_list(items: list, label: str, unknown: dict) -> list:
    if len(items) <= _MAX_LIST_ENTRIES:
        return items
    unknown[f"{label}_beyond_limit"] = f"{len(items) - _MAX_LIST_ENTRIES} more {label} exist but were not listed (cap of {_MAX_LIST_ENTRIES})"
    return items[:_MAX_LIST_ENTRIES]


def _normalize_pseudocode(text: str) -> str:
    text = _GHIDRA_SYNTHETIC_NAME_RE.sub("VAR", text)
    return _WHITESPACE_RE.sub(" ", text).strip()


def _content_digest(file_path: str, function_name: str) -> tuple[str | None, str | None]:
    """Returns (digest, error) -- never raises; a function Ghidra can't resolve/decompile in one
    of the two files is a real, expected outcome (renamed/inlined/optimized away), not a crash."""
    try:
        raw = run_ghidra({"file_path": file_path, "mode": "decompile_function", "target": function_name})
    except Exception as exc:  # pragma: no cover -- run_ghidra itself is defensive; this is a last resort
        return None, str(exc)
    if raw.get("status") != "ok":
        return None, raw.get("error") or f"ghidra status={raw.get('status')!r}"
    pseudocode = (raw.get("observed") or {}).get("pseudocode")
    if not pseudocode:
        reason = (raw.get("unknown") or {}).get("pseudocode") or "no pseudocode in the Ghidra result"
        return None, reason
    digest = hashlib.sha256(_normalize_pseudocode(pseudocode).encode("utf-8")).hexdigest()
    return digest, None


def _deep_diff(file_a: str, file_b: str, candidates: list[str], unknown: dict) -> list[dict]:
    if not ghidra_available():
        unknown["deep_diff"] = "Ghidra (analyzeHeadless) is not available on this host -- only the cheap-inventory diff above was computed."
        return []

    capped = candidates[:_MAX_DEEP_FUNCTIONS]
    if len(candidates) > _MAX_DEEP_FUNCTIONS:
        unknown["deep_diff_beyond_limit"] = (
            f"{len(candidates) - _MAX_DEEP_FUNCTIONS} more common functions could have been deep-diffed "
            f"but were skipped (cap of {_MAX_DEEP_FUNCTIONS} per call, prioritizing functions the cheap "
            f"size-based pass could not already resolve)."
        )

    results = []
    for name in capped:
        digest_a, error_a = _content_digest(file_a, name)
        digest_b, error_b = _content_digest(file_b, name)
        if error_a or error_b:
            results.append({
                "name": name,
                "result": "unknown",
                "reason": error_a or error_b,
            })
            continue
        results.append({
            "name": name,
            "result": "same" if digest_a == digest_b else "changed",
            "digest_a": digest_a,
            "digest_b": digest_b,
        })
    logger.debug("binary_semantic_diff: deep-diffed %d/%d common functions", len(capped), len(candidates))
    return results


def run_binary_semantic_diff(params: dict) -> dict:
    file_a = validate_safe_value(str(params["file_a"]).strip())
    file_b = validate_safe_value(str(params["file_b"]).strip())
    for label, path in (("file_a", file_a), ("file_b", file_b)):
        if not Path(path).is_file():
            raise ValueError(f"{label} does not exist or is not a file: {path!r}")

    deep = params.get("deep", True)
    if isinstance(deep, str):
        deep = deep.strip().lower() not in ("false", "0", "no", "")

    executable = _resolve_radare2()
    if executable is None:
        return {"status": "tool_unavailable", "tool": "binary_semantic_diff"}

    inv_a = _cheap_inventory(executable, file_a)
    inv_b = _cheap_inventory(executable, file_b)

    unknown: dict[str, str] = {}

    info_a, info_b = inv_a["info"], inv_b["info"]
    architecture_match = (
        isinstance(info_a, dict) and isinstance(info_b, dict)
        and info_a.get("arch") == info_b.get("arch")
        and info_a.get("bits") == info_b.get("bits")
    )
    if not architecture_match:
        unknown["architecture_match"] = (
            f"file_a is {info_a.get('arch')!r}/{info_a.get('bits')!r}-bit, file_b is "
            f"{info_b.get('arch')!r}/{info_b.get('bits')!r}-bit -- a cross-architecture/cross-bitness "
            f"comparison has no meaningful per-function match; only the cheap inventory below is comparable."
        )

    names_a, names_b = set(inv_a["functions"]), set(inv_b["functions"])
    added = sorted(names_b - names_a)
    removed = sorted(names_a - names_b)
    common = sorted(names_a & names_b)

    changed_by_size: list[dict] = []
    same_size: list[str] = []
    for name in common:
        size_a, size_b = inv_a["functions"][name].get("size"), inv_b["functions"][name].get("size")
        if size_a != size_b:
            changed_by_size.append({"name": name, "size_a": size_a, "size_b": size_b})
        else:
            same_size.append(name)

    imports_added = sorted(inv_b["imports"] - inv_a["imports"])
    imports_removed = sorted(inv_a["imports"] - inv_b["imports"])

    observed = {
        "file_a": file_a,
        "file_b": file_b,
        "architecture_match": architecture_match,
        "compiler_a": info_a.get("compiler") if isinstance(info_a, dict) else None,
        "compiler_b": info_b.get("compiler") if isinstance(info_b, dict) else None,
        "functions_added": _cap_list(added, "functions_added", unknown),
        "functions_removed": _cap_list(removed, "functions_removed", unknown),
        "functions_changed_by_size": _cap_list(changed_by_size, "functions_changed_by_size", unknown),
        "functions_same_size": _cap_list(same_size, "functions_same_size", unknown),
        "total_functions_common": len(common),
        "imports_added": _cap_list(imports_added, "imports_added", unknown),
        "imports_removed": _cap_list(imports_removed, "imports_removed", unknown),
    }

    if deep and common:
        # Ambiguous (same-size) functions first -- that's exactly the case the cheap pass above
        # could NOT resolve on its own; "changed by size" functions are already fairly confidently
        # different, so they only fill remaining cap budget, not take priority over genuine unknowns.
        priority = same_size + [entry["name"] for entry in changed_by_size]
        observed["deep_diff"] = _deep_diff(file_a, file_b, priority, unknown)

    logger.debug(
        "binary_semantic_diff: %s vs %s -- +%d/-%d functions, %d common (%d size-changed, %d same-size)",
        file_a, file_b, len(added), len(removed), len(common), len(changed_by_size), len(same_size),
    )
    return {"status": "ok", "tool": "binary_semantic_diff", **evidence_result(observed, unknown=unknown, method="static")}
