"""Native (tier-1) reader for Go's own embedded build/module metadata -- a Go binary carries its
own module path, dependency list (with versions and checksums), and build settings (GOOS/GOARCH,
CGO_ENABLED, VCS revision, ...) inside itself, since the `runtime/debug` package records this at
compile time. This is the RE-triage step for "what is this binary actually made of" that nothing
else in this project's toolset covers for Go specifically: radare2/jadx/apktool target other
ecosystems, and binwalk/unblob look for embedded containers, not a language runtime's own
self-description.

Two ways to read it, both implemented here:

1. `go version -m <binary>` (the real Go toolchain's own tool) -- the authoritative, fully-parsed
   path. Requires a `go` binary to be present.
2. A pure-Python fallback when no `go` toolchain is available: since Go 1.18, the exact same
   tab-separated "path/mod/dep/build" text block `go version -m` prints is embedded verbatim inside
   the binary itself (that is the whole point of embedding it as plain text rather than only as
   pointers -- so tooling can find it without needing to resolve virtual addresses through the
   binary's own section table). This fallback just locates that text block by its literal `path\t`
   marker and parses it with the exact same tab-line parser, rather than reimplementing the
   lower-level, version-specific pointer/header format `go version -m` itself falls back to for
   binaries that don't carry the newer plain-text blob (e.g. very old Go versions) -- that lower
   level is not implemented here; see run_go_buildinfo's own `unknown` entry when neither form of
   the data is found.

A second mode, `nm_symbols` (via `go tool nm`), reads the binary's own symbol table -- unlike
`go version -m`'s embedded text blob, there is no toolchain-free fallback for this: a symbol table
is a real structured binary section (ELF/PE/Mach-O specific), not a plain-text blob with a findable
marker, so this mode genuinely requires the `go` toolchain and reports tool_unavailable without it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.custom_tools_root import resolve_via_custom_root
from agent.tools.re_evidence import evidence_result
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Same practical ceiling as unblob.py's own _MAX_LIST_ENTRIES -- an honest total count survives
# even when the list itself is capped, never a silent truncation.
_MAX_LIST_ENTRIES = 50

_TIMEOUT_SECONDS = int(os.getenv("GO_BUILDINFO_TIMEOUT_SECONDS", "60"))

# How far into the file to scan for the embedded "path\t..." text blob when no `go` toolchain is
# available -- generous relative to how small that blob actually is (a handful of KB even for a
# binary with hundreds of dependencies), bounded so a scan against a huge stripped binary doesn't
# read the whole thing into memory for nothing.
_FALLBACK_SCAN_BYTES = int(os.getenv("GO_BUILDINFO_FALLBACK_SCAN_BYTES", str(64 * 1024 * 1024)))

_GO_VERSION_PATTERN = re.compile(rb"go1\.\d+(?:\.\d+)?")
# `go version -m`'s own CLI output indents every metadata line with one leading tab (it prints
# the exact text below with each '\n' replaced by '\n\t'); the raw text blob embedded in the
# binary itself (read by the fallback scan) has no such leading tab -- `\t?` tolerates both without
# needing two separate parsers for what is otherwise identical content.
_MODINFO_LINE_PATTERN = re.compile(r"^\t?(path|mod|dep|build)\t(.*)$", re.MULTILINE)

_VALID_MODES = frozenset({"buildinfo", "nm_symbols"})


def _resolve_go() -> str | None:
    # Same {TOOL}_PATH-then-PATH-then-custom-root convention as unblob.py's own _resolve_unblob.
    override = os.getenv("GO_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    found_on_path = shutil.which("go")
    if found_on_path:
        return found_on_path
    return resolve_via_custom_root("go")


def _parse_modinfo_lines(text: str) -> dict:
    """Parses the tab-separated path/mod/dep/build lines shared by both the real `go version -m`
    output and the fallback's raw embedded-text extraction -- one parser, two sources, so the two
    modes can never silently disagree on what a given line means."""
    module_path: str | None = None
    main_module: dict | None = None
    dependencies: list[dict] = []
    build_settings: dict[str, str] = {}

    for match in _MODINFO_LINE_PATTERN.finditer(text):
        tag, rest = match.group(1), match.group(2)
        fields = rest.split("\t")
        if tag == "path" and fields and fields[0]:
            module_path = fields[0]
        elif tag == "mod" and len(fields) >= 2 and main_module is None:
            main_module = {
                "path": fields[0],
                "version": fields[1],
                "sum": fields[2] if len(fields) > 2 else None,
            }
        elif tag == "dep" and len(fields) >= 2:
            dependencies.append({
                "path": fields[0],
                "version": fields[1],
                "sum": fields[2] if len(fields) > 2 else None,
            })
        elif tag == "build" and fields and fields[0]:
            key, _, value = fields[0].partition("=")
            build_settings[key] = value if value else "true"

    return {
        "module_path": module_path,
        "main_module": main_module,
        "dependencies": dependencies,
        "build_settings": build_settings,
    }


def _run_version_m(executable: str, file_path: str) -> dict:
    command = [executable, "version", "-m", file_path]
    logger.debug("go_buildinfo: dispatching go version -m file_path=%s", file_path)
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        logger.debug("go_buildinfo: go version -m timed out after %ss", _TIMEOUT_SECONDS)
        return {"status": "timeout", "tool": "go_buildinfo", "command": command}

    stdout = proc.stdout or ""
    header = stdout.splitlines()[0] if stdout else ""
    _, _, version_part = header.partition(": ")
    version_part = version_part.strip()

    # `go version -m` exits nonzero on a non-Go binary too (real, confirmed behavior) -- its own
    # "not a Go executable" message on stdout is itself the useful result, not a tool failure, so
    # it's checked before a nonzero exit code is treated as a hard error.
    if version_part == "not a Go executable":
        return {
            "status": "ok",
            "tool": "go_buildinfo",
            **evidence_result({"is_go_binary": False}, method="static"),
        }

    if proc.returncode != 0 or not stdout.strip():
        error = (proc.stderr or stdout or "").strip()
        logger.debug("go_buildinfo: go version -m failed exit_code=%s stderr_preview=%s", proc.returncode, error[:500])
        return {"status": "error", "tool": "go_buildinfo", "exit_code": proc.returncode, "error": error[-2000:]}

    parsed = _parse_modinfo_lines(stdout)
    total_deps = len(parsed["dependencies"])
    dependencies = parsed["dependencies"][:_MAX_LIST_ENTRIES]
    unknown: dict[str, str] = {}
    if total_deps > _MAX_LIST_ENTRIES:
        unknown["dependencies_beyond_limit"] = (
            f"{total_deps - _MAX_LIST_ENTRIES} more dependencies exist but were not listed "
            f"(cap of {_MAX_LIST_ENTRIES})"
        )

    observed = {
        "is_go_binary": True,
        "go_version": version_part,
        "module_path": parsed["module_path"],
        "main_module": parsed["main_module"],
        "dependencies": dependencies,
        "total_dependencies": total_deps,
        "build_settings": parsed["build_settings"],
        "source": "go version -m",
    }
    logger.debug("go_buildinfo: finished status=ok go_version=%s total_dependencies=%d", version_part, total_deps)
    return {"status": "ok", "tool": "go_buildinfo", **evidence_result(observed, unknown=unknown, method="static")}


def _run_fallback_scan(file_path: str) -> dict:
    """No `go` toolchain available -- see this module's own docstring for why locating the
    embedded plain-text modinfo blob directly is a real, not approximate, source for the same
    fields `go version -m` reports, when that blob is present at all."""
    logger.debug("go_buildinfo: no go toolchain, falling back to raw embedded-text scan file_path=%s", file_path)
    try:
        with open(file_path, "rb") as fh:
            raw = fh.read(_FALLBACK_SCAN_BYTES)
    except OSError as exc:
        return {"status": "error", "tool": "go_buildinfo", "error": f"could not read file: {exc}"}

    version_match = _GO_VERSION_PATTERN.search(raw)
    go_version = version_match.group(0).decode("ascii") if version_match else None

    marker_idx = raw.find(b"path\t")
    if marker_idx == -1:
        unknown = {
            "module_metadata": (
                "no embedded 'path\\t...' modinfo text block found within the first "
                f"{_FALLBACK_SCAN_BYTES} bytes, and no 'go' toolchain was available to run "
                "`go version -m` instead -- this binary may predate Go 1.18's plain-text modinfo "
                "format, may have been built with build info stripped, or the blob may sit "
                "beyond the scanned prefix"
            )
        }
        observed = {"is_go_binary": go_version is not None, "go_version": go_version, "source": "raw byte scan"}
        return {"status": "ok", "tool": "go_buildinfo", **evidence_result(observed, unknown=unknown, method="static")}

    # The embedded text block ends at the first non-text byte (the blob was written as a plain Go
    # string literal, length-prefixed elsewhere -- this scan has no access to that length, so the
    # end is inferred from the first byte outside the printable range the block's own content uses).
    window = raw[marker_idx:marker_idx + 65536]
    end = next((i for i, b in enumerate(window) if b not in (9, 10) and (b < 32 or b > 126)), len(window))
    text = window[:end].decode("ascii", errors="replace")

    parsed = _parse_modinfo_lines(text)
    total_deps = len(parsed["dependencies"])
    dependencies = parsed["dependencies"][:_MAX_LIST_ENTRIES]
    unknown: dict[str, str] = {}
    if total_deps > _MAX_LIST_ENTRIES:
        unknown["dependencies_beyond_limit"] = (
            f"{total_deps - _MAX_LIST_ENTRIES} more dependencies exist but were not listed "
            f"(cap of {_MAX_LIST_ENTRIES})"
        )

    observed = {
        "is_go_binary": True,
        "go_version": go_version,
        "module_path": parsed["module_path"],
        "source": "raw byte scan (no go toolchain available)",
    }
    inferred = {
        "main_module": parsed["main_module"],
        "dependencies": dependencies,
        "total_dependencies": total_deps,
        "build_settings": parsed["build_settings"],
        "confidence_caveat": (
            "parsed from a heuristic byte-range scan around the embedded modinfo marker, not from "
            "`go version -m` itself -- install a 'go' toolchain for an authoritative read"
        ),
    }
    logger.debug("go_buildinfo: finished status=ok (fallback) go_version=%s total_dependencies=%d", go_version, total_deps)
    return {"status": "ok", "tool": "go_buildinfo", **evidence_result(observed, inferred=inferred, unknown=unknown, method="static")}


def _run_nm_symbols(executable: str, file_path: str) -> dict:
    command = [executable, "tool", "nm", file_path]
    logger.debug("go_buildinfo: dispatching go tool nm file_path=%s", file_path)
    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        logger.debug("go_buildinfo: go tool nm timed out after %ss", _TIMEOUT_SECONDS)
        return {"status": "timeout", "tool": "go_buildinfo", "command": command}

    if proc.returncode != 0:
        error = (proc.stderr or proc.stdout or "").strip()
        logger.debug("go_buildinfo: go tool nm failed exit_code=%s stderr_preview=%s", proc.returncode, error[:500])
        return {"status": "error", "tool": "go_buildinfo", "exit_code": proc.returncode, "error": error[-2000:]}

    all_symbols: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3:
            all_symbols.append({"address": parts[0], "type": parts[1], "name": parts[2]})
        elif len(parts) == 2:
            # Undefined symbols print with no address column (" U <name>").
            all_symbols.append({"address": None, "type": parts[0], "name": parts[1]})

    total_symbols = len(all_symbols)
    symbols = all_symbols[:_MAX_LIST_ENTRIES]
    unknown: dict[str, str] = {}
    if total_symbols > _MAX_LIST_ENTRIES:
        unknown["symbols_beyond_limit"] = (
            f"{total_symbols - _MAX_LIST_ENTRIES} more symbols exist but were not listed "
            f"(cap of {_MAX_LIST_ENTRIES}) -- re-run `go tool nm` directly on {file_path} for the rest"
        )

    observed = {"symbols": symbols, "total_symbols": total_symbols}
    logger.debug("go_buildinfo: finished status=ok (nm_symbols) total_symbols=%d", total_symbols)
    return {"status": "ok", "tool": "go_buildinfo", **evidence_result(observed, unknown=unknown, method="static")}


def run_go_buildinfo(params: dict) -> dict:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    path_obj = Path(file_path)
    if path_obj.is_dir():
        raise ValueError(f"file_path is a directory, not a file: {file_path!r}")
    if not path_obj.is_file():
        raise ValueError(f"file_path does not exist: {file_path!r}")

    mode = str(params.get("mode") or "buildinfo").strip()
    if mode not in _VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(_VALID_MODES)}, got {mode!r}")

    executable = _resolve_go()

    if mode == "nm_symbols":
        if executable is None:
            return {
                "status": "tool_unavailable",
                "tool": "go_buildinfo",
                "error": "mode=\"nm_symbols\" requires a 'go' toolchain -- none found on PATH/GO_PATH/custom tools root. mode=\"buildinfo\" (the default) still works without one.",
            }
        return _run_nm_symbols(executable, file_path)

    if executable is not None:
        return _run_version_m(executable, file_path)
    return _run_fallback_scan(file_path)
