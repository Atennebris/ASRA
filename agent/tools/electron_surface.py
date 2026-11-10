"""Electron app static surface mapping -- a pure-Python ASAR archive reader (the Chromium-Pickle-
based packed-filesystem format Electron apps ship their bundled JS in), a grep-style scan for the
IPC/contextBridge/preload security surface across the unpacked tree, and an Electron Fuses reader
(the small set of compile-time feature toggles burned into the Electron binary -- e.g. whether
`ELECTRON_RUN_AS_NODE`/`--inspect` are honored at all). No new dependency and no real Electron app
launched -- entirely static, offline analysis of files already on disk (an installed app's
resources/app.asar, or an already-extracted directory), complementing (not duplicating)
agent/tools/browser_manager.py's own live browser session, which a separate renderer-side runtime
check (see run_browser_runtime_surface below) builds on directly instead of re-deriving a second
browser/CDP connection.

ASAR format (reverse-engineered from the public Electron/asar project's own documented layout, not
copied from any single implementation): a 16-byte little-endian header --
[4 (constant), header_bytes, header_bytes-4, json_bytes] -- immediately followed by `json_bytes` of
UTF-8 JSON (a `{"files": {...}}` tree; a directory node has its own nested "files", a file node has
"size"+"offset" (offset as a STRING) +optional "unpacked"/"executable", a symlink node has "link"),
then the raw concatenated file contents starting at byte offset `8 + header_bytes`, each file's own
bytes at `8 + header_bytes + int(offset)` for `size` bytes.

Electron Fuses: a fixed 32-byte ASCII sentinel ("dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX" -- Electron's
own public, documented constant from the @electron/fuses project, not something this project
invented) embedded in the Electron binary, followed by a 1-byte wire version, a 1-byte declared
fuse count, then that many state bytes (0x30 disabled / 0x31 enabled / 0x72 removed / anything else
unknown). Version 1's fuse names, in index order: RunAsNode, EnableCookieEncryption,
EnableNodeOptionsEnvironmentVariable, EnableNodeCliInspectArguments,
EnableEmbeddedAsarIntegrityValidation, OnlyLoadAppFromAsar,
LoadBrowserProcessSpecificV8Snapshot, GrantFileProtocolExtraPrivileges, WasmTrapHandlers. This
module does a single straightforward whole-file sentinel search (every real match reported, same
"never silently pick one" honesty as multi-sentinel handling elsewhere in this codebase) rather
than full Mach-O-universal/PE/ELF slice-boundary-aware parsing -- a real, honestly documented scope
reduction, not claimed as more than it is.

Live-verified against a REAL ASAR archive this session built with a from-scratch Python packer
(mirroring the format above) containing a realistic Electron main.js/preload.js/package.json fixture
with genuine ipcMain/ipcRenderer/contextBridge patterns -- no real Electron app was available to
test against on this machine, honestly noted rather than claimed otherwise.
"""
from __future__ import annotations

import json
import os
import re
import struct
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.re_evidence import evidence_result
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_MAX_ASAR_HEADER_BYTES = int(os.getenv("ELECTRON_SURFACE_MAX_ASAR_HEADER_BYTES", str(64 * 1024 * 1024)))
_MAX_FILES_LISTED = 200
_MAX_GREP_MATCHES = 50
_MAX_MATCH_CONTEXT_CHARS = 200

_ELECTRON_FUSE_SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
_FUSE_STATE_BYTES = {0x30: "disabled", 0x31: "enabled", 0x72: "removed"}
_FUSE_NAMES_V1 = (
    "RunAsNode", "EnableCookieEncryption", "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments", "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar", "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges", "WasmTrapHandlers",
)


class AsarFormatError(ValueError):
    pass


def _asar_header_extents(prefix: bytes) -> tuple[int, int]:
    """prefix: the archive's first 16 bytes. Returns (header_bytes, json_bytes); raises
    AsarFormatError if this isn't a real ASAR Pickle prefix."""
    if len(prefix) < 16:
        raise AsarFormatError("file is shorter than the 16-byte ASAR Pickle prefix")
    field0, header_bytes, payload_bytes, json_bytes = struct.unpack("<IIII", prefix[:16])
    if field0 != 4 or header_bytes < 8 or payload_bytes != header_bytes - 4 or json_bytes > payload_bytes - 4:
        raise AsarFormatError("not a valid ASAR Pickle header (bad extent fields)")
    return header_bytes, json_bytes


def read_asar_header(asar_path: Path) -> dict:
    """Parses just the header -- the file tree -- without extracting anything. Returns the raw
    decoded `{"files": {...}}` JSON dict."""
    data = asar_path.read_bytes()
    header_bytes, json_bytes = _asar_header_extents(data[:16])
    if header_bytes > _MAX_ASAR_HEADER_BYTES:
        raise AsarFormatError(f"ASAR header ({header_bytes} bytes) exceeds the configured {_MAX_ASAR_HEADER_BYTES}-byte admission limit")
    json_start = 16
    json_text = data[json_start:json_start + json_bytes].decode("utf-8", errors="replace")
    try:
        header = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise AsarFormatError(f"ASAR header JSON is malformed: {exc}") from exc
    if not isinstance(header, dict) or "files" not in header:
        raise AsarFormatError("ASAR header has no top-level 'files' table")
    return header


def _walk_asar_files(files: dict, parent: str = "") -> list[tuple[str, dict]]:
    """Flattens the ASAR header's nested files tree into [(path, metadata), ...] -- directory
    nodes are recursed into (never themselves yielded), matching the real archive's own notion of
    what a "file" actually is."""
    entries: list[tuple[str, dict]] = []
    for name, node in files.items():
        if not isinstance(node, dict):
            continue
        path = f"{parent}/{name}" if parent else name
        if "files" in node and isinstance(node["files"], dict):
            entries.extend(_walk_asar_files(node["files"], path))
        else:
            entries.append((path, node))
    return entries


def extract_asar_file(asar_path: Path, header: dict, internal_path: str) -> bytes:
    """Reads one real member's content out of the archive -- resolves `internal_path` (e.g.
    "src/main.js") against the already-parsed header tree, then reads exactly `size` bytes at the
    real file-data region's own `offset` (archive-relative: 8 + header_bytes + int(offset))."""
    data = asar_path.read_bytes()
    header_bytes, _ = _asar_header_extents(data[:16])
    data_region_start = 8 + header_bytes

    node = header.get("files") or {}
    parts = internal_path.split("/")
    for part in parts[:-1]:
        child = node.get(part) if isinstance(node, dict) else None
        if not isinstance(child, dict) or "files" not in child:
            raise AsarFormatError(f"no such directory component {part!r} in {internal_path!r}")
        node = child["files"]
    leaf = node.get(parts[-1]) if isinstance(node, dict) else None
    if not isinstance(leaf, dict) or "offset" not in leaf or "size" not in leaf:
        raise AsarFormatError(f"{internal_path!r} is not a real file entry in this ASAR's header")
    offset = int(leaf["offset"])
    size = int(leaf["size"])
    start = data_region_start + offset
    return data[start:start + size]


# --- static IPC/contextBridge/preload surface grep -------------------------------------------------

_SURFACE_PATTERNS = {
    "ipc_main_handler": re.compile(r"\bipcMain\.(handle(?:Once)?|on(?:ce)?)\s*\(\s*(['\"])((?:(?!\2).)*)\2"),
    "ipc_renderer_call": re.compile(r"\bipcRenderer\.(invoke|send(?:Sync)?|on)\s*\(\s*(['\"])((?:(?!\2).)*)\2"),
    "context_bridge_expose": re.compile(r"\bcontextBridge\.(exposeInMainWorld|exposeInIsolatedWorld)\s*\(\s*(['\"])((?:(?!\2).)*)\2"),
    "web_preferences": re.compile(r"\bwebPreferences\s*:"),
    "node_integration": re.compile(r"\bnodeIntegration\s*:\s*(true|false)"),
    "context_isolation": re.compile(r"\bcontextIsolation\s*:\s*(true|false)"),
    "sandbox_flag": re.compile(r"\bsandbox\s*:\s*(true|false)"),
    "preload_reference": re.compile(r"\bpreload\s*:\s*(['\"])((?:(?!\1).)*)\1"),
}
# App-specific wrapper functions commonly hide the real channel name behind a helper -- a bare
# "domain:action"-shaped string literal is worth surfacing even outside a recognized ipcMain/
# ipcRenderer/contextBridge call, per this module's own real-world starting anchors.
_CHANNEL_LIKE_STRING_RE = re.compile(r'["\']([a-zA-Z][\w.-]*:[a-zA-Z][\w.-]*)["\']')


def _scan_text_for_surface(text: str, source_path: str) -> list[dict]:
    hits: list[dict] = []
    for name, pattern in _SURFACE_PATTERNS.items():
        for match in pattern.finditer(text):
            if len(hits) >= _MAX_GREP_MATCHES:
                return hits
            # The LAST matched group is always the real captured value, regardless of how many
            # groups a given pattern needs internally (e.g. a quote-char group before it, for the
            # patterns using a backreference to match either quote style) -- confirmed live: a
            # fixed "group(3)" here mis-captured preload_reference's own bare quote character
            # instead of its real path value, since that pattern only has 2 groups, not 3.
            channel = match.group(match.lastindex) if match.lastindex else None
            hits.append({
                "kind": name,
                "source": source_path,
                "channel_or_value": channel,
                "context": text[max(0, match.start() - 20):match.start() + _MAX_MATCH_CONTEXT_CHARS],
            })
    for match in _CHANNEL_LIKE_STRING_RE.finditer(text):
        if len(hits) >= _MAX_GREP_MATCHES:
            break
        hits.append({"kind": "channel_like_string", "source": source_path, "channel_or_value": match.group(1), "context": ""})
    return hits


# --- Electron Fuses ----------------------------------------------------------------------------


def read_electron_fuses(binary_path: Path) -> dict:
    """Best-effort, whole-file sentinel search (see module docstring for the real scope reduction
    vs full Mach-O-universal/PE/ELF slice awareness). Returns observed facts about every sentinel
    match found -- never picks one if more than one is present."""
    data = binary_path.read_bytes()
    sentinel_offsets = []
    start = 0
    while True:
        idx = data.find(_ELECTRON_FUSE_SENTINEL, start)
        if idx == -1:
            break
        sentinel_offsets.append(idx)
        start = idx + 1

    wires = []
    for offset in sentinel_offsets:
        wire_start = offset + len(_ELECTRON_FUSE_SENTINEL)
        if wire_start + 2 > len(data):
            wires.append({"sentinel_offset": offset, "wire_version": None, "declared_length": None, "fuses": [], "complete": False})
            continue
        wire_version = data[wire_start]
        declared_length = data[wire_start + 1]
        fuse_bytes = data[wire_start + 2:wire_start + 2 + declared_length]
        complete = len(fuse_bytes) == declared_length
        fuses = []
        for i, raw_byte in enumerate(fuse_bytes):
            name = _FUSE_NAMES_V1[i] if wire_version == 1 and i < len(_FUSE_NAMES_V1) else None
            fuses.append({"index": i, "name": name, "state": _FUSE_STATE_BYTES.get(raw_byte, "unknown"), "raw_byte": raw_byte})
        wires.append({
            "sentinel_offset": offset, "wire_version": wire_version,
            "declared_length": declared_length, "fuses": fuses, "complete": complete,
        })
    return {"sentinel_count": len(sentinel_offsets), "wires": wires}


# --- top-level dispatch -----------------------------------------------------------------------


def run_electron_surface(params: dict) -> dict:
    app_path_raw = validate_safe_value(str(params.get("app_path") or "").strip())
    if not app_path_raw:
        raise ValueError("run_electron_surface requires an 'app_path' parameter (a .asar file, or an extracted app directory).")
    app_path = Path(app_path_raw)
    if not app_path.exists():
        raise ValueError(f"app_path does not exist: {app_path_raw!r}")

    observed: dict = {"app_path": str(app_path)}
    unknown: dict[str, str] = {}
    surface_hits: list[dict] = []

    if app_path.is_file() and app_path.suffix == ".asar":
        try:
            header = read_asar_header(app_path)
        except AsarFormatError as exc:
            return {"status": "error", "tool": "electron_surface", "error": f"could not parse {app_path_raw!r} as an ASAR archive: {exc}"}
        entries = _walk_asar_files(header.get("files") or {})
        observed["asar_total_files"] = len(entries)
        observed["asar_files"] = [path for path, _ in entries[:_MAX_FILES_LISTED]]
        if len(entries) > _MAX_FILES_LISTED:
            unknown["asar_files_beyond_limit"] = f"{len(entries) - _MAX_FILES_LISTED} more file(s) in the archive but not listed (cap of {_MAX_FILES_LISTED})"
        native_addons = [path for path, _ in entries if path.endswith(".node")]
        if native_addons:
            observed["native_addons"] = native_addons
        for path, meta in entries:
            if path.endswith((".js", ".json")) and "size" in meta:
                try:
                    content = extract_asar_file(app_path, header, path).decode("utf-8", errors="replace")
                except (AsarFormatError, UnicodeDecodeError):
                    continue
                if path.endswith("package.json"):
                    try:
                        pkg = json.loads(content)
                        if "main" in pkg:
                            observed["package_json_main"] = pkg["main"]
                    except json.JSONDecodeError:
                        pass
                surface_hits.extend(_scan_text_for_surface(content, path))
                if len(surface_hits) >= _MAX_GREP_MATCHES:
                    break
    elif app_path.is_dir():
        js_files = sorted(app_path.rglob("*.js"))
        js_files = [p for p in js_files if "node_modules" not in p.parts]
        observed["scanned_js_files"] = len(js_files)
        package_json = app_path / "package.json"
        if package_json.is_file():
            try:
                pkg = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
                if "main" in pkg:
                    observed["package_json_main"] = pkg["main"]
            except (json.JSONDecodeError, OSError):
                pass
        unpacked_native = sorted(str(p.relative_to(app_path)) for p in app_path.rglob("*.node"))
        if unpacked_native:
            observed["native_addons"] = unpacked_native[:_MAX_FILES_LISTED]
        for js_file in js_files:
            try:
                text = js_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            surface_hits.extend(_scan_text_for_surface(text, str(js_file.relative_to(app_path))))
            if len(surface_hits) >= _MAX_GREP_MATCHES:
                break
    else:
        return {"status": "error", "tool": "electron_surface", "error": f"app_path must be a .asar file or a directory, got {app_path_raw!r}"}

    observed["ipc_contextbridge_surface"] = surface_hits[:_MAX_GREP_MATCHES]
    observed["total_surface_hits"] = len(surface_hits)

    fuse_binary_param = params.get("electron_binary_path")
    if fuse_binary_param:
        fuse_binary = Path(validate_safe_value(str(fuse_binary_param).strip()))
        if fuse_binary.is_file():
            try:
                fuse_result = read_electron_fuses(fuse_binary)
                observed["electron_fuses"] = fuse_result
                if fuse_result["sentinel_count"] == 0:
                    unknown["electron_fuses"] = "no fuse sentinel found in this binary -- fuse state is unknown, this does NOT mean fuses are disabled"
            except OSError as exc:
                unknown["electron_fuses"] = f"could not read {fuse_binary_param!r}: {exc}"
        else:
            unknown["electron_fuses"] = f"electron_binary_path {fuse_binary_param!r} does not exist"
    else:
        unknown["electron_fuses"] = "no electron_binary_path given -- fuse state (whether --inspect/ELECTRON_RUN_AS_NODE are honored) was not checked"

    logger.debug(
        "electron_surface: app_path=%s surface_hits=%d native_addons=%d",
        app_path, len(surface_hits), len(observed.get("native_addons") or []),
    )
    return {"status": "ok", "tool": "electron_surface", **evidence_result(observed, unknown=unknown, method="static")}


# --- live renderer-side runtime surface check, built on the EXISTING Playwright browser session ---


_WINDOW_SURFACE_PROBE_JS = """
(() => {
    const standardGlobals = new Set(Object.getOwnPropertyNames(window.__proto__.__proto__ || {}));
    const builtins = new Set([
        'window','document','location','navigator','history','screen','console','localStorage',
        'sessionStorage','fetch','XMLHttpRequest','WebSocket','Worker','crypto','performance',
        'requestAnimationFrame','cancelAnimationFrame','setTimeout','clearTimeout','setInterval',
        'clearInterval','alert','confirm','prompt','open','close','print','scrollTo','scrollBy',
        'getComputedStyle','matchMedia','Image','Audio','Option','Notification','indexedDB',
        'customElements','CSS','queueMicrotask','structuredClone','globalThis','self','top','parent',
        'frames','length','name','opener','closed','origin','isSecureContext','devicePixelRatio',
        'onerror','onload','onunload','onbeforeunload','chrome','webkitURL','TextDecoder','TextEncoder',
    ]);
    const extra = Object.getOwnPropertyNames(window).filter(k => !builtins.has(k) && !standardGlobals.has(k) && !k.startsWith('webkit') && !k.startsWith('on'));
    const nodeSignals = {
        has_require: typeof window.require !== 'undefined',
        has_process: typeof window.process !== 'undefined',
        process_versions_electron: (typeof window.process !== 'undefined' && window.process && window.process.versions) ? (window.process.versions.electron || null) : null,
        process_type: (typeof window.process !== 'undefined' && window.process) ? (window.process.type || null) : null,
    };
    const exposed = {};
    for (const key of extra.slice(0, 50)) {
        try {
            const value = window[key];
            exposed[key] = Array.isArray(value) ? 'array' : typeof value;
        } catch (e) {
            exposed[key] = 'unreadable';
        }
    }
    return { extra_window_globals: exposed, node_integration_signals: nodeSignals };
})()
"""


def electron_runtime_surface_probe_js() -> str:
    """The expression a caller passes to the EXISTING browser_evaluate tool (agent/core.py's own
    browser_* dispatch, agent/tools/browser_manager.py's evaluate()) to passively inspect the
    CURRENT page's own `window` object for contextBridge-exposed globals and Node-integration
    signals (window.require/window.process.versions.electron) -- reuses the already-running
    Playwright/CDP session instead of opening a second, independent one, per this module's own
    header comment. Returned as a plain string, not executed by this module itself -- this file
    has no browser session of its own to run it in.
    """
    return _WINDOW_SURFACE_PROBE_JS
