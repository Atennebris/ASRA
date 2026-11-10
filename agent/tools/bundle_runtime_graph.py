"""Synthesis layer over two already-shipped static analyzers, not a reimplementation of either:
`electron_surface.py` (ASAR file tree + IPC/contextBridge surface grep + Electron Fuses) and
`js_bundle_graph.py` (bundle -> original-source reconstruction via source maps). Neither of those
tools on its own answers "which runtime process does this file's code actually run in, and what
does it talk to over the network" -- this module ties their outputs into one per-file graph:
file -> inferred runtime context (main process / preload bridge / renderer / unclassified) ->
endpoint-shaped strings referenced from that file's own text.

Runtime-context classification is PATTERN-BASED, not ground truth -- Electron's real process
model isn't observable from static files alone (the same file's code can behave differently
depending on how it's actually loaded at runtime). It leans on signals already computed by
electron_surface's own IPC/contextBridge grep: `contextBridge.exposeInMainWorld/
exposeInIsolatedWorld` is only ever callable from a preload script, so that call is treated as
strong (observed) evidence; `ipcMain.handle/on` identifies main-process code the same way; a
`preload:` key's own referenced path (found in whichever file configures a BrowserWindow) is
followed to positively tag that OTHER file as the preload script, rather than relying on filename
guessing alone. `ipcRenderer.*` calls are honestly reported as ambiguous (valid in both a preload
script and a sandboxed renderer) rather than guessed at. Every classification carries its own
`basis` string explaining exactly which signal produced it, so the caller can judge confidence
itself instead of trusting an opaque label.

Endpoint extraction here is a SEPARATE, narrower regex pass from native.py's own js_bundle_scan
(which fetches a REMOTE JS URL over HTTP and additionally scans for a fixed set of secret-key
formats) -- this module only ever reads LOCAL files already on disk (an installed app's
resources/app.asar, or an extracted directory) and only ever looks for endpoint-shaped strings
(absolute http(s)/ws(s) URLs, relative "*api*" paths), deliberately not re-doing the secret scan
(that stays js_bundle_scan's own job; run both for full coverage of a given file if it's reachable
both ways).

Bundle expansion (attaching a large .js file's own source-map-reconstructed original files, via
js_bundle_graph, as children of that file's graph node) is only attempted in DIRECTORY mode, not
against raw .asar bytes -- js_bundle_graph needs a real path on disk to resolve a sibling ".map"
file or re-read the bundle text, and extracting every candidate bundle out of a .asar to a temp
file on every run is real, avoidable engineering effort this pass deliberately skips; unpack the
.asar first (e.g. via a real `asar extract`, or reuse electron_surface's own ASAR reader for bulk
extraction, which doesn't exist yet) if bundle expansion is specifically needed against a packed
app -- documented here as an honest scope limit, not silently assumed away.

Live-verified against a real from-scratch ASAR archive and a real extracted-directory fixture
(matching this project's own `test_electron_surface.py` testing style), each with genuine
ipcMain/ipcRenderer/contextBridge calls and endpoint-shaped string literals.
"""
from __future__ import annotations

import re
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.electron_surface import (
    AsarFormatError,
    extract_asar_file,
    read_asar_header,
    run_electron_surface,
)
from agent.tools.js_bundle_graph import run_js_bundle_graph
from agent.tools.re_evidence import evidence_result
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_MAX_FILES_CLASSIFIED = 200
_MAX_ENDPOINTS_PER_FILE = 30
# Each expansion means a full second read + source-map decode pass over one file -- capped so a
# large app with many sizeable bundles can't turn one call into dozens of nested decode passes.
_MAX_BUNDLE_EXPANSIONS = 10
# Heuristic only: a bundle worth expanding is "big enough to plausibly be a built artifact, not a
# small hand-written file" -- js_bundle_graph itself still honestly reports "no sourcemap found"
# for anything that doesn't actually have one, so a wrong guess here costs nothing but one skipped
# call, never a wrong answer.
_BUNDLE_EXPANSION_MIN_BYTES = 20_000

_ABS_URL_RE = re.compile(r'["\'`](https?://[^\s"\'`]{4,300})["\'`]')
_WS_URL_RE = re.compile(r'["\'`](wss?://[^\s"\'`]{4,300})["\'`]')
_RELATIVE_API_RE = re.compile(r'["\'`](/[a-zA-Z0-9_\-./]{0,100}api[a-zA-Z0-9_\-./]{0,100})["\'`]', re.IGNORECASE)
_PRELOAD_FILENAME_HINT_RE = re.compile(r"preload", re.IGNORECASE)


def _scan_endpoints(text: str) -> list[str]:
    hits = sorted(set(_ABS_URL_RE.findall(text)) | set(_WS_URL_RE.findall(text)) | set(_RELATIVE_API_RE.findall(text)))
    return hits[:_MAX_ENDPOINTS_PER_FILE]


def _iter_asar_entries(header: dict) -> list[tuple[str, dict]]:
    """Trivial local flatten of the ASAR header's own nested "files" tree -- the real archive-
    format parsing (header extents, byte offsets) stays reused from electron_surface's own
    read_asar_header/extract_asar_file, this is just a dict walk, not a second format reader."""
    entries: list[tuple[str, dict]] = []

    def _walk(files: dict, parent: str) -> None:
        for name, node in files.items():
            if not isinstance(node, dict):
                continue
            path = f"{parent}/{name}" if parent else name
            if "files" in node and isinstance(node["files"], dict):
                _walk(node["files"], path)
            else:
                entries.append((path, node))

    _walk(header.get("files") or {}, "")
    return entries


def _classify_runtime_context(file_path: str, hits_here: list[dict], preload_targets: set[str]) -> tuple[str, str]:
    kinds = {hit["kind"] for hit in hits_here}
    if file_path in preload_targets or Path(file_path).name in preload_targets:
        return "preload (isolated bridge)", "referenced as a BrowserWindow webPreferences.preload path elsewhere in this app"
    if "context_bridge_expose" in kinds:
        return "preload (isolated bridge)", "calls contextBridge.exposeInMainWorld/exposeInIsolatedWorld, which is only ever callable from a preload script"
    if "ipc_main_handler" in kinds:
        return "main process", "calls ipcMain.handle/handleOnce/on/once"
    if "ipc_renderer_call" in kinds:
        return "renderer or preload (ambiguous)", "calls ipcRenderer.invoke/send/sendSync/on -- valid in both a preload script and a sandboxed renderer, this signal alone can't disambiguate"
    if _PRELOAD_FILENAME_HINT_RE.search(file_path):
        return "preload (isolated bridge, by filename only)", "filename contains 'preload' but no contextBridge/webPreferences.preload reference was observed"
    return "unclassified", "no IPC/contextBridge call and no preload-path reference observed in this file"


def _expand_bundle(real_path: Path, node: dict, expansions_done: list[int]) -> None:
    if expansions_done[0] >= _MAX_BUNDLE_EXPANSIONS:
        return
    try:
        size = real_path.stat().st_size
    except OSError:
        return
    if size < _BUNDLE_EXPANSION_MIN_BYTES:
        return
    expansions_done[0] += 1
    bundle_result = run_js_bundle_graph({"bundle_path": str(real_path)})
    sources = (bundle_result.get("observed") or {}).get("sources") or []
    if not sources:
        return
    expanded = []
    for src in sources:
        src_entry: dict = {"source": src["source"], "structure": src.get("structure")}
        preview = src.get("content_preview")
        if preview:
            endpoints = _scan_endpoints(preview)
            if endpoints:
                src_entry["endpoints_referenced"] = endpoints
        expanded.append(src_entry)
    node["bundle_expansion"] = expanded


def run_bundle_runtime_graph(params: dict) -> dict:
    app_path_raw = validate_safe_value(str(params.get("app_path") or "").strip())
    if not app_path_raw:
        raise ValueError("run_bundle_runtime_graph requires an 'app_path' parameter (a .asar file, or an extracted app directory) -- same shape as electron_surface.")
    app_path = Path(app_path_raw)
    if not app_path.exists():
        raise ValueError(f"app_path does not exist: {app_path_raw!r}")

    surface_result = run_electron_surface(params)
    if surface_result.get("status") != "ok":
        return {"status": "error", "tool": "bundle_runtime_graph", "error": f"electron_surface could not analyze this app_path, nothing to synthesize: {surface_result.get('error')}"}
    surface_observed = surface_result.get("observed") or {}
    surface_hits = surface_observed.get("ipc_contextbridge_surface") or []

    hits_by_file: dict[str, list[dict]] = {}
    for hit in surface_hits:
        hits_by_file.setdefault(hit["source"], []).append(hit)

    preload_targets = {
        hit["channel_or_value"] for hit in surface_hits
        if hit["kind"] == "preload_reference" and hit.get("channel_or_value")
    }
    preload_targets |= {Path(p).name for p in preload_targets}

    nodes: list[dict] = []
    unknown: dict[str, str] = {}
    expansions_done = [0]
    bundle_expansion_attempted = False

    if app_path.is_file() and app_path.suffix == ".asar":
        try:
            header = read_asar_header(app_path)
        except AsarFormatError as exc:
            return {"status": "error", "tool": "bundle_runtime_graph", "error": f"could not parse {app_path_raw!r} as an ASAR archive: {exc}"}
        entries = _iter_asar_entries(header)
        for file_path, meta in entries[:_MAX_FILES_CLASSIFIED]:
            context, basis = _classify_runtime_context(file_path, hits_by_file.get(file_path, []), preload_targets)
            node = {
                "file": file_path,
                "runtime_context": context,
                "runtime_context_basis": basis,
                "ipc_contextbridge_hits": len(hits_by_file.get(file_path, [])),
            }
            if file_path.endswith((".js", ".json")) and "size" in meta:
                try:
                    text = extract_asar_file(app_path, header, file_path).decode("utf-8", errors="replace")
                except (AsarFormatError, UnicodeDecodeError):
                    text = None
                if text:
                    endpoints = _scan_endpoints(text)
                    if endpoints:
                        node["endpoints_referenced"] = endpoints
            nodes.append(node)
        if len(entries) > _MAX_FILES_CLASSIFIED:
            unknown["files_beyond_limit"] = f"{len(entries) - _MAX_FILES_CLASSIFIED} more file(s) in the archive but not classified here (cap of {_MAX_FILES_CLASSIFIED})"
        unknown["bundle_expansion"] = "not attempted against a packed .asar in this pass -- js_bundle_graph needs a real file on disk per bundle; extract the archive to a directory first and re-run against that directory for sourcemap-based expansion of any large bundle inside it"
    elif app_path.is_dir():
        js_files = sorted(p for p in app_path.rglob("*.js") if "node_modules" not in p.parts)
        for js_file in js_files[:_MAX_FILES_CLASSIFIED]:
            rel_path = str(js_file.relative_to(app_path))
            context, basis = _classify_runtime_context(rel_path, hits_by_file.get(rel_path, []), preload_targets)
            node = {
                "file": rel_path,
                "runtime_context": context,
                "runtime_context_basis": basis,
                "ipc_contextbridge_hits": len(hits_by_file.get(rel_path, [])),
            }
            try:
                text = js_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = None
            if text:
                endpoints = _scan_endpoints(text)
                if endpoints:
                    node["endpoints_referenced"] = endpoints
                bundle_expansion_attempted = True
                _expand_bundle(js_file, node, expansions_done)
            nodes.append(node)
        if len(js_files) > _MAX_FILES_CLASSIFIED:
            unknown["files_beyond_limit"] = f"{len(js_files) - _MAX_FILES_CLASSIFIED} more .js file(s) under this directory but not classified here (cap of {_MAX_FILES_CLASSIFIED})"
        if bundle_expansion_attempted and expansions_done[0] >= _MAX_BUNDLE_EXPANSIONS:
            unknown["bundle_expansion_beyond_limit"] = f"stopped attempting sourcemap-based bundle expansion after {_MAX_BUNDLE_EXPANSIONS} file(s) -- more large .js files exist under this directory than that cap"
    else:
        return {"status": "error", "tool": "bundle_runtime_graph", "error": f"app_path must be a .asar file or a directory, got {app_path_raw!r}"}

    context_counts: dict[str, int] = {}
    for node in nodes:
        context_counts[node["runtime_context"]] = context_counts.get(node["runtime_context"], 0) + 1

    observed = {
        "app_path": str(app_path),
        "total_files_classified": len(nodes),
        "runtime_context_counts": context_counts,
        "nodes": nodes,
    }
    logger.debug(
        "bundle_runtime_graph: app_path=%s files_classified=%d contexts=%s",
        app_path, len(nodes), context_counts,
    )
    return {"status": "ok", "tool": "bundle_runtime_graph", **evidence_result(observed, unknown=unknown, method="static")}
