"""agent/tools/bundle_runtime_graph.py -- synthesis layer over electron_surface + js_bundle_graph.

Same testing philosophy as test_electron_surface.py: real, from-scratch ASAR archives and real
extracted-directory fixtures, not mocks -- this module does no subprocess/network calls itself.
"""
from __future__ import annotations

import json
import struct

import pytest

from agent.tools.bundle_runtime_graph import (
    _classify_runtime_context,
    _scan_endpoints,
    run_bundle_runtime_graph,
)


def _build_asar(files: dict[str, bytes]) -> bytes:
    tree: dict = {"files": {}}
    blob = b""
    offset = 0
    for name, content in files.items():
        parts = name.split("/")
        node = tree["files"]
        for part in parts[:-1]:
            node = node.setdefault(part, {"files": {}})["files"]
        node[parts[-1]] = {"size": len(content), "offset": str(offset)}
        blob += content
        offset += len(content)
    json_text = json.dumps(tree).encode("utf-8")
    pad = (4 - (len(json_text) % 4)) % 4
    json_padded = json_text + b"\x00" * pad
    payload_bytes = 4 + len(json_padded)
    header_bytes = payload_bytes + 4
    prefix = struct.pack("<IIII", 4, header_bytes, payload_bytes, len(json_text))
    return prefix + json_padded + blob


# --- _scan_endpoints ---------------------------------------------------------------------------


def test_scan_endpoints_finds_absolute_https_url():
    hits = _scan_endpoints("fetch('https://api.example.com/v1/users')")
    assert "https://api.example.com/v1/users" in hits


def test_scan_endpoints_finds_websocket_url():
    hits = _scan_endpoints("new WebSocket('wss://live.example.com/socket')")
    assert "wss://live.example.com/socket" in hits


def test_scan_endpoints_finds_relative_api_path():
    hits = _scan_endpoints("axios.get('/internal/api/v2/status')")
    assert "/internal/api/v2/status" in hits


def test_scan_endpoints_ignores_text_with_no_endpoint_shape():
    assert _scan_endpoints("const x = 1; console.log('hello world');") == []


# --- _classify_runtime_context -----------------------------------------------------------------


def test_classify_context_bridge_expose_as_preload():
    context, basis = _classify_runtime_context("preload-ish-name.js", [{"kind": "context_bridge_expose", "source": "x", "channel_or_value": "y"}], set())
    assert context == "preload (isolated bridge)"
    assert "contextBridge" in basis


def test_classify_ipc_main_handler_as_main_process():
    context, _ = _classify_runtime_context("main.js", [{"kind": "ipc_main_handler", "source": "x", "channel_or_value": "y"}], set())
    assert context == "main process"


def test_classify_ipc_renderer_call_as_ambiguous():
    context, basis = _classify_runtime_context("app.js", [{"kind": "ipc_renderer_call", "source": "x", "channel_or_value": "y"}], set())
    assert context == "renderer or preload (ambiguous)"
    assert "ambiguous" in basis.lower() or "can't disambiguate" in basis


def test_classify_preload_target_reference_wins_even_without_own_ipc_calls():
    context, basis = _classify_runtime_context("bridge.js", [], {"bridge.js"})
    assert context == "preload (isolated bridge)"
    assert "webPreferences.preload" in basis


def test_classify_unclassified_file():
    context, _ = _classify_runtime_context("utils.js", [], set())
    assert context == "unclassified"


# --- run_bundle_runtime_graph: validation -------------------------------------------------------


def test_run_bundle_runtime_graph_requires_app_path():
    with pytest.raises(ValueError, match="app_path"):
        run_bundle_runtime_graph({})


def test_run_bundle_runtime_graph_rejects_missing_path():
    with pytest.raises(ValueError, match="does not exist"):
        run_bundle_runtime_graph({"app_path": "/does/not/exist.asar"})


# --- run_bundle_runtime_graph: real ASAR fixture ------------------------------------------------


def test_run_bundle_runtime_graph_classifies_main_preload_and_endpoints_in_a_real_asar(tmp_path):
    main_js = b"""
const { ipcMain, BrowserWindow } = require('electron');
ipcMain.handle('app:getVersion', async () => '1.0.0');
function createWindow() {
    return new BrowserWindow({ webPreferences: { preload: 'preload.js' } });
}
"""
    preload_js = b"""
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('electronAPI', {
    getVersion: () => ipcRenderer.invoke('app:getVersion'),
    reportHome: () => fetch('https://telemetry.example.com/api/report'),
});
"""
    archive = _build_asar({"main.js": main_js, "preload.js": preload_js, "package.json": b'{"main":"main.js"}'})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)

    result = run_bundle_runtime_graph({"app_path": str(asar_path)})

    assert result["status"] == "ok"
    nodes_by_file = {n["file"]: n for n in result["observed"]["nodes"]}

    assert nodes_by_file["main.js"]["runtime_context"] == "main process"
    assert nodes_by_file["preload.js"]["runtime_context"] == "preload (isolated bridge)"
    assert "https://telemetry.example.com/api/report" in nodes_by_file["preload.js"]["endpoints_referenced"]
    assert result["observed"]["runtime_context_counts"]["main process"] == 1
    assert result["observed"]["runtime_context_counts"]["preload (isolated bridge)"] == 1
    assert "bundle_expansion" in result["unknown"]


def test_run_bundle_runtime_graph_preload_reference_resolves_across_files(tmp_path):
    main_js = b"const { BrowserWindow } = require('electron'); new BrowserWindow({ webPreferences: { preload: './bridge.js' } });"
    bridge_js = b"const { contextBridge } = require('electron');"  # no contextBridge CALL here, just referenced by filename
    archive = _build_asar({"main.js": main_js, "bridge.js": bridge_js})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)

    result = run_bundle_runtime_graph({"app_path": str(asar_path)})

    nodes_by_file = {n["file"]: n for n in result["observed"]["nodes"]}
    assert nodes_by_file["bridge.js"]["runtime_context"] == "preload (isolated bridge)"
    assert "webPreferences.preload" in nodes_by_file["bridge.js"]["runtime_context_basis"]


# --- run_bundle_runtime_graph: real extracted-directory fixture, including bundle expansion -----


def test_run_bundle_runtime_graph_works_on_an_extracted_directory(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.js").write_text("ipcMain.on('window:close', () => {});")

    result = run_bundle_runtime_graph({"app_path": str(app_dir)})

    assert result["status"] == "ok"
    nodes_by_file = {n["file"]: n for n in result["observed"]["nodes"]}
    assert nodes_by_file["main.js"]["runtime_context"] == "main process"


def test_run_bundle_runtime_graph_expands_a_real_webpack_bundle_with_sourcemap(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()

    # A real (if minimal) source-map v3 document for one generated line mapping to one original
    # file, built by hand per the spec -- mirrors test_js_bundle_graph.py's own fixture style.
    original_source = "export function reportEndpoint() {\n  return fetch('https://api.example.com/report');\n}\n"
    source_map = {
        "version": 3,
        "sources": ["src/report.js"],
        "sourcesContent": [original_source],
        "names": [],
        "mappings": "AAAA",
    }
    bundle_js = ("// webpack bootstrap padding to clear the expansion size threshold\n" + ("x" * 25_000) + "\n").encode("utf-8")
    bundle_path = app_dir / "renderer.bundle.js"
    bundle_path.write_bytes(bundle_js)
    (app_dir / "renderer.bundle.js.map").write_text(json.dumps(source_map))

    result = run_bundle_runtime_graph({"app_path": str(app_dir)})

    nodes_by_file = {n["file"]: n for n in result["observed"]["nodes"]}
    node = nodes_by_file["renderer.bundle.js"]
    assert "bundle_expansion" in node
    expansion = node["bundle_expansion"][0]
    assert expansion["source"] == "src/report.js"
    assert "https://api.example.com/report" in expansion["endpoints_referenced"]
