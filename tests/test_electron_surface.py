"""agent/tools/electron_surface.py -- pure-Python ASAR reader, IPC/contextBridge static surface
grep, and Electron Fuses reader.

All tests build real, from-scratch ASAR archives and fuse-wire binaries (the same byte layout this
module's own header comment documents), not mocks -- this module does no subprocess/network calls
at all, so exercising the real parsing logic end to end is both correct AND fast.
"""
from __future__ import annotations

import json
import struct

import pytest

from agent.tools.electron_surface import (
    AsarFormatError,
    _ELECTRON_FUSE_SENTINEL,
    _scan_text_for_surface,
    electron_runtime_surface_probe_js,
    extract_asar_file,
    read_asar_header,
    read_electron_fuses,
    run_electron_surface,
)


def _build_asar(files: dict[str, bytes]) -> bytes:
    """files: {"a/b/c.js": b"..."} -- builds a REAL nested ASAR tree (one "files" dict per path
    component, matching the actual archive format), not a flat tree with slashes in the key."""
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


# --- ASAR header/extraction ------------------------------------------------------------------------


def test_read_asar_header_recovers_the_real_file_tree(tmp_path):
    archive = _build_asar({"main.js": b"console.log(1);", "package.json": b'{"main":"main.js"}'})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)

    header = read_asar_header(asar_path)

    assert set(header["files"].keys()) == {"main.js", "package.json"}


def test_extract_asar_file_recovers_exact_original_bytes(tmp_path):
    archive = _build_asar({"main.js": b"const secret = 'AKIAABCDEFGHIJKLMNOP';\n"})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)
    header = read_asar_header(asar_path)

    content = extract_asar_file(asar_path, header, "main.js")

    assert content == b"const secret = 'AKIAABCDEFGHIJKLMNOP';\n"


def test_extract_asar_file_handles_nested_directories(tmp_path):
    archive = _build_asar({"src/lib/util.js": b"export const x = 1;"})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)
    header = read_asar_header(asar_path)

    content = extract_asar_file(asar_path, header, "src/lib/util.js")

    assert content == b"export const x = 1;"


def test_read_asar_header_rejects_a_non_asar_file(tmp_path):
    not_asar = tmp_path / "not.asar"
    not_asar.write_bytes(b"this is not an asar archive at all, just plain bytes")

    with pytest.raises(AsarFormatError):
        read_asar_header(not_asar)


def test_extract_asar_file_rejects_an_unknown_path(tmp_path):
    archive = _build_asar({"main.js": b"x"})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)
    header = read_asar_header(asar_path)

    with pytest.raises(AsarFormatError):
        extract_asar_file(asar_path, header, "does/not/exist.js")


# --- run_electron_surface: dispatch + surface grep -------------------------------------------------


def test_run_electron_surface_requires_app_path():
    with pytest.raises(ValueError, match="app_path"):
        run_electron_surface({})


def test_run_electron_surface_rejects_a_missing_path():
    with pytest.raises(ValueError, match="does not exist"):
        run_electron_surface({"app_path": "/does/not/exist.asar"})


def test_run_electron_surface_detects_ipc_and_context_bridge_in_a_real_asar(tmp_path):
    main_js = b"""
const { ipcMain } = require('electron');
ipcMain.handle('app:getVersion', async () => '1.0.0');
"""
    preload_js = b"""
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('electronAPI', {
    getVersion: () => ipcRenderer.invoke('app:getVersion'),
});
"""
    archive = _build_asar({"main.js": main_js, "preload.js": preload_js, "package.json": b'{"main":"main.js"}'})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)

    result = run_electron_surface({"app_path": str(asar_path)})

    assert result["status"] == "ok"
    assert result["observed"]["package_json_main"] == "main.js"
    kinds = {h["kind"] for h in result["observed"]["ipc_contextbridge_surface"]}
    assert "ipc_main_handler" in kinds
    assert "ipc_renderer_call" in kinds
    assert "context_bridge_expose" in kinds
    channels = {h["channel_or_value"] for h in result["observed"]["ipc_contextbridge_surface"]}
    assert "app:getVersion" in channels
    assert "electronAPI" in channels


def test_run_electron_surface_detects_native_addons(tmp_path):
    archive = _build_asar({"main.js": b"x", "build/native.node": b"\x7fELF-fake-native-addon"})
    asar_path = tmp_path / "app.asar"
    asar_path.write_bytes(archive)

    result = run_electron_surface({"app_path": str(asar_path)})

    assert "build/native.node" in result["observed"]["native_addons"]


def test_run_electron_surface_works_on_an_extracted_directory_not_just_asar(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "package.json").write_text('{"main": "main.js"}')
    (app_dir / "main.js").write_text("ipcMain.on('window:close', () => {});")

    result = run_electron_surface({"app_path": str(app_dir)})

    assert result["status"] == "ok"
    assert result["observed"]["package_json_main"] == "main.js"
    kinds = {h["kind"] for h in result["observed"]["ipc_contextbridge_surface"]}
    assert "ipc_main_handler" in kinds


def test_run_electron_surface_extracted_directory_skips_node_modules(tmp_path):
    app_dir = tmp_path / "app"
    (app_dir / "node_modules" / "some-dep").mkdir(parents=True)
    (app_dir / "node_modules" / "some-dep" / "index.js").write_text("ipcMain.handle('vendor:thing', () => {});")
    app_dir.mkdir(exist_ok=True)
    (app_dir / "main.js").write_text("console.log('real app code');")

    result = run_electron_surface({"app_path": str(app_dir)})

    sources = {h["source"] for h in result["observed"]["ipc_contextbridge_surface"]}
    assert not any("node_modules" in s for s in sources)


def test_run_electron_surface_without_electron_binary_path_marks_fuses_unknown(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.js").write_text("console.log(1);")

    result = run_electron_surface({"app_path": str(app_dir)})

    assert "electron_fuses" in result["unknown"]
    assert "electron_fuses" not in result["observed"]


# --- read_electron_fuses ---------------------------------------------------------------------------


def test_read_electron_fuses_decodes_a_real_wire(tmp_path):
    fuses = bytes([0x30, 0x31, 0x30, 0x31, 0x31, 0x31, 0x30, 0x30, 0x31])
    wire = bytes([1, len(fuses)]) + fuses
    data = b"PADDING_BEFORE" + _ELECTRON_FUSE_SENTINEL + wire + b"PADDING_AFTER"
    binary = tmp_path / "electron_fake"
    binary.write_bytes(data)

    result = read_electron_fuses(binary)

    assert result["sentinel_count"] == 1
    wire_result = result["wires"][0]
    assert wire_result["wire_version"] == 1
    assert wire_result["complete"] is True
    assert wire_result["fuses"][0] == {"index": 0, "name": "RunAsNode", "state": "disabled", "raw_byte": 0x30}
    assert wire_result["fuses"][3] == {"index": 3, "name": "EnableNodeCliInspectArguments", "state": "enabled", "raw_byte": 0x31}
    assert wire_result["fuses"][8] == {"index": 8, "name": "WasmTrapHandlers", "state": "enabled", "raw_byte": 0x31}


def test_read_electron_fuses_reports_zero_sentinels_honestly(tmp_path):
    binary = tmp_path / "no_fuses"
    binary.write_bytes(b"just a plain binary with no sentinel anywhere in it")

    result = read_electron_fuses(binary)

    assert result["sentinel_count"] == 0
    assert result["wires"] == []


def test_read_electron_fuses_reports_every_sentinel_never_picks_one(tmp_path):
    fuses = bytes([0x31])
    wire = bytes([1, 1]) + fuses
    data = (_ELECTRON_FUSE_SENTINEL + wire) * 2
    binary = tmp_path / "double_sentinel"
    binary.write_bytes(data)

    result = read_electron_fuses(binary)

    assert result["sentinel_count"] == 2
    assert len(result["wires"]) == 2


def test_read_electron_fuses_handles_a_truncated_wire(tmp_path):
    binary = tmp_path / "truncated"
    binary.write_bytes(b"xxx" + _ELECTRON_FUSE_SENTINEL + bytes([1]))  # version byte only, no length/fuses

    result = read_electron_fuses(binary)

    assert result["sentinel_count"] == 1
    assert result["wires"][0]["complete"] is False


def test_run_electron_surface_reads_fuses_when_binary_given(tmp_path):
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "main.js").write_text("console.log(1);")
    fuses = bytes([0x31] * 9)
    wire = bytes([1, 9]) + fuses
    binary = tmp_path / "Electron"
    binary.write_bytes(_ELECTRON_FUSE_SENTINEL + wire)

    result = run_electron_surface({"app_path": str(app_dir), "electron_binary_path": str(binary)})

    assert result["observed"]["electron_fuses"]["sentinel_count"] == 1
    assert "electron_fuses" not in result["unknown"]


# --- _scan_text_for_surface: the group-index fix regression --------------------------------------


def test_scan_text_preload_reference_captures_the_real_value_not_the_quote_char():
    """Real, confirmed bug this guards against: a naive fixed group(3) extraction mis-captured
    this pattern's own quote character instead of its actual value, since preload_reference only
    has 2 regex groups, not 3 like the ipcMain/ipcRenderer/contextBridge patterns."""
    hits = _scan_text_for_surface("webPreferences: { preload: 'my-preload.js' }", "main.js")
    preload_hit = next(h for h in hits if h["kind"] == "preload_reference")
    assert preload_hit["channel_or_value"] == "my-preload.js"


def test_scan_text_finds_channel_like_string_literals_outside_known_calls():
    hits = _scan_text_for_surface("const CHANNEL = 'domain:action';", "app.js")
    assert any(h["kind"] == "channel_like_string" and h["channel_or_value"] == "domain:action" for h in hits)


# --- electron_runtime_surface_probe_js --------------------------------------------------------------


def test_runtime_surface_probe_js_is_a_nonempty_self_contained_expression():
    js = electron_runtime_surface_probe_js()
    assert "window.require" in js
    assert "process.versions" in js
    assert js.strip().startswith("(")
