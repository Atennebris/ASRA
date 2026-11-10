"""agent/tools/builders/binary_semantic_diff.py -- semantic cross-version diff of two local
binaries. The cheap-inventory half is tested against MOCKED radare2 subprocess calls (deterministic
JSON fixtures, same style as test_radare2_builder.py's own approach) since the real live-verified
run against two actually-compiled binaries was done manually during this phase's own self-check,
not re-run here (too slow/environment-dependent for the committed suite). The deep-diff half is
tested against a mocked run_ghidra.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agent.tools.builders.binary_semantic_diff import (
    _normalize_pseudocode,
    binary_semantic_diff_available,
    run_binary_semantic_diff,
)

_INFO_A = {"arch": "x86", "bits": 64, "compiler": "GCC 13"}
_INFO_B = {"arch": "x86", "bits": 64, "compiler": "GCC 13"}

_SYMBOLS_A = [
    {"name": "add", "type": "FUNC", "bind": "GLOBAL", "is_imported": False, "size": 24},
    {"name": "sub", "type": "FUNC", "bind": "GLOBAL", "is_imported": False, "size": 22},
    {"name": "unchanged", "type": "FUNC", "bind": "GLOBAL", "is_imported": False, "size": 18},
    {"name": "deregister_tm_clones", "type": "FUNC", "bind": "LOCAL", "is_imported": False, "size": 0},
]
_SYMBOLS_B = [
    {"name": "add", "type": "FUNC", "bind": "GLOBAL", "is_imported": False, "size": 32},
    {"name": "mul", "type": "FUNC", "bind": "GLOBAL", "is_imported": False, "size": 23},
    {"name": "unchanged", "type": "FUNC", "bind": "GLOBAL", "is_imported": False, "size": 18},
]

_IMPORTS_A = [{"name": "printf", "type": "FUNC", "bind": "GLOBAL"}]
_IMPORTS_B = [{"name": "printf", "type": "FUNC", "bind": "GLOBAL"}, {"name": "malloc", "type": "FUNC", "bind": "GLOBAL"}]


def _fake_r2_run(file_path_to_fixtures):
    """Builds a subprocess.run replacement keyed on which fixture file ("a"/"b") and which r2 flag."""
    def _run(cmd, **kwargs):
        file_path = cmd[-1]
        r2_flag = cmd[cmd.index("-c") + 1]
        fixtures = file_path_to_fixtures[file_path]
        if r2_flag == "iIj":
            payload = fixtures["info"]
        elif r2_flag == "isj":
            payload = fixtures["symbols"]
        elif r2_flag == "iij":
            payload = fixtures["imports"]
        else:
            payload = None
        result = MagicMock()
        result.stdout = json.dumps(payload)
        return result
    return _run


@pytest.fixture
def mocked_r2(tmp_path, monkeypatch):
    file_a = str(tmp_path / "file_a")
    file_b = str(tmp_path / "file_b")
    (tmp_path / "file_a").write_bytes(b"\x7fELF")
    (tmp_path / "file_b").write_bytes(b"\x7fELF")
    fixtures = {
        file_a: {"info": _INFO_A, "symbols": _SYMBOLS_A, "imports": _IMPORTS_A},
        file_b: {"info": _INFO_B, "symbols": _SYMBOLS_B, "imports": _IMPORTS_B},
    }
    monkeypatch.setattr(
        "agent.tools.builders.binary_semantic_diff.subprocess.run",
        _fake_r2_run(fixtures),
    )
    monkeypatch.setattr(
        "agent.tools.builders.binary_semantic_diff._resolve_radare2",
        lambda: "radare2",
    )
    return fixtures


def test_availability_reflects_radare2_resolution(monkeypatch):
    monkeypatch.setattr("agent.tools.builders.binary_semantic_diff._resolve_radare2", lambda: None)
    assert binary_semantic_diff_available() is False
    monkeypatch.setattr("agent.tools.builders.binary_semantic_diff._resolve_radare2", lambda: "/usr/bin/radare2")
    assert binary_semantic_diff_available() is True


def test_rejects_missing_files():
    with pytest.raises(ValueError, match="does not exist"):
        run_binary_semantic_diff({"file_a": "/no/such/file-a", "file_b": "/no/such/file-b"})


def test_tool_unavailable_when_radare2_missing(mocked_r2, monkeypatch):
    monkeypatch.setattr("agent.tools.builders.binary_semantic_diff._resolve_radare2", lambda: None)
    file_a, file_b = list(mocked_r2)
    result = run_binary_semantic_diff({"file_a": file_a, "file_b": file_b})
    assert result["status"] == "tool_unavailable"


def test_cheap_inventory_diff_detects_added_removed_changed(mocked_r2):
    file_a, file_b = list(mocked_r2)
    result = run_binary_semantic_diff({"file_a": file_a, "file_b": file_b, "deep": False})
    assert result["status"] == "ok"
    observed = result["observed"]
    assert observed["architecture_match"] is True
    assert observed["functions_added"] == ["mul"]
    assert observed["functions_removed"] == ["sub"]
    assert observed["functions_same_size"] == ["unchanged"]
    assert observed["functions_changed_by_size"] == [{"name": "add", "size_a": 24, "size_b": 32}]
    assert observed["imports_added"] == ["malloc"]
    assert observed["imports_removed"] == []
    # LOCAL deregister_tm_clones must never surface -- see module docstring.
    assert "deregister_tm_clones" not in observed["functions_removed"]
    assert "deep_diff" not in observed


def test_architecture_mismatch_flagged_as_unknown(mocked_r2, monkeypatch):
    file_a, file_b = list(mocked_r2)
    mismatched_info = {"arch": "arm", "bits": 32, "compiler": "clang"}
    monkeypatch.setitem(mocked_r2[file_b], "info", mismatched_info)
    result = run_binary_semantic_diff({"file_a": file_a, "file_b": file_b, "deep": False})
    assert result["observed"]["architecture_match"] is False
    assert "architecture_match" in result["unknown"]


def test_deep_diff_skipped_when_ghidra_unavailable(mocked_r2, monkeypatch):
    file_a, file_b = list(mocked_r2)
    monkeypatch.setattr("agent.tools.builders.binary_semantic_diff.ghidra_available", lambda: False)
    result = run_binary_semantic_diff({"file_a": file_a, "file_b": file_b, "deep": True})
    assert result["observed"]["deep_diff"] == []
    assert "Ghidra" in result["unknown"]["deep_diff"]


def test_deep_diff_reports_same_and_changed(mocked_r2, monkeypatch):
    file_a, file_b = list(mocked_r2)
    monkeypatch.setattr("agent.tools.builders.binary_semantic_diff.ghidra_available", lambda: True)

    def _fake_run_ghidra(params):
        if params["file_path"] == file_a:
            pseudocode = "int unchanged(int a) { return a * 2; }"
        else:
            pseudocode = "int unchanged(int   a)\n{\n  return a * 2;\n}"
        return {"status": "ok", "observed": {"pseudocode": pseudocode}, "unknown": {}}

    monkeypatch.setattr("agent.tools.builders.binary_semantic_diff.run_ghidra", _fake_run_ghidra)
    result = run_binary_semantic_diff({"file_a": file_a, "file_b": file_b, "deep": True})
    deep = {entry["name"]: entry for entry in result["observed"]["deep_diff"]}
    # "unchanged" is the only same-size common function, so it's the one prioritized for deep diff.
    assert deep["unchanged"]["result"] == "same"


def test_deep_diff_reports_unknown_on_resolution_failure(mocked_r2, monkeypatch):
    file_a, file_b = list(mocked_r2)
    monkeypatch.setattr("agent.tools.builders.binary_semantic_diff.ghidra_available", lambda: True)
    monkeypatch.setattr(
        "agent.tools.builders.binary_semantic_diff.run_ghidra",
        lambda params: {"status": "error", "error": "no function found"},
    )
    result = run_binary_semantic_diff({"file_a": file_a, "file_b": file_b, "deep": True})
    deep = {entry["name"]: entry for entry in result["observed"]["deep_diff"]}
    assert deep["unchanged"]["result"] == "unknown"


def test_normalize_pseudocode_blanks_synthetic_names_and_collapses_whitespace():
    text_a = "int f(void) {\n  int local_1c;\n  iVar1 = local_1c + 1;\n  return iVar1;\n}"
    text_b = "int f(void) { int local_8; iVar9 = local_8 + 1; return iVar9; }"
    assert _normalize_pseudocode(text_a) == _normalize_pseudocode(text_b)
