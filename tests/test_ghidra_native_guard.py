"""Guard that stops the Ghidra builder from being pointed at a non-native target.

Real incident behind this: a chat RE session had target crackme.jar (a JVM archive wrapping a
native DLL) and the agent kept calling ghidra with mode=decompile_function against it. analyzeHeadless
imports a .jar as Java bytecode, the postScript finds no native program, and the process exits 0
before the decompiler socket binds -- surfacing as a generic "server exited early" the agent then
retried forever. run_ghidra must reject a positively-identified container up front, with an
actionable verdict, WITHOUT starting any server; a genuine native binary must still pass through.
"""
from __future__ import annotations

import pytest

from agent.tools.builders import ghidra


def _boom(*_args, **_kwargs):
    raise AssertionError("_ensure_server_running must not run for a rejected non-native target")


def test_jar_is_rejected_before_any_server_work(tmp_path, monkeypatch):
    # Guard must fire before analyzeHeadless is even resolved/started -- proven by making the server
    # path explode if reached.
    monkeypatch.setattr(ghidra, "_ensure_server_running", _boom)

    jar = tmp_path / "crackme.jar"
    jar.write_bytes(b"PK\x03\x04" + b"\x00" * 32)

    result = ghidra.run_ghidra({"file_path": str(jar), "mode": "decompile_function", "target": "fcn.1"})

    assert result["status"] == "unsupported_target"
    assert result["tool"] == "ghidra"
    assert "jadx" in result["error"]
    assert result["detected_type"]


def test_dex_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "_ensure_server_running", _boom)

    dex = tmp_path / "classes.dex"
    dex.write_bytes(b"dex\n035\x00" + b"\x00" * 32)

    result = ghidra.run_ghidra({"file_path": str(dex), "mode": "decompile_function", "target": "fcn.1"})

    assert result["status"] == "unsupported_target"
    assert "jadx" in result["error"]


def test_class_file_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra, "_ensure_server_running", _boom)

    klass = tmp_path / "Main.class"
    klass.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 32)

    result = ghidra.run_ghidra({"file_path": str(klass), "mode": "decompile_function", "target": "fcn.1"})

    assert result["status"] == "unsupported_target"
    assert "jadx" in result["error"]


def test_native_elf_passes_the_guard(tmp_path, monkeypatch):
    # An ELF binary (no container extension) must NOT be rejected by the guard. Resolving the tool
    # to None short-circuits the normal path right after the guard, so a "tool_unavailable" verdict
    # proves the guard let the file through rather than rejecting it as unsupported.
    monkeypatch.setattr(ghidra, "_resolve_analyzeheadless", lambda: None)

    elf = tmp_path / "native.bin"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 60)

    result = ghidra.run_ghidra({"file_path": str(elf), "mode": "info"})

    assert result["status"] == "tool_unavailable"
    assert result["status"] != "unsupported_target"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
