"""agent/tools/builders/wasm.py's run_wasm_analyze -- static analysis for a compiled .wasm module
via WABT (wasm-validate/wasm-objdump/wasm2wat). All of this is tested on mocked subprocess calls
with real-shaped WABT output (captured from an actual live `wat2wasm`-built fixture, not invented
by hand) -- same discipline as tests/test_go_buildinfo_builder.py's own mocked-subprocess tests, no
real WABT installation needed to run this suite.
"""
from __future__ import annotations

import subprocess

import pytest

import agent.tools.builders.wasm as wasm_module
from agent.tools.builders.wasm import run_wasm_analyze
from agent.tools.registry import get_tool

# Captured from a real `wasm-objdump -h -x` run against a wat2wasm-compiled fixture with one
# import, one memory, one global, two functions (one calling the imported host function).
_SAMPLE_OBJDUMP_INFO_STDOUT = """
test_fixture.wasm:\tfile format wasm 0x1

Sections:

     Type start=0x0000000a end=0x00000019 (size=0x0000000f) count: 3
   Import start=0x0000001b end=0x0000002c (size=0x00000011) count: 1
 Function start=0x0000002e end=0x00000031 (size=0x00000003) count: 2
   Memory start=0x00000033 end=0x00000036 (size=0x00000003) count: 1
   Global start=0x00000038 end=0x0000003e (size=0x00000006) count: 1
   Export start=0x00000040 end=0x0000005f (size=0x0000001f) count: 3
     Code start=0x00000061 end=0x0000007a (size=0x00000019) count: 2

Section Details:

Type[3]:
 - type[0] (i32) -> nil
 - type[1] (i32, i32) -> i32
 - type[2] () -> i32
Import[1]:
 - func[0] sig=0 <env.log_value> <- env.log_value
Function[2]:
 - func[1] sig=1 <add>
 - func[2] sig=2 <bump_counter>
Memory[1]:
 - memory[0] pages: initial=1
Global[1]:
 - global[0] i32 mutable=1 - init i32=0
Export[3]:
 - memory[0] -> "memory"
 - func[1] <add> -> "add"
 - func[2] <bump_counter> -> "bump_counter"
Code[2]:
 - func[1] size=7 <add>
 - func[2] size=15 <bump_counter>
"""

# Captured from the same fixture's real `wasm-objdump -d` run.
_SAMPLE_OBJDUMP_DISASSEMBLE_STDOUT = """
test_fixture.wasm:\tfile format wasm 0x1

Code Disassembly:

000063 func[1] <add>:
 000064: 20 00                      | local.get 0
 000066: 20 01                      | local.get 1
 000068: 6a                         | i32.add
 000069: 0b                         | end
00006b func[2] <bump_counter>:
 00006c: 23 00                      | global.get 0
 00006e: 41 01                      | i32.const 1
 000070: 6a                         | i32.add
 000071: 24 00                      | global.set 0
 000073: 23 00                      | global.get 0
 000075: 10 00                      | call 0 <env.log_value>
 000077: 23 00                      | global.get 0
 000079: 0b                         | end
"""

_SAMPLE_WAT_STDOUT = """(module
  (type (;0;) (func (param i32)))
  (import "env" "log_value" (func (;0;) (type 0)))
  (func (;1;) (type 1) (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)
  (export "add" (func 1)))
"""


def _completed(command, returncode, stdout, stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def _wasm_bytes() -> bytes:
    # Real wasm magic number + version -- just enough that this is unambiguously "a wasm-shaped
    # file" for tests that don't care about the mocked tool's own parsing of real module content.
    return b"\x00asm\x01\x00\x00\x00"


# --- run_wasm_analyze: input validation ----------------------------------------------------------


def test_run_wasm_analyze_rejects_a_directory(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        run_wasm_analyze({"file_path": str(tmp_path)})


def test_run_wasm_analyze_rejects_a_missing_file():
    with pytest.raises(ValueError, match="does not exist"):
        run_wasm_analyze({"file_path": "/does/not/exist.wasm"})


def test_run_wasm_analyze_rejects_unknown_mode(tmp_path):
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())
    with pytest.raises(ValueError, match="mode"):
        run_wasm_analyze({"file_path": str(target), "mode": "bogus"})


# --- run_wasm_analyze: tool_unavailable ----------------------------------------------------------


def test_run_wasm_analyze_reports_tool_unavailable_when_wabt_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: None)
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "info"})

    assert result["status"] == "tool_unavailable"
    assert "wasm-objdump" in result["error"]


# --- run_wasm_analyze: mode="validate" ------------------------------------------------------------


def test_run_wasm_analyze_validate_reports_valid_module(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm-validate")
    monkeypatch.setattr(wasm_module.subprocess, "run", lambda command, **kwargs: _completed(command, 0, ""))
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "validate"})

    assert result["status"] == "ok"
    assert result["observed"]["is_valid_wasm"] is True
    assert result["_evidence"]["untrusted_content"] is True


def test_run_wasm_analyze_validate_reports_invalid_module(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm-validate")
    monkeypatch.setattr(
        wasm_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 1, "", "0000004: error: bad magic value"),
    )
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "validate"})

    assert result["status"] == "ok"
    assert result["observed"]["is_valid_wasm"] is False
    assert "bad magic value" in result["observed"]["validation_error"]


def test_run_wasm_analyze_validate_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm-validate")

    def _raise_timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=60)

    monkeypatch.setattr(wasm_module.subprocess, "run", _raise_timeout)
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "validate"})

    assert result["status"] == "timeout"


# --- run_wasm_analyze: mode="info" (default) ------------------------------------------------------


def test_run_wasm_analyze_info_parses_real_shaped_objdump_output(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm-objdump")
    monkeypatch.setattr(
        wasm_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 0, _SAMPLE_OBJDUMP_INFO_STDOUT),
    )
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target)})  # mode defaults to "info"

    assert result["status"] == "ok"
    sections = result["observed"]["sections"]
    # The "Sections:" header-summary block (no bullet lines under it) must not leak through as a
    # confusing empty entry alongside the real per-section detail.
    assert "Sections" not in sections
    assert sections["Import"] == ["func[0] sig=0 <env.log_value> <- env.log_value"]
    assert sections["Export"] == [
        'memory[0] -> "memory"',
        'func[1] <add> -> "add"',
        'func[2] <bump_counter> -> "bump_counter"',
    ]
    assert sorted(result["observed"]["section_names"]) == [
        "Code", "Export", "Function", "Global", "Import", "Memory", "Type",
    ]


def test_run_wasm_analyze_info_command_error(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm-objdump")
    monkeypatch.setattr(
        wasm_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 1, "", "unknown binary format"),
    )
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "info"})

    assert result["status"] == "error"
    assert "unknown binary format" in result["error"]


# --- run_wasm_analyze: mode="disassemble" --------------------------------------------------------


def test_run_wasm_analyze_disassemble_parses_real_shaped_objdump_output(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm-objdump")
    monkeypatch.setattr(
        wasm_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 0, _SAMPLE_OBJDUMP_DISASSEMBLE_STDOUT),
    )
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "disassemble"})

    assert result["status"] == "ok"
    functions = result["observed"]["functions"]
    assert result["observed"]["total_functions"] == 2
    assert functions[0] == {
        "index": 1,
        "name": "add",
        "instructions": ["local.get 0", "local.get 1", "i32.add", "end"],
    }
    assert functions[1]["name"] == "bump_counter"
    assert "call 0 <env.log_value>" in functions[1]["instructions"]


def test_run_wasm_analyze_disassemble_handles_unnamed_function(tmp_path, monkeypatch):
    stdout = (
        "mod.wasm:\tfile format wasm 0x1\n\nCode Disassembly:\n\n"
        "000010 func[0]:\n"
        " 000011: 41 00                      | i32.const 0\n"
        " 000013: 0b                         | end\n"
    )
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm-objdump")
    monkeypatch.setattr(wasm_module.subprocess, "run", lambda command, **kwargs: _completed(command, 0, stdout))
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "disassemble"})

    assert result["observed"]["functions"][0]["name"] is None
    assert result["observed"]["functions"][0]["instructions"] == ["i32.const 0", "end"]


# --- run_wasm_analyze: mode="decompile_wat" -------------------------------------------------------


def test_run_wasm_analyze_decompile_wat_returns_wat_text(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm2wat")
    monkeypatch.setattr(wasm_module.subprocess, "run", lambda command, **kwargs: _completed(command, 0, _SAMPLE_WAT_STDOUT))
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "decompile_wat"})

    assert result["status"] == "ok"
    assert "(module" in result["observed"]["wat"]
    assert 'local.get 0' in result["observed"]["wat"]


def test_run_wasm_analyze_decompile_wat_command_error(tmp_path, monkeypatch):
    monkeypatch.setattr(wasm_module, "_resolve_binary", lambda name: "/usr/bin/wasm2wat")
    monkeypatch.setattr(
        wasm_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 1, "", "unable to read file"),
    )
    target = tmp_path / "mod.wasm"
    target.write_bytes(_wasm_bytes())

    result = run_wasm_analyze({"file_path": str(target), "mode": "decompile_wat"})

    assert result["status"] == "error"
    assert "unable to read file" in result["error"]


# --- _resolve_binary -------------------------------------------------------------------------------


def test_resolve_binary_prefers_wabt_path_override(monkeypatch, tmp_path):
    override_dir = tmp_path / "wabt_bin"
    override_dir.mkdir()
    binary_path = override_dir / "wasm2wat"
    binary_path.write_text("#!/bin/sh\n")
    monkeypatch.setenv("WABT_PATH", str(override_dir))
    monkeypatch.setattr(wasm_module.shutil, "which", lambda name: None)

    assert wasm_module._resolve_binary("wasm2wat") == str(binary_path)


def test_resolve_binary_falls_back_to_path_then_custom_root(monkeypatch):
    monkeypatch.delenv("WABT_PATH", raising=False)
    monkeypatch.setattr(wasm_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(wasm_module, "resolve_via_custom_root", lambda exe: f"/mnt/e/tools/{exe}")

    assert wasm_module._resolve_binary("wasm-objdump") == "/mnt/e/tools/wasm-objdump"


# --- ToolSpec shape --------------------------------------------------------------------------------


def test_the_registered_wasm_analyze_tool_has_the_expected_shape():
    spec = get_tool("wasm_analyze")
    assert spec.category == "re"
    assert spec.tool_tier == 1
    assert spec.requires_allowed_target is False
    assert spec.native_function is run_wasm_analyze
    assert spec.parameters_schema["required"] == ["file_path"]
    assert set(spec.parameters_schema["properties"]["mode"]["enum"]) == {
        "validate", "info", "disassemble", "decompile_wat",
    }
