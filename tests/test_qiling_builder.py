"""agent/tools/builders/qiling.py + agent/tools/qiling_runner.py: the cross-platform Qiling
emulation tool that replaced the removed Windows-only cdb tool."""
import json
import sys

from agent.tools import qiling_runner
from agent.tools.builders import qiling


def test_build_command_targets_runner_with_json_params():
    cmd = qiling.build_qiling_command({"file_path": "/tmp/sample.exe"})
    assert cmd[0] == sys.executable
    assert cmd[1].endswith("qiling_runner.py")
    params = json.loads(cmd[2])
    assert params == {"file_path": "/tmp/sample.exe"}


def test_build_command_passes_optional_fields():
    cmd = qiling.build_qiling_command({
        "file_path": "/tmp/a.bin", "rootfs": "/opt/rootfs/x86_windows",
        "args": ["--flag", "value"], "max_instructions": 500000,
    })
    params = json.loads(cmd[2])
    assert params["rootfs"] == "/opt/rootfs/x86_windows"
    assert params["args"] == ["--flag", "value"]
    assert params["max_instructions"] == 500000


def test_parse_output_extracts_json_after_sentinel():
    stdout = "qiling noise line\nmore noise\n===QILING_RESULT===\n" + json.dumps(
        {"status": "ok", "os": "windows", "instructions_executed": 42})
    parsed = qiling.parse_qiling_output(stdout)
    assert parsed["status"] == "ok"
    assert parsed["os"] == "windows"
    assert parsed["instructions_executed"] == 42


def test_parse_output_falls_back_to_raw_without_sentinel():
    parsed = qiling.parse_qiling_output("just some raw text, no sentinel")
    assert parsed == {"raw_output": "just some raw text, no sentinel"}


def test_parse_output_falls_back_on_bad_json():
    parsed = qiling.parse_qiling_output("===QILING_RESULT===\n{not valid json")
    assert "raw_output" in parsed


def test_qiling_available_reflects_find_spec(monkeypatch):
    monkeypatch.setattr(qiling.importlib.util, "find_spec", lambda name: None)
    assert qiling.qiling_available() is False
    monkeypatch.setattr(qiling.importlib.util, "find_spec", lambda name: object())
    assert qiling.qiling_available() is True


def test_runner_errors_cleanly_on_missing_file(tmp_path):
    result = qiling_runner._run({"file_path": str(tmp_path / "does_not_exist.exe")})
    assert result["status"] == "error"
    assert "does not exist" in result["error"]


def test_runner_errors_cleanly_on_missing_rootfs(tmp_path):
    real_file = tmp_path / "sample.bin"
    real_file.write_bytes(b"\x00")
    result = qiling_runner._run({"file_path": str(real_file), "rootfs": str(tmp_path / "nope")})
    assert result["status"] == "error"
    assert "rootfs" in result["error"].lower()


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def _elf(machine_le):
    head = bytearray(64)
    head[:4] = b"\x7fELF"
    head[4] = 2  # 64-bit
    head[5] = 1  # little-endian
    head[18:20] = machine_le.to_bytes(2, "little")
    return bytes(head)


def _pe(machine_le):
    head = bytearray(0x90)
    head[:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")  # e_lfanew -> PE header at 0x80
    head[0x80:0x84] = b"PE\x00\x00"
    head[0x84:0x86] = machine_le.to_bytes(2, "little")
    return bytes(head)


def test_detect_rootfs_subdir_from_headers(tmp_path):
    macho = bytes.fromhex("feedfacf") + b"\x00" * 60
    assert qiling_runner._detect_rootfs_subdir(_write(tmp_path, "a", _elf(0x3E))) == "x8664_linux"
    assert qiling_runner._detect_rootfs_subdir(_write(tmp_path, "b", _elf(0xB7))) == "arm64_linux"
    assert qiling_runner._detect_rootfs_subdir(_write(tmp_path, "c", _pe(0x8664))) == "x8664_windows"
    assert qiling_runner._detect_rootfs_subdir(_write(tmp_path, "d", macho)) == "x8664_macos"
    assert qiling_runner._detect_rootfs_subdir(_write(tmp_path, "e", b"not a binary")) is None


def test_resolve_rootfs_picks_matching_subdir(tmp_path):
    base = tmp_path / "rootfs"
    (base / "x8664_windows").mkdir(parents=True)
    target = _write(tmp_path, "app.exe", _pe(0x8664))
    assert qiling_runner._resolve_rootfs(target, str(base)) == str(base / "x8664_windows")


def test_resolve_rootfs_uses_base_when_no_subdir(tmp_path):
    base = tmp_path / "specific_rootfs"
    base.mkdir()
    target = _write(tmp_path, "app.bin", b"\x7fELF" + b"\x00" * 60)  # unknown machine
    assert qiling_runner._resolve_rootfs(target, str(base)) == str(base)
