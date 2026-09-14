"""build_upx_command / parse_upx_output -- packed-binary detection (mode="detect", the default)
and unpacking (mode="unpack") ahead of radare2/gdb static analysis.
"""
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import _apply_output_parser
from agent.tools.builders.upx import build_upx_command, interpret_upx_not_packed, parse_upx_output
from agent.tools.registry import get_tool


def test_build_command_detect_mode_is_the_default():
    command = build_upx_command({"file_path": "/tmp/sample.bin"})
    assert command == ["upx", "-t", "/tmp/sample.bin"]


def test_build_command_unpack_mode_writes_to_a_new_sibling_file_never_overwriting_the_original():
    command = build_upx_command({"file_path": "/tmp/sample.bin", "mode": "unpack"})
    assert command == ["upx", "-d", "/tmp/sample.bin", "-o", "/tmp/sample.bin.unpacked"]
    # The original path must never appear as the -o target -- unpacking must never clobber it.
    assert command[command.index("-o") + 1] != "/tmp/sample.bin"


def test_build_command_rejects_an_unknown_mode():
    with pytest.raises(ValueError):
        build_upx_command({"file_path": "/tmp/sample.bin", "mode": "explode"})


def test_parse_detects_a_genuinely_packed_file():
    # Exercises parse_upx_output's own documented heuristic (its docstring says upx's exit code
    # alone isn't a reliably confirmed signal across versions) -- "upx" + "ok" together, its
    # actual detection rule -- not a claim about one specific upx release's exact wording.
    parsed = parse_upx_output("upx: sample.bin [ELF32,x86]\nsample.bin: OK\n")
    assert parsed["appears_upx_packed"] is True


def test_parse_detects_a_not_packed_file():
    parsed = parse_upx_output("upx: sample.bin: NotPackedException: not packed by UPX\n")
    assert parsed["appears_upx_packed"] is False


def test_parse_unknown_file_format_is_treated_as_not_packed():
    parsed = parse_upx_output("upx: sample.bin: CantPackException: Unknown file format\n")
    assert parsed["appears_upx_packed"] is False


def test_parse_always_preserves_the_raw_output_text():
    parsed = parse_upx_output("sample.bin: OK\n")
    assert parsed["raw_output"] == "sample.bin: OK"


def test_the_registered_upx_tool_has_the_expected_shape():
    spec = get_tool("upx")
    assert spec.category == "re"
    assert spec.executable == "upx"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_upx_command
    assert spec.ok_exit_codes == frozenset({0, 1})


# --- interpret_upx_not_packed: skip the wasted 1-Step Retry round-trip on a deterministic result ---


def test_interpret_upx_not_packed_fires_on_detect_mode_failure():
    """Real, confirmed incident this fixes (fss-usr_d5b09a): `upx --detect` correctly determined
    a file wasn't UPX-packed (exit_code=2, outside ok_exit_codes={0,1}), but the resulting
    status="error" still triggered a full 1-Step Retry round-trip -- the model spent it switching
    to mode="unpack", which failed with the exact same signal for the exact same reason."""
    result = {"status": "error", "exit_code": 2, "stdout": "", "stderr": "upx: sample.bin: NotPackedException: not packed by UPX\n"}
    hint = interpret_upx_not_packed(result)
    assert hint is not None
    assert "not upx-packed" in hint.lower()


def test_interpret_upx_not_packed_fires_on_unpack_mode_failure_too():
    """Same deterministic fact, reached via the OTHER mode -- must fire identically so a
    correction retry that switched modes (or a direct unpack call) is caught just the same."""
    result = {"status": "error", "exit_code": 2, "stdout": "upx: sample.bin: CantUnpackException: Unknown file format\n", "stderr": ""}
    assert interpret_upx_not_packed(result) is not None


def test_interpret_upx_not_packed_returns_none_for_a_genuine_other_failure():
    result = {"status": "error", "exit_code": 1, "stdout": "", "stderr": "upx: sample.bin: FileNotFoundError\n"}
    assert interpret_upx_not_packed(result) is None


def test_interpret_upx_not_packed_returns_none_for_a_successful_result():
    result = {"status": "ok", "exit_code": 0, "stdout": "sample.bin: OK\n", "stderr": ""}
    assert interpret_upx_not_packed(result) is None


def test_apply_output_parser_marks_upx_not_packed_failed_not_retryable():
    """End-to-end proof through the real dispatch path: the "not packed" case must land on
    status="failed" (not in _RETRYABLE_STATUSES), the same mechanism that already skips the
    doomed Arjun-crash retry, so _run_tool_with_retry never pays for the wasted correction call."""
    spec = get_tool("upx")
    raw_result = {"status": "error", "exit_code": 2, "stdout": "", "stderr": "upx: sample.bin: NotPackedException: not packed by UPX\n"}

    result = _apply_output_parser(spec, raw_result)

    assert result["status"] == "failed"
    assert "not upx-packed" in result["error"].lower()
