"""build_binwalk_command / parse_binwalk_output -- firmware/embedded-image signature scanning
(mode="scan", the default) and extraction (mode="extract"). Sample table below mirrors binwalk's
own documented plain-text "<decimal>   <hex>   <description>" row format (no structured output
mode exists in this version).
"""
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.binwalk import build_binwalk_command, parse_binwalk_output
from agent.tools.registry import get_tool

_REAL_SHAPED_SCAN_OUTPUT = """DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, image size: 2097152 bytes
64            0x40            LZMA compressed data, properties: 0x5D
2097216       0x200040        Squashfs filesystem, little endian, version 4.0
"""


def test_build_command_scan_mode_is_the_default():
    command = build_binwalk_command({"file_path": "/tmp/firmware.bin"})
    assert command == ["binwalk", "-B", "/tmp/firmware.bin"]


def test_build_command_extract_mode_writes_into_a_sibling_extracted_directory():
    command = build_binwalk_command({"file_path": "/tmp/firmware.bin", "mode": "extract"})
    assert command == ["binwalk", "-e", "-M", "-C", "/tmp/firmware.bin.extracted", "/tmp/firmware.bin"]


def test_build_command_rejects_an_unknown_mode():
    with pytest.raises(ValueError):
        build_binwalk_command({"file_path": "/tmp/firmware.bin", "mode": "unpack"})


def test_parse_real_shaped_scan_output_extracts_every_signature():
    parsed = parse_binwalk_output(_REAL_SHAPED_SCAN_OUTPUT)
    assert parsed == {
        "signatures": [
            {"offset_decimal": 0, "offset_hex": "0x0", "description": "uImage header, header size: 64 bytes, image size: 2097152 bytes"},
            {"offset_decimal": 64, "offset_hex": "0x40", "description": "LZMA compressed data, properties: 0x5D"},
            {"offset_decimal": 2097216, "offset_hex": "0x200040", "description": "Squashfs filesystem, little endian, version 4.0"},
        ]
    }


def test_parse_truncates_a_huge_signature_list_with_an_honest_count():
    lines = "\n".join(f"{i}\t0x{i:x}\tsignature {i}" for i in range(150))
    parsed = parse_binwalk_output(lines)
    assert len(parsed["signatures"]) == 100
    assert parsed["total_signatures"] == 150
    assert "100" in parsed["note"]


def test_parse_falls_back_to_raw_output_when_nothing_matches():
    parsed = parse_binwalk_output("binwalk: no signatures found\n")
    assert parsed == {"raw_output": "binwalk: no signatures found"}


def test_the_registered_binwalk_tool_has_the_expected_shape():
    spec = get_tool("binwalk")
    assert spec.category == "re"
    assert spec.executable == "binwalk"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_binwalk_command
