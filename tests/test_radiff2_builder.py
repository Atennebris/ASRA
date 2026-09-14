"""build_radiff2_command / parse_radiff2_output -- binary diffing (n-day/version comparison).
mode="similarity" (default) parses radiff2's own "similarity: N distance: N" -s -V text output;
mode="changes" parses its -j JSON output.
"""
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.radiff2 import build_radiff2_command, parse_radiff2_output
from agent.tools.registry import get_tool


def test_build_command_similarity_mode_is_the_default():
    command = build_radiff2_command({"file_a": "/tmp/old.bin", "file_b": "/tmp/new.bin"})
    assert command == ["radiff2", "-s", "-V", "/tmp/old.bin", "/tmp/new.bin"]


def test_build_command_changes_mode_uses_json_output():
    command = build_radiff2_command({"file_a": "/tmp/old.bin", "file_b": "/tmp/new.bin", "mode": "changes"})
    assert command == ["radiff2", "-j", "/tmp/old.bin", "/tmp/new.bin"]


def test_build_command_rejects_an_unknown_mode():
    with pytest.raises(ValueError):
        build_radiff2_command({"file_a": "/tmp/old.bin", "file_b": "/tmp/new.bin", "mode": "xor"})


def test_parse_similarity_output_extracts_score_and_distance():
    parsed = parse_radiff2_output("similarity: 0.847\ndistance: 123\n")
    assert parsed == {"similarity": 0.847, "distance": 123}


def test_parse_similarity_output_tolerates_a_missing_distance_line():
    parsed = parse_radiff2_output("similarity: 1.000\n")
    assert parsed == {"similarity": 1.0, "distance": None}


def test_parse_changes_mode_json_output():
    parsed = parse_radiff2_output('{"changes": [{"offset": "0x10", "type": "byte"}]}')
    assert parsed == {"result": {"changes": [{"offset": "0x10", "type": "byte"}]}}


def test_parse_truncates_a_huge_changes_list_with_an_honest_count():
    changes = [{"offset": f"0x{i:x}"} for i in range(80)]
    import json
    parsed = parse_radiff2_output(json.dumps({"changes": changes}))
    assert len(parsed["result"]["changes"]) == 50
    assert parsed["total_changes"] == 80
    assert "50" in parsed["note"]


def test_parse_falls_back_to_raw_output_when_neither_shape_matches():
    parsed = parse_radiff2_output("radiff2: cannot open file\n")
    assert parsed == {"raw_output": "radiff2: cannot open file"}


def test_the_registered_radiff2_tool_has_the_expected_shape():
    spec = get_tool("radiff2")
    assert spec.category == "re"
    assert spec.executable == "radiff2"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_radiff2_command
