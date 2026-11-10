"""build_slither_command / parse_slither_output -- Solidity static analysis. Sample JSON below
mirrors slither's own documented `--json -` schema (results.detectors list of
{check,impact,confidence,description})."""
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.slither import build_slither_command, parse_slither_output
from agent.tools.registry import get_tool

_REAL_SHAPED_DETECTORS_OUTPUT = """{
  "results": {
    "detectors": [
      {
        "check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
        "description": "Reentrancy in Vault.withdraw() (contracts/Vault.sol#10-15)"
      }
    ]
  },
  "success": true
}"""

_CLEAN_OUTPUT = '{"results": {"detectors": []}, "success": true}'


def test_build_command_shape():
    command = build_slither_command({"path": "/tmp/Vault.sol"})
    assert command == ["slither", "/tmp/Vault.sol", "--json", "-"]


def test_build_command_rejects_control_characters():
    with pytest.raises(ValueError):
        build_slither_command({"path": "/tmp/Vault.sol\x00"})


def test_parse_real_shaped_detectors_output():
    parsed = parse_slither_output(_REAL_SHAPED_DETECTORS_OUTPUT)
    assert parsed["observed"] == {"total_findings": 1}
    assert parsed["inferred"]["findings"] == [
        {
            "check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
            "description": "Reentrancy in Vault.withdraw() (contracts/Vault.sol#10-15)",
        }
    ]
    assert "confidence_caveat" in parsed["inferred"]
    assert parsed["unknown"] == {}
    assert parsed["_evidence"]["untrusted_content"] is True


def test_parse_clean_output_returns_empty_findings_not_an_error():
    parsed = parse_slither_output(_CLEAN_OUTPUT)
    assert parsed["observed"] == {"total_findings": 0}
    assert parsed["inferred"]["findings"] == []


def test_parse_non_json_output_falls_back_to_raw_text_and_marks_unknown():
    parsed = parse_slither_output("Error: Vault.sol does not compile\n")
    assert parsed["raw_output"] == "Error: Vault.sol does not compile"
    assert "findings" in parsed["unknown"]
    assert parsed["observed"] == {}


def test_parse_handles_a_results_object_with_no_detectors_key_at_all():
    parsed = parse_slither_output('{"results": {}, "success": true}')
    assert parsed["observed"] == {"total_findings": 0}


def test_the_registered_slither_tool_has_the_expected_shape():
    spec = get_tool("slither")
    assert spec.category == "re"
    assert spec.executable == "slither"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_slither_command
