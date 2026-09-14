"""build_mythril_command / parse_mythril_output -- symbolic-execution contract analysis, same
bytecode-or-local-file dual shape as heimdall.py/native.py's disassemble_evm_bytecode. Sample JSON
below mirrors mythril's own documented `myth analyze -o json` schema (a top-level "issues" list of
{title,severity,swc-id,description,function}).
"""
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.mythril import build_mythril_command, parse_mythril_output
from agent.tools.registry import get_tool

_REAL_SHAPED_ISSUES_OUTPUT = """{
  "issues": [
    {
      "title": "Integer Arithmetic Bugs", "severity": "High", "swc-id": "101",
      "description": "The subtraction can result in an integer underflow.",
      "function": "withdraw(uint256)"
    }
  ],
  "success": true
}"""

_CLEAN_OUTPUT = '{"issues": [], "success": true}'


def test_build_command_uses_a_real_local_file_as_analyze_target(tmp_path):
    contract = tmp_path / "Vault.sol"
    contract.write_text("contract Vault {}")
    command = build_mythril_command({"bytecode_or_path": str(contract)})
    assert command == ["myth", "analyze", str(contract), "-o", "json"]


def test_build_command_treats_a_non_existent_path_as_raw_bytecode():
    command = build_mythril_command({"bytecode_or_path": "0x6080604052"})
    assert command == ["myth", "analyze", "-c", "6080604052", "-o", "json"]


def test_build_command_bytecode_without_0x_prefix_is_passed_through_unchanged():
    command = build_mythril_command({"bytecode_or_path": "6080604052"})
    assert command[command.index("-c") + 1] == "6080604052"


def test_parse_real_shaped_issues_output():
    parsed = parse_mythril_output(_REAL_SHAPED_ISSUES_OUTPUT)
    assert parsed == {
        "findings": [
            {
                "title": "Integer Arithmetic Bugs", "severity": "High", "swc_id": "101",
                "description": "The subtraction can result in an integer underflow.",
                "function": "withdraw(uint256)",
            }
        ]
    }


def test_parse_clean_output_returns_empty_findings_not_an_error():
    assert parse_mythril_output(_CLEAN_OUTPUT) == {"findings": []}


def test_parse_tolerates_a_bare_json_list_of_issues_not_just_a_dict_wrapper():
    parsed = parse_mythril_output('[{"title": "Reentrancy", "severity": "High"}]')
    assert parsed == {
        "findings": [{"title": "Reentrancy", "severity": "High", "swc_id": None, "description": None, "function": None}]
    }


def test_parse_non_json_output_falls_back_to_raw_text():
    parsed = parse_mythril_output("Error: could not connect to any node\n")
    assert parsed == {"raw_output": "Error: could not connect to any node"}


def test_build_command_rejects_control_characters():
    with pytest.raises(ValueError):
        build_mythril_command({"bytecode_or_path": "0x6080\x00"})


def test_the_registered_mythril_tool_has_the_expected_shape():
    spec = get_tool("mythril")
    assert spec.category == "re"
    assert spec.executable == "myth"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_mythril_command
