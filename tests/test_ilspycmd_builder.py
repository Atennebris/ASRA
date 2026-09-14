"""build_ilspycmd_command / parse_ilspycmd_output -- .NET/C# decompilation, three cheapest-first
modes (list/type/full, mirroring radare2.py's own "info before decompile_function" discipline).
"""
import pytest

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.ilspycmd import build_ilspycmd_command, parse_ilspycmd_output
from agent.tools.registry import get_tool


def test_build_command_list_mode_is_the_default_and_lists_every_entity_kind():
    command = build_ilspycmd_command({"file_path": "/tmp/App.dll"})
    assert command == ["ilspycmd", "-l", "c i s d e", "/tmp/App.dll"]


def test_build_command_type_mode_decompiles_one_named_type():
    command = build_ilspycmd_command({"file_path": "/tmp/App.dll", "mode": "type", "type_name": "MyApp.Program"})
    assert command == ["ilspycmd", "-t", "MyApp.Program", "/tmp/App.dll"]


def test_build_command_type_mode_requires_a_type_name():
    with pytest.raises(ValueError):
        build_ilspycmd_command({"file_path": "/tmp/App.dll", "mode": "type"})


def test_build_command_full_mode_decompiles_the_whole_assembly():
    command = build_ilspycmd_command({"file_path": "/tmp/App.dll", "mode": "full"})
    assert command == ["ilspycmd", "/tmp/App.dll"]


def test_build_command_rejects_an_unknown_mode():
    with pytest.raises(ValueError):
        build_ilspycmd_command({"file_path": "/tmp/App.dll", "mode": "decompile-all-the-things"})


def test_parse_strips_the_trailing_version_nag_lines():
    stdout = (
        "public class Program\n{\n    static void Main() { }\n}\n"
        "You are not using the latest version of ilspycmd\n"
        "Latest version is 9.1.0.7988\n"
    )
    parsed = parse_ilspycmd_output(stdout)
    assert parsed == {"output": "public class Program\n{\n    static void Main() { }\n}"}


def test_parse_leaves_real_output_untouched_when_no_version_nag_is_present():
    parsed = parse_ilspycmd_output("MyApp.Program\nMyApp.Utils\n")
    assert parsed == {"output": "MyApp.Program\nMyApp.Utils"}


def test_the_registered_ilspycmd_tool_has_the_expected_shape():
    spec = get_tool("ilspycmd")
    assert spec.category == "re"
    assert spec.executable == "ilspycmd"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_ilspycmd_command
