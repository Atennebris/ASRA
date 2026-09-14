"""build_apktool_command / parse_apktool_output -- Android APK resource/smali decompilation, a
preparation step (not a finding-producing scanner) ahead of reading the extracted tree or pointing
semgrep at it.
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.apktool import build_apktool_command, parse_apktool_output
from agent.tools.registry import get_tool


def test_build_command_decompiles_into_a_sibling_directory_named_after_the_apk():
    command = build_apktool_command({"file_path": "/tmp/app.apk"})
    assert command == ["apktool", "d", "/tmp/app.apk", "-o", "/tmp/app_apktool", "-f"]


def test_build_command_always_forces_overwrite_so_a_retry_never_fails_on_an_existing_dir():
    command = build_apktool_command({"file_path": "/tmp/app.apk"})
    assert "-f" in command


def test_build_command_strips_whitespace_from_the_file_path():
    command = build_apktool_command({"file_path": "  /tmp/app.apk  "})
    assert command[2] == "/tmp/app.apk"


def test_parse_output_wraps_raw_text_stripped():
    parsed = parse_apktool_output("I: Using Apktool 2.9.3\nI: Baksmaling classes.dex...\n")
    assert parsed == {"raw_output": "I: Using Apktool 2.9.3\nI: Baksmaling classes.dex..."}


def test_the_registered_apktool_tool_has_the_expected_shape():
    spec = get_tool("apktool")
    assert spec.category == "re"
    assert spec.executable == "apktool"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_apktool_command
