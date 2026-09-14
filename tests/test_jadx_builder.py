"""build_jadx_command / parse_jadx_output -- Android APK/DEX/JAR decompilation to readable Java
source, apktool's complementary sibling (smali disassembly vs. genuine higher-level source).
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.jadx import build_jadx_command, parse_jadx_output
from agent.tools.registry import get_tool


def test_build_command_decompiles_into_a_sibling_directory_named_after_the_apk():
    command = build_jadx_command({"file_path": "/tmp/app.apk"})
    assert command == ["jadx", "-d", "/tmp/app_jadx", "/tmp/app.apk"]


def test_build_command_works_for_a_bare_dex_file_too():
    command = build_jadx_command({"file_path": "/tmp/classes.dex"})
    assert command == ["jadx", "-d", "/tmp/classes_jadx", "/tmp/classes.dex"]


def test_build_command_strips_whitespace_from_the_file_path():
    command = build_jadx_command({"file_path": "  /tmp/app.apk  "})
    assert command[-1] == "/tmp/app.apk"


def test_parse_output_wraps_raw_text_stripped():
    parsed = parse_jadx_output("INFO  - loading ...\nINFO  - done\n")
    assert parsed == {"raw_output": "INFO  - loading ...\nINFO  - done"}


def test_the_registered_jadx_tool_has_the_expected_shape():
    spec = get_tool("jadx")
    assert spec.category == "re"
    assert spec.executable == "jadx"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_jadx_command
