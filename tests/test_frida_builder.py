"""build_frida_trace_command/build_frida_ps_command + their parsers -- dynamic instrumentation,
RE mode's runtime complement to radare2/gdb's static-only analysis. frida-ps's "PID  Name" table
shape below mirrors its own documented plain-text output (no --json flag exists for the local
process list).
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.frida import (
    build_frida_ps_command,
    build_frida_trace_command,
    parse_frida_ps_output,
    parse_frida_trace_output,
)
from agent.tools.registry import get_tool

_REAL_SHAPED_PS_OUTPUT = """  PID  Name
-----  ------------
 1234  firefox
 5678  Xorg
"""


def test_build_frida_trace_command_spawns_with_include_pattern():
    command = build_frida_trace_command({"file_path": "/tmp/crackme", "function_pattern": "strcmp"})
    assert command == ["frida-trace", "-f", "/tmp/crackme", "-i", "strcmp"]


def test_build_frida_trace_command_appends_target_args_after_a_separator():
    command = build_frida_trace_command({"file_path": "/tmp/crackme", "function_pattern": "open*", "args": ["--verbose", "input.txt"]})
    assert command == ["frida-trace", "-f", "/tmp/crackme", "-i", "open*", "--", "--verbose", "input.txt"]


def test_build_frida_trace_command_omits_the_separator_with_no_args():
    command = build_frida_trace_command({"file_path": "/tmp/crackme", "function_pattern": "strcmp"})
    assert "--" not in command


def test_build_frida_ps_command_takes_no_arguments():
    assert build_frida_ps_command({}) == ["frida-ps"]


def test_parse_frida_trace_output_passes_text_through_unchanged():
    trace_text = "   322 ms  opendir(name=\"/tmp\")\n   340 ms  strcmp(a=\"foo\", b=\"bar\")\n"
    parsed = parse_frida_trace_output(trace_text)
    assert parsed == {"trace_output": trace_text.strip()}


def test_parse_frida_ps_output_extracts_pid_and_name_pairs():
    parsed = parse_frida_ps_output(_REAL_SHAPED_PS_OUTPUT)
    assert parsed == {"processes": [{"pid": 1234, "name": "firefox"}, {"pid": 5678, "name": "Xorg"}]}


def test_parse_frida_ps_output_falls_back_to_raw_output_when_nothing_parses():
    parsed = parse_frida_ps_output("frida-ps: unable to connect to device\n")
    assert parsed == {"raw_output": "frida-ps: unable to connect to device"}


def test_the_registered_frida_trace_tool_has_the_expected_shape():
    spec = get_tool("frida_trace")
    assert spec.category == "re"
    assert spec.executable == "frida-trace"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_frida_trace_command
    assert spec.ok_exit_codes == frozenset({0, 1})


def test_the_registered_frida_ps_tool_has_the_expected_shape():
    spec = get_tool("frida_ps")
    assert spec.category == "re"
    assert spec.executable == "frida-ps"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_frida_ps_command
