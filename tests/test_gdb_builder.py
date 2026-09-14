"""build_gdb_command's own real behavior -- a previous version supported exactly ONE breakpoint, no
`continue`, and no way to read memory anywhere but `x/10i $pc`, effectively a single snapshot, not
real debugging (see gdb.py's own module docstring for the real incident this rewrite fixes). These
tests pin the new multi-breakpoint/stops/reads behavior, the backward-compatible single-breakpoint
default, and the injection-safety allowlist on `reads[].address`.
"""
import pytest

from agent.tools.builders.gdb import build_gdb_command


def test_default_single_breakpoint_matches_old_behavior():
    command = build_gdb_command({"file_path": "/tmp/target"})
    assert command == [
        "gdb", "--batch",
        "-ex", "break main",
        "-ex", "run",
        "-ex", "info registers",
        "-ex", "backtrace",
        "-ex", "x/10i $pc",
        "-ex", "quit",
        "/tmp/target",
    ]


def test_break_at_accepts_a_list_of_targets():
    command = build_gdb_command({"file_path": "/tmp/target", "break_at": ["main", "0x401000", "check_key"]})
    ex_values = [command[i + 1] for i, tok in enumerate(command) if tok == "-ex"]
    assert ex_values[:3] == ["break main", "break 0x401000", "break check_key"]


def test_stops_continues_between_each_and_repeats_inspection():
    command = build_gdb_command({"file_path": "/tmp/target", "stops": 3})
    ex_values = [command[i + 1] for i, tok in enumerate(command) if tok == "-ex"]
    assert ex_values.count("info registers") == 3
    assert ex_values.count("continue") == 2  # one fewer than stops -- never continues past the last
    assert ex_values[-1] == "quit"


def test_stops_out_of_range_rejected():
    with pytest.raises(ValueError, match="stops"):
        build_gdb_command({"file_path": "/tmp/target", "stops": 6})
    with pytest.raises(ValueError, match="stops"):
        build_gdb_command({"file_path": "/tmp/target", "stops": -1})


def test_too_many_breakpoints_rejected():
    with pytest.raises(ValueError, match="break_at"):
        build_gdb_command({"file_path": "/tmp/target", "break_at": ["a", "b", "c", "d", "e", "f"]})


def test_reads_produce_the_right_x_command_per_type():
    command = build_gdb_command({
        "file_path": "/tmp/target",
        "reads": [
            {"address": "$rax", "type": "string", "count": 4},
            {"address": "0x401000+0x8", "type": "hex"},
            {"address": "$pc-0x10", "type": "instructions", "count": 5},
        ],
    })
    ex_values = [command[i + 1] for i, tok in enumerate(command) if tok == "-ex"]
    assert "x/4s $rax" in ex_values
    assert "x/8xb 0x401000+0x8" in ex_values  # default count=8 when omitted
    assert "x/5i $pc-0x10" in ex_values


def test_reads_are_repeated_at_every_stop():
    command = build_gdb_command({
        "file_path": "/tmp/target", "stops": 2,
        "reads": [{"address": "$rax", "type": "string"}],
    })
    ex_values = [command[i + 1] for i, tok in enumerate(command) if tok == "-ex"]
    assert ex_values.count("x/8s $rax") == 2


@pytest.mark.parametrize("bad_address", [
    "foo()",  # function-call syntax -- GDB's expression evaluator can invoke it
    "$rax + system(1)",
    "0x401000; shell rm -rf /",
    "$rax`id`",
    "",
])
def test_reads_address_rejects_anything_not_a_bare_register_or_offset(bad_address):
    with pytest.raises(ValueError, match="address"):
        build_gdb_command({"file_path": "/tmp/target", "reads": [{"address": bad_address, "type": "hex"}]})


def test_reads_type_must_be_a_known_value():
    with pytest.raises(ValueError, match="type"):
        build_gdb_command({"file_path": "/tmp/target", "reads": [{"address": "$rax", "type": "float"}]})


def test_reads_count_out_of_range_rejected():
    with pytest.raises(ValueError, match="count"):
        build_gdb_command({"file_path": "/tmp/target", "reads": [{"address": "$rax", "type": "hex", "count": 65}]})


def test_break_at_still_validated_against_injection():
    with pytest.raises(ValueError, match="break_at"):
        build_gdb_command({"file_path": "/tmp/target", "break_at": "main; shell id"})
