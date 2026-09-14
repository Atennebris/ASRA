"""sqlmap: build_sqlmap_command's --tamper support (new — a real WAF that blocked every injection
attempt outright, a real session, usr_136b4c, motivated giving the model a way to retry with a bypass
instead of surrendering) plus baseline coverage this file never had before (this project's own
"thin existing coverage on a file I'm touching -> fix it now" rule — confirmed no
test_sqlmap_builder.py existed prior to this).
"""
import pytest

from agent.tools.builders.sqlmap import build_sqlmap_command, parse_sqlmap_output


def test_build_command_includes_target_and_default_dbs():
    command = build_sqlmap_command({"target": "https://example.com/item?id=1"})
    assert command[:2] == ["sqlmap", "-u"]
    assert "https://example.com/item?id=1" in command
    assert "--dbs" in command


def test_build_command_omits_tamper_when_not_given():
    command = build_sqlmap_command({"target": "https://example.com/item?id=1"})
    assert "--tamper" not in command


def test_build_command_includes_tamper_when_given():
    command = build_sqlmap_command({"target": "https://example.com/item?id=1", "tamper": "space2comment,charencode"})
    assert command[command.index("--tamper") + 1] == "space2comment,charencode"


def test_build_command_rejects_a_tamper_value_with_control_characters():
    with pytest.raises(ValueError):
        build_sqlmap_command({"target": "https://example.com/item?id=1", "tamper": "space2comment\n; rm -rf /"})


def test_build_command_sets_ignore_code_when_data_is_given():
    """A login endpoint legitimately answers wrong-credentials probes with 401/403 -- sqlmap
    otherwise hard-stops on the first non-2xx response instead of testing the payload."""
    command = build_sqlmap_command({"target": "https://example.com/login", "data": "user=a&pass=b"})
    assert "--data" in command
    assert command[command.index("--data") + 1] == "user=a&pass=b"
    assert "--ignore-code" in command
    assert command[command.index("--ignore-code") + 1] == "401,403"


def test_build_command_omits_ignore_code_without_data():
    command = build_sqlmap_command({"target": "https://example.com/item?id=1"})
    assert "--ignore-code" not in command


def test_build_command_merges_extra_headers_into_the_single_headers_flag():
    command = build_sqlmap_command({
        "target": "https://example.com/item?id=1",
        "headers": "X-Custom: 1",
        "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert command.count("--headers") == 1  # sqlmap only accepts one occurrence
    joined = command[command.index("--headers") + 1]
    assert "X-Custom: 1" in joined
    assert "X-HackerOne-Research: my_handle" in joined


def test_build_command_dump_table_path_uses_dump_not_dbs():
    command = build_sqlmap_command({
        "target": "https://example.com/item?id=1", "database": "shopdb", "dump_table": "users",
    })
    assert "--dbs" not in command
    assert command[command.index("-D") + 1] == "shopdb"
    assert command[command.index("-T") + 1] == "users"
    assert "--dump" in command


def test_build_command_includes_user_agent_when_configured():
    command = build_sqlmap_command({"target": "https://example.com/item?id=1", "_user_agent": "bugbounty-0421"})
    assert command[command.index("--user-agent") + 1] == "bugbounty-0421"


def test_parse_output_extracts_vulnerable_parameter():
    stdout = "Parameter: id (GET)\n    Type: boolean-based blind\n"
    parsed = parse_sqlmap_output(stdout)
    assert parsed["injection_confirmed"] is True
    assert parsed["vulnerable_parameters"] == [{"parameter": "id", "place": "GET"}]


def test_parse_output_no_injection_found():
    parsed = parse_sqlmap_output("all tested parameters do not appear to be injectable\n")
    assert parsed["injection_confirmed"] is False
    assert parsed["vulnerable_parameters"] == []
