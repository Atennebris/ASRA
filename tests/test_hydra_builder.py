"""build_hydra_command / parse_hydra_result.

Confirmed live against a real local test login server (not a real target): the exact
"<path>:<form-data>:<F=fail|S=success>" http-post-form module syntax (pinned against hydra -U
http-post-form's own module help text), and that "-o <file> -b json" needs a REAL file, not a
pipe -- same seekability lesson already learned the hard way from Arjun's -oJ.
"""
from pathlib import Path

import pytest

from agent.tools.builders.hydra import (
    _DEFAULT_PASSWORDS,
    _DEFAULT_USERNAMES,
    build_hydra_command,
    parse_hydra_result,
)

# Real wordlist-assignment isolation (a leaking real data/wordlist_assignments.json would silently
# override the wordlists these tests assert on) is handled globally by tests/conftest.py's autouse
# _never_touch_real_app_state fixture -- same guarantee SESSIONS_DIR/INDEX_PATH already get there,
# not something each test file re-implements individually.


def test_build_command_rejects_an_unknown_protocol(tmp_path):
    with pytest.raises(ValueError):
        build_hydra_command({"target": "10.0.0.1", "protocol": "made-up-protocol"}, "job1", tmp_path)


def test_build_command_network_protocol_uses_default_wordlists_when_none_given(tmp_path, monkeypatch):
    # Force the "large wordlist" auto-detection to miss, so the small built-in default is used --
    # deterministic regardless of what's actually installed on the machine running this test.
    monkeypatch.setattr("agent.tools.builders.hydra._LARGE_USERNAME_WORDLIST", "/definitely/not/a/real/path.txt")
    monkeypatch.setattr("agent.tools.builders.hydra._LARGE_PASSWORD_WORDLISTS", ("/definitely/not/a/real/path2.txt",))

    command = build_hydra_command({"target": "10.0.0.1", "protocol": "ssh"}, "job1", tmp_path)

    assert command[0] == "hydra"
    assert "10.0.0.1" in command
    assert "ssh" in command
    users_path = Path(command[command.index("-L") + 1])
    passwords_path = Path(command[command.index("-P") + 1])
    assert users_path.read_text().splitlines() == _DEFAULT_USERNAMES
    assert passwords_path.read_text().splitlines() == _DEFAULT_PASSWORDS


def test_build_command_prefers_an_existing_large_wordlist_over_the_small_default(tmp_path, monkeypatch):
    fake_large = tmp_path / "fake_large_users.txt"
    fake_large.write_text("realuser1\nrealuser2\n")
    monkeypatch.setattr("agent.tools.builders.hydra._LARGE_USERNAME_WORDLIST", str(fake_large))

    command = build_hydra_command({"target": "10.0.0.1", "protocol": "ssh"}, "job1", tmp_path)

    assert command[command.index("-L") + 1] == str(fake_large)


def test_build_command_honors_a_single_username_and_password(tmp_path):
    command = build_hydra_command({"target": "10.0.0.1", "protocol": "ftp", "username": "admin", "password": "hunter2"}, "job1", tmp_path)
    assert command[command.index("-l") + 1] == "admin"
    assert command[command.index("-p") + 1] == "hunter2"
    assert "-L" not in command
    assert "-P" not in command


def test_build_command_honors_explicit_username_and_password_lists(tmp_path):
    command = build_hydra_command(
        {"target": "10.0.0.1", "protocol": "ftp", "username_list": ["a", "b"], "password_list": ["x", "y"]}, "job1", tmp_path,
    )
    users_path = Path(command[command.index("-L") + 1])
    passwords_path = Path(command[command.index("-P") + 1])
    assert users_path.read_text().splitlines() == ["a", "b"]
    assert passwords_path.read_text().splitlines() == ["x", "y"]


def test_build_command_uses_the_default_moderate_thread_count(tmp_path):
    command = build_hydra_command({"target": "10.0.0.1", "protocol": "ssh"}, "job1", tmp_path)
    assert command[command.index("-t") + 1] == "4"


def test_build_command_honors_a_custom_port(tmp_path):
    command = build_hydra_command({"target": "10.0.0.1", "protocol": "ssh", "port": 2222}, "job1", tmp_path)
    assert command[command.index("-s") + 1] == "2222"


def test_build_command_http_post_form_requires_login_path(tmp_path):
    with pytest.raises(ValueError):
        build_hydra_command({"target": "http://example.com", "protocol": "http-post-form", "failure_string": "bad"}, "job1", tmp_path)


def test_build_command_http_post_form_requires_failure_or_success_string(tmp_path):
    with pytest.raises(ValueError):
        build_hydra_command({"target": "http://example.com", "protocol": "http-post-form", "login_path": "/login"}, "job1", tmp_path)


def test_build_command_http_post_form_constructs_the_real_module_syntax(tmp_path):
    """Confirmed live against a real local server: this exact shape (path:body:F=string) found a
    real "admin:letmein123" credential pair."""
    command = build_hydra_command(
        {
            "target": "http://127.0.0.1:8899", "protocol": "http-post-form", "port": 8899,
            "login_path": "/login", "username_field": "username", "password_field": "password",
            "failure_string": "Invalid credentials",
        },
        "job1", tmp_path,
    )
    assert command[-3:] == ["127.0.0.1", "http-post-form", "/login:username=^USER^&password=^PASS^:F=Invalid credentials"]


def test_build_command_http_post_form_supports_success_string_and_extra_fields(tmp_path):
    command = build_hydra_command(
        {
            "target": "http://example.com", "protocol": "http-post-form", "login_path": "/login",
            "success_string": "Welcome", "extra_fields": {"remember": "1"},
        },
        "job1", tmp_path,
    )
    module_arg = command[-1]
    assert module_arg == "/login:username=^USER^&password=^PASS^&remember=1:S=Welcome"


def test_build_command_adds_ssl_flag_for_https_target(tmp_path):
    command = build_hydra_command(
        {"target": "https://example.com", "protocol": "http-post-form", "login_path": "/login", "failure_string": "bad"},
        "job1", tmp_path,
    )
    assert "-S" in command


def test_build_command_no_ssl_flag_for_plain_http(tmp_path):
    command = build_hydra_command(
        {"target": "http://example.com", "protocol": "http-post-form", "login_path": "/login", "failure_string": "bad"},
        "job1", tmp_path,
    )
    assert "-S" not in command


def test_build_command_result_file_path_is_job_specific(tmp_path):
    command = build_hydra_command({"target": "10.0.0.1", "protocol": "ssh"}, "myjobid", tmp_path)
    assert str(tmp_path / "myjobid_result.json") in command


# --- parse_hydra_result: pinned against a real hydra v9.5 -o/-b json output (both the "found a
# credential" and the "clean, zero results" shape -- confirmed live that Hydra, unlike Arjun,
# writes this file every time it actually runs, not only on a hit) ---

_REAL_HIT_OUTPUT = """{ "generator": {
	"software": "Hydra", "version": "v9.5", "built": "2026-07-28 11:35:21",
	"server": "127.0.0.1", "service": "http-post-form", "jsonoutputversion": "1.00",
	"commandline": "hydra -L users.txt -P passwords.txt -s 8899 127.0.0.1 http-post-form ..."
	},
"results": [
	{"port": 8899, "service": "http-post-form", "host": "127.0.0.1", "login": "admin", "password": "letmein123"}
	],
"success": true,
"errormessages": [  ],
"quantityfound": 1   }"""

_REAL_CLEAN_OUTPUT = """{ "generator": {
	"software": "Hydra", "version": "v9.5", "built": "2026-07-28 11:35:08",
	"server": "127.0.0.1", "service": "http-post-form", "jsonoutputversion": "1.00",
	"commandline": "hydra ..."
	},
"results": [
	],
"success": true,
"errormessages": [  ],
"quantityfound": 0   }"""


def test_parse_real_hit_output(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(_REAL_HIT_OUTPUT)
    result = parse_hydra_result(result_path)
    assert result == {"credentials": [{"host": "127.0.0.1", "login": "admin", "password": "letmein123", "port": 8899}]}


def test_parse_real_clean_output(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(_REAL_CLEAN_OUTPUT)
    assert parse_hydra_result(result_path) == {"credentials": []}


def test_parse_missing_file_returns_empty_credentials_not_a_crash(tmp_path):
    assert parse_hydra_result(tmp_path / "does_not_exist.json") == {"credentials": []}


def test_parse_malformed_json_returns_empty_credentials_not_a_crash(tmp_path):
    result_path = tmp_path / "bad.json"
    result_path.write_text("not json at all")
    assert parse_hydra_result(result_path) == {"credentials": []}


def test_hydra_start_and_background_job_check_are_registered_correctly():
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    hydra_spec = get_tool("hydra_start")
    assert hydra_spec.tool_tier == 1
    assert hydra_spec.category == "exploit"
    assert hydra_spec.requires_allowed_target is True

    check_spec = get_tool("background_job_check")
    assert check_spec.requires_allowed_target is False
    assert get_tool("hydra_check") is None  # renamed to the generic background_job_check
