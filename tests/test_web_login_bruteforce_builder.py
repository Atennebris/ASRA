"""build_web_login_bruteforce_command / parse_web_login_bruteforce_result.

Confirmed live against two real local test servers (not real targets): a plain login form (found
"admin:letmein123") and, critically, a form requiring a fresh one-time CSRF token per request
(found "admin:s3cur3pass" -- a case Hydra's own http-post-form module cannot handle at all, since
it sends a static request body with no way to refresh a token between attempts).
"""
import json
import sys

import pytest

from agent.tools.builders.web_login_bruteforce import (
    build_web_login_bruteforce_command,
    parse_web_login_bruteforce_result,
)


def test_build_command_rejects_missing_login_path(tmp_path):
    with pytest.raises(ValueError):
        build_web_login_bruteforce_command({"target": "http://example.com", "failure_string": "bad"}, "job1", tmp_path)


def test_build_command_rejects_missing_failure_and_success_string(tmp_path):
    with pytest.raises(ValueError):
        build_web_login_bruteforce_command({"target": "http://example.com", "login_path": "/login"}, "job1", tmp_path)


def test_build_command_uses_sys_executable_and_a_config_file_argument(tmp_path):
    command = build_web_login_bruteforce_command(
        {"target": "http://example.com", "login_path": "/login", "failure_string": "bad"}, "job1", tmp_path,
    )
    assert command[0] == sys.executable
    script_path, config_path = command[1], command[2]
    assert script_path.endswith("job1_script.py")
    assert config_path.endswith("job1_config.json")


def test_build_command_writes_a_real_syntactically_valid_script(tmp_path):
    import py_compile

    command = build_web_login_bruteforce_command(
        {"target": "http://example.com", "login_path": "/login", "failure_string": "bad"}, "job1", tmp_path,
    )
    script_path = command[1]
    py_compile.compile(script_path, doraise=True)  # must not raise -- the generated script is real Python


def test_build_command_config_reflects_all_given_fields(tmp_path):
    command = build_web_login_bruteforce_command(
        {
            "target": "http://example.com/", "login_path": "/login", "username_field": "email",
            "password_field": "pwd", "csrf_field": "my_token", "failure_string": "nope",
            "username_list": ["a", "b"], "password_list": ["x", "y"], "_user_agent": "ASRA-Scanner",
        },
        "job1", tmp_path,
    )
    config_path = command[2]
    config = json.loads(open(config_path, encoding="utf-8").read())
    assert config["login_url"] == "http://example.com/login"
    assert config["username_field"] == "email"
    assert config["password_field"] == "pwd"
    assert config["csrf_field"] == "my_token"
    assert config["failure_string"] == "nope"
    assert config["usernames"] == ["a", "b"]
    assert config["passwords"] == ["x", "y"]
    assert config["user_agent"] == "ASRA-Scanner"


def test_build_command_config_reflects_extra_headers(tmp_path):
    command = build_web_login_bruteforce_command(
        {
            "target": "http://example.com/", "login_path": "/login", "failure_string": "nope",
            "_extra_headers": {"X-HackerOne-Research": "my_handle"},
        },
        "job1", tmp_path,
    )
    config = json.loads(open(command[2], encoding="utf-8").read())
    assert config["extra_headers"] == {"X-HackerOne-Research": "my_handle"}


def test_build_command_defaults_usernames_and_passwords_when_omitted(tmp_path):
    command = build_web_login_bruteforce_command(
        {"target": "http://example.com", "login_path": "/login", "failure_string": "bad"}, "job1", tmp_path,
    )
    config = json.loads(open(command[2], encoding="utf-8").read())
    assert "admin" in config["usernames"]
    assert len(config["usernames"]) > 1
    assert len(config["passwords"]) > 1


def test_build_command_single_username_and_password_win_over_defaults(tmp_path):
    command = build_web_login_bruteforce_command(
        {"target": "http://example.com", "login_path": "/login", "failure_string": "bad", "username": "solo", "password": "onlyone"},
        "job1", tmp_path,
    )
    config = json.loads(open(command[2], encoding="utf-8").read())
    assert config["usernames"] == ["solo"]
    assert config["passwords"] == ["onlyone"]


def test_parse_result_reads_real_credentials(tmp_path):
    result_path = tmp_path / "result.json"
    result_path.write_text(json.dumps({"credentials": [{"username": "admin", "password": "s3cur3pass"}]}))
    assert parse_web_login_bruteforce_result(result_path) == {"credentials": [{"username": "admin", "password": "s3cur3pass"}]}


def test_parse_result_missing_file_returns_empty_not_a_crash(tmp_path):
    assert parse_web_login_bruteforce_result(tmp_path / "missing.json") == {"credentials": []}


def test_parse_result_malformed_json_returns_empty_not_a_crash(tmp_path):
    result_path = tmp_path / "bad.json"
    result_path.write_text("not json")
    assert parse_web_login_bruteforce_result(result_path) == {"credentials": []}


def test_web_login_bruteforce_start_is_registered_correctly():
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("web_login_bruteforce_start")
    assert spec.tool_tier == 1
    assert spec.category == "exploit"
    assert spec.requires_allowed_target is True
