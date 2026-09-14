"""WPScan: build_wpscan_command places --url/--user-agent itself (same pattern as sqlmap/nuclei),
parse_wpscan_output extracts the real core version + enumerated plugin name/version pairs from its
actual CLI text output -- not a guess, a direct read of the "[+] <plugin>" / "| Version: X" lines
WPScan itself prints.
"""
from agent.tools.builders.wpscan import build_wpscan_command, interpret_wpscan_timeout, parse_wpscan_output

_WPSCAN_OUTPUT = """[+] WordPress version 5.8.1 identified (Insecure, released on 2021-07-20).

[+] WordPress theme in use: twentytwentyone

[i] Plugin(s) Identified:

[+] contact-form-7
 | Location: http://example.com/wp-content/plugins/contact-form-7/
 | Latest Version: 5.5.3 (up to date)
 | Last Updated: 2021-08-10T00:00:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.4 (80% confidence)
 | Found By: Query Parameter (Passive Detection)
"""


def test_build_command_uses_url_flag():
    command = build_wpscan_command({"target": "http://example.com"})
    assert command[0] == "wpscan"
    assert "--url" in command
    assert command[command.index("--url") + 1] == "http://example.com"


def test_build_command_does_not_duplicate_url_when_extra_args_already_has_it():
    """Real, confirmed incident this fixes: extra_args also carrying "--url" duplicated the flag
    ("--url X --url X") in the real executed command four separate times -- same class of bug
    already fixed for whatweb's own aggression/user-agent/target dedup."""
    command = build_wpscan_command({
        "target": "http://example.com", "extra_args": ["--url", "http://example.com", "--enumerate", "p"],
    })
    assert command.count("--url") == 1


# --- --update default: real incident this covers -------------------------------------------
# WPScan's local vulnerability database going stale makes it print an interactive "Do you want
# to update now? [Y]es [N]o" prompt and block reading an answer -- confirmed live to eat ~9 real
# minutes before the subprocess timeout finally killed it. --update runs the update non-
# interactively then proceeds straight into the scan in the same invocation, so it's a better
# default than --no-update (accurate results, not just a suppressed question).


def test_build_command_adds_update_flag_by_default():
    command = build_wpscan_command({"target": "http://example.com"})
    assert "--update" in command


def test_build_command_does_not_duplicate_update_when_model_already_chose_update():
    command = build_wpscan_command({"target": "http://example.com", "extra_args": ["--update"]})
    assert command.count("--update") == 1


def test_build_command_respects_model_choosing_no_update():
    """An explicit model choice wins outright -- if the model deliberately wants to skip the
    update (e.g. it already updated recently in this same session), this builder must not force
    --update on top of that."""
    command = build_wpscan_command({"target": "http://example.com", "extra_args": ["--no-update"]})
    assert "--update" not in command
    assert "--no-update" in command


def test_build_command_appends_extra_args():
    command = build_wpscan_command({"target": "http://example.com", "extra_args": ["--enumerate", "p"]})
    assert "--enumerate" in command and "p" in command


def test_build_command_includes_user_agent_when_configured():
    command = build_wpscan_command({"target": "http://example.com", "_user_agent": "MyBugBountyUA/1.0"})
    assert "--user-agent" in command
    assert command[command.index("--user-agent") + 1] == "MyBugBountyUA/1.0"


def test_build_command_omits_user_agent_when_not_configured():
    command = build_wpscan_command({"target": "http://example.com"})
    assert "--user-agent" not in command


def test_build_command_joins_multiple_extra_headers_with_semicolons():
    command = build_wpscan_command({
        "target": "http://example.com",
        "_extra_headers": {"X-HackerOne-Research": "my_handle", "X-Forwarded-For": "127.0.0.1"},
    })
    assert command.count("--headers") == 1
    value = command[command.index("--headers") + 1]
    assert value == "X-HackerOne-Research: my_handle; X-Forwarded-For: 127.0.0.1"


def test_build_command_omits_headers_flag_when_no_extra_headers_configured():
    command = build_wpscan_command({"target": "http://example.com"})
    assert "--headers" not in command


def test_interpret_wpscan_timeout_hints_at_aggressive_mode():
    """Real incident this covers: the same wpscan call, and its own near-identical 1-Step Retry,
    both timed out after 600s with --plugins-detection aggressive -- a corrected retry can't fix a
    fundamentally too-slow scan mode by re-sending the same slow mode."""
    result = {"status": "timeout", "command": ["wpscan", "--url", "x", "--plugins-detection", "aggressive"]}
    hint = interpret_wpscan_timeout(result)
    assert hint is not None
    assert "aggressive" in hint


def test_interpret_wpscan_timeout_returns_none_without_aggressive_mode():
    result = {"status": "timeout", "command": ["wpscan", "--url", "x"]}
    assert interpret_wpscan_timeout(result) is None


def test_interpret_wpscan_timeout_returns_none_for_a_real_error_not_a_timeout():
    result = {"status": "error", "command": ["wpscan", "--url", "x", "--plugins-detection", "aggressive"]}
    assert interpret_wpscan_timeout(result) is None


def test_parse_output_extracts_wordpress_version():
    parsed = parse_wpscan_output(_WPSCAN_OUTPUT)
    assert parsed["wordpress_version"] == "5.8.1"


def test_parse_output_extracts_plugin_name_and_version():
    parsed = parse_wpscan_output(_WPSCAN_OUTPUT)
    assert parsed["plugins"] == [{"name": "contact-form-7", "version": "5.4"}]


def test_parse_output_wordpress_version_is_none_when_absent():
    parsed = parse_wpscan_output("[+] No WPScan API Token given\n")
    assert parsed["wordpress_version"] is None
    assert parsed["plugins"] == []
