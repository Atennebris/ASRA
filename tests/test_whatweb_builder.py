"""WhatWeb: build_whatweb_command reliably places the target/user-agent itself (the model only
adds extra flags via extra_args, same pattern as nmap/nuclei), forces JSON-Verbose reporting to
stdout (--quiet --log-json-verbose=-, the only WhatWeb output format that carries a per-plugin
certainty figure at all), and parse_whatweb_output turns that JSON into a flat Name[value] token
list plus a specific WordPress signal -- the one thing agent/core.py's wpscan gate checks before
letting that tool run at all -- and a parallel {name: certainty} map.
"""
import json

from agent.tools.builders.whatweb import build_whatweb_command, interpret_whatweb_degraded_ok, interpret_whatweb_timeout, parse_whatweb_output


def _json_verbose_line(url: str, http_status: int, plugins: dict) -> str:
    """Builds one real WhatWeb `--log-json-verbose=-` record: `[url, http_status, [[name,
    [match, ...]], ...]]`. `plugins` maps plugin name -> list of match dicts (each optionally
    carrying "string"/"module"/"certainty"), the same shape a real run emits."""
    return json.dumps([url, http_status, [[name, matches] for name, matches in plugins.items()]])


_WORDPRESS_STDOUT = _json_verbose_line("http://example.com", 200, {
    "Country": [{"string": "UNITED STATES", "module": "US", "certainty": 100}],
    "HTTPServer": [{"string": "Apache/2.4.41 (Ubuntu)", "certainty": 100}],
    "IP": [{"string": "93.184.216.34", "certainty": 100}],
    "MetaGenerator": [{"string": "WordPress 5.8.1", "certainty": 100}],
    "Title": [{"string": "Example Site", "certainty": 100}],
    "WordPress": [{"string": "5.8.1", "certainty": 90}],
    "WordPress-Theme": [{"string": "twentytwentyone", "certainty": 75}],
})

_NON_WORDPRESS_STDOUT = _json_verbose_line("http://example.com", 200, {
    "Country": [{"string": "UNITED STATES", "module": "US", "certainty": 100}],
    "HTTPServer": [{"string": "nginx/1.18.0", "certainty": 100}],
    "IP": [{"string": "93.184.216.34", "certainty": 100}],
    "Title": [{"string": "Example", "certainty": 100}],
})


def test_build_command_includes_target_and_default_aggression():
    command = build_whatweb_command({"target": "http://example.com"})
    assert command[0] == "whatweb"
    assert command[-1] == "http://example.com"
    assert "-a" in command and command[command.index("-a") + 1] == "3"


def test_build_command_always_forces_quiet_json_verbose_reporting():
    # This project's whole recon pipeline (recon_result["technologies"], _merge_protection_
    # detection's per-plugin certainty) depends on WhatWeb's own JSON-Verbose log, the only
    # format that carries a certainty figure at all -- --quiet suppresses the old brief report so
    # stdout carries ONLY that JSON.
    command = build_whatweb_command({"target": "http://example.com"})
    assert "--quiet" in command
    assert "--log-json-verbose=-" in command


def test_build_command_does_not_duplicate_quiet_when_the_model_already_passed_it():
    command = build_whatweb_command({"target": "http://example.com", "extra_args": ["-q"]})
    assert command.count("--quiet") == 0
    assert command.count("-q") == 1


def test_build_command_does_not_duplicate_log_json_verbose_when_the_model_already_passed_it():
    command = build_whatweb_command({"target": "http://example.com", "extra_args": ["--log-json-verbose=/tmp/out.json"]})
    assert command.count("--log-json-verbose=-") == 0
    assert "--log-json-verbose=/tmp/out.json" in command


def test_build_command_appends_extra_args():
    command = build_whatweb_command({"target": "http://example.com", "extra_args": ["--no-errors"]})
    assert "--no-errors" in command


# --- -a/--aggression dedup: real incident this covers -------------------------------------------
# A model wanting a HIGHER aggression level passed extra_args=["-a", "4"] on top of this builder's
# own hardcoded default -- the real, executed command ended up with "-a" specified TWICE with
# conflicting values ("-a 3 ... -a 4"), and WhatWeb hung until the hard subprocess timeout killed
# it (600s, twice in a row across the 1-Step Retry) instead of running with either value.


def test_build_command_does_not_duplicate_aggression_when_model_passes_short_flag():
    command = build_whatweb_command({"target": "http://example.com", "extra_args": ["-a", "4"]})
    assert command.count("-a") == 1
    assert command[command.index("-a") + 1] == "4"  # the model's own value wins, not the default


def test_build_command_does_not_duplicate_aggression_when_model_passes_long_flag():
    command = build_whatweb_command({"target": "http://example.com", "extra_args": ["--aggression", "4"]})
    assert "-a" not in command  # the default short-flag form is never added alongside it
    assert "--aggression" in command
    assert command[command.index("--aggression") + 1] == "4"


def test_build_command_still_adds_the_default_aggression_when_the_model_does_not_specify_one():
    command = build_whatweb_command({"target": "http://example.com", "extra_args": ["--no-errors"]})
    assert command.count("-a") == 1
    assert command[command.index("-a") + 1] == "3"


def test_build_command_does_not_scan_the_target_twice_when_the_model_redundantly_repeats_it():
    """Real incident this covers: the model redundantly re-included the target URL inside
    extra_args three separate times in one real session (once alone, twice alongside a real flag)
    -- since this builder already appends `target` unconditionally, the duplicate made WhatWeb
    scan the exact same URL twice in one invocation."""
    command = build_whatweb_command({"target": "https://example.com", "extra_args": ["https://example.com"]})
    assert command.count("https://example.com") == 1


def test_build_command_does_not_scan_the_target_twice_when_extra_args_has_a_schemed_variant():
    """Real incident this covers, confirmed live 4 times in a separate real session: `target` was
    a bare hostname while the model's own extra_args entry for the SAME host was scheme-prefixed
    (design.example.com / https://design.example.com) -- the exact-string check above never
    caught this, since the two strings never compare equal, so both landed as separate positional
    targets on one invocation and WhatWeb scanned the host twice."""
    command = build_whatweb_command({"target": "design.example.com", "extra_args": ["https://design.example.com"]})
    assert command.count("design.example.com") == 1
    assert "https://design.example.com" not in command


def test_build_command_does_not_treat_a_different_host_as_a_duplicate():
    command = build_whatweb_command({"target": "example.com", "extra_args": ["https://other.example.com"]})
    assert "https://other.example.com" in command


def test_build_command_dedup_survives_alongside_a_real_extra_flag():
    command = build_whatweb_command({
        "target": "https://example.com",
        "extra_args": ["-a", "3", "https://example.com"],
    })
    assert command.count("https://example.com") == 1
    assert command.count("-a") == 1


def test_build_command_includes_user_agent_flag_when_configured():
    command = build_whatweb_command({"target": "http://example.com", "_user_agent": "MyBugBountyUA/1.0"})
    assert any(arg == "--user-agent=MyBugBountyUA/1.0" for arg in command)


def test_build_command_omits_user_agent_flag_when_not_configured():
    command = build_whatweb_command({"target": "http://example.com"})
    assert not any(arg.startswith("--user-agent=") for arg in command)


# --- --user-agent/-U dedup: real incident this covers -------------------------------------------
# A model wanting its own user-agent passed extra_args=["--user-agent", "bugbounty-0421"] while the
# server-injected _user_agent (New Project form's Custom User-Agent field) carried the same value --
# the real, executed command got the flag TWICE with different spellings ("--user-agent ... --user-
# agent=..."), and WhatWeb hung until the hard 600s subprocess timeout killed it, confirmed live on
# a real bug-bounty session. Same failure mode and same fix pattern as the aggression dedup above.


def test_build_command_does_not_duplicate_user_agent_when_model_passes_long_flag_in_extra_args():
    command = build_whatweb_command({
        "target": "http://example.com",
        "extra_args": ["--user-agent", "bugbounty-0421"],
        "_user_agent": "bugbounty-0421",
    })
    assert command.count("--user-agent") + sum(1 for a in command if a.startswith("--user-agent=")) == 1


def test_build_command_does_not_duplicate_user_agent_when_model_passes_short_flag_in_extra_args():
    command = build_whatweb_command({
        "target": "http://example.com",
        "extra_args": ["-U", "bugbounty-0421"],
        "_user_agent": "bugbounty-0421",
    })
    assert not any(arg.startswith("--user-agent=") for arg in command)
    assert "-U" in command


def test_build_command_still_adds_the_configured_user_agent_when_the_model_does_not_specify_one():
    command = build_whatweb_command({
        "target": "http://example.com", "extra_args": ["--no-errors"], "_user_agent": "bugbounty-0421",
    })
    assert command.count("--user-agent=bugbounty-0421") == 1


def test_build_command_adds_a_repeated_header_flag_per_extra_header():
    command = build_whatweb_command({
        "target": "http://example.com", "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert command[command.index("--header") + 1] == "X-HackerOne-Research:my_handle"


def test_parse_output_extracts_technology_tokens():
    parsed = parse_whatweb_output(_WORDPRESS_STDOUT)
    assert "HTTPServer[Apache/2.4.41 (Ubuntu)]" in parsed["technologies"]
    assert any(tech.startswith("WordPress[") for tech in parsed["technologies"])


def test_parse_output_detects_wordpress():
    parsed = parse_whatweb_output(_WORDPRESS_STDOUT)
    assert parsed["detected_cms"] == "WordPress"


def test_parse_output_detects_cms_is_none_when_absent():
    parsed = parse_whatweb_output(_NON_WORDPRESS_STDOUT)
    assert parsed["detected_cms"] is None


def test_parse_output_extracts_a_double_valued_token_as_one_comma_joined_bracket():
    # Country carries BOTH a "string" (the country name) and a "module" (its ISO code) --
    # WhatWeb's own brief format renders that as two back-to-back bracket groups
    # ("Country[UNITED STATES][US]"), which _group_technology_tokens (main.py) can't split
    # cleanly either way; one comma-joined bracket is simpler and just as readable.
    parsed = parse_whatweb_output(_WORDPRESS_STDOUT)
    assert "Country[UNITED STATES,US]" in parsed["technologies"]


def test_parse_output_bare_token_with_no_string_or_module_value_has_no_brackets():
    stdout = _json_verbose_line("http://example.com", 200, {"HTML5": [{"regexp": ["<!DOCTYPE html>"], "certainty": 100}]})
    parsed = parse_whatweb_output(stdout)
    assert parsed["technologies"] == ["HTML5"]


def test_parse_output_captures_per_plugin_certainty():
    parsed = parse_whatweb_output(_WORDPRESS_STDOUT)
    assert parsed["technology_certainty"]["WordPress"] == 90
    assert parsed["technology_certainty"]["WordPress-Theme"] == 75
    assert parsed["technology_certainty"]["HTTPServer"] == 100


def test_parse_output_certainty_takes_the_best_match_across_repeated_lines():
    # Two records for the same host (e.g. a redirect hop) can both report the same plugin --
    # the map keeps the HIGHEST certainty seen for it, not just whichever record came last.
    stdout = "\n".join([
        _json_verbose_line("http://example.com", 302, {"HTTPServer": [{"string": "nginx", "certainty": 60}]}),
        _json_verbose_line("https://example.com/", 200, {"HTTPServer": [{"string": "nginx", "certainty": 100}]}),
    ])
    parsed = parse_whatweb_output(stdout)
    assert parsed["technology_certainty"]["HTTPServer"] == 100


def test_parse_output_ignores_non_json_lines_and_malformed_json():
    stdout = "not json at all\n[broken\n" + _WORDPRESS_STDOUT
    parsed = parse_whatweb_output(stdout)
    assert parsed["detected_cms"] == "WordPress"


def test_parse_output_empty_stdout_returns_empty_shape():
    parsed = parse_whatweb_output("")
    assert parsed == {"technologies": [], "technology_certainty": {}, "detected_cms": None}


def test_interpret_whatweb_timeout_hints_at_max_aggression():
    """Real, confirmed incident: the SAME host, scanned with the default -a 3 elsewhere in the
    same session, finished in 6-27s every time; only -a 4 ever hung -- five times in a row in one
    real session (~50 of that session's 80 total minutes), because each 1-Step Retry only ever
    corrected the --user-agent spelling and kept resending -a 4."""
    result = {"status": "timeout", "command": ["whatweb", "--color=never", "-a", "4", "http://example.com"]}
    hint = interpret_whatweb_timeout(result)
    assert hint is not None
    assert "-a 4" in hint


def test_interpret_whatweb_timeout_returns_none_at_default_aggression():
    result = {"status": "timeout", "command": ["whatweb", "--color=never", "-a", "3", "http://example.com"]}
    assert interpret_whatweb_timeout(result) is None


def test_interpret_whatweb_timeout_returns_none_for_a_real_error_not_a_timeout():
    result = {"status": "error", "command": ["whatweb", "-a", "4", "http://example.com"]}
    assert interpret_whatweb_timeout(result) is None


def test_interpret_whatweb_degraded_ok_flags_its_own_internal_timeout_marker():
    """Real, confirmed incident this fixes (test-2-again2-usr_2f4db1): WhatWeb hit its own
    internal per-URL timeout mid-scan (stderr: "ERROR Opening: ... - execution expired") but
    still exited 0 -- four separate times in one real session, each read as a clean, information-
    free "ok" indistinguishable from a genuine "no technology detected" negative."""
    result = {"status": "ok", "exit_code": 0, "stderr": "ERROR Opening: http://slow.example.com - execution expired"}
    note = interpret_whatweb_degraded_ok(result)
    assert note is not None
    assert "timeout" in note.lower()


def test_interpret_whatweb_degraded_ok_returns_none_for_a_clean_result():
    result = {"status": "ok", "exit_code": 0, "stderr": ""}
    assert interpret_whatweb_degraded_ok(result) is None
