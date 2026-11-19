"""Nikto: build_nikto_command reliably places -host <target> itself (the model only adds tuning
flags via extra_args, same pattern as whatweb/nmap). Real incident this fixes: nikto rejects a
bare invocation with no -host and dumps its own usage text instead ("ERROR: No host specified"),
exiting 0 -- a real scan session called nikto with empty extra_args and got that usage dump back
as a "success" result, achieving zero real scanning without anyone noticing.
"""
from agent.tools.builders.nikto import build_nikto_command, parse_nikto_output


def test_nikto_is_registered_with_its_own_build_command_not_the_generic_discovered_path():
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("nikto")
    assert spec.build_command is build_nikto_command


def test_build_command_places_host_flag_with_the_target():
    command = build_nikto_command({"target": "https://example.com"})
    assert command[0] == "nikto"
    assert "-host" in command
    assert command[command.index("-host") + 1] == "https://example.com"


def test_build_command_appends_extra_args():
    command = build_nikto_command({"target": "https://example.com", "extra_args": ["-Tuning", "1,2,3"]})
    assert "-Tuning" in command
    assert "1,2,3" in command


def test_build_command_never_relies_on_the_model_for_the_target():
    """Even with no extra_args at all, -host must still be present -- the whole point of this
    builder existing instead of the generic discovered-tool path."""
    command = build_nikto_command({"target": "https://example.com"})
    assert "-host" in command


# --- -maxtime: nikto must never rely on the external subprocess hard-kill to end a long scan ---


def test_build_command_adds_a_default_maxtime(monkeypatch):
    monkeypatch.delenv("TOOL_TIMEOUT_SECONDS", raising=False)
    command = build_nikto_command({"target": "https://example.com"})
    assert "-maxtime" in command
    maxtime_value = command[command.index("-maxtime") + 1]
    assert maxtime_value.endswith("s")
    assert int(maxtime_value[:-1]) < 120  # under the runner's own 120s default, with margin to spare


def test_build_command_maxtime_tracks_the_configured_external_timeout(monkeypatch):
    monkeypatch.setenv("TOOL_TIMEOUT_SECONDS", "600")
    command = build_nikto_command({"target": "https://example.com"})
    maxtime_value = command[command.index("-maxtime") + 1]
    assert maxtime_value == "570s"  # 600 - the 30s safety margin


def test_build_command_maxtime_never_goes_below_the_floor(monkeypatch):
    monkeypatch.setenv("TOOL_TIMEOUT_SECONDS", "10")
    command = build_nikto_command({"target": "https://example.com"})
    maxtime_value = command[command.index("-maxtime") + 1]
    assert maxtime_value == "30s"  # floor, not a near-zero/negative value


def test_build_command_does_not_double_up_when_the_model_already_set_maxtime():
    command = build_nikto_command({"target": "https://example.com", "extra_args": ["-maxtime", "45s"]})
    assert command.count("-maxtime") == 1
    assert command[command.index("-maxtime") + 1] == "45s"


# --- parse_nikto_output: real findings only, banner/metadata/progress dropped --------------------

# A representative real nikto run: the fixed banner + run metadata, a server banner, several real
# reported items, and the per-run summary line -- exactly the mix the parser has to separate.
_SAMPLE_NIKTO_STDOUT = """- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    example.com
+ Target Port:        443
+ SSL Info:           Subject: /CN=example.com
                      Ciphers: TLS_AES_256_GCM_SHA384
+ Start Time:         2024-01-01 12:00:00 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/
+ /: The X-Content-Type-Options header is not set. See: https://www.netsparker.com/
+ /robots.txt: Entry '/admin/' in robots.txt returned a non-forbidden or redirect HTTP code (200).
+ 8074 requests: 0 error(s) and 3 item(s) reported on remote host
+ End Time:           2024-01-01 12:05:00 (GMT0) (300 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
"""


def test_parse_extracts_only_real_findings_not_banner_or_metadata():
    parsed = parse_nikto_output(_SAMPLE_NIKTO_STDOUT)
    joined = " ".join(parsed["findings"])
    assert any("X-Frame-Options" in f for f in parsed["findings"])
    assert any("X-Content-Type-Options" in f for f in parsed["findings"])
    assert any("robots.txt" in f for f in parsed["findings"])
    # Run metadata and the banner must never leak into findings.
    assert "Target IP" not in joined
    assert "Start Time" not in joined
    assert "Nikto v2.5.0" not in joined
    assert "host(s) tested" not in joined


def test_parse_pulls_server_out_as_its_own_field_not_a_finding():
    parsed = parse_nikto_output(_SAMPLE_NIKTO_STDOUT)
    assert parsed["server"] == "nginx/1.18.0"
    assert not any("Server:" in f for f in parsed["findings"])


def test_parse_captures_the_item_count_and_drops_the_request_tally():
    parsed = parse_nikto_output(_SAMPLE_NIKTO_STDOUT)
    assert parsed["items_reported"] == 3
    # The "N requests: ..." summary itself is noise and must not become a finding.
    assert not any("requests:" in f for f in parsed["findings"])


def test_parse_handles_empty_or_findingless_output_without_crashing():
    empty = parse_nikto_output("")
    assert empty == {"findings": [], "server": None, "items_reported": None}

    no_findings = parse_nikto_output(
        "- Nikto v2.5.0\n+ Target IP:  1.2.3.4\n+ 100 requests: 0 error(s) and 0 item(s) reported on remote host\n"
    )
    assert no_findings["findings"] == []
    assert no_findings["items_reported"] == 0
