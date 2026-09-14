"""build_dalfox_command / parse_dalfox_output — the real JSON shape here is pinned from an actual
live scan against public-firing-range.appspot.com (this project's own approved live-verification
target for XSS checks), not guessed from documentation: dalfox scan
"https://public-firing-range.appspot.com/reflected/parameter/body?q=a" -f json --skip-mining-dom
--skip-mining-dict returned exactly one verified finding with the shape _REAL_LIVE_OUTPUT below.
"""
from agent.tools.builders.dalfox import build_dalfox_command, parse_dalfox_output


def test_build_command_defaults_to_reflected_dom_scan():
    command = build_dalfox_command({"target": "https://example.com/search?q=a"})
    assert command[:5] == ["dalfox", "scan", "https://example.com/search?q=a", "-f", "json"]
    assert "--sxss" not in command


def test_build_command_stored_mode_adds_sxss_flags():
    command = build_dalfox_command({
        "target": "https://example.com/comment", "mode": "stored", "sxss_url": "https://example.com/post/42",
    })
    assert "--sxss" in command
    assert command[command.index("--sxss-url") + 1] == "https://example.com/post/42"


def test_build_command_param_names_accepts_a_single_string_or_a_list():
    command = build_dalfox_command({"target": "https://example.com/search?q=a", "param": "q"})
    assert command.count("-p") == 1
    assert "q" in command

    command = build_dalfox_command({"target": "https://example.com/search?q=a&r=b", "param": ["q", "r"]})
    assert command.count("-p") == 2
    assert "q" in command and "r" in command


def test_build_command_injects_user_agent_and_cookie():
    command = build_dalfox_command({
        "target": "https://example.com", "cookie": "session=abc", "_user_agent": "ASRA-Scanner",
    })
    assert command[command.index("--cookies") + 1] == "session=abc"
    assert command[command.index("--user-agent") + 1] == "ASRA-Scanner"


def test_build_command_adds_a_repeated_h_flag_per_extra_header():
    command = build_dalfox_command({
        "target": "https://example.com", "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert command[command.index("-H") + 1] == "X-HackerOne-Research: my_handle"


# Captured verbatim from a real dalfox v3.1.2 run, trimmed to what parse_dalfox_output reads.
_REAL_LIVE_OUTPUT = """{
  "findings": [
    {
      "cwe": "CWE-79",
      "data": "https://public-firing-range.appspot.com/reflected/parameter/body?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx044491ec%3E",
      "evidence": "DOM verification successful for param q (DOM marker)",
      "inject_type": "inHTML",
      "location": "Query",
      "message_id": 606,
      "message_str": "Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx044491ec>",
      "method": "GET",
      "param": "q",
      "payload": "<svg onload=alert(1) class=dlx044491ec>",
      "severity": "High",
      "type": "V",
      "type_description": "Verified XSS - payload confirmed executed in parsed DOM"
    }
  ],
  "meta": {
    "dalfox_version": "3.1.2",
    "findings_count": 1,
    "scan_duration_ms": 3123,
    "target_summary": [{"findings_count": 1, "status": "findings", "target": "https://public-firing-range.appspot.com/reflected/parameter/body?q=a"}],
    "targets": ["https://public-firing-range.appspot.com/reflected/parameter/body?q=a"],
    "total_requests": 27
  }
}"""


def test_parse_real_live_output_maps_verified_type_correctly():
    findings = parse_dalfox_output(_REAL_LIVE_OUTPUT)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["xss_type"] == "verified_dom_execution"
    assert finding["severity"] == "High"
    assert finding["param"] == "q"
    assert finding["payload"] == "<svg onload=alert(1) class=dlx044491ec>"
    assert finding["evidence"] == "DOM verification successful for param q (DOM marker)"
    assert finding["cwe"] == "CWE-79"


def test_parse_output_with_zero_findings():
    findings = parse_dalfox_output('{"findings": [], "meta": {"findings_count": 0}}')
    assert findings == []


def test_parse_maps_reflected_and_ast_dom_type_codes():
    output = '{"findings": [{"type": "R", "severity": "Medium"}, {"type": "A", "severity": "Low"}]}'
    findings = parse_dalfox_output(output)
    assert findings[0]["xss_type"] == "reflected_unconfirmed"
    assert findings[1]["xss_type"] == "dom_based_ast"


def test_parse_malformed_json_returns_empty_list_not_a_crash():
    assert parse_dalfox_output("not json at all") == []
