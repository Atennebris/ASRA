"""build_ffuf_command / parse_ffuf_output.

Real gap this tool closes: nothing else in this registry actively brute-forces hidden content
with a real wordlist -- common_exposure_scan checks a short fixed path list, authenticated_crawl
only finds what's already linked, js_bundle_scan only finds endpoint strings already in JS.

parse_ffuf_output's shape is pinned from a real live scan against
public-firing-range.appspot.com (this project's own approved live-verification target):
ffuf -u https://public-firing-range.appspot.com/FUZZ -w /usr/share/wordlists/ffuf/common.txt
-mc 200,204,301,302,307,401,403,405,500 -t 20 -of json -o /dev/stdout -s returned 4 real hits, and
confirmed live that -s does NOT stop ffuf from also printing each match as a plain text line to
stdout throughout the run -- the JSON report is the LAST line, everything before it is that noise.
"""
import json

from agent.tools.builders.ffuf import build_ffuf_command, parse_ffuf_output


def test_build_command_appends_fuzz_marker_when_missing():
    command = build_ffuf_command({"target": "https://example.com/api"})
    assert command[command.index("-u") + 1] == "https://example.com/api/FUZZ"


def test_build_command_leaves_an_explicit_fuzz_marker_alone():
    command = build_ffuf_command({"target": "https://example.com/FUZZ/profile"})
    assert command[command.index("-u") + 1] == "https://example.com/FUZZ/profile"


def test_build_command_uses_the_default_wordlist_when_none_given(monkeypatch):
    monkeypatch.delenv("FFUF_WORDLIST_PATH", raising=False)
    command = build_ffuf_command({"target": "https://example.com"})
    assert command[command.index("-w") + 1] == "/usr/share/wordlists/ffuf/common.txt"


def test_build_command_honors_a_model_supplied_wordlist():
    command = build_ffuf_command({"target": "https://example.com", "wordlist": "/tmp/my-list.txt"})
    assert command[command.index("-w") + 1] == "/tmp/my-list.txt"


def test_build_command_honors_the_env_default_wordlist(monkeypatch):
    monkeypatch.setenv("FFUF_WORDLIST_PATH", "/opt/wordlists/big.txt")
    command = build_ffuf_command({"target": "https://example.com"})
    assert command[command.index("-w") + 1] == "/opt/wordlists/big.txt"


def test_build_command_adds_default_match_codes_and_threads():
    command = build_ffuf_command({"target": "https://example.com"})
    assert command[command.index("-mc") + 1] == "200,204,301,302,307,401,403,405,500"
    assert command[command.index("-t") + 1] == "40"


def test_build_command_extensions_accepts_a_list():
    command = build_ffuf_command({"target": "https://example.com", "extensions": [".php", ".bak"]})
    assert command[command.index("-e") + 1] == ".php,.bak"


def test_build_command_injects_user_agent():
    command = build_ffuf_command({"target": "https://example.com", "_user_agent": "ASRA-Scanner"})
    assert command[command.index("-H") + 1] == "User-Agent: ASRA-Scanner"


def test_build_command_adds_a_repeated_h_flag_per_extra_header():
    command = build_ffuf_command({
        "target": "https://example.com",
        "_user_agent": "ASRA-Scanner",
        "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })
    assert command.count("-H") == 2
    assert "X-HackerOne-Research: my_handle" in command


def test_build_command_adds_a_default_maxtime(monkeypatch):
    monkeypatch.delenv("TOOL_TIMEOUT_SECONDS", raising=False)
    command = build_ffuf_command({"target": "https://example.com"})
    assert command[command.index("-maxtime") + 1] == "90"  # 120 default - 30s safety margin


def test_build_command_does_not_double_up_maxtime_from_extra_args():
    command = build_ffuf_command({"target": "https://example.com", "extra_args": ["-maxtime", "45"]})
    assert command.count("-maxtime") == 1
    assert command[command.index("-maxtime") + 1] == "45"


def test_build_command_appends_extra_args():
    command = build_ffuf_command({"target": "https://example.com", "extra_args": ["-recursion"]})
    assert "-recursion" in command


def test_build_command_adds_auto_calibration_by_default():
    """Real, confirmed incident this fixes: a real scan ran its complete -maxtime budget producing
    a 532KB+ dump of catch-all 403s, even though the model's own reasoning mid-scan had already
    recognized the pattern -- ffuf's own -ac auto-calibration filters exactly this out."""
    command = build_ffuf_command({"target": "https://example.com"})
    assert "-ac" in command


def test_build_command_does_not_add_default_ac_when_model_already_picked_a_filter():
    command = build_ffuf_command({"target": "https://example.com", "extra_args": ["-fc", "403"]})
    assert "-ac" not in command
    assert "-fc" in command


def test_build_command_does_not_double_up_ac_when_model_explicitly_set_it():
    command = build_ffuf_command({"target": "https://example.com", "extra_args": ["-ac"]})
    assert command.count("-ac") == 1


# Captured verbatim (trimmed) from a real ffuf v2.2.1 run against the approved live target.
_REAL_LIVE_OUTPUT = (
    "address\nindex.html\nredirect\ntags\n"
    '{"commandline":"ffuf -u https://public-firing-range.appspot.com/FUZZ ...",'
    '"time":"2026-07-28T08:32:26+03:00",'
    '"results":['
    '{"input":{"FUZZ":"address"},"status":200,"length":3410,"words":314,"redirectlocation":"",'
    '"url":"https://public-firing-range.appspot.com/address"},'
    '{"input":{"FUZZ":"index.html"},"status":200,"length":1926,"words":226,"redirectlocation":"",'
    '"url":"https://public-firing-range.appspot.com/index.html"}'
    '],"config":{}}'
)


def test_parse_real_live_output_skips_the_plain_text_match_lines():
    """The real bug this guards against: json.loads(stdout) on the whole blob always fails (the
    plain-text match lines come first), which silently returned zero hits for every real scan
    until this was caught by actually running ffuf, not just reading its docs."""
    hits = parse_ffuf_output(_REAL_LIVE_OUTPUT)
    assert len(hits) == 2
    assert hits[0]["path"] == "address"
    assert hits[0]["url"] == "https://public-firing-range.appspot.com/address"
    assert hits[0]["status"] == 200
    assert hits[1]["path"] == "index.html"


def test_parse_output_with_zero_results():
    output = 'garbage line\n{"commandline":"x","results":[],"config":{}}'
    assert parse_ffuf_output(output) == []


def test_parse_malformed_output_returns_empty_list_not_a_crash():
    assert parse_ffuf_output("not json at all, just noise\nmore noise") == []


def _build_waf_flood_output(flood_count: int, real_hit: bool = False) -> str:
    """Synthesizes ffuf's own -of json shape: `flood_count` identical WAF-block-shaped hits
    (status=403, length=4570, words=656 -- the real shape confirmed live,
    a real YesWeHack session, usr_45dd32), optionally plus one genuinely distinct real hit."""
    results = [
        {"input": {"FUZZ": f"word{i}"}, "status": 403, "length": 4570, "words": 656, "redirectlocation": "", "url": f"https://example.com/word{i}"}
        for i in range(flood_count)
    ]
    if real_hit:
        results.append({"input": {"FUZZ": "backup.zip"}, "status": 200, "length": 128, "words": 4, "redirectlocation": "", "url": "https://example.com/backup.zip"})
    return json.dumps({"commandline": "ffuf ...", "results": results, "config": {}})


def test_parse_ffuf_output_collapses_a_waf_block_flood_into_one_summary_entry():
    """Real, confirmed incident: a real scan (a real YesWeHack session, usr_45dd32) against a
    Cloudflare-fronted host returned 9,570 of 9,570 "hits", every single one an identical WAF block
    page -- -ac's own runtime calibration didn't catch it. This deterministic downstream backstop
    must collapse a large uniform-shape flood to one clearly-labeled summary record."""
    hits = parse_ffuf_output(_build_waf_flood_output(50))

    assert len(hits) == 1
    assert hits[0]["status"] == 403
    assert "50 of 50" in hits[0]["note"]
    assert "WAF" in hits[0]["note"]


def test_parse_ffuf_output_keeps_a_genuinely_distinct_hit_alongside_the_collapsed_flood():
    """The collapse must never remove a real, distinctly-shaped result -- only the dominant,
    duplicate-shaped noise around it."""
    hits = parse_ffuf_output(_build_waf_flood_output(50, real_hit=True))

    assert len(hits) == 2
    real_hits = [h for h in hits if h.get("path") == "backup.zip"]
    assert len(real_hits) == 1
    assert real_hits[0]["status"] == 200
    summary_hits = [h for h in hits if "note" in h]
    assert len(summary_hits) == 1
    assert "50 of 51" in summary_hits[0]["note"]


def test_parse_ffuf_output_does_not_collapse_below_the_minimum_hit_threshold():
    """A small, real batch of same-shaped hits (a handful of identically-sized 404-alternative
    pages) is exactly the ambiguous case not worth collapsing -- only a large flood should."""
    hits = parse_ffuf_output(_build_waf_flood_output(5))
    assert len(hits) == 5
    assert all("note" not in h for h in hits)


def test_parse_ffuf_output_does_not_collapse_a_genuinely_mixed_result_set():
    """When no single response shape dominates, every hit is real signal -- nothing gets collapsed."""
    results = [
        {"input": {"FUZZ": f"path{i}"}, "status": 200, "length": 100 + i, "words": 10 + i, "redirectlocation": "", "url": f"https://example.com/path{i}"}
        for i in range(25)
    ]
    output = json.dumps({"commandline": "ffuf ...", "results": results, "config": {}})

    hits = parse_ffuf_output(output)

    assert len(hits) == 25
    assert all("note" not in h for h in hits)


def test_ffuf_is_registered_with_its_own_build_command_and_scan_category():
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("ffuf")
    assert spec.build_command is build_ffuf_command
    # Not "exploit" -- content discovery doesn't need the allowlist/human-approval gate exploit
    # tools require, same category as nikto/whatweb/nuclei.
    assert spec.category == "scan"
    assert spec.requires_allowed_target is False
