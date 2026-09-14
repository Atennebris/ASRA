"""build_nuclei_command's default tag set -- pins the takeover/default-login/xss/ssrf additions
(each re-verified live against the real installed nuclei-templates set to actually have
templates before being added; earlier tags in this same constant were added for the same reason
originally, see the comment in agent/tools/builders/nuclei.py).
"""
from agent.tools.builders.nuclei import build_nuclei_command, interpret_nuclei_failure


def test_default_tags_include_the_original_and_the_new_confirmable_classes():
    command = build_nuclei_command({"target": "https://example.com"})
    tags = command[command.index("-tags") + 1]
    for expected in ("cve", "vuln", "exposure", "rce", "misconfig", "takeover", "default-login", "xss", "ssrf"):
        assert expected in tags.split(",")


def test_explicit_tags_argument_still_overrides_the_default():
    command = build_nuclei_command({"target": "https://example.com", "tags": "sqli"})
    assert command[command.index("-tags") + 1] == "sqli"


def test_tags_as_a_list_still_gets_joined():
    command = build_nuclei_command({"target": "https://example.com", "tags": ["xss", "ssrf"]})
    assert command[command.index("-tags") + 1] == "xss,ssrf"


def test_command_omits_raw_request_response_pairs_and_banner_noise():
    """Real incident this covers: two real nuclei calls in one session returned 2.27MB/1.73MB of
    raw stdout each, almost entirely embedded request/response pairs nothing downstream ever reads
    (parse_nuclei_output only extracts template_id/name/severity/matched_at) -- confirmed live
    against an approved test target, -omit-raw cut identical-match output by ~7x with the same set
    of matched template-ids."""
    command = build_nuclei_command({"target": "https://example.com"})
    assert "-silent" in command
    assert "-omit-raw" in command


_REAL_NO_TEMPLATES_STDERR = """
                     __     _
   ____  __  _______/ /__  (_)
  / __ \\/ / / / ___/ / _ \\/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\\__,_/\\___/_/\\___/_/   v3.11.0

		projectdiscovery.io

[WRN] Excluded 200 template[s] with known weak matchers / tags excluded from default run using .nuclei-ignore
[INF] Current nuclei version: v3.11.0 (latest)
[INF] Current nuclei-templates version: v10.4.6 (latest)
[INF] Targets loaded for current scan: 1
[INF] Scan completed in 314.937µs. No results found.
[FTL] Could not run nuclei: no templates provided for scan
"""


def test_interpret_nuclei_failure_recognizes_the_real_no_templates_error():
    hint = interpret_nuclei_failure({"status": "error", "stderr": _REAL_NO_TEMPLATES_STDERR})
    assert hint is not None
    assert "cve,vuln,exposure,rce,misconfig,takeover,default-login,xss,ssrf" in hint
    assert "cookies-without-httponly" in hint  # the confirmed real-incident example, kept as a concrete anti-pattern


def test_interpret_nuclei_failure_returns_none_for_an_unrelated_error():
    hint = interpret_nuclei_failure({"status": "error", "stderr": "some real network/target error, nothing to do with tags"})
    assert hint is None


def test_interpret_nuclei_failure_handles_a_missing_stderr_key():
    assert interpret_nuclei_failure({"status": "error"}) is None
