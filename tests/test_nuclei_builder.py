"""build_nuclei_command's default tag set -- pins the takeover/default-login/xss/ssrf additions
(each re-verified live against the real installed nuclei-templates set to actually have
templates before being added; earlier tags in this same constant were added for the same reason
originally, see the comment in agent/tools/builders/nuclei.py).
"""
import json

from agent.tools.builders.nuclei import build_nuclei_command, interpret_nuclei_failure, parse_nuclei_output


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


def test_command_always_disables_the_update_check():
    """Real, confirmed incident this fixes (Live-Nation-HackerOne-usr_0f5c71): a live timed scan
    against an approved target (ginandjuice.shop) with this exact tag/template setup did not
    finish even within 1800s, and a short diagnostic (-stats) run showed why -- it never got past
    "[INF] Your current nuclei-templates vX are outdated. Latest is vY", zero scan progress for
    the whole window. -duc must always be present so a real scan never blocks on that check again."""
    command = build_nuclei_command({"target": "https://example.com"})
    assert "-duc" in command


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


# --- parse_nuclei_output: CVE/CVSS/description/reference ---


def test_parse_nuclei_output_extracts_cve_classification_fields():
    """A CVE-tagged template's `info:` block already carries CVE id(s), CVSS score/vector, a
    description and advisory/PoC references -- real shape of a nuclei -jsonl CVE match."""
    line = json.dumps({
        "template-id": "CVE-2021-41773",
        "matched-at": "https://example.com/",
        "info": {
            "name": "Apache Path Traversal",
            "severity": "critical",
            "description": "Apache HTTP Server path traversal and RCE via CGI scripts.",
            "reference": [
                "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
                "https://github.com/some/poc",
            ],
            "classification": {
                "cve-id": ["CVE-2021-41773"],
                "cvss-score": 9.8,
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
        },
    })
    findings = parse_nuclei_output(line)
    assert len(findings) == 1
    f = findings[0]
    assert f["cve_ids"] == ["CVE-2021-41773"]
    assert f["cvss_score"] == 9.8
    assert f["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert f["description"] == "Apache HTTP Server path traversal and RCE via CGI scripts."
    assert f["references"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        "https://github.com/some/poc",
    ]


def test_parse_nuclei_output_handles_scalar_cve_id_and_single_reference():
    """Nuclei template YAML lets cve-id/reference be a single scalar instead of a list -- both
    shorthands must normalize to the same list shape."""
    line = json.dumps({
        "template-id": "cve-2022-0001",
        "matched-at": "https://example.com/",
        "info": {
            "name": "Something",
            "severity": "high",
            "reference": "https://example.com/advisory",
            "classification": {"cve-id": "cve-2022-0001"},
        },
    })
    f = parse_nuclei_output(line)[0]
    assert f["cve_ids"] == ["CVE-2022-0001"]
    assert f["references"] == ["https://example.com/advisory"]


def test_parse_nuclei_output_defaults_are_empty_for_a_non_cve_template():
    line = json.dumps({
        "template-id": "tech-detect",
        "matched-at": "https://example.com/",
        "info": {"name": "Tech Detect", "severity": "info"},
    })
    f = parse_nuclei_output(line)[0]
    assert f["cve_ids"] == []
    assert f["cvss_score"] is None
    assert f["cvss_vector"] is None
    assert f["description"] is None
    assert f["references"] == []
