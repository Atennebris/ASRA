"""CVE auto-record version gating: a real, reported false-positive problem — cve_lookup(product)
returns every CVE that product name has ever had, and _run_analyze used to auto-record a finding
card for every single one regardless of whether the actual installed version (already sitting in
Recon's own target list) falls in the affected range at all. This exercises the fix: a CVE whose
range is confirmed NOT to include the real installed version gets false_positive_reason set (kept
for audit trail, not silently dropped) instead of reading as an equally-weighted live lead, and the
exploit phase skips it deterministically without spending an LLM call re-discovering the same
conclusion.
"""
import asyncio
import dataclasses

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_analyze, _run_exploit
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.native import (
    _affected_version_bounds,
    _parse_combined_range_string,
    _parse_dotted_version,
    _version_definitely_not_affected,
    version_is_ruled_out,
)
from agent.tools.registry import TOOL_REGISTRY
from sessions import store


def _run(coro):
    return asyncio.run(coro)


# --- pure unit tests for the version-comparison primitives (no LLM, no session) ---


def test_parse_dotted_version_pulls_the_leading_numeric_version_out_of_free_text():
    assert _parse_dotted_version("nginx 1.14.0 (Ubuntu)") == (1, 14, 0)
    assert _parse_dotted_version("1.13.2") == (1, 13, 2)


def test_parse_dotted_version_returns_none_when_nothing_dotted_numeric_is_present():
    assert _parse_dotted_version("Cloudflare http proxy") is None


def test_affected_version_bounds_reads_lessthan_as_an_exclusive_upper_bound():
    cna = {"affected": [{"versions": [{"status": "affected", "version": "0.5.6", "lessThan": "1.13.2"}]}]}
    assert _affected_version_bounds(cna) == [((0, 5, 6), (1, 13, 2), False)]


def test_affected_version_bounds_treats_a_bare_zero_lower_bound_as_unbounded():
    """This dataset's convention for "every version before the fix", not literally version 0.0."""
    cna = {"affected": [{"versions": [{"status": "affected", "version": "0", "lessThan": "0.8.14"}]}]}
    assert _affected_version_bounds(cna) == [(None, (0, 8, 14), False)]


# --- GitHub-CNA combined range strings (real incident: Ghost CMS CVEs on a real scan) ---


def test_parse_combined_range_string_reads_both_edges():
    assert _parse_combined_range_string(">= 3.24.0, < 6.19.1") == ((3, 24, 0), (6, 19, 1), False)


def test_parse_combined_range_string_reads_an_inclusive_upper_edge():
    assert _parse_combined_range_string(">= 1.0.0, <= 1.2.3") == ((1, 0, 0), (1, 2, 3), True)


def test_parse_combined_range_string_handles_an_upper_edge_only():
    assert _parse_combined_range_string("< 6.19.1") == (None, (6, 19, 1), False)


def test_parse_combined_range_string_returns_none_for_a_plain_version_with_no_operator():
    """A normal single-version entry (most CNAs' convention) must fall through to the existing
    version + lessThan/lessThanOrEqual field-based parsing, not be mistaken for a combined range."""
    assert _parse_combined_range_string("1.13.2") is None


def test_affected_version_bounds_parses_a_github_style_combined_range_in_the_version_field():
    """Real incident this fixes: GitHub-issued GHSA-derived CVEs (confirmed live on Ghost CMS'
    own advisory data) put the whole range in "version" instead of using lessThan/
    lessThanOrEqual — the field-based parser silently dropped the upper bound entirely, so a
    genuinely patched install (e.g. Ghost 6.54, fixed in 6.19.1) could never be ruled out.
    """
    cna = {"affected": [{"versions": [{"status": "affected", "version": ">= 3.24.0, < 6.19.1"}]}]}
    assert _affected_version_bounds(cna) == [((3, 24, 0), (6, 19, 1), False)]


def test_version_is_ruled_out_true_for_a_patched_version_past_a_combined_range_upper_bound():
    cna = {"affected": [{"versions": [{"status": "affected", "version": ">= 3.24.0, < 6.19.1"}]}]}
    bounds = _affected_version_bounds(cna)
    assert version_is_ruled_out("Ghost CMS 6.54", bounds) is True
    assert version_is_ruled_out("Ghost CMS 5.0.0", bounds) is False


def test_version_definitely_not_affected_survives_a_json_cache_round_trip():
    """cve_lookup's result is cached to a JSON file (cache.py) and read back with json.load, which
    turns every tuple _affected_version_bounds built into a plain list -- real incident this fixes:
    a bare list-vs-tuple "<" comparison raised TypeError, crashing the whole Analyze phase outright
    the first time a cached (not freshly-computed) CVE lookup hit this path.
    """
    bounds_after_json_round_trip = [[[3, 24, 0], [6, 19, 1], False]]
    assert _version_definitely_not_affected((6, 54), bounds_after_json_round_trip) is True
    assert _version_definitely_not_affected((5, 0, 0), bounds_after_json_round_trip) is False


def test_version_definitely_not_affected_true_when_confirmed_version_is_above_every_range():
    bounds = [((0, 5, 6), (1, 13, 2), False)]
    assert _version_definitely_not_affected((1, 14, 0), bounds) is True


def test_version_definitely_not_affected_false_when_version_falls_inside_a_range():
    bounds = [((0, 5, 6), (1, 13, 2), False)]
    assert _version_definitely_not_affected((1, 0, 0), bounds) is False


def test_version_definitely_not_affected_false_when_there_are_no_bounds_to_check_against():
    """Absence of data must never be read as proof of exclusion."""
    assert _version_definitely_not_affected((1, 14, 0), []) is False


def test_version_is_ruled_out_false_when_the_confirmed_version_text_does_not_parse():
    bounds = [((0, 5, 6), (1, 13, 2), False)]
    assert version_is_ruled_out("Cloudflare http proxy", bounds) is False


def test_version_is_ruled_out_true_for_a_real_confirmed_version_above_the_range():
    bounds = [((0, 5, 6), (1, 13, 2), False)]
    assert version_is_ruled_out("nginx 1.14.0 (Ubuntu)", bounds) is True


# --- _affected_version_bounds: text fallback ("fixed in X.Y") when cna.affected[] is empty ---
# Real incident this fixes: CVE-2023-25136's own record has no structured "affected" array at
# all -- the only place the fix version appears is prose ("This is fixed in OpenSSH 9.2."). The
# confirmed installed version (9.2p1) is unambiguously patched, but the gate could never say so,
# costing a whole exploit-phase LLM round-trip to work out by hand what a substring match answers
# for free.


def _cna_with_description(text):
    return {"descriptions": [{"lang": "en", "value": text}]}


def test_affected_version_bounds_falls_back_to_fixed_in_phrasing_when_no_structured_range():
    cna = _cna_with_description(
        "OpenSSH server (sshd) 9.1 introduced a double-free vulnerability. This is fixed in OpenSSH 9.2."
    )
    assert _affected_version_bounds(cna) == [(None, (9, 2), False)]


def test_affected_version_bounds_text_fallback_recognizes_patched_in_phrasing():
    cna = _cna_with_description("A buffer overflow exists in the parser. Patched in 2.4.1.")
    assert _affected_version_bounds(cna) == [(None, (2, 4, 1), False)]


def test_affected_version_bounds_text_fallback_recognizes_resolved_in_phrasing():
    cna = _cna_with_description("The issue was resolved in version 3.0.")
    assert _affected_version_bounds(cna) == [(None, (3, 0), False)]


def test_affected_version_bounds_text_fallback_empty_when_no_fix_version_mentioned():
    cna = _cna_with_description("A theoretical vulnerability with no known fix at this time.")
    assert _affected_version_bounds(cna) == []


def test_affected_version_bounds_prefers_structured_data_over_text_when_both_exist():
    cna = {
        "descriptions": [{"lang": "en", "value": "Fixed in 9.9 per the changelog, but see the real range below."}],
        "affected": [{"versions": [{"status": "affected", "version": "1.0.0", "lessThan": "2.0.0"}]}],
    }
    assert _affected_version_bounds(cna) == [((1, 0, 0), (2, 0, 0), False)]


def test_version_is_ruled_out_true_via_text_fallback_for_a_patched_confirmed_version():
    cna = _cna_with_description(
        "OpenSSH server (sshd) 9.1 introduced a double-free vulnerability. This is fixed in OpenSSH 9.2."
    )
    bounds = _affected_version_bounds(cna)
    assert version_is_ruled_out("OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)", bounds) is True
    assert version_is_ruled_out("OpenSSH 9.1p1 Debian", bounds) is False


# --- integration: _run_analyze's cve_lookup auto-record, with a real recon_result["targets"] ---


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0
        self.last_messages = None

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        self.last_messages = messages
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def _swap_cve_lookup(fake_result):
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, native_function=lambda params: fake_result)
    return index, original_spec


_NGINX_2017_7529 = {
    "status": "ok",
    "cve_ids": ["CVE-2017-7529"],
    "details": {
        "CVE-2017-7529": {
            "description": "Integer overflow in nginx range filter module.",
            "severity": "Medium",
            "affected_versions": "0.5.6 – 1.13.2",
            "affected_version_bounds": [((0, 5, 6), (1, 13, 2), False)],
            "references": ["http://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html"],
        },
    },
}


def test_auto_record_flags_false_positive_when_confirmed_version_is_outside_the_cve_range(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec = _swap_cve_lookup(_NGINX_2017_7529)
    try:
        recon_result = {"targets": [{"host": "beta-www.example.com", "port": 443, "service": "ssl/http", "version": "nginx 1.14.0 (Ubuntu)"}], "cves": []}
        session = {
            "session_id": "usr_cve_ruled_out", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            # _run_analyze reads confirmed targets from ctx.session["recon_result"], not from its
            # own recon_result parameter (that one only shapes the task text shown to the LLM) —
            # must be pre-populated here for the auto-record gate to see it.
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "nginx"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        finding = session["findings"][0]
        assert finding["false_positive_reason"] is not None
        assert "beta-www.example.com" in finding["false_positive_reason"]
        assert "1.14.0" in finding["technology"]
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_auto_record_leaves_false_positive_reason_unset_when_confirmed_version_is_inside_the_range(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec = _swap_cve_lookup(_NGINX_2017_7529)
    try:
        recon_result = {"targets": [{"host": "old.example.com", "port": 443, "service": "ssl/http", "version": "nginx 1.10.0"}], "cves": []}
        session = {
            "session_id": "usr_cve_in_range", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": recon_result,
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "nginx"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", recon_result))

        finding = session["findings"][0]
        assert finding["false_positive_reason"] is None
        assert "old.example.com" in finding["technology"]
    finally:
        TOOL_REGISTRY[index] = original_spec


def test_auto_record_creates_nothing_with_no_confirmed_target_at_all(tmp_path, monkeypatch):
    """No ground truth means no card and no CVE chip at all -- a product-name match with zero
    evidence any in-scope host runs it is noise, not a lead, and must not be recorded as either.
    """
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec = _swap_cve_lookup(_NGINX_2017_7529)
    try:
        session = {
            "session_id": "usr_cve_unknown", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "nginx"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", {"targets": []}))

        assert session["findings"] == []
        assert session["recon_result"]["cves"] == []
    finally:
        TOOL_REGISTRY[index] = original_spec


# --- integration: exploit phase deterministically skips a ruled-out / non-qualifying finding ---


class _FailIfCalledLLM:
    """Exploit must never even ask this model anything for a finding that's already been ruled
    out or marked non-qualifying — any call at all is the bug."""
    provider_id = "test-provider"
    model = "test-model"

    def complete(self, messages, tools=None, stop_check=None):
        raise AssertionError("exploit phase should have skipped this finding without any LLM call")


def test_exploit_phase_skips_a_false_positive_finding_without_any_llm_call(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {
        "session_id": "usr_skip_fp", "target": "example.com", "status": "processing",
        "logs": [],
        "findings": [{
            "title": "nginx — CVE-2017-7529", "severity": "Medium", "verification": "inferred",
            "false_positive_reason": "Confirmed version 1.14.0 is outside the affected range.",
        }],
        "approvals": [], "chat": {"summary": "", "messages": []},
    }
    ctx = RunContext(llm=_FailIfCalledLLM(), session=session, session_id=session["session_id"])

    _run(_run_exploit(ctx, "example.com"))

    finding = session["findings"][0]
    assert finding["exploited"] is False
    assert finding["advisory_note"] == "Confirmed version 1.14.0 is outside the affected range."


def test_exploit_phase_skips_a_non_qualifying_finding_without_any_llm_call(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {
        "session_id": "usr_skip_nq", "target": "example.com", "status": "processing",
        "logs": [],
        "findings": [{
            "title": "Missing security headers", "severity": "Low", "verification": "verified",
            "qualifies_for_bounty": "non_qualifying",
        }],
        "approvals": [], "chat": {"summary": "", "messages": []},
    }
    ctx = RunContext(llm=_FailIfCalledLLM(), session=session, session_id=session["session_id"])

    _run(_run_exploit(ctx, "example.com"))

    finding = session["findings"][0]
    assert finding["exploited"] is False
    assert "Non-qualifying" in finding["advisory_note"]
