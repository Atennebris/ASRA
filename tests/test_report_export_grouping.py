"""Grouping of near-duplicate findings in exported reports (agent/utils/report_export.py). Real
incident this guards against: a real rescan produced 9 near-identical "Fastly CDN Debug Headers
Exposure on <host>" findings, each independently and correctly confirmed on its own host -- not a
dedup bug -- but a flat report listed them as 9 separate issues, exactly the kind of thing a
HackerOne triager would bundle/duplicate-close on submission.
"""
from agent.utils.report_export import (
    _group_findings,
    _split_title_host_suffix,
    build_report_data,
    render_doc,
    render_docx,
    render_md,
    render_pdf,
    render_txt,
)


def _fastly_finding(host: str) -> dict:
    return {
        "title": f"Fastly CDN Debug Headers Exposure on {host}",
        "severity": "Low", "qualifies_for_bounty": "qualifying",
        "description": f"Fastly-Debug headers exposed on {host}.",
        "verification": "verified", "exploited": False,
        "evidence": f"curl -H 'Fastly-Debug: 1' https://{host}/",
    }


def _unique_finding() -> dict:
    return {
        "title": "Broad CORS Misconfiguration on tequila.kiwi.com",
        "severity": "Medium", "qualifies_for_bounty": "qualifying",
        "description": "Reflects any origin with credentials.",
        "verification": "verified", "exploited": False,
    }


# --- _split_title_host_suffix / _group_findings (pure data logic) ---


def test_split_title_host_suffix_extracts_a_trailing_host_clause():
    stripped, host = _split_title_host_suffix("Fastly CDN Debug Headers Exposure on auth.skypicker.com")
    assert stripped == "Fastly CDN Debug Headers Exposure"
    assert host == "auth.skypicker.com"


def test_split_title_host_suffix_none_when_no_host_suffix():
    assert _split_title_host_suffix("Broad CORS Misconfiguration") == (None, None)


def test_group_findings_collapses_same_issue_across_hosts():
    findings = [_fastly_finding("a.example.com"), _fastly_finding("b.example.com"), _fastly_finding("c.example.com")]
    groups = _group_findings(findings)
    assert len(groups) == 1
    assert groups[0]["group_title"] == "Fastly CDN Debug Headers Exposure"
    assert len(groups[0]["members"]) == 3
    assert groups[0]["hosts"] == ["a.example.com", "b.example.com", "c.example.com"]


def test_group_findings_leaves_a_unique_title_as_its_own_single_member_group():
    groups = _group_findings([_unique_finding()])
    assert len(groups) == 1
    assert groups[0]["group_title"] is None  # not really a group -- render like before this existed
    assert groups[0]["members"][0]["title"] == "Broad CORS Misconfiguration on tequila.kiwi.com"


def test_group_findings_never_merges_across_different_severities():
    low = _fastly_finding("a.example.com")
    high = _fastly_finding("b.example.com")
    high["severity"] = "High"  # same title shape, different severity -- must NOT merge
    groups = _group_findings([low, high])
    assert len(groups) == 2
    assert all(g["group_title"] is None for g in groups)


def test_group_findings_preserves_original_order_single_finding_does_not_group():
    # A lone finding sharing the title shape but with no SIBLING to group with stays singleton.
    groups = _group_findings([_fastly_finding("solo.example.com")])
    assert len(groups) == 1
    assert groups[0]["group_title"] is None


# --- build_report_data wiring ---


def test_build_report_data_includes_finding_groups():
    session = {"findings": [_fastly_finding("a.example.com"), _fastly_finding("b.example.com")]}
    data = build_report_data(session, "2026-11-20T00:00:00+00:00")
    assert len(data["findings"]) == 2  # flat list untouched
    assert len(data["finding_groups"]) == 1
    assert data["finding_groups"][0]["group_title"] == "Fastly CDN Debug Headers Exposure"


# --- render_txt / render_md: grouped output actually shows one heading + every host ---


def test_render_txt_shows_one_heading_for_a_grouped_issue_listing_every_host():
    session = {"findings": [_fastly_finding("a.example.com"), _fastly_finding("b.example.com"), _unique_finding()]}
    data = build_report_data(session, "2026-11-20T00:00:00+00:00")
    text = render_txt(data)
    # One shared heading for the Fastly group, not two separate "[n] Fastly..." headings.
    assert text.count("Fastly CDN Debug Headers Exposure --") == 1
    assert "a.example.com, b.example.com" in text
    assert "a.example.com" in text and "b.example.com" in text
    # The unrelated finding still gets its own ordinary heading.
    assert "Broad CORS Misconfiguration on tequila.kiwi.com -- Medium" in text


def test_render_txt_renders_a_singleton_finding_exactly_as_before_grouping_existed():
    session = {"findings": [_unique_finding()]}
    data = build_report_data(session, "2026-11-20T00:00:00+00:00")
    text = render_txt(data)
    assert "[1] Broad CORS Misconfiguration on tequila.kiwi.com -- Medium -- qualifying" in text
    assert "Reflects any origin with credentials." in text


def test_render_md_shows_one_heading_for_a_grouped_issue_listing_every_host():
    session = {"findings": [_fastly_finding("a.example.com"), _fastly_finding("b.example.com")]}
    data = build_report_data(session, "2026-11-20T00:00:00+00:00")
    md = render_md(data)
    assert md.count("### 1. Fastly CDN Debug Headers Exposure") == 1
    assert "#### a.example.com" in md
    assert "#### b.example.com" in md
    assert "independently confirmed on 2 hosts" in md


# --- render_pdf / render_docx / render_doc: must not crash on a mixed grouped+singleton set ---


def test_render_pdf_does_not_crash_on_a_mixed_grouped_and_singleton_set():
    session = {"findings": [_fastly_finding("a.example.com"), _fastly_finding("b.example.com"), _unique_finding()]}
    data = build_report_data(session, "2026-11-20T00:00:00+00:00")
    pdf_bytes = render_pdf(data)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")


def test_render_docx_does_not_crash_on_a_mixed_grouped_and_singleton_set():
    session = {"findings": [_fastly_finding("a.example.com"), _fastly_finding("b.example.com"), _unique_finding()]}
    data = build_report_data(session, "2026-11-20T00:00:00+00:00")
    docx_bytes = render_docx(data)
    assert isinstance(docx_bytes, bytes)
    assert docx_bytes.startswith(b"PK")  # docx is a zip container


def test_render_doc_does_not_crash_on_a_mixed_grouped_and_singleton_set():
    session = {"findings": [_fastly_finding("a.example.com"), _fastly_finding("b.example.com"), _unique_finding()]}
    data = build_report_data(session, "2026-11-20T00:00:00+00:00")
    doc_bytes = render_doc(data)
    assert isinstance(doc_bytes, bytes)
    assert doc_bytes.startswith(b"{\\rtf1")
    text = doc_bytes.decode("ascii")
    assert "a.example.com" in text
    assert "b.example.com" in text
