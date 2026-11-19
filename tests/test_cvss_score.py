"""cvss_base_score turns a CVSS vector into the base score + severity a triager reads
(agent/cvss_score.py). The reference scores below are the published NVD values for these exact
vectors, so these tests also guard the formula against a silent regression."""
from agent.cvss_score import cvss_base_score, severity_rating


def test_critical_scope_unchanged_rce_vector():
    # CVSS:3.1 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> 9.8 Critical (NVD reference).
    result = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result["version"] == "3.1"
    assert result["score"] == 9.8
    assert result["severity"] == "Critical"


def test_scope_changed_vector_applies_the_1_08_multiplier():
    # CVSS:3.1 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' -> 10.0 Critical.
    result = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert result["score"] == 10.0
    assert result["severity"] == "Critical"


def test_medium_reflected_xss_vector():
    # CVSS:3.1 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' -> 6.1 Medium (classic reflected-XSS score).
    result = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert result["score"] == 6.1
    assert result["severity"] == "Medium"


def test_no_impact_metrics_scores_zero():
    result = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert result["score"] == 0.0
    assert result["severity"] == "None"


def test_v30_vector_is_scored_too():
    result = cvss_base_score("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert result["version"] == "3.0"
    assert result["score"] == 9.8


def test_v40_vector_returns_version_without_a_fabricated_score():
    """v4.0 scoring needs published lookup tables this module deliberately doesn't reimplement -- it
    must surface the version honestly, never a made-up number."""
    result = cvss_base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert result["version"] == "4.0"
    assert result["score"] is None
    assert result["severity"] is None


def test_non_cvss_string_returns_none():
    assert cvss_base_score("not a vector") is None
    assert cvss_base_score("") is None
    assert cvss_base_score(None) is None


def test_missing_required_metric_does_not_guess_a_score():
    # No impact metrics at all -- the formula can't run, so score is None rather than invented.
    result = cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
    assert result["version"] == "3.1"
    assert result["score"] is None


def test_severity_rating_band_edges():
    assert severity_rating(0.0) == "None"
    assert severity_rating(3.9) == "Low"
    assert severity_rating(4.0) == "Medium"
    assert severity_rating(6.9) == "Medium"
    assert severity_rating(7.0) == "High"
    assert severity_rating(8.9) == "High"
    assert severity_rating(9.0) == "Critical"
    assert severity_rating(10.0) == "Critical"
