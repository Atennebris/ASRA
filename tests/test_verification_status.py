"""derive_verification_status collapses a finding's several confidence signals
(agent/verification_status.py) into one derived status + context trail, computed on read rather than
stored. These tests pin the precedence contract (which signal wins when several apply) and the shape
of the context trail, since the UI badge and the proof report both render off this one function."""
from agent.verification_status import (
    derive_verification_status,
    latest_reverify_outcome_by_title,
)


def test_needs_verification_is_the_default_for_a_bare_finding():
    result = derive_verification_status({})
    assert result["status"] == "needs_verification"
    assert result["disagreement"] is False
    assert result["independently_reproduced"] is False
    assert result["context"] == [{"source": "primary_analysis", "outcome": "needs_verification"}]


def test_plain_verified_finding_reports_verified():
    result = derive_verification_status({"verification": "verified"})
    assert result["status"] == "verified"


def test_inferred_finding_reports_inferred():
    assert derive_verification_status({"verification": "inferred"})["status"] == "inferred"


def test_false_positive_wins_over_every_other_signal():
    """An explicitly ruled-out finding is ruled out no matter how it was once graded -- the
    highest-precedence state so a human skimming never mistakes it for a live lead."""
    finding = {
        "verification": "verified",
        "skeptical_verification": "confirmed",
        "false_positive_reason": "version is outside the CVE's affected range",
        "ensemble_disagreement": True,
    }
    assert derive_verification_status(finding)["status"] == "false_positive"


def test_confirmed_fixed_reverify_outcome_reports_fixed():
    result = derive_verification_status({"verification": "verified"}, reverify_outcome="confirmed_fixed")
    assert result["status"] == "fixed"
    assert result["reverify_outcome"] == "confirmed_fixed"


def test_ensemble_disagreement_surfaces_as_disputed_even_when_verified():
    """A disagreement between two providers used to be computed and then shown nowhere. It must beat
    a plain 'verified' so the conflict is the thing an operator sees, not a hidden flag."""
    finding = {
        "verification": "verified",
        "ensemble_disagreement": True,
        "ensemble_secondary_verdict": "refuted",
        "ensemble_secondary_provider": "anthropic/claude-x",
    }
    result = derive_verification_status(finding)
    assert result["status"] == "disputed"
    assert result["disagreement"] is True


def test_refuted_skeptical_pass_reports_refuted_not_needs_verification():
    """A skeptical 'refuted' already downgrades the finding's own verification to needs_verification
    in core.py -- the derived status must still show the stronger 'refuted' so the operator sees it
    was actively disproven, not merely never checked."""
    finding = {"verification": "needs_verification", "skeptical_verification": "refuted"}
    assert derive_verification_status(finding)["status"] == "refuted"


def test_skeptical_confirmed_marks_independently_reproduced_but_stays_verified():
    finding = {"verification": "verified", "skeptical_verification": "confirmed"}
    result = derive_verification_status(finding)
    assert result["status"] == "verified"
    assert result["independently_reproduced"] is True


def test_context_trail_includes_every_pass_that_actually_ran():
    finding = {
        "verification": "verified",
        "skeptical_verification": "confirmed",
        "skeptical_verification_note": "reproduced the reflected payload independently",
        "ensemble_secondary_verdict": "confirmed",
        "ensemble_secondary_provider": "openai/gpt-x",
        "ensemble_secondary_note": "second model agrees",
    }
    context = derive_verification_status(finding, reverify_outcome="confirmed_present")["context"]
    sources = [entry["source"] for entry in context]
    assert sources == [
        "primary_analysis",
        "skeptical_verification",
        "ensemble_second_opinion",
        "reverify",
    ]
    skeptical_entry = next(e for e in context if e["source"] == "skeptical_verification")
    assert skeptical_entry["note"] == "reproduced the reflected payload independently"
    ensemble_entry = next(e for e in context if e["source"] == "ensemble_second_opinion")
    assert ensemble_entry["provider"] == "openai/gpt-x"


def test_context_trail_omits_passes_that_never_ran():
    context = derive_verification_status({"verification": "inferred"})["context"]
    assert context == [{"source": "primary_analysis", "outcome": "inferred"}]


def test_latest_reverify_outcome_by_title_keeps_the_most_recent_per_title():
    history = [
        {"title": "SQLi in /login", "verification_outcome": "confirmed_present"},
        {"title": "Open redirect", "verification_outcome": "inconclusive"},
        {"title": "SQLi in /login", "verification_outcome": "confirmed_fixed"},
    ]
    outcomes = latest_reverify_outcome_by_title(history)
    assert outcomes["SQLi in /login"] == "confirmed_fixed"
    assert outcomes["Open redirect"] == "inconclusive"


def test_latest_reverify_outcome_by_title_tolerates_none_and_empty():
    assert latest_reverify_outcome_by_title(None) == {}
    assert latest_reverify_outcome_by_title([]) == {}
    assert latest_reverify_outcome_by_title([{"title": "x"}]) == {}
