"""agent/core.py's re_record_target_profile -- per-project durable target facts (RE mode), with
the source="tool"/"operator" provenance distinction: an operator-stated fact gets recorded and
built on immediately (no forced re-verification, that would just waste the operator's own time),
but stays visibly distinct from a tool-confirmed one so a later tool result touching the same fact
can correct it instead of a wrong operator guess silently staying "settled" forever.
"""
from __future__ import annotations

from agent.core import re_record_target_profile


def _params(session, **overrides):
    base = {"_session_id": "s1", "_session": session, "label": "Language", "value": "Go"}
    base.update(overrides)
    return base


def test_records_a_new_fact_with_default_source_tool(monkeypatch):
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {}

    result = re_record_target_profile(_params(session))

    assert result["status"] == "ok"
    assert result["recorded"] == {"label": "Language", "value": "Go", "source": "tool"}
    assert session["target_profile"] == [{"label": "Language", "value": "Go", "source": "tool"}]


def test_records_an_operator_stated_fact_with_explicit_source(monkeypatch):
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {}

    result = re_record_target_profile(_params(session, source="operator"))

    assert result["recorded"]["source"] == "operator"
    assert session["target_profile"][0]["source"] == "operator"


def test_updates_an_existing_label_in_place_not_duplicated(monkeypatch):
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {"target_profile": [{"label": "Language", "value": "Rust", "source": "tool"}]}

    re_record_target_profile(_params(session, value="Go"))

    assert len(session["target_profile"]) == 1
    assert session["target_profile"][0]["value"] == "Go"


def test_label_matching_is_case_insensitive(monkeypatch):
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {"target_profile": [{"label": "language", "value": "Rust", "source": "tool"}]}

    re_record_target_profile(_params(session, label="Language", value="Go"))

    assert len(session["target_profile"]) == 1
    assert session["target_profile"][0]["value"] == "Go"


def test_tool_correction_of_a_different_operator_claim_keeps_the_prior_value(monkeypatch):
    """The real gap this closes: an operator says "Rust" in chat (recorded as source=operator,
    unverified), then a LATER tool call (for some other reason) actually reveals it's Go -- the
    wrong operator claim must not be silently erased, it needs to stay visible as a correction."""
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {"target_profile": [{"label": "Language", "value": "Rust", "source": "operator"}]}

    result = re_record_target_profile(_params(session, value="Go", source="tool"))

    assert result["recorded"]["source"] == "tool"
    assert result["recorded"]["value"] == "Go"
    assert result["recorded"]["corrected_from_operator_claim"] == "Rust"
    entry = session["target_profile"][0]
    assert entry["value"] == "Go"
    assert entry["corrected_from_operator_claim"] == "Rust"


def test_tool_confirming_the_same_value_an_operator_already_stated_does_not_mark_a_correction(monkeypatch):
    """Confirming, not correcting -- the operator was right, so there's nothing to flag as wrong."""
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {"target_profile": [{"label": "Language", "value": "Go", "source": "operator"}]}

    result = re_record_target_profile(_params(session, value="Go", source="tool"))

    assert "corrected_from_operator_claim" not in result["recorded"]
    assert "corrected_from_operator_claim" not in session["target_profile"][0]
    assert session["target_profile"][0]["source"] == "tool"


def test_operator_source_overwriting_a_tool_value_does_not_mark_a_correction(monkeypatch):
    """corrected_from_operator_claim is specifically for a TOOL correcting an OPERATOR's own
    earlier claim -- the reverse direction (operator overwriting a tool-confirmed fact) isn't the
    same "we caught a wrong guess" event, so it gets no such marker."""
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {"target_profile": [{"label": "Language", "value": "Go", "source": "tool"}]}

    result = re_record_target_profile(_params(session, value="Rust", source="operator"))

    assert "corrected_from_operator_claim" not in result["recorded"]


def test_invalid_source_falls_back_to_tool(monkeypatch):
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    session = {}

    result = re_record_target_profile(_params(session, source="made-up-value"))

    assert result["recorded"]["source"] == "tool"


def test_missing_label_is_an_error(monkeypatch):
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    result = re_record_target_profile(_params({}, label=""))
    assert result["status"] == "error"


def test_missing_value_is_an_error(monkeypatch):
    monkeypatch.setattr("agent.core.save_session", lambda *a, **k: None)
    result = re_record_target_profile(_params({}, value=""))
    assert result["status"] == "error"


def test_missing_session_context_is_an_error():
    result = re_record_target_profile({"label": "Language", "value": "Go"})
    assert result["status"] == "error"
