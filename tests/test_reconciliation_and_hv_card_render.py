"""Real HTTP render checks for the four template-facing pieces of this log-review pass's fix set:
reverify's three-outcome badges (was a boolean still_present), the frozen chain+validate
reconciliation line (was clobbered by a later validate re-entry), the hypothesis_verification
duration card (didn't exist at all), and the scope_rules_warning notice (didn't exist at all).
Mirrors tests/test_hypothesis_ui.py's own pattern -- a real TestClient hitting a real saved
session, not a hand-rolled Jinja render, so a template typo/undefined-variable would actually fail
these the way it would in production.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, **overrides):
    session = {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


def test_reverify_history_renders_all_three_outcomes():
    session_id = "usr_render_reverify_outcomes"
    store.save_session(session_id, _session(
        session_id,
        reverification_history=[
            {"title": "Still-broken bug", "verification_outcome": "confirmed_present", "reasoning": "re-fired the payload"},
            {"title": "Fixed bug", "verification_outcome": "confirmed_fixed", "reasoning": "now 404s"},
            {"title": "Blocked-by-waf bug", "verification_outcome": "inconclusive", "reasoning": "every attempt hit a challenge page"},
        ],
    ))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Still present" in resp.text
    assert "Resolved since last scan" in resp.text
    assert "Could not confirm or refute" in resp.text


def test_chain_validate_reconciliation_uses_the_frozen_reconciled_at_not_the_live_finished_at():
    """Real, confirmed incident this guards against: a later validate re-entry (a deep-dive or
    hypothesis-verification pass, hours after the original chain+validate run) pushed
    finished_at forward and made this line balloon to hours -- reconciled_at must be what's
    actually rendered."""
    session_id = "usr_render_reconciliation"
    store.save_session(session_id, _session(
        session_id,
        phase_timings={
            "chain": {"started_at": "2026-01-01T10:00:00+00:00", "finished_at": "2026-01-01T10:05:00+00:00"},
            "validate": {
                "started_at": "2026-01-01T10:05:00+00:00",
                # The live finished_at was pushed hours later by an unrelated re-entry...
                "finished_at": "2026-01-01T13:00:00+00:00",
                # ...but reconciled_at is what was actually frozen right after the original run.
                "reconciled_at": "2026-01-01T10:10:00+00:00",
            },
        },
    ))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Other processing (chain + validate): 10m 0s" in resp.text
    assert "2h" not in resp.text.split("Other processing (chain + validate)")[1][:20]


def test_hypothesis_verification_card_renders_the_accumulated_total_not_a_naive_span():
    session_id = "usr_render_hv_card"
    store.save_session(session_id, _session(
        session_id,
        phase_timings={
            # started_at pinned hours before finished_at (two passes far apart) -- a naive span
            # would read as ~3h; accumulated_seconds (900s = 15m) is the real total.
            "hypothesis_verification": {
                "started_at": "2026-01-01T10:00:00+00:00", "finished_at": "2026-01-01T13:00:00+00:00",
                "accumulated_seconds": 900,
            },
        },
    ))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Other processing (hypothesis verification): 15m 0s" in resp.text


def test_hypothesis_verification_card_absent_when_never_run():
    session_id = "usr_render_hv_card_absent"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "hypothesis verification" not in resp.text.lower()


def test_scope_rules_warning_renders_when_set():
    session_id = "usr_render_scope_warning"
    store.save_session(session_id, _session(session_id, scope_rules_warning="Scope rules were provided, but no finding ended up tagged."))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Scope rules were provided, but no finding ended up tagged." in resp.text


def test_scope_rules_warning_absent_by_default():
    session_id = "usr_render_scope_warning_absent"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Scope rules were provided" not in resp.text
