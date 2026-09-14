"""The Hypotheses tab (templates/partials/session_fragment.html): a session["hypotheses"] entry
was persisted server-side long before this tab existed, but never rendered anywhere and had no
operator entry point at all. Mirrors tests/test_finding_card_exploited_display.py's pattern --
TestClient against a real saved session, relying on the global autouse SESSIONS_DIR/INDEX_PATH
isolation fixture in conftest.py, never a manual script (a manual, unisolated run of this exact
check once wrote a real project folder + real sessions_index.json entry outside pytest -- cleaned
up, but the lesson is to always go through pytest's isolation here, never a bare script).
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, hypotheses=None, status="completed"):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "hypotheses": hypotheses or [],
    }


def _hypothesis(**overrides):
    entry = {
        "id": "hyp001", "text": "staging debug mode might be on", "evidence": "", "source_phase": "recon",
        "source": "agent", "status": "unconfirmed", "resolution_note": None,
        "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
    }
    entry.update(overrides)
    return entry


def test_hypotheses_tab_renders_an_unconfirmed_entry():
    session_id = "usr_hyp_ui_unconfirmed"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis()]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Hypotheses" in resp.text
    assert "staging debug mode might be on" in resp.text
    assert "Unconfirmed" in resp.text


def test_hypotheses_tab_renders_confirmed_and_ruled_out_with_resolution_note():
    session_id = "usr_hyp_ui_resolved"
    hypotheses = [
        _hypothesis(id="h1", text="confirmed lead", status="confirmed", resolution_note="proved via record_finding"),
        _hypothesis(id="h2", text="ruled out lead", status="ruled_out", resolution_note="checked, not present"),
    ]
    store.save_session(session_id, _session(session_id, hypotheses=hypotheses))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "confirmed lead" in resp.text
    assert "proved via record_finding" in resp.text
    assert "Confirmed" in resp.text
    assert "ruled out lead" in resp.text
    assert "checked, not present" in resp.text
    assert "Ruled out" in resp.text


def test_hypotheses_tab_distinguishes_user_from_agent_source():
    session_id = "usr_hyp_ui_source"
    hypotheses = [_hypothesis(id="h1", text="user's own idea", source="user"), _hypothesis(id="h2", text="agent's own idea", source="agent")]
    store.save_session(session_id, _session(session_id, hypotheses=hypotheses))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Your hypothesis" in resp.text
    assert "Agent-found lead" in resp.text


def test_hypotheses_tab_empty_state_when_none_recorded():
    session_id = "usr_hyp_ui_empty"
    store.save_session(session_id, _session(session_id, hypotheses=[]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "No hypotheses yet." in resp.text


def test_hypotheses_tab_renders_for_a_session_predating_this_feature():
    """Backward compatibility: a real session saved before this feature existed has NO
    "hypotheses" key in its dict at all -- the template must not raise on session.hypotheses
    being fully absent, not just empty."""
    session_id = "usr_hyp_ui_legacy"
    legacy_session = _session(session_id)
    del legacy_session["hypotheses"]
    store.save_session(session_id, legacy_session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "No hypotheses yet." in resp.text


def test_investigate_now_button_shown_for_an_open_hypothesis_on_an_idle_session():
    session_id = "usr_hyp_ui_idle_button"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis()], status="completed"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Investigate now" in resp.text


def test_prioritize_now_button_shown_for_an_open_hypothesis_on_a_live_session():
    """Real operator-reported bug this fixes: the button used to be silently hidden whenever the
    session was live, with nothing on screen explaining why -- read as "some cards have it, some
    don't, no clear pattern." Now always present for every open hypothesis regardless of session
    state; only its own label (and what the backend route does with the click) differs."""
    session_id = "usr_hyp_ui_live_button"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis()], status="processing"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Prioritize now" in resp.text
    assert "Investigate now" not in resp.text


def test_investigate_button_never_shown_for_a_resolved_hypothesis():
    session_id = "usr_hyp_ui_resolved_no_button"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis(status="confirmed")], status="completed"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert "Investigate now" not in resp.text
    assert "Prioritize now" not in resp.text


def test_hypotheses_tab_shows_the_single_field_submit_form():
    session_id = "usr_hyp_ui_form"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert f'/api/session/{session_id}/hypotheses' in resp.text
    assert 'name="raw_text"' in resp.text
    assert 'name="text"' not in resp.text
    assert 'name="evidence"' not in resp.text


def test_verify_all_hypotheses_button_shown_on_an_idle_session_with_hypotheses():
    session_id = "usr_hyp_ui_verify_all_shown"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis()], status="completed"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert f"/api/session/{session_id}/hypotheses/verify-all" in resp.text
    assert "Verify/recheck all" in resp.text


def test_verify_all_hypotheses_button_hidden_on_a_live_session():
    session_id = "usr_hyp_ui_verify_all_hidden_live"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis()], status="processing"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert f"/api/session/{session_id}/hypotheses/verify-all" not in resp.text


def test_verify_all_hypotheses_button_hidden_with_no_hypotheses():
    session_id = "usr_hyp_ui_verify_all_hidden_empty"
    store.save_session(session_id, _session(session_id, hypotheses=[], status="completed"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert f"/api/session/{session_id}/hypotheses/verify-all" not in resp.text


def test_recon_tab_no_longer_duplicates_the_hypotheses_list():
    """Real, confirmed complaint this fixes: hypotheses used to render a second time inside the
    Recon tab, its own hand-rolled markup with no verify action -- the Hypotheses tab is now the
    only place this data renders, Recon shows only its own recon-specific content."""
    session_id = "usr_hyp_ui_no_recon_dup"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis(text="only rendered once")]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    # The Hypotheses tab (which comes before the Recon tab in the fragment) is the only place this
    # renders — the Recon tab and every later tab must not re-render the hypotheses list. Counting the
    # slice from the Recon tab onward instead of a whole-page count tolerates the card's own Copy
    # button, which legitimately embeds the same text a second time in its data-copy-text payload
    # inside the Hypotheses tab card itself.
    recon_tab_start = resp.text.index('data-tab="recon"')
    assert "only rendered once" not in resp.text[recon_tab_start:]


def test_verify_all_hypotheses_route_starts_a_background_task_on_an_idle_session(monkeypatch):
    session_id = "usr_hyp_ui_verify_all_post"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis()], status="completed"))
    started = []
    monkeypatch.setattr(main, "run_all_hypotheses_verification", lambda sid: started.append(sid))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/hypotheses/verify-all")

    assert resp.status_code == 200
    assert started == [session_id]


def test_verify_all_hypotheses_route_rejects_a_live_session():
    session_id = "usr_hyp_ui_verify_all_live_reject"
    store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis()], status="processing"))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/hypotheses/verify-all")

    assert resp.status_code == 409
