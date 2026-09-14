"""Finding detail card (session_fragment.html): agent/core.py's _run_skeptical_verification sets
finding.skeptical_verification/skeptical_verification_note -- "refuted" must be visibly distinct
(a real downgrade warning, not just quieter text) from "confirmed"/"inconclusive", and absent
(None, the default/never-ran case) must render neither block at all.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, findings):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": findings, "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


def _finding(**overrides):
    finding = {
        "title": "Reflected XSS in search", "severity": "Medium", "description": "desc",
        "verification": "verified", "exploited": False,
    }
    finding.update(overrides)
    return finding


def test_refuted_verdict_shows_the_downgrade_warning():
    session_id = "usr_skeptical_ui_refuted"
    finding = _finding(skeptical_verification="refuted", skeptical_verification_note="Re-ran the exact payload, response no longer reflects it unescaped.")
    store.save_session(session_id, _session(session_id, [finding]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Could not be independently reproduced" in resp.text
    assert "Re-ran the exact payload, response no longer reflects it unescaped." in resp.text


def test_confirmed_verdict_shows_the_badge():
    session_id = "usr_skeptical_ui_confirmed"
    finding = _finding(skeptical_verification="confirmed", skeptical_verification_note="Re-ran the payload, script still fires.")
    store.save_session(session_id, _session(session_id, [finding]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Independently reproduced" in resp.text
    assert "Could not be independently reproduced" not in resp.text


def test_inconclusive_verdict_shows_the_muted_note():
    session_id = "usr_skeptical_ui_inconclusive"
    finding = _finding(skeptical_verification="inconclusive", skeptical_verification_note="Target blocked every attempt with a WAF challenge.")
    store.save_session(session_id, _session(session_id, [finding]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "could not confirm or refute this independently" in resp.text
    assert "Target blocked every attempt with a WAF challenge." in resp.text


def test_no_skeptical_verification_renders_no_block_at_all():
    session_id = "usr_skeptical_ui_none"
    store.save_session(session_id, _session(session_id, [_finding()]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Independently reproduced" not in resp.text
    assert "Could not be independently reproduced" not in resp.text
    assert "could not confirm or refute this independently" not in resp.text
