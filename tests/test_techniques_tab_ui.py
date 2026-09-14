"""The Techniques tab (templates/partials/session_fragment.html + macros/ui.html's tab_bar):
agent/tools/playbook_store.py's cross-session Playbook already records every technique the agent
captures (technique text, evidence, timestamp, vuln_class/purpose) keyed by source_session_ids, but
had no per-session UI surface -- an operator looking at one project's session had no way to see
"was any technique applied here, with what evidence, when, and for what". Same TestClient-against-
a-real-saved-session pattern as tests/test_chain_tab_ui.py, isolated playbook store file same as
tests/test_playbook_manager.py.
"""
import json

import pytest
from fastapi.testclient import TestClient

import main
from agent.tools import playbook_store
from sessions import store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")


def _session(session_id, status="completed"):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "hypotheses": [], "chain_attempts": [],
        "asset_graph": {"credentials": []},
    }


def _seed_technique(eid, session_ids, **extra):
    key = json.dumps({"tech": ["php"], "waf": []}, sort_keys=True)
    entry = {
        "id": eid, "technique": "Double URL-encoding bypasses the WAF's input filter",
        "vuln_class": "SQL injection", "payload_or_command": "id=1%2527%20OR%201=1",
        "evidence_ref": "HTTP 200, database error leaked in response body",
        "last_seen": "2026-01-02T00:00:00+00:00", "last_confirmed_at": "2026-01-02T00:00:00+00:00",
        "source_session_ids": session_ids, "outcome": "worked", "cves": [],
        **extra,
    }
    playbook_store.record_technique(key, entry)


def test_techniques_tab_appears_in_the_tab_bar():
    session_id = "usr_tech_tab_bar"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert 'id="tab-techniques"' in resp.text
    assert "Techniques" in resp.text


def test_techniques_tab_renders_empty_state_when_none_applied():
    session_id = "usr_tech_tab_empty"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "No technique applied yet this session." in resp.text


def test_techniques_tab_renders_a_technique_captured_this_session():
    session_id = "usr_tech_tab_applied"
    _seed_technique("tech1", [session_id])
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Technique applied" in resp.text
    assert "Double URL-encoding bypasses the WAF" in resp.text
    assert "SQL injection" in resp.text
    assert "database error leaked in response body" in resp.text
    assert "id=1%2527%20OR%201=1" in resp.text


def test_techniques_tab_shows_dead_end_badge_for_failed_outcome():
    session_id = "usr_tech_tab_deadend"
    _seed_technique("tech2", [session_id], outcome="failed")
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Dead-end" in resp.text


def test_techniques_tab_does_not_show_a_technique_from_a_different_session():
    session_id = "usr_tech_tab_other_session"
    _seed_technique("tech3", ["some_other_session"])
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "No technique applied yet this session." in resp.text
    assert "Double URL-encoding bypasses the WAF" not in resp.text
