"""The Chain tab (templates/partials/session_fragment.html + macros/ui.html's tab_bar): session
["chain_attempts"] (agent/core.py's _persist_chain_attempt) was persisted server-side but had no
tab/UI surface at all before this -- an operator otherwise can't tell "Chain ran and genuinely
found nothing" apart from "Chain never ran". Same TestClient-against-a-real-saved-session pattern
as tests/test_hypothesis_ui.py.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, chain_attempts=None, credentials=None, status="completed"):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "hypotheses": [],
        "chain_attempts": chain_attempts if chain_attempts is not None else [],
        "asset_graph": {"credentials": credentials if credentials is not None else []},
    }


def test_chain_tab_appears_in_the_tab_bar():
    session_id = "usr_chain_tab_bar"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert 'id="tab-chain"' in resp.text
    assert "Chain" in resp.text


def test_chain_tab_renders_empty_state_when_never_run():
    session_id = "usr_chain_tab_empty"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Chain hasn&#39;t run yet." in resp.text or "Chain hasn't run yet." in resp.text


def test_chain_tab_renders_a_confirmed_chain_attempt():
    session_id = "usr_chain_tab_confirmed"
    attempt = {
        "ran_at": "2026-01-01T00:00:00+00:00",
        "outcome": "chain_confirmed",
        "finding_titles": ["Exposed sourcemap on scim.example.com"],
        "reasoning": "The sourcemap-confirmed op-scim version has a known, in-range CVE.",
        "evidence_quotes": ["op-scim 2.3.0 (from sourcemap)"],
        "tool_call_proof": "cve_lookup(product='op-scim 2.3.0') -> CVE-2024-12345 (in range)",
        "reverified_finding_titles": [],
        "material_considered": {"findings": 1, "recon_technologies": 1, "hypotheses": 0},
    }
    store.save_session(session_id, _session(session_id, chain_attempts=[attempt]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Chain confirmed" in resp.text
    assert "Exposed sourcemap on scim.example.com" in resp.text
    assert "op-scim 2.3.0 (from sourcemap)" in resp.text
    assert "cve_lookup(product=" in resp.text


def test_chain_tab_renders_impact_scenario_and_hop_badge():
    session_id = "usr_chain_tab_impact"
    attempt = {
        "ran_at": "2026-01-01T00:00:00+00:00",
        "hop": 2,
        "outcome": "chain_confirmed",
        "finding_titles": ["WAF bypass on /api", "Bypass reaches internal status endpoint"],
        "reasoning": "The bypass reaches a normally-blocked internal endpoint.",
        "impact_scenario": "An unauthenticated attacker uses the bypass to read internal build metadata.",
        "evidence_quotes": ["waf_evasion_probe bypassed the filter"],
        "tool_call_proof": "http_request(url='/internal/status', ...) -> 200",
        "reverified_finding_titles": [],
        "material_considered": {"findings": 1, "recon_technologies": 0, "hypotheses": 0},
    }
    store.save_session(session_id, _session(session_id, chain_attempts=[attempt]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "An unauthenticated attacker uses the bypass to read internal build metadata." in resp.text
    assert "Hop 2" in resp.text


def test_chain_tab_renders_a_no_chain_found_attempt():
    session_id = "usr_chain_tab_no_chain"
    attempt = {
        "ran_at": "2026-01-01T00:00:00+00:00",
        "outcome": "no_chain_found",
        "finding_titles": [],
        "reasoning": "No recon fact or hypothesis combined with the one finding to produce real impact.",
        "evidence_quotes": [],
        "tool_call_proof": None,
        "reverified_finding_titles": [],
        "material_considered": {"findings": 1, "recon_technologies": 0, "hypotheses": 0},
    }
    store.save_session(session_id, _session(session_id, chain_attempts=[attempt]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "No chain found" in resp.text
    assert "No recon fact or hypothesis combined" in resp.text


def test_chain_tab_shows_no_discovered_credentials_subsection_when_empty():
    session_id = "usr_chain_tab_no_creds"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Discovered credentials" not in resp.text


def test_chain_tab_renders_a_discovered_credential_with_identity_and_suggestions():
    session_id = "usr_chain_tab_creds"
    credential = {
        "id": "abc123", "username": "admin", "password": "admin123",
        "found_on_host": "host-a.example.com", "source_tool": "default_creds_check",
        "identity_name": "discovered_1", "discovered_at": "2026-01-01T00:00:00+00:00",
        "suggested_hosts": ["host-b.example.com"],
    }
    store.save_session(session_id, _session(session_id, credentials=[credential]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Discovered credentials" in resp.text
    assert "admin:admin123" in resp.text
    assert "host-a.example.com" in resp.text
    assert "discovered_1" in resp.text
    assert "host-b.example.com" in resp.text


def test_chain_tab_renders_a_credential_with_no_suggestions_yet():
    session_id = "usr_chain_tab_creds_none_yet"
    credential = {
        "id": "abc456", "username": "root", "password": "toor",
        "found_on_host": "host-c.example.com", "source_tool": "hydra",
        "identity_name": None, "discovered_at": "2026-01-01T00:00:00+00:00",
        "suggested_hosts": [],
    }
    store.save_session(session_id, _session(session_id, credentials=[credential]))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "root:toor" in resp.text
    assert "Not yet suggested against any other in-scope host." in resp.text
    assert "ready for authenticated_request" not in resp.text  # no identity_name -> no such line
