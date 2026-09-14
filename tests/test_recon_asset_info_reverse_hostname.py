"""session_fragment.html's Recon / Asset Info tab (and proof_report.html's exported table): a
recon target's own "host" is sometimes the literal IP itself (nmap's own output is IP-based, and a
model reasoning straight from an nmap result naturally records that IP as "host" rather than the
hostname that resolved to it) -- confirmed live: a real rescan recorded every target by IP, and
with no reverse lookup against recon_result["dns_map"], the operator lost every human-readable
hostname this tab used to show, even though dns_map already has the exact reverse mapping needed.
"""
from fastapi.testclient import TestClient

import main


def _session(session_id, targets, dns_map):
    return {
        "session_id": session_id, "name": "test", "target": "https://unrelated-app.example", "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": targets, "cves": [], "dns_map": dns_map, "os_guesses": {}, "technologies": {}, "host_health": {}},
    }


def test_asset_info_shows_the_known_hostname_for_an_ip_only_target(tmp_path, monkeypatch):
    from sessions import store
    session_id = "usr_reverse_hostname_test"
    session = _session(
        session_id,
        targets=[{"host": "185.132.176.192", "port": 443, "service": "https", "version": "nginx"}],
        dns_map={"example.com": ["185.132.176.192"]},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "example.com" in resp.text
    assert "185.132.176.192" in resp.text


def test_asset_info_shows_nothing_extra_when_the_ip_matches_no_known_hostname(tmp_path, monkeypatch):
    from sessions import store
    session_id = "usr_reverse_hostname_unknown_test"
    session = _session(
        session_id,
        targets=[{"host": "203.0.113.5", "port": 22, "service": "ssh", "version": "OpenSSH"}],
        dns_map={"example.com": ["185.132.176.192"]},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "203.0.113.5" in resp.text
    # Scoped to before the Map tab's own attack-surface JSON blob (main.py's
    # _build_attack_surface_graph) -- that tab legitimately lists EVERY dns_map entry as its own
    # node, "example.com" included, since it's real recon data worth showing on the map even though
    # it's unrelated to 203.0.113.5's own target. This test's actual claim is narrower: the Recon
    # tab's own Asset Info card for 203.0.113.5 specifically must not show it.
    recon_tab_text = resp.text.split('id="attack-surface-data"')[0]
    assert "example.com" not in recon_tab_text


def test_asset_info_lists_every_hostname_sharing_the_same_ip(tmp_path, monkeypatch):
    """A CDN-fronted IP (Cloudflare, shared hosting) commonly resolves for several hostnames at
    once -- all of them are real and relevant, not just the first one found."""
    from sessions import store
    session_id = "usr_reverse_hostname_multi_test"
    session = _session(
        session_id,
        targets=[{"host": "104.21.4.96", "port": 443, "service": "https", "version": None}],
        dns_map={
            "library.example.com": ["104.21.4.96"],
            "p-ab-test.example.com": ["104.21.4.96"],
        },
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "library.example.com" in resp.text
    assert "p-ab-test.example.com" in resp.text


def test_asset_info_still_shows_resolved_ips_for_a_domain_host_unchanged(tmp_path, monkeypatch):
    """Regression guard: the ORIGINAL direction (host is a domain -> show its resolved IP) must
    keep working exactly as before -- this fix only adds the missing reverse direction."""
    from sessions import store
    session_id = "usr_reverse_hostname_original_direction_test"
    session = _session(
        session_id,
        targets=[{"host": "example.com", "port": 443, "service": "https", "version": "nginx"}],
        dns_map={"example.com": ["185.132.176.192"]},
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "185.132.176.192" in resp.text
