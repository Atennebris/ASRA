"""main.py's recon_stats Jinja filter -- the Recon / Asset Info tab's concrete counts (hosts,
domains vs. subdomains discovered, unique IPs, open ports, CVEs) surfaced above the existing
per-target detail cards.
"""
from fastapi.testclient import TestClient

import main
from main import _recon_stats


def _session(session_id, target, targets, dns_map, cves):
    return {
        "session_id": session_id, "name": "test", "target": target, "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": targets, "cves": cves, "dns_map": dns_map, "os_guesses": {}, "technologies": {}, "host_health": {}},
    }


def test_recon_stats_splits_original_scope_domain_from_discovered_subdomains():
    session = _session(
        "usr_stats_test",
        target="*.example.com",
        targets=[
            {"host": "example.com", "port": 443, "service": "https", "version": None},
            {"host": "www.example.com", "port": 443, "service": "https", "version": None},
            {"host": "www.example.com", "port": 80, "service": "http", "version": None},
        ],
        dns_map={"example.com": ["93.184.216.34"], "www.example.com": ["93.184.216.35"]},
        cves=["CVE-2024-0001"],
    )
    stats = _recon_stats(session)

    assert stats["hosts_scanned"] == 2  # example.com + www.example.com, not 3 (one host has 2 ports)
    assert stats["domains"] == 1  # example.com itself matches the original *.example.com scope entry
    assert stats["subdomains_discovered"] == 1  # www.example.com is not the literal scope entry
    assert stats["unique_ips"] == 2
    assert stats["open_ports"] == 3  # every recon_target row is its own open port
    assert stats["cves_found"] == 1


def test_recon_stats_counts_ips_recorded_directly_as_targets():
    session = _session(
        "usr_stats_ip_test",
        target="203.0.113.5",
        targets=[{"host": "203.0.113.5", "port": 22, "service": "ssh", "version": "OpenSSH"}],
        dns_map={},
        cves=[],
    )
    stats = _recon_stats(session)

    assert stats["hosts_scanned"] == 1
    assert stats["unique_ips"] == 1  # the IP itself, even with no dns_map entry at all
    assert stats["domains"] == 0
    assert stats["subdomains_discovered"] == 0


def test_recon_stats_tile_renders_on_the_live_session_page():
    from sessions import store
    session_id = "usr_stats_render_test"
    session = _session(
        session_id,
        target="example.com",
        targets=[{"host": "example.com", "port": 443, "service": "https", "version": None}],
        dns_map={"example.com": ["93.184.216.34"]},
        cves=[],
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "Hosts" in resp.text
    assert "Subdomains" in resp.text
    assert "Unique IPs" in resp.text


def test_recon_stats_returns_domain_and_subdomain_host_sets():
    session = _session(
        "usr_stats_sets_test",
        target="*.example.com",
        targets=[
            {"host": "example.com", "port": 443, "service": "https", "version": None},
            {"host": "www.example.com", "port": 443, "service": "https", "version": None},
        ],
        dns_map={},
        cves=[],
    )
    stats = _recon_stats(session)

    assert stats["domain_hosts"] == {"example.com"}
    assert stats["subdomain_hosts"] == {"www.example.com"}


# --- Recon tab's stat-tile filters (static/js/recon_filter.js): the tiles themselves and each
# target row's own data-filter-category/data-filter-ip attributes, sourced from the exact same
# domain_hosts/subdomain_hosts sets the tile counts came from.


def test_recon_target_rows_carry_the_matching_filter_category():
    from sessions import store
    session_id = "usr_stats_filter_category_test"
    session = _session(
        session_id,
        target="*.example.com",
        targets=[
            {"host": "example.com", "port": 443, "service": "https", "version": None},
            {"host": "www.example.com", "port": 443, "service": "https", "version": None},
            {"host": "203.0.113.5", "port": 22, "service": "ssh", "version": None},
        ],
        dns_map={},
        cves=[],
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert 'data-filter-category="domain"' in resp.text
    assert 'data-filter-category="subdomain"' in resp.text
    assert 'data-filter-ip="true"' in resp.text


def test_recon_filter_tiles_and_empty_message_render():
    from sessions import store
    session_id = "usr_stats_filter_tiles_test"
    session = _session(
        session_id,
        target="example.com",
        targets=[{"host": "example.com", "port": 443, "service": "https", "version": None}],
        dns_map={},
        cves=[],
    )
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert "data-recon-filter-tile" in resp.text
    assert 'data-filter="domain"' in resp.text
    assert 'data-filter="subdomain"' in resp.text
    assert 'data-filter="ip"' in resp.text
    assert 'data-filter="cves"' in resp.text
    assert "data-recon-filter-empty" in resp.text
