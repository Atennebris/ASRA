"""/program (main.py) -- the drill-down from /dashboard's "By program" table into one target's
aggregated Recon Intelligence + Findings, defined as every session whose own target string matches
exactly (same grouping agent/core.py's compute_portfolio_summary already uses, see
tests/test_dashboard.py's sibling coverage of that). Monkeypatches main.list_session_summaries/
main.load_session directly -- the same names main.py's own /program route calls, not
agent.core's copies (a different import of the same underlying sessions.store functions).
"""
from fastapi.testclient import TestClient

import main


def _summary(session_id, target, created_at="2026-01-01T00:00:00+00:00"):
    return {"session_id": session_id, "target": target, "created_at": created_at}


def _session(session_id, target, name=None, created_at="2026-01-01T00:00:00+00:00", recon_result=None, findings=None):
    return {
        "session_id": session_id, "name": name or session_id, "target": target, "status": "completed",
        "created_at": created_at, "logs": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": recon_result or {}, "findings": findings or [],
    }


def test_program_route_404s_without_matching_sessions(monkeypatch):
    monkeypatch.setattr(main, "list_session_summaries", lambda: [_summary("s1", "other.com")])
    client = TestClient(main.app)

    resp = client.get("/program", params={"target": "example.com"})

    assert resp.status_code == 404


def test_program_route_aggregates_recon_and_findings_across_sessions(monkeypatch):
    sessions_by_id = {
        "s1": _session(
            "s1", "example.com", name="first scan", created_at="2026-01-01T00:00:00+00:00",
            recon_result={
                "targets": [{"host": "api.example.com", "port": 443, "service": "https", "version": "nginx"}],
                "dns_map": {"api.example.com": ["1.2.3.4"]},
                "technologies": {"api.example.com": ["Nginx[1.18]"]},
                "cves": ["CVE-2024-0001"],
            },
            findings=[{"title": "SQLi in login", "severity": "Critical", "description": "x", "verification": "verified"}],
        ),
        "s2": _session(
            "s2", "example.com", name="second scan", created_at="2026-01-02T00:00:00+00:00",
            recon_result={
                "targets": [{"host": "api.example.com", "port": 22, "service": "ssh", "version": "openssh"}],
                "dns_map": {"api.example.com": ["1.2.3.4"]},
                "technologies": {"api.example.com": ["Nginx[1.18]", "OpenSSH[8.9]"]},
                "cves": ["CVE-2024-0002"],
            },
            findings=[{"title": "Weak SSH ciphers", "severity": "Low", "description": "x", "verification": "verified"}],
        ),
    }
    monkeypatch.setattr(main, "list_session_summaries", lambda: [
        _summary("s1", "example.com", created_at="2026-01-01T00:00:00+00:00"),
        _summary("s2", "example.com", created_at="2026-01-02T00:00:00+00:00"),
        _summary("s3", "other.com"),
    ])
    monkeypatch.setattr(main, "load_session", lambda sid: sessions_by_id.get(sid))
    client = TestClient(main.app)

    resp = client.get("/program", params={"target": "example.com"})

    assert resp.status_code == 200
    html = resp.text
    # Both sessions' ports merged onto the SAME host card (DNS-identity merge), not two cards.
    assert html.count("api.example.com") >= 1
    assert "2 ports" in html
    # Both findings present, tagged back to their real origin session.
    assert "SQLi in login" in html
    assert "Weak SSH ciphers" in html
    assert "/session/s1" in html
    assert "/session/s2" in html


def test_aggregate_recon_merges_dns_and_dedupes_technologies():
    sessions = [
        {"recon_result": {"dns_map": {"h": ["1.1.1.1"]}, "technologies": {"h": ["Nginx[1.18]"]}, "cves": ["CVE-1"]}},
        {"recon_result": {"dns_map": {"h": ["1.1.1.1", "2.2.2.2"]}, "technologies": {"h": ["Nginx[1.18]", "PHP[8.1]"]}, "cves": ["CVE-1", "CVE-2"]}},
    ]

    merged = main._aggregate_recon_for_sessions(sessions)

    assert merged["dns_map"]["h"] == ["1.1.1.1", "2.2.2.2"]
    assert merged["technologies"]["h"] == ["Nginx[1.18]", "PHP[8.1]"]
    assert merged["cves"] == ["CVE-1", "CVE-2"]


def test_aggregate_findings_tags_each_with_its_source_session():
    sessions = [
        {"session_id": "s1", "name": "n1", "created_at": "2026-01-01T00:00:00+00:00", "findings": [{"title": "A", "severity": "High"}]},
        {"session_id": "s2", "name": "n2", "created_at": "2026-01-02T00:00:00+00:00", "findings": [{"title": "B", "severity": "Low"}]},
    ]

    merged = main._aggregate_findings_for_sessions(sessions)

    assert [f["title"] for f in merged] == ["A", "B"]
    assert merged[0]["_source_session_id"] == "s1"
    assert merged[1]["_source_session_id"] == "s2"


def test_program_route_caps_sessions_and_flags_truncated(monkeypatch):
    monkeypatch.setattr(main, "_PROGRAM_MAX_SESSIONS", 1)
    sessions_by_id = {
        "s1": _session("s1", "example.com", created_at="2026-01-02T00:00:00+00:00"),
        "s2": _session("s2", "example.com", created_at="2026-01-01T00:00:00+00:00"),
    }
    monkeypatch.setattr(main, "list_session_summaries", lambda: [
        _summary("s1", "example.com", created_at="2026-01-02T00:00:00+00:00"),
        _summary("s2", "example.com", created_at="2026-01-01T00:00:00+00:00"),
    ])
    monkeypatch.setattr(main, "load_session", lambda sid: sessions_by_id.get(sid))
    client = TestClient(main.app)

    resp = client.get("/program", params={"target": "example.com"})

    assert resp.status_code == 200
    assert "most recent sessions" in resp.text
