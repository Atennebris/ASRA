"""main.py's /api/session/{id}/export?format=... (agent/utils/report_export.py) -- the Export
button used to only ever produce one hardcoded HTML file; this covers every format the operator can
now pick, including the "all formats bundled together" zip.
"""
import zipfile
from io import BytesIO

from fastapi.testclient import TestClient

import main


def _completed_session(session_id):
    return {
        "session_id": session_id, "name": "test", "target": "example.com", "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "recon_result": {
            "targets": [{"host": "example.com", "port": 443, "service": "https", "version": "nginx"}],
            "cves": ["CVE-2024-0001"], "dns_map": {"example.com": ["93.184.216.34"]},
            "os_guesses": {}, "technologies": {}, "host_health": {},
        },
        "findings": [{
            "title": "SQL injection in login form", "severity": "High",
            "description": "Confirmed SQLi via the username parameter.",
            "verification": "verified", "exploited": True,
            "qualifies_for_bounty": "qualifying",
            "extracted_artifact": "admin:5f4dcc3b5aa765d61d8327deb882cf99",
            "artifact_usage_hint": "Use these credentials to log in as admin.",
            "evidence": "HTTP/1.1 200 OK\nSet-Cookie: session=abc123",
            "reproduction_steps": "1. Go to /login\n2. Submit admin' OR 1=1--",
        }],
        "chain_attempts": [
            {
                "ran_at": "2026-01-01T00:00:00+00:00",
                "hop": 1,
                "outcome": "chain_confirmed",
                "finding_titles": ["WAF bypass on /api", "SQL injection in login form"],
                "reasoning": "The WAF bypass reaches the login form's own injectable parameter.",
                "impact_scenario": "An unauthenticated attacker chains the WAF bypass with the SQL "
                "injection to dump the admin password hash and log in as admin.",
                "evidence_quotes": ["waf_evasion_probe bypassed the filter", "admin' OR 1=1-- -> 200"],
                "tool_call_proof": "sqlmap(url='/login', data='user=admin&pass=x') -> dumped admin:5f4dcc3b...",
                "reverified_finding_titles": [],
                "material_considered": {"findings": 2, "recon_technologies": 0, "hypotheses": 0},
            },
            {
                "ran_at": "2026-01-01T00:05:00+00:00",
                "hop": 1,
                "outcome": "no_chain_found",
                "finding_titles": [],
                "reasoning": "No further reusable evidence this pass.",
                "material_considered": {"findings": 2, "recon_technologies": 0, "hypotheses": 0},
            },
        ],
    }


def _client_and_session(session_id):
    from sessions import store
    session = _completed_session(session_id)
    store.save_session(session_id, session)
    return TestClient(main.app), session


def test_export_html_still_works():
    client, _ = _client_and_session("usr_export_html_test")
    resp = client.get("/api/session/usr_export_html_test/export?format=html")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "SQL injection in login form" in resp.text


def test_export_html_shows_confirmed_chain_impact_but_not_no_chain_found_passes():
    client, _ = _client_and_session("usr_export_html_chain_test")
    resp = client.get("/api/session/usr_export_html_chain_test/export?format=html")
    assert resp.status_code == 200
    assert "Attack chains" in resp.text
    assert "dump the admin password hash and log in as admin" in resp.text
    assert "No further reusable evidence this pass." not in resp.text


def test_export_defaults_to_html_when_format_omitted():
    client, _ = _client_and_session("usr_export_default_test")
    resp = client.get("/api/session/usr_export_default_test/export")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


def test_export_txt_contains_finding_content():
    client, _ = _client_and_session("usr_export_txt_test")
    resp = client.get("/api/session/usr_export_txt_test/export?format=txt")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert "SQL injection in login form" in resp.text
    assert "admin:5f4dcc3b5aa765d61d8327deb882cf99" in resp.text


def test_export_txt_contains_confirmed_chain_impact_but_not_no_chain_found_passes():
    client, _ = _client_and_session("usr_export_txt_chain_test")
    resp = client.get("/api/session/usr_export_txt_chain_test/export?format=txt")
    assert resp.status_code == 200
    assert "ATTACK CHAINS -- DEMONSTRATED IMPACT" in resp.text
    assert "WAF bypass on /api → SQL injection in login form" in resp.text
    assert "dump the admin password hash and log in as admin" in resp.text
    assert "No further reusable evidence this pass." not in resp.text


def test_export_md_contains_a_recon_table():
    client, _ = _client_and_session("usr_export_md_test")
    resp = client.get("/api/session/usr_export_md_test/export?format=md")
    assert resp.status_code == 200
    assert "text/markdown" in resp.headers["content-type"]
    assert "| Host | Port | Service | Version | Technologies |" in resp.text
    assert "example.com" in resp.text


def test_export_md_contains_confirmed_chain_impact():
    client, _ = _client_and_session("usr_export_md_chain_test")
    resp = client.get("/api/session/usr_export_md_chain_test/export?format=md")
    assert resp.status_code == 200
    assert "Attack chains" in resp.text
    assert "**Impact:** An unauthenticated attacker chains the WAF bypass" in resp.text


def test_export_pdf_is_a_real_pdf():
    client, _ = _client_and_session("usr_export_pdf_test")
    resp = client.get("/api/session/usr_export_pdf_test/export?format=pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")
    assert len(resp.content) > 500


def test_export_docx_is_a_real_docx():
    client, _ = _client_and_session("usr_export_docx_test")
    resp = client.get("/api/session/usr_export_docx_test/export?format=docx")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    # .docx is a real zip container -- PK magic bytes and a valid, openable archive.
    assert resp.content.startswith(b"PK")
    with zipfile.ZipFile(BytesIO(resp.content)) as zf:
        assert "word/document.xml" in zf.namelist()


def test_export_docx_contains_confirmed_chain_impact():
    from docx import Document

    client, _ = _client_and_session("usr_export_docx_chain_test")
    resp = client.get("/api/session/usr_export_docx_chain_test/export?format=docx")
    assert resp.status_code == 200
    doc = Document(BytesIO(resp.content))
    full_text = "\n".join(p.text for p in doc.paragraphs)
    assert "Attack chains" in full_text
    assert "dump the admin password hash and log in as admin" in full_text
    assert "No further reusable evidence this pass." not in full_text


def test_export_doc_is_real_rtf_content():
    client, _ = _client_and_session("usr_export_doc_test")
    resp = client.get("/api/session/usr_export_doc_test/export?format=doc")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/msword"
    # RTF's own real signature -- Word opens this correctly regardless of the .doc extension, but
    # it must actually BE RTF underneath, not some placeholder.
    assert resp.content.startswith(b"{\\rtf1")
    assert resp.content.rstrip().endswith(b"}")
    assert b"SQL injection in login form" in resp.content
    assert b"dump the admin password hash and log in as admin" in resp.content
    assert b"No further reusable evidence this pass." not in resp.content


def test_export_zip_bundles_every_format_and_a_readme():
    client, _ = _client_and_session("usr_export_zip_test")
    resp = client.get("/api/session/usr_export_zip_test/export?format=zip")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert "all-formats.zip" in resp.headers["content-disposition"]
    with zipfile.ZipFile(BytesIO(resp.content)) as zf:
        names = set(zf.namelist())
        assert names == {
            "README.txt",
            "asra-proof-usr_export_zip_test.html",
            "asra-proof-usr_export_zip_test.txt",
            "asra-proof-usr_export_zip_test.md",
            "asra-proof-usr_export_zip_test.pdf",
            "asra-proof-usr_export_zip_test.docx",
            "asra-proof-usr_export_zip_test.doc",
        }
        readme = zf.read("README.txt").decode("utf-8")
        assert "all formats bundled together" in readme


def test_export_rejects_unknown_format():
    client, _ = _client_and_session("usr_export_bad_format_test")
    resp = client.get("/api/session/usr_export_bad_format_test/export?format=exe")
    assert resp.status_code == 400
