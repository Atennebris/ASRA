"""Finding card external badges (templates/macros/ui.html's exploited_badge + the already-existing
bounty_badge/false_positive_badge, now also rendered on the collapsed Findings-tab card itself, not
just inside the detail dialog) -- real operator ask: someone triaging many scans a day needs
exploited/not, qualifying/not, false-positive-or-not readable straight off the closed card, without
opening every single one.
"""
import pathlib
import tempfile

from fastapi.testclient import TestClient

import main
from sessions import store


def _client_with_session(session):
    tmp = pathlib.Path(tempfile.mkdtemp())
    store.SESSIONS_DIR = tmp
    store.INDEX_PATH = tmp / "sessions_index.json"
    main.SESSIONS_DIR = tmp
    store.save_session(session["session_id"], session)
    return TestClient(main.app)


def _base_session(session_id, findings):
    return {
        "session_id": session_id, "name": "test", "target": "example.com", "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "findings": findings,
    }


def test_exploited_finding_shows_exploited_badge_on_the_card():
    session = _base_session("usr_badge_exploited", [
        {"title": "RCE via deserialization", "severity": "Critical", "description": "x", "verification": "verified", "exploited": True},
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_exploited").text
    # The card list appears before the dialog block -- check the badge shows up at all, and that
    # it appears (at least) twice: once on the card, once inside the dialog.
    assert html.count("Exploited") >= 2


def test_skipped_finding_with_advisory_note_shows_not_exploitable_badge():
    session = _base_session("usr_badge_not_exploitable", [
        {
            "title": "CORS misconfiguration", "severity": "Medium", "description": "x", "verification": "verified",
            "exploited": False, "advisory_note": "No credentialed session available to demonstrate impact.",
        },
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_not_exploitable").text
    assert "Not exploitable" in html


def test_pending_finding_shows_no_exploited_badge_yet():
    """exploited=False with no advisory_note means Exploit hasn't reached this finding yet -- no
    badge at all, matching scenario_badge/bounty_badge's own "nothing to report yet" restraint."""
    session = _base_session("usr_badge_pending", [
        {"title": "Untested finding", "severity": "Low", "description": "x", "verification": "needs_verification", "exploited": False},
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_pending").text
    assert "Not exploitable" not in html
    assert "&#9873; Exploited" not in html


def test_qualifying_finding_shows_bounty_badge_on_the_card():
    session = _base_session("usr_badge_qualifying", [
        {"title": "SQLi in login form", "severity": "High", "description": "x", "verification": "verified", "exploited": False, "qualifies_for_bounty": "qualifying"},
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_qualifying").text
    assert "Qualifying" in html


def test_false_positive_finding_shows_false_positive_badge_on_the_card():
    session = _base_session("usr_badge_fp", [
        {
            "title": "CVE-2024-0001", "severity": "High", "description": "x", "verification": "inferred", "exploited": False,
            "false_positive_reason": "Installed version is outside the affected range.",
        },
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_fp").text
    assert "Likely false positive" in html


def test_possible_duplicate_finding_shows_duplicate_badge_on_the_card():
    session = _base_session("usr_badge_dup", [
        {
            "title": "Stored XSS in comments", "severity": "Medium", "description": "x", "verification": "verified", "exploited": False,
            "possible_duplicate": {"matched_title": "Persistent XSS via profile comments", "confidence": "high", "checked_at": "2026-01-01T00:00:00+00:00"},
        },
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_dup").text
    assert "Possible duplicate" in html


def test_info_severity_finding_renders_its_own_badge_not_unknown():
    """Info is a real severity tier (macros/ui.html's badge()), distinct from the "unknown" bucket
    reserved for a missing/invalid severity -- must render text-severity-info, not
    text-severity-unknown, even though both currently share the same neutral color."""
    session = _base_session("usr_badge_info", [
        {"title": "Exposed version banner", "severity": "Info", "description": "x", "verification": "verified", "exploited": False},
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_info").text
    assert "text-severity-info" in html


def test_finding_with_no_duplicate_match_shows_no_duplicate_badge():
    session = _base_session("usr_badge_no_dup", [
        {"title": "Open redirect", "severity": "Low", "description": "x", "verification": "verified", "exploited": False, "possible_duplicate": None},
    ])
    client = _client_with_session(session)
    html = client.get("/session/usr_badge_no_dup").text
    assert "Possible duplicate" not in html
