"""Findings tab's own live count (macros/ui.html's tab_bar(), session_fragment.html): the tab bar
is a deliberate direct sibling of #session-stream, outside the SSE morph target entirely (keeping
it there is what stops a live update from resetting whichever tab the operator has open) -- but
that same isolation meant the findings COUNT baked into the tab label text never got a live update
either, stuck at whatever it was on the very first page load. Real operator complaint: "Findings
(6)" only ever changes on a manual page reload.

An htmx out-of-band swap (hx-swap-oob) was the first fix attempted here and had to be reverted:
with hx-ext="sse, morph" active on #session-stream, the "morph" extension's own isInlineSwap only
recognizes swap-style strings starting with "morph" -- confirmed live via real headless-browser
testing, any OOB element made it throw "Cannot read properties of undefined (reading 'swapStyle')"
on every single SSE update, even though the swap itself still silently completed. Fixed instead by
having #session-content (the always-correctly-morphed root) carry a fresh data-findings-count
attribute on every render, and static/js/findings_tab_count.js copy that value into the tab bar's
own span on every htmx:afterSwap -- no OOB/morph interaction involved at all.
"""
from fastapi.testclient import TestClient

import main
from sessions import store


def _session(session_id, findings):
    return {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": "processing",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": findings, "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


def test_tab_bar_count_span_shows_the_real_findings_count_on_first_load(tmp_path, monkeypatch):
    session_id = "usr_findings_count_tab_test"
    findings = [{"title": "A", "severity": "High"}, {"title": "B", "severity": "Low"}]
    session = _session(session_id, findings)
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert '<span id="findings-tab-count"> (2)</span>' in resp.text


def test_tab_bar_count_span_is_empty_with_no_findings(tmp_path, monkeypatch):
    session_id = "usr_findings_count_tab_empty_test"
    session = _session(session_id, findings=[])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert '<span id="findings-tab-count"></span>' in resp.text


def test_session_content_carries_the_fresh_findings_count_attribute(tmp_path, monkeypatch):
    """The data attribute findings_tab_count.js reads on every htmx:afterSwap -- must be present
    and correct on both the full page and the fragment endpoint (what every SSE update sends)."""
    session_id = "usr_findings_count_attr_test"
    findings = [{"title": "A", "severity": "Critical"}]
    session = _session(session_id, findings)
    store.save_session(session_id, session)
    client = TestClient(main.app)

    full_page = client.get(f"/session/{session_id}").text
    fragment = client.get(f"/api/session/{session_id}/fragment").text

    assert 'data-findings-count="1"' in full_page
    assert 'data-findings-count="1"' in fragment


def test_no_hx_swap_oob_used_for_the_findings_count(tmp_path, monkeypatch):
    """Regression guard for the reverted OOB approach -- hx-swap-oob interacting with the "morph"
    extension is what caused the isInlineSwap crash; must never come back for this element."""
    session_id = "usr_findings_count_no_oob_test"
    session = _session(session_id, findings=[{"title": "A", "severity": "Low"}])
    store.save_session(session_id, session)
    client = TestClient(main.app)

    fragment = client.get(f"/api/session/{session_id}/fragment").text

    assert "hx-swap-oob" not in fragment
