"""main.py's toggle_pinned_ref route (POST /api/session/{id}/pin) -- toggles one F#/H#/R# id in/out
of session["pinned_refs"] (macros/ui.html's chat_ref, opted into pinning on every finding/
hypothesis/recon-target card) and returns that same chat_ref span re-rendered with its new state.
"""
from fastapi.testclient import TestClient

import main


def _session(session_id, **extra):
    return {
        "session_id": session_id, "name": "test", "target": "example.com", "status": "processing",
        "mode": "agent", "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [],
        "approvals": [], "chat": {"summary": "", "messages": []},
        **extra,
    }


def test_pin_toggle_adds_then_removes_a_ref():
    from sessions import store
    session_id = "usr_pin_test"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/pin", data={"ref": "F1"})
    assert resp.status_code == 200
    assert "Unpin F1" in resp.text
    assert store.load_session(session_id)["pinned_refs"] == ["F1"]

    resp2 = client.post(f"/api/session/{session_id}/pin", data={"ref": "F1"})
    assert resp2.status_code == 200
    assert "Unpin F1" not in resp2.text
    assert "Pin F1" in resp2.text
    assert store.load_session(session_id)["pinned_refs"] == []
    store.delete_session(session_id)


def test_pin_toggle_does_not_disturb_other_pinned_refs():
    from sessions import store
    session_id = "usr_pin_multi_test"
    store.save_session(session_id, _session(session_id, pinned_refs=["H1"]))
    client = TestClient(main.app)

    client.post(f"/api/session/{session_id}/pin", data={"ref": "F2"})

    assert set(store.load_session(session_id)["pinned_refs"]) == {"H1", "F2"}
    store.delete_session(session_id)


def test_pin_toggle_for_a_missing_session_returns_404():
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_does_not_exist/pin", data={"ref": "F1"})
    assert resp.status_code == 404
