"""main.py's save_session_notes route (POST /api/session/{id}/notes) -- the collapsed-chat side
panel's personal scratchpad (session["operator_notes"]), saved via reload_merge_save so a concurrent
agent-loop save can never be clobbered by a stale in-memory copy. See test_chat.py's own
test_session_snapshot_never_leaks_operator_notes_or_pinned_refs for the guarantee this never
reaches the model.
"""
from fastapi.testclient import TestClient

import main


def _session(session_id):
    return {
        "session_id": session_id, "name": "test", "target": "example.com", "status": "processing",
        "mode": "agent", "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [],
        "approvals": [], "chat": {"summary": "", "messages": []},
    }


def test_notes_save_persists_and_is_reflected_on_next_load():
    from sessions import store
    session_id = "usr_notes_test"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/notes", data={"operator_notes": "check the WAF bypass later"})

    assert resp.status_code == 200
    assert resp.text == ""
    saved = store.load_session(session_id)
    assert saved["operator_notes"] == "check the WAF bypass later"
    store.delete_session(session_id)


def test_notes_save_does_not_clobber_a_concurrently_changed_field():
    # reload_merge_save reloads from disk right before applying this one field -- a concurrent
    # writer's own change to an unrelated field (here: status) must survive.
    from sessions import store
    session_id = "usr_notes_concurrent_test"
    store.save_session(session_id, _session(session_id))

    # Simulate the agent loop's own concurrent save landing in between.
    concurrent = store.load_session(session_id)
    concurrent["status"] = "completed"
    store.save_session(session_id, concurrent)

    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/notes", data={"operator_notes": "a note"})
    assert resp.status_code == 200

    saved = store.load_session(session_id)
    assert saved["operator_notes"] == "a note"
    assert saved["status"] == "completed"
    store.delete_session(session_id)


def test_notes_save_for_a_missing_session_returns_404():
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_does_not_exist/notes", data={"operator_notes": "x"})
    assert resp.status_code == 404
