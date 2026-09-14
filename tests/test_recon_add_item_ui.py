"""The Recon tab's "Add target or note" field (templates/partials/session_fragment.html) +
/api/session/{id}/recon/add (main.py's submit_recon_item): lets the operator add a new scope target
or a plain-language idea/lead at any point, mid-scan or after. Same TestClient-against-a-real-saved-
session pattern as tests/test_hypothesis_ui.py.
"""
from fastapi.testclient import TestClient

import agent.core as core
import main
from sessions import store


def _session(session_id, status="completed", **overrides):
    session = {
        "session_id": session_id, "name": "test", "target": "https://example.com", "status": status,
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "hypotheses": [], "chain_attempts": [],
        "out_of_scope": [], "authorize_exploit": False, "enumerate_subdomains": False,
    }
    session.update(overrides)
    return session


def test_recon_tab_renders_the_add_field():
    session_id = "usr_recon_add_ui"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert f'/api/session/{session_id}/recon/add' in resp.text
    assert "Add target or note" in resp.text
    assert "Add and investigate now" in resp.text  # idle session -> this label


def test_recon_tab_shows_the_live_label_for_a_processing_session():
    session_id = "usr_recon_add_ui_live"
    store.save_session(session_id, _session(session_id, status="processing"))
    client = TestClient(main.app)

    resp = client.get(f"/session/{session_id}")

    assert resp.status_code == 200
    assert ">Add<" in resp.text


def test_submit_recon_item_queues_when_session_is_live(monkeypatch):
    session_id = "usr_recon_add_live_submit"
    store.save_session(session_id, _session(session_id, status="processing"))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/recon/add", data={"raw_text": "new-target.example.com"})

    assert resp.status_code == 200
    queue = main.get_instruction_queue(session_id)
    assert not queue.empty()
    instruction = queue.get_nowait()
    assert instruction == {"type": "add_recon_item", "raw_text": "new-target.example.com"}


def test_submit_recon_item_starts_background_investigation_when_idle(monkeypatch):
    session_id = "usr_recon_add_idle_submit"
    store.save_session(session_id, _session(session_id, status="completed"))
    client = TestClient(main.app)
    called = []

    async def fake_investigation(sid, raw_text, provider_id=None):
        called.append((sid, raw_text))

    monkeypatch.setattr(main, "run_recon_note_investigation", fake_investigation)

    resp = client.post(f"/api/session/{session_id}/recon/add", data={"raw_text": "the login form might reuse the same session cookie across subdomains"})

    assert resp.status_code == 200
    assert called == [(session_id, "the login form might reuse the same session cookie across subdomains")]


def test_submit_recon_item_rejects_empty_text():
    session_id = "usr_recon_add_empty"
    store.save_session(session_id, _session(session_id))
    client = TestClient(main.app)

    resp = client.post(f"/api/session/{session_id}/recon/add", data={"raw_text": "   "})

    assert resp.status_code == 400


class _FakeLLM:
    pass


def _ctx(session_id, session):
    return core.RunContext(llm=_FakeLLM(), session=session, session_id=session_id)


def test_classify_and_record_recon_item_takes_the_target_path_for_a_clean_target(monkeypatch):
    """A clean target string must NOT trigger the LLM-structuring call -- fully deterministic."""
    session_id = "usr_classify_target"
    session = _session(session_id)
    ctx = _ctx(session_id, session)
    store.save_session(session_id, session)

    called = []

    async def fake_structure(*args, **kwargs):
        called.append(1)
        return {"text": "should not be used", "evidence": ""}

    monkeypatch.setattr(core, "_structure_hypothesis_text", fake_structure)

    import asyncio
    recorded = asyncio.run(core._classify_and_record_recon_item(ctx, "new-target.example.com", "recon"))

    assert called == []  # no LLM call for a clean target
    assert recorded is not None
    assert "new-target.example.com" in recorded["text"]
    assert "new-target.example.com" in ctx.session["target"]


def test_classify_and_record_recon_item_takes_the_free_text_path_for_prose(monkeypatch):
    session_id = "usr_classify_prose"
    session = _session(session_id)
    ctx = _ctx(session_id, session)
    store.save_session(session_id, session)

    async def fake_structure(ctx_arg, raw_text):
        return {"text": "the login form might leak session cookies", "evidence": "operator hunch"}

    monkeypatch.setattr(core, "_structure_hypothesis_text", fake_structure)

    import asyncio
    recorded = asyncio.run(core._classify_and_record_recon_item(
        ctx, "I think the login form, which is old, might leak session cookies", "recon",
    ))

    assert recorded is not None
    assert recorded["text"] == "the login form might leak session cookies"
    assert recorded["evidence"] == "operator hunch"
    # target must be untouched -- this was prose, not a target submission
    assert ctx.session["target"] == "https://example.com"


def test_classify_and_record_recon_item_skips_out_of_scope_targets(monkeypatch):
    session_id = "usr_classify_out_of_scope"
    session = _session(session_id, out_of_scope=["excluded.example.com"])
    ctx = _ctx(session_id, session)
    store.save_session(session_id, session)

    import asyncio
    recorded = asyncio.run(core._classify_and_record_recon_item(ctx, "excluded.example.com", "recon"))

    assert recorded is not None
    assert "excluded from this session's scope" in recorded["text"]
    assert "excluded.example.com" not in ctx.session["target"]


def test_run_recon_note_investigation_hands_off_to_run_hypothesis_verification_for_a_clean_target(monkeypatch):
    """The idle-session path ("Add and investigate now"): must reuse run_hypothesis_verification's
    own full investigation pipeline rather than writing a second one, and must NOT call the LLM
    structuring step for a clean target (fully deterministic)."""
    session_id = "usr_recon_note_idle_target"
    store.save_session(session_id, _session(session_id, status="completed"))

    structure_called = []

    async def fake_structure(*args, **kwargs):
        structure_called.append(1)
        return {"text": "should not be used", "evidence": ""}

    handed_off = []

    async def fake_verify(sid, raw_text="", hypothesis_id=None, provider_id=None):
        handed_off.append((sid, hypothesis_id))

    monkeypatch.setattr(core, "_structure_hypothesis_text", fake_structure)
    monkeypatch.setattr(core, "run_hypothesis_verification", fake_verify)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())

    import asyncio
    asyncio.run(core.run_recon_note_investigation(session_id, "new-target.example.com"))

    assert structure_called == []
    assert len(handed_off) == 1
    handed_sid, handed_hyp_id = handed_off[0]
    assert handed_sid == session_id
    saved = store.load_session(session_id)
    assert saved["hypotheses"][0]["id"] == handed_hyp_id
    assert "new-target.example.com" in saved["target"]


def test_run_recon_note_investigation_hands_off_to_run_hypothesis_verification_for_prose(monkeypatch):
    session_id = "usr_recon_note_idle_prose"
    store.save_session(session_id, _session(session_id, status="completed"))

    async def fake_structure(ctx_arg, raw_text):
        return {"text": "the admin panel might reuse a stale session cookie", "evidence": ""}

    handed_off = []

    async def fake_verify(sid, raw_text="", hypothesis_id=None, provider_id=None):
        handed_off.append((sid, hypothesis_id))

    monkeypatch.setattr(core, "_structure_hypothesis_text", fake_structure)
    monkeypatch.setattr(core, "run_hypothesis_verification", fake_verify)
    monkeypatch.setattr(core, "get_provider", lambda provider_id: object())

    import asyncio
    asyncio.run(core.run_recon_note_investigation(session_id, "I bet the admin panel reuses a stale session cookie somewhere"))

    assert len(handed_off) == 1
    saved = store.load_session(session_id)
    assert saved["hypotheses"][0]["text"] == "the admin panel might reuse a stale session cookie"
    assert saved["hypotheses"][0]["id"] == handed_off[0][1]
