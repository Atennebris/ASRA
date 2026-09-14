"""The three operator-facing entry points for session["hypotheses"]: pre-scan (New Project form's
"Hypotheses to check" field -> create_session's own initial_hypotheses), live (a running session,
POST /api/session/{id}/hypotheses -> the instruction queue), and post-completion (the same route,
idle branch -> run_hypothesis_verification). This file covers the pre-scan + route-branching pieces;
run_hypothesis_verification's own internals are covered in test_hypothesis_verification_pass.py.
"""
from fastapi.testclient import TestClient

import main
import projects.paths as project_paths
from agent.core import get_instruction_queue
from sessions import store
from sessions.store import load_session


async def _fake_run_session(session_id, provider_id=None, entry_point="recon"):
    return None


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(main, "run_session", _fake_run_session)


# --- (a) pre-scan: New Project form's initial_hypotheses -> create_session ---


def test_scan_form_pre_seeds_hypotheses_one_per_line(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post(
            "/api/scan",
            data={
                "name": "Hypotheses Pre-Seed Project",
                "target": "example.com",
                "initial_hypotheses": "staging debug mode might be on\n\nold /api/v1 might still be reachable\n",
            },
            follow_redirects=False,
        )

        assert resp.status_code == 303, resp.text
        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        hypotheses = load_session(session_id)["hypotheses"]

        assert [h["text"] for h in hypotheses] == ["staging debug mode might be on", "old /api/v1 might still be reachable"]
        assert all(h["source"] == "user" and h["source_phase"] == "pre_scan" and h["status"] == "unconfirmed" for h in hypotheses)
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_scan_form_caps_initial_hypotheses_count(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        many_lines = "\n".join(f"hypothesis {i}" for i in range(30))
        resp = client.post(
            "/api/scan",
            data={"name": "Hypotheses Cap Project", "target": "example.com", "initial_hypotheses": many_lines},
            follow_redirects=False,
        )

        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert len(load_session(session_id)["hypotheses"]) == 20
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_scan_form_blank_initial_hypotheses_leaves_it_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post(
            "/api/scan", data={"name": "No Hypotheses Project", "target": "example.com"}, follow_redirects=False,
        )

        session_id = resp.headers["location"].rsplit("/", 1)[-1]
        assert load_session(session_id)["hypotheses"] == []
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


# --- (b)/(c) live + post-completion: POST /api/session/{id}/hypotheses ---


def test_submit_hypothesis_on_a_live_session_queues_it_deterministically(tmp_path, monkeypatch):
    """No LLM classification step (unlike the chat panel's add_guidance) decides WHAT the operator
    wants -- their raw paste goes straight onto the same instruction queue _drain_pending_guidance
    already reads from, as a fully-formed {"type": "add_hypothesis", ...} directive; splitting it
    into a clean {text, evidence} pair happens downstream, when the running loop drains it
    (agent/core.py's _structure_hypothesis_text, own dedicated tests elsewhere)."""
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        session_id = store.create_session("example.com")
        session = load_session(session_id)
        session["status"] = "processing"
        store.save_session(session_id, session)

        resp = client.post(f"/api/session/{session_id}/hypotheses", data={"raw_text": "check for exposed .git, saw a 403"})

        assert resp.status_code == 200, resp.text
        queue = get_instruction_queue(session_id)
        assert not queue.empty()
        instruction = queue.get_nowait()
        assert instruction == {"type": "add_hypothesis", "raw_text": "check for exposed .git, saw a 403"}
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_submit_hypothesis_id_on_a_live_session_queues_a_priority_nudge(tmp_path, monkeypatch):
    """"Investigate now"/"Prioritize now" on an EXISTING open hypothesis now works while live too
    (previously rejected with a 400 -- the real bug an operator reported: the button was present or
    absent depending on session state with no visible reason why). No duplicate entry, no structuring
    call needed -- just a same-turn nudge pointing the running loop at what already exists."""
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        session_id = store.create_session("example.com")
        session = load_session(session_id)
        session["status"] = "processing"
        session["hypotheses"] = [{
            "id": "hyp1", "text": "old lead", "evidence": "", "source_phase": "recon", "source": "agent",
            "status": "unconfirmed", "resolution_note": None, "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
        }]
        store.save_session(session_id, session)

        resp = client.post(f"/api/session/{session_id}/hypotheses", data={"hypothesis_id": "hyp1"})

        assert resp.status_code == 200, resp.text
        queue = get_instruction_queue(session_id)
        assert queue.get_nowait() == {"type": "prioritize_hypothesis", "hypothesis_id": "hyp1"}
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_submit_hypothesis_on_a_completed_session_schedules_verification(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    scheduled = []
    monkeypatch.setattr(main, "run_hypothesis_verification", lambda *a, **k: scheduled.append((a, k)))
    try:
        client = TestClient(main.app)
        session_id = store.create_session("example.com")
        session = load_session(session_id)
        session["status"] = "completed"
        store.save_session(session_id, session)

        resp = client.post(f"/api/session/{session_id}/hypotheses", data={"raw_text": "check for exposed .git, saw a 403 on /.git/config"})

        assert resp.status_code == 200, resp.text
        assert len(scheduled) == 1
        args, kwargs = scheduled[0]
        assert args[0] == session_id
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_submit_hypothesis_id_on_a_completed_session_schedules_verification(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    scheduled = []
    monkeypatch.setattr(main, "run_hypothesis_verification", lambda *a, **k: scheduled.append((a, k)))
    try:
        client = TestClient(main.app)
        session_id = store.create_session("example.com")
        session = load_session(session_id)
        session["status"] = "completed"
        store.save_session(session_id, session)

        resp = client.post(f"/api/session/{session_id}/hypotheses", data={"hypothesis_id": "hyp1"})

        assert resp.status_code == 200, resp.text
        assert len(scheduled) == 1
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_submit_hypothesis_rejects_blank_text(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        session_id = store.create_session("example.com")

        resp = client.post(f"/api/session/{session_id}/hypotheses", data={"raw_text": "   "})

        assert resp.status_code == 400
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_submit_hypothesis_404s_for_a_missing_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        client = TestClient(main.app)
        resp = client.post("/api/session/usr_doesnotexist/hypotheses", data={"raw_text": "x"})
        assert resp.status_code == 404
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
