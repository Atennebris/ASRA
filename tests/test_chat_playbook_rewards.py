"""Chat write-path to the cross-session playbook + gamified storage rewards + interactive findings.

Interactive/chat mode gained the ability to WRITE techniques into the playbook (previously only the
autonomous agent could) and to record situational findings; both emit a "+N" reward into the chat.
These pin the storage writes, the reward payloads, and the negative-knowledge (worked=false) path.
"""
import projects.paths as project_paths
import pytest
from fastapi.testclient import TestClient

import agent.chat as chat
import main
from agent.tools import playbook_store
from sessions import store
from sessions.store import load_session, save_session


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    return tmp_path


def _interactive_session() -> str:
    return store.create_session("", name="i", mode="interactive", initial_status="interactive")


# --- record_technique write path ---


def test_record_technique_writes_to_playbook_and_returns_reward():
    sid = _interactive_session()
    confirmation, reward = chat._apply_chat_record_technique(sid, {
        "technique": "Bypass the WAF by double-URL-encoding the payload",
        "tech_keywords": ["nginx", "php"], "waf_vendors": ["cloudflare"], "worked": True,
    })
    assert "playbook" in confirmation.lower()
    assert playbook_store.count_techniques() == 1
    assert reward == {"kind": "technique", "label": "New technique captured", "delta": 1,
                      "total": 1, "total_label": "in playbook", "detail": "Bypass the WAF by double-URL-encoding the payload"}
    stored = next(iter(playbook_store.load_playbook_store().values()))[0]
    assert stored["outcome"] == "worked"
    assert stored["source_type"] == "live"
    assert stored["confidence"] == "confirmed"


def test_record_technique_dead_end_stores_failed_outcome():
    sid = _interactive_session()
    _, reward = chat._apply_chat_record_technique(sid, {
        "technique": "Tried a UNION-based SQLi -- the endpoint is not injectable", "tech_keywords": ["mysql"], "worked": False,
    })
    assert reward["label"] == "New dead-end captured"
    stored = next(iter(playbook_store.load_playbook_store().values()))[0]
    assert stored["outcome"] == "failed"


def test_record_technique_rejects_empty_technique():
    sid = _interactive_session()
    confirmation, reward = chat._apply_chat_record_technique(sid, {"technique": "   "})
    assert reward is None
    assert playbook_store.count_techniques() == 0


# --- record_finding (interactive) write path ---


def test_record_finding_appends_to_session_and_returns_reward():
    sid = _interactive_session()
    confirmation, reward = chat._apply_chat_record_finding(sid, {
        "title": "Origin IP recovered", "detail": "Found 1.2.3.4 behind Cloudflare via an old DNS record", "artifact": "1.2.3.4",
    })
    findings = load_session(sid)["findings"]
    assert len(findings) == 1
    assert findings[0]["title"] == "Origin IP recovered"
    assert findings[0]["source"] == "interactive"
    assert findings[0]["extracted_artifact"] == "1.2.3.4"
    assert reward == {"kind": "finding", "label": "New finding recorded", "delta": 1,
                      "total": 1, "total_label": "this session", "detail": "Origin IP recovered"}


def test_record_finding_requires_title_and_detail():
    sid = _interactive_session()
    _, reward = chat._apply_chat_record_finding(sid, {"title": "x", "detail": ""})
    assert reward is None
    assert load_session(sid)["findings"] == []


# --- deliver_storage_reward_to_chat ---


def test_deliver_storage_reward_appends_a_reward_message():
    sid = _interactive_session()
    chat.deliver_storage_reward_to_chat(sid, kind="technique", label="New technique captured",
                                        delta=2, total=7, total_label="in playbook", detail="something")
    thread = load_session(sid)["chat_threads"][-1]
    reward_msgs = [m for m in thread["messages"] if m.get("role") == "reward"]
    assert len(reward_msgs) == 1
    assert reward_msgs[0]["reward"]["delta"] == 2
    assert reward_msgs[0]["reward"]["total"] == 7


# --- interactive-findings route ---


def test_interactive_findings_route_empty_then_populated():
    client = TestClient(main.app)
    resp = client.post("/api/scan/interactive", data={"name": "F"}, follow_redirects=False)
    sid = resp.headers["location"].rsplit("/", 1)[-1]

    empty = client.get(f"/api/session/{sid}/interactive-findings")
    assert empty.status_code == 200
    assert "No findings yet" in empty.text

    session = load_session(sid)
    session.setdefault("findings", []).append({"title": "Flag captured", "description": "found it", "severity": "high", "found_at": "2026-01-01T00:00:00+00:00"})
    save_session(sid, session)

    populated = client.get(f"/api/session/{sid}/interactive-findings")
    assert "Flag captured" in populated.text
    assert "high" in populated.text


def test_interactive_findings_route_unknown_session_404s():
    client = TestClient(main.app)
    assert client.get("/api/session/usr_nope/interactive-findings").status_code == 404
