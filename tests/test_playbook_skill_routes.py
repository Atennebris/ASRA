"""Playbook skill UI: the routes behind the per-card Run/Trust/Edit/Export controls and the
New-skill / Import-skills forms (main.py), over the store's skill API (agent/tools/playbook_store.py
+ agent/tools/skill_runner.py). Instructions-kind skills are used throughout so nothing here spawns
a real subprocess -- execute_skill returns an instructions body as text, never runs it."""
import json

import pytest
from fastapi.testclient import TestClient

import main
from agent.tools import library_store
from agent.tools import playbook_store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    monkeypatch.setattr(library_store, "resolve_global_app_dir", lambda: tmp_path)


def _add_instructions_skill(body="Step 1: open the login page\nStep 2: submit the payload", **kw):
    """A trusted, executable-free instructions skill + its backing technique -- the common fixture
    every test here runs against. Returns the backing technique id."""
    return playbook_store.add_manual_skill(kind="instructions", body=body, technique="reusable login attack", **kw)


def test_add_skill_route_creates_a_skill():
    client = TestClient(main.app)
    resp = client.post("/api/playbook/add-skill", data={
        "kind": "instructions", "body": "do the thing then the other thing",
        "technique": "a hand-authored skill", "params": "target, port", "tech_keywords": "nginx",
    })
    assert resp.status_code == 200
    skills = playbook_store.list_all_skills()
    assert len(skills) == 1
    sk = skills[0]
    assert sk["skill"]["kind"] == "instructions"
    assert sk["skill"]["trust"] == "operator_trusted"  # operator-authored == trusted
    assert [p["name"] for p in sk["skill"]["params"]] == ["target", "port"]
    # The new skill renders on the list with its Run control.
    assert "a hand-authored skill" in resp.text
    assert "/run-skill" in resp.text


def test_add_skill_route_empty_body_is_a_noop():
    client = TestClient(main.app)
    resp = client.post("/api/playbook/add-skill", data={"kind": "instructions", "body": "   "})
    assert resp.status_code == 200
    assert playbook_store.list_all_skills() == []


def test_run_skill_route_returns_instructions_text():
    tid = _add_instructions_skill()
    client = TestClient(main.app)
    resp = client.post(f"/api/playbook/{tid}/run-skill", data={})
    assert resp.status_code == 200
    assert "open the login page" in resp.text
    assert "Ran" in resp.text  # the ok-status header


def test_run_skill_route_reports_missing_skill():
    client = TestClient(main.app)
    resp = client.post("/api/playbook/does-not-exist/run-skill", data={})
    assert resp.status_code == 200
    assert "Did not run" in resp.text


def test_skill_trust_toggle_route_flips_trust():
    tid = _add_instructions_skill()
    assert playbook_store.get_technique_skill(tid)["trust"] == "operator_trusted"
    client = TestClient(main.app)

    off = client.post(f"/api/playbook/{tid}/skill-trust", data={"trusted": "false"})
    assert off.status_code == 200
    assert playbook_store.get_technique_skill(tid)["trust"] == "unreviewed"

    on = client.post(f"/api/playbook/{tid}/skill-trust", data={"trusted": "true"})
    assert on.status_code == 200
    assert playbook_store.get_technique_skill(tid)["trust"] == "operator_trusted"


def test_update_skill_route_rewrites_body_and_repins():
    tid = _add_instructions_skill()
    original = playbook_store.get_technique_skill(tid)["body_sha256"]
    client = TestClient(main.app)

    resp = client.post(f"/api/playbook/{tid}/update-skill", data={"body": "a brand new body", "params": "host"})
    assert resp.status_code == 200
    sk = playbook_store.get_technique_skill(tid)
    assert sk["body"] == "a brand new body"
    assert sk["body_sha256"] != original  # hash re-pinned over the new bytes
    assert sk["trust"] == "unreviewed"  # a body change resets an earlier vouch
    assert [p["name"] for p in sk["params"]] == ["host"]


def test_skill_export_round_trips_through_import():
    _add_instructions_skill(body="exported step one\nexported step two")
    client = TestClient(main.app)

    exported = client.get("/api/playbook/skills/export")
    assert exported.status_code == 200
    payload = json.loads(exported.text)
    assert payload["schema"] == playbook_store.SKILL_EXPORT_SCHEMA
    assert len(payload["skills"]) == 1

    # Fresh store: importing the exported envelope reconstructs the skill (as unreviewed).
    playbook_store._write_playbook_store({})
    assert playbook_store.list_all_skills() == []

    imported = client.post("/api/playbook/skills/import", data={"data": exported.text})
    assert imported.status_code == 200
    skills = playbook_store.list_all_skills()
    assert len(skills) == 1
    assert "exported step one" in skills[0]["skill"]["body"]
    assert skills[0]["skill"]["trust"] == "unreviewed"  # a body from elsewhere is untrusted by default


def test_per_skill_export_route_scopes_to_one_skill():
    tid = _add_instructions_skill(body="only this one")
    _add_instructions_skill(body="a different skill")
    client = TestClient(main.app)

    resp = client.get(f"/api/playbook/{tid}/skill-export")
    assert resp.status_code == 200
    payload = json.loads(resp.text)
    assert len(payload["skills"]) == 1
    assert payload["skills"][0]["body"] == "only this one"


def test_per_skill_export_route_404_without_a_skill():
    # A technique with no skill attached has nothing to export.
    tid = playbook_store.add_manual_technique("a plain technique, no skill")
    client = TestClient(main.app)
    resp = client.get(f"/api/playbook/{tid}/skill-export")
    assert resp.status_code == 404


def test_skills_import_route_rejects_bad_json():
    client = TestClient(main.app)
    resp = client.post("/api/playbook/skills/import", data={"data": "{not json"})
    assert resp.status_code == 200
    assert "not valid JSON" in resp.text
    assert playbook_store.list_all_skills() == []


def test_skill_enabled_toggle_route_flips_enabled():
    tid = _add_instructions_skill()
    assert playbook_store.skill_enabled(playbook_store.get_technique_skill(tid)) is True
    client = TestClient(main.app)

    off = client.post(f"/api/playbook/{tid}/skill-enabled", data={"enabled": "false"})
    assert off.status_code == 200
    assert playbook_store.skill_enabled(playbook_store.get_technique_skill(tid)) is False

    on = client.post(f"/api/playbook/{tid}/skill-enabled", data={"enabled": "true"})
    assert on.status_code == 200
    assert playbook_store.skill_enabled(playbook_store.get_technique_skill(tid)) is True


def test_disabled_skill_is_refused_by_run_route():
    tid = _add_instructions_skill()
    client = TestClient(main.app)
    client.post(f"/api/playbook/{tid}/skill-enabled", data={"enabled": "false"})

    resp = client.post(f"/api/playbook/{tid}/run-skill", data={})
    assert resp.status_code == 200
    assert "Did not run" in resp.text  # execute_skill refuses a switched-off skill


def test_disabled_skill_card_renders_disabled_state():
    tid = _add_instructions_skill()
    client = TestClient(main.app)
    client.post(f"/api/playbook/{tid}/skill-enabled", data={"enabled": "false"})

    resp = client.get("/api/playbook")
    assert 'data-enabled="false"' in resp.text
    assert "Disabled" in resp.text


def test_skills_only_filter_shows_only_skill_entries():
    _add_instructions_skill(body="only skills here")  # technique "reusable login attack" + a skill
    playbook_store.add_manual_technique("a plain technique with no skill")
    client = TestClient(main.app)

    all_resp = client.get("/api/playbook")
    assert "reusable login attack" in all_resp.text
    assert "a plain technique with no skill" in all_resp.text

    skills = client.get("/api/playbook", params={"skills_only": "yes"})
    assert skills.status_code == 200
    assert "reusable login attack" in skills.text
    assert "a plain technique with no skill" not in skills.text
