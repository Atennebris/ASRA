"""Skill artifacts on playbook techniques: build/attach/hash/trust/run-counters, cross-mode
(target_shape) matching, and the security invariants around importing a skill authored elsewhere.
Isolated to a tmp store so nothing touches the operator's real playbook."""
import pytest

from agent.tools import playbook_store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    monkeypatch.setattr(playbook_store, "PLAYBOOK_EMBEDDINGS_PATH", tmp_path / "playbook" / "embeddings.json")


def _add_technique(**kw):
    defaults = dict(technique="do the thing", worked=True)
    defaults.update(kw)
    return playbook_store.add_manual_technique(**defaults)


def test_build_skill_normalizes_and_pins_hash():
    skill = playbook_store.build_skill(
        kind="script", body="print('hi')\n", params=["target", {"name": "port", "required": False}],
        interpreter="python", session_id="s1", target_shape="pe_x86_64", mode="reverse",
    )
    assert skill["kind"] == "script"
    assert skill["body"] == "print('hi')"  # stripped
    assert skill["interpreter"] == "python"
    assert skill["trust"] == "unreviewed"  # fresh skill proves nothing yet
    assert skill["runs"] == 0 and skill["run_successes"] == 0
    assert skill["provenance"]["derived_from"] == "agent_run"
    assert skill["provenance"]["target_shape"] == "pe_x86_64"
    assert skill["body_sha256"] == playbook_store.skill_body_hash("print('hi')")
    # params coerced to {name, desc, required}
    names = {p["name"] for p in skill["params"]}
    assert names == {"target", "port"}
    assert next(p for p in skill["params"] if p["name"] == "port")["required"] is False


def test_build_skill_rejects_bad_kind_or_empty_body():
    assert playbook_store.build_skill(kind="nonsense", body="x") is None
    assert playbook_store.build_skill(kind="script", body="   ") is None


def test_attach_and_get_skill_roundtrip():
    tid = _add_technique()
    skill = playbook_store.build_skill(kind="command", body="nmap {{target}}", interpreter="sh")
    assert playbook_store.attach_skill(tid, skill) is True
    got = playbook_store.get_technique_skill(tid)
    assert got["body"] == "nmap {{target}}"
    # unknown technique id -> no-op
    assert playbook_store.attach_skill("deadbeef", skill) is False


def test_tamper_detection_on_body_change():
    tid = _add_technique()
    skill = playbook_store.build_skill(kind="script", body="legit", interpreter="python")
    playbook_store.attach_skill(tid, skill)
    stored = playbook_store.get_technique_skill(tid)
    assert playbook_store.skill_body_tampered(stored) is False
    # Simulate an out-of-band edit of the body without re-pinning the hash.
    store = playbook_store.load_playbook_store()
    _k, entry = playbook_store._find_entry_by_id(store, tid)
    entry["skill"]["body"] = "malicious"
    playbook_store._write_playbook_store(store)
    assert playbook_store.skill_body_tampered(playbook_store.get_technique_skill(tid)) is True


def test_missing_hash_counts_as_tampered():
    # A legacy/hand-added skill with no pinned hash must never be treated as clean.
    assert playbook_store.skill_body_tampered({"body": "x"}) is True
    assert playbook_store.skill_body_tampered(None) is True


def test_bump_skill_run_and_success_rate():
    tid = _add_technique()
    playbook_store.attach_skill(tid, playbook_store.build_skill(kind="script", body="x", interpreter="python"))
    assert playbook_store.skill_success_rate(playbook_store.get_technique_skill(tid)) is None
    playbook_store.bump_skill_run(tid, success=True)
    playbook_store.bump_skill_run(tid, success=False)
    skill = playbook_store.get_technique_skill(tid)
    assert skill["runs"] == 2 and skill["run_successes"] == 1
    assert playbook_store.skill_success_rate(skill) == 0.5


def test_update_skill_body_rehashes_and_resets_trust():
    tid = _add_technique()
    playbook_store.attach_skill(tid, playbook_store.build_skill(kind="script", body="v1", interpreter="python"))
    playbook_store.set_skill_trust(tid, True)
    assert playbook_store.get_technique_skill(tid)["trust"] == "operator_trusted"
    playbook_store.update_skill_body(tid, body="v2")
    skill = playbook_store.get_technique_skill(tid)
    assert skill["body"] == "v2"
    assert skill["body_sha256"] == playbook_store.skill_body_hash("v2")
    assert skill["trust"] == "unreviewed"  # vouch was for the old bytes
    assert playbook_store.skill_body_tampered(skill) is False


def test_add_manual_skill_is_first_class_and_trusted():
    tid = playbook_store.add_manual_skill(
        kind="command", body="strings {{target}}", technique="dump strings",
        target_shape="elf", mode="reverse",
    )
    assert tid is not None
    skill = playbook_store.get_technique_skill(tid)
    assert skill["trust"] == "operator_trusted"
    assert skill["provenance"]["derived_from"] == "operator"
    entry = next(e for e in playbook_store.list_all_techniques() if e["id"] == tid)
    assert entry["target_shape"] == "elf" and entry["mode"] == "reverse"
    assert entry["skill"]["kind"] == "command"


def test_cross_mode_shape_match_surfaces_entry_with_zero_tech_overlap():
    # An RE capture: empty waf, thin/absent tech tokens, but a target shape.
    playbook_store.add_manual_technique(
        technique="patch the license check at the compare", target_shape="pe_x86_64", mode="reverse",
    )
    # A query that shares NO tech keywords but the same shape must still surface it.
    hits = playbook_store.find_similar_techniques(
        tech_keywords=set(), waf_vendors=set(), limit=5, target_shape="pe_x86_64",
    )
    assert len(hits) == 1
    assert "license check" in hits[0]["technique"]
    # A different shape with no tech overlap must NOT surface it.
    assert playbook_store.find_similar_techniques(
        tech_keywords=set(), waf_vendors=set(), limit=5, target_shape="jvm_bytecode",
    ) == []


def test_export_import_skills_roundtrip_untrusts_foreign_body():
    src = playbook_store.add_manual_skill(kind="script", body="print(1)", interpreter="python", technique="t")
    assert playbook_store.get_technique_skill(src)["trust"] == "operator_trusted"
    payload = playbook_store.export_skills()
    assert payload["schema"] == playbook_store.SKILL_EXPORT_SCHEMA
    assert len(payload["skills"]) == 1

    # Fresh store (simulate another machine importing it).
    playbook_store._write_playbook_store({})
    added = playbook_store.import_skills(payload)
    assert added == 1
    imported = playbook_store.list_all_skills()[0]["skill"]
    assert imported["trust"] == "unreviewed"  # foreign body never auto-trusted
    assert imported["provenance"]["derived_from"] == "import"
    assert imported["body_sha256"] == playbook_store.skill_body_hash("print(1)")


def test_whole_playbook_import_sanitizes_inline_skill():
    # A colleague's export carrying a skill marked operator_trusted with a stale/foreign hash.
    foreign = {
        playbook_store.make_fingerprint_key([], []): [{
            "id": "foreign01", "technique": "their trick", "tech_keywords": [], "waf_vendors": [],
            "outcome": "worked", "times_confirmed": 1,
            "skill": {
                "kind": "script", "body": "do_x()", "interpreter": "python",
                "trust": "operator_trusted", "body_sha256": "stale-wrong-hash",
                "provenance": {"derived_from": "agent_run"}, "runs": 9, "run_successes": 9,
            },
        }],
    }
    assert playbook_store.import_entries(foreign) == 1
    skill = playbook_store.list_all_skills()[0]["skill"]
    assert skill["trust"] == "unreviewed"
    assert skill["provenance"]["derived_from"] == "import"
    assert skill["body_sha256"] == playbook_store.skill_body_hash("do_x()")  # re-pinned, not stale
    assert playbook_store.skill_body_tampered(skill) is False
