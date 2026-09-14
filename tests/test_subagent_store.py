"""agent/tools/subagent_store.py — persisted Subagent profile CRUD. Same on-disk convention as
agent/tools/wordlist_store.py (load/_write pair, atomic tmp+os.replace, corrupt/missing file
treated as the default seed, never an error).
"""
import json

from agent.tools import subagent_store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "profiles.json")


def test_load_subagent_profiles_seeds_one_default_disabled_profile_when_file_is_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.load_subagent_profiles()
    assert len(store["profiles"]) == 1
    assert store["profiles"][0]["enabled"] is False
    assert store["profiles"][0]["name"] == "Default Subagent"
    # Seeding is in-memory only until a real change happens -- nothing written yet.
    assert not subagent_store.SUBAGENT_STORE_PATH.exists()


def test_load_subagent_profiles_treats_corrupt_json_as_the_default_seed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    subagent_store.SUBAGENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    subagent_store.SUBAGENT_STORE_PATH.write_text("{not valid json", encoding="utf-8")
    store = subagent_store.load_subagent_profiles()
    assert len(store["profiles"]) == 1
    assert store["profiles"][0]["id"] == "default"


def test_load_subagent_profiles_treats_a_non_object_json_as_the_default_seed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    subagent_store.SUBAGENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    subagent_store.SUBAGENT_STORE_PATH.write_text("[1, 2, 3]", encoding="utf-8")
    store = subagent_store.load_subagent_profiles()
    assert len(store["profiles"]) == 1


def test_add_profile_persists_a_real_new_profile(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    subagent_store.add_profile(
        "OSINT-разведчик", ["dns_lookup", "subfinder"], "Focus on passive subdomain discovery.",
        "opencode-zen", "big-pickle",
    )

    on_disk = json.loads(subagent_store.SUBAGENT_STORE_PATH.read_text(encoding="utf-8"))
    # add_profile starts from the seeded default (still present), plus the new one.
    assert len(on_disk["profiles"]) == 2
    new_profile = next(p for p in on_disk["profiles"] if p["name"] == "OSINT-разведчик")
    assert new_profile["enabled"] is False
    assert new_profile["allowed_tools"] == ["dns_lookup", "subfinder"]
    assert new_profile["provider"] == "opencode-zen"
    assert new_profile["model"] == "big-pickle"
    assert new_profile["id"] != "default"


def test_update_profile_changes_only_the_given_fields(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("A", [], "", None, None)
    profile_id = store["profiles"][-1]["id"]

    subagent_store.update_profile(profile_id, enabled=True, allowed_tools=["nmap"])

    updated = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == profile_id)
    assert updated["enabled"] is True
    assert updated["allowed_tools"] == ["nmap"]
    assert updated["name"] == "A"  # untouched


def test_update_profile_ignores_unrecognized_fields_rather_than_raising(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("A", [], "", None, None)
    profile_id = store["profiles"][-1]["id"]

    subagent_store.update_profile(profile_id, made_up_field="whatever")  # must not raise

    updated = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == profile_id)
    assert "made_up_field" not in updated


def test_update_profile_raises_for_an_unknown_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    try:
        subagent_store.update_profile("does-not-exist", enabled=True)
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_delete_profile_removes_it(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("A", [], "", None, None)
    profile_id = store["profiles"][-1]["id"]

    subagent_store.delete_profile(profile_id)

    remaining_ids = {p["id"] for p in subagent_store.load_subagent_profiles()["profiles"]}
    assert profile_id not in remaining_ids


def test_get_enabled_profiles_only_returns_enabled_ones(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("Enabled one", [], "", None, None)
    enabled_id = store["profiles"][-1]["id"]
    subagent_store.update_profile(enabled_id, enabled=True)
    subagent_store.add_profile("Disabled one", [], "", None, None)

    enabled = subagent_store.get_enabled_profiles()
    assert [p["name"] for p in enabled] == ["Enabled one"]


def test_get_profile_by_name_only_matches_an_enabled_profile(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("Recon Bot", ["dns_lookup"], "", None, None)
    profile_id = store["profiles"][-1]["id"]

    assert subagent_store.get_profile_by_name("Recon Bot") is None  # still disabled

    subagent_store.update_profile(profile_id, enabled=True)
    found = subagent_store.get_profile_by_name("Recon Bot")
    assert found is not None
    assert found["id"] == profile_id


def test_get_profile_by_name_returns_none_for_an_unknown_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert subagent_store.get_profile_by_name("nope") is None


def test_get_enabled_profiles_with_allowed_ids_none_means_no_restriction(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("A", [], "", None, None)
    subagent_store.update_profile(store["profiles"][-1]["id"], enabled=True)

    assert len(subagent_store.get_enabled_profiles(None)) == 1


def test_get_enabled_profiles_with_allowed_ids_narrows_to_that_project(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("A", [], "", None, None)
    a_id = store["profiles"][-1]["id"]
    subagent_store.update_profile(a_id, enabled=True)
    store = subagent_store.add_profile("B", [], "", None, None)
    b_id = store["profiles"][-1]["id"]
    subagent_store.update_profile(b_id, enabled=True)

    narrowed = subagent_store.get_enabled_profiles([a_id])
    assert [p["name"] for p in narrowed] == ["A"]

    # An explicit empty allowlist means "no subagent at all for this project" -- not "unrestricted".
    assert subagent_store.get_enabled_profiles([]) == []


def test_get_enabled_profiles_with_allowed_ids_ignores_a_since_disabled_profile(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("A", [], "", None, None)
    a_id = store["profiles"][-1]["id"]
    subagent_store.update_profile(a_id, enabled=True)

    # The project's own allowlist still names A, but it was disabled globally since then --
    # must never come back just because this project's list still has its id in it.
    subagent_store.update_profile(a_id, enabled=False)

    assert subagent_store.get_enabled_profiles([a_id]) == []


def test_get_profile_by_name_respects_a_projects_own_allowlist(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.add_profile("Recon Bot", [], "", None, None)
    profile_id = store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)

    # Globally enabled, but this project's own allowlist doesn't name it.
    assert subagent_store.get_profile_by_name("Recon Bot", ["some-other-id"]) is None
    assert subagent_store.get_profile_by_name("Recon Bot", [profile_id]) is not None
    assert subagent_store.get_profile_by_name("Recon Bot", None) is not None


def test_import_profiles_adds_new_ones_disabled_regardless_of_source_enabled_flag(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    incoming = {"profiles": [
        {"id": "imported-1", "name": "Recon Bot", "enabled": True, "allowed_tools": ["dns_lookup"],
         "instructions": "recon only", "provider": "opencode-zen", "model": "big-pickle",
         "icon": "robot", "icon_color": "#60a5fa"},
    ]}

    added = subagent_store.import_profiles(incoming)

    assert added == 1
    imported = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == "imported-1")
    assert imported["enabled"] is False
    assert imported["name"] == "Recon Bot"
    assert imported["allowed_tools"] == ["dns_lookup"]
    assert imported["provider"] == "opencode-zen"


def test_import_profiles_dedups_by_id_on_reimport(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    incoming = {"profiles": [{"id": "imported-1", "name": "Recon Bot", "allowed_tools": []}]}

    first = subagent_store.import_profiles(incoming)
    second = subagent_store.import_profiles(incoming)

    assert first == 1
    assert second == 0
    matching = [p for p in subagent_store.load_subagent_profiles()["profiles"] if p["id"] == "imported-1"]
    assert len(matching) == 1


def test_import_profiles_skips_entries_with_no_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    incoming = {"profiles": [{"id": "no-name", "name": "  ", "allowed_tools": []}]}

    added = subagent_store.import_profiles(incoming)

    assert added == 0
    assert not any(p["id"] == "no-name" for p in subagent_store.load_subagent_profiles()["profiles"])


def test_import_profiles_generates_an_id_when_the_source_omits_one(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    incoming = {"profiles": [{"name": "No-id profile", "allowed_tools": []}]}

    added = subagent_store.import_profiles(incoming)

    assert added == 1
    new_profile = next(p for p in subagent_store.load_subagent_profiles()["profiles"] if p["name"] == "No-id profile")
    assert new_profile["id"]


def test_import_profiles_rejects_malformed_shapes_without_raising(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert subagent_store.import_profiles({}) == 0
    assert subagent_store.import_profiles({"profiles": "not-a-list"}) == 0
    assert subagent_store.import_profiles("not-a-dict-at-all") == 0
