"""agent/tools/subagent_store.py — persisted Subagent profile CRUD. Same on-disk convention as
agent/tools/wordlist_store.py (load/_write pair, atomic tmp+os.replace, corrupt/missing file
treated as the default seed, never an error).
"""
import json

from agent.tools import subagent_store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "profiles.json")


def test_load_subagent_profiles_seeds_the_full_disabled_roster_when_file_is_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    store = subagent_store.load_subagent_profiles()
    # The original generic default PLUS the built-in specialist fleet, every one disabled.
    assert len(store["profiles"]) == len(subagent_store._SEED_PROFILES)
    assert all(p["enabled"] is False for p in store["profiles"])
    names = {p["name"] for p in store["profiles"]}
    assert "Default Subagent" in names
    assert {"Recon-Scout", "SQLi-Verifier", "RE-Binary", "Reporter"} <= names
    # Seeding is in-memory only until a real change happens -- nothing written yet.
    assert not subagent_store.SUBAGENT_STORE_PATH.exists()


def test_load_subagent_profiles_returns_fresh_copies_not_the_module_constant(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    first = subagent_store.load_subagent_profiles()["profiles"]
    first[0]["name"] = "mutated"
    # A caller mutating a returned profile must never corrupt the seed every later load depends on.
    second = subagent_store.load_subagent_profiles()["profiles"]
    assert second[0]["name"] == "Default Subagent"


def test_load_subagent_profiles_treats_corrupt_json_as_the_default_seed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    subagent_store.SUBAGENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    subagent_store.SUBAGENT_STORE_PATH.write_text("{not valid json", encoding="utf-8")
    store = subagent_store.load_subagent_profiles()
    assert len(store["profiles"]) == len(subagent_store._SEED_PROFILES)
    assert any(p["id"] == "default" for p in store["profiles"])


def test_load_subagent_profiles_treats_a_non_object_json_as_the_default_seed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    subagent_store.SUBAGENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    subagent_store.SUBAGENT_STORE_PATH.write_text("[1, 2, 3]", encoding="utf-8")
    store = subagent_store.load_subagent_profiles()
    assert len(store["profiles"]) == len(subagent_store._SEED_PROFILES)


def test_seed_specialists_use_only_real_registered_tool_names():
    # A profile naming a tool that isn't registered yields an empty, useless capability hint for
    # the delegating model (_profile_capability_hint falls back) -- the exact bug the fleet must not
    # ship. Every seed tool name must resolve in the real registry.
    from agent.tools.registry import get_tool
    for profile in subagent_store._SEED_PROFILES:
        for tool_name in profile["allowed_tools"]:
            assert get_tool(tool_name) is not None, f"{profile['name']}: unknown tool {tool_name!r}"


def test_no_seed_profile_uses_a_tool_disallowed_for_subagents():
    # A subagent-disallowed tool (record_finding, the phase-terminal recording tools, ...) is
    # stripped from any subagent's toolset at delegation time and never offered as a checkbox, so
    # seeding one just inflates a profile's tool badge with options the editor can never show -- the
    # exact Reporter bug this guards against.
    for profile in subagent_store._SEED_PROFILES:
        offending = set(profile["allowed_tools"]) & subagent_store._SUBAGENT_DISALLOWED_TOOLS
        assert not offending, f"{profile['name']}: seeds subagent-disallowed tool(s) {offending}"


def test_migration_scrubs_disallowed_tools_from_an_existing_profile(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    # A profile persisted with a disallowed tool (the shape the first Reporter seed wrote to disk).
    _write_store(tmp_path, [{"id": "seed-reporter", "name": "Reporter", "enabled": False,
                             "allowed_tools": ["record_finding", "record_chain_result", "update_plan"],
                             "instructions": "", "provider": None, "model": None,
                             "icon": "wrench", "icon_color": "#fbbf24"}])

    subagent_store.ensure_builtin_specialists_migrated()

    reporter = next(p for p in subagent_store.load_subagent_profiles()["profiles"]
                    if p["id"] == "seed-reporter")
    # The disallowed record_* tools are gone; the one genuinely usable tool is kept.
    assert reporter["allowed_tools"] == ["update_plan"]


def test_seed_profiles_all_use_valid_icons():
    from agent.tools.subagent_icons import is_valid_icon, is_valid_color
    for profile in subagent_store._SEED_PROFILES:
        assert is_valid_icon(profile["icon"]), f"{profile['name']}: bad icon {profile['icon']!r}"
        assert is_valid_color(profile["icon_color"]), f"{profile['name']}: bad color"


def test_add_profile_persists_a_real_new_profile(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    subagent_store.add_profile(
        "OSINT-разведчик", ["dns_lookup", "subfinder"], "Focus on passive subdomain discovery.",
        "opencode-zen", "big-pickle",
    )

    on_disk = json.loads(subagent_store.SUBAGENT_STORE_PATH.read_text(encoding="utf-8"))
    # add_profile starts from the seeded roster (still present), plus the new one.
    assert len(on_disk["profiles"]) == len(subagent_store._SEED_PROFILES) + 1
    assert any(p["name"] == "Default Subagent" for p in on_disk["profiles"])
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


def _write_store(tmp_path, profiles, **extra):
    import json as _json
    payload = {"profiles": profiles, **extra}
    subagent_store.SUBAGENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    subagent_store.SUBAGENT_STORE_PATH.write_text(_json.dumps(payload), encoding="utf-8")


def test_migration_adds_fleet_to_a_pre_fleet_store_once_then_is_a_noop(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    # A store that predates the fleet -- only the old generic default, no version marker.
    _write_store(tmp_path, [{"id": "default", "name": "Default Subagent", "enabled": False,
                             "allowed_tools": [], "instructions": "", "provider": None,
                             "model": None, "icon": "robot", "icon_color": "#60a5fa"}])

    added = subagent_store.ensure_builtin_specialists_migrated()
    assert added == len(subagent_store._SEED_PROFILES) - 1  # every specialist, default already there
    names = {p["name"] for p in subagent_store.load_subagent_profiles()["profiles"]}
    assert "Recon-Scout" in names and "RE-Binary" in names
    # Migrated specialists land disabled, like every seeded/imported profile.
    assert all(p["enabled"] is False for p in subagent_store.load_subagent_profiles()["profiles"])

    # Second run does nothing -- the marker is now current.
    assert subagent_store.ensure_builtin_specialists_migrated() == 0


def test_migration_does_not_resurrect_a_deleted_builtin(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _write_store(tmp_path, [{"id": "default", "name": "Default Subagent", "enabled": False,
                             "allowed_tools": [], "instructions": "", "provider": None,
                             "model": None, "icon": "robot", "icon_color": "#60a5fa"}])
    subagent_store.ensure_builtin_specialists_migrated()

    # Operator deletes a specialist AFTER the one-time migration already ran.
    reporter_id = next(p["id"] for p in subagent_store._SEED_PROFILES if p["name"] == "Reporter")
    subagent_store.delete_profile(reporter_id)

    # A later startup migration must NOT bring it back (marker already current).
    subagent_store.ensure_builtin_specialists_migrated()
    names = {p["name"] for p in subagent_store.load_subagent_profiles()["profiles"]}
    assert "Reporter" not in names


def test_migration_is_a_noop_when_no_store_file_exists(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert subagent_store.ensure_builtin_specialists_migrated() == 0
    assert not subagent_store.SUBAGENT_STORE_PATH.exists()


def test_restore_builtin_specialists_readds_a_deleted_one_ignoring_the_marker(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _write_store(tmp_path, [{"id": "default", "name": "Default Subagent", "enabled": False,
                             "allowed_tools": [], "instructions": "", "provider": None,
                             "model": None, "icon": "robot", "icon_color": "#60a5fa"}])
    subagent_store.ensure_builtin_specialists_migrated()
    reporter_id = next(p["id"] for p in subagent_store._SEED_PROFILES if p["name"] == "Reporter")
    subagent_store.delete_profile(reporter_id)

    # Explicit operator "restore" brings it back even though the version marker is current.
    added = subagent_store.restore_builtin_specialists()
    assert added == 1
    assert "Reporter" in {p["name"] for p in subagent_store.load_subagent_profiles()["profiles"]}
