"""agent/operator_profile_store.py — the persistent, cross-project "operator profile" for the MAIN
agent. Same on-disk convention as agent/tools/wordlist_store.py (load/_write pair, atomic
tmp+os.replace, corrupt/missing/non-object file treated as "nothing configured yet", never an
error). The store path is computed at import time from projects.paths.resolve_global_app_dir(), so
every test isolates it onto a tmp_path file first — the real user profile on disk is never touched.
"""
import json

import agent.operator_profile_store as ops


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(ops, "OPERATOR_PROFILE_PATH", tmp_path / "operator_profile.json")


def test_load_returns_empty_defaults_when_file_is_missing(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    profile = ops.load_operator_profile()
    assert profile == {
        "schema_version": ops.SCHEMA_VERSION,
        "standing_instructions": "",
        "focus_classes": "",
        "communication_style": "",
        "approval_severities": [],
    }
    assert ops.operator_profile_is_empty() is True
    assert ops.operator_profile_is_empty(profile) is True


def test_save_then_load_round_trips_every_field(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = ops.save_operator_profile(
        standing_instructions="Always stay in scope.",
        focus_classes="IDOR, broken auth",
        communication_style="concise",
    )
    assert saved == {
        "schema_version": ops.SCHEMA_VERSION,
        "standing_instructions": "Always stay in scope.",
        "focus_classes": "IDOR, broken auth",
        "communication_style": "concise",
        "approval_severities": [],
    }

    loaded = ops.load_operator_profile()
    assert loaded == saved
    assert ops.operator_profile_is_empty(loaded) is False
    assert ops.operator_profile_is_empty() is False


def test_save_writes_valid_json_to_disk(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ops.save_operator_profile(standing_instructions="Prefer low-noise probes.")

    on_disk = json.loads(ops.OPERATOR_PROFILE_PATH.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == ops.SCHEMA_VERSION
    assert on_disk["standing_instructions"] == "Prefer low-noise probes."
    assert on_disk["focus_classes"] == ""
    assert on_disk["communication_style"] == ""


def test_save_strips_whitespace_from_text_fields(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = ops.save_operator_profile(
        standing_instructions="  stay quiet on WAF targets  \n",
        focus_classes="\tSSRF\t",
    )
    assert saved["standing_instructions"] == "stay quiet on WAF targets"
    assert saved["focus_classes"] == "SSRF"


def test_save_coerces_an_invalid_communication_style_to_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    saved = ops.save_operator_profile(communication_style="loud")
    assert saved["communication_style"] == ""
    assert ops.load_operator_profile()["communication_style"] == ""


def test_save_accepts_each_valid_communication_style(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    for style in ("concise", "detailed"):
        ops.save_operator_profile(communication_style=style)
        assert ops.load_operator_profile()["communication_style"] == style


def test_load_treats_corrupt_json_as_empty_defaults(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ops.OPERATOR_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ops.OPERATOR_PROFILE_PATH.write_text("{ not json", encoding="utf-8")

    profile = ops.load_operator_profile()
    assert profile == ops._default_profile()
    assert ops.operator_profile_is_empty(profile) is True


def test_load_treats_a_non_object_json_as_empty_defaults(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ops.OPERATOR_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ops.OPERATOR_PROFILE_PATH.write_text("[]", encoding="utf-8")

    assert ops.load_operator_profile() == ops._default_profile()


def test_load_fills_defaults_for_missing_keys_and_drops_extras(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ops.OPERATOR_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ops.OPERATOR_PROFILE_PATH.write_text(
        json.dumps({
            "standing_instructions": "only this key is set",
            "surprise_extra_field": "should be dropped",
        }),
        encoding="utf-8",
    )

    profile = ops.load_operator_profile()
    assert profile == {
        "schema_version": ops.SCHEMA_VERSION,
        "standing_instructions": "only this key is set",
        "focus_classes": "",
        "communication_style": "",
        "approval_severities": [],
    }
    assert "surprise_extra_field" not in profile
    assert ops.operator_profile_is_empty(profile) is False


def test_load_ignores_an_on_disk_invalid_communication_style(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    ops.OPERATOR_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    ops.OPERATOR_PROFILE_PATH.write_text(
        json.dumps({"communication_style": "screaming"}), encoding="utf-8"
    )
    assert ops.load_operator_profile()["communication_style"] == ""


def test_operator_profile_is_empty_true_for_whitespace_only_fields(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert ops.operator_profile_is_empty({
        "standing_instructions": "   ",
        "focus_classes": "\n\t",
        "communication_style": "",
    }) is True


def test_addendum_is_empty_for_an_empty_profile(monkeypatch):
    from agent import core

    monkeypatch.setattr(core, "load_operator_profile", lambda: ops._default_profile())
    assert core._operator_profile_task_addendum() == ""


def test_addendum_embeds_standing_instructions_and_starts_with_two_newlines(monkeypatch):
    from agent import core

    monkeypatch.setattr(core, "load_operator_profile", lambda: {
        "schema_version": ops.SCHEMA_VERSION,
        "standing_instructions": "NEVER touch production data.",
        "focus_classes": "SSRF",
        "communication_style": "",
    })
    addendum = core._operator_profile_task_addendum()
    assert addendum.startswith("\n\n")
    assert "NEVER touch production data." in addendum
    assert "SSRF" in addendum


def test_addendum_distinguishes_concise_from_detailed(monkeypatch):
    from agent import core

    def _profile(style):
        return {
            "schema_version": ops.SCHEMA_VERSION,
            "standing_instructions": "",
            "focus_classes": "",
            "communication_style": style,
        }

    monkeypatch.setattr(core, "load_operator_profile", lambda: _profile("concise"))
    concise = core._operator_profile_task_addendum()
    assert concise.startswith("\n\n")
    assert "brief" in concise and "filler" in concise

    monkeypatch.setattr(core, "load_operator_profile", lambda: _profile("detailed"))
    detailed = core._operator_profile_task_addendum()
    assert "more detail" in detailed and "verbose" in detailed

    assert concise != detailed
