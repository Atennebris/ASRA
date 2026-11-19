"""detect_target_shape/RE_TARGET_TOOLSETS (agent/tools/builders/re_target.py) and the pieces that
consume them -- apply_detected_target_profile/_merge_target_profile_fact/_target_shape_task_addendum
(agent/core.py). Real, confirmed gap this closes: session["target_profile"] used to stay empty from
project creation until the model's own triage pass got around to calling radare2 and then
record_target_profile -- every pass re-derived "what even is this file" from scratch, at
LLM-reasoning cost, even on the most common/obvious shapes. This is that same classification,
deterministic and zero-LLM-cost, run once at project creation.
"""
import json
import subprocess

import agent.core as core
from agent.tools.builders.re_target import RE_TARGET_TOOLSETS, detect_target_shape


# --- single-file shape classification by extension -- the cheap, unambiguous cases ---

def test_apk_by_extension(tmp_path):
    target = tmp_path / "app.apk"
    target.write_bytes(b"PK\x03\x04")  # a real .apk is a zip -- content irrelevant, extension decides
    assert detect_target_shape(str(target))["shape"] == "android_apk"


def test_ipa_by_extension(tmp_path):
    target = tmp_path / "app.ipa"
    target.write_bytes(b"PK\x03\x04")
    assert detect_target_shape(str(target))["shape"] == "ios_ipa"


def test_sol_file_by_extension(tmp_path):
    target = tmp_path / "Vault.sol"
    target.write_text("contract Vault {}")
    assert detect_target_shape(str(target))["shape"] == "smart_contract_source"


def test_wasm_by_extension(tmp_path):
    target = tmp_path / "core.wasm"
    target.write_bytes(b"\x00asm")
    assert detect_target_shape(str(target))["shape"] == "wasm_module"


def test_jsc_by_extension(tmp_path):
    target = tmp_path / "index.jsc"
    target.write_bytes(b"\xc0\xde\xde\xed")
    assert detect_target_shape(str(target))["shape"] == "node_bytecode"


def test_asar_by_extension(tmp_path):
    target = tmp_path / "app.asar"
    target.write_bytes(b"\x04\x00\x00\x00")
    assert detect_target_shape(str(target))["shape"] == "electron_app"


# --- single-file: magic-byte-sniffed compiled binaries ---

def test_elf_binary_without_radare2_installed_still_classifies(tmp_path, monkeypatch):
    """radare2 missing/unavailable must degrade to fewer facts, never block classification."""
    import agent.tools.builders.re_target as re_target_module
    monkeypatch.setattr(re_target_module.shutil, "which", lambda name: None)
    target = tmp_path / "crackme"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = detect_target_shape(str(target))
    assert result["shape"] == "native_binary"
    assert result["facts"] == []


def test_pe_binary_with_radare2_info_facts(tmp_path, monkeypatch):
    import agent.tools.builders.re_target as re_target_module
    monkeypatch.setattr(re_target_module.shutil, "which", lambda name: "/usr/bin/radare2" if name == "radare2" else None)

    def _fake_run(argv, **kwargs):
        assert argv[:3] == ["radare2", "-q", "-c"]
        assert argv[3] == "iIj"
        info = {"bintype": "pe", "arch": "x86", "bits": 64, "os": "windows", "lang": "c", "compiler": "", "canary": False}
        return subprocess.CompletedProcess(argv, 0, json.dumps(info), "")

    monkeypatch.setattr(re_target_module.subprocess, "run", _fake_run)
    target = tmp_path / "crackme.exe"
    target.write_bytes(b"MZ" + b"\x00" * 60)

    result = detect_target_shape(str(target))

    assert result["shape"] == "native_binary"
    facts_by_label = {f["label"]: f["value"] for f in result["facts"]}
    assert facts_by_label["Format"] == "pe"
    assert facts_by_label["Architecture"] == "x86"
    assert facts_by_label["Bits"] == "64"
    # canary=False is a real, meaningful fact (not the same as "absent") -- must still be reported.
    assert facts_by_label["Stack canary"] == "False"


def test_dotnet_assembly_detected_from_radare2_lang_field(tmp_path, monkeypatch):
    import agent.tools.builders.re_target as re_target_module
    monkeypatch.setattr(re_target_module.shutil, "which", lambda name: "/usr/bin/radare2")
    monkeypatch.setattr(
        re_target_module.subprocess, "run",
        lambda argv, **k: subprocess.CompletedProcess(argv, 0, json.dumps({"bintype": "pe", "lang": "cil"}), ""),
    )
    target = tmp_path / "app.dll"
    target.write_bytes(b"MZ" + b"\x00" * 60)

    assert detect_target_shape(str(target))["shape"] == "dotnet_assembly"


def test_radare2_missing_binary_degrades_gracefully(tmp_path, monkeypatch):
    import agent.tools.builders.re_target as re_target_module
    monkeypatch.setattr(re_target_module.shutil, "which", lambda name: "/usr/bin/radare2")

    def _raise_not_found(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(re_target_module.subprocess, "run", _raise_not_found)
    target = tmp_path / "crackme"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    result = detect_target_shape(str(target))
    assert result["shape"] == "native_binary"
    assert result["facts"] == []


def test_radare2_unparseable_output_degrades_gracefully(tmp_path, monkeypatch):
    import agent.tools.builders.re_target as re_target_module
    monkeypatch.setattr(re_target_module.shutil, "which", lambda name: "/usr/bin/radare2")
    monkeypatch.setattr(
        re_target_module.subprocess, "run", lambda argv, **k: subprocess.CompletedProcess(argv, 1, "not json at all", "error"),
    )
    target = tmp_path / "crackme"
    target.write_bytes(b"\x7fELF" + b"\x00" * 60)

    result = detect_target_shape(str(target))
    assert result["shape"] == "native_binary"
    assert result["facts"] == []


# --- single-file: non-magic, non-extension fallbacks ---

def test_evm_bytecode_detected_from_long_hex_text(tmp_path):
    target = tmp_path / "bytecode.txt"
    target.write_text("0x" + "60" * 40)
    assert detect_target_shape(str(target))["shape"] == "evm_bytecode"


def test_short_hex_text_is_not_evm_bytecode(tmp_path):
    target = tmp_path / "small.txt"
    target.write_text("dead")
    assert detect_target_shape(str(target))["shape"] == "unknown_binary_blob"


def test_large_unrecognized_blob_is_firmware(tmp_path, monkeypatch):
    import agent.tools.builders.re_target as re_target_module
    monkeypatch.setattr(re_target_module, "_FIRMWARE_BLOB_MIN_SIZE_BYTES", 10)
    target = tmp_path / "update.bin"
    target.write_bytes(b"\x01" * 100)
    assert detect_target_shape(str(target))["shape"] == "firmware_blob"


def test_small_unrecognized_blob_is_unknown(tmp_path):
    target = tmp_path / "mystery.bin"
    target.write_bytes(b"\x01\x02\x03\x04")
    assert detect_target_shape(str(target))["shape"] == "unknown_binary_blob"


def test_missing_path_is_unknown(tmp_path):
    assert detect_target_shape(str(tmp_path / "does_not_exist"))["shape"] == "unknown"


# --- directories ---

def test_directory_with_sol_file_is_smart_contract_source(tmp_path):
    (tmp_path / "Vault.sol").write_text("contract Vault {}")
    assert detect_target_shape(str(tmp_path))["shape"] == "smart_contract_source"


def test_directory_with_electron_dependency_is_electron_app(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"electron": "^30.0.0"}}))
    assert detect_target_shape(str(tmp_path))["shape"] == "electron_app"


def test_directory_with_asar_is_electron_app(tmp_path):
    (tmp_path / "app.asar").write_bytes(b"\x00")
    assert detect_target_shape(str(tmp_path))["shape"] == "electron_app"


def test_directory_with_top_level_executable_names_it(tmp_path):
    (tmp_path / "readme.txt").write_text("hi")
    (tmp_path / "crackme").write_bytes(b"\x7fELF" + b"\x00" * 60)
    result = detect_target_shape(str(tmp_path))
    assert result["shape"] == "directory_with_executable"
    assert result["facts"] == [{"label": "Executable found in directory", "value": "crackme"}]


def test_directory_of_source_files_is_source_repository(tmp_path):
    (tmp_path / "main.go").write_text("package main")
    (tmp_path / "util.go").write_text("package main")
    assert detect_target_shape(str(tmp_path))["shape"] == "source_repository"


def test_empty_directory_is_unknown_directory(tmp_path):
    assert detect_target_shape(str(tmp_path))["shape"] == "unknown_directory"


# --- multi-target (comma-separated session["target"]) ---

def test_two_files_is_binary_diff_pair(tmp_path):
    a = tmp_path / "v1.exe"
    b = tmp_path / "v2.exe"
    a.write_bytes(b"MZ")
    b.write_bytes(b"MZ")
    result = detect_target_shape(f"{a}, {b}")
    assert result["shape"] == "binary_diff_pair"
    assert result["facts"] == [{"label": "Target 1", "value": str(a)}, {"label": "Target 2", "value": str(b)}]


def test_three_targets_is_multi_target(tmp_path):
    paths = []
    for name in ("one.sol", "two.sol", "three.sol"):
        p = tmp_path / name
        p.write_text("contract C {}")
        paths.append(p)
    result = detect_target_shape(", ".join(str(p) for p in paths))
    assert result["shape"] == "multi_target"


def test_empty_target_string_is_unknown():
    assert detect_target_shape("")["shape"] == "unknown"


# --- RE_TARGET_TOOLSETS: every shape with an entry has at least one real tool name ---

def test_every_toolset_entry_has_primary_tools():
    for shape, entry in RE_TARGET_TOOLSETS.items():
        assert entry.get("primary_tools"), f"{shape!r} has no primary_tools"


# --- apply_detected_target_profile / _merge_target_profile_fact (agent/core.py) ---

def test_apply_detected_target_profile_writes_shape_and_auto_sourced_facts():
    session = {}
    core.apply_detected_target_profile(session, {
        "shape": "native_binary",
        "facts": [{"label": "Format", "value": "PE32+"}, {"label": "Architecture", "value": "x86-64"}],
    })
    assert session["target_shape"] == "native_binary"
    assert session["target_profile"] == [
        {"label": "Format", "value": "PE32+", "source": "auto"},
        {"label": "Architecture", "value": "x86-64", "source": "auto"},
    ]


def test_apply_detected_target_profile_updates_in_place_on_repeat_call():
    session = {}
    core.apply_detected_target_profile(session, {"shape": "native_binary", "facts": [{"label": "Format", "value": "unknown"}]})
    core.apply_detected_target_profile(session, {"shape": "native_binary", "facts": [{"label": "Format", "value": "PE32+"}]})
    assert len(session["target_profile"]) == 1
    assert session["target_profile"][0]["value"] == "PE32+"


def test_apply_detected_target_profile_never_raises_on_empty_detection():
    session = {}
    core.apply_detected_target_profile(session, {"shape": "unknown", "facts": []})
    assert session["target_shape"] == "unknown"
    assert session.get("target_profile", []) == []


def test_record_target_profile_accepts_auto_source():
    session = {"session_id": "usr_auto_source_test"}
    result = core.re_record_target_profile({
        "_session_id": "usr_auto_source_test", "_session": session,
        "label": "Format", "value": "PE32+", "source": "auto",
    })
    assert result["status"] == "ok"
    assert result["recorded"]["source"] == "auto"


def test_tool_sourced_call_overwrites_an_auto_fact_without_special_marking():
    """Unlike an operator claim, an auto-detected fact getting corrected by a real tool call is a
    plain, uninteresting update -- no corrected_from_operator_claim-style provenance needed."""
    session = {"session_id": "usr_auto_overwrite_test"}
    core.apply_detected_target_profile(session, {"shape": "native_binary", "facts": [{"label": "Compiler", "value": "unknown"}]})
    result = core.re_record_target_profile({
        "_session_id": "usr_auto_overwrite_test", "_session": session,
        "label": "Compiler", "value": "go1.22", "source": "tool",
    })
    assert result["recorded"]["value"] == "go1.22"
    assert "corrected_from_operator_claim" not in result["recorded"]


# --- _target_shape_task_addendum (agent/core.py) ---

def test_target_shape_task_addendum_includes_shape_and_facts():
    session = {
        "target_shape": "native_binary",
        "target_profile": [{"label": "Format", "value": "PE32+", "source": "auto"}],
    }
    text = core._target_shape_task_addendum(session)
    assert "PE32+" in text
    assert "native_binary" in text
    assert "radare2" in text  # native_binary's own primary_tools


def test_target_shape_task_addendum_ignores_non_auto_facts_for_the_already_established_line():
    session = {
        "target_shape": "native_binary",
        "target_profile": [{"label": "Password", "value": "hunter2", "source": "tool"}],
    }
    text = core._target_shape_task_addendum(session)
    assert "hunter2" not in text


def test_target_shape_task_addendum_empty_when_nothing_detected():
    assert core._target_shape_task_addendum({}) == ""


def test_target_shape_task_addendum_empty_for_a_shape_with_no_toolset_entry():
    session = {"target_shape": "unknown_directory", "target_profile": []}
    assert core._target_shape_task_addendum(session) == ""
