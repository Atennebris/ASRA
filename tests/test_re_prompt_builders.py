"""Regression tests for the shape-routed RE prompt builders (agent/prompts.py).

The old flat RE_TRIAGE_PROMPT/RE_CHAT_PROMPT enumerated all ~16 target shapes on every call, so
~95% of each prompt was irrelevant to any one target -- diluting weaker models and burning prompt
tokens. These builders emit only the CORE plus the block(s) matching the detected target shape.
What these tests pin down: (1) a routed prompt is much shorter than the full concatenation, (2) it
contains the right shape's guidance and excludes an irrelevant shape's, (3) no guidance is lost --
the full back-compat strings still carry every shape, (4) the CORE invariants (recording is
required, crackme-completion, the Windows-PE/managed-.NET down-ranking) survive routing.
"""
from agent.prompts import (
    RE_CHAT_PROMPT,
    RE_TRIAGE_PROMPT,
    build_re_chat_prompt,
    build_re_triage_prompt,
)
from agent.tools.builders.re_target import RE_TARGET_TOOLSETS

# A token that uniquely identifies each shape's own guidance block (not present in the CORE).
_TRIAGE_SHAPE_MARKERS = {
    "android_apk": "apktool",
    "dotnet_assembly": "ilspycmd",
    "wasm_module": "wasm_analyze",
    "smart_contract_source": "slither",
    "evm_bytecode": "heimdall_decompile",
    "source_repository": "trufflehog",
    "native_binary": "afl_fuzz_start",
    "firmware_blob": "binwalk",
}


def test_builders_return_nonempty_str_for_every_detected_shape():
    # Every shape detect_target_shape can emit, plus the unknown/ambiguous ones, must route
    # without KeyError and never return the full prompt.
    shapes = list(RE_TARGET_TOOLSETS) + [
        "unknown", "unknown_directory", "unknown_binary_blob", "multi_target", None,
    ]
    for shape in shapes:
        tri = build_re_triage_prompt(shape)
        chat = build_re_chat_prompt(shape)
        assert isinstance(tri, str) and tri
        assert isinstance(chat, str) and chat
        assert len(tri) < len(RE_TRIAGE_PROMPT)
        assert len(chat) < len(RE_CHAT_PROMPT)


def test_routed_prompt_is_much_shorter_than_full():
    # A small shape (smart-contract source) is the clearest case: it should be well under half the
    # size of the all-shapes concatenation.
    assert len(build_re_triage_prompt("smart_contract_source")) < 0.5 * len(RE_TRIAGE_PROMPT)
    assert len(build_re_chat_prompt("smart_contract_source")) < 0.5 * len(RE_CHAT_PROMPT)


def test_routing_includes_matching_block_and_excludes_irrelevant_one():
    sol = build_re_triage_prompt("smart_contract_source")
    assert "slither" in sol and "mythril" in sol
    # the Android/binary guidance must NOT ride along on a smart-contract target
    assert "apktool" not in sol
    assert "afl_fuzz_start" not in sol

    apk = build_re_triage_prompt("android_apk")
    assert "apktool" in apk and "jadx" in apk
    assert "slither" not in apk

    # same discipline for the chat builder
    csol = build_re_chat_prompt("smart_contract_source")
    assert "slither" in csol and "apktool" not in csol
    capk = build_re_chat_prompt("android_apk")
    assert "apktool" in capk and "slither" not in capk


def test_each_shape_marker_lands_in_its_own_routed_prompt():
    for shape, marker in _TRIAGE_SHAPE_MARKERS.items():
        assert marker in build_re_triage_prompt(shape), (shape, marker)


def test_unknown_and_none_route_to_binary_block():
    # Unknown/ambiguous shapes fall back to the generic binary block (the most common real target).
    for shape in (None, "unknown", "unknown_binary_blob", "multi_target"):
        assert "afl_fuzz_start" in build_re_triage_prompt(shape)
        assert "Cheat Engine" in build_re_chat_prompt(shape)  # memscan workflow rides with binary


def test_directory_with_executable_routes_to_binary():
    assert "afl_fuzz_start" in build_re_triage_prompt("directory_with_executable")


def test_core_recording_invariants_present_in_every_build():
    for shape in ("smart_contract_source", "android_apk", "native_binary", None):
        tri = build_re_triage_prompt(shape)
        for required in ("record_target_profile", "record_finding", "record_technique"):
            assert required in tri, (shape, required)
        assert "identify the target shape" in tri
        # recording is stated as REQUIRED, not optional
        assert "REQUIRED output" in tri


def test_crackme_completion_wording_in_core():
    # RC#5: the "should not try to fully solve" blanket is gone; a crackme answer is expected + recorded.
    tri = build_re_triage_prompt("native_binary")
    assert "crackme" in tri
    assert "recovered password/serial/key" in tri
    assert "should not try" not in tri


def test_broken_dynamic_tools_are_down_ranked():
    # B5: Windows PE under WSL2 -> static-first; managed .NET -> frida_trace can't instrument it.
    nb = build_re_triage_prompt("native_binary")
    assert "STATIC analysis" in nb
    assert "structurally unable to run or attach to a PE" in nb

    dn = build_re_triage_prompt("dotnet_assembly")
    assert "cannot instrument managed" in dn
    assert "ilspycmd" in dn

    cnb = build_re_chat_prompt("native_binary")
    assert "lead with STATIC analysis" in cnb
    cdn = build_re_chat_prompt("dotnet_assembly")
    assert "cannot instrument managed" in cdn


def test_full_concatenations_still_carry_every_shape():
    # Back-compat: the module-level strings remain the full all-shapes prompt, so existing imports
    # keep behaving as before. Every shape's signature tool must still be present in both.
    for tok in (
        "apktool", "ipa_extract", "ilspycmd", "wasm_analyze", "bundle_runtime_graph",
        "afl_fuzz_start", "slither", "heimdall_decompile", "trufflehog", "binwalk",
        "sigrok_cli", "binary_semantic_diff",
    ):
        assert tok in RE_TRIAGE_PROMPT, tok
        assert tok in RE_CHAT_PROMPT, tok
