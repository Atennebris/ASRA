"""RE-triage durability fixes -- the recurring "agent did real work but recorded NOTHING durable,
so every panel looks empty" failure mode, traced across three real RE sessions.

Covers:
- auto_record_target_profile_from_tool: a radare2 `info` call deterministically lands Target Profile
  facts without the model having to call record_target_profile (the main reason triage left nothing).
- _extract_target_host: an RE function referenced as both fcn.<addr> and 0x<addr> collapses to ONE
  host_health key instead of being double-tracked.
- _solve_hint: a tool result that looks like a SOLVE nudges the model to capture it.
- _re_fingerprint / RE playbook capture: a solved RE finding is captured into the cross-session
  playbook keyed by target shape, so the learning loop actually fills for RE.
- _re_triage_end_reason_message: a safeguard-stopped pass that DID record something says so, instead
  of a blanket "may be incomplete" that undersells it.
"""
import agent.core as core
from agent.core import (
    RunContext,
    _extract_target_host,
    _normalize_target_token,
    _re_fingerprint,
    _re_triage_end_reason_message,
    _solve_hint,
    auto_record_target_profile_from_tool,
)


def _radare2_info_result(**overrides) -> dict:
    info = {
        "arch": "x86", "bits": 64, "bintype": "elf", "class": "ELF64",
        "compiler": "GCC 11", "lang": "c", "os": "linux",
        "static": False, "stripped": False, "endian": "little",
    }
    info.update(overrides)
    return {"status": "ok", "tool": "radare2", "parsed": {"result": info}}


# --- task 1: deterministic auto-record of target-profile facts ---------------


def test_auto_record_lands_the_obvious_profile_facts():
    session = {"target_profile": []}
    added = auto_record_target_profile_from_tool(session, "radare2", _radare2_info_result())

    facts = {f["label"]: f["value"] for f in session["target_profile"]}
    assert facts["Architecture"] == "x86 64-bit"
    assert facts["Format"] == "elf (ELF64)"
    assert facts["Compiler"] == "GCC 11"
    assert facts["Language"] == "c"
    assert facts["Platform"] == "linux"
    assert facts["Linking"] == "dynamically linked"
    assert facts["Symbols"] == "not stripped"
    # Every auto-recorded fact is flagged as auto-detected provenance.
    assert all(f["source"] == "auto" for f in session["target_profile"])
    assert {f["label"] for f in added} == set(facts)


def test_auto_record_is_idempotent_and_non_clobbering():
    session = {"target_profile": []}
    auto_record_target_profile_from_tool(session, "radare2", _radare2_info_result())
    count_after_first = len(session["target_profile"])

    # A second identical info call must add nothing (dedup by label).
    second = auto_record_target_profile_from_tool(session, "radare2", _radare2_info_result())
    assert second == []
    assert len(session["target_profile"]) == count_after_first


def test_auto_record_never_overwrites_an_existing_fact():
    # An operator already stated the language; an auto-derived guess must not clobber it.
    session = {"target_profile": [{"label": "Language", "value": "Rust (operator)", "source": "operator"}]}
    auto_record_target_profile_from_tool(session, "radare2", _radare2_info_result())
    language = next(f for f in session["target_profile"] if f["label"] == "Language")
    assert language["value"] == "Rust (operator)"
    assert language["source"] == "operator"


def test_auto_record_ignores_non_radare2_and_non_info_results():
    session = {"target_profile": []}
    assert auto_record_target_profile_from_tool(session, "ghidra", _radare2_info_result()) == []
    # A radare2 list result (e.g. functions) is not an info block -> nothing recorded.
    list_result = {"status": "ok", "tool": "radare2", "parsed": {"result": [{"name": "main"}]}}
    assert auto_record_target_profile_from_tool(session, "radare2", list_result) == []
    assert session["target_profile"] == []


# --- task 5: function-ref host-key normalization -----------------------------


def test_function_refs_normalize_to_one_key():
    assert _normalize_target_token("fcn.140040d7c") == "0x140040d7c"
    assert _normalize_target_token("0x140040D7C") == "0x140040d7c"
    assert _normalize_target_token("sym.140040d7c") == "0x140040d7c"
    # The two spellings of the same function collapse to the same host_health key.
    assert _extract_target_host({"target": "fcn.140040d7c"}) == _extract_target_host({"target": "0x140040d7c"})


def test_real_hostnames_are_left_untouched():
    # A real host/URL (and a bare hex-looking word with no fcn./0x marker) must NOT be rewritten.
    assert _extract_target_host({"target": "https://example.com/x"}) == "example.com"
    assert _normalize_target_token("deadbeef") == "deadbeef"
    assert _normalize_target_token("juice-shop.herokuapp.com") == "juice-shop.herokuapp.com"


# --- task 4: solve-side nudge ------------------------------------------------


def test_solve_hint_fires_on_a_success_banner():
    result = {"status": "ok", "stdout": "Checking serial... Congratulations, the flag is flag{abc}"}
    hinted = _solve_hint(result, "custom_re_script")
    assert "solve_hint" in hinted
    assert "record_technique" in hinted["solve_hint"]


def test_solve_hint_is_silent_without_a_solve_signal():
    result = {"status": "ok", "stdout": "disassembled 40 instructions"}
    assert "solve_hint" not in _solve_hint(result, "custom_re_script")
    # And it never fires on a non-run analysis tool, even with a banner-looking string.
    assert "solve_hint" not in _solve_hint({"status": "ok", "stdout": "flag{x}"}, "radare2")
    # Nor on a failed run.
    assert "solve_hint" not in _solve_hint({"status": "error", "stdout": "flag{x}"}, "custom_re_script")


# --- task 4: RE fingerprint + playbook capture -------------------------------


def test_re_fingerprint_keys_off_target_profile_and_filename():
    session = {
        "mode": "reverse_engineering",
        "target": "/tmp/crackme.bin",
        "target_shape": "pe32",
        "target_profile": [{"label": "Language", "value": "dotnet"}],
    }
    fp = _re_fingerprint(session)
    assert "crackme" in fp
    assert "dotnet" in fp
    assert "pe32" in fp


def test_re_finding_is_captured_into_the_playbook(monkeypatch):
    captured = {}

    def _fake_record_technique(key, entry):
        captured["key"] = key
        captured["entry"] = entry
        return "tech123"

    monkeypatch.setattr(core.playbook_store, "record_technique", _fake_record_technique)
    monkeypatch.setattr(core.playbook_store, "count_techniques", lambda: 1)
    monkeypatch.setattr(core.playbook_store, "extract_cves", lambda *a, **k: [])
    monkeypatch.setattr(core, "_embed_playbook_entries", lambda *a, **k: 0)
    monkeypatch.setattr(core, "_notify_storage_reward", lambda *a, **k: None)
    monkeypatch.setattr(core, "_append_playbook_note", lambda *a, **k: None)

    session = {
        "mode": "reverse_engineering",
        "target": "/tmp/crackme.bin",
        "target_shape": "pe32",
        "target_profile": [{"label": "Language", "value": "dotnet"}],
        "findings": [],
    }
    ctx = RunContext(llm=None, session=session, session_id="usr_re_capture")
    finding = {
        "title": "Hardcoded serial check bypassable by patching jne at 0x401050",
        "evidence": "patched jne->jmp, binary now accepts any serial",
    }

    core._maybe_capture_playbook_entry(ctx, finding)

    assert captured["entry"]["technique"].startswith("Hardcoded serial check")
    assert captured["entry"]["waf_vendors"] == []
    # Keyed off the RE shape fingerprint, not an (empty) web tech fingerprint.
    assert "crackme" in captured["key"]
    assert "pe32" in captured["key"]


# --- task 9: honest end-reason that reflects what WAS recorded ---------------


def test_end_reason_reports_what_was_recorded():
    session = {
        "findings": [{"title": "a"}, {"title": "b"}],
        "hypotheses": [{"text": "lead", "status": "open"}],
        "target_profile": [{"label": "Language", "value": "c"}],
    }
    msg = _re_triage_end_reason_message("exceeded the 1800s wall-clock backstop", session)
    assert msg is not None
    assert "2 findings" in msg
    assert "1 open lead" in msg
    assert "1 target-profile fact" in msg
    # It no longer undersells a productive pass as "may be incomplete".
    assert "may be incomplete" not in msg


def test_end_reason_still_says_may_be_incomplete_when_nothing_recorded():
    empty = {"findings": [], "hypotheses": [], "target_profile": []}
    msg = _re_triage_end_reason_message("exceeded the 1800s wall-clock backstop", empty)
    assert "may be incomplete" in msg
    # Backward compatible: no session argument keeps the old wording too.
    assert "may be incomplete" in _re_triage_end_reason_message("exceeded the 1800s wall-clock backstop")
