"""Cross-session technique playbook: agent/tools/playbook_store.py's persistence + agent/core.py's
fingerprint helper, deterministic capture hook (_maybe_capture_playbook_entry), lookup/injection
(_playbook_task_addendum), and the periodic LLM distillation pass
(_run_playbook_distillation_pass).

A technique gets captured once a finding is genuinely proven (exploited=True + real evidence), and
resurfaces the next time a similarly fingerprinted target (same WAF vendor + overlapping tech
keywords) shows up — exact key match first, keyword-overlap fuzzy fallback otherwise. See
agent/core.py's _confirmed_tech_facts_task_addendum for the same-session precedent this
generalizes across sessions.
"""
import asyncio
import json

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import agent.core as core
from agent.core import (
    RunContext,
    _finding_fingerprint,
    _maybe_capture_playbook_entry,
    _playbook_fingerprint_key,
    _playbook_notes_path,
    _playbook_task_addendum,
    _run_playbook_distillation_pass,
    _waf_vendors_from_protections,
)
from agent.llm_client import LLMResponse
from agent.tools import playbook_store


def _isolate_store(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "techniques.json")


def _session(session_id, **overrides):
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "hypotheses": [], "recon_result": {},
    }
    session.update(overrides)
    return session


def _exploited_finding(**overrides):
    finding = {
        "title": "SQLi in search param bypasses WAF via double URL encoding",
        "technology": "WordPress 5.8.1",
        "exploitation_scenario": "remote_direct",
        "exploited": True,
        "evidence": "GET /?s=%2527%2520OR%25201%3D1 returned full user table",
        "poc_command": "curl 'https://target/?s=%2527%2520OR%25201%3D1'",
    }
    finding.update(overrides)
    return finding


# --- playbook_store: persistence ---


def test_load_playbook_store_returns_empty_dict_when_file_missing(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    assert playbook_store.load_playbook_store() == {}


def test_load_playbook_store_treats_corrupt_json_as_empty(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.PLAYBOOK_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    playbook_store.PLAYBOOK_STORE_PATH.write_text("not valid json{{{", encoding="utf-8")
    assert playbook_store.load_playbook_store() == {}


def test_load_playbook_store_drops_malformed_entries(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.PLAYBOOK_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    playbook_store.PLAYBOOK_STORE_PATH.write_text(json.dumps({"good_key": [{"technique": "x"}], "bad_key": "not a list"}), encoding="utf-8")
    assert playbook_store.load_playbook_store() == {"good_key": [{"technique": "x"}]}


def test_record_technique_appends_a_new_entry(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {"id": "a1", "technique": "SQLi via double encoding", "times_confirmed": 1, "source_session_ids": ["s1"]})

    store = playbook_store.load_playbook_store()
    assert len(store["key1"]) == 1
    assert store["key1"][0]["technique"] == "SQLi via double encoding"


def test_record_technique_bumps_a_near_identical_entry_instead_of_duplicating(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {"id": "a1", "technique": "SQLi via double encoding", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})

    playbook_store.record_technique("key1", {"id": "a2", "technique": "SQLi VIA DOUBLE ENCODING", "times_confirmed": 1, "last_seen": "t2", "source_session_ids": ["s2"]})

    store = playbook_store.load_playbook_store()
    assert len(store["key1"]) == 1
    entry = store["key1"][0]
    assert entry["times_confirmed"] == 2
    assert set(entry["source_session_ids"]) == {"s1", "s2"}


def test_record_technique_auto_confirms_unreviewed_entry_on_live_dedup(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {
        "id": "extracted1", "technique": "SQLi via double encoding", "times_confirmed": 1,
        "last_seen": "t1", "source_session_ids": [], "source_type": "extracted", "confidence": "unreviewed",
    })

    playbook_store.record_technique("key1", {
        "id": "live1", "technique": "SQLi VIA DOUBLE ENCODING", "times_confirmed": 1,
        "last_seen": "t2", "source_session_ids": ["s1"], "source_type": "live", "confidence": "confirmed",
    })

    entry = playbook_store.load_playbook_store()["key1"][0]
    assert entry["id"] == "extracted1"  # same entry, auto-confirmed in place -- not a second record
    assert entry["confidence"] == "confirmed"
    assert entry["times_confirmed"] == 2


def test_record_technique_never_demotes_an_already_confirmed_entry(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {
        "id": "live1", "technique": "SQLi via double encoding", "times_confirmed": 1,
        "last_seen": "t1", "source_session_ids": ["s1"], "source_type": "live", "confidence": "confirmed",
    })

    # A later library-extracted match on the same technique text must never flip a proven entry
    # back to "unreviewed" -- extraction only ever adds new leads, never downgrades a real fact.
    playbook_store.record_technique("key1", {
        "id": "extracted1", "technique": "SQLi VIA DOUBLE ENCODING", "times_confirmed": 1,
        "last_seen": "t2", "source_session_ids": [], "source_type": "extracted", "confidence": "unreviewed",
    })

    entry = playbook_store.load_playbook_store()["key1"][0]
    assert entry["confidence"] == "confirmed"


def test_mark_reviewed_confirmed_flips_confidence_in_place(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {
        "id": "extracted1", "technique": "SQLi via double encoding", "times_confirmed": 1,
        "last_seen": "t1", "source_session_ids": [], "source_type": "extracted", "confidence": "unreviewed",
    })

    ok = playbook_store.mark_reviewed("extracted1", confirmed=True)

    assert ok is True
    entry = playbook_store.load_playbook_store()["key1"][0]
    assert entry["confidence"] == "confirmed"
    assert entry["id"] == "extracted1"  # kept, not recreated


def test_mark_reviewed_rejected_deletes_the_entry(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {
        "id": "extracted1", "technique": "SQLi via double encoding", "times_confirmed": 1,
        "last_seen": "t1", "source_session_ids": [], "source_type": "extracted", "confidence": "unreviewed",
    })

    ok = playbook_store.mark_reviewed("extracted1", confirmed=False)

    assert ok is True
    assert playbook_store.load_playbook_store() == {}


def test_mark_reviewed_returns_false_for_unknown_id(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    assert playbook_store.mark_reviewed("nope", confirmed=True) is False


def test_list_all_techniques_defaults_source_type_and_confidence_for_pre_existing_entries(tmp_path, monkeypatch):
    """An entry recorded before source_type/confidence existed carries neither field -- must read
    as "live"/"confirmed" (exactly what it always implicitly was), never as an unreviewed extract."""
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {
        "id": "old1", "technique": "pre-existing entry", "times_confirmed": 1, "source_session_ids": ["s1"],
    })

    listed = playbook_store.list_all_techniques()

    assert len(listed) == 1
    assert listed[0]["source_type"] == "live"
    assert listed[0]["confidence"] == "confirmed"


def test_replace_technique_entries_overwrites_and_removes_empty_key(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    playbook_store.record_technique("key1", {"id": "a1", "technique": "x", "times_confirmed": 1, "source_session_ids": ["s1"]})

    playbook_store.replace_technique_entries("key1", [{"id": "a1", "technique": "merged wording", "times_confirmed": 2, "source_session_ids": ["s1", "s2"]}])
    assert playbook_store.load_playbook_store()["key1"][0]["technique"] == "merged wording"

    playbook_store.replace_technique_entries("key1", [])
    assert "key1" not in playbook_store.load_playbook_store()


def test_find_similar_techniques_exact_match(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["php", "wordpress"], "waf": ["cloudflare"]}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a1", "technique": "known bypass", "times_confirmed": 3, "last_seen": "t1", "source_session_ids": ["s1"]})

    matches = playbook_store.find_similar_techniques({"php", "wordpress"}, {"cloudflare"}, limit=5)
    assert len(matches) == 1
    assert matches[0]["technique"] == "known bypass"


def test_find_similar_techniques_fuzzy_fallback_on_keyword_overlap(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["php", "wordpress", "xmlrpc"], "waf": ["cloudflare"]}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a1", "technique": "known bypass", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})

    # No exact match (different waf set), but "wordpress"/"php" overlap -> fuzzy fallback fires.
    matches = playbook_store.find_similar_techniques({"php", "wordpress"}, {"akamai"}, limit=5)
    assert len(matches) == 1
    assert matches[0]["technique"] == "known bypass"


def test_find_similar_techniques_returns_empty_when_nothing_overlaps(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["drupal"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a1", "technique": "unrelated", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})

    assert playbook_store.find_similar_techniques({"wordpress"}, set(), limit=5) == []


def test_find_similar_techniques_respects_limit(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["wordpress"], "waf": []}, sort_keys=True)
    for i in range(3):
        playbook_store.record_technique(key, {"id": f"a{i}", "technique": f"technique {i}", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})

    assert len(playbook_store.find_similar_techniques({"wordpress"}, set(), limit=2)) == 2


def test_find_similar_ranks_a_shared_waf_above_a_pure_tech_match(tmp_path, monkeypatch):
    # A WAF bypass proven on the SAME WAF (different CMS) should outrank an unrelated-WAF entry with
    # the same single-keyword tech overlap -- the whole point of the weighted score.
    _isolate_store(tmp_path, monkeypatch)
    waf_key = json.dumps({"tech": ["php"], "waf": ["cloudflare"]}, sort_keys=True)
    plain_key = json.dumps({"tech": ["php"], "waf": ["akamai"]}, sort_keys=True)
    playbook_store.record_technique(plain_key, {"id": "plain", "technique": "plain php trick", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})
    playbook_store.record_technique(waf_key, {"id": "waf", "technique": "cloudflare bypass", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})

    matches = playbook_store.find_similar_techniques({"php"}, {"cloudflare"}, limit=5)
    assert [m["id"] for m in matches][0] == "waf"


def test_find_similar_boosts_a_matching_vuln_class(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "xss", "technique": "xss one", "vuln_class": "xss", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "sqli", "technique": "sqli one", "vuln_class": "sqli", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})

    matches = playbook_store.find_similar_techniques({"nginx"}, set(), limit=5, vuln_class="xss")
    assert matches[0]["id"] == "xss"


def test_find_similar_prefers_more_distinct_targets(tmp_path, monkeypatch):
    # Proven across several DISTINCT sessions/targets beats the same-strength entry proven on one.
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "one", "technique": "one target", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "many", "technique": "many targets", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1", "s2", "s3", "s4"]})

    matches = playbook_store.find_similar_techniques({"nginx"}, set(), limit=5)
    assert matches[0]["id"] == "many"


# --- attribution: injected/led counters + pruning ---


def test_bump_injected_and_led_increment_the_right_entries(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "t1", "technique": "a", "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "t2", "technique": "b", "source_session_ids": ["s1"]})

    playbook_store.bump_injected({"t1", "t2"})
    playbook_store.bump_injected({"t1"})
    playbook_store.bump_led_to_finding({"t1"})

    by_id = {e["id"]: e for e in playbook_store.load_playbook_store()[key]}
    assert by_id["t1"]["injected_count"] == 2
    assert by_id["t1"]["led_to_finding_count"] == 1
    assert by_id["t2"]["injected_count"] == 1
    assert by_id["t2"].get("led_to_finding_count", 0) == 0


def test_success_rate_lifts_ranking(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "proven", "technique": "proven", "injected_count": 4, "led_to_finding_count": 4, "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "cold", "technique": "cold", "injected_count": 4, "led_to_finding_count": 0, "source_session_ids": ["s1"]})

    matches = playbook_store.find_similar_techniques({"nginx"}, set(), limit=5)
    assert matches[0]["id"] == "proven"


def test_prune_low_value_removes_noise_but_keeps_dead_ends_and_winners(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "noise", "technique": "noise", "injected_count": 10, "led_to_finding_count": 0, "outcome": "worked", "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "winner", "technique": "winner", "injected_count": 10, "led_to_finding_count": 2, "outcome": "worked", "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "deadend", "technique": "deadend", "injected_count": 10, "led_to_finding_count": 0, "outcome": "failed", "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "young", "technique": "young", "injected_count": 2, "led_to_finding_count": 0, "outcome": "worked", "source_session_ids": ["s1"]})

    removed = playbook_store.prune_low_value(min_injections=8)
    assert removed == 1
    remaining = {e["id"] for e in playbook_store.load_playbook_store()[key]}
    assert remaining == {"winner", "deadend", "young"}


def test_prune_low_value_disabled_when_threshold_zero(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "noise", "technique": "noise", "injected_count": 99, "led_to_finding_count": 0, "outcome": "worked", "source_session_ids": ["s1"]})
    assert playbook_store.prune_low_value(min_injections=0) == 0
    assert len(playbook_store.load_playbook_store()[key]) == 1


# --- chaining: record_technique returns id, resolve_technique_texts, kill-chain links ---


def test_record_technique_returns_id_for_new_and_deduped(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    assert playbook_store.record_technique(key, {"id": "t1", "technique": "a", "source_session_ids": ["s1"]}) == "t1"
    # dedup on identical technique text returns the EXISTING entry's id, not the new one's
    assert playbook_store.record_technique(key, {"id": "t2", "technique": "A", "source_session_ids": ["s2"]}) == "t1"


def test_resolve_technique_texts_maps_ids(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "t1", "technique": "first step", "source_session_ids": ["s1"]})
    assert playbook_store.resolve_technique_texts({"t1", "missing"}) == {"t1": "first step"}


def test_capture_builds_a_kill_chain_across_sequential_captures(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_chain")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _maybe_capture_playbook_entry(ctx, _exploited_finding(title="Foothold via LFI"))
    _maybe_capture_playbook_entry(ctx, _exploited_finding(title="RCE via log poisoning"))

    recorded = session["playbook_recorded_ids"]
    assert len(recorded) == 2
    first_id, second_id = recorded
    by_id = {e["id"]: e for lst in playbook_store.load_playbook_store().values() for e in lst}
    assert by_id[first_id]["chained_from_ids"] == []
    assert by_id[second_id]["chained_from_ids"] == [first_id]


def _build_three_step_chain():
    key = json.dumps({"tech": ["nginx"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a", "technique": "step1", "chained_from_ids": [], "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "b", "technique": "step2", "chained_from_ids": ["a"], "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "c", "technique": "step3", "chained_from_ids": ["b"], "source_session_ids": ["s1"]})


# --- Unit 5: re-keying ---


def test_update_technique_rekeys_on_tech_change(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    old_key = json.dumps({"tech": ["php"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(old_key, {"id": "t1", "technique": "x", "tech_keywords": ["php"], "waf_vendors": [], "source_session_ids": ["s1"]})

    assert playbook_store.update_technique("t1", {}, tech_keywords=["nginx"], waf_vendors=["cloudflare"]) is True

    store = playbook_store.load_playbook_store()
    assert old_key not in store  # it was the only entry under the old key -> key dropped
    new_key = json.dumps({"tech": ["nginx"], "waf": ["cloudflare"]}, sort_keys=True)
    assert store[new_key][0]["id"] == "t1"
    assert store[new_key][0]["tech_keywords"] == ["nginx"]
    assert store[new_key][0]["waf_vendors"] == ["cloudflare"]


def test_update_technique_no_rekey_when_tech_unchanged(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["php"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "t1", "technique": "x", "tech_keywords": ["php"], "waf_vendors": [], "source_session_ids": ["s1"]})

    playbook_store.update_technique("t1", {"technique": "y"}, tech_keywords=["php"], waf_vendors=[])
    store = playbook_store.load_playbook_store()
    assert list(store.keys()) == [key]  # same key, no move
    assert store[key][0]["technique"] == "y"


# --- Unit 6: full recipe chains ---


def test_get_technique_chains_walks_to_root(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    _build_three_step_chain()
    chains = playbook_store.get_technique_chains(["c"])
    assert [e["technique"] for e in chains["c"]] == ["step1", "step2", "step3"]


def test_list_all_techniques_attaches_recipe_chain(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    _build_three_step_chain()
    items = {i["id"]: i for i in playbook_store.list_all_techniques()}
    assert items["c"]["chain"] == ["step1", "step2", "step3"]
    assert items["a"]["chain"] == []  # a root technique has no recipe


def test_recipe_lines_render_only_the_maximal_chain(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    _build_three_step_chain()
    # Both step2 and step3 are surfaced; step2's chain is a prefix of step3's, so only the full
    # (maximal) recipe should render.
    matches = [{"id": "b", "chained_from_ids": ["a"]}, {"id": "c", "chained_from_ids": ["b"]}]
    lines = core._playbook_recipe_lines(matches)
    assert len(lines) == 1
    assert "step1" in lines[0] and "step2" in lines[0] and "step3" in lines[0]


# --- _finding_fingerprint / _waf_vendors_from_protections ---


def test_waf_vendors_from_protections_parses_vendor_name_out_of_labels():
    session = _session("usr_fp1", recon_result={"protections": {"host1": ["Cloudflare (WAF, nuclei global-waf-detect)", "sucuri (WAF/CDN, whatweb)"]}})
    assert _waf_vendors_from_protections(session) == frozenset({"cloudflare", "sucuri"})


def test_waf_vendors_from_protections_drops_unidentified_waf():
    session = _session("usr_fp2", recon_result={"protections": {"host1": ["Unidentified WAF (nuclei global-waf-detect)"]}})
    assert _waf_vendors_from_protections(session) == frozenset()


def test_finding_fingerprint_uses_technology_keywords_and_waf_vendors():
    session = _session("usr_fp3", recon_result={"protections": {"host1": ["Cloudflare (WAF, nuclei global-waf-detect)"]}})
    finding = _exploited_finding()

    tech_keywords, waf_vendors = _finding_fingerprint(session, finding)

    assert "wordpress" in tech_keywords
    assert waf_vendors == frozenset({"cloudflare"})


def test_playbook_fingerprint_key_is_order_independent():
    key_a = _playbook_fingerprint_key(frozenset({"wordpress", "php"}), frozenset({"cloudflare"}))
    key_b = _playbook_fingerprint_key(frozenset({"php", "wordpress"}), frozenset({"cloudflare"}))
    assert key_a == key_b


# --- _maybe_capture_playbook_entry ---


def test_capture_skipped_when_not_exploited(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_cap1")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    finding = _exploited_finding(exploited=False)

    _maybe_capture_playbook_entry(ctx, finding)

    assert playbook_store.load_playbook_store() == {}
    assert "playbook_touched_keys" not in session


def test_capture_skipped_when_no_evidence(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_cap2")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    finding = _exploited_finding(evidence=None)

    _maybe_capture_playbook_entry(ctx, finding)

    assert playbook_store.load_playbook_store() == {}


def test_capture_skipped_when_playbook_disabled(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setenv("PLAYBOOK_ENABLED", "false")
    session = _session("usr_cap3")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _maybe_capture_playbook_entry(ctx, _exploited_finding())

    assert playbook_store.load_playbook_store() == {}


def test_capture_writes_a_global_entry_and_tracks_touched_key(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_cap4", recon_result={"protections": {"host1": ["Cloudflare (WAF, nuclei global-waf-detect)"]}})
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    monkeypatch.setattr(core, "get_session_folder", lambda session_id: None)  # no local notes for this test

    _maybe_capture_playbook_entry(ctx, _exploited_finding())

    store = playbook_store.load_playbook_store()
    assert len(store) == 1
    entry = list(store.values())[0][0]
    assert "sqli" in entry["technique"].lower()
    assert entry["evidence_ref"]
    assert entry["source_session_ids"] == ["usr_cap4"]
    assert entry["source_type"] == "live"
    assert entry["confidence"] == "confirmed"
    assert session["playbook_touched_keys"] == list(store.keys())


def test_capture_appends_a_local_project_note(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    project_folder = tmp_path / "project"
    project_folder.mkdir()
    monkeypatch.setattr(core, "get_session_folder", lambda session_id: str(project_folder))
    session = _session("usr_cap5")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _maybe_capture_playbook_entry(ctx, _exploited_finding())

    notes = (project_folder / "playbook_notes.md").read_text(encoding="utf-8")
    assert "SQLi in search param" in notes


def test_playbook_notes_path_is_none_without_a_project_folder(monkeypatch):
    monkeypatch.setattr(core, "get_session_folder", lambda session_id: None)
    assert _playbook_notes_path("usr_no_folder") is None


# --- _playbook_task_addendum ---


def test_addendum_empty_when_playbook_disabled(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setenv("PLAYBOOK_ENABLED", "false")
    assert _playbook_task_addendum(_session("usr_add1"), _exploited_finding()) == ""


def test_addendum_empty_when_no_matches(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    assert _playbook_task_addendum(_session("usr_add2"), _exploited_finding()) == ""


def test_addendum_surfaces_a_prior_match_for_a_finding(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": sorted(["wordpress"]), "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a1", "technique": "Known WAF bypass technique", "payload_or_command": "curl ...", "times_confirmed": 4, "last_seen": "t1", "source_session_ids": ["s1"]})

    addendum = _playbook_task_addendum(_session("usr_add3"), _exploited_finding(technology="WordPress 6.0"))

    assert "Known WAF bypass technique" in addendum
    assert "4x" in addendum


def test_addendum_analyze_phase_shape_reads_recon_technologies(tmp_path, monkeypatch):
    """finding=None (the Analyze-phase call shape) sources tech_keywords from
    recon_result["technologies"] instead of a single finding's own technology field."""
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": sorted(["wordpress"]), "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a1", "technique": "Known WAF bypass technique", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})
    session = _session("usr_add4", recon_result={"technologies": {"host1": ["WordPress[6.0]", "PHP[8.1]"]}})

    addendum = _playbook_task_addendum(session, finding=None)

    assert "Known WAF bypass technique" in addendum


# --- _run_playbook_distillation_pass ---


class _FakeLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, response_content):
        self._response_content = response_content

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content=self._response_content)


def test_distillation_noop_when_nothing_captured_this_session(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_dist1")
    ctx = RunContext(llm=_FakeLLM("should never be called"), session=session, session_id=session["session_id"])

    asyncio.run(_run_playbook_distillation_pass(ctx))  # must not raise, must not call the LLM


def test_distillation_tolerates_unparseable_llm_response(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["wordpress"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a1", "technique": "x", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})
    session = _session("usr_dist2", playbook_touched_keys=[key])
    ctx = RunContext(llm=_FakeLLM("not json at all"), session=session, session_id=session["session_id"])

    asyncio.run(_run_playbook_distillation_pass(ctx))

    # Left exactly as-is -- a failed distillation pass must never lose the deterministic entry.
    assert playbook_store.load_playbook_store()[key][0]["technique"] == "x"


def test_distillation_merges_duplicate_entries_under_a_touched_key(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    key = json.dumps({"tech": ["wordpress"], "waf": []}, sort_keys=True)
    playbook_store.record_technique(key, {"id": "a1", "technique": "SQLi via double encoding v1", "times_confirmed": 1, "last_seen": "t1", "source_session_ids": ["s1"]})
    playbook_store.record_technique(key, {"id": "a2", "technique": "SQLi via double encoding v2 (deep dive)", "times_confirmed": 1, "last_seen": "t2", "source_session_ids": ["s2"]})
    store_before = playbook_store.load_playbook_store()
    ids = [e["id"] for e in store_before[key]]
    assert len(ids) == 2

    response = json.dumps({
        "merges": [{"fingerprint_key": key, "keep_id": ids[0], "merge_ids": [ids[1]], "technique": "SQLi bypass via double URL encoding on search param"}],
        "local_notes": None,
    })
    session = _session("usr_dist3", playbook_touched_keys=[key])
    ctx = RunContext(llm=_FakeLLM(response), session=session, session_id=session["session_id"])
    monkeypatch.setattr(core, "get_session_folder", lambda session_id: None)

    asyncio.run(_run_playbook_distillation_pass(ctx))

    entries = playbook_store.load_playbook_store()[key]
    assert len(entries) == 1
    assert entries[0]["technique"] == "SQLi bypass via double URL encoding on search param"
    assert entries[0]["times_confirmed"] == 2
    assert set(entries[0]["source_session_ids"]) == {"s1", "s2"}
