"""Cross-session tool-selection memory: agent/tools/tool_memory_store.py's persistence + agent/
core.py's deterministic dispatch hook (_track_tool_memory), deferred credit
(_credit_tool_memory_for_finding), and lookup/injection (_tool_memory_task_addendum).

Deliberately separate from the playbook (agent/tools/playbook_store.py): the playbook remembers
proven EXPLOITATION TECHNIQUES/payloads; this module remembers which SCAN TOOL actually got
dispatched, and whether it ever led anywhere, against a target with a given tech/WAF fingerprint --
a coarser, tool-selection-level question.
"""
from datetime import datetime, timedelta, timezone

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _credit_tool_memory_for_finding,
    _current_target_fingerprint,
    _playbook_fingerprint_key,
    _tool_memory_task_addendum,
    _track_tool_memory,
)
from agent.tools import tool_memory_store


def _isolate_store(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_memory_store, "TOOL_MEMORY_STORE_PATH", tmp_path / "tool_outcomes.json")


def _session(session_id, **overrides):
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "recon_result": {},
    }
    session.update(overrides)
    return session


# --- tool_memory_store: persistence ---


def test_load_tool_memory_store_returns_empty_dict_when_file_missing(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    assert tool_memory_store.load_tool_memory_store() == {}


def test_load_tool_memory_store_treats_corrupt_json_as_empty(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.TOOL_MEMORY_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tool_memory_store.TOOL_MEMORY_STORE_PATH.write_text("not valid json{{{", encoding="utf-8")
    assert tool_memory_store.load_tool_memory_store() == {}


def test_load_tool_memory_store_drops_malformed_entries(tmp_path, monkeypatch):
    import json
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.TOOL_MEMORY_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tool_memory_store.TOOL_MEMORY_STORE_PATH.write_text(
        json.dumps({"good_key": [{"tool": "nmap"}], "bad_key": "not a list"}), encoding="utf-8",
    )
    assert tool_memory_store.load_tool_memory_store() == {"good_key": [{"tool": "nmap"}]}


# --- record_tool_run ---


def test_record_tool_run_appends_a_new_entry(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.record_tool_run("key1", "nmap_scan", "empty", "usr_s1")

    store = tool_memory_store.load_tool_memory_store()
    assert len(store["key1"]) == 1
    entry = store["key1"][0]
    assert entry["tool"] == "nmap_scan"
    assert entry["outcome"] == "empty"
    assert entry["times_run"] == 1
    assert entry["led_to_finding_count"] == 0
    assert entry["source_session_ids"] == ["usr_s1"]


def test_record_tool_run_bumps_an_existing_entry_for_the_same_tool_instead_of_duplicating(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.record_tool_run("key1", "nmap_scan", "empty", "usr_s1")
    tool_memory_store.record_tool_run("key1", "nmap_scan", "empty", "usr_s2")

    store = tool_memory_store.load_tool_memory_store()
    assert len(store["key1"]) == 1
    assert store["key1"][0]["times_run"] == 2
    assert store["key1"][0]["source_session_ids"] == ["usr_s1", "usr_s2"]


def test_record_tool_run_never_downgrades_an_already_productive_tool(tmp_path, monkeypatch):
    """Non-punitive by design, same philosophy as playbook_store.record_technique's dedup -- a tool
    that has ever been productive here stays "has worked here" even if a later run comes back
    empty/failed."""
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.record_tool_run("key1", "nmap_scan", "empty", "usr_s1")
    tool_memory_store.credit_tool_run("key1", {"nmap_scan"})
    tool_memory_store.record_tool_run("key1", "nmap_scan", "failed", "usr_s2", error="timeout")

    entry = tool_memory_store.load_tool_memory_store()["key1"][0]
    assert entry["outcome"] == "productive"
    assert entry["times_run"] == 2


def test_record_tool_run_rejects_an_invalid_outcome(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    result = tool_memory_store.record_tool_run("key1", "nmap_scan", "bogus", "usr_s1")
    assert result is None
    assert tool_memory_store.load_tool_memory_store() == {}


# --- credit_tool_run ---


def test_credit_tool_run_upgrades_outcome_and_bumps_led_to_finding_count(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.record_tool_run("key1", "nuclei_scan", "empty", "usr_s1")

    tool_memory_store.credit_tool_run("key1", {"nuclei_scan"})

    entry = tool_memory_store.load_tool_memory_store()["key1"][0]
    assert entry["outcome"] == "productive"
    assert entry["led_to_finding_count"] == 1
    assert entry["last_productive_at"] is not None


def test_credit_tool_run_is_a_noop_for_an_unknown_tool_name(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.record_tool_run("key1", "nuclei_scan", "empty", "usr_s1")

    tool_memory_store.credit_tool_run("key1", {"some_other_tool"})

    entry = tool_memory_store.load_tool_memory_store()["key1"][0]
    assert entry["outcome"] == "empty"
    assert entry["led_to_finding_count"] == 0


def test_credit_tool_run_is_a_noop_for_an_unknown_fingerprint_key(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.credit_tool_run("never-seen-key", {"nmap_scan"})
    assert tool_memory_store.load_tool_memory_store() == {}


# --- is_stale ---


def test_is_stale_is_false_for_a_recently_run_productive_entry():
    entry = {"outcome": "productive", "last_run_at": datetime.now(timezone.utc).isoformat()}
    assert tool_memory_store.is_stale(entry) is False


def test_is_stale_is_true_for_an_old_productive_entry(monkeypatch):
    monkeypatch.setenv("TOOL_MEMORY_STALE_DAYS", "1")
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    assert tool_memory_store.is_stale({"outcome": "productive", "last_run_at": old_ts}) is True


def test_is_stale_is_always_false_for_a_non_productive_entry():
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10000)).isoformat()
    assert tool_memory_store.is_stale({"outcome": "empty", "last_run_at": old_ts}) is False


def test_is_stale_is_false_when_disabled_via_zero(monkeypatch):
    monkeypatch.setenv("TOOL_MEMORY_STALE_DAYS", "0")
    old_ts = (datetime.now(timezone.utc) - timedelta(days=10000)).isoformat()
    assert tool_memory_store.is_stale({"outcome": "productive", "last_run_at": old_ts}) is False


# --- find_tool_history ---


def test_find_tool_history_is_empty_for_an_unknown_key(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    assert tool_memory_store.find_tool_history("never-seen-key") == []


def test_find_tool_history_returns_the_exact_stored_entries(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    tool_memory_store.record_tool_run("key1", "nmap_scan", "empty", "usr_s1")
    history = tool_memory_store.find_tool_history("key1")
    assert len(history) == 1
    assert history[0]["tool"] == "nmap_scan"


# --- _current_target_fingerprint ---


def test_current_target_fingerprint_is_empty_for_a_session_with_no_recon_data():
    tech_keywords, waf_vendors = _current_target_fingerprint(_session("usr_x"))
    assert tech_keywords == frozenset()
    assert waf_vendors == frozenset()


def test_current_target_fingerprint_pulls_technology_tokens_from_recon_result():
    session = _session("usr_x", recon_result={"technologies": {"example.com": ["WordPress", "Nginx"]}})
    tech_keywords, _ = _current_target_fingerprint(session)
    assert "wordpress" in tech_keywords
    assert "nginx" in tech_keywords


# --- _track_tool_memory: deterministic dispatch hook ---


def test_track_tool_memory_records_a_successful_scan_tool_dispatch_as_empty(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x", recon_result={"technologies": {"example.com": ["WordPress"]}})
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _track_tool_memory(ctx, {"status": "ok", "tool": "nuclei"})

    fingerprint_key = _playbook_fingerprint_key(*_current_target_fingerprint(session))
    history = tool_memory_store.find_tool_history(fingerprint_key)
    assert len(history) == 1
    assert history[0]["tool"] == "nuclei"
    assert history[0]["outcome"] == "empty"


def test_track_tool_memory_records_a_failed_scan_tool_dispatch_with_the_error(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x", recon_result={"technologies": {"example.com": ["WordPress"]}})
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _track_tool_memory(ctx, {"status": "error", "tool": "nuclei", "error": "connection refused"})

    fingerprint_key = _playbook_fingerprint_key(*_current_target_fingerprint(session))
    entry = tool_memory_store.find_tool_history(fingerprint_key)[0]
    assert entry["outcome"] == "failed"
    assert entry["last_error"] == "connection refused"


def test_track_tool_memory_ignores_a_skipped_status(tmp_path, monkeypatch):
    """A guardrail decision (out-of-scope, dead-host block) is not a real attempt -- same
    discrimination _track_host_health already applies."""
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _track_tool_memory(ctx, {"status": "skipped", "tool": "nuclei", "reason": "out of scope"})

    assert tool_memory_store.load_tool_memory_store() == {}


def test_track_tool_memory_ignores_a_tier_1_native_tool(tmp_path, monkeypatch):
    """Scoped to tool_tier=2 scan-category tools only -- a native (tier-1) helper doesn't answer
    "which scanner is worth reaching for on a similar stack" at all."""
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _track_tool_memory(ctx, {"status": "ok", "tool": "record_finding"})

    assert tool_memory_store.load_tool_memory_store() == {}


def test_track_tool_memory_ignores_an_unknown_tool_name(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _track_tool_memory(ctx, {"status": "ok", "tool": "not_a_real_tool"})

    assert tool_memory_store.load_tool_memory_store() == {}


# --- _credit_tool_memory_for_finding ---


def test_credit_tool_memory_for_finding_credits_every_tool_in_the_findings_timeline(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x", recon_result={"technologies": {"example.com": ["WordPress"]}})
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    fingerprint_key = _playbook_fingerprint_key(*_current_target_fingerprint(session))
    tool_memory_store.record_tool_run(fingerprint_key, "nuclei_scan", "empty", "usr_x")

    finding = {"title": "X", "tool_timeline": [{"tool": "nuclei_scan", "stage": "discovery"}]}
    _credit_tool_memory_for_finding(ctx, finding)

    entry = tool_memory_store.find_tool_history(fingerprint_key)[0]
    assert entry["outcome"] == "productive"
    assert entry["led_to_finding_count"] == 1


def test_credit_tool_memory_for_finding_is_a_noop_with_no_tool_timeline(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    _credit_tool_memory_for_finding(ctx, {"title": "X"})
    assert tool_memory_store.load_tool_memory_store() == {}


# --- _tool_memory_task_addendum ---


def test_tool_memory_task_addendum_is_empty_with_no_stored_history():
    session = _session("usr_x", recon_result={"technologies": {"example.com": ["WordPress"]}})
    assert _tool_memory_task_addendum(session) == ""


def test_tool_memory_task_addendum_is_empty_with_no_technology_signal_at_all():
    session = _session("usr_x")
    assert _tool_memory_task_addendum(session) == ""


def test_tool_memory_task_addendum_lists_productive_and_quiet_tools(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    session = _session("usr_x", recon_result={"technologies": {"example.com": ["WordPress"]}})
    fingerprint_key = _playbook_fingerprint_key(*_current_target_fingerprint(session))
    tool_memory_store.record_tool_run(fingerprint_key, "nuclei_scan", "empty", "usr_prior")
    tool_memory_store.credit_tool_run(fingerprint_key, {"nuclei_scan"})
    tool_memory_store.record_tool_run(fingerprint_key, "nikto_scan", "empty", "usr_prior")

    addendum = _tool_memory_task_addendum(session)

    assert "nuclei_scan" in addendum
    assert "PRODUCED SIGNAL" in addendum
    assert "nikto_scan" in addendum
    assert "empty" in addendum.lower()
    assert "skip" not in addendum.lower()  # calibration only, never an instruction to skip


def test_tool_memory_task_addendum_flags_a_stale_productive_tool(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setenv("TOOL_MEMORY_STALE_DAYS", "1")
    session = _session("usr_x", recon_result={"technologies": {"example.com": ["WordPress"]}})
    fingerprint_key = _playbook_fingerprint_key(*_current_target_fingerprint(session))
    tool_memory_store.record_tool_run(fingerprint_key, "nuclei_scan", "empty", "usr_prior")
    tool_memory_store.credit_tool_run(fingerprint_key, {"nuclei_scan"})
    store = tool_memory_store.load_tool_memory_store()
    store[fingerprint_key][0]["last_run_at"] = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
    tool_memory_store._write_tool_memory_store(store)

    addendum = _tool_memory_task_addendum(session)

    assert "may be outdated" in addendum
