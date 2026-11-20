"""agent/tools/tool_affinity_store.py -- focused unit coverage for the item-5/6 additions
(tool-selection roadmap): the public shape_bucket() facet and run_maintenance_pass()'s prune/
consolidate behavior. The store's already-shipped item-1/2/7 machinery (record_outcome,
score_record, recommended_tools_for, operator feedback) is exercised here only as much as these
new pieces need as fixtures -- it's otherwise covered indirectly via tests/test_update_plan.py's
own _apply_plan_recommendations wiring tests.
"""
from datetime import datetime, timedelta, timezone

import pytest

from agent.tools import tool_affinity_store as store


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "TOOL_AFFINITY_STORE_PATH", tmp_path / "tool_affinity.json")
    monkeypatch.delenv("TOOL_AFFINITY_ENABLED", raising=False)
    monkeypatch.delenv("TOOL_AFFINITY_MIN_ATTEMPTS", raising=False)
    monkeypatch.delenv("TOOL_AFFINITY_DECAY_DAYS", raising=False)
    monkeypatch.delenv("TOOL_AFFINITY_NEGATIVE_WEIGHT", raising=False)
    monkeypatch.delenv("TOOL_AFFINITY_PRUNE_SCORE_THRESHOLD", raising=False)
    monkeypatch.delenv("TOOL_AFFINITY_PRUNE_STALE_DAYS", raising=False)
    monkeypatch.delenv("TOOL_AFFINITY_CONSOLIDATE_SCORE_THRESHOLD", raising=False)


def _make_record(tool="nmap", target_shape="web", phase="recon", attempts=0, successes=0,
                  null_results=0, failures=0, age_days=0.0, operator_feedback=None, consolidated=False):
    last_updated = (datetime.now(timezone.utc) - timedelta(days=age_days)).isoformat()
    record = {
        "id": f"{tool}-{target_shape}-{phase}",
        "tool": tool,
        "target_shape": target_shape,
        "phase": phase,
        "attempts": attempts,
        "successes": successes,
        "null_results": null_results,
        "failures": failures,
        "last_updated": last_updated,
        "source_session_ids": [],
        "operator_feedback": operator_feedback,
        "operator_feedback_at": None,
    }
    if consolidated:
        record["consolidated"] = True
    return record


def _seed(records: dict[str, dict]) -> None:
    store._write_tool_affinity_store(records)


# --- shape_bucket (item 5 -- promoted to public so tool_retrieval_store can reuse it) ---


def test_shape_bucket_classifies_binary_web_and_unknown():
    assert store.shape_bucket("pe_x86_64") == "binary"
    assert store.shape_bucket("elf") == "binary"
    assert store.shape_bucket("jvm_bytecode") == "binary"
    assert store.shape_bucket("web") == "web"
    assert store.shape_bucket("") == "unknown"
    assert store.shape_bucket("unknown") == "unknown"


def test_cold_start_tools_still_works_through_the_renamed_public_shape_bucket():
    # cold_start_tools calls shape_bucket() internally -- confirms the rename didn't break the one
    # existing caller.
    assert store.cold_start_tools("pe_x86_64", "recon") == store._COLD_START_PRIORS[("binary", "recon")]
    assert store.cold_start_tools("web", "exploit") == store._COLD_START_PRIORS[("web", "exploit")]


# --- new env knobs (item 6) ---


def test_maintenance_env_knobs_have_defaults_and_are_overridable(monkeypatch):
    assert store._prune_score_threshold() == 0.05
    assert store._prune_stale_days() == 365.0
    assert store._consolidate_score_threshold() == 0.75
    monkeypatch.setenv("TOOL_AFFINITY_PRUNE_SCORE_THRESHOLD", "0.1")
    monkeypatch.setenv("TOOL_AFFINITY_PRUNE_STALE_DAYS", "30")
    monkeypatch.setenv("TOOL_AFFINITY_CONSOLIDATE_SCORE_THRESHOLD", "0.9")
    assert store._prune_score_threshold() == 0.1
    assert store._prune_stale_days() == 30.0
    assert store._consolidate_score_threshold() == 0.9


# --- run_maintenance_pass (item 6) ---


def test_maintenance_pass_prunes_a_degrading_and_stale_record():
    _seed({
        "k1": _make_record(tool="bad_tool", attempts=10, successes=0, null_results=0, failures=10, age_days=500),
    })
    result = store.run_maintenance_pass()
    assert result == {"pruned": 1, "consolidated": 0}
    assert store.load_tool_affinity_store() == {}


def test_maintenance_pass_leaves_a_degrading_but_fresh_record_alone():
    # Low score but recently updated -- not "long past any plausible comeback" yet, decay-on-read
    # already handles the fresh case; the pass must not double-dip.
    _seed({
        "k1": _make_record(tool="bad_tool", attempts=10, successes=0, null_results=0, failures=10, age_days=1),
    })
    result = store.run_maintenance_pass()
    assert result == {"pruned": 0, "consolidated": 0}
    assert "k1" in store.load_tool_affinity_store()


def test_maintenance_pass_consolidates_a_consistently_strong_record():
    _seed({
        "k1": _make_record(tool="great_tool", attempts=20, successes=18, null_results=2, failures=0, age_days=1),
    })
    result = store.run_maintenance_pass()
    assert result == {"pruned": 0, "consolidated": 1}
    record = store.load_tool_affinity_store()["k1"]
    assert record["consolidated"] is True
    assert record.get("consolidated_at")
    # explain_record surfaces the consolidation as an auditable, non-invented citation.
    assert store.explain_record(record).startswith("confirmed stable — ")


def test_maintenance_pass_is_idempotent_for_an_already_consolidated_record():
    _seed({
        "k1": _make_record(tool="great_tool", attempts=20, successes=18, null_results=2, failures=0,
                            age_days=1, consolidated=True),
    })
    result = store.run_maintenance_pass()
    # Already consolidated -- not re-counted as a fresh consolidation this pass.
    assert result == {"pruned": 0, "consolidated": 0}


@pytest.mark.parametrize("feedback", ["trusted", "irrelevant"])
def test_maintenance_pass_never_touches_an_operator_marked_record(feedback):
    # Real, confirmed bug this guards against: pruning an "irrelevant"-marked record would delete
    # the very row recommended_tools_for's operator_excluded set depends on existing, silently
    # undoing item 2's own fix. A "trusted" record must never be pruned for being stale either.
    _seed({
        "k1": _make_record(tool="marked_tool", attempts=10, successes=0, null_results=0, failures=10,
                            age_days=900, operator_feedback=feedback),
    })
    result = store.run_maintenance_pass()
    assert result == {"pruned": 0, "consolidated": 0}
    assert "k1" in store.load_tool_affinity_store()


def test_maintenance_pass_skips_records_below_min_attempts(monkeypatch):
    monkeypatch.setenv("TOOL_AFFINITY_MIN_ATTEMPTS", "4")
    _seed({
        "k1": _make_record(tool="thin_sample", attempts=1, successes=0, null_results=0, failures=1, age_days=900),
    })
    result = store.run_maintenance_pass()
    assert result == {"pruned": 0, "consolidated": 0}
    assert "k1" in store.load_tool_affinity_store()


def test_maintenance_pass_noop_on_empty_or_disabled_store(monkeypatch):
    assert store.run_maintenance_pass() == {"pruned": 0, "consolidated": 0}
    _seed({"k1": _make_record(attempts=10, successes=0, failures=10, age_days=900)})
    monkeypatch.setenv("TOOL_AFFINITY_ENABLED", "false")
    result = store.run_maintenance_pass()
    assert result == {"pruned": 0, "consolidated": 0}
    # Disabled -- the record from the seeded store above must be left untouched, not pruned.
    assert "k1" in store.load_tool_affinity_store()
