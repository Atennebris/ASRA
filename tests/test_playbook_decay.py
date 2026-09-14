"""Confidence decay + staleness (Unit 3): a proven technique's "how proven" weight fades with time
since it last worked (WAF bypasses get patched), and one not confirmed in a long while gets flagged
'stale — re-verify' both in the manager UI (via list_all_techniques) and in the agent's context
(_playbook_task_addendum). Relevance and exploitability (KEV/EPSS) are NOT decayed."""
from datetime import datetime, timedelta, timezone

from agent.tools import playbook_store


def _iso(days_ago: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _entry(**overrides) -> dict:
    entry = {
        "technique": "double URL encoding bypasses the WAF",
        "outcome": "worked",
        "times_confirmed": 3,
        "source_session_ids": ["a", "b"],
        "last_confirmed_at": _iso(0),
    }
    entry.update(overrides)
    return entry


# --- decay multiplier ---


def test_fresh_technique_has_no_decay(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_DECAY_HALFLIFE_DAYS", "365")
    assert playbook_store._staleness_decay(_entry(last_confirmed_at=_iso(0))) > 0.999


def test_one_halflife_old_technique_decays_to_half(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_DECAY_HALFLIFE_DAYS", "100")
    decay = playbook_store._staleness_decay(_entry(last_confirmed_at=_iso(100)))
    assert abs(decay - 0.5) < 0.02


def test_decay_is_floored_so_ancient_still_beats_untested(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_DECAY_HALFLIFE_DAYS", "30")
    assert playbook_store._staleness_decay(_entry(last_confirmed_at=_iso(3650))) == 0.2


def test_decay_disabled_when_halflife_zero(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_DECAY_HALFLIFE_DAYS", "0")
    assert playbook_store._staleness_decay(_entry(last_confirmed_at=_iso(9999))) == 1.0


def test_missing_timestamp_is_not_penalized():
    entry = _entry()
    entry.pop("last_confirmed_at", None)
    entry.pop("last_seen", None)
    assert playbook_store._staleness_decay(entry) == 1.0


def test_naive_timestamp_is_treated_as_utc(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_DECAY_HALFLIFE_DAYS", "365")
    naive = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None).isoformat()
    # Must not raise on aware/naive subtraction, and stays near-fresh after one day.
    assert 0.99 < playbook_store._staleness_decay(_entry(last_confirmed_at=naive)) <= 1.0


# --- decay actually lowers the relevance score ---


def test_stale_technique_scores_below_identical_fresh_one(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_DECAY_HALFLIFE_DAYS", "100")
    q_tech, q_waf, k_tech, k_waf = {"wordpress"}, set(), {"wordpress"}, set()
    fresh = playbook_store._relevance_score(
        q_tech, q_waf, None, k_tech, k_waf, _entry(last_confirmed_at=_iso(0)))
    old = playbook_store._relevance_score(
        q_tech, q_waf, None, k_tech, k_waf, _entry(last_confirmed_at=_iso(300)))
    assert old < fresh


# --- is_stale flag ---


def test_worked_technique_past_window_is_stale(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_STALE_DAYS", "180")
    assert playbook_store.is_stale(_entry(last_confirmed_at=_iso(200))) is True


def test_recent_worked_technique_is_not_stale(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_STALE_DAYS", "180")
    assert playbook_store.is_stale(_entry(last_confirmed_at=_iso(30))) is False


def test_dead_end_never_goes_stale(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_STALE_DAYS", "180")
    assert playbook_store.is_stale(_entry(outcome="failed", last_confirmed_at=_iso(999))) is False


def test_staleness_disabled_when_window_zero(monkeypatch):
    monkeypatch.setenv("PLAYBOOK_STALE_DAYS", "0")
    assert playbook_store.is_stale(_entry(last_confirmed_at=_iso(999))) is False


def test_list_all_techniques_carries_stale_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "techniques.json")
    monkeypatch.setenv("PLAYBOOK_STALE_DAYS", "180")
    playbook_store.add_manual_technique(
        technique="old bypass", tech_keywords=["nginx"], waf_vendors=["cloudflare"], worked=True,
    )
    store = playbook_store.load_playbook_store()
    for entries in store.values():
        for entry in entries:
            entry["last_confirmed_at"] = _iso(400)
    playbook_store._write_playbook_store(store)
    listed = playbook_store.list_all_techniques()
    assert listed and all(t["stale"] for t in listed)


# --- rank tiers (weak-to-legendary) ---


def test_dead_end_is_never_ranked():
    assert playbook_store.technique_rank(_entry(outcome="failed")) is None


def test_fresh_once_confirmed_technique_is_bronze():
    entry = _entry(times_confirmed=1, source_session_ids=["a"])
    assert playbook_store.technique_rank(entry) == "bronze"


def test_heavily_confirmed_cross_target_technique_reaches_legendary():
    # 10 confirmations across 10 distinct targets with a perfect attributed success rate is the
    # documented "earn Legendary with no threat-intel needed" case (playbook_store's RANK_TIERS
    # comment) -- confirmed fresh (no decay) so it lands at the true max, 3.5, which is >= the
    # legendary threshold.
    entry = _entry(
        times_confirmed=10, source_session_ids=[f"s{i}" for i in range(10)],
        injected_count=10, led_to_finding_count=10,
    )
    assert playbook_store.technique_rank(entry) == "legendary"


def test_kev_boost_can_push_a_modest_technique_up_a_tier():
    base = _entry(times_confirmed=2, source_session_ids=["a"])
    boosted = _entry(times_confirmed=2, source_session_ids=["a"], kev=True)
    base_rank = playbook_store.RANK_ORDER.index(playbook_store.technique_rank(base))
    boosted_rank = playbook_store.RANK_ORDER.index(playbook_store.technique_rank(boosted))
    assert boosted_rank > base_rank


def test_rank_tiers_are_monotonically_non_decreasing_with_confidence():
    # More confirmations/targets should never rank BELOW fewer -- a basic sanity check on the
    # tier-threshold table itself, independent of the exact cutoff values.
    weak = _entry(times_confirmed=1, source_session_ids=["a"])
    strong = _entry(times_confirmed=8, source_session_ids=["a", "b", "c", "d"])
    weak_rank = playbook_store.RANK_ORDER.index(playbook_store.technique_rank(weak))
    strong_rank = playbook_store.RANK_ORDER.index(playbook_store.technique_rank(strong))
    assert strong_rank >= weak_rank


def test_list_all_techniques_carries_rank_and_rank_score(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "techniques.json")
    playbook_store.add_manual_technique(technique="fresh lead", tech_keywords=["nginx"], worked=True)
    playbook_store.add_manual_technique(technique="confirmed dead-end", tech_keywords=["nginx"], worked=False)
    listed = {t["technique"]: t for t in playbook_store.list_all_techniques()}
    assert listed["fresh lead"]["rank"] == "bronze"
    assert isinstance(listed["fresh lead"]["rank_score"], float)
    assert listed["confirmed dead-end"]["rank"] is None
