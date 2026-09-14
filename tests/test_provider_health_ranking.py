"""_provider_model_health_ranking / _cached_provider_health_ranking (agent/core.py) -- the
per-(provider_id, model) cleanliness score that feeds get_next_chain_step's own optional
health_ranking parameter (agent/llm_client.py), so a fallback-chain walk reorders by which pairs
have actually behaved cleanly recently instead of staying fixed at the operator's static Settings
row order. See agent/llm_client.py's own get_next_chain_step tests for the reordering logic
itself; this file covers only how the ranking dict gets built from session summaries.
"""
import agent.core as core


def _summary(llm_usage, phase_efficiency=None, stall_events=None):
    return {
        "llm_usage": llm_usage,
        "phase_efficiency": phase_efficiency or {},
        "stall_events": stall_events or [],
    }


def _usage_entry(provider_id, model, calls=10):
    return {
        "provider_id": provider_id, "model": model, "calls": calls,
        "total_latency_seconds": calls * 2.0, "prompt_tokens": 100, "completion_tokens": 50,
        "calls_with_usage": calls,
    }


def test_ranking_averages_the_score_across_every_session_for_the_same_pair(monkeypatch):
    summaries = [
        _summary([_usage_entry("qwen", "qwen-plus")], phase_efficiency={"recon": {"tool_calls": 10, "non_ok": 0, "retried": 0, "duplicates": 0}}),
        _summary([_usage_entry("qwen", "qwen-plus")], phase_efficiency={"recon": {"tool_calls": 10, "non_ok": 10, "retried": 0, "duplicates": 0}}),
    ]
    monkeypatch.setattr(core, "list_session_summaries", lambda: summaries)

    ranking = core._provider_model_health_ranking()

    # First session: 0% failure -> score 100. Second: 100% failure -> a large negative penalty.
    # The averaged score must sit strictly between the two individual extremes.
    assert ("qwen", "qwen-plus") in ranking
    assert -100 < ranking[("qwen", "qwen-plus")] < 100


def test_ranking_excludes_sessions_with_no_real_tool_calls(monkeypatch):
    summaries = [_summary([_usage_entry("qwen", "qwen-plus")], phase_efficiency={})]  # has_data=False
    monkeypatch.setattr(core, "list_session_summaries", lambda: summaries)

    ranking = core._provider_model_health_ranking()

    assert ranking == {}


def test_ranking_ignores_sessions_with_no_llm_usage_at_all(monkeypatch):
    monkeypatch.setattr(core, "list_session_summaries", lambda: [_summary([])])

    assert core._provider_model_health_ranking() == {}


def test_ranking_attributes_a_session_to_its_dominant_pair_only(monkeypatch):
    """Same attribution rule compute_provider_leaderboard already uses -- a session that fell back
    mid-run is attributed to whichever (provider, model) made the MOST calls, not split."""
    summary = _summary(
        [_usage_entry("qwen", "qwen-plus", calls=2), _usage_entry("mistral", "mistral-small-latest", calls=8)],
        phase_efficiency={"recon": {"tool_calls": 10, "non_ok": 0, "retried": 0, "duplicates": 0}},
    )
    monkeypatch.setattr(core, "list_session_summaries", lambda: [summary])

    ranking = core._provider_model_health_ranking()

    assert ("mistral", "mistral-small-latest") in ranking
    assert ("qwen", "qwen-plus") not in ranking


def test_cached_ranking_reuses_the_result_within_the_ttl(monkeypatch):
    calls = {"count": 0}

    def fake_ranking():
        calls["count"] += 1
        return {("qwen", "qwen-plus"): 42.0}

    monkeypatch.setattr(core, "_provider_model_health_ranking", fake_ranking)
    monkeypatch.setattr(core, "_provider_health_ranking_cache", None)

    first = core._cached_provider_health_ranking()
    second = core._cached_provider_health_ranking()

    assert first == second == {("qwen", "qwen-plus"): 42.0}
    assert calls["count"] == 1  # second call served from cache, not recomputed


def test_cached_ranking_recomputes_once_the_ttl_expires(monkeypatch):
    calls = {"count": 0}

    def fake_ranking():
        calls["count"] += 1
        return {}

    monkeypatch.setattr(core, "_provider_model_health_ranking", fake_ranking)
    # Seed a stale cache entry (timestamp far in the past) rather than sleeping in a test.
    monkeypatch.setattr(core, "_provider_health_ranking_cache", (0.0, {}))

    core._cached_provider_health_ranking()

    assert calls["count"] == 1
