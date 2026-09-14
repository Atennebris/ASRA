"""compute_portfolio_summary (agent/core.py) and the /dashboard route (main.py) -- pure
aggregation of list_session_summaries() data, grouped by target/program, plus a smoke test that
the standalone page actually renders. See tests/test_provider_health_ranking.py for the sibling
per-(provider, model) aggregation this reuses the same summary shape from.
"""
from fastapi.testclient import TestClient

import agent.core as core
import main


def _summary(target, findings_count=0, llm_usage=None, phase_efficiency=None, stall_events=None):
    return {
        "target": target,
        "findings_count": findings_count,
        "llm_usage": llm_usage or [],
        "phase_efficiency": phase_efficiency or {},
        "stall_events": stall_events or [],
    }


def _usage_entry(provider_id="opencode-zen", model="big-pickle", calls=10):
    return {
        "provider_id": provider_id, "model": model, "calls": calls,
        "total_latency_seconds": calls * 2.0, "prompt_tokens": 100, "completion_tokens": 50,
        "calls_with_usage": calls,
    }


def test_portfolio_summary_groups_by_target(monkeypatch):
    summaries = [
        _summary("example.com", findings_count=2),
        _summary("example.com", findings_count=1),
        _summary("other.com", findings_count=5),
    ]
    monkeypatch.setattr(core, "list_session_summaries", lambda: summaries)

    portfolio = core.compute_portfolio_summary()

    assert portfolio["total_sessions"] == 3
    assert portfolio["total_findings"] == 8
    by_target = {p["target"]: p for p in portfolio["programs"]}
    assert by_target["example.com"]["sessions_count"] == 2
    assert by_target["example.com"]["findings_count"] == 3
    assert by_target["other.com"]["findings_count"] == 5


def test_portfolio_summary_sorts_programs_by_findings_descending(monkeypatch):
    summaries = [_summary("low.com", findings_count=1), _summary("high.com", findings_count=9)]
    monkeypatch.setattr(core, "list_session_summaries", lambda: summaries)

    portfolio = core.compute_portfolio_summary()

    assert [p["target"] for p in portfolio["programs"]] == ["high.com", "low.com"]


def test_portfolio_summary_cost_is_none_without_pricing_data(monkeypatch):
    monkeypatch.setattr(core, "list_session_summaries", lambda: [_summary("example.com")])

    portfolio = core.compute_portfolio_summary()

    assert portfolio["total_estimated_cost_usd"] is None
    assert portfolio["programs"][0]["cost_usd"] is None


def test_portfolio_summary_empty_portfolio(monkeypatch):
    monkeypatch.setattr(core, "list_session_summaries", lambda: [])

    portfolio = core.compute_portfolio_summary()

    assert portfolio == {"total_sessions": 0, "total_findings": 0, "total_estimated_cost_usd": None, "programs": []}


def test_dashboard_route_renders_with_no_sessions(monkeypatch):
    monkeypatch.setattr(core, "list_session_summaries", lambda: [])
    client = TestClient(main.app)

    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert "Dashboard" in resp.text


def test_dashboard_route_renders_with_real_data(monkeypatch):
    summaries = [
        _summary("example.com", findings_count=2, llm_usage=[_usage_entry()], phase_efficiency={"recon": {"tool_calls": 5, "non_ok": 0, "retried": 0, "duplicates": 0}}),
    ]
    monkeypatch.setattr(core, "list_session_summaries", lambda: summaries)
    client = TestClient(main.app)

    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert "example.com" in resp.text


def test_dashboard_program_row_links_to_the_program_drilldown(monkeypatch):
    monkeypatch.setattr(core, "list_session_summaries", lambda: [_summary("example.com", findings_count=2)])
    client = TestClient(main.app)

    resp = client.get("/dashboard")

    assert resp.status_code == 200
    assert "/program?target=example.com" in resp.text
