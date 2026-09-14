"""graphql_batching_probe: builds ONE GraphQL request with several ALIASED copies of the same
query/mutation field call and fires it as a SINGLE HTTP request -- real evidence for whether a
per-request rate limiter (login, coupon redemption, OTP) can be bypassed by batching operations
into one call instead of sending them as separate requests. count is capped at _MAX_BATCH_COUNT,
mirroring EXPLOIT_PROMPT's own existing DoS-safety limit for concurrent-request race tests.
"""
import httpx

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import native
from agent.tools.registry import get_tool, get_tools_by_category

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


# --- _graphql_arg_literal: pure-function cases ---


def test_arg_literal_quotes_and_escapes_strings():
    assert native._graphql_arg_literal("admin") == '"admin"'
    assert native._graphql_arg_literal('say "hi"') == '"say \\"hi\\""'


def test_arg_literal_leaves_numbers_and_booleans_bare():
    assert native._graphql_arg_literal(5) == "5"
    assert native._graphql_arg_literal(3.14) == "3.14"
    assert native._graphql_arg_literal(True) == "true"
    assert native._graphql_arg_literal(False) == "false"


def test_arg_literal_none_is_null():
    assert native._graphql_arg_literal(None) == "null"


# --- graphql_batching_probe: registration ---


def test_is_registered_as_an_exploit_tier_tool():
    spec = get_tool("graphql_batching_probe")
    assert spec.requires_allowed_target is True
    assert spec.allows_repeated_attempts is True
    assert "graphql_batching_probe" in {s.name for s in get_tools_by_category("exploit")}
    assert "graphql_batching_probe" in {s.name for s in get_tools_by_category("scan")}


# --- graphql_batching_probe: orchestration ---


def test_builds_the_correct_n_aliased_query_and_fires_exactly_one_request(monkeypatch):
    requests_made = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_made.append(request)
        return httpx.Response(200, json={"data": {f"a{i}": {"token": "x"} for i in range(3)}})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.graphql_batching_probe({
        "target": "https://api.example.com/graphql", "operation_type": "mutation",
        "field_name": "login", "arguments": {"username": "admin", "password": "pw1"},
        "selection": "token", "count": 3,
    })

    assert result["status"] == "ok"
    assert len(requests_made) == 1  # exactly one HTTP request regardless of count
    assert result["query_sent"].startswith("mutation { a0: login(")
    assert 'username: "admin"' in result["query_sent"]
    assert result["query_sent"].count("login(") == 3
    assert result["total_count"] == 3
    assert result["succeeded_count"] == 3


def test_count_is_clamped_to_the_max_batch_count(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {f"a{i}": {"ok": True} for i in range(native._MAX_BATCH_COUNT)}})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.graphql_batching_probe({
        "target": "https://api.example.com/graphql", "field_name": "redeemCoupon",
        "arguments": {"code": "SAVE20"}, "count": 999,
    })

    assert result["total_count"] == native._MAX_BATCH_COUNT
    assert result["query_sent"].count("redeemCoupon(") == native._MAX_BATCH_COUNT


def test_parses_a_mixed_response_of_successes_and_per_alias_errors(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "data": {"a0": {"token": "x"}, "a1": None, "a2": {"token": "y"}},
            "errors": [{"message": "rate limited", "path": ["a1"]}],
        })

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.graphql_batching_probe({
        "target": "https://api.example.com/graphql", "field_name": "login",
        "arguments": {"username": "admin", "password": "pw1"}, "count": 3,
    })

    assert result["succeeded_count"] == 2
    assert result["per_alias"]["a0"]["succeeded"] is True
    assert result["per_alias"]["a1"]["succeeded"] is False
    assert result["per_alias"]["a1"]["errors"] == ["rate limited"]
    assert result["per_alias"]["a2"]["succeeded"] is True
    assert result["top_level_errors_present"] is True


def test_rejects_an_invalid_operation_type():
    result = native.graphql_batching_probe({"target": "https://api.example.com/graphql", "field_name": "x", "operation_type": "subscription"})
    assert result["status"] == "error"
    assert "operation_type" in result["error"]


def test_a_network_error_is_reported_not_swallowed(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))
    result = native.graphql_batching_probe({"target": "https://api.example.com/graphql", "field_name": "login"})

    assert result["status"] == "error"
