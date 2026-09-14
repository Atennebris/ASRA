"""agent/tools/toolkit_sequencer.py -- extract_value, analyze_samples (pure functions), and both
sample-collection paths: collect_stored_samples (reads toolkit_store directly) and
collect_live_samples (fires real requests via toolkit_repeater.send_raw_request, mocked HTTP, same
httpx.MockTransport convention as tests/test_toolkit_repeater.py / test_toolkit_intruder.py).
"""
import asyncio
import secrets

import httpx
import pytest

from agent.tools import toolkit_sequencer, toolkit_store

_RealAsyncHTTPXClient = httpx.AsyncClient


def _mock_httpx_async_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealAsyncHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))


def _run(coro):
    return asyncio.run(coro)


def _seed_entry(session_id, **overrides):
    entry = toolkit_store.build_traffic_entry(
        session_id=session_id, method="GET", url="https://example.com/",
        request_headers={}, request_body="",
        response_status=200, response_headers={"X-Token": "abc"}, response_body="",
    )
    entry.update(overrides)
    toolkit_store.append_traffic_entry(entry)
    return entry


# --- extract_value ---------------------------------------------------------------------------


def test_extract_value_plain_header_case_insensitive():
    assert toolkit_sequencer.extract_value({"X-CSRF-Token": "tok123"}, "x-csrf-token") == "tok123"


def test_extract_value_cookie_prefix_pulls_one_cookie_out_of_set_cookie():
    headers = {"Set-Cookie": "session=xyz789; Path=/; HttpOnly"}
    assert toolkit_sequencer.extract_value(headers, "cookie:session") == "xyz789"


def test_extract_value_cookie_prefix_missing_cookie_returns_none():
    headers = {"Set-Cookie": "other=val; Path=/"}
    assert toolkit_sequencer.extract_value(headers, "cookie:session") is None


def test_extract_value_missing_header_returns_none():
    assert toolkit_sequencer.extract_value({"X-Token": "abc"}, "X-Missing") is None


# --- analyze_samples ---------------------------------------------------------------------------


def test_analyze_samples_flags_exact_duplicates_as_weak():
    result = toolkit_sequencer.analyze_samples(["abc123", "abc123", "def456"])
    assert result["status"] == "ok"
    assert result["duplicate_count"] == 1
    assert "weak" in result["verdict"]


def test_analyze_samples_sequential_tokens_score_low_entropy():
    samples = [f"sess{i:04d}" for i in range(20)]
    result = toolkit_sequencer.analyze_samples(samples)
    assert result["status"] == "ok"
    assert result["duplicate_count"] == 0
    assert result["total_entropy_estimate_bits"] < 32
    assert "weak" in result["verdict"]


def test_analyze_samples_real_random_tokens_score_high_entropy():
    samples = [secrets.token_hex(16) for _ in range(20)]
    result = toolkit_sequencer.analyze_samples(samples)
    assert result["status"] == "ok"
    assert result["total_entropy_estimate_bits"] > 64
    assert "strong" in result["verdict"]


def test_analyze_samples_too_few_samples_is_an_error():
    result = toolkit_sequencer.analyze_samples(["only-one"])
    assert result["status"] == "error"


def test_analyze_samples_ignores_blank_samples():
    result = toolkit_sequencer.analyze_samples(["abc", "", "def", None])
    assert result["status"] == "ok"
    assert result["sample_count"] == 2


def test_analyze_samples_compares_positions_only_up_to_shortest_length():
    result = toolkit_sequencer.analyze_samples(["abcde", "abc"])
    assert result["status"] == "ok"
    assert result["min_length"] == 3
    assert result["max_length"] == 5
    assert result["length_varies"] is True
    assert len(result["position_entropies"]) == 3


# --- collect_stored_samples ----------------------------------------------------------------


def test_collect_stored_samples_extracts_from_every_matching_entry():
    _seed_entry("sess_1", response_headers={"X-Token": "one"})
    _seed_entry("sess_1", response_headers={"X-Token": "two"})
    _seed_entry("sess_1", response_headers={"Other": "x"})  # no X-Token -- silently skipped

    samples = toolkit_sequencer.collect_stored_samples("sess_1", "X-Token")
    assert sorted(samples) == ["one", "two"]


def test_collect_stored_samples_empty_session_returns_empty_list():
    assert toolkit_sequencer.collect_stored_samples("sess_empty", "X-Token") == []


def test_collect_stored_samples_preserves_newest_first_order(monkeypatch):
    """Real fix this covers (a real HackerOne rescan session, ~136MB traffic.jsonl after 18h of
    proxy/repeater activity): this used to be list(reversed(load_traffic_entries(...)))[:limit] --
    a full-file parse AND a full-list reverse just to keep the newest `limit` entries. Switched to
    load_recent_traffic_entries (tail-read, doesn't parse the rest of the file) -- must still
    return samples in the exact same newest-first order as before."""
    _seed_entry("sess_order", response_headers={"X-Token": "oldest"})
    _seed_entry("sess_order", response_headers={"X-Token": "middle"})
    _seed_entry("sess_order", response_headers={"X-Token": "newest"})

    samples = toolkit_sequencer.collect_stored_samples("sess_order", "X-Token")
    assert samples == ["newest", "middle", "oldest"]


def test_collect_stored_samples_respects_limit_keeping_only_the_newest(monkeypatch):
    for i in range(5):
        _seed_entry("sess_limit", response_headers={"X-Token": f"tok{i}"})

    samples = toolkit_sequencer.collect_stored_samples("sess_limit", "X-Token", limit=2)
    assert samples == ["tok4", "tok3"]


# --- collect_live_samples: real send-and-record loop, mocked HTTP ---------------------------


def test_collect_live_samples_fires_the_requested_count_and_extracts_the_header(monkeypatch):
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        return httpx.Response(200, headers={"X-Token": f"tok{counter['n']}"}, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_sequencer.collect_live_samples(
        session_id="sess_1", method="GET", url="https://example.com/token", headers_text="", body="",
        header_name="X-Token", count=5,
    ))

    assert result["status"] == "ok"
    assert result["requested"] == 5
    assert result["collected"] == 5
    assert len(set(result["samples"])) == 5  # each response got a distinct token in this test


def test_collect_live_samples_records_each_attempt_as_repeater_sourced(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"X-Token": "tok"}, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    _run(toolkit_sequencer.collect_live_samples(
        session_id="sess_1", method="GET", url="https://example.com/token", headers_text="", body="",
        header_name="X-Token", count=3,
    ))

    entries = toolkit_store.load_traffic_entries("sess_1")
    assert len(entries) == 3
    assert all(e["source"] == "repeater" for e in entries)


def test_collect_live_samples_skips_responses_missing_the_header(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")  # no X-Token at all

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_sequencer.collect_live_samples(
        session_id="sess_1", method="GET", url="https://example.com/token", headers_text="", body="",
        header_name="X-Token", count=3,
    ))
    assert result["collected"] == 0


def test_collect_live_samples_caps_count_to_the_max(monkeypatch):
    # Not actually firing 10000 requests -- caps before dispatch, verified via the "requested"
    # field; the send itself is stubbed so a mis-set cap would still run fast, not hang the test.
    async def fake_send(**kwargs):
        return {"status": "error", "error": "unused"}

    monkeypatch.setattr(toolkit_sequencer, "send_raw_request", fake_send)

    result = _run(toolkit_sequencer.collect_live_samples(
        session_id="sess_1", method="GET", url="https://example.com/token", headers_text="", body="",
        header_name="X-Token", count=10_000,
    ))
    assert result["requested"] <= toolkit_sequencer._MAX_LIVE_SAMPLES
