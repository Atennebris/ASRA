"""agent/tools/toolkit_intruder.py -- position parsing/rendering (pure functions), sniper/
pitchfork attempt-building, and the real send-and-record loop (via httpx.MockTransport, same
convention as tests/test_toolkit_repeater.py -- run_attack calls toolkit_repeater.send_raw_request
per attempt, so the underlying HTTP client is mocked the same way, not toolkit_intruder's own).
"""
import asyncio

import httpx
import pytest

from agent.tools import toolkit_intruder, toolkit_store

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


# --- count_positions / render_request (pure) -----------------------------------------------


def test_count_positions_counts_across_all_three_fields():
    assert toolkit_intruder.count_positions("https://x/§a§", "H: §b§", "body §c§ §d§") == 4


def test_count_positions_zero_when_no_markers():
    assert toolkit_intruder.count_positions("https://x/plain", "H: v", "body") == 0


def test_render_request_substitutes_in_url_header_then_body_order():
    url, headers, body = toolkit_intruder.render_request("https://x/§1§", "Cookie: §2§", "id=§3§", ["A", "B", "C"])
    assert url == "https://x/A"
    assert headers == "Cookie: B"
    assert body == "id=C"


def test_render_request_leaves_marker_baseline_when_substitution_list_is_short():
    url, _, _ = toolkit_intruder.render_request("https://x/§1§/§2§", "", "", ["A"])
    assert url == "https://x/A/2"


# --- parse_payload_lines / build_attempts (pure) ------------------------------------------


def test_parse_payload_lines_sniper_attacks_each_position_with_the_full_set():
    result = toolkit_intruder.parse_payload_lines("sniper", 2, "A\nB")
    assert result["status"] == "ok"
    assert result["attempts"] == [["A", ""], ["B", ""], ["", "A"], ["", "B"]]


def test_parse_payload_lines_sniper_ignores_blank_lines():
    result = toolkit_intruder.parse_payload_lines("sniper", 1, "A\n\nB\n")
    assert result["attempts"] == [["A"], ["B"]]


def test_parse_payload_lines_pitchfork_needs_matching_column_count_per_line():
    result = toolkit_intruder.parse_payload_lines("pitchfork", 2, "alice\tpass1\nbob\tpass2")
    assert result["status"] == "ok"
    assert result["attempts"] == [["alice", "pass1"], ["bob", "pass2"]]


def test_parse_payload_lines_pitchfork_rejects_a_mismatched_line_by_number():
    result = toolkit_intruder.parse_payload_lines("pitchfork", 2, "alice\tpass1\nbob")
    assert result["status"] == "error"
    assert "line 2" in result["error"]


def test_parse_payload_lines_no_payloads_is_an_error():
    result = toolkit_intruder.parse_payload_lines("sniper", 1, "   \n\n")
    assert result["status"] == "error"


def test_parse_payload_lines_no_positions_is_an_error():
    result = toolkit_intruder.parse_payload_lines("sniper", 0, "A\nB")
    assert result["status"] == "error"
    assert "position" in result["error"]


def test_build_attempts_enforces_the_max_attempts_cap(monkeypatch):
    monkeypatch.setenv("INTRUDER_MAX_ATTEMPTS", "3")
    result = toolkit_intruder.build_attempts("sniper", 1, "A\nB\nC\nD")
    assert result["status"] == "error"
    assert "safety cap" in result["error"]


def test_build_attempts_within_the_cap_succeeds(monkeypatch):
    monkeypatch.setenv("INTRUDER_MAX_ATTEMPTS", "10")
    result = toolkit_intruder.build_attempts("sniper", 1, "A\nB\nC")
    assert result["status"] == "ok"
    assert len(result["attempts"]) == 3


# --- run_attack: real send-and-record loop, mocked HTTP --------------------------------------


def test_run_attack_sniper_fires_one_request_per_payload_per_position(monkeypatch):
    seen_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_intruder.run_attack(
        session_id="sess_1", method="GET", url="https://example.com/user/§1§", headers_text="", body="",
        mode="sniper", payload_text="A\nB",
    ))

    assert result["status"] == "ok"
    assert result["attempts"] == 2
    assert result["ok"] == 2
    assert sorted(seen_urls) == ["https://example.com/user/A", "https://example.com/user/B"]


def test_run_attack_records_every_attempt_with_source_intruder_and_run_id(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_intruder.run_attack(
        session_id="sess_1", method="GET", url="https://example.com/§1§", headers_text="", body="",
        mode="sniper", payload_text="A\nB\nC",
    ))

    entries = toolkit_store.load_traffic_entries("sess_1")
    assert len(entries) == 3
    assert all(e["source"] == "intruder" for e in entries)
    assert all(e["intruder_run_id"] == result["run_id"] for e in entries)
    assert sorted(e["intruder_payload_values"][0] for e in entries) == ["A", "B", "C"]
    assert all(e["duration_ms"] is not None for e in entries)


def test_run_attack_pitchfork_substitutes_every_position_together(monkeypatch):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((str(request.url), request.headers.get("x-secret")))
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_intruder.run_attack(
        session_id="sess_1", method="GET", url="https://example.com/§1§", headers_text="X-Secret: §2§", body="",
        mode="pitchfork", payload_text="alice\tsecretA\nbob\tsecretB",
    ))

    assert result["status"] == "ok"
    assert result["attempts"] == 2
    assert sorted(seen) == [("https://example.com/alice", "secretA"), ("https://example.com/bob", "secretB")]


def test_run_attack_invalid_template_never_sends_anything(monkeypatch):
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_intruder.run_attack(
        session_id="sess_1", method="GET", url="https://example.com/no-positions", headers_text="", body="",
        mode="sniper", payload_text="A",
    ))

    assert result["status"] == "error"
    assert called["count"] == 0
    assert toolkit_store.load_traffic_entries("sess_1") == []


def test_run_attack_counts_connection_failures_as_errors_not_a_crash(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_intruder.run_attack(
        session_id="sess_1", method="GET", url="https://example.com/§1§", headers_text="", body="",
        mode="sniper", payload_text="A\nB",
    ))

    assert result["status"] == "ok"
    assert result["ok"] == 0
    assert result["errors"] == 2


def test_run_attack_respects_a_custom_run_id(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_intruder.run_attack(
        session_id="sess_1", method="GET", url="https://example.com/§1§", headers_text="", body="",
        mode="sniper", payload_text="A", run_id="fixed-run-id",
    ))
    assert result["run_id"] == "fixed-run-id"


# --- start_attack_in_background / attack_status ------------------------------------------------


def test_start_attack_in_background_returns_running_then_done(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    async def _scenario():
        started = toolkit_intruder.start_attack_in_background(
            session_id="sess_1", method="GET", url="https://example.com/§1§", headers_text="", body="",
            mode="sniper", payload_text="A\nB",
        )
        assert started["status"] == "ok"
        assert started["expected"] == 2
        # Give the background task a chance to actually finish before checking "done".
        task = toolkit_intruder._RUNNING_ATTACKS[started["run_id"]]
        await task
        assert toolkit_intruder.attack_status(started["run_id"]) == "done"
        return started

    _run(_scenario())
    entries = toolkit_store.load_traffic_entries("sess_1")
    assert len(entries) == 2


def test_start_attack_in_background_invalid_template_returns_error_and_starts_nothing():
    started = toolkit_intruder.start_attack_in_background(
        session_id="sess_1", method="GET", url="https://example.com/no-positions", headers_text="", body="",
        mode="sniper", payload_text="A",
    )
    assert started["status"] == "error"
    assert toolkit_store.load_traffic_entries("sess_1") == []


def test_attack_status_unknown_run_id_is_done():
    assert toolkit_intruder.attack_status("never-existed") == "done"
