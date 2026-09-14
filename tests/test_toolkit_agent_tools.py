"""agent/tools/toolkit_agent_tools.py -- the native_function bridges between the agent
tool-calling convention and the native toolkit's own engines. send_raw_request/run_attack's real
HTTP dispatch is mocked via httpx.MockTransport, same convention as tests/test_toolkit_repeater.py/
test_toolkit_intruder.py (whose own suites already cover the underlying engines in full -- these
tests are about the BRIDGE's own argument mapping/response shaping, not re-testing those engines).
"""
import socket
import threading

import httpx
import pytest

from agent.tools import toolkit_agent_tools, toolkit_store
from agent.tools.toolkit_agent_tools import (
    _decode_value_native,
    _diff_requests_native,
    _intruder_run_native,
    _list_captured_traffic_native,
    _racer_run_native,
    _send_raw_request_native,
    _sequencer_analyze_native,
)

_RealAsyncHTTPXClient = httpx.AsyncClient


def _mock_httpx_async_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealAsyncHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))


def _seed_entry(session_id, **overrides):
    entry = toolkit_store.build_traffic_entry(
        session_id=session_id, method="GET", url="https://example.com/",
        request_headers={"Host": "example.com"}, request_body="",
        response_status=200, response_headers={"Content-Type": "text/plain"}, response_body="hello",
    )
    entry.update(overrides)
    toolkit_store.append_traffic_entry(entry)
    return entry


# --- _send_raw_request_native ------------------------------------------------------------------


def test_send_raw_request_native_maps_target_to_url_and_returns_a_trimmed_shape(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://example.com/login"
        assert request.headers.get("x-test") == "1"
        assert request.content == b"a=1"
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _send_raw_request_native({
        "_session_id": "sess_1", "method": "post", "target": "https://example.com/login",
        "headers": {"X-Test": "1"}, "body": "a=1",
    })

    assert result["status"] == "ok"
    assert result["response_status"] == 200
    assert result["response_body_preview"] == "ok"
    assert "entry_id" in result
    assert set(result.keys()) == {"status", "entry_id", "response_status", "response_headers", "response_body_preview"}


def test_send_raw_request_native_defaults_method_to_get(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _send_raw_request_native({"_session_id": "sess_1", "target": "https://example.com/"})
    assert result["status"] == "ok"


def test_send_raw_request_native_rejects_non_object_headers():
    result = _send_raw_request_native({"_session_id": "sess_1", "target": "https://example.com/", "headers": "not-a-dict"})
    assert result["status"] == "error"
    assert "headers" in result["error"]


def test_send_raw_request_native_surfaces_a_connection_error(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _send_raw_request_native({"_session_id": "sess_1", "target": "https://example.com/"})
    assert result["status"] == "error"
    assert "error" in result


def test_send_raw_request_native_never_shows_a_binary_body_as_text(monkeypatch):
    raw_png = b"\x89PNG\r\n\x1a\n" + bytes(range(20))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "image/png"}, content=raw_png)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _send_raw_request_native({"_session_id": "sess_1", "target": "https://example.com/image.png"})
    assert result["status"] == "ok"
    assert "binary content" in result["response_body_preview"]
    assert str(raw_png) not in result["response_body_preview"]


def test_send_raw_request_native_truncates_a_very_long_text_body(monkeypatch):
    long_body = "x" * 5000

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "text/plain"}, text=long_body)

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _send_raw_request_native({"_session_id": "sess_1", "target": "https://example.com/"})
    assert result["status"] == "ok"
    assert len(result["response_body_preview"]) < 5000
    assert "truncated" in result["response_body_preview"]


# --- _list_captured_traffic_native --------------------------------------------------------------


def test_list_captured_traffic_native_returns_newest_first_trimmed_entries():
    _seed_entry("sess_1", url="https://example.com/first")
    _seed_entry("sess_1", url="https://example.com/second")

    result = _list_captured_traffic_native({"_session_id": "sess_1"})

    assert result["status"] == "ok"
    assert result["count"] == 2
    assert [e["url"] for e in result["entries"]] == ["https://example.com/second", "https://example.com/first"]
    assert set(result["entries"][0].keys()) == {"id", "method", "url", "status", "source", "timestamp", "flags"}


def test_list_captured_traffic_native_respects_limit():
    for i in range(5):
        _seed_entry("sess_1", url=f"https://example.com/{i}")

    result = _list_captured_traffic_native({"_session_id": "sess_1", "limit": 2})
    assert result["count"] == 2


def test_list_captured_traffic_native_empty_session_returns_empty_list():
    result = _list_captured_traffic_native({"_session_id": "sess_empty"})
    assert result == {"status": "ok", "count": 0, "entries": []}


def test_list_captured_traffic_native_query_filters_entries():
    _seed_entry("sess_1", url="https://example.com/login", method="POST", response_status=500)
    _seed_entry("sess_1", url="https://example.com/home", method="GET", response_status=200)

    result = _list_captured_traffic_native({"_session_id": "sess_1", "query": "method.eq:POST"})

    assert result["status"] == "ok"
    assert result["count"] == 1
    assert result["entries"][0]["url"] == "https://example.com/login"


def test_list_captured_traffic_native_invalid_query_returns_clean_error():
    result = _list_captured_traffic_native({"_session_id": "sess_1", "query": "not a valid query"})
    assert result["status"] == "error"
    assert "invalid query" in result["error"]


def test_list_captured_traffic_native_query_no_matches_returns_empty():
    _seed_entry("sess_1", method="GET")
    result = _list_captured_traffic_native({"_session_id": "sess_1", "query": "method.eq:POST"})
    assert result == {"status": "ok", "count": 0, "entries": []}


# --- _decode_value_native ------------------------------------------------------------------------


def test_decode_value_native_delegates_to_run_codec():
    result = _decode_value_native({"scheme": "base64", "mode": "encode", "text": "hello"})
    assert result == {"status": "ok", "result": "aGVsbG8="}


def test_decode_value_native_needs_no_session_id():
    result = _decode_value_native({"scheme": "url", "mode": "encode", "text": "a b"})
    assert result == {"status": "ok", "result": "a%20b"}


# --- _diff_requests_native -----------------------------------------------------------------------


def test_diff_requests_native_returns_a_unified_text_diff():
    entry_a = _seed_entry("sess_1", response_body="hello world")
    entry_b = _seed_entry("sess_1", response_body="hello there")

    result = _diff_requests_native({
        "_session_id": "sess_1", "entry_id_a": entry_a["id"], "entry_id_b": entry_b["id"], "part": "response",
    })

    assert result["status"] == "ok"
    assert "-" in result["diff"] and "+" in result["diff"]


def test_diff_requests_native_missing_entry_returns_error_not_a_crash():
    entry_a = _seed_entry("sess_1")
    result = _diff_requests_native({"_session_id": "sess_1", "entry_id_a": entry_a["id"], "entry_id_b": "missing"})
    assert result["status"] == "error"
    assert "not found" in result["error"]


def test_diff_rows_to_unified_text_truncates_a_very_long_diff():
    rows = [{"tag": "equal", "left_text": "x" * 100, "right_text": "x" * 100} for _ in range(100)]
    text = toolkit_agent_tools._diff_rows_to_unified_text(rows)
    assert len(text) <= toolkit_agent_tools._DIFF_TEXT_MAX_CHARS + len("\n…(truncated)")
    assert "truncated" in text


# --- _intruder_run_native ------------------------------------------------------------------------


def test_intruder_run_native_maps_target_to_url_and_awaits_full_completion(monkeypatch):
    seen_urls = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_urls.append(str(request.url))
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _intruder_run_native({
        "_session_id": "sess_1", "target": "https://example.com/user/§1§",
        "mode": "sniper", "payload_text": "A\nB",
    })

    assert result["status"] == "ok"
    assert result["attempts"] == 2
    assert result["ok"] == 2
    assert sorted(seen_urls) == ["https://example.com/user/A", "https://example.com/user/B"]


def test_intruder_run_native_invalid_template_returns_error_not_a_crash():
    result = _intruder_run_native({"_session_id": "sess_1", "target": "https://example.com/no-positions", "mode": "sniper", "payload_text": "A"})
    assert result["status"] == "error"
    assert "position" in result["error"]


def test_intruder_run_native_defaults_method_to_get(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, text="ok")

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _intruder_run_native({"_session_id": "sess_1", "target": "https://example.com/§1§", "mode": "sniper", "payload_text": "A"})
    assert result["status"] == "ok"


# --- _sequencer_analyze_native --------------------------------------------------------------------


def test_sequencer_analyze_native_requires_header_name():
    result = _sequencer_analyze_native({"_session_id": "sess_1", "mode": "stored"})
    assert result["status"] == "error"
    assert "header_name" in result["error"]


def test_sequencer_analyze_native_stored_mode_analyzes_captured_traffic():
    for value in ("aaaa1111", "bbbb2222", "cccc3333", "dddd4444"):
        _seed_entry("sess_1", response_headers={"X-CSRF-Token": value})

    result = _sequencer_analyze_native({"_session_id": "sess_1", "header_name": "X-CSRF-Token"})

    assert result["status"] == "ok"
    assert result["sample_count"] == 4
    assert result["duplicate_count"] == 0
    assert "verdict" in result


def test_sequencer_analyze_native_stored_mode_too_few_samples_returns_error():
    _seed_entry("sess_1", response_headers={"X-CSRF-Token": "only-one"})

    result = _sequencer_analyze_native({"_session_id": "sess_1", "header_name": "X-CSRF-Token"})

    assert result["status"] == "error"
    assert "need at least" in result["error"]


def test_sequencer_analyze_native_live_mode_requires_a_target():
    result = _sequencer_analyze_native({"_session_id": "sess_1", "header_name": "X-CSRF-Token", "mode": "live"})
    assert result["status"] == "error"
    assert "target" in result["error"]


def test_sequencer_analyze_native_live_mode_rejects_a_target_outside_the_exploitation_allowlist(monkeypatch):
    monkeypatch.setattr(toolkit_agent_tools, "is_target_allowed", lambda target: False)

    result = _sequencer_analyze_native({
        "_session_id": "sess_1", "header_name": "X-CSRF-Token", "mode": "live",
        "target": "https://out-of-scope.example.com/",
    })

    assert result["status"] == "skipped"
    assert "allowlist" in result["reason"]


def test_sequencer_analyze_native_live_mode_fires_real_requests_and_analyzes_the_result(monkeypatch):
    monkeypatch.setattr(toolkit_agent_tools, "is_target_allowed", lambda target: True)
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        return httpx.Response(200, headers={"X-CSRF-Token": f"token-{counter['n']:04d}"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_httpx_async_client(handler))

    result = _sequencer_analyze_native({
        "_session_id": "sess_1", "header_name": "X-CSRF-Token", "mode": "live",
        "target": "https://example.com/session", "count": 5,
    })

    assert result["status"] == "ok"
    assert result["sample_count"] == 5
    assert result["duplicate_count"] == 0


# --- _racer_run_native -----------------------------------------------------------------------
# toolkit_racer.py deliberately bypasses httpx entirely (raw sockets, for byte-level send timing
# control -- see its own docstring), so httpx.MockTransport can't stand in here. A plain blocking
# socket server on a background thread stands in instead -- unlike the asyncio local-server helper
# tests/test_toolkit_racer.py uses (which shares ONE event loop with the code under test),
# _racer_run_native is a SYNC function that opens its OWN fresh event loop internally
# (asyncio.run), so the fake server needs to outlive that boundary regardless of which loop is
# calling it -- a real OS thread with blocking sockets does that for free.


def _start_thread_server(response: bytes):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(50)
    sock.settimeout(0.2)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except socket.timeout:
                continue
            with conn:
                data = b""
                conn.settimeout(2)
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(response)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return sock, thread, stop, port


def _stop_thread_server(sock, thread, stop):
    # Join BEFORE closing the socket -- the accept loop re-checks stop.is_set() every 0.2s (its own
    # accept() timeout) and exits cleanly on its own; closing the socket out from under a thread
    # still blocked inside accept() raises a noisy (though harmless) "Bad file descriptor" there.
    stop.set()
    thread.join(timeout=2)
    sock.close()


def test_racer_run_native_happy_path_against_a_real_local_server():
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    sock, thread, stop, port = _start_thread_server(response)
    try:
        result = _racer_run_native({
            "_session_id": "sess_1", "target": f"http://127.0.0.1:{port}/vote", "request_count": 4,
        })
    finally:
        _stop_thread_server(sock, thread, stop)

    assert result["status"] == "ok"
    assert result["strategy"] == "last_byte"
    assert result["requests"] == 4
    assert result["ok"] == 4
    assert result["response_status_counts"] == {"200": 4}
    # The full per-attempt `results` list is deliberately not part of what the model sees --
    # see _racer_run_native's own docstring for why.
    assert "results" not in result


def test_racer_run_native_defaults_method_and_strategy():
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    sock, thread, stop, port = _start_thread_server(response)
    try:
        result = _racer_run_native({"_session_id": "sess_1", "target": f"http://127.0.0.1:{port}/x"})
    finally:
        _stop_thread_server(sock, thread, stop)

    assert result["status"] == "ok"
    assert result["strategy"] == "last_byte"
    assert result["requests"] == 10  # toolkit_racer's own default request_count


def test_racer_run_native_sequential_strategy():
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    sock, thread, stop, port = _start_thread_server(response)
    try:
        result = _racer_run_native({
            "_session_id": "sess_1", "target": f"http://127.0.0.1:{port}/x",
            "strategy": "sequential", "request_count": 3,
        })
    finally:
        _stop_thread_server(sock, thread, stop)

    assert result["status"] == "ok"
    assert result["strategy"] == "sequential"
    assert result["requests"] == 3


def test_racer_run_native_invalid_request_count_returns_error_not_a_crash():
    result = _racer_run_native({"_session_id": "sess_1", "target": "https://example.com/", "request_count": 1})
    assert result["status"] == "error"
    assert "at least" in result["error"]
