"""agent/tools/toolkit_racer.py -- race-condition testing via last-byte synchronization. Parser-
level pieces (_build_raw_request, _read_raw_response, validate_request_count) are tested directly
against in-memory data, no sockets involved. run_last_byte_race/run_sequential_race are tested
end-to-end against a real local asyncio TCP server (port 0 -- OS-assigned, so parallel test runs
never collide) -- httpx.MockTransport can't stand in here, this engine deliberately bypasses httpx
entirely (see toolkit_racer.py's own docstring for why)."""
import asyncio

import pytest

from agent.tools import toolkit_racer, toolkit_store


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))


async def _read_response_from_bytes(data: bytes, timeout: float = 2) -> dict:
    # asyncio.StreamReader() needs a running event loop to construct (it binds to one in
    # __init__) -- built here, inside the coroutine _run() drives via asyncio.run(), rather than
    # by a plain sync helper called before that loop exists.
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return await toolkit_racer._read_raw_response(reader, timeout)


# --- validate_request_count ------------------------------------------------------------------


def test_validate_request_count_rejects_too_few():
    result = toolkit_racer.validate_request_count(1)
    assert result["status"] == "error"
    assert "at least" in result["error"]


def test_validate_request_count_rejects_over_the_cap(monkeypatch):
    monkeypatch.setenv("RACER_MAX_REQUESTS", "10")
    result = toolkit_racer.validate_request_count(11)
    assert result["status"] == "error"
    assert "exceeds" in result["error"]


def test_validate_request_count_accepts_a_reasonable_value(monkeypatch):
    monkeypatch.setenv("RACER_MAX_REQUESTS", "10")
    assert toolkit_racer.validate_request_count(5) is None
    assert toolkit_racer.validate_request_count(10) is None


# --- _build_raw_request ----------------------------------------------------------------------


def test_build_raw_request_sets_host_content_length_and_connection():
    raw, final_headers = toolkit_racer._build_raw_request(
        "POST", "example.com", "/vote?opt=1", {"X-Test": "1", "Content-Length": "999", "Connection": "keep-alive"}, b"a=1",
    )
    assert final_headers["Host"] == "example.com"
    assert final_headers["Content-Length"] == "3"  # real body length, never the caller's own value
    assert final_headers["Connection"] == "close"
    assert final_headers["X-Test"] == "1"
    assert raw.startswith(b"POST /vote?opt=1 HTTP/1.1\r\n")
    assert raw.endswith(b"a=1")


def test_build_raw_request_no_body_still_has_a_final_byte_to_split():
    raw, _ = toolkit_racer._build_raw_request("GET", "example.com", "/", {}, b"")
    assert raw.endswith(b"\r\n\r\n")
    assert len(raw) > 1  # always splittable: prefix = raw[:-1], last_byte = raw[-1:]


# --- _read_raw_response -----------------------------------------------------------------------


def test_read_raw_response_content_length_body():
    data = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello"
    result = _run(_read_response_from_bytes(data))
    assert result["status"] == 200
    assert result["headers"]["Content-Type"] == "text/plain"
    assert result["body"] == b"hello"


def test_read_raw_response_chunked_body():
    data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    result = _run(_read_response_from_bytes(data))
    assert result["status"] == 200
    assert result["body"] == b"hello world"


def test_read_raw_response_no_length_reads_until_close():
    data = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nwhatever is left"
    result = _run(_read_response_from_bytes(data))
    assert result["status"] == 200
    assert result["body"] == b"whatever is left"


def test_read_raw_response_non_200_status():
    data = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    result = _run(_read_response_from_bytes(data))
    assert result["status"] == 404


def test_read_raw_response_closed_before_status_line_raises():
    with pytest.raises(ConnectionError):
        _run(_read_response_from_bytes(b""))


# --- End-to-end: run_last_byte_race / run_sequential_race against a real local server ---------


async def _serve_fixed_response(status_line: bytes, extra_headers: bytes, body: bytes, hit_counter: list):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        hit_counter.append(1)
        response = status_line + extra_headers + f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    return server, port


def test_run_last_byte_race_records_every_attempt_as_a_traffic_entry():
    async def scenario():
        hits: list = []
        server, port = await _serve_fixed_response(b"HTTP/1.1 200 OK\r\n", b"Content-Type: text/plain\r\n", b"ok", hits)
        async with server:
            return await toolkit_racer.run_last_byte_race(
                session_id="sess_1", method="GET", url=f"http://127.0.0.1:{port}/vote",
                headers_text="", body="", request_count=5,
            )

    result = _run(scenario())

    assert result["status"] == "ok"
    assert result["strategy"] == "last_byte"
    assert result["requests"] == 5
    assert result["ok"] == 5
    assert result["errors"] == 0
    assert result["response_status_counts"] == {"200": 5}

    entries = [e for e in toolkit_store.load_traffic_entries("sess_1") if e["source"] == "racer"]
    assert len(entries) == 5
    assert all(e["response_status"] == 200 for e in entries)
    assert all("flags" in e for e in entries)


def test_run_last_byte_race_rejects_an_out_of_range_count_without_connecting():
    async def scenario():
        return await toolkit_racer.run_last_byte_race(
            session_id="sess_1", method="GET", url="http://127.0.0.1:1/nope",
            headers_text="", body="", request_count=1,
        )

    result = _run(scenario())
    assert result["status"] == "error"
    assert toolkit_store.load_traffic_entries("sess_1") == []  # never even tried to connect


def test_run_last_byte_race_rejects_unsupported_scheme():
    async def scenario():
        return await toolkit_racer.run_last_byte_race(
            session_id="sess_1", method="GET", url="ftp://example.com/",
            headers_text="", body="", request_count=3,
        )

    result = _run(scenario())
    assert result["status"] == "error"
    assert "scheme" in result["error"]


def test_run_last_byte_race_records_connection_errors_without_crashing():
    async def scenario():
        # Nothing listens on this port -- every attempt should fail to connect and be reported as
        # its own per-attempt error, not raise out of run_last_byte_race itself.
        return await toolkit_racer.run_last_byte_race(
            session_id="sess_1", method="GET", url="http://127.0.0.1:1/nope",
            headers_text="", body="", request_count=3,
        )

    result = _run(scenario())
    assert result["status"] == "ok"
    assert result["ok"] == 0
    assert result["errors"] == 3


def test_run_sequential_race_sends_the_same_request_n_times_one_after_another():
    async def scenario():
        hits: list = []
        server, port = await _serve_fixed_response(b"HTTP/1.1 200 OK\r\n", b"Content-Type: text/plain\r\n", b"ok", hits)
        async with server:
            return await toolkit_racer.run_sequential_race(
                session_id="sess_1", method="GET", url=f"http://127.0.0.1:{port}/vote",
                headers_text="", body="", request_count=4,
            )

    result = _run(scenario())

    assert result["status"] == "ok"
    assert result["strategy"] == "sequential"
    assert result["requests"] == 4
    assert result["ok"] == 4
    assert result["response_status_counts"] == {"200": 4}

    entries = [e for e in toolkit_store.load_traffic_entries("sess_1") if e["source"] == "racer"]
    assert len(entries) == 4


def test_run_sequential_race_validates_request_count_too():
    async def scenario():
        return await toolkit_racer.run_sequential_race(
            session_id="sess_1", method="GET", url="http://127.0.0.1:1/nope",
            headers_text="", body="", request_count=1,
        )

    result = _run(scenario())
    assert result["status"] == "error"


# --- run_race dispatch -------------------------------------------------------------------------


def test_run_race_dispatches_to_sequential_strategy():
    async def scenario():
        hits: list = []
        server, port = await _serve_fixed_response(b"HTTP/1.1 200 OK\r\n", b"", b"", hits)
        async with server:
            return await toolkit_racer.run_race(
                session_id="sess_1", method="GET", url=f"http://127.0.0.1:{port}/vote",
                headers_text="", body="", request_count=2, strategy="sequential",
            )

    result = _run(scenario())
    assert result["strategy"] == "sequential"


def test_run_race_defaults_to_last_byte_strategy():
    async def scenario():
        hits: list = []
        server, port = await _serve_fixed_response(b"HTTP/1.1 200 OK\r\n", b"", b"", hits)
        async with server:
            return await toolkit_racer.run_race(
                session_id="sess_1", method="GET", url=f"http://127.0.0.1:{port}/vote",
                headers_text="", body="", request_count=2,
            )

    result = _run(scenario())
    assert result["strategy"] == "last_byte"
