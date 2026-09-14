"""agent/tools/toolkit_repeater.py -- send_raw_request's real HTTP dispatch (via httpx.MockTransport,
same "real client, fake transport" convention as tests/test_authenticated_identity.py and friends,
not a crude monkeypatch of the whole function), timeout config, and that a sent request is recorded
into the traffic store as source="repeater" with the same text/binary encoding rules Proxy captures
use (agent/tools/toolkit_store.encode_body). Never touches a real network -- the real end-to-end
send was verified live, out of band, as this phase's own manual self-check.
"""
import asyncio

import httpx
import pytest

from agent.tools import toolkit_repeater, toolkit_store

_RealAsyncHTTPXClient = httpx.AsyncClient  # captured before any test monkeypatches httpx.AsyncClient


def _run(coro):
    return asyncio.run(coro)


def _mock_httpx_async_client(handler):
    """Factory matching httpx.AsyncClient's call signature, backed by a MockTransport instead of
    real sockets -- built from the real class captured above so patching httpx.AsyncClient with
    this doesn't recurse into itself."""
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealAsyncHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))


# --- config ---------------------------------------------------------------------------------


def test_timeout_seconds_defaults_to_10(monkeypatch):
    monkeypatch.delenv("HTTP_REQUEST_TIMEOUT_SECONDS", raising=False)
    assert toolkit_repeater._timeout_seconds() == 10.0


def test_timeout_seconds_respects_env_override(monkeypatch):
    monkeypatch.setenv("HTTP_REQUEST_TIMEOUT_SECONDS", "5")
    assert toolkit_repeater._timeout_seconds() == 5.0


# --- send_raw_request: success paths ---------------------------------------------------------


def test_send_raw_request_returns_ok_and_records_a_repeater_entry(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == "https://example.com/login"
        assert request.headers.get("x-test") == "1"
        assert request.content == b"username=admin"
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>welcome</html>")

    import httpx as httpx_mod
    monkeypatch.setattr(httpx_mod, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_repeater.send_raw_request(
        session_id="sess_1", method="POST", url="https://example.com/login",
        headers={"X-Test": "1"}, body="username=admin",
    ))

    assert result["status"] == "ok"
    entry = result["entry"]
    assert entry["source"] == "repeater"
    assert entry["method"] == "POST"
    assert entry["response_status"] == 200
    assert entry["response_body"] == "<html>welcome</html>"
    assert entry["response_body_encoding"] == "text"

    stored = toolkit_store.load_traffic_entries("sess_1")
    assert len(stored) == 1
    assert stored[0]["id"] == entry["id"]


def test_send_raw_request_stores_a_binary_response_as_base64_not_garbled_text(monkeypatch):
    """Same real bug this whole encoding scheme fixes (a binary response rendering as garbled
    text instead of being base64-preserved), now also covered for Repeater's own send path, not
    just passive Proxy capture."""
    import base64
    raw_png = b"\x89PNG\r\n\x1a\n" + bytes(range(50))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "image/png"}, content=raw_png)

    import httpx as httpx_mod
    monkeypatch.setattr(httpx_mod, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_repeater.send_raw_request(
        session_id="sess_1", method="GET", url="https://example.com/image.png", headers={}, body="",
    ))

    assert result["status"] == "ok"
    entry = result["entry"]
    assert entry["response_body_encoding"] == "base64"
    assert base64.b64decode(entry["response_body"]) == raw_png
    assert entry["response_content_length"] == len(raw_png)


def test_send_raw_request_records_the_response_regardless_of_http_status(monkeypatch):
    """A 500/404 is still a real, successful SEND from this function's own point of view -- only a
    connection-level failure (no response at all) is an "error" result."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal server error")

    import httpx as httpx_mod
    monkeypatch.setattr(httpx_mod, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_repeater.send_raw_request(
        session_id="sess_1", method="GET", url="https://example.com/", headers={}, body="",
    ))

    assert result["status"] == "ok"
    assert result["entry"]["response_status"] == 500


# --- send_raw_request: failure path -----------------------------------------------------------


def test_send_raw_request_returns_error_on_connection_failure_and_stores_nothing(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    import httpx as httpx_mod
    monkeypatch.setattr(httpx_mod, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_repeater.send_raw_request(
        session_id="sess_1", method="GET", url="https://example.com/", headers={}, body="",
    ))

    assert result["status"] == "error"
    assert "error" in result
    assert toolkit_store.load_traffic_entries("sess_1") == []


def test_send_raw_request_error_is_never_empty_for_a_bare_exception(monkeypatch):
    """Real, confirmed incident this fixes (again-tests-usr_73fe2f): httpx's own
    ConnectTimeout()/ReadTimeout() are frequently raised with NO message at all -- str(exc) is
    literally "" -- which used to leave result["error"] empty, giving a model's 1-Step Retry
    correction nothing to react to (it just resent the identical failing call)."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout()  # bare, no message -- the real confirmed shape

    import httpx as httpx_mod
    monkeypatch.setattr(httpx_mod, "AsyncClient", _mock_httpx_async_client(handler))

    result = _run(toolkit_repeater.send_raw_request(
        session_id="sess_1", method="GET", url="https://example.com/", headers={}, body="",
    ))

    assert result["status"] == "error"
    assert result["error"]  # never "" -- at minimum the exception's own class name
