"""authz_diff_sweep -- the bulk counterpart to idor_probe: replays every already-captured,
resource-shaped, authenticated traffic entry as identity_b and diffs each against the response
already captured for it. Same real-httpx.MockTransport approach as
test_authenticated_crawl_and_idor_probe.py; toolkit_store.load_traffic_entries is monkeypatched
directly to a fixed fixture list rather than going through the real JSONL file, since that storage
layer already has its own tests (test_toolkit_store.py).
"""
import asyncio

import httpx
import pytest

from agent.tools import allowed_targets, native, toolkit_store
from agent.tools.allowed_targets import add_allowed_target
from sessions import store

_RealHTTPXClient = httpx.Client  # captured before any test monkeypatches httpx.Client


def _run(coro):
    return asyncio.run(coro)


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _entry(**overrides):
    base = {
        "id": "e1",
        "method": "GET",
        "url": "https://example.com/orders/1",
        "request_headers": {"Cookie": "a=1"},
        "request_body": "",
        "request_body_encoding": "text",
        "response_status": 200,
        "response_headers": {},
        "response_body": "order #1: 4 widgets",
        "response_body_encoding": "text",
    }
    base.update(overrides)
    return base


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(native, "_CREDENTIALS_DIR", tmp_path / "credentials")
    # authz_diff_sweep re-checks is_target_allowed per candidate URL itself (defense-in-depth,
    # since its ToolSpec sweeps many URLs rather than the single "target" param runner.py's own
    # guardrail checks) -- calling native.authz_diff_sweep directly here bypasses that guardrail
    # entirely, so the allowlist must be seeded the same way test_idor_probe_is_exempt... does for
    # its own core.py integration test, or every candidate would be rejected as out-of-scope by
    # default (the allowlist is empty, not wildcard-open, unless explicitly populated).
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    add_allowed_target("example.com")
    native._authenticated_clients.clear()
    yield
    native._authenticated_clients.clear()


def test_errors_for_an_unconfigured_identity_b():
    monkeypatch_entries = []
    _ = monkeypatch_entries  # unused, keeps this test independent of traffic content
    result = native.authz_diff_sweep({"_session_id": "usr_none", "target": "example.com", "identity_b": "user_b"})
    assert result["status"] == "error"
    assert "user_b" in result["error"]


def test_flags_likely_idor_for_a_resource_shaped_authenticated_entry(monkeypatch):
    native.save_identity_credentials("usr_sweep", {"user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""}})
    monkeypatch.setattr(toolkit_store, "load_traffic_entries", lambda session_id: [_entry()])

    def handler(request: httpx.Request) -> httpx.Response:
        # Same order data regardless of which identity's cookie made the request -- an IDOR.
        return httpx.Response(200, text="order #1: 4 widgets")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authz_diff_sweep({"_session_id": "usr_sweep", "target": "example.com", "identity_b": "user_b"})

    assert result["status"] == "ok"
    assert result["swept_count"] == 1
    assert result["likely_idor_count"] == 1
    assert result["results"][0]["likely_idor"] is True
    assert result["likely_idor_hits"][0]["identity_b_body_preview"]


def test_does_not_flag_idor_when_access_control_actually_works(monkeypatch):
    native.save_identity_credentials("usr_sweep_denied", {"user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""}})
    monkeypatch.setattr(toolkit_store, "load_traffic_entries", lambda session_id: [_entry()])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authz_diff_sweep({"_session_id": "usr_sweep_denied", "target": "example.com", "identity_b": "user_b"})

    assert result["status"] == "ok"
    assert result["results"][0]["status_b"] == 403
    assert result["results"][0]["likely_idor"] is False
    assert result["likely_idor_count"] == 0


def test_skips_entries_with_no_id_shaped_path_or_query(monkeypatch):
    native.save_identity_credentials("usr_sweep_noid", {"user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""}})
    monkeypatch.setattr(toolkit_store, "load_traffic_entries", lambda session_id: [_entry(url="https://example.com/dashboard")])

    result = native.authz_diff_sweep({"_session_id": "usr_sweep_noid", "target": "example.com", "identity_b": "user_b"})

    assert result["status"] == "ok"
    assert result["swept_count"] == 0
    assert result["captured_traffic_candidates_found"] == 0


def test_skips_entries_with_no_auth_header_at_all(monkeypatch):
    native.save_identity_credentials("usr_sweep_noauth", {"user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""}})
    monkeypatch.setattr(toolkit_store, "load_traffic_entries", lambda session_id: [_entry(request_headers={})])

    result = native.authz_diff_sweep({"_session_id": "usr_sweep_noauth", "target": "example.com", "identity_b": "user_b"})

    assert result["status"] == "ok"
    assert result["captured_traffic_candidates_found"] == 0


def test_skips_mutating_methods_by_default_but_includes_them_when_asked(monkeypatch):
    native.save_identity_credentials("usr_sweep_mutate", {"user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""}})
    monkeypatch.setattr(toolkit_store, "load_traffic_entries", lambda session_id: [_entry(method="POST")])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="order #1: 4 widgets")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    default_result = native.authz_diff_sweep({"_session_id": "usr_sweep_mutate", "target": "example.com", "identity_b": "user_b"})
    assert default_result["swept_count"] == 0
    assert default_result["skipped_mutating_methods"] == 1

    opted_in_result = native.authz_diff_sweep({"_session_id": "usr_sweep_mutate", "target": "example.com", "identity_b": "user_b", "include_mutating": True})
    assert opted_in_result["swept_count"] == 1


def test_skips_out_of_scope_captured_urls(monkeypatch):
    native.save_identity_credentials("usr_sweep_scope", {"user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""}})
    monkeypatch.setattr(
        toolkit_store, "load_traffic_entries",
        lambda session_id: [_entry(url="https://evil-thirdparty.example/orders/1")],
    )

    result = native.authz_diff_sweep({"_session_id": "usr_sweep_scope", "target": "example.com", "identity_b": "user_b"})

    assert result["status"] == "ok"
    assert result["captured_traffic_candidates_found"] == 1
    assert result["skipped_out_of_scope"] == 1
    assert result["swept_count"] == 0


def test_respects_max_candidates_cap_and_reports_capped(monkeypatch):
    native.save_identity_credentials("usr_sweep_cap", {"user_b": {"username": "", "password": "", "login_url": "", "cookie": "b=1", "authorization_header": ""}})
    entries = [_entry(url=f"https://example.com/orders/{i}") for i in range(5)]
    monkeypatch.setattr(toolkit_store, "load_traffic_entries", lambda session_id: entries)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="order data")

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = native.authz_diff_sweep({"_session_id": "usr_sweep_cap", "target": "example.com", "identity_b": "user_b", "max_candidates": 2})

    assert result["captured_traffic_candidates_found"] == 5
    assert result["swept_count"] == 2
    assert result["capped"] is True
