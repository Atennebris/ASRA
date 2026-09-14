"""agent/tools/toolkit_proxy.py -- config parsing, the addon's flow-to-traffic-entry mapping, and
ensure_started()'s disabled-feature short circuit. Never drives a real mitmproxy instance (that
was verified live, out of band, as this phase's own manual self-check) -- same project-wide
convention as every other test suite (tests/test_browser_tools.py's own module docstring), mocked
at the manager/mitmproxy-object boundary.
"""
import asyncio

import pytest

from agent.tools import toolkit_proxy, toolkit_store


def _run(coro):
    return asyncio.run(coro)


# --- config parsing ---------------------------------------------------------------------------


def test_toolkit_enabled_defaults_true(monkeypatch):
    monkeypatch.delenv("TOOLKIT_ENABLED", raising=False)
    assert toolkit_proxy.toolkit_enabled() is True


def test_toolkit_enabled_false(monkeypatch):
    monkeypatch.setenv("TOOLKIT_ENABLED", "false")
    assert toolkit_proxy.toolkit_enabled() is False


def test_proxy_port_defaults_to_8081(monkeypatch):
    monkeypatch.delenv("TOOLKIT_PROXY_PORT", raising=False)
    assert toolkit_proxy._proxy_port() == 8081


def test_proxy_port_respects_env_override(monkeypatch):
    monkeypatch.setenv("TOOLKIT_PROXY_PORT", "9999")
    assert toolkit_proxy._proxy_port() == 9999


# --- ToolkitProxyManager -----------------------------------------------------------------------


def test_proxy_config_for_session_shape(monkeypatch):
    monkeypatch.setenv("TOOLKIT_PROXY_PORT", "8081")
    manager = toolkit_proxy.ToolkitProxyManager()
    config = manager.proxy_config_for_session("sess_abc")
    assert config == {
        "server": "http://127.0.0.1:8081",
        "username": "sess_abc",
        "password": toolkit_proxy._PROXY_AUTH_PASSWORD,
    }


def test_ensure_started_returns_false_when_disabled(monkeypatch):
    monkeypatch.setenv("TOOLKIT_ENABLED", "false")
    manager = toolkit_proxy.ToolkitProxyManager()
    assert _run(manager.ensure_started()) is False
    assert manager._master is None  # never even attempted to construct mitmproxy's DumpMaster


def test_shutdown_is_a_no_op_when_never_started():
    manager = toolkit_proxy.ToolkitProxyManager()
    _run(manager.shutdown())  # must not raise


# --- _TrafficCaptureAddon: fake mitmproxy flow, no real proxy involved ------------------------
# is_text_content_type/encode_body themselves now live in agent/tools/toolkit_store.py (shared
# with the Repeater send engine, agent/tools/toolkit_repeater.py) -- their own tests moved to
# tests/test_toolkit_store.py.


class _CaseInsensitiveHeaders(dict):
    """Miniature stand-in for mitmproxy's own real Headers class (confirmed live: case-insensitive
    .get()) -- toolkit_proxy.py relies on that case-insensitivity (always queries lowercase
    "content-type" regardless of how the real target capitalized it)."""

    def get(self, key, default=None):
        key_lower = key.lower()
        for k, v in self.items():
            if k.lower() == key_lower:
                return v
        return default


class _FakeMessage:
    def __init__(self, headers, content: bytes):
        self.headers = _CaseInsensitiveHeaders(headers)
        self.content = content


class _FakeResponse(_FakeMessage):
    def __init__(self, headers, content: bytes, status_code):
        super().__init__(headers, content)
        self.status_code = status_code


class _FakeFlow:
    def __init__(self, *, proxyauth=None, method="GET", url="https://example.com/", response=None):
        self.metadata = {"proxyauth": proxyauth} if proxyauth else {}
        self.request = _FakeMessage({"User-Agent": "test"}, b"")
        self.request.method = method
        self.request.pretty_url = url
        self.response = response


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))
    # Module-level caches (_scope_cache/_seen_body_hashes) must not leak session_id state between
    # tests -- several tests below reuse "sess_1" with deliberately different scope/body fixtures.
    toolkit_proxy._scope_cache.clear()
    toolkit_proxy._seen_body_hashes.clear()


def test_response_hook_appends_entry_when_authenticated():
    response = _FakeResponse({"Content-Type": "text/html"}, b"<html></html>", 200)
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), response=response)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entries = toolkit_store.load_traffic_entries("sess_1")
    assert len(entries) == 1
    assert entries[0]["method"] == "GET"
    assert entries[0]["url"] == "https://example.com/"
    assert entries[0]["response_status"] == 200
    assert entries[0]["response_body"] == "<html></html>"
    assert entries[0]["response_body_encoding"] == "text"
    assert entries[0]["response_content_length"] == len(b"<html></html>")
    assert entries[0]["source"] == "proxy"


def test_response_hook_skips_flow_without_proxyauth():
    flow = _FakeFlow(proxyauth=None, response=_FakeResponse({}, b"", 200))

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    assert toolkit_store.load_traffic_entries("sess_1") == []


def test_response_hook_handles_missing_response_gracefully():
    """A flow can reach response() hooks with flow.response still None in edge cases (e.g. the
    connection was interrupted) -- must not raise, and should record it as a response-less entry."""
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), response=None)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entries = toolkit_store.load_traffic_entries("sess_1")
    assert len(entries) == 1
    assert entries[0]["response_status"] is None
    assert entries[0]["response_body"] == ""


# --- scope filter + body dedup -----------------------------------------------------------------
# Real, confirmed incident (a real HackerOne session): 76.8MB of a 128MB traffic.jsonl came
# from off-scope third-party hosts (js.stripe.com, hackerone.com), including one ~2MB JS bundle
# captured 5 times byte-for-byte. Both filters fail open when scope can't be determined at all
# (no session on disk / no "target" field) -- see _session_scope_apex_domains' own docstring.


def test_response_hook_keeps_body_for_a_host_matching_the_session_target(monkeypatch):
    monkeypatch.setattr(toolkit_proxy, "load_session", lambda session_id: {"target": "example.com"})
    response = _FakeResponse({"Content-Type": "text/html"}, b"<html>in-scope</html>", 200)
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), url="https://trk.notify.example.com/x", response=response)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entry = toolkit_store.load_traffic_entries("sess_1")[0]
    assert entry["response_body"] == "<html>in-scope</html>"


def test_response_hook_drops_body_for_a_host_outside_the_session_target(monkeypatch):
    monkeypatch.setattr(toolkit_proxy, "load_session", lambda session_id: {"target": "example.com"})
    response = _FakeResponse({"Content-Type": "application/javascript"}, b"var stripe = {};", 200)
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), url="https://js.stripe.com/v3/", response=response)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entry = toolkit_store.load_traffic_entries("sess_1")[0]
    # Metadata (status/URL/content-length) is still recorded -- only the body is dropped.
    assert entry["response_body"] == ""
    assert entry["response_status"] == 200
    assert entry["response_content_length"] == len(b"var stripe = {};")


def test_response_hook_keeps_body_for_a_recon_discovered_sibling_host(monkeypatch):
    monkeypatch.setattr(
        toolkit_proxy, "load_session",
        lambda session_id: {"target": "example.com", "recon_result": {"targets": [{"host": "support.example.com"}]}},
    )
    response = _FakeResponse({"Content-Type": "text/html"}, b"<html>ok</html>", 200)
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), url="https://support.example.com/help", response=response)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entry = toolkit_store.load_traffic_entries("sess_1")[0]
    assert entry["response_body"] == "<html>ok</html>"


def test_response_hook_fails_open_when_session_has_no_target(monkeypatch):
    monkeypatch.setattr(toolkit_proxy, "load_session", lambda session_id: {})
    response = _FakeResponse({"Content-Type": "text/html"}, b"<html>kept</html>", 200)
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), url="https://anything.example.com/", response=response)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entry = toolkit_store.load_traffic_entries("sess_1")[0]
    assert entry["response_body"] == "<html>kept</html>"


def test_response_hook_respects_scope_filter_disabled_env(monkeypatch):
    monkeypatch.setenv("TOOLKIT_SCOPE_FILTER_ENABLED", "false")
    monkeypatch.setattr(toolkit_proxy, "load_session", lambda session_id: {"target": "example.com"})
    response = _FakeResponse({"Content-Type": "text/html"}, b"<html>kept</html>", 200)
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), url="https://js.stripe.com/v3/", response=response)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entry = toolkit_store.load_traffic_entries("sess_1")[0]
    assert entry["response_body"] == "<html>kept</html>"


def test_response_hook_drops_body_of_an_exact_repeat_seen_earlier_this_session(monkeypatch):
    monkeypatch.setattr(toolkit_proxy, "load_session", lambda session_id: {"target": "example.com"})
    monkeypatch.setattr(toolkit_proxy, "_DEDUP_MIN_BODY_BYTES", 10)  # keep the fixture body small
    body = b"identical payload bytes, repeated"
    flow_1 = _FakeFlow(proxyauth=("sess_1", "asra"), url="https://example.com/bundle.js?v=1", response=_FakeResponse({"Content-Type": "application/javascript"}, body, 200))
    flow_2 = _FakeFlow(proxyauth=("sess_1", "asra"), url="https://example.com/bundle.js?v=2", response=_FakeResponse({"Content-Type": "application/javascript"}, body, 200))

    addon = toolkit_proxy._TrafficCaptureAddon()
    addon.response(flow_1)
    addon.response(flow_2)

    entries = toolkit_store.load_traffic_entries("sess_1")
    assert entries[0]["response_body"] != ""       # first sighting kept
    assert entries[1]["response_body"] == ""        # exact repeat dropped
    assert entries[1]["response_content_length"] == len(body)  # metadata still recorded


def test_response_hook_stores_a_binary_body_as_base64_not_garbled_text():
    """The real bug a user found live: an image/jpeg response rendered as mojibake in the Site
    Map's detail view, because the capture always force-decoded the body as text regardless of
    Content-Type."""
    import base64
    raw_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF" + bytes(range(256)) * 4  # realistic binary content
    response = _FakeResponse({"Content-Type": "image/jpeg"}, raw_jpeg, 200)
    flow = _FakeFlow(proxyauth=("sess_1", "asra"), response=response)

    toolkit_proxy._TrafficCaptureAddon().response(flow)

    entry = toolkit_store.load_traffic_entries("sess_1")[0]
    assert entry["response_body_encoding"] == "base64"
    assert entry["response_content_length"] == len(raw_jpeg)
    assert base64.b64decode(entry["response_body"]) == raw_jpeg
