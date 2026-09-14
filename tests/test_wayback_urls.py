"""wayback_urls (agent/tools/native.py): the model's own timeout override must actually reach the
httpx.Client, not be silently ignored by a hardcoded value.

Real, confirmed incident this fixes: the model passed timeout=60 to work around a slow/flaky
web.archive.org response, but the client below hardcoded timeout=45.0 regardless -- the override
wasn't wired to anything, and the same failure repeated. ~90s was wasted on two failed attempts
before the model gave up on the tool entirely.
"""
import httpx

from agent.tools import native
from agent.tools.native import wayback_urls

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(captured_kwargs, handler):
    def factory(**kwargs):
        captured_kwargs.append(kwargs)
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _cdx_handler(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=[["original"], ["https://example.com/old-page"]])


def test_wayback_urls_uses_the_default_timeout_when_none_given(monkeypatch):
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)
    captured = []
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(captured, _cdx_handler))

    result = wayback_urls({"domain": "example.com"})

    assert result["status"] == "ok"
    assert captured[0]["timeout"] == 45.0


def test_wayback_urls_honors_a_model_supplied_timeout(monkeypatch):
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)
    captured = []
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(captured, _cdx_handler))

    result = wayback_urls({"domain": "example.com", "timeout": 60})

    assert result["status"] == "ok"
    assert captured[0]["timeout"] == 60.0


def test_wayback_urls_persists_discovered_urls_as_site_map_candidates(monkeypatch):
    # Real gap this closes: before _persist_candidate_urls existed, a wayback_urls call's own
    # discovered URLs landed nowhere but a truncated session["logs"] JSON blob -- invisible to the
    # Map tab's Site Map Tree (main.py's _build_site_map_tree) entirely.
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client([], _cdx_handler))
    fake_session: dict = {}
    seen_session_ids = []

    def fake_reload_merge_save(session_id, apply):
        seen_session_ids.append(session_id)
        apply(fake_session)

    monkeypatch.setattr(native, "reload_merge_save", fake_reload_merge_save)

    result = wayback_urls({"domain": "example.com", "_session_id": "sess-1"})

    assert result["status"] == "ok"
    assert seen_session_ids == ["sess-1"]
    assert fake_session["recon_result"]["candidate_urls"] == ["https://example.com/old-page"]


def test_wayback_urls_skips_persistence_without_a_session_id(monkeypatch):
    # The standalone Quick Chat / any caller that never had a real project session must not crash
    # or silently create session state out of thin air.
    monkeypatch.setattr(native, "cache_get", lambda *a: None)
    monkeypatch.setattr(native, "cache_set", lambda *a: None)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client([], _cdx_handler))
    calls = []
    monkeypatch.setattr(native, "reload_merge_save", lambda *a: calls.append(a))

    result = wayback_urls({"domain": "example.com"})

    assert result["status"] == "ok"
    assert calls == []


def test_wayback_urls_persists_candidates_on_a_cache_hit_too(monkeypatch):
    # Both callers (this one and common_crawl_urls) return the cached result BEFORE the normal
    # persistence call below them ever runs -- a second session querying the same domain within
    # the shared cross-session URL cache's TTL must still get its OWN candidate_urls populated.
    cached_result = {"status": "ok", "urls": ["https://example.com/cached-page"]}
    monkeypatch.setattr(native, "cache_get", lambda *a: cached_result)
    fake_session: dict = {}
    monkeypatch.setattr(native, "reload_merge_save", lambda session_id, apply: apply(fake_session))

    result = wayback_urls({"domain": "example.com", "_session_id": "sess-2"})

    assert result is cached_result
    assert fake_session["recon_result"]["candidate_urls"] == ["https://example.com/cached-page"]
