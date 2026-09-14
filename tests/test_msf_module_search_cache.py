"""msf_module_search result caching in _run_tool_with_retry: its real cost is spinning up a whole
msfconsole process (~2-3s) per call, and a real exploit phase re-ran the exact same product-level
query ("openssh") six times across one session because several auto-recorded CVE findings shared
the same technology. Same TTL file cache exploit_db_lookup/cve_lookup already use (agent/tools/cache.py)
-- a local module-database lookup is safe to reuse within a session, unlike a live scan of the
actual target, which must never be cached.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_tool_with_retry
from agent.llm_client import LLMResponse
from agent.tools.registry import get_tool
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _session():
    return {"session_id": "usr_msf_cache", "logs": [], "findings": []}


class _UnparsableCorrectionLLM:
    """Stands in wherever _run_tool_with_retry's 1-Step Retry correction step might fire --
    replying with something that fails to parse as {"arguments": {...}} so the retry gives up
    on its first attempt instead of looping."""
    provider_id = "test-provider"
    model = "test-model"

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content="not valid json", tool_calls=[])


def test_identical_msf_module_search_queries_only_run_the_subprocess_once(tmp_path, monkeypatch):
    from agent.tools import cache as cache_module

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path / "cache")

    calls = []

    def fake_run_tool(spec, arguments):
        calls.append(arguments)
        return {"status": "ok", "tool": "msf_module_search", "stdout": ""}

    monkeypatch.setattr("agent.core.run_tool", fake_run_tool)

    ctx = RunContext(llm=None, session=_session(), session_id="usr_msf_cache")
    spec = get_tool("msf_module_search")

    first = _run(_run_tool_with_retry(ctx, spec, {"query": "openssh"}))
    second = _run(_run_tool_with_retry(ctx, spec, {"query": "openssh"}))

    assert len(calls) == 1  # the real subprocess only ran for the first, uncached call
    assert first["status"] == "ok"
    assert second == first


def test_different_msf_module_search_queries_each_run_for_real(tmp_path, monkeypatch):
    from agent.tools import cache as cache_module

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path / "cache")

    calls = []

    def fake_run_tool(spec, arguments):
        calls.append(arguments["query"])
        return {"status": "ok", "tool": "msf_module_search", "stdout": ""}

    monkeypatch.setattr("agent.core.run_tool", fake_run_tool)

    ctx = RunContext(llm=None, session=_session(), session_id="usr_msf_cache_diff")
    spec = get_tool("msf_module_search")

    _run(_run_tool_with_retry(ctx, spec, {"query": "openssh"}))
    _run(_run_tool_with_retry(ctx, spec, {"query": "openssh 7.4"}))

    assert calls == ["openssh", "openssh 7.4"]


def test_a_failed_msf_module_search_is_never_cached(tmp_path, monkeypatch):
    from agent.tools import cache as cache_module

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path / "cache")

    calls = []

    def fake_run_tool(spec, arguments):
        calls.append(arguments)
        return {"status": "error", "tool": "msf_module_search", "error": "msfconsole not found"}

    monkeypatch.setattr("agent.core.run_tool", fake_run_tool)

    ctx = RunContext(llm=_UnparsableCorrectionLLM(), session=_session(), session_id="usr_msf_cache_fail")
    spec = get_tool("msf_module_search")

    _run(_run_tool_with_retry(ctx, spec, {"query": "openssh"}))
    _run(_run_tool_with_retry(ctx, spec, {"query": "openssh"}))

    assert len(calls) == 2  # a failed lookup is retried for real, not served stale/wrong from cache


def test_other_tools_are_never_cached_by_this_mechanism(tmp_path, monkeypatch):
    """A live scan tool (http_request here, standing in for nmap/nuclei/sqlmap) must always hit
    run_tool for real -- caching would silently return stale target state."""
    from agent.tools import cache as cache_module

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(cache_module, "CACHE_DIR", tmp_path / "cache")

    calls = []

    def fake_run_tool(spec, arguments):
        calls.append(arguments)
        return {"status": "ok", "tool": "http_request", "status_code": 200}

    monkeypatch.setattr("agent.core.run_tool", fake_run_tool)

    ctx = RunContext(llm=None, session=_session(), session_id="usr_msf_cache_other")
    spec = get_tool("http_request")

    _run(_run_tool_with_retry(ctx, spec, {"target": "https://example.com"}))
    _run(_run_tool_with_retry(ctx, spec, {"target": "https://example.com"}))

    assert len(calls) == 2
