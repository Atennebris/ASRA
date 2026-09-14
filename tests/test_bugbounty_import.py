"""Coverage for agent/tools/bugbounty_import.py (the New Project dialog's "Study program page /
Use this link as the target" wizard buttons) and the two main.py routes that front it.

analyze_bugbounty_program's own real dependencies (a live Playwright browser render + a real LLM
call) are mocked at the module level it calls them through -- no live network/LLM traffic, same
discipline every other test in this suite already applies to tool calls.
"""
import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

import main
from agent.tools import bugbounty_import
from sessions import store

_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _run(coro):
    return asyncio.run(coro)


# --- prepare_target_only (button 2 -- two best-effort real checks against the target itself: its
# own real, browser-rendered page title, and RFC 9116 security.txt; no LLM call) ---


@pytest.fixture(autouse=True)
def _no_live_network_for_target_only(monkeypatch):
    """Defaults both of prepare_target_only's own real checks to "nothing found" for every test in
    this file, so existing assertions (name falls back to the bare hostname, no custom_instructions)
    keep holding and this suite never makes live network/browser traffic. Patches at the transport
    level (get_browser_manager's own dependency, and httpx.Client itself) rather than replacing
    _fetch_page_title/_fetch_security_txt wholesale -- the dedicated tests for those below need the
    REAL functions to still run against their own per-test overrides, not a fixture-level stand-in
    that would silently short-circuit them.
    """
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: _FakeBrowserManager({}))

    def _refuse(request):
        raise httpx.ConnectError("mocked: no network in tests", request=request)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_refuse))


def test_prepare_target_only_keeps_full_url_with_path():
    result = _run(bugbounty_import.prepare_target_only("https://app.example.com/admin/login"))
    assert result["status"] == "ok"
    assert result["target"] == "https://app.example.com/admin/login"
    assert result["name"] == "app.example.com"


def test_prepare_target_only_bare_host_stays_bare():
    result = _run(bugbounty_import.prepare_target_only("example.com"))
    assert result["status"] == "ok"
    assert result["target"] == "example.com"
    assert result["name"] == "example.com"


def test_prepare_target_only_strips_www_from_derived_name_only():
    result = _run(bugbounty_import.prepare_target_only("https://www.example.com"))
    assert result["status"] == "ok"
    assert result["name"] == "example.com"
    assert result["target"] == "https://www.example.com"  # the target itself is left untouched


def test_prepare_target_only_empty_input_is_an_error():
    result = _run(bugbounty_import.prepare_target_only("   "))
    assert result["status"] == "error"


def test_prepare_target_only_rejects_unparseable_input():
    result = _run(bugbounty_import.prepare_target_only("not a url at all"))
    assert result["status"] == "error"


def test_prepare_target_only_uses_real_page_title_as_name(monkeypatch):
    """Real, confirmed bug this fixes: an earlier version fetched the title via a plain HTTP GET
    (agent/tools/native.py's web_fetch), which never sees a JS-rendered site's real title (only a
    generic/build-tool default from the raw initial HTML) -- now uses a real browser render, same
    as button 1's own program-page analysis."""
    fake_manager = _FakeBrowserManager({"https://umbra.expert": {"text": "...", "title": "Umbra — Security Research"}})
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    result = _run(bugbounty_import.prepare_target_only("https://umbra.expert"))
    assert result["status"] == "ok"
    assert result["name"] == "Umbra — Security Research"
    assert result["target"] == "https://umbra.expert"


def test_prepare_target_only_falls_back_to_hostname_when_title_fetch_fails():
    # The autouse fixture's own empty-pages _FakeBrowserManager already makes every navigate() fail.
    result = _run(bugbounty_import.prepare_target_only("https://umbra.expert"))
    assert result["status"] == "ok"
    assert result["name"] == "umbra.expert"


def test_prepare_target_only_surfaces_a_found_security_txt(monkeypatch):
    monkeypatch.setattr(bugbounty_import, "_fetch_security_txt", lambda hostname, scheme: "Contact: mailto:security@umbra.expert\nPolicy: https://umbra.expert/security-policy")
    result = _run(bugbounty_import.prepare_target_only("https://umbra.expert"))
    assert result["status"] == "ok"
    assert "security@umbra.expert" in result["custom_instructions"]
    assert "security.txt" in result["custom_instructions"]


def test_prepare_target_only_empty_custom_instructions_when_no_security_txt():
    result = _run(bugbounty_import.prepare_target_only("https://umbra.expert"))
    assert result["status"] == "ok"
    assert result["custom_instructions"] == ""


# --- _fetch_security_txt directly (real HTTP call mocked via httpx.MockTransport) ---


def test_fetch_security_txt_returns_the_real_body_on_200(monkeypatch):
    def handler(request):
        assert request.url.path == "/.well-known/security.txt"
        return httpx.Response(200, text="Contact: mailto:security@example.com\n")
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = bugbounty_import._fetch_security_txt("example.com", "https")
    assert "security@example.com" in result


def test_fetch_security_txt_empty_on_404(monkeypatch):
    def handler(request):
        return httpx.Response(404)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = bugbounty_import._fetch_security_txt("example.com", "https")
    assert result == ""


def test_fetch_security_txt_empty_on_connection_error(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = bugbounty_import._fetch_security_txt("dead.example", "https")
    assert result == ""


# --- _hackerone_scope_url (HackerOne's own real, separate /policy_scopes route) ---


def test_hackerone_scope_url_builds_policy_scopes_path():
    assert bugbounty_import._hackerone_scope_url("https://hackerone.com/acme") == "https://hackerone.com/acme/policy_scopes"


def test_hackerone_scope_url_strips_query_string():
    assert bugbounty_import._hackerone_scope_url("https://hackerone.com/acme?type=team") == "https://hackerone.com/acme/policy_scopes"


def test_hackerone_scope_url_none_for_other_hosts():
    assert bugbounty_import._hackerone_scope_url("https://bugcrowd.com/engagements/acme") is None


def test_hackerone_scope_url_none_for_bare_root():
    assert bugbounty_import._hackerone_scope_url("https://hackerone.com/") is None
    assert bugbounty_import._hackerone_scope_url("https://hackerone.com") is None


def test_hackerone_scope_url_none_when_already_the_scope_page():
    assert bugbounty_import._hackerone_scope_url("https://hackerone.com/acme/policy_scopes") is None


# --- _hackerone_hacktivity_url / _bugcrowd_crowdstream_url / _yeswehack_sitewide_url /
# _disclosed_reports_feed_url / check_disclosed_reports -------------------------------------------


def test_hackerone_hacktivity_url_builds_hacktivity_path():
    assert bugbounty_import._hackerone_hacktivity_url("https://hackerone.com/acme") == "https://hackerone.com/acme/hacktivity"


def test_hackerone_hacktivity_url_strips_query_string():
    assert bugbounty_import._hackerone_hacktivity_url("https://hackerone.com/acme?type=team") == "https://hackerone.com/acme/hacktivity"


def test_hackerone_hacktivity_url_none_for_other_hosts():
    assert bugbounty_import._hackerone_hacktivity_url("https://bugcrowd.com/engagements/acme") is None


def test_hackerone_hacktivity_url_none_for_bare_root():
    assert bugbounty_import._hackerone_hacktivity_url("https://hackerone.com/") is None
    assert bugbounty_import._hackerone_hacktivity_url("https://hackerone.com") is None


def test_hackerone_hacktivity_url_none_when_already_the_hacktivity_page():
    assert bugbounty_import._hackerone_hacktivity_url("https://hackerone.com/acme/hacktivity") is None


def test_bugcrowd_crowdstream_url_builds_crowdstream_path_from_engagements_form():
    assert bugbounty_import._bugcrowd_crowdstream_url("https://bugcrowd.com/engagements/tesla") == "https://bugcrowd.com/engagements/tesla/crowdstream"


def test_bugcrowd_crowdstream_url_normalizes_the_short_handle_form():
    """bugcrowd.com/<handle> (no /engagements/) is a real, working short URL for the BARE handle
    page -- confirmed live that appending /crowdstream to the short form instead 404s, so the
    short form must be normalized to /engagements/<handle> here before appending."""
    assert bugbounty_import._bugcrowd_crowdstream_url("https://bugcrowd.com/tesla") == "https://bugcrowd.com/engagements/tesla/crowdstream"


def test_bugcrowd_crowdstream_url_none_for_other_hosts():
    assert bugbounty_import._bugcrowd_crowdstream_url("https://hackerone.com/acme") is None


def test_bugcrowd_crowdstream_url_none_for_a_sub_path():
    assert bugbounty_import._bugcrowd_crowdstream_url("https://bugcrowd.com/engagements/tesla/crowdstream") is None
    assert bugbounty_import._bugcrowd_crowdstream_url("https://bugcrowd.com/engagements/tesla/submissions/new") is None


def test_yeswehack_sitewide_url_returns_the_sitewide_feed_for_any_program_page():
    """YesWeHack has no per-program disclosed-reports page (confirmed live: the program page's own
    "Program activity" tab is a same-page hash toggle showing a researcher leaderboard, not report
    content) -- every yeswehack.com program URL maps to the same sitewide feed."""
    assert bugbounty_import._yeswehack_sitewide_url("https://yeswehack.com/programs/yes-we-hack") == "https://yeswehack.com/hacktivity"
    assert bugbounty_import._yeswehack_sitewide_url("https://yeswehack.com/programs/anything-else") == "https://yeswehack.com/hacktivity"


def test_yeswehack_sitewide_url_none_for_other_hosts():
    assert bugbounty_import._yeswehack_sitewide_url("https://hackerone.com/acme") is None


def test_disclosed_reports_feed_url_dispatches_by_platform():
    assert bugbounty_import._disclosed_reports_feed_url("https://hackerone.com/acme") == ("https://hackerone.com/acme/hacktivity", "hackerone")
    assert bugbounty_import._disclosed_reports_feed_url("https://bugcrowd.com/tesla") == ("https://bugcrowd.com/engagements/tesla/crowdstream", "bugcrowd")
    assert bugbounty_import._disclosed_reports_feed_url("https://yeswehack.com/programs/x") == ("https://yeswehack.com/hacktivity", "yeswehack_sitewide")


def test_disclosed_reports_feed_url_none_for_an_unsupported_platform():
    assert bugbounty_import._disclosed_reports_feed_url("https://example.com/some-program") is None


def test_check_disclosed_reports_errors_for_an_unsupported_platform(monkeypatch):
    result = _run(bugbounty_import.check_disclosed_reports("https://example.com/some-program"))
    assert result["status"] == "error"
    assert "HackerOne" in result["error"]


def test_check_disclosed_reports_summarizes_the_hacktivity_page_text(monkeypatch):
    fake_manager = _FakeBrowserManager({
        "https://hackerone.com/acme/hacktivity": {"text": "XSS in login form - $500 - resolved", "title": "Acme Hacktivity"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    llm_json = json.dumps({"reports": [{"title": "XSS in login form", "detail": "$500 - resolved"}], "coverage_note": "1 report visible."})
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.check_disclosed_reports("https://hackerone.com/acme"))

    assert result["status"] == "ok"
    assert result["platform"] == "hackerone"
    assert result["reports"] == [{"title": "XSS in login form", "detail": "$500 - resolved"}]
    assert result["coverage_note"] == "1 report visible."
    assert "XSS in login form - $500 - resolved" in result["text"]  # raw text still returned too
    assert fake_manager.navigated == ["https://hackerone.com/acme/hacktivity"]
    assert fake_manager.closed_sessions  # the throwaway session was always torn back down


def test_check_disclosed_reports_degrades_gracefully_when_summarization_fails(monkeypatch):
    fake_manager = _FakeBrowserManager({
        "https://hackerone.com/acme/hacktivity": {"text": "some report text", "title": "Acme"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM("not json at all"))

    result = _run(bugbounty_import.check_disclosed_reports("https://hackerone.com/acme"))

    assert result["status"] == "ok"  # never blocked by a failed summarization pass
    assert result["reports"] == []
    assert "some report text" in result["text"]


def test_check_disclosed_reports_bugcrowd_uses_the_crowdstream_url(monkeypatch):
    fake_manager = _FakeBrowserManager({
        "https://bugcrowd.com/engagements/tesla/crowdstream": {"text": "SQLi report - $1000", "title": "Tesla CrowdStream"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    llm_json = json.dumps({"reports": [{"title": "SQLi report", "detail": "$1000"}], "coverage_note": "note"})
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.check_disclosed_reports("https://bugcrowd.com/tesla"))

    assert result["status"] == "ok"
    assert result["platform"] == "bugcrowd"
    assert fake_manager.navigated == ["https://bugcrowd.com/engagements/tesla/crowdstream"]


def test_check_disclosed_reports_yeswehack_flags_the_sitewide_caveat(monkeypatch):
    fake_manager = _FakeBrowserManager({
        "https://yeswehack.com/hacktivity": {"text": "some sitewide report", "title": "Hacktivity"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    llm_json = json.dumps({"reports": [], "coverage_note": "no reports plausibly matched this program."})
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.check_disclosed_reports("https://yeswehack.com/programs/x"))

    assert result["status"] == "ok"
    assert result["platform"] == "yeswehack_sitewide"
    assert "SITEWIDE" in result["coverage_note"]


def test_check_disclosed_reports_surfaces_a_navigation_failure_cleanly(monkeypatch):
    fake_manager = _FakeBrowserManager({})  # nothing mocked -- navigate() will report "no such page"
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import.check_disclosed_reports("https://hackerone.com/acme"))

    assert result["status"] == "error"
    assert fake_manager.closed_sessions  # still torn down even on failure


def test_check_disclosed_reports_normalizes_a_bare_host_first(monkeypatch):
    """_normalize_url (already used by prepare_target_only/analyze_bugbounty_program) adds the
    https:// scheme a bare "hackerone.com/acme" paste is missing -- must apply here too."""
    fake_manager = _FakeBrowserManager({
        "https://hackerone.com/acme/hacktivity": {"text": "some report", "title": "Acme"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(json.dumps({"reports": [], "coverage_note": "n/a"})))

    result = _run(bugbounty_import.check_disclosed_reports("hackerone.com/acme"))

    assert result["status"] == "ok"


# --- check_disclosed_reports as a real agent-callable tool (agent/core.py's _dispatch_tool) -----
# Wired in so the model can call this mid-scan, not just via the New Project wizard button.
# check_disclosed_reports opens a real Playwright session -- same "async, needs the calling
# event loop, can't go through asyncio.to_thread" bypass as delegate_to_subagent/browser_*, PLUS
# a genuine circular-import constraint (bugbounty_import.py imports FROM agent.core), so the
# bypass uses a lazy import instead of a module-top-level one -- these tests confirm that
# wiring actually reaches the real function, not just that it compiles.


def test_check_disclosed_reports_is_registered_as_an_exploit_category_tool():
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool, get_tools_by_category

    spec = get_tool("check_disclosed_reports")
    assert spec is not None
    assert spec.requires_allowed_target is False
    assert "check_disclosed_reports" in {s.name for s in get_tools_by_category("exploit")}


def test_dispatch_tool_routes_check_disclosed_reports_to_the_real_function(monkeypatch):
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    import agent.core as core
    from agent.core import _dispatch_tool
    from agent.tools.registry import get_tool

    async def fake_check_disclosed_reports(url):
        return {"status": "ok", "text": f"checked {url}", "url": url}

    monkeypatch.setattr(bugbounty_import, "check_disclosed_reports", fake_check_disclosed_reports)

    async def fail_if_native_function_called(*args, **kwargs):
        raise AssertionError("check_disclosed_reports must never reach the generic native-tool path")
    monkeypatch.setattr(core, "run_tool", fail_if_native_function_called)

    spec = get_tool("check_disclosed_reports")
    result = _run(_dispatch_tool(spec, {"program_url": "https://hackerone.com/acme"}))

    assert result == {"status": "ok", "text": "checked https://hackerone.com/acme", "url": "https://hackerone.com/acme"}


def test_check_disclosed_reports_native_stub_reports_a_clear_error_if_ever_actually_called():
    """The registered ToolSpec's own native_function is never reached in practice (the bypass
    above intercepts first) -- confirms it still fails LOUDLY, not silently, if that bypass is
    ever itself broken."""
    from agent.tools import _check_disclosed_reports_native

    result = _check_disclosed_reports_native({"program_url": "https://hackerone.com/acme"})

    assert result["status"] == "error"
    assert "_dispatch_tool" in result["error"]


# --- _fetch_program_page_text (real browser_manager calls mocked out) ---


class _FakeBrowserManager:
    """Tracks every navigate()/close_session() call so a test can assert HOW MANY pages got read,
    not just what the final combined text looks like -- the whole point of the HackerOne fix is
    that it reads a SECOND page, not just that some text comes back."""

    def __init__(self, pages_by_url):
        self.pages_by_url = pages_by_url
        self.navigated = []
        self.closed_sessions = []

    async def navigate(self, session_id, url, wait_until="domcontentloaded", out_of_scope_entries=None):
        self.navigated.append(url)
        if url not in self.pages_by_url:
            return {"status": "error", "error": f"no such page mocked: {url}"}
        return {"status": "ok", "url": url}

    async def evaluate(self, session_id, expression, out_of_scope_entries=None):
        last_url = self.navigated[-1]
        page = self.pages_by_url[last_url]
        return {"status": "ok", "eval_result": page["text"], "title": page.get("title", ""), "url": last_url}

    async def close_session(self, session_id):
        self.closed_sessions.append(session_id)

    async def mouse_wheel_scroll(self, session_id, delta_y=900):
        return {"status": "ok"}


def test_fetch_program_page_text_reads_hackerone_scope_page_too(monkeypatch):
    fake_manager = _FakeBrowserManager({
        "https://hackerone.com/acme": {"text": "guidelines and rules text", "title": "Acme"},
        "https://hackerone.com/acme/policy_scopes": {"text": "api.acme.com is in scope", "title": "Acme"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import._fetch_program_page_text("https://hackerone.com/acme"))
    assert result["status"] == "ok"
    assert "guidelines and rules text" in result["text"]
    assert "api.acme.com is in scope" in result["text"]
    assert fake_manager.navigated == ["https://hackerone.com/acme", "https://hackerone.com/acme/policy_scopes"]
    assert fake_manager.closed_sessions  # the throwaway session was always torn back down


def test_fetch_program_page_text_non_hackerone_reads_only_one_page(monkeypatch):
    fake_manager = _FakeBrowserManager({
        "https://bugcrowd.com/engagements/acme": {"text": "bugcrowd page text", "title": "Acme"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import._fetch_program_page_text("https://bugcrowd.com/engagements/acme"))
    assert result["status"] == "ok"
    assert result["text"] == "bugcrowd page text"
    assert fake_manager.navigated == ["https://bugcrowd.com/engagements/acme"]


def test_fetch_program_page_text_hackerone_scope_page_failure_keeps_primary_text(monkeypatch):
    """The scope page can 404/fail (a program with no /policy_scopes, an edge case) -- the primary
    page's own real text must still come back rather than the whole call failing over one extra,
    best-effort read."""
    fake_manager = _FakeBrowserManager({
        "https://hackerone.com/acme": {"text": "guidelines and rules text", "title": "Acme"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import._fetch_program_page_text("https://hackerone.com/acme"))
    assert result["status"] == "ok"
    assert result["text"] == "guidelines and rules text"


# --- _navigate_and_harvest_scrollable_text (HackerOne's own scroll-triggered "load more" scope
# table -- real, confirmed live: a 44-asset program only ever showed ~19 on a single read) ---


class _GrowingScrollBrowserManager:
    """Simulates a scroll-triggered "load more" list: each successive evaluate() call for the same
    URL returns progressively MORE content, exactly like HackerOne's own GraphQL-paginated scope
    table, until content_rounds is exhausted and it stabilizes on the final (complete) snapshot --
    the real, confirmed shape mouse_wheel_scroll's own docstring documents. Content advances once
    per evaluate() call (once per OUTER harvest round), deliberately decoupled from however many
    individual wheel ticks happen within a round, so these tests stay correct regardless of
    _SCOPE_HARVEST_WHEEL_TICKS_PER_ROUND's own tuning. Tracks wheel-scroll call count so a test can
    assert the harvest loop actually drove the scrolling, not just read the same page once.
    """

    def __init__(self, content_rounds):
        self.content_rounds = content_rounds
        self.evaluate_calls = 0
        self.wheel_scroll_calls = 0
        self.navigated = []
        self.closed_sessions = []

    async def navigate(self, session_id, url, wait_until="domcontentloaded", out_of_scope_entries=None):
        self.navigated.append(url)
        return {"status": "ok", "url": url}

    async def evaluate(self, session_id, expression, out_of_scope_entries=None):
        index = min(self.evaluate_calls, len(self.content_rounds) - 1)
        self.evaluate_calls += 1
        return {"status": "ok", "eval_result": self.content_rounds[index], "title": "Acme", "url": self.navigated[-1]}

    async def mouse_wheel_scroll(self, session_id, delta_y=900):
        self.wheel_scroll_calls += 1
        return {"status": "ok"}

    async def close_session(self, session_id):
        self.closed_sessions.append(session_id)


def test_harvest_scrollable_text_accumulates_until_content_stabilizes(monkeypatch):
    manager = _GrowingScrollBrowserManager([
        "19 assets loaded so far...",
        "31 assets loaded so far...",
        "44 assets loaded so far...",
        "44 assets loaded so far...",  # same as previous round -- signals the real end
    ])
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    monkeypatch.setattr(bugbounty_import, "_SCOPE_HARVEST_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import._navigate_and_harvest_scrollable_text(manager, "sess", "https://hackerone.com/acme/policy_scopes"))
    assert result["status"] == "ok"
    assert result["text"] == "44 assets loaded so far..."
    # 3 outer rounds actually grew content before the 4th (stable) read stopped the loop -- each
    # growing round ticks the wheel _SCOPE_HARVEST_WHEEL_TICKS_PER_ROUND times, the final
    # stable-detecting read ticks zero more.
    assert manager.wheel_scroll_calls == 3 * bugbounty_import._SCOPE_HARVEST_WHEEL_TICKS_PER_ROUND


def test_harvest_scrollable_text_needs_no_scrolling_for_a_static_page(monkeypatch):
    manager = _GrowingScrollBrowserManager(["everything already here"])
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    monkeypatch.setattr(bugbounty_import, "_SCOPE_HARVEST_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import._navigate_and_harvest_scrollable_text(manager, "sess", "https://hackerone.com/acme/policy_scopes"))
    assert result["status"] == "ok"
    assert result["text"] == "everything already here"
    # One outer round found real (new-vs-None) content and ticked once; the second read found the
    # same text and stopped without ticking again.
    assert manager.wheel_scroll_calls == bugbounty_import._SCOPE_HARVEST_WHEEL_TICKS_PER_ROUND


def test_fetch_program_page_text_uses_harvest_for_hackerone_scope_page(monkeypatch):
    """Confirms _fetch_program_page_text's own HackerOne branch actually routes through the
    scroll-harvest path, not the plain single-read one -- the real bug this whole chain fixes."""
    manager = _GrowingScrollBrowserManager(["primary page (unused by this manager's navigate)"])
    # This fake manager doesn't distinguish primary vs scope URL content (both routes just return
    # content_rounds), so this test only asserts wheel_scroll_calls happened at all -- proof the
    # harvest path (not _navigate_and_read_text, which never scrolls) ran for the scope page.
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)
    monkeypatch.setattr(bugbounty_import, "_SCOPE_HARVEST_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import._fetch_program_page_text("https://hackerone.com/acme"))
    assert result["status"] == "ok"
    assert manager.navigated == ["https://hackerone.com/acme", "https://hackerone.com/acme/policy_scopes"]
    assert manager.wheel_scroll_calls >= 1


def test_fetch_program_page_text_prioritizes_scope_text_when_over_budget(monkeypatch):
    """Real, confirmed gap this fixes: naive end-truncation of the concatenated text let a long
    guidelines page silently crowd out the separately-fetched HackerOne scope section appended
    after it -- exactly the section the whole two-page fetch exists to capture. The scope text must
    survive intact even when the combined text would otherwise blow the budget."""
    monkeypatch.setattr(bugbounty_import, "_MAX_PAGE_TEXT_CHARS", 100)
    fake_manager = _FakeBrowserManager({
        "https://hackerone.com/acme": {"text": "G" * 500, "title": "Acme"},
        "https://hackerone.com/acme/policy_scopes": {"text": "api.acme.com is in scope " * 3, "title": "Acme"},
    })
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    result = _run(bugbounty_import._fetch_program_page_text("https://hackerone.com/acme"))
    assert result["status"] == "ok"
    assert "api.acme.com is in scope" in result["text"]  # scope text kept whole, not truncated away
    assert len(result["text"]) <= 100 + len("\n\n--- Scope & Rewards page ---\n\n")


# --- _reroute_misplaced_ua (server-side safety net against the exact live-confirmed misroute) ---


def test_reroute_misplaced_ua_moves_a_bare_token_to_snippet():
    """Real, confirmed live incident this guards against: the model put a YesWeHack program's own
    literal, no-placeholder append-token ("MCN-Prime-aux-bogues") straight into custom_user_agent."""
    fields = {"custom_user_agent": "MCN-Prime-aux-bogues", "user_agent_snippet": ""}
    bugbounty_import._reroute_misplaced_ua(fields)
    assert fields["custom_user_agent"] == ""
    assert fields["user_agent_snippet"] == "MCN-Prime-aux-bogues"


def test_reroute_misplaced_ua_leaves_a_real_browser_ua_alone():
    fields = {
        "custom_user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "user_agent_snippet": "",
    }
    bugbounty_import._reroute_misplaced_ua(fields)
    assert fields["custom_user_agent"].startswith("Mozilla/5.0")
    assert fields["user_agent_snippet"] == ""


def test_reroute_misplaced_ua_does_not_overwrite_an_already_set_snippet():
    fields = {"custom_user_agent": "some-token", "user_agent_snippet": "already-set"}
    bugbounty_import._reroute_misplaced_ua(fields)
    assert fields["custom_user_agent"] == "some-token"
    assert fields["user_agent_snippet"] == "already-set"


def test_reroute_misplaced_ua_noop_on_empty_custom_user_agent():
    fields = {"custom_user_agent": "", "user_agent_snippet": ""}
    bugbounty_import._reroute_misplaced_ua(fields)
    assert fields == {"custom_user_agent": "", "user_agent_snippet": ""}


# --- analyze_bugbounty_program (button 1 -- fetch + LLM extraction, both mocked) ---


class _FakeLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, content: str):
        self._content = content

    def complete(self, messages, tools=None, stop_check=None):
        return SimpleNamespace(content=self._content)


def test_analyze_bugbounty_program_happy_path(monkeypatch):
    async def fake_fetch(url):
        return {"status": "ok", "text": "OpenAI is in scope. api.openai.com is in scope.", "title": "OpenAI Bounty", "url": url}

    llm_json = json.dumps({
        "name": "OpenAI — Bugcrowd",
        "target": "api.openai.com, *.openai.com",
        "out_of_scope": "staging.openai.com",
        "qualifying_vulnerabilities": "RCE, SQLi, auth bypass",
        "non_qualifying_vulnerabilities": "Model jailbreaks",
        "custom_instructions": "Use the Bugcrowd Ninja test account.",
        "custom_user_agent": "",
        "custom_headers": "",
    })
    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.analyze_bugbounty_program("https://bugcrowd.com/engagements/openai"))
    assert result["status"] == "ok"
    assert result["name"] == "OpenAI — Bugcrowd"
    assert result["target"] == "api.openai.com, *.openai.com"
    assert result["out_of_scope"] == "staging.openai.com"
    assert "RCE" in result["qualifying_vulnerabilities"]


def test_analyze_bugbounty_program_drops_invalid_scope_entries(monkeypatch):
    async def fake_fetch(url):
        return {"status": "ok", "text": "some real page text", "title": "t", "url": url}

    llm_json = json.dumps({
        "name": "Acme",
        "target": "api.example.com, not a valid target at all",
        "out_of_scope": "",
        "qualifying_vulnerabilities": "",
        "non_qualifying_vulnerabilities": "",
        "custom_instructions": "",
        "custom_user_agent": "",
        "custom_headers": "",
    })
    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.analyze_bugbounty_program("https://example.com/program"))
    assert result["status"] == "ok"
    assert result["target"] == "api.example.com"  # the malformed second entry was dropped, not kept


def test_analyze_bugbounty_program_fetch_failure_is_a_clean_error(monkeypatch):
    async def fake_fetch(url):
        return {"status": "error", "error": "navigation to 'https://dead.example' failed: timeout"}

    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)

    result = _run(bugbounty_import.analyze_bugbounty_program("https://dead.example"))
    assert result["status"] == "error"
    assert "dead.example" in result["error"] or "timeout" in result["error"]


def test_analyze_bugbounty_program_empty_page_text_is_an_error(monkeypatch):
    async def fake_fetch(url):
        return {"status": "ok", "text": "   ", "title": "", "url": url}

    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)

    result = _run(bugbounty_import.analyze_bugbounty_program("https://example.com"))
    assert result["status"] == "error"


def test_analyze_bugbounty_program_malformed_llm_json_is_an_error(monkeypatch):
    async def fake_fetch(url):
        return {"status": "ok", "text": "some real page text", "title": "t", "url": url}

    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM("not json at all"))

    result = _run(bugbounty_import.analyze_bugbounty_program("https://example.com"))
    assert result["status"] == "error"


def test_analyze_bugbounty_program_no_target_extracted_keeps_partial_fields(monkeypatch):
    async def fake_fetch(url):
        return {"status": "ok", "text": "a page with rules but no concrete host table", "title": "t", "url": url}

    llm_json = json.dumps({
        "name": "", "target": "", "out_of_scope": "",
        "qualifying_vulnerabilities": "RCE", "non_qualifying_vulnerabilities": "",
        "custom_instructions": "Only test during business hours.",
        "custom_user_agent": "", "custom_headers": "",
    })
    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.analyze_bugbounty_program("https://example.com"))
    assert result["status"] == "error"
    assert result["qualifying_vulnerabilities"] == "RCE"  # partial extraction preserved, not discarded
    assert result["custom_instructions"] == "Only test during business hours."


def test_analyze_bugbounty_program_empty_url_is_an_error():
    result = _run(bugbounty_import.analyze_bugbounty_program(""))
    assert result["status"] == "error"


def test_analyze_bugbounty_program_dedupes_repeated_targets(monkeypatch):
    """Real, confirmed behavior: a program's own scope table commonly lists the same host under
    more than one target group, and the model echoes it that many times."""
    async def fake_fetch(url):
        return {"status": "ok", "text": "t", "title": "t", "url": url}

    llm_json = json.dumps({
        "name": "Acme", "target": "api.example.com, api.example.com, API.EXAMPLE.COM",
        "out_of_scope": "staging.example.com, staging.example.com",
        "qualifying_vulnerabilities": "", "non_qualifying_vulnerabilities": "",
        "custom_instructions": "", "custom_user_agent": "", "user_agent_snippet": "", "custom_headers": "",
    })
    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.analyze_bugbounty_program("https://example.com"))
    assert result["status"] == "ok"
    assert result["target"] == "api.example.com"  # case-insensitive dedup, first-seen casing kept
    assert result["out_of_scope"] == "staging.example.com"


def test_analyze_bugbounty_program_routes_ua_requirement_to_snippet_not_full_ua(monkeypatch):
    """Real bug this fixes: a YesWeHack-style "add bug-bounty-HunterName to your User-Agent,
    replace HunterName with your nickname" used to land verbatim (broken instructional prose and
    all) in custom_user_agent. It must now land in user_agent_snippet, with the placeholder
    standardized on YOUR_HANDLE, and custom_user_agent must stay empty so the operator's existing
    "Merge into my browser's UA" flow is what actually builds the final UA."""
    async def fake_fetch(url):
        return {"status": "ok", "text": "t", "title": "t", "url": url}

    llm_json = json.dumps({
        "name": "Acme", "target": "api.example.com", "out_of_scope": "",
        "qualifying_vulnerabilities": "", "non_qualifying_vulnerabilities": "",
        "custom_instructions": "", "custom_user_agent": "",
        "user_agent_snippet": "bug-bounty-YOUR_HANDLE", "custom_headers": "X-HackerOne-Research: YOUR_HANDLE",
    })
    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.analyze_bugbounty_program("https://example.com"))
    assert result["status"] == "ok"
    assert result["custom_user_agent"] == ""
    assert result["user_agent_snippet"] == "bug-bounty-YOUR_HANDLE"
    assert result["custom_headers"] == "X-HackerOne-Research: YOUR_HANDLE"


def test_analyze_bugbounty_program_reroutes_ua_even_when_the_model_gets_it_wrong(monkeypatch):
    """End-to-end version of the _reroute_misplaced_ua unit tests -- the model itself misrouting a
    bare append-token into custom_user_agent (the real, live-confirmed failure mode) must still
    come out of analyze_bugbounty_program correctly rerouted, not just when isolated field dicts
    are fed to the helper directly."""
    async def fake_fetch(url):
        return {"status": "ok", "text": "t", "title": "t", "url": url}

    llm_json = json.dumps({
        "name": "Acme", "target": "api.example.com", "out_of_scope": "",
        "qualifying_vulnerabilities": "", "non_qualifying_vulnerabilities": "",
        "custom_instructions": "", "custom_user_agent": "MCN-Prime-aux-bogues",
        "user_agent_snippet": "", "custom_headers": "",
    })
    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.analyze_bugbounty_program("https://example.com"))
    assert result["status"] == "ok"
    assert result["custom_user_agent"] == ""
    assert result["user_agent_snippet"] == "MCN-Prime-aux-bogues"


# --- the two main.py wizard routes ---


@pytest.fixture
def client():
    return TestClient(main.app)


def test_wizard_target_only_route_prefills_form(client):
    resp = client.post("/api/scan/wizard/target-only", data={"url": "https://app.example.com/login"})
    assert resp.status_code == 200
    assert 'value="https://app.example.com/login"' in resp.text
    assert 'id="new-project-form-container"' in resp.text


def test_wizard_target_only_route_error_stays_200_and_preserves_input(client):
    resp = client.post("/api/scan/wizard/target-only", data={"url": ""})
    assert resp.status_code == 200  # htmx only swaps on 2xx -- a 4xx here would freeze the dialog
    assert "Enter a target URL first" in resp.text


def test_wizard_import_program_route_uses_analyze_bugbounty_program(client, monkeypatch):
    async def fake_analyze(url):
        return {
            "status": "ok", "name": "Acme — HackerOne", "target": "api.acme.com",
            "out_of_scope": "", "qualifying_vulnerabilities": "SQLi",
            "non_qualifying_vulnerabilities": "", "custom_instructions": "",
            "custom_user_agent": "", "custom_headers": "",
        }
    monkeypatch.setattr(main, "analyze_bugbounty_program", fake_analyze)

    resp = client.post("/api/scan/wizard/import-program", data={"url": "https://hackerone.com/acme"})
    assert resp.status_code == 200
    assert "api.acme.com" in resp.text
    assert "SQLi" in resp.text


def test_wizard_check_disclosed_reports_route_shows_the_summarized_reports(client, monkeypatch):
    async def fake_check(url):
        return {
            "status": "ok",
            "reports": [{"title": "Stored XSS in profile bio", "detail": "$750 - resolved"}],
            "coverage_note": "1 report visible.",
            "text": "Stored XSS in profile bio - $750 - resolved",
            "url": url, "platform": "hackerone",
        }
    monkeypatch.setattr(main, "check_disclosed_reports", fake_check)

    resp = client.post("/api/scan/wizard/check-disclosed-reports", data={"url": "https://hackerone.com/acme"})

    assert resp.status_code == 200
    assert "Stored XSS in profile bio" in resp.text
    assert "1 report visible." in resp.text
    assert "Stored XSS in profile bio - $750 - resolved" in resp.text  # raw text, collapsed but present


def test_wizard_check_disclosed_reports_route_shows_no_reports_found(client, monkeypatch):
    async def fake_check(url):
        return {"status": "ok", "reports": [], "coverage_note": "No reports visible.", "text": "", "url": url, "platform": "hackerone"}
    monkeypatch.setattr(main, "check_disclosed_reports", fake_check)

    resp = client.post("/api/scan/wizard/check-disclosed-reports", data={"url": "https://hackerone.com/acme"})

    assert resp.status_code == 200
    assert "No disclosed reports found" in resp.text


def test_wizard_check_disclosed_reports_route_shows_the_error_message(client, monkeypatch):
    async def fake_check(url):
        return {"status": "error", "error": "Checking disclosed reports is currently only supported for HackerOne, Bugcrowd, or YesWeHack program URLs."}
    monkeypatch.setattr(main, "check_disclosed_reports", fake_check)

    resp = client.post("/api/scan/wizard/check-disclosed-reports", data={"url": "https://example.com/some-program"})

    assert resp.status_code == 200  # htmx only swaps on 2xx, same convention as the other wizard routes
    assert "only supported for HackerOne" in resp.text


def test_wizard_import_program_route_prefills_ua_snippet_field(client, monkeypatch):
    """user_agent_snippet is NOT one of _WIZARD_FORM_FIELDS (it has no name= on the real form at
    all) -- confirms main.py's _wizard_form_response still routes it into the template's own
    separate ua_snippet context var, prefilling the "Merge into my browser's UA" input."""
    async def fake_analyze(url):
        return {
            "status": "ok", "name": "Acme", "target": "api.acme.com", "out_of_scope": "",
            "qualifying_vulnerabilities": "", "non_qualifying_vulnerabilities": "",
            "custom_instructions": "", "custom_user_agent": "",
            "user_agent_snippet": "bug-bounty-YOUR_HANDLE", "custom_headers": "",
        }
    monkeypatch.setattr(main, "analyze_bugbounty_program", fake_analyze)

    resp = client.post("/api/scan/wizard/import-program", data={"url": "https://yeswehack.com/programs/acme"})
    assert resp.status_code == 200
    assert 'value="bug-bounty-YOUR_HANDLE"' in resp.text
    assert "Auto-merged" in resp.text and "YOUR_HANDLE" in resp.text  # the reminder hint rendered too


def test_wizard_import_program_route_surfaces_error_without_losing_url(client, monkeypatch):
    async def fake_analyze(url):
        return {"status": "error", "error": "Couldn't open that page: timeout"}
    monkeypatch.setattr(main, "analyze_bugbounty_program", fake_analyze)

    resp = client.post("/api/scan/wizard/import-program", data={"url": "https://slow.example/program"})
    assert resp.status_code == 200
    assert "Couldn" in resp.text  # the real error message made it into the re-rendered form


# --- _run_extraction_with_reserve_chain (reserve-chain retry on an all-blank/failed extraction) ---
#
# Real, confirmed incident this fixes: a real HackerOne program page (redox_bbp) was fetched
# correctly TWICE, byte-for-byte the same real scope table both times, sent to the same model both
# times -- one run produced a complete correct extraction, the other silently returned an all-blank
# JSON shell with no error at all. Previously indistinguishable from a genuinely scope-less page,
# and nothing retried it, not even on the same provider.


def _blank_bugbounty_json() -> str:
    return json.dumps({
        "name": "", "target": "", "out_of_scope": "", "qualifying_vulnerabilities": "",
        "non_qualifying_vulnerabilities": "", "custom_instructions": "",
        "custom_user_agent": "", "user_agent_snippet": "", "custom_headers": "",
    })


def test_reserve_chain_retries_after_an_all_blank_first_result(monkeypatch):
    good_json = json.dumps({
        "name": "Redox — HackerOne", "target": "testapp.redoxengine.com", "out_of_scope": "",
        "qualifying_vulnerabilities": "", "non_qualifying_vulnerabilities": "",
        "custom_instructions": "", "custom_user_agent": "", "user_agent_snippet": "", "custom_headers": "",
    })
    reserve_llm = _FakeLLM(good_json)
    reserve_llm.provider_id, reserve_llm.model = "reserve-provider", "reserve-model"

    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(_blank_bugbounty_json()))
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain", lambda: [{"provider": "reserve-provider", "model": "reserve-model"}])
    monkeypatch.setattr(bugbounty_import, "get_next_chain_step", lambda chain, tried: reserve_llm if ("reserve-provider", "reserve-model") not in tried else None)

    parsed, error = _run(bugbounty_import._run_extraction_with_reserve_chain([{"role": "user", "content": "x"}]))
    assert error is None
    assert parsed["target"] == "testapp.redoxengine.com"


def test_reserve_chain_not_consulted_when_disabled(monkeypatch):
    """Off by default (Settings -> Reserve providers) -- an all-blank result must fail immediately,
    never silently try a second (possibly paid) provider the operator never opted into for this."""
    calls = []
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: calls.append((provider, model)) or _FakeLLM(_blank_bugbounty_json()))
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain_enabled", lambda: False)

    parsed, error = _run(bugbounty_import._run_extraction_with_reserve_chain([{"role": "user", "content": "x"}]))
    assert parsed is None
    assert error is not None
    assert len(calls) == 1  # never asked for a second provider


def test_reserve_chain_retries_after_a_raised_exception_too(monkeypatch):
    """Not just an all-blank result -- a real provider failure (rate limit, auth, connection drop)
    is exactly the "problems with the model" case the reserve chain exists for."""
    good_json = json.dumps({"name": "Acme", "target": "api.acme.com", "out_of_scope": "",
                             "qualifying_vulnerabilities": "", "non_qualifying_vulnerabilities": "",
                             "custom_instructions": "", "custom_user_agent": "", "user_agent_snippet": "", "custom_headers": ""})
    reserve_llm = _FakeLLM(good_json)
    reserve_llm.provider_id, reserve_llm.model = "reserve-provider", "reserve-model"

    class _RaisingLLM:
        provider_id = "primary"
        model = "primary-model"
        def complete(self, messages, tools=None, stop_check=None):
            raise RuntimeError("provider is down")

    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _RaisingLLM())
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain", lambda: [{"provider": "reserve-provider", "model": "reserve-model"}])
    monkeypatch.setattr(bugbounty_import, "get_next_chain_step", lambda chain, tried: reserve_llm if ("reserve-provider", "reserve-model") not in tried else None)

    parsed, error = _run(bugbounty_import._run_extraction_with_reserve_chain([{"role": "user", "content": "x"}]))
    assert error is None
    assert parsed["target"] == "api.acme.com"


def test_reserve_chain_exhausted_returns_the_last_error(monkeypatch):
    def make_blank_reserve_llm():
        llm = _FakeLLM(_blank_bugbounty_json())
        llm.provider_id, llm.model = "reserve-provider", "reserve-model"  # must match the chain
        # entry below, or the helper's own tried_steps set never records this step's real identity
        # and the retry loop never terminates (the real bug an earlier draft of this test had).
        return llm

    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(_blank_bugbounty_json()))
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain", lambda: [{"provider": "reserve-provider", "model": "reserve-model"}])
    # Every step, including the one reserve entry, comes back blank -- get_next_chain_step must
    # eventually report nothing left once that single reserve step is also in tried_steps.
    monkeypatch.setattr(bugbounty_import, "get_next_chain_step", lambda chain, tried: (
        make_blank_reserve_llm() if ("reserve-provider", "reserve-model") not in tried else None
    ))

    parsed, error = _run(bugbounty_import._run_extraction_with_reserve_chain([{"role": "user", "content": "x"}]))
    assert parsed is None
    assert error is not None


def test_analyze_bugbounty_program_recovers_via_reserve_chain_end_to_end(monkeypatch):
    """Integration-level proof the wiring in analyze_bugbounty_program itself (not just the helper
    in isolation) actually reaches the reserve chain on a real all-blank first attempt."""
    async def fake_fetch(url):
        return {"status": "ok", "text": "a real scope table with real hosts in it", "title": "t", "url": url}

    good_json = json.dumps({
        "name": "Redox — HackerOne", "target": "testapp.redoxengine.com, 10x.redoxengine.com",
        "out_of_scope": "", "qualifying_vulnerabilities": "", "non_qualifying_vulnerabilities": "",
        "custom_instructions": "", "custom_user_agent": "", "user_agent_snippet": "", "custom_headers": "",
    })
    reserve_llm = _FakeLLM(good_json)
    reserve_llm.provider_id, reserve_llm.model = "reserve-provider", "reserve-model"

    monkeypatch.setattr(bugbounty_import, "_fetch_program_page_text", fake_fetch)
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(_blank_bugbounty_json()))
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(bugbounty_import, "get_fallback_chain", lambda: [{"provider": "reserve-provider", "model": "reserve-model"}])
    monkeypatch.setattr(bugbounty_import, "get_next_chain_step", lambda chain, tried: reserve_llm if ("reserve-provider", "reserve-model") not in tried else None)

    result = _run(bugbounty_import.analyze_bugbounty_program("https://hackerone.com/redox_bbp?type=team"))
    assert result["status"] == "ok"
    assert result["name"] == "Redox — HackerOne"
    assert "testapp.redoxengine.com" in result["target"]


# --- refresh_program_check (session["program_url"]'s own periodic freshness/disclosed-reports cache) --
# Reads via _fetch_disclosed_reports_text (raw fetch only, no LLM) -- never mocks get_provider,
# confirming the background cache refresh genuinely never pays for check_disclosed_reports's own
# separate LLM-summarization pass.


def _blank_program_check():
    return {"last_checked": None, "last_error": None, "disclosed_reports_text": "", "disclosed_reports_checked_at": None}


def test_refresh_program_check_fetches_disclosed_reports_for_a_hackerone_url(monkeypatch):
    session_id = "usr_refresh_hackerone"
    store.save_session(session_id, {"session_id": session_id, "program_url": "https://hackerone.com/acme", "program_check": _blank_program_check()})
    fake_manager = _FakeBrowserManager({"https://hackerone.com/acme/hacktivity": {"text": "XSS in login - resolved", "title": "Acme Hacktivity"}})
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    _run(bugbounty_import.refresh_program_check(session_id, "https://hackerone.com/acme"))

    saved = store.load_session(session_id)["program_check"]
    assert saved["disclosed_reports_text"] == "XSS in login - resolved"
    assert saved["last_checked"] is not None
    assert saved["disclosed_reports_checked_at"] is not None
    assert saved["last_error"] is None


def test_refresh_program_check_fetches_disclosed_reports_for_a_bugcrowd_url(monkeypatch):
    session_id = "usr_refresh_bugcrowd"
    store.save_session(session_id, {"session_id": session_id, "program_url": "https://bugcrowd.com/tesla", "program_check": _blank_program_check()})
    fake_manager = _FakeBrowserManager({"https://bugcrowd.com/engagements/tesla/crowdstream": {"text": "SQLi report", "title": "Tesla CrowdStream"}})
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    _run(bugbounty_import.refresh_program_check(session_id, "https://bugcrowd.com/tesla"))

    saved = store.load_session(session_id)["program_check"]
    assert saved["disclosed_reports_text"] == "SQLi report"
    assert saved["last_error"] is None


def test_refresh_program_check_is_a_no_op_within_the_ttl(monkeypatch):
    session_id = "usr_refresh_ttl_noop"
    recent = datetime.now(timezone.utc).isoformat()
    store.save_session(session_id, {
        "session_id": session_id, "program_url": "https://hackerone.com/acme",
        "program_check": {"last_checked": recent, "last_error": None, "disclosed_reports_text": "old text", "disclosed_reports_checked_at": recent},
    })
    fake_manager = _FakeBrowserManager({"https://hackerone.com/acme/hacktivity": {"text": "fresh text", "title": "Acme"}})
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)

    _run(bugbounty_import.refresh_program_check(session_id, "https://hackerone.com/acme"))

    assert fake_manager.navigated == []  # never fetched -- still within the TTL
    assert store.load_session(session_id)["program_check"]["disclosed_reports_text"] == "old text"


def test_refresh_program_check_force_bypasses_the_ttl(monkeypatch):
    session_id = "usr_refresh_force"
    recent = datetime.now(timezone.utc).isoformat()
    store.save_session(session_id, {
        "session_id": session_id, "program_url": "https://hackerone.com/acme",
        "program_check": {"last_checked": recent, "last_error": None, "disclosed_reports_text": "old text", "disclosed_reports_checked_at": recent},
    })
    fake_manager = _FakeBrowserManager({"https://hackerone.com/acme/hacktivity": {"text": "fresh text", "title": "Acme"}})
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    _run(bugbounty_import.refresh_program_check(session_id, "https://hackerone.com/acme", force=True))

    assert store.load_session(session_id)["program_check"]["disclosed_reports_text"] == "fresh text"


def test_refresh_program_check_records_a_failed_disclosed_reports_fetch(monkeypatch):
    session_id = "usr_refresh_failure"
    store.save_session(session_id, {"session_id": session_id, "program_url": "https://hackerone.com/acme", "program_check": _blank_program_check()})
    fake_manager = _FakeBrowserManager({})  # nothing mocked -- navigate() reports "no such page"
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    _run(bugbounty_import.refresh_program_check(session_id, "https://hackerone.com/acme"))

    saved = store.load_session(session_id)["program_check"]
    assert saved["disclosed_reports_text"] == ""
    assert saved["last_error"] is not None
    assert saved["last_checked"] is not None  # the attempt itself is still recorded


def test_refresh_program_check_unsupported_platform_only_checks_reachability(monkeypatch):
    session_id = "usr_refresh_unsupported"
    store.save_session(session_id, {"session_id": session_id, "program_url": "https://example.com/some-program", "program_check": _blank_program_check()})
    fake_manager = _FakeBrowserManager({"https://example.com/some-program": {"text": "program page", "title": "Acme"}})
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)
    monkeypatch.setattr(bugbounty_import, "_RENDER_SETTLE_SECONDS", 0)

    _run(bugbounty_import.refresh_program_check(session_id, "https://example.com/some-program"))

    saved = store.load_session(session_id)["program_check"]
    assert saved["last_checked"] is not None
    assert saved["disclosed_reports_text"] == ""  # never maintained for an unsupported platform
    assert saved["last_error"] is None


def test_refresh_program_check_is_a_no_op_for_a_vanished_session(monkeypatch):
    """The session was deleted between the phase hook deciding to refresh and this actually
    running (a real, if narrow, race) -- must not raise."""
    fake_manager = _FakeBrowserManager({})
    monkeypatch.setattr(bugbounty_import, "get_browser_manager", lambda: fake_manager)

    _run(bugbounty_import.refresh_program_check("usr_does_not_exist_at_all", "https://hackerone.com/acme"))
    # no assertion needed beyond "did not raise"


# --- match_finding_against_disclosed_reports (agent/core.py's _persist_new_finding duplicate check) ----


def test_match_finding_against_disclosed_reports_returns_false_for_empty_feed_text():
    result = _run(bugbounty_import.match_finding_against_disclosed_reports("", "SQL Injection in login", "desc"))
    assert result == {"is_duplicate": False}


def test_match_finding_against_disclosed_reports_returns_false_for_empty_title():
    result = _run(bugbounty_import.match_finding_against_disclosed_reports("some hacktivity text", "", "desc"))
    assert result == {"is_duplicate": False}


def test_match_finding_against_disclosed_reports_reports_a_confident_match(monkeypatch):
    llm_json = json.dumps({"is_duplicate": True, "matched_title": "Persistent XSS via profile comments", "confidence": "high"})
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.match_finding_against_disclosed_reports(
        "Persistent XSS via profile comments - $500 - resolved", "Stored XSS in comment field", "An attacker can inject a script tag.",
    ))

    assert result == {"is_duplicate": True, "matched_title": "Persistent XSS via profile comments", "confidence": "high"}


def test_match_finding_against_disclosed_reports_no_match_found(monkeypatch):
    llm_json = json.dumps({"is_duplicate": False, "matched_title": "", "confidence": "low"})
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.match_finding_against_disclosed_reports("unrelated report titles here", "Open redirect on logout", "desc"))

    assert result == {"is_duplicate": False}


def test_match_finding_against_disclosed_reports_defaults_an_unrecognized_confidence_to_low(monkeypatch):
    llm_json = json.dumps({"is_duplicate": True, "matched_title": "Some report", "confidence": "extremely sure"})
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM(llm_json))

    result = _run(bugbounty_import.match_finding_against_disclosed_reports("some text", "Candidate finding", "desc"))

    assert result["confidence"] == "low"


def test_match_finding_against_disclosed_reports_never_raises_on_a_provider_error(monkeypatch):
    def _raise(provider, model):
        raise RuntimeError("no provider configured")
    monkeypatch.setattr(bugbounty_import, "get_provider", _raise)

    result = _run(bugbounty_import.match_finding_against_disclosed_reports("some text", "Candidate finding", "desc"))

    assert result == {"is_duplicate": False}


def test_match_finding_against_disclosed_reports_never_raises_on_unparseable_llm_output(monkeypatch):
    monkeypatch.setattr(bugbounty_import, "get_provider", lambda provider, model: _FakeLLM("not json at all"))

    result = _run(bugbounty_import.match_finding_against_disclosed_reports("some text", "Candidate finding", "desc"))

    assert result == {"is_duplicate": False}
