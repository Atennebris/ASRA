"""The browser_* tool suite: agent/core.py's _dispatch_tool/_dispatch_browser_tool bypass (same
shape as delegate_to_subagent -- a Playwright browser session must stay on the event loop that
created it, never routed through asyncio.to_thread), the _run_tool_with_retry server-side
_session_id/_session injection those 9 tools rely on, and agent/tools/browser_manager.py's
BrowserSessionManager itself. Never drives a real Chromium -- every test here is mocked at the
manager/Playwright-object boundary, same project-wide convention as every other test suite.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY with the browser_* tools)
import agent.core as core
from agent.core import RunContext, _BROWSER_TOOL_NAMES, _dispatch_tool, _run_tool_with_retry
from agent.tools.browser_manager import BrowserSessionManager, _loopback_or_link_local
from agent.tools.browser_stealth import STEALTH_INIT_SCRIPT
from agent.tools.registry import ToolSpec, get_tool, get_tools_by_category


def _run(coro):
    return asyncio.run(coro)


def _session(session_id="usr_browser_test", out_of_scope=None):
    return {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "hypotheses": [], "approvals": [],
        "chat": {"summary": "", "messages": []}, "out_of_scope": out_of_scope or [],
    }


# --- registration: all 9 tools exist, in every phase category -------------------------------


def test_all_nine_browser_tools_are_registered():
    for name in _BROWSER_TOOL_NAMES:
        assert get_tool(name) is not None, name


def test_browser_tools_appear_in_recon_scan_and_exploit_categories():
    for category in ("recon", "scan", "exploit"):
        names_in_category = {spec.name for spec in get_tools_by_category(category)}
        missing = _BROWSER_TOOL_NAMES - names_in_category
        assert not missing, f"{category} is missing: {missing}"


# --- _dispatch_tool: bypasses to_thread/run_tool, same as delegate_to_subagent --------------


def test_dispatch_tool_routes_every_browser_name_to_the_async_bypass(monkeypatch):
    calls = []

    async def fake_dispatch_browser_tool(name, arguments):
        calls.append((name, arguments))
        return {"status": "ok"}

    async def fail_if_called(*args, **kwargs):
        raise AssertionError("run_tool must never be reached for a browser_* tool")

    monkeypatch.setattr(core, "_dispatch_browser_tool", fake_dispatch_browser_tool)
    monkeypatch.setattr(core, "run_tool", fail_if_called)

    for name in _BROWSER_TOOL_NAMES:
        spec = ToolSpec(
            name=name, category="scan", tool_tier=1, executable="", build_command=None,
            requires_allowed_target=False, installed_by_default=True,
            native_function=lambda p: {"status": "error", "error": "must never actually run"},
        )
        result = _run(_dispatch_tool(spec, {"_session_id": "usr_x"}))
        assert result == {"status": "ok"}

    assert {name for name, _ in calls} == _BROWSER_TOOL_NAMES


def test_dispatch_browser_tool_routes_navigate_arguments_to_the_manager(monkeypatch):
    captured = {}

    class _FakeManager:
        async def navigate(self, session_id, target, wait_until, out_of_scope_entries, identity):
            captured["args"] = (session_id, target, wait_until, out_of_scope_entries, identity)
            return {"status": "ok"}

    monkeypatch.setattr(core, "get_browser_manager", lambda: _FakeManager())

    result = _run(core._dispatch_browser_tool(
        "browser_navigate",
        {
            "target": "https://example.com/", "wait_until": "networkidle", "identity": "user_a",
            "_session_id": "usr_nav", "_session": {"out_of_scope": ["evil.com"]},
        },
    ))

    assert result == {"status": "ok"}
    assert captured["args"] == ("usr_nav", "https://example.com/", "networkidle", ["evil.com"], "user_a")


def test_dispatch_browser_tool_navigate_defaults_wait_until_to_domcontentloaded_not_load(monkeypatch):
    """Real, confirmed incident: with the old default (wait_until="load"), a
    Cloudflare/bot-challenge-fronted site (platform.openai.com, openai.com's own apex) never fires
    "load" at all, burning a full BROWSER_ACTION_TIMEOUT_SECONDS timeout + a wasted LLM retry
    round-trip every time the model omitted wait_until -- 4 separate times in one real session."""
    captured = {}

    class _FakeManager:
        async def navigate(self, session_id, target, wait_until, out_of_scope_entries, identity):
            captured["wait_until"] = wait_until
            return {"status": "ok"}

    monkeypatch.setattr(core, "get_browser_manager", lambda: _FakeManager())

    _run(core._dispatch_browser_tool("browser_navigate", {"target": "https://example.com/", "_session_id": "usr_nav"}))

    assert captured["wait_until"] == "domcontentloaded"


def test_dispatch_browser_tool_close_session_calls_manager_and_returns_ok(monkeypatch):
    closed = []

    class _FakeManager:
        async def close_session(self, session_id):
            closed.append(session_id)

    monkeypatch.setattr(core, "get_browser_manager", lambda: _FakeManager())

    result = _run(core._dispatch_browser_tool("browser_close_session", {"_session_id": "usr_close"}))

    assert result == {"status": "ok"}
    assert closed == ["usr_close"]


# --- _run_tool_with_retry: server-side _session_id/_session injection -----------------------


def test_run_tool_with_retry_injects_session_id_and_session_for_every_browser_tool(monkeypatch):
    session = _session()
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    captured = []

    async def fake_dispatch_browser_tool(name, arguments):
        captured.append((name, arguments.get("_session_id"), arguments.get("_session")))
        return {"status": "ok"}

    monkeypatch.setattr(core, "_dispatch_browser_tool", fake_dispatch_browser_tool)

    for name in _BROWSER_TOOL_NAMES:
        spec = get_tool(name)
        arguments = {"target": "https://example.com/"} if name == "browser_navigate" else {}
        _run(_run_tool_with_retry(ctx, spec, arguments))

    assert len(captured) == len(_BROWSER_TOOL_NAMES)
    for _, session_id, injected_session in captured:
        assert session_id == "usr_browser_test"
        assert injected_session is session  # the SAME live object, not a copy


def test_run_tool_with_retry_lets_the_model_never_see_or_override_session_id(monkeypatch):
    """The model could try to pass its own _session_id -- server-side injection must win, since
    a wrong/malicious value would let a session read another session's browser context."""
    session = _session()
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    captured = {}

    async def fake_dispatch_browser_tool(name, arguments):
        captured["session_id"] = arguments.get("_session_id")
        return {"status": "ok"}

    monkeypatch.setattr(core, "_dispatch_browser_tool", fake_dispatch_browser_tool)

    _run(_run_tool_with_retry(ctx, get_tool("browser_snapshot"), {"_session_id": "usr_spoofed"}))

    assert captured["session_id"] == "usr_browser_test"


# --- BrowserSessionManager: mocked at the Playwright-object boundary ------------------------


class _FakePage:
    """Implements only the subset of Playwright's Page API browser_manager.py actually calls --
    enough to exercise navigate/click/evaluate/_bundle's own logic without a real browser."""

    def __init__(self, url="https://example.com/"):
        self.url = url
        self._title = "Fake Page"
        self.evaluate_calls = []
        self.go_back_called = False
        self.keyboard = self._Keyboard()
        self.mouse = self._Mouse()
        self.viewport_size = {"width": 1280, "height": 720}

    class _Mouse:
        """Mirrors Playwright's real Mouse.move(x, y)/Mouse.wheel(delta_x, delta_y) signatures --
        used by browser_manager.py's mouse_wheel_scroll (agent/tools/bugbounty_import.py's own
        HackerOne scope-table scroll-harvest relies on this being a REAL, CDP-trusted input event,
        confirmed live that a programmatic element.scrollTop assignment does not trigger the same
        re-render at all)."""

        def __init__(self):
            self.moves = []
            self.wheels = []

        async def move(self, x, y):
            self.moves.append((x, y))

        async def wheel(self, delta_x, delta_y):
            self.wheels.append((delta_x, delta_y))

    class _Keyboard:
        """Mirrors Playwright's REAL Keyboard.press(key, delay=None) signature exactly -- no
        timeout= kwarg (that only exists on Locator/Page action methods, which wait for an element
        to become actionable; Keyboard has no target element to wait on at all). Confirmed live: a
        real press_key call crashed every single time with "press() got an unexpected keyword
        argument 'timeout'" because browser_manager.py's own press_key called
        page.keyboard.press(key, timeout=...) -- this fake would raise the identical TypeError if
        that bug ever came back, unlike a fake that silently accepts **kwargs and hides it."""

        def __init__(self):
            self.pressed = []

        async def press(self, key, delay=None):
            self.pressed.append(key)

    def on(self, event, handler):
        # get_or_create_context wires up console/pageerror/dialog/request listeners on every real
        # page it creates -- a no-op here is enough for tests that only care about the CONTEXT's
        # own wiring (stealth init-script ordering, user_agent), not these specific events.
        pass

    class _Locator:
        def __init__(self, page):
            self._page = page

        async def aria_snapshot(self, mode="default", timeout=None):
            return '- button "Click me" [ref=e1]'

        async def click(self, timeout=None):
            pass

        async def fill(self, text, timeout=None):
            pass

    def locator(self, selector):
        return self._Locator(self)

    async def title(self):
        return self._title

    async def goto(self, url, wait_until="load", timeout=None):
        self.url = url

        class _Response:
            status = 200
        return _Response()

    async def evaluate(self, expression):
        self.evaluate_calls.append(expression)
        return {"ok": True}

    async def go_back(self, timeout=None):
        self.go_back_called = True


class _FailingLocator:
    """Mirrors Playwright's real failure shape for a selector matching nothing -- e.g. "body" on a
    frameset-based document, which has no <body> element at all."""

    def __init__(self, selector):
        self._selector = selector

    async def aria_snapshot(self, mode="default", timeout=None):
        raise Exception(f'Selector "{self._selector}" does not match any element')


class _FrameStub:
    def __init__(self, url):
        self.url = url


class _NoAccessibleContentPage(_FakePage):
    """Both "body" and "html" locators fail -- the shape of a page with no real accessible content
    on its own top-level document at all (a frameset with no top-level body/html snapshot content,
    or a canvas-only client). `frames` mirrors Playwright's real Page.frames property."""

    def __init__(self, url="https://example.com/", frames=None):
        super().__init__(url=url)
        self.frames = frames or []

    def locator(self, selector):
        return _FailingLocator(selector)


class _HtmlOnlyPage(_FakePage):
    """"body" fails, "html" succeeds -- the fallback locator alone is enough to recover a real
    snapshot without needing the frame/canvas hint at all."""

    def locator(self, selector):
        if selector == "body":
            return _FailingLocator(selector)
        return self._Locator(self)


def test_bundle_falls_back_to_the_html_locator_when_body_is_absent():
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _HtmlOnlyPage(url="https://example.com/oldschool.html")
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.snapshot("usr1"))

    assert result["status"] == "ok"
    assert result["snapshot"] == '- button "Click me" [ref=e1]'


def test_bundle_lists_real_frame_urls_when_the_page_is_a_frameset():
    """Real, confirmed incident this fixes: a browser MMORPG's own in-game screen returned
    "Selector "body" does not match any element" with no fallback at all -- the agent had no way to
    discover anything inside the game and gave up on browser interaction entirely. A frameset's own
    child frames are real, independently navigable documents -- the fix hands their URLs back
    instead of an opaque exception string."""
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _NoAccessibleContentPage(
        url="https://example.com/game.php",
        frames=[
            _FrameStub("https://example.com/game.php"),  # the top frame itself -- must be excluded
            _FrameStub("about:blank"),  # never a real frame -- must be excluded
            _FrameStub("https://example.com/main_frame.php"),
        ],
    )
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.snapshot("usr1"))

    assert result["status"] == "ok"
    assert "https://example.com/main_frame.php" in result["snapshot"]
    assert result["snapshot"].count("example.com/game.php") == 0


def test_bundle_hints_at_a_canvas_client_when_there_are_no_frames_either():
    """No frames at all means the top-level document itself is the whole page -- most likely a
    canvas-rendered client (a game, a chart) with no real accessible DOM. The hint must point the
    model at a concrete next move (JS reverse-engineering), not just repeat the raw exception."""
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _NoAccessibleContentPage(url="https://example.com/game.php", frames=[])
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.snapshot("usr1"))

    assert result["status"] == "ok"
    assert "canvas" in result["snapshot"]
    assert "js_bundle_scan" in result["snapshot"]


def test_bundle_returns_out_of_scope_and_stops_when_the_page_drifted():
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _FakePage(url="https://evil.com/")
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.snapshot("usr1", out_of_scope_entries=["evil.com"]))

    assert result["status"] == "out_of_scope"
    assert result["url"] == "https://evil.com/"


def test_bundle_blocks_a_page_that_drifted_to_a_loopback_address():
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _FakePage(url="http://127.0.0.1:8000/admin")
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.snapshot("usr1"))

    assert result["status"] == "out_of_scope"


def test_bundle_ok_when_in_scope_and_drains_console_network_buffers_in_place():
    """Real, confirmed bug this guards against: the FIRST version of _bundle rebound
    self._console_buffers[session_id] = [] instead of clearing the existing list in place --
    since the page.on(...) closures captured the ORIGINAL list object by reference, every event
    after the first drain silently landed in an orphaned list nothing read again."""
    manager = BrowserSessionManager()
    console_buffer = [{"type": "log", "text": "hello"}]
    network_buffer = [{"method": "GET", "url": "https://example.com/api", "resource_type": "fetch"}]
    manager._pages["usr1"] = _FakePage()
    manager._console_buffers["usr1"] = console_buffer
    manager._network_buffers["usr1"] = network_buffer

    result = _run(manager.snapshot("usr1"))

    assert result["status"] == "ok"
    assert result["console_since_last"] == [{"type": "log", "text": "hello"}]
    assert result["network_since_last"][0]["url"] == "https://example.com/api"
    # Drained in place (.clear()), not rebound -- the SAME list objects (still referenced by
    # manager._console_buffers/_network_buffers) must now be empty, proving future events
    # appended by page.on(...) closures (which hold this exact reference) will still be seen.
    assert console_buffer == []
    assert network_buffer == []
    assert manager._console_buffers["usr1"] is console_buffer
    assert manager._network_buffers["usr1"] is network_buffer


def test_navigate_rejects_a_loopback_target_before_ever_opening_a_context():
    manager = BrowserSessionManager()
    result = _run(manager.navigate("usr1", "http://127.0.0.1:9999/"))
    assert result["status"] == "error"
    assert "loopback" in result["error"]
    assert "usr1" not in manager._pages  # never consumed a concurrency slot for a rejected target


class _RecordingIdentityContext:
    """Implements only the subset of Playwright's BrowserContext API _apply_identity actually
    calls -- enough to prove cookies/headers are swapped BEFORE navigating, without a real browser."""

    def __init__(self):
        self.cleared = False
        self.cookies_added = None
        self.headers_set = None

    async def clear_cookies(self):
        self.cleared = True

    async def add_cookies(self, cookies):
        self.cookies_added = cookies

    async def set_extra_http_headers(self, headers):
        self.headers_set = headers


def test_navigate_with_identity_swaps_cookies_and_headers_before_navigating(monkeypatch):
    """The role-diff workflow this exists for: browser_navigate(identity="user_a") must apply that
    identity's real logged-in cookies/headers -- reusing the SAME server-side login
    authenticated_request/idor_probe already use (get_identity_browser_creds), never a credential
    the model ever sees -- BEFORE the actual page.goto(), so the navigation itself is authenticated."""
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(
        bm, "get_identity_browser_creds",
        lambda session_id, identity: {
            "status": "ok",
            "cookies": [{"name": "sessionid", "value": "abc123", "domain": "example.com", "path": "/", "expires": -1, "secure": False}],
            "headers": {"Authorization": "Bearer tok123"},
        },
    )
    manager = BrowserSessionManager()
    page = _FakePage(url="about:blank")
    context = _RecordingIdentityContext()
    manager._pages["usr1"] = page
    manager._contexts["usr1"] = context
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.navigate("usr1", "https://example.com/dashboard", identity="user_a"))

    assert result["status"] == "ok"
    assert context.cleared is True  # never mixes a previous identity's cookies into the new one
    assert context.cookies_added == [{"name": "sessionid", "value": "abc123", "domain": "example.com", "path": "/", "expires": -1, "secure": False}]
    assert context.headers_set == {"Authorization": "Bearer tok123"}
    assert page.url == "https://example.com/dashboard"  # goto() ran AFTER the identity was applied


def test_navigate_with_an_unconfigured_identity_errors_without_ever_navigating(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(
        bm, "get_identity_browser_creds",
        lambda session_id, identity: {"status": "error", "error": "no credentials configured for identity 'user_a' -- permanent for this project"},
    )
    manager = BrowserSessionManager()
    page = _FakePage(url="about:blank")
    context = _RecordingIdentityContext()
    manager._pages["usr1"] = page
    manager._contexts["usr1"] = context

    result = _run(manager.navigate("usr1", "https://example.com/dashboard", identity="user_a"))

    assert result["status"] == "error"
    assert "user_a" in result["error"]
    assert context.cleared is False  # the lookup failed before any cookie swap was attempted
    assert page.url == "about:blank"  # goto() never ran


def test_interpret_browser_navigate_permanent_failure_matches_missing_identity():
    from agent.core import _PERMANENT_ERROR_HINTS
    from agent.tools.browser_manager import interpret_browser_navigate_permanent_failure

    result = {"status": "error", "error": "No credentials configured for identity 'user_a' on this project -- this is a permanent, deterministic condition for this project for the rest of this session, ..."}
    assert interpret_browser_navigate_permanent_failure(result) == result["error"]
    assert _PERMANENT_ERROR_HINTS["browser_navigate"] is interpret_browser_navigate_permanent_failure


def test_interpret_browser_navigate_permanent_failure_matches_a_download_triggering_url():
    """Real, confirmed incident this fixes (a real HackerOne rescan session): a .js.map URL made
    Chromium raise "Page.goto: Download is starting" instead of rendering a page -- retrying the
    identical URL fails identically every time, and a blind corrected retry once hallucinated an
    unrelated `identity` argument chasing this exact failure, triggering the sibling bug above."""
    from agent.tools.browser_manager import interpret_browser_navigate_permanent_failure

    result = {"status": "error", "error": "navigation to 'https://example.com/app.js.map' failed: Page.goto: Download is starting"}
    hint = interpret_browser_navigate_permanent_failure(result)
    assert hint is not None
    assert "http_request" in hint


def test_interpret_browser_navigate_permanent_failure_ignores_unrelated_errors():
    from agent.tools.browser_manager import interpret_browser_navigate_permanent_failure

    assert interpret_browser_navigate_permanent_failure({"status": "error", "error": "navigation to 'https://example.com/' failed: net::ERR_CONNECTION_REFUSED"}) is None
    assert interpret_browser_navigate_permanent_failure({"status": "ok"}) is None


def test_navigate_without_identity_never_touches_the_context_at_all(monkeypatch):
    """Omitting identity (every pre-existing browser_navigate call) must be a complete no-op on
    this path -- get_identity_browser_creds must never even be called."""
    import agent.tools.browser_manager as bm

    def _fail_if_called(session_id, identity):
        raise AssertionError("get_identity_browser_creds must not be called when identity is omitted")

    monkeypatch.setattr(bm, "get_identity_browser_creds", _fail_if_called)
    manager = BrowserSessionManager()
    page = _FakePage(url="about:blank")
    context = _RecordingIdentityContext()
    manager._pages["usr1"] = page
    manager._contexts["usr1"] = context
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.navigate("usr1", "https://example.com/"))

    assert result["status"] == "ok"
    assert context.cleared is False


def test_click_reports_a_clear_error_when_no_session_is_open():
    manager = BrowserSessionManager()
    result = _run(manager.click("usr_never_opened", "e3"))
    assert result["status"] == "error"
    assert "browser_navigate" in result["error"]


def test_press_key_reports_a_clear_error_when_no_session_is_open():
    manager = BrowserSessionManager()
    result = _run(manager.press_key("usr_never_opened", "Enter"))
    assert result["status"] == "error"
    assert "browser_navigate" in result["error"]


def test_press_key_calls_the_real_keyboard_api_and_succeeds():
    """Regression test for a real, confirmed-live bug: press_key used to call
    page.keyboard.press(key, timeout=...) -- Keyboard.press has no timeout parameter (it's not a
    Locator/Page action, it never waits on an element), so every real press_key call crashed
    outright with a TypeError, every single time, from the very first use. _FakePage.keyboard
    mirrors Playwright's real signature exactly, so this test fails the same way the real tool did
    if that extra kwarg is ever reintroduced."""
    manager = BrowserSessionManager()
    page = _FakePage()
    manager._pages["usr1"] = page
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.press_key("usr1", "Enter"))

    assert result["status"] == "ok"
    assert page.keyboard.pressed == ["Enter"]


def test_mouse_wheel_scroll_reports_a_clear_error_when_no_session_is_open():
    manager = BrowserSessionManager()
    result = _run(manager.mouse_wheel_scroll("usr_never_opened", 900))
    assert result["status"] == "error"
    assert "browser_navigate" in result["error"]


def test_mouse_wheel_scroll_moves_to_viewport_center_then_wheels():
    """agent/tools/bugbounty_import.py's own scroll-harvest depends on this being a genuine,
    CDP-trusted wheel event (confirmed live against a real HackerOne scope table -- a programmatic
    element.scrollTop assignment never triggered its own "load more" re-render at all, only a real
    wheel input did)."""
    manager = BrowserSessionManager()
    page = _FakePage()
    manager._pages["usr1"] = page

    result = _run(manager.mouse_wheel_scroll("usr1", 900))

    assert result == {"status": "ok"}
    assert page.mouse.moves == [(640, 360)]  # viewport {"width": 1280, "height": 720} center
    assert page.mouse.wheels == [(0, 900)]


def test_mouse_wheel_scroll_wraps_a_real_exception_as_an_error():
    class _BrokenMouse:
        async def move(self, x, y):
            raise RuntimeError("CDP connection dropped")

    manager = BrowserSessionManager()
    page = _FakePage()
    page.mouse = _BrokenMouse()
    manager._pages["usr1"] = page

    result = _run(manager.mouse_wheel_scroll("usr1", 900))

    assert result["status"] == "error"
    assert "CDP connection dropped" in result["error"]


def test_evaluate_returns_a_json_safe_result():
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _FakePage()
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []

    result = _run(manager.evaluate("usr1", "1 + 1"))

    assert result["status"] == "ok"
    assert result["eval_result"] == {"ok": True}


def test_close_session_is_idempotent():
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _FakePage()
    manager._console_buffers["usr1"] = []
    manager._network_buffers["usr1"] = []
    manager._last_activity["usr1"] = 0.0

    _run(manager.close_session("usr1"))  # no real context object -- must not raise
    _run(manager.close_session("usr1"))  # already gone -- must still not raise

    assert "usr1" not in manager._pages


def test_get_or_create_context_reports_a_clear_error_when_chromium_is_not_installed(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(bm, "_chromium_installed", lambda: False)
    manager = BrowserSessionManager()

    result = _run(manager.get_or_create_context("usr1"))

    assert result["status"] == "error"
    assert "setup_tools.sh" in result["error"]


def test_get_or_create_context_respects_the_concurrency_cap(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(bm, "_chromium_installed", lambda: True)
    monkeypatch.setenv("BROWSER_MAX_CONCURRENT_CONTEXTS", "1")
    manager = BrowserSessionManager()
    manager._pages["usr_already_open"] = _FakePage()

    result = _run(manager.get_or_create_context("usr_new"))

    assert result["status"] == "skipped"
    assert "usr_new" not in manager._pages


def test_loopback_or_link_local_blocks_loopback_and_metadata_but_not_private_ranges():
    assert _loopback_or_link_local("http://127.0.0.1/") == "127.0.0.1"
    assert _loopback_or_link_local("http://169.254.169.254/latest/meta-data/") == "169.254.169.254"
    assert _loopback_or_link_local("http://10.0.0.5/") is None  # RFC1918 -- a legitimate internal target
    assert _loopback_or_link_local("https://example.com/") is None


async def _idle_reaper_closes_stale_sessions_scenario(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setenv("BROWSER_SESSION_IDLE_TIMEOUT_SECONDS", "0")
    manager = BrowserSessionManager()
    manager._pages["usr_stale"] = _FakePage()
    manager._console_buffers["usr_stale"] = []
    manager._network_buffers["usr_stale"] = []
    manager._last_activity["usr_stale"] = 0.0  # already "expired" the instant the reaper checks

    monkeypatch.setattr(bm, "_IDLE_REAPER_POLL_SECONDS", 0.01)
    task = asyncio.create_task(manager._idle_reaper_loop())
    for _ in range(50):
        await asyncio.sleep(0.01)
        if "usr_stale" not in manager._pages:
            break
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    return manager


def test_idle_reaper_closes_a_session_past_its_timeout(monkeypatch):
    manager = _run(_idle_reaper_closes_stale_sessions_scenario(monkeypatch))
    assert "usr_stale" not in manager._pages


# --- real incident regression: TOOL_TIMEOUT_SECONDS=600 hung an entire agent loop for ~10min ---
# on a single browser_navigate against a slow/bot-challenge page -- browser actions must use their
# own short, independent timeout, never inherit a value tuned for nmap/nuclei-length tool calls.


def test_action_timeout_has_its_own_short_default_independent_of_tool_timeout_seconds(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setenv("TOOL_TIMEOUT_SECONDS", "600")
    monkeypatch.delenv("BROWSER_ACTION_TIMEOUT_SECONDS", raising=False)

    assert bm._action_timeout_ms() == 45_000  # NOT 600_000


def test_action_timeout_is_configurable_via_its_own_env_var(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setenv("BROWSER_ACTION_TIMEOUT_SECONDS", "20")

    assert bm._action_timeout_ms() == 20_000


# --- real incident regression: the shared Browser's driver connection died after a hung
# navigation, and self._browser stayed a stale non-None reference forever afterward -- every
# browser_* call for every session would have silently kept failing for the rest of the server
# process's life, since "not None" was mistaken for "still healthy".


class _FakeDeadBrowser:
    def is_connected(self):
        return False


class _FakeTmpPageForUaDerivation:
    async def evaluate(self, expression):
        return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/149.0.0.0 Safari/537.36"


class _FakeTmpContextForUaDerivation:
    async def new_page(self):
        return _FakeTmpPageForUaDerivation()

    async def close(self):
        pass


class _FakeHealthyBrowser:
    def is_connected(self):
        return True

    async def new_context(self, **kwargs):
        # _ensure_browser's own one-time UA-derivation step (agent/tools/browser_stealth.py)
        # needs a throwaway context+page to read a real navigator.userAgent from.
        return _FakeTmpContextForUaDerivation()


class _FakePlaywrightDriver:
    def __init__(self):
        self.stopped = False

    async def stop(self):
        self.stopped = True

    class _Chromium:
        async def launch(self, headless=True):
            return _FakeHealthyBrowser()

    @property
    def chromium(self):
        return self._Chromium()


def test_ensure_browser_relaunches_when_the_shared_browser_connection_died(monkeypatch):
    # _ensure_browser does `from playwright.async_api import async_playwright` as a LOCAL import
    # (inside the function body, not at module top-level) -- patching the real source module's own
    # name is what a fresh local import picks up on its next call, same as any other lazy import.
    async def fake_async_playwright_start():
        return _FakePlaywrightDriver()

    class _FakeAsyncPlaywrightCtx:
        def start(self):
            return fake_async_playwright_start()

    import playwright.async_api as pw_async_api
    monkeypatch.setattr(pw_async_api, "async_playwright", lambda: _FakeAsyncPlaywrightCtx())

    manager = BrowserSessionManager()
    dead_playwright = _FakePlaywrightDriver()
    manager._playwright = dead_playwright
    manager._browser = _FakeDeadBrowser()

    _run(manager._ensure_browser())

    assert dead_playwright.stopped, "the dead driver must be stopped before relaunching, not just abandoned"
    assert isinstance(manager._browser, _FakeHealthyBrowser)


def test_ensure_browser_reuses_a_still_healthy_browser_without_relaunching():
    manager = BrowserSessionManager()
    healthy = _FakeHealthyBrowser()
    manager._browser = healthy

    _run(manager._ensure_browser())

    assert manager._browser is healthy  # untouched -- no relaunch attempted


# --- stealth wiring: real incident this guards against -- headless Chromium leaked
# navigator.webdriver/plugins/window.chrome/UA by default (live-confirmed this session against
# this repo's own pinned playwright version); get_or_create_context must apply the stealth
# user_agent AND register the init script BEFORE the first page is ever created.


class _RecordingContext:
    def __init__(self):
        self.new_page_calls = 0
        self.init_script_calls: list[str] = []
        self.call_order: list[str] = []

    def set_default_timeout(self, ms):
        pass

    def on(self, event, handler):
        pass

    async def add_init_script(self, script):
        self.init_script_calls.append(script)
        self.call_order.append("add_init_script")

    async def new_page(self):
        self.new_page_calls += 1
        self.call_order.append("new_page")
        return _FakePage()

    async def close(self):
        pass


class _RecordingBrowser:
    def __init__(self):
        self.new_context_kwargs: dict | None = None
        self.created_context: _RecordingContext | None = None

    def is_connected(self):
        return True

    async def new_context(self, **kwargs):
        self.new_context_kwargs = kwargs
        self.created_context = _RecordingContext()
        return self.created_context


def test_get_or_create_context_applies_stealth_user_agent_and_init_script(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(bm, "_chromium_installed", lambda: True)
    manager = BrowserSessionManager()
    manager._browser = _RecordingBrowser()
    manager._stealth_user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.7827.55 Safari/537.36"

    result = _run(manager.get_or_create_context("usr1"))

    assert result["status"] == "ok"
    browser = manager._browser
    assert browser.new_context_kwargs["user_agent"] == manager._stealth_user_agent
    ctx = browser.created_context
    assert ctx.init_script_calls == [STEALTH_INIT_SCRIPT]
    # Real ordering bug this guards against: add_init_script only reliably covers pages created
    # AFTER it's registered -- registering it after new_page() would let the first page's own
    # initial document load run completely unpatched.
    assert ctx.call_order == ["add_init_script", "new_page"]


# --- native toolkit proxy wiring: routes this context through agent/tools/toolkit_proxy.py's
# shared mitmproxy instance when enabled, stays a plain None (unchanged pre-toolkit behavior)
# when disabled. Never touches the real toolkit_proxy singleton (which would try to bind a real
# port) -- a fake stands in, same "mocked at the manager boundary" convention as everything else
# in this file.


class _FakeToolkitProxyManager:
    def __init__(self, started: bool):
        self._started = started
        self.config_requested_for: str | None = None

    async def ensure_started(self):
        return self._started

    def proxy_config_for_session(self, session_id):
        self.config_requested_for = session_id
        return {"server": "http://127.0.0.1:8081", "username": session_id, "password": "asra"}


def test_get_or_create_context_passes_toolkit_proxy_config_when_enabled(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(bm, "_chromium_installed", lambda: True)
    # A real project session -- get_session_folder must resolve to something truthy for the
    # proxy-routing gate below to even be considered (see the "no project folder" test further
    # down for the other branch).
    monkeypatch.setattr(bm, "get_session_folder", lambda session_id: f"/projects/{session_id}")
    fake_proxy_manager = _FakeToolkitProxyManager(started=True)
    monkeypatch.setattr(bm, "get_toolkit_proxy_manager", lambda: fake_proxy_manager)
    manager = BrowserSessionManager()
    manager._browser = _RecordingBrowser()

    result = _run(manager.get_or_create_context("usr1"))

    assert result["status"] == "ok"
    assert manager._browser.new_context_kwargs["proxy"] == {
        "server": "http://127.0.0.1:8081", "username": "usr1", "password": "asra",
    }
    assert fake_proxy_manager.config_requested_for == "usr1"


def test_get_or_create_context_passes_no_proxy_when_toolkit_disabled(monkeypatch):
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(bm, "_chromium_installed", lambda: True)
    monkeypatch.setattr(bm, "get_session_folder", lambda session_id: f"/projects/{session_id}")
    fake_proxy_manager = _FakeToolkitProxyManager(started=False)
    monkeypatch.setattr(bm, "get_toolkit_proxy_manager", lambda: fake_proxy_manager)
    manager = BrowserSessionManager()
    manager._browser = _RecordingBrowser()

    result = _run(manager.get_or_create_context("usr1"))

    assert result["status"] == "ok"
    assert manager._browser.new_context_kwargs["proxy"] is None
    assert fake_proxy_manager.config_requested_for is None  # never asked, since ensure_started() was False


def test_get_or_create_context_skips_toolkit_proxy_entirely_with_no_project_folder(monkeypatch):
    """The New Project wizard's own throwaway "wizard-<uuid>" browser sessions (used to read a
    bug-bounty program page before any project exists) have no project folder at all --
    real, confirmed operator confusion this guards against: routing that traffic through the
    toolkit's mitmproxy anyway meant real TLS-interception overhead on every wizard click, thrown
    away at the very last step (toolkit_store.py's own "no project folder, skipping"), plus a wall
    of near-identical debug lines with nothing explaining why the toolkit was involved at all.
    The proxy manager must never even be asked to start for a session in this shape."""
    import agent.tools.browser_manager as bm
    monkeypatch.setattr(bm, "_chromium_installed", lambda: True)
    monkeypatch.setattr(bm, "get_session_folder", lambda session_id: None)
    fake_proxy_manager = _FakeToolkitProxyManager(started=True)
    monkeypatch.setattr(bm, "get_toolkit_proxy_manager", lambda: fake_proxy_manager)
    manager = BrowserSessionManager()
    manager._browser = _RecordingBrowser()

    result = _run(manager.get_or_create_context("wizard-abc123"))

    assert result["status"] == "ok"
    assert manager._browser.new_context_kwargs["proxy"] is None
    assert fake_proxy_manager.config_requested_for is None
