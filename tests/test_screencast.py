"""Native toolkit's Live View: BrowserSessionManager's screencast methods
(agent/tools/browser_manager.py). Never drives a real Chromium/CDP session -- a fake CDP session
object stands in, same "mocked at the manager/Playwright-object boundary" convention as
tests/test_browser_tools.py. The real CDP wiring (Page.startScreencast producing genuine JPEG
frames, Page.screencastFrameAck's backpressure requirement) was verified live, out of band,
against a real browser session.
"""
import asyncio

from agent.tools.browser_manager import BrowserSessionManager


def _run(coro):
    return asyncio.run(coro)


class _FakeCDPSession:
    def __init__(self):
        self.handlers: dict = {}
        self.sent: list[tuple] = []
        self.acked: list[int] = []
        self.detached = False

    def on(self, event, handler):
        self.handlers[event] = handler

    async def send(self, method, params=None):
        self.sent.append((method, params))
        if method == "Page.screencastFrameAck":
            self.acked.append(params["sessionId"])

    async def detach(self):
        self.detached = True


class _FakeContextWithCDP:
    def __init__(self):
        self.cdp_session = _FakeCDPSession()

    async def new_cdp_session(self, page):
        return self.cdp_session

    async def close(self):
        pass


def _wire_active_session(manager: BrowserSessionManager, session_id: str) -> _FakeContextWithCDP:
    fake_context = _FakeContextWithCDP()
    manager._contexts[session_id] = fake_context
    manager._pages[session_id] = object()  # page identity is never touched by the fake
    return fake_context


# --- start_screencast ----------------------------------------------------------------------


def test_start_screencast_errors_without_an_active_browser_session():
    manager = BrowserSessionManager()
    result = _run(manager.start_screencast("usr1"))
    assert result["status"] == "error"


def test_start_screencast_is_idempotent_once_already_running():
    manager = BrowserSessionManager()
    sentinel = object()
    manager._cdp_sessions["usr1"] = sentinel
    result = _run(manager.start_screencast("usr1"))
    assert result["status"] == "ok"
    assert manager._cdp_sessions["usr1"] is sentinel  # never touched/replaced


def test_start_screencast_sends_the_expected_cdp_command():
    manager = BrowserSessionManager()
    fake_context = _wire_active_session(manager, "usr1")

    result = _run(manager.start_screencast("usr1"))

    assert result["status"] == "ok"
    assert manager._cdp_sessions["usr1"] is fake_context.cdp_session
    assert ("Page.startScreencast", {
        "format": "jpeg", "quality": 60, "maxWidth": 1024, "maxHeight": 768, "everyNthFrame": 1,
    }) in fake_context.cdp_session.sent


# --- the Page.screencastFrame handler ------------------------------------------------------


def test_frame_handler_stores_latest_frame_and_acks_it():
    manager = BrowserSessionManager()
    fake_context = _wire_active_session(manager, "usr1")

    async def scenario():
        await manager.start_screencast("usr1")
        handler = fake_context.cdp_session.handlers["Page.screencastFrame"]
        handler({"data": "base64jpegdata", "sessionId": 42})
        await asyncio.sleep(0)  # let the fire-and-forget ack task actually run
        return manager.get_latest_screencast_frame("usr1")

    frame = _run(scenario())
    assert frame == {"id": 1, "data": "base64jpegdata"}
    assert 42 in fake_context.cdp_session.acked


def test_frame_ids_increment_and_latest_overwrites_not_queues():
    manager = BrowserSessionManager()
    fake_context = _wire_active_session(manager, "usr1")

    async def scenario():
        await manager.start_screencast("usr1")
        handler = fake_context.cdp_session.handlers["Page.screencastFrame"]
        handler({"data": "frame1", "sessionId": 1})
        handler({"data": "frame2", "sessionId": 2})
        await asyncio.sleep(0)
        return manager.get_latest_screencast_frame("usr1")

    frame = _run(scenario())
    assert frame == {"id": 2, "data": "frame2"}  # only the latest is kept, id 1 never lingers


def test_get_latest_screencast_frame_is_none_before_any_frame_arrives():
    manager = BrowserSessionManager()
    assert manager.get_latest_screencast_frame("usr1") is None


# --- stop_screencast -------------------------------------------------------------------------


def test_stop_screencast_sends_stop_detaches_and_clears_state():
    manager = BrowserSessionManager()
    fake_context = _wire_active_session(manager, "usr1")

    async def scenario():
        await manager.start_screencast("usr1")
        await manager.stop_screencast("usr1")

    _run(scenario())
    assert ("Page.stopScreencast", None) in fake_context.cdp_session.sent
    assert fake_context.cdp_session.detached is True
    assert "usr1" not in manager._cdp_sessions
    assert manager.get_latest_screencast_frame("usr1") is None


def test_stop_screencast_is_a_no_op_when_never_started():
    manager = BrowserSessionManager()
    _run(manager.stop_screencast("usr1"))  # must not raise


# --- close_session also tears down an active screencast, not just the browser context --------


def test_close_session_stops_an_active_screencast_too():
    manager = BrowserSessionManager()
    fake_context = _wire_active_session(manager, "usr1")

    async def scenario():
        await manager.start_screencast("usr1")
        await manager.close_session("usr1")

    _run(scenario())
    assert "usr1" not in manager._cdp_sessions
    assert fake_context.cdp_session.detached is True


# --- Live View input forwarding (dispatch_live_view_input/get_live_view_viewport) -------------


class _FakeMouse:
    def __init__(self):
        self.clicks: list[tuple] = []
        self.wheels: list[tuple] = []

    async def click(self, x, y, button="left", click_count=1):
        self.clicks.append((x, y, button, click_count))

    async def wheel(self, dx, dy):
        self.wheels.append((dx, dy))


class _FakeKeyboard:
    def __init__(self):
        self.pressed: list[str] = []

    async def press(self, key):
        self.pressed.append(key)


class _FakePage:
    def __init__(self, viewport_size=None):
        self.mouse = _FakeMouse()
        self.keyboard = _FakeKeyboard()
        self.viewport_size = viewport_size


def test_get_live_view_viewport_is_none_without_an_active_page():
    manager = BrowserSessionManager()
    assert manager.get_live_view_viewport("usr1") is None


def test_get_live_view_viewport_returns_the_real_page_viewport():
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _FakePage(viewport_size={"width": 1280, "height": 720})
    assert manager.get_live_view_viewport("usr1") == {"width": 1280, "height": 720}


def test_dispatch_live_view_input_errors_without_an_active_page():
    manager = BrowserSessionManager()
    result = _run(manager.dispatch_live_view_input("usr1", "click", x=1, y=2))
    assert result["status"] == "error"


def test_dispatch_live_view_input_click_calls_page_mouse_click():
    manager = BrowserSessionManager()
    page = _FakePage()
    manager._pages["usr1"] = page
    result = _run(manager.dispatch_live_view_input("usr1", "click", x=10.0, y=20.0, button="right", click_count=2))
    assert result["status"] == "ok"
    assert page.mouse.clicks == [(10.0, 20.0, "right", 2)]


def test_dispatch_live_view_input_wheel_calls_page_mouse_wheel():
    manager = BrowserSessionManager()
    page = _FakePage()
    manager._pages["usr1"] = page
    result = _run(manager.dispatch_live_view_input("usr1", "wheel", dx=5.0, dy=-3.0))
    assert result["status"] == "ok"
    assert page.mouse.wheels == [(5.0, -3.0)]


def test_dispatch_live_view_input_keydown_calls_page_keyboard_press():
    manager = BrowserSessionManager()
    page = _FakePage()
    manager._pages["usr1"] = page
    result = _run(manager.dispatch_live_view_input("usr1", "keydown", key="Enter"))
    assert result["status"] == "ok"
    assert page.keyboard.pressed == ["Enter"]


def test_dispatch_live_view_input_maps_the_space_bar_to_playwrights_key_name():
    """JS KeyboardEvent.key for the space bar is a literal " " -- Playwright's own
    USKeyboardLayout names it "Space" instead."""
    manager = BrowserSessionManager()
    page = _FakePage()
    manager._pages["usr1"] = page
    _run(manager.dispatch_live_view_input("usr1", "keydown", key=" "))
    assert page.keyboard.pressed == ["Space"]


def test_dispatch_live_view_input_rejects_an_unknown_event_type():
    manager = BrowserSessionManager()
    manager._pages["usr1"] = _FakePage()
    result = _run(manager.dispatch_live_view_input("usr1", "drag"))
    assert result["status"] == "error"
