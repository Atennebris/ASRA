"""Stateful Playwright browser automation backing the browser_* tools (agent/tools/browser.py's
bypass stubs, registered in agent/tools/__init__.py) -- gives the agent a real, JS-executing
Chromium instance instead of the raw-HTTP-only view every other tool is limited to (http_request,
whatweb, dalfox, ...), which is structurally blind to DOM-rendered content, client-side routing,
and the real XHR/fetch calls a JS app makes at runtime. A browser session must persist ACROSS
separate LLM tool calls (navigate now, click later, read state later) -- the reason this needs a
stateful manager at all, unlike every other tool in this registry, which is one call in, one
result out.

Deliberately does NOT import agent.core -- see agent/tools/subagent_tasks.py's own module
docstring for why: agent.core imports the whole agent.tools package at load time to populate
TOOL_REGISTRY, so the reverse import would be circular. agent/core.py's _dispatch_browser_tool is
the only caller of the public async methods below, always on the main event loop, never via
asyncio.to_thread -- Playwright's async API objects are tied to the event loop that created them,
same reasoning delegate_to_subagent's own to_thread bypass exists for asyncio.create_task.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from agent.tools.allowed_targets import extract_hostname, is_target_out_of_scope
from agent.tools.browser_stealth import STEALTH_INIT_SCRIPT, derive_stealth_user_agent, launch_headless
from agent.tools.native import get_identity_browser_creds, interpret_missing_identity
from agent.tools.toolkit_proxy import get_toolkit_proxy_manager
from agent.utils.debug import truncate_for_log
from agent.utils.logger import get_logger
from sessions.store import get_session_folder

logger = get_logger("TOOLS")

_DEFAULT_IDLE_TIMEOUT_SECONDS = 600
_DEFAULT_MAX_CONCURRENT_CONTEXTS = 5
_IDLE_REAPER_POLL_SECONDS = 30
# Bounding console/network buffer output the same way native.py's web_fetch/js_bundle_scan bound
# their own output (module-level _MAX_ constant, slice, a *_truncated flag) -- a long-running
# interactive session against a chatty SPA can accumulate far more than is useful to hand an LLM.
_MAX_CONSOLE_ENTRIES = 40
_MAX_NETWORK_ENTRIES = 40
# Unlike console/network above, the accessibility snapshot had no cap at all -- on a real
# production SPA it can alone consume most/all of core.py's own flat 8000-char tool-result
# truncation, silently clipping away whatever comes after it in the result dict. Combined with
# _bundle() putting `extra` (browser_evaluate's own eval_result) last, this made two independent
# real evaluate() calls come back with no eval_result at all, confirmed live from the raw captured
# response bodies -- both syntactically valid calls, both status="success", neither had its result
# visible to the model. Fixed by both capping snapshot here AND reordering `extra` before it below.
_MAX_SNAPSHOT_CHARS = 4000


def _idle_timeout_seconds() -> int:
    return int(os.getenv("BROWSER_SESSION_IDLE_TIMEOUT_SECONDS", str(_DEFAULT_IDLE_TIMEOUT_SECONDS)))


def _max_concurrent_contexts() -> int:
    return int(os.getenv("BROWSER_MAX_CONCURRENT_CONTEXTS", str(_DEFAULT_MAX_CONCURRENT_CONTEXTS)))


_DEFAULT_ACTION_TIMEOUT_SECONDS = 45


def _action_timeout_ms() -> int:
    # Its OWN env var, deliberately NOT a reuse of TOOL_TIMEOUT_SECONDS (agent/tools/runner.py's
    # own _timeout_for convention) despite this module's original design saying it would --
    # confirmed live, real incident: an operator's real .env has TOOL_TIMEOUT_SECONDS=600 (a
    # sane value for nmap/nuclei, which can legitimately run that long), and a single
    # browser_navigate against a slow/bot-challenge-gated page (platform.openai.com's own
    # Cloudflare Turnstile interstitial) hung the ENTIRE agent loop for ~10 real minutes before
    # failing -- nothing else in the session can proceed while one tool call is in flight, and the
    # Stop button itself can only take effect at the next safe checkpoint, which never arrived
    # until that one call finally returned. A real browser page either finishes loading in
    # seconds or is genuinely stuck/blocked -- there is no legitimate case for a single
    # interactive browser action needing anywhere near nmap-scan-length patience, so this gets
    # its own short, independent default instead of inheriting a value tuned for a completely
    # different class of tool.
    return int(os.getenv("BROWSER_ACTION_TIMEOUT_SECONDS", str(_DEFAULT_ACTION_TIMEOUT_SECONDS))) * 1000


def _adopt_other_users_playwright_cache() -> None:
    """run-root.bat runs the whole agent as WSL root (README's "Running as root" — no sudo prompts
    needed for nmap -O etc.), whose own $HOME is /root, never /home/<the real user> -- but
    setup_tools.sh's install_playwright() deliberately downloads Chromium as the real invoking
    user, not root (see that function's own comment: root-owned files under /root would be
    invisible to the normal, non-root run.bat path). Root can always READ another user's files
    regardless of permission bits (CAP_DAC_OVERRIDE) -- the only reason root's own Playwright
    can't see an already-downloaded Chromium is that Playwright resolves its browsers dir from
    $HOME, and root's $HOME points somewhere that was never populated. Real, confirmed incident:
    run.bat (normal user) showed every browser_* tool as installed; run-root.bat, same machine,
    same already-downloaded Chromium, showed them all as "Not found on PATH".

    If PLAYWRIGHT_BROWSERS_PATH is already set explicitly (.env override) or this user's own
    default cache already has Chromium, there's nothing to adopt. Otherwise look for whichever
    other /home/*/.cache/ms-playwright actually has it and point Playwright there instead -- no
    second ~150MB download, no setup_tools.sh changes, self-heals regardless of which WSL user
    ends up running the server. No-op on native Linux/macOS single-user machines and on the normal
    (non-root) WSL run.bat path, where the current user's own cache already has it.
    """
    if os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
        return
    own_cache = Path.home() / ".cache" / "ms-playwright"
    if any(own_cache.glob("chromium-*")):
        return
    homes_root = Path("/home")
    if not homes_root.is_dir():
        return
    for candidate in sorted(homes_root.glob("*/.cache/ms-playwright")):
        if any(candidate.glob("chromium-*")):
            logger.debug("browser_manager: this user's own Playwright cache (%s) has no Chromium -- "
                         "adopting %s instead", own_cache, candidate)
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(candidate)
            return


_adopt_other_users_playwright_cache()

_chromium_installed_cache: bool = False


def _chromium_installed() -> bool:
    """Cheap, cached-once-it's-True check for whether Playwright's own Chromium download is
    actually present -- a tool_tier=1 native tool is normally ALWAYS "installed" (agent/tools/
    runner.py's tool_is_installed): true for an ordinary native tool, wrong here, since the Python
    code always imports fine but its real runtime dependency (the ~150MB browser build `playwright
    install` downloads separately) might not be.

    Deliberately only memoizes a True result, not False -- real, confirmed incident: an earlier
    version used @functools.lru_cache(maxsize=1), which pins whatever the FIRST call ever returned
    for the rest of the process's life. A server started (or that already answered one /tools
    request) before `playwright install chromium` finished downloading got False cached forever,
    with the Tools tab still showing every browser_* tool as "Not found on PATH" long after the
    download genuinely completed -- nothing short of restarting the whole server could ever notice.
    Once genuinely installed, Chromium doesn't get un-installed mid-process, so a True result is
    still safe to cache permanently and skip the subprocess cost on every later call; a False result
    re-runs the real check each time so the app self-heals the moment install actually finishes,
    with no restart required.

    Runs the actual Playwright sync-API check in a throwaway subprocess, not in-process -- real,
    confirmed incident: in-process, this silently returned False under the real production server
    (uvicorn/uvloop) even with Chromium genuinely installed (confirmed via a direct check in a
    plain process, and via Starlette's TestClient, which does NOT install uvloop -- both correctly
    returned True; only the real uvloop-driven server got it wrong), while raising nothing this
    function's own try/except could see -- a known Playwright-sync-API/uvloop incompatibility, not
    a bug in the isolation logic itself. A dedicated subprocess has no event loop of its own at
    all, uvloop or otherwise, so it's immune to this regardless of which server/loop called it —
    simpler and more robust than trying to detect/dodge uvloop specifically from inside this
    process. Same "own subprocess, stdin=DEVNULL, bounded timeout" shape every other tool call in
    this project already uses (agent/tools/runner.py's own _run_tracked).
    """
    global _chromium_installed_cache
    if _chromium_installed_cache:
        return True
    try:
        result = subprocess.run(
            [sys.executable, "-c", (
                "from playwright.sync_api import sync_playwright\n"
                "import os, sys\n"
                "with sync_playwright() as p:\n"
                "    sys.exit(0 if os.path.isfile(p.chromium.executable_path) else 1)\n"
            )],
            capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL,
        )
        _chromium_installed_cache = result.returncode == 0
    except Exception as exc:
        logger.debug("browser_manager: chromium availability check failed (%s) -- treating as not installed", exc)
        _chromium_installed_cache = False
    return _chromium_installed_cache


def _loopback_or_link_local(url: str) -> str | None:
    """Same restrictive check as agent/core.py's own _loopback_or_link_local_target, duplicated in
    miniature here rather than imported -- this module cannot import agent.core (circular import,
    see module docstring above), and the check itself is small enough that carving out a shared
    helper isn't worth touching an existing, working function for. Blocks 127.0.0.0/8, ::1, and
    169.254.0.0/16 (link-local, includes the 169.254.169.254 cloud-metadata address) -- never
    RFC1918 private ranges, which can be a legitimate internal-network engagement target.
    """
    hostname = extract_hostname(url) or url
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_link_local:
        return hostname
    return None


def interpret_browser_navigate_permanent_failure(result: dict) -> str | None:
    """Two deterministic, argument-independent browser_navigate failures, registered together
    since a tool name can only map to one _PERMANENT_ERROR_HINTS entry:

    1. Missing identity credentials (navigate()'s own _apply_identity path reuses
       get_identity_browser_creds -> agent.tools.native._get_authenticated_client, the exact same
       check and error text authenticated_request/idor_probe/etc. already share -- see
       interpret_missing_identity's own docstring for the confirmed incident).
    2. A URL that triggers a browser-native file download instead of rendering a page (Chromium
       raises "Page.goto: Download is starting" for this, e.g. a .js.map/.pdf/.zip URL) --
       confirmed live (a real HackerOne rescan session): retrying the identical URL fails the
       identical way every time, and once even led the model to hallucinate an unrelated `identity`
       argument on its blind corrected retry, chasing bug #1 above for no reason.
    """
    identity_hint = interpret_missing_identity(result)
    if identity_hint is not None:
        return identity_hint
    error_text = result.get("error") or ""
    if "Download is starting" not in error_text:
        return None
    return (
        f"{error_text} -- this URL triggers a file download in the browser rather than rendering "
        "a page; retrying browser_navigate against the same URL will fail identically every time. "
        "Use http_request/send_raw_request to fetch its content instead."
    )


class BrowserSessionManager:
    """One shared Chromium Browser process (lazily launched, process-lifetime singleton), one
    isolated BrowserContext per session_id -- cheap (shared browser process) and correctly
    isolated (separate cookies/storage/permissions per pentest session, so two concurrent
    sessions against different targets, or even the same target under different identities,
    never bleed into each other)."""

    def __init__(self) -> None:
        self._playwright: Any = None
        self._browser: Any = None
        self._contexts: dict[str, Any] = {}
        self._pages: dict[str, Any] = {}
        self._console_buffers: dict[str, list[dict]] = {}
        self._network_buffers: dict[str, list[dict]] = {}
        self._last_activity: dict[str, float] = {}
        # Native toolkit's Live View (CDP Page.startScreencast, see start_screencast below) --
        # only ever populated for a session whose live view is actually being watched right now
        # (started/stopped by the SSE stream route's own connection lifecycle, main.py), never
        # unconditionally for every browser_* session.
        self._cdp_sessions: dict[str, Any] = {}
        self._screencast_frames: dict[str, dict] = {}
        self._screencast_frame_counters: dict[str, int] = {}
        # Guards the shared Browser's own first-launch -- two sessions racing to be the first
        # ever to call get_or_create_context() must not both try to launch a second Chromium.
        self._launch_lock = asyncio.Lock()
        self._reaper_task: asyncio.Task | None = None
        # Derived once, live, from the real launched browser (agent/tools/browser_stealth.py's
        # derive_stealth_user_agent) -- never a hardcoded string, so it can never claim a Chromium
        # version different from what's actually installed.
        self._stealth_user_agent: str | None = None

    async def _ensure_browser(self) -> None:
        # is_connected(), not just "is it not None" -- real, confirmed incident: after a
        # browser_navigate call hung against a slow/bot-challenge page and finally timed out, the
        # underlying Playwright driver connection itself died ("Connection closed while reading
        # from the driver" / "unable to perform operation on <WriteUnixTransport closed=True ...>"
        # on the next close attempt) -- self._browser stayed a stale, non-None reference forever
        # after that, which would have silently broken every browser_* call for every session for
        # the rest of this server process's life (this check never ran before, so a dead browser
        # was indistinguishable from a healthy one).
        if self._browser is not None and self._browser.is_connected():
            return
        async with self._launch_lock:
            if self._browser is not None and self._browser.is_connected():
                return  # a concurrent first-caller may have already won the race and relaunched
            if self._browser is not None:
                logger.debug("browser_manager: shared browser connection was dead -- relaunching")
                try:
                    await self._playwright.stop()
                except Exception as exc:
                    logger.debug("browser_manager: error stopping the dead playwright driver (%s) -- ignored", exc)
                self._browser = None
                self._playwright = None
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            headless = launch_headless()
            self._browser = await self._playwright.chromium.launch(headless=headless)
            logger.debug("browser_manager: shared Chromium browser launched (headless=%s)", headless)
            if self._stealth_user_agent is None:
                # One throwaway context+page, immediately discarded -- the only way to learn the
                # REAL UA this exact installed Chromium build reports, so the derived stealth UA
                # (browser_stealth.derive_stealth_user_agent) never drifts from the real version.
                tmp_context = await self._browser.new_context()
                tmp_page = await tmp_context.new_page()
                real_user_agent = await tmp_page.evaluate("navigator.userAgent")
                await tmp_context.close()
                self._stealth_user_agent = derive_stealth_user_agent(real_user_agent)
                logger.debug("browser_manager: derived stealth user-agent from %r", real_user_agent)

    def _touch(self, session_id: str) -> None:
        self._last_activity[session_id] = time.time()

    def _ensure_reaper_started(self) -> None:
        if self._reaper_task is None or self._reaper_task.done():
            self._reaper_task = asyncio.create_task(self._idle_reaper_loop())

    async def _idle_reaper_loop(self) -> None:
        """Crash/cancel safety net, not the primary cleanup path -- the primary path is
        agent/core.py's own run_session/run_focused_exploit finally blocks calling close_session()
        directly the moment a run actually ends. This exists for the run that DIDN'T reach its own
        finally (a hard crash, a killed process that somehow left this one alive, or simply a run
        that opened a browser session and then genuinely forgot to close it for the rest of a long
        idle session)."""
        try:
            while True:
                await asyncio.sleep(_IDLE_REAPER_POLL_SECONDS)
                timeout = _idle_timeout_seconds()
                now = time.time()
                stale = [sid for sid, last in list(self._last_activity.items()) if now - last > timeout]
                for session_id in stale:
                    logger.debug("browser_manager: session=%s idle for >%ds -- closing", session_id, timeout)
                    await self.close_session(session_id)
        except asyncio.CancelledError:
            raise

    async def get_or_create_context(self, session_id: str) -> dict:
        """Returns {"status": "ok"} once this session has a live page ready to use, or a
        model-facing {"status": "skipped"/"error", ...} if it couldn't (concurrency cap, or
        Chromium genuinely isn't installed) -- never raises."""
        if session_id in self._pages:
            self._touch(session_id)
            return {"status": "ok"}
        # to_thread, not a direct call -- this runs on the main event loop (agent/core.py's
        # _dispatch_browser_tool), and _chromium_installed() blocks on a real subprocess.run
        # (up to its own 15s timeout) -- calling it directly here would freeze the entire server,
        # not just this one browser session, for however long that takes.
        if not await asyncio.to_thread(_chromium_installed):
            return {
                "status": "error",
                "error": "Chromium is not installed for the browser_* tools -- run ./setup_tools.sh "
                         "(or `playwright install --with-deps chromium` inside ./venv) first.",
            }
        if len(self._pages) >= _max_concurrent_contexts():
            return {
                "status": "skipped",
                "reason": (
                    f"{len(self._pages)} browser session(s) already open (max {_max_concurrent_contexts()}) "
                    "-- close one with browser_close_session, or wait for another session to finish, before "
                    "opening a new one"
                ),
            }
        await self._ensure_browser()
        # Routes this context's traffic through the native toolkit's own mitmproxy instance
        # (agent/tools/toolkit_proxy.py) so it's captured into that session's Proxy/Repeater
        # history -- a no-op (proxy stays None) when TOOLKIT_ENABLED=false, so a disabled toolkit
        # never changes browser_* behavior at all. ignore_https_errors=True below (already needed
        # regardless, for real targets with self-signed/expired certs) is also exactly what lets
        # this context trust mitmproxy's own locally-generated CA without installing/trusting it
        # anywhere -- no separate certificate step needed for the agent's own browser.
        #
        # Skipped entirely for a session with no real project folder -- e.g. the New Project
        # wizard's own throwaway "wizard-<uuid>" browser sessions (agent/tools/bugbounty_import.py,
        # used to read a bug-bounty program page or a target's title/security.txt BEFORE any
        # project exists at all). Real, confirmed operator confusion this fixes: routing that
        # traffic through the proxy anyway meant every single request the wizard's page-read made
        # (a JS-heavy SPA like hackerone.com easily fires dozens, more with the scope-table's own
        # scroll-harvest re-fetching) got fully intercepted, then thrown away at the very last step
        # by append_traffic_entry's own "no project folder, skipping" (toolkit_store.py) -- real
        # proxy/TLS-interception overhead spent on every wizard click for zero benefit, plus a wall
        # of near-identical debug lines burying whatever else was happening in the log at the same
        # time, with nothing explaining WHY a toolkit built for capturing a live pentest's own
        # traffic was involved in a page read that happens before any pentest has even started.
        # get_session_folder is the exact same check append_traffic_entry already makes at the end
        # of this same pipeline -- just applied here, first, so the wasted work never happens at
        # all instead of happening and then being discarded.
        proxy_config = None
        if not get_session_folder(session_id):
            logger.debug("browser_manager: session=%s has no project folder -- skipping toolkit traffic capture for this context", session_id)
        elif await get_toolkit_proxy_manager().ensure_started():
            proxy_config = get_toolkit_proxy_manager().proxy_config_for_session(session_id)
        context = await self._browser.new_context(
            accept_downloads=False, ignore_https_errors=True, user_agent=self._stealth_user_agent,
            proxy=proxy_config,
        )
        context.set_default_timeout(_action_timeout_ms())
        # BEFORE new_page(), not after -- add_init_script only reliably covers pages created after
        # it's registered; registering it after new_page() risks the very first page's own initial
        # document load running completely unpatched (agent/tools/browser_stealth.py's own
        # STEALTH_INIT_SCRIPT/module docstring has the real motivation: this repo's own headless
        # Chromium leaked navigator.webdriver/plugins/window.chrome/UA by default, live-confirmed).
        await context.add_init_script(STEALTH_INIT_SCRIPT)
        page = await context.new_page()

        console_buffer: list[dict] = []
        network_buffer: list[dict] = []

        def _on_console(msg: Any) -> None:
            console_buffer.append({"type": msg.type, "text": msg.text})

        def _on_page_error(err: Any) -> None:
            console_buffer.append({"type": "pageerror", "text": str(err)})

        async def _handle_dialog(dialog: Any) -> None:
            # Always captured as evidence before being dismissed -- a JS alert() firing at all can
            # itself be the proof of a DOM XSS finding, not just a nuisance to clear. Always
            # dismissed, never accepted -- accepting a confirm()/prompt() could trigger a real,
            # unintended action on the target application (a "delete account" confirm, e.g.).
            console_buffer.append({"type": f"dialog:{dialog.type}", "text": dialog.message})
            await dialog.dismiss()

        def _on_request(request: Any) -> None:
            # "request" (fires the instant a request is INITIATED), not "requestfinished" -- a
            # request a WAF/CORS/CSP policy blocks never reaches "requestfinished" at all (confirmed
            # live: a cross-origin fetch blocked by CORS fired "request" then "requestfailed", never
            # "requestfinished"), and a blocked call is itself real signal (an API endpoint exists
            # and the SPA tried to call it) that would otherwise silently vanish from this log.
            network_buffer.append({"method": request.method, "url": request.url, "resource_type": request.resource_type})

        async def _handle_popup(popup: Any) -> None:
            # v1 deliberately does not track a second tab -- auto-close and log that one was
            # suppressed. Registered AFTER this session's own page.new_page() call above already
            # returned, so this only ever fires for a genuinely NEW page (a target=_blank link, a
            # window.open()), never for the initial page's own creation.
            logger.debug("browser_manager: session=%s suppressed a popup/new tab -> %s", session_id, popup.url)
            await popup.close()

        # Async handlers passed DIRECTLY (not wrapped in a lambda + asyncio.create_task) --
        # Playwright's own async event emitter awaits a coroutine handler as part of its normal
        # event-dispatch protocol. Confirmed live this matters, not just a style choice: a
        # create_task-wrapped handler races the calling action (e.g. a click() that triggers the
        # dialog) instead of being awaited as part of it, and the dialog's own message was silently
        # never captured in the very first end-to-end smoke test of this module.
        page.on("console", _on_console)
        page.on("pageerror", _on_page_error)
        page.on("dialog", _handle_dialog)
        page.on("request", _on_request)
        context.on("page", _handle_popup)

        self._contexts[session_id] = context
        self._pages[session_id] = page
        self._console_buffers[session_id] = console_buffer
        self._network_buffers[session_id] = network_buffer
        self._touch(session_id)
        self._ensure_reaper_started()
        logger.debug("browser_manager: session=%s new browser context created (%d/%d open)", session_id, len(self._pages), _max_concurrent_contexts())
        return {"status": "ok"}

    async def _bundle(self, session_id: str, out_of_scope_entries: list[str] | None, extra: dict | None = None) -> dict:
        """Common result shape for every browser_* action: current URL/title, a fresh
        ref-addressable accessibility snapshot, and whatever accumulated in the console/network
        buffers since the last bundle (buffers are drained here, not just read, so the same entry
        never appears twice across two different tool-call results).

        Re-validates the CURRENT page URL against loopback/out-of-scope rules on every single
        call, not just at the initial browser_navigate -- a real, new risk class no existing tool
        has: agent/core.py's own _out_of_scope_target/_loopback_or_link_local_target
        (_run_tool_with_retry) only ever look at the target ARGUMENT of the one browser_navigate
        call that started this session; a redirect, a clicked link, or JS-driven navigation during
        the interactive part of a browser session never passes through that check at all otherwise.
        """
        page = self._pages.get(session_id)
        if page is None:
            return {"status": "error", "error": "no active browser session for this call -- call browser_navigate first"}
        url = page.url
        if url and url != "about:blank":
            loopback_hit = _loopback_or_link_local(url)
            if loopback_hit is not None:
                logger.debug("browser_manager: session=%s page reached loopback/link-local %r -- stopping interaction", session_id, loopback_hit)
                return {"status": "out_of_scope", "url": url, "reason": f"the page navigated to a loopback/link-local address ({loopback_hit!r}) -- no further action was taken"}
            if out_of_scope_entries and is_target_out_of_scope(url, out_of_scope_entries):
                logger.debug("browser_manager: session=%s page drifted out of scope to %r -- stopping interaction", session_id, url)
                return {"status": "out_of_scope", "url": url, "reason": "the page navigated to a URL explicitly marked out of scope for this project -- no further action was taken; navigate back to an in-scope URL to continue"}

        try:
            snapshot = await page.locator("body").aria_snapshot(mode="ai", timeout=_action_timeout_ms())
        except Exception as exc:
            # A frameset-based page (an old-school <frameset><frame>...</frameset> top-level
            # document, no <body> element at all) fails the "body" locator outright even though the
            # page itself is a completely ordinary, ref-clickable document one level down -- each
            # <frame> is its own full document with its own <body>, just not reachable through the
            # PARENT document's own locator. Real, confirmed incident this fixes: a browser MMORPG's
            # actual in-game screen returned "Selector "body" does not match any element" here every
            # single time (even freshly authenticated, freshly navigated) -- with no fallback at
            # all, the agent had no way to discover or click anything inside the game and fell back
            # to static JS analysis + raw HTTP replay instead of ever actually using it. Trying the
            # top-level <html> element next covers plenty of non-<body> document shapes for free; a
            # genuine frameset still won't have real content at the TOP level either, so this also
            # enumerates page.frames and, if any exist, hands back their real URLs -- a real
            # <frame>'s own document can be snapshotted/clicked normally by navigating straight to
            # its URL, no different from any other page.
            try:
                snapshot = await page.locator("html").aria_snapshot(mode="ai", timeout=_action_timeout_ms())
            except Exception:
                frame_urls = [f.url for f in getattr(page, "frames", []) if getattr(f, "url", None) and f.url not in (url, "about:blank")]
                if frame_urls:
                    snapshot = (
                        "(snapshot unavailable on this top-level document -- it uses HTML frames, not a "
                        f"normal single-document layout. Real child frame(s) found: {frame_urls}. This "
                        "tool snapshots/clicks the CURRENT page only, never a frame's separate document -- "
                        "browser_navigate straight to one of those frame URLs to actually see/interact with "
                        "what's rendered inside it.)"
                    )
                else:
                    # No frames either -- most likely the real content renders inside a <canvas> (a
                    # game client, a chart, anything drawn as pixels rather than real DOM elements),
                    # which has no accessible structure at all for this tool to see or click into,
                    # not a fixable locator problem. Named explicitly rather than left as an opaque
                    # exception string, so the model has a concrete next move instead of repeating
                    # the same failing snapshot call.
                    snapshot = (
                        f"(snapshot unavailable: {exc}. No usable accessibility tree and no child frames "
                        "either -- if this page's real content renders inside a <canvas> rather than real "
                        "DOM elements, there is nothing here for browser_snapshot/browser_click to see or "
                        "click into at all. Pivot to reading the page's own loaded JavaScript (js_bundle_scan "
                        "on each <script src=...>) to find its underlying AJAX/API endpoints, and drive it "
                        "directly with http_request/send_raw_request using this same session's cookies "
                        "instead of relying on browser_click.)"
                    )
        try:
            title = await page.title()
        except Exception:
            title = ""

        # .clear(), never a rebind (self._console_buffers[session_id] = []) -- the page.on(...)
        # closures registered in get_or_create_context captured THIS SAME list object by reference;
        # rebinding the dict entry here would silently detach them from it, so every event after
        # the first drain would land in an orphaned list nothing ever reads again. Confirmed live:
        # the very first end-to-end smoke test's dialog-capture assertion failed until this was a
        # .clear() instead of a rebind.
        console = self._console_buffers.get(session_id, [])
        network = self._network_buffers.get(session_id, [])
        console_out = list(console[:_MAX_CONSOLE_ENTRIES])
        network_out = list(network[:_MAX_NETWORK_ENTRIES])
        console_truncated = len(console) > _MAX_CONSOLE_ENTRIES
        network_truncated = len(network) > _MAX_NETWORK_ENTRIES
        console.clear()
        network.clear()

        result: dict[str, Any] = {
            "status": "ok",
            "url": url,
            "title": title,
        }
        # `extra` (e.g. browser_evaluate's own eval_result) merges BEFORE snapshot/console/network
        # -- see _MAX_SNAPSHOT_CHARS's docstring above for why the old last-place ordering could
        # silently lose it to the outer 8000-char tool-result truncation.
        if extra:
            result.update(extra)
        result["snapshot"] = snapshot[:_MAX_SNAPSHOT_CHARS]
        result["snapshot_truncated"] = len(snapshot) > _MAX_SNAPSHOT_CHARS
        result["console_since_last"] = console_out
        result["console_truncated"] = console_truncated
        result["network_since_last"] = network_out
        result["network_truncated"] = network_truncated
        self._touch(session_id)
        return result

    async def _apply_identity(self, session_id: str, identity: str) -> dict | None:
        """Swaps this session's single browser context to browse as `identity` -- reuses the SAME
        server-side login agent/tools/native.py's authenticated_request/idor_probe already use
        (get_identity_browser_creds), never exposing raw credentials to the model (browser_navigate's
        own schema only ever takes an identity NAME). One shared context per session_id, not one per
        identity, so a role-based diff test is "navigate as user_a, walk the workflow, navigate again
        with identity=user_b, walk the same workflow, diff_requests the two captured traffic entries"
        -- sequential, same as a human pentester re-logging into one browser tab, not two concurrent
        contexts (which would need identity threaded through every one of the other 8 browser_* tools
        too, for no real benefit here).

        clear_cookies()/reset extra headers BEFORE applying the new identity's own -- otherwise a
        session already browsing as one identity would silently mix its cookies/Authorization header
        with the next one applied, defeating the whole point of a role-diff test. Returns a
        model-facing error dict if the identity has no configured credentials, None on success.
        """
        # to_thread -- get_identity_browser_creds does a real blocking httpx login POST the first
        # time an identity is used, same reasoning _chromium_installed()'s own to_thread call above
        # has: this runs on the main event loop and must never block it.
        creds = await asyncio.to_thread(get_identity_browser_creds, session_id, identity)
        if creds.get("status") != "ok":
            return creds
        context = self._contexts[session_id]
        await context.clear_cookies()
        if creds["cookies"]:
            await context.add_cookies(creds["cookies"])
        await context.set_extra_http_headers(creds["headers"])
        logger.debug("browser_manager: session=%s now browsing as identity=%s (%d cookies)", session_id, identity, len(creds["cookies"]))
        return None

    async def navigate(self, session_id: str, url: str, wait_until: str = "domcontentloaded", out_of_scope_entries: list[str] | None = None, identity: str | None = None) -> dict:
        logger.debug("browser_manager: session=%s navigate url=%r wait_until=%s", session_id, url, wait_until)
        # Checked BEFORE get_or_create_context, not after -- a rejected navigate must not still
        # consume one of this session's (or the whole process's) concurrency-capped context slots
        # for a page that was never going anywhere real anyway.
        loopback_hit = _loopback_or_link_local(url)
        if loopback_hit is not None:
            logger.debug("browser_manager: session=%s navigate url=%r rejected -- loopback/link-local", session_id, url)
            return {"status": "error", "error": f"target {loopback_hit!r} is a loopback/link-local address -- this can never be the real pentest target"}
        ensure = await self.get_or_create_context(session_id)
        if ensure["status"] != "ok":
            logger.debug("browser_manager: session=%s navigate url=%r failed to get a context (%s)", session_id, url, ensure.get("error") or ensure.get("reason"))
            return ensure
        if identity:
            identity_error = await self._apply_identity(session_id, identity)
            if identity_error is not None:
                logger.debug("browser_manager: session=%s navigate url=%r identity=%s failed (%s)", session_id, url, identity, identity_error.get("error"))
                return identity_error
        page = self._pages[session_id]
        try:
            response = await page.goto(url, wait_until=wait_until, timeout=_action_timeout_ms())
        except Exception as exc:
            logger.debug("browser_manager: session=%s navigate url=%r failed (%s)", session_id, url, exc)
            return {"status": "error", "error": f"navigation to {url!r} failed: {exc}"}
        http_status = response.status if response is not None else None
        logger.debug("browser_manager: session=%s navigate url=%r ok http_status=%s", session_id, url, http_status)
        return await self._bundle(session_id, out_of_scope_entries, extra={"http_status": http_status})

    async def snapshot(self, session_id: str, out_of_scope_entries: list[str] | None = None) -> dict:
        return await self._bundle(session_id, out_of_scope_entries)

    async def click(self, session_id: str, ref: str, out_of_scope_entries: list[str] | None = None) -> dict:
        return await self._act(session_id, ref, "click", out_of_scope_entries)

    async def fill(self, session_id: str, ref: str, text: str, out_of_scope_entries: list[str] | None = None) -> dict:
        return await self._act(session_id, ref, "fill", out_of_scope_entries, text)

    async def select_option(self, session_id: str, ref: str, value: str, out_of_scope_entries: list[str] | None = None) -> dict:
        return await self._act(session_id, ref, "select_option", out_of_scope_entries, value)

    async def _act(self, session_id: str, ref: str, action: str, out_of_scope_entries: list[str] | None, *args: str) -> dict:
        logger.debug("browser_manager: session=%s %s(ref=%r)", session_id, action, ref)
        page = self._pages.get(session_id)
        if page is None:
            return {"status": "error", "error": "no active browser session for this call -- call browser_navigate first"}
        try:
            locator = page.locator(f"aria-ref={ref}")
            await getattr(locator, action)(*args, timeout=_action_timeout_ms())
        except Exception as exc:
            logger.debug("browser_manager: session=%s %s(ref=%r) failed (%s)", session_id, action, ref, exc)
            return {
                "status": "error",
                "error": f"{action}(ref={ref!r}) failed: {exc} -- refs from an earlier snapshot are invalid after "
                         "any action that could have changed the page; call browser_snapshot again for fresh refs",
            }
        return await self._bundle(session_id, out_of_scope_entries)

    async def press_key(self, session_id: str, key: str, out_of_scope_entries: list[str] | None = None) -> dict:
        logger.debug("browser_manager: session=%s press_key(%r)", session_id, key)
        page = self._pages.get(session_id)
        if page is None:
            return {"status": "error", "error": "no active browser session for this call -- call browser_navigate first"}
        try:
            # page.keyboard.press -- unlike _act's locator.click/fill/select_option above -- is
            # Playwright's low-level Keyboard API, not a Locator action: it has no target element to
            # wait on becoming actionable, so it takes no timeout= kwarg at all (only key/delay).
            # Confirmed live: every real press_key call in this app crashed outright with
            # "press() got an unexpected keyword argument 'timeout'" -- this tool was completely
            # broken from the very first use, not just slow/flaky.
            await page.keyboard.press(key)
        except Exception as exc:
            logger.debug("browser_manager: session=%s press_key(%r) failed (%s)", session_id, key, exc)
            return {"status": "error", "error": f"press_key({key!r}) failed: {exc}"}
        return await self._bundle(session_id, out_of_scope_entries)

    async def evaluate(self, session_id: str, expression: str, out_of_scope_entries: list[str] | None = None) -> dict:
        logger.debug("browser_manager: session=%s evaluate(%s)", session_id, truncate_for_log(expression))
        page = self._pages.get(session_id)
        if page is None:
            return {"status": "error", "error": "no active browser session for this call -- call browser_navigate first"}
        try:
            eval_result = await page.evaluate(expression)
        except Exception as exc:
            logger.debug("browser_manager: session=%s evaluate() failed (%s)", session_id, exc)
            return {"status": "error", "error": f"evaluate() failed: {exc}"}
        try:
            import json
            json.dumps(eval_result)
        except (TypeError, ValueError):
            eval_result = str(eval_result)
        bundle = await self._bundle(session_id, out_of_scope_entries, extra={"eval_result": eval_result})
        return bundle

    async def mouse_wheel_scroll(self, session_id: str, delta_y: float = 900) -> dict:
        """Dispatches a real, trusted mouse-wheel scroll (Playwright's page.mouse -- the same
        underlying CDP Input mechanism a genuine user's scroll wheel generates), moved to the
        current viewport's own center first. Not exposed as its own browser_* agent tool -- this
        exists purely to drive scroll-triggered lazy-loading before a plain evaluate() re-read
        (agent/tools/bugbounty_import.py's own scope-table harvesting), not as a general-purpose
        LLM-facing action, so it deliberately skips the usual _bundle() snapshot/console/network
        return shape every other method here returns.

        Confirmed live this actually matters, not a redundant belt-and-suspenders check: against a
        real HackerOne program's own /policy_scopes table (GraphQL-paginated, "load more on scroll"
        -- a real 44-asset program only ever showed ~19 until scrolled further), a programmatic
        element.scrollTop assignment -- even paired with a manually dispatched 'scroll' Event --
        never triggered its own pagination fetch at all. Only a genuine wheel input does.
        """
        logger.debug("browser_manager: session=%s mouse_wheel_scroll(delta_y=%s)", session_id, delta_y)
        page = self._pages.get(session_id)
        if page is None:
            return {"status": "error", "error": "no active browser session for this call -- call browser_navigate first"}
        try:
            viewport = page.viewport_size or {"width": 1280, "height": 720}
            await page.mouse.move(viewport["width"] / 2, viewport["height"] / 2)
            await page.mouse.wheel(0, delta_y)
        except Exception as exc:
            logger.debug("browser_manager: session=%s mouse_wheel_scroll failed (%s)", session_id, exc)
            return {"status": "error", "error": f"mouse_wheel_scroll failed: {exc}"}
        return {"status": "ok"}

    async def go_back(self, session_id: str, out_of_scope_entries: list[str] | None = None) -> dict:
        logger.debug("browser_manager: session=%s go_back()", session_id)
        page = self._pages.get(session_id)
        if page is None:
            return {"status": "error", "error": "no active browser session for this call -- call browser_navigate first"}
        try:
            await page.go_back(timeout=_action_timeout_ms())
        except Exception as exc:
            logger.debug("browser_manager: session=%s go_back() failed (%s)", session_id, exc)
            return {"status": "error", "error": f"go_back() failed: {exc}"}
        return await self._bundle(session_id, out_of_scope_entries)

    async def start_screencast(self, session_id: str) -> dict:
        """Idempotent -- a second call while already running is a cheap no-op, so main.py's SSE
        stream route (toolkit_screencast_stream) can call this on every poll tick rather than once
        upfront: a live-view opened BEFORE the agent has called browser_navigate at all (no page
        yet) keeps retrying here for free until a page genuinely exists, instead of failing once
        and never recovering for the rest of that SSE connection's life."""
        if session_id in self._cdp_sessions:
            return {"status": "ok"}
        page = self._pages.get(session_id)
        context = self._contexts.get(session_id)
        if page is None or context is None:
            return {"status": "error", "error": "no active browser session yet -- call browser_navigate first"}

        cdp = await context.new_cdp_session(page)
        self._screencast_frame_counters[session_id] = 0

        def _on_frame(params: dict) -> None:
            # Real, required CDP protocol: the browser stops sending further frames until each one
            # is acknowledged (backpressure) -- fire-and-forget the ack rather than awaiting it
            # inline here, since this handler itself is a plain sync callback (Playwright's own
            # CDPSession.on dispatch), not a coroutine.
            self._screencast_frame_counters[session_id] = self._screencast_frame_counters.get(session_id, 0) + 1
            self._screencast_frames[session_id] = {
                "id": self._screencast_frame_counters[session_id],
                "data": params["data"],
            }
            asyncio.create_task(self._ack_screencast_frame(session_id, cdp, params["sessionId"]))

        cdp.on("Page.screencastFrame", _on_frame)
        try:
            # 1024x768/quality 60 -- a live low-bandwidth preview, not a lossless recording; CDP
            # downscales while preserving aspect ratio. everyNthFrame=1 (every real repaint) is
            # safe to leave uncapped here since only the LATEST frame is ever kept (overwritten,
            # never queued) and main.py's own stream loop throttles how often it's actually pushed
            # out over SSE -- CDP producing frames faster than that never grows unbounded memory.
            await cdp.send("Page.startScreencast", {
                "format": "jpeg", "quality": 60, "maxWidth": 1024, "maxHeight": 768, "everyNthFrame": 1,
            })
        except Exception as exc:
            logger.debug("browser_manager: session=%s failed to start screencast (%s)", session_id, exc)
            try:
                await cdp.detach()
            except Exception:
                pass
            return {"status": "error", "error": f"failed to start screencast: {exc}"}

        self._cdp_sessions[session_id] = cdp
        logger.debug("browser_manager: session=%s screencast started", session_id)
        return {"status": "ok"}

    async def _ack_screencast_frame(self, session_id: str, cdp: Any, frame_session_id: int) -> None:
        try:
            await cdp.send("Page.screencastFrameAck", {"sessionId": frame_session_id})
        except Exception as exc:
            # A late ack racing the screencast already being stopped (stop_screencast detaches the
            # CDP session) is expected, not a real error -- the frame it was acking is already
            # moot at that point.
            logger.debug("browser_manager: session=%s screencast frame ack failed (%s) -- ignored", session_id, exc)

    async def stop_screencast(self, session_id: str) -> None:
        """Idempotent -- safe to call on a session whose live view was never opened at all."""
        cdp = self._cdp_sessions.pop(session_id, None)
        self._screencast_frames.pop(session_id, None)
        self._screencast_frame_counters.pop(session_id, None)
        if cdp is None:
            return
        try:
            await cdp.send("Page.stopScreencast")
        except Exception as exc:
            logger.debug("browser_manager: session=%s error stopping screencast (%s) -- ignored", session_id, exc)
        try:
            await cdp.detach()
        except Exception as exc:
            logger.debug("browser_manager: session=%s error detaching screencast CDP session (%s) -- ignored", session_id, exc)
        logger.debug("browser_manager: session=%s screencast stopped", session_id)

    def get_latest_screencast_frame(self, session_id: str) -> dict | None:
        """{"id": int, "data": base64-jpeg-str} for whatever frame most recently arrived, or None
        if the live view was never opened (or no frame has arrived yet). "id" lets the SSE stream
        loop (main.py) tell "still the same frame as last tick" apart from "a new one landed"
        without comparing the (much larger) base64 payload itself."""
        return self._screencast_frames.get(session_id)

    def get_live_view_viewport(self, session_id: str) -> dict | None:
        """The real page viewport size (Playwright's own context default when none is set
        explicitly here) -- the Live View frontend (static/js/live_view_input.js) needs this to
        convert a click's position on the displayed, CDP-downscaled screencast image back into
        real page-space coordinates for input dispatch. Deliberately NOT the screencast's own
        maxWidth/maxHeight (1024x768, start_screencast above) -- that is a separate, unrelated
        number (the downscaled IMAGE resolution), not the actual page/viewport coordinate space
        page.mouse/page.keyboard operate in."""
        page = self._pages.get(session_id)
        if page is None:
            return None
        size = page.viewport_size
        return {"width": size["width"], "height": size["height"]} if size else None

    # JS KeyboardEvent.key for the space bar is a literal " " -- Playwright's own USKeyboardLayout
    # names it "Space" instead; every other key this feature forwards (letters, digits, Enter,
    # Backspace, Escape, Arrow*, ...) already matches between the two, so this is the one override
    # actually needed rather than a full remapping table for keys that already agree.
    _LIVE_VIEW_KEY_OVERRIDES = {" ": "Space"}

    async def dispatch_live_view_input(
        self, session_id: str, event_type: str, x: float = 0.0, y: float = 0.0,
        button: str = "left", click_count: int = 1, key: str = "", dx: float = 0.0, dy: float = 0.0,
    ) -> dict:
        """Forwards one real mouse/keyboard/wheel event from the operator's own interaction with
        the Live View panel (static/js/live_view_input.js) straight into this session's real
        Playwright page -- the plain page.mouse/page.keyboard API, not the raw CDP Input.dispatch*
        primitives, since the page object is already tracked here (self._pages) and Playwright's
        own high-level methods already handle the real click-vs-drag/modifier-key protocol details
        that raw CDP dispatch would otherwise leave to this code.

        Deliberately NOT serialized behind any lock shared with the agent's own browser_* tool
        calls (_dispatch_browser_tool_impl, agent/core.py) -- the real motivating case is an
        operator manually clicking through a live bot-challenge (Cloudflare Turnstile, see
        agent/tools/browser_stealth.py's own module docstring, confirmed live against
        platform.openai.com) WHILE the agent's own browser_navigate call is still blocked waiting
        on that exact same page load. A lock here would block the one intervention that scenario
        actually needs -- Playwright's own protocol multiplexes concurrent calls on the same page
        by design, so this is safe without one.
        """
        page = self._pages.get(session_id)
        if page is None:
            return {"status": "error", "error": "no active browser session for this call"}
        try:
            if event_type == "click":
                await page.mouse.click(x, y, button=button, click_count=click_count)
            elif event_type == "wheel":
                await page.mouse.wheel(dx, dy)
            elif event_type == "keydown":
                await page.keyboard.press(self._LIVE_VIEW_KEY_OVERRIDES.get(key, key))
            else:
                return {"status": "error", "error": f"unknown live-view input event type: {event_type!r}"}
        except Exception as exc:
            logger.debug("browser_manager: session=%s live-view input %s failed (%s)", session_id, event_type, exc)
            return {"status": "error", "error": str(exc)}
        self._touch(session_id)
        return {"status": "ok"}

    async def close_session(self, session_id: str) -> None:
        """Idempotent -- safe to call on a session with no open browser context at all (the
        common case: most sessions never touch the browser_* tools)."""
        await self.stop_screencast(session_id)
        context = self._contexts.pop(session_id, None)
        self._pages.pop(session_id, None)
        self._console_buffers.pop(session_id, None)
        self._network_buffers.pop(session_id, None)
        self._last_activity.pop(session_id, None)
        if context is not None:
            try:
                await context.close()
            except Exception as exc:
                logger.debug("browser_manager: session=%s error closing context (%s) -- ignored, already dropped from tracking", session_id, exc)
            logger.debug("browser_manager: session=%s browser context closed", session_id)

    async def shutdown(self) -> None:
        """Called once from main.py's app-shutdown hook -- closes every remaining context, then
        the shared Browser and the Playwright driver itself, so no orphaned Chromium process
        survives a server restart."""
        if self._reaper_task is not None:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
            self._reaper_task = None
        for session_id in list(self._pages.keys()):
            await self.close_session(session_id)
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception as exc:
                logger.debug("browser_manager: error closing shared browser (%s)", exc)
            self._browser = None
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception as exc:
                logger.debug("browser_manager: error stopping playwright driver (%s)", exc)
            self._playwright = None
        logger.debug("browser_manager: shutdown complete")


_manager = BrowserSessionManager()


def get_browser_manager() -> BrowserSessionManager:
    return _manager
