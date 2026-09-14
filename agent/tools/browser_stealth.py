"""Fingerprint/bot-detection evasion for the browser_* tools (agent/tools/browser_manager.py).

Real motivation, live-confirmed this session against this repo's own pinned playwright==1.61.0:
headless Chromium leaks every cheap, first-tier bot-detection signal by default --
navigator.webdriver=True, navigator.plugins.length=0, window.chrome absent, and the User-Agent
literally contains the substring "HeadlessChrome". A real live session (Safety-Bug-Bounty-usr_158b31,
openai.com scope) got blocked by Cloudflare Turnstile on platform.openai.com, the model's own words:
"The Vercel/Cloudflare checkpoints block headless access to the Astro app."

Closes the CHEAP/COMMON detection tier -- known, well-documented signature patches (navigator
properties, a plausible window.chrome shape, WebGL vendor/renderer strings, a realistic
User-Agent), each one's own toString() also spoofed to report native code rather than leaking its
own real JS source (a known next-tier check on top of the cheap tier itself). BROWSER_HEADLESS=false
(agent/tools/browser_manager.py's _headless) closes a real, structural gap none of the above can --
Chromium's own headless mode carries fingerprint differences beyond anything a page-level JS patch
can paper over, and a real display is the only way to genuinely not be headless.

Does NOT address determined behavioral/IP-reputation/TLS-fingerprint systems (Cloudflare
Turnstile-grade challenges are a separate, harder problem) or the CDP "Runtime.enable leak"
technique (a page can detect an attached DevTools Protocol client -- Playwright always attaches
one -- via a documented console.debug/getter timing side-channel; genuinely defeating it means
intercepting/deferring that specific CDP command beneath Playwright's own public API, which isn't
exposed here, and none of this project's approved live-verification targets actually exercise
Turnstile to validate a real fix against -- left as a documented, deliberately unattempted gap
rather than an unverified one shipped as if it were solid).
"""
from __future__ import annotations

import os


def derive_stealth_user_agent(real_user_agent: str) -> str:
    """Strips 'Headless' from a real, live Chromium UA string -- keeps everything else, including
    the real installed Chromium version, byte-for-byte unchanged. Deliberately derived from the
    browser's own actual UA at runtime (agent/tools/browser_manager.py's _ensure_browser, once per
    process) rather than a hardcoded string here -- a spoofed UA that claims a DIFFERENT Chromium
    version than what's actually running would itself be a detectable inconsistency (e.g. via
    navigator.userAgentData reporting a conflicting version).
    """
    return real_user_agent.replace("HeadlessChrome/", "Chrome/")


def launch_headless() -> bool:
    """BROWSER_HEADLESS (default true, unchanged behavior) -- an explicit opt-out for an operator
    running ASRA somewhere a real display actually exists (WSLg, X11, a real desktop), trading a
    visible Chromium window on the machine running the agent for a browser that isn't headless at
    the process-launch level at all, closing detection surface no page-level JS patch below can
    touch. Off by default since most real deployments (a headless server, a bare WSL2 without
    WSLg) have no display to launch a real window against at all -- launch would simply fail there.
    """
    return os.getenv("BROWSER_HEADLESS", "true").strip().lower() not in ("false", "0", "no")


# Injected via BrowserContext.add_init_script() before every page's own first script runs (Playwright
# guarantees this ordering) -- so every patch below is in place before any target page's own
# detection script gets a chance to observe the unpatched values.
STEALTH_INIT_SCRIPT = r"""
(() => {
  // 0. Function.prototype.toString leak -- every real native browser API reports "[native code]"
  // when introspected via Function.prototype.toString; every patched function below is real,
  // user-defined JS and would otherwise reveal its own actual source the same way -- itself a
  // cheap, well-documented next-tier tell (checking not just THAT navigator.webdriver is
  // undefined, but HOW it became undefined). Each patch below registers its own replacement
  // function here with the exact string a genuine native implementation reports for that same
  // slot (a getter's own native stub is spelled "get X", not just "X"), and
  // Function.prototype.toString itself is overridden to report that instead of the real source --
  // falling through to the real implementation for every other function on the page, since
  // changing toString's behavior for anything else would itself become the tell.
  const nativeStubs = new WeakMap();
  const nativeToString = Function.prototype.toString;
  Function.prototype.toString = function () {
    return nativeStubs.has(this) ? nativeStubs.get(this) : nativeToString.call(this);
  };
  nativeStubs.set(Function.prototype.toString, nativeToString.call(nativeToString));

  // 1. navigator.webdriver -- the single most-checked automation flag (a W3C WebDriver spec
  // requirement Playwright itself sets True). Real Chrome's own property descriptor is a getter,
  // not a plain value -- redefining it the same way (not just assignment) survives a
  // `'webdriver' in navigator` existence check too.
  const webdriverGetter = () => undefined;
  nativeStubs.set(webdriverGetter, 'function get webdriver() { [native code] }');
  Object.defineProperty(Navigator.prototype, 'webdriver', { get: webdriverGetter, configurable: true });

  // 2/3. navigator.plugins / navigator.mimeTypes -- headless Chromium reports an empty
  // PluginArray; real Chrome always has at least the built-in PDF viewer. Paired so a plugin
  // without a matching mimeType (or vice versa) doesn't itself become the tell.
  const fakePluginData = [
    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer', description: 'Portable Document Format', mime: 'application/pdf' },
    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', description: '', mime: 'application/pdf' },
    { name: 'Native Client', filename: 'internal-nacl-plugin', description: '', mime: 'application/x-nacl' },
  ];
  const makeMimeType = (p) => ({ type: p.mime, suffixes: '', description: p.description, enabledPlugin: null });
  const fakeMimeTypes = fakePluginData.map(makeMimeType);
  const fakePlugins = fakePluginData.map((p, i) => {
    const plugin = { name: p.name, filename: p.filename, description: p.description, length: 1, item: () => fakeMimeTypes[i], namedItem: () => fakeMimeTypes[i], 0: fakeMimeTypes[i] };
    fakeMimeTypes[i].enabledPlugin = plugin;
    return plugin;
  });
  const pluginArrayLike = (arr) => Object.assign(Object.create(Object.prototype), arr, {
    length: arr.length, item: (i) => arr[i], namedItem: (n) => arr.find((x) => x.name === n) || null,
  });
  const pluginsGetter = () => pluginArrayLike(fakePlugins);
  nativeStubs.set(pluginsGetter, 'function get plugins() { [native code] }');
  Object.defineProperty(Navigator.prototype, 'plugins', { get: pluginsGetter, configurable: true });
  const mimeTypesGetter = () => pluginArrayLike(fakeMimeTypes);
  nativeStubs.set(mimeTypesGetter, 'function get mimeTypes() { [native code] }');
  Object.defineProperty(Navigator.prototype, 'mimeTypes', { get: mimeTypesGetter, configurable: true });

  // 4. window.chrome -- genuinely absent in headless by default (live-confirmed); every real
  // Chrome install always has this global. A minimal but present shape, not a full implementation.
  if (!window.chrome) {
    const loadTimes = function () {};
    const csi = function () {};
    nativeStubs.set(loadTimes, 'function loadTimes() { [native code] }');
    nativeStubs.set(csi, 'function csi() { [native code] }');
    window.chrome = { runtime: {}, loadTimes, csi, app: {} };
  }

  // 5. navigator.languages -- a plausible, common default rather than whatever the container's
  // own locale happens to report.
  const languagesGetter = () => ['en-US', 'en'];
  nativeStubs.set(languagesGetter, 'function get languages() { [native code] }');
  Object.defineProperty(Navigator.prototype, 'languages', { get: languagesGetter, configurable: true });

  // 6. WebGL vendor/renderer -- headless's software (SwiftShader) renderer string is itself a
  // fingerprinting tell. Intercepts only the two UNMASKED_* parameters (from the standard
  // WEBGL_debug_renderer_info extension), falls through to the real implementation otherwise.
  const UNMASKED_VENDOR_WEBGL = 37445;
  const UNMASKED_RENDERER_WEBGL = 37446;
  for (const proto of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
    if (!proto) continue;
    const originalGetParameter = proto.prototype.getParameter;
    const patchedGetParameter = function (parameter) {
      if (parameter === UNMASKED_VENDOR_WEBGL) return 'Google Inc. (Intel)';
      if (parameter === UNMASKED_RENDERER_WEBGL) return 'ANGLE (Intel, Intel(R) UHD Graphics 620, OpenGL 4.5)';
      return originalGetParameter.call(this, parameter);
    };
    nativeStubs.set(patchedGetParameter, 'function getParameter() { [native code] }');
    proto.prototype.getParameter = patchedGetParameter;
  }

  // 7. navigator.permissions.query('notifications') -- headless reports a hardcoded 'denied' with
  // no prompt, inconsistent with a real browser's actual Notification.permission state (a known,
  // cheaply-checkable mismatch). Every other permission name is passed through unchanged.
  if (window.navigator.permissions && window.navigator.permissions.query) {
    const originalQuery = window.navigator.permissions.query.bind(window.navigator.permissions);
    const patchedQuery = (parameters) => (
      parameters && parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission, onchange: null })
        : originalQuery(parameters)
    );
    nativeStubs.set(patchedQuery, 'function query() { [native code] }');
    window.navigator.permissions.query = patchedQuery;
  }
})();
"""
