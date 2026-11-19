/* Whole-UI zoom for the DESKTOP shell: Ctrl/Cmd + "+" / "-" step it, Ctrl/Cmd + mouse wheel (or a
   trackpad pinch) scales it, Ctrl/Cmd + "0" returns to 100%.

   This drives the webview's NATIVE zoom (the `set_page_zoom` Tauri command -> WebView2 ZoomFactor),
   the same mechanism Electron's webContents.setZoomFactor and a browser's own Ctrl +/- use: the
   engine re-lays out the page at a smaller/larger CSS viewport, so the sidebar, the h-screen shell,
   fixed panels and canvases all stay glued to the window edges. An earlier version set CSS `zoom` on
   <html> instead, which scales elements but not the viewport units the app shell is built on
   (h-screen, calc(100vh - ...)) -- zoomed out, the whole UI shrank into the top-left corner with
   empty space below and to the right; zoomed in, it overflowed.

   In a plain browser tab this file does nothing on purpose: the browser's own Ctrl +/- and
   Ctrl+wheel already zoom natively there, and intercepting them would only get in its way.

   The level is remembered per machine (localStorage) and re-applied on every page load, because a
   full navigation inside the shell does not reliably keep the webview's zoom. An element (or
   ancestor) marked [data-asra-no-page-zoom] keeps Ctrl+wheel for its own use (e.g. a canvas with its
   own zoom). */
(function () {
  "use strict";

  var tauri = window.__TAURI__;
  var invoke = tauri && tauri.core && tauri.core.invoke;
  if (!invoke) return;

  var STORAGE_KEY = "asra-ui-zoom";
  var DEFAULT = 1;
  // Chrome's own zoom steps (what Electron/Edge users already expect), clamped to a usable range.
  var LEVELS = [0.5, 0.67, 0.75, 0.8, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2, 2.5, 3];
  var WHEEL_STEP_DELTA = 40; // accumulated deltaY that counts as one step, so a trackpad pinch is not a firehose
  var toastTimer = null;
  var wheelAccumulator = 0;
  var current = DEFAULT;

  function read() {
    try {
      var stored = parseFloat(localStorage.getItem(STORAGE_KEY));
      return isNaN(stored) ? DEFAULT : Math.min(LEVELS[LEVELS.length - 1], Math.max(LEVELS[0], stored));
    } catch (e) { return DEFAULT; }
  }

  function nextLevel(from, direction) {
    if (direction > 0) {
      for (var i = 0; i < LEVELS.length; i++) if (LEVELS[i] > from + 0.001) return LEVELS[i];
      return LEVELS[LEVELS.length - 1];
    }
    for (var j = LEVELS.length - 1; j >= 0; j--) if (LEVELS[j] < from - 0.001) return LEVELS[j];
    return LEVELS[0];
  }

  function showToast(level, label) {
    var toast = document.getElementById("asra-zoom-toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "asra-zoom-toast";
      toast.setAttribute("role", "status");
      toast.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:2147483647;padding:6px 12px;" +
        "border-radius:8px;font:600 12px/1 ui-monospace,monospace;background:rgba(20,28,28,.92);" +
        "color:#e6edf3;border:1px solid rgba(255,255,255,.18);pointer-events:none;transition:opacity .2s;" +
        "transform-origin:bottom right;";
      document.body.appendChild(toast);
    }
    // Native zoom scales the toast like everything else; undo that so it stays a constant size.
    toast.style.transform = "scale(" + (1 / level) + ")";
    toast.textContent = label || ("Zoom " + Math.round(level * 100) + "%");
    toast.style.opacity = "1";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.style.opacity = "0"; }, 1200);
  }

  function setNative(level) {
    return invoke("set_page_zoom", { factor: level }).then(function () { return true; }, function (error) {
      // An older desktop build without the command: nothing to zoom with, never break the page.
      if (window.asraDebugEvent) window.asraDebugEvent("ui-zoom", "native zoom unavailable: " + error);
      return false;
    });
  }

  function apply(level) {
    level = Math.round(level * 100) / 100;
    current = level;
    try { localStorage.setItem(STORAGE_KEY, String(level)); } catch (e) { /* private window: still zooms, just not remembered */ }
    // A refusal must be visible: the first version of this failed silently (the command was missing
    // from the ACL) and looked like "zoom does nothing" with no clue why.
    setNative(level).then(function (ok) {
      showToast(ok ? level : 1, ok ? "" : "Zoom unavailable - update the ASRA desktop app");
    });
    if (window.asraDebugEvent) window.asraDebugEvent("ui-zoom", "level=" + level);
  }

  window.addEventListener("keydown", function (event) {
    if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
    var key = event.key;
    if (key === "+" || key === "=") apply(nextLevel(current, 1));
    else if (key === "-" || key === "_") apply(nextLevel(current, -1));
    else if (key === "0") apply(DEFAULT);
    else return;
    event.preventDefault();
  }, true);

  // passive:false -- preventDefault is what stops the engine's own pinch/page zoom from stacking on ours.
  window.addEventListener("wheel", function (event) {
    if (!(event.ctrlKey || event.metaKey)) return;
    if (event.target && event.target.closest && event.target.closest("[data-asra-no-page-zoom]")) return;
    event.preventDefault();
    wheelAccumulator += event.deltaY;
    if (Math.abs(wheelAccumulator) < WHEEL_STEP_DELTA) return;
    apply(nextLevel(current, wheelAccumulator < 0 ? 1 : -1));
    wheelAccumulator = 0;
  }, { passive: false, capture: true });

  // Re-apply the remembered level on every full page load (silently: no toast on navigation).
  // At 100% there is nothing to restore (a fresh page starts there), so skip the IPC round trip and
  // the relayout it can trigger -- every sidebar click is a full page load and must stay instant.
  current = read();
  if (current !== DEFAULT) setNative(current);
})();
