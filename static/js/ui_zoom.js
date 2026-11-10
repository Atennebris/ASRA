/* Whole-UI zoom: Ctrl/Cmd + "+" / "-" step it, Ctrl/Cmd + mouse wheel scales it, Ctrl/Cmd + "0"
   returns to 100%. Done in-page (CSS zoom on <html>) because the desktop shell's WebView2 has its
   native zoom hotkeys switched off, and a plain browser tab gets the identical behavior this way.
   The level is remembered per machine (localStorage) and applied by base.html's tiny inline snippet
   before first paint, so a reload never flashes at 100%. An element (or ancestor) marked
   [data-asra-no-page-zoom] keeps Ctrl+wheel for its own use (e.g. a canvas with its own zoom). */
(function () {
  "use strict";

  var STORAGE_KEY = "asra-ui-zoom";
  var MIN = 0.5, MAX = 3, STEP = 0.1, DEFAULT = 1;
  var toastTimer = null;

  function read() {
    try {
      var stored = parseFloat(localStorage.getItem(STORAGE_KEY));
      return isNaN(stored) ? DEFAULT : Math.min(MAX, Math.max(MIN, stored));
    } catch (e) { return DEFAULT; }
  }

  function showToast(level) {
    var toast = document.getElementById("asra-zoom-toast");
    if (!toast) {
      toast = document.createElement("div");
      toast.id = "asra-zoom-toast";
      toast.setAttribute("role", "status");
      toast.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:2147483647;padding:6px 12px;" +
        "border-radius:8px;font:600 12px/1 ui-monospace,monospace;background:rgba(20,28,28,.92);" +
        "color:#e6edf3;border:1px solid rgba(255,255,255,.18);pointer-events:none;transition:opacity .2s;";
      document.body.appendChild(toast);
    }
    toast.textContent = "Zoom " + Math.round(level * 100) + "%";
    toast.style.opacity = "1";
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { toast.style.opacity = "0"; }, 1200);
  }

  function apply(level) {
    level = Math.min(MAX, Math.max(MIN, Math.round(level * 100) / 100));
    document.documentElement.style.zoom = level === DEFAULT ? "" : String(level);
    try { localStorage.setItem(STORAGE_KEY, String(level)); } catch (e) { /* private window: still zooms, just not remembered */ }
    showToast(level);
    if (window.asraDebugEvent) window.asraDebugEvent("ui-zoom", "level=" + level);
  }

  window.addEventListener("keydown", function (event) {
    if (!(event.ctrlKey || event.metaKey) || event.altKey) return;
    var key = event.key;
    if (key === "+" || key === "=") apply(read() + STEP);
    else if (key === "-" || key === "_") apply(read() - STEP);
    else if (key === "0") apply(DEFAULT);
    else return;
    event.preventDefault();
  }, true);

  // passive:false -- preventDefault is what stops the browser's own pinch/page zoom from stacking on ours.
  window.addEventListener("wheel", function (event) {
    if (!(event.ctrlKey || event.metaKey)) return;
    if (event.target && event.target.closest && event.target.closest("[data-asra-no-page-zoom]")) return;
    event.preventDefault();
    apply(read() + (event.deltaY < 0 ? STEP : -STEP));
  }, { passive: false, capture: true });
})();
