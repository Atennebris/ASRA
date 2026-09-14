// Browser-side half of the debug module (agent/utils/debug.py's "UI" category) — sends a compact
// description of every click, form field change, and htmx request/response/SSE lifecycle event to
// /api/debug/client-event, which logs it server-side under the UI category. No-ops entirely
// unless window.ASRA_DEBUG is true (base.html only sets that when DEBUG=true) so there is zero
// extra network traffic in normal use — this app's debug module is meant to cover every module,
// backend and UI alike, without extra runtime cost when it's turned off.
(function () {
  function currentSessionId() {
    var match = window.location.pathname.match(/\/session\/([A-Za-z0-9_]+)/);
    return match ? match[1] : null;
  }

  function send(action, detail) {
    if (!window.ASRA_DEBUG) return;
    try {
      fetch("/api/debug/client-event", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        keepalive: true,
        body: JSON.stringify({ session_id: currentSessionId(), action: action, detail: detail }),
      });
    } catch (e) {
      // Debug telemetry must never be able to break the actual UI it's watching.
    }
  }

  // Exposed so other page-specific scripts (e.g. hypotheses_paste_guard.js) can log a meaningful
  // decision point through the same category/endpoint instead of each reimplementing this fetch —
  // still a silent no-op whenever ASRA_DEBUG is off, callers never need their own guard for that.
  window.asraDebugEvent = send;
  if (!window.ASRA_DEBUG) return;

  function describe(el) {
    if (!el) return "unknown element";
    var label = el.id ? "#" + el.id
      : el.getAttribute("name") ? el.tagName.toLowerCase() + "[name=" + el.getAttribute("name") + "]"
      : el.tagName.toLowerCase();
    var text = (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 60);
    return text ? label + ' "' + text + '"' : label;
  }

  // Capture phase, delegated on document — catches every click regardless of which page/partial
  // it landed in, survives htmx morph swaps replacing the actual elements underneath it.
  document.addEventListener("click", function (event) {
    var el = event.target.closest("button, summary, a, [role='button'], input[type='checkbox'], input[type='submit']");
    if (el) send("click", describe(el));
  }, true);

  document.addEventListener("change", function (event) {
    var el = event.target;
    if (!el.matches || !el.matches("input, select, textarea")) return;
    // Never the actual value for a password/credential-shaped field — just that it changed.
    var value = el.type === "password" ? "(hidden)" : el.type === "checkbox" ? String(el.checked) : "(value omitted)";
    send("change", describe(el) + " -> " + value);
  }, true);

  // Attached to `document`, not `document.body` -- this <script> tag (base.html) loads in <head>
  // with no defer/async, so it executes while <head> is still being parsed, before <body> exists
  // at all. `document.body.addEventListener(...)` here threw a TypeError synchronously
  // ("Cannot read properties of null"), unconditionally, the instant this ran -- confirmed live
  // with DEBUG=true (the only condition under which this code past the window.ASRA_DEBUG guard
  // above ever runs at all): every one of these five listeners silently failed to register, so the
  // debug console's own UI-click/htmx-lifecycle tracking (get_logger("UI")) never fired a single
  // event, the entire time DEBUG has been enabled. `document` is always available regardless of
  // parse timing, and these events bubble to it exactly the same way they would to document.body.
  document.addEventListener("htmx:beforeRequest", function (event) {
    var cfg = event.detail.requestConfig;
    send("htmx-request", cfg.verb.toUpperCase() + " " + cfg.path);
  });
  document.addEventListener("htmx:afterRequest", function (event) {
    var cfg = event.detail.requestConfig;
    var status = event.detail.xhr.status;
    // Not event.detail.successful -- htmx's own HX-Redirect handling (vendor/htmx.min.js) returns
    // from its response handler as soon as it sets location.href, BEFORE the code that sets
    // "successful" runs, so every response carrying that header (main.py's /api/scan, /api/scan/re,
    // ...) always logged "failed 200" here despite the request genuinely succeeding. A 2xx/3xx
    // status is a real success regardless of which internal branch htmx took to get there.
    var ok = status >= 200 && status < 400;
    send("htmx-response", (ok ? "ok" : "failed") + " " + status + " " + cfg.path);
  });
  document.addEventListener("htmx:responseError", function (event) {
    send("htmx-error", event.detail.xhr.status + " " + event.detail.requestConfig.path);
  });
  document.addEventListener("htmx:sseOpen", function () { send("sse", "connected"); });
  document.addEventListener("htmx:sseError", function () { send("sse", "error/reconnecting"); });
})();
