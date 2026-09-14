// Live View input forwarding (main.py's toolkit_live_view_input route, agent/tools/
// browser_manager.py's dispatch_live_view_input) -- turns the read-only screencast frame
// (templates/partials/toolkit_live_view.html) into something you can actually click/scroll/type
// into, by forwarding real browser events straight into the agent's own Playwright page.
//
// Delegated on document, never attached directly to the <img> -- main.py's toolkit_screencast_
// stream SSE route replaces that element's innerHTML roughly every 300ms (a new frame), which
// would silently drop any listener attached to the old element the instant the first new frame
// arrived (same reasoning debug_events.js's own document-level delegation already documents for
// htmx-morphed elements).
(function () {
  function liveFrame(el) {
    var img = el && el.closest ? el.closest("#toolkit-live-frame") : null;
    return img && img.tagName === "IMG" ? img : null;
  }

  function send(type, detail) {
    var match = window.location.pathname.match(/\/session\/([A-Za-z0-9_]+)/);
    if (!match) return;
    try {
      fetch("/api/session/" + match[1] + "/toolkit/live-view/input", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(detail),
      }).catch(function () {});
    } catch (e) {
      // A dropped input event must never break the rest of the page.
    }
    if (window.asraDebugEvent) window.asraDebugEvent("live-view-input", type + " " + JSON.stringify(detail));
  }

  // Converts an on-screen click position into real page-space coordinates -- the displayed <img>
  // is a CDP-downscaled preview (start_screencast's own maxWidth/maxHeight=1024x768), not the
  // actual page viewport size page.mouse operates in, so this scales by the real viewport
  // dimensions main.py's stream route stamps onto the element (data-viewport-*), never by the
  // image's own rendered/natural pixel size.
  function pagePoint(img, clientX, clientY) {
    var rect = img.getBoundingClientRect();
    var vpWidth = parseFloat(img.dataset.viewportWidth);
    var vpHeight = parseFloat(img.dataset.viewportHeight);
    if (!rect.width || !rect.height || !vpWidth || !vpHeight) return null;
    return {
      x: ((clientX - rect.left) / rect.width) * vpWidth,
      y: ((clientY - rect.top) / rect.height) * vpHeight,
    };
  }

  document.addEventListener("click", function (event) {
    var img = liveFrame(event.target);
    if (!img) return;
    img.focus();
    var point = pagePoint(img, event.clientX, event.clientY);
    if (!point) return;
    send("click", { type: "click", x: point.x, y: point.y, button: "left" });
  });

  document.addEventListener("dblclick", function (event) {
    var img = liveFrame(event.target);
    if (!img) return;
    var point = pagePoint(img, event.clientX, event.clientY);
    if (!point) return;
    send("dblclick", { type: "click", x: point.x, y: point.y, button: "left", click_count: 2 });
  });

  // The browser's own right-click context menu makes no sense over a remote page preview --
  // suppressed so the click reaches the target page's own context menu (or plain right-click
  // handler) instead of ASRA's.
  document.addEventListener("contextmenu", function (event) {
    var img = liveFrame(event.target);
    if (!img) return;
    event.preventDefault();
    var point = pagePoint(img, event.clientX, event.clientY);
    if (!point) return;
    send("right-click", { type: "click", x: point.x, y: point.y, button: "right" });
  });

  // passive: false -- required for preventDefault() to actually stop the whole ASRA page from
  // scrolling underneath the frame while the operator scrolls the remote page inside it.
  document.addEventListener("wheel", function (event) {
    var img = liveFrame(event.target);
    if (!img) return;
    event.preventDefault();
    send("wheel", { type: "wheel", dx: event.deltaX, dy: event.deltaY });
  }, { passive: false });

  // JS KeyboardEvent.key for the space bar is a literal " " -- Playwright's own USKeyboardLayout
  // names it "Space" instead (agent/tools/browser_manager.py's own _LIVE_VIEW_KEY_OVERRIDES has
  // the matching server-side override); every other key already matches between the two.
  var KEY_OVERRIDES = { " ": "Space" };
  document.addEventListener("keydown", function (event) {
    var img = liveFrame(document.activeElement);
    if (!img) return;
    event.preventDefault();
    send("keydown", { type: "keydown", key: KEY_OVERRIDES[event.key] || event.key });
  });
})();
