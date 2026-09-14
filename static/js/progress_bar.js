// Top loading bar. Drives #asra-progress (base.html): a thin accent strip that fills while the page
// (or an htmx request) is in flight, then completes and fades out. No dependency -- just width/opacity
// transitions nudged by a timer, plus htmx lifecycle hooks.
//
// Two triggers:
//   - initial document load: start as soon as this script runs, finish on window 'load' (covers the
//     Tailwind first-paint work that makes a fresh page feel slow).
//   - htmx requests: user-driven swaps/navigations only. Background pollers (the sidebar's active-
//     session/system-health widgets, hx-trigger="every Ns") are excluded so the bar never flickers
//     on its own every few seconds.
(function () {
  var bar = document.getElementById("asra-progress");
  if (!bar) return;

  var timer = null;
  var progress = 0;

  function paint(pct) {
    progress = pct;
    bar.style.width = pct + "%";
  }

  function start() {
    if (timer) return; // already running -- don't restart from 0 mid-flight
    bar.classList.add("asra-progress--active");
    paint(8);
    timer = setInterval(function () {
      // Ease toward 90% and hold there until done() -- never reach 100% on the timer alone, so the
      // bar can't "complete" before the request actually has.
      if (progress < 90) {
        var increment = (90 - progress) * 0.15;
        paint(progress + (increment < 0.4 ? 0.4 : increment));
      }
    }, 200);
  }

  function done() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    paint(100);
    setTimeout(function () {
      bar.classList.remove("asra-progress--active");
      setTimeout(function () { paint(0); }, 300); // reset width only after the fade-out finishes
    }, 200);
  }

  function isBackgroundPoll(evt) {
    var elt = evt.detail && evt.detail.elt;
    if (!elt || !elt.getAttribute) return false;
    return /\bevery\b/.test(elt.getAttribute("hx-trigger") || "");
  }

  // Opt-out for a request whose target ALREADY gives its own instant, local feedback -- a
  // page-wide loading bar on top of that reads as "still working" noise for something that
  // finished (visually) the instant it was clicked. Real, confirmed operator complaint this
  // fixes: switching a chat tab already flips the active tab synchronously (chat_panel.html's
  // own markTabActiveOptimistically), but the bar still ran for the ~200-500ms its actual
  // /chat/switch-thread round trip took, reading as a visible "loading" moment the operator
  // explicitly did not want to see at all. `closest` (not just the exact element) since the
  // marker sits on the <form>, matching how hx-confirm/hx-disabled-elt etc. are placed relative
  // to the thing that actually issues the request.
  function isSuppressed(evt) {
    var elt = evt.detail && evt.detail.elt;
    return !!(elt && elt.closest && elt.closest("[data-no-progress-bar]"));
  }

  // Initial page load.
  start();
  if (document.readyState === "complete") {
    done();
  } else {
    window.addEventListener("load", done);
  }

  // htmx request lifecycle (user-driven only).
  document.body.addEventListener("htmx:beforeRequest", function (e) {
    if (!isBackgroundPoll(e) && !isSuppressed(e)) start();
  });
  document.body.addEventListener("htmx:afterRequest", function (e) {
    if (!isBackgroundPoll(e) && !isSuppressed(e)) done();
  });

  // Full-page navigations (plain <a href> / non-htmx form posts). No page here uses hx-boost, so a
  // sidebar click is a genuine navigation: the browser keeps rendering the CURRENT document while
  // the server works on the next one. In a normal browser the tab's own spinner covers that gap;
  // in the chromeless desktop shell there is no such spinner, so a slow render (e.g. Settings) looks
  // like a frozen window. Starting the bar on the click/submit that triggers the navigation fills
  // that gap -- the destination document's own initial-load handling above takes over once it lands.
  // A real navigation tears down this whole document (timer included), so the safety timeout below
  // only ever fires if the navigation was cancelled, self-healing a bar that would otherwise stick.
  var navSafetyTimer = null;
  function startForNavigation() {
    start();
    if (navSafetyTimer) clearTimeout(navSafetyTimer);
    navSafetyTimer = setTimeout(done, 12000);
  }
  function isModifiedClick(e) {
    return e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey;
  }
  document.addEventListener("click", function (e) {
    if (e.defaultPrevented || isModifiedClick(e)) return;
    var link = e.target.closest && e.target.closest("a[href]");
    if (!link) return;
    if (link.target && link.target !== "_self") return;   // opens elsewhere -- this page stays put
    if (link.hasAttribute("download")) return;             // a download, not a navigation
    if (link.closest("[hx-get],[hx-post],[hx-put],[hx-delete],[hx-boost]")) return; // htmx handles it
    var href = link.getAttribute("href") || "";
    if (!href || href.charAt(0) === "#" || href.lastIndexOf("javascript:", 0) === 0) return;
    startForNavigation();
  });
  document.addEventListener("submit", function (e) {
    if (e.defaultPrevented) return;
    var form = e.target;
    if (form && form.closest && form.closest("[hx-get],[hx-post],[hx-put],[hx-delete],[hx-boost]")) return;
    startForNavigation();
  });
})();
