// Shared, generic "remember what I had open/selected in THIS session" persistence -- one small
// localStorage-backed key/value store, namespaced per session, so every other page script that
// wants to survive a reload (recon_filter.js/findings_filter.js's own active filter tiles, this
// file's own <details> open/closed tracking below) reads from and writes to the same place instead
// of each reinventing its own storage-key scheme. Loaded before those scripts in base.html --
// they call straight into window.asraSessionState, same "load once, other scripts depend on it"
// convention as window.asraConfirm/window.asraDebugEvent.
//
// Deliberately NOT what restores the active session TAB itself -- that one restore has to run
// synchronously, inline, immediately after the tab bar's own radios (macros/ui.html's tab_bar()
// macro has the real reasoning) so there's nothing to visibly flash on a large page; everything
// here is fine running on the normal DOMContentLoaded schedule, since a filter tile or an expanded
// <details> row popping into its saved state a moment after first paint is a small, ordinary
// enhancement flicker, not a jarring "wrong content, then right content" full-panel swap.
(function () {
  function sessionIdFromPath() {
    var match = window.location.pathname.match(/\/session\/([^/?#]+)/);
    return match ? match[1] : null;
  }

  function storageKey(key) {
    var sessionId = sessionIdFromPath();
    return sessionId ? "asra-session-state-" + sessionId + "-" + key : null;
  }

  // Every "restore on load" listener in this app (this file's own <details> restore below,
  // recon_filter.js/findings_filter.js's own active-tile restore) needs this instead of a bare
  // `document.addEventListener("DOMContentLoaded", fn)` -- confirmed live, on this exact page: a
  // completed scan's session page is large enough, and StaticFiles serves each of the many
  // <script src> tags in base.html's <head> as its own separate request, that DOMContentLoaded can
  // already have fired by the time a LATER script in that list (findings_filter.js, near the end)
  // finishes loading and reaches its own `addEventListener("DOMContentLoaded", ...)` call --
  // registering a listener for an event that already happened means it silently never fires again,
  // real, reproducible, not a hypothetical: a saved Findings-tab filter reload-tested as "restored
  // instantly" every time it happened to land before the event, and "never restored at all" every
  // time it didn't, no error, no visible sign why. document.readyState is authoritative for
  // whether the event has already passed ("loading" is the only state before it fires) --
  // checking it and running immediately in that case closes the race regardless of root cause.
  window.asraOnDomReady = function (fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  };

  window.asraSessionState = {
    get: function (key) {
      var storageKeyStr = storageKey(key);
      if (!storageKeyStr) return null;
      try {
        var raw = localStorage.getItem(storageKeyStr);
        return raw === null ? null : JSON.parse(raw);
      } catch (e) {
        return null;
      }
    },
    set: function (key, value) {
      var storageKeyStr = storageKey(key);
      if (!storageKeyStr) return;
      try {
        localStorage.setItem(storageKeyStr, JSON.stringify(value));
      } catch (e) {
        // Storage can legitimately be full/unavailable (private browsing) -- losing this one bit
        // of remembered UI state is a minor inconvenience, never worth breaking the real feature
        // (the filter/details toggle itself, which already happened) over.
      }
    },
  };

  // <details> open/closed state -- generic, id-based, no per-feature code needed: any
  // <details id="..."> inside the page (recon target rows, log entry cards, the Summary tab's
  // "View as table") is covered automatically just by having a stable id. Capture phase on
  // `document` so this keeps working regardless of whether "toggle" bubbles in a given browser,
  // and survives any later SSE morph swap replacing the actual element underneath it -- same
  // delegation reasoning as recon_filter.js/debug_events.js's own listeners.
  //
  // Restore uses querySelectorAll + a manual id match, never document.getElementById -- confirmed
  // live, a real operator complaint: log_entry_card() (session_fragment.html) renders the SAME
  // log-step-N id more than once on purpose (the same step shows in its own phase tab -- Recon/
  // Analyze/Exploit -- AND again in the unfiltered main Logs tab, AND again inside whichever
  // finding's own "Activity for this finding" dialog references it), so log-step ids are
  // genuinely, deliberately duplicated across the page. getElementById only ever returns the
  // FIRST match in document order, which is very often a copy sitting in a different, currently
  // hidden tab than the one the operator actually expanded and reloaded from -- so their own
  // visible row silently stayed closed while an invisible duplicate elsewhere got the state
  // instead. Setting .open on every matching id keeps every copy of the same log step in sync,
  // which is the actually-correct behavior for what's conceptually one underlying entry anyway.
  document.addEventListener("toggle", function (event) {
    var el = event.target;
    if (!el.id || el.tagName !== "DETAILS") return;
    var openDetails = window.asraSessionState.get("open-details") || {};
    openDetails[el.id] = el.open;
    window.asraSessionState.set("open-details", openDetails);
  }, true);

  window.asraOnDomReady(function () {
    var openDetails = window.asraSessionState.get("open-details") || {};
    if (!Object.keys(openDetails).length) return;
    document.querySelectorAll("details[id]").forEach(function (el) {
      if (Object.prototype.hasOwnProperty.call(openDetails, el.id)) el.open = openDetails[el.id];
    });
  });

  // Scroll position -- <main> (base.html's real scroll container: the app shell is a fixed
  // h-screen flex row with overflow-hidden, and <main> itself carries overflow-y-auto -- confirmed
  // live that window/document never scroll at all here, window.scrollY stayed 0 through a real,
  // visible scroll gesture, so a naive window.scrollY/scrollTo implementation would silently do
  // nothing on this app), plus any internal panel opted in via data-scroll-persist="<unique key>"
  // (the main Logs list, each phase tab's own log list, each Subagent log group's own list --
  // session_fragment.html). Real, confirmed operator complaint: scrolling deep into a long log
  // list, or deep into a long tab's own content, then reloading, always teleported straight back
  // to the top with no way back to where they'd actually been reading.
  //
  // <main> is the ONE element shared across every session tab (only the section[data-tab] panels
  // inside it toggle visibility, see macros/ui.html's tab_bar()), so its scrollTop means something
  // completely different depending which tab happens to be showing through it -- keyed by
  // whichever tab was active at save time (mainScrollKey below), so restoring never applies a deep
  // Plan-tab scroll position under Findings' own, much shorter content. Every other, non-session
  // page (no tab bar at all) falls back to one flat key -- still useful, just not tab-scoped.
  function activeSessionTabId() {
    var checked = document.querySelector('input[name="session-tab"]:checked');
    return checked ? checked.id : null;
  }

  function mainScrollKey() {
    var tabId = activeSessionTabId();
    return tabId ? "main-content-" + tabId : "main-content";
  }

  // 'scroll' doesn't bubble either (same as 'toggle' above) -- capture phase on `document` still
  // reaches it regardless. Saves are debounced (a scroll gesture fires dozens of events a second --
  // writing localStorage on every single one would be pure waste, the last one after scrolling
  // stops is all that matters) and merged into one object so N scrollable panels cost one storage
  // key, not N.
  var SCROLL_SAVE_DEBOUNCE_MS = 150;
  var scrollSaveTimers = {};

  function saveScrollPosition(key, value) {
    clearTimeout(scrollSaveTimers[key]);
    scrollSaveTimers[key] = setTimeout(function () {
      var positions = window.asraSessionState.get("scroll-positions") || {};
      positions[key] = value;
      window.asraSessionState.set("scroll-positions", positions);
    }, SCROLL_SAVE_DEBOUNCE_MS);
  }

  document.addEventListener("scroll", function (event) {
    var el = event.target;
    if (!el.tagName) return;
    if (el.tagName === "MAIN") {
      saveScrollPosition(mainScrollKey(), el.scrollTop);
      return;
    }
    var key = el.getAttribute && el.getAttribute("data-scroll-persist");
    if (!key) return;
    saveScrollPosition(key, el.scrollTop);
  }, true);

  // Applied through a real page reload's own layout settling (restoreScrollPositions runs after
  // asraOnDomReady, which can itself run before every OTHER restore this app does -- an open
  // <details> restored a moment later adds real height above a scroll target, an SSE morph a
  // moment after that can reflow a panel's contents again) -- double requestAnimationFrame defers
  // to the frame AFTER every synchronous DOMContentLoaded listener (regardless of which script
  // registered it, session_state.js's own included) has already run and finished mutating the DOM,
  // so this always measures/restores against the page's actually settled layout, never a transient
  // one. mainScrollKey() reads whichever tab radio is checked AT RESTORE TIME -- always correct
  // here since the tab bar's own restore (macros/ui.html's inline script) runs synchronously,
  // before this ever gets a chance to fire. Re-run on every "htmx:afterSwap" too (same reapply
  // pattern findings_filter.js/recon_filter.js already use) -- confirmed live elsewhere on this
  // page: idiomorph patching a scrollable container's own children can reset its scrollTop to 0 as
  // a side effect, independent of anything this app's own beforeAttributeUpdated guards cover.
  // Exposed on window so session_tab_memory.js can re-run it right after a tab switch too --
  // <main>'s own scrollTop doesn't reset itself just because the tab underneath it changed, so
  // without this a tab switched into would keep showing wherever the PREVIOUS tab happened to be
  // scrolled to.
  //
  // Two modes, not one, because "apply the saved value" is actively wrong in one of the three
  // callers below: mode="force" (initial load, tab switch) always sets scrollTop from whatever's
  // saved, resetting to 0 when nothing is -- exactly right for "this tab/page just became visible,
  // start it from a known state". mode="gentle" (htmx:afterSwap) only RESCUES a container idiomorph
  // just reset to 0 as a side effect of patching its children (the real, confirmed bug this whole
  // feature exists for) -- confirmed live, the very first version of this function used "force"
  // logic for the afterSwap case too, and on a session whose SSE stream keeps re-rendering every
  // few seconds (a real, observed behavior on this app, not hypothetical), that meant every
  // afterSwap event SNAPPED THE OPERATOR'S OWN, ACTIVE, MID-GESTURE SCROLLING BACK to whatever
  // position had been saved BEFORE they started scrolling -- an unusable page for as long as the
  // stream kept updating. Checking current scrollTop === 0 before touching anything means a
  // container the operator is genuinely, currently scrolling (nonzero scrollTop, whether or not
  // the debounce above has flushed it to storage yet) is never touched by this path at all.
  function restoreScrollPositions(mode) {
    var positions = window.asraSessionState.get("scroll-positions") || {};
    var force = mode === "force";

    function apply(el, key) {
      var saved = positions[key];
      if (force) {
        el.scrollTop = typeof saved === "number" ? saved : 0;
      } else if (typeof saved === "number" && saved > 0 && el.scrollTop === 0) {
        el.scrollTop = saved;
      }
    }

    var mainEl = document.querySelector("main");
    if (mainEl) apply(mainEl, mainScrollKey());
    document.querySelectorAll("[data-scroll-persist]").forEach(function (el) {
      apply(el, el.getAttribute("data-scroll-persist"));
    });
  }
  window.asraRestoreScrollPositions = restoreScrollPositions;

  window.asraOnDomReady(function () {
    requestAnimationFrame(function () { requestAnimationFrame(function () { restoreScrollPositions("force"); }); });
  });
  document.addEventListener("htmx:afterSwap", function () {
    requestAnimationFrame(function () { restoreScrollPositions("gentle"); });
  });
})();
