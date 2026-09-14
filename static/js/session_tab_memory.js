// Session tab bar (macros/ui.html's tab_bar(), CSS-only radio+:has()) -- persists whichever tab
// the operator switches to, so a later reload can restore it. Also covers RE mode's own separate
// Graph/Logs/Findings/Summary tab bar (session.html, name="re-info-tab") -- a different radio
// group with its own id prefix, but the same "remember it, restore before paint" need; one shared
// listener here covers both rather than a second copy-pasted file. The actual RESTORE-on-load half
// of this feature is deliberately NOT here: it has to run synchronously, inline, immediately after
// each tab bar's own radios (see tab_bar()'s own long comment, and session.html's matching inline
// script for the RE tab bar, for why a deferred script here would let the server-rendered default
// tab visibly flash on screen first on a large page). This file is only the "remember the
// operator's later choices" half -- every click that actually changes tabs after the initial
// restore.
(function () {
  function sessionIdFromPath() {
    var match = window.location.pathname.match(/\/session\/([^/?#]+)/);
    return match ? match[1] : null;
  }

  document.addEventListener("change", function (event) {
    var el = event.target;
    var isSessionTab = el.matches && el.matches('input[name="session-tab"]');
    var isReInfoTab = el.matches && el.matches('input[name="re-info-tab"]');
    if (!el.checked || (!isSessionTab && !isReInfoTab)) return;
    var sessionId = sessionIdFromPath();
    if (!sessionId) return;
    if (isSessionTab) {
      localStorage.setItem("asra-session-tab-" + sessionId, el.id.replace(/^tab-/, ""));
    } else {
      localStorage.setItem("asra-re-info-tab-" + sessionId, el.id.replace(/^re-info-/, ""));
    }
    // <main>'s own scroll position is keyed per-tab (session_state.js's mainScrollKey) -- without
    // this, switching tabs kept showing whichever scroll depth the PREVIOUS tab was left at,
    // instead of either restoring this tab's own last position or starting fresh at the top.
    // "force" (not "gentle") is deliberate here -- see session_state.js's own comment on the two
    // modes: a tab switch is a real "this content just became visible" moment, unlike a mid-scan
    // SSE morph landing while the operator is actively scrolling, so it should always apply
    // whatever's saved (or reset to top) rather than only rescuing an accidental reset-to-0.
    if (window.asraRestoreScrollPositions) window.asraRestoreScrollPositions("force");
  });
})();
