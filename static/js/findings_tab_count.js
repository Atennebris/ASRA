// Findings tab's own live count (macros/ui.html's tab_bar()) -- the tab bar is a deliberate direct
// sibling of #session-stream, outside the SSE morph target entirely (session.html's own long
// comment on tab_bar() explains why: keeping it there is what stops a live update from resetting
// whichever tab the operator currently has open). That same isolation means the count baked into
// the tab label text never got a live update either, stuck at whatever it was on the page's very
// first load until a manual reload -- the operator's own real complaint.
//
// htmx's own out-of-band swap (hx-swap-oob) looks like the obvious fix, but doesn't work here:
// with hx-ext="sse, morph" active on #session-stream, the "morph" extension's own isInlineSwap
// only recognizes swap-style strings starting with "morph" -- ANY other swap style (including
// whatever an hx-swap-oob="true" element resolves to) makes it throw
// "TypeError: Cannot read properties of undefined (reading 'swapStyle')", confirmed live on every
// single SSE update once an OOB element was added, real headless-browser testing (Playwright), not
// a guess. The OOB swap itself still silently completed despite the thrown error, but a real
// exception on every live update forever is not an acceptable "it technically works" state.
//
// This sidesteps the whole morph/OOB interaction: #session-content (the actual, always-correctly-
// morphed root) already carries a fresh data-findings-count attribute on every real render
// (session_fragment.html) -- htmx:afterSwap already fires on every successful SSE morph (same
// event diagram_builder.js's own re-init already listens for), so just copy that attribute's
// current value into the tab bar's span by hand, no OOB/morph interaction involved at all.
(function () {
  function syncFindingsCount() {
    var content = document.getElementById("session-content");
    var badge = document.getElementById("findings-tab-count");
    if (!content || !badge) return;
    var count = parseInt(content.getAttribute("data-findings-count") || "0", 10);
    badge.textContent = count > 0 ? " (" + count + ")" : "";
  }

  document.addEventListener("DOMContentLoaded", syncFindingsCount);
  document.addEventListener("htmx:afterSwap", syncFindingsCount);
})();
