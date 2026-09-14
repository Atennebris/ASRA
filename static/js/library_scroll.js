// Real, confirmed operator complaint: any action on a Library source card (delete, analyze,
// stop-analysis, the per-card self-poll) swaps the WHOLE #library-sources list via
// hx-swap="outerHTML" -- htmx replaces that node with a fresh one, and if the new content is even
// one card shorter than before (a delete being the obvious case), the ancestor scroll container's
// scrollHeight shrinks; the browser then clamps its own scrollTop down to the new max, which reads
// as "the list jumped to the bottom" the moment several sources are loaded and the operator wasn't
// already scrolled to the very top. Fixed the general way, not per-button: save that ancestor's
// scrollTop right before ANY swap of #library-sources, restore it right after -- still clamped
// naturally by the browser to whatever the new (possibly shorter) content can actually support,
// never forced further than that, just no longer reset to whatever the browser's own default
// landed on.
//
// Attached to `document`, not `document.body` -- this <script> tag (base.html) loads in <head>,
// before <body> exists at all yet, and `document.body.addEventListener(...)` here threw a
// TypeError synchronously on every page load (confirmed live via the browser console, not caught
// by any manual click-through -- the exception fires before the operator does anything), silently
// making the whole fix inert: neither listener ever actually got registered, so every symptom
// this file was meant to fix kept happening exactly as before. `document` itself always exists
// regardless of <script> placement, and these events bubble to it exactly the same way they would
// to document.body -- same root cause and same fix shape debug_events.js's own top-of-file
// comment already documents for the identical mistake made once before in this project.
(function () {
  var savedScrollTop = null;
  var scrollHost = null;

  // Only ever touches these two variables from the event pair that actually matches
  // #library-sources itself -- a #library-sources swap's own newly-inserted content immediately
  // fires MORE htmx requests of its own (every card's chunk-estimate span re-triggers on "load"
  // the instant it lands in the DOM), and those unrelated swaps' own beforeSwap/afterSwap events
  // fire in between this swap's own pair; filtering by target id here means none of them can ever
  // clobber the saved position before the real afterSwap gets to use it.
  document.addEventListener("htmx:beforeSwap", function (evt) {
    var target = evt.detail.target;
    if (!target || target.id !== "library-sources") return;
    scrollHost = target.closest(".overflow-y-auto");
    savedScrollTop = scrollHost ? scrollHost.scrollTop : null;
  });

  document.addEventListener("htmx:afterSwap", function (evt) {
    var target = evt.detail.target;
    if (!target || target.id !== "library-sources") return;
    if (scrollHost && savedScrollTop !== null) {
      scrollHost.scrollTop = savedScrollTop;
    }
    scrollHost = null;
    savedScrollTop = null;
  });
})();
