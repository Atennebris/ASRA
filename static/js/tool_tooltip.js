// Hover description for the Subagents tab's tool checklist (subagents.html's tool_checklist
// macro, label[data-tool-description]). A single shared floating element, positioned via JS,
// permanently parented in <body> -- NOT a CSS :hover span positioned relative to its own row,
// which had two confirmed live bugs: (1) it was shown via :hover OR :focus-within, and a checkbox
// keeps focus after being clicked, so :focus-within stayed true and the tooltip never went away
// once you actually checked a box; (2) position:absolute inside the checklist's own scrolling
// container (overflow-y-auto, which forces overflow-x into a scrollport too) got clipped or
// rendered overlapping neighboring columns depending on which row it was anchored to.
//
// Uses the native Popover API (popover="manual" + show/hidePopover()) instead of re-parenting the
// element into whichever <dialog> is currently open. Two earlier attempts at painting above an
// open <dialog> (position:fixed re-parented into the dialog; then position:absolute re-parented
// into the dialog, to dodge a Chromium stacking-order quirk where position:fixed descendants of a
// top-layer <dialog> paint BELOW its own plain content) both required re-deriving the tooltip's
// left/top relative to the dialog's own on-screen offset -- and that math silently broke the
// dialog itself: <dialog> is position:static, so a position:absolute child's containing block is
// NOT the dialog, it's the viewport -- yet the child was still a real DOM descendant of <dialog>,
// so its (wrongly-placed, sometimes far off-screen) box still inflated the dialog's own scrollable
// overflow region. The browser would then auto-scroll the dialog itself (not just the intended
// inner .overflow-y-auto list) to keep a newly-focused checkbox in view, and that scroll position
// never reset back to 0 once the tooltip hid again -- collapsing the whole dialog's visible
// content off-screen. Confirmed live: dialog.scrollHeight (1603) vs clientHeight (756) with the
// tooltip as its second child, vs no such gap with the tooltip removed from the dialog entirely.
// popover="manual" sidesteps all of this: the browser promotes the element straight into the top
// layer itself (always painting above an earlier-opened <dialog>, per top-layer stacking order),
// so it can stay a permanent position:fixed <body> child with plain viewport-relative coordinates
// -- no re-parenting, no origin-offset math, and therefore no way to perturb any dialog's own
// scroll state.
(function () {
  var floatEl = null;

  function ensureFloat() {
    if (floatEl) return floatEl;
    floatEl = document.createElement("div");
    floatEl.className = "tool-tooltip-float";
    floatEl.setAttribute("role", "tooltip");
    floatEl.setAttribute("popover", "manual");
    document.body.appendChild(floatEl);
    return floatEl;
  }

  function show(label) {
    var text = label.getAttribute("data-tool-description");
    if (!text) return;
    var el = ensureFloat();

    el.textContent = text;
    el.showPopover();

    var rect = label.getBoundingClientRect();
    var elRect = el.getBoundingClientRect();
    var maxLeft = window.innerWidth - elRect.width - 8;
    var left = rect.left;
    if (left > maxLeft) left = Math.max(8, maxLeft);
    var top = rect.top - elRect.height - 6;
    if (top < 8) top = rect.bottom + 6; // not enough room above -- show below instead
    el.style.left = left + "px";
    el.style.top = top + "px";
  }

  function hide() {
    if (floatEl) floatEl.hidePopover();
  }

  function wire(label) {
    label.addEventListener("mouseenter", function () { show(label); });
    label.addEventListener("mouseleave", hide);
    var checkbox = label.querySelector("input[type='checkbox']");
    if (checkbox) {
      checkbox.addEventListener("focus", function () { show(label); });
      checkbox.addEventListener("blur", hide);
    }
  }

  function wireAllIn(scope) {
    (scope || document).querySelectorAll("label[data-tool-description]").forEach(wire);
  }

  document.addEventListener("DOMContentLoaded", function () { wireAllIn(document); });
  // Each subagent's own Edit dialog is present in the initial page HTML (subagents.html renders
  // every profile's dialog inline, not htmx-fetched later), so DOMContentLoaded alone already
  // covers them -- no morph/afterSwap re-scan needed on this page.
})();
