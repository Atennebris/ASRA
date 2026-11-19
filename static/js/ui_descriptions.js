// Helper-description long-hover tooltips + live hide toggle.
//
// Pairs with Settings -> Customization -> "Show helper descriptions". When the operator opts into
// the leaner layout, the <body> carries data-hide-descriptions="true" and every `.ui-desc`
// explanatory paragraph is collapsed by CSS (themes.css). This script keeps that text reachable:
// on a long hover over the element a description belongs to, it shows the text in a themed tooltip.
// It also exposes window.asraSetHideDescriptions(bool) so the Settings toggle flips the whole app
// live in the same frame, before its save round-trips (the project's live-visual-feedback rule).
(function () {
  var HOVER_DELAY_MS = 500; // a deliberate "long hover" before the hidden description surfaces
  var tooltip = null;
  var hoverTimer = null;

  function hidden() {
    return !!(document.body && document.body.getAttribute("data-hide-descriptions") === "true");
  }

  function ensureTooltip() {
    if (tooltip) return tooltip;
    tooltip = document.createElement("div");
    tooltip.id = "asra-ui-tooltip";
    tooltip.setAttribute("role", "tooltip");
    document.body.appendChild(tooltip);
    return tooltip;
  }

  // The element a description explains: an explicit data-desc-for target wins, otherwise the
  // element right before the paragraph (its heading/label/control), otherwise its parent card.
  function ownerFor(desc) {
    var ref = desc.getAttribute("data-desc-for");
    if (ref) {
      var byId = document.getElementById(ref);
      if (byId) return byId;
    }
    if (desc.previousElementSibling) return desc.previousElementSibling;
    return desc.parentElement;
  }

  // Copy each .ui-desc's text onto the element it explains so a hover there can reveal it once the
  // paragraph itself is collapsed. Idempotent (processed nodes are marked) and cheap to re-run after
  // an htmx swap brings in new .ui-desc nodes. Tooltip DISPLAY is gated on hidden() at hover time,
  // so marking even while descriptions are visible is harmless.
  function markOwners(root) {
    var scope = root && root.querySelectorAll ? root : document;
    var list = scope.querySelectorAll(".ui-desc:not([data-ui-desc-marked])");
    for (var i = 0; i < list.length; i++) {
      var desc = list[i];
      desc.setAttribute("data-ui-desc-marked", "1");
      var text = (desc.textContent || "").trim().replace(/\s+/g, " ");
      if (!text) continue;
      var owner = ownerFor(desc);
      if (!owner || owner === document.body) continue;
      owner.setAttribute("data-ui-desc-tooltip", text);
    }
  }

  function showTooltip(owner) {
    var text = owner.getAttribute("data-ui-desc-tooltip");
    if (!text) return;
    var tip = ensureTooltip();
    tip.textContent = text;
    tip.classList.add("asra-ui-tooltip-visible");
    // Measure after it's rendered, then place it above the owner (or below if there's no room up).
    var rect = owner.getBoundingClientRect();
    var tw = tip.offsetWidth;
    var th = tip.offsetHeight;
    var left = Math.min(Math.max(8, rect.left), window.innerWidth - tw - 8);
    var top = rect.top - th - 8;
    if (top < 8) top = rect.bottom + 8;
    tip.style.left = left + "px";
    tip.style.top = top + "px";
  }

  function hideTooltip() {
    clearTimeout(hoverTimer);
    if (tooltip) tooltip.classList.remove("asra-ui-tooltip-visible");
  }

  document.addEventListener("mouseover", function (event) {
    if (!hidden() || !event.target.closest) return;
    var owner = event.target.closest("[data-ui-desc-tooltip]");
    if (!owner) return;
    clearTimeout(hoverTimer);
    hoverTimer = setTimeout(function () { showTooltip(owner); }, HOVER_DELAY_MS);
  });

  document.addEventListener("mouseout", function (event) {
    if (!event.target.closest) return;
    if (event.target.closest("[data-ui-desc-tooltip]")) hideTooltip();
  });

  // Live toggle entry point for the Settings switch -- flip the whole app the same frame, no reload.
  window.asraSetHideDescriptions = function (hide) {
    window.ASRA_HIDE_DESCRIPTIONS = !!hide;
    if (!document.body) return;
    if (hide) {
      document.body.setAttribute("data-hide-descriptions", "true");
      markOwners(document);
    } else {
      document.body.removeAttribute("data-hide-descriptions");
      hideTooltip();
    }
  };

  function init() {
    markOwners(document);
    // New content swapped in by htmx carries its own .ui-desc nodes -- mark their owners too.
    document.body.addEventListener("htmx:afterSettle", function (event) {
      markOwners(event.target || document);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
