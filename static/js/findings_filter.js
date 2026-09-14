// Findings tab's own filter tiles (session_fragment.html's [data-findings-filter-tiles]) --
// click a tile (severity, exploitation scenario, or one of the status chips: Exploited/Qualifying/
// False positive/Reconfirmed) to narrow the card list below. Severity and scenario are each their
// own OR-group (select several severities at once, e.g. Critical + High together; same for
// scenario, e.g. remote_direct + mitm_active together to mean "no victim action needed" as a
// group); the status chips are independent toggles ANDed on top of whichever severities/scenarios
// are active. Clicking an already-active tile clears just that one filter -- same "click again to
// clear" convention recon_filter.js already established for the Recon tab's own stat tiles.
//
// Delegated to `document`, never bound to the tiles/rows directly -- same reasoning as
// recon_filter.js: this tab's own content lives inside #session-content, which an in-progress
// scan's own SSE morph can replace at any moment, and a listener attached straight to an element
// would silently stop working the instant that element gets swapped out from under it. Loaded
// once via base.html (same convention as confirm_dialog.js/debug_events.js), never re-declared
// per fragment render.
//
// Persisted via session_state.js's shared store (loaded first, see that file) so the active tile
// selection survives a reload instead of silently resetting to "everything" -- a real, confirmed
// operator complaint (reloading mid-triage of a filtered list lost the filter every time). Restored
// via window.asraOnDomReady (see that file's own comment for why a bare DOMContentLoaded listener
// isn't safe here).
//
// The restored/clicked filter also has to survive the SSE morph itself, not just get applied once
// -- confirmed live: main.py's stream_session unconditionally yields ONE render the instant the
// SSE connection opens (even for an already-completed session, see base.html's own Idiomorph
// comment on this exact behavior), which morphs #session-content back to the server's own
// always-unfiltered markup moments after DOMContentLoaded, silently wiping every "hidden" class
// this file had just added -- a live scan's own later real updates would do the same thing
// repeatedly. Re-applying on every "htmx:afterSwap" (same event findings_tab_count.js already
// resyncs on) closes this regardless of how many times it happens or in what order relative to the
// initial restore.
(function () {
  var activeSeverities = new Set();
  var activeScenarios = new Set(); // OR-group, same convention as activeSeverities -- e.g. "remote_direct" + "mitm_active" together
  var activeToggles = {}; // group -> true when that boolean/value filter is active

  function context() {
    var tilesRoot = document.querySelector("[data-findings-filter-tiles]");
    var section = tilesRoot ? tilesRoot.closest("section") : null;
    return tilesRoot && section ? { tilesRoot: tilesRoot, section: section } : null;
  }

  function saveState() {
    if (!window.asraSessionState) return;
    window.asraSessionState.set("findings-filters", {
      severities: Array.from(activeSeverities),
      scenarios: Array.from(activeScenarios),
      toggles: activeToggles,
    });
  }

  function rowMatches(row) {
    if (activeSeverities.size && !activeSeverities.has(row.getAttribute("data-severity"))) return false;
    if (activeScenarios.size && !activeScenarios.has(row.getAttribute("data-scenario"))) return false;
    if (activeToggles.exploited && row.getAttribute("data-exploited") !== "true") return false;
    if (activeToggles.qualifying && row.getAttribute("data-qualifying") !== "qualifying") return false;
    if (activeToggles.false_positive && row.getAttribute("data-false-positive") !== "true") return false;
    if (activeToggles.carried_over && row.getAttribute("data-carried-over") !== "true") return false;
    return true;
  }

  function anyFilterActive() {
    return activeSeverities.size > 0 || activeScenarios.size > 0 || Object.keys(activeToggles).some(function (k) { return activeToggles[k]; });
  }

  function applyFilters(section) {
    var visibleCount = 0;
    section.querySelectorAll("[data-finding-row]").forEach(function (row) {
      var matches = rowMatches(row);
      row.classList.toggle("hidden", !matches);
      if (matches) visibleCount += 1;
    });
    var emptyMessage = section.querySelector("[data-findings-filter-empty]");
    if (emptyMessage) emptyMessage.classList.toggle("hidden", !anyFilterActive() || visibleCount > 0);
    // Real, confirmed operator complaint this fixes: severity's "Critical" tile and scenario's
    // "Remote — no victim needed" tile share the exact same red tone (both use badge()/
    // scenario_badge()'s own "critical" color, macros/ui.html) -- with no other signal, a filter
    // restored from an earlier visit (session_state.js) that's still active but currently off-
    // screen/scrolled-past reads as "the filter tiles are stuck/broken" rather than "something is
    // already filtering this list". This button makes that state impossible to miss.
    var clearBtn = section.querySelector("[data-findings-clear-filters]");
    if (clearBtn) clearBtn.classList.toggle("hidden", !anyFilterActive());
    return visibleCount;
  }

  function syncTileStyles(tilesRoot) {
    tilesRoot.querySelectorAll("[data-findings-filter-tile]").forEach(function (tile) {
      var group = tile.getAttribute("data-filter-group");
      var value = tile.getAttribute("data-filter-value");
      var isActive = group === "severity" ? activeSeverities.has(value) : group === "scenario" ? activeScenarios.has(value) : !!activeToggles[group];
      tile.classList.toggle("border-accent", isActive);
      tile.classList.toggle("ring-1", isActive);
      tile.classList.toggle("ring-accent/40", isActive);
    });
  }

  function reapply() {
    var ctx = context();
    if (!ctx) return;
    applyFilters(ctx.section);
    syncTileStyles(ctx.tilesRoot);
  }

  document.addEventListener("click", function (event) {
    var clearBtn = event.target.closest("[data-findings-clear-filters]");
    if (clearBtn) {
      var clearCtx = context();
      if (!clearCtx) return;
      activeSeverities.clear();
      activeScenarios.clear();
      activeToggles = {};
      applyFilters(clearCtx.section);
      syncTileStyles(clearCtx.tilesRoot);
      saveState();
      return;
    }

    var tile = event.target.closest("[data-findings-filter-tile]");
    if (!tile) return;
    var ctx = context();
    if (!ctx) return;

    var group = tile.getAttribute("data-filter-group");
    var value = tile.getAttribute("data-filter-value");

    if (group === "severity") {
      if (activeSeverities.has(value)) activeSeverities.delete(value);
      else activeSeverities.add(value);
    } else if (group === "scenario") {
      if (activeScenarios.has(value)) activeScenarios.delete(value);
      else activeScenarios.add(value);
    } else {
      activeToggles[group] = !activeToggles[group];
    }

    applyFilters(ctx.section);
    syncTileStyles(ctx.tilesRoot);
    saveState();
  });

  document.addEventListener("htmx:afterSwap", reapply);

  window.asraOnDomReady(function () {
    if (!window.asraSessionState) return;
    var saved = window.asraSessionState.get("findings-filters");
    if (!saved) return;

    (saved.severities || []).forEach(function (v) { activeSeverities.add(v); });
    (saved.scenarios || []).forEach(function (v) { activeScenarios.add(v); });
    Object.keys(saved.toggles || {}).forEach(function (g) {
      if (saved.toggles[g]) activeToggles[g] = true;
    });

    var ctx = context();
    if (!ctx) return;
    var visibleCount = applyFilters(ctx.section);
    if (!anyFilterActive() || visibleCount > 0) {
      syncTileStyles(ctx.tilesRoot);
      return;
    }
    // Real, confirmed operator complaint this fixes: a rescan/re-triage can reclassify existing
    // findings between one visit and the next (severity change, false_positive_reason set,
    // qualifies_for_bounty flip) -- a filter combination that matched something during the
    // original scan can end up matching zero findings once the data has moved on. Restoring it
    // anyway leaves the operator staring at an empty list with no active-looking tile to blame
    // (a tile whose count is now zero doesn't even render), reading as "my findings got wiped"
    // rather than "you still have an old filter on". Nothing is lost by dropping a restored
    // filter that already matches nothing -- there was nothing left for it to show anyway.
    activeSeverities.clear();
    activeScenarios.clear();
    activeToggles = {};
    applyFilters(ctx.section);
    syncTileStyles(ctx.tilesRoot);
    saveState();
  });
})();
