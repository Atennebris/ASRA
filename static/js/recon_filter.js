// Recon / Asset Info tab's stat-tile filters (session_fragment.html, main.py's recon_stats
// filter) -- click a tile ("Domains", "Subdomains", "Unique IPs") to show only the matching target
// rows below; click the same tile again (or "Hosts"/"Open ports", which both mean "everything") to
// clear it. "CVEs" has no per-target-row meaning of its own (CVEs render as one flat chip list, not
// one row per target) -- clicking it scrolls that list into view instead of filtering rows.
//
// Delegated to `document`, never attached to the tiles/rows directly -- this tab's own content can
// be replaced by an in-progress scan's own SSE morph (a new target discovered live) at any moment,
// and a listener attached straight to a tile element would silently stop working the instant that
// element gets swapped out from under it. Loaded once via base.html (same convention as
// confirm_dialog.js/debug_events.js), never re-declared per fragment render -- event delegation is
// exactly what makes that "attach once, keep working forever regardless of later DOM swaps" safe.
//
// Persisted via session_state.js's shared store (loaded first, see that file) so the active tile
// survives a reload instead of silently resetting to "everything" -- a real, confirmed operator
// complaint (reloading mid-triage of a filtered Recon list lost the filter every time). Restored
// via window.asraOnDomReady, not a bare DOMContentLoaded listener -- see session_state.js's own
// comment on that helper for the real race it closes.
//
// The restored/clicked filter also has to survive the SSE morph itself, not just get applied once
// -- confirmed live: main.py's stream_session unconditionally yields ONE render the instant the SSE
// connection opens (even for an already-completed session, see base.html's own Idiomorph comment on
// this exact behavior), which morphs #session-content back to the server's own always-unfiltered
// markup moments after DOMContentLoaded, silently wiping every "hidden" class this file had just
// added -- a live scan's own later real updates would do the same thing repeatedly. Re-applying on
// every "htmx:afterSwap" (same event findings_tab_count.js already resyncs on) closes this
// regardless of how many times it happens or in what order relative to the initial restore.
// activeFilter (a plain string) is what's re-resolved back into a tile element on each re-apply,
// never a stored element reference -- a DOM node idiomorph patches in place usually survives, but
// re-querying by the filter value itself doesn't depend on that being true.
(function () {
  var activeFilter = null;

  function saveState() {
    if (window.asraSessionState) window.asraSessionState.set("recon-filter", activeFilter);
  }

  function applyFilter(section, filter) {
    var visibleCount = 0;
    section.querySelectorAll("[data-recon-target-row]").forEach(function (row) {
      var matches =
        !filter
          ? true
          : filter === "ip"
          ? row.getAttribute("data-filter-ip") === "true"
          : row.getAttribute("data-filter-category") === filter;
      row.classList.toggle("hidden", !matches);
      if (matches) visibleCount += 1;
    });
    var emptyMessage = section.querySelector("[data-recon-filter-empty]");
    if (emptyMessage) emptyMessage.classList.toggle("hidden", !filter || visibleCount > 0);
  }

  function setActiveTile(tilesRoot, tile) {
    tilesRoot.querySelectorAll("[data-recon-filter-tile]").forEach(function (t) {
      var isActive = t === tile;
      t.classList.toggle("border-accent", isActive);
      t.classList.toggle("ring-1", isActive);
      t.classList.toggle("ring-accent/40", isActive);
    });
  }

  function reapply() {
    var tilesRoot = document.querySelector("[data-recon-filter-tiles]");
    var section = tilesRoot ? tilesRoot.closest("section") : null;
    if (!tilesRoot || !section) return;
    var tile = activeFilter ? tilesRoot.querySelector('[data-recon-filter-tile][data-filter="' + activeFilter + '"]') : null;
    applyFilter(section, activeFilter);
    setActiveTile(tilesRoot, tile);
  }

  document.addEventListener("click", function (event) {
    var tile = event.target.closest("[data-recon-filter-tile]");
    if (!tile) return;
    var tilesRoot = tile.closest("[data-recon-filter-tiles]");
    var section = tilesRoot ? tilesRoot.closest("section") : null;
    if (!section) return;

    var filter = tile.getAttribute("data-filter");

    if (filter === "cves") {
      var cveList = section.querySelector("[data-recon-cve-list]");
      if (cveList) cveList.scrollIntoView({ behavior: "smooth", block: "nearest" });
      return;
    }

    // "all" (Hosts/Open ports) and re-clicking the currently active tile both mean "show
    // everything, nothing highlighted" -- everything else applies its own filter.
    var clearing = filter === "all" || activeFilter === filter;
    activeFilter = clearing ? null : filter;
    applyFilter(section, activeFilter);
    setActiveTile(tilesRoot, clearing ? null : tile);
    saveState();
  });

  document.addEventListener("htmx:afterSwap", reapply);

  window.asraOnDomReady(function () {
    if (!window.asraSessionState) return;
    var saved = window.asraSessionState.get("recon-filter");
    if (!saved) return;
    activeFilter = saved;
    reapply();
  });
})();
