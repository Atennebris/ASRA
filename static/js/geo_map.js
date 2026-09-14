// Recon tab's Geopolitical Map (session_fragment.html's #map-geo-panel, Map tab's own leftmost
// sub-tab) -- every distinct IP session["recon_result"]["ip_intel"] holds (agent/core.py's
// automatic _update_ip_intel hook, geoip_lookup/classify_ip_role in agent/tools/native.py) plotted
// as a real marker on an interactive world map (jsvectormap, vendored locally under static/vendor,
// MIT-licensed, map data derived from Natural Earth's own public-domain dataset), colored by its
// role guess (CDN/WAF edge, cloud/VPS hosting, or likely origin). Country hover/click-for-name is
// jsvectormap's own built-in tooltip, not custom code here.
//
// Real motivation: a domain's resolved IP is routinely mistaken for "the target's own server"
// (paste it into whois, treat whatever comes back as ground truth) when it's actually a CDN/WAF
// edge node, shared/cloud hosting, or something else entirely unrelated to the real origin -- this
// makes that distinction visible on an actual map instead of depending on a human's own habit to
// catch it.
//
// Same "don't reinitialize the live instance on every SSE tick" + "don't initialize against a
// hidden, zero-size container" discipline attack_surface_graph.js's own cytoscape instance already
// established for the exact same reasons (pan/zoom reset, broken initial layout) -- this file
// avoids the second problem entirely rather than patching it after the fact: initMap() only ever
// runs once the mount is actually visible (real width/height), so there's never a broken-size
// instance to fix up in the first place. The mount div itself is guarded from idiomorph's own
// generic child-node diffing the same way #attack-surface-graph-mount is -- see base.html's own
// beforeNodeMorphed callback (keyed on this same #geo-map-mount id).
(function () {
  var mapInstance = null;
  var lastAppliedJson = null;

  // --severity-critical/--severity-unknown/--chart-1 are RGB TRIPLETS ("220 38 38"), not hex
  // strings (same convention attack_surface_graph.js's own severityColor() already documents).
  // Read fresh each time rather than cached, so a live theme switch (Settings) is picked up on the
  // next marker refresh without a page reload.
  //
  // Deliberately red / neutral-gray / blue, not the more obvious red / amber / blue -- confirmed
  // live (real operator screenshot): --severity-critical and --severity-medium render close enough
  // in hue at a small marker's size (a handful of pixels, heavily anti-aliased) to be mistaken for
  // the same color, exactly the "these colors get confused" complaint this fixes. --severity-low
  // is also out for the THIRD role -- it's already documented elsewhere in this codebase as
  // rendering as the same blue as --accent, so using both here would recreate the identical
  // confusion one tier up. severity-unknown's neutral gray/slate also reads correctly as "genuinely
  // ambiguous", not just "a third alarm color" -- fitting for a role that's deliberately NOT a
  // confident CDN/WAF match.
  //
  // "likely_origin" reads --chart-1, not --accent -- confirmed live (real operator screenshot,
  // Catppuccin theme active): --accent is a per-theme brand color, not a guaranteed blue, and in
  // every Catppuccin variant plus Rose Pine it's a PINK (#f5c2e7-family) sitting in the same hue
  // family as --severity-critical's own pink-red (#f38ba8-family) -- the "likely origin" marker and
  // the "CDN/WAF edge" marker rendered as the same red/pink dot on those themes, recreating the
  // exact "two markers look the same color" bug this function already exists to prevent for the
  // other two roles. --chart-1 is the one namespace themes.css documents as deliberately
  // theme-independent (same "57 135 229" blue in every theme block, see subagents.html's own
  // identical use of it for exactly this reason) -- unlike --accent, it can never coincide with
  // --severity-critical's red/pink regardless of which theme is active.
  function roleColor(role) {
    var styles = getComputedStyle(document.documentElement);
    var rgbTriplet = function (prop, fallback) {
      var raw = styles.getPropertyValue(prop).trim();
      return raw ? "rgb(" + raw.replace(/\s+/g, " ").split(" ").join(", ") + ")" : fallback;
    };
    switch (role) {
      case "cdn_waf": return rgbTriplet("--severity-critical", "#ef4444");
      case "cloud_hosting": return rgbTriplet("--severity-unknown", "#94a3b8");
      case "likely_origin": return rgbTriplet("--chart-1", "#3b82f6");
      default: return rgbTriplet("--severity-unknown", "#94a3b8");
    }
  }

  var ROLE_LABELS = {
    cdn_waf: "CDN / WAF edge",
    cloud_hosting: "Cloud / VPS hosting",
    likely_origin: "Likely origin",
  };

  function readIpIntel() {
    var el = document.getElementById("geo-map-data");
    if (!el) return null;
    try {
      return JSON.parse(el.textContent || "{}");
    } catch (e) {
      return null;
    }
  }

  function buildMarkers(ipIntel) {
    var ips = Object.keys(ipIntel).filter(function (ip) {
      var entry = ipIntel[ip];
      return entry && entry.lat != null && entry.lon != null;
    });
    return {
      ips: ips,
      markers: ips.map(function (ip) {
        var entry = ipIntel[ip];
        return { name: ip, coords: [entry.lat, entry.lon], style: { fill: roleColor(entry.role) } };
      }),
    };
  }

  function escapeHtml(text) {
    var div = document.createElement("div");
    div.textContent = text == null ? "" : String(text);
    return div.innerHTML;
  }

  function showDetail(entry, ip) {
    var panel = document.getElementById("geo-map-detail");
    if (!panel) return;
    var roleLabel = ROLE_LABELS[entry.role] || entry.role || "Unknown";
    var hostnames = (entry.hostnames || []).join(", ") || "(no hostname resolves here yet)";
    var location = [entry.city, entry.region, entry.country].filter(Boolean).join(", ") || "unknown";
    panel.innerHTML =
      '<p class="text-primary font-mono text-sm mb-1">' + escapeHtml(ip) + "</p>" +
      "<p>Hostnames: <span class=\"text-primary\">" + escapeHtml(hostnames) + "</span></p>" +
      "<p>Location: <span class=\"text-primary\">" + escapeHtml(location) + "</span></p>" +
      "<p>ISP / Org: <span class=\"text-primary\">" + escapeHtml(entry.isp || entry.org || "unknown") + "</span></p>" +
      "<p>ASN: <span class=\"text-primary\">" + escapeHtml(entry.asn || "unknown") + "</span></p>" +
      '<p class="mt-1"><span class="font-semibold" style="color:' + roleColor(entry.role) + '">' + escapeHtml(roleLabel) +
        "</span> &mdash; confidence: " + escapeHtml(entry.confidence || "unknown") + "</p>" +
      '<p class="mt-1 text-secondary/80">' + escapeHtml(entry.reason || "") + "</p>";
    panel.hidden = false;
  }

  function styleTooltip(tooltip) {
    tooltip.css({
      backgroundColor: "#111827", color: "#e5e7eb", padding: "4px 8px",
      borderRadius: "4px", fontSize: "11px", border: "1px solid #374151",
    });
  }

  function isVisible(el) {
    return el.offsetWidth > 0 && el.offsetHeight > 0;
  }

  function updateMarkers(ipIntel) {
    if (!mapInstance) return;
    try {
      mapInstance.removeMarkers();
    } catch (e) { /* no markers yet -- harmless */ }
    mapInstance.addMarkers(buildMarkers(ipIntel).markers);
  }

  function initMap(ipIntel) {
    var built = buildMarkers(ipIntel);
    mapInstance = new window.jsVectorMap({
      selector: "#geo-map-mount",
      map: "world",
      zoomButtons: true,
      regionsSelectable: false,
      markersSelectable: false,
      markerStyle: { initial: { fill: "#94a3b8", stroke: "#0f172a", "stroke-width": 1, r: 5 } },
      markers: built.markers,
      onRegionTooltipShow: function (_event, tooltip) {
        styleTooltip(tooltip);
      },
      onMarkerTooltipShow: function (_event, tooltip, index) {
        styleTooltip(tooltip);
        var ip = built.ips[index];
        if (ip && ipIntel[ip]) {
          tooltip.text(ip + " -- " + (ROLE_LABELS[ipIntel[ip].role] || ipIntel[ip].role || "unknown"), false);
        }
      },
      onMarkerClick: function (_event, index) {
        var ip = built.ips[index];
        if (ip && ipIntel[ip]) showDetail(ipIntel[ip], ip);
      },
      onRegionClick: function (_event, code) {
        var panel = document.getElementById("geo-map-detail");
        if (!panel) return;
        // world.js's own per-country path entries (jsVectorMap.addMap("world", {paths: {...}}))
        // already carry a human-readable "name" field -- reused here directly rather than a
        // second, hand-maintained ISO-code -> country-name table. Confirmed live: the library
        // keeps its loaded map data on the INSTANCE (mapInstance._mapData.paths[code].name), not
        // on the window.jsVectorMap class itself (which only ever exposes the static addMap
        // method) -- the same private field the library's own tooltip code reads internally.
        var name = (mapInstance._mapData && mapInstance._mapData.paths[code] && mapInstance._mapData.paths[code].name) || code;
        panel.innerHTML = '<p class="text-primary font-mono text-sm">' + escapeHtml(name) + " (" + escapeHtml(code) + ")</p>";
        panel.hidden = false;
      },
    });
  }

  function refresh() {
    var ipIntel = readIpIntel();
    if (!ipIntel) return;
    var rawJson = JSON.stringify(ipIntel);
    if (mapInstance) {
      if (rawJson !== lastAppliedJson) {
        lastAppliedJson = rawJson;
        updateMarkers(ipIntel);
      }
      return;
    }
    if (Object.keys(ipIntel).length === 0) return; // nothing to plot yet -- wait for real data
    var mount = document.getElementById("geo-map-mount");
    if (!mount || !window.jsVectorMap || !isVisible(mount)) return; // not visible yet -- avoid a broken zero-size init
    lastAppliedJson = rawJson;
    initMap(ipIntel);
  }

  refresh();
  document.addEventListener("DOMContentLoaded", refresh);

  // Same MutationObserver-on-the-data-blob convention attack_surface_graph.js already uses for
  // #attack-surface-data -- #geo-map-data is a plain text node inside the same live SSE/morph
  // subtree, refreshed on every tick.
  var dataEl = document.getElementById("geo-map-data");
  if (dataEl) {
    new MutationObserver(refresh).observe(dataEl, { childList: true, characterData: true, subtree: true });
  }

  // The outer "Map" tab and this file's own "Geopolitical Map" sub-tab are both pure CSS (a radio's
  // :checked state driving a `:has()` visibility rule) -- neither is a real DOM mutation, so the
  // MutationObserver above never fires just from switching tabs. Real, confirmed bug class this
  // guards against (same one attack_surface_graph.js's own tab-map listener documents for
  // cytoscape): on first page load this tab is very likely not the active one (Overview is), so
  // the very first refresh() call above sees a hidden, zero-size mount and correctly skips
  // initializing -- these listeners are what actually create the map once it becomes visible.
  var outerMapTab = document.getElementById("tab-map");
  if (outerMapTab) outerMapTab.addEventListener("change", refresh);
  var geoSubtab = document.getElementById("map-subtab-geo");
  if (geoSubtab) geoSubtab.addEventListener("change", refresh);
})();
