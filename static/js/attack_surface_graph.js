// Map tab's Attack Surface graph (session.html only, Agent mode) -- a single cytoscape.js instance
// (static/vendor/cytoscape.min.js) rendering main.py's _build_attack_surface_graph output, embedded
// by session_fragment.html as a <script type="application/json" id="attack-surface-data"> blob
// inside the SAME #session-stream SSE/morph subtree every other tab already lives in.
//
// That data blob is SUPPOSED to update on every live SSE tick (a new host, a new finding's
// severity, a new credential-reuse edge) -- but the cytoscape instance itself must NOT be torn
// down and reinitialized each time that happens, or the operator's own pan/zoom/selection resets
// mid-scan. Same class of bug this codebase has already hit and fixed elsewhere (xterm's own
// terminal instance, the mascot, the theme picker) -- a MutationObserver on the data blob's own
// text content, diffing against the last-applied payload, is what keeps this from re-initializing
// on every tick: only a REAL change to the underlying graph data ever touches the live instance.
// The mount div itself is ALSO guarded from idiomorph's own generic child-node diffing wiping its
// cytoscape-injected canvas back to the server's always-empty markup -- see base.html's own
// beforeNodeMorphed callback (keyed on this same #attack-surface-graph-mount id) for that half.
//
// Real operator feedback this version addresses (session review, not a guess): the previous
// version's flat colored circles ("pokemon bubbles"), permanent glow halo on every node, and an
// animated conic-gradient "radar sweep" behind the graph were all called out as ugly/distracting,
// with an explicit ask for something closer to Cobalt Strike's own plain host-icon graph. On top
// of that: the graph must survive a real page reload (F5), not just an in-page SSE tick, and the
// operator wants to hand-author nodes/connections (a suspected pivot, a beacon relationship) with
// full control over direction/data-type/volume/format/interval, plus a couple of Obsidian-graph-
// style conveniences (a physics/"magnetism" toggle, a Home button to recover from a lost pan/zoom).
(function () {
  var cy = null;
  var lastAppliedJson = null;
  var sessionId = null;
  // Set by wireEdgeDialog() once it exists; called from the right-click context menu's own "Add
  // connection from here" action, which fires long after both are wired -- a plain shared var
  // (not a window global, this whole file already avoids polluting window except for the two
  // editor-open functions dialogs need to reach from inline onclick=) is enough for that ordering.
  var openEdgeDialogFrom = null;

  function severityColor(name) {
    var styles = getComputedStyle(document.documentElement);
    // --severity-* is an RGB TRIPLET ("220 38 38"), not a hex string -- themes.css's own comment on
    // why (Tailwind's opacity modifiers need separate R/G/B channels) -- so only these four need
    // wrapping in rgb(...). Real, confirmed bug this fixes: the "no finding yet" fallback used this
    // same wrapping on --text-secondary, which (like --accent) is a plain hex value in every theme
    // -- cytoscape silently rejected the resulting "rgb(#8b949e)" as an invalid color and left
    // every unlocated node with NO background color set at all, node circles included.
    var severityRgbTriplet = function (prop, fallback) {
      var raw = styles.getPropertyValue(prop).trim();
      return raw ? "rgb(" + raw.replace(/\s+/g, " ").split(" ").join(", ") + ")" : fallback;
    };
    switch (name) {
      case "Critical": return severityRgbTriplet("--severity-critical", "#e53e3e");
      case "High": return severityRgbTriplet("--severity-high", "#ea580c");
      case "Medium": return severityRgbTriplet("--severity-medium", "#d97706");
      case "Low": return severityRgbTriplet("--severity-low", "#2563eb");
      case "Info": return severityRgbTriplet("--severity-unknown", "#94a3b8");
      default:
        var raw = styles.getPropertyValue("--text-secondary").trim();
        return raw || "#94a3b8";
    }
  }

  // Confirmed-access fill -- same severity CSS vars severityColor() already reads, but as a
  // translucent rgba() fill rather than a solid border color. Cobalt Strike's own beacon graph
  // draws a REAL foothold as a filled box, not just an outlined one -- has_confirmed_access
  // (main.py, set only when a real finding's own "exploited" flag is true) is this app's own
  // equivalent of that distinction, and a tinted fill is the one visual dimension the node style
  // hadn't used yet (background-color was always a flat, severity-blind surfaceColor() before).
  function severityFillColor(name, alpha) {
    var propByName = {
      Critical: "--severity-critical", High: "--severity-high", Medium: "--severity-medium",
      Low: "--severity-low", Info: "--severity-unknown",
    };
    var prop = propByName[name];
    if (!prop) return null;
    var raw = getComputedStyle(document.documentElement).getPropertyValue(prop).trim();
    return raw ? "rgba(" + raw.replace(/\s+/g, " ").split(" ").join(", ") + ", " + alpha + ")" : null;
  }

  function accentColor() {
    var raw = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();
    return raw || "#3b82f6";
  }

  function textSecondaryColor() {
    var raw = getComputedStyle(document.documentElement).getPropertyValue("--text-secondary").trim();
    return raw || "#94a3b8";
  }

  function surfaceColor() {
    var raw = getComputedStyle(document.documentElement).getPropertyValue("--surface").trim();
    return raw || "#1e1e1e";
  }

  // ---- Node icons -------------------------------------------------------------------------
  // Severity now lives ONLY on the border (solid/dashed, colored) -- the icon itself stays one
  // flat neutral color for every node, "kind" (host/service/domain/actor) picking the GLYPH, not
  // the color. This is the actual fix for "make normal nodes, closer to Cobalt Strike": a plain
  // computer/globe/person icon in a quiet chip reads as an operator tool, not a filled colored
  // ball. Baked as a literal color in the SVG string (not currentColor) because this becomes a
  // static data: URI cytoscape hands to the canvas, outside the browser's own CSS cascade.
  function svgIcon(inner, color) {
    // width/height="128" (viewBox stays the original 24x24 coordinate space -- every existing path
    // command below is unchanged) is the actual fix for a real, confirmed bug: without an explicit
    // intrinsic raster size, cytoscape.js rasterizes this SVG data URI once at whatever on-screen
    // pixel size the node happens to be at that exact moment, caches that bitmap, and does not
    // reliably re-rasterize it at a matching resolution on every subsequent zoom step -- confirmed
    // live by actually scrolling to zoom on a real node (Map tab, Attack Surface): at some
    // intermediate zoom levels the icon visibly grew past its own background-width/height box and
    // was cropped by background-clip:"node", while it rendered cleanly at both the original zoom
    // and the max zoom cap (2.5) -- exactly the signature of a stale, wrongly-scaled cached bitmap
    // being reused once an intermediate zoom factor is crossed, not a real proportion/CSS problem
    // (changing background-width/height from a percentage to a fixed pixel value made no difference).
    // A high fixed intrinsic size gives cytoscape's own cache a single, always-larger-than-needed
    // source bitmap to scale DOWN from at every real zoom level this graph's minZoom/maxZoom
    // actually allows, instead of needing to scale UP from whatever small size it happened to
    // rasterize at first -- downscaling a cached bitmap is what canvas 2D always does correctly.
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="128" height="128" fill="none" stroke="' + color +
      '" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">' + inner + "</svg>";
    return "data:image/svg+xml," + encodeURIComponent(svg);
  }

  function nodeIcon(kind, color) {
    switch (kind) {
      case "service":
        // A plain "</>" bracket pair -- API/running-service shorthand, no color-coding of its own.
        return svgIcon('<polyline points="8 6 3 12 8 18"/><polyline points="16 6 21 12 16 18"/>', color);
      case "domain":
        return svgIcon('<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/>' +
          '<path d="M12 3c3.2 3.6 3.2 14.4 0 18M12 3c-3.2 3.6-3.2 14.4 0 18"/>', color);
      case "actor":
        return svgIcon('<circle cx="12" cy="8" r="3.4"/><path d="M6 20v-1.2A4.8 4.8 0 0 1 10.8 14h2.4A4.8 4.8 0 0 1 18 18.8V20"/>', color);
      case "host":
      default:
        return svgIcon('<rect x="2.5" y="3.5" width="19" height="6" rx="1"/><rect x="2.5" y="14.5" width="19" height="6" rx="1"/>' +
          '<circle cx="6.5" cy="6.5" r=".6" fill="' + color + '"/><circle cx="6.5" cy="17.5" r=".6" fill="' + color + '"/>', color);
    }
  }

  // ---- Data shaping -------------------------------------------------------------------------
  // Real, confirmed bug this guards against: a node with NO saved position used to get no
  // `position` field at all -- cytoscape's "preset" layout then defaults every such node to the
  // exact same (0,0), so a fresh graph (nothing dragged yet) piled every node on top of one
  // another at a single point. The very next fit-to-content (this tab becoming visible, or the
  // Home button) then zoomed in on that near-zero-area cluster to the point of absurdity --
  // exactly the "giant overlapping icons" an operator reported live. Every node now ALWAYS gets a
  // real, distinct position (its own saved one, or a deterministic cascade slot) before it ever
  // reaches cytoscape, so two nodes can never start out coincident -- which is also why
  // "Auto-arrange" (cose with randomize:false, i.e. refine from the CURRENT positions) used to do
  // nothing: refining a force layout from a pile of identical starting coordinates has no
  // asymmetry to actually break.
  function toElements(graph) {
    var elements = [];
    (graph.nodes || []).forEach(function (node, index) {
      var el = {
        data: {
          id: node.id,
          label: node.label,
          worst_severity: node.worst_severity,
          has_open_hypothesis: !!node.has_open_hypothesis,
          kind: node.kind || "host",
          manual: !!node.manual,
          notes: node.notes || "",
          known_hostnames: node.known_hostnames || [],
          resolved_ips: node.resolved_ips || [],
          ports: node.ports || [],
          technologies: node.technologies || [],
          has_confirmed_access: !!node.has_confirmed_access,
          surface_score: node.surface_score || 0,
          first_seen_at: node.first_seen_at || null,
          finding_count_by_severity: node.finding_count_by_severity || {},
          hypothesis_count: node.hypothesis_count || 0,
        },
      };
      // Cytoscape elements take position as a SIBLING of data, not inside it -- this is what makes
      // the graph survive a real page reload: a saved position came from session["map_manual"]
      // ["positions"] server-side, not from anything this browser tab remembers on its own; a
      // node with no saved position yet still gets a real, distinct slot (see comment above).
      el.position = node.position ? { x: node.position.x, y: node.position.y } : cascadePosition(index);
      elements.push(el);
    });
    (graph.edges || []).forEach(function (edge) {
      elements.push({
        data: {
          id: edge.id || (edge.source + "->" + edge.target + ":" + edge.kind),
          source: edge.source,
          target: edge.target,
          kind: edge.kind,
          label: edge.label || "",
          direction: edge.direction || "none",
          manual: !!edge.manual,
          data_type: edge.data_type || "",
          volume: edge.volume || "",
          format: edge.format || "",
          interval: edge.interval || "",
          notes: edge.notes || "",
          at: edge.at || null,
        },
      });
    });
    return elements;
  }

  function style() {
    var neutral = textSecondaryColor();
    return [
      {
        selector: "node",
        style: {
          shape: "round-rectangle",
          "background-color": function (ele) {
            if (ele.data("has_confirmed_access")) {
              return severityFillColor(ele.data("worst_severity"), 0.32) || surfaceColor();
            }
            return surfaceColor();
          },
          "background-image": function (ele) { return nodeIcon(ele.data("kind"), neutral); },
          // background-clip left at its default ("node", clips to the node's own shape) -- "none"
          // was a real, confirmed bug: it let the icon paint outside the chip's own rounded-
          // rectangle bounding box, which read as a crooked/cropped icon (the bottom of the host
          // glyph visibly cut off) rather than a clean, centered icon inside the node. This same
          // clip:"node" is also why a STALE cached icon bitmap crops instead of just blurring --
          // see svgIcon's own docstring for the real zoom-dependent bug this combination exposed
          // and its actual fix (a bigger intrinsic SVG raster size, not anything in this block).
          "background-fit": "contain",
          "background-width": "62%",
          "background-height": "62%",
          // No permanent glow here (the previous "pokemon bubble" halo) -- underlay is reserved
          // entirely for the Critical pulse animation below, invisible (opacity 0) at rest.
          "underlay-color": function (ele) { return severityColor(ele.data("worst_severity")); },
          "underlay-opacity": 0,
          "underlay-padding": 6,
          "underlay-shape": "round-rectangle",
          label: "data(label)",
          "font-size": 10,
          color: neutral,
          "text-valign": "bottom",
          "text-margin-y": 4,
          // Node SIZE encodes main.py's surface_score (severity + confirmed access + open
          // hypotheses + risky open ports, _map_surface_score) -- the eye should land on the
          // juiciest target first, the same instinct Cobalt Strike's own graph gives a fatter box
          // to a more valuable beacon. Capped growth (score 8+ all render the same max size) so
          // one extreme outlier host doesn't visually swallow the rest of a real session's map.
          width: function (ele) { return 34 + Math.min(ele.data("surface_score") || 0, 8) * 2.5; },
          height: function (ele) { return 34 + Math.min(ele.data("surface_score") || 0, 8) * 2.5; },
          "border-width": 2,
          // Real, confirmed bug this replaces: record_hypothesis has no "severity" field at all --
          // a hypothesis is an open question, not a scored vulnerability -- so borrowing a fake
          // severity from it (the previous "suspected Critical" dashed-red idea) was pure fiction
          // that never even triggered in a real session (host was almost never set either). An open
          // hypothesis with no confirmed finding gets its own honest, neutral accent-colored dashed
          // border instead of a made-up severity color -- "something is being looked at here", not
          // a claim about how bad it is.
          "border-color": function (ele) {
            if (ele.data("worst_severity")) return severityColor(ele.data("worst_severity"));
            if (ele.data("has_open_hypothesis")) return accentColor();
            return severityColor(null);
          },
          "border-opacity": 0.9,
          "border-style": function (ele) {
            return !ele.data("worst_severity") && ele.data("has_open_hypothesis") ? "dashed" : "solid";
          },
        },
      },
      {
        // Theme-aware colors (was a flat "#888") -- cytoscape parses style VALUES itself for canvas
        // rendering, it does not run them through the browser's own CSS engine, so a live var()/
        // color-mix() string here would mean nothing to it. Real resolved hex read once via
        // textSecondaryColor()/surfaceColor() below, same pattern severityColor()/accentColor() use.
        selector: "edge",
        style: {
          width: function (ele) { return ele.data("manual") ? 2 : 1.5; },
          "line-color": neutral,
          "line-opacity": 0.65,
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": 8,
          color: neutral,
          "text-background-color": surfaceColor(),
          "text-background-opacity": 0.8,
          "text-background-padding": 2,
          // Arrows encode the operator's own "who talks to whom" -- one style function reading a
          // single "direction" field (forward/reverse/bidirectional/none) rather than four
          // duplicated selectors, so dns edges (server-assigned "forward") and manual edges (the
          // operator's own choice) share one code path.
          "target-arrow-shape": function (ele) {
            var d = ele.data("direction");
            return d === "forward" || d === "bidirectional" ? "triangle" : "none";
          },
          "source-arrow-shape": function (ele) {
            var d = ele.data("direction");
            return d === "reverse" || d === "bidirectional" ? "triangle" : "none";
          },
          "target-arrow-color": neutral,
          "source-arrow-color": neutral,
          "arrow-scale": 0.8,
        },
      },
      {
        selector: "edge[kind = 'credential_reuse']",
        style: { "line-color": accentColor(), "target-arrow-color": accentColor(), "source-arrow-color": accentColor(), "line-style": "dashed", width: 2 },
      },
      {
        // domain_family (a subdomain -> its own registrable parent) is left on the plain base
        // "edge" style above -- it's a structural fact (the map's own backbone, see
        // _build_attack_surface_graph's own docstring), not a hint, so it gets the same quiet
        // solid line dns already uses rather than another new color to learn.
        //
        // shared_surface is different on purpose: "these two hosts show the same nginx/WAF" is
        // inferred kinship, not a proven fact (two hosts can share a common CDN's fingerprint by
        // total coincidence) -- dotted is this app's own established "under investigation, not yet
        // confirmed" visual language (see the has_open_hypothesis dashed-border comment above), so
        // reusing it here for an inferred-not-proven edge keeps that language consistent instead of
        // inventing a fourth line style with no established meaning.
        selector: "edge[kind = 'shared_surface']",
        style: { "line-style": "dotted", "line-opacity": 0.55 },
      },
      {
        // attack_path is the single most actionable line on this map -- a real Chain pass's own
        // proven pivot from one host's finding to another's (see _build_attack_surface_graph's own
        // docstring), the closest thing here to Cobalt Strike's own beacon-to-beacon pivot lines.
        // Bold and severity-Critical-colored on purpose: nothing else on this graph should compete
        // with it for attention.
        selector: "edge[kind = 'attack_path']",
        style: {
          "line-color": function () { return severityColor("Critical"); },
          "target-arrow-color": function () { return severityColor("Critical"); },
          "source-arrow-color": function () { return severityColor("Critical"); },
          width: 2.5, "line-opacity": 0.85,
        },
      },
      {
        // Operator-drawn connections read as deliberate, not automated -- accent-colored and a
        // touch bolder than the neutral dns/credential lines, without introducing a third random
        // color into the palette.
        selector: "edge[manual]",
        style: { "line-color": accentColor(), "target-arrow-color": accentColor(), "source-arrow-color": accentColor() },
      },
      {
        // refreshMapDimming's own dimming class (below) -- shared by the filter row and the
        // timeline scrubber, last in the array on purpose so its opacity wins over every selector
        // above regardless of kind/manual/severity. A real recon-heavy session (several projects
        // here already run 20-50+ hosts) turns unreadable fast with no way to focus on just what
        // matters right now.
        selector: ".map-dimmed",
        style: { opacity: 0.12 },
      },
    ];
  }

  // ---- Detail panel (click a node OR an edge) ------------------------------------------------
  function renderDetailPanel(ele) {
    var panel = document.getElementById("attack-surface-detail-panel");
    if (!panel) return;
    var d = ele.data();
    if (ele.isNode()) {
      var portsHtml = (d.ports || []).map(function (p) {
        return "<li>" + (p.port != null ? p.port : "?") + "/" + (p.service || "?") + "</li>";
      }).join("");
      var findingsHtml = Object.keys(d.finding_count_by_severity || {}).map(function (sev) {
        return "<li>" + sev + ": " + d.finding_count_by_severity[sev] + "</li>";
      }).join("") || "<li>No confirmed findings on this host yet.</li>";
      panel.innerHTML =
        '<p class="font-semibold text-primary mb-1">' + d.label + "</p>" +
        (d.has_confirmed_access ? '<p class="mb-1 font-semibold" style="color: ' + severityColor(d.worst_severity) + '">&#9679; Confirmed access</p>' : "") +
        (d.manual ? '<p class="text-secondary mb-1 italic">Operator-created (' + d.kind + ")</p>" : "") +
        (d.notes ? '<p class="text-secondary mb-1">' + d.notes + "</p>" : "") +
        (d.known_hostnames.length ? "<p class=\"text-secondary mb-1\">Also known as: " + d.known_hostnames.join(", ") + "</p>" : "") +
        (d.resolved_ips.length ? "<p class=\"text-secondary mb-1\">Resolves to: " + d.resolved_ips.join(", ") + "</p>" : "") +
        (d.manual ? "" :
          "<p class=\"text-secondary mt-2 mb-0.5\">Ports:</p><ul class=\"list-disc pl-4\">" + (portsHtml || "<li>none recorded</li>") + "</ul>" +
          // Same tokens shared_surface edges compare (main.py's _map_surface_signal) -- shown here
          // too so clicking a shared_surface edge's own endpoint explains WHY it's connected,
          // without needing a second lookup anywhere else.
          (d.technologies && d.technologies.length ? "<p class=\"text-secondary mt-2 mb-0.5\">Technologies:</p><p class=\"text-primary\">" + d.technologies.join(", ") + "</p>" : "") +
          "<p class=\"text-secondary mt-2 mb-0.5\">Findings:</p><ul class=\"list-disc pl-4\">" + findingsHtml + "</ul>" +
          (d.hypothesis_count > 0 ? "<p class=\"text-secondary mt-2 italic\">" + d.hypothesis_count + " open hypothes" + (d.hypothesis_count === 1 ? "is" : "es") + " naming this host, not yet confirmed or ruled out.</p>" : "")) +
        (d.manual ? '<button type="button" class="mt-2 h-7 px-2 text-[11px] rounded bg-elevated text-primary border border-default hover:bg-overlay" onclick="window.asraOpenMapNodeEditor(\'' + d.id + '\')">Edit node</button>' : "");
    } else {
      var metaRows = [
        ["Direction", { forward: "→", reverse: "←", bidirectional: "↔", none: "none" }[d.direction] || d.direction],
        ["Data type", d.data_type], ["Volume", d.volume], ["Format", d.format], ["Interval", d.interval],
      ].filter(function (row) { return row[1]; });
      // The raw source/target ids ARE the label for a real host, but a manual node's id is an
      // opaque "manual-<hex>" string -- always resolve through the live node's own display label
      // instead, so e.g. a beacon FROM an operator-named actor never shows its internal id here.
      var sourceLabel = (cy.getElementById(d.source).data("label")) || d.source;
      var targetLabel = (cy.getElementById(d.target).data("label")) || d.target;
      panel.innerHTML =
        '<p class="font-semibold text-primary mb-1">' + sourceLabel + " &rarr; " + targetLabel + "</p>" +
        (d.manual ? "" : '<p class="text-secondary mb-1 italic">' + d.kind + " (automatic)</p>") +
        metaRows.map(function (row) { return "<p class=\"text-secondary\">" + row[0] + ": <span class=\"text-primary\">" + row[1] + "</span></p>"; }).join("") +
        (d.notes ? '<p class="text-secondary mt-2">' + d.notes + "</p>" : "") +
        (!d.manual && metaRows.length === 0 ? '<p class="text-secondary italic">No additional data recorded for this connection.</p>' : "") +
        (d.manual ? '<button type="button" class="mt-2 h-7 px-2 text-[11px] rounded bg-elevated text-primary border border-default hover:bg-overlay" onclick="window.asraOpenMapEdgeEditor(\'' + d.id + '\')">Edit connection</button>' : "");
    }
    panel.classList.remove("hidden");
  }

  // ---- Position persistence (the actual "survives F5" mechanism) ----------------------------
  var positionSaveTimers = {};
  function saveNodePosition(nodeId, pos) {
    if (!sessionId) return;
    clearTimeout(positionSaveTimers[nodeId]);
    positionSaveTimers[nodeId] = setTimeout(function () {
      var body = new URLSearchParams({ node_id: nodeId, x: String(pos.x), y: String(pos.y) });
      fetch("/api/session/" + sessionId + "/map/position", { method: "POST", body: body });
    }, 150);
  }

  // ---- Layout: preserve the operator's own arrangement, never silently rearrange it ---------
  // The single biggest complaint this version fixes: the graph used to re-run a full force layout
  // on every SSE tick, visibly relocating every node the operator had already placed. Now a real
  // layout pass only ever runs (a) once, the very first time a graph with no saved positions at
  // all appears, or (b) on an explicit "Auto-arrange" click. Any other time new elements appear,
  // they're added in place with a plain deterministic cascade -- never touching an existing node.
  function magnetismEnabled() {
    try {
      var raw = localStorage.getItem("asra-map-magnetism");
      return raw === null ? true : raw === "1";
    } catch (e) { return true; }
  }

  // Real, confirmed bug this fixes: the base button markup carried a permanent "hover:bg-overlay"
  // (meant for the OFF/neutral state) that never got swapped out when a toggle turned ON -- on
  // hover, Tailwind's own utility source order puts that hover variant AFTER the plain "bg-accent"
  // in the generated stylesheet, so it silently WON regardless of which order the classes appear
  // in the element's own class attribute (HTML class order never affects CSS cascade, only
  // stylesheet source order/specificity do) -- an ON toggle visibly greyed out to the OFF-state
  // color the instant the cursor rested on it. The hover class now travels WITH the on/off set
  // (hover:bg-accent-hover, this app's own established accent-button hover convention -- see e.g.
  // templates/macros/ui.html's "primary" button style) instead of living statically on the element.
  var TOOLBAR_BTN_OFF_CLASSES = ["bg-elevated", "text-primary", "border-default", "hover:bg-overlay"];
  var TOOLBAR_BTN_ON_CLASSES = ["bg-accent", "text-white", "border-accent", "hover:bg-accent-hover"];

  function setMagnetism(enabled) {
    try { localStorage.setItem("asra-map-magnetism", enabled ? "1" : "0"); } catch (e) { /* ignore */ }
    var btn = document.getElementById("map-magnetism-toggle");
    if (btn) {
      btn.textContent = "Magnetism: " + (enabled ? "On" : "Off");
      btn.setAttribute("aria-pressed", enabled ? "true" : "false");
      // A text-only state change on a small toolbar button is easy to miss entirely -- a real
      // operator complaint ("magnetism doesn't work") turned out to be exactly this: the toggle
      // WAS flipping, there was just no visible confirmation that anything had happened. A filled
      // vs outline button, matching this app's own primary/secondary button styling, makes the
      // current state unmistakable at a glance.
      (enabled ? TOOLBAR_BTN_OFF_CLASSES : TOOLBAR_BTN_ON_CLASSES).forEach(function (c) { btn.classList.remove(c); });
      (enabled ? TOOLBAR_BTN_ON_CLASSES : TOOLBAR_BTN_OFF_CLASSES).forEach(function (c) { btn.classList.add(c); });
    }
  }

  function cascadePosition(index) {
    // A plain deterministic stagger, not a random scatter -- reproducible, and cheap to reason
    // about when several new nodes land in the same tick. Spacing is wide enough for a REAL
    // hostname label (e.g. "checkout.example.com") to sit under its own node without touching its
    // neighbor's -- a real, confirmed operator report: the previous tight 90px grid packed long
    // domain names into each other on first render, even before anyone dragged anything.
    return { x: 90 + (index % 5) * 170, y: 70 + Math.floor(index / 5) * 110 };
  }

  // Real, confirmed finding from actually testing "Auto-arrange" against several mutually
  // DISCONNECTED nodes (recon found several sibling domains with no relationship between them yet
  // -- a real, common case): tuning cose's own nodeRepulsion/componentSpacing constants could not
  // be made reliable -- cose is a physics simulation, not a guarantee, and it kept settling with
  // long hostname labels visibly overlapping regardless of how those two knobs were adjusted.
  // resolveNodeOverlaps() below is the actual guarantee: a plain, deterministic relaxation pass
  // run AFTER cose settles, using cytoscape's own real label-inclusive bounding boxes (not a
  // guessed character count) to detect and separate anything still too close. cose still does the
  // useful part (pulling genuinely connected nodes into a sensible shape); this pass is what
  // turns "usually fine" into "actually guaranteed" for the specific ask that mattered here --
  // normal-looking nodes even after Auto-arrange, not just on first creation.
  function resolveNodeOverlaps(nodes, margin) {
    var arr = nodes.toArray ? nodes.toArray() : nodes;
    var pad = margin || 24;
    for (var iter = 0; iter < 200; iter++) {
      var movedAny = false;
      for (var i = 0; i < arr.length; i++) {
        for (var j = i + 1; j < arr.length; j++) {
          var a = arr[i], b = arr[j];
          if (a.locked() && b.locked()) continue; // neither can move -- nothing to resolve
          var ba = a.boundingBox({ includeLabels: true });
          var bb = b.boundingBox({ includeLabels: true });
          var overlapX = Math.min(ba.x2, bb.x2) - Math.max(ba.x1, bb.x1) + pad;
          var overlapY = Math.min(ba.y2, bb.y2) - Math.max(ba.y1, bb.y1) + pad;
          if (overlapX <= 0 || overlapY <= 0) continue;
          movedAny = true;
          var pa = a.position(), pb = b.position();
          // Real bug this replaced: pushing along the diagonal center-to-center direction, scaled
          // by the smaller-axis overlap amount, barely moves a pair that's mostly offset along the
          // OTHER axis -- e.g. two nodes stacked almost directly above one another got pushed
          // sideways by a tiny amount and downward/upward by an even tinier one, needing far more
          // than 80 passes to actually separate a 3-way cluster (confirmed live: it didn't, three
          // real hostname labels stayed visibly merged). The standard, correct fix is a PURE
          // axis-aligned separation along whichever single axis is cheaper to fix (the actual
          // "minimum translation vector" for two overlapping boxes) -- one push per pair fully
          // clears that pair on that axis, converging in far fewer iterations.
          var pushAlongX = overlapX < overlapY;
          var push = (pushAlongX ? overlapX : overlapY) / 2 + 1;
          var ux = 0, uy = 0;
          if (pushAlongX) {
            // Centers can coincide exactly on this axis (the very bug this file exists to
            // prevent) -- fall back to a deterministic, pair-indexed tie-break instead of a
            // zero-length direction that would leave both stuck in place forever.
            ux = pa.x !== pb.x ? (pa.x > pb.x ? 1 : -1) : (i % 2 === 0 ? 1 : -1);
          } else {
            uy = pa.y !== pb.y ? (pa.y > pb.y ? 1 : -1) : (i % 2 === 0 ? 1 : -1);
          }
          if (a.locked()) {
            b.position({ x: pb.x - ux * push * 2, y: pb.y - uy * push * 2 });
          } else if (b.locked()) {
            a.position({ x: pa.x + ux * push * 2, y: pa.y + uy * push * 2 });
          } else {
            a.position({ x: pa.x + ux * push, y: pa.y + uy * push });
            b.position({ x: pb.x - ux * push, y: pb.y - uy * push });
          }
        }
      }
      if (!movedAny) break;
    }
  }

  // Real, confirmed finding from actually testing "Auto-arrange" against several mutually
  // DISCONNECTED nodes (recon found several sibling domains with no relationship between them yet
  // -- a real, common case): tuning cose's own nodeRepulsion/componentSpacing constants could not
  // be made reliable on their own -- cose is a physics simulation, not a guarantee, and it kept
  // settling with long hostname labels visibly overlapping regardless of how those knobs were
  // adjusted. cose still does the useful part here (pulling genuinely connected nodes into a
  // sensible shape); resolveNodeOverlaps (run once cose actually settles, via layoutstop -- an
  // animated layout's own .run() returns immediately, well before the animation finishes) is the
  // actual guarantee layered on top, using cytoscape's real label-inclusive bounding boxes.
  function runCoseThenResolve(target, overrides, afterResolve) {
    var layout = target.layout(coseOptions(overrides));
    layout.one("layoutstop", function () {
      resolveNodeOverlaps(cy.nodes());
      if (afterResolve) afterResolve();
    });
    layout.run();
  }

  function coseOptions(overrides) {
    return Object.assign({
      name: "cose",
      nodeDimensionsIncludeLabels: true,
      componentSpacing: 160,
      idealEdgeLength: 140,
      nodeRepulsion: 12000,
    }, overrides);
  }

  // ---- Optimistic local mutations (the actual "instant" half of add/edit/delete) -------------
  // Real, confirmed operator complaint: adding/deleting a node used to feel laggy, not instant --
  // create/edit/delete/hide all POST then just close their dialog, with NOTHING touching the live
  // cy instance; the only path to actually seeing the change land was the next SSE tick (up to
  // main.py's _SSE_POLL_INTERVAL_SECONDS=1s) re-rendering the WHOLE session fragment and this
  // file's own MutationObserver noticing the data blob's text changed. On a long-running session
  // (a big #session-stream subtree) that round trip is easily multiple seconds, not "instant" by
  // any reasonable reading -- same "must apply live in the DOM, never only on next poll" rule this
  // project already enforces for every other visual toggle. Applying the mutation locally the
  // instant the POST succeeds (create_map_node/create_map_edge now return the real created
  // id/data for exactly this) is safe to do alongside the eventual SSE reconciliation: initOrUpdate
  // above only adds elements whose id isn't ALREADY present, so the later tick just re-applies the
  // same data onto the node this function already created, never a duplicate.
  function addLocalNode(nodeData) {
    if (!cy || cy.getElementById(nodeData.id).length) return;
    placeNewElements([{
      data: {
        id: nodeData.id, label: nodeData.label, worst_severity: null, has_open_hypothesis: false,
        kind: nodeData.kind || "host", manual: true, notes: nodeData.notes || "",
        known_hostnames: [], resolved_ips: [], ports: [], technologies: [], finding_count_by_severity: {}, hypothesis_count: 0,
        has_confirmed_access: false, surface_score: 0,
      },
      position: cascadePosition(cy.nodes().length),
    }]);
  }

  function addLocalEdge(edgeData) {
    if (!cy || cy.getElementById(edgeData.id).length) return;
    cy.add({
      data: {
        id: edgeData.id, source: edgeData.source, target: edgeData.target, kind: "manual",
        label: edgeData.label || "", direction: edgeData.direction || "forward", manual: true,
        data_type: edgeData.data_type || "", volume: edgeData.volume || "",
        format: edgeData.format || "", interval: edgeData.interval || "", notes: edgeData.notes || "",
      },
    });
  }

  function updateLocalElement(id, data) {
    if (!cy) return;
    var ele = cy.getElementById(id);
    if (ele.length) ele.data(Object.assign({}, ele.data(), data));
  }

  function removeLocalElement(id) {
    if (!cy) return;
    var ele = cy.getElementById(id);
    if (ele.length) ele.remove();
  }

  function placeNewElements(newElements) {
    if (!newElements.length) return;
    // Every element already carries a real, distinct position from toElements() (its own saved
    // one, or a cascade slot) -- magnetism only decides whether cose then refines that starting
    // layout based on connectivity, never whether a position exists at all.
    if (magnetismEnabled()) {
      var existing = cy.nodes();
      existing.lock();
      cy.add(newElements);
      runCoseThenResolve(cy, { randomize: false, fit: false, animate: false });
      existing.unlock();
    } else {
      cy.add(newElements);
    }
  }

  // ---- Right-click context menu ---------------------------------------------------------------
  // Real, direct operator ask: add/edit/delete a node or connection via right-click, the
  // conventional interaction for a graph editor (Miro, draw.io, Maltego) -- the existing
  // toolbar-button + click-to-open-detail-panel flow wasn't discoverable enough on its own. A
  // small self-built menu (not a cytoscape extension) keeps this dependency-free and lets it match
  // this app's own button/panel styling exactly, same reasoning the dialogs already follow.
  function closeMapContextMenu() {
    var existing = document.getElementById("map-context-menu");
    if (existing) existing.remove();
  }

  function showMapContextMenu(clientX, clientY, items) {
    closeMapContextMenu();
    var menu = document.createElement("div");
    menu.id = "map-context-menu";
    // z-[55], not z-50 -- must stay above #map-graph-row's own z-50 once "Expand" (Fullscreen mode,
    // themes.css) is on, or a right-click inside the expanded map would open a menu the fullscreen
    // overlay then painted straight over.
    menu.className = "fixed z-[55] bg-surface border border-default rounded-lg shadow-lg py-1 text-[12px] min-w-[180px]";
    menu.style.left = clientX + "px";
    menu.style.top = clientY + "px";
    items.forEach(function (item) {
      if (item === "-") {
        var hr = document.createElement("div");
        hr.className = "my-1 border-t border-default";
        menu.appendChild(hr);
        return;
      }
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "w-full text-left px-3 py-1.5 hover:bg-elevated " + (item.danger ? "text-severity-high" : "text-primary");
      btn.textContent = item.label;
      btn.addEventListener("click", function (evt) {
        evt.stopPropagation();
        closeMapContextMenu();
        item.action();
      });
      menu.appendChild(btn);
    });
    document.body.appendChild(menu);
    // Keep the menu on-screen even when the right-click lands near an edge of the viewport.
    var rect = menu.getBoundingClientRect();
    if (rect.right > window.innerWidth) menu.style.left = Math.max(8, window.innerWidth - rect.width - 8) + "px";
    if (rect.bottom > window.innerHeight) menu.style.top = Math.max(8, window.innerHeight - rect.height - 8) + "px";
  }

  document.addEventListener("click", closeMapContextMenu);
  document.addEventListener("keydown", function (evt) { if (evt.key === "Escape") closeMapContextMenu(); });

  function wireContextMenus() {
    // cytoscape's own right-click event is "cxttap" -- the mount's native browser context menu is
    // suppressed globally (below) so it never fights this custom one.
    cy.on("cxttap", "node", function (evt) {
      var node = evt.target;
      var items = [];
      if (node.data("manual")) {
        items.push({ label: "Edit node", action: function () { window.asraOpenMapNodeEditor(node.id()); } });
        items.push({ label: "Delete node", danger: true, action: function () {
          removeLocalElement(node.id());
          fetch("/api/session/" + sessionId + "/map/node/" + node.id() + "/delete", { method: "POST" });
        } });
      } else {
        // A real recon-derived node has nothing to delete (see hide_map_node's own docstring) --
        // "hide" is the honest equivalent, a display preference, never a claim of removing data.
        items.push({ label: "Hide from map", action: function () {
          removeLocalElement(node.id());
          var body = new URLSearchParams({ hidden: "true" });
          fetch("/api/session/" + sessionId + "/map/node/" + node.id() + "/hide", { method: "POST", body: body });
        } });
      }
      items.push("-");
      items.push({ label: "Add connection from here", action: function () {
        if (openEdgeDialogFrom) openEdgeDialogFrom(node.id());
      } });
      showMapContextMenu(evt.originalEvent.clientX, evt.originalEvent.clientY, items);
    });

    cy.on("cxttap", "edge", function (evt) {
      var edge = evt.target;
      if (!edge.data("manual")) return; // an auto (dns/credential_reuse) edge has nothing to edit
      showMapContextMenu(evt.originalEvent.clientX, evt.originalEvent.clientY, [
        { label: "Edit connection", action: function () { window.asraOpenMapEdgeEditor(edge.id()); } },
        { label: "Delete connection", danger: true, action: function () {
          removeLocalElement(edge.id());
          fetch("/api/session/" + sessionId + "/map/edge/" + edge.id() + "/delete", { method: "POST" });
        } },
      ]);
    });

    cy.on("cxttap", function (evt) {
      if (evt.target !== cy) return; // a node/edge tap already handled above
      var addNodeBtn = document.getElementById("map-add-node-btn");
      var addEdgeBtn = document.getElementById("map-add-edge-btn");
      showMapContextMenu(evt.originalEvent.clientX, evt.originalEvent.clientY, [
        { label: "Add node here", action: function () { if (addNodeBtn) addNodeBtn.click(); } },
        { label: "Add connection", action: function () { if (addEdgeBtn) addEdgeBtn.click(); } },
      ]);
    });
  }

  function wireInteractionHandlers() {
    wireContextMenus();
    // The browser's own native right-click menu would otherwise pop up ON TOP of (or instead of)
    // the custom one above every single time -- this is the one place on the whole page a
    // right-click has real, intentional meaning, so suppressing it here is scoped, not a blanket
    // page-wide change.
    var mount = document.getElementById("attack-surface-graph-mount");
    if (mount) mount.addEventListener("contextmenu", function (evt) { evt.preventDefault(); });
    // Real, confirmed rough edge found alongside the zoom-bounds fix above: once cytoscape's own
    // zoom hits minZoom/maxZoom, it stops consuming further wheel events -- the leftover scroll
    // then bubbles up and scrolls the WHOLE PAGE instead, so an operator who kept scrolling past
    // the cap (an easy thing to do without realizing the graph already maxed out) suddenly found
    // themselves scrolled away to a completely different tab's content. { passive: false } is
    // required for preventDefault() to actually have effect on a wheel listener.
    if (mount) mount.addEventListener("wheel", function (evt) { evt.preventDefault(); }, { passive: false });
    // Real, confirmed operator complaint: panning with the middle mouse button felt laggy/janky.
    // Root cause -- cytoscape's own default panning is bound to a LEFT-drag on empty canvas only;
    // nothing here (or in cytoscape itself) ever told the middle button to do anything, so a
    // middle-button drag fell straight through to the BROWSER's own native middle-click
    // autoscroll (Chrome/Firefox: press-and-hold middle button enters a page-autoscroll mode with
    // its own floating indicator) fighting the canvas's own repaint on every frame -- exactly the
    // "laggy" feel reported, and it was scrolling the outer PAGE, not panning the graph, the whole
    // time. Wiring the middle button to cytoscape's own cy.panBy() directly (same call Home/wheel-
    // zoom already drive) is both the fix (real graph panning, not page autoscroll) and the actual
    // feature this app's own doc comments already promise ("a physics/magnetism toggle, a Home
    // button" -- middle-mouse-drag-to-pan is the same category of Miro/draw.io-style convenience).
    if (mount) {
      var panState = null; // {lastX, lastY} while the middle button is held, else null
      mount.addEventListener("mousedown", function (evt) {
        if (evt.button !== 1) return;
        evt.preventDefault(); // blocks the browser's own native middle-click autoscroll
        panState = { lastX: evt.clientX, lastY: evt.clientY };
        mount.style.cursor = "grabbing";
      });
      document.addEventListener("mousemove", function (evt) {
        if (!panState) return;
        var dx = evt.clientX - panState.lastX, dy = evt.clientY - panState.lastY;
        panState.lastX = evt.clientX;
        panState.lastY = evt.clientY;
        cy.panBy({ x: dx, y: dy });
      });
      // Listened on document, not just mount -- a fast drag can easily carry the cursor outside
      // the mount's own bounds mid-gesture, and the release still has to end the pan cleanly
      // rather than leaving it stuck "on" until the next unrelated middle click.
      document.addEventListener("mouseup", function (evt) {
        if (!panState || evt.button !== 1) return;
        panState = null;
        mount.style.cursor = "";
      });
    }
    cy.on("tap", "node, edge", function (evt) { renderDetailPanel(evt.target); });
    cy.on("dragfree", "node", function (evt) {
      var node = evt.target;
      saveNodePosition(node.id(), node.position());
      if (!magnetismEnabled()) return;
      // Obsidian-graph-style "magnetism": dragging a node gives its DIRECTLY connected neighbors a
      // brief, visible nudge toward a natural spacing around its new spot -- confirms the toggle is
      // doing something real (a real operator complaint: the toggle flipped its own label but
      // nothing ever visibly happened).
      //
      // Real, confirmed bug this replaces: the previous version ran a cose layout scoped to just
      // node.closedNeighborhood() with everything else locked -- sound in theory, but confirmed
      // live (a throwaway cytoscape instance, same cose options, same 1-2-node subgraph) that
      // cose's own randomize:false mode does not meaningfully move anything on a subgraph this
      // small: with no other nodes to push against, it converges instantly with zero perceptible
      // motion. Same root cause "Auto-arrange" already had to work around elsewhere in this file
      // (see resolveNodeOverlaps's own comment on cose needing real asymmetry to break) -- this
      // interaction needed the same kind of deterministic guarantee, not another cose call.
      //
      // The actual fix: a plain spring-toward-ideal-length step, not a layout at all. Any direct
      // neighbor that ended up farther than idealEdgeLength from the dragged node's NEW position
      // gets animated straight toward that ideal distance along the line to it (a neighbor already
      // close enough is left alone -- this only pulls, never pushes, so a tight cluster never
      // visibly scatters just because one member got dragged). resolveNodeOverlaps still runs
      // afterward, same as Auto-arrange, to guarantee no two labels end up overlapping regardless.
      var neighbors = node.neighborhood().nodes();
      if (neighbors.length === 0) return; // an isolated node has nothing to nudge
      var anchor = node.position();
      var idealLength = coseOptions().idealEdgeLength;
      function settle() {
        resolveNodeOverlaps(cy.nodes());
        neighbors.forEach(function (n) { saveNodePosition(n.id(), n.position()); });
      }
      var toPull = neighbors.filter(function (n) {
        var p = n.position();
        return Math.hypot(p.x - anchor.x, p.y - anchor.y) > idealLength * 1.4;
      });
      if (!toPull.length) { settle(); return; }
      var remaining = toPull.length;
      toPull.forEach(function (n) {
        var p = n.position();
        var dx = p.x - anchor.x, dy = p.y - anchor.y;
        var dist = Math.hypot(dx, dy) || 1;
        var scale = idealLength / dist;
        n.animate(
          { position: { x: anchor.x + dx * scale, y: anchor.y + dy * scale } },
          { duration: 300, easing: "ease-in-out", complete: function () {
            remaining -= 1;
            if (remaining === 0) settle();
          } }
        );
      });
    });
  }

  function initOrUpdate() {
    var dataEl = document.getElementById("attack-surface-data");
    var mount = document.getElementById("attack-surface-graph-mount");
    if (!dataEl || !mount) {
      cy = null; // the empty-state branch is rendering instead -- nothing to keep alive
      lastAppliedJson = null;
      return;
    }
    var rawJson = dataEl.textContent;
    if (rawJson === lastAppliedJson) return; // no real change -- this is what stops the loop below
    lastAppliedJson = rawJson;

    var graph;
    try {
      graph = JSON.parse(rawJson);
    } catch (e) {
      return;
    }

    var elements = toElements(graph);

    if (!cy) {
      // Plain "preset" only, on the cascade positions toElements() already guaranteed every node
      // -- deliberately NOT an automatic cose pass here even with magnetism on. A real, confirmed
      // regression: for a batch of new, mutually disconnected nodes (recon just found several
      // sibling domains, nothing links them to each other yet), cose has no attraction to counter
      // its own repulsion with, and its label-overlap-avoidance pass proved unreliable in practice
      // -- long hostname labels still visibly collided even with nodeDimensionsIncludeLabels on.
      // The deterministic cascade grid is the one thing that's actually guaranteed correct on
      // first render ("normal the moment it's created", a direct operator ask) -- cose stays
      // available on request (the Auto-arrange button) for when the operator wants it, instead of
      // silently substituting its own less predictable result for a plain new graph's first paint.
      cy = cytoscape({
        container: mount, elements: elements, style: style(), layout: { name: "preset" },
        // Real, confirmed bug: cytoscape's own default wheel sensitivity turns a single scroll
        // tick into a huge zoom jump -- an operator's own mouse wheel could zoom in enough to fill
        // the entire viewport with ONE node's icon in a single tick, reading as "the images break"
        // when it was really just an extreme, unbounded zoom level. wheelSensitivity gentles the
        // per-tick jump; minZoom/maxZoom is the actual guarantee -- a hard ceiling/floor so no
        // amount of scrolling can ever reach a genuinely unusable extreme, regardless of how the
        // wheel/trackpad's own delta happens to be reported by a given OS or input device.
        wheelSensitivity: 0.15,
        minZoom: 0.2,
        maxZoom: 2.5,
      });
      wireInteractionHandlers();
      pulseCriticalNodes(cy);
      refreshMapTimelineBounds();
      refreshMapDimming();
    } else {
      var existingIds = {};
      cy.elements().forEach(function (ele) { existingIds[ele.id()] = true; });
      var freshIds = {};
      elements.forEach(function (el) { freshIds[el.data.id] = true; });

      // Remove elements no longer present (a manual node/edge the operator just deleted).
      cy.elements().forEach(function (ele) { if (!freshIds[ele.id()]) ele.remove(); });

      var brandNew = elements.filter(function (el) { return !existingIds[el.data.id]; });
      placeNewElements(brandNew);

      // Update data (not position) on everything that already existed -- a severity change, a new
      // finding count, edited notes -- without moving anything the operator already arranged.
      elements.forEach(function (el) {
        if (existingIds[el.data.id]) {
          var ele = cy.getElementById(el.data.id);
          ele.data(el.data);
        }
      });
      pulseCriticalNodes(cy);
      refreshMapTimelineBounds();
      refreshMapDimming();
    }
  }

  // The one signature flourish on this graph (frontend-2's own "spend the boldness in a single
  // place" discipline) -- a slow breathing pulse on Critical-severity nodes only, so the single
  // most urgent thing on the map is also the one thing quietly moving, without turning the whole
  // graph into a light show. Starts from underlay-opacity 0 (invisible at rest, unlike every other
  // node) so this reads as an alert ring around Critical nodes specifically, not a permanent glow
  // every node shares.
  function pulseCriticalNodes(cyInstance) {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    cyInstance.nodes('[worst_severity = "Critical"]').forEach(function (node) {
      if (node.scratch("_pulsing")) return;
      node.scratch("_pulsing", true);
      (function loop() {
        if (!cyInstance.getElementById(node.id()).length) return; // node removed by a later update
        node.animate(
          { style: { "underlay-opacity": 0.6, "underlay-padding": 10 } },
          { duration: 900, easing: "ease-in-out", complete: function () {
            node.animate(
              { style: { "underlay-opacity": 0, "underlay-padding": 6 } },
              { duration: 900, easing: "ease-in-out", complete: loop }
            );
          } }
        );
      })();
    });
  }

  // ---- Toolbar: Add node / Add connection / Auto-arrange / Magnetism / Home -----------------
  function fillNodePicker(select, excludeId) {
    select.innerHTML = "";
    if (!cy) return;
    cy.nodes().forEach(function (node) {
      if (node.id() === excludeId) return;
      var opt = document.createElement("option");
      opt.value = node.id();
      opt.textContent = node.data("label");
      select.appendChild(opt);
    });
  }

  function showDialogError(dialogPrefix, message) {
    var el = document.getElementById(dialogPrefix + "-dialog-error");
    if (!el) return;
    el.textContent = message;
    el.classList.toggle("hidden", !message);
  }

  async function postForm(url, formEl) {
    var body = new URLSearchParams(new FormData(formEl));
    var resp = await fetch(url, { method: "POST", body: body });
    if (!resp.ok) {
      var detail = "Something went wrong.";
      try { detail = (await resp.json()).detail || detail; } catch (e) { /* ignore */ }
      throw new Error(detail);
    }
    // create_map_node/create_map_edge return the real created id/data as JSON so the caller can
    // apply it to the live graph immediately (see addLocalNode/addLocalEdge); every other route
    // here still returns an empty body, which resp.json() rejects -- null is the correct "nothing
    // to apply, the caller already knows everything it needs from its own editingId" signal.
    try { return await resp.json(); } catch (e) { return null; }
  }

  function wireNodeDialog() {
    var dialog = document.getElementById("map-node-dialog");
    var form = document.getElementById("map-node-form");
    var deleteBtn = document.getElementById("map-node-delete-btn");
    if (!dialog || !form) return;
    var editingId = null;

    function openCreate() {
      editingId = null;
      document.getElementById("map-node-dialog-title").textContent = "Add node";
      form.reset();
      deleteBtn.classList.add("hidden");
      showDialogError("map-node", "");
      dialog.showModal();
    }
    window.asraOpenMapNodeEditor = function (nodeId) {
      if (!cy) return;
      var node = cy.getElementById(nodeId);
      if (!node.length) return;
      editingId = nodeId;
      document.getElementById("map-node-dialog-title").textContent = "Edit node";
      form.elements.label.value = node.data("label") || "";
      form.elements.kind.value = node.data("kind") || "host";
      form.elements.notes.value = node.data("notes") || "";
      deleteBtn.classList.remove("hidden");
      showDialogError("map-node", "");
      dialog.showModal();
    };
    document.getElementById("map-add-node-btn").addEventListener("click", openCreate);
    document.getElementById("map-node-cancel-btn").addEventListener("click", function () { dialog.close(); });
    deleteBtn.addEventListener("click", async function () {
      if (!editingId) return;
      try {
        await postForm("/api/session/" + sessionId + "/map/node/" + editingId + "/delete", new FormData());
        removeLocalElement(editingId);
        dialog.close();
      } catch (e) { showDialogError("map-node", e.message); }
    });
    form.addEventListener("submit", async function (evt) {
      evt.preventDefault();
      var url = editingId
        ? "/api/session/" + sessionId + "/map/node/" + editingId + "/edit"
        : "/api/session/" + sessionId + "/map/node";
      try {
        var result = await postForm(url, form);
        if (editingId) {
          updateLocalElement(editingId, { label: form.elements.label.value, kind: form.elements.kind.value, notes: form.elements.notes.value });
        } else if (result && result.id) {
          addLocalNode(result);
        }
        dialog.close();
      } catch (e) { showDialogError("map-node", e.message); }
    });
  }

  function wireEdgeDialog() {
    var dialog = document.getElementById("map-edge-dialog");
    var form = document.getElementById("map-edge-form");
    var deleteBtn = document.getElementById("map-edge-delete-btn");
    if (!dialog || !form) return;
    var editingId = null;

    function openCreate(preselectSourceId) {
      editingId = null;
      document.getElementById("map-edge-dialog-title").textContent = "Add connection";
      form.reset();
      var sourceSelect = document.getElementById("map-edge-source");
      fillNodePicker(sourceSelect);
      fillNodePicker(document.getElementById("map-edge-target"));
      if (preselectSourceId) sourceSelect.value = preselectSourceId;
      deleteBtn.classList.add("hidden");
      showDialogError("map-edge", "");
      dialog.showModal();
    }
    // Right-click a node -> "Add connection from here" (attack_surface_graph.js's own context
    // menu, wired well before this dialog exists) -- a shared module-level var is how it reaches
    // this closure's own openCreate once wireEdgeDialog actually runs.
    openEdgeDialogFrom = openCreate;
    window.asraOpenMapEdgeEditor = function (edgeId) {
      if (!cy) return;
      var edge = cy.getElementById(edgeId);
      if (!edge.length) return;
      editingId = edgeId;
      document.getElementById("map-edge-dialog-title").textContent = "Edit connection";
      var sourceSelect = document.getElementById("map-edge-source");
      var targetSelect = document.getElementById("map-edge-target");
      fillNodePicker(sourceSelect);
      fillNodePicker(targetSelect);
      sourceSelect.value = edge.data("source");
      sourceSelect.disabled = true;
      targetSelect.value = edge.data("target");
      targetSelect.disabled = true;
      form.elements.direction.value = edge.data("direction") || "forward";
      form.elements.data_type.value = edge.data("data_type") || "";
      form.elements.volume.value = edge.data("volume") || "";
      form.elements.format.value = edge.data("format") || "";
      form.elements.interval.value = edge.data("interval") || "";
      form.elements.label.value = edge.data("label") || "";
      form.elements.notes.value = edge.data("notes") || "";
      deleteBtn.classList.remove("hidden");
      showDialogError("map-edge", "");
      dialog.showModal();
    };
    // Real bug this guards against: addEventListener hands its callback the click Event as the
    // first argument -- openCreate now takes an optional preselectSourceId, so binding it directly
    // would try to set the source dropdown's value to a PointerEvent object on every plain
    // toolbar-button click.
    document.getElementById("map-add-edge-btn").addEventListener("click", function () { openCreate(); });
    document.getElementById("map-edge-cancel-btn").addEventListener("click", function () {
      document.getElementById("map-edge-source").disabled = false;
      document.getElementById("map-edge-target").disabled = false;
      dialog.close();
    });
    deleteBtn.addEventListener("click", async function () {
      if (!editingId) return;
      try {
        await postForm("/api/session/" + sessionId + "/map/edge/" + editingId + "/delete", new FormData());
        removeLocalElement(editingId);
        dialog.close();
      } catch (e) { showDialogError("map-edge", e.message); }
    });
    form.addEventListener("submit", async function (evt) {
      evt.preventDefault();
      var url = editingId
        ? "/api/session/" + sessionId + "/map/edge/" + editingId + "/edit"
        : "/api/session/" + sessionId + "/map/edge";
      try {
        var result = await postForm(url, form);
        if (editingId) {
          updateLocalElement(editingId, {
            direction: form.elements.direction.value, data_type: form.elements.data_type.value,
            volume: form.elements.volume.value, format: form.elements.format.value,
            interval: form.elements.interval.value, label: form.elements.label.value, notes: form.elements.notes.value,
          });
        } else if (result && result.id) {
          addLocalEdge(result);
        }
        document.getElementById("map-edge-source").disabled = false;
        document.getElementById("map-edge-target").disabled = false;
        dialog.close();
      } catch (e) { showDialogError("map-edge", e.message); }
    });
  }

  // ---- Filter (a real, confirmed necessity once a session has 20-50+ hosts) --------------------
  // State lives here, not in the DOM inputs' own value -- initOrUpdate() re-applies it (including
  // re-syncing the inputs' displayed value) on every live SSE tick, the same "own the re-
  // application, don't trust server-rendered morphing to preserve client state" pattern
  // recon_filter.js/findings_filter.js already use for their own filters (see the filter row's own
  // template comment for the exact bug this avoids).
  var mapFilterState = { text: "", severity: "any", confirmedOnly: false };
  var _SEVERITY_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

  function mapFilterActive() {
    return !!mapFilterState.text || mapFilterState.severity !== "any" || mapFilterState.confirmedOnly;
  }

  function nodeMatchesMapFilter(node) {
    var d = node.data();
    if (mapFilterState.confirmedOnly && !d.has_confirmed_access) return false;
    if (mapFilterState.severity === "unlocated") {
      if (d.worst_severity) return false;
    } else if (mapFilterState.severity !== "any") {
      var minRank = _SEVERITY_RANK[mapFilterState.severity];
      var ownRank = d.worst_severity ? _SEVERITY_RANK[d.worst_severity] : -1;
      if (ownRank === -1 || ownRank > minRank) return false; // higher rank number = LESS severe
    }
    if (mapFilterState.text) {
      var haystack = [d.label, (d.known_hostnames || []).join(" "), (d.technologies || []).join(" "), d.notes || ""]
        .join(" ").toLowerCase();
      if (haystack.indexOf(mapFilterState.text) === -1) return false;
    }
    return true;
  }

  // ---- Timeline (replays roughly the order things were actually found in) ----------------------
  // Off by default -- the map always shows everything until the operator deliberately turns this
  // on, same "never silently change what's visible" discipline the filter row above follows.
  // Bounds (min/max) are recomputed against the LIVE data on every tick (refreshMapTimelineBounds,
  // called from initOrUpdate) since a running scan keeps adding new timestamps; cutoff is a plain
  // fraction (0-1000) of that range, not a raw timestamp, so the slider stays meaningful even as
  // the underlying min/max shift between ticks.
  var mapTimelineState = { active: false, cutoff: 1000, minMs: null, maxMs: null, playing: false, playTimer: null };

  function mapTimelineCutoffMs() {
    if (mapTimelineState.minMs === null || mapTimelineState.maxMs === null) return null;
    return mapTimelineState.minMs + (mapTimelineState.maxMs - mapTimelineState.minMs) * (mapTimelineState.cutoff / 1000);
  }

  function elementVisibleByTimeline(iso) {
    if (!mapTimelineState.active) return true;
    if (!iso) return true; // no known timestamp -- never hidden by the scrubber, see the node/edge's own "at"/"first_seen_at" doc comment (main.py)
    var cutoffMs = mapTimelineCutoffMs();
    if (cutoffMs === null) return true;
    var ms = Date.parse(iso);
    return isNaN(ms) || ms <= cutoffMs;
  }

  function refreshMapTimelineBounds() {
    if (!cy) return;
    var stampsMs = [];
    cy.nodes().forEach(function (n) { var t = Date.parse(n.data("first_seen_at")); if (!isNaN(t)) stampsMs.push(t); });
    cy.edges().forEach(function (e) { var t = Date.parse(e.data("at")); if (!isNaN(t)) stampsMs.push(t); });
    var slider = document.getElementById("map-timeline-slider");
    var toggleBtn = document.getElementById("map-timeline-toggle");
    var playBtn = document.getElementById("map-timeline-play-btn");
    if (!stampsMs.length) {
      mapTimelineState.minMs = mapTimelineState.maxMs = null;
      if (slider) slider.disabled = true;
      if (playBtn) playBtn.disabled = true;
      return;
    }
    mapTimelineState.minMs = Math.min.apply(null, stampsMs);
    mapTimelineState.maxMs = Math.max.apply(null, stampsMs);
    if (slider) slider.disabled = !mapTimelineState.active;
    if (playBtn) playBtn.disabled = !mapTimelineState.active;
    if (toggleBtn) toggleBtn.disabled = false;
  }

  function updateMapTimelineLabel() {
    var label = document.getElementById("map-timeline-label");
    if (!label) return;
    if (!mapTimelineState.active) { label.textContent = "Live"; return; }
    var cutoffMs = mapTimelineCutoffMs();
    label.textContent = cutoffMs === null ? "No timestamped events yet" : new Date(cutoffMs).toLocaleString();
  }

  function stopMapTimelinePlay() {
    mapTimelineState.playing = false;
    if (mapTimelineState.playTimer) clearInterval(mapTimelineState.playTimer);
    mapTimelineState.playTimer = null;
    var playBtn = document.getElementById("map-timeline-play-btn");
    if (playBtn) playBtn.textContent = "Play";
  }

  // ---- Combined dimming (filter above + timeline here both feed the SAME .map-dimmed class) ----
  function refreshMapDimming() {
    if (!cy) return;
    var filterOn = mapFilterActive();
    cy.nodes().forEach(function (node) {
      var dim = (filterOn && !nodeMatchesMapFilter(node)) || !elementVisibleByTimeline(node.data("first_seen_at"));
      node.toggleClass("map-dimmed", dim);
    });
    cy.edges().forEach(function (edge) {
      // Filter: only dims once BOTH endpoints are dimmed (preserves context around a match).
      // Timeline: dims the instant EITHER endpoint hasn't happened yet, or the edge's own event
      // (an attack_path pivot) hasn't -- a "replay" should never show a relationship before both
      // ends of it are already visible.
      var filterDim = filterOn && edge.source().hasClass("map-dimmed") && edge.target().hasClass("map-dimmed");
      var timelineDim = mapTimelineState.active && (
        !elementVisibleByTimeline(edge.data("at"))
        || !elementVisibleByTimeline(edge.source().data("first_seen_at"))
        || !elementVisibleByTimeline(edge.target().data("first_seen_at"))
      );
      edge.toggleClass("map-dimmed", filterDim || timelineDim);
    });
    // Self-heals the filter controls' own displayed value against a live SSE morph that already
    // ran before this executes -- cheap, and correct regardless of whether a wipe actually
    // happened.
    var textInput = document.getElementById("map-filter-text");
    var severitySelect = document.getElementById("map-filter-severity");
    var confirmedCheckbox = document.getElementById("map-filter-confirmed");
    if (textInput && document.activeElement !== textInput) textInput.value = mapFilterState.text;
    if (severitySelect) severitySelect.value = mapFilterState.severity;
    if (confirmedCheckbox) confirmedCheckbox.checked = mapFilterState.confirmedOnly;
    updateMapTimelineLabel();
  }

  function wireMapFilter() {
    var textInput = document.getElementById("map-filter-text");
    var severitySelect = document.getElementById("map-filter-severity");
    var confirmedCheckbox = document.getElementById("map-filter-confirmed");
    var clearBtn = document.getElementById("map-filter-clear-btn");
    if (textInput) {
      textInput.addEventListener("input", function () {
        mapFilterState.text = textInput.value.trim().toLowerCase();
        refreshMapDimming();
      });
    }
    if (severitySelect) {
      severitySelect.addEventListener("change", function () {
        mapFilterState.severity = severitySelect.value;
        refreshMapDimming();
      });
    }
    if (confirmedCheckbox) {
      confirmedCheckbox.addEventListener("change", function () {
        mapFilterState.confirmedOnly = confirmedCheckbox.checked;
        refreshMapDimming();
      });
    }
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        mapFilterState = { text: "", severity: "any", confirmedOnly: false };
        refreshMapDimming();
      });
    }
  }

  function wireMapTimeline() {
    var toggleBtn = document.getElementById("map-timeline-toggle");
    var slider = document.getElementById("map-timeline-slider");
    var playBtn = document.getElementById("map-timeline-play-btn");
    if (toggleBtn) {
      toggleBtn.addEventListener("click", function () {
        mapTimelineState.active = !mapTimelineState.active;
        toggleBtn.textContent = "Timeline: " + (mapTimelineState.active ? "On" : "Off");
        toggleBtn.setAttribute("aria-pressed", mapTimelineState.active ? "true" : "false");
        (mapTimelineState.active ? TOOLBAR_BTN_OFF_CLASSES : TOOLBAR_BTN_ON_CLASSES).forEach(function (c) { toggleBtn.classList.remove(c); });
        (mapTimelineState.active ? TOOLBAR_BTN_ON_CLASSES : TOOLBAR_BTN_OFF_CLASSES).forEach(function (c) { toggleBtn.classList.add(c); });
        if (slider) slider.disabled = !mapTimelineState.active || mapTimelineState.minMs === null;
        if (playBtn) playBtn.disabled = !mapTimelineState.active || mapTimelineState.minMs === null;
        if (!mapTimelineState.active) stopMapTimelinePlay();
        refreshMapDimming();
      });
    }
    if (slider) {
      slider.addEventListener("input", function () {
        mapTimelineState.cutoff = Number(slider.value);
        refreshMapDimming();
      });
    }
    if (playBtn) {
      playBtn.addEventListener("click", function () {
        if (mapTimelineState.playing) { stopMapTimelinePlay(); return; }
        if (!mapTimelineState.active || !slider) return;
        mapTimelineState.playing = true;
        playBtn.textContent = "Pause";
        mapTimelineState.playTimer = setInterval(function () {
          var next = mapTimelineState.cutoff + 15;
          if (next >= 1000) { next = 1000; stopMapTimelinePlay(); }
          mapTimelineState.cutoff = next;
          slider.value = String(next);
          refreshMapDimming();
        }, 200);
      });
    }
  }

  function wireToolbar() {
    setMagnetism(magnetismEnabled());
    var magnetBtn = document.getElementById("map-magnetism-toggle");
    if (magnetBtn) {
      magnetBtn.addEventListener("click", function () { setMagnetism(!magnetismEnabled()); });
    }
    var homeBtn = document.getElementById("map-home-btn");
    if (homeBtn) {
      homeBtn.addEventListener("click", function () {
        // For when the operator has scrolled/zoomed themselves lost -- a quick, cheap animated fit
        // rather than an instant jump, so the eye can follow where the view just came from.
        if (cy && cy.elements().length) cy.animate({ fit: { eles: cy.elements(), padding: 30 } }, { duration: 200 });
      });
    }
    var arrangeBtn = document.getElementById("map-auto-arrange-btn");
    if (arrangeBtn) {
      arrangeBtn.addEventListener("click", function () {
        if (!cy || !cy.elements().length) return;
        runCoseThenResolve(cy, { randomize: false, animate: false }, function () {
          cy.nodes().forEach(function (node) { saveNodePosition(node.id(), node.position()); });
        });
      });
    }
    var showHiddenBtn = document.getElementById("map-show-hidden-btn");
    if (showHiddenBtn) {
      showHiddenBtn.addEventListener("click", function () {
        fetch("/api/session/" + sessionId + "/map/unhide-all", { method: "POST" });
      });
    }
    var exportBtn = document.getElementById("map-export-btn");
    if (exportBtn) {
      exportBtn.addEventListener("click", function () {
        if (!cy || !cy.elements().length) return;
        // full:true frames every element, not just the current viewport -- a report screenshot
        // should show the whole map as arranged, not whatever happened to be panned into view.
        // scale:2 for a crisp image on a real document/slide, not a blurry 1x screen capture.
        var dataUri = cy.png({ full: true, scale: 2, bg: surfaceColor() });
        var link = document.createElement("a");
        link.href = dataUri;
        link.download = "attack-surface-map.png";
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
      });
    }
    // "Expand" -- real, confirmed operator complaint: the mount's own fixed height is cramped for
    // any session with more than a handful of hosts. #map-graph-row.map-fullscreen (themes.css)
    // takes the mount + detail panel out of the tab's normal scroll flow and over the viewport;
    // cy.resize() is cytoscape's own public API for "the container's real size just changed,
    // recompute" (same call the Map-tab-becomes-visible handler below already needs for the exact
    // same reason), and a re-fit afterward keeps the current graph centered in the new, much larger
    // canvas instead of leaving the camera wherever the cramped view happened to be.
    var expandBtn = document.getElementById("map-expand-btn");
    var surfacePanel = document.getElementById("map-surface-panel");
    function setExpanded(expanded) {
      if (!surfacePanel) return;
      surfacePanel.classList.toggle("map-fullscreen", expanded);
      if (expandBtn) expandBtn.textContent = expanded ? "Collapse" : "Expand";
      if (cy) {
        cy.resize();
        if (cy.elements().length) cy.fit(cy.elements(), 30);
      }
    }
    if (expandBtn) {
      expandBtn.addEventListener("click", function () {
        setExpanded(!surfacePanel.classList.contains("map-fullscreen"));
      });
    }
    document.addEventListener("keydown", function (evt) {
      if (evt.key === "Escape" && surfacePanel && surfacePanel.classList.contains("map-fullscreen")) {
        setExpanded(false);
      }
    });
    wireNodeDialog();
    wireEdgeDialog();
  }

  var mountForSessionId = document.getElementById("attack-surface-graph-mount") || document.getElementById("map-add-node-btn");
  if (mountForSessionId) {
    var match = window.location.pathname.match(/\/session\/([^/]+)/);
    sessionId = match ? match[1] : null;
  }

  initOrUpdate();
  wireToolbar();
  wireMapFilter();
  wireMapTimeline();

  // Scoped to #session-stream specifically, not document.body -- that's the one element this data
  // blob can ever appear/change inside (session_fragment.html's own SSE/morph target), same
  // "observe the smallest real scope, not the whole page" discipline chat_panel.html's own
  // MutationObserver already follows for the identical reason (avoiding needless work on every
  // unrelated mutation elsewhere, e.g. the terminal's own high-frequency output). childList +
  // subtree: catches both the data blob's own text content changing on a live tick AND the mount
  // div appearing for the first time (the empty-state branch swapping to the real graph markup
  // once Recon records its first target) or disappearing again.
  var streamEl = document.getElementById("session-stream");
  if (streamEl) {
    new MutationObserver(initOrUpdate).observe(streamEl, { childList: true, subtree: true, characterData: true });
  }

  // Real, confirmed bug this fixes: session.html's own tab switching (macros/ui.html's tab_bar())
  // is pure CSS -- a radio's :checked pseudo-state driving a `:has()` visibility rule, never an
  // actual DOM mutation -- so a MutationObserver (above) NEVER fires when the operator clicks from
  // some other tab over to Map. On first page load the Map tab is very likely NOT the active one
  // (Overview is), so cytoscape's own initial init above runs against a `display:none` container
  // with zero width/height -- it silently produces a broken, invisible/mis-laid-out graph, and
  // nothing ever told it to fix itself up once the container actually became visible. Listening
  // for the tab radio's own "change" event (a REAL event, unlike the CSS-only :checked state) and
  // calling cy.resize() -- cytoscape's own public API for "the container's real size may have
  // changed, recompute" -- is what actually recovers from that; re-fitting the viewport too, since
  // a preset layout computed against a 0x0 container can leave the camera looking at the wrong spot.
  var mapTabRadio = document.getElementById("tab-map");
  if (mapTabRadio) {
    mapTabRadio.addEventListener("change", function () {
      if (!mapTabRadio.checked) return;
      initOrUpdate();
      if (cy) {
        cy.resize();
        if (cy.elements().length) cy.fit(cy.elements(), 30);
      }
    });
  }
})();
