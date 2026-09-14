// Summary tab's diagram builder (session_fragment.html's [data-diagram-builder]) — a self-serve
// chart constructor over this session's own already-recorded data (findings, recon results,
// tool-call logs), additional to and separate from the fixed severity/verification/scope charts
// already on that tab. Server-gated to session.status === "completed" only: a completed session's
// own data never changes again, so main.py's stream_session never emits another SSE event for it
// and #session-content's morph never touches this block once rendered — no need to defend this
// against the SSE-reset problem the rest of the session page works around (see session.html/
// themes.css's own comments on that).
(function () {
  var CHART_SLOTS = ["chart-1", "chart-2", "chart-3", "chart-4", "chart-5", "chart-6", "chart-7", "chart-8"];
  var PHASE_ORDER = ["recon", "analyze", "exploit"];
  var VERIFICATION_STATUSES = ["verified", "inferred", "needs_verification"];
  var VERIFICATION_TONE = { verified: "low", inferred: "medium", needs_verification: "unknown" };
  var SCOPE_STATUSES = ["qualifying", "non_qualifying", "unclear"];
  var SCOPE_TONE = { qualifying: "critical", non_qualifying: "unknown", unclear: "medium" };
  var SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

  function cssVar(name) { return "rgb(var(--" + name + "))"; }
  function paletteColor(index) { return cssVar(CHART_SLOTS[index % CHART_SLOTS.length]); }

  function titleCase(value) {
    return String(value).replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
    });
  }

  // Counts occurrences of keyFn(item) across items, preserving first-seen order (so chart color
  // assignment and axis order stay stable run to run instead of resorting alphabetically).
  function countBy(items, keyFn) {
    var counts = {};
    var order = [];
    items.forEach(function (item) {
      var key = keyFn(item);
      if (key === null || key === undefined || key === "") return;
      key = String(key);
      if (!(key in counts)) { counts[key] = 0; order.push(key); }
      counts[key] += 1;
    });
    return order.map(function (key) { return { label: key, value: counts[key] }; });
  }

  // ---- Metric catalog — each compute(session) returns {series: [{label, value, color}]} ----

  function findingsBySeverity(session) {
    var findings = session.findings || [];
    return {
      series: SEVERITY_ORDER.map(function (sev) {
        var count = findings.filter(function (f) { return f.severity === sev; }).length;
        return { label: sev, value: count, color: cssVar("severity-" + sev.toLowerCase()) };
      }),
    };
  }

  function findingsByVerification(session) {
    var findings = session.findings || [];
    return {
      series: VERIFICATION_STATUSES.map(function (status) {
        var count = findings.filter(function (f) { return f.verification === status; }).length;
        return { label: titleCase(status), value: count, color: cssVar("severity-" + VERIFICATION_TONE[status]) };
      }),
    };
  }

  function findingsByScope(session) {
    var findings = session.findings || [];
    return {
      series: SCOPE_STATUSES.map(function (status) {
        var count = findings.filter(function (f) { return f.qualifies_for_bounty === status; }).length;
        return { label: titleCase(status), value: count, color: cssVar("severity-" + SCOPE_TONE[status]) };
      }),
    };
  }

  function targetsByField(field) {
    return function (session) {
      var targets = (session.recon_result && session.recon_result.targets) || [];
      var pairs = countBy(targets, function (t) { return t[field]; });
      return { series: pairs.map(function (p, i) { return { label: p.label, value: p.value, color: paletteColor(i) }; }) };
    };
  }

  function hostHealth(session) {
    var health = (session.recon_result && session.recon_result.host_health) || {};
    var successes = 0, failures = 0;
    Object.keys(health).forEach(function (host) {
      successes += health[host].successes || 0;
      failures += health[host].failures || 0;
    });
    return {
      series: [
        { label: "Successful", value: successes, color: cssVar("severity-low") },
        { label: "Failed", value: failures, color: cssVar("severity-high") },
      ],
    };
  }

  function callsByPhase(session) {
    var logs = session.logs || [];
    return {
      series: PHASE_ORDER.map(function (phase, i) {
        var count = logs.filter(function (l) { return l.phase === phase; }).length;
        return { label: titleCase(phase), value: count, color: paletteColor(i) };
      }),
    };
  }

  function statusByPhase(session) {
    var logs = session.logs || [];
    var series = [];
    PHASE_ORDER.forEach(function (phase) {
      var phaseLogs = logs.filter(function (l) { return l.phase === phase; });
      var ok = phaseLogs.filter(function (l) { return l.status !== "error" && l.status !== "failed"; }).length;
      series.push({ label: titleCase(phase) + " — ok", value: ok, color: cssVar("severity-low") });
      series.push({ label: titleCase(phase) + " — error", value: phaseLogs.length - ok, color: cssVar("severity-high") });
    });
    return { series: series };
  }

  function durationByPhase(session) {
    var logs = session.logs || [];
    return {
      series: PHASE_ORDER.map(function (phase, i) {
        var totalMs = logs
          .filter(function (l) { return l.phase === phase && typeof l.duration_ms === "number"; })
          .reduce(function (sum, l) { return sum + l.duration_ms; }, 0);
        return { label: titleCase(phase), value: Math.round(totalMs / 1000), color: paletteColor(i) };
      }),
    };
  }

  // Log entries mix two "command" string shapes (agent/core.py's _describe_command): a
  // subprocess-tier tool logs its real shell invocation ("nmap -F -sV target.com" — space-
  // separated, tool name is the first token) while a native tier-1 tool logs "name({...json...})"
  // with NO space before the paren — but json.dumps' own default separators put a space *inside*
  // the arguments (e.g. '{"phases": [...'), so a plain split-on-whitespace grabs
  // 'update_plan({"phases":' instead of the tool name for every native call. Matching the
  // name(...) shape first, and only falling back to the first whitespace token when that doesn't
  // match, handles both shapes correctly.
  function extractToolName(command) {
    var trimmed = String(command).trim();
    var nativeMatch = /^([A-Za-z_]\w*)\(/.exec(trimmed);
    if (nativeMatch) return nativeMatch[1];
    // A subprocess tool run via its resolved absolute path (radare2/gdb/etc, e.g.
    // "/usr/local/bin/radare2 -q -c ...") must reduce to just the basename ("radare2"), not the
    // whole path -- kept in sync with main.py's own _extract_tool_name_from_command fix for the
    // identical bug (a graph node once showed the literal truncated path as its "tool name").
    var firstToken = trimmed.split(/\s+/)[0];
    if (!firstToken) return null;
    var slashParts = firstToken.split("/");
    return slashParts[slashParts.length - 1];
  }

  function topTools(session) {
    var logs = session.logs || [];
    var pairs = countBy(logs, function (l) {
      return l.command ? extractToolName(l.command) : null;
    });
    pairs.sort(function (a, b) { return b.value - a.value; });
    return { series: pairs.slice(0, 8).map(function (p, i) { return { label: p.label, value: p.value, color: paletteColor(i) }; }) };
  }

  var METRIC_GROUPS = {
    findings: {
      label: "Findings",
      metrics: {
        severity: { label: "By severity", compute: findingsBySeverity },
        verification: { label: "By verification status", compute: findingsByVerification },
        scope: { label: "By bounty scope match", compute: findingsByScope },
      },
    },
    recon: {
      label: "Recon",
      metrics: {
        service: { label: "Targets by service", compute: targetsByField("service") },
        port: { label: "Targets by port", compute: targetsByField("port") },
        host: { label: "Open ports by host", compute: targetsByField("host") },
        host_health: { label: "Host connectivity (ok vs failed)", compute: hostHealth },
      },
    },
    activity: {
      label: "Tool activity",
      metrics: {
        calls_by_phase: { label: "Tool calls by phase", compute: callsByPhase },
        status_by_phase: { label: "Success vs error by phase", compute: statusByPhase },
        duration_by_phase: { label: "Total duration by phase (sec)", compute: durationByPhase },
        top_tools: { label: "Most-used tools (top 8)", compute: topTools },
      },
    },
  };

  // ---- Rendering — plain SVG/DOM, no chart library, same hand-rolled approach as the fixed
  // severity donut/bars above this block (session_fragment.html) ----

  function toPercent(series) {
    var total = series.reduce(function (s, p) { return s + p.value; }, 0);
    return series.map(function (p) { return { label: p.label, value: total ? (p.value / total) * 100 : 0, color: p.color }; });
  }

  function displayValue(series, valueMode) {
    return valueMode === "percent" ? toPercent(series) : series;
  }

  function formatValue(value, valueMode) {
    var rounded = Math.round(value * 10) / 10;
    return valueMode === "percent" ? rounded + "%" : String(Math.round(value * 100) / 100);
  }

  function renderBar(container, series, valueMode) {
    var shown = displayValue(series, valueMode);
    var maxVal = Math.max.apply(null, shown.map(function (p) { return p.value; }).concat([0.0001]));
    var wrap = document.createElement("div");
    wrap.className = "space-y-2";
    series.forEach(function (p, i) {
      var row = document.createElement("div");
      row.className = "flex items-center gap-2";
      row.title = p.label + ": " + formatValue(shown[i].value, valueMode);
      var label = document.createElement("span");
      label.className = "w-32 shrink-0 text-[11px] text-secondary truncate";
      label.textContent = p.label;
      var track = document.createElement("div");
      track.className = "flex-1 h-4 bg-elevated rounded-full overflow-hidden";
      var fill = document.createElement("div");
      fill.className = "h-full rounded-full";
      fill.style.backgroundColor = p.color;
      fill.style.width = (shown[i].value / maxVal * 100) + "%";
      track.appendChild(fill);
      var value = document.createElement("span");
      value.className = "w-14 shrink-0 text-[11px] text-primary text-right tabular-nums";
      value.textContent = formatValue(shown[i].value, valueMode);
      row.appendChild(label);
      row.appendChild(track);
      row.appendChild(value);
      wrap.appendChild(row);
    });
    container.appendChild(wrap);
  }

  var SVG_NS = "http://www.w3.org/2000/svg";

  function polarPoint(cx, cy, r, angleDeg) {
    var rad = (angleDeg * Math.PI) / 180;
    return { x: cx + r * Math.sin(rad), y: cy - r * Math.cos(rad) };
  }

  // Donut uses the same stroke-dasharray-on-a-circle trick as the fixed severity chart above this
  // block (r sized so its own circumference is exactly 100 units — dasharray/offset are plain
  // percentages). Pie draws real filled wedge paths instead — the dasharray trick only works for a
  // ring, never a solid slice from center.
  function renderRingOrPie(container, series, valueMode, isPie) {
    var total = series.reduce(function (s, p) { return s + p.value; }, 0);
    var shown = displayValue(series, valueMode);
    var wrap = document.createElement("div");
    wrap.className = "flex flex-col sm:flex-row items-center gap-4";
    var svgBox = document.createElement("div");
    svgBox.className = "relative w-28 h-28 shrink-0";
    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 36 36");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", isPie ? "w-28 h-28" : "w-28 h-28 -rotate-90");

    if (isPie) {
      var cumAngle = 0;
      series.forEach(function (p, i) {
        var fraction = total ? p.value / total : 0;
        var sweep = fraction * 360;
        if (sweep <= 0) return;
        var start = polarPoint(18, 18, 16, cumAngle);
        var end = polarPoint(18, 18, 16, cumAngle + sweep);
        var largeArc = sweep > 180 ? 1 : 0;
        var path = document.createElementNS(SVG_NS, "path");
        path.setAttribute(
          "d",
          "M 18 18 L " + start.x + " " + start.y + " A 16 16 0 " + largeArc + " 1 " + end.x + " " + end.y + " Z"
        );
        path.setAttribute("fill", p.color);
        var titleEl = document.createElementNS(SVG_NS, "title");
        titleEl.textContent = p.label + ": " + formatValue(shown[i].value, valueMode);
        path.appendChild(titleEl);
        svg.appendChild(path);
        cumAngle += sweep;
      });
    } else {
      var bg = document.createElementNS(SVG_NS, "circle");
      bg.setAttribute("cx", "18"); bg.setAttribute("cy", "18"); bg.setAttribute("r", "15.9155");
      bg.setAttribute("fill", "none"); bg.setAttribute("stroke", "var(--border)"); bg.setAttribute("stroke-width", "4");
      svg.appendChild(bg);
      var cumPct = 0;
      series.forEach(function (p, i) {
        var pct = total ? (p.value / total) * 100 : 0;
        if (pct <= 0) return;
        var seg = document.createElementNS(SVG_NS, "circle");
        seg.setAttribute("cx", "18"); seg.setAttribute("cy", "18"); seg.setAttribute("r", "15.9155");
        seg.setAttribute("fill", "none"); seg.setAttribute("stroke", p.color); seg.setAttribute("stroke-width", "4");
        seg.setAttribute("stroke-linecap", "butt");
        seg.setAttribute("stroke-dasharray", pct.toFixed(3) + " " + (100 - pct).toFixed(3));
        seg.setAttribute("stroke-dashoffset", (-1 * cumPct).toFixed(3));
        var titleEl = document.createElementNS(SVG_NS, "title");
        titleEl.textContent = p.label + ": " + formatValue(shown[i].value, valueMode);
        seg.appendChild(titleEl);
        svg.appendChild(seg);
        cumPct += pct;
      });
    }
    svgBox.appendChild(svg);
    if (!isPie) {
      var centerLabel = document.createElement("div");
      centerLabel.className = "absolute inset-0 flex flex-col items-center justify-center pointer-events-none";
      centerLabel.innerHTML =
        '<span class="text-lg font-semibold text-primary tabular-nums leading-none">' + escapeHtml(total) + "</span>"
        + '<span class="text-[9px] text-secondary uppercase tracking-wider">total</span>';
      svgBox.appendChild(centerLabel);
    }
    wrap.appendChild(svgBox);
    container.appendChild(wrap);
  }

  function renderLine(container, series, valueMode) {
    var shown = displayValue(series, valueMode);
    var width = 320, height = 150, padLeft = 28, padRight = 12, padTop = 12, padBottom = 26;
    var maxVal = Math.max.apply(null, shown.map(function (p) { return p.value; }).concat([0.0001]));
    var n = series.length;
    var stepX = n > 1 ? (width - padLeft - padRight) / (n - 1) : 0;
    var points = shown.map(function (p, i) {
      return {
        x: padLeft + stepX * i,
        y: height - padBottom - (p.value / maxVal) * (height - padTop - padBottom),
        raw: series[i],
        value: p.value,
      };
    });

    var svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("viewBox", "0 0 " + width + " " + height);
    svg.setAttribute("class", "w-full max-w-md h-40");

    var baseline = document.createElementNS(SVG_NS, "line");
    baseline.setAttribute("x1", padLeft); baseline.setAttribute("x2", width - padRight);
    baseline.setAttribute("y1", height - padBottom); baseline.setAttribute("y2", height - padBottom);
    baseline.setAttribute("stroke", "var(--border)"); baseline.setAttribute("stroke-width", "1");
    svg.appendChild(baseline);

    var polyline = document.createElementNS(SVG_NS, "polyline");
    polyline.setAttribute("points", points.map(function (pt) { return pt.x + "," + pt.y; }).join(" "));
    polyline.setAttribute("fill", "none");
    polyline.setAttribute("stroke", "var(--accent)");
    polyline.setAttribute("stroke-width", "2");
    polyline.setAttribute("stroke-linejoin", "round");
    polyline.setAttribute("stroke-linecap", "round");
    svg.appendChild(polyline);

    points.forEach(function (pt) {
      var dot = document.createElementNS(SVG_NS, "circle");
      dot.setAttribute("cx", pt.x); dot.setAttribute("cy", pt.y); dot.setAttribute("r", "4");
      dot.setAttribute("fill", pt.raw.color);
      dot.setAttribute("stroke", "var(--surface)"); dot.setAttribute("stroke-width", "2");
      var titleEl = document.createElementNS(SVG_NS, "title");
      titleEl.textContent = pt.raw.label + ": " + formatValue(pt.value, valueMode);
      dot.appendChild(titleEl);
      svg.appendChild(dot);

      var label = document.createElementNS(SVG_NS, "text");
      label.setAttribute("x", pt.x);
      label.setAttribute("y", height - padBottom + 14);
      label.setAttribute("text-anchor", "middle");
      label.setAttribute("fill", "var(--text-secondary)");
      label.setAttribute("font-size", "7");
      var text = pt.raw.label.length > 10 ? pt.raw.label.slice(0, 9) + "…" : pt.raw.label;
      label.textContent = text;
      svg.appendChild(label);
    });

    container.appendChild(svg);
  }

  function renderLegend(series) {
    var wrap = document.createElement("div");
    wrap.className = "flex flex-wrap gap-x-3 gap-y-1 mt-2";
    series.forEach(function (p) {
      var item = document.createElement("span");
      item.className = "inline-flex items-center gap-1.5 text-[11px] text-secondary";
      var swatch = document.createElement("span");
      swatch.className = "inline-block w-2.5 h-2.5 rounded-sm shrink-0";
      swatch.style.backgroundColor = p.color;
      item.appendChild(swatch);
      item.appendChild(document.createTextNode(p.label));
      wrap.appendChild(item);
    });
    return wrap;
  }

  function renderTable(series, valueMode) {
    var shown = displayValue(series, valueMode);
    var details = document.createElement("details");
    details.className = "group rounded-lg border border-default bg-elevated mt-2";
    var summary = document.createElement("summary");
    summary.className = "flex items-center justify-between gap-2 px-3 py-2 cursor-pointer list-none text-[11px] text-primary";
    summary.textContent = "View as table";
    details.appendChild(summary);
    var body = document.createElement("div");
    body.className = "px-3 pb-2 border-t border-default pt-2 overflow-x-auto";
    var rows = series.map(function (p, i) {
      return "<tr class=\"border-b border-default/50 last:border-b-0\">"
        + "<td class=\"py-1 pr-3 text-primary break-words\">" + escapeHtml(p.label) + "</td>"
        + "<td class=\"py-1 pr-3 text-secondary whitespace-nowrap\">" + escapeHtml(formatValue(shown[i].value, valueMode)) + "</td>"
        + "</tr>";
    });
    var table = document.createElement("table");
    table.className = "w-full text-[11px]";
    table.innerHTML =
      "<thead><tr class=\"text-left text-secondary border-b border-default\">"
      + "<th class=\"py-1 pr-3 font-medium\">Label</th><th class=\"py-1 pr-3 font-medium\">Value</th></tr></thead>"
      + "<tbody>" + rows.join("") + "</tbody>";
    body.appendChild(table);
    details.appendChild(body);
    return details;
  }

  function renderMetricInto(container, metricResult, chartType, valueMode, title) {
    container.innerHTML = "";
    if (title) {
      var heading = document.createElement("h4");
      heading.className = "text-[11px] font-semibold text-secondary mb-1.5";
      heading.textContent = title;
      container.appendChild(heading);
    }
    var series = ((metricResult && metricResult.series) || []).filter(function (p) { return p.value > 0; });
    if (!series.length) {
      var empty = document.createElement("p");
      empty.className = "text-[11px] text-secondary";
      empty.textContent = "No data recorded for this metric yet — try a different Data source above (e.g. Activity or Recon).";
      container.appendChild(empty);
      return;
    }
    var chartBox = document.createElement("div");
    container.appendChild(chartBox);
    if (chartType === "bar") renderBar(chartBox, series, valueMode);
    else if (chartType === "donut") renderRingOrPie(chartBox, series, valueMode, false);
    else if (chartType === "pie") renderRingOrPie(chartBox, series, valueMode, true);
    else renderLine(chartBox, series, valueMode);
    if (chartType !== "bar") container.appendChild(renderLegend(series));
    container.appendChild(renderTable(series, valueMode));
  }

  // ---- Controller — wires the selects/checkbox to the metric catalog and (re)renders on change ----

  function populateMetricSelect(selectEl, sourceKey) {
    var group = METRIC_GROUPS[sourceKey];
    selectEl.innerHTML = "";
    Object.keys(group.metrics).forEach(function (metricKey) {
      var opt = document.createElement("option");
      opt.value = metricKey;
      opt.textContent = group.metrics[metricKey].label;
      selectEl.appendChild(opt);
    });
  }

  function initBuilder(root) {
    var sessionId = root.getAttribute("data-session-id");
    var sourceSelect = root.querySelector("[data-db-source]");
    var metricSelect = root.querySelector("[data-db-metric]");
    var chartTypeSelect = root.querySelector("[data-db-chart-type]");
    var valueModeSelect = root.querySelector("[data-db-value-mode]");
    var compareToggle = root.querySelector("[data-db-compare-toggle]");
    var compareRow = root.querySelector("[data-db-compare-row]");
    var compareSourceSelect = root.querySelector("[data-db-compare-source]");
    var compareMetricSelect = root.querySelector("[data-db-compare-metric]");
    var output = root.querySelector("[data-db-output]");
    if (!sourceSelect || !metricSelect || !output) return;

    Object.keys(METRIC_GROUPS).forEach(function (key) {
      var opt = document.createElement("option");
      opt.value = key;
      opt.textContent = METRIC_GROUPS[key].label;
      sourceSelect.appendChild(opt);
      compareSourceSelect.appendChild(opt.cloneNode(true));
    });
    // Default to Activity (tool calls by phase) rather than the first group (Findings) -- Findings
    // is empty for any session with 0 recorded findings (a real, common outcome on a heavily
    // WAF-gated or out-of-scope target, confirmed live), which made the whole widget look broken
    // on first load even though every dropdown and the chart logic itself worked correctly. Every
    // session has logs, so this default is populated regardless of how many findings came out of it.
    if (METRIC_GROUPS.activity) sourceSelect.value = "activity";
    populateMetricSelect(metricSelect, sourceSelect.value);
    populateMetricSelect(compareMetricSelect, compareSourceSelect.value);

    var sessionData = null;
    var fetchPromise = null;
    function ensureSessionData() {
      if (sessionData) return Promise.resolve(sessionData);
      if (!fetchPromise) {
        fetchPromise = fetch("/api/session/" + encodeURIComponent(sessionId))
          .then(function (r) { return r.json(); })
          .then(function (data) { sessionData = data; return data; })
          .catch(function () {
            output.innerHTML = "";
            var errorEl = document.createElement("p");
            errorEl.className = "text-[11px] text-severity-high";
            errorEl.textContent = "Could not load this session's data for the diagram builder.";
            output.appendChild(errorEl);
            return null;
          });
      }
      return fetchPromise;
    }

    function metricFor(sourceSel, metricSel) {
      var group = METRIC_GROUPS[sourceSel.value];
      return group && group.metrics[metricSel.value];
    }

    function update() {
      ensureSessionData().then(function (data) {
        if (!data) return;
        var metric = metricFor(sourceSelect, metricSelect);
        if (!metric) return;
        var chartType = chartTypeSelect.value;
        var valueMode = valueModeSelect.value;
        output.innerHTML = "";
        if (compareToggle.checked) {
          var compareMetric = metricFor(compareSourceSelect, compareMetricSelect);
          var grid = document.createElement("div");
          grid.className = "grid grid-cols-1 sm:grid-cols-2 gap-4";
          var boxA = document.createElement("div");
          var boxB = document.createElement("div");
          grid.appendChild(boxA);
          grid.appendChild(boxB);
          output.appendChild(grid);
          renderMetricInto(boxA, metric.compute(data), chartType, valueMode, metric.label);
          renderMetricInto(boxB, compareMetric ? compareMetric.compute(data) : null, chartType, valueMode, compareMetric ? compareMetric.label : "");
        } else {
          renderMetricInto(output, metric.compute(data), chartType, valueMode, null);
        }
      });
    }

    sourceSelect.addEventListener("change", function () { populateMetricSelect(metricSelect, sourceSelect.value); update(); });
    metricSelect.addEventListener("change", update);
    chartTypeSelect.addEventListener("change", update);
    valueModeSelect.addEventListener("change", update);
    compareToggle.addEventListener("change", function () {
      compareRow.classList.toggle("hidden", !compareToggle.checked);
      update();
    });
    compareSourceSelect.addEventListener("change", function () { populateMetricSelect(compareMetricSelect, compareSourceSelect.value); update(); });
    compareMetricSelect.addEventListener("change", update);

    update();
  }

  function initAllIn(scope) {
    (scope || document).querySelectorAll("[data-diagram-builder]:not([data-db-ready])").forEach(function (el) {
      el.setAttribute("data-db-ready", "true");
      initBuilder(el);
    });
  }

  document.addEventListener("DOMContentLoaded", function () { initAllIn(document); });
  // A session can transition from running to completed while its page is already open — the next
  // SSE morph swap then renders this block for the first time (server-gated on status ==
  // "completed"), well after DOMContentLoaded already fired. htmx:afterSwap fires for every such
  // swap (see session.html's own use of the same event on #session-stream) with event.target set
  // to the swapped element, so re-scanning just that subtree picks up the newly-added block.
  //
  // Listener attached to `document`, not `document.body` — this <script> tag (base.html) loads in
  // <head>, with no defer/async, so it executes as soon as it's fetched, WHILE <head> is still
  // being parsed — document.body does not exist yet at that exact moment (the parser hasn't
  // reached the <body> tag). `document.body.addEventListener(...)` here would throw a TypeError
  // synchronously ("Cannot read properties of null"), unconditionally, on every single page load,
  // for every user — real, confirmed-live incident: this line's own crash meant this listener was
  // NEVER actually registered, so the diagram builder never initialized for the single most common
  // real usage pattern (an operator watching a scan run, then it completing while the Summary tab
  // is already open) — permanently stuck on empty dropdowns and the server-rendered "Loading…"
  // placeholder, with no error visible anywhere in the UI itself (only in the browser console).
  // `document` is always available regardless of parse timing, and htmx's custom events bubble to
  // it exactly the same way they would to document.body, so this is a strict improvement with no
  // downside — same fix as the DOMContentLoaded listener just above already uses `document`, not
  // `document.body`.
  document.addEventListener("htmx:afterSwap", function (event) { initAllIn(event.target); });
})();
