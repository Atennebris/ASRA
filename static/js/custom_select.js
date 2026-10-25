// Progressive-enhancement replacement for a native <select>'s own OS-rendered dropdown popup --
// built specifically because that native popup silently refuses to open at all inside an open
// <dialog> on some WebView2 runtime builds (the desktop app's embedded webview). Real, confirmed
// incident: Subagents' Provider/Model <select>s inside the Edit-subagent dialog (templates/
// subagents.html). Two separate CSS-only fix attempts for the same symptom -- removing
// `overflow-hidden` from the <dialog> itself, then from every remaining ancestor between it and
// the <select> -- both failed live, confirmed by the operator after a genuine hard-refresh ruled
// out a stale cached page. The native popup is a
// browser/OS-drawn surface outside this page's own rendering -- no CSS can make it open if that
// WebView2 build's own implementation just won't. The only fix that doesn't depend on the
// operator's WebView2 version at all is to stop asking the browser to render that popup in the
// first place: this file keeps the real <select> fully in charge of the actual value/name/form
// submission/htmx wiring, and drives it from a plain in-page button + panel instead.
//
// Opt-in via `data-custom-select` on the <select>, inside a `[data-custom-select-wrap]` ancestor
// (that wrapper owns layout/spacing in the template and gives the now-sr-only <select> a sane,
// non-<dialog>-top-layer containing block for its own position:absolute -- see the long comment at
// this feature's call site in subagents.html for why that specifically matters). Nothing else
// about the <select> changes: same id/name, same value, same real 'change' events (htmx's own
// hx-trigger="change" on the provider <select> keeps working untouched), same thing every other
// script on the page (static/js/free_models_filter.js, the per-row free-only toggle) already reads
// or mutates directly by id -- this file only changes how the <select> gets OPENED.
//
// Why a plain DOM-nested panel instead of the Popover API or a second nested <dialog>: a <dialog>
// shown via showModal() paints in the browser's top layer, above all regular content regardless of
// z-index -- a plain fixed-position element that's just a normal <body> descendant (not itself
// promoted to the top layer) would render BEHIND an open <dialog> no matter its z-index. The
// Popover API solves that the "real" way but is new enough that an old, pinned WebView2 runtime
// (exactly the kind of build already producing this bug) might not support it at all. The actual
// fix used here needs no new browser API: this panel is a plain DOM DESCENDANT of the <select>'s
// own <dialog> (never reparented to <body>), so it's already painted inside that dialog's own
// top-layer box for free. `position: fixed`, computed from the trigger button's own
// getBoundingClientRect() at open time, is what lets it escape the scrolling field area's own
// `overflow-y-auto` clipping and float above the rest of the dialog's content -- fixed positioning
// resolves its containing block against the viewport (not the nearest scrolling ancestor) as long
// as nothing in between sets `transform`/`filter`/`perspective`/`contain` (confirmed none of this
// dialog's ancestors do, live, via getComputedStyle, while diagnosing this exact bug).
(function () {
  function checkIcon() {
    var span = document.createElement("span");
    span.innerHTML = '<svg class="w-3.5 h-3.5 shrink-0" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M3 8l3.5 3.5L13 5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    return span.firstElementChild;
  }

  function chevronIcon() {
    var span = document.createElement("span");
    span.className = "shrink-0 text-secondary";
    span.innerHTML = '<svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 9l6 6 6-6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    return span;
  }

  function enhance(select) {
    if (select.dataset.customSelectEnhanced) return;
    var wrap = select.closest("[data-custom-select-wrap]");
    if (!wrap) return; // template didn't provide the expected wrapper -- stay native rather than guess at DOM surgery
    select.dataset.customSelectEnhanced = "1";

    // Captured BEFORE adding sr-only, so the trigger button ends up styled identically to how the
    // <select> used to look (same bg/border/padding/text size, font-mono for the model picker) --
    // one source of truth for the visual style, never duplicated as a second hardcoded class string.
    var baseClassName = select.className;
    var isMono = baseClassName.indexOf("font-mono") !== -1;
    select.classList.add("sr-only");
    select.setAttribute("tabindex", "-1");
    select.setAttribute("aria-hidden", "true");

    var trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = baseClassName + " flex items-center justify-between gap-2 text-left cursor-pointer";
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");

    var labelSpan = document.createElement("span");
    labelSpan.className = "truncate";
    trigger.appendChild(labelSpan);
    trigger.appendChild(chevronIcon());

    var panel = document.createElement("div");
    panel.className = "fixed z-[70] hidden bg-elevated border border-default rounded-lg shadow-2xl p-1 overflow-y-auto asra-scroll";
    panel.setAttribute("role", "listbox");

    wrap.appendChild(trigger);
    wrap.appendChild(panel);

    function refreshLabel() {
      var opt = select.options[select.selectedIndex];
      labelSpan.textContent = opt ? opt.textContent : "";
    }
    refreshLabel();

    function onOutsideMouseDown(event) {
      if (!wrap.contains(event.target)) closePanel();
    }
    function onScroll(event) {
      // Any ancestor scrolling (most commonly the dialog's own scrolling field area) invalidates
      // the fixed-position coordinates computed at open time. Closing is simpler and safer than
      // re-tracking position on every scroll tick for a panel that's only ever open briefly.
      if (event.target === panel || panel.contains(event.target)) return;
      closePanel();
    }
    function closePanel() {
      panel.classList.add("hidden");
      trigger.setAttribute("aria-expanded", "false");
      document.removeEventListener("mousedown", onOutsideMouseDown, true);
      window.removeEventListener("resize", closePanel);
      document.removeEventListener("scroll", onScroll, true);
    }
    function positionPanel() {
      var rect = trigger.getBoundingClientRect();
      var margin = 6, maxDesired = 280;
      var spaceBelow = window.innerHeight - rect.bottom - margin;
      var spaceAbove = rect.top - margin;
      // Flip upward when there's genuinely more room above than below -- this picker commonly
      // sits near the bottom of a scrolled dialog, where "always open downward" would get clipped
      // against the viewport edge instead of the (removed) overflow-hidden ancestor.
      var openUp = spaceBelow < 160 && spaceAbove > spaceBelow;
      var maxHeight = Math.max(100, Math.min(maxDesired, openUp ? spaceAbove : spaceBelow));
      panel.style.left = rect.left + "px";
      panel.style.width = rect.width + "px";
      panel.style.maxHeight = maxHeight + "px";
      if (openUp) {
        panel.style.top = "auto";
        panel.style.bottom = (window.innerHeight - rect.top + margin) + "px";
      } else {
        panel.style.bottom = "auto";
        panel.style.top = (rect.bottom + margin) + "px";
      }
    }
    function pick(value) {
      select.value = value;
      select.dispatchEvent(new Event("change", { bubbles: true }));
      refreshLabel();
      closePanel();
      trigger.focus();
    }
    function appendOption(opt) {
      // Mirrors free_models_filter.js's own hide mechanism (option.hidden) -- a hidden option
      // (filtered out by a "Free models only" switch) never appears in this panel either.
      if (opt.hidden) return false;
      var selected = opt.value === select.value;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.setAttribute("role", "option");
      btn.setAttribute("aria-selected", String(selected));
      btn.className = "flex items-center justify-between gap-2 w-full text-left rounded-md px-2 py-1.5 text-[12px] transition-colors "
        + (isMono ? "font-mono " : "")
        + (opt.disabled ? "opacity-40 cursor-not-allowed " : "hover:bg-overlay focus:outline-none focus:bg-overlay cursor-pointer ")
        + (selected ? "text-accent font-medium" : "text-primary");
      var text = document.createElement("span");
      text.className = "truncate";
      text.textContent = opt.textContent;
      btn.appendChild(text);
      if (selected) btn.appendChild(checkIcon());
      if (opt.disabled) {
        btn.disabled = true;
      } else {
        btn.addEventListener("click", function () { pick(opt.value); });
      }
      panel.appendChild(btn);
      return true;
    }
    function buildOptions() {
      panel.innerHTML = "";
      var any = false;
      var nodes = select.children;
      for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        if (node.tagName === "OPTGROUP") {
          var groupLabel = document.createElement("div");
          groupLabel.className = "px-2 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-secondary";
          groupLabel.textContent = node.label;
          panel.appendChild(groupLabel);
          for (var j = 0; j < node.children.length; j++) {
            if (appendOption(node.children[j])) any = true;
          }
        } else if (node.tagName === "OPTION") {
          if (appendOption(node)) any = true;
        }
      }
      if (!any) {
        var empty = document.createElement("div");
        empty.className = "px-2 py-1.5 text-[12px] text-secondary";
        empty.textContent = "No options available";
        panel.appendChild(empty);
      }
    }
    function openPanel() {
      buildOptions();
      positionPanel();
      panel.classList.remove("hidden");
      trigger.setAttribute("aria-expanded", "true");
      document.addEventListener("mousedown", onOutsideMouseDown, true);
      window.addEventListener("resize", closePanel);
      document.addEventListener("scroll", onScroll, true);
    }

    // Real, confirmed operator gap this closes: the model picker's own <option> list only becomes
    // correct once the provider picker's own hx-get (triggered by the 'change' event `pick()`
    // dispatches above) actually RESOLVES -- a real network/WSL round trip, not instant like a
    // local Chrome test. Clicking the model trigger WHILE that request is still in flight opened a
    // panel built from whatever options were still sitting in the DOM a moment ago (the previous
    // provider's), which reads as "doesn't react"/"models don't update" even though nothing is
    // actually broken -- it just hadn't arrived yet. Disabling the trigger (and closing any open
    // panel) for the span of that one request, driven by htmx's own beforeRequest/afterSettle
    // lifecycle below, makes that window visible instead of silently serving stale content.
    function setLoading(loading) {
      trigger.disabled = loading;
      trigger.classList.toggle("opacity-50", loading);
      trigger.classList.toggle("cursor-wait", loading);
      if (loading) closePanel();
    }

    trigger.addEventListener("click", function () {
      if (panel.classList.contains("hidden")) openPanel(); else closePanel();
    });
    trigger.addEventListener("keydown", function (event) {
      if (event.key === "Escape") closePanel();
    });
    panel.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { closePanel(); trigger.focus(); }
    });

    // Re-read by refreshAllLabels()/setAllLoading() below, keyed off this <select>'s own element
    // (stable across an htmx swap that only replaces its <option> children, never the element
    // itself) rather than its id -- one shared lookup mechanism for both.
    select._asraCustomSelectRefreshLabel = refreshLabel;
    select._asraCustomSelectSetLoading = setLoading;
  }

  function enhanceAll() {
    var selects = document.querySelectorAll("select[data-custom-select]");
    for (var i = 0; i < selects.length; i++) enhance(selects[i]);
  }
  function refreshAllLabels() {
    var selects = document.querySelectorAll("select[data-custom-select]");
    for (var i = 0; i < selects.length; i++) {
      if (selects[i]._asraCustomSelectRefreshLabel) selects[i]._asraCustomSelectRefreshLabel();
    }
  }

  document.addEventListener("DOMContentLoaded", enhanceAll);
  if (document.readyState !== "loading") enhanceAll();
  // beforeRequest -- event.detail.target is the real element about to be swapped into (htmx's own
  // requestConfig.target), the same element hx-target="#subagent-model-..." resolves to. Marking
  // it loading here, the instant the request is dispatched, is what actually closes the race
  // described above -- afterSettle alone (firing only once the response has already landed) is too
  // late to stop a click that happened WHILE the request was still in flight.
  document.addEventListener("htmx:beforeRequest", function (event) {
    var target = event.detail && event.detail.target;
    if (target && target._asraCustomSelectSetLoading) target._asraCustomSelectSetLoading(true);
  });
  // afterSettle (not afterSwap) -- runs after free_models_filter.js's own afterSwap-driven
  // hide/show pass on the fresh <option> list has already applied, so a label/panel rebuild here
  // never races that filter's own option.hidden/disabled writes.
  document.addEventListener("htmx:afterSettle", function () {
    enhanceAll();
    refreshAllLabels();
    var selects = document.querySelectorAll("select[data-custom-select]");
    for (var i = 0; i < selects.length; i++) {
      if (selects[i]._asraCustomSelectSetLoading) selects[i]._asraCustomSelectSetLoading(false);
    }
  });
})();
