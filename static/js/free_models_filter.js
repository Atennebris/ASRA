// Settings -> "Free models only" -- TWO independent mechanisms sharing the same core filter logic:
//
// 1. The single global switch (templates/settings.html, #free-models-only-toggle) next to the main
//    AI Provider & Model picker -- persisted (POST /api/settings/free-models-only), applies to
//    #model-select plus a few other single-instance pickers that have no row of their own to carry
//    an independent switch (secondary verification, chat panel, library). Driven by
//    window.ASRA_FREE_MODELS_ONLY, via window.asraApplyFreeModelsOnly(enabled).
//
// 2. Per-row switches -- Reserve providers chain rows and subagent profile rows each get their OWN
//    independent toggle (settings.html / subagents.html), scoped to just that row's own model
//    <select>, with no shared global state at all. Real, confirmed operator complaint this exists
//    for: a single global switch can't express "free-only for THIS reserve step but not that one" --
//    every row needs its own. Both mechanisms call the same window.asraApplyFreeFilterToSelect and
//    window.asraFreeFilterReasonFor primitives below, so the actual hide/show and disable logic
//    never drifts between the two.
//
// In every case: each <option>'s own data-free="true"/"false" attribute (set server-side,
// templates/partials/model_options.html and templates/macros/ui.html's model_options() macro, from
// main.py's _model_free_flags) is the one source of truth; an <option> with NO data-free attribute
// at all (price unknown for that provider/model) is never hidden -- this filter only ever hides
// what it's actually confident is paid, never guesses.
(function () {
  // The core hide/show pass for ONE select, given an explicit enabled flag -- never reads any
  // global state itself, so it's equally correct for the one global-flag-driven picker and for
  // every independently-toggled row.
  window.asraApplyFreeFilterToSelect = function (select, enabled) {
    var hide = !!enabled;
    var options = select.options;
    if (hide) {
      // Never hide EVERY option -- an empty, unselectable dropdown is worse than an unfiltered
      // one. Confirmed real risk, not hypothetical: a provider with no real free tier (Mistral,
      // most of the time) must not have its own list silently wrecked just because some free-only
      // switch -- global or this row's own -- happens to be on.
      var anyWouldStayVisible = false;
      for (var j = 0; j < options.length; j++) {
        if (options[j].getAttribute("data-free") !== "false") { anyWouldStayVisible = true; break; }
      }
      hide = anyWouldStayVisible;
    }
    for (var i = 0; i < options.length; i++) {
      var opt = options[i];
      var isPaid = opt.getAttribute("data-free") === "false";
      opt.hidden = hide && isPaid;
      opt.disabled = hide && isPaid;
    }
  };

  // Providers whose switch is forced disabled everywhere, regardless of what the per-model data
  // says -- mirrors main.py's own _FORCE_DISABLED_FREE_FILTER_PROVIDERS exactly (same constant,
  // same reasoning, see that dict's own docstring for why Mistral specifically is an explicit
  // operator override rather than something the data-driven rule below already catches).
  var FORCE_DISABLED_FREE_FILTER_PROVIDERS = {
    mistral: "Mistral has no free tier here -- explicitly always disabled",
  };

  // Why a free-only switch for THIS select should be disabled, or null when it's fine to leave
  // enabled -- mirrors main.py's own _free_filter_reason exactly (see that function's own
  // docstring): an explicit per-provider override first, then the one data-driven outcome that's
  // actually harmful -- turning the switch on would hide EVERY option -- never merely because it
  // would be a no-op. providerId is optional -- omitted entirely, the override simply never fires
  // and only the data-driven rule applies (every caller that has a provider id handy should still
  // pass it, see every call site below).
  window.asraFreeFilterReasonFor = function (select, providerId) {
    if (providerId && Object.prototype.hasOwnProperty.call(FORCE_DISABLED_FREE_FILTER_PROVIDERS, providerId)) {
      return FORCE_DISABLED_FREE_FILTER_PROVIDERS[providerId];
    }
    var total = select.options.length, paid = 0;
    for (var i = 0; i < total; i++) {
      if (select.options[i].getAttribute("data-free") === "false") paid++;
    }
    if (total > 0 && paid === total) return "none of these models is free here";
    return null;
  };

  // Real, confirmed bug this fixes: this used to apply window.ASRA_FREE_MODELS_ONLY to every
  // select unconditionally, never consulting asraFreeFilterReasonFor/the force-disabled-provider
  // override above -- so switching the provider dropdown straight to Mistral (global flag still
  // on from a previous provider) left Mistral's own paid options hidden/disabled, even though the
  // switch itself correctly showed as greyed out. The override existed in main.py/this file the
  // whole time but was only ever wired into the DISPLAY toggle (templates/settings.html's own
  // refresh()), never into the actual hide/show pass -- exactly the gap the per-row toggles
  // (Reserve chain rows, subagent rows: settings.html/subagents.html/chat_panel.html/playbook.html)
  // never had, since each of those already computes `reason` before calling
  // asraApplyFreeFilterToSelect. Each select that wants its paired provider consulted carries
  // data-asra-provider-select="<id of that provider <select>>" (settings.html's #model-select is
  // the one that does today); one with no such attribute just gets providerId=null, which makes
  // asraFreeFilterReasonFor fall back to its own data-driven rule only -- never a silent crash.
  function applyToPage() {
    var selects = document.querySelectorAll("select[data-asra-model-select]");
    for (var i = 0; i < selects.length; i++) {
      var select = selects[i];
      var providerSelectId = select.getAttribute("data-asra-provider-select");
      var providerSelect = providerSelectId ? document.getElementById(providerSelectId) : null;
      var reason = window.asraFreeFilterReasonFor(select, providerSelect ? providerSelect.value : null);
      window.asraApplyFreeFilterToSelect(select, !reason && window.ASRA_FREE_MODELS_ONLY);
    }
  }

  // Re-applied on every htmx swap -- a provider change re-fetches a fresh <option> list
  // (model_options.html) with no idea this filter exists, so it has to be reapplied each time,
  // not just once at page load. Listens on `document`, NOT `document.body` -- real, confirmed
  // bug this fixes: this file is loaded from base.html's own <head> with a plain, non-deferred
  // <script src>, which runs the instant the parser reaches it -- BEFORE <body> exists at all, so
  // `document.body` was still null and `.addEventListener` on it threw a TypeError that aborted
  // this entire IIFE right there, silently skipping everything below it -- including
  // window.asraApplyFreeModelsOnly's own definition. The toggle's checkbox still visually flipped
  // (plain native <input> behavior, nothing to do with this script), its onchange handler calling
  // the now-undefined function threw a second error, and the actual filter never ran once, on any
  // page, for anyone -- confirmed live via the real browser console. `document` itself always
  // exists this early, even in <head>, and event bubbling to it works identically to body.
  document.addEventListener("htmx:afterSwap", applyToPage);
  document.addEventListener("DOMContentLoaded", applyToPage);
  if (document.readyState !== "loading") applyToPage();

  // The single global switch -- #model-select and whichever other single-instance pickers still
  // carry data-asra-model-select (secondary verification, chat panel, library). Reserve chain rows
  // and subagent rows do NOT carry that attribute (removed from their markup on purpose) -- they
  // have their own independent per-row toggle instead, wired directly to
  // window.asraApplyFreeFilterToSelect, never to this global flag.
  window.asraApplyFreeModelsOnly = function (enabled) {
    window.ASRA_FREE_MODELS_ONLY = enabled;
    applyToPage();
  };
})();
