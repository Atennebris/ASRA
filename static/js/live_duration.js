// Live-ticking durations (session time, Plan tab's phase/task/subtask durations) -- the server
// only ever computes these at render time (agent/core.py's format_duration_between family), so
// without this they only visibly change on the next real SSE update (a new log line, a status
// change), not with the actual passage of time -- a still-running phase could show "49s" for
// minutes at a stretch between two unrelated tool calls. Real operator complaint this fixes:
// "the numbers should be dynamic, changing in real time."
//
// Deliberately NOT wired the same way diagram_builder.js's own init is (DOMContentLoaded +
// htmx:afterSwap re-init, tracked via a data-*-ready guard attribute) -- that whole mechanism
// exists to survive a subtree getting freshly re-rendered by SSE without double-initializing, but
// a live-ticking clock has no state to lose or double-register: a single global setInterval that
// just re-queries the live DOM on every tick, unconditionally, needs no per-node bookkeeping at
// all and is immune to whatever idiomorph does to any given node between ticks (add, remove,
// morph in place -- the next tick just sees whatever's actually there right now).
(function () {
  // Mirrors agent/core.py's format_duration_between exactly (kept in sync deliberately, same
  // "two implementations of one calculation, one server-side one client-side" pattern already
  // used for diagram_builder.js's own chart math) -- the server's own rendered text is what shows
  // until the first tick, then this takes over for the seconds in between real page updates.
  function formatDuration(totalSeconds) {
    totalSeconds = Math.max(0, Math.floor(totalSeconds));
    var days = Math.floor(totalSeconds / 86400); totalSeconds -= days * 86400;
    var hours = Math.floor(totalSeconds / 3600); totalSeconds -= hours * 3600;
    var minutes = Math.floor(totalSeconds / 60); var seconds = totalSeconds - minutes * 60;
    if (days) return days + "d " + hours + "h " + minutes + "m";
    if (hours) return hours + "h " + minutes + "m";
    if (minutes) return minutes + "m " + seconds + "s";
    return seconds + "s";
  }

  function tick() {
    document.querySelectorAll("[data-live-duration]").forEach(function (el) {
      var startedAt = el.getAttribute("data-started-at");
      if (!startedAt) return;
      var startMs = Date.parse(startedAt);
      if (isNaN(startMs)) return;
      el.textContent = formatDuration((Date.now() - startMs) / 1000);
    });
    // Overview tab's time-budget countdown (session_fragment.html) -- deadline-epoch is the same
    // agent/core.py's own enforcement check reads (main.py's time_budget_deadline_epoch filter),
    // so this never shows a different number than what's actually being enforced. Counts DOWN to
    // 0 and stops there (never negative) -- the real stop happens server-side at the next LLM
    // turn (_time_budget_expired), this is purely a display, not a client-side timer that fires
    // anything on its own.
    document.querySelectorAll("[data-live-countdown]").forEach(function (el) {
      var deadlineEpoch = parseFloat(el.getAttribute("data-deadline-epoch"));
      if (isNaN(deadlineEpoch)) return;
      var remainingSeconds = deadlineEpoch - (Date.now() / 1000);
      el.textContent = remainingSeconds > 0 ? formatDuration(remainingSeconds) + " remaining" : "expired — wrapping up the current step";
    });
  }

  tick();
  setInterval(tick, 1000);
})();
