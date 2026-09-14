// Sidebar footer's live clock (base.html) -- shows the current time in Settings -> Timezone's
// saved display zone (agent/timezone_settings.py), the same zone main.py's own human_dt Jinja
// filter renders every stored UTC timestamp into. Real operator complaint this fixes: every
// finding/hypothesis/approval timestamp used to read hours off from the operator's own wall clock
// with no way to change it, and nothing on screen showed which zone was even being assumed.
//
// Same "single global setInterval that re-queries the live DOM every tick, no per-node
// bookkeeping" pattern as live_duration.js -- a clock has no state to lose across an idiomorph
// swap, the next tick just formats whatever's actually on screen right now. Intl.DateTimeFormat
// takes a real IANA zone name directly (data-tz, server-rendered) -- no separate timezone-data
// library needed, every evergreen browser's own built-in tz database already has it.
//
// data-style (Settings -> Timezone's clock-style picker, themes.css's .clock-style-* rules) picks
// between 3 display styles -- "minimal" (the original HH:MM, no seconds) and "digital"/"terminal"
// (both add live seconds, since a still, minute-granularity readout would look broken sitting
// inside a styled "digital display" chrome that implies something is actively ticking).
//
// #asra-clock-date (Settings -> Timezone's "Show date" toggle) renders underneath, in the same
// data-tz zone as the time itself -- so a date rollover at local midnight in that zone is reflected
// immediately, not the browser's own local midnight, which could be hours off from it.
(function () {
  function tick() {
    var el = document.getElementById("asra-clock");
    var dateEl = document.getElementById("asra-clock-date");
    if (!el) return;
    var tz = el.getAttribute("data-tz");
    if (!tz) return;
    var showSeconds = el.getAttribute("data-style") !== "minimal";
    try {
      el.textContent = new Intl.DateTimeFormat(undefined, {
        hour: "2-digit", minute: "2-digit",
        second: showSeconds ? "2-digit" : undefined,
        hour12: false, timeZone: tz,
      }).format(new Date());
    } catch (err) {
      // An unrecognized zone name (a stale save from before an IANA database update dropped it,
      // say) must never break the whole sidebar footer -- leave whatever was last shown in place.
    }
    if (dateEl && !dateEl.hidden) {
      try {
        dateEl.textContent = new Intl.DateTimeFormat(undefined, {
          dateStyle: "medium", timeZone: tz,
        }).format(new Date());
      } catch (err) {
        // Same graceful-degrade as the time above -- an unrecognized zone must never break the row.
      }
    }
  }

  tick();
  setInterval(tick, 1000);
})();
