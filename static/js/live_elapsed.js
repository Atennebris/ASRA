/* Live "running 3m 12s" ticker for a tool row that has not finished yet (macros/ui.html's
   tool_timing renders <span data-asra-elapsed-since="ISO-start">). One page-wide 1s interval
   rewrites every such span from the wall clock, so the timer keeps counting between server pushes
   and survives idiomorph re-rendering the row (the server only ever emits the "running" placeholder;
   the next tick restores the number). Same format as main.py's _human_duration, so a row reads the
   same while it ticks and after it finishes. */
(function () {
  "use strict";

  function formatElapsed(totalSeconds) {
    if (totalSeconds < 60) return totalSeconds + "s";
    if (totalSeconds < 3600) {
      var seconds = totalSeconds % 60;
      return Math.floor(totalSeconds / 60) + "m " + (seconds < 10 ? "0" : "") + seconds + "s";
    }
    var minutes = Math.floor((totalSeconds % 3600) / 60);
    return Math.floor(totalSeconds / 3600) + "h " + (minutes < 10 ? "0" : "") + minutes + "m";
  }

  function tick() {
    var nodes = document.querySelectorAll("[data-asra-elapsed-since]");
    var now = Date.now();
    for (var i = 0; i < nodes.length; i++) {
      var started = Date.parse(nodes[i].getAttribute("data-asra-elapsed-since"));
      if (isNaN(started)) continue;
      var text = "running " + formatElapsed(Math.max(0, Math.floor((now - started) / 1000)));
      if (nodes[i].textContent !== text) nodes[i].textContent = text;
    }
  }

  setInterval(tick, 1000);
  tick();
})();
