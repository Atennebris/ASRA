// Summary tab severity filter (session_fragment.html's .summary-filter, radio + :has() driven --
// see themes.css's own comment on why this is CSS state, not JS, for the filtering itself). A
// native radio can't un-check itself by being clicked again, so clicking an already-active
// severity a second time did nothing on its own -- the operator had to reach for the separate
// "Clear filter" link every time. This adds just that one bit of missing interaction: clicking the
// currently-active severity a second time switches back to "All" (the same thing "Clear filter"
// already does), without touching the CSS-only filtering mechanism itself.
//
// Delegated on document (not bound to specific radio/label nodes) so it keeps working across any
// number of SSE morph re-renders of #session-content -- same reasoning as debug_events.js's own
// delegated listeners.
(function () {
  var GROUP_NAME = "summary-severity-filter";
  var toggleOffCandidateId = null;

  function radioForLabel(label) {
    var forId = label.getAttribute("for");
    if (!forId) return null;
    var radio = document.getElementById(forId);
    return radio && radio.type === "radio" && radio.name === GROUP_NAME ? radio : null;
  }

  // Recorded on mousedown, before the browser's own click-to-check default action runs, so this
  // reflects whether the radio was ALREADY checked going into this click -- by the time a plain
  // "click" listener sees it, checked is already true regardless (freshly checked or already was).
  document.addEventListener("mousedown", function (event) {
    var label = event.target.closest("label[for]");
    var radio = label && radioForLabel(label);
    toggleOffCandidateId = radio && radio.checked ? radio.id : null;
  });

  document.addEventListener("click", function (event) {
    var label = event.target.closest("label[for]");
    if (!label) return;
    var radio = radioForLabel(label);
    if (!radio || radio.id !== toggleOffCandidateId || radio.id === "sumfilter-all") return;
    // Confirmed live bug without this: clicking a <label for="x"> fires TWO click events -- the
    // one that reaches this listener, then a second, synthetic one the browser dispatches on the
    // associated input itself as that label's own default "activate the labeled control" action.
    // That second click's own native behavior re-checks the SAME radio (it always does, that's
    // what clicking a radio does) -- silently undoing the override below the instant after it
    // ran. preventDefault() here cancels the label's default action, so the synthetic click (and
    // its re-check) never happens at all.
    event.preventDefault();
    var allRadio = document.getElementById("sumfilter-all");
    if (allRadio) allRadio.checked = true;
  });
})();
