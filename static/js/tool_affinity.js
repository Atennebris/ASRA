// Instant client-side feedback for the "Learned tool recommendations" panel's trusted/irrelevant
// buttons (templates/partials/tool_affinity_list.html) -- flips the clicked button's own active
// state the same frame the operator clicks, so a round trip to the server never makes the click
// look like it did nothing ("Live visual feedback" / "Tab/nav switching must be visually instant"
// discipline). The real htmx post (main.py's tool_affinity_feedback route) still re-renders the
// whole panel afterward and is the authority once it lands -- same optimistic pattern
// static/js/playbook_skill.js's own trust-badge flip already uses. Feedback is advisory metadata
// only and never gates tool execution, so flipping the button ahead of the round trip can't
// misrepresent what the agent will actually do. No-op (never throws into the UI) if anything's
// missing -- the htmx post still runs regardless.
(function () {
  var ACTIVE_CLASSES = {
    trusted: ["text-severity-low", "border-severity-low/40", "bg-severity-low/10"],
    irrelevant: ["text-severity-high", "border-severity-high/40", "bg-severity-high/10"],
  };
  var INACTIVE_CLASSES = ["text-secondary", "border-default", "bg-transparent"];

  function setActive(btn, kind, active) {
    var add = active ? ACTIVE_CLASSES[kind] : INACTIVE_CLASSES;
    var remove = active ? INACTIVE_CLASSES : ACTIVE_CLASSES[kind];
    remove.forEach(function (c) { btn.classList.remove(c); });
    add.forEach(function (c) { btn.classList.add(c); });
    btn.setAttribute("data-active", active ? "true" : "false");
  }

  window.asraFlipToolAffinityFeedback = function (btn, kind) {
    try {
      var card = btn.closest("[data-affinity-card]");
      if (!card) return;
      var nowActive = btn.getAttribute("data-active") !== "true";
      // Marking one kind trusted/irrelevant always clears the OTHER kind on the same record (a
      // record is either trusted, irrelevant, or neither -- never both) -- mirrors the server's
      // own set_operator_feedback, which stores a single operator_feedback field, not two.
      card.querySelectorAll("[data-affinity-feedback-btn]").forEach(function (other) {
        var otherKind = other.getAttribute("data-feedback-value");
        setActive(other, otherKind, other === btn ? nowActive : false);
      });
    } catch (e) {
      // A failed optimistic flip must never block the real htmx toggle underneath it.
    }
  };
})();
