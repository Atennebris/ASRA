// Persisted privacy/redaction toggle for lists that show client-identifying data (project/target
// names, links) -- macros/ui.html's privacy_toggle_button/privacy_placeholder/privacy_restore_script
// are the three pieces that always travel together; see that file's own comment for the full
// design, including why the collapsed flag always lives on an ancestor element, never on the
// sensitive rows/placeholder themselves (those get replaced wholesale by a live htmx poll on the
// Projects list and home page's Recent projects, which would otherwise silently undo the choice).
(function () {
  function readState() {
    try {
      return JSON.parse(localStorage.getItem("asra-privacy-collapsed") || "{}");
    } catch (e) {
      return {};
    }
  }

  function writeState(state) {
    try {
      localStorage.setItem("asra-privacy-collapsed", JSON.stringify(state));
    } catch (e) {
      // Private-browsing/storage-denied -- the toggle still works live for this page view, it
      // just won't survive a reload. Never let that break the click itself.
    }
  }

  window.asraTogglePrivacy = function (key) {
    var wrap = document.querySelector('[data-privacy-key="' + key + '"]');
    if (!wrap) return;
    var collapsed = wrap.getAttribute("data-privacy-collapsed") !== "true";
    wrap.setAttribute("data-privacy-collapsed", String(collapsed));

    var btn = document.querySelector('[data-privacy-toggle="' + key + '"]');
    if (btn) {
      btn.setAttribute("aria-pressed", String(collapsed));
      var label = btn.querySelector("[data-privacy-label]");
      if (label) label.textContent = collapsed ? "Show" : "Hide";
    }

    var state = readState();
    if (collapsed) state[key] = true;
    else delete state[key];
    writeState(state);
  };
})();
