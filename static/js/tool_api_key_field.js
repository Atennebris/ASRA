// Settings -> Tool API Keys: makes a saved tool key field LOOK saved. The server never re-renders
// the real secret (main.py's _tool_api_keys_context exposes only a bool), so without this a
// configured field falls back to a dim placeholder that reads as empty -- the operator sees a
// blank box with a blinking caret and can't tell a key is actually stored. This upgrades every
// configured field to a solid masked value (real input text, not placeholder), so it always looks
// filled, exactly like a browser's own saved-password field.
//
// Progressive enhancement, attribute-driven so it covers every current AND future tool row in
// settings.html's loop with no per-tool code:
//   * data-tool-key-field       -- any tool API-key input
//   * data-tool-key-configured  -- one that already has a key saved server-side
// If this script never loads, the template's own placeholder still shows -- nothing breaks.
//
// The mask is a fixed constant here (never the real key), so it is the single source of truth --
// the template renders no value at all. Editing: focusing a masked field clears it to accept a new
// key; blurring it empty restores the mask (so it never reverts to looking empty); submitting a
// still-masked field blanks it, so the backend's "empty means didn't retype it" no-op rule
// (main.py's save_tool_api_key_route) fires instead of trying to save the mask itself.
(function () {
  var MASK = "••••••••••••";

  function isKeyField(el) {
    return el instanceof HTMLInputElement && el.hasAttribute("data-tool-key-field");
  }

  function applyMask(el) {
    el.value = MASK;
    el.readOnly = true;
    el.dataset.toolKeyMasked = "true";
  }

  function fillConfigured() {
    document.querySelectorAll("input[data-tool-key-field][data-tool-key-configured]").forEach(applyMask);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", fillConfigured);
  } else {
    fillConfigured();
  }
  // Settings tab bodies can be swapped in by htmx after initial load -- re-mask any that arrive.
  document.body && document.body.addEventListener("htmx:afterSwap", fillConfigured);

  document.addEventListener("focusin", function (event) {
    var el = event.target;
    if (!isKeyField(el) || el.dataset.toolKeyMasked !== "true") return;
    el.value = "";
    el.readOnly = false;
    el.dataset.toolKeyMasked = "false";
    if (window.asraDebugEvent) {
      window.asraDebugEvent("tool-api-key-field", "edit mode: " + (el.name || "?"));
    }
  });

  document.addEventListener("focusout", function (event) {
    var el = event.target;
    if (!isKeyField(el) || el.dataset.toolKeyMasked === "true") return;
    if (el.hasAttribute("data-tool-key-configured") && el.value === "") {
      applyMask(el);
      if (window.asraDebugEvent) {
        window.asraDebugEvent("tool-api-key-field", "restored mask (unchanged): " + (el.name || "?"));
      }
    }
  });

  // Never let the mask itself get submitted as if it were a real key.
  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    form.querySelectorAll("input[data-tool-key-field]").forEach(function (el) {
      if (el.dataset.toolKeyMasked === "true") el.value = "";
    });
  }, true);
})();
