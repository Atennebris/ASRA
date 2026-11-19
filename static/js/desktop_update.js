// "Install & restart" for a staged desktop-app update -- hands an already SHA256-verified binary
// path (agent/desktop_update.py's stage_desktop_update, translated to a real Windows-shaped path by
// projects.paths.resolve_path_for_windows_shell when needed) to the Rust shell's own
// apply_desktop_update command (desktop/src-tauri/src/main.rs), which does the actual rename-swap +
// relaunch. Used by BOTH places that can stage an update: Settings -> Updates' own "Update now"
// (one restart finishes code + launcher) and the Desktop app card. This is NOT an htmx request
// (there is nothing left to fetch, and a plain hx-post can't call a Tauri command) -- a delegated
// click listener instead, same pattern as external_links.js's own target="_blank" catcher, so it
// keeps working after htmx swaps a panel's innerHTML in.
(function () {
  function applyStagedUpdate(btn) {
    var t = window.__TAURI__;
    // This button is only ever rendered inside the desktop shell (the templates gate it the same
    // way), but guard here too -- defense in depth, never a silent no-op that looks like the click
    // did nothing.
    if (!(t && t.core && t.core.invoke)) return;
    // Same underlying native confirm() every hx-confirm button elsewhere in this app already
    // uses -- this one can't use hx-confirm itself since it isn't an htmx-triggered request.
    if (!window.confirm("Install the new desktop app version and restart ASRA now?")) return;

    var path = btn.getAttribute("data-staged-path");
    // Looked up inside the button's own block, not by one global id: the Updates panel and the
    // Desktop app card can both be on screen, each with its own message slot.
    var block = btn.closest("[data-desktop-update-block]");
    var errorEl = block && block.querySelector("[data-desktop-update-error]");
    if (!path) {
      if (errorEl) errorEl.textContent = "No staged update path -- start the update again.";
      return;
    }

    btn.disabled = true;
    btn.textContent = "Restarting...";
    if (errorEl) errorEl.textContent = "";
    t.core.invoke("apply_desktop_update", { stagedPath: path }).catch(function (err) {
      console.error("apply_desktop_update failed", err);
      if (window.asraDebugEvent) window.asraDebugEvent("apply_desktop_update_failed", String(err));
      btn.disabled = false;
      btn.textContent = "Install & restart";
      if (errorEl) errorEl.textContent = "Could not apply the update: " + err;
    });
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-desktop-update-apply]");
    if (btn) applyStagedUpdate(btn);
  });

  // A button marked data-auto-apply arrives in a response that already finished the slow part
  // (download + checksum), so ask for the restart right away -- one click + one confirm instead of
  // a second button the operator has to notice. The button stays as the retry path if they cancel.
  // Deferred a tick so the new panel is painted before the blocking confirm opens.
  document.addEventListener("htmx:afterSwap", function (e) {
    var btn = e.target.querySelector && e.target.querySelector("[data-desktop-update-apply][data-auto-apply]");
    if (!btn) return;
    btn.removeAttribute("data-auto-apply");
    if (window.asraDebugEvent) window.asraDebugEvent("desktop_update_auto_prompt", btn.getAttribute("data-staged-path") || "");
    setTimeout(function () { applyStagedUpdate(btn); }, 100);
  });
})();
