// Settings -> Updates' desktop-shell card "Install & restart" button -- hands a staged, already
// SHA256-verified binary path (agent/desktop_update.py's stage_desktop_update, translated to a
// real Windows-shaped path by projects.paths.resolve_path_for_windows_shell when needed) to the
// Rust shell's own apply_desktop_update command (desktop/src-tauri/src/main.rs), which does the
// actual rename-swap + relaunch. This is NOT an htmx request (there is nothing left to fetch, and
// a plain hx-post can't call a Tauri command) -- a delegated click listener instead, same pattern
// as external_links.js's own target="_blank" catcher, so it keeps working after htmx swaps the
// panel's innerHTML in.
(function () {
  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-desktop-update-apply]");
    if (!btn) return;
    var t = window.__TAURI__;
    // This button is only ever rendered inside the desktop shell (templates/partials/
    // desktop_update_status.html gates it the same way), but guard here too -- defense in depth,
    // never a silent no-op that looks like the click did nothing.
    if (!(t && t.core && t.core.invoke)) return;
    // Same underlying native confirm() every hx-confirm button elsewhere in this app already
    // uses (e.g. agent/updater.py's own "Update now") -- this one can't use hx-confirm itself
    // since it isn't an htmx-triggered request.
    if (!window.confirm("Install the new desktop app version and restart ASRA now?")) return;

    var path = btn.getAttribute("data-staged-path");
    var errorEl = document.getElementById("desktop-update-apply-error");
    if (!path) {
      if (errorEl) errorEl.textContent = "No staged update path -- click “Download & verify” again.";
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
  });
})();
