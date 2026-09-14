// Desktop shell (Tauri webview): a plain <a target="_blank"> click or a window.open() call does
// nothing at all -- main.rs's own window.navigate() only ever retargets THIS window, and Tauri's
// webview has no default "open this in a real OS browser window" handling wired up on its own.
// Real, confirmed operator complaint, seen in several unrelated places: a Library source's own
// "source" link, Settings' Codex/Copilot OAuth "Connect" flow, "Get a key" provider links.
// window.asraOpenExternal is the one shared fix -- routes through the new open_external_url Tauri
// command (desktop/src-tauri/src/main.rs) when running inside the desktop shell
// (window.__TAURI__ present, same presence-gated pattern session.html's own notify_session_done
// call already uses), otherwise falls back to a plain window.open so a real browser tab is
// completely unaffected.
(function () {
  function openExternal(url) {
    var t = window.__TAURI__;
    if (t && t.core && t.core.invoke) {
      // A rejected invoke used to be swallowed here with no trace anywhere -- a real failure
      // (e.g. the OS launch itself failing) looked identical to "the operator didn't click
      // anything." The Rust side (open_external_url, desktop/src-tauri/src/main.rs) now logs
      // every failure to its own debug.log regardless; this mirrors that on the JS side so the
      // browser devtools console (and, when DEBUG is on, the UI category log) show it too.
      t.core.invoke("open_external_url", { url: url }).catch(function (err) {
        console.error("asraOpenExternal: open_external_url failed for", url, err);
        if (window.asraDebugEvent) window.asraDebugEvent("open_external_url_failed", url + " -- " + err);
      });
    } else {
      window.open(url, "_blank", "noopener");
    }
  }
  window.asraOpenExternal = openExternal;

  // Catches every plain <a target="_blank"> anywhere on the page, present now or added later by
  // an htmx swap -- one delegated listener instead of hunting down and patching each link site.
  // No-ops immediately outside the desktop shell, so a real browser's own native target="_blank"
  // handling is never interfered with.
  document.addEventListener("click", function (e) {
    if (!(window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke)) return;
    var a = e.target.closest && e.target.closest('a[target="_blank"]');
    if (!a || !a.href) return;
    e.preventDefault();
    openExternal(a.href);
  });
})();
