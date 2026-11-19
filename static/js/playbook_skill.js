// Instant client-side feedback for the Playbook skill "Trusted on/off" toggle, so the trust badge
// flips the same frame the operator clicks -- the real server toggle (main.py's playbook_skill_trust)
// still re-renders the whole list afterward and is the authority once it lands, same optimistic
// pattern settings toggles / the chat tab-active flip use. Trust is advisory only and never gates
// execution, so flipping the badge ahead of the round trip can't misrepresent whether a skill will
// run. No-op if anything's missing -- the htmx post still runs regardless.
(function () {
  var TRUSTED_CLASSES = ["text-severity-low", "border-severity-low/40", "bg-severity-low/10"];
  var UNREVIEWED_CLASSES = ["text-secondary", "border-default", "bg-elevated", "border-dashed"];

  function setClasses(el, add, remove) {
    remove.forEach(function (c) { el.classList.remove(c); });
    add.forEach(function (c) { el.classList.add(c); });
  }

  window.asraFlipSkillTrust = function (btn) {
    try {
      var card = btn.closest("[data-skill-card]");
      if (!card) return;
      var badge = card.querySelector("[data-skill-trust-badge]");
      var label = card.querySelector("[data-skill-trust-label]");
      var action = btn.querySelector("[data-skill-trust-action]");
      if (!badge) return;
      var nowTrusted = badge.getAttribute("data-trusted") !== "true";
      badge.setAttribute("data-trusted", nowTrusted ? "true" : "false");
      if (nowTrusted) {
        setClasses(badge, TRUSTED_CLASSES, UNREVIEWED_CLASSES);
      } else {
        setClasses(badge, UNREVIEWED_CLASSES, TRUSTED_CLASSES);
      }
      if (label) label.textContent = nowTrusted ? "Operator-trusted" : "Unreviewed";
      if (action) action.textContent = nowTrusted ? "Trusted on" : "Mark trusted";
    } catch (e) {
      // A failed optimistic flip must never block the real htmx toggle underneath it.
    }
  };

  // Instant feedback for the per-skill "Enable/Disable" toggle -- dims the block, hides Run, flips
  // the Disabled badge and the button label the same frame, before the real server toggle
  // (main.py's playbook_skill_enabled) re-renders the list and becomes the authority. A disabled
  // skill is already refused by execute_skill server-side, so hiding Run ahead of the round trip is
  // purely cosmetic and never misrepresents what will run.
  window.asraFlipSkillEnabled = function (btn) {
    try {
      var card = btn.closest("[data-skill-card]");
      if (!card) return;
      var block = card.querySelector("[data-skill-block]");
      var badge = card.querySelector("[data-skill-disabled-badge]");
      var runBtn = card.querySelector("[data-skill-run-btn]");
      var action = btn.querySelector("[data-skill-enabled-action]");
      if (!block) return;
      var nowEnabled = block.getAttribute("data-enabled") !== "true";
      block.setAttribute("data-enabled", nowEnabled ? "true" : "false");
      block.classList.toggle("opacity-60", !nowEnabled);
      if (badge) badge.hidden = nowEnabled;
      if (runBtn) runBtn.hidden = !nowEnabled;
      if (action) action.textContent = nowEnabled ? "Disable" : "Enable";
    } catch (e) {
      // A failed optimistic flip must never block the real htmx toggle underneath it.
    }
  };

  // Export flow for every "Export" button on the Playbook page (whole playbook, all skills, one
  // skill). The whole point is a REAL "choose where to save" step, defaulting to Downloads -- not a
  // silent drop into Downloads. How that choice is offered depends on where we're running:
  //   - Desktop shell (Tauri/WebView2): window.showSaveFilePicker does NOT exist here, so we invoke
  //     the Rust `save_export_file` command, which opens the OS-native "Save As" dialog (defaulting
  //     to the last folder / Downloads) and writes the file. This is the real fix for the shell.
  //   - A real browser with the File System Access API: use window.showSaveFilePicker directly.
  //   - Anything else: a plain blob/anchor download into the browser's own Downloads.
  // The GET route is just the data source -- we fetch its JSON and hand the text to whichever path
  // applies. A cancelled dialog is always a silent no-op.
  function tauriInvoke() {
    var t = window.__TAURI__;
    if (t && t.core && typeof t.core.invoke === "function") return t.core.invoke;
    if (t && typeof t.invoke === "function") return t.invoke;
    return null;
  }

  window.asraExportJson = async function (url, suggestedName) {
    try {
      var resp = await fetch(url);
      if (!resp.ok) {
        if (window.asraConfirm) {
          window.asraConfirm({ title: "Export failed", message: "The server returned " + resp.status + ".", confirmLabel: "OK", danger: false });
        }
        return;
      }
      var text = await resp.text();

      var invoke = tauriInvoke();
      if (invoke) {
        // Native OS "Save As" dialog -- the operator picks the folder and name (defaults to
        // Downloads / last used). Cancel returns null; any real error surfaces via the debug module.
        try {
          await invoke("save_export_file", { suggestedName: suggestedName, contents: text });
        } catch (err) {
          if (window.asraDebugEvent) window.asraDebugEvent("playbook-export-error", String(err));
        }
        return;
      }

      if (window.showSaveFilePicker) {
        var handle;
        try {
          handle = await window.showSaveFilePicker({
            suggestedName: suggestedName,
            types: [{ description: "JSON", accept: { "application/json": [".json"] } }],
          });
        } catch (err) {
          if (err && err.name === "AbortError") return; // operator cancelled -- do nothing
          throw err;
        }
        var writable = await handle.createWritable();
        await writable.write(text);
        await writable.close();
        return;
      }

      // Last resort (a browser without the File System Access API): the browser's own Downloads.
      var blob = new Blob([text], { type: "application/json" });
      var objectUrl = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = objectUrl;
      a.download = suggestedName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (e) {
      // Surfaced through the debug module when DEBUG is on; never throws into the UI otherwise.
      if (window.asraDebugEvent) window.asraDebugEvent("playbook-export-error", String(e));
    }
  };
})();
