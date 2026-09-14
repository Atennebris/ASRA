// Shared clipboard-copy helper for every finding/hypothesis/credential/chain/log card's own Copy
// button (templates/macros/ui.html's copy_button() macro, onclick="asraCopyCard(this)"). Loaded
// unconditionally in base.html so it's available on every page regardless of session mode --
// real, confirmed-live bug this fixes: these functions used to live inline inside session.html's
// own Interactive/Reverse-Engineering-only branch, so window.asraCopyCard was simply never
// defined for an Agent-mode session at all (session_fragment.html, included from a completely
// separate {% else %} branch, never got it) -- every copy button anywhere in Agent mode threw a
// silent "asraCopyCard is not defined" on click, doing nothing visible, exactly the same symptom
// later also reported for Reverse Engineering mode's own findings panel.
(function () {
  // navigator.clipboard.writeText() can reject in more real-world situations than "the browser
  // doesn't support it" -- no clipboard-write permission granted in this specific context, the
  // tab genuinely not focused at the exact click moment (a real, easy-to-hit case for a button
  // inside a just-opened <dialog>), a non-HTTPS/non-localhost origin. Every call site used to be a
  // bare `.then(...)` with no `.catch()` at all -- a rejected promise meant the button did
  // NOTHING and showed NOTHING, indistinguishable from "the click didn't register". Falls back to
  // the older execCommand("copy") (a temporary off-screen textarea, no such focus/permission
  // restriction) when the real Clipboard API isn't available or rejects.
  function asraCopyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).catch(function () {
        return asraCopyTextFallback(text);
      });
    }
    return asraCopyTextFallback(text);
  }

  function asraCopyTextFallback(text) {
    var textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.top = "0";
    textarea.style.left = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    document.body.removeChild(textarea);
    return ok ? Promise.resolve() : Promise.reject(new Error("execCommand(copy) failed"));
  }

  function asraFlashCopyResult(btn, ok) {
    if (!btn) return;
    var original = btn.textContent;
    btn.textContent = ok ? "Copied!" : "Copy failed";
    setTimeout(function () { btn.textContent = original; }, 1500);
  }

  // Copy a finding/hypothesis/chain/credential card's normalized details (built server-side into
  // data-copy-text, see main.py's *_copy_text filters and macros/ui.html's copy_button) to the
  // clipboard, with a brief "Copied!" confirmation on the button itself. Delegated click logging
  // (static/js/debug_events.js) already records the raw click; this adds one explicit UI-category
  // event naming what was copied, so a debug trace shows the real action, not just "button click".
  window.asraCopyCard = function (btn) {
    var text = (btn && btn.dataset && btn.dataset.copyText) || "";
    if (!text) return;
    asraCopyText(text)
      .then(function () {
        if (window.asraDebugEvent) {
          window.asraDebugEvent("copy-card", text.split("\n", 1)[0].slice(0, 80));
        }
        asraFlashCopyResult(btn, true);
      })
      .catch(function () { asraFlashCopyResult(btn, false); });
  };

  // textContent (not innerText) deliberately -- a collapsed <details> still has its body in the
  // DOM, just not painted, and innerText respects that rendered/hidden state while textContent
  // doesn't, so this is the only way to grab every entry's full text regardless of which cards
  // are expanded on screen right now. Interactive/RE mode's own "Copy logs" button
  // (#copy-logs-btn, #session-log-list) -- kept here too since it shares the exact same
  // copy/fallback/flash mechanics as the card buttons, not worth a second copy of that logic.
  window.asraCopyLogs = function () {
    var log = document.getElementById("session-log-list");
    var btn = document.getElementById("copy-logs-btn");
    if (!log) return;
    var lines = Array.prototype.map.call(log.querySelectorAll("details"), function (entry) {
      return entry.textContent.replace(/\s+/g, " ").trim();
    });
    asraCopyText(lines.join("\n\n"))
      .then(function () { asraFlashCopyResult(btn, true); })
      .catch(function () { asraFlashCopyResult(btn, false); });
  };
})();
