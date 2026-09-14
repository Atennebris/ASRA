// Guards the New Project form's "Hypotheses to check" textarea (new_project_form.html) against a
// real, confirmed mistake: an operator pasting the program's whole rules/policy page in there
// instead of one short suspicion per line. main.py splits that field on newlines with no content
// check at all, so a pasted policy document (testing rules, reward eligibility, disclosure terms —
// nothing about the actual target) turns into a pile of "hypotheses" that aren't security claims
// and can never be legitimately confirmed or ruled out by a real investigation. The end-of-session
// hypothesis gate (agent/core.py's _run_hypothesis_resolution_gate) then burns real tool calls
// trying and failing to resolve every one of them, and they're left stuck "Unconfirmed" forever —
// this is a real incident this file exists to catch before it happens, not a hypothetical.
//
// Deliberately a soft speed bump, not a hard block: past LINE_WARN_THRESHOLD lines, ask for
// confirmation via the app's own styled dialog (static/js/confirm_dialog.js) instead of silently
// submitting. A legitimate long list of real hypotheses can still go through by confirming once.
(function () {
  var LINE_WARN_THRESHOLD = 8;

  document.addEventListener("submit", function (event) {
    var form = event.target;
    // Matched by action, not id -- new_project_form.html is included twice on the index page
    // (the page's own inline form and base.html's sidebar "New Project" dialog), so a shared id
    // would be a duplicate-id situation neither of those two copies otherwise has.
    if (!(form instanceof HTMLFormElement) || form.getAttribute("action") !== "/api/scan") return;
    var textarea = form.querySelector('textarea[name="initial_hypotheses"]');
    if (!textarea) return;

    var lines = textarea.value.split("\n").map(function (line) { return line.trim(); }).filter(Boolean);
    if (lines.length <= LINE_WARN_THRESHOLD) return;

    event.preventDefault();
    if (window.asraDebugEvent) {
      window.asraDebugEvent("hypotheses-paste-guard", "blocked submit pending confirmation: " + lines.length + " lines parsed");
    }
    window.asraConfirm({
      title: "That's a lot of hypotheses",
      message: '"Hypotheses to check" parses ' + lines.length + " separate lines — each one becomes its own " +
        "hypothesis the agent must individually investigate before the scan is considered done. If you pasted " +
        "the program's rules/policy page by mistake, that belongs in \"Custom instructions for this program\" " +
        "instead. Continue with " + lines.length + " hypotheses?",
      confirmLabel: "Yes, create " + lines.length + " hypotheses",
      danger: false,
    }).then(function (confirmed) {
      if (window.asraDebugEvent) {
        window.asraDebugEvent("hypotheses-paste-guard", confirmed ? "confirmed, submitting" : "cancelled");
      }
      if (confirmed) form.submit();
    });
  });
})();
