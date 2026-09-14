// Reveal/hide toggle for a configured identity's own secret fields (username/email/password/
// login URL/cookie/Authorization header) on the Recon tab's Credentials card
// (templates/partials/session_fragment.html). Each field starts masked; the first click on its
// eye button fetches the real value once via htmx (main.py's reveal_identity_field route) --
// every click after that just flips the same value between shown/masked entirely client-side, no
// further server round trip needed. Loaded page-wide (base.html), same posture as copy_card.js.
window.asraToggleIdentityField = function (btn) {
  var textEl = btn.previousElementSibling;
  if (!textEl) return;
  var showing = textEl.textContent !== btn.dataset.masked;
  textEl.textContent = showing ? btn.dataset.masked : btn.dataset.value;
  var label = showing ? "Show" : "Hide";
  btn.setAttribute("title", label);
  btn.setAttribute("aria-label", label);
  btn.classList.toggle("asra-identity-shown", !showing);
};
