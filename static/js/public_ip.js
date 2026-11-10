// Sidebar "My IP" block (base.html #asra-public-ip). The address is confidential, so it is hidden
// by default and exists in the DOM ONLY while revealed:
//   - reveal  -> one GET /api/public-ip per click (never polled, so a VPN switched on a minute ago
//                shows its own exit IP the next time the operator looks); a loading state shows
//                until the response lands, and a family that failed says "unavailable".
//   - hide    -> manual second click, the auto-hide timer (data-autohide-seconds, from env
//                PUBLIC_IP_AUTOHIDE_SECONDS), or the tab becoming hidden. Hiding resets the text
//                nodes to their masked placeholder, so a forgotten window never leaks the IP.
// Delegated click handler on document: this <script> runs in <head> before the sidebar exists, and
// delegation also survives any future swap of the sidebar markup.
(function () {
  var FETCH_TIMEOUT_MS = 10000;
  var hideTimer = null;
  var requestToken = 0;
  var revealed = false;

  function parts() {
    var root = document.getElementById("asra-public-ip");
    if (!root) return null;
    return {
      root: root,
      btn: document.getElementById("asra-public-ip-toggle"),
      v4: document.getElementById("asra-public-ip-v4"),
      v6: document.getElementById("asra-public-ip-v6"),
    };
  }

  function debug(action, detail) {
    // Outcome only, never the address itself -- see agent/public_ip.py.
    if (window.asraDebugEvent) window.asraDebugEvent(action, detail);
  }

  function setButtonState(p, on) {
    var label = on ? "Hide IP address" : "Show IP address";
    p.btn.setAttribute("aria-pressed", on ? "true" : "false");
    p.btn.setAttribute("aria-label", label);
    p.btn.setAttribute("title", label);
    // toggleAttribute, not `.hidden =`: SVG elements have no `hidden` property, so assigning it
    // would silently do nothing and the eye icon would never swap.
    p.btn.querySelector('[data-icon="show"]').toggleAttribute("hidden", on);
    p.btn.querySelector('[data-icon="hide"]').toggleAttribute("hidden", !on);
  }

  function hide(reason) {
    var p = parts();
    clearTimeout(hideTimer);
    hideTimer = null;
    requestToken += 1; // a response still in flight must not repopulate a hidden block
    if (!p || !revealed) return;
    revealed = false;
    p.v4.textContent = p.v4.getAttribute("data-masked");
    p.v6.textContent = p.v6.getAttribute("data-masked");
    setButtonState(p, false);
    debug("public-ip", "hidden (" + reason + ")");
  }

  function show(p, data) {
    var v4 = data && data.ipv4 && data.ipv4.address;
    var v6 = data && data.ipv6 && data.ipv6.address;
    p.v4.textContent = v4 || "unavailable";
    p.v6.textContent = v6 || "unavailable";
  }

  function reveal(p) {
    var token = ++requestToken;
    var seconds = parseInt(p.root.getAttribute("data-autohide-seconds"), 10);
    revealed = true;
    setButtonState(p, true);
    p.v4.textContent = "loading...";
    p.v6.textContent = "loading...";

    // The timer starts now, not when the response lands: a hung lookup must not keep the block
    // "revealed" past the configured window.
    clearTimeout(hideTimer);
    hideTimer = setTimeout(function () { hide("auto-hide"); }, (seconds > 0 ? seconds : 30) * 1000);

    var controller = new AbortController();
    var abortTimer = setTimeout(function () { controller.abort(); }, FETCH_TIMEOUT_MS);
    fetch("/api/public-ip", { cache: "no-store", signal: controller.signal })
      .then(function (resp) {
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        return resp.json();
      })
      .then(function (data) {
        if (token !== requestToken) return;
        show(p, data);
        debug("public-ip", "revealed (ipv4=" + !!(data.ipv4 && data.ipv4.address) +
          ", ipv6=" + !!(data.ipv6 && data.ipv6.address) + ")");
      })
      .catch(function (err) {
        if (token !== requestToken) return;
        show(p, null);
        debug("public-ip", "lookup failed (" + (err && err.name) + ")");
      })
      .finally(function () { clearTimeout(abortTimer); });
  }

  document.addEventListener("click", function (event) {
    var btn = event.target.closest && event.target.closest("#asra-public-ip-toggle");
    if (!btn) return;
    var p = parts();
    if (!p) return;
    if (revealed) hide("manual");
    else reveal(p);
  });

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) hide("tab hidden");
  });
  // bfcache restore can bring back a page whose reveal state/timer no longer matches the DOM.
  window.addEventListener("pagehide", function () { hide("page hide"); });
})();
