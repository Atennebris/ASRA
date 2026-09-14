// Standalone Terminal tab (templates/terminal.html) -- a real xterm.js frontend wired to a real
// PTY-backed shell over a WebSocket (main.py's /ws/terminal/{id}, agent/tools/terminal_manager.py).
// Multiple independent tabs can be open at once, each its own shell process/WebSocket; only the
// active tab's xterm.js instance is visible, the rest keep running in the background (their own
// WebSocket stays open, so switching back shows whatever kept happening while it was hidden).
//
// Wire protocol (binary WebSocket frames only):
//   client -> server: byte 0 = command tag. 0x00 = raw stdin bytes follow.
//                      0x01 = resize; 4 bytes follow, cols then rows, each big-endian uint16.
//   server -> client: binary frames are raw PTY output, written straight into xterm.js.
//                      text frames are JSON lifecycle events ({"type": "exited"/"error", ...}).
(function () {
  "use strict";

  var tabs = {}; // terminal_id -> tab record, see openTab() for shape
  var activeId = null;
  var tabBar = document.getElementById("terminal-tab-bar");
  var newTabGroup = document.querySelector(".terminal-newtab"); // lives inside tabBar, at its end
  var panes = document.getElementById("terminal-panes");
  var newTabBtn = document.getElementById("terminal-new-tab-btn");
  var newTabChevron = document.getElementById("terminal-new-tab-chevron");
  var emptyState = document.getElementById("terminal-empty-state");
  var titlebar = document.getElementById("terminal-titlebar");
  var titlebarDot = document.getElementById("terminal-titlebar-dot");
  var titlebarShell = document.getElementById("terminal-titlebar-shell");
  var titlebarPath = document.getElementById("terminal-titlebar-path");

  if (!tabBar || !panes || !newTabBtn) return; // not on the Terminal page

  // Portals both floating popovers (.terminal-popover, position:fixed) out to a direct child of
  // <body> -- position:fixed only ever positions relative to the true viewport when NO ancestor
  // has a transform/filter/perspective (any of those creates a new CSS containing block for fixed
  // descendants instead). session.html's drawer wraps this whole workspace in a
  // translateX(...)-transformed element for its own slide animation -- without this, showPopover()'s
  // own math (window.innerWidth, anchorEl.getBoundingClientRect(), both genuinely viewport-relative)
  // got applied to an element that was actually positioning itself relative to the DRAWER's own
  // box instead, real confirmed operator report: the shell-type/color picker opened fully
  // off-screen the first click and looked permanently stuck afterward (same broken math every
  // time, just never visible). No-op positioning-wise on the standalone Terminal page (terminal.html
  // has no transformed ancestor to begin with), so this is safe to do unconditionally.
  ["terminal-shell-picker", "terminal-color-picker"].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) document.body.appendChild(el);
  });

  var skipCloseConfirm = panes.getAttribute("data-skip-close-confirm") === "true";

  // Real PTY sessions (agent/tools/terminal_manager.py) outlive a single page load -- but until
  // this existed, nothing on the frontend remembered which terminal_ids were open across a full
  // page reload/navigation (this app never uses hx-boost; every nav is a real document unload, see
  // base.html's own pageshow/bfcache comment), so the bottom of this file always called a plain
  // openTab() on every load, spawning a BRAND NEW shell and leaving the previous one running
  // invisibly forever -- a real, confirmed operator report ("терминал не сейвится при обновлении
  // страницы / переходе между вкладками"). This localStorage record (tab order, custom name/color
  // per tab, which one was active) plus /api/terminal/list (main.py) is what lets restoreTabs()
  // below reconnect to whatever's still actually alive server-side instead.
  //
  // data-storage-scope (session.html's drawer, partials/terminal_panel.html) suffixes this key so
  // each project's drawer keeps its OWN tab list, isolated from every other project's -- real,
  // confirmed operator report: without this, EVERY project's drawer shared the exact same list (the
  // plain key below, unsuffixed), so a terminal opened in project A was still sitting there, fully
  // visible, after navigating to project B's own drawer -- the terminal equivalent of one project's
  // chat thread leaking into another's. The standalone Terminal page (terminal.html) renders no
  // such attribute at all, so it keeps the original, unsuffixed, genuinely-global key -- unchanged,
  // on purpose: that page is deliberately NOT project-scoped (see its own top comment).
  var storageScope = panes.getAttribute("data-storage-scope");
  var TABS_STORAGE_KEY = "asra-terminal-tabs-v1" + (storageScope ? "-" + storageScope : "");

  function wsUrl(terminalId) {
    var proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return proto + "//" + window.location.host + "/ws/terminal/" + terminalId;
  }

  function encodeInput(str) {
    var body = new TextEncoder().encode(str);
    var frame = new Uint8Array(1 + body.length);
    frame[0] = 0x00;
    frame.set(body, 1);
    return frame;
  }

  function encodeResize(cols, rows) {
    var frame = new Uint8Array(5);
    frame[0] = 0x01;
    frame[1] = (cols >> 8) & 0xff;
    frame[2] = cols & 0xff;
    frame[3] = (rows >> 8) & 0xff;
    frame[4] = rows & 0xff;
    return frame;
  }

  // ---- close-confirmation dialog (middle-click only -- the x button stays a plain, unconfirmed
  // close, same convention as a browser tab's own x) ------------------------------------------
  var closeConfirmDialog = document.getElementById("terminal-close-confirm");
  var closeConfirmCheckbox = document.getElementById("terminal-close-confirm-skip");
  var closeConfirmOkBtn = document.getElementById("terminal-close-confirm-ok");
  var closeConfirmCancelBtn = document.getElementById("terminal-close-confirm-cancel");
  var closeConfirmCurrent = null; // {resolve, result}

  if (closeConfirmDialog) {
    // Attached exactly once, for the page's whole lifetime -- HTMLDialogElement.close() queues its
    // "close" event as a real browser task, not synchronously, so a listener attached fresh per
    // call can race a still-pending event from the previous call. Same fix confirm_dialog.js's own
    // shared modal already uses for the identical race.
    closeConfirmOkBtn.addEventListener("click", function () {
      if (closeConfirmCurrent) closeConfirmCurrent.result = true;
      closeConfirmDialog.close();
    });
    closeConfirmCancelBtn.addEventListener("click", function () {
      if (closeConfirmCurrent) closeConfirmCurrent.result = false;
      closeConfirmDialog.close();
    });
    closeConfirmDialog.addEventListener("close", function () {
      var finishing = closeConfirmCurrent;
      closeConfirmCurrent = null;
      if (!finishing) return;
      if (finishing.result && closeConfirmCheckbox.checked) {
        skipCloseConfirm = true;
        fetch("/api/terminal/settings", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ skip_close_confirm: true }),
        }).catch(function () {});
      }
      finishing.resolve(finishing.result);
    });
  }

  function requestCloseConfirm() {
    if (!closeConfirmDialog) return Promise.resolve(true); // fail open if the markup is ever missing
    closeConfirmCheckbox.checked = false;
    return new Promise(function (resolve) {
      closeConfirmCurrent = { resolve: resolve, result: false };
      closeConfirmDialog.showModal();
    });
  }

  // ---- small floating popovers (new-terminal picker / per-tab color picker) -----------------
  function showPopover(el, anchorEl) {
    var rect = anchorEl.getBoundingClientRect();
    // Measure the popover's REAL size first -- reading offsetWidth/offsetHeight while the element
    // is still `hidden` (display:none) always returns 0, which silently defeated the viewport
    // clamping below (the right-edge check against a 0-width box never triggers), confirmed live:
    // a popover opened near the right edge of the window rendered mostly off-screen. Made visible
    // via `visibility: hidden` (still takes up layout, still measurable) rather than the `hidden`
    // attribute, so there's no visible flash before the real position is applied.
    el.hidden = false;
    el.style.visibility = "hidden";
    el.style.top = "0px";
    el.style.left = "0px";
    var width = el.offsetWidth;
    var height = el.offsetHeight;
    // Right-aligned to the anchor by default -- these triggers (the chevron, a tab's color dot)
    // tend to sit near the right side of their own row, so hanging the popover down-LEFT from the
    // anchor is the common case; still clamped to the viewport either way for a trigger near the
    // left edge instead.
    //
    // minLeft is NOT a flat viewport margin -- base.html's own #sidebar is a real, always-present
    // fixed column (w-56, ~224px) that a plain 8px-from-window-edge clamp knows nothing about.
    // Real, confirmed bug this fixes: with a short tab strip, the chevron sits close to the left
    // edge of the content area -- rect.right - width lands LESS than the sidebar's own width, so
    // the popover rendered starting underneath the sidebar, with its first ~50-70px of content
    // hidden behind it (the operator's own screenshot: "Terminal name" showing as "minal name").
    // Reading the sidebar's own live geometry (rather than hardcoding 224px) also does the right
    // thing automatically when it's collapsed off-screen on a narrow/mobile layout.
    var sidebarEl = document.getElementById("sidebar");
    var minLeft = (sidebarEl ? sidebarEl.getBoundingClientRect().right : 0) + 8;
    var left = rect.right - width;
    left = Math.max(minLeft, Math.min(left, window.innerWidth - width - 8));
    var top = rect.bottom + 4;
    if (top + height > window.innerHeight - 8) top = Math.max(8, rect.top - height - 4); // flip above the anchor if there's no room below
    el.style.left = left + "px";
    el.style.top = top + "px";
    el.style.visibility = "";
    // Real, confirmed bug this guards against: picking a color via the native <input type="color">
    // swatch never used to call hidePopover() (only the "Default color" menu item did), so its own
    // outside-click listener stayed registered on `document` after the popover was, in effect,
    // still "open". The NEXT time this same shared popover opened for a DIFFERENT tab, that stale
    // listener fired during the very click that opened it (its own closure still pointed at the
    // OLD anchor, which the new click target never matches) and immediately hid the popover again
    // -- looked exactly like "recoloring stops working after the first couple of tabs". Removing
    // any previous handler here, unconditionally, before ever registering a new one, means this
    // holds regardless of whether whatever closed the popover last time remembered to clean up
    // after itself.
    if (el._asraOutsideHandler) {
      document.removeEventListener("click", el._asraOutsideHandler);
      el._asraOutsideHandler = null;
    }
    var onOutsideClick = function (event) {
      if (!el.contains(event.target) && event.target !== anchorEl) hidePopover(el);
    };
    el._asraOutsideHandler = onOutsideClick;
    // Deferred past this same click's own event-loop turn, or the click that opened the popover
    // would immediately be seen as an "outside" click and close it right back.
    setTimeout(function () { document.addEventListener("click", onOutsideClick); }, 0);
  }
  function hidePopover(el) {
    el.hidden = true;
    if (el._asraOutsideHandler) {
      document.removeEventListener("click", el._asraOutsideHandler);
      el._asraOutsideHandler = null;
    }
  }

  function fetchShells() {
    return fetch("/api/terminal/shells").then(function (r) { return r.json(); });
  }

  // The chevron's own popover -- name + color for the terminal ABOUT to be created, plus the
  // real detected shell-type list, grouped WSL(Linux) vs native Windows (only present at all on a
  // dual-system/WSL2 host -- see terminal_manager.detect_available_shells' own docstring for why
  // the Windows group carries an explicit "experimental" note rather than looking identical to
  // the WSL ones). Picking any shell entry creates the tab immediately with whatever name/color
  // are currently in the form.
  var newTerminalPendingName = "";
  var newTerminalPendingColor = null;

  function openNewTerminalPicker(anchorEl) {
    var el = document.getElementById("terminal-shell-picker");
    fetchShells().then(function (data) {
      el.innerHTML = "";

      var nameInput = document.createElement("input");
      nameInput.type = "text";
      nameInput.placeholder = "Terminal name (optional)";
      nameInput.className = "terminal-newterm-name";
      nameInput.value = newTerminalPendingName;
      nameInput.addEventListener("input", function () { newTerminalPendingName = nameInput.value; });
      nameInput.addEventListener("click", function (event) { event.stopPropagation(); });
      el.appendChild(nameInput);

      el.appendChild(_newColorRow(newTerminalPendingColor, function (value) { newTerminalPendingColor = value; }));
      el.appendChild(_popoverDivider());

      var groups = { wsl: [], windows: [] };
      (data.shells || []).forEach(function (s) { (groups[s.kind] || groups.wsl).push(s); });

      function appendShellItem(shellInfo, experimental) {
        var item = document.createElement("div");
        item.className = "terminal-popover-item";
        item.textContent = shellInfo.name + (shellInfo.path === data.default ? " (default)" : "");
        if (experimental) {
          var badge = document.createElement("span");
          badge.className = "terminal-popover-badge";
          // Real tab-completion/PSReadLine now work here (windows-pty-bridge/ gives the target
          // shell an actual Win32 ConPTY of its own, confirmed live -- PowerShell's own syntax
          // highlighting and path completion, cmd.exe's own path completion, both verified
          // working end to end). Still labeled experimental because the bridge itself is new and
          // exercised far less than the WSL shells above it, not because Tab is broken.
          badge.title = "Runs a native Windows process through ASRA's own ConPTY bridge (windows-pty-bridge/) -- tab-completion and PSReadLine work here. Still labeled experimental: this bridge is new and far less exercised than the WSL shells above.";
          badge.textContent = "experimental";
          item.appendChild(badge);
        }
        item.addEventListener("click", function () {
          hidePopover(el);
          var name = newTerminalPendingName;
          var color = newTerminalPendingColor;
          newTerminalPendingName = "";
          newTerminalPendingColor = null;
          openTab("", shellInfo.path, name, color);
        });
        el.appendChild(item);
      }

      if (groups.wsl.length) {
        el.appendChild(_popoverLabel("WSL (Linux)"));
        groups.wsl.forEach(function (s) { appendShellItem(s, false); });
      }
      if (groups.windows.length) {
        el.appendChild(_popoverDivider());
        el.appendChild(_popoverLabel("Windows (native)"));
        groups.windows.forEach(function (s) { appendShellItem(s, true); });
      }
      if (!groups.wsl.length && !groups.windows.length) {
        var empty = document.createElement("div");
        empty.className = "terminal-popover-item";
        empty.textContent = "No shells detected";
        el.appendChild(empty);
      }

      showPopover(el, anchorEl);
      nameInput.focus();
    });
  }

  function _popoverLabel(text) {
    var label = document.createElement("div");
    label.className = "terminal-popover-label";
    label.textContent = text;
    return label;
  }
  function _popoverDivider() {
    var divider = document.createElement("div");
    divider.className = "terminal-popover-divider";
    return divider;
  }

  // Full-spectrum <input type="color">, styled via themes.css's own .icon-picker-colorbtn (the
  // exact same round swatch control the New Project form's icon color already uses) -- real
  // operator ask after the first pass only offered 8 preset chart colors here: "палитру всего",
  // the whole palette, not a curated handful of swatches.
  function _newColorRow(currentValue, onChange, onCommit) {
    var row = document.createElement("div");
    row.className = "terminal-color-row";
    var label = document.createElement("span");
    label.textContent = "Color";
    row.appendChild(label);
    var colorLabel = document.createElement("label");
    colorLabel.className = "icon-picker-colorbtn";
    colorLabel.title = "Terminal color — pick any";
    colorLabel.addEventListener("click", function (event) { event.stopPropagation(); });
    var colorInput = document.createElement("input");
    colorInput.type = "color";
    colorInput.value = currentValue || "#808080";
    colorInput.addEventListener("input", function () { onChange(colorInput.value); }); // live preview while dragging the native picker
    if (onCommit) {
      // "change" fires once, when the native color dialog actually closes with a value -- the
      // real "I'm done picking" moment, unlike "input" which can fire continuously mid-drag.
      colorInput.addEventListener("change", function () { onCommit(colorInput.value); });
    }
    colorLabel.appendChild(colorInput);
    row.appendChild(colorLabel);
    return row;
  }

  function openColorPicker(anchorEl, terminalId) {
    var el = document.getElementById("terminal-color-picker");
    el.innerHTML = "";
    var tab = tabs[terminalId];
    el.appendChild(_newColorRow(
      tab && tab.color,
      function (value) { setTabColor(terminalId, value); },
      function (value) { setTabColor(terminalId, value); hidePopover(el); }
    ));
    el.appendChild(_popoverDivider());
    var resetItem = document.createElement("div");
    resetItem.className = "terminal-popover-item";
    resetItem.textContent = "Default color";
    resetItem.addEventListener("click", function () {
      setTabColor(terminalId, null);
      hidePopover(el);
    });
    el.appendChild(resetItem);
    showPopover(el, anchorEl);
  }

  // Perceived brightness (ITU-R BT.601 luma) -- picks whichever of near-black/near-white text
  // reliably contrasts against an arbitrary, fully user-chosen background color. A fixed
  // "--text-secondary" foreground (the previous, class-only-swatch design) can't work once the
  // background itself is any color from a full spectrum picker -- pale yellow with light-gray
  // text, for one real example, is close to unreadable.
  function _readableTextColor(hex) {
    var m = /^#([0-9a-f]{6})$/i.exec(hex);
    if (!m) return "#f5f5f5";
    var n = parseInt(m[1], 16);
    var r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
    var brightness = (r * 299 + g * 587 + b * 114) / 1000;
    return brightness > 140 ? "#14161a" : "#f5f5f5";
  }

  function _hexToRgbTriplet(hex) {
    var m = /^#([0-9a-f]{6})$/i.exec(hex);
    if (!m) return "128, 128, 128";
    var n = parseInt(m[1], 16);
    return ((n >> 16) & 255) + ", " + ((n >> 8) & 255) + ", " + (n & 255);
  }

  function setTabColor(terminalId, colorValue) {
    var tab = tabs[terminalId];
    if (!tab) return;
    tab.color = colorValue;
    var style = tab.tabButton.style;
    if (colorValue) {
      // Three custom properties, not one -- the whole tab background is painted now (real
      // operator ask: "весь таб", not just a thin top accent bar), and inactive vs. active needs
      // to stay visually distinguishable even with a custom color, so inactive gets a translucent
      // wash of the same color (--terminal-tab-color-dim) while the active tab gets it solid.
      style.setProperty("--terminal-tab-color", colorValue);
      style.setProperty("--terminal-tab-color-dim", "rgba(" + _hexToRgbTriplet(colorValue) + ", 0.35)");
      style.setProperty("--terminal-tab-fg", _readableTextColor(colorValue));
    } else {
      style.removeProperty("--terminal-tab-color");
      style.removeProperty("--terminal-tab-color-dim");
      style.removeProperty("--terminal-tab-fg");
    }
    saveTabsState();
  }

  // ---- tab bookkeeping -------------------------------------------------------------------------

  // Persists tab order (real DOM order -- drag-and-drop reorders independently of creation order)
  // plus each tab's custom name/color and which one is active. Called after anything that changes
  // that picture (open, close, rename, recolor, reorder, activate) -- cheap enough (a handful of
  // tabs, at most) to just call it unconditionally rather than debouncing.
  function saveTabsState() {
    try {
      var order = Array.prototype.filter.call(tabBar.children, function (el) {
        return el.classList && el.classList.contains("terminal-tab");
      });
      var records = [];
      order.forEach(function (btn) {
        var id = null;
        for (var key in tabs) {
          if (tabs[key].tabButton === btn) { id = key; break; }
        }
        if (!id) return;
        records.push({ id: id, name: tabs[id].labelEl.textContent, color: tabs[id].color });
      });
      localStorage.setItem(TABS_STORAGE_KEY, JSON.stringify({ tabs: records, activeId: activeId }));
    } catch (e) {} // private-browsing/storage-disabled -- just means no restore next load
  }

  function updateEmptyState() {
    var hasTabs = Object.keys(tabs).length > 0;
    if (emptyState) emptyState.hidden = hasTabs;
    panes.hidden = !hasTabs;
    if (titlebar) titlebar.hidden = !hasTabs;
    // tabBar itself is deliberately NEVER hidden, even with zero tabs open -- its own "+"/chevron
    // live inside it (so "+" sits right after the last tab, see openTab's own comment), and a real,
    // confirmed bug this fixes: closing every open tab used to hide the whole strip along with
    // them, leaving the operator staring at "Opening a terminal…" forever with no way back in
    // short of a full page reload -- there was no visible "+" left anywhere to click.
  }

  function setTabLive(terminalId, isLive) {
    var tab = tabs[terminalId];
    if (!tab) return;
    tab.dotEl.classList.toggle("is-live", isLive);
    if (terminalId === activeId) titlebarDot.classList.toggle("is-live", isLive);
  }

  function updateTitlebar(terminalId) {
    var tab = tabs[terminalId];
    if (!tab || !titlebar) return;
    titlebarShell.textContent = tab.shellName + (tab.shellKind === "windows" ? " (Windows)" : "");
    titlebarPath.textContent = tab.cwd;
    titlebarPath.title = tab.cwd;
    titlebarDot.classList.toggle("is-live", tab.dotEl.classList.contains("is-live"));
  }

  function setActive(terminalId) {
    if (!tabs[terminalId]) return;
    activeId = terminalId;
    Object.keys(tabs).forEach(function (id) {
      var tab = tabs[id];
      var isActive = id === terminalId;
      tab.container.hidden = !isActive;
      tab.tabButton.classList.toggle("terminal-tab-active", isActive);
    });
    updateTitlebar(terminalId);
    saveTabsState();
    var tab = tabs[terminalId];
    // fit() needs the container to actually be visible (real layout dimensions) -- deferred one
    // frame past the hidden-attribute flip above so the browser has already reflowed it.
    requestAnimationFrame(function () {
      try { tab.fitAddon.fit(); } catch (e) {}
      // Skipped mid-rename -- a double-click's own two "click" events (each of which calls
      // setActive) both fire, and both schedule this same deferred focus() BEFORE the dblclick
      // handler that actually starts the rename ever runs. Without this guard, whichever of those
      // two already-queued calls fires next steals focus right back from the label the instant
      // rename mode turns on -- confirmed live, this was why rename looked completely broken.
      if (!tab.renaming) tab.term.focus();
    });
  }

  function connect(terminalId, tab) {
    var ws = new WebSocket(wsUrl(terminalId));
    ws.binaryType = "arraybuffer";
    tab.ws = ws;

    ws.onopen = function () {
      tab.reconnectAttempts = 0;
      setTabLive(terminalId, true);
      if (window.asraDebugEvent) window.asraDebugEvent("terminal", "connected " + terminalId);
      try {
        var dims = tab.fitAddon.proposeDimensions();
        if (dims) ws.send(encodeResize(dims.cols, dims.rows));
      } catch (e) {}
    };
    ws.onmessage = function (event) {
      if (typeof event.data === "string") {
        try {
          var msg = JSON.parse(event.data);
          if (msg.type === "exited") {
            tab.term.write("\r\n\x1b[90m[process exited" + (msg.code !== null && msg.code !== undefined ? " with code " + msg.code : "") + "]\x1b[0m\r\n");
            setTabLive(terminalId, false);
          } else if (msg.type === "error") {
            tab.term.write("\r\n\x1b[31m[" + (msg.message || "terminal error") + "]\x1b[0m\r\n");
          }
        } catch (e) {}
        return;
      }
      tab.term.write(new Uint8Array(event.data));
    };
    ws.onclose = function () {
      setTabLive(terminalId, false);
      if (tab.closedByUser) return;
      if (window.asraDebugEvent) window.asraDebugEvent("terminal", "disconnected " + terminalId);
      // Local-only backend (127.0.0.1) -- a close almost always means a dev/server restart, not a
      // real network failure, so a patient, indefinite backoff (capped at 10s) is the right shape:
      // no reason to ever give up entirely on a tab the operator still has open.
      tab.reconnectAttempts = (tab.reconnectAttempts || 0) + 1;
      var delay = Math.min(10000, 500 * Math.pow(2, tab.reconnectAttempts));
      tab.reconnectTimer = setTimeout(function () {
        if (!tabs[terminalId] || tab.closedByUser) return;
        connect(terminalId, tab);
      }, delay);
    };
  }

  function shortLabel(cwd) {
    if (!cwd) return "shell";
    var parts = cwd.replace(/[\\/]+$/, "").split(/[\\/]/);
    return parts[parts.length - 1] || cwd;
  }

  // Real operator ask: a project's "Open terminal here" link (and the plain "+" button) must
  // always open a genuinely NEW tab, even when one for that same project/cwd is already open --
  // e.g. one tab running a long scan, another kept free for ad-hoc commands is a normal, deliberate
  // workflow, not a mistake to silently collapse back into the first tab. But two tabs both plainly
  // named e.g. "myproject" are hard to tell apart at a glance, so the second/third/... one for the
  // same base name gets " 2"/" 3"/... appended -- the very first tab with a given name stays
  // unnumbered. Only applied to the auto-derived (from cwd) label; an operator's own explicit
  // custom name (the new-tab picker's name field) is used exactly as typed, never auto-suffixed.
  function uniqueLabelFor(baseLabel) {
    var existing = {};
    Object.keys(tabs).forEach(function (id) { existing[tabs[id].labelEl.textContent] = true; });
    if (!existing[baseLabel]) return baseLabel;
    var n = 2;
    while (existing[baseLabel + " " + n]) n++;
    return baseLabel + " " + n;
  }

  function terminalTheme() {
    // Matches static/css/themes.css's own CSS custom properties so xterm.js reads as part of the
    // app, not a visually foreign embed -- re-read live (not cached) so a theme switch picks it up
    // the next time a tab is opened, same "live visual feedback" bar the rest of the UI holds to.
    var styles = getComputedStyle(document.documentElement);
    var v = function (name, fallback) {
      var val = styles.getPropertyValue(name).trim();
      return val || fallback;
    };
    return {
      background: v("--surface", "#1e1e1e"),
      foreground: v("--text-primary", "#e5e5e5"),
      cursor: v("--accent", "#e5e5e5"),
      selectionBackground: v("--accent", "#2563eb") + "55",
    };
  }

  // ---- drag-and-drop tab reordering --------------------------------------------------------
  var dragTerminalId = null;

  function wireDragAndDrop(tabButton, terminalId) {
    tabButton.draggable = true;
    tabButton.addEventListener("dragstart", function (event) {
      dragTerminalId = terminalId;
      tabButton.classList.add("is-dragging");
      event.dataTransfer.effectAllowed = "move";
      try { event.dataTransfer.setData("text/plain", terminalId); } catch (e) {}
    });
    tabButton.addEventListener("dragend", function () {
      tabButton.classList.remove("is-dragging");
      dragTerminalId = null;
      Array.prototype.forEach.call(tabBar.children, function (el) {
        el.classList.remove("drag-over-left", "drag-over-right");
      });
    });
    tabButton.addEventListener("dragover", function (event) {
      if (!dragTerminalId || dragTerminalId === terminalId) return;
      event.preventDefault();
      var rect = tabButton.getBoundingClientRect();
      var isLeftHalf = (event.clientX - rect.left) < rect.width / 2;
      tabButton.classList.toggle("drag-over-left", isLeftHalf);
      tabButton.classList.toggle("drag-over-right", !isLeftHalf);
    });
    tabButton.addEventListener("dragleave", function () {
      tabButton.classList.remove("drag-over-left", "drag-over-right");
    });
    tabButton.addEventListener("drop", function (event) {
      event.preventDefault();
      tabButton.classList.remove("drag-over-left", "drag-over-right");
      var draggedId = dragTerminalId;
      dragTerminalId = null;
      if (!draggedId || draggedId === terminalId || !tabs[draggedId]) return;
      var draggedBtn = tabs[draggedId].tabButton;
      var rect = tabButton.getBoundingClientRect();
      var isLeftHalf = (event.clientX - rect.left) < rect.width / 2;
      tabBar.insertBefore(draggedBtn, isLeftHalf ? tabButton : tabButton.nextSibling);
      saveTabsState();
      if (window.asraDebugEvent) window.asraDebugEvent("terminal", "reordered tab " + draggedId);
    });
  }

  // ---- rename ---------------------------------------------------------------------------------
  function wireRename(labelEl, tab) {
    labelEl.addEventListener("dblclick", function (event) {
      event.stopPropagation();
      tab.renaming = true; // checked by setActive's own deferred term.focus() -- see there for why
      labelEl.contentEditable = "true";
      labelEl.focus();
      var range = document.createRange();
      range.selectNodeContents(labelEl);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    });
    function commit() {
      labelEl.contentEditable = "false";
      var text = labelEl.textContent.replace(/\s+/g, " ").trim();
      labelEl.textContent = text || tab.defaultLabel;
      tab.tabButton.title = labelEl.textContent + " — " + tab.cwd;
      tab.renaming = false;
      saveTabsState();
    }
    labelEl.addEventListener("blur", commit);
    labelEl.addEventListener("keydown", function (event) {
      if (event.key === "Enter") { event.preventDefault(); labelEl.blur(); }
      else if (event.key === "Escape") { labelEl.textContent = tab.lastCommittedLabel || tab.defaultLabel; labelEl.blur(); }
    });
  }

  // Builds one tab's whole UI (xterm.js instance, tab button, wiring) and connects its WebSocket --
  // shared by openTab() (a brand-new PTY, just created via POST /api/terminal/new) and reattachTab()
  // (an already-running PTY from BEFORE this page load, found via /api/terminal/list) alike. The
  // only real difference between "new" and "restored" is where terminalId/cwd/shellPath/kind came
  // from -- the WebSocket attach itself already replays scrollback for either case identically
  // (main.py's ws_terminal handler), so there's nothing else reattach needs to do differently.
  function createTab(terminalId, cwd, shellPath, kind, name, color, restored) {
    var shellName = (shellPath || "").split("/").pop() || "shell";

    var container = document.createElement("div");
    container.className = "terminal-pane";
    container.hidden = true;
    panes.appendChild(container);

    var defaultLabel = (name && name.trim()) || uniqueLabelFor(shortLabel(cwd));
    var tabButton = document.createElement("button");
    tabButton.type = "button";
    tabButton.className = "terminal-tab";
    tabButton.title = defaultLabel + " — " + cwd;
    tabButton.innerHTML =
      '<span class="terminal-tab-dot"></span>' +
      '<span class="terminal-tab-label"></span>' +
      '<span class="terminal-tab-color-btn" title="Tab color"><span></span></span>' +
      '<span class="terminal-tab-close" title="Close">&times;</span>';
    var labelEl = tabButton.querySelector(".terminal-tab-label");
    labelEl.textContent = defaultLabel;
    var dotEl = tabButton.querySelector(".terminal-tab-dot");
    var colorBtn = tabButton.querySelector(".terminal-tab-color-btn");
    // Inserted right before the +/chevron group -- both live inside the same scrollable
    // #terminal-tab-bar, so "+" always sits immediately after the last tab (like a real
    // browser tab strip) instead of being pinned to the container's own far edge.
    tabBar.insertBefore(tabButton, newTabGroup);

    var term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
      theme: terminalTheme(),
      allowProposedApi: true,
    });
    var fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);

    var tab = {
      term: term, fitAddon: fitAddon, ws: null, container: container,
      tabButton: tabButton, dotEl: dotEl, labelEl: labelEl,
      cwd: cwd, shellName: shellName, shellKind: kind || "wsl", defaultLabel: defaultLabel, color: null,
      reconnectAttempts: 0, reconnectTimer: null, closedByUser: false, renaming: false,
    };
    tabs[terminalId] = tab;
    if (color) setTabColor(terminalId, color);

    term.onData(function (str) {
      if (tab.ws && tab.ws.readyState === WebSocket.OPEN) tab.ws.send(encodeInput(str));
    });
    term.onResize(function (size) {
      if (tab.ws && tab.ws.readyState === WebSocket.OPEN) tab.ws.send(encodeResize(size.cols, size.rows));
    });

    tabButton.addEventListener("click", function (event) {
      if (event.target.closest(".terminal-tab-close")) { closeTab(terminalId); return; }
      if (event.target.closest(".terminal-tab-color-btn")) { openColorPicker(colorBtn, terminalId); return; }
      if (event.target.isContentEditable) return; // renaming in progress -- don't steal focus
      // event.detail is the click's own position in a multi-click sequence (2 = the second
      // click of what's about to become a dblclick) -- skipped so this click's own setActive
      // doesn't queue another deferred term.focus() fighting the rename the dblclick handler
      // is about to start (see setActive's own comment for the full race).
      if (event.detail > 1) return;
      setActive(terminalId);
    });
    // Middle-click closes -- with a confirm dialog unless the operator already opted out.
    tabButton.addEventListener("mousedown", function (event) {
      if (event.button === 1) event.preventDefault(); // suppress the OS's own autoscroll icon
    });
    tabButton.addEventListener("auxclick", function (event) {
      if (event.button !== 1) return;
      event.preventDefault();
      if (skipCloseConfirm) { closeTab(terminalId); return; }
      requestCloseConfirm().then(function (confirmed) {
        if (confirmed) closeTab(terminalId);
      });
    });

    wireDragAndDrop(tabButton, terminalId);
    wireRename(labelEl, tab);

    connect(terminalId, tab);
    updateEmptyState();
    setActive(terminalId);
    if (window.asraDebugEvent) {
      window.asraDebugEvent("terminal", (restored ? "restored tab " : "opened tab ") + terminalId + " cwd=" + cwd + " shell=" + shellName);
    }
  }

  function openTab(cwd, shellPath, name, color) {
    var body = { cwd: cwd || "" };
    if (shellPath) body.shell = shellPath;
    fetch("/api/terminal/new", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        createTab(data.terminal_id, data.cwd, data.shell, data.kind, name, color, false);
      })
      .catch(function () {
        // Best-effort UI action -- a failed open just means no new tab appears, nothing to recover.
      });
  }

  // Reconnects to a real PTY that was already running before this page load (found via
  // /api/terminal/list) -- no /api/terminal/new call, since the shell process itself never
  // stopped; this just rebuilds the xterm.js UI for it and attaches a fresh WebSocket, which
  // immediately replays its scrollback (main.py's ws_terminal handler).
  function reattachTab(terminalId, cwd, shellPath, kind, name, color) {
    createTab(terminalId, cwd, shellPath, kind, name, color, true);
  }

  // Runs once on page load in place of a plain openTab(): reads THIS SCOPE's own persisted tab
  // list (TABS_STORAGE_KEY, saveTabsState() above), cross-checks it against /api/terminal/list (the
  // terminals ACTUALLY still alive server-side), and reattaches to every one that survived -- a
  // persisted entry whose PTY is gone (a full ASRA server restart -- terminal_manager.py's own
  // documented trade-off, no tmux-style adoption across a restart) is just dropped instead of
  // erroring. Falls back to a plain fresh tab when there's nothing to restore, or when a project's
  // "Open terminal here" link (?cwd=...) asks for a cwd that isn't already one of the restored tabs.
  function restoreTabs() {
    var initialCwd = panes.getAttribute("data-initial-cwd") || "";
    // "new" (default, terminal.html's standalone page + its own "Open terminal here" link):
    // initialCwd always opens a genuinely new tab on EVERY load, even when this scope already has
    // one for the same cwd -- real, confirmed operator ask: a second/third terminal for the same
    // project (one running a long scan, another free for ad-hoc commands) is a normal, deliberate
    // workflow, not a mistake to silently collapse into whichever tab happened to already be open.
    // "reuse" (session.html's drawer, data-cwd-mode="reuse"): the drawer's toggle is a PANEL, not a
    // "give me one more terminal" link -- reopening it should show whatever this project's scope
    // already has, never spawn a duplicate. Combined with TABS_STORAGE_KEY's own per-project scoping
    // above, "this scope already has one" now just falls out of the normal reattach-and-restore flow
    // below with no special-casing needed there -- the only place "reuse" still changes anything is
    // the true-first-ever-open case just below, adopting a live orphan instead of assuming there
    // is none.
    var cwdMode = panes.getAttribute("data-cwd-mode") || "new";
    var persisted = null;
    try {
      var raw = localStorage.getItem(TABS_STORAGE_KEY);
      persisted = raw ? JSON.parse(raw) : null;
    } catch (e) { persisted = null; }
    var persistedTabs = (persisted && Array.isArray(persisted.tabs)) ? persisted.tabs : [];

    if (!persistedTabs.length) {
      // Nothing recorded for this scope yet. In "reuse" mode, before spawning a brand-new PTY,
      // check whether a live terminal already exists rooted at exactly this cwd -- e.g. one opened
      // before this scope's own storage key existed, or from a browser profile that never recorded
      // it -- and adopt it instead of leaving an orphaned duplicate running alongside a fresh one.
      if (initialCwd && cwdMode === "reuse") {
        fetch("/api/terminal/list")
          .then(function (resp) { return resp.json(); })
          .then(function (data) {
            var match = (data.terminals || []).find(function (t) { return t.cwd === initialCwd; });
            if (match) reattachTab(match.terminal_id, match.cwd, match.shell, match.kind, "", null);
            else openTab(initialCwd);
          })
          .catch(function () { openTab(initialCwd); });
      } else {
        openTab(initialCwd);
      }
      return;
    }

    fetch("/api/terminal/list")
      .then(function (resp) { return resp.json(); })
      .then(function (data) {
        var liveById = {};
        (data.terminals || []).forEach(function (t) { liveById[t.terminal_id] = t; });

        persistedTabs.forEach(function (rec) {
          var live = liveById[rec.id];
          if (!live) return; // no longer running server-side -- drop it, nothing to reattach to
          reattachTab(live.terminal_id, live.cwd, live.shell, live.kind, rec.name, rec.color);
        });

        var restoredCount = Object.keys(tabs).length;
        if (restoredCount && window.asraDebugEvent) {
          window.asraDebugEvent("terminal", "restored " + restoredCount + " tab(s) after reload");
        }

        if (initialCwd && cwdMode !== "reuse") {
          // createTab's own uniqueLabelFor() keeps same-named tabs distinguishable ("project",
          // "project 2", ...). Only applied to the auto-derived (from cwd) label; an operator's own
          // explicit custom name (the new-tab picker's name field) is used exactly as typed, never
          // auto-suffixed.
          openTab(initialCwd);
        } else if (!restoredCount) {
          openTab(initialCwd);
        } else {
          var wantActive = persisted.activeId;
          if (wantActive && tabs[wantActive]) setActive(wantActive);
        }
      })
      .catch(function () {
        openTab(initialCwd);
      });
  }

  function closeTab(terminalId) {
    var tab = tabs[terminalId];
    if (!tab) return;
    tab.closedByUser = true;
    if (tab.reconnectTimer) clearTimeout(tab.reconnectTimer);
    if (tab.ws) { try { tab.ws.close(); } catch (e) {} }
    try { tab.term.dispose(); } catch (e) {}
    tab.container.remove();
    tab.tabButton.remove();
    delete tabs[terminalId];
    fetch("/api/terminal/" + terminalId + "/close", { method: "POST" }).catch(function () {});

    if (activeId === terminalId) {
      // Pick a DOM-order neighbor (drag-and-drop can reorder tabs independently of creation
      // order), not an insertion-order guess. Filtered to real tab buttons only -- tabBar also
      // permanently holds the +/chevron group as one of its children now.
      var remainingButtons = Array.prototype.filter.call(tabBar.children, function (el) {
        return el !== tab.tabButton && el.classList.contains("terminal-tab");
      });
      activeId = null;
      if (remainingButtons.length) {
        var neighborId = Object.keys(tabs).filter(function (id) { return tabs[id].tabButton === remainingButtons[remainingButtons.length - 1]; })[0];
        if (neighborId) setActive(neighborId); // setActive() saves the new activeId itself
      }
    }
    updateEmptyState();
    // Covers both branches above: setActive() (if a neighbor took over) already saved once with
    // the new activeId, and this second call is a no-op duplicate then; when there was no
    // neighbor left, this is the ONLY save that reflects the tab actually being gone and
    // activeId now being null.
    saveTabsState();
    if (window.asraDebugEvent) window.asraDebugEvent("terminal", "closed tab " + terminalId);
  }

  function onWindowResize() {
    if (activeId && tabs[activeId]) {
      try { tabs[activeId].fitAddon.fit(); } catch (e) {}
    }
  }
  window.addEventListener("resize", onWindowResize);

  newTabBtn.addEventListener("click", function () { openTab(""); });
  if (newTabChevron) {
    newTabChevron.addEventListener("click", function (event) {
      openNewTerminalPicker(event.currentTarget);
    });
  }

  // Always restores/ensures this scope's own tab(s) right away, on every page load -- including
  // session.html's embedded drawer, even while the drawer panel itself stays visually collapsed
  // (that's the drawer's own script's job, session.html, entirely separate from whether the tab
  // data underneath it exists). Real, confirmed operator ask: the project's own terminal must
  // always be there and ready the instant the drawer IS opened, including right after the operator
  // explicitly closed every tab and reloaded the page -- not something that only gets created on
  // first open. cwdMode's own "reuse" handling (restoreTabs() above) is what keeps this safe to run
  // unconditionally: reattaching an already-live tab, or adopting an orphaned one, never spawns a
  // second PTY for the same scope -- a fresh one is only ever actually spawned when this scope
  // genuinely has none.
  restoreTabs();

  // Real incident this exists to prevent: this whole file is a plain IIFE, re-executed FRESH every
  // time a page containing it (the standalone Terminal tab, or a session's embedded drawer) loads --
  // always true before boosted navigation existed anywhere in this app, since a real page load
  // guaranteed the OLD instance's window (and everything on it) was gone first. Once #sidebar's own
  // hx-boost can carry the operator from one session straight to another WITHOUT a real reload, a
  // second execution of this same IIFE would leave the FIRST instance's own WebSockets, reconnect
  // timers, and this "resize" listener above all still alive and referencing DOM nodes the swap just
  // removed -- orphaned connections quietly burning a PTY each, and N stacked resize listeners after
  // N such moves. window.asraPageCleanups is base.html's own hook (see its htmx:beforeSwap
  // listener) -- an array every function on it gets called from right before a boosted swap
  // removes this page's content, shutting down exactly what a real navigation's own unload used to
  // make irrelevant, so boost is safe to extend to session pages.
  window.asraPageCleanups = window.asraPageCleanups || [];
  window.asraPageCleanups.push(function () {
    window.removeEventListener("resize", onWindowResize);
    Object.keys(tabs).forEach(function (id) {
      var tab = tabs[id];
      tab.closedByUser = true; // same flag a real user-initiated close sets -- onclose won't reconnect
      if (tab.reconnectTimer) clearTimeout(tab.reconnectTimer);
      if (tab.ws) { try { tab.ws.close(); } catch (e) {} }
    });
  });
})();
