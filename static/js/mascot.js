// Optional companion in the session header (Settings -> Customization -> Mascot). Purely decorative --
// reacts to session-content's own data-status/data-findings-count attributes (autonomous mode) or
// #chat-messages growing (interactive mode), never anything the agent's own reasoning reads or
// depends on. Skin/size choices live in localStorage (asra-mascot-skin, asra-mascot-size), same
// client-only convention as asra-theme (base.html) -- no server round-trip, no settings.py
// plumbing. Default (nothing saved yet) skin is "sych", size "md"; explicitly choosing "off" in
// Settings mounts nothing at all.
//
// Each skin is a small, cute ASCII pet that WALKS along the header's bottom rule -- it patrols the
// empty middle gap of the header row (between the title block on the left and the status badges on
// the right), turning around at each end. A two-frame walk cycle (legs/feet alternate) plays while
// it moves; it pauses now and then for a short idle (a blink), then carries on. Direction is a
// single CSS scaleX(-1) flip of the art, so only one right-facing frame set is authored per pet.
// State is communicated the same way as before: a brief speech bubble (LINES) plus a color pulse
// (asra-mascot-react-* classes, themes.css), cleared after REACTION_HOLD_MS -- during a reaction
// the pet stops and stands so the message is readable.
//
// The pet is absolutely positioned inside the header row (the [data-mascot-track] element,
// session.html), so it escapes the flex layout entirely and the empty mount <span> collapses to
// nothing -- no header restructuring, no overlap with the title/badges (patrol bounds are derived
// from those siblings' real widths). prefers-reduced-motion: the pet stands still at one spot and
// still recolors/speaks on events, but never walks.
(function () {
  var SKIN_KEY = "asra-mascot-skin";
  var SIZE_KEY = "asra-mascot-size";
  var REACTION_HOLD_MS = 2600;
  var STEP_MS = 210;          // walk-frame swap cadence
  var SPEED_PX = 0.5;         // horizontal travel per animation frame (slow, ambient)
  var IDLE_CHANCE = 0.0035;   // per-frame chance to pause for a short idle while walking
  var EDGE_PAD = 6;           // keep this far from each patrol bound

  var SIZE_PX = { sm: 10, md: 12, lg: 15 };

  // Right-facing ASCII pets. walk = [frameA, frameB] (legs/feet alternate), idle = a resting pose
  // (used during pauses and reactions). Lines are padded to a constant width per pet so the CSS
  // scaleX(-1) flip mirrors around the true center.
  var PETS = {
    sych: {   // a small watchful owl -- bobs on its perch rather than striding
      walk: [[" {o,o} ", " |)_(| ", '  " "  '], [" {o,o} ", " |)_(| ", "  ' '  "]],
      idle: [" {-,-} ", " |)_(| ", '  " "  ']
    },
    bug: {    // a round eager beetle, six little legs
      walk: [[" (o.o) ", " [===] ", " /|_|\\ "], [" (o.o) ", " [===] ", " \\|_|/ "]],
      idle: [" (o.o) ", " [===] ", "  |_|  "]
    },
    spider: { // a tiny spider, legs scuttling
      walk: [[" (\\/) ", " (oo) ", " /||\\ "], [" (/\\) ", " (oo) ", " \\||/ "]],
      idle: [" (\\/) ", " (oo) ", "  ||  "]
    }
  };

  var NAMES = { sych: "Sych", bug: "Bug", spider: "Spider" };

  var LINES = {
    busy: { sych: "Watching.", bug: "Digging...", spider: "Crawling..." },
    found: { sych: "Confirmed.", bug: "Got one!", spider: "New thread found." },
    done: { sych: "Done.", bug: "Full.", spider: "Mapped." },
    error: { sych: "Error.", bug: "Ow.", spider: "Thread broke." },
    reply: { sych: "Noted.", bug: "Heard.", spider: "Got it." }
  };

  // Exposed for the Settings preview (settings.html) so its swatches show the real walk frame
  // without re-typing the art anywhere -- returns a skin's resting right-facing frame, or "".
  window.asraMascotFrame = function (id) {
    return PETS[id] ? PETS[id].walk[0].join("\n") : "";
  };

  var REDUCED_MOTION = window.matchMedia &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function chosenSkinId() {
    var v = localStorage.getItem(SKIN_KEY);
    if (v === "off") return null;
    return v && PETS[v] ? v : "sych";
  }

  function chosenSizePx() {
    var v = localStorage.getItem(SIZE_KEY);
    return SIZE_PX[v] || SIZE_PX.md;
  }

  // The pet lives on the header row so it can walk its full width. The mount <span> only carries
  // the context; the row itself (marked data-mascot-track) is the track.
  function findTrack(container) {
    return container.closest("[data-mascot-track]") || container;
  }

  function createPet(track, skinId) {
    var pet = PETS[skinId];
    if (!pet) return null;

    var box = document.createElement("div");
    box.className = "asra-mascot";
    box.style.setProperty("--mascot-font-size", chosenSizePx() + "px");
    var bubble = document.createElement("div");
    bubble.className = "asra-mascot-bubble hidden";
    var art = document.createElement("pre");
    art.className = "asra-mascot-art";
    box.appendChild(bubble);
    box.appendChild(art);
    track.appendChild(box);

    function render(lines) { art.textContent = lines.join("\n"); }
    render(pet.idle);

    // Patrol bounds: the empty gap between the title block (first child) and the status group
    // (last non-pet child). Falls back to the whole track width if that gap can't be measured or
    // would be too small. Recomputed on resize so a window change never traps the pet off-screen.
    var minX = EDGE_PAD, maxX = EDGE_PAD;
    function recomputeBounds() {
      var trackRect = track.getBoundingClientRect();
      var petW = box.offsetWidth || 60;
      var kids = [];
      for (var i = 0; i < track.children.length; i++) {
        if (track.children[i] !== box) kids.push(track.children[i]);
      }
      var left = EDGE_PAD, right = trackRect.width - petW - EDGE_PAD;
      if (kids.length) {
        var firstRect = kids[0].getBoundingClientRect();
        var lastRect = kids[kids.length - 1].getBoundingClientRect();
        left = (firstRect.right - trackRect.left) + EDGE_PAD;
        right = (lastRect.left - trackRect.left) - petW - EDGE_PAD;
      }
      if (right <= left) { left = EDGE_PAD; right = Math.max(EDGE_PAD, trackRect.width - petW - EDGE_PAD); }
      minX = left; maxX = right;
    }
    recomputeBounds();
    window.addEventListener("resize", recomputeBounds);

    var x = REDUCED_MOTION ? maxX : (minX + Math.random() * Math.max(1, maxX - minX));
    var dir = Math.random() < 0.5 ? -1 : 1;
    var frame = 0;
    var lastStep = 0;
    var mode = "walk";       // "walk" | "idle" | "react"
    var modeUntil = 0;
    var reactTimer = null;

    box.style.transform = "translateX(" + x + "px)";

    function react(stateName) {
      var line = LINES[stateName] && LINES[stateName][skinId];
      if (!line) return;
      bubble.textContent = line;
      bubble.classList.remove("hidden");
      art.className = "asra-mascot-art asra-mascot-react-" + stateName;
      mode = "react";
      modeUntil = performance.now() + REACTION_HOLD_MS;
      render(pet.idle);
      if (window.asraDebugEvent) window.asraDebugEvent("mascot", NAMES[skinId] + " -> " + stateName);
      if (reactTimer) clearTimeout(reactTimer);
      reactTimer = setTimeout(function () {
        reactTimer = null;
        bubble.classList.add("hidden");
        art.className = "asra-mascot-art";
      }, REACTION_HOLD_MS);
    }

    if (REDUCED_MOTION) return { react: react };

    function tick(ts) {
      if (!lastStep) lastStep = ts;
      if (mode === "react" || mode === "idle") {
        if (ts > modeUntil) { mode = "walk"; lastStep = ts; }
      } else {
        x += dir * SPEED_PX;
        if (x <= minX) { x = minX; dir = 1; }
        else if (x >= maxX) { x = maxX; dir = -1; }
        box.classList.toggle("asra-mascot-flip", dir < 0);
        if (ts - lastStep >= STEP_MS) { frame ^= 1; lastStep = ts; render(pet.walk[frame]); }
        if (Math.random() < IDLE_CHANCE) { mode = "idle"; modeUntil = ts + 800 + Math.random() * 1400; render(pet.idle); }
      }
      box.style.transform = "translateX(" + x + "px)";
      requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);

    return { react: react };
  }

  // Autonomous mode: session_fragment.html stamps a fresh data-status/data-findings-count onto
  // #session-content on every real render, and htmx:afterSwap already fires on every successful
  // SSE morph (static/js/findings_tab_count.js relies on the exact same two facts) -- so this
  // needs no SSE wiring of its own, just piggybacking on an event that already fires.
  function watchSessionContext(widget) {
    var lastStatus = null;
    var lastFindings = null;
    function check() {
      var content = document.getElementById("session-content");
      if (!content) return;
      var status = content.getAttribute("data-status");
      var findings = parseInt(content.getAttribute("data-findings-count") || "0", 10);
      if (lastFindings !== null && findings > lastFindings) {
        widget.react("found");
      } else if (lastStatus !== null && status !== lastStatus) {
        if (status === "completed") widget.react("done");
        else if (status === "failed" || status === "interrupted") widget.react("error");
        else if (status === "processing") widget.react("busy");
      }
      lastStatus = status;
      lastFindings = findings;
    }
    check();
    document.addEventListener("htmx:afterSwap", check);
  }

  // Interactive/Reverse Engineering mode: no session_fragment.html at all on that page, so there's
  // no data-status to read -- react to the chat thread actually growing instead (a real reply
  // having landed). A new message carrying a reward-card with data-reward-kind="finding"
  // (chat_messages.html's own reward-role rendering, agent/chat.py's deliver_storage_reward_to_chat)
  // gets the same "found" reaction watchSessionContext already gives a real new finding in
  // autonomous mode, instead of the generic "reply" every other new message gets -- distinguishing
  // "a finding just landed" from "the assistant said literally anything" was previously impossible
  // in this context, since DOM child-count growth alone can't tell the two apart.
  function watchChatContext(widget) {
    var messages = document.getElementById("chat-messages");
    if (!messages) return;
    var lastCount = messages.children.length;
    new MutationObserver(function (mutations) {
      var count = messages.children.length;
      if (count > lastCount) {
        var foundFinding = mutations.some(function (mutation) {
          return Array.prototype.some.call(mutation.addedNodes, function (node) {
            if (node.nodeType !== 1) return false;
            return node.matches(".reward-card[data-reward-kind='finding']") ||
                   !!node.querySelector(".reward-card[data-reward-kind='finding']");
          });
        });
        widget.react(foundFinding ? "found" : "reply");
      }
      lastCount = count;
    }).observe(messages, { childList: true });
  }

  function init() {
    var skinId = chosenSkinId();
    if (!skinId) return;
    var mounts = document.querySelectorAll("[data-mascot-mount]");
    mounts.forEach(function (mountSpan) {
      var track = findTrack(mountSpan);
      var widget = createPet(track, skinId);
      if (!widget) return;
      var context = mountSpan.getAttribute("data-mascot-context");
      if (context === "session") watchSessionContext(widget);
      else if (context === "chat") watchChatContext(widget);
    });
  }

  document.addEventListener("DOMContentLoaded", init);
})();
