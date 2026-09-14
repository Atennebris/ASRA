// Settings -> Appearance's "Neo" theme -- the one theme (static/css/themes.css) that gets real
// per-frame JS treatment (canvas digital rain + interaction) instead of a purely static palette.
// A MutationObserver on <html data-theme> (not a listener wired into settings.html's own
// applyTheme()) is what reacts to a live theme switch -- decoupled on purpose, same "never make a
// shared mechanism depend on one specific caller" reasoning as this file's own teardown functions:
// settings.html can change how it applies a theme without this file ever needing to know.
//
// Mr. Robot is intentionally NOT here anymore: its whole treatment (the "fuck society" ghost
// watermark behind the content, the amped signal-glitch, the hover channel-split) is pure CSS in
// themes.css, so it needs no JS, works with JS disabled, and -- the actual reason it was rebuilt --
// no longer floats a fixed terminal box in the bottom-right corner where it overlapped the chat
// composer's send button.
(function () {
  var THEME_ATTR = "data-theme";

  function currentTheme() {
    return document.documentElement.getAttribute(THEME_ATTR);
  }

  function reducedMotion() {
    return matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  // ============================================================================================
  // Neo -- canvas digital rain + a one-shot decode-in on the sidebar wordmark, plus two real
  // interactions: a click sends a bright burst down the columns nearest the pointer, and switching
  // to the theme flashes a brief "wake up." across the screen. Cursor proximity already brightens
  // and speeds up nearby columns ("the code is aware you're there"); the click burst is the same
  // idea made deliberate and momentary.
  //
  // Glyphs are binary-dominant (0/1) with an occasional hex digit or code symbol mixed in -- richer
  // than a pure 0/1 field, still reads as security-tool code rain "on its own merits, not a
  // reproduction of a licensed visual" (the source material's katakana is deliberately never used
  // in the falling rain -- same choice themes.css's own neo comment documents for its CSS fallback).
  // ============================================================================================
  var neoCanvas = null, neoCtx = null, neoRafId = null, neoColumns = [];
  var neoLastFrame = 0;
  var NEO_FRAME_INTERVAL = 1000 / 24; // ~24fps -- legible falling motion, a fraction of the GPU/CPU cost of 60fps
  var NEO_COLUMN_WIDTH = 20;
  var neoMouseX = -9999, neoMouseY = -9999;
  var NEO_EXTRA = "ABCDEF<>/\\=+*?#$%".split(""); // the ~30% of glyphs that are not a bare 0/1
  var NEO_BURST_MS = 750;
  var NEO_BURST_RADIUS = 95;

  function neoGlyph() {
    if (Math.random() < 0.7) return Math.random() < 0.5 ? "0" : "1";
    return NEO_EXTRA[(Math.random() * NEO_EXTRA.length) | 0];
  }

  function neoResize() {
    if (!neoCanvas) return;
    neoCanvas.width = innerWidth;
    neoCanvas.height = innerHeight;
    var count = Math.ceil(innerWidth / NEO_COLUMN_WIDTH);
    neoColumns = [];
    for (var i = 0; i < count; i++) neoColumns.push(neoMakeColumn(i));
  }

  function neoMakeColumn(i) {
    return {
      x: i * NEO_COLUMN_WIDTH,
      y: Math.random() * -innerHeight,
      speed: 2.2 + Math.random() * 3,
      length: 12 + Math.floor(Math.random() * 16),
      glyphs: [],
      burstUntil: 0,
    };
  }

  function neoTrackMouse(e) {
    neoMouseX = e.clientX;
    neoMouseY = e.clientY;
  }

  // A click ripples outward: every column whose head is within NEO_BURST_RADIUS of the pointer is
  // marked "bursting" for NEO_BURST_MS, during which it falls faster and glows brighter -- a
  // momentary shockwave through the rain rather than a permanent change.
  function neoOnClick(e) {
    if (!neoColumns.length) return;
    var now = performance.now();
    for (var i = 0; i < neoColumns.length; i++) {
      if (Math.abs(neoColumns[i].x - e.clientX) < NEO_BURST_RADIUS) {
        neoColumns[i].burstUntil = now + NEO_BURST_MS;
      }
    }
  }

  function neoOnVisibility() {
    if (document.hidden) cancelAnimationFrame(neoRafId);
    else neoRafId = requestAnimationFrame(neoTick);
  }

  function neoTick(ts) {
    neoRafId = requestAnimationFrame(neoTick);
    if (ts - neoLastFrame < NEO_FRAME_INTERVAL) return;
    neoLastFrame = ts;
    if (!neoCtx) return;
    // A translucent fill (not clearRect) each frame is what leaves the fading trail behind each
    // head glyph -- the same trick screen-saver rain effects have always used; real motion blur
    // would cost far more to compute per-frame.
    neoCtx.fillStyle = "rgba(3, 9, 5, 0.15)";
    neoCtx.fillRect(0, 0, neoCanvas.width, neoCanvas.height);
    neoCtx.font = "14px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace";
    neoCtx.textAlign = "center";
    for (var i = 0; i < neoColumns.length; i++) neoDrawColumn(neoColumns[i], ts);
  }

  function neoDrawColumn(col, ts) {
    var bursting = ts < col.burstUntil;
    var nearMouse = Math.abs(col.x - neoMouseX) < 70 && neoMouseY > -9999;
    var hot = bursting || nearMouse;
    col.y += col.speed * (bursting ? 2.6 : nearMouse ? 1.9 : 1);
    if (col.y - col.length * 18 > neoCanvas.height) {
      col.y = Math.random() * -200;
      col.speed = 2.2 + Math.random() * 3;
      col.glyphs = [];
    }
    for (var j = 0; j < col.length; j++) {
      var gy = col.y - j * 18;
      if (gy < -18 || gy > neoCanvas.height + 18) continue;
      // Glyphs mostly hold steady frame-to-frame (a real character sitting in the column) with a
      // small per-frame chance of flipping -- constant re-randomization every frame reads as
      // static noise, not falling code; holding still is what makes the MOTION read as the head
      // glyph moving downward past stationary-feeling trail characters, closer to the reference.
      if (col.glyphs[j] === undefined || Math.random() < 0.03) col.glyphs[j] = neoGlyph();
      var t = j / col.length;
      var alpha = Math.max(0, 1 - t) * (hot ? 1 : 0.85);
      neoCtx.fillStyle = j === 0
        ? "rgba(210, 255, 225, " + alpha + ")"
        : bursting ? "rgba(140, 255, 180, " + alpha + ")" : "rgba(34, 255, 102, " + alpha + ")";
      neoCtx.fillText(col.glyphs[j], col.x + NEO_COLUMN_WIDTH / 2, gy);
    }
  }

  function initNeoRain() {
    if (neoCanvas || reducedMotion()) return;
    neoCanvas = document.createElement("canvas");
    neoCanvas.id = "asra-neo-rain-canvas";
    document.body.appendChild(neoCanvas);
    neoCtx = neoCanvas.getContext("2d");
    document.documentElement.classList.add("neo-canvas-active");
    neoResize();
    addEventListener("resize", neoResize);
    document.addEventListener("mousemove", neoTrackMouse);
    document.addEventListener("click", neoOnClick);
    document.addEventListener("visibilitychange", neoOnVisibility);
    neoRafId = requestAnimationFrame(neoTick);
  }

  function teardownNeoRain() {
    if (!neoCanvas) return;
    cancelAnimationFrame(neoRafId);
    removeEventListener("resize", neoResize);
    document.removeEventListener("mousemove", neoTrackMouse);
    document.removeEventListener("click", neoOnClick);
    document.removeEventListener("visibilitychange", neoOnVisibility);
    neoCanvas.remove();
    neoCanvas = null;
    neoCtx = null;
    neoColumns = [];
    document.documentElement.classList.remove("neo-canvas-active");
  }

  // One-shot "wake up." on theme activation -- an homage to the reference's own cold-open in ASRA's
  // own register (never the scripted line verbatim), gone in well under two seconds so it's a
  // moment, not a permanent overlay. CSS (#asra-neo-wake) owns the look and the fade-out; this only
  // mounts it and removes it once the animation is spent.
  function neoWakeFlash() {
    if (reducedMotion()) return;
    var el = document.createElement("div");
    el.id = "asra-neo-wake";
    el.setAttribute("aria-hidden", "true");
    el.textContent = "wake up.";
    document.body.appendChild(el);
    setTimeout(function () { if (el.parentNode) el.remove(); }, 1700);
  }

  // Decode-in on the wordmark ("ASRA" in the sidebar + the mobile header) -- the other unmistakably
  // "Matrix UI" trope beyond rain: text resolving out of scrambled glyphs. Real content (session
  // data, findings) is never touched by this -- only the app's own static chrome, once, on
  // activation, never a recurring distraction while someone is actually working.
  var NEO_DECODE_CHARS = "!<>-_\\/[]{}=+*^?#01アカサタナ".split(""); // a few katakana mixed into the SCRAMBLE only (never the final resolved text) reads as "decoding," not a reproduction of anything -- the settled result is always the plain word "ASRA"
  function neoDecodeText(el) {
    if (!el || el.dataset.neoDecoding === "1") return;
    var original = el.textContent;
    el.dataset.neoDecoding = "1";
    var frame = 0;
    var totalFrames = 16;
    var timer = setInterval(function () {
      var revealCount = Math.round((frame / totalFrames) * original.length);
      var out = "";
      for (var i = 0; i < original.length; i++) {
        out += i < revealCount ? original[i] : NEO_DECODE_CHARS[(Math.random() * NEO_DECODE_CHARS.length) | 0];
      }
      el.textContent = out;
      frame++;
      if (frame > totalFrames) {
        el.textContent = original;
        clearInterval(timer);
        delete el.dataset.neoDecoding;
      }
    }, 45);
  }

  function initNeoDecode() {
    document.querySelectorAll(".asra-wordmark").forEach(neoDecodeText);
  }

  // ============================================================================================
  // Mr. Robot -- the "fuck society" ghost watermark. It has to be a child of <body> (not an html
  // pseudo-element): body carries an opaque background-color, which paints OVER anything the html
  // element renders beneath it, so an html::before would be invisible. As a body child with a
  // negative z-index it paints just above body's background and below every app panel, showing only
  // through the open background between panels. Styling + the slow breathe/glitch live in themes.css
  // (#asra-fsociety); this only mounts and unmounts it with the theme. Created even under
  // prefers-reduced-motion -- it's a static graphic, not motion (the CSS drops its animation there).
  // ============================================================================================
  var fsocietyEl = null;

  function initFsociety() {
    if (fsocietyEl) return;
    fsocietyEl = document.createElement("div");
    fsocietyEl.id = "asra-fsociety";
    fsocietyEl.setAttribute("aria-hidden", "true");
    fsocietyEl.textContent = "FUCK\nSOCIETY";
    document.body.appendChild(fsocietyEl);
  }

  function teardownFsociety() {
    if (!fsocietyEl) return;
    fsocietyEl.remove();
    fsocietyEl = null;
  }

  // ============================================================================================
  // Wiring: run Neo's per-frame treatment while it's the active theme, tear it down otherwise --
  // idempotent either way (init/teardown each no-op if already in the asked-for state), so this can
  // run freely on load and on every observed data-theme change. Mr. Robot needs nothing here (CSS).
  // ============================================================================================
  // isSwitch is true only when the MutationObserver saw data-theme actually change (the user picked
  // the theme just now) -- so the "wake up." flash fires on activation, never on every page load
  // where Neo simply happened to already be the saved theme.
  function applyForCurrentTheme(isSwitch) {
    var theme = currentTheme();
    if (theme === "neo") {
      var wasActive = !!neoCanvas;
      initNeoRain();
      initNeoDecode();
      if (isSwitch && !wasActive) neoWakeFlash();
    } else {
      teardownNeoRain();
    }
    if (theme === "mr-robot") initFsociety();
    else teardownFsociety();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { applyForCurrentTheme(false); });
  } else {
    applyForCurrentTheme(false);
  }
  new MutationObserver(function () { applyForCurrentTheme(true); }).observe(document.documentElement, {
    attributes: true,
    attributeFilter: [THEME_ATTR],
  });
})();
