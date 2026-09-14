// Decorative header light (hangs from macros/ui.html's page_header() bar -- Settings/Chat
// settings/Tools/Toolkit) -- Settings -> Customization -> Header light. Purely cosmetic, same
// client-only convention as asra-theme and asra-mascot-skin (no server round-trip, no settings.py
// plumbing): every choice lives in localStorage and is re-applied here on load. Three styles exist
// in CSS (pendant lamp, garland, comet) sharing the same custom properties (static/css/themes.css's
// .header-light rules), but only "bulb" ships selectable right now -- see AVAILABLE_STYLES below --
// this file only ever toggles attributes/custom properties, it never swaps markup, since all three
// styles' DOM is always present (templates/macros/header_light.html) and CSS shows just one.
(function () {
  var KEY_ENABLED = "asra-header-light-enabled";
  var KEY_STYLE = "asra-header-light-style";
  var KEY_COLOR_MODE = "asra-header-light-color-mode";
  var KEY_COLOR = "asra-header-light-color";
  var KEY_TEMPERATURE = "asra-header-light-temperature";
  var KEY_SPEED = "asra-header-light-speed";
  var KEY_INTENSITY = "asra-header-light-intensity";
  var KEY_POSITION = "asra-header-light-position";
  var KEY_SPREAD = "asra-header-light-spread";
  var KEY_LIT = "asra-header-light-lit";

  var DEFAULTS = {
    enabled: "true",
    style: "bulb",
    colorMode: "auto",
    color: "#58a6ff",
    temperature: "4000",
    speed: "3",
    intensity: "60",
    position: "68",
    spread: "100",
    lit: "true",
  };

  // Settings' own Random/Reset buttons (settings.html) read this instead of hardcoding a second
  // copy of these values -- one source of truth for "what does this feature look like out of the
  // box."
  window.asraHeaderLightDefaults = DEFAULTS;

  function read(key, fallback) {
    var val = localStorage.getItem(key);
    return val === null ? fallback : val;
  }

  // Real incandescent/LED color-temperature stops (Kelvin -> sRGB), the same warm-to-cold range
  // Settings -> Customization -> Header light's own reference picture shows (2000K candle-warm through 8000K
  // cold-blue daylight). Linear-interpolated between neighboring stops rather than a full
  // black-body radiation formula -- plenty accurate at this size, and it's guaranteed to match the
  // picture's own labeled colors exactly at each stop instead of drifting from it.
  var TEMPERATURE_STOPS = [
    [2000, [255, 137, 18]],
    [2700, [255, 169, 87]],
    [3000, [255, 180, 107]],
    [3500, [255, 196, 137]],
    [4000, [255, 209, 163]],
    [5000, [255, 228, 206]],
    [6000, [255, 243, 239]],
    [6500, [255, 249, 253]],
    [8000, [227, 233, 255]],
  ];

  function componentToHex(value) {
    return Math.max(0, Math.min(255, Math.round(value))).toString(16).padStart(2, "0");
  }

  // Exposed so settings.html's own Kelvin slider can paint its live swatch/label from the exact
  // same table this file applies to the real header light, instead of a second copy that could
  // drift from it.
  window.asraKelvinToHex = function (kelvin) {
    var k = Math.max(2000, Math.min(8000, kelvin));
    for (var i = 0; i < TEMPERATURE_STOPS.length - 1; i++) {
      var lo = TEMPERATURE_STOPS[i], hi = TEMPERATURE_STOPS[i + 1];
      if (k >= lo[0] && k <= hi[0]) {
        var t = (k - lo[0]) / (hi[0] - lo[0]);
        var r = lo[1][0] + (hi[1][0] - lo[1][0]) * t;
        var g = lo[1][1] + (hi[1][1] - lo[1][1]) * t;
        var b = lo[1][2] + (hi[1][2] - lo[1][2]) * t;
        return "#" + componentToHex(r) + componentToHex(g) + componentToHex(b);
      }
    }
    return "#ffffff";
  };

  // Exposed so settings.html's own "Random" button (Header light -> Color) can roll a fresh Fixed
  // color -- fixed saturation/lightness (70%/58%) so every roll lands vivid and readable instead of
  // a fully random RGB that could just as easily come out muddy brown or near-invisible dark.
  window.asraHslToHex = function (h, s, l) {
    s /= 100;
    l /= 100;
    var c = (1 - Math.abs(2 * l - 1)) * s;
    var x = c * (1 - Math.abs(((h / 60) % 2) - 1));
    var m = l - c / 2;
    var r = 0, g = 0, b = 0;
    if (h < 60) { r = c; g = x; b = 0; }
    else if (h < 120) { r = x; g = c; b = 0; }
    else if (h < 180) { r = 0; g = c; b = x; }
    else if (h < 240) { r = 0; g = x; b = c; }
    else if (h < 300) { r = x; g = 0; b = c; }
    else { r = c; g = 0; b = x; }
    return "#" + componentToHex((r + m) * 255) + componentToHex((g + m) * 255) + componentToHex((b + m) * 255);
  };

  // Exposed so settings.html's own controls can re-paint the real header elements the instant
  // something changes, instead of only taking effect after the next full page load -- same "live
  // visual feedback" requirement as the clock-style picker/theme picker right above it.
  // Only "bulb" ships for real right now -- garland/comet are drawn in CSS but sit disabled
  // ("Soon") in Settings' own style picker. Clamp here too so a value saved by an earlier build
  // (or hand-edited in devtools) can't make the real header render a style nobody can pick anymore.
  var AVAILABLE_STYLES = ["bulb"];

  // The app's only two light-background themes (static/css/themes.css's own :root[data-theme]
  // blocks -- every other theme's --surface resolves dark). Kept in sync with that file's matching
  // ":root[data-theme=\"light\"], :root[data-theme=\"snow\"]" selectors below (.hl-pool's blend-mode
  // override) -- both lists exist because of the SAME fact (these two themes paint a near-white
  // bar) and must be edited together if a new light theme is ever added.
  var LIGHT_BG_THEMES = ["light", "snow"];

  window.asraHeaderLightApply = function () {
    var enabled = read(KEY_ENABLED, DEFAULTS.enabled) === "true";
    var style = read(KEY_STYLE, DEFAULTS.style);
    if (AVAILABLE_STYLES.indexOf(style) === -1) style = DEFAULTS.style;
    var colorMode = read(KEY_COLOR_MODE, DEFAULTS.colorMode);
    var speed = parseFloat(read(KEY_SPEED, DEFAULTS.speed)) || 3;
    var intensity = parseInt(read(KEY_INTENSITY, DEFAULTS.intensity), 10) || 60;
    // A full-strength glow reads as a smudge on the near-white bar these two themes paint --
    // real, confirmed bug this fixes: a CSS-only ":root[data-theme=\"light\"] { --hl-glow: 0.3 }"
    // override used to sit in themes.css for exactly this, but it never actually applied -- the
    // line right below sets --hl-glow as an INLINE style on the same elements, and inline style
    // always wins over any stylesheet rule for the same property on the same element, so that CSS
    // override was dead code from the day it was written. Scaling the operator's own Intensity
    // slider here, in the one place that actually wins the cascade, is what makes the dimming real.
    var isLightBg = LIGHT_BG_THEMES.indexOf(document.documentElement.dataset.theme || "") !== -1;
    if (isLightBg) intensity *= 0.5;
    var position = parseFloat(read(KEY_POSITION, DEFAULTS.position));
    if (isNaN(position)) position = parseFloat(DEFAULTS.position);
    var spread = parseFloat(read(KEY_SPREAD, DEFAULTS.spread));
    if (isNaN(spread)) spread = parseFloat(DEFAULTS.spread);
    var lit = read(KEY_LIT, DEFAULTS.lit) === "true";

    // "temperature" reuses --hl-color/the "fixed" flat-color CSS path (static/css/themes.css) --
    // it's just a different, physically-grounded way to arrive at one fixed color, computed here
    // instead of picked from a raw hex swatch.
    var color = colorMode === "temperature"
      ? window.asraKelvinToHex(parseInt(read(KEY_TEMPERATURE, DEFAULTS.temperature), 10) || 4000)
      : read(KEY_COLOR, DEFAULTS.color);

    document.querySelectorAll("[data-header-light]").forEach(function (el) {
      el.hidden = !enabled;
      el.dataset.style = style;
      el.dataset.colorMode = colorMode;
      el.dataset.lit = String(lit);
      el.style.setProperty("--hl-color", color);
      el.style.setProperty("--hl-speed", speed + "s");
      el.style.setProperty("--hl-glow", String(intensity / 100));
      el.style.setProperty("--hl-x", position + "%");
      el.style.setProperty("--hl-spread", String(spread / 100));
    });
  };

  document.addEventListener("DOMContentLoaded", window.asraHeaderLightApply);

  // Real, confirmed bug this fixes: since .header-light-fixture's clickable icon (themes.css) now
  // sits in NORMAL stacking (needed so it can receive clicks at all -- see that file's own comment
  // on why), a mousedown that starts there is a mousedown like any other, and the browser's default
  // behavior for ANY mousedown is to arm a text-selection drag -- reported live as clicking the lamp
  // selecting unrelated page text (a heading far below the bar, nowhere near the lamp) on every tab.
  // preventDefault() on "click" (below) fires too late to stop this: mousedown is what arms
  // selection, click only fires after mouseup, by which point the drag/selection already happened.
  // The standard, well-established fix is exactly this -- preventDefault() on mousedown itself, the
  // same technique every drag-and-drop/resize handle uses to stay text-selection-safe.
  document.addEventListener("mousedown", function (event) {
    if (event.target.closest("[data-header-light]")) event.preventDefault();
  }, true);

  // Click-to-toggle "lit" state -- the "переключатель"/pull-cord part of the feature, purely
  // cosmetic and independent of the real enabled/disabled setting. Delegated on document (survives
  // htmx swaps) with preventDefault/stopPropagation: page_header()'s bar has no link/button of its
  // own here, but this stays defensive in case that ever changes.
  document.addEventListener("click", function (event) {
    var el = event.target.closest("[data-header-light]");
    if (!el) return;
    event.preventDefault();
    event.stopPropagation();
    var lit = read(KEY_LIT, DEFAULTS.lit) === "true";
    localStorage.setItem(KEY_LIT, String(!lit));
    if (window.asraDebugEvent) window.asraDebugEvent("header-light-toggle", "lit -> " + String(!lit));
    if (window.asraPlayEventSound) window.asraPlayEventSound("header_light_toggle");
    window.asraHeaderLightApply();
  }, true);
})();
