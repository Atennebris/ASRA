// Mini sound-notification system -- every tone is synthesized on the fly via the Web Audio API,
// no audio files anywhere (see agent/sound_settings.py's own docstring for why: no licensed
// samples in this repo, adding third-party mp3/wav would be dead weight and a licensing question).
// Everything defaults to OFF -- window.ASRA_SOUND_SETTINGS (base.html, from
// agent/sound_settings.py's load_sound_settings()) starts with master_enabled=false and every
// event disabled until the operator turns something on from Settings -> Customization -> Sounds.
(function () {
  var SOUND_VOLUME = 0.35; // One shared gain for every profile -- no per-event volume control
                            // exists (nobody asked for it, YAGNI), just this one comfortable level.

  var AudioContextClass = window.AudioContext || window.webkitAudioContext;
  var ctx = null;
  function getContext() {
    if (!AudioContextClass) return null;
    if (!ctx) ctx = new AudioContextClass();
    if (ctx.state === "suspended") ctx.resume().catch(function () {});
    return ctx;
  }
  // Chrome/Safari refuse to run an AudioContext until a real user gesture has happened anywhere on
  // the page -- pre-warm it on the first click/keydown so the FIRST real notification (which can
  // fire off a background SSE tick with no gesture of its own behind it) isn't silently swallowed.
  ["click", "keydown"].forEach(function (type) {
    document.addEventListener(type, function warm() {
      getContext();
      document.removeEventListener(type, warm, true);
    }, true);
  });

  // freqEnd (optional): an exponential frequency ramp from freq to freqEnd over `duration` --
  // what turns a flat beep into a siren/sweep/drop, used by the sweep-based profiles below.
  function tone(t0, freq, duration, type, gainScale, freqEnd) {
    var audioCtx = getContext();
    if (!audioCtx) return;
    var osc = audioCtx.createOscillator();
    var gain = audioCtx.createGain();
    osc.type = type || "sine";
    osc.frequency.setValueAtTime(freq, t0);
    if (freqEnd != null) osc.frequency.exponentialRampToValueAtTime(Math.max(freqEnd, 1), t0 + duration);
    var peak = SOUND_VOLUME * (gainScale == null ? 1 : gainScale);
    gain.gain.setValueAtTime(0, t0);
    gain.gain.linearRampToValueAtTime(peak, t0 + 0.008);
    gain.gain.exponentialRampToValueAtTime(0.001, t0 + duration);
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    osc.start(t0);
    osc.stop(t0 + duration + 0.02);
  }

  // One shared white-noise buffer (regenerated only once per AudioContext, cheap: a fraction of a
  // second of random samples) that every noiseBurst() call below slices via a fresh
  // AudioBufferSourceNode -- the raw material behind the "glitch"/"critical"/"terminal_click"
  // profiles' static/click textures, which a pure oscillator can't produce on its own.
  var noiseBufferCache = null;
  function getNoiseBuffer(audioCtx) {
    if (noiseBufferCache) return noiseBufferCache;
    var length = Math.ceil(audioCtx.sampleRate * 0.5);
    var buffer = audioCtx.createBuffer(1, length, audioCtx.sampleRate);
    var data = buffer.getChannelData(0);
    for (var i = 0; i < length; i++) data[i] = Math.random() * 2 - 1;
    noiseBufferCache = buffer;
    return buffer;
  }

  // filterFreqEnd (optional): sweeps the filter's own cutoff/center from filterFreq to
  // filterFreqEnd over `duration` -- e.g. a "radio tuning through static" swell, used by
  // static_swell below (glitch/critical/terminal_click all leave it unset, a fixed filter).
  function noiseBurst(t0, duration, gainScale, filterFreq, filterType, filterQ, filterFreqEnd) {
    var audioCtx = getContext();
    if (!audioCtx) return;
    var src = audioCtx.createBufferSource();
    src.buffer = getNoiseBuffer(audioCtx);
    var filter = audioCtx.createBiquadFilter();
    filter.type = filterType || "bandpass";
    filter.frequency.setValueAtTime(filterFreq || 2000, t0);
    if (filterFreqEnd != null) filter.frequency.exponentialRampToValueAtTime(Math.max(filterFreqEnd, 1), t0 + duration);
    filter.Q.value = filterQ == null ? 1 : filterQ;
    var gain = audioCtx.createGain();
    var peak = SOUND_VOLUME * (gainScale == null ? 1 : gainScale);
    gain.gain.setValueAtTime(0, t0);
    gain.gain.linearRampToValueAtTime(peak, t0 + 0.004);
    gain.gain.exponentialRampToValueAtTime(0.001, t0 + duration);
    src.connect(filter);
    filter.connect(gain);
    gain.connect(audioCtx.destination);
    src.start(t0);
    src.stop(t0 + duration + 0.02);
  }

  // Keys here MUST match agent/sound_settings.py's own SOUND_PROFILES tuple -- that's the only
  // place profile ids are validated server-side. Each profile is a short (<0.6s) sequence of
  // tone()/noiseBurst() calls relative to "now" so several firing close together never stack into
  // real noise. Grows by ADDING, never by removing/renaming an id -- see agent/sound_settings.py's
  // own SOUND_PROFILES comment for the real incident this rule exists because of. Three batches
  // that all coexist: the original plain six (chime/ping/success/alert/pop/error), a first "hacker
  // terminal" pass (access_granted..terminal_click), and a punchier second pass
  // (laser_zap..encrypted_ping) -- an operator request for more character/danger/impact on top of,
  // not instead of, what was already there.
  var SOUND_PROFILES = {
    chime: function (t0) { tone(t0, 880, 0.18, "sine"); tone(t0 + 0.1, 1318.5, 0.22, "sine"); },
    ping: function (t0) { tone(t0, 1568, 0.14, "sine", 0.8); },
    success: function (t0) { tone(t0, 659.3, 0.12, "sine"); tone(t0 + 0.09, 830.6, 0.12, "sine"); tone(t0 + 0.18, 1046.5, 0.22, "sine"); },
    alert: function (t0) { tone(t0, 740, 0.12, "square", 0.5); tone(t0 + 0.16, 740, 0.12, "square", 0.5); },
    pop: function (t0) { tone(t0, 300, 0.06, "sine", 0.6); },
    error: function (t0) { tone(t0, 415, 0.14, "sawtooth", 0.5); tone(t0 + 0.13, 220, 0.2, "sawtooth", 0.5); },
    // Bright ascending confirm arpeggio + a crisp high "lock" blip -- "you're in" feel.
    access_granted: function (t0) {
      tone(t0, 523.3, 0.09, "square", 0.35);
      tone(t0 + 0.07, 659.3, 0.09, "square", 0.35);
      tone(t0 + 0.14, 987.8, 0.16, "sine", 0.6);
      tone(t0 + 0.14, 1975.5, 0.1, "sine", 0.25);
    },
    // Two alternating up/down frequency sweeps -- a real klaxon/siren shape, not a flat double-beep.
    breach_alert: function (t0) {
      tone(t0, 500, 0.14, "sawtooth", 0.55, 900);
      tone(t0 + 0.16, 900, 0.14, "sawtooth", 0.55, 500);
      tone(t0 + 0.32, 500, 0.14, "sawtooth", 0.55, 900);
    },
    // Harsh downward-sweeping dissonant tone plus a burst of low static underneath it.
    critical: function (t0) {
      tone(t0, 440, 0.22, "sawtooth", 0.5, 130);
      noiseBurst(t0 + 0.02, 0.18, 0.35, 500, "lowpass", 0.7);
    },
    // Stuttering filtered noise micro-clicks, rising in pitch -- signal-interference/terminal-error
    // texture, deliberately not a clean tone at all.
    glitch: function (t0) {
      [0, 0.05, 0.085, 0.14].forEach(function (offset, i) {
        noiseBurst(t0 + offset, 0.03, i % 2 ? 0.5 : 0.7, 1800 + i * 600, "bandpass", 6);
      });
    },
    // Three deep pulses building into a low sawtooth drop -- ominous, "this needs you right now".
    intrusion: function (t0) {
      [0, 0.14, 0.28].forEach(function (offset) { tone(t0 + offset, 220, 0.1, "square", 0.45); });
      tone(t0 + 0.34, 165, 0.22, "sawtooth", 0.4);
    },
    // Fast ascending run of five short blips -- data scrolling past, a discovery/exfil feel.
    data_stream: function (t0) {
      [660, 784, 932, 1109, 1319].forEach(function (freq, i) { tone(t0 + i * 0.045, freq, 0.05, "square", 0.4); });
    },
    // Two dry, high-pass-filtered clicks -- a mechanical keystroke, subtle enough for a chat reply.
    terminal_click: function (t0) {
      noiseBurst(t0, 0.02, 0.5, 3200, "highpass", 3);
      noiseBurst(t0 + 0.05, 0.02, 0.4, 2600, "highpass", 3);
    },
    // Fast, high-pitched descending sweep -- a classic sci-fi laser-zap.
    laser_zap: function (t0) { tone(t0, 3000, 0.12, "sawtooth", 0.5, 180); },
    // Low-to-high rising sweep -- a device/system "powering up" feel.
    power_up: function (t0) { tone(t0, 150, 0.35, "square", 0.45, 1200); },
    // Single heavy low-frequency thump + a short crack of noise underneath -- meant to feel
    // physical, not just loud.
    impact_hit: function (t0) {
      tone(t0, 90, 0.28, "sine", 0.85, 35);
      noiseBurst(t0, 0.05, 0.6, 800, "lowpass", 0.8);
    },
    // Three descending urgent beeps -- countdown-timer tension.
    countdown: function (t0) {
      tone(t0, 880, 0.08, "square", 0.5);
      tone(t0 + 0.18, 740, 0.08, "square", 0.5);
      tone(t0 + 0.36, 622, 0.16, "square", 0.6);
    },
    // One long noise swell with the filter itself sweeping upward -- "radio tuning through static",
    // a very different texture from glitch's short stutter or critical's fixed-filter grit.
    static_swell: function (t0) { noiseBurst(t0, 0.32, 0.45, 400, "bandpass", 4, 4200); },
    // Two near-identical detuned oscillators beating against each other -- a metallic, "encrypted
    // signal" shimmer, plus a brief high overtone.
    encrypted_ping: function (t0) {
      tone(t0, 1200, 0.22, "sine", 0.35);
      tone(t0, 1218, 0.22, "sine", 0.35);
      tone(t0 + 0.02, 1600, 0.14, "sine", 0.2);
    },
  };

  function playProfile(profileId) {
    var audioCtx = getContext();
    var play = SOUND_PROFILES[profileId];
    if (!audioCtx || !play) return;
    play(audioCtx.currentTime);
  }
  // Settings -> Customization -> Sounds' own "Test" button per row -- always plays regardless of the master/event
  // enabled state, so an operator can preview a sound before ever turning its event on.
  window.asraPreviewSound = playProfile;

  function playEventSound(eventId) {
    var settings = window.ASRA_SOUND_SETTINGS;
    if (!settings || !settings.master_enabled) return;
    var event = settings.events && settings.events[eventId];
    if (!event || !event.enabled) return;
    playProfile(event.sound);
  }
  // Exposed so scripts outside this closure (header_light.js's click-to-toggle handler) can fire a
  // registered event's sound through the same master/per-event gating as the MutationObserver-driven
  // events below, instead of duplicating the enabled/master checks.
  window.asraPlayEventSound = playEventSound;

  // Lets settings.html's own toggle/select onchange handlers mutate this in place -- same "the
  // real effect shows up live, not just after a reload" rule as every other Settings toggle in
  // this app, the audible equivalent of it: flipping
  // a sound on/off or switching its profile takes effect for the very next event, same tab,
  // without a refresh.
  window.asraSoundSettings = {
    setMasterEnabled: function (enabled) {
      if (window.ASRA_SOUND_SETTINGS) window.ASRA_SOUND_SETTINGS.master_enabled = enabled;
    },
    setEvent: function (eventId, enabled, sound) {
      if (!window.ASRA_SOUND_SETTINGS) return;
      if (!window.ASRA_SOUND_SETTINGS.events) window.ASRA_SOUND_SETTINGS.events = {};
      window.ASRA_SOUND_SETTINGS.events[eventId] = { enabled: enabled, sound: sound };
    },
  };

  // ---- Event detection ---------------------------------------------------------------------
  // #session-content (partials/session_fragment.html) already carries data-status/
  // data-findings-count for other client scripts -- session.html's #session-stream morphs only
  // this node's CHILDREN (hx-swap="morph:innerHTML"), so idiomorph patches #session-content's own
  // attributes in place on every SSE tick rather than replacing the node. A MutationObserver
  // attached once at DOMContentLoaded therefore survives every future update; no per-tick
  // re-attachment needed.
  var TERMINAL_STATUSES = ["completed", "failed", "interrupted"];

  function watchSessionContent() {
    var el = document.getElementById("session-content");
    if (!el) return;
    var lastStatus = el.getAttribute("data-status");
    var lastFindings = parseInt(el.getAttribute("data-findings-count") || "0", 10);
    new MutationObserver(function () {
      var status = el.getAttribute("data-status");
      var findings = parseInt(el.getAttribute("data-findings-count") || "0", 10);
      if (findings > lastFindings) playEventSound("finding");
      if (status !== lastStatus) {
        if (status === "awaiting_approval") playEventSound("approval_needed");
        else if (TERMINAL_STATUSES.indexOf(status) !== -1) playEventSound("session_done");
      }
      lastStatus = status;
      lastFindings = findings;
    }).observe(el, { attributes: true, attributeFilter: ["data-status", "data-findings-count"] });
  }

  // #chat-messages (partials/chat_messages.html) carries data-message-count/data-last-role/
  // data-thread-id, same in-place morph target as above (chat_panel.html's #chat-stream). Tracking
  // data-thread-id too, not just count, matters: switching to a DIFFERENT thread also bumps the
  // count (a longer thread has more messages than whatever was showing before) with no new reply
  // having actually arrived -- resetting the baseline on a thread-id change (without firing)
  // avoids that false positive; only a genuine append within the SAME thread counts.
  function watchChatMessages() {
    var el = document.getElementById("chat-messages");
    if (!el) return;
    var lastThreadId = el.getAttribute("data-thread-id");
    var lastCount = parseInt(el.getAttribute("data-message-count") || "0", 10);
    new MutationObserver(function () {
      var threadId = el.getAttribute("data-thread-id");
      var count = parseInt(el.getAttribute("data-message-count") || "0", 10);
      var lastRole = el.getAttribute("data-last-role");
      if (threadId === lastThreadId && count > lastCount && lastRole === "assistant") {
        playEventSound("chat_reply");
      }
      lastThreadId = threadId;
      lastCount = count;
    }).observe(el, { attributes: true, attributeFilter: ["data-message-count", "data-last-role", "data-thread-id"] });
  }

  window.asraOnDomReady(function () {
    watchSessionContent();
    watchChatMessages();
  });
})();
