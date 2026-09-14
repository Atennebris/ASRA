// Custom confirm dialog (base.html's #asra-confirm-modal) replacing the native browser confirm()
// popup -- consistent with every other <dialog> in this app (New project, Edit subagent,
// per-finding detail) instead of an unstyled, inconsistent browser default.
//
// window.asraConfirm(opts) -> Promise<boolean>, resolved true on Confirm, false on
// Cancel/Esc/backdrop-click. window.asraConfirmSubmit(event, opts) is the common case: block a
// form's normal submit until the promise resolves, then submit it for real if confirmed.
(function () {
  var DANGER_CLASSES = ["bg-severity-high/10", "text-severity-high", "border-severity-high/20", "hover:bg-severity-high/20"];
  var PRIMARY_CLASSES = ["bg-accent", "hover:bg-accent-hover", "text-white"];
  var dialog, titleEl, messageEl, okBtn, cancelBtn;
  var checkboxRow, checkboxInput, checkboxLabelEl;
  var initialized = false;
  var current = null; // {resolve, result} for whichever confirmation is showing right now
  var queuedNext = null; // {opts, resolve} waiting for the CURRENT one to actually finish closing

  // Confirmed live bug this design replaced (found via a real rapid-click reproduction, not just
  // reasoning about the code): HTMLDialogElement.close() queues its "close" event as a genuine
  // browser TASK, not synchronously -- so a previous asraConfirm() call's close() (from Confirm,
  // Cancel, or reusing the dialog for a chained second confirmation) can still have a "close"
  // event PENDING in the task queue at the exact moment a NEW call attaches its own fresh "close"
  // listener to the same shared <dialog> element. Nothing scopes a queued DOM event to "which JS
  // call" originally triggered it -- whichever listener is attached when the task finally runs
  // catches it. With a listener added-then-removed per call (an earlier version of this file),
  // that stale event got delivered to the NEW call's own listener instead, which read it as a
  // real Cancel and silently tore the new confirmation back down moments after it opened -- every
  // further rapid click just repeated the same race, and it looked exactly like a permanently
  // unresponsive dialog. The fix: attach the click/close listeners exactly ONCE, for the whole
  // page's lifetime, never re-attached per call -- there is then only ever one thing that could
  // possibly receive a "close" event, so a stale queued one from an earlier call is handled by
  // the exact same logic that would have handled it on time, not misattributed to something else.
  function init() {
    if (initialized) return true;
    dialog = document.getElementById("asra-confirm-modal");
    titleEl = document.getElementById("asra-confirm-title");
    messageEl = document.getElementById("asra-confirm-message");
    okBtn = document.getElementById("asra-confirm-ok");
    cancelBtn = document.getElementById("asra-confirm-cancel");
    checkboxRow = document.getElementById("asra-confirm-checkbox-row");
    checkboxInput = document.getElementById("asra-confirm-checkbox");
    checkboxLabelEl = document.getElementById("asra-confirm-checkbox-label");
    if (!dialog || !titleEl || !messageEl || !okBtn || !cancelBtn) return false;

    okBtn.addEventListener("click", function () {
      if (current) {
        current.result = true;
        current.checked = !!(checkboxInput && checkboxInput.checked);
      }
      dialog.close();
    });
    cancelBtn.addEventListener("click", function () {
      if (current) current.result = false;
      dialog.close();
    });
    // Fires for every way the dialog can close: Confirm, Cancel, Escape, or a backdrop click --
    // "result" already defaults to false (set in reallyShow), so anything that closes it without
    // going through the Confirm button resolves as Cancel automatically.
    dialog.addEventListener("close", function () {
      var finishing = current;
      current = null;
      if (finishing) {
        // Callers that never asked for a checkbox (the overwhelming majority) keep getting a plain
        // boolean, exactly as before -- only a call that passed opts.checkboxLabel gets the richer
        // {confirmed, checked} shape, so this never breaks an existing asraConfirm(...).then(bool).
        finishing.resolve(finishing.hasCheckbox ? { confirmed: finishing.result, checked: !!finishing.checked } : finishing.result);
      }
      if (queuedNext) {
        var next = queuedNext;
        queuedNext = null;
        next.resolve(reallyShow(next.opts));
      }
    });

    initialized = true;
    return true;
  }

  function reallyShow(opts) {
    titleEl.textContent = opts.title || "Are you sure?";
    messageEl.textContent = opts.message || "";
    okBtn.textContent = opts.confirmLabel || "Confirm";
    okBtn.classList.remove.apply(okBtn.classList, DANGER_CLASSES.concat(PRIMARY_CLASSES));
    okBtn.classList.add.apply(okBtn.classList, opts.danger === false ? PRIMARY_CLASSES : DANGER_CLASSES);
    if (checkboxRow && checkboxInput && checkboxLabelEl) {
      if (opts.checkboxLabel) {
        checkboxLabelEl.textContent = opts.checkboxLabel;
        checkboxInput.checked = false;
        checkboxRow.hidden = false;
      } else {
        // Reset the label/checked state here too, not just hidden -- this single row is reused by
        // EVERY confirmation in the app, so a call that passes no checkboxLabel at all must leave
        // it exactly as blank/unchecked as a call that never existed, not carrying over whatever a
        // PREVIOUS checkboxLabel call last left in these same two fields (see the [hidden] fix in
        // themes.css for why that stale state was ever visible to begin with).
        checkboxRow.hidden = true;
        checkboxInput.checked = false;
        checkboxLabelEl.textContent = "";
      }
    }
    return new Promise(function (resolve) {
      current = { resolve: resolve, result: false, checked: false, hasCheckbox: !!opts.checkboxLabel };
      dialog.showModal();
    });
  }

  // opts.checkboxLabel (optional): shows a single opt-out checkbox above the buttons and changes
  // the resolved value from a plain boolean to {confirmed, checked} -- see the "close" listener
  // above. Callers that don't pass it are completely unaffected (still get a plain boolean).
  window.asraConfirm = function (opts) {
    opts = opts || {};
    // Fail open (never silently block a real action) if the shared dialog markup is ever missing.
    if (!init()) return Promise.resolve(true);

    if (dialog.open) {
      // Something is already showing (a chained confirmation's next step, or an impatient
      // double-click on the trigger button) -- queue this request and force-close the current
      // one; the persistent "close" listener above shows this one the moment the browser
      // confirms the previous one has actually finished closing, never racing it.
      return new Promise(function (resolve) {
        queuedNext = { opts: opts, resolve: resolve };
        dialog.close();
      });
    }
    return reallyShow(opts);
  };

  window.asraConfirmSubmit = function (event, opts) {
    event.preventDefault();
    var form = event.target;
    window.asraConfirm(opts).then(function (confirmed) {
      if (confirmed) form.submit();
    });
    return false;
  };

  // Two genuinely separate confirmations, chained -- for an action too destructive for even the
  // usual single confirm (Projects tab's "Delete all"). The second dialog only ever opens once
  // the first is confirmed; declining either resolves false.
  window.asraConfirmTwoStep = function (firstOpts, secondOpts) {
    return window.asraConfirm(firstOpts).then(function (confirmed) {
      return confirmed ? window.asraConfirm(secondOpts) : false;
    });
  };

  // Projects list's per-row Delete (sessions_list_fragment.html) -- reads the project's own
  // name/target from data-* attributes (plain HTML-attribute values, never re-parsed as JS
  // source) and builds the confirm message here in real JS, instead of the template interpolating
  // the name/target directly into an onsubmit="..." JS-source string. Real incident this
  // prevents: this list polls every 5s and rows commonly re-sort as their own status changes, so
  // a click can land on a different project's Delete button than the one the operator was
  // actually looking at moments earlier -- naming the real target in the confirm dialog is what
  // catches that before a real, unrecoverable delete_session() runs; interpolating it unescaped
  // into a JS string would also let a project name containing a genuine apostrophe/quote (a
  // realistic bug-bounty program name) break the handler outright.
  window.asraConfirmDeleteProject = function (event) {
    var form = event.target;
    var name = form.dataset.projectName || "this project";
    var target = form.dataset.projectTarget || "";
    var message = "Delete “" + name + "”" + (target ? " (" + target + ")" : "")
      + "? This cannot be undone — the project folder, its findings, and its logs are all removed.";
    return window.asraConfirmSubmit(event, { title: "Delete this project?", message: message, confirmLabel: "Delete" });
  };

  // Every other <dialog> in this app (New project, Edit subagent, per-finding detail) is opened
  // via a plain inline onclick="document.getElementById('x').showModal()" -- calling showModal()
  // on a dialog that's already open throws. Cheap, safe insurance: skip the call outright if
  // already open, instead of ever attempting a second showModal().
  window.asraOpenDialog = function (id) {
    var dlg = document.getElementById(id);
    if (dlg && !dlg.open) dlg.showModal();
  };

  // Rescan's own 3-choice dialog (base.html's #asra-rescan-modal, triggered from
  // session_fragment.html's Rescan button) -- sets both forms' own action URL to this specific
  // session's real rescan/rescan-in-place routes right before opening, since the shared dialog
  // markup itself has no session_id of its own to render server-side (it lives in base.html,
  // outside session_fragment.html's own SSE-morphed subtree, same placement every other dialog on
  // this page already uses).
  // Copies the dialog's own Goal/Time-budget inputs into BOTH forms' hidden mirrors -- a plain
  // input can only ever belong to one <form>, so this is what makes whichever button the operator
  // actually clicks (New project vs Same project) submit the same current values either way.
  // Called on every edit (oninput/onchange on the visible controls) and once up front by
  // asraOpenRescanDialog right after it prefills them, since a programmatic .value= set doesn't
  // itself fire those events.
  window.asraSyncRescanExtras = function () {
    var goalInput = document.getElementById("asra-rescan-goal-input");
    var presetSelect = document.getElementById("asra-rescan-time-budget-preset");
    var customMinutesInput = document.getElementById("asra-rescan-time-budget-custom-minutes");
    ["asra-rescan-new-project-form", "asra-rescan-in-place-form"].forEach(function (formId) {
      var form = document.getElementById(formId);
      if (!form) return;
      if (goalInput) form.querySelector("input[name=goal]").value = goalInput.value;
      if (presetSelect) form.querySelector("input[name=time_budget_preset]").value = presetSelect.value;
      if (customMinutesInput) form.querySelector("input[name=time_budget_custom_minutes]").value = customMinutesInput.value;
    });
  };

  // currentGoal/currentTimeBudgetSeconds: the project's own session.goal/time_budget_seconds
  // right now (session_fragment.html's own Rescan button passes both via | tojson, same escaping
  // convention settings.html already uses for a Jinja value embedded in an onclick attribute) --
  // prefills the dialog so rescanning an old project that predates these fields, or updating a
  // stale value, doesn't require retyping from scratch. Genuinely editable/clearable here, not
  // just a read-only echo.
  window.asraOpenRescanDialog = function (sessionId, currentGoal, currentTimeBudgetSeconds) {
    var newProjectForm = document.getElementById("asra-rescan-new-project-form");
    var inPlaceForm = document.getElementById("asra-rescan-in-place-form");
    var goalInput = document.getElementById("asra-rescan-goal-input");
    var presetSelect = document.getElementById("asra-rescan-time-budget-preset");
    var customRow = document.getElementById("asra-rescan-time-budget-custom-row");
    var customMinutesInput = document.getElementById("asra-rescan-time-budget-custom-minutes");
    if (!newProjectForm || !inPlaceForm) return;
    newProjectForm.action = "/api/session/" + sessionId + "/rescan";
    inPlaceForm.action = "/api/session/" + sessionId + "/rescan-in-place";
    if (goalInput) goalInput.value = currentGoal || "";
    if (presetSelect && customRow && customMinutesInput) {
      // Same fixed-preset seconds as base.html's own <option value=...> list -- a value that
      // doesn't exactly match one of these (or is unset) falls back to "custom" with its minutes
      // spelled out, same as a plain refresh of the New Project form itself would never need to
      // do (it always starts blank) but this dialog, prefilling from a REAL existing value, does.
      var fixedPresetSeconds = ["1800", "3600", "7200", "14400", "28800"];
      var seconds = currentTimeBudgetSeconds || null;
      if (seconds && fixedPresetSeconds.indexOf(String(seconds)) !== -1) {
        presetSelect.value = String(seconds);
        customMinutesInput.value = "";
        customRow.classList.add("hidden");
      } else if (seconds) {
        presetSelect.value = "custom";
        customMinutesInput.value = String(Math.round(seconds / 60));
        customRow.classList.remove("hidden");
      } else {
        presetSelect.value = "";
        customMinutesInput.value = "";
        customRow.classList.add("hidden");
      }
    }
    window.asraSyncRescanExtras();
    window.asraOpenDialog("asra-rescan-modal");
  };

  // Real, confirmed bug this closes: the Stop-session button (session_fragment.html) uses htmx's
  // OWN hx-confirm attribute, not asraConfirmSubmit -- hx-confirm's default behavior is a raw
  // window.confirm() (the "127.0.0.1:8000 says..." OS-drawn popup an operator screenshotted, not
  // this app's own styled dialog), because it's a genuinely different mechanism from a plain form
  // onsubmit. The module comment above claiming this file "replaces the native browser confirm()
  // popup everywhere in this app" was true for every plain-form case it lists, but never actually
  // covered hx-confirm at all until now.
  //
  // htmx dispatches a cancelable "htmx:confirm" event before EVERY request it's about to issue
  // (hx-confirm present or not) -- evt.detail.question is the hx-confirm text when present, null
  // otherwise. Hooking this once, globally, is what htmx's own docs recommend for replacing the
  // default confirm() with a custom dialog: preventDefault() stops htmx's own built-in
  // window.confirm() call, and evt.detail.issueRequest(true) resumes the request once our own
  // dialog resolves. An element with no hx-confirm at all (question is null/empty) is left
  // completely untouched -- this must never block a request that never asked to be confirmed.
  //
  // Real, explicit operator ask: repeatedly deleting several chat tabs in a row (or any other
  // hx-confirm-backed delete) shouldn't mean clicking Confirm once per tab -- the exact same
  // "Don't ask again for the rest of this session" checkbox settings.html's own fallback-chain
  // Remove button already uses (asraConfirm's opts.checkboxLabel/result.checked), just wired
  // through hx-confirm generically instead of a bespoke per-page click handler: any hx-confirm
  // element opts in by adding data-confirm-checkbox-key (a string identifying WHICH confirmation
  // this is, shared across every surface that should agree on one skip decision -- e.g. the chat
  // tab strip and the chat history dialog's own delete button both use "chat-delete-thread", so
  // checking it in either suppresses both) and, optionally, data-confirm-checkbox-label (a default
  // applies otherwise). Page-scoped only (a plain JS object, not localStorage) -- same "this
  // session" lifetime the settings.html checkbox's own label already promises, resets on reload.
  var skipConfirmKeys = {};
  document.addEventListener("htmx:confirm", function (evt) {
    var question = evt.detail && evt.detail.question;
    if (!question) return;
    evt.preventDefault();
    var elt = evt.detail.elt;
    var checkboxKey = elt && elt.dataset ? elt.dataset.confirmCheckboxKey : null;
    if (checkboxKey && skipConfirmKeys[checkboxKey]) {
      evt.detail.issueRequest(true);
      return;
    }
    var opts = { message: question };
    if (checkboxKey) opts.checkboxLabel = elt.dataset.confirmCheckboxLabel || "Don't ask again for the rest of this session";
    window.asraConfirm(opts).then(function (result) {
      var confirmed = checkboxKey ? result.confirmed : result;
      if (!confirmed) return;
      if (checkboxKey && result.checked) skipConfirmKeys[checkboxKey] = true;
      evt.detail.issueRequest(true);
    });
  });
})();
