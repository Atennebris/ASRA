// Settings -> General -> "Transfer settings": drives the Export and Import dialogs
// (templates/partials/settings_transfer_dialogs.html) against /api/settings/transfer/*.
//
// One delegated listener for the whole page instead of per-button wiring, so it keeps working after
// an htmx navigation re-renders the Settings panels; the guard below keeps a second copy of this
// script (re-run by such a navigation) from stacking a second set of listeners.
(function () {
  if (window.__asraSettingsTransfer) return;
  window.__asraSettingsTransfer = true;

  var ENDPOINT = "/api/settings/transfer/";
  // Matches agent/settings_transfer.py's MAX_PAYLOAD_BYTES so an oversized file is refused before it is read.
  var MAX_FILE_BYTES = 1000000;
  var AUTO_RELOAD_DELAY_MS = 900;
  var COPIED_VISIBLE_MS = 2500;

  var currentExport = null;
  var previewReady = false;
  var copiedTimer = null;

  function $(id) { return document.getElementById(id); }
  function show(el, visible) { if (el) el.classList.toggle("hidden", !visible); }
  function setText(id, text) { var el = $(id); if (el) el.textContent = text; }

  function post(path, fields) {
    var body = new URLSearchParams();
    Object.keys(fields).forEach(function (key) { body.set(key, fields[key]); });
    return fetch(ENDPOINT + path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    }).then(function (response) {
      return response.json().then(function (json) { return { ok: response.ok, json: json }; });
    }).catch(function () {
      return { ok: false, json: { ok: false, error: "Could not reach the ASRA server." } };
    });
  }

  function sectionLine(item) {
    var li = document.createElement("li");
    li.className = "flex items-center justify-between gap-3 text-[12px]";
    var name = document.createElement("span");
    name.className = "text-primary";
    name.textContent = item.label;
    var count = document.createElement("span");
    count.className = "text-secondary tabular-nums";
    count.textContent = String(item.count);
    li.appendChild(name);
    li.appendChild(count);
    return li;
  }

  function fillList(listId, items) {
    var list = $(listId);
    list.textContent = "";
    items.forEach(function (item) { list.appendChild(sectionLine(item)); });
  }

  // ---- clipboard -------------------------------------------------------------------------------

  // The desktop shell is a Tauri WebView where navigator.clipboard can be unavailable or refused, so
  // fall back to a selected textarea + execCommand. It is appended INSIDE the open dialog: a modal
  // <dialog> makes everything outside itself inert, and an inert element cannot be selected/copied.
  function legacyCopy(text, host) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.cssText = "position:fixed;top:0;left:0;opacity:0;";
    (host || document.body).appendChild(area);
    area.select();
    var copied = false;
    try { copied = document.execCommand("copy"); } catch (err) { copied = false; }
    area.remove();
    return copied;
  }

  function copyText(text, host) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return legacyCopy(text, host); });
    }
    return Promise.resolve(legacyCopy(text, host));
  }

  function flashCopyStatus(copied) {
    var status = $("transfer-copy-status");
    status.textContent = copied ? "Copied" : "Copy failed - select the code and copy it by hand";
    status.classList.toggle("text-status-online", copied);
    status.classList.toggle("text-severity-high", !copied);
    show(status, true);
    clearTimeout(copiedTimer);
    copiedTimer = setTimeout(function () { show(status, false); }, COPIED_VISIBLE_MS);
  }

  // ---- export ----------------------------------------------------------------------------------

  function resetExportDialog() {
    currentExport = null;
    show($("transfer-export-choose"), true);
    show($("transfer-export-result"), false);
    show($("transfer-export-error"), false);
    $("transfer-export-passphrase").value = "";
    $("transfer-export-code").value = "";
    show($("transfer-copy-status"), false);
    updatePassphraseHint();
  }

  function updatePassphraseHint() {
    var field = $("transfer-export-passphrase");
    if (!field) return;
    show($("transfer-export-plain-hint"), !field.value);
    show($("transfer-export-encrypted-hint"), !!field.value);
  }

  function setExportBusy(busy) {
    document.querySelectorAll("[data-transfer-action^='export-']").forEach(function (btn) { btn.disabled = busy; });
  }

  function runExport(includeSensitive) {
    var fields = { include_sensitive: includeSensitive ? "true" : "false" };
    if (includeSensitive) fields.passphrase = $("transfer-export-passphrase").value;
    show($("transfer-export-error"), false);
    setExportBusy(true);
    post("export", fields).then(function (result) {
      setExportBusy(false);
      if (!result.ok || !result.json.ok) {
        setText("transfer-export-error", result.json.error || "Export failed.");
        show($("transfer-export-error"), true);
        return;
      }
      var data = result.json;
      currentExport = { fileJson: data.file_json, filename: data.filename };
      $("transfer-export-code").value = data.code;
      fillList("transfer-export-sections", data.sections);
      var note = $("transfer-export-sensitivity");
      if (!data.sensitive_included) {
        note.textContent = "No API keys, sudo password or sign-in tokens are included.";
      } else if (data.encrypted) {
        note.textContent = "Includes API keys and the sudo password, encrypted with your passphrase. You need that passphrase to import.";
      } else {
        note.textContent = "Includes API keys and the sudo password WITHOUT encryption. Anyone holding this code or file can read them.";
      }
      note.classList.toggle("text-severity-high", data.sensitive_included && !data.encrypted);
      show($("transfer-export-choose"), false);
      show($("transfer-export-result"), true);
    });
  }

  function downloadExport(host) {
    if (!currentExport) return;
    var blob = new Blob([currentExport.fileJson], { type: "application/json" });
    var url = URL.createObjectURL(blob);
    var link = document.createElement("a");
    link.href = url;
    link.download = currentExport.filename;
    host.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  // ---- import ----------------------------------------------------------------------------------

  function resetImportDialog() {
    previewReady = false;
    $("transfer-import-data").value = "";
    $("transfer-import-passphrase").value = "";
    $("transfer-import-file").value = "";
    invalidatePreview();
    show($("transfer-import-error"), false);
    show($("transfer-import-results"), false);
    show($("transfer-import-reload"), false);
    setText("transfer-import-file-name", "");
  }

  function invalidatePreview() {
    previewReady = false;
    show($("transfer-import-preview"), false);
    $("transfer-import-apply").disabled = true;
  }

  function showImportError(message) {
    setText("transfer-import-error", message);
    show($("transfer-import-error"), true);
  }

  function runPreview() {
    show($("transfer-import-error"), false);
    show($("transfer-import-results"), false);
    invalidatePreview();
    var button = $("transfer-import-preview-btn");
    button.disabled = true;
    post("preview", { data: $("transfer-import-data").value, passphrase: $("transfer-import-passphrase").value }).then(function (result) {
      button.disabled = false;
      if (!result.ok || !result.json.ok) {
        showImportError(result.json.error || "Could not read those settings.");
        return;
      }
      var preview = result.json.preview;
      fillList("transfer-import-sections", preview.sections);
      show($("transfer-import-sensitive"), preview.has_sensitive);
      var detail;
      if (!preview.has_sensitive) {
        detail = "";
      } else if (preview.sensitive_sections) {
        detail = "Contains API keys and/or a sudo password (" + preview.sensitive_sections.map(function (s) { return s.label + ": " + s.count; }).join(", ") + ").";
      } else {
        detail = "Contains API keys and/or a sudo password, encrypted. Enter the passphrase and press Preview again to check it.";
      }
      setText("transfer-import-sensitive-text", detail);
      show($("transfer-import-passphrase-wrap"), preview.has_sensitive && preview.sensitive_encrypted);
      show($("transfer-import-include-wrap"), preview.has_sensitive);
      show($("transfer-import-preview"), true);
      previewReady = true;
      $("transfer-import-apply").disabled = false;
    });
  }

  function renderResults(results) {
    var list = $("transfer-import-result-list");
    list.textContent = "";
    results.forEach(function (item) {
      var li = document.createElement("li");
      li.className = "text-[12px] flex items-start justify-between gap-3";
      var name = document.createElement("span");
      name.className = "text-primary";
      name.textContent = item.label;
      var state = document.createElement("span");
      var failed = item.status !== "applied";
      state.className = (failed ? "text-severity-high" : "text-secondary") + " text-right break-words";
      state.textContent = failed ? "Failed: " + item.detail : (item.detail === "applied" ? "Applied" : "Applied - " + item.detail);
      li.appendChild(name);
      li.appendChild(state);
      list.appendChild(li);
    });
    show($("transfer-import-results"), true);
  }

  // The tab lives in the URL hash (Settings' own tab script), so keeping the hash on a reload lands
  // the owner back on the General tab with the freshly imported values visible.
  function reloadSettings() {
    history.replaceState(null, "", "/settings" + (location.hash || "#general"));
    location.reload();
  }

  function runApply() {
    if (!previewReady) return;
    var includeBox = $("transfer-import-include");
    var includeSensitive = includeBox && !$("transfer-import-sensitive").classList.contains("hidden") && includeBox.checked;
    var button = $("transfer-import-apply");
    button.disabled = true;
    show($("transfer-import-error"), false);
    post("apply", {
      data: $("transfer-import-data").value,
      passphrase: $("transfer-import-passphrase").value,
      include_sensitive: includeSensitive ? "true" : "false",
    }).then(function (result) {
      if (!result.json.results) {
        button.disabled = false;
        showImportError(result.json.error || "Import failed; nothing was changed.");
        return;
      }
      renderResults(result.json.results);
      if (result.json.ok) {
        setText("transfer-import-done", "Imported. Reloading Settings...");
        show($("transfer-import-done"), true);
        setTimeout(reloadSettings, AUTO_RELOAD_DELAY_MS);
      } else {
        setText("transfer-import-done", "Some sections could not be applied. Review them below.");
        show($("transfer-import-done"), true);
        show($("transfer-import-reload"), true);
      }
    });
  }

  function readChosenFile(input) {
    var file = input.files && input.files[0];
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      showImportError("That file is larger than a settings export can be.");
      input.value = "";
      return;
    }
    var reader = new FileReader();
    reader.onload = function () {
      $("transfer-import-data").value = String(reader.result || "");
      setText("transfer-import-file-name", file.name);
      runPreview();
    };
    reader.onerror = function () { showImportError("That file could not be read."); };
    reader.readAsText(file);
  }

  // ---- wiring ----------------------------------------------------------------------------------

  document.addEventListener("click", function (event) {
    var opener = event.target.closest("[data-transfer-open]");
    if (opener) {
      var which = opener.getAttribute("data-transfer-open");
      var dialog = $("settings-" + which + "-dialog");
      if (!dialog) return;
      if (which === "export") resetExportDialog(); else resetImportDialog();
      dialog.showModal();
      return;
    }
    var actionEl = event.target.closest("[data-transfer-action]");
    if (!actionEl) return;
    var dialogHost = actionEl.closest("dialog") || document.body;
    switch (actionEl.getAttribute("data-transfer-action")) {
      case "export-plain": runExport(false); break;
      case "export-sensitive": runExport(true); break;
      case "export-back": resetExportDialog(); break;
      case "copy-code": copyText($("transfer-export-code").value, dialogHost).then(flashCopyStatus); break;
      case "download-file": downloadExport(dialogHost); break;
      case "import-preview": runPreview(); break;
      case "import-apply": runApply(); break;
      case "import-reload": reloadSettings(); break;
      case "close": dialogHost.close && dialogHost.close(); break;
    }
  });

  document.addEventListener("input", function (event) {
    if (event.target.id === "transfer-export-passphrase") updatePassphraseHint();
    if (event.target.id === "transfer-import-data") invalidatePreview();
  });

  document.addEventListener("change", function (event) {
    if (event.target.id === "transfer-import-file") readChosenFile(event.target);
  });

  // The result stage holds the code (possibly with live API keys) -- drop it as soon as the dialog closes.
  document.addEventListener("close", function (event) {
    if (event.target && event.target.id === "settings-export-dialog") resetExportDialog();
    if (event.target && event.target.id === "settings-import-dialog") resetImportDialog();
  }, true);
})();
