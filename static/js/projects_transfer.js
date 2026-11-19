// Projects tab -> Export / Import dialogs (templates/partials/projects_transfer_dialogs.html)
// against /api/projects/export and /api/projects/import (sessions/transfer.py).
//
// The export list is built from the live rows of the polled Projects list at open time, so there is
// no extra "list projects" endpoint to keep in sync with that list. Export is a plain file
// download (<a download>), never fetched into memory: a long scan's project can be gigabytes.
(function () {
  "use strict";
  // An htmx-boosted navigation re-runs this script; every lookup below is by id at call time, so the
  // first copy keeps working and a second one would only stack a duplicate change listener.
  if (window.asraProjectsTransfer) return;

  var EXPORT_URL = "/api/projects/export";
  var IMPORT_URL = "/api/projects/import";
  var STATUS_LABELS = {
    imported: "Imported", replaced: "Replaced", copied: "Imported as copy",
    skipped: "Skipped", error: "Failed"
  };
  var STATUS_CLASSES = {
    imported: "text-severity-low", replaced: "text-severity-low", copied: "text-severity-low",
    skipped: "text-secondary", error: "text-severity-high"
  };
  var importedSomething = false;

  function $(id) { return document.getElementById(id); }
  function show(el, visible) { if (el) el.hidden = !visible; }
  function debug(message) { if (window.asraDebugEvent) window.asraDebugEvent("projects-transfer", message); }

  function projectRows() {
    var rows = document.querySelectorAll('#sessions-list-fragment li[id^="session-row-"]');
    return Array.prototype.map.call(rows, function (row) {
      var form = row.querySelector("form[data-project-name]");
      return { id: row.id.replace("session-row-", ""), name: form ? form.dataset.projectName : row.id };
    });
  }

  function checkedIds() {
    var boxes = document.querySelectorAll("#projects-export-list input[type=checkbox]:checked");
    return Array.prototype.map.call(boxes, function (box) { return box.value; });
  }

  function syncExportControls() {
    var all = document.querySelectorAll("#projects-export-list input[type=checkbox]");
    var selected = checkedIds().length;
    $("projects-export-all").checked = all.length > 0 && selected === all.length;
    $("projects-export-count").textContent = "(" + selected + " of " + all.length + ")";
    $("projects-export-go").disabled = selected === 0;
  }

  function exportItem(project) {
    var label = document.createElement("label");
    label.className = "flex items-center gap-2 text-[12px] text-primary select-none cursor-pointer";
    var box = document.createElement("input");
    box.type = "checkbox";
    box.value = project.id;
    box.checked = true;
    box.className = "rounded border-default";
    box.addEventListener("change", syncExportControls);
    var text = document.createElement("span");
    text.className = "truncate";
    text.textContent = project.name;
    label.appendChild(box);
    label.appendChild(text);
    var item = document.createElement("li");
    item.appendChild(label);
    return item;
  }

  function openExport() {
    var list = $("projects-export-list");
    list.textContent = "";
    projectRows().forEach(function (project) { list.appendChild(exportItem(project)); });
    $("projects-export-logs").checked = false;
    $("projects-export-headers").checked = false;
    show($("projects-export-status"), false);
    syncExportControls();
    window.asraOpenDialog("projects-export-modal");
  }

  function runExport() {
    var ids = checkedIds();
    if (!ids.length) return;
    var query = new URLSearchParams({ ids: ids.join(",") });
    if ($("projects-export-logs").checked) query.set("include_logs", "1");
    if ($("projects-export-headers").checked) query.set("include_headers", "1");
    // Shared export flow (warn + choose path, default Downloads) -- CLAUDE.md's export rule. The
    // helper streams the response straight to the chosen file (response.body.pipeTo), so a
    // multi-gigabyte project archive never has to be buffered in memory.
    window.asraExportDownload({
      url: EXPORT_URL + "?" + query.toString(),
      filename: "asra_projects.zip",
      mime: "application/zip",
    });
    var status = $("projects-export-status");
    status.textContent = "Building the archive -- the download starts when it is ready (large projects take a while).";
    show(status, true);
    debug("export ids=" + ids.length + " logs=" + $("projects-export-logs").checked);
  }

  function resetImportDialog() {
    $("projects-import-file").value = "";
    $("projects-import-conflict").value = "skip";
    show($("projects-import-replace-warning"), false);
    show($("projects-import-status"), false);
    show($("projects-import-error"), false);
    var results = $("projects-import-results");
    results.textContent = "";
    show(results, false);
    $("projects-import-go").disabled = false;
    importedSomething = false;
  }

  function openImport() {
    resetImportDialog();
    window.asraOpenDialog("projects-import-modal");
  }

  // The list polls itself, but a reload makes the new projects appear at once instead of "within 5s".
  function closeImport() {
    $("projects-import-modal").close();
    if (importedSomething) window.location.reload();
  }

  function showImportError(message) {
    var error = $("projects-import-error");
    error.textContent = message;
    show(error, true);
    show($("projects-import-status"), false);
    $("projects-import-go").disabled = false;
  }

  function renderResults(results) {
    var list = $("projects-import-results");
    list.textContent = "";
    results.forEach(function (result) {
      var item = document.createElement("li");
      item.className = "flex items-baseline justify-between gap-3";
      var name = document.createElement("span");
      name.className = "text-primary truncate";
      name.textContent = result.name || result.source_id;
      var state = document.createElement("span");
      state.className = "shrink-0 " + (STATUS_CLASSES[result.status] || "text-secondary");
      state.textContent = STATUS_LABELS[result.status] || result.status;
      state.title = result.message || "";
      item.appendChild(name);
      item.appendChild(state);
      list.appendChild(item);
    });
    show(list, true);
  }

  function runImport() {
    var file = $("projects-import-file").files[0];
    if (!file) { showImportError("Choose a .zip archive first."); return; }
    var form = new FormData();
    form.append("file", file);
    form.append("conflict", $("projects-import-conflict").value);
    show($("projects-import-error"), false);
    var status = $("projects-import-status");
    status.textContent = "Importing -- large archives take a while...";
    show(status, true);
    $("projects-import-go").disabled = true;
    fetch(IMPORT_URL, { method: "POST", body: form }).then(function (response) {
      return response.json().then(function (json) { return { ok: response.ok, json: json }; });
    }).then(function (reply) {
      if (!reply.ok || !reply.json.ok) { showImportError(reply.json.error || "Import failed."); return; }
      importedSomething = reply.json.results.some(function (r) { return /^(imported|replaced|copied)$/.test(r.status); });
      show(status, false);
      renderResults(reply.json.results);
      debug("import results=" + reply.json.results.length);
    }).catch(function () {
      showImportError("Could not reach the ASRA server.");
    });
  }

  document.addEventListener("change", function (event) {
    if (event.target && event.target.id === "projects-export-all") {
      var on = event.target.checked;
      document.querySelectorAll("#projects-export-list input[type=checkbox]").forEach(function (box) { box.checked = on; });
      syncExportControls();
    } else if (event.target && event.target.id === "projects-import-conflict") {
      show($("projects-import-replace-warning"), event.target.value === "replace");
    }
  });

  window.asraProjectsTransfer = { openExport: openExport, openImport: openImport, closeImport: closeImport, runExport: runExport, runImport: runImport };
})();
