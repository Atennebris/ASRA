// Reusable "export a file" flow, used by EVERY Export button in the app (CLAUDE.md rule: an export
// must never silently stream straight into Downloads — it must warn and let the operator choose
// where to save, defaulting to the Downloads folder on every OS).
//
// Three tiers, in order:
//   1. Desktop shell (Tauri/WebView2): window.showSaveFilePicker does NOT exist here, so we hand the
//      content to a Rust command (save_export_file for text, save_export_bytes for binary) that
//      opens the OS "Save As" dialog DEFAULTING TO Downloads, and writes the chosen file from Rust.
//      This is the operator's real path on Windows.
//   2. A real browser with the File System Access API (Chromium): window.showSaveFilePicker with
//      startIn:"downloads" — same "warn + choose path, default Downloads" behavior natively.
//   3. Last resort (Firefox/Safari/WebKit without either): an explicit asraConfirm() warning, then a
//      plain download to the browser's own Downloads folder.
(function () {
  "use strict";

  function tauriInvoke() {
    var t = window.__TAURI__;
    if (t && t.core && typeof t.core.invoke === "function") return t.core.invoke;
    if (t && typeof t.invoke === "function") return t.invoke;
    return null;
  }

  function deriveFilename(url, explicit) {
    if (explicit) return explicit;
    try {
      var path = new URL(url, location.href).pathname;
      var last = path.split("/").filter(Boolean).pop() || "download";
      return last.indexOf(".") === -1 ? last + ".dat" : last;
    } catch (e) {
      return "download.dat";
    }
  }

  function extOf(filename) {
    var dot = filename.lastIndexOf(".");
    return dot === -1 ? "" : filename.slice(dot + 1).toLowerCase();
  }

  var TEXT_EXTS = ["json", "txt", "md", "markdown", "html", "htm", "csv", "xml", "log", "yaml", "yml", "svg"];

  function isTextExport(filename, mime) {
    var m = (mime || "").toLowerCase();
    if (m) return /json|text|xml|html|csv|markdown|javascript|svg/.test(m);
    return TEXT_EXTS.indexOf(extOf(filename)) !== -1;
  }

  function getContent(opts) {
    if (opts.getBlob) return Promise.resolve(opts.getBlob());
    if (opts.blob) return Promise.resolve(opts.blob);
    return fetch(opts.url).then(function (r) {
      if (!r.ok) throw new Error("export http " + r.status);
      return r.blob();
    });
  }

  function blobToBase64(blob) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        var res = String(reader.result || "");
        var comma = res.indexOf(",");
        resolve(comma === -1 ? "" : res.slice(comma + 1)); // strip the "data:...;base64," prefix
      };
      reader.onerror = function () { reject(reader.error); };
      reader.readAsDataURL(blob);
    });
  }

  function anchorDownload(url, filename) {
    var a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  }

  function anchorDownloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    anchorDownload(url, filename);
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  // Tier 1 — desktop shell. All three Rust commands open a native Save As dialog defaulting to
  // Downloads; a null result means the operator cancelled.
  function desktopSave(invoke, opts, filename) {
    // A server-route export (has a URL) is fetched + streamed to the chosen file entirely in Rust,
    // so even a multi-GB project .zip never has to be buffered in webview memory.
    if (opts.url && !opts.getBlob && !opts.blob) {
      var absUrl;
      try { absUrl = new URL(opts.url, location.href).href; } catch (e) { absUrl = opts.url; }
      return invoke("save_export_url", { url: absUrl, suggestedName: filename }).then(function (path) { return path !== null; });
    }
    // A client-generated blob (the attack-surface PNG, an in-memory settings bundle): hand the bytes
    // over -- text as a string, binary as base64. These are small, so no streaming needed.
    return getContent(opts).then(function (blob) {
      if (isTextExport(filename, opts.mime || (blob && blob.type))) {
        return blob.text().then(function (text) {
          return invoke("save_export_file", { suggestedName: filename, contents: text });
        }).then(function (path) { return path !== null; });
      }
      return blobToBase64(blob).then(function (b64) {
        return invoke("save_export_bytes", { suggestedName: filename, dataB64: b64 });
      }).then(function (path) { return path !== null; });
    });
  }

  // Tier 2 — browser File System Access API. Called inside the click gesture (showSaveFilePicker is
  // invoked before the first await) so the browser accepts the user-activation requirement.
  function browserPickerSave(opts, filename) {
    var pickerPromise;
    try {
      var types;
      if (opts.mime) {
        var ext = extOf(filename);
        if (ext) { var accept = {}; accept[opts.mime] = ["." + ext]; types = [{ description: filename, accept: accept }]; }
      }
      pickerPromise = window.showSaveFilePicker({ suggestedName: filename, startIn: "downloads", types: types });
    } catch (e) {
      return Promise.reject(e);
    }
    return pickerPromise.then(function (handle) {
      return getContent(opts).then(function (blob) {
        return handle.createWritable().then(function (writable) {
          return writable.write(blob).then(function () { return writable.close(); });
        });
      });
    }).then(function () { return true; });
  }

  // Tier 3 — plain download, with an explicit warning first since there's no native dialog to serve
  // as one.
  function fallbackDownload(opts, filename) {
    var confirmFn = window.asraConfirm || function () { return Promise.resolve(true); };
    return confirmFn({
      title: opts.warnTitle || "Export file",
      message: opts.warnMessage || ("\"" + filename + "\" will be downloaded to your Downloads folder."),
      confirmLabel: "Download",
      danger: false,
    }).then(function (ok) {
      if (!ok) return false;
      if (opts.getBlob) return Promise.resolve(opts.getBlob()).then(function (b) { anchorDownloadBlob(b, filename); return true; });
      if (opts.blob) { anchorDownloadBlob(opts.blob, filename); return true; }
      anchorDownload(opts.url, filename);
      return true;
    });
  }

  // opts: { url } OR { blob } OR { getBlob: () => Promise<Blob> }; filename, mime?, warnTitle?, warnMessage?
  // Returns a Promise<boolean> (true = saved, false = cancelled). Never throws into the UI.
  window.asraExportDownload = function (opts) {
    opts = opts || {};
    var filename = deriveFilename(opts.url, opts.filename);
    var invoke = tauriInvoke();

    if (invoke) {
      return desktopSave(invoke, opts, filename).catch(function (err) {
        if (window.asraDebugEvent) window.asraDebugEvent("export-error", String(err));
        return fallbackDownload(opts, filename); // never silently lose the export
      });
    }

    if (window.showSaveFilePicker) {
      return browserPickerSave(opts, filename).catch(function (err) {
        if (err && err.name === "AbortError") return false; // operator cancelled the Save As dialog
        return fallbackDownload(opts, filename);
      });
    }

    return fallbackDownload(opts, filename);
  };

  // Delegated interceptor: any <a data-export>/<button data-export> (not a form) is routed through
  // the flow above with no per-site JS. The element supplies the source via data-export-url (or its
  // own href) and an optional data-export-filename / data-export-mime / data-export-warn.
  document.addEventListener("click", function (event) {
    var el = event.target.closest && event.target.closest("[data-export]:not(form)");
    if (!el) return;
    if (el.tagName === "BUTTON" && el.type === "submit") return; // handled by its form's submit
    event.preventDefault();
    window.asraExportDownload({
      url: el.getAttribute("data-export-url") || el.getAttribute("href"),
      filename: el.getAttribute("data-export-filename") || el.getAttribute("download") || null,
      mime: el.getAttribute("data-export-mime") || null,
      warnMessage: el.getAttribute("data-export-warn") || null,
    });
  }, true);

  document.addEventListener("submit", function (event) {
    var form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-export")) return;
    event.preventDefault();
    var action = form.getAttribute("action") || "";
    var method = (form.getAttribute("method") || "get").toLowerCase();
    var url = action;
    if (method === "get") {
      var params = new URLSearchParams(new FormData(form)).toString();
      if (params) url += (action.indexOf("?") === -1 ? "?" : "&") + params;
    }
    // A multi-format export (the proof report: html/pdf/docx/zip/...) can't carry one static
    // filename -- data-export-filename-base + data-export-ext-from=<field name> builds it from the
    // chosen format at submit time, so the Save As dialog suggests the right extension.
    var filename = form.getAttribute("data-export-filename");
    if (!filename) {
      var base = form.getAttribute("data-export-filename-base");
      if (base) {
        var extField = form.getAttribute("data-export-ext-from");
        var ext = extField && form.elements[extField] ? String(form.elements[extField].value || "").trim() : "";
        filename = ext ? base + "." + ext : base;
      }
    }
    window.asraExportDownload({
      url: url,
      filename: filename || null,
      mime: form.getAttribute("data-export-mime") || null,
      warnMessage: form.getAttribute("data-export-warn") || null,
    });
  }, true);
})();
