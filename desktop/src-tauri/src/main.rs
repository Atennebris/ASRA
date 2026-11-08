// Native GUI subsystem: no stray console window of our own. Backend/WSL output goes
// to the DEBUG console (opened only when DEBUG=true) or the debug log files, not a raw
// terminal attached to this process.
#![windows_subsystem = "windows"]

// ASRA desktop shell.
//
// Flow: the window first shows a local start screen (dist/index.html) -- launch mode
// (desktop/web), run-as-root, WSL distro (Windows), and .env settings (toggles/fields
// parsed from the file). Save persists .env for next time; Start calls launch_backend,
// which writes changed .env values, opens the familiar DEBUG console when DEBUG=true
// (Windows), starts the backend the way the shell scripts do, waits until it serves,
// then navigates this window to the live UI (desktop, locked to this window via a
// per-launch token) or hands back the URL (web -- opened in a browser only on the
// explicit "Open" click, never automatically). Closing the window stops a shell-started
// backend cleanly (SIGINT).
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant, UNIX_EPOCH};

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
// Keep child console apps (wsl.exe, reg.exe, rundll32) windowless now that this shell is
// a GUI process -- otherwise each spawn would flash its own console window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x0000_0008;

// Runs only inside the native shell, never in a browser. Hides the sidebar's logo emblem
// (centered wordmark only). Defensive + idempotent; init script (no flash) + on_page_load.
const DESKTOP_TWEAKS: &str = r#"(function () {
  function apply() {
    try {
      document.documentElement.classList.add('asra-desktop');
      if (document.getElementById('asra-desktop-style')) return;
      var style = document.createElement('style');
      style.id = 'asra-desktop-style';
      style.textContent = '#sidebar a[href="/"] > div, .asra-brand-emblem{display:none!important}'
        + ' #sidebar a[href="/"]{justify-content:center!important}';
      (document.head || document.documentElement).appendChild(style);
    } catch (e) {}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', apply);
  }
  apply();
})();"#;

struct Backend {
    child: Child,
    #[cfg_attr(not(windows), allow(dead_code))]
    as_root: bool,
    #[cfg_attr(not(windows), allow(dead_code))]
    distro: String,
}
struct OwnedBackend(Mutex<Option<Backend>>);

#[derive(serde::Serialize)]
struct EnvSetting {
    key: String,
    value: String,
    description: String,
    kind: String, // "toggle" | "password" | "text"
}

#[derive(serde::Serialize)]
struct WslDistro {
    name: String,
    is_default: bool,
}

#[derive(serde::Serialize)]
struct StartConfig {
    os: String,
    version: String,
    default_mode: String,
    run_as_root: bool,
    intro_enabled: bool,
    intro_sound_enabled: bool,
    // Distinguishes "wsl.exe isn't on this machine at all" from "wsl.exe works but zero distros
    // are registered" -- list_wsl_distros() alone collapses both into an empty `distros`, which is
    // exactly the ambiguity the start screen's WSL-missing/distro-missing banners need resolved.
    wsl_installed: bool,
    // Which distro the "Install a Linux distro" button offers when none exist yet -- read from
    // ASRA_WSL_AUTO_INSTALL_DISTRO (.env), never hardcoded, so an operator can point it at
    // Debian/etc. instead of Ubuntu without a code change.
    wsl_default_distro: String,
    distros: Vec<WslDistro>,
    settings: Vec<EnvSetting>,
    // False when repo_dir()'s own upward search never found run.sh -- i.e. this exe is running
    // on its own, downloaded straight from a GitHub Release with no ASRA checkout above it. The
    // start screen uses this to offer bootstrap_full_project's "pick a folder & install" button
    // instead of only letting the operator hit Start and wait out launch_backend's fast-fail.
    repo_found: bool,
    // Set only on the ONE launch right after bootstrap_full_project relaunched this exe's freshly
    // installed copy (via the ASRA_JUST_INSTALLED env var it sets on that spawn) -- the install
    // path, so the start screen can tell the operator plainly where the real app now lives and
    // that the originally downloaded .exe elsewhere (e.g. Downloads) was only the installer.
    // Real, confirmed incident this exists because of: bootstrap_full_project's own success path
    // was a silent exit()+relaunch with nothing user-visible at all -- an operator who closed the
    // new window without reading its title bar had no way to tell the install even happened, and
    // re-ran the original Downloads .exe later expecting it to now work, landing back on the same
    // "pick a folder & install" screen with no idea why "already installed" didn't stick.
    just_installed: Option<String>,
}

// Mirrors install_wsl's two possible jobs. Kept as a String (not a Rust enum) on the wire --
// serde already round-trips plain strings with zero ceremony, and the frontend has no reason to
// see anything richer than "install-wsl" | "install-distro".
#[derive(serde::Deserialize)]
struct WslSetupArgs {
    // Only read by install_wsl's #[cfg(windows)] body -- the non-Windows stub takes an unused
    // `_args: WslSetupArgs` instead, same "real fields, deliberately unread on that platform"
    // shape Backend's own as_root/distro already use above, same reason: these are Windows-only
    // concepts (a WSL distro name, an install mode) that still need to deserialize everywhere
    // since the struct itself has no #[cfg(windows)] of its own -- serde needs it on every
    // platform to parse the JS-side invoke() payload.
    #[cfg_attr(not(windows), allow(dead_code))]
    mode: String,
    #[cfg_attr(not(windows), allow(dead_code))]
    distro: String,
}

#[derive(serde::Serialize)]
struct WslSetupStatus {
    // "running" | "stalled" | "done" -- see get_wsl_setup_status's own comment for why this is
    // derived from real WSL/distro state on every poll, never from parsing the elevated
    // process's log output.
    state: String,
    log: String,
}

#[derive(serde::Deserialize)]
struct LaunchArgs {
    mode: String,
    as_root: bool,
    distro: String,
    updates: HashMap<String, String>,
}

fn repo_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("ASRA_REPO_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe;
        dir.pop();
        loop {
            if dir.join("run.sh").is_file() {
                // Keep the marker in sync with reality on every successful direct resolution, not
                // just right after bootstrap_full_project's own install -- so an operator who later
                // just drags the whole installed folder to a different drive/path (no reinstall, no
                // button click) has the marker catch up automatically the next time they launch the
                // one real exe that lives inside that folder, instead of it quietly going stale.
                record_install_location(&dir);
                return dir;
            }
            if !dir.pop() {
                break;
            }
        }
    }
    // This exe's own upward search found nothing -- it may simply be a DIFFERENT copy than the one
    // bootstrap_full_project relaunched after installing (e.g. the original download, left alone
    // on purpose where the operator put it -- see that function's own comment). Check the one
    // fixed, zero-config marker every copy of this exe agrees on before giving up, so ANY copy
    // keeps working once ASRA has been installed anywhere on this machine, not just the one path
    // bootstrap happened to relaunch from. Real, confirmed incident this exists because of: without
    // this, re-running the originally downloaded .exe after a successful install landed back on
    // the "pick a folder & install" screen with no way to tell an install already happened
    // elsewhere -- the operator has to remember and keep using one specific exe path forever,
    // which is exactly the inconvenience this fallback removes.
    if let Some(installed) = recorded_install_location() {
        if installed.join("run.sh").is_file() {
            return installed;
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

// Fixed, zero-config location every copy of this exe resolves identically, with no .env and no
// existing project required to find it -- resolve_app_dir("") already defaults to this same
// Documents/ASRA path with no override applied, exactly what's needed before any real install
// (and its own possibly-customized APP_DATA_DIR) exists at all.
fn install_location_marker_path() -> PathBuf {
    resolve_app_dir("").join("install_location.txt")
}

fn recorded_install_location() -> Option<PathBuf> {
    let text = std::fs::read_to_string(install_location_marker_path()).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

// Best-effort: a failure to record this must never block the install/relaunch it's attached to --
// worst case, only this one fallback path is unavailable, the direct upward search still works
// for whichever copy was actually relaunched.
fn record_install_location(target: &Path) {
    let marker = install_location_marker_path();
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, target.to_string_lossy().as_bytes());
}

fn port_from_env_text(text: &str) -> String {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("PORT=") {
            let value = rest.trim().trim_matches('"').trim();
            if !value.is_empty() {
                return value.to_string();
            }
        }
    }
    "8000".to_string()
}

fn port_is_up(port: &str) -> bool {
    match format!("127.0.0.1:{port}").parse::<SocketAddr>() {
        Ok(addr) => TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok(),
        Err(_) => false,
    }
}

// Real, confirmed incident this fixes: a fixed 300s readiness timeout has no way to tell apart a
// genuinely broken backend from a perfectly healthy but slow FIRST-TIME dependency install --
// confirmed live, a fresh machine installing ~150 packages (several large: frida, semgrep,
// mitmproxy, playwright) legitimately ran past 300s while `run.sh`'s own log kept growing the
// whole time, and the readiness wait gave up and reported failure mid-install, with pip still
// actively working. A single bigger fixed number just moves the same wrong tradeoff to a
// different value -- it would make a genuinely hung backend (dead network, crashed process) wait
// that same long before ever saying so. Watching the backend's own launch log for real progress
// instead of guessing a duration solves both: keep waiting as long as that log keeps growing
// (there's forward motion, however slow), but give up quickly once it goes quiet for a while
// (nothing left changing means nothing left to wait for, regardless of how much total time has
// passed). `stall_after` is how long with NO log growth before calling it stuck; `hard_cap` is an
// absolute ceiling so a truly wedged process (alive but stuck) can't wait forever either.
//
// Earlier versions of this guessed "stuck" from log silence (pip's own undifferentiated
// "Installing collected packages: ..." phase prints that line ONCE, then goes completely silent
// for however long writing every package's files to disk actually takes) -- first 90s, then 600s,
// each confirmed too short live by a real install that was still genuinely working past that
// point, on a slow/antivirus-laden real machine with ~150 packages. Guessing a bigger silence
// threshold was never going to stop being a guess. The actual fact that mattered the whole time
// is directly observable instead: whether the backend's own OS process (the wsl.exe/bash run.sh
// invocation spawn_backend started) has exited. While it's still running, the install/launch is
// still making progress no matter how long any one phase stays quiet; once it exits without the
// port ever opening, that's an immediate, authoritative failure -- no silence threshold to tune.
fn backend_process_has_exited(app: &AppHandle) -> bool {
    let owned = app.state::<OwnedBackend>();
    let mut guard = owned.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    match guard.as_mut() {
        Some(backend) => matches!(backend.child.try_wait(), Ok(Some(_))),
        // Nothing to poll (e.g. the "adopted an already-running backend" path never stores a
        // child) -- can't observe exit this way, so never treat that as a failure signal.
        None => false,
    }
}

fn wait_for_port_adaptive(port: &str, app: &AppHandle) -> bool {
    let hard_cap = Duration::from_secs(2700);
    let start = Instant::now();
    loop {
        if port_is_up(port) {
            return true;
        }
        if start.elapsed() >= hard_cap {
            return false;
        }
        if backend_process_has_exited(app) {
            return false;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
}

fn wait_for_port_to_clear(port: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !port_is_up(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    !port_is_up(port)
}

// Real, confirmed incident this fixes: an operator restarted ASRA FOUR separate times through
// this desktop shell and hit the identical broken state every time. Root cause, traced through
// the whole launch stack: launch_backend's own "already_up" check below is a bare TCP connect --
// it has never once asked WHETHER the thing answering is running current code, only whether
// SOMETHING answers at all. Every one of those four relaunches therefore "adopted" the exact same
// stale backend (unchanged, still running main.py from long before that day's edits) instead of
// ever giving it a chance to actually restart -- and an adopted backend is never stored in
// OwnedBackend (see the `if already_up {...}` branch below), so nothing on ANY later exit path
// (including the tray's own "Quit ASRA", see stop_backend's `guard.take()`) could ever reach back
// and end it either. This is the missing other half of main.py's own _terminate_stale_asra
// (Python-side self-heal on a plain run.bat/run.sh launch) -- the desktop shell needed the SAME
// staleness check BEFORE deciding to adopt, not just a "does anything answer" probe, or a launch
// through this app could never even reach main.py's own self-heal code in the first place.
fn remote_source_mtime(port: &str) -> Option<f64> {
    let addr = format!("127.0.0.1:{port}").parse::<SocketAddr>().ok()?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(800)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(800))).ok()?;
    let request = format!("GET /api/system-health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    let mut response = String::new();
    // A slow/hanging peer would otherwise block this indefinitely -- the read timeout above turns
    // that into an Err (mapped to None via .ok()) instead of hanging the whole launch.
    let _ = stream.read_to_string(&mut response);
    response
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("x-asra-source-mtime:"))
        .and_then(|line| line.split_once(':'))
        .and_then(|(_, value)| value.trim().parse::<f64>().ok())
}

fn local_main_py_mtime(repo: &Path) -> Option<f64> {
    let modified = std::fs::metadata(repo.join("main.py")).ok()?.modified().ok()?;
    Some(modified.duration_since(UNIX_EPOCH).ok()?.as_secs_f64())
}

// Runs a child process with a hard deadline instead of Command::status()'s unbounded wait --
// protects against a wedged wsl.exe. Real, confirmed incident: WSL2's own VM service went
// unresponsive after a long uptime (`wsl -l -v` still claimed the distro "Running", but any
// `wsl.exe -- ...` call failed with Wsl/Service/0x8007274c); a plain `.status()` call in that
// state can hang indefinitely with no way for the caller to ever get control back. Returns None
// if the deadline passed before the child exited (the child is then force-killed, best-effort) --
// callers read that as "the thing we tried to run appears wedged," not as "it ran and did nothing".
#[cfg(windows)]
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Option<std::process::ExitStatus> {
    let mut child = cmd.spawn().ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(150)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

// Same wedged-wsl.exe protection as run_with_timeout, but also captures stdout/stderr -- needed by
// test_wsl_setup below, which has to read back what the distro actually said, not just whether it
// exited. Reads happen only after the child has already exited (confirmed via try_wait before
// returning), so this is deliberately NOT a general-purpose subprocess runner: it's only safe
// because every caller here runs a short, fixed, tiny-output smoke-test command (a handful of echo
// lines), never anything that could fill a pipe buffer before exiting.
#[cfg(windows)]
fn run_with_timeout_output(mut cmd: Command, timeout: Duration) -> Option<std::process::Output> {
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().ok()?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                if let Some(mut out) = child.stdout.take() {
                    let _ = out.read_to_end(&mut stdout);
                }
                if let Some(mut err) = child.stderr.take() {
                    let _ = err.read_to_end(&mut stderr);
                }
                return Some(std::process::Output { status, stdout, stderr });
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(150)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

// Pattern-matched (not PID-tracked) on purpose -- this runs BEFORE any decision to adopt or spawn,
// so there is no Backend/Child stored yet to kill by a specific handle, exactly the same
// constraint stop_backend's own pkill already accepts for the identical reason.
// Returns false when the kill attempt itself could not complete (wsl.exe appears wedged, see
// run_with_timeout) -- distinct from "ran fine and found nothing to kill" (still true), so a
// caller can tell those two apart instead of treating both as silent success.
fn kill_stale_backend_by_pattern(as_root: bool, distro: &str) -> bool {
    eprintln!("[ASRA-DESKTOP] backend on this port is running code older than what's on disk -- terminating it before adopting");
    #[cfg(windows)]
    {
        let mut kill = Command::new("wsl.exe");
        apply_wsl_target(&mut kill, as_root, distro);
        kill.arg("--")
            .arg("bash")
            .arg("-lc")
            .arg("pkill -TERM -f 'python main.py'")
            .creation_flags(CREATE_NO_WINDOW);
        run_with_timeout(kill, Duration::from_secs(10)).is_some()
    }
    #[cfg(not(windows))]
    {
        // No WSL2 involved on native Linux/macOS (see this project's own run.sh) -- as_root/distro
        // only matter for targeting a WSL distro, so there's nothing to do with them here.
        let _ = (&as_root, &distro);
        Command::new("pkill")
            .arg("-TERM")
            .arg("-f")
            .arg("python main.py")
            .status()
            .is_ok()
    }
}

// ---- .env parsing / rewriting -------------------------------------------------

fn is_valid_env_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .next()
            .map(|c| c.is_ascii_alphabetic() || c == '_')
            .unwrap_or(false)
        && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn unquote(raw: &str) -> String {
    let value = raw.trim();
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return value[1..value.len() - 1].to_string();
        }
    }
    value.to_string()
}

fn setting_kind(key: &str, value: &str) -> &'static str {
    let upper = key.to_ascii_uppercase();
    if ["KEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD"]
        .iter()
        .any(|needle| upper.contains(needle))
    {
        return "password";
    }
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "false" | "yes" | "no" | "on" | "off" => "toggle",
        _ => "text",
    }
}

fn parse_env_settings(text: &str) -> Vec<EnvSetting> {
    let mut settings = Vec::new();
    let mut comment: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            comment.push(trimmed.trim_start_matches('#').trim().to_string());
        } else if trimmed.is_empty() {
            comment.clear();
        } else if let Some(eq) = trimmed.find('=') {
            let key = trimmed[..eq].trim();
            // ASRA_RUN_AS_ROOT is surfaced as the top-level "Run as root" toggle, so it is
            // excluded from the Advanced list to avoid showing it twice. ASRA_INTRO_ENABLED and
            // ASRA_INTRO_SOUND_ENABLED are excluded the same way -- they're surfaced in the WEB
            // app's own Settings -> Customization -> Visual instead (their own toggles need live
            // description text this generic list can't give them), not as a second, redundant raw
            // row here.
            if is_valid_env_key(key)
                && key != "ASRA_RUN_AS_ROOT"
                && key != "ASRA_INTRO_ENABLED"
                && key != "ASRA_INTRO_SOUND_ENABLED"
            {
                let value = unquote(&trimmed[eq + 1..]);
                let kind = setting_kind(key, &value);
                settings.push(EnvSetting {
                    key: key.to_string(),
                    value,
                    description: comment.join(" "),
                    kind: kind.to_string(),
                });
            }
            comment.clear();
        } else {
            comment.clear();
        }
    }
    settings
}

// bash sources .env (run.sh: `set -a; source .env`), so a value with spaces/specials must
// be quoted. Single-quote anything not made only of shell-safe chars.
fn format_env_value(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return String::new();
    }
    let safe = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./:@=+-".contains(c));
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn rewrite_env(original: &str, updates: &HashMap<String, String>) -> String {
    let mut seen: HashSet<String> = HashSet::new();
    let mut lines: Vec<String> = original
        .lines()
        .map(|raw| {
            let line = raw.trim_end_matches('\r');
            let trimmed = line.trim_start();
            if !trimmed.starts_with('#') {
                if let Some(eq) = trimmed.find('=') {
                    let key = trimmed[..eq].trim();
                    if let Some(value) = updates.get(key) {
                        seen.insert(key.to_string());
                        return format!("{}={}", key, format_env_value(value));
                    }
                }
            }
            line.to_string()
        })
        .collect();
    // Append any updated keys the file didn't already have (e.g. a shell-owned pref written
    // for the first time), sorted for a stable result.
    let mut missing: Vec<(&String, &String)> = updates
        .iter()
        .filter(|(k, _)| !seen.contains(k.as_str()))
        .collect();
    missing.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in missing {
        lines.push(format!("{}={}", key, format_env_value(value)));
    }
    lines.join("\n") + "\n"
}

fn env_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix(key) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.trim().trim_matches('"').trim_matches('\''));
            }
        }
    }
    None
}

fn env_flag(text: &str, key: &str) -> bool {
    matches!(
        env_value(text, key).unwrap_or("").to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

// Same as env_flag, but a MISSING key falls back to `default` instead of always reading as false.
// ASRA_INTRO_ENABLED needs this: it ships "on by default" (Settings -> Customization -> Visual's own
// docstring/agent/intro_settings.py), so a .env that predates this feature -- the key simply isn't
// there yet -- must still play the intro, not silently act as if an operator had turned it off.
fn env_flag_default(text: &str, key: &str, default: bool) -> bool {
    match env_value(text, key) {
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"),
        None => default,
    }
}

// Not #[cfg(windows)]-gated: append_desktop_log_line below (cross-platform) reads this to decide
// whether to write at all, same DEBUG=true gate agent/utils/logger.py's own get_logger() uses --
// silent otherwise, so this shell's own debug.log never grows for an operator who never turned
// debug logging on.
fn is_debug_enabled(env_text: &str) -> bool {
    env_flag(env_text, "DEBUG")
}

// Same "Documents/ASRA" resolution open_debug_console below already needs -- pulled out so
// append_desktop_log_line (called from get_start_config/launch_backend, before any window/console
// exists) can reach the same debug.log file without duplicating this logic.
fn resolve_app_dir(env_text: &str) -> PathBuf {
    match env_value(env_text, "APP_DATA_DIR").filter(|s| !s.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var("USERPROFILE").unwrap_or_default())
            .join("Documents")
            .join("ASRA"),
    }
}

// This shell's own counterpart to agent/utils/logger.py's get_logger("DESKTOP") -- there is no
// Python process running yet for most of what this file does (WSL distro discovery, waiting for
// the backend's port), so those steps have never shown up in debug.log at all; an operator
// reporting a slow desktop launch had no way to tell which step was actually slow. Matches
// agent/utils/debug.py's own file format exactly (same timestamp shape, same
// "[asra.CATEGORY] message" tail) so the same tailing console window (scripts/debug_console.ps1)
// picks these lines up with no changes of its own. Best-effort: a write failure here must never
// break the actual launch it's trying to describe.
fn append_desktop_log_line(env_text: &str, message: &str) {
    if !is_debug_enabled(env_text) {
        return;
    }
    let app_dir = resolve_app_dir(env_text);
    if std::fs::create_dir_all(&app_dir).is_err() {
        return;
    }
    let now = chrono::Local::now();
    let line = format!(
        "{},{:03} {} [asra.DESKTOP] {}\n",
        now.format("%Y-%m-%d %H:%M:%S"),
        now.timestamp_subsec_millis(),
        now.format("%z"),
        message
    );
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(app_dir.join("debug.log"))
    {
        let _ = file.write_all(line.as_bytes());
    }
}

// ---- WSL distro discovery (Windows) -------------------------------------------

#[cfg(windows)]
fn decode_wsl(bytes: &[u8]) -> String {
    // wsl.exe emits UTF-16LE; ASCII names show a null high byte at index 1.
    if bytes.len() >= 2 && bytes[1] == 0 {
        let mut units = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i + 1 < bytes.len() {
            units.push(u16::from_le_bytes([bytes[i], bytes[i + 1]]));
            i += 2;
        }
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

#[cfg(windows)]
fn list_wsl_distros() -> Vec<WslDistro> {
    let output = match Command::new("wsl.exe")
        .args(["-l", "-v"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(out) => out,
        Err(_) => return Vec::new(),
    };
    let mut distros = Vec::new();
    for raw in decode_wsl(&output.stdout).lines() {
        let trimmed = raw.trim_end_matches('\r').trim();
        if trimmed.is_empty() || trimmed.starts_with("NAME") {
            continue;
        }
        let is_default = trimmed.starts_with('*');
        let rest = trimmed.trim_start_matches('*').trim();
        let name = rest.split_whitespace().next().unwrap_or("").to_string();
        if name.is_empty() || name.starts_with("docker-desktop") {
            continue;
        }
        distros.push(WslDistro { name, is_default });
    }
    distros
}

#[cfg(not(windows))]
fn list_wsl_distros() -> Vec<WslDistro> {
    Vec::new()
}

// `wsl.exe -l -v` alone can't tell "not installed" apart from "installed, zero distros" -- both
// print nothing list_wsl_distros() can parse. `--status` is cheap (no VM to spin up) and succeeds
// (an Ok output, regardless of its own exit code) the instant wsl.exe genuinely exists on PATH --
// that's the one bit list_wsl_distros() itself can't give a caller.
#[cfg(windows)]
fn wsl_is_installed() -> bool {
    Command::new("wsl.exe")
        .arg("--status")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok()
}

#[cfg(not(windows))]
fn wsl_is_installed() -> bool {
    false
}

// ASRA_WSL_AUTO_INSTALL_DISTRO (.env) -- see StartConfig::wsl_default_distro's own comment for why
// this isn't hardcoded to "Ubuntu" directly at the call site.
fn default_wsl_install_distro(env_text: &str) -> String {
    env_value(env_text, "ASRA_WSL_AUTO_INSTALL_DISTRO")
        .filter(|s| !s.is_empty())
        .unwrap_or("Ubuntu")
        .to_string()
}

// ---- process spawn / stop -----------------------------------------------------

#[cfg(windows)]
fn apply_wsl_target(cmd: &mut Command, as_root: bool, distro: &str) {
    let distro = if distro.is_empty() {
        std::env::var("WSL_DISTRO").unwrap_or_default()
    } else {
        distro.to_string()
    };
    if !distro.is_empty() {
        cmd.arg("-d").arg(distro);
    }
    let user = if as_root {
        "root".to_string()
    } else {
        std::env::var("WSL_USER").unwrap_or_default()
    };
    if !user.is_empty() {
        cmd.arg("--user").arg(user);
    }
}

// Real, confirmed gap this fixes: run.sh's own stdout/stderr (first-run venv creation, pip
// install -- deliberately NOT run with pip's -q, see run.sh's own comment on why silent output
// there once got mistaken for a hang -- and any Python traceback before uvicorn starts) was never
// captured at all when launched from this GUI exe (`windows_subsystem = "windows"`, no console to
// inherit) -- it simply vanished, so a legitimate multi-minute first-time dependency install and a
// genuinely broken backend were indistinguishable from the start screen: both just showed "Starting
// backend..." until the 300s readiness timeout, with nothing for the operator to actually look at.
// Redirecting both streams straight into a file (fresh each launch, `Command::stdout`/`stderr`
// taking the file's own handle -- no shell redirection or wslpath translation needed, since the
// child process inherits whichever handle Rust itself already opened on the host side) means the
// REAL cause -- a pip resolver still working, or a real traceback -- is always on disk and named
// in the readiness-timeout error below, with no extra manual step (opening a terminal, running
// run.sh by hand) required to see it.
fn backend_launch_log_path(env_text: &str) -> PathBuf {
    resolve_app_dir(env_text).join("backend-launch.log")
}

fn open_backend_launch_log(env_text: &str) -> std::io::Result<std::fs::File> {
    let path = backend_launch_log_path(env_text);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::File::create(&path)
}

#[cfg(windows)]
fn spawn_backend(
    repo: &Path,
    as_root: bool,
    distro: &str,
    ui_token: &str,
    log_file: std::fs::File,
) -> std::io::Result<Child> {
    let win_path = repo.to_string_lossy().replace('\'', "'\\''");
    // Inject the UI token, plus this binary's own version/platform, as prefix envs of the inner
    // command so run.sh's own `source .env` cannot clobber them. ASRA_DESKTOP_VERSION/PLATFORM let
    // the Python backend (agent/desktop_update.py) know whether it's running under the desktop
    // shell at all, and which GitHub Release asset would match THIS binary if a newer one exists --
    // std::env::consts::OS, not sys.platform on the Python side, since under this Windows/WSL2
    // launch path the backend's own sys.platform is always "linux" (see CLAUDE.md's runtime-
    // architecture rule), which would resolve to the wrong release asset if read from there instead.
    let token_prefix = if ui_token.is_empty() {
        String::new()
    } else {
        format!("ASRA_UI_TOKEN='{ui_token}' ")
    };
    let version = env!("CARGO_PKG_VERSION");
    let platform = std::env::consts::OS;
    let inner = format!(
        "cd \"$(wslpath -a '{win_path}')\" && ASRA_DESKTOP_VERSION='{version}' ASRA_DESKTOP_PLATFORM='{platform}' {token_prefix}bash run.sh"
    );
    let mut cmd = Command::new("wsl.exe");
    apply_wsl_target(&mut cmd, as_root, distro);
    cmd.arg("--")
        .arg("bash")
        .arg("-lc")
        .arg(inner)
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(log_file.try_clone()?)
        .stderr(log_file);
    cmd.spawn()
}

#[cfg(not(windows))]
fn spawn_backend(
    repo: &Path,
    _as_root: bool,
    _distro: &str,
    ui_token: &str,
    log_file: std::fs::File,
) -> std::io::Result<Child> {
    let mut cmd = Command::new("bash");
    cmd.arg("run.sh").current_dir(repo);
    if !ui_token.is_empty() {
        cmd.env("ASRA_UI_TOKEN", ui_token);
    }
    // Same desktop-update signal as the Windows branch above -- see its comment for why this has
    // to come from the shell (std::env::consts::OS), not guessed on the Python side.
    cmd.env("ASRA_DESKTOP_VERSION", env!("CARGO_PKG_VERSION"));
    cmd.env("ASRA_DESKTOP_PLATFORM", std::env::consts::OS);
    cmd.stdout(log_file.try_clone()?).stderr(log_file);
    cmd.spawn()
}

// Per-launch secret that locks the desktop-mode UI to this window (see the backend's
// ASRA_UI_TOKEN gate). Not persisted anywhere; regenerated on every launch.
fn gen_token() -> String {
    let mut buf = [0u8; 16];
    if getrandom::getrandom(&mut buf).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        buf.copy_from_slice(&nanos.to_le_bytes());
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// Open the familiar DEBUG console (scripts/debug_console.ps1) the same way run.bat does:
// seed the console appearance in the registry, fetch CATEGORY_COLORS once from its single
// source of truth via WSL, then start a plain PowerShell tail of the global debug log.
// Windows only -- on Linux/macOS run.sh opens its own debug terminal.
#[cfg(windows)]
fn open_debug_console(repo: &Path, env_text: &str, as_root: bool, distro: &str) {
    let app_dir = resolve_app_dir(env_text);
    let _ = std::fs::create_dir_all(&app_dir);
    let log_path = app_dir.join("debug.log");
    if !log_path.exists() {
        let _ = std::fs::write(&log_path, b"");
    }

    // Console appearance, pre-seeded before the window exists so it opens at the right
    // size (same keys/values run.bat writes). Best-effort; failures are cosmetic.
    let font_h: i64 = env_value(env_text, "DEBUG_CONSOLE_FONT_SIZE")
        .and_then(|s| s.parse().ok())
        .unwrap_or(28);
    let font_packed = (font_h / 2) + font_h * 65536;
    let win_w: i64 = env_value(env_text, "DEBUG_CONSOLE_WIDTH")
        .and_then(|s| s.parse().ok())
        .unwrap_or(90);
    let win_h: i64 = env_value(env_text, "DEBUG_CONSOLE_HEIGHT")
        .and_then(|s| s.parse().ok())
        .unwrap_or(25);
    let win_packed = win_w + win_h * 65536;
    let buf_packed = win_w + 3000 * 65536;
    let key = r"HKCU\Console\ASRA Debug Log";
    let reg = |value: &str, kind: &str, data: &str| {
        let _ = Command::new("reg.exe")
            .args(["add", key, "/v", value, "/t", kind, "/d", data, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .status();
    };
    reg("LineWrap", "REG_DWORD", "0");
    reg("FontSize", "REG_DWORD", &font_packed.to_string());
    reg("FaceName", "REG_SZ", "Consolas");
    reg("FontFamily", "REG_DWORD", "54");
    reg("FontWeight", "REG_DWORD", "400");
    reg("WindowSize", "REG_DWORD", &win_packed.to_string());
    reg("ScreenBufferSize", "REG_DWORD", &buf_packed.to_string());

    // Category colors from their single source of truth (agent/utils/debug.py), fetched
    // once non-interactively via WSL and written for the PowerShell tail to read.
    let colors_file = std::env::temp_dir().join("asra_category_colors.json");
    let win_repo = repo.to_string_lossy().replace('\'', "'\\''");
    let inner = format!(
        "cd \"$(wslpath -a '{win_repo}')\" && ./venv/bin/python -c \"import json,sys; sys.path.insert(0, '.'); from agent.utils.debug import CATEGORY_COLORS; print(json.dumps(CATEGORY_COLORS))\""
    );
    let mut colors_cmd = Command::new("wsl.exe");
    apply_wsl_target(&mut colors_cmd, as_root, distro);
    colors_cmd
        .arg("--")
        .arg("bash")
        .arg("-lc")
        .arg(&inner)
        .creation_flags(CREATE_NO_WINDOW);
    if let Ok(out) = colors_cmd.output() {
        let _ = std::fs::write(&colors_file, &out.stdout);
    }

    // Launcher .cmd, then `start` a real console window running the PowerShell tail.
    let ps1 = repo.join("scripts").join("debug_console.ps1");
    let launcher = std::env::temp_dir().join("asra_debug_console.cmd");
    let launcher_body = format!(
        "@echo off\r\ntitle ASRA Debug Log\r\npowershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File \"{}\" -LogPath \"{}\" -ColorsFile \"{}\" -Width {} -Height {}\r\n",
        ps1.display(),
        log_path.display(),
        colors_file.display(),
        win_w,
        win_h
    );
    if std::fs::write(&launcher, launcher_body).is_ok() {
        let _ = Command::new("cmd")
            .args([
                "/c",
                "start",
                "ASRA Debug Log",
                "cmd",
                "/k",
                &launcher.to_string_lossy(),
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        eprintln!("[ASRA-DESKTOP] opened DEBUG console (DEBUG=true)");
    }
}

fn stop_backend(owned: &OwnedBackend) {
    let mut guard = owned.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(mut backend) = guard.take() else {
        return;
    };
    eprintln!("[ASRA-DESKTOP] stopping backend (clean SIGINT)");

    #[cfg(windows)]
    {
        let mut kill = Command::new("wsl.exe");
        apply_wsl_target(&mut kill, backend.as_root, &backend.distro);
        kill.arg("--")
            .arg("bash")
            .arg("-lc")
            .arg("pkill -INT -f 'python main.py'")
            .creation_flags(CREATE_NO_WINDOW);
        let _ = kill.status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .arg("-INT")
            .arg(backend.child.id().to_string())
            .status();
    }

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match backend.child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            _ => {
                let _ = backend.child.kill();
                let _ = backend.child.wait();
                break;
            }
        }
    }
}

// ---- commands -----------------------------------------------------------------

#[tauri::command]
fn get_start_config() -> StartConfig {
    let repo = repo_dir();
    let env_text = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    // Timed on purpose: list_wsl_distros() runs `wsl.exe -l -v` synchronously on the start
    // screen's own load, before the operator has clicked anything -- a cold WSL2 VM (not already
    // running) can make this the actual source of a "slow to open" complaint, and until this line
    // existed nothing recorded how long it took.
    let wsl_probe_start = Instant::now();
    let distros = list_wsl_distros();
    let wsl_installed = wsl_is_installed();
    let wsl_probe_ms = wsl_probe_start.elapsed().as_millis();
    let settings = parse_env_settings(&env_text);
    let repo_found = repo.join("run.sh").is_file();
    eprintln!(
        "[ASRA-DESKTOP] start screen loaded (os={}, wsl_installed={}, wsl_distros={}, env_settings={}, run_as_root={}, repo_found={})",
        std::env::consts::OS,
        wsl_installed,
        distros.len(),
        settings.len(),
        env_flag(&env_text, "ASRA_RUN_AS_ROOT"),
        repo_found
    );
    append_desktop_log_line(
        &env_text,
        &format!(
            "start screen loaded: os={} wsl_installed={} wsl_distros={} wsl_probe_ms={} env_settings={} run_as_root={} repo_found={}",
            std::env::consts::OS,
            wsl_installed,
            distros.len(),
            wsl_probe_ms,
            settings.len(),
            env_flag(&env_text, "ASRA_RUN_AS_ROOT"),
            repo_found
        ),
    );
    StartConfig {
        os: std::env::consts::OS.to_string(),
        // env!("CARGO_PKG_VERSION") reads Cargo.toml's own [package] version at compile time --
        // one number to bump per release (Cargo.toml, this build reads it automatically), never a
        // second hardcoded copy that could drift from what actually got built.
        version: env!("CARGO_PKG_VERSION").to_string(),
        default_mode: "desktop".to_string(),
        run_as_root: env_flag(&env_text, "ASRA_RUN_AS_ROOT"),
        intro_enabled: env_flag_default(&env_text, "ASRA_INTRO_ENABLED", true),
        intro_sound_enabled: env_flag_default(&env_text, "ASRA_INTRO_SOUND_ENABLED", true),
        wsl_installed,
        wsl_default_distro: default_wsl_install_distro(&env_text),
        distros,
        settings,
        repo_found,
        just_installed: std::env::var("ASRA_JUST_INSTALLED").ok().filter(|s| !s.is_empty()),
    }
}

// Desktop shell self-update -- the Python backend (agent/desktop_update.py) downloads and
// SHA256-verifies the new binary against the release's own SHA256SUMS.txt BEFORE ever calling
// this; this command only ever receives an already-verified path and does the actual file swap +
// relaunch, the one part only the shell itself (not its own child backend process) can safely do.
//
// Windows cannot overwrite or delete a running .exe's file in place, but CAN rename it -- the
// currently-running process keeps executing fine from its own already-open handle to the
// renamed-away file, while the original path is freed for the new binary to take. Unix allows an
// outright overwrite too, but the same rename-based swap works identically there, so one code
// path covers all three platforms instead of an OS-specific branch. The renamed-away old binary
// can't be deleted here (still open/locked by THIS running process on Windows) -- it's cleaned up
// at the START of the NEXT launch instead (see main()'s own startup cleanup below), once nothing
// holds it open anymore.
#[tauri::command]
fn apply_desktop_update(app: AppHandle, staged_path: String) -> Result<(), String> {
    let staged = PathBuf::from(&staged_path);
    if !staged.is_file() {
        return Err(format!("Staged update file not found: {staged_path}"));
    }
    let current = std::env::current_exe()
        .map_err(|e| format!("Could not resolve the running executable's own path: {e}"))?;
    let backup = current.with_extension("old");
    // Best-effort: a leftover .old from an update that staged but never got cleaned up (e.g. this
    // process crashed before its own next startup ran the cleanup) must never block a fresh one.
    let _ = std::fs::remove_file(&backup);

    std::fs::rename(&current, &backup)
        .map_err(|e| format!("Could not rename the running executable out of the way: {e}"))?;
    if let Err(e) = std::fs::rename(&staged, &current) {
        // Roll back immediately so the install is never left with no exe at its real path at all.
        let _ = std::fs::rename(&backup, &current);
        return Err(format!("Could not move the new binary into place (rolled back): {e}"));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&current) {
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o111);
            let _ = std::fs::set_permissions(&current, perms);
        }
    }

    let mut cmd = Command::new(&current);
    #[cfg(windows)]
    cmd.creation_flags(DETACHED_PROCESS);
    cmd.spawn().map_err(|e| {
        format!("Swap succeeded, but relaunching failed -- start {} yourself: {e}", current.display())
    })?;

    app.exit(0);
    Ok(())
}

// An operator who downloaded only the standalone exe from a GitHub Release (no ASRA checkout
// above it -- see repo_dir()'s own fallback and get_start_config's repo_found) has nothing for
// launch_backend to actually run; this is the start screen's "pick a folder & install" fix for
// that. Unlike apply_desktop_update above, this COPIES the running exe rather than renaming it --
// the original download is left alone where the operator put it, not replaced in place -- then
// spawns the installed copy and exits, so the session continues seamlessly from the real checkout.
#[tauri::command]
fn bootstrap_full_project(app: AppHandle) -> Result<(), String> {
    let picked = app
        .dialog()
        .file()
        .set_title("Choose where to install the full ASRA project")
        .blocking_pick_folder()
        .ok_or_else(|| "cancelled".to_string())?;
    let picked_path = picked
        .into_path()
        .map_err(|e| format!("could not resolve the picked folder: {e}"))?;

    // No real repo exists yet at this point (that's the whole reason this command exists) -- this
    // is only ever used to decide whether DEBUG logging is on and where the global app dir is,
    // same as open_external_url's own env_text read above, never anything functional.
    let log_env_text = std::fs::read_to_string(repo_dir().join(".env"))
        .or_else(|_| std::fs::read_to_string(repo_dir().join(".env.example")))
        .unwrap_or_default();
    append_desktop_log_line(
        &log_env_text,
        &format!("bootstrap_full_project: installing into {}", picked_path.join("ASRA").display()),
    );

    // Always nest under one fixed subfolder name, whatever parent the operator picked -- never
    // write repo files loose into a folder that might already hold unrelated stuff of theirs.
    let target = picked_path.join("ASRA");
    if target.join("run.sh").is_file() {
        // Already bootstrapped here before (a retry, or a second launch of the leftover exe) --
        // nothing to download again, just adopt it as-is.
    } else if target.exists() {
        let has_entries = std::fs::read_dir(&target)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);
        if has_entries {
            return Err(format!(
                "{} already exists and isn't an ASRA checkout (no run.sh) -- pick an empty or different folder.",
                target.display()
            ));
        }
        download_and_extract_repo(&target)?;
    } else {
        std::fs::create_dir_all(&target)
            .map_err(|e| format!("could not create {}: {e}", target.display()))?;
        download_and_extract_repo(&target)?;
    }

    // Recorded as soon as `target` is confirmed to hold a real checkout -- see repo_dir()'s own
    // fallback for why: this is what lets ANY copy of this exe (including the operator's original
    // download, left alone right where they put it) find this same install on its own next launch,
    // not just the freshly relaunched copy below.
    record_install_location(&target);

    let current = std::env::current_exe()
        .map_err(|e| format!("could not resolve the running executable's own path: {e}"))?;
    let filename = current
        .file_name()
        .ok_or_else(|| "running executable has no file name".to_string())?;
    // Placed directly at the installed project's own root (not desktop/bin/, where a git-clone
    // developer's own cargo-built copy lives) -- an exe-only operator never sees or cares about
    // that internal layout, they just want the one obvious thing to double-click sitting right
    // where they can see it when they open the folder they picked.
    let installed_exe = target.join(filename);
    std::fs::copy(&current, &installed_exe).map_err(|e| {
        format!("could not copy the running executable into {}: {e}", installed_exe.display())
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&installed_exe) {
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o111);
            let _ = std::fs::set_permissions(&installed_exe, perms);
        }
    }

    let mut cmd = Command::new(&installed_exe);
    #[cfg(windows)]
    cmd.creation_flags(DETACHED_PROCESS);
    cmd.env("ASRA_JUST_INSTALLED", target.to_string_lossy().to_string());
    cmd.spawn().map_err(|e| {
        format!(
            "ASRA was installed to {}, but relaunching failed -- start {} yourself: {e}",
            target.display(),
            installed_exe.display()
        )
    })?;

    append_desktop_log_line(
        &log_env_text,
        &format!("bootstrap_full_project: installed and relaunched from {}", installed_exe.display()),
    );

    // The originally downloaded installer .exe (e.g. sitting in Downloads) has done its one job
    // and would otherwise just sit there forever as a confusing leftover duplicate -- clean it up
    // automatically instead of leaving the operator to notice and delete it themselves. Skipped
    // when it's already the same file as the installed copy (re-running bootstrap from inside an
    // existing install, pointed at that same install) -- nothing to delete out from under itself.
    if current != installed_exe {
        self_delete_after_exit(&current, &log_env_text);
    }

    app.exit(0);
    Ok(())
}

// Deletes `path` once the CURRENT process has exited and released its lock on it. A running
// executable's own file can't just be removed in place on Windows (ERROR_SHARING_VIOLATION --
// the OS keeps it locked while it's the image of a running process) the way apply_desktop_update's
// rename-in-place trick works around for a same-directory self-update; here `path` is somewhere
// else entirely (wherever the operator originally downloaded it), so there's no later startup of
// THAT file to run a cleanup pass on it either -- it needs to go away on its own, shortly after
// this process exits. On Unix, deleting a running binary's own file works immediately (unlinking
// only removes the directory entry; the process keeps using its already-open inode), so no helper
// is needed there at all.
fn self_delete_after_exit(path: &Path, log_env_text: &str) {
    #[cfg(windows)]
    {
        let mut cmd = Command::new("cmd");
        cmd.arg("/C")
            // `ping -n 2 127.0.0.1` is the standard trick for "wait ~1s with no console/GUI
            // prompt" in a detached cmd -- `timeout` refuses to run without a real attached
            // console, which this DETACHED_PROCESS deliberately has none of.
            .arg(format!(
                "ping -n 2 127.0.0.1 >nul & del /f /q \"{}\"",
                path.display()
            ))
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
        match cmd.spawn() {
            Ok(_) => append_desktop_log_line(
                log_env_text,
                &format!("bootstrap_full_project: scheduled cleanup of the original installer at {}", path.display()),
            ),
            Err(e) => append_desktop_log_line(
                log_env_text,
                &format!("bootstrap_full_project: could not schedule cleanup of {}: {e} (harmless leftover file)", path.display()),
            ),
        }
    }
    #[cfg(not(windows))]
    {
        match std::fs::remove_file(path) {
            Ok(()) => append_desktop_log_line(
                log_env_text,
                &format!("bootstrap_full_project: removed the original installer at {}", path.display()),
            ),
            Err(e) => append_desktop_log_line(
                log_env_text,
                &format!("bootstrap_full_project: could not remove {}: {e} (harmless leftover file)", path.display()),
            ),
        }
    }
}

// Downloads the GitHub source archive matching this exe's own Cargo.toml version (falls back to
// the main branch if that tag was never pushed -- e.g. a dev build whose release never shipped)
// and extracts it into `target` with the archive's own top-level "ASRA-<version>/" wrapper
// stripped. Shells out to curl/tar -- both already bundled on Windows 10+/macOS/Linux -- rather
// than adding HTTP/zip crates, the same choice every other network-ish thing in this file already
// makes (wsl.exe, bash, powershell.exe).
// GitHub's tag-name archive URL goes through codeload.github.com's own CDN cache, keyed by that
// URL -- confirmed live, this is a real bug, not a hypothesis: redoing a release in place
// (deleting and recreating the SAME tag name, this project's established pattern for fixing an
// already-published version without bumping it) does not reliably bust that cache. An operator
// re-bootstrapping shortly after a redo-release kept getting an old cached archive back from the
// unchanged tag URL, silently undoing a real fix with no error anywhere to explain it -- the tag
// itself was correct on GitHub the whole time, confirmed by fetching it directly and comparing.
// Archive-by-commit-SHA URLs (.../archive/<sha>.tar.gz) are immutable: a different commit is a
// different URL, so there's no stale cache entry to ever hit. Resolving the tag to its commit SHA
// first and downloading THAT URL is what actually avoids the bug.
fn resolve_tag_commit_sha(version: &str) -> Option<String> {
    let output = Command::new("curl")
        .arg("-fsSL")
        .arg(format!(
            "https://api.github.com/repos/Atennebris/ASRA/git/refs/tags/v{version}"
        ))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&output.stdout);
    let after_key = body.find("\"sha\":")? + "\"sha\":".len();
    let rest = body[after_key..].trim_start().strip_prefix('"')?;
    let sha = &rest[..rest.find('"')?];
    (sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit())).then(|| sha.to_string())
}

fn download_and_extract_repo(target: &Path) -> Result<(), String> {
    let version = env!("CARGO_PKG_VERSION");
    let archive = std::env::temp_dir().join(format!("asra-bootstrap-{}.tar.gz", std::process::id()));
    let sha_url = resolve_tag_commit_sha(version)
        .map(|sha| format!("https://github.com/Atennebris/ASRA/archive/{sha}.tar.gz"));
    let tagged_url = format!("https://github.com/Atennebris/ASRA/archive/refs/tags/v{version}.tar.gz");
    let main_url = "https://github.com/Atennebris/ASRA/archive/refs/heads/main.tar.gz";

    let download = |url: &str| -> bool {
        Command::new("curl")
            .arg("-fsSL")
            .arg("-o")
            .arg(&archive)
            .arg(url)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    // SHA URL first (immune to the cache bug above), then the tag URL, then main -- same overall
    // fallback shape as before, just with the one reliable option tried ahead of the risky one.
    let downloaded = sha_url.as_deref().map(download).unwrap_or(false)
        || download(&tagged_url)
        || download(main_url);
    if !downloaded {
        let _ = std::fs::remove_file(&archive);
        return Err(format!(
            "could not download the ASRA source archive (tried v{version} and main) -- check your internet connection"
        ));
    }

    let extract = Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("--strip-components=1")
        .arg("-C")
        .arg(target)
        .status();
    let _ = std::fs::remove_file(&archive);

    match extract {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("tar exited with status {status} while extracting the ASRA archive")),
        Err(e) => Err(format!("could not run tar to extract the ASRA archive: {e}")),
    }
}

// Real, confirmed bug this floor fixes: the intro (Settings -> Customization -> Visual's "Play
// launch intro" switch, dist/index.html) was written assuming the backend always takes at least a
// few seconds to become reachable -- true for a genuinely fresh launch, but NOT true the moment
// port_is_up() below finds an already-running backend to adopt (a previous launch left running,
// minimized to the tray rather than quit) -- wait_for_port then returns almost instantly and
// window.navigate() below fires within milliseconds, cutting the intro off well under a second
// in. Reported live: "start -> intro plays for under a second -> straight into the app." Below
// enforces a floor on the total time between this command starting and the point it hands off
// (web mode's return / desktop mode's navigate), so the intro always gets to actually finish
// playing regardless of how fast the backend itself turns out to be -- exactly like a real game
// intro, which plays out in full even when the disk read behind it was instant. Skipped entirely
// when the intro is off, so turning it off is still the zero-added-latency path it always was.
// Real, confirmed second incident on top of the one above: this floor itself drifted stale after
// dist/index.html's own sequence grew from one impact to three (ATENNEBRIS at t=3.0s, "presents"
// at t=5.0s, the full product name at t=7.0s, last one-shot animation -- introFlash--3 -- ending
// at 7.6s, see that file's own "Total settled ~7.3s" comment and its per-impact timing block)
// while this constant was left at its OLD value from when the sequence really was only ~4.1s long
// -- the exact "keep this in sync" maintenance this comment already asked for, just never done.
// Reported live: the intro visibly cut off mid-flight on the SECOND text ("presents", which
// doesn't even finish flying in and striking until 5.0s) whenever the backend was fast enough to
// adopt an already-running instance -- 4600ms lands well before that, let alone the third impact
// or the settled ambient state after it. 8100ms = 7600ms (the real last one-shot animation event)
// plus the same ~500ms settle-and-be-seen buffer the original value already used, scaled to the
// CURRENT sequence length instead of the old one. Keep this in sync with dist/index.html's own
// timing if that file's sequence length changes again.
const MIN_INTRO_DISPLAY: Duration = Duration::from_millis(8100);

#[tauri::command]
async fn launch_backend(app: AppHandle, args: LaunchArgs) -> Result<String, String> {
    let launch_start = Instant::now();
    let repo = repo_dir();
    // repo_dir() falls back to the exe's own (or current) directory when it can't find run.sh
    // anywhere above it -- which happens whenever someone runs this binary on its own, downloaded
    // straight from a GitHub Release, without the rest of the ASRA repo next to it. Every step
    // below (writing .env, spawning `bash run.sh` in WSL/natively, waiting for a port to open)
    // would otherwise run against that wrong folder and only fail, confusingly, after the full
    // readiness timeout -- exactly what happened to an operator's friend who grabbed only the
    // .exe. Catch it here, before touching the filesystem or spawning anything, with a message
    // that says what's actually missing instead of a bare "did not come up in time".
    if !repo.join("run.sh").is_file() {
        let msg = format!(
            "This isn't a full ASRA checkout -- no run.sh found next to (or above) {}. \
            This .exe is the desktop shell only; it needs the full ASRA project alongside it. \
            Clone or download https://github.com/Atennebris/ASRA and put this binary in its \
            desktop/bin/ folder (or run it via run.bat from inside that project).",
            repo.display()
        );
        append_desktop_log_line(&std::fs::read_to_string(repo.join(".env")).unwrap_or_default(), &msg);
        return Err(msg);
    }
    let original = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    let new_env = rewrite_env(&original, &args.updates);
    std::fs::write(repo.join(".env"), &new_env).map_err(|e| format!("could not write .env: {e}"))?;

    // With DEBUG on, open the familiar tail console (Windows). Linux/macOS run.sh does its own.
    #[cfg(windows)]
    if is_debug_enabled(&new_env) {
        open_debug_console(&repo, &new_env, args.as_root, &args.distro);
    }

    let port = port_from_env_text(&new_env);
    let backend_url = format!("http://127.0.0.1:{port}");
    let mut already_up = port_is_up(&port);
    // Something's answering -- but is it running CURRENT code, or a stale instance from before
    // today's edits? A bare "does anything answer" check (the old behavior) would silently adopt
    // a stale backend forever, since an adopted backend is never stored in OwnedBackend and so is
    // never a candidate for this app's own stop/restart logic to end later either -- see the
    // real incident recorded on kill_stale_backend_by_pattern's own comment above.
    //
    // wsl_wedged tracks a DIFFERENT real incident from the one above: a bare TCP connect (what
    // already_up itself checks) only proves wslrelay.exe's Windows-side listen socket is open --
    // not that anything behind it can actually answer. WSL2's own VM can go fully unresponsive
    // (`wsl.exe -- ...` failing with Wsl/Service/0x8007274c) while that relay keeps the socket
    // open, so remote_source_mtime (an actual HTTP round trip) returns None -- not "matches",
    // "mismatches" -- because it never got a response at all. The old code only ever compared
    // mtimes when BOTH sides resolved, so a fully unreachable backend fell through neither branch
    // and was silently adopted forever: three relaunches that same day (16:04, 16:07, 16:09) each
    // re-adopted the identical dead backend, the window opened (hidden behind other windows) and
    // immediately showed ERR_CONNECTION_RESET, with no error surfaced anywhere the operator could
    // see. A live backend always answers /api/system-health within remote_source_mtime's own
    // short timeout, so treat "no answer at all" as needing the same terminate-before-adopt
    // handling as "answers, but with old code" -- and if the kill attempt itself can't even
    // complete (WSL wedged, not just the python process), say so instead of adopting anyway.
    let mut wsl_wedged = false;
    if already_up {
        let remote_mtime = remote_source_mtime(&port);
        let local_mtime = local_main_py_mtime(&repo);
        let is_stale = matches!((remote_mtime, local_mtime), (Some(r), Some(l)) if r < l);
        let is_unreachable = remote_mtime.is_none();
        if is_stale || is_unreachable {
            let killed = kill_stale_backend_by_pattern(args.as_root, &args.distro);
            let cleared = wait_for_port_to_clear(&port, Duration::from_secs(8));
            append_desktop_log_line(
                &new_env,
                &format!(
                    "{} backend on port {port} terminated before adopt (killed={killed} port cleared={cleared})",
                    if is_stale { "stale" } else { "unreachable" }
                ),
            );
            // If it somehow refuses to die, fall through to "adopt" rather than spawn a SECOND
            // instance on top of one that might still be alive -- the exact duplicate-launch
            // hazard main.py's own probe-bind exists to prevent, from the other direction. But
            // only when we actually managed to ask it to die (killed=true) -- if the kill attempt
            // itself never completed, "still up" doesn't mean "alive and fine", it means WSL is
            // wedged, and adopting it would repeat the exact silent-failure incident this fixes.
            already_up = !cleared || port_is_up(&port);
            wsl_wedged = already_up && !killed;
        }
    }
    if wsl_wedged {
        let msg = "WSL2 itself is not responding (the stuck backend could not be stopped). Run \"wsl --shutdown\" yourself in a terminal -- this restarts WSL entirely, closing any other WSL terminals too -- or use Force Restart, then try again.".to_string();
        append_desktop_log_line(&new_env, &msg);
        return Err(msg);
    }
    // Desktop mode gets a per-launch UI token so a plain browser can't reach the backend;
    // web mode intentionally has none. Adoption can't set a token on a server we didn't start.
    let ui_token = if args.mode == "desktop" && !already_up {
        gen_token()
    } else {
        String::new()
    };
    eprintln!(
        "[ASRA-DESKTOP] launch: mode={} as_root={} distro='{}' port={} changed={}",
        args.mode,
        args.as_root,
        args.distro,
        port,
        args.updates.len()
    );
    append_desktop_log_line(
        &new_env,
        &format!(
            "launch: mode={} as_root={} distro='{}' port={} changed={} already_up={}",
            args.mode, args.as_root, args.distro, port, args.updates.len(), already_up
        ),
    );

    if already_up {
        eprintln!("[ASRA-DESKTOP] backend already up -- adopting it (won't stop it on close)");
    } else {
        let spawn_start = Instant::now();
        let log_file = open_backend_launch_log(&new_env)
            .map_err(|e| format!("could not open the backend launch log: {e}"))?;
        let child = spawn_backend(&repo, args.as_root, &args.distro, &ui_token, log_file)
            .map_err(|e| format!("could not start backend: {e}"))?;
        // Only the wsl.exe/bash *process spawn* itself, not the backend becoming reachable --
        // that part is the wait_for_port measurement right below. A slow spawn here (vs. a slow
        // wait_for_port after) tells apart "WSL2 VM was cold" from "the backend itself was slow to
        // come up once WSL was already running" -- two different real causes an operator report of
        // "the desktop app takes forever to start" could otherwise not distinguish between.
        append_desktop_log_line(
            &new_env,
            &format!("backend process spawned in {}ms (wsl.exe/bash invocation only, not readiness)", spawn_start.elapsed().as_millis()),
        );
        app.state::<OwnedBackend>().0.lock().unwrap().replace(Backend {
            child,
            as_root: args.as_root,
            distro: args.distro.clone(),
        });
    }

    let port_for_wait = port.clone();
    let app_for_wait = app.clone();
    let wait_start = Instant::now();
    let ready = tauri::async_runtime::spawn_blocking(move || {
        wait_for_port_adaptive(&port_for_wait, &app_for_wait)
    })
    .await
    .map_err(|e| format!("readiness wait failed: {e}"))?;
    append_desktop_log_line(
        &new_env,
        &format!("waited {}ms for backend port {} to come up (ready={})", wait_start.elapsed().as_millis(), port, ready),
    );

    if !ready {
        append_desktop_log_line(&new_env, "backend did not come up -- its own process exited without the port ever opening (or the 45-minute hard cap was hit)");
        let log_path = backend_launch_log_path(&new_env);
        let tail = std::fs::read_to_string(&log_path)
            .map(|text| {
                let lines: Vec<&str> = text.lines().collect();
                // A real pip wheel-build failure (compiler/cmake invocation + its own diagnostic
                // output) routinely runs well past 40 lines before pip's final "ERROR: Failed
                // building wheel for X" summary -- 40 was confirmed too short live: it cut off
                // exactly before the real underlying compiler error on a genuine pip build failure
                // (unicorn, a pwntools dependency), leaving only the unhelpful final line visible.
                let start = lines.len().saturating_sub(150);
                lines[start..].join("\n")
            })
            .unwrap_or_default();
        return Err(if tail.trim().is_empty() {
            format!(
                "backend did not come up in time -- nothing was captured at all in {}, so the process likely never even started (see above for a spawn error)",
                log_path.display()
            )
        } else {
            format!(
                "backend did not come up in time -- last output from run.sh (full log: {}):\n{}",
                log_path.display(),
                tail
            )
        });
    }

    if env_flag_default(&new_env, "ASRA_INTRO_ENABLED", true) {
        let remaining = MIN_INTRO_DISPLAY.saturating_sub(launch_start.elapsed());
        if !remaining.is_zero() {
            append_desktop_log_line(
                &new_env,
                &format!("holding {}ms for the launch intro to finish playing (backend was ready sooner)", remaining.as_millis()),
            );
            tauri::async_runtime::spawn_blocking(move || std::thread::sleep(remaining))
                .await
                .map_err(|e| format!("intro min-display wait failed: {e}"))?;
        }
    }

    if args.mode == "web" {
        // Web mode: hand back the URL. The browser is opened only on the explicit "Open"
        // click (open_in_browser), never automatically here.
        Ok(backend_url)
    } else {
        // First navigation carries the token as a query param; the backend then sets the
        // cookie every later same-origin request rides on.
        let nav_url = if ui_token.is_empty() {
            backend_url.clone()
        } else {
            format!("{backend_url}/?__asra={ui_token}")
        };
        let app_for_nav = app.clone();
        let _ = app.run_on_main_thread(move || {
            if let Some(window) = app_for_nav.get_webview_window("main") {
                if let Ok(parsed) = tauri::Url::parse(&nav_url) {
                    let _ = window.navigate(parsed);
                }
            }
        });
        Ok("desktop".to_string())
    }
}

// Manual escape hatch for the exact failure launch_backend's own wsl_wedged handling now detects
// automatically: a stuck/unreachable backend that keeps getting silently re-adopted on every
// relaunch. Deliberately narrow in scope -- only this app's own tracked child process (if any)
// and its own WSL process pattern ('python main.py' inside the ONE targeted distro), never a
// wider `wsl --shutdown` (that would kill every other distro and any other WSL terminal open at
// the time, including a concurrent session's own work) and never anything Windows-side beyond
// this app's own window. Returns a plain status string the start screen shows as-is; the operator
// still has to click Start again afterward -- this only clears the way, it doesn't relaunch.
#[tauri::command]
async fn force_restart_agent(app: AppHandle, distro: String, as_root: bool) -> Result<String, String> {
    let repo = repo_dir();
    let env_text = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    let port = port_from_env_text(&env_text);

    // Best-effort: only does anything if THIS shell spawned the current backend (OwnedBackend).
    // An adopted-but-now-wedged backend (the common case that sends an operator to this button)
    // was never stored there, so this is a no-op for it -- the pattern-based kill right below is
    // what actually reaches it.
    stop_backend(&app.state::<OwnedBackend>());

    let port_for_wait = port.clone();
    let killed = tauri::async_runtime::spawn_blocking(move || kill_stale_backend_by_pattern(as_root, &distro))
        .await
        .map_err(|e| format!("force restart failed: {e}"))?;
    let cleared = tauri::async_runtime::spawn_blocking(move || wait_for_port_to_clear(&port_for_wait, Duration::from_secs(8)))
        .await
        .map_err(|e| format!("force restart failed: {e}"))?;
    append_desktop_log_line(
        &env_text,
        &format!("force restart: killed={killed} port {port} cleared={cleared}"),
    );

    if !killed {
        return Err("WSL2 itself did not respond to the stop request -- it looks wedged. Run \"wsl --shutdown\" yourself in a terminal (this restarts WSL entirely, closing any other WSL terminals too), then click Start again.".to_string());
    }
    if !cleared {
        return Err("Stopped the backend process, but its port is still occupied -- wait a few seconds, then click Start again.".to_string());
    }
    Ok("Backend stopped. Click Start to launch a fresh one.".to_string())
}

// Persist changed .env values without starting anything, so the operator's choices are
// remembered for the next launch (the "Save" button on the start screen).
#[tauri::command]
fn save_env(updates: HashMap<String, String>) -> Result<(), String> {
    let repo = repo_dir();
    let original = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    let new_env = rewrite_env(&original, &updates);
    std::fs::write(repo.join(".env"), new_env).map_err(|e| format!("could not write .env: {e}"))?;
    eprintln!("[ASRA-DESKTOP] .env saved ({} changed)", updates.len());
    Ok(())
}

// Open a local URL in the operator's default browser. Fires ONLY on an explicit click of
// the web-mode "Open" button, never automatically -- so the project's no-auto-open rule
// still holds. Opened from this native shell via rundll32.exe's url.dll,FileProtocolHandler
// (see open_external_url below and spawn_default_browser's own comment for why this is NOT
// cmd.exe's "start" builtin), detached, so it cannot deliver the stray CTRL_C into the
// backend's process group that the rule's real incident was about. Loopback URLs only.
#[tauri::command]
fn open_in_browser(url: String) -> Result<(), String> {
    let repo = repo_dir();
    let env_text = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    if !(url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:")) {
        let msg = format!("refused to open non-local url: {url}");
        eprintln!("[ASRA-DESKTOP] {msg}");
        append_desktop_log_line(&env_text, &msg);
        return Err("refusing to open a non-local URL".to_string());
    }
    if let Err(e) = spawn_default_browser(&url) {
        let msg = format!("failed to open {url} in default browser: {e}");
        eprintln!("[ASRA-DESKTOP] {msg}");
        append_desktop_log_line(&env_text, &msg);
        return Err(e);
    }
    let msg = format!("opened {url} in default browser (user-initiated)");
    eprintln!("[ASRA-DESKTOP] {msg}");
    append_desktop_log_line(&env_text, &msg);
    Ok(())
}

// Shared OS-level "open this URL in the default browser" launch, detached (no window of its
// own, survives this process exiting). Windows: `rundll32.exe url.dll,FileProtocolHandler`, NOT
// cmd.exe's "start" builtin -- that was tried here first and reverted after it broke the
// ChatGPT sign-in flow ("Authentication Error: A required parameter is missing" from
// auth.openai.com). Root-caused by direct reproduction on 2026-09-02: even though the URL is
// passed to Command::args as its own argv element (so Rust's own quoting is correct),
// `cmd.exe /C start "" "<url>"` still hands the WHOLE line to cmd's own interpreter, and cmd
// treats every unescaped `&` in it as a command separator regardless of the surrounding double
// quotes -- confirmed with `cmd.exe /C start "" "http://x/?a=1&b=2"` actually attempting to run
// `b=2` as a second command. An OAuth authorize URL is exactly the shape this destroys
// (client_id/redirect_uri/code_challenge/state/scope chained with `&`): only the parameters
// before the first `&` survive, so OpenAI's server sees `response_type=code` and nothing else.
// rundll32's FileProtocolHandler takes the URL as a single argv element with no shell
// re-parsing in between, and was re-verified directly against a local test server with a
// same-length/shape synthetic OAuth URL (373 chars, same param set) -- the full query string,
// every `&`, arrived intact. (Plain `explorer.exe <url>` was also tried as a third option and
// rejected: in this environment it doesn't reliably launch the default browser at all --
// observed opening bare File Explorer windows instead.)
fn spawn_default_browser(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        Command::new("rundll32.exe")
            .args(["url.dll,FileProtocolHandler", url])
            .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
            .spawn()
            .map_err(|e| e.to_string())?;
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open").arg(url).spawn().map_err(|e| e.to_string())?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open").arg(url).spawn().map_err(|e| e.to_string())?;
    }
    Ok(())
}

// Opens an ARBITRARY http(s) URL -- a Library source's own article link, an OAuth provider's
// authorization page (Settings' Codex/Copilot "Connect" flow), a "Get a key" link, and anywhere
// else the web UI already uses <a target="_blank"> or window.open() -- in the operator's default
// OS browser. The counterpart to open_in_browser above, which is deliberately loopback-only for
// this app's own local UI; this one is for links that are deliberately NOT that. Real, confirmed
// operator complaint: inside this desktop shell's own webview, a plain target="_blank" link or
// window.open() call just does nothing at all -- Tauri's webview has no default handling for
// "open this in a real OS browser window" wired up, and main.rs's own window.navigate() only ever
// retargets THIS window, it doesn't spawn a new one. static/js/external_links.js is the one
// shared frontend fix (window.__TAURI__-gated, same pattern session.html's own
// notify_session_done call already uses) that routes every such link/call through this command
// instead of patching each site individually. Same OS-level launch mechanism as open_in_browser
// (spawn_default_browser -- rundll32.exe url.dll,FileProtocolHandler on Windows, detached, no
// window of its own), but scheme-validated via a real URL parse (http/https only) rather than a
// string-prefix check, since this command's whole point is accepting URLs open_in_browser would
// refuse. Real, confirmed second-round incident: even after this command shipped correctly
// wired end to end, the operator's own Codex/Copilot "Connect" clicks still silently did nothing
// -- at the time this was pinned on rundll32's FileProtocolHandler itself supposedly mishandling
// long query strings, and the launch mechanism was swapped to cmd.exe's "start" builtin instead.
// That diagnosis was wrong: it was re-tested directly (2026-09-02, see spawn_default_browser's
// own comment) and rundll32 handles a same-shape/length OAuth URL perfectly, while "start" is the
// one that actually corrupts it -- cmd.exe treats every `&` in the query string as a command
// separator even inside the double-quoted URL, so it silently ships only the parameters before
// the first `&`. That regression is what broke ChatGPT sign-in ("A required parameter is
// missing"); rundll32 is back. The original "Connect does nothing" symptom this paragraph used to
// blame on rundll32 was most likely the frontend's own bare `.catch(function(){})` swallowing
// whatever error DID come back, not the launch mechanism -- fixed here regardless: every failure
// path now logs to stderr and this app's own debug.log (append_desktop_log_line) before returning
// its Err, so a silent failure is never silent again.
#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    let repo = repo_dir();
    let env_text = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    let parsed = match tauri::Url::parse(&url) {
        Ok(p) => p,
        Err(e) => {
            let msg = format!("refused to open external url (parse error on {url:?}): {e}");
            eprintln!("[ASRA-DESKTOP] {msg}");
            append_desktop_log_line(&env_text, &msg);
            return Err(e.to_string());
        }
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        let msg = format!("refused to open external url with non-http(s) scheme: {url}");
        eprintln!("[ASRA-DESKTOP] {msg}");
        append_desktop_log_line(&env_text, &msg);
        return Err("refusing to open a non-http(s) URL".to_string());
    }
    if let Err(e) = spawn_default_browser(&url) {
        let msg = format!("failed to open external url {url} in default browser: {e}");
        eprintln!("[ASRA-DESKTOP] {msg}");
        append_desktop_log_line(&env_text, &msg);
        return Err(e);
    }
    let msg = format!("opened external url in default browser (user-initiated): {url}");
    eprintln!("[ASRA-DESKTOP] {msg}");
    append_desktop_log_line(&env_text, &msg);
    Ok(())
}

// Fire a native OS notification. Called by the web UI (session.html) only when a session reaches a
// terminal state -- it rides on the app's own SSE stream as the single source of truth, never a
// second one. Desktop-only: the caller guards on window.__TAURI__ being present.
#[tauri::command]
fn notify_session_done(app: AppHandle, title: String, body: String) -> Result<(), String> {
    app.notification()
        .builder()
        .title(title)
        .body(body)
        .show()
        .map_err(|e| e.to_string())?;
    Ok(())
}

// Kicks off `wsl --install` (mode "install-wsl") or `wsl --install -d <distro>` (mode
// "install-distro") elevated, for the start screen's own "Install WSL"/"Install <distro>"
// buttons (see renderSystem()'s wsl_installed/distros-empty branches, dist/index.html). Detached
// and non-blocking by design -- same fire-and-forget shape as
// agent/tools/arsenal_install.py's start_arsenal_install, with get_wsl_setup_status below as the
// poll target the frontend tails every ~2s, mirroring arsenal_install.html's own log window.
//
// `wsl --install` needs admin rights (Windows shows its own UAC prompt); elevating is done via
// `Start-Process -Verb RunAs`, which cannot also redirect the elevated child's stdout/stderr
// itself (a documented PowerShell limitation) -- so the REAL install work and its log redirection
// both happen one level down, inside scripts/wsl_setup.ps1, which runs already-elevated and
// redirects ITS OWN child (wsl.exe) into -LogPath without hitting that restriction at all.
#[cfg(windows)]
#[tauri::command]
fn install_wsl(args: WslSetupArgs) -> Result<(), String> {
    let repo = repo_dir();
    let env_text = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    let app_dir = resolve_app_dir(&env_text);
    std::fs::create_dir_all(&app_dir)
        .map_err(|e| format!("could not create {}: {e}", app_dir.display()))?;
    let log_path = app_dir.join("wsl-setup.log");
    let distro = if args.distro.trim().is_empty() {
        default_wsl_install_distro(&env_text)
    } else {
        args.distro.clone()
    };

    // Fresh header on every attempt -- a retry after a cancelled UAC prompt must not show the
    // previous attempt's stale tail as if it were still relevant.
    let header = format!(
        "=== ASRA WSL setup started: mode={} distro={} ({}) ===\r\n",
        args.mode,
        distro,
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
    );
    std::fs::write(&log_path, header)
        .map_err(|e| format!("could not write {}: {e}", log_path.display()))?;

    let ps1 = repo.join("scripts").join("wsl_setup.ps1");
    // One flat argument string, exactly like every other inner-command string this file already
    // builds for wsl.exe/bash -- Start-Process -ArgumentList accepts a single string and hands it
    // to the elevated process's own command-line parsing unchanged. Any literal single quote is
    // doubled for the single-quoted PowerShell string this gets embedded in below.
    let inner_args = format!(
        "-NoProfile -ExecutionPolicy Bypass -File \"{}\" -LogPath \"{}\" -Mode \"{}\" -Distro \"{}\"",
        ps1.display(),
        log_path.display(),
        args.mode,
        distro
    )
    .replace('\'', "''");
    let elevate_cmd = format!("Start-Process powershell.exe -Verb RunAs -ArgumentList '{inner_args}'");

    append_desktop_log_line(
        &env_text,
        &format!("WSL setup requested: mode={} distro={}", args.mode, distro),
    );
    Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &elevate_cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("could not launch WSL setup: {e}"))?;
    Ok(())
}

#[cfg(not(windows))]
#[tauri::command]
fn install_wsl(_args: WslSetupArgs) -> Result<(), String> {
    Err("WSL is Windows-only".to_string())
}

// Poll target for the start screen's WSL-setup log window (every ~2s while a setup is in
// progress). "done" is derived from REAL WSL/distro state (wsl_is_installed + list_wsl_distros),
// never from parsing the elevated process's own log output -- main.rs never holds that process's
// handle (Start-Process -Verb RunAs launches a separate process tree), so a log-text sentinel
// would be the only other option and far more fragile than just re-checking the thing that
// actually matters. "stalled" is a soft hint (log file untouched for a while, most likely a
// cancelled/ignored UAC prompt -- both look identical from here) -- never a hard failure, the
// button stays retryable either way.
#[cfg(windows)]
#[tauri::command]
fn get_wsl_setup_status() -> WslSetupStatus {
    let repo = repo_dir();
    let env_text = std::fs::read_to_string(repo.join(".env"))
        .or_else(|_| std::fs::read_to_string(repo.join(".env.example")))
        .unwrap_or_default();
    let log_path = resolve_app_dir(&env_text).join("wsl-setup.log");
    let log = std::fs::read_to_string(&log_path).unwrap_or_default();

    let distros = list_wsl_distros();
    let done = wsl_is_installed() && !distros.is_empty();

    const STALL_AFTER: Duration = Duration::from_secs(90);
    let stalled = !done
        && std::fs::metadata(&log_path)
            .and_then(|m| m.modified())
            .map(|modified| modified.elapsed().unwrap_or(Duration::ZERO) > STALL_AFTER)
            .unwrap_or(false);

    let state = if done {
        "done"
    } else if stalled {
        "stalled"
    } else {
        "running"
    };
    WslSetupStatus { state: state.to_string(), log }
}

#[cfg(not(windows))]
#[tauri::command]
fn get_wsl_setup_status() -> WslSetupStatus {
    WslSetupStatus { state: "done".to_string(), log: String::new() }
}

// "Test WSL setup" button, shown next to the distro picker even when a distro is already
// detected -- list_wsl_distros()/`wsl -l -v` only proves WSL considers the distro registered, not
// that it actually boots and works. Real, confirmed failure mode this guards against (see
// run_with_timeout's own comment): WSL2's VM service can go unresponsive after a long uptime while
// `wsl -l -v` keeps reporting the distro "Running" regardless -- an operator would otherwise only
// discover that the hard way, via launch_backend's own 5-minute wait_for_port timeout. This runs
// the exact same smoke test README.md's own "Verify it worked" step documents (`wsl -- echo ok`),
// plus a `bash`/`wslpath` presence check since those are the only two things run.bat itself
// actually needs inside the distro.
#[cfg(windows)]
#[tauri::command]
fn test_wsl_setup(distro: String, as_root: bool) -> Result<String, String> {
    let label = if distro.is_empty() {
        "The default WSL distro".to_string()
    } else {
        distro.clone()
    };
    let inner = "echo ASRA_WSL_OK && command -v bash >/dev/null 2>&1 && command -v wslpath >/dev/null 2>&1 && echo ASRA_TOOLS_OK";
    let mut cmd = Command::new("wsl.exe");
    apply_wsl_target(&mut cmd, as_root, &distro);
    cmd.arg("--")
        .arg("bash")
        .arg("-lc")
        .arg(inner)
        .creation_flags(CREATE_NO_WINDOW);
    match run_with_timeout_output(cmd, Duration::from_secs(20)) {
        Some(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if out.status.success() && stdout.contains("ASRA_WSL_OK") && stdout.contains("ASRA_TOOLS_OK") {
                Ok(format!("{label} responded, and bash/wslpath are both present — ready for run.bat."))
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let detail = if stderr.trim().is_empty() { stdout.trim() } else { stderr.trim() };
                Err(format!(
                    "{label} started but the check failed (bash/wslpath missing, or something inside the distro is broken){}",
                    if detail.is_empty() { String::new() } else { format!(": {detail}") }
                ))
            }
        }
        None => Err(format!(
            "{label} did not respond within 20s -- it may be stuck (a known WSL2 failure mode even when `wsl -l -v` still shows it as \"Running\"). Try `wsl --shutdown` in PowerShell, then retry."
        )),
    }
}

#[cfg(not(windows))]
#[tauri::command]
fn test_wsl_setup(_distro: String, _as_root: bool) -> Result<String, String> {
    Err("WSL is Windows-only".to_string())
}

fn main() {
    // Leftover <exe>.old from a previous apply_desktop_update's rename-swap -- only deletable now,
    // since the OLD process (which held it open) has fully exited by the time THIS new process
    // starts. Best-effort and silent: a first-ever launch (nothing to clean up) is the common case.
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(exe.with_extension("old"));
    }

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // Window may be hidden in the tray on a second launch -- show it, don't just focus.
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(OwnedBackend(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            get_start_config,
            launch_backend,
            apply_desktop_update,
            bootstrap_full_project,
            force_restart_agent,
            save_env,
            open_in_browser,
            open_external_url,
            notify_session_done,
            install_wsl,
            get_wsl_setup_status,
            test_wsl_setup
        ])
        .on_window_event(|window, event| {
            // The X minimizes to the tray instead of quitting, so a long scan keeps running in the
            // background. Real quit is the tray's "Quit ASRA" (app.exit -> RunEvent::Exit ->
            // stop_backend). Without this, closing the window would kill the backend mid-scan.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .setup(|app| {
            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("")
                .inner_size(1200.0, 820.0)
                .min_inner_size(820.0, 600.0)
                .center()
                .resizable(true)
                // Windows/WebView2 default: the OS-level drag&drop handler owns the window,
                // which silently breaks the Settings page's own HTML5 drag-and-drop (Reserve
                // providers row reordering, settings.html) -- dragstart/drop never reach the
                // page. This is Tauri's own documented fix, required specifically to let the
                // frontend's native HTML5 drag and drop APIs work on Windows.
                .disable_drag_drop_handler()
                .initialization_script(DESKTOP_TWEAKS)
                .on_page_load(|webview, _payload| {
                    let _ = webview.eval(DESKTOP_TWEAKS);
                })
                // The X minimizes to the tray (below) instead of quitting, so a real scan can run
                // for hours with this window sitting hidden/occluded. Windows WebView2 (Chromium's
                // own Page Lifecycle) throttles/freezes JS timers -- and, once actually occluded
                // long enough, the whole renderer -- for exactly this "backgrounded, not the
                // foreground window" state, same as a normal Chrome tab left in a background tab
                // group. Real, confirmed operator report this fixes: stepping away, coming back,
                // and clicks doing nothing at all for a long stretch before the UI "catches up" --
                // this is that freeze thawing out. Chromium's own flags to opt this one window out
                // of that throttling; --disable-features=... is wry's own DEFAULT value (see
                // additional_browser_args' own doc comment: setting this string REPLACES it, so it
                // has to be repeated here or those defaults would silently be lost, not just added
                // to). Windows/WebView2-only -- a documented no-op on macOS/Linux, safe to call
                // unconditionally rather than #[cfg(windows)]-gating this whole block.
                //
                // msWebOOUI dropped from that disabled-features list -- real, confirmed operator
                // report this caused: a native <select>'s own dropdown (e.g. a subagent's Provider
                // picker, templates/subagents.html) silently refused to open AT ALL inside the
                // desktop app specifically -- no list, no error -- while working fine in a regular
                // Chrome tab. msWebOOUI is WebView2/Edge's "Web Out-Of-process UI" feature, which
                // governs exactly this class of popup surface (select dropdowns, among others)
                // rendering in its own properly-composited process; disabling it forces an
                // in-process fallback that this WebView2 build apparently fails to render at all
                // for a <select> living inside a <dialog>. Keeping it enabled costs nothing this
                // window actually needs -- the backgrounding-throttle fix this block exists for
                // lives entirely in the three --disable-backgrounding-occluded-windows/
                // --disable-renderer-backgrounding/--disable-background-timer-throttling flags
                // below, none of which depend on msWebOOUI being off.
                .additional_browser_args(
                    "--disable-features=msPdfOOUI,msSmartScreenProtection \
                     --disable-backgrounding-occluded-windows \
                     --disable-renderer-backgrounding \
                     --disable-background-timer-throttling",
                )
                .build()?;

            // System tray: the minimize-to-tray target + the only explicit-quit path. Icon is
            // embedded so the tray never depends on a default-window-icon being set.
            let show_item = MenuItem::with_id(app, "show", "Show ASRA", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quit ASRA", true, None::<&str>)?;
            let tray_menu = Menu::with_items(app, &[&show_item, &quit_item])?;
            let tray_icon = tauri::image::Image::from_bytes(include_bytes!("../icons/icon.png"))?;
            TrayIconBuilder::new()
                .icon(tray_icon)
                .tooltip("ASRA")
                .menu(&tray_menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building the ASRA desktop shell");

    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            stop_backend(&app_handle.state::<OwnedBackend>());
        }
    });
}
