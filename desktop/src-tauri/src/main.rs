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
    distros: Vec<WslDistro>,
    settings: Vec<EnvSetting>,
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
                return dir;
            }
            if !dir.pop() {
                break;
            }
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
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

fn wait_for_port(port: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if port_is_up(port) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(400));
    }
    false
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

#[cfg(windows)]
fn spawn_backend(repo: &Path, as_root: bool, distro: &str, ui_token: &str) -> std::io::Result<Child> {
    let win_path = repo.to_string_lossy().replace('\'', "'\\''");
    // Inject the UI token as a prefix env of the inner command so run.sh's own
    // `source .env` (which has no such line) cannot clobber it. Empty in web mode.
    let token_prefix = if ui_token.is_empty() {
        String::new()
    } else {
        format!("ASRA_UI_TOKEN='{ui_token}' ")
    };
    let inner = format!("cd \"$(wslpath -a '{win_path}')\" && {token_prefix}bash run.sh");
    let mut cmd = Command::new("wsl.exe");
    apply_wsl_target(&mut cmd, as_root, distro);
    cmd.arg("--")
        .arg("bash")
        .arg("-lc")
        .arg(inner)
        .creation_flags(CREATE_NO_WINDOW);
    cmd.spawn()
}

#[cfg(not(windows))]
fn spawn_backend(repo: &Path, _as_root: bool, _distro: &str, ui_token: &str) -> std::io::Result<Child> {
    let mut cmd = Command::new("bash");
    cmd.arg("run.sh").current_dir(repo);
    if !ui_token.is_empty() {
        cmd.env("ASRA_UI_TOKEN", ui_token);
    }
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
    let wsl_probe_ms = wsl_probe_start.elapsed().as_millis();
    let settings = parse_env_settings(&env_text);
    eprintln!(
        "[ASRA-DESKTOP] start screen loaded (os={}, wsl_distros={}, env_settings={}, run_as_root={})",
        std::env::consts::OS,
        distros.len(),
        settings.len(),
        env_flag(&env_text, "ASRA_RUN_AS_ROOT")
    );
    append_desktop_log_line(
        &env_text,
        &format!(
            "start screen loaded: os={} wsl_distros={} wsl_probe_ms={} env_settings={} run_as_root={}",
            std::env::consts::OS,
            distros.len(),
            wsl_probe_ms,
            settings.len(),
            env_flag(&env_text, "ASRA_RUN_AS_ROOT")
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
        distros,
        settings,
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
        let child = spawn_backend(&repo, args.as_root, &args.distro, &ui_token)
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
    let wait_start = Instant::now();
    let ready = tauri::async_runtime::spawn_blocking(move || {
        wait_for_port(&port_for_wait, Duration::from_secs(300))
    })
    .await
    .map_err(|e| format!("readiness wait failed: {e}"))?;
    append_desktop_log_line(
        &new_env,
        &format!("waited {}ms for backend port {} to come up (ready={})", wait_start.elapsed().as_millis(), port, ready),
    );

    if !ready {
        append_desktop_log_line(&new_env, "backend did not come up within the 300s readiness timeout");
        return Err("backend did not come up in time".to_string());
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

fn main() {
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
        .manage(OwnedBackend(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            get_start_config,
            launch_backend,
            force_restart_agent,
            save_env,
            open_in_browser,
            open_external_url,
            notify_session_done
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
                .additional_browser_args(
                    "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection \
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
