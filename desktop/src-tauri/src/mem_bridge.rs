// Windows live-memory bridge: closes the one real gap ASRA's Linux-side memscan tools
// (agent/tools/memscan_manager.py, backed by scanmem) cannot reach at all -- a real, currently
// running Windows process. ASRA's own agent process lives inside WSL2 even when "running on
// Windows", so scanmem's ptrace-based
// attach can only ever see a Linux/WSL2 process; a native Windows game/app is completely
// invisible to it. This module runs natively in THIS already-Windows process instead and exposes
// the same classic "Cheat Engine" workflow (attach, scan, narrow, list, patch one match to
// confirm) over a small local protocol the WSL2-side Python agent can call into directly.
//
// Why a plain loopback TCP listener, not a Tauri IPC command: open_in_browser/open_external_url
// (see main.rs) are Tauri commands invoked from JS running inside the webview, reached only via a
// user click or page logic -- there is no path for the WSL2-side Python tool-call loop to invoke
// a Tauri command directly, it isn't a browser. The agent needs a direct, synchronous channel of
// its own, so this starts an ordinary background `std::net::TcpListener` thread instead, same
// `std::net` style this file's own `port_is_up`/`remote_source_mtime` already use for loopback
// probing in the other direction.
//
// Protocol: newline-delimited single-line JSON request/response, one TCP connection per request
// -- the exact same shape agent/tools/builders/ghidra.py's own persistent-server bridge already
// proved out for a different problem (avoiding repeated Ghidra JVM startup cost); a fresh connect
// costs microseconds next to anything this bridge actually does, so there is no reason to
// multiplex connections.
//
// Auth: a per-launch random token, generated the same way gen_token() already does for
// ASRA_UI_TOKEN (regenerated every launch, never persisted), written alongside the chosen port as
// JSON to a fixed file under resolve_app_dir() -- the Python side reads that file to learn how to
// connect. This reuses the exact trust model this project already accepts for ASRA_UI_TOKEN
// rather than inventing a second one; the listener itself is bound to 127.0.0.1 only, so the
// token's real job is keeping some OTHER local process on the same machine from driving live
// process-memory access through this port, not defending against a network attacker.
//
// Security boundary this relies on rather than reimplementing: OpenProcess against a
// higher-integrity-level or protected process simply fails under Windows' own process-security
// model when this Tauri app itself isn't elevated -- there is no custom privilege check here, the
// OS already enforces this and a second, hand-rolled check would only risk getting it wrong.
//
// Enabled by default (ASRA_MEM_BRIDGE_ENABLED, default true) -- matching this project's existing
// posture toward similarly sensitive RE capability (EXPLOIT_REQUIRE_APPROVAL itself defaults to
// false, i.e. exploit tools run without a confirmation gate by default; this project's whole
// stance is that responsibility for how these tools get used
// sits with the operator, not a built-in gate) -- loopback+token is the same protection level
// ASRA_UI_TOKEN already gets for the main UI, not a lesser one.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READWRITE,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleBaseNameW};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

use std::os::windows::process::CommandExt;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const DEFAULT_PORT: u16 = 47219;
// Hard ceiling on how many candidate addresses one scan session may hold at once -- a mode="unknown"
// snapshot over a large writable address space (routine for a modern game) could otherwise try to
// track tens of millions of byte-aligned positions and exhaust memory; scanmem/Cheat Engine both
// accept the same kind of practical cap in spirit even if their exact numbers differ. Hit this cap
// with an honest `truncated` flag in the scan response rather than silently stopping partway with
// no sign anything was cut.
const MAX_CANDIDATES: usize = 2_000_000;
// Skip a single VirtualQueryEx region larger than this -- a pathological single allocation (some
// games reserve very large private arenas) would otherwise dominate the whole scan's time budget
// for comparatively little signal; same "a bound is a ceiling, not worth failing the whole call
// over" reasoning this project already applies elsewhere (see tshark.py's own duration clamp).
const MAX_REGION_BYTES: usize = 256 * 1024 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

fn env_flag_or(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes" | "on"),
        Err(_) => default,
    }
}

// WSL2's own "localhost forwarding" only works Windows-to-WSL2, not the reverse -- confirmed live
// on this project's own dev machine: a plain 127.0.0.1-only bind here was unreachable from inside
// WSL2 even via its default-gateway IP (the usual NAT-mode trick), under WSL2's default NAT
// networking mode (not the newer, opt-in "mirrored" mode, which WOULD make a bare 127.0.0.1 bind
// work both ways). The fix is NOT binding 0.0.0.0 -- that would expose this to every adapter on
// the machine, including a real LAN/Wi-Fi NIC, for a capability that does live process-memory
// access. Instead: find the specific "vEthernet (WSL...)" virtual adapter's own IPv4 address (the
// same address WSL2 reports as its own default-route gateway) via `ipconfig`, and bind there in
// addition to 127.0.0.1 -- reachable from WSL2 either way (NAT-mode via the adapter address,
// mirrored-mode via 127.0.0.1), never from a real network adapter. Confirmed live on this machine:
// `vEthernet (WSL (Hyper-V firewall))` at 172.22.144.1, matching WSL2's own `ip route show
// default` gateway exactly.
fn find_wsl_adapter_ip() -> Option<IpAddr> {
    let output = Command::new("ipconfig")
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut in_wsl_adapter = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':') && trimmed.to_ascii_lowercase().contains("adapter") {
            in_wsl_adapter = trimmed.to_ascii_lowercase().contains("vethernet (wsl");
            continue;
        }
        if in_wsl_adapter {
            if let Some(idx) = trimmed.find(':') {
                let label = trimmed[..idx].to_ascii_lowercase();
                if label.contains("ipv4") {
                    let value = trimmed[idx + 1..].trim();
                    if let Ok(addr) = value.parse::<IpAddr>() {
                        return Some(addr);
                    }
                }
            }
        }
    }
    None
}

fn gen_token() -> String {
    let mut buf = [0u8; 16];
    if getrandom::getrandom(&mut buf).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        buf.copy_from_slice(&nanos.to_le_bytes()[..16.min(16)]);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// --- wire shapes -----------------------------------------------------------------------------

#[derive(Deserialize)]
struct Request {
    mode: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    pid: Option<i64>,
    #[serde(default)]
    scan_id: Option<String>,
    #[serde(default)]
    scan_data_type: Option<String>,
    #[serde(default)]
    scan_mode: Option<String>,
    #[serde(default)]
    value: Option<Value>,
    #[serde(default)]
    list_index: Option<usize>,
}

// --- candidate value handling ------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ValueType {
    Int8,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Str,
    Bytearray,
}

impl ValueType {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "int8" => Some(Self::Int8),
            "int16" => Some(Self::Int16),
            "int32" => Some(Self::Int32),
            "int64" => Some(Self::Int64),
            "float32" => Some(Self::Float32),
            "float64" => Some(Self::Float64),
            "string" => Some(Self::Str),
            "bytearray" => Some(Self::Bytearray),
            _ => None,
        }
    }

    // Fixed-width types only -- string/bytearray have no single "snapshot width" (their own
    // search pattern/text defines the match length instead), so mode="unknown" is only meaningful
    // for the six numeric types, same restriction memscan_manager.py's own _NON_ORDERED_VALUE_TYPES
    // already documents for a related reason on the Linux side.
    fn fixed_width(&self) -> Option<usize> {
        match self {
            Self::Int8 => Some(1),
            Self::Int16 => Some(2),
            Self::Int32 => Some(4),
            Self::Int64 => Some(8),
            Self::Float32 => Some(4),
            Self::Float64 => Some(8),
            Self::Str | Self::Bytearray => None,
        }
    }

    fn numeric_to_bytes(&self, value: &Value) -> Option<Vec<u8>> {
        match self {
            Self::Int8 => value.as_i64().map(|v| (v as i8).to_le_bytes().to_vec()),
            Self::Int16 => value.as_i64().map(|v| (v as i16).to_le_bytes().to_vec()),
            Self::Int32 => value.as_i64().map(|v| (v as i32).to_le_bytes().to_vec()),
            Self::Int64 => value.as_i64().map(|v| v.to_le_bytes().to_vec()),
            Self::Float32 => value.as_f64().map(|v| (v as f32).to_le_bytes().to_vec()),
            Self::Float64 => value.as_f64().map(|v| v.to_le_bytes().to_vec()),
            Self::Str | Self::Bytearray => None,
        }
    }

    fn bytes_to_value(&self, bytes: &[u8]) -> Value {
        match self {
            Self::Int8 => json!(bytes.first().map(|b| *b as i8).unwrap_or(0)),
            Self::Int16 => json!(i16::from_le_bytes(bytes.try_into().unwrap_or([0; 2]))),
            Self::Int32 => json!(i32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
            Self::Int64 => json!(i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))),
            Self::Float32 => json!(f32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]))),
            Self::Float64 => json!(f64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))),
            Self::Str => json!(String::from_utf8_lossy(bytes).to_string()),
            Self::Bytearray => json!(bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")),
        }
    }
}

// "FF ?? EE" -> [Some(0xFF), None, Some(0xEE)] -- ?? is a per-byte wildcard, same syntax
// memscan_manager.py's own _BYTEARRAY_PATTERN already accepts on the Linux side, kept identical
// so the model doesn't need to learn a second syntax for the Windows path.
fn parse_bytearray_pattern(s: &str) -> Option<Vec<Option<u8>>> {
    s.split_whitespace()
        .map(|tok| {
            if tok == "??" {
                Some(None)
            } else if tok.len() == 2 {
                u8::from_str_radix(tok, 16).ok().map(Some)
            } else {
                None
            }
        })
        .collect()
}

fn pattern_matches(haystack: &[u8], pattern: &[Option<u8>]) -> bool {
    haystack.len() == pattern.len()
        && haystack
            .iter()
            .zip(pattern.iter())
            .all(|(b, p)| p.map(|want| want == *b).unwrap_or(true))
}

// --- live process memory access --------------------------------------------------------------

struct Candidate {
    address: usize,
    last_bytes: Vec<u8>,
}

struct ScanSession {
    handle: HANDLE, // isize-backed, Send+Sync by construction -- see module doc comment.
    pid: u32,
    value_type: ValueType,
    candidates: Vec<Candidate>,
    truncated: bool,
    last_activity: Instant,
}

// SAFETY: HANDLE wraps a plain isize (a Windows kernel handle value), not a pointer into this
// process's own memory -- it carries no borrowed data and is safe to hand across threads the same
// way any other integer-like OS handle value is.
unsafe impl Send for ScanSession {}

fn enumerate_regions(process: HANDLE) -> Vec<(usize, usize)> {
    let mut regions = Vec::new();
    let mut address: usize = 0;
    loop {
        let mut info = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                process,
                Some(address as *const _),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        let region_size = info.RegionSize;
        let readable = info.State == MEM_COMMIT
            && info.Type == MEM_PRIVATE
            && (info.Protect & PAGE_NOACCESS).0 == 0
            && (info.Protect & PAGE_GUARD).0 == 0
            && ((info.Protect & PAGE_READWRITE).0 != 0
                || (info.Protect & PAGE_WRITECOPY).0 != 0
                || (info.Protect & PAGE_EXECUTE_READWRITE).0 != 0);
        if readable && region_size > 0 && region_size <= MAX_REGION_BYTES {
            regions.push((info.BaseAddress as usize, region_size));
        }
        let next = (info.BaseAddress as usize).saturating_add(region_size.max(1));
        if next <= address {
            break; // no forward progress -- stop rather than loop forever
        }
        address = next;
    }
    regions
}

fn read_region(process: HANDLE, base: usize, size: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; size];
    let mut read: usize = 0;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            base as *const _,
            buf.as_mut_ptr() as *mut _,
            size,
            Some(&mut read),
        )
    };
    if ok.is_ok() && read > 0 {
        buf.truncate(read);
        Some(buf)
    } else {
        None
    }
}

fn read_at(process: HANDLE, address: usize, size: usize) -> Option<Vec<u8>> {
    read_region(process, address, size)
}

fn write_at(process: HANDLE, address: usize, bytes: &[u8]) -> bool {
    let mut written: usize = 0;
    unsafe {
        WriteProcessMemory(
            process,
            address as *mut _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            Some(&mut written),
        )
    }
    .is_ok()
        && written == bytes.len()
}

fn list_processes() -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }) else {
        return out;
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe {
        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())],
                );
                out.push(json!({"pid": entry.th32ProcessID, "name": name}));
                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
    }
    out
}

// --- session table ----------------------------------------------------------------------------

struct SharedState {
    sessions: Mutex<HashMap<String, ScanSession>>,
    next_id: AtomicU64,
    token: String,
}

fn reject(msg: &str) -> Value {
    json!({"status": "error", "error": msg})
}

fn handle_request(state: &Arc<SharedState>, req: Request) -> Value {
    if req.token != state.token {
        return reject("unauthorized: missing or incorrect bridge token");
    }

    match req.mode.as_str() {
        "ping" => json!({"status": "ok"}),

        "list_processes" => json!({"status": "ok", "processes": list_processes()}),

        "attach" => {
            let Some(pid) = req.pid else {
                return reject("attach requires 'pid'");
            };
            let pid = pid as u32;
            let my_pid = std::process::id();
            if pid == 0 || pid == 4 || pid == my_pid {
                return reject("refusing to attach to pid 0/4 (System) or this desktop shell's own pid");
            }
            let Some(type_str) = req.scan_data_type.as_deref() else {
                return reject("attach requires 'scan_data_type'");
            };
            let Some(value_type) = ValueType::parse(type_str) else {
                return reject("scan_data_type must be one of int8/int16/int32/int64/float32/float64/string/bytearray");
            };
            let rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
            let handle = match unsafe { OpenProcess(rights, false, pid) } {
                Ok(h) => h,
                // The most common real cause here is Windows' own security model refusing a
                // higher-integrity-level/protected process -- not something this bridge works
                // around, see the module doc comment.
                Err(e) => return reject(&format!("OpenProcess failed for pid {pid}: {e} (often means the target runs at a higher integrity level, or no such process)")),
            };
            let scan_id = format!("win{}", state.next_id.fetch_add(1, Ordering::SeqCst));
            state.sessions.lock().unwrap().insert(
                scan_id.clone(),
                ScanSession {
                    handle,
                    pid,
                    value_type,
                    candidates: Vec::new(),
                    truncated: false,
                    last_activity: Instant::now(),
                },
            );
            json!({"status": "ok", "scan_id": scan_id, "pid": pid, "scan_data_type": type_str})
        }

        "scan" => {
            let Some(scan_id) = req.scan_id.as_deref() else {
                return reject("scan requires 'scan_id'");
            };
            let Some(scan_mode) = req.scan_mode.as_deref() else {
                return reject("scan requires 'scan_mode'");
            };
            let mut sessions = state.sessions.lock().unwrap();
            let Some(session) = sessions.get_mut(scan_id) else {
                return reject("no active session for that scan_id -- call attach first");
            };
            session.last_activity = Instant::now();
            let process = session.handle;
            let value_type = session.value_type;

            match scan_mode {
                "unknown" => {
                    let Some(width) = value_type.fixed_width() else {
                        return reject("mode=\"unknown\" only applies to numeric scan_data_types");
                    };
                    let regions = enumerate_regions(process);
                    let mut candidates = Vec::new();
                    let mut truncated = false;
                    'regions: for (base, size) in regions {
                        if let Some(buf) = read_region(process, base, size) {
                            let mut off = 0;
                            while off + width <= buf.len() {
                                if candidates.len() >= MAX_CANDIDATES {
                                    truncated = true;
                                    break 'regions;
                                }
                                candidates.push(Candidate {
                                    address: base + off,
                                    last_bytes: buf[off..off + width].to_vec(),
                                });
                                off += width;
                            }
                        }
                    }
                    let count = candidates.len();
                    session.candidates = candidates;
                    session.truncated = truncated;
                    json!({"status": "ok", "match_count": count, "truncated": truncated})
                }
                "exact" => {
                    let Some(value) = req.value.as_ref() else {
                        return reject("mode=\"exact\" requires 'value'");
                    };
                    let target_bytes: Option<Vec<u8>> = match value_type {
                        ValueType::Str => value.as_str().map(|s| s.as_bytes().to_vec()),
                        ValueType::Bytearray => None, // handled via pattern below
                        _ => value_type.numeric_to_bytes(value),
                    };
                    if value_type == ValueType::Bytearray {
                        let Some(pattern_str) = value.as_str() else {
                            return reject("bytearray value must be a string like \"FF ?? EE\"");
                        };
                        let Some(pattern) = parse_bytearray_pattern(pattern_str) else {
                            return reject("value must be space-separated hex byte pairs (\"??\" wildcard allowed)");
                        };
                        if session.candidates.is_empty() {
                            // First scan: search every region for the pattern.
                            let regions = enumerate_regions(process);
                            let mut candidates = Vec::new();
                            let mut truncated = false;
                            'r2: for (base, size) in regions {
                                if let Some(buf) = read_region(process, base, size) {
                                    if buf.len() < pattern.len() {
                                        continue;
                                    }
                                    for off in 0..=(buf.len() - pattern.len()) {
                                        if pattern_matches(&buf[off..off + pattern.len()], &pattern) {
                                            if candidates.len() >= MAX_CANDIDATES {
                                                truncated = true;
                                                break 'r2;
                                            }
                                            candidates.push(Candidate {
                                                address: base + off,
                                                last_bytes: buf[off..off + pattern.len()].to_vec(),
                                            });
                                        }
                                    }
                                }
                            }
                            let count = candidates.len();
                            session.candidates = candidates;
                            session.truncated = truncated;
                            return json!({"status": "ok", "match_count": count, "truncated": truncated});
                        }
                        // Narrow: re-read each known candidate and keep the ones that still match.
                        let mut kept = Vec::new();
                        for c in session.candidates.drain(..) {
                            if let Some(fresh) = read_at(process, c.address, pattern.len()) {
                                if pattern_matches(&fresh, &pattern) {
                                    kept.push(Candidate { address: c.address, last_bytes: fresh });
                                }
                            }
                        }
                        let count = kept.len();
                        session.candidates = kept;
                        return json!({"status": "ok", "match_count": count, "truncated": false});
                    }
                    let Some(target_bytes) = target_bytes else {
                        return reject("could not interpret 'value' for this scan_data_type");
                    };
                    if session.candidates.is_empty() {
                        let width = target_bytes.len();
                        let regions = enumerate_regions(process);
                        let mut candidates = Vec::new();
                        let mut truncated = false;
                        'r3: for (base, size) in regions {
                            if let Some(buf) = read_region(process, base, size) {
                                if buf.len() < width {
                                    continue;
                                }
                                for off in 0..=(buf.len() - width) {
                                    if buf[off..off + width] == target_bytes[..] {
                                        if candidates.len() >= MAX_CANDIDATES {
                                            truncated = true;
                                            break 'r3;
                                        }
                                        candidates.push(Candidate { address: base + off, last_bytes: target_bytes.clone() });
                                    }
                                }
                            }
                        }
                        let count = candidates.len();
                        session.candidates = candidates;
                        session.truncated = truncated;
                        json!({"status": "ok", "match_count": count, "truncated": truncated})
                    } else {
                        let width = target_bytes.len();
                        let mut kept = Vec::new();
                        for c in session.candidates.drain(..) {
                            if let Some(fresh) = read_at(process, c.address, width) {
                                if fresh == target_bytes {
                                    kept.push(Candidate { address: c.address, last_bytes: fresh });
                                }
                            }
                        }
                        let count = kept.len();
                        session.candidates = kept;
                        json!({"status": "ok", "match_count": count, "truncated": false})
                    }
                }
                "increased" | "decreased" | "changed" | "unchanged" => {
                    let Some(width) = value_type.fixed_width() else {
                        return reject("increased/decreased/changed/unchanged only apply to numeric scan_data_types");
                    };
                    let explicit: Option<Vec<u8>> = req.value.as_ref().and_then(|v| value_type.numeric_to_bytes(v));
                    let mut kept = Vec::new();
                    for c in session.candidates.drain(..) {
                        let Some(fresh) = read_at(process, c.address, width) else { continue };
                        let keep = if let Some(target) = &explicit {
                            fresh == *target
                        } else {
                            match (scan_mode, value_type) {
                                ("changed", _) => fresh != c.last_bytes,
                                ("unchanged", _) => fresh == c.last_bytes,
                                ("increased", ValueType::Float32) => f32::from_le_bytes(fresh.clone().try_into().unwrap_or([0; 4])) > f32::from_le_bytes(c.last_bytes.clone().try_into().unwrap_or([0; 4])),
                                ("decreased", ValueType::Float32) => f32::from_le_bytes(fresh.clone().try_into().unwrap_or([0; 4])) < f32::from_le_bytes(c.last_bytes.clone().try_into().unwrap_or([0; 4])),
                                ("increased", ValueType::Float64) => f64::from_le_bytes(fresh.clone().try_into().unwrap_or([0; 8])) > f64::from_le_bytes(c.last_bytes.clone().try_into().unwrap_or([0; 8])),
                                ("decreased", ValueType::Float64) => f64::from_le_bytes(fresh.clone().try_into().unwrap_or([0; 8])) < f64::from_le_bytes(c.last_bytes.clone().try_into().unwrap_or([0; 8])),
                                ("increased", _) => signed_of(&fresh, width) > signed_of(&c.last_bytes, width),
                                ("decreased", _) => signed_of(&fresh, width) < signed_of(&c.last_bytes, width),
                                _ => false,
                            }
                        };
                        if keep {
                            kept.push(Candidate { address: c.address, last_bytes: fresh });
                        }
                    }
                    let count = kept.len();
                    session.candidates = kept;
                    json!({"status": "ok", "match_count": count, "truncated": false})
                }
                other => reject(&format!("unknown scan_mode {other:?}")),
            }
        }

        "list" => {
            let Some(scan_id) = req.scan_id.as_deref() else {
                return reject("list requires 'scan_id'");
            };
            let mut sessions = state.sessions.lock().unwrap();
            let Some(session) = sessions.get_mut(scan_id) else {
                return reject("no active session for that scan_id -- call attach first");
            };
            session.last_activity = Instant::now();
            let process = session.handle;
            let value_type = session.value_type;
            let total = session.candidates.len();
            let limit = 50usize;
            let mut matches = Vec::new();
            for (idx, c) in session.candidates.iter_mut().take(limit).enumerate() {
                // Refresh to the live value, same "update before list" behavior
                // memscan_manager.py's own list_matches already does via scanmem's `update`.
                let width = c.last_bytes.len();
                if let Some(fresh) = read_at(process, c.address, width) {
                    c.last_bytes = fresh;
                }
                matches.push(json!({
                    "index": idx,
                    "address": format!("{:x}", c.address),
                    "value": value_type.bytes_to_value(&c.last_bytes),
                }));
            }
            json!({"status": "ok", "matches": matches, "total_count": total, "truncated": total > limit || session.truncated, "pid": session.pid})
        }

        "write" => {
            let Some(scan_id) = req.scan_id.as_deref() else {
                return reject("write requires 'scan_id'");
            };
            let Some(list_index) = req.list_index else {
                return reject("write requires 'list_index'");
            };
            let Some(value) = req.value.as_ref() else {
                return reject("write requires 'value'");
            };
            let mut sessions = state.sessions.lock().unwrap();
            let Some(session) = sessions.get_mut(scan_id) else {
                return reject("no active session for that scan_id -- call attach first");
            };
            session.last_activity = Instant::now();
            // By list_index into this session's OWN last-known candidate list ONLY -- never a raw
            // address supplied by the caller. Matches memscan_manager.py's CRITICAL SAFETY
            // PROPERTY exactly: you can only ever write to something this session's own scan
            // already found, word for word the same guarantee on the Windows path.
            let Some(candidate) = session.candidates.get(list_index) else {
                return reject("list_index is out of range for this session's current candidate list");
            };
            let address = candidate.address;
            let value_type = session.value_type;
            let bytes = match value_type {
                ValueType::Str => value.as_str().map(|s| s.as_bytes().to_vec()),
                ValueType::Bytearray => value.as_str().and_then(|s| {
                    let pattern = parse_bytearray_pattern(s)?;
                    pattern.into_iter().collect::<Option<Vec<u8>>>()
                }),
                _ => value_type.numeric_to_bytes(value),
            };
            let Some(bytes) = bytes else {
                return reject("could not interpret 'value' for this session's scan_data_type (bytearray write cannot contain \"??\" wildcards)");
            };
            if write_at(session.handle, address, &bytes) {
                session.candidates[list_index].last_bytes = bytes;
                json!({"status": "ok"})
            } else {
                reject("WriteProcessMemory failed -- the address may no longer be valid, or the process may not grant write access there")
            }
        }

        "detach" => {
            let Some(scan_id) = req.scan_id.as_deref() else {
                return reject("detach requires 'scan_id'");
            };
            let mut sessions = state.sessions.lock().unwrap();
            if let Some(session) = sessions.remove(scan_id) {
                unsafe { let _ = CloseHandle(session.handle); }
                json!({"status": "ok"})
            } else {
                reject("no active session for that scan_id")
            }
        }

        other => reject(&format!("unknown mode {other:?}")),
    }
}

fn signed_of(bytes: &[u8], width: usize) -> i64 {
    match width {
        1 => bytes.first().map(|b| *b as i8 as i64).unwrap_or(0),
        2 => i16::from_le_bytes(bytes.try_into().unwrap_or([0; 2])) as i64,
        4 => i32::from_le_bytes(bytes.try_into().unwrap_or([0; 4])) as i64,
        8 => i64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])),
        _ => 0,
    }
}

fn idle_reaper(state: Arc<SharedState>) {
    loop {
        std::thread::sleep(Duration::from_secs(30));
        let mut sessions = state.sessions.lock().unwrap();
        let stale: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.last_activity.elapsed() > IDLE_TIMEOUT)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            if let Some(session) = sessions.remove(&id) {
                unsafe { let _ = CloseHandle(session.handle); }
            }
        }
    }
}

fn handle_connection(state: &Arc<SharedState>, stream: TcpStream) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone tcp stream"));
    let mut line = String::new();
    if reader.read_line(&mut line).is_err() || line.is_empty() {
        return;
    }
    let response = match serde_json::from_str::<Request>(&line) {
        Ok(req) => handle_request(state, req),
        Err(e) => reject(&format!("malformed request: {e}")),
    };
    let mut out = stream;
    let _ = out.write_all((response.to_string() + "\n").as_bytes());
}

#[derive(Serialize)]
struct BridgeInfo {
    port: u16,
    token: String,
    // Every address this process actually bound successfully, in try-order -- the Python side
    // tries each in turn rather than re-deriving WSL2's gateway IP itself, so there is exactly one
    // place (this function) that decides which addresses are meant to work.
    hosts: Vec<String>,
}

/// Starts the bridge if enabled, writing {port, token} to `app_dir/mem_bridge.json` for the
/// Python side to read. No-op (and removes any stale info file) when disabled, so a Python-side
/// read of a leftover file from a PREVIOUS, bridge-enabled launch never looks live.
pub fn start(app_dir: PathBuf) {
    let enabled = env_flag_or("ASRA_MEM_BRIDGE_ENABLED", true);
    let info_path = app_dir.join("mem_bridge.json");
    if !enabled {
        let _ = std::fs::remove_file(&info_path);
        eprintln!("[ASRA-DESKTOP] mem_bridge: disabled (ASRA_MEM_BRIDGE_ENABLED=false)");
        return;
    }
    let port: u16 = std::env::var("ASRA_MEM_BRIDGE_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_PORT);
    let token = gen_token();

    // Bind 127.0.0.1 unconditionally (works today if WSL2 mirrored networking is on, and is free
    // either way), plus the WSL-facing vEthernet adapter's own address when found (the NAT-mode
    // case, confirmed live necessary -- see find_wsl_adapter_ip's own comment). Never 0.0.0.0.
    let mut bind_addrs: Vec<IpAddr> = vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
    if let Some(adapter_ip) = find_wsl_adapter_ip() {
        if !bind_addrs.contains(&adapter_ip) {
            bind_addrs.push(adapter_ip);
        }
    }

    let mut listeners = Vec::new();
    for addr in &bind_addrs {
        match TcpListener::bind((*addr, port)) {
            Ok(l) => listeners.push((*addr, l)),
            Err(e) => eprintln!("[ASRA-DESKTOP] mem_bridge: could not bind {addr}:{port}: {e}"),
        }
    }
    if listeners.is_empty() {
        eprintln!("[ASRA-DESKTOP] mem_bridge: could not bind any address on port {port} -- live Windows memory access will be unavailable this launch");
        let _ = std::fs::remove_file(&info_path);
        return;
    }

    let _ = std::fs::create_dir_all(&app_dir);
    let info = BridgeInfo {
        port,
        token: token.clone(),
        hosts: listeners.iter().map(|(addr, _)| addr.to_string()).collect(),
    };
    if let Ok(json_text) = serde_json::to_string(&info) {
        let _ = std::fs::write(&info_path, json_text);
    }

    let state = Arc::new(SharedState {
        sessions: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        token,
    });

    let reaper_state = state.clone();
    std::thread::spawn(move || idle_reaper(reaper_state));

    for (addr, listener) in listeners {
        let state = state.clone();
        std::thread::spawn(move || {
            eprintln!("[ASRA-DESKTOP] mem_bridge: listening on {addr}:{port}");
            for stream in listener.incoming() {
                if let Ok(stream) = stream {
                    let state = state.clone();
                    std::thread::spawn(move || handle_connection(&state, stream));
                }
            }
        });
    }
}

// Silence an "unused" warning on EnumProcessModules/GetModuleBaseNameW/HMODULE -- reserved for a
// future "does this pid have a visible main window / module name" enrichment of list_processes;
// Toolhelp32Snapshot's own szExeFile already gives a usable process name today, so this isn't
// wired in yet, but the imports document the intended next step rather than being speculative.
#[allow(dead_code)]
fn _reserved_for_future_module_enrichment(_: HMODULE) {
    let _ = EnumProcessModules;
    let _ = GetModuleBaseNameW;
}
