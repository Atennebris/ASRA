"""Client for the Windows live-memory bridge (desktop/src-tauri/src/mem_bridge.rs) -- the
Windows-process counterpart to agent/tools/memscan_manager.py's scanmem-based implementation,
which can only ever reach a Linux/WSL2 process (ASRA's own agent process runs inside WSL2 even
when "running on Windows"). A real, currently
running native Windows process is otherwise completely invisible to the Linux-side tools -- this
module is what lets memscan_attach/memscan_scan/memscan_list/memscan_write/memscan_detach
(agent/tools/__init__.py) reach one anyway, selected via each tool's own `platform="windows"`
parameter (default "linux", routing to memscan_manager.py as before).

Connectivity: the bridge runs natively in the desktop shell process (mem_bridge.rs), outside
WSL2 entirely. WSL2 can reach it only via the specific addresses that Rust process itself bound
and wrote to mem_bridge.json (see that file's own module doc comment for why a bare 127.0.0.1
bind alone is NOT enough under WSL2's default NAT networking -- confirmed live on this project's
own dev machine: 127.0.0.1 connection refused, the WSL-facing vEthernet adapter's own address
worked). This module tries each host mem_bridge.json lists, in order, and caches whichever one
actually connects for the rest of this process's life -- never re-derives the address itself, the
Rust side is the single source of truth for which addresses it actually bound.

Protocol: newline-delimited single-line JSON request/response, one TCP connection per request --
the same shape agent/tools/builders/ghidra.py's own persistent-server bridge already uses for a
different problem; a fresh connect costs microseconds next to anything a scan/write actually does.

Auth: every request carries the per-launch token mem_bridge.json holds alongside the port -- a
mismatched/missing token is rejected immediately by the Rust side (see its own module doc comment
for the full trust model: loopback/WSL-adapter-only bind, token is the real access boundary).

Honest unavailability: when the desktop shell isn't running, ASRA was launched on a non-Windows
platform, or ASRA_MEM_BRIDGE_ENABLED=false, mem_bridge.json simply doesn't exist (or is stale) --
every public function here returns a clear {"status": "error", "error": ...} explaining the
bridge needs the desktop app running on Windows, the same honest-limitation-messaging pattern
agent/prompts.py already uses for the kernel-mode-anti-cheat-driver case (RE_TRIAGE_PROMPT), never
a silent/confusing failure.
"""
from __future__ import annotations

import json
import socket
from pathlib import Path

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

_REQUEST_TIMEOUT_SECONDS = 15
_UNAVAILABLE_MESSAGE = (
    "the Windows live-memory bridge is unavailable -- this requires launching ASRA via the "
    "desktop app on Windows (ASRA_MEM_BRIDGE_ENABLED must not be set to false); it cannot reach "
    "a real Windows process from a plain run.sh/run.bat launch"
)

# Cached once a working host is found -- avoids re-trying every candidate host on every call for
# the life of this process. Reset only by a fresh _bridge_info() read reporting a different port
# (a desktop-shell restart regenerates both the port's own listener state and the token).
_cached_host: str | None = None
_cached_port: int | None = None


def _bridge_info_path() -> Path:
    return resolve_global_app_dir() / "mem_bridge.json"


def _read_bridge_info() -> dict | None:
    try:
        return json.loads(_bridge_info_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _send(host: str, port: int, request: dict) -> dict:
    with socket.create_connection((host, port), timeout=_REQUEST_TIMEOUT_SECONDS) as sock:
        sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = sock.recv(1 << 20)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf.decode("utf-8", errors="replace"))


def _call(mode: str, **fields) -> dict:
    global _cached_host, _cached_port
    info = _read_bridge_info()
    if info is None:
        return {"status": "error", "error": _UNAVAILABLE_MESSAGE}
    port = int(info["port"])
    token = info["token"]
    hosts = info.get("hosts") or ["127.0.0.1"]
    request = {"mode": mode, "token": token, **fields}

    # Try the cached host first (still the same port this info file names), then every host the
    # bridge itself reported binding, in order -- see module docstring for why this never
    # re-derives an address on its own.
    candidates = []
    if _cached_host is not None and _cached_port == port:
        candidates.append(_cached_host)
    candidates += [h for h in hosts if h not in candidates]

    last_error: Exception | None = None
    for host in candidates:
        try:
            response = _send(host, port, request)
            _cached_host, _cached_port = host, port
            return response
        except (OSError, ValueError) as exc:
            last_error = exc
            continue
    logger.debug("win_memscan_bridge: could not reach any bridge host %s on port %s (%s)", hosts, port, last_error)
    return {"status": "error", "error": f"{_UNAVAILABLE_MESSAGE} (tried {hosts}: {last_error})"}


# --- public functions, mirroring memscan_manager.py's own signature shape exactly --------------
# session_id is accepted (and logged) for signature symmetry with the Linux-side module even
# though the bridge's own session state is keyed purely by scan_id, not per-ASRA-session -- keeps
# the two backends mechanically interchangeable for the dispatch wrappers in memscan_manager.py.

def attach(session_id: str, pid: object, scan_data_type: str) -> dict:
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return {"status": "error", "error": f"pid must be an integer, got {pid!r}"}
    logger.debug("win_memscan_bridge: session=%s attach pid=%s scan_data_type=%s", session_id, pid_int, scan_data_type)
    return _call("attach", pid=pid_int, scan_data_type=scan_data_type)


def scan(session_id: str, scan_id: str, mode: str, value: object = None) -> dict:
    logger.debug("win_memscan_bridge: session=%s scan_id=%s scan mode=%s", session_id, scan_id, mode)
    return _call("scan", scan_id=scan_id, scan_mode=mode, value=value)


def list_matches(session_id: str, scan_id: str, limit: int = 50) -> dict:
    result = _call("list", scan_id=scan_id)
    if result.get("status") == "ok" and "matches" in result:
        result["matches"] = result["matches"][:limit]
    logger.debug("win_memscan_bridge: session=%s scan_id=%s list -> status=%s", session_id, scan_id, result.get("status"))
    return result


def write(session_id: str, scan_id: str, list_index: object, value: object) -> dict:
    try:
        index_int = int(list_index)
    except (TypeError, ValueError):
        return {"status": "error", "error": f"list_index must be an integer, got {list_index!r}"}
    logger.debug("win_memscan_bridge: session=%s scan_id=%s write list_index=%s", session_id, scan_id, index_int)
    return _call("write", scan_id=scan_id, list_index=index_int, value=value)


def detach(session_id: str, scan_id: str) -> dict:
    logger.debug("win_memscan_bridge: session=%s scan_id=%s detach", session_id, scan_id)
    return _call("detach", scan_id=scan_id)


def list_processes() -> dict:
    return _call("list_processes")


def bridge_available() -> bool:
    """Cheap availability check (no network call) -- just whether a bridge info file exists at
    all, used by ToolSpec-level availability checks that must not block on a network round trip."""
    return _bridge_info_path().is_file()
