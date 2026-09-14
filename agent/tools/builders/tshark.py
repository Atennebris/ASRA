"""build_command()/parser for tshark (Wireshark's CLI) -- RE mode's packet-capture/analysis
capability. tshark_capture does a live, time-boxed capture (raw .pcap saved into this session's own
project folder so it survives for later re-reading, plus a live field-based summary printed to
stdout at capture time -- the exact save path is visible in the tool result's own "command" list,
right after -w, same place any other tool's real invocation already lives). tshark_read_pcap re-
reads an existing .pcap with no live capture involved at all -- no elevated capability needed,
works the same way on a capture tshark_capture just made or one supplied from an external sandbox.

WSL2 networking caveat (genuinely worth knowing before relying on tshark_capture against a
Windows-side target): WSL2's default NAT networking mode only exposes WSL2's OWN virtual adapter's
traffic -- a native Windows-side process (a game launched directly on Windows, not inside WSL2) is
invisible to a capture running in here unless the operator has switched WSL2 to mirrored networking
(Windows 11 22H2+, `networkingMode=mirrored` in .wslconfig) -- a one-time machine-level setting,
never something this project can flip on its own. A Linux-side target (a service running inside
this same WSL2/Linux environment, or a genuinely remote host reachable over the network) captures
normally either way, mirrored mode or not.

Live capture needs raw-socket capability -- setup_tools.sh's install_tshark grants
cap_net_raw,cap_net_admin on dumpcap (the actual capture helper tshark shells out to internally)
once at install time via setcap, specifically so an ordinary (non-root) run of this tool works
exactly like every other tier-2 tool here, no per-call sudo prompt.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from projects.paths import resolve_global_app_dir
from sessions.store import get_session_folder

# One shared column layout for both capture's live -T fields output and read_pcap's own re-read --
# same shape either way, so a human/model reading either tool's output learns it once. Deliberately
# a fixed, curated set (not "every field tshark could possibly extract") -- covers the protocols an
# RE session actually cares about (raw IP/TCP/UDP framing, DNS, HTTP, TLS SNI) without needing the
# model to know tshark's own field-name grammar to get something useful back.
_FIELD_NAMES = (
    "frame.time_relative", "frame.protocols", "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
    "dns.qry.name", "http.host", "http.request.method", "http.request.uri",
    "tls.handshake.extensions_server_name",
)

_DEFAULT_CAPTURE_SECONDS = 20
_MAX_CAPTURE_SECONDS_ENV = "TSHARK_CAPTURE_MAX_SECONDS"
_DEFAULT_MAX_CAPTURE_SECONDS = 120


def _field_output_args() -> list[str]:
    # occurrence=f: a field repeated within one packet (rare, e.g. more than one dns.qry.name in an
    # unusual query) keeps only the first instead of tshark's own default of joining all of them
    # with a comma inside the same tab-separated column -- keeps the table's own column count
    # honest (one value per column, never a surprise embedded comma-list) for _parse_field_table
    # below.
    args = ["-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "occurrence=f"]
    for field in _FIELD_NAMES:
        args += ["-e", field]
    return args


def _captures_dir(session_id: str | None) -> Path:
    folder = get_session_folder(session_id) if session_id else None
    base = Path(folder) if folder else resolve_global_app_dir()
    captures_dir = base / "captures"
    captures_dir.mkdir(parents=True, exist_ok=True)
    return captures_dir


def build_tshark_capture_command(params: dict) -> list[str]:
    interface = validate_safe_value(str(params.get("interface") or "any").strip())
    requested = int(params.get("duration_seconds") or _DEFAULT_CAPTURE_SECONDS)
    max_seconds = int(os.getenv(_MAX_CAPTURE_SECONDS_ENV, str(_DEFAULT_MAX_CAPTURE_SECONDS)))
    # Silently clamped, not rejected -- same "a bound is a ceiling, not something worth failing a
    # whole call over" reasoning INTRUDER_MAX_ATTEMPTS/BROWSER_MAX_CONCURRENT_CONTEXTS already
    # follow elsewhere in this project; a model asking for more than the configured ceiling still
    # gets a real, useful, shorter capture back instead of an outright error.
    duration = max(1, min(requested, max_seconds))

    # Server-side injected (agent/core.py's _run_tool_with_retry, same convention as
    # custom_exploit_run/exploit_db_run's own _session_id) -- never part of this tool's own params
    # schema, so never model-supplied; keeps the raw capture in THIS session's own project folder,
    # not mixed into some other engagement's.
    pcap_path = _captures_dir(params.get("_session_id")) / f"capture_{int(time.time() * 1000)}.pcap"
    command = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-w", str(pcap_path)]
    bpf_filter = params.get("bpf_filter")
    if bpf_filter:
        command += ["-f", validate_safe_value(str(bpf_filter))]
    command += _field_output_args()
    return command


def build_tshark_read_pcap_command(params: dict) -> list[str]:
    pcap_path = validate_safe_value(str(params["pcap_path"]).strip())
    command = ["tshark", "-r", pcap_path]
    display_filter = params.get("display_filter")
    if display_filter:
        command += ["-Y", validate_safe_value(str(display_filter))]
    command += _field_output_args()
    return command


def _parse_field_table(stdout: str) -> dict:
    """tshark's own -T fields -E header=y output: one header line (real field names, tab-
    separated), then one line per packet -- an empty column means that field didn't apply to this
    packet (e.g. udp.srcport on a TCP packet), not a parse failure, so it's simply omitted from
    that packet's own dict rather than stored as "" ."""
    lines = stdout.strip("\n").splitlines()
    if not lines:
        return {"packets": [], "packet_count": 0}
    header = lines[0].split("\t")
    packets = []
    for line in lines[1:]:
        values = line.split("\t")
        row = {header[i]: values[i] for i in range(min(len(header), len(values))) if values[i]}
        if row:
            packets.append(row)
    return {"packets": packets, "packet_count": len(packets)}


def parse_tshark_capture_output(stdout: str) -> dict:
    return _parse_field_table(stdout)


def parse_tshark_read_pcap_output(stdout: str) -> dict:
    return _parse_field_table(stdout)
