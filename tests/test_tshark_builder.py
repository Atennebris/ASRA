"""build_tshark_capture_command/build_tshark_read_pcap_command + their shared field-table parser --
RE mode's packet-capture/analysis capability. tests/conftest.py's autouse _never_touch_real_app_state
fixture already isolates APP_DATA_DIR/resolve_global_app_dir for every test here, so the session-
scoped capture-path tests write into a throwaway location, never a real install's own data.
"""
from pathlib import Path

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.tshark import (
    build_tshark_capture_command,
    build_tshark_read_pcap_command,
    parse_tshark_capture_output,
    parse_tshark_read_pcap_output,
)
from agent.tools.registry import get_tool
from sessions import store

_REAL_SHAPED_FIELD_OUTPUT = (
    "frame.time_relative\tframe.protocols\tip.src\tip.dst\ttcp.srcport\ttcp.dstport\tudp.srcport\tudp.dstport\tdns.qry.name\thttp.host\thttp.request.method\thttp.request.uri\ttls.handshake.extensions_server_name\n"
    "0.000000\teth:ip:tcp:tls\t10.0.0.5\t93.184.216.34\t51514\t443\t\t\t\t\t\t\texample.com\n"
    "0.041232\teth:ip:udp:dns\t10.0.0.5\t8.8.8.8\t\t\t52341\t53\texample.com\t\t\t\t\n"
)


def test_build_tshark_capture_command_defaults_to_any_interface_and_writes_a_pcap():
    command = build_tshark_capture_command({})
    assert command[:2] == ["tshark", "-i"]
    assert command[2] == "any"
    assert "-w" in command
    pcap_path = command[command.index("-w") + 1]
    assert pcap_path.endswith(".pcap")
    assert "-T" in command and "fields" in command


def test_build_tshark_capture_command_honors_an_explicit_interface_and_bpf_filter():
    command = build_tshark_capture_command({"interface": "eth0", "bpf_filter": "tcp port 443"})
    assert command[1:3] == ["-i", "eth0"]
    assert "-f" in command
    assert command[command.index("-f") + 1] == "tcp port 443"


def test_build_tshark_capture_command_clamps_duration_to_the_configured_ceiling(monkeypatch):
    monkeypatch.setenv("TSHARK_CAPTURE_MAX_SECONDS", "30")
    command = build_tshark_capture_command({"duration_seconds": 9999})
    duration_arg = command[command.index("-a") + 1]
    assert duration_arg == "duration:30"


def test_build_tshark_capture_command_uses_the_requested_duration_when_under_the_ceiling(monkeypatch):
    monkeypatch.setenv("TSHARK_CAPTURE_MAX_SECONDS", "120")
    command = build_tshark_capture_command({"duration_seconds": 15})
    duration_arg = command[command.index("-a") + 1]
    assert duration_arg == "duration:15"


def test_build_tshark_capture_command_writes_the_pcap_into_this_sessions_own_project_folder():
    session_id = store.create_session("local-target", name="tshark-capture-persist-test")

    command = build_tshark_capture_command({"_session_id": session_id})

    pcap_path = Path(command[command.index("-w") + 1])
    session_folder = Path(store.get_session_folder(session_id))
    assert pcap_path.parent == session_folder / "captures"
    assert pcap_path.parent.is_dir()


def test_build_tshark_capture_command_falls_back_to_the_global_app_dir_without_a_session_id():
    from projects.paths import resolve_global_app_dir

    command = build_tshark_capture_command({})

    pcap_path = Path(command[command.index("-w") + 1])
    assert pcap_path.parent == resolve_global_app_dir() / "captures"


def test_build_tshark_read_pcap_command_reads_a_given_file():
    command = build_tshark_read_pcap_command({"pcap_path": "/tmp/capture.pcap"})
    assert command[:3] == ["tshark", "-r", "/tmp/capture.pcap"]
    assert "-Y" not in command


def test_build_tshark_read_pcap_command_applies_a_display_filter():
    command = build_tshark_read_pcap_command({"pcap_path": "/tmp/capture.pcap", "display_filter": "http.request"})
    assert "-Y" in command
    assert command[command.index("-Y") + 1] == "http.request"


def test_parse_field_table_extracts_one_dict_per_packet_omitting_blank_columns():
    parsed = parse_tshark_capture_output(_REAL_SHAPED_FIELD_OUTPUT)
    assert parsed["packet_count"] == 2
    tls_packet, dns_packet = parsed["packets"]
    assert tls_packet["ip.dst"] == "93.184.216.34"
    assert tls_packet["tls.handshake.extensions_server_name"] == "example.com"
    assert "udp.srcport" not in tls_packet  # blank column omitted, not stored as ""
    assert dns_packet["dns.qry.name"] == "example.com"


def test_parse_field_table_handles_empty_output():
    assert parse_tshark_read_pcap_output("") == {"packets": [], "packet_count": 0}


def test_the_registered_tshark_capture_tool_has_the_expected_shape():
    spec = get_tool("tshark_capture")
    assert spec.category == "re"
    assert spec.executable == "tshark"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_tshark_capture_command


def test_the_registered_tshark_read_pcap_tool_has_the_expected_shape():
    spec = get_tool("tshark_read_pcap")
    assert spec.category == "re"
    assert spec.executable == "tshark"
    assert spec.requires_allowed_target is False
    assert spec.build_command is build_tshark_read_pcap_command
    assert spec.parameters_schema["required"] == ["pcap_path"]
