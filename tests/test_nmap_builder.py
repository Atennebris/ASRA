"""nmap OS fingerprinting: -O needs raw sockets (root), and nmap hard-fails the WHOLE scan (not
just OS detection) when asked for it without that privilege -- build_nmap_command must only add
the flag when this process actually has root, never unconditionally. parse_nmap_output must
extract a real, non-invented OS guess (or None when nmap had nothing to report) alongside the
existing port/service/version data.
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.builders.nmap import (
    build_nmap_command,
    parse_nmap_output,
    retry_nmap_without_os_detection_on_timeout,
)
from agent.tools.registry import get_tool

_NMAP_OUTPUT_WITH_OS_DETAILS = """Starting Nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1
80/tcp open  http    Apache httpd 2.4.41
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.4
Network Distance: 1 hop
"""

_NMAP_OUTPUT_WITH_GUESS_ONLY = """Starting Nmap
PORT   STATE SERVICE VERSION
443/tcp open  https   nginx 1.18.0
Aggressive OS guesses: Linux 5.0 - 5.4 (92%), Linux 5.3 - 5.4 (91%), Linux 4.15 - 5.6 (90%)
No exact OS matches for host (test conditions non-ideal).
"""

_NMAP_OUTPUT_NO_OS_DATA = """Starting Nmap
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0
"""


# --- -Pn is now a base default, never discovered via a wasted-then-corrected retry ---------------


def test_build_command_always_includes_pn_without_root_or_a_saved_password(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr("agent.tools.builders.nmap.has_sudo_password", lambda: False)
    command = build_nmap_command({"target": "example.com"})
    assert "-O" not in command
    assert command == ["nmap", "-Pn", "-F", "-sV", "example.com"]


def test_build_command_adds_os_flag_as_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
    command = build_nmap_command({"target": "example.com"})
    assert command == ["nmap", "-Pn", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


def test_build_command_uses_sudo_when_not_root_but_a_password_is_saved(monkeypatch):
    """A saved sudo password (Settings -> Optional interpreters/compilers) is what actually gets
    OS fingerprinting to work without the whole ASRA process needing to run as root."""
    monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr("agent.tools.builders.nmap.has_sudo_password", lambda: True)

    command = build_nmap_command({"target": "example.com"})

    assert command == ["sudo", "-S", "nmap", "-Pn", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


# --- _skip_os_detection: caller (agent/core.py's recon execute() closure) already knows the OS ---


def test_skip_os_detection_drops_o_flag_even_as_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
    command = build_nmap_command({"target": "example.com", "_skip_os_detection": True})
    assert command == ["nmap", "-Pn", "-F", "-sV", "example.com"]


def test_skip_os_detection_never_escalates_via_sudo_either(monkeypatch):
    """No -O means no raw-socket privilege is needed at all -- escalating via sudo just to run a
    plain -F -sV scan would be pointless privilege use for zero extra capability gained."""
    monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr("agent.tools.builders.nmap.has_sudo_password", lambda: True)
    command = build_nmap_command({"target": "example.com", "_skip_os_detection": True})
    assert command == ["nmap", "-Pn", "-F", "-sV", "example.com"]


def test_skip_os_detection_false_or_absent_behaves_exactly_like_before(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
    assert build_nmap_command({"target": "example.com", "_skip_os_detection": False}) == \
        ["nmap", "-Pn", "-F", "-sV", "example.com", "-O", "--osscan-guess"]
    assert build_nmap_command({"target": "example.com"}) == \
        ["nmap", "-Pn", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


def test_parse_output_still_extracts_ports():
    parsed = parse_nmap_output(_NMAP_OUTPUT_WITH_OS_DETAILS)
    assert parsed["ports"] == [
        {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1"},
        {"port": 80, "service": "http", "version": "Apache httpd 2.4.41"},
    ]


def test_parse_output_prefers_exact_os_details_line():
    parsed = parse_nmap_output(_NMAP_OUTPUT_WITH_OS_DETAILS)
    assert parsed["os_guess"] == "Linux 5.0 - 5.4"


def test_parse_output_falls_back_to_highest_confidence_guess():
    parsed = parse_nmap_output(_NMAP_OUTPUT_WITH_GUESS_ONLY)
    assert parsed["os_guess"] == "Linux 5.0 - 5.4 (92%)"


def test_parse_output_os_guess_is_none_when_nmap_reported_nothing():
    """Absence of data must never be read/rendered as a guessed OS."""
    parsed = parse_nmap_output(_NMAP_OUTPUT_NO_OS_DATA)
    assert parsed["os_guess"] is None


# --- retry_nmap_without_os_detection_on_timeout: real incident this covers ----------------------
# -O/--osscan-guess sends extra raw-socket probes on top of the ordinary port scan, and a slow/
# filtering host can make those probes the difference between finishing well inside
# TOOL_TIMEOUT_SECONDS and burning the whole budget -- confirmed live (midnight-usr_24ba7e): the
# same nmap call against the same host timed out twice in a row, once per session resume, always
# with -O --osscan-guess present, while shodan_internetdb_lookup returned the same ports in 190ms.


def test_retry_without_os_detection_drops_o_and_osscan_guess():
    command = ["nmap", "-Pn", "-F", "-sV", "5.252.32.97", "-O", "--osscan-guess"]
    retry_command = retry_nmap_without_os_detection_on_timeout(command)
    assert retry_command == ["nmap", "-Pn", "-F", "-sV", "5.252.32.97"]


def test_retry_without_os_detection_works_with_a_sudo_prefixed_command():
    command = ["sudo", "-S", "nmap", "-Pn", "-F", "-sV", "5.252.32.97", "-O", "--osscan-guess"]
    retry_command = retry_nmap_without_os_detection_on_timeout(command)
    assert retry_command == ["sudo", "-S", "nmap", "-Pn", "-F", "-sV", "5.252.32.97"]


def test_retry_without_os_detection_returns_none_when_there_was_never_an_o_flag():
    """Nothing to drop -- this invocation wasn't root and had no saved sudo password (or already
    had _skip_os_detection set), so a second identical dispatch would just be a second guaranteed-
    identical timeout; None tells the caller not to retry at all rather than looping pointlessly."""
    command = ["nmap", "-Pn", "-F", "-sV", "5.252.32.97"]
    assert retry_nmap_without_os_detection_on_timeout(command) is None


def test_the_registered_nmap_tool_is_wired_to_the_timeout_retry_hook():
    spec = get_tool("nmap")
    assert spec.retry_command_on_timeout is retry_nmap_without_os_detection_on_timeout
    # The old result-based -Pn retry hook is gone -- -Pn is a base default now (see the tests
    # above), there's nothing left for a retry_command_on_result hook to correct on nmap.
    assert spec.retry_command_on_result is None
