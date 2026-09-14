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
    retry_nmap_with_pn_if_host_seemed_down,
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


def test_build_command_omits_os_flag_without_root_or_a_saved_password(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr("agent.tools.builders.nmap.has_sudo_password", lambda: False)
    command = build_nmap_command({"target": "example.com"})
    assert "-O" not in command
    assert command == ["nmap", "-F", "-sV", "example.com"]


def test_build_command_adds_os_flag_as_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0, raising=False)
    command = build_nmap_command({"target": "example.com"})
    assert "-O" in command
    assert "--osscan-guess" in command


def test_build_command_uses_sudo_when_not_root_but_a_password_is_saved(monkeypatch):
    """A saved sudo password (Settings -> Optional interpreters/compilers) is what actually gets
    OS fingerprinting to work without the whole ASRA process needing to run as root."""
    monkeypatch.setattr("os.geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr("agent.tools.builders.nmap.has_sudo_password", lambda: True)

    command = build_nmap_command({"target": "example.com"})

    assert command == ["sudo", "-S", "nmap", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


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


# --- retry_nmap_with_pn_if_host_seemed_down: real incident this covers --------------------------
# nmap's default host-discovery ping gets silently blocked by nearly every CDN/cloud firewall
# (ICMP dropped) -- it does NOT fail (exit_code 0), it just skips ALL port scanning and prints
# "Host seems down... try -Pn". Confirmed live: two real, independently-reachable hosts got zero
# port-scan coverage this way, with no way for the model to add -Pn itself (no extra_args exists).

_HOST_SEEMS_DOWN_STDOUT = """Starting Nmap 7.94SVN ( https://nmap.org )
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.21 seconds
"""


def test_retry_nmap_with_pn_returns_none_for_a_normal_successful_scan():
    command = ["nmap", "-F", "-sV", "example.com"]
    result = {"stdout": "PORT   STATE SERVICE\n80/tcp open  http\n", "exit_code": 0}
    assert retry_nmap_with_pn_if_host_seemed_down(command, result) is None


def test_retry_nmap_with_pn_detects_the_host_seems_down_marker():
    command = ["nmap", "-F", "-sV", "example.com"]
    result = {"stdout": _HOST_SEEMS_DOWN_STDOUT, "exit_code": 0}
    retry_command = retry_nmap_with_pn_if_host_seemed_down(command, result)
    assert retry_command == ["nmap", "-Pn", "-F", "-sV", "example.com"]


def test_retry_nmap_with_pn_inserts_before_a_trailing_os_flags_not_just_appended(monkeypatch):
    """build_nmap_command appends -O/--osscan-guess AFTER the target when running as root, so the
    target is not reliably command[-1] -- -Pn must be inserted right after the executable, not
    blindly at the end (which could land -Pn after the target, which nmap still accepts, but
    inserting after the executable is the one position that's always safe regardless of what else
    is in the command)."""
    command = ["nmap", "-F", "-sV", "example.com", "-O", "--osscan-guess"]
    result = {"stdout": _HOST_SEEMS_DOWN_STDOUT, "exit_code": 0}
    retry_command = retry_nmap_with_pn_if_host_seemed_down(command, result)
    assert retry_command == ["nmap", "-Pn", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


def test_retry_nmap_with_pn_works_with_a_sudo_prefixed_command():
    """build_nmap_command can prefix the whole command with ["sudo", "-S"] when running privileged
    via a saved sudo password -- -Pn must land right after the real "nmap" token (index 2 here),
    never between "sudo" and "-S" (which would corrupt the privileged invocation entirely)."""
    command = ["sudo", "-S", "nmap", "-F", "-sV", "example.com", "-O", "--osscan-guess"]
    result = {"stdout": _HOST_SEEMS_DOWN_STDOUT, "exit_code": 0}
    retry_command = retry_nmap_with_pn_if_host_seemed_down(command, result)
    assert retry_command == ["sudo", "-S", "nmap", "-Pn", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


def test_retry_nmap_with_pn_works_after_runner_has_substituted_the_resolved_path():
    """Real, confirmed incident: agent/tools/runner.py's _run_subprocess overwrites
    command[executable_index] with the tool's fully resolved path (a {TOOL}_PATH override or a
    plain shutil.which result) BEFORE calling retry_command_on_result -- by retry time the literal
    "nmap" token build_nmap_command put there no longer exists in the list at all. Searching for it
    by name (command.index("nmap")) raised an unhandled ValueError and crashed the whole session,
    three times in one real project, every time nmap hit an ICMP-blocking host (confirmed live:
    "/usr/bin/nmap" resolved and substituted, then this same crash on the very next line)."""
    command = ["/usr/bin/nmap", "-F", "-sV", "example.com"]
    result = {"stdout": _HOST_SEEMS_DOWN_STDOUT, "exit_code": 0}
    retry_command = retry_nmap_with_pn_if_host_seemed_down(command, result)
    assert retry_command == ["/usr/bin/nmap", "-Pn", "-F", "-sV", "example.com"]


def test_retry_nmap_with_pn_works_after_runner_has_substituted_a_sudo_prefixed_resolved_path():
    command = ["sudo", "-S", "/usr/bin/nmap", "-F", "-sV", "example.com", "-O", "--osscan-guess"]
    result = {"stdout": _HOST_SEEMS_DOWN_STDOUT, "exit_code": 0}
    retry_command = retry_nmap_with_pn_if_host_seemed_down(command, result)
    assert retry_command == ["sudo", "-S", "/usr/bin/nmap", "-Pn", "-F", "-sV", "example.com", "-O", "--osscan-guess"]


def test_retry_nmap_with_pn_never_loops_a_second_time():
    """A command that already has -Pn (the retry itself, or a future model-driven call that
    somehow already included it) must never trigger a second retry, even if the host is STILL
    down with -Pn (a genuinely, fully unreachable host, not just ICMP-blocked)."""
    command = ["nmap", "-Pn", "-F", "-sV", "example.com"]
    result = {"stdout": _HOST_SEEMS_DOWN_STDOUT, "exit_code": 0}
    assert retry_nmap_with_pn_if_host_seemed_down(command, result) is None


def test_the_registered_nmap_tool_is_wired_to_the_pn_retry_hook():
    spec = get_tool("nmap")
    assert spec.retry_command_on_result is retry_nmap_with_pn_if_host_seemed_down


# --- retry_nmap_without_os_detection_on_timeout: real incident this covers ----------------------
# -O/--osscan-guess sends extra raw-socket probes on top of the ordinary port scan, and a slow/
# filtering host can make those probes the difference between finishing well inside
# TOOL_TIMEOUT_SECONDS and burning the whole budget -- confirmed live (midnight-usr_24ba7e): the
# same nmap call against the same host timed out twice in a row, once per session resume, always
# with -O --osscan-guess present, while shodan_internetdb_lookup returned the same ports in 190ms.


def test_retry_without_os_detection_drops_o_and_osscan_guess():
    command = ["nmap", "-F", "-sV", "5.252.32.97", "-O", "--osscan-guess"]
    retry_command = retry_nmap_without_os_detection_on_timeout(command)
    assert retry_command == ["nmap", "-F", "-sV", "5.252.32.97"]


def test_retry_without_os_detection_works_with_a_sudo_prefixed_command():
    command = ["sudo", "-S", "nmap", "-F", "-sV", "5.252.32.97", "-O", "--osscan-guess"]
    retry_command = retry_nmap_without_os_detection_on_timeout(command)
    assert retry_command == ["sudo", "-S", "nmap", "-F", "-sV", "5.252.32.97"]


def test_retry_without_os_detection_returns_none_when_there_was_never_an_o_flag():
    """Nothing to drop -- this invocation wasn't root and had no saved sudo password, so a second
    identical dispatch would just be a second guaranteed-identical timeout; None tells the caller
    not to retry at all rather than looping pointlessly."""
    command = ["nmap", "-F", "-sV", "5.252.32.97"]
    assert retry_nmap_without_os_detection_on_timeout(command) is None


def test_the_registered_nmap_tool_is_wired_to_the_timeout_retry_hook():
    spec = get_tool("nmap")
    assert spec.retry_command_on_timeout is retry_nmap_without_os_detection_on_timeout
