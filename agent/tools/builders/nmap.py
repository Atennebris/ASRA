"""build_command() and output parser for Nmap."""
from __future__ import annotations

import os
import re

from agent.tools.builders.validators import validate_target
from agent.tools.capability_install import has_sudo_password

_PORT_LINE_PATTERN = re.compile(
    r"^(?P<port>\d+)/(?P<protocol>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)\s*(?P<version>.*)$"
)
# nmap prints an exact match as "OS details: <text>" when confident, or falls back to one or more
# "Aggressive OS guesses: <text1> (NN%), <text2> (NN%), ..." lines when it isn't — either way this
# is real signal from the actual TCP/IP stack fingerprint, never invented.
_OS_DETAILS_PATTERN = re.compile(r"^OS details:\s*(?P<text>.+)$", re.MULTILINE)
_OS_GUESS_PATTERN = re.compile(r"^Aggressive OS guesses:\s*(?P<text>.+)$", re.MULTILINE)


def build_nmap_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    command = ["nmap", "-F", "-sV", target]
    # -O (TCP/IP stack fingerprinting) needs raw sockets, which needs root — nmap hard-fails the
    # ENTIRE scan (not just OS detection) when asked for it without that privilege, so only add
    # the flag when this invocation can actually use it. --osscan-guess widens the match instead
    # of requiring nmap's own high-confidence threshold, trading some precision for actually
    # getting a guess on more hosts (still labeled with its own confidence %, never hidden).
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        command += ["-O", "--osscan-guess"]
    elif has_sudo_password():
        # Not root ourselves, but a saved sudo password (Settings -> Optional
        # interpreters/compilers) lets agent/tools/runner.py's _run_tracked elevate this one
        # specific, self-aware invocation via `sudo -S` (see that function's own comment for the
        # exact mechanism/guarantees). No password saved -- same unprivileged scan as before this
        # existed, just without -O, never a hard failure.
        command = ["sudo", "-S", *command, "-O", "--osscan-guess"]
    return command


_HOST_SEEMS_DOWN_MARKER = "Host seems down"


def retry_nmap_with_pn_if_host_seemed_down(command: list[str], result: dict) -> list[str] | None:
    """nmap's own default host-discovery ping is routinely blocked by a firewall/CDN (ICMP is
    dropped by nearly every cloud provider/Cloudflare-fronted host) — when that happens nmap does
    NOT fail (exit_code 0, a normal "ok" result), it silently skips ALL port scanning and prints
    "Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn". Confirmed
    live: two real, independently-reachable hosts (one shared between two subdomains of the same
    target, both had genuine successful http_request hits elsewhere in the same session)
    got ZERO port-scan coverage this way, and the model correctly recognized the exact fix nmap's
    own output was suggesting but had no way to act on it (no extra_args/flag passthrough exists in
    nmap's schema at all). One silent, automatic retry with -Pn closes this without needing the
    model to somehow special-case a "successful" nmap result. -Pn is inserted right after the real
    executable token rather than at the end, since build_nmap_command appends -O/--osscan-guess
    AFTER the target when running as root — the target is not reliably command[-1].

    By the time this runs, agent/tools/runner.py's _run_subprocess has already overwritten
    command[executable_index] with the tool's fully resolved path (a {TOOL}_PATH override or a
    plain shutil.which result, e.g. "/usr/bin/nmap") for the real dispatch that already happened —
    the literal "nmap" token build_nmap_command put there no longer exists in this list by retry
    time, so it must be located the same way runner.py itself locates it: index 0, or index 2 right
    after a ["sudo", "-S"] prefix (the same prefix build_nmap_command adds for a privileged
    invocation via a saved sudo password) — never by searching for the bare name.
    """
    if "-Pn" in command:
        return None  # already retried once this call, never loop further
    if _HOST_SEEMS_DOWN_MARKER not in (result.get("stdout") or ""):
        return None
    nmap_index = 2 if command[:2] == ["sudo", "-S"] else 0
    return [*command[:nmap_index + 1], "-Pn", *command[nmap_index + 1:]]


def retry_nmap_without_os_detection_on_timeout(command: list[str]) -> list[str] | None:
    """OS-detection (-O --osscan-guess) sends extra raw-socket probes on top of the ordinary port
    scan, and a slow/filtering host can make those probes the difference between finishing well
    inside TOOL_TIMEOUT_SECONDS and hanging for the entire budget. It's optional enrichment for
    recon, not something worth spending a second full timeout on to get — confirmed live
    (midnight-usr_24ba7e): the same nmap invocation against the same host timed out twice in a row
    (once per session resume, a day and a half apart), always with -O --osscan-guess present, while
    shodan_internetdb_lookup returned the same open ports for that host in 190ms. The normal 1-Step
    Retry can't help here either — runner.py's own timeout path has no stdout/stderr for the
    correction call to react to, so the model's "corrected" arguments come back byte-identical to
    the ones that just timed out (nmap's own schema only exposes `target`, nothing to correct). One
    deterministic retry without the OS-detection flags — never routed through the model, nothing
    about "drop -O" needs guessing — trades a best-effort OS guess for actually finishing the scan.
    """
    if "-O" not in command:
        return None  # nothing to drop -- this invocation never had it (not root, no sudo password)
    return [token for token in command if token not in ("-O", "--osscan-guess")]


def _parse_os_guess(stdout: str) -> str | None:
    match = _OS_DETAILS_PATTERN.search(stdout)
    if match:
        return match.group("text").strip()
    match = _OS_GUESS_PATTERN.search(stdout)
    if match:
        # First (highest-confidence) entry only, e.g. "Linux 5.0 - 5.4 (92%)" from a
        # comma-separated list of guesses ordered by descending confidence.
        return match.group("text").split(",")[0].strip()
    return None


def parse_nmap_output(stdout: str) -> dict:
    """Extracts open {port, service, version} entries plus a best-effort OS guess (None when
    nmap had no confident/guessed match at all — e.g. run without -O, or an unfingerprintable
    target) from Nmap's default text output."""
    ports = []
    for line in stdout.splitlines():
        match = _PORT_LINE_PATTERN.match(line.strip())
        if not match:
            continue
        if match.group("state") != "open":
            continue
        ports.append(
            {
                "port": int(match.group("port")),
                "service": match.group("service"),
                "version": match.group("version").strip(),
            }
        )
    return {"ports": ports, "os_guess": _parse_os_guess(stdout)}
