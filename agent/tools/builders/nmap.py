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
    # -Pn (skip host-discovery ping, assume the host is up and go straight to port scanning) used
    # to only get added via a wasted-then-corrected retry cycle, discovered fresh on every single
    # host: a first attempt without it routinely printed "Host seems down" (ICMP is blocked by
    # nearly every cloud provider/CDN-fronted host on the public internet -- the NORM for a recon
    # target, not a rare edge case) and got zero port-scan coverage, then a corrected retry added
    # -Pn and actually scanned. Confirmed live (Telenor-Sweden-YesWeHack rescan session): this cost
    # roughly 30+ extra seconds per host, on EVERY host, across a mass-subdomain recon sweep, for
    # an outcome ("add -Pn") that's already known ahead of time rather than genuinely discovered.
    # -Pn as the base default trades a slightly slower result against a host that's genuinely down
    # (nmap probes its ports directly instead of a quick ping-fail) for never paying this tax on
    # the overwhelmingly common case of a reachable host that merely blocks ICMP.
    command = ["nmap", "-Pn", "-F", "-sV", target]
    # Caller-supplied marker (agent/core.py's recon execute() closure) -- set once this exact
    # host's OS is already confidently known, either carried over from an earlier rescan pass or
    # recorded minutes earlier this same pass under one of its other DNS identities (its hostname
    # vs. its own resolved IP). Redoing a ~30s raw-socket OS fingerprint for zero new information
    # is exactly the other half of the same real incident -Pn above fixes. Skipping it here also
    # means there's no reason to escalate via sudo at all -- that privilege exists solely for -O.
    if params.get("_skip_os_detection"):
        return command
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
