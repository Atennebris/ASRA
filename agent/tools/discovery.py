"""KNOWN_TOOLS autodiscovery + custom_tools.yaml manual registration."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

from agent.tools.builders.discovered import make_generic_discovered_command
from agent.tools.registry import Category, ToolSpec
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Flat list of well-known binaries per category — extend as needed, this is a seed list,
# not an exhaustive one. Only binaries actually found via shutil.which()
# at startup get registered; nothing here is installed automatically.
KNOWN_TOOLS: dict[Category, list[str]] = {
    "recon": ["dnsx", "httpx"],
    # whatweb/wpscan/nikto/ffuf/subfinder/hydra moved to explicit ToolSpec registrations
    # (agent/tools/__init__.py) — they have real build_command/parser/gating logic now, not the
    # generic discovered path. ffuf in particular was miscategorized here as "exploit" (gating it
    # behind the human-approval/allowlist requirement it doesn't actually need) — its real
    # registration correctly places it under "scan", the same category as nikto/whatweb/nuclei.
    # Hydra needed its own native tier-1 wrapper (hydra_start/hydra_check) instead of the generic
    # tier-2 subprocess path entirely -- a real brute-force run takes many minutes, background_jobs.py
    # runs it without blocking, which the generic discovered-tool path has no way to express.
    # amass moved the same way (agent/tools/amass_runner.py's amass_enum, registered under
    # "amass_enum" not the bare binary name) -- the generic discovered path would call `amass`
    # directly with whatever args the model guesses, which is actively wrong for this binary: v5's
    # own CLI needs two separate invocations (enum populates a local graph datastore, subs -names
    # queries it back out) to get any discovered names back at all, confirmed live -- a naive
    # single generic call always returns nothing.
    "scan": [],
    "exploit": ["gobuster"],
}

CUSTOM_TOOLS_PATH = Path("custom_tools.yaml")


def _resolve_httpx_candidate() -> str | None:
    """Same override convention as agent/tools/runner.py's own _resolve_executable (HTTPX_PATH,
    same env var name it already reads at real dispatch time) — the liveness check below has to
    resolve the SAME path dispatch will actually use, or the two can disagree (a broken PATH-order
    binary could pass shutil.which() here while HTTPX_PATH points dispatch somewhere else real, or
    vice versa). Confirmed live in this project's own dev environment: activating venv/ (needed for
    the app's own Python dependencies, one of which is ALSO named httpx) puts venv/bin/httpx --
    itself the broken pip-installed CLI shim, not a stray global install -- ahead of the real
    ProjectDiscovery binary setup_tools.sh installs to /usr/local/bin/httpx, every single time the
    venv is active. Setting HTTPX_PATH=/usr/local/bin/httpx in .env is the real, permanent fix for
    that specific shadowing; this override path is what lets it take effect here too, not just at
    dispatch time.
    """
    override = os.getenv("HTTPX_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    return shutil.which("httpx")


def _httpx_binary_is_real() -> bool:
    """A plain shutil.which("httpx")/HTTPX_PATH presence check alone is not a safe "already
    installed" signal for this one binary -- setup_tools.sh's install_httpx() documents the real
    incident this guards against: a `pip install httpx[cli]` console-script shim can sit on PATH
    under the exact same name as ProjectDiscovery's Go recon tool, and calling it always fails with
    "The httpx command line client could not run because the required dependencies were not
    installed. Make sure you've installed everything with: pip install 'httpx[cli]'" -- confirmed
    live: a whole recon phase burned 9 targets x (1 call + 1 wasted 1-Step Retry) because this shim
    got registered without ever being test-invoked first, and the model had no way to guess this
    was an environment problem rather than a flag/argument mistake. setup_tools.sh already runs
    `httpx -version` before trusting it; this mirrors that same check for the running app's own
    discovery.
    """
    path = _resolve_httpx_candidate()
    if path is None:
        return False
    try:
        result = subprocess.run([path, "-version"], capture_output=True, timeout=5, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


_HTTPX_SHIM_MARKER = "pip install 'httpx[cli]'"
_HTTPX_UNKNOWN_FLAG_RE = re.compile(r"flag provided but not defined:\s*(\S+)")
# Confirmed-real ProjectDiscovery httpx flags (verified against a real, live scan's own successful
# calls this exact hint replaced -- not a guess at what httpx probably accepts).
_HTTPX_KNOWN_GOOD_FLAGS = (
    "-u (target URL, repeatable)", "-json", "-title", "-status-code", "-tech-detect", "-server",
    "-location", "-follow-redirects", "-silent", "-timeout <seconds>", "-retries <n>",
    "-include-response (full response body/headers in -json output)",
)


def interpret_httpx_failure(result: dict) -> str | None:
    """Defense-in-depth alongside _httpx_binary_is_real's own startup check above: if the wrong
    httpx (Python httpx[cli] package's own CLI shim) still somehow got registered — a PATH change
    after startup, a manual custom_tools.yaml entry, anything this module's own one-time discovery
    check couldn't see — this recognizes its own fixed failure text instead of leaving the model to
    guess at flag syntax that could never work.

    Second, separate case this also covers: a REAL httpx binary rejecting a flag that doesn't
    exist ("flag provided but not defined: -whatever", exit code 2) -- confirmed live, a real
    session repeated the exact same hallucinated flag ("-response-in-json") 5 times across several
    minutes despite already having a working call minutes earlier using the real equivalent
    (-include-response), racking up enough real, genuine failures against the target to trip
    agent/core.py's own _dead_host_blocked guard and lock the ENTIRE host out of every OTHER tool
    for the rest of the session. Naming the actual flag that failed, plus a short list of
    known-good real flags, gives the model something concrete to correct toward instead of
    guessing a second made-up flag on the very next attempt.

    None when the failure isn't either of these two specific cases.
    """
    output = (result.get("stdout") or "") + (result.get("stderr") or "")
    if _HTTPX_SHIM_MARKER in output:
        return (
            "This is not a real argument/flag error — the 'httpx' binary on PATH in this environment "
            "is the Python `httpx` library's own CLI shim (pip install httpx[cli]), not ProjectDiscovery's "
            "httpx recon tool of the same name. No combination of arguments will make this work. Stop "
            "retrying this call; skip httpx for the rest of this session and use whatweb/nuclei/nikto for "
            "technology detection instead, or ask the operator to fix PATH so the real httpx (see "
            "setup_tools.sh's install_httpx) takes precedence."
        )
    unknown_flag_match = _HTTPX_UNKNOWN_FLAG_RE.search(output)
    if unknown_flag_match:
        return (
            f"{unknown_flag_match.group(1)!r} is not a real httpx flag — httpx's own CLI rejected it "
            "outright (this is a genuine argument mistake, not a target/connectivity problem). Known-"
            f"good real flags: {', '.join(_HTTPX_KNOWN_GOOD_FLAGS)}. Don't guess another made-up flag "
            "name — use one of these, or drop the flag if you're not sure it exists."
        )
    return None


def discover_known_tools() -> list[ToolSpec]:
    """Registers any KNOWN_TOOLS binary that's actually installed and on PATH — zero config needed."""
    discovered = []
    for category, names in KNOWN_TOOLS.items():
        for name in names:
            if name == "httpx":
                if not _httpx_binary_is_real():
                    logger.debug("discover_known_tools: httpx on PATH doesn't respond to -version (broken/shadowed binary) — not registering it")
                    continue
            elif shutil.which(name) is None:
                continue
            discovered.append(
                ToolSpec(
                    name=name,
                    category=category,
                    tool_tier=2,
                    executable=name,
                    build_command=make_generic_discovered_command(name),
                    requires_allowed_target=category in ("exploit", "post_exploit"),
                    installed_by_default=False,
                )
            )
            logger.debug("discover_known_tools: found %s (category=%s)", name, category)
    return discovered


def load_custom_tools(path: Path = CUSTOM_TOOLS_PATH) -> list[ToolSpec]:
    """Registers tools listed in custom_tools.yaml — personal scripts, never in KNOWN_TOOLS."""
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as f:
        entries = yaml.safe_load(f) or []

    tools = []
    for entry in entries:
        name = entry["id"]
        executable = entry["executable"]
        tools.append(
            ToolSpec(
                name=name,
                category=entry["category"],
                tool_tier=2,
                executable=executable,
                build_command=make_generic_discovered_command(executable),
                requires_allowed_target=entry.get("requires_allowed_target", False),
                installed_by_default=False,
                full_description=entry.get("full_description"),
            )
        )
        logger.debug("load_custom_tools: registered %s from custom_tools.yaml", name)
    return tools
