"""Arsenal readiness summary for the Tools page's "Check" button -- one honest, live answer to
"was setup_tools.sh actually run on this machine, and what is the agent missing without it".

Deliberately NOT a marker file recording "the installer ran once": that would lie in both
directions -- it wouldn't recognise an already-provisioned machine (tools installed some other
way, e.g. a Kali base image) and it wouldn't notice a tool later removed. The only trustworthy
signal is the SAME live check the agent itself makes before running a tool
(agent/tools/runner.py's tool_is_installed, surfaced via tool_inventory.list_tool_availability),
counted over the external (Tier-2) tools -- the ones setup_tools.sh actually provisions and the
only ones that can genuinely be missing. Native (Tier-1) Python tools ship with ASRA and are
always present, so they never move this verdict; they're reported only as context.

The per-mode breakdown answers the operator's real question ("which capabilities degrade without
the arsenal") rather than a bare count: web-scan tools, reverse-engineering tools, and manual
HTTP-toolkit tools are independent buckets -- a machine can be fully ready for one and empty for
another, and a single global percentage would hide that.
"""
from __future__ import annotations

from agent.opencode_cli import diagnose_opencode_cli
from agent.tools.tool_inventory import list_tool_availability

# Tier-2 == external subprocess binary (setup_tools.sh's job); Tier-1 == native Python, always
# present. Same split tools.html already draws as "External" vs "Native".
_EXTERNAL_TIER = 2


def _mode_of(categories: tuple[str, ...]) -> str:
    """Which capability bucket an external tool belongs to. registry.py's Category type guarantees
    "re" and "toolkit" never co-occur with each other or a web category in one ToolSpec (same
    exhaustive, non-overlapping partition main.py's _tool_domain already relies on), so this is a
    clean classification, not a guess."""
    if "re" in categories:
        return "re"
    if "toolkit" in categories:
        return "toolkit"
    return "web"


_MODE_LABELS = {
    "web": "Web scan / exploitation",
    "re": "Reverse engineering",
    "toolkit": "HTTP toolkit (external)",
}


def _percent(installed: int, total: int) -> int:
    return round(installed * 100 / total) if total else 0


def _dependencies() -> list[dict]:
    """Dependencies that are NOT recon/exploit tools -- today just the opencode CLI (agent/opencode_local_provider.py's "opencode (local server)" LLM provider).
    Deliberately separate from external/native/modes/verdict above, never folded into any of
    those counts: this answers "does one particular, optional LLM provider work", not "can the
    agent run its own tools" -- counting it in would make a fresh install missing only this one
    optional dependency read as a degraded tool arsenal, which it isn't. It has its own one-click
    installer (agent/opencode_install.py), surfaced as a button on this row.
    """
    opencode = diagnose_opencode_cli()
    # "installed" means USABLE here (a native copy), not merely "something named opencode is on
    # PATH" -- a Windows-side copy visible through WSL2's PATH interop is reported for what it is.
    return [
        {
            "name": "opencode",
            "label": "opencode CLI",
            "installed": opencode.usable,
            "note": opencode.explanation() or "Dependency for the \"opencode (local server)\" LLM provider (Settings -> AI Provider & Model) — not a recon/exploit tool.",
            "install_label": opencode.install_label,
            "auto_install": opencode.auto_install,
        },
    ]


def summarize_arsenal() -> dict:
    """Live snapshot for the Tools page. Never runs anything -- pure read over the registry's own
    installed-check. Shape (all counts are over EXTERNAL tools unless the name says native):

        verdict:            "none" | "partial" | "full"
        external_total/installed, native_total/installed: int
        percent:            0-100 (external installed ratio, the headline number)
        modes:              [{key,label,total,installed,percent,available}], only buckets that
                            actually have at least one external tool, ordered web -> re -> toolkit
        missing/present:    sorted external tool names, for the expandable detail list
        dependencies:       [{name,label,installed,note}] -- non-tool dependencies (see
                            _dependencies' own docstring); never affects verdict/percent above.
    """
    inventory = list_tool_availability()
    # heavy tools (ToolSpec.heavy=True -- provisioned by setup_tools_heavy.sh, not setup_tools.sh)
    # are split out BEFORE everything below: they must never count toward the base arsenal's own
    # verdict/percent/modes/missing/present, or a heavy tool the operator never installs (by
    # design, via its own separate "Install (heavy)" button) would make the ordinary "Check
    # arsenal" verdict read as perpetually degraded for something setup_tools.sh was never
    # responsible for provisioning in the first place.
    #
    # Real, operator-caught bug this comment used to describe wrong: this filter used to ALSO
    # require tier == _EXTERNAL_TIER (2) for a tool to count as "heavy" -- but Ghidra/unblob are
    # BOTH heavy=True AND tool_tier=1 (native_function dispatch for architectural reasons -- a
    # socket protocol / a --report file the generic tier-2 pipeline can't read -- not because
    # they're "always present" the way an ordinary tier-1 Python helper is). The old filter
    # silently excluded them from heavy_total/heavy_installed entirely, so the Tools page's own
    # "Heavy arsenal (Ghidra, ...)" block could read "100%" while Ghidra itself was never even
    # checked -- confirmed live: only sigrok_cli/adb (the tier=2 heavy tools) were ever counted.
    # heavy is now keyed on the heavy flag ALONE, independent of tier; native (below) excludes
    # anything heavy so a heavy tier-1 tool isn't ALSO double-counted as "native, always present".
    heavy = [e for e in inventory if e.get("heavy", False)]
    external = [e for e in inventory if e["tier"] == _EXTERNAL_TIER and not e.get("heavy", False)]
    native = [e for e in inventory if e["tier"] != _EXTERNAL_TIER and not e.get("heavy", False)]

    external_installed = [e for e in external if e["installed"]]
    external_missing = [e for e in external if not e["installed"]]
    heavy_installed = [e for e in heavy if e["installed"]]
    heavy_missing = [e for e in heavy if not e["installed"]]

    modes: list[dict] = []
    for key in ("web", "re", "toolkit"):
        bucket = [e for e in external if _mode_of(e["categories"]) == key]
        if not bucket:
            continue
        installed = sum(1 for e in bucket if e["installed"])
        modes.append({
            "key": key,
            "label": _MODE_LABELS[key],
            "total": len(bucket),
            "installed": installed,
            "percent": _percent(installed, len(bucket)),
            "available": installed > 0,
        })

    installed_count = len(external_installed)
    if installed_count == 0:
        verdict = "none"
    elif installed_count == len(external):
        verdict = "full"
    else:
        verdict = "partial"

    return {
        "verdict": verdict,
        "external_total": len(external),
        "external_installed": installed_count,
        "native_total": len(native),
        "native_installed": sum(1 for e in native if e["installed"]),
        "percent": _percent(installed_count, len(external)),
        "modes": modes,
        "missing": sorted(e["name"] for e in external_missing),
        "present": sorted(e["name"] for e in external_installed),
        "dependencies": _dependencies(),
        # The "heavy" arsenal (tools provisioned by setup_tools_heavy.sh instead of the fast base
        # setup_tools.sh), entirely separate from everything above: 0/0 until a tool that actually
        # needs the heavy installer (Ghidra, ...) registers heavy=True on its own ToolSpec -- the
        # Tools page only shows this block once heavy_total > 0, so a fresh install with no heavy
        # tools registered yet shows nothing extra here, not a confusing permanent "0/0" row.
        "heavy_total": len(heavy),
        "heavy_installed": len(heavy_installed),
        "heavy_percent": _percent(len(heavy_installed), len(heavy)),
        "heavy_missing": sorted(e["name"] for e in heavy_missing),
        "heavy_present": sorted(e["name"] for e in heavy_installed),
    }
