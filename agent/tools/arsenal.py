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


def summarize_arsenal() -> dict:
    """Live snapshot for the Tools page. Never runs anything -- pure read over the registry's own
    installed-check. Shape (all counts are over EXTERNAL tools unless the name says native):

        verdict:            "none" | "partial" | "full"
        external_total/installed, native_total/installed: int
        percent:            0-100 (external installed ratio, the headline number)
        modes:              [{key,label,total,installed,percent,available}], only buckets that
                            actually have at least one external tool, ordered web -> re -> toolkit
        missing/present:    sorted external tool names, for the expandable detail list
    """
    inventory = list_tool_availability()
    external = [e for e in inventory if e["tier"] == _EXTERNAL_TIER]
    native = [e for e in inventory if e["tier"] != _EXTERNAL_TIER]

    external_installed = [e for e in external if e["installed"]]
    external_missing = [e for e in external if not e["installed"]]

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
    }
