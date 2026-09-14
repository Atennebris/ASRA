"""Live inventory of every registered tool + whether it's actually installed on this machine right
now -- feeds both the Tools settings tab (a read-only "what does this WSL install actually have"
view) and the Subagents settings tab's tool checklist (only real, installed tools are offered,
never a hardcoded list). No such "list everything + is it really there" function existed before
this -- ToolSpec.installed_by_default is a static flag every hardcoded tool sets unconditionally,
not a live check; agent/tools/discovery.py's autodiscovery simply never registers a missing tool
at all, leaving no record of having checked. agent/tools/runner.py's own tool_is_installed is the
real, live check (the SAME one _run_subprocess itself consults before ever running a tool), reused
here rather than a second, separately-drifting guess.
"""
from __future__ import annotations

from agent.tools.registry import TOOL_REGISTRY, categories_of
from agent.tools.runner import tool_is_installed


def list_tool_availability() -> list[dict]:
    """Sorted by name for a stable, predictable UI listing order. Each entry:
    {"name", "categories", "tier", "installed", "description"} -- categories is always a tuple
    (categories_of already normalizes a single-category ToolSpec the same way), tier is 1 (native
    Python) or 2 (external subprocess binary), matching ToolSpec.tool_tier directly. description
    is the same LLM-facing one-liner every hardcoded tool already carries (ToolSpec.description),
    falling back to full_description for a discovered/custom tool with no --help-derived summary,
    or "" when neither exists -- the Subagents tab's tool checklist (subagents.html) surfaces this
    on hover so picking a tool doesn't require already knowing what it does.
    """
    entries = [
        {
            "name": spec.name,
            "categories": categories_of(spec),
            "tier": spec.tool_tier,
            "installed": tool_is_installed(spec),
            "description": spec.description or spec.full_description or "",
            # A tool whose presence is decided by a custom availability_check (an importable package
            # like qiling, or the browser tools' Playwright download) rather than a plain binary on
            # PATH -- lets the UI say "Not installed" instead of a misleading "Not found on PATH".
            "checks_dependency": spec.availability_check is not None,
        }
        for spec in TOOL_REGISTRY
    ]
    entries.sort(key=lambda e: e["name"])
    return entries


def list_installed_tool_names() -> list[str]:
    """The Subagents tab's own tool checklist only ever offers what's real -- this is that
    filtered, name-only view of list_tool_availability() above."""
    return [entry["name"] for entry in list_tool_availability() if entry["installed"]]
