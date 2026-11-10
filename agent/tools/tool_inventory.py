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

import os
import threading
import time

from agent.tools.registry import TOOL_REGISTRY, categories_of
from agent.tools.runner import tool_is_installed

# Short-TTL cache for list_tool_availability() -- real, confirmed incident (2026-11-08): this used
# to re-check EVERY registered tool (tool_is_installed, a real shutil.which()/availability_check()
# per tool -- dozens of them) on every single render of /settings (the Tools tab) and /subagents
# (its own tool checklist), landing a real, measurable multi-hundred-ms cost on both pages' every
# single load even though which tools are installed essentially never changes except right after
# the operator explicitly installs/uninstalls one. Same TTL-cache shape as agent/llm_client.py's
# own get_model_choices cache: a mutation that can change the real answer (an arsenal/nuclei-pack
# install or uninstall completing) explicitly invalidates it so the result still updates right
# away, not only after the TTL expires.
_TOOL_AVAILABILITY_CACHE_TTL_SECONDS = float(os.getenv("TOOL_AVAILABILITY_CACHE_TTL_SECONDS", "30"))
_tool_availability_cache: tuple[float, list[dict]] | None = None
_tool_availability_cache_lock = threading.Lock()


def invalidate_tool_availability_cache() -> None:
    """Drop the cached tool-availability list so the next list_tool_availability() call re-checks
    every tool live. Call after any install/uninstall that can change what's actually on disk."""
    global _tool_availability_cache
    with _tool_availability_cache_lock:
        _tool_availability_cache = None


def list_tool_availability() -> list[dict]:
    """Cached wrapper over _list_tool_availability_uncached (TTL:
    TOOL_AVAILABILITY_CACHE_TTL_SECONDS). See invalidate_tool_availability_cache for how an
    install/uninstall bypasses the TTL. Returns a fresh copy (list of fresh dicts) every call, even
    on a cache hit -- callers elsewhere filter this into new lists but never mutate an entry dict
    in place today, and a fresh copy keeps it that way guaranteed, not just true by convention."""
    global _tool_availability_cache
    now = time.monotonic()
    with _tool_availability_cache_lock:
        if _tool_availability_cache is not None and now - _tool_availability_cache[0] < _TOOL_AVAILABILITY_CACHE_TTL_SECONDS:
            return [dict(entry) for entry in _tool_availability_cache[1]]
    entries = _list_tool_availability_uncached()
    with _tool_availability_cache_lock:
        _tool_availability_cache = (now, entries)
    return [dict(entry) for entry in entries]


def _list_tool_availability_uncached() -> list[dict]:
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
            # Provisioned by setup_tools_heavy.sh rather than the base setup_tools.sh -- see
            # ToolSpec.heavy's own docstring. Always False for a tier-1 tool (that field's default).
            "heavy": spec.heavy,
        }
        for spec in TOOL_REGISTRY
    ]
    entries.sort(key=lambda e: e["name"])
    return entries


def list_installed_tool_names() -> list[str]:
    """The Subagents tab's own tool checklist only ever offers what's real -- this is that
    filtered, name-only view of list_tool_availability() above."""
    return [entry["name"] for entry in list_tool_availability() if entry["installed"]]
