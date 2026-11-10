"""Mints one real, named ToolSpec per ENABLED custom-tool record (agent/tools/
custom_tools_store.py) -- visible to the model exactly like radare2/gdb/any other registered tool,
not a single "run_custom_tool(name, args)" multiplexer the model would also have to pick a name out
of correctly. The actual universality lives one level down, in run_registered_custom_tool below:
every minted ToolSpec is a thin wrapper around that ONE shared executor with its own `record`
bound in, not N copies of dispatch logic.

tool_tier=1 (native), not 2 (external subprocess), even though every record names a real binary on
disk -- deliberate: a tier-2 tool dispatches through agent/tools/runner.py's own _run_subprocess,
which never sandboxes anything (every existing tier-2 tool -- nmap, radare2, ... -- is ASRA's own
long-vetted toolset, trusted structurally). An operator-added "(custom)" binary has no such track
record, and the MODEL decides the arguments on every call with no human review -- the same risk
shape agent/tools/sandbox.py already exists for (custom_exploit_run/custom_re_script's own
model-written/fetched, unreviewed code). Tier-1 lets the native_function own its own execution
path end to end, so it can run through that exact same sandbox instead of plain, unsandboxed
_run_tracked.
"""
from __future__ import annotations

import os
import subprocess
from functools import partial
from pathlib import Path

from agent.tools.builders.discovered import make_generic_discovered_command
from agent.tools.custom_tools_store import load_custom_tools
from agent.tools.registry import Category, ToolSpec
from agent.tools.sandbox import run_sandboxed
from agent.utils.debug import truncate_for_log
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Its own knob, same spirit as custom_exploit_run's own CUSTOM_SCRIPT_TIMEOUT_SECONDS -- an
# unfamiliar binary hanging (no stdin fed, waiting on a prompt that never comes -- run_sandboxed's
# own stdin=DEVNULL already turns that into a fast EOF for any well-behaved CLI, same protection
# runner.py's _run_tracked documents) shouldn't eat the shared EXPLOIT_TIMEOUT_SECONDS budget every
# other exploit-class tool call also waits on.
_TIMEOUT_SECONDS = int(os.getenv("CUSTOM_TOOL_TIMEOUT_SECONDS", "180"))

# What an operator-facing record["category"] of "custom" (picked when unsure which bucket fits)
# actually becomes on the minted ToolSpec: every ordinary web-pentest category at once.
# ToolSpec.category already supports a tuple for exactly this case (a tool genuinely useful in more
# than one phase, e.g. http_request) -- reused here rather than inventing a new literal "custom"
# Category value nothing else in the registry would understand.
_ORDINARY_CATEGORIES: tuple[Category, ...] = ("recon", "scan", "exploit", "post_exploit")


def _category_for(record: dict) -> Category | tuple[Category, ...]:
    declared = record.get("category", "custom")
    if declared == "custom":
        return _ORDINARY_CATEGORIES
    return declared  # type: ignore[return-value]


def _scratch_dir_for(session_id: str | None) -> Path:
    """Same session-scoped-else-global-app-dir writable scratch root custom_exploit_run's own
    _exploit_scripts_dir already uses -- imported locally to avoid a module import cycle
    (agent/tools/native.py imports a good deal of the tools package at module scope; this module
    is itself imported from agent/core.py's tool-set assembly, so importing native.py back at this
    module's own top level would risk a circular import depending on load order)."""
    from agent.tools.native import _exploit_scripts_dir
    return _exploit_scripts_dir(session_id)


def run_registered_custom_tool(params: dict, *, record: dict) -> dict:
    """The one real executor behind every minted custom-tool ToolSpec. Reuses
    make_generic_discovered_command's own proven argv assembly + "target must actually appear in
    extra_args" validation (agent/tools/builders/discovered.py -- the exact gap an ordinary
    autodiscovered tool already had to solve, since there's no universal target-flag convention
    across unrelated CLI tools), then runs the result through agent/tools/sandbox.py's
    run_sandboxed -- see this module's own header comment for why tier-1 + the sandbox, not a
    plain tier-2 dispatch.

    requires_allowed_target for this specific tool was already decided once, at mint time, from
    the record's own stored value (build_dynamic_toolspecs below sets
    ToolSpec.requires_allowed_target=record["requires_target"]) -- this is the one tool in the
    registry where several different minted ToolSpecs share this one function body, each with its
    own static value baked in, rather than one ToolSpec/one hardcoded builder the way every other
    tool works; run_tool()'s own guardrail (agent/tools/runner.py) already enforced it against the
    allowlist before this function was ever reached, using whichever specific ToolSpec the model
    actually called.
    """
    build_command = make_generic_discovered_command(record["path"])
    try:
        command = build_command(params)
    except ValueError as exc:
        return {"status": "error", "error": str(exc)}

    scratch_dir = _scratch_dir_for(params.get("_session_id"))
    logger.debug("run_registered_custom_tool: name=%s path=%s command=%s", record["name"], record["path"], command)
    try:
        proc = run_sandboxed(command, scratch_dir, _TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        logger.debug("run_registered_custom_tool: %s timed out after %ss", record["name"], _TIMEOUT_SECONDS)
        return {
            "status": "timeout",
            "error": f"{record['name']} exceeded its {_TIMEOUT_SECONDS}s timeout and was killed "
                     "-- it either hung waiting on input, or is genuinely slower than this budget.",
        }

    logger.debug(
        "run_registered_custom_tool: %s finished exit_code=%s stdout_preview=%s stderr_preview=%s",
        record["name"], proc.returncode, truncate_for_log(proc.stdout), truncate_for_log(proc.stderr),
    )
    result = {
        "status": "ok" if proc.returncode == 0 else "error",
        "exit_code": proc.returncode,
        "stdout": proc.stdout[:8000],
        "stderr": proc.stderr[:2000],
    }
    if proc.returncode != 0:
        result["error"] = (result["stderr"] or f"{record['name']} exited with code {proc.returncode} and no stderr output").strip()
    return result


def _mint_toolspec(record: dict) -> ToolSpec:
    path = record["path"]
    return ToolSpec(
        name=record["name"],
        category=_category_for(record),
        tool_tier=1,
        executable="",  # dispatch never uses this (native_function owns it) -- see header comment
        build_command=None,
        requires_allowed_target=record.get("requires_target", True),
        installed_by_default=False,
        native_function=partial(run_registered_custom_tool, record=record),
        # Always real content for _tool_description's fallback chain (agent/core.py) to never need
        # -- a record always gets SOME description (operator-written, or capture_usage_hint's own
        # --help capture at add time, or this last-resort line) before it's ever minted.
        description=(record.get("description") or f"Custom tool {record['name']!r} ({path}).")[:4000],
        parameters_schema=None,  # -> _GENERIC_DISCOVERED_SCHEMA fallback (target + extra_args)
        # A tier-1 tool is normally ALWAYS "installed" (runner.py's tool_is_installed) -- wrong
        # here: the operator can move/delete the real binary after registering it. Real existence
        # check, same purpose ToolSpec.availability_check's own docstring describes for exactly
        # this "tier-1 wrapper with a real external dependency" shape.
        availability_check=partial(os.path.isfile, path),
    )


def build_dynamic_toolspecs() -> list[ToolSpec]:
    """Every ENABLED custom-tool record, minted fresh on each call -- never cached, so flipping a
    toggle in Settings takes effect on the very next tool-set assembly (the next phase transition,
    or the next subagent delegation), not only after a server restart. Returns [] with negligible
    cost when no custom tools are registered at all, the common case -- this is called from every
    phase's own tool-set assembly (agent/core.py), same unconditional-append pattern already used
    for the toolkit's own extras, so it must stay cheap when there is nothing to add.
    """
    return [_mint_toolspec(record) for record in load_custom_tools() if record.get("enabled")]
