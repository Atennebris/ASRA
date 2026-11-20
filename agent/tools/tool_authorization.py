"""Default-deny authorization for tool execution: a ToolSpec may run only if it is a recognized
ASRA tool. Everything else is refused with an explicit reason, the same posture as a firewall's
default-deny rule.

Recognized means exactly one of:
- the very ToolSpec object registered in TOOL_REGISTRY under that name (built-in and
  autodiscovered tools). Identity, not just a matching name: a spec that merely reuses a
  registered name carries its own code and must not inherit the registered tool's trust;
- an operator-registered custom tool (Settings -> Tools -> Custom tools) that is still enabled,
  with the same id/name/path the spec was minted from -- disabling it takes effect immediately,
  even for a tool set already handed to the model earlier in the same run.

Tools in the external-provider namespace (EXTERNAL_TOOL_NAME_PREFIX -- what an external MCP
server's tools are registered under) never auto-run, even when present in TOOL_REGISTRY: being
registered only proves the tool was discovered, not that the operator vetted it, and its author is
outside ASRA's control. Such a tool runs only once the operator lists it in
ASRA_ALLOWED_EXTERNAL_TOOLS.

This layer answers only "is this tool allowed to run at all". It sits in front of, and never
replaces, the per-call gates (scope/allowlist, approval tiers, egress kill-switch).
"""
from __future__ import annotations

import os
from functools import partial

from agent.tools.custom_tool_runtime import run_registered_custom_tool
from agent.tools.custom_tools_store import load_custom_tools
from agent.tools.registry import ToolSpec, get_tool
from agent.utils.debug import current_subagent_label
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

EXTERNAL_TOOL_NAME_PREFIX = "mcp_"

# Shared across every site in the codebase that refuses a tool call because of ASRA's OWN policy
# decision -- this gate, the per-call exploitation allowlist (agent/tools/runner.py's
# _check_guardrail, agent/tools/toolkit_agent_tools.py's mirrored live-mode check), the scope/
# out-of-scope guard, and the exploit-approval tier (agent/core.py's _await_exploit_approval) --
# never because of anything the target itself did. Without this explicit framing a model can
# mistake its own tool's refusal for target-side defense (a WAF block, a 403, rate-limiting) and
# waste turns on a pointless "workaround" (re-encoding a payload, changing a header, trying another
# method), which cannot possibly succeed against a policy decision and is conceptually the wrong
# thing to attempt in the first place. Every site composes its own reason text around this same
# notice rather than writing a second, differently-worded version.
PLATFORM_POLICY_REFUSAL_NOTICE = (
    "This is an ASRA platform policy decision, not a target-side defense (not a WAF block, a 403, "
    "or rate-limiting) -- do not attempt to bypass it."
)

_REFUSAL_SUFFIX = (
    f" {PLATFORM_POLICY_REFUSAL_NOTICE} No retry or change of arguments will make this tool run -- "
    "use one of ASRA's recognized tools instead."
)


def _operator_allowed_external_tools() -> set[str]:
    """Read per call, not cached at import, so an edit to the allowlist applies to the next call."""
    raw = os.getenv("ASRA_ALLOWED_EXTERNAL_TOOLS", "")
    return {name.strip() for name in raw.split(",") if name.strip()}


def _is_enabled_custom_tool(spec: ToolSpec) -> bool:
    executor = spec.native_function
    if not (isinstance(executor, partial) and executor.func is run_registered_custom_tool):
        return False
    bound = executor.keywords.get("record") or {}
    if bound.get("name") != spec.name:
        return False
    return any(
        record.get("enabled")
        and record.get("id") == bound.get("id")
        and record.get("name") == bound.get("name")
        and record.get("path") == bound.get("path")
        for record in load_custom_tools()
    )


def unrecognized_tool_reason(spec: ToolSpec) -> str | None:
    """None when `spec` is authorized to run, otherwise a model-facing reason it is refused."""
    name = spec.name
    if name.startswith(EXTERNAL_TOOL_NAME_PREFIX):
        if name not in _operator_allowed_external_tools():
            return (
                f"tool {name!r} comes from an external tool provider and has not been classified/allowed "
                "by the operator, so ASRA refuses to run it by default."
            )
        logger.debug("tool authorization: external tool %r explicitly allowed via ASRA_ALLOWED_EXTERNAL_TOOLS", name)
    registered = get_tool(name)
    if registered is spec or _is_enabled_custom_tool(spec):
        return None
    if registered is not None:
        return (
            f"this {name!r} is not ASRA's own registered tool of that name (an unrecognized tool "
            "reusing a registered name), so ASRA refuses to run it."
        )
    return f"tool {name!r} is not a recognized ASRA tool (not registered, not an enabled custom tool), so ASRA refuses to run it."


def authorization_block_result(spec: ToolSpec) -> dict | None:
    """The model-facing refusal for an unrecognized tool, or None when it may proceed."""
    reason = unrecognized_tool_reason(spec)
    if reason is None:
        return None
    # Tagged with the delegating subagent (if any), same as runner.py's own TOOLS lines, so a
    # subagent's refusal is distinguishable from the main loop's in a shared debug.log.
    caller = current_subagent_label.get() or "main"
    logger.debug("tool authorization: [%s] refused tool=%r tier=%s -- %s", caller, spec.name, spec.tool_tier, reason)
    return {"status": "blocked", "tool": spec.name, "reason": reason + _REFUSAL_SUFFIX}
