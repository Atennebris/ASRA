"""Shared run_tool(): health-check, allowlist guardrail, subprocess/native dispatch."""
from __future__ import annotations

import os
import shutil
import subprocess
import time

from agent.tools.allowed_targets import is_target_allowed
from agent.tools.registry import ToolSpec
from agent.utils.debug import truncate_for_log
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_DEFAULT_TOOL_TIMEOUT_SECONDS = 120
_DEFAULT_EXPLOIT_TIMEOUT_SECONDS = 180


def _timeout_for(spec: ToolSpec) -> int:
    env_var = "EXPLOIT_TIMEOUT_SECONDS" if spec.category in ("exploit", "post_exploit") else "TOOL_TIMEOUT_SECONDS"
    default = _DEFAULT_EXPLOIT_TIMEOUT_SECONDS if spec.category in ("exploit", "post_exploit") else _DEFAULT_TOOL_TIMEOUT_SECONDS
    return int(os.getenv(env_var, str(default)))


def _resolve_executable(spec: ToolSpec) -> str | None:
    # Optional per-tool override for a non-PATH install, e.g. NMAP_PATH=/opt/nmap/bin/nmap.
    override = os.getenv(f"{spec.name.upper()}_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    return shutil.which(spec.executable)


def _check_guardrail(spec: ToolSpec, params: dict) -> dict | None:
    """Returns a skip result if the guardrail blocks this call, None if it's clear to proceed."""
    if not spec.requires_allowed_target:
        return None

    target = params.get("target")
    if not target or not is_target_allowed(target):
        logger.debug("run_tool: %s skipped, target=%r not in allowed_targets", spec.name, target)
        return {"status": "skipped", "tool": spec.name, "reason": "target not in allowed_targets"}
    return None


def _run_native(spec: ToolSpec, params: dict) -> dict:
    # Tier-1 tools own their own timeout/error handling internally; this is a last-resort net so a
    # bug in one native tool can never take down the agent's main loop.
    try:
        result = spec.native_function(params)
    except Exception as exc:
        logger.debug("run_tool: %s native call raised %s", spec.name, exc)
        return {"status": "error", "tool": spec.name, "error": str(exc)}

    result.setdefault("tool", spec.name)
    logger.debug("run_tool: %s (native) finished status=%s", spec.name, result.get("status"))
    return result


def _run_subprocess(spec: ToolSpec, params: dict) -> dict:
    resolved_executable = _resolve_executable(spec)
    if resolved_executable is None:
        logger.debug("run_tool: %s unavailable (executable not found)", spec.name)
        return {"status": "tool_unavailable", "tool": spec.name}

    if spec.classify_risk is not None:
        risk = spec.classify_risk(params)
        if risk != "default":
            logger.debug("run_tool: %s classified risk=%s params=%s", spec.name, risk, params)

    command = spec.build_command(params)
    timeout_seconds = _timeout_for(spec)
    step_id = f"{spec.name}_{int(time.time() * 1000)}"

    try:
        result = subprocess.run(command, timeout=timeout_seconds, capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        logger.debug("run_tool: %s timed out after %ss", spec.name, timeout_seconds)
        return {"status": "timeout", "tool": spec.name, "command": command}

    logger.debug(
        "run_tool: %s finished exit_code=%s stdout_preview=%s",
        spec.name,
        result.returncode,
        truncate_for_log(result.stdout, step_id=step_id),
    )

    return {
        "status": "ok" if result.returncode == 0 else "error",
        "tool": spec.name,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": command,
    }


def run_tool(spec: ToolSpec, params: dict) -> dict:
    logger.debug("run_tool start: tool=%s category=%s tier=%s params=%s", spec.name, spec.category, spec.tool_tier, params)

    skip_result = _check_guardrail(spec, params)
    if skip_result is not None:
        return skip_result

    if spec.tool_tier == 1:
        return _run_native(spec, params)
    return _run_subprocess(spec, params)
