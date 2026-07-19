"""ReAct-cycle orchestrator: Recon -> Analyze -> Exploit -> Validate & Confirm.

Each sub-phase is one LLM<->tools conversation (_run_llm_tool_loop): the model gets a system
prompt (agent/prompts.py) plus whatever tools its registry category exposes, calls tools until
it has enough to answer, then replies with the sub-phase's JSON contract. Tool selection is by
category, never by a hardcoded name — a new registry entry (built-in, autodiscovered, or from
custom_tools.yaml) is picked up automatically the next time its category is used.

Every LLM call in a session (sub-phase conversations, exploit-approval-gated calls, 1-step
retry corrections) goes through RunContext/_llm_complete, the single place that counts against
MAX_ITERATIONS and raises MaxIterationsReached once the session's LLM-call budget is spent.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from typing import Awaitable, Callable

from agent.llm_client import LLMProvider, LLMResponse, ToolCallRequest, get_provider
from agent.prompts import ANALYZE_PROMPT, EXPLOIT_PROMPT, RECON_PROMPT, VALIDATE_PROMPT
from agent.tools.builders.discovered import get_tool_help
from agent.tools.builders.exploit import parse_exploit_output, parse_msf_module_search
from agent.tools.builders.nmap import parse_nmap_output
from agent.tools.builders.nuclei import parse_nuclei_output
from agent.tools.builders.sqlmap import parse_sqlmap_output

# Importing agent.tools.registry forces Python to first fully run agent/tools/__init__.py (the
# composition root that populates TOOL_REGISTRY) — spelled out explicitly rather than relied on
# implicitly, since it's easy to miss that package-init side effect on a later refactor.
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.registry import ToolSpec, get_tools_by_category
from agent.tools.runner import run_tool
from agent.utils.logger import get_logger
from sessions.store import create_session, load_session, save_session

logger = get_logger("AGENT")

_MAX_TOOL_ITERATIONS = 8
_TOOL_RESULT_CHAR_LIMIT = 8000
_DEFAULT_MAX_ITERATIONS = 20

_GENERIC_DISCOVERED_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Target host/URL for this tool"},
        "extra_args": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Extra CLI flags/arguments for this tool, based on its --help text below",
        },
    },
    "required": ["target"],
}

# Structured parsers for the hand-written subprocess tools (agent/tools/builders/*) — reused as-is
# from Phase 2 rather than asking the LLM to re-derive them from raw, ANSI-laden CLI output.
# Autodiscovered/custom tools deliberately have no entry here: their raw stdout goes to the model
# unparsed, by design (agent/tools/builders/discovered.py).
_OUTPUT_PARSERS: dict[str, Callable[[str], object]] = {
    "nmap": parse_nmap_output,
    "nuclei": parse_nuclei_output,
    "exploit": parse_exploit_output,
    "msf_module_search": parse_msf_module_search,
    "sqlmap": parse_sqlmap_output,
}

# A tool call ending in one of these can plausibly be fixed by different arguments (bad flag,
# malformed target, wrong module name) — worth the one corrective retry. "skipped" (guardrail
# decision) and "tool_unavailable" (missing binary) are not fixable by different arguments, so
# they're deliberately excluded.
_RETRYABLE_STATUSES = {"error", "timeout"}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# The session schema (sessions/store.py) promises every finding has all of these keys.
# Analyze's own output only carries a subset (title/severity/description/verification/
# evidence_ref) — normally Validate fills in the rest, but a session can end (MAX_ITERATIONS
# cutoff, a parse failure) before Validate ever runs. Without this, downstream consumers
# (Phase 4's export/UI) would hit missing keys instead of a real, if incomplete, finding.
_FINDING_DEFAULTS = {
    "title": "Untitled finding",
    "severity": "Low",
    "description": "",
    "poc_command": None,
    "exploited": False,
    "evidence": None,
    "verification": "needs_verification",
    "advisory_note": None,
}


def _normalize_findings(findings: list[dict]) -> list[dict]:
    return [{**_FINDING_DEFAULTS, **finding} for finding in findings]

_JSON_FENCE_PATTERN = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)

# Module-level per-session approval signal: set by the web layer's approve-exploit endpoint
# (Phase 4), waited on here. Lives here rather than in main.py since core.py owns the
# wait/timeout mechanics; the web layer only ever needs to call .set() on it.
_approval_events: dict[str, asyncio.Event] = {}


def get_approval_event(session_id: str) -> asyncio.Event:
    return _approval_events.setdefault(session_id, asyncio.Event())


@dataclass
class RunContext:
    """Shared, mutable state for one run_session() call — threaded through every sub-phase
    instead of passing (llm, session, session_id) separately everywhere, since MAX_ITERATIONS
    (below) needs exactly one counter shared across all of them.
    """

    llm: LLMProvider
    session: dict
    session_id: str
    max_iterations: int = _DEFAULT_MAX_ITERATIONS
    iteration_count: int = field(default=0)


class MaxIterationsReached(Exception):
    """Raised when a session's LLM-call budget (MAX_ITERATIONS) runs out mid-flight."""


async def _llm_complete(ctx: RunContext, messages: list[dict], tools: list[dict] | None) -> LLMResponse:
    """The single choke point every LLM call in a session goes through — sub-phase conversations,
    1-step retry corrections, all of it — so MAX_ITERATIONS counts the true total, not just the
    top-level per-phase calls.
    """
    if ctx.iteration_count >= ctx.max_iterations:
        raise MaxIterationsReached()
    ctx.iteration_count += 1
    logger.debug("core: session=%s llm call %d/%d", ctx.session_id, ctx.iteration_count, ctx.max_iterations)
    return await asyncio.to_thread(ctx.llm.complete, messages, tools)


def _apply_output_parser(spec: ToolSpec, result: dict) -> dict:
    parser = _OUTPUT_PARSERS.get(spec.name)
    if parser is None or result.get("status") != "ok":
        return result
    return {**result, "parsed": parser(result["stdout"])}


def _tool_description(spec: ToolSpec) -> str:
    if spec.description:
        return spec.description
    # Autodiscovered/custom tools carry no hand-written description — pull their real --help
    # text (cached after the first fetch) so the model knows how to call them at all.
    help_text = get_tool_help(spec.name, spec.executable, spec.full_description)
    return help_text[:4000] if help_text else f"Tool {spec.name!r} (no description available)."


def _tool_to_openai_schema(spec: ToolSpec) -> dict:
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": _tool_description(spec),
            "parameters": spec.parameters_schema or _GENERIC_DISCOVERED_SCHEMA,
        },
    }


def _parse_json_response(content: str | None) -> dict | None:
    if not content:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    match = _JSON_FENCE_PATTERN.search(content)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    logger.debug("core: failed to parse JSON from LLM response: %s", content[:500])
    return None


def _describe_command(call: ToolCallRequest, result: dict) -> str:
    command = result.get("command")
    if isinstance(command, list):
        return " ".join(command)
    return f"{call.name}({json.dumps(call.arguments)})"


def _log_status(result: dict) -> str:
    status = result.get("status", "error")
    return "success" if status == "ok" else status


def _log_error(result: dict) -> str | None:
    if result.get("status") == "ok":
        return None
    return result.get("error") or result.get("stderr") or result.get("reason")


def _append_log(ctx: RunContext, phase: str, thought: str | None, command: str | None, status: str, error: str | None) -> None:
    ctx.session["logs"].append(
        {
            "step": len(ctx.session["logs"]) + 1,
            "phase": phase,
            "thought": (thought[:500] if thought else None) or None,
            "command": command,
            "status": status,
            "error": error,
        }
    )
    save_session(ctx.session_id, ctx.session)


async def _run_tool_with_retry(ctx: RunContext, spec: ToolSpec, arguments: dict) -> dict:
    """1-Step Retry: runs a tool once; on a genuine failure, asks the model for exactly one
    corrected set of arguments and retries once more. A second failure is marked "failed" and
    left alone — no open-ended retry loop. Applies uniformly to every tool, exploit calls
    included; it fixes a broken invocation, it does not grant a second exploitation attempt
    (that's state["attempted"] in _run_exploit_for_finding, a separate rule).
    """
    result = _apply_output_parser(spec, await asyncio.to_thread(run_tool, spec, arguments))
    if result.get("status") not in _RETRYABLE_STATUSES:
        return result

    logger.debug("core: session=%s tool=%s failed (%s), requesting one corrected retry", ctx.session_id, spec.name, result.get("status"))
    correction_messages = [
        {
            "role": "system",
            "content": 'You correct one failed security-tool invocation. Reply with ONLY this JSON: {"arguments": {<corrected arguments for the same tool>}}',
        },
        {
            "role": "user",
            "content": (
                f"Tool {spec.name!r} failed with these arguments: {json.dumps(arguments)}\n"
                f"Error: {_log_error(result)}\n"
                "Provide corrected arguments for the same tool."
            ),
        },
    ]
    response = await _llm_complete(ctx, correction_messages, None)
    corrected = _parse_json_response(response.content)
    if not corrected or not isinstance(corrected.get("arguments"), dict):
        logger.debug("core: session=%s tool=%s retry correction unparsable, giving up", ctx.session_id, spec.name)
        return {**result, "status": "failed"}

    retry_result = _apply_output_parser(spec, await asyncio.to_thread(run_tool, spec, corrected["arguments"]))
    if retry_result.get("status") in _RETRYABLE_STATUSES:
        logger.debug("core: session=%s tool=%s retry failed again, marking step failed", ctx.session_id, spec.name)
        retry_result["status"] = "failed"
    else:
        logger.debug("core: session=%s tool=%s retry succeeded", ctx.session_id, spec.name)
    retry_result["retried"] = True
    return retry_result


async def _run_llm_tool_loop(
    ctx: RunContext,
    system_prompt: str,
    task_content: str,
    tool_specs: list[ToolSpec],
    phase: str,
    execute_tool: Callable[[ToolSpec, dict], Awaitable[dict]] | None = None,
) -> tuple[dict | None, list[dict]]:
    """Drives one LLM<->tools conversation for a sub-phase until the model stops calling tools
    and replies with its final JSON. Returns (parsed_json_or_None, raw_tool_call_trace).
    """
    tools_schema = [_tool_to_openai_schema(spec) for spec in tool_specs]
    specs_by_name = {spec.name: spec for spec in tool_specs}
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task_content},
    ]
    trace: list[dict] = []

    for _iteration in range(_MAX_TOOL_ITERATIONS):
        response = await _llm_complete(ctx, messages, tools_schema)

        if not response.tool_calls:
            parsed = _parse_json_response(response.content)
            _append_log(
                ctx, phase, response.content, None,
                "success" if parsed is not None else "error",
                None if parsed is not None else "could not parse a final JSON response from the model",
            )
            return parsed, trace

        messages.append(
            {
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [
                    {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                    for c in response.tool_calls
                ],
            }
        )

        for call in response.tool_calls:
            spec = specs_by_name.get(call.name)
            if spec is None:
                result = {"status": "error", "error": f"unknown tool {call.name!r}"}
            elif execute_tool is not None:
                result = await execute_tool(spec, call.arguments)
            else:
                result = await _run_tool_with_retry(ctx, spec, call.arguments)

            trace.append({"tool": call.name, "arguments": call.arguments, "result": result})
            _append_log(ctx, phase, response.content, _describe_command(call, result), _log_status(result), _log_error(result))
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT]})

    logger.debug("core: session=%s %s phase hit max tool iterations (%d), forcing a final answer", ctx.session_id, phase, _MAX_TOOL_ITERATIONS)
    messages.append({"role": "user", "content": "Stop calling tools now and reply with the final JSON only."})
    response = await _llm_complete(ctx, messages, None)
    return _parse_json_response(response.content), trace


async def _run_recon(ctx: RunContext, target: str) -> dict:
    tools = get_tools_by_category("recon")
    logger.debug("core: session=%s starting recon phase (%d tools available)", ctx.session_id, len(tools))
    task = f"Target: {target}\nGather recon data using the tools available to you."
    result, _trace = await _run_llm_tool_loop(ctx, RECON_PROMPT, task, tools, "recon")
    if result is None:
        logger.debug("core: session=%s recon phase produced no parseable result, falling back to empty targets", ctx.session_id)
        return {"targets": [], "summary": "recon failed to produce a parseable result"}
    logger.debug("core: session=%s recon phase found %d target(s)", ctx.session_id, len(result.get("targets", [])))
    return result


async def _run_analyze(ctx: RunContext, target: str, recon_result: dict) -> dict:
    tools = get_tools_by_category("scan")
    logger.debug("core: session=%s starting analyze phase (%d tools available)", ctx.session_id, len(tools))
    task = (
        f"Target: {target}\n"
        f"Recon results:\n{json.dumps(recon_result)}\n\n"
        "Analyze these for vulnerabilities using the tools available to you."
    )
    result, _trace = await _run_llm_tool_loop(ctx, ANALYZE_PROMPT, task, tools, "analyze")
    if result is None:
        logger.debug("core: session=%s analyze phase produced no parseable result, falling back to empty findings", ctx.session_id)
        return {"findings": [], "summary": "analyze failed to produce a parseable result"}
    logger.debug("core: session=%s analyze phase found %d finding(s)", ctx.session_id, len(result.get("findings", [])))
    return result


def _severity_key(finding: dict) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity", "")).lower(), len(_SEVERITY_RANK))


async def _await_exploit_approval(ctx: RunContext) -> bool:
    """Waits for a human to approve exploitation this session (see get_approval_event — the
    Phase 4 approve-exploit endpoint sets that event). No endpoint exists yet in this phase, so
    this always times out today, correctly, and the finding is skipped rather than the session
    hanging — that is the expected behavior until the web layer exists. Approval is per session,
    not per finding: once granted (session["exploit_approved"]), later findings in the same
    session skip the wait entirely; a timeout never sets that flag, so the next finding asks again.
    """
    if ctx.session.get("exploit_approved"):
        return True

    ctx.session["status"] = "awaiting_approval"
    save_session(ctx.session_id, ctx.session)
    logger.debug("core: session=%s awaiting exploit approval", ctx.session_id)

    timeout_seconds = int(os.getenv("EXPLOIT_APPROVAL_TIMEOUT_SECONDS", "300"))
    try:
        await asyncio.wait_for(get_approval_event(ctx.session_id).wait(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.debug("core: session=%s exploit approval timed out after %ds", ctx.session_id, timeout_seconds)
        ctx.session["status"] = "processing"
        save_session(ctx.session_id, ctx.session)
        return False

    ctx.session["exploit_approved"] = True
    ctx.session["status"] = "processing"
    save_session(ctx.session_id, ctx.session)
    logger.debug("core: session=%s exploit approved", ctx.session_id)
    return True


async def _run_exploit_for_finding(ctx: RunContext, target: str, finding: dict, exploit_tools: list[ToolSpec]) -> tuple[dict | None, list[dict]]:
    # "attempted" enforces exactly one real exploitation attempt per finding (independent of how
    # many tool calls the model makes in this conversation, and independent of 1-Step Retry —
    # a retried invocation of the *same* attempt doesn't count as a second one); "verified" gates
    # that attempt behind at least one prior tool call when the finding wasn't already
    # verification="verified" coming in from Analyze — an approximation of "run a real
    # verification step first", not a semantic check of what that call actually confirmed, but
    # it's enough to stop a same-turn blind shot.
    state = {"attempted": False, "verified": finding.get("verification") == "verified"}

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        if not spec.requires_allowed_target:
            result = await _run_tool_with_retry(ctx, spec, arguments)
            state["verified"] = True
            return result

        if not state["verified"]:
            return {"status": "skipped", "reason": "finding is not verification=verified yet — call a verification tool first"}
        if state["attempted"]:
            return {"status": "skipped", "reason": "one exploitation attempt already used for this finding"}

        approved = await _await_exploit_approval(ctx)
        state["attempted"] = True
        if not approved:
            return {"status": "skipped", "reason": "exploit not approved in time"}
        return await _run_tool_with_retry(ctx, spec, arguments)

    task = (
        f"Target: {target}\n"
        f"Finding to evaluate:\n{json.dumps(finding)}\n\n"
        "If the finding is verified and a fitting tool is available, call that tool now through "
        "function-calling and report its real result — do not just describe what you would do. "
        "The allowlist/approval gates are enforced automatically on the call itself; if it comes "
        "back skipped, that is a real, valid outcome to report, but you only find out by actually "
        "calling it. Only answer skipped_needs_verification/skipped_no_suitable_tool without "
        "calling a tool if that's genuinely the situation (not verified yet, or nothing fits)."
    )
    return await _run_llm_tool_loop(ctx, EXPLOIT_PROMPT, task, exploit_tools, "exploit", execute_tool=execute)


async def _run_exploit(ctx: RunContext, target: str, findings: list[dict]) -> list[dict]:
    if os.getenv("ENABLE_EXPLOIT", "true").lower() != "true":
        logger.debug("core: session=%s ENABLE_EXPLOIT=false, skipping exploit phase entirely (%d findings)", ctx.session_id, len(findings))
        return []

    exploit_tools = get_tools_by_category("exploit")
    logger.debug(
        "core: session=%s starting exploit phase, %d finding(s) by descending severity (%d exploit tools available)",
        ctx.session_id, len(findings), len(exploit_tools),
    )
    records = []
    for finding in sorted(findings, key=_severity_key):
        logger.debug(
            "core: session=%s exploit: evaluating finding=%r severity=%s verification=%s",
            ctx.session_id, finding.get("title"), finding.get("severity"), finding.get("verification"),
        )
        action, trace = await _run_exploit_for_finding(ctx, target, finding, exploit_tools)
        logger.debug("core: session=%s exploit: finding=%r resolved action=%s", ctx.session_id, finding.get("title"), (action or {}).get("action"))
        records.append({"finding": finding, "action": action, "tool_calls": trace})
    return records


async def _run_validate(ctx: RunContext, findings: list[dict], exploit_records: list[dict]) -> dict:
    logger.debug("core: session=%s starting validate phase (%d findings, %d exploit records)", ctx.session_id, len(findings), len(exploit_records))
    task = (
        f"Analyze findings:\n{json.dumps(findings)}\n\n"
        f"Exploit phase results:\n{json.dumps(exploit_records)}\n\n"
        "Produce the final findings list."
    )
    # No tools here — Validate reasons over data already collected, it doesn't gather new data.
    result, _trace = await _run_llm_tool_loop(ctx, VALIDATE_PROMPT, task, [], "validate")
    return result or {"findings": findings}


async def run_session(session_id: str, provider_id: str | None = None) -> None:
    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")

    target = session["target"]
    session["status"] = "processing"
    save_session(session_id, session)
    logger.debug("core: session=%s target=%s starting", session_id, target)

    max_iterations = int(os.getenv("MAX_ITERATIONS", str(_DEFAULT_MAX_ITERATIONS)))
    ctx = RunContext(llm=get_provider(provider_id), session=session, session_id=session_id, max_iterations=max_iterations)

    findings: list[dict] = []
    try:
        recon_result = await _run_recon(ctx, target)
        analyze_result = await _run_analyze(ctx, target, recon_result)
        findings = analyze_result.get("findings", [])
        exploit_records = await _run_exploit(ctx, target, findings)
        validate_result = await _run_validate(ctx, findings, exploit_records)

        session["findings"] = _normalize_findings(validate_result.get("findings", findings))
        session["status"] = "completed"
        save_session(session_id, session)
        logger.debug("core: session=%s completed with %d findings", session_id, len(session["findings"]))
    except MaxIterationsReached:
        # Not an error: a hard, configured budget ran out. Report whatever was already
        # established rather than losing it — completed if Analyze got that far, failed if the
        # budget ran out before any finding existed at all. Still schema-normalized: these are
        # raw Analyze findings, never Validate-finalized, so the poc_command/exploited/evidence/
        # advisory_note fields wouldn't exist otherwise.
        logger.debug("core: session=%s stopped: MAX_ITERATIONS=%d reached", session_id, max_iterations)
        _append_log(ctx, "session", None, None, "failed", f"stopped: MAX_ITERATIONS ({max_iterations}) reached before completion")
        session["findings"] = _normalize_findings(findings)
        session["status"] = "completed" if findings else "failed"
        save_session(session_id, session)
    except Exception:
        logger.debug("core: session=%s failed", session_id, exc_info=True)
        session["status"] = "failed"
        save_session(session_id, session)
        raise


def _cli() -> None:
    parser = argparse.ArgumentParser(description="Run one ASRA scan session from the command line.")
    parser.add_argument("--target", required=True, help="Target host/URL to scan.")
    parser.add_argument("--provider", default=None, help="Override LLM_PROVIDER for this run.")
    args = parser.parse_args()

    session_id = create_session(args.target)
    print(f"Session {session_id} started for target {args.target}")

    asyncio.run(run_session(session_id, provider_id=args.provider))

    session = load_session(session_id)
    print(f"Status: {session['status']}")
    print(json.dumps(session["findings"], indent=2))


if __name__ == "__main__":
    _cli()
