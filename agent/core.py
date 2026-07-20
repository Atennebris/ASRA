"""ReAct-cycle orchestrator: Recon -> Analyze -> Exploit -> Validate.

Each sub-phase is one LLM<->tools conversation (_run_llm_tool_loop): the model gets a system
prompt (agent/prompts.py) plus whatever tools its registry category exposes, and calls tools
until it's done. Tool selection is by category, never by a hardcoded name — a new registry entry
(built-in, autodiscovered, or from custom_tools.yaml) is picked up automatically the next time
its category is used.

Recon/Analyze report structured data live: record_target/record_finding tool calls persist into
session["recon_result"]/session["findings"] the instant the model reports them (see the execute
closures in _run_recon/_run_analyze), not batched into a final JSON answer at phase end — a
process crash mid-phase loses nothing already found. Exploit mutates each finding's schema
fields (exploited/evidence/poc_command/advisory_note) in place, persisted right after that one
finding is resolved — no parallel "exploit_records" structure to reconcile later. Validate runs
once at the end purely to deduplicate; it is no longer the sole creator of finding data, so a
session that never reaches Validate (crash, budget cutoff) still ends with real, schema-complete
findings, just not deduplicated.

entry_point (run_session's parameter) picks where a run starts — "recon" (default, full
pipeline), "analyze" (skips Recon, needs session["recon_result"] already present), or "exploit"
(skips Recon+Analyze, needs session["findings"] already present). It's chosen once at the start
of a run, not a live state machine — after entering at that point, the remaining sub-phases still
run in their normal order.

Every LLM call in a session (sub-phase conversations, exploit-approval-gated calls, 1-step
retry corrections, exploit-result confirmation) goes through RunContext/_llm_complete, the single
choke point that counts and logs them — no cap on the total, and no cap on tool-calling rounds
within a phase either. A fixed count cap (either one) has the same flaw regardless of where it
sits: it cuts off legitimate work the moment a scope is big enough to need more calls than
whatever number seemed reasonable in isolation — a scan covering many subdomains/targets can
legitimately need far more tool calls than one covering a single host, and a count cap can't tell
the difference between "still making progress" and "actually stuck". _run_llm_tool_loop instead
detects an actual stall directly: the same tool call (name + arguments) repeated identically
_STALL_REPEAT_THRESHOLD times in a row ends that phase — real, distinct work never trips it no
matter how much of it there is. A generous, non-configurable wall-clock backstop per phase
(_PHASE_WALLCLOCK_LIMIT_SECONDS) exists purely as a last-resort safety valve for a genuine bug
that produces endless non-repeating garbage; it is not meant to be reachable by legitimate use.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

from agent.llm_client import LLMProvider, LLMResponse, ToolCallRequest, get_provider
from agent.prompts import (
    ANALYZE_PROMPT,
    CONFIRM_EXPLOIT_PROMPT,
    EXPLOIT_PROMPT,
    RECON_PROMPT,
    VALIDATE_PROMPT,
)
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

_TOOL_RESULT_CHAR_LIMIT = 8000
# Loop/stall protection for _run_llm_tool_loop — see the module docstring for why this replaced
# a fixed per-phase call-count cap.
_STALL_REPEAT_THRESHOLD = 6
_PHASE_WALLCLOCK_LIMIT_SECONDS = 7200

# Tool-result fields that mean "a deterministic check in agent/tools/native.py already confirmed a
# real vulnerability" (see http_request's detectors) — any one of these firing gets a loud hint
# injected into the tool result, not just left for the model to maybe notice on its own.
_DETERMINISTIC_DETECTION_FIELDS = (
    "reflected_payload_detected",
    "sql_error_detected",
    "open_redirect_detected",
    "command_injection_detected",
)

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
# rather than asking the LLM to re-derive them from raw, ANSI-laden CLI output.
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
# evidence_ref) — normally Validate fills in the rest, but a session can end early (an unhandled
# error, a parse failure) before Validate ever runs. Without this, downstream consumers
# (the export/UI) would hit missing keys instead of a real, if incomplete, finding.
_FINDING_DEFAULTS = {
    "title": "Untitled finding",
    "severity": "Low",
    "description": "",
    "technology": None,
    "reproduction_steps": None,
    "poc_command": None,
    "exploited": False,
    "evidence": None,
    "verification": "needs_verification",
    "advisory_note": None,
    "found_at": None,
}


def _normalize_findings(findings: list[dict]) -> list[dict]:
    return [{**_FINDING_DEFAULTS, **finding} for finding in findings]

_JSON_FENCE_PATTERN = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)

# Module-level per-session approval signal: set by the web layer's approve-exploit endpoint,
# waited on here. Lives here rather than in main.py since core.py owns the
# wait/timeout mechanics; the web layer only ever needs to call .set() on it.
_approval_events: dict[str, asyncio.Event] = {}


def get_approval_event(session_id: str) -> asyncio.Event:
    return _approval_events.setdefault(session_id, asyncio.Event())


# Same pattern and same honest tradeoff as _approval_events above, for a different purpose: chat
# (agent/chat.py) queues short operator directives here instead of writing them into
# the session file — run_session() already owns that file's read-modify-write cycle, a second
# writer would race it. In-memory only, so a directive queued right as the process dies is lost —
# acceptable, since it is a live nudge, not data (findings/recon stay durable regardless).
_instruction_queues: dict[str, asyncio.Queue] = {}


def get_instruction_queue(session_id: str) -> asyncio.Queue:
    return _instruction_queues.setdefault(session_id, asyncio.Queue())


def _drain_pending_guidance(session_id: str) -> list[str]:
    """Non-blocking drain of any add_guidance directives the chat layer queued for this
    session — checked at the top of every tool-loop iteration, the natural point between LLM
    turns to inject one. skip_finding directives are left in the queue (put back below) — those
    are matched separately, per finding title, at the per-finding boundary in _run_exploit
    (a title not yet reached in the exploit loop must survive to be seen on a later finding).
    """
    queue = get_instruction_queue(session_id)
    guidance: list[str] = []
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if instruction.get("type") == "add_guidance":
            guidance.append(instruction["text"])
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return guidance


def _pop_skip_instruction(session_id: str, finding_title: str) -> bool:
    """Non-blocking check: was exactly this finding queued to be skipped? Consumes only a
    matching instruction — everything else (skip_finding for a different, not-yet-reached
    finding; any add_guidance) goes back into the queue untouched for a later drain to see.
    """
    queue = get_instruction_queue(session_id)
    matched = False
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if not matched and instruction.get("type") == "skip_finding" and instruction.get("finding_title") == finding_title:
            matched = True
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return matched


def _pop_deep_dive_instruction(session_id: str) -> str | None:
    """Non-blocking: was a "focus on this finding now" directive queued (the finding-detail
    modal's Deep dive button, main.py's /deep-dive route, for a session that's already live)?
    Unlike skip_finding this isn't matched against a specific title by the caller — _run_exploit
    checks it once per loop iteration and reorders its own remaining work, so whichever finding
    was most recently requested (if any) always wins the reorder. Consumed either way once
    popped, same as add_guidance — a stale request for a finding already processed just no-ops.
    """
    queue = get_instruction_queue(session_id)
    found_title: str | None = None
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if instruction.get("type") == "deep_dive":
            found_title = instruction.get("finding_title")
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return found_title


@dataclass
class RunContext:
    """Shared, mutable state for one run_session() call — threaded through every sub-phase
    instead of passing (llm, session, session_id) separately everywhere. iteration_count is a
    running total for logging only (see _llm_complete) — no budget attached to it.
    current_finding_title is set for the duration of one finding's exploit attempt
    (_run_exploit_for_finding) so _append_log can tag that finding's log entries — lets the UI
    show a per-finding scoped log instead of just the whole session's undifferentiated stream.
    """

    llm: LLMProvider
    session: dict
    session_id: str
    iteration_count: int = field(default=0)
    current_finding_title: str | None = field(default=None)


async def _llm_complete(ctx: RunContext, messages: list[dict], tools: list[dict] | None) -> LLMResponse:
    """The single choke point every LLM call in a session goes through — sub-phase conversations,
    1-step retry corrections, all of it. No cap here: loop/stall protection lives in
    _run_llm_tool_loop's stall detector instead, which stops a phase on genuine repetition
    without capping how much distinct work a whole scan can do overall.
    """
    ctx.iteration_count += 1
    logger.debug("core: session=%s llm call %d", ctx.session_id, ctx.iteration_count)
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
            "finding_title": ctx.current_finding_title,
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
    expect_json_final: bool = True,
) -> tuple[dict | None, list[dict]]:
    """Drives one LLM<->tools conversation for a sub-phase until the model stops calling tools.
    Returns (parsed_json_or_None, raw_tool_call_trace).

    expect_json_final=True (Exploit/Validate): the final non-tool-call reply must be the
    sub-phase's JSON contract — a reply that doesn't parse is logged as an error. Recon/Analyze
    pass False: their real output already landed via record_target/record_finding tool calls
    (see their execute closures), so the final reply is just an optional wrap-up sentence, not
    something to parse or complain about.
    """
    tools_schema = [_tool_to_openai_schema(spec) for spec in tool_specs]
    specs_by_name = {spec.name: spec for spec in tool_specs}
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task_content},
    ]
    trace: list[dict] = []
    recent_call_signatures: list[str] = []
    phase_started_at = time.monotonic()
    stop_reason: str | None = None

    while True:
        elapsed = time.monotonic() - phase_started_at
        if elapsed > _PHASE_WALLCLOCK_LIMIT_SECONDS:
            stop_reason = f"exceeded the {_PHASE_WALLCLOCK_LIMIT_SECONDS}s wall-clock backstop"
            break

        for hint in _drain_pending_guidance(ctx.session_id):
            messages.append({"role": "user", "content": f"[Operator note] {hint}"})
            logger.debug("core: session=%s %s phase: operator guidance applied: %r", ctx.session_id, phase, hint)

        response = await _llm_complete(ctx, messages, tools_schema)

        if not response.tool_calls:
            if not expect_json_final:
                # Real output already landed via record_target/record_finding tool calls — this
                # reply is just a free-text wrap-up, never attempt to parse it as JSON (that would
                # log a misleading "failed to parse" line for completely normal operation).
                _append_log(ctx, phase, response.content, None, "success", None)
                return None, trace
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

            # Stall detection, not a work-count cap: only the exact same call (name + arguments)
            # repeated back-to-back trips this — any different call in between resets progress
            # toward the threshold, so a scan doing real, varied work across many targets never
            # comes close no matter how many tool calls that legitimately takes.
            signature = f"{call.name}:{json.dumps(call.arguments, sort_keys=True)}"
            recent_call_signatures.append(signature)
            del recent_call_signatures[:-_STALL_REPEAT_THRESHOLD]
            if len(recent_call_signatures) == _STALL_REPEAT_THRESHOLD and len(set(recent_call_signatures)) == 1:
                stop_reason = f"{call.name!r} called identically {_STALL_REPEAT_THRESHOLD} times in a row"

        if stop_reason:
            break

    if not expect_json_final:
        logger.debug("core: session=%s %s phase stopped: %s", ctx.session_id, phase, stop_reason)
        return None, trace

    logger.debug("core: session=%s %s phase stopped: %s — forcing a final answer", ctx.session_id, phase, stop_reason)
    messages.append({"role": "user", "content": "Stop calling tools now and reply with the final JSON only."})
    response = await _llm_complete(ctx, messages, None)
    return _parse_json_response(response.content), trace


async def _run_recon(ctx: RunContext, target: str) -> dict:
    tools = get_tools_by_category("recon")
    logger.debug("core: session=%s starting recon phase (%d tools available)", ctx.session_id, len(tools))
    ctx.session.setdefault("recon_result", {"targets": [], "cves": []})
    ctx.session["recon_result"].setdefault("cves", [])

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        result = await _run_tool_with_retry(ctx, spec, arguments)
        if spec.name == "record_target" and result.get("status") == "ok" and "recorded" in result:
            ctx.session["recon_result"]["targets"].append(result["recorded"])
            save_session(ctx.session_id, ctx.session)
            logger.debug("core: session=%s recon: recorded target host=%r", ctx.session_id, result["recorded"].get("host"))
        return result

    # "target" can be a comma-separated scope (multiple URLs/hosts/IPs from the New Project
    # form) — phrased as free text here on purpose, no special-casing needed: the model reads
    # "a, b, c" as a multi-host scope and record_target already supports recording many.
    task = f"Target(s): {target}\nGather recon data using the tools available to you."
    await _run_llm_tool_loop(ctx, RECON_PROMPT, task, tools, "recon", execute_tool=execute, expect_json_final=False)
    recon_result = ctx.session["recon_result"]
    logger.debug("core: session=%s recon phase found %d target(s)", ctx.session_id, len(recon_result["targets"]))
    return recon_result


async def _run_analyze(ctx: RunContext, target: str, recon_result: dict) -> list[dict]:
    tools = get_tools_by_category("scan")
    logger.debug("core: session=%s starting analyze phase (%d tools available)", ctx.session_id, len(tools))
    ctx.session.setdefault("findings", [])
    # cve_lookup is a "scan"-category tool (get_tools_by_category("scan") above) — Analyze is the
    # only phase that actually has it available, matching ANALYZE_PROMPT's own instruction to use
    # it ("a service+version string calls for a CVE lookup"). It used to be hooked in _run_recon's
    # execute() instead, where the model never had this tool in its schema at all and so could
    # never trigger the hook — moved here to where it's actually reachable. setdefault here too,
    # not just in _run_recon: an entry_point="analyze" resume skips recon entirely and builds its
    # own recon_result fallback (run_session) without a "cves" key.
    ctx.session.setdefault("recon_result", {"targets": [], "cves": []})
    ctx.session["recon_result"].setdefault("cves", [])

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        result = await _run_tool_with_retry(ctx, spec, arguments)
        if spec.name == "record_finding" and result.get("status") == "ok" and "recorded" in result:
            # Stamped here, not asked of the model — a timestamp is a fact about when ASRA
            # recorded it, not something the LLM has any business guessing at.
            result["recorded"]["found_at"] = datetime.now(timezone.utc).isoformat()
            ctx.session["findings"].append(result["recorded"])
            save_session(ctx.session_id, ctx.session)
            logger.debug("core: session=%s analyze: recorded finding title=%r", ctx.session_id, result["recorded"].get("title"))
        elif spec.name == "cve_lookup" and result.get("status") == "ok" and result.get("cve_ids"):
            existing = set(ctx.session["recon_result"]["cves"])
            existing.update(result["cve_ids"])
            ctx.session["recon_result"]["cves"] = sorted(existing)
            save_session(ctx.session_id, ctx.session)
            logger.debug("core: session=%s analyze: cve_lookup returned %s, total known now %d", ctx.session_id, result["cve_ids"], len(existing))
        else:
            fired = [field for field in _DETERMINISTIC_DETECTION_FIELDS if field in result]
            if fired:
                # A model can see a signal buried in a result dict and still not act on it in the
                # same turn, especially deep in a long tool-call conversation — a loud, adjacent
                # hint closes that gap without auto-recording anything (the model still decides).
                result["hint"] = (
                    f"{', '.join(fired)} confirms a real vulnerability — call record_finding for it now, "
                    "before calling any other tool."
                )
        return result

    task = (
        f"Target: {target}\n"
        f"Recon results:\n{json.dumps(recon_result)}\n\n"
        "Analyze these for vulnerabilities using the tools available to you."
    )
    await _run_llm_tool_loop(ctx, ANALYZE_PROMPT, task, tools, "analyze", execute_tool=execute, expect_json_final=False)
    findings = ctx.session["findings"]
    logger.debug("core: session=%s analyze phase found %d finding(s)", ctx.session_id, len(findings))
    return findings


def _severity_key(finding: dict) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity", "")).lower(), len(_SEVERITY_RANK))


def _record_approval(ctx: RunContext, finding: dict, outcome: str) -> None:
    ctx.session.setdefault("approvals", []).append(
        {
            "finding_title": finding.get("title"),
            "outcome": outcome,
            "at": datetime.now(timezone.utc).isoformat(),
        }
    )


async def _await_exploit_approval(ctx: RunContext, finding: dict) -> bool:
    """Waits for a human to approve exploitation this session (see get_approval_event — the
    web layer's approve-exploit endpoint sets that event). Approval is per session, not per finding:
    once granted (session["exploit_approved"]), later findings in the same session skip the wait
    entirely; a timeout never sets that flag, so the next finding asks again. Every outcome
    (approved or timed out) is recorded in session["approvals"] — the audit trail Export Proof
    relies on to show exploitation was a deliberate human decision, not an automatic one.
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
        _record_approval(ctx, finding, "timeout")
        save_session(ctx.session_id, ctx.session)
        return False

    ctx.session["exploit_approved"] = True
    ctx.session["status"] = "processing"
    _record_approval(ctx, finding, "approved")
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

        approved = await _await_exploit_approval(ctx, finding)
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
    # Tag every log entry this finding's attempt produces with its title, so the UI can show a
    # scoped log for this one finding — reset in finally so a later finding never inherits it.
    ctx.current_finding_title = finding.get("title")
    try:
        return await _run_llm_tool_loop(ctx, EXPLOIT_PROMPT, task, exploit_tools, "exploit", execute_tool=execute)
    finally:
        ctx.current_finding_title = None


def _apply_skip_outcome(finding: dict, action: dict) -> None:
    """Deterministic, no LLM call needed: exploit was never actually attempted for this
    finding (skipped for lack of a fitting tool, missing verification, allowlist, or approval
    timeout) — there is no real tool output to judge, so there's nothing for an LLM to confirm.
    """
    finding["exploited"] = False
    finding["evidence"] = None
    finding.setdefault("poc_command", None)
    reason = action.get("reasoning")
    if reason:
        finding["advisory_note"] = reason


async def _confirm_exploit_result(ctx: RunContext, finding: dict, action: dict, trace: list[dict]) -> dict:
    """The one case that does need an LLM judgment call: exploit reported "exploit_attempted",
    so a human-readable read of the real tool trace decides whether it actually succeeded and
    what the real evidence was (catches a model that claims success with no real tool call
    behind it).
    """
    messages = [
        {"role": "system", "content": CONFIRM_EXPLOIT_PROMPT},
        {
            "role": "user",
            "content": (
                f"Finding:\n{json.dumps(finding)}\n\n"
                f"Exploit phase action:\n{json.dumps(action)}\n\n"
                f"Real tool call trace from the attempt:\n{json.dumps(trace)}"
            ),
        },
    ]
    response = await _llm_complete(ctx, messages, None)
    parsed = _parse_json_response(response.content)
    if parsed is None:
        logger.debug("core: session=%s confirm-exploit produced no parseable result for finding=%r", ctx.session_id, finding.get("title"))
        return {"exploited": False, "evidence": None, "poc_command": None, "advisory_note": "Could not parse exploit confirmation"}
    return parsed


async def _run_exploit(ctx: RunContext, target: str) -> None:
    findings = ctx.session["findings"]
    if os.getenv("ENABLE_EXPLOIT", "true").lower() != "true":
        logger.debug("core: session=%s ENABLE_EXPLOIT=false, skipping exploit phase entirely (%d findings)", ctx.session_id, len(findings))
        return

    exploit_tools = get_tools_by_category("exploit")
    logger.debug(
        "core: session=%s starting exploit phase, %d finding(s) by descending severity (%d exploit tools available)",
        ctx.session_id, len(findings), len(exploit_tools),
    )
    # A plain "for finding in sorted(...)" can't react to a deep_dive request that arrives
    # mid-phase (the finding-detail modal's Deep dive button, for a session that's already live)
    # — remaining is a real mutable work queue instead, checked for a reorder before every pop,
    # so "prioritize this one now" actually jumps the queue instead of only taking effect next
    # time exploit runs from scratch. Whatever's left keeps going in its normal order afterward.
    remaining = sorted(findings, key=_severity_key)
    while remaining:
        deep_dive_title = _pop_deep_dive_instruction(ctx.session_id)
        if deep_dive_title:
            match = next((f for f in remaining if f.get("title") == deep_dive_title), None)
            if match:
                remaining.remove(match)
                remaining.insert(0, match)
                logger.debug("core: session=%s operator instruction applied: deep_dive(%r) — prioritized next", ctx.session_id, deep_dive_title)
            else:
                logger.debug("core: session=%s deep_dive(%r) requested but not in the remaining queue — ignoring", ctx.session_id, deep_dive_title)

        finding = remaining.pop(0)
        title = finding.get("title")
        if _pop_skip_instruction(ctx.session_id, title):
            logger.debug("core: session=%s operator instruction applied: skip_finding(%r)", ctx.session_id, title)
            _apply_skip_outcome(finding, {"reasoning": "Skipped at the operator's request via chat."})
            save_session(ctx.session_id, ctx.session)
            continue

        logger.debug(
            "core: session=%s exploit: evaluating finding=%r severity=%s verification=%s",
            ctx.session_id, finding.get("title"), finding.get("severity"), finding.get("verification"),
        )
        action, trace = await _run_exploit_for_finding(ctx, target, finding, exploit_tools)

        if action and action.get("action") == "exploit_attempted":
            confirmed = await _confirm_exploit_result(ctx, finding, action, trace)
            finding["exploited"] = confirmed.get("exploited", False)
            finding["evidence"] = confirmed.get("evidence")
            finding["poc_command"] = confirmed.get("poc_command")
            finding["advisory_note"] = confirmed.get("advisory_note")
        else:
            _apply_skip_outcome(finding, action or {"reasoning": "Exploit phase produced no parseable decision"})

        # finding is the same dict object living inside ctx.session["findings"] (sorted()
        # reorders references, it doesn't copy them) — mutating it above already updated the
        # session in memory; this just makes it durable before moving to the next finding.
        save_session(ctx.session_id, ctx.session)
        logger.debug(
            "core: session=%s exploit: finding=%r resolved exploited=%s",
            ctx.session_id, finding.get("title"), finding.get("exploited"),
        )


async def run_focused_exploit(session_id: str, finding_title: str, provider_id: str | None = None) -> None:
    """The Deep dive button's path for a session that ISN'T currently live (main.py's
    /deep-dive route) — a bounded, single-finding re-attempt safe to run as its own
    BackgroundTask precisely because nothing else is touching this session file at the same
    time (the live case instead queues a deep_dive instruction for the already-running loop to
    pick up — see _pop_deep_dive_instruction/_run_exploit — rather than risking two writers).
    Reuses _run_exploit_for_finding/_confirm_exploit_result unchanged, same as a normal exploit
    pass would for this one finding; everything else in the session is left exactly as it was.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_focused_exploit: unknown session %r", session_id)
        return

    matching = [f for f in session.get("findings", []) if f.get("title") == finding_title]
    if not matching:
        logger.debug("run_focused_exploit: session=%s no finding titled %r", session_id, finding_title)
        return
    finding = matching[0]

    resume_status = session["status"]
    session["status"] = "processing"
    save_session(session_id, session)
    logger.debug("run_focused_exploit: session=%s target=%s finding=%r starting", session_id, session["target"], finding_title)

    ctx = RunContext(llm=get_provider(provider_id), session=session, session_id=session_id)
    exploit_tools = get_tools_by_category("exploit")
    try:
        action, trace = await _run_exploit_for_finding(ctx, session["target"], finding, exploit_tools)
        if action and action.get("action") == "exploit_attempted":
            confirmed = await _confirm_exploit_result(ctx, finding, action, trace)
            finding["exploited"] = confirmed.get("exploited", False)
            finding["evidence"] = confirmed.get("evidence")
            finding["poc_command"] = confirmed.get("poc_command")
            finding["advisory_note"] = confirmed.get("advisory_note")
        else:
            _apply_skip_outcome(finding, action or {"reasoning": "Deep dive produced no parseable decision"})
        logger.debug("run_focused_exploit: session=%s finding=%r resolved exploited=%s", session_id, finding_title, finding.get("exploited"))
    finally:
        session["status"] = resume_status if resume_status in ("completed", "failed", "interrupted") else "completed"
        save_session(session_id, session)


async def _run_validate(ctx: RunContext) -> list[dict]:
    findings = ctx.session["findings"]
    logger.debug("core: session=%s starting validate phase (%d findings)", ctx.session_id, len(findings))
    if len(findings) <= 1:
        return findings  # nothing to deduplicate

    task = f"Findings:\n{json.dumps(findings)}"
    messages = [
        {"role": "system", "content": VALIDATE_PROMPT},
        {"role": "user", "content": task},
    ]
    response = await _llm_complete(ctx, messages, None)
    parsed = _parse_json_response(response.content)
    _append_log(
        ctx, "validate", response.content, None,
        "success" if parsed is not None else "error",
        None if parsed is not None else "could not parse a final JSON response from the model",
    )
    if parsed is None or not isinstance(parsed.get("findings"), list):
        logger.debug("core: session=%s validate phase produced no parseable result, keeping pre-dedup findings", ctx.session_id)
        return findings
    return parsed["findings"]


_VALID_ENTRY_POINTS = {"recon", "analyze", "exploit"}


async def run_session(
    session_id: str,
    provider_id: str | None = None,
    entry_point: str = "recon",
) -> None:
    if entry_point not in _VALID_ENTRY_POINTS:
        raise ValueError(f"Unknown entry_point {entry_point!r}, expected one of {sorted(_VALID_ENTRY_POINTS)}")

    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")

    target = session["target"]
    session["status"] = "processing"
    session["entry_point"] = entry_point
    save_session(session_id, session)
    logger.debug("core: session=%s target=%s starting (entry_point=%s)", session_id, target, entry_point)

    ctx = RunContext(llm=get_provider(provider_id), session=session, session_id=session_id)

    try:
        if entry_point == "recon":
            recon_result = await _run_recon(ctx, target)
        else:
            recon_result = session.get("recon_result") or {"targets": []}

        if entry_point in ("recon", "analyze"):
            await _run_analyze(ctx, target, recon_result)
        # entry_point == "exploit": session["findings"] already holds what's already known —
        # nothing to gather, go straight to exploiting it.

        await _run_exploit(ctx, target)
        session["findings"] = await _run_validate(ctx)

        session["findings"] = _normalize_findings(session["findings"])
        session["status"] = "completed"
        save_session(session_id, session)
        logger.debug("core: session=%s completed with %d findings", session_id, len(session["findings"]))
    except Exception:
        logger.debug("core: session=%s failed", session_id, exc_info=True)
        session["status"] = "failed"
        save_session(session_id, session)
        raise


def _cli() -> None:
    parser = argparse.ArgumentParser(description="Run one ASRA scan session from the command line.")
    parser.add_argument("--target", default=None, help="Target host/URL to scan. Required unless --session-id is given.")
    parser.add_argument("--provider", default=None, help="Override LLM_PROVIDER for this run.")
    parser.add_argument(
        "--entry-point", default="recon", choices=sorted(_VALID_ENTRY_POINTS),
        help="Skip earlier sub-phases, using data already recorded in the session (needs --session-id for anything but 'recon').",
    )
    parser.add_argument("--session-id", default=None, help="Resume an existing session by ID instead of creating a new one.")
    args = parser.parse_args()

    if args.session_id:
        session_id = args.session_id
        if load_session(session_id) is None:
            raise SystemExit(f"Unknown session {session_id!r}")
    else:
        if not args.target:
            raise SystemExit("--target is required unless --session-id is given")
        session_id = create_session(args.target)
        print(f"Session {session_id} started for target {args.target}")

    asyncio.run(run_session(session_id, provider_id=args.provider, entry_point=args.entry_point))

    session = load_session(session_id)
    print(f"Status: {session['status']}")
    print(json.dumps(session["findings"], indent=2))


if __name__ == "__main__":
    _cli()
