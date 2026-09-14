"""Intruder: automated payload-substitution attack against a request template -- sniper and
pitchfork modes, the same marker convention a commercial payload-injection tool uses (a pair of
`§` characters wraps the baseline value at each attack position, e.g. `id=§1§`). Every real
attempt is sent through toolkit_repeater's own
send_raw_request (source="intruder") -- one send-and-record code path shared with Repeater, so an
attempt's encoding/storage behavior can never drift between the two features. Results are never
buffered separately here: they land in toolkit_store the instant each attempt completes, so the
manual UI's live-polling results table (main.py's own intruder routes) and this module never need
a second, in-memory "results so far" structure to stay in sync.

sniper: ONE payload set applied to each position in turn, one position "live" per attempt while
every other position stays at its own baseline value -- num_positions * len(payloads) attempts.
pitchfork: one payload set PER position, stepped in lockstep (attempt k substitutes every
position's own set at index k simultaneously) -- min(len(set) for set in payload_sets) attempts.
cluster bomb (every combination of every set) is deliberately not implemented -- a scope tradeoff,
since sniper+pitchfork already cover the two most common real attack shapes (fuzzing one position
at a time; testing matched identity/credential pairs together).
"""
from __future__ import annotations

import asyncio
import os
import re
import uuid
from typing import Literal

from agent.tools import toolkit_store
from agent.tools.toolkit_repeater import send_raw_request
from agent.utils.logger import get_logger

logger = get_logger("TOOLKIT")

AttackMode = Literal["sniper", "pitchfork"]

_POSITION_PATTERN = re.compile(r"§(.*?)§")

_DEFAULT_MAX_CONCURRENT = 5
# A hard ceiling regardless of what's requested -- this sends real, possibly-many-times-repeated
# traffic to a real target; unlike a read-only tool, an uncapped concurrency knob here is a real
# way to accidentally DoS the very target being tested.
_MAX_ALLOWED_CONCURRENT = 20
# A hard ceiling on total requests one attack run can ever fire -- the same "this is a scoped,
# bounded assessment action, not an open-ended flood" reasoning already applied to
# waf_evasion_probe's own fixed ~12-request mutation set, just a much larger bound since an
# Intruder run is explicitly meant to try many payloads.
_MAX_ATTEMPTS = 500


def _max_concurrent_default() -> int:
    return int(os.getenv("INTRUDER_MAX_CONCURRENT_REQUESTS", str(_DEFAULT_MAX_CONCURRENT)))


def _max_attempts_cap() -> int:
    return int(os.getenv("INTRUDER_MAX_ATTEMPTS", str(_MAX_ATTEMPTS)))


def count_positions(url: str, headers_text: str, body: str) -> int:
    """Total §...§ markers across the three template fields, in the fixed url→headers→body order
    every other function in this module also iterates in -- one shared ordering convention, not
    three independent ones that could disagree."""
    return len(_POSITION_PATTERN.findall(url)) + len(_POSITION_PATTERN.findall(headers_text)) + len(_POSITION_PATTERN.findall(body))


def _baseline_values(url: str, headers_text: str, body: str) -> list[str]:
    """The original text each §...§ marker wrapped, in position order -- what a position reverts
    to on any attempt where it isn't the one under attack (sniper) or has run out of payload
    values (shouldn't happen for pitchfork, whose attempt count is capped to the shortest set)."""
    return _POSITION_PATTERN.findall(url) + _POSITION_PATTERN.findall(headers_text) + _POSITION_PATTERN.findall(body)


def render_request(url: str, headers_text: str, body: str, substitutions: list[str]) -> tuple[str, str, str]:
    """Replaces every §...§ marker across url/headers_text/body (that fixed order) with
    substitutions[i] for the i-th marker encountered -- the actual request text to send for one
    attempt. len(substitutions) must equal count_positions(url, headers_text, body); callers build
    that list from baseline values (for positions not currently under attack) mixed with real
    payloads (see build_attempts)."""
    counter = {"i": 0}

    def repl(match: re.Match) -> str:
        idx = counter["i"]
        counter["i"] += 1
        return substitutions[idx] if idx < len(substitutions) else match.group(1)

    return (
        _POSITION_PATTERN.sub(repl, url),
        _POSITION_PATTERN.sub(repl, headers_text),
        _POSITION_PATTERN.sub(repl, body),
    )


def parse_payload_lines(mode: AttackMode, num_positions: int, payload_text: str) -> dict:
    """Turns the operator's single payload textarea into a list of attempts -- each attempt is a
    list of length num_positions, entry i being the payload string for position i on that attempt.

    sniper: one payload per non-empty line, applied to EVERY position in turn (line count doesn't
    need to relate to num_positions at all -- the same set attacks each position independently).
    pitchfork: each non-empty line holds num_positions tab-separated values, one per position, all
    substituted together on that one attempt -- every line MUST have exactly num_positions columns,
    checked upfront (line number named in the error) rather than silently skipping a malformed
    line, which would just as silently under-count the real attack.

    Returns {"status": "ok", "attempts": [...]} or {"status": "error", "error": "..."}."""
    lines = [line for line in payload_text.splitlines() if line.strip() != ""]
    if not lines:
        return {"status": "error", "error": "no payloads given -- add at least one line to the payload set"}
    if num_positions == 0:
        return {"status": "error", "error": "no §...§ attack positions found in the request template"}

    if mode == "sniper":
        attempts: list[list[str]] = []
        for position_index in range(num_positions):
            for payload in lines:
                attempt = [""] * num_positions
                attempt[position_index] = payload
                attempts.append(attempt)
        return {"status": "ok", "attempts": attempts}

    # pitchfork
    for line_number, line in enumerate(lines, start=1):
        columns = line.split("\t")
        if len(columns) != num_positions:
            return {
                "status": "error",
                "error": (
                    f"pitchfork line {line_number} has {len(columns)} tab-separated value(s), "
                    f"but the template has {num_positions} position(s) -- every line needs exactly "
                    f"{num_positions}, tab-separated"
                ),
            }
    attempts = [line.split("\t") for line in lines]
    return {"status": "ok", "attempts": attempts}


def build_attempts(mode: AttackMode, num_positions: int, payload_text: str) -> dict:
    """Public entry point combining parse_payload_lines with the attempt-count safety cap -- the
    one place both checks are guaranteed to run together, so no caller can send an uncapped
    attack by forgetting the second check."""
    parsed = parse_payload_lines(mode, num_positions, payload_text)
    if parsed["status"] != "ok":
        return parsed
    cap = _max_attempts_cap()
    if len(parsed["attempts"]) > cap:
        return {
            "status": "error",
            "error": f"{len(parsed['attempts'])} attempts would exceed the {cap}-request safety cap for one attack run -- use fewer payload lines",
        }
    return parsed


async def run_attack(
    *, session_id: str | None, method: str, url: str, headers_text: str, body: str,
    mode: AttackMode, payload_text: str, max_concurrent: int | None = None, run_id: str | None = None,
) -> dict:
    """Fires every attempt concurrently (bounded by an asyncio.Semaphore), each one a real call to
    toolkit_repeater.send_raw_request with source="intruder" and this run's own run_id -- returns
    once every attempt has completed (or failed to connect at all), with a plain summary.

    run_id: pass one in when the caller needs to know it BEFORE the attack finishes (the manual UI
    route, main.py, needs it immediately to render a live-polling results view pointed at the
    right run) -- generated here otherwise (the agent-facing `intruder_run` tool has no such need,
    it just awaits the final summary).

    The manual UI route does NOT await this directly -- see start_attack_in_background below, which
    wraps it in asyncio.create_task so the operator's browser tab gets an immediately-rendered,
    live-polling view instead of a request that hangs for the whole attack's real duration; the
    agent-facing `intruder_run` tool (agent/tools/toolkit_agent_tools.py) DOES await this function
    directly, the same "a slow tool call just takes as long as it takes" convention every other
    long-running tier-1 tool (nmap/sqlmap-equivalent) already follows in this project."""
    num_positions = count_positions(url, headers_text, body)
    prepared = build_attempts(mode, num_positions, payload_text)
    if prepared["status"] != "ok":
        return prepared

    baseline = _baseline_values(url, headers_text, body)
    limit = max(1, min(int(max_concurrent or _max_concurrent_default()), _MAX_ALLOWED_CONCURRENT))
    semaphore = asyncio.Semaphore(limit)
    run_id = run_id or uuid.uuid4().hex[:12]
    attempts = prepared["attempts"]

    async def _fire(attempt: list[str]) -> dict:
        # A blank cell (sniper's own untouched positions) falls back to that position's real
        # baseline value -- never sent as a literal empty string standing in for "unchanged".
        substitutions = [value if value else baseline[i] for i, value in enumerate(attempt)]
        rendered_url, rendered_headers_text, rendered_body = render_request(url, headers_text, body, substitutions)
        headers = toolkit_store.parse_header_lines(rendered_headers_text)
        async with semaphore:
            return await send_raw_request(
                session_id=session_id, method=method, url=rendered_url, headers=headers, body=rendered_body,
                source="intruder", intruder_run_id=run_id, intruder_payload_values=substitutions,
            )

    results = await asyncio.gather(*(_fire(attempt) for attempt in attempts))
    ok_count = sum(1 for r in results if r["status"] == "ok")
    logger.debug(
        "toolkit_intruder: session=%s run=%s mode=%s positions=%d attempts=%d ok=%d concurrency=%d",
        session_id, run_id, mode, num_positions, len(attempts), ok_count, limit,
    )
    return {
        "status": "ok", "run_id": run_id, "mode": mode, "positions": num_positions,
        "attempts": len(attempts), "ok": ok_count, "errors": len(attempts) - ok_count,
    }


# Live asyncio.Task objects, keyed by run_id -- module-level, in-process only (same "no
# cross-restart tracking" limitation agent/tools/subagent_tasks.py's own _RUNNING_SUBAGENT_TASKS
# already accepts; a server restart mid-attack loses live status, but every attempt already
# completed is still safely in toolkit_store regardless). Holding a strong reference here is not
# optional -- nothing else keeps a fire-and-forget asyncio.create_task() alive, and an
# unreferenced pending Task is a real, documented risk of being garbage-collected mid-run.
_RUNNING_ATTACKS: dict[str, asyncio.Task] = {}


def start_attack_in_background(
    *, session_id: str | None, method: str, url: str, headers_text: str, body: str,
    mode: AttackMode, payload_text: str, max_concurrent: int | None = None,
) -> dict:
    """Validates the template/payloads SYNCHRONOUSLY first (so a malformed request never even
    starts a background task, and the operator sees the real error immediately instead of an
    empty "running" view that silently goes nowhere), then fires run_attack() as a background
    asyncio.Task and returns right away -- see run_attack's own docstring for why the UI route
    needs this fire-and-forget shape instead of a normal awaited call. Returns
    {"status": "ok", "run_id": ..., "expected": <attempt count>} or
    {"status": "error", "error": "..."} (nothing started)."""
    num_positions = count_positions(url, headers_text, body)
    prepared = build_attempts(mode, num_positions, payload_text)
    if prepared["status"] != "ok":
        return prepared

    run_id = uuid.uuid4().hex[:12]
    task = asyncio.create_task(run_attack(
        session_id=session_id, method=method, url=url, headers_text=headers_text, body=body,
        mode=mode, payload_text=payload_text, max_concurrent=max_concurrent, run_id=run_id,
    ))
    _RUNNING_ATTACKS[run_id] = task
    task.add_done_callback(lambda t: _RUNNING_ATTACKS.pop(run_id, None))
    return {"status": "ok", "run_id": run_id, "expected": len(prepared["attempts"])}


def attack_status(run_id: str) -> str:
    """"running" | "done" -- "done" also covers a run_id this process has never heard of (either
    it genuinely finished and its done-callback already popped it, or the server restarted since
    it started) -- the results poll route (main.py) treats both the same way: stop polling, show
    whatever's in toolkit_store as final."""
    task = _RUNNING_ATTACKS.get(run_id)
    return "running" if task is not None and not task.done() else "done"
