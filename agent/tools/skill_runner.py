"""The one place a playbook skill actually executes -- shared by RE mode (agent/core.py's
re_run_skill) and chat (agent/chat.py's _apply_chat_run_skill) so there is a single, auditable
execution path, not two drifting copies.

Why this module is shaped the way it is (the OpenClaw skill-poisoning lesson): a skill body is code
that runs LATER, sometimes with no human in the loop, driven by an agent whose whole job is chewing
on hostile targets. So every execution passes three gates before anything runs:
  1. hash gate   -- the stored body must still match its pinned body_sha256 (a body changed
                    out-of-band -- hand-edited store, tampered import -- is refused until re-vetted).
  2. provenance  -- the body's derived_from must be one we accept (agent's own run, operator-typed,
                    or a reviewed library/import), never an unknown origin.
  3. sandbox     -- a script always runs through agent/tools/sandbox.py's run_sandboxed; a command
                    may only invoke a binary ASRA's own registry already knows, and also runs
                    sandboxed. Filesystem/process isolation, same path custom_exploit_run uses.
'instructions' skills are never executed -- they are returned to the model as text.
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import uuid

from agent.tools import playbook_store
from agent.tools.registry import TOOL_REGISTRY
from agent.tools.sandbox import run_sandboxed
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# A skill body may only run if its provenance is one of these. "library" is a skill distilled from
# operator-ingested study material -- untrusted-by-default and surfaced for review, but a reviewed
# one is runnable; "import" is a skill brought in from another machine/agent (always starts
# unreviewed). An unknown/absent provenance is refused outright.
_ALLOWED_DERIVED_FROM = frozenset({"agent_run", "operator", "library", "import"})

_TIMEOUT_SECONDS = int(os.getenv("SKILL_SANDBOX_TIMEOUT_SECONDS", "180"))

_TEMPLATE_SLOT_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")


def _scratch_dir(session_id: str | None):
    """The same session-scoped-else-global writable scratch root custom_exploit_run uses -- imported
    locally to avoid a module import cycle (native.py pulls in much of the tools package)."""
    from agent.tools.native import _exploit_scripts_dir
    return _exploit_scripts_dir(session_id)


def _allowed_command_binaries() -> set[str]:
    """Executables ASRA's own registry knows about -- the allowlist a 'command' skill's first token
    must be in. Built fresh each call off the live registry so a newly-registered tool is covered
    without any extra wiring; the registry is small, so this is cheap."""
    allowed: set[str] = set()
    for spec in TOOL_REGISTRY:
        exe = (getattr(spec, "executable", "") or "").strip()
        if exe:
            allowed.add(exe)
            allowed.add(os.path.basename(exe))
    return allowed


def _render_body(skill: dict, params: dict) -> tuple[str, list[str]]:
    """Fills the body's {{slots}} from params and reports any still-unfilled slot names -- a required
    param left unsupplied must stop execution, not run a half-rendered body."""
    body = playbook_store.render_payload_template(skill.get("body", ""), params or {})
    leftovers = sorted(set(_TEMPLATE_SLOT_RE.findall(body)))
    return body, leftovers


def execute_skill(technique_id: str, params: dict | None = None, session_id: str | None = None) -> dict:
    """Runs the skill attached to a technique (by the technique's own id). Returns a result dict in
    the same {status, ...} shape every other native tool returns. Never raises on a bad/absent/
    tampered skill -- it returns an actionable error instead, same discipline as custom_exploit_run."""
    params = params or {}
    skill = playbook_store.get_technique_skill(technique_id)
    if not skill:
        return {"status": "error", "error": f"no skill is attached to technique id {technique_id!r} -- nothing to run."}

    if not playbook_store.skill_enabled(skill):
        return {"status": "error", "error": "this skill is switched off -- enable it in the Playbook before running it."}

    if playbook_store.skill_body_tampered(skill):
        return {
            "status": "error",
            "error": (
                "this skill's stored body no longer matches its pinned hash -- refusing to run it "
                "until it's re-vetted. Re-save it in the Playbook (which re-pins the hash) or "
                "re-capture it, then try again."
            ),
        }

    derived = str((skill.get("provenance") or {}).get("derived_from") or "")
    if derived not in _ALLOWED_DERIVED_FROM:
        return {
            "status": "error",
            "error": f"this skill has an unrecognized provenance ({derived!r}) and will not be run -- re-create it through the normal capture/author path.",
        }

    kind = skill.get("kind")
    body, leftovers = _render_body(skill, params)
    if leftovers:
        return {"status": "error", "error": f"missing required skill parameter(s): {', '.join(leftovers)}. Supply them in `params` and retry."}
    if not body.strip():
        return {"status": "error", "error": "the rendered skill body is empty -- nothing to run."}

    if kind == "instructions":
        # Never executed -- handed back to the model as steps to follow itself.
        logger.debug("skill_runner: returned instructions skill id=%s (not executed)", technique_id)
        return {"status": "ok", "kind": "instructions", "instructions": body}

    scratch = _scratch_dir(session_id)

    if kind == "script":
        return _run_script_skill(technique_id, skill, body, scratch)
    if kind == "command":
        return _run_command_skill(technique_id, body, scratch)
    return {"status": "error", "error": f"unknown skill kind {kind!r}."}


def execute_skill_chain(technique_id: str, params: dict | None = None, session_id: str | None = None) -> dict:
    """Replays a proven multi-step recipe: runs each skill along a technique's kill-chain in order
    (root -> ... -> this), stopping at the first step that fails -- a later step only made sense
    because an earlier one unlocked it, so pressing on past a failure would run it against a state
    that never materialized. Every step goes through execute_skill, so each one is individually
    hash/provenance/sandbox-gated. Returns the per-step results plus which step (if any) stopped it."""
    sequence = playbook_store.chain_skill_sequence(technique_id)
    if not sequence:
        return {"status": "error", "error": f"technique id {technique_id!r} has no runnable skill chain (no skills along its chain)."}
    steps: list[dict] = []
    stopped_at = None
    for i, step in enumerate(sequence):
        result = execute_skill(step["technique_id"], params, session_id)
        steps.append({"technique_id": step["technique_id"], "technique": step["technique"], "result": result})
        if result.get("status") not in ("ok",):
            stopped_at = i
            break
    ran = len(steps)
    ok = stopped_at is None
    logger.debug("skill_runner: ran skill chain id=%s steps=%d/%d ok=%s", technique_id, ran, len(sequence), ok)
    return {
        "status": "ok" if ok else "error",
        "steps_run": ran,
        "steps_total": len(sequence),
        "stopped_at_step": stopped_at,
        "steps": steps,
    }


def _run_script_skill(technique_id: str, skill: dict, body: str, scratch) -> dict:
    interp = (skill.get("interpreter") or "").lower()
    skill_id = uuid.uuid4().hex[:12]
    if interp in ("python", "pwntools"):
        # Same free, deterministic SyntaxError pre-flight custom_exploit_run runs before paying for a
        # subprocess -- a stray indent shouldn't cost a real sandbox dispatch to discover.
        try:
            compile(body, "<skill>", "exec")
        except SyntaxError as exc:
            return {"status": "error", "error": f"SyntaxError at line {exc.lineno}: {exc.msg} -- the skill was not run. Fix it (update_skill) and retry."}
        script_path = scratch / f"skill_{skill_id}.py"
        script_path.write_text(body, encoding="utf-8")
        # sys.executable, not a PATH python3 -- same reason custom_exploit_run pins it: only this
        # interpreter's venv has the project's deps (httpx, pwntools, ...).
        cmd = [sys.executable, str(script_path)]
    elif interp == "sh":
        script_path = scratch / f"skill_{skill_id}.sh"
        script_path.write_text(body, encoding="utf-8")
        cmd = ["bash", str(script_path)]
    else:
        return {"status": "error", "error": f"a script skill needs interpreter 'python', 'pwntools' or 'sh' (got {interp!r})."}

    result = _run_sandboxed_capture(cmd, scratch)
    playbook_store.bump_skill_run(technique_id, success=result.get("status") == "ok")
    logger.debug("skill_runner: ran script skill id=%s interp=%s status=%s", technique_id, interp, result.get("status"))
    return result


def _run_command_skill(technique_id: str, body: str, scratch) -> dict:
    try:
        argv = shlex.split(body)
    except ValueError as exc:
        return {"status": "error", "error": f"could not parse the command ({exc}) -- check quoting."}
    if not argv:
        return {"status": "error", "error": "the command skill rendered to an empty command."}
    exe = os.path.basename(argv[0])
    if exe not in _allowed_command_binaries():
        return {
            "status": "error",
            "error": (
                f"a command skill may only invoke a binary ASRA's registry already knows; {exe!r} is "
                "not one. Use a script skill (sandboxed) for anything else, or register the tool first."
            ),
        }
    result = _run_sandboxed_capture(argv, scratch)
    playbook_store.bump_skill_run(technique_id, success=result.get("status") == "ok")
    logger.debug("skill_runner: ran command skill id=%s exe=%s status=%s", technique_id, exe, result.get("status"))
    return result


def _run_sandboxed_capture(cmd: list[str], scratch) -> dict:
    """Runs cmd through the shared sandbox with the skill timeout and normalizes the outcome into the
    standard {status, exit_code, stdout, stderr} result shape (truncated like custom_exploit_run)."""
    try:
        proc = run_sandboxed(cmd, scratch, _TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "error": f"the skill exceeded its {_TIMEOUT_SECONDS}s timeout and was killed (a hang, or genuinely too slow). Bound any blocking call and retry."}
    return {
        "status": "ok" if proc.returncode == 0 else "error",
        "exit_code": proc.returncode,
        "stdout": (proc.stdout or "")[:8000],
        "stderr": (proc.stderr or "")[:2000],
    }
