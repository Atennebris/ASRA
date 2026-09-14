"""Generic build_command() and --help caching shared by autodiscovered and custom tools."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from agent.tools.builders.validators import validate_safe_value
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
TOOL_HELP_CACHE_DIR = resolve_global_app_dir() / "data" / "cache" / "tool_help"
_HELP_FLAGS = ("--help", "-h", "help")


def make_generic_discovered_command(executable: str) -> Callable[[dict], list[str]]:
    """Builds [executable, *extra_args] — deliberately does NOT auto-append target as a bare
    positional argument. Confirmed by a real run: nikto rejects a bare target ("ERROR: No host
    specified", dumps its help) because it requires an explicit -h/-host flag; other tools use
    -u/-target/--url/etc. There is no single convention across "big tools". The LLM sees the
    tool's full --help text (get_tool_help) and must put the correctly-flagged target token(s)
    into extra_args itself — e.g. ["-h", "http://target", "-Tuning", "1,2,3"] for nikto.
    params["target"] is NOT consumed here; it only feeds the requires_allowed_target guardrail
    in run_tool(), which is independent of what actually reaches argv.

    Real incident this last part fixes: confirmed live, a model called httpx 5 separate times in
    one real session with params={"target": "https://x", ...} and NO actual target-carrying flag
    (-u/-l/etc.) anywhere in extra_args — every single call, it just never put the target where
    the tool would actually see it, because _GENERIC_DISCOVERED_SCHEMA's own "target" field is
    marked "required" with a description ("Target host/URL for this tool") that reads exactly
    like every OTHER tool's target field, where it genuinely IS auto-consumed. httpx ran with
    nothing to scan every time, silently exited 0 with empty stdout (no error at all), and the
    model's own postmortem wrongly concluded "httpx produced no output in this environment" —
    a plausible-sounding but false explanation for what was actually its own missed flag, five
    times over, with nothing anywhere pointing that out. A bare substring check (the target,
    or its scheme-stripped core, appearing somewhere in extra_args) can't verify the flag is
    correct, but it reliably catches "target is not referenced in extra_args AT ALL" — exactly
    this incident's own shape — and turns it into a clear, actionable, retryable error instead of
    a silent, misleading no-op.
    """

    def build_command(params: dict) -> list[str]:
        extra_args = [validate_safe_value(str(arg)) for arg in params.get("extra_args", [])]
        target = params.get("target")
        if not target and not extra_args:
            # Real, confirmed incident: a 1-Step Retry correction call gave up on a bad flag
            # (e.g. httpx's own "-body" doesn't exist) and replied with an empty {"arguments": {}}
            # instead of a real fix, dropping BOTH target and extra_args entirely rather than just
            # failing to reference target in extra_args (the case the check below already
            # catches). Unlike the legitimate "no target field, but extra_args does real work"
            # case (e.g. subfinder called with just ["-d", "example.com"]), a command with
            # NEITHER target nor extra_args reduces to plain [executable] -- never legitimate,
            # since it can't scan anything. Without this, build_command happily returned exactly
            # that, ran it, got a clean exit_code=0 with empty output, and the caller logged "retry
            # succeeded" for a call that scanned nothing and proved nothing, burning the one retry
            # chance on a silent no-op.
            raise ValueError(
                "this call had neither a target nor any extra_args -- the resulting command would "
                "just be the bare executable with nothing to scan. Re-send the call with a real "
                "target, put into extra_args yourself using whichever flag this tool's --help "
                "documents for it (see target's own schema description)."
            )
        if not target:
            return [executable] + extra_args
        target_core = target.split("://", 1)[-1].rstrip("/")
        if target_core and not any(target_core in arg for arg in extra_args):
            raise ValueError(
                f"target={target!r} was given but never appears anywhere in extra_args — "
                f"this tool's own build_command never auto-adds the target to the command "
                f"line (every tool has its own flag for it — -u/-l/-h/-target/etc., see this "
                f"tool's --help text below), so this call would otherwise silently run with "
                f"nothing to actually scan. Put the target into extra_args yourself, using "
                f"whichever flag this specific tool's --help documents for it."
            )
        return [executable] + extra_args

    return build_command


def get_tool_help(name: str, executable: str, full_description: str | None = None) -> str:
    """Returns cached --help text (or a hand-written full_description) for a discovered/custom tool."""
    cache_path = TOOL_HELP_CACHE_DIR / f"{name}.txt"

    if full_description is not None:
        _write_cache(cache_path, full_description)
        return full_description

    if cache_path.exists():
        return cache_path.read_text(encoding="utf-8")

    for flag in _HELP_FLAGS:
        try:
            result = subprocess.run([executable, flag], capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("get_tool_help: %s %s failed (%s)", executable, flag, exc)
            continue

        output = (result.stdout or result.stderr).strip()
        if output:
            _write_cache(cache_path, output)
            logger.debug("get_tool_help: cached %s via %s (%d chars)", name, flag, len(output))
            return output

    logger.debug("get_tool_help: no --help/-h/help output available for %s", name)
    return ""


def _write_cache(cache_path: Path, content: str) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(content, encoding="utf-8")
