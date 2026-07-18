"""Generic build_command() and --help caching shared by autodiscovered and custom tools."""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable

from agent.tools.builders.validators import validate_safe_value
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

TOOL_HELP_CACHE_DIR = Path("data/cache/tool_help")
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
    """

    def build_command(params: dict) -> list[str]:
        return [executable] + [validate_safe_value(str(arg)) for arg in params.get("extra_args", [])]

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
            result = subprocess.run([executable, flag], capture_output=True, text=True, timeout=15)
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
