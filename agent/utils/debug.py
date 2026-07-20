"""DEBUG=true wiring: data/debug.log, CATEGORY_COLORS, two-tier logging to data/debug/tool-calls/."""
import logging
import os
from pathlib import Path

# Matches LOG_CATEGORIES in logger.py — extend both together when a new module starts logging.
CATEGORY_COLORS: dict[str, str] = {
    "TOOLS": "\033[36m",  # cyan
    "SESSION": "\033[35m",  # magenta
    "LLM": "\033[33m",  # yellow
    "AGENT": "\033[32m",  # green
    "API": "\033[34m",  # blue
    "CHAT": "\033[31m",  # red
    "PROJECTS": "\033[92m",  # bright green
}
_RESET = "\033[0m"
_FALLBACK_COLOR = "\033[37m"  # white, for a category missing from CATEGORY_COLORS

DEBUG_LOG_PATH = Path("data/debug.log")
TOOL_CALL_DUMP_DIR = Path("data/debug/tool-calls")

# Chars kept inline in data/debug.log before a large payload is truncated and
# dumped to its own file under TOOL_CALL_DUMP_DIR (nmap/nuclei output can be huge).
_INLINE_PREVIEW_CHARS = 500


def is_debug_enabled() -> bool:
    return os.getenv("DEBUG", "false").strip().lower() in ("1", "true", "yes")


class _CategoryConsoleFormatter(logging.Formatter):
    def __init__(self, category: str):
        super().__init__("%(asctime)s %(message)s", datefmt="%H:%M:%S")
        self._color = CATEGORY_COLORS.get(category, _FALLBACK_COLOR)
        self._category = category

    def format(self, record: logging.LogRecord) -> str:
        return f"{self._color}[{self._category}]{_RESET} {super().format(record)}"


def build_console_handler(category: str) -> logging.StreamHandler:
    handler = logging.StreamHandler()
    handler.setFormatter(_CategoryConsoleFormatter(category))
    return handler


def build_file_handler() -> logging.FileHandler:
    DEBUG_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(DEBUG_LOG_PATH, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s"))
    return handler


def dump_large_payload(step_id: str, content: str) -> str:
    """Writes full content to data/debug/tool-calls/<step_id>.txt, returns the path as a string."""
    TOOL_CALL_DUMP_DIR.mkdir(parents=True, exist_ok=True)
    dump_path = TOOL_CALL_DUMP_DIR / f"{step_id}.txt"
    dump_path.write_text(content, encoding="utf-8")
    return str(dump_path)


def truncate_for_log(content: str, step_id: str | None = None) -> str:
    """Compact preview for a debug.log line; if content is large and step_id is given, also dumps the full text to disk."""
    if len(content) <= _INLINE_PREVIEW_CHARS:
        return content

    remainder = len(content) - _INLINE_PREVIEW_CHARS
    suffix = f"... (+{remainder} chars)"

    if step_id:
        dump_path = dump_large_payload(step_id, content)
        suffix += f", full dump: {dump_path}"

    return content[:_INLINE_PREVIEW_CHARS] + suffix
