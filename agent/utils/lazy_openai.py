"""Lazy proxy for the `openai` SDK.

Importing openai eagerly pulls its entire `openai.types` tree -- hundreds of tiny modules. On WSL2's
/mnt/c mount (the project's supported launch path) that is several seconds of pure file-open latency
at server startup, even though nothing openai-related is touched until the first real LLM call. This
proxy defers the import to first attribute access (a client construction, or an exception class read
inside a handler), so the web server becomes responsive fast and pays the SDK's load cost once,
lazily, on the first provider call -- where it's dwarfed by network latency anyway.

Usage is drop-in: `from agent.utils.lazy_openai import openai` then `openai.OpenAI(...)`,
`openai.APIStatusError`, `openai.Omit()` exactly as with a direct `import openai`.
"""
from __future__ import annotations

from typing import Any

_real_module = None


def _load() -> Any:
    global _real_module
    if _real_module is None:
        import time  # noqa: PLC0415

        from agent.utils.logger import get_logger  # noqa: PLC0415  -- avoid import at module load
        start = time.time()
        import openai as _openai  # noqa: PLC0415  -- deferred on purpose; that's the whole point
        _real_module = _openai
        get_logger("LLM").debug("lazy_openai: openai SDK imported on first use (%.2fs)", time.time() - start)
    return _real_module


class _LazyOpenAI:
    """Forwards every attribute to the real openai module, importing it on the first access."""

    def __getattr__(self, name: str) -> Any:
        return getattr(_load(), name)


openai = _LazyOpenAI()


def warm_up() -> None:
    """Triggers the deferred import early, off the request path. Real, confirmed incident this
    fixes: without this, the ~10-15s import cost (measured live, well above this module's own
    "a few seconds" estimate above) lands entirely on whichever request happens to be the first to
    touch an LLM provider -- typically an operator's first Settings "Test" click, which then just
    looks hung. Call once, from a background thread, right after the server starts serving (so it
    never delays startup itself) -- by the time a real request needs openai, it's already loaded.
    """
    _load()
