"""LOG_CATEGORIES and get_logger(category): central logging entrypoint for every module."""
import logging

# Every module with real logic gets a category here before it starts logging.
# Pre-declared for the modules already planned: TOOLS, SESSION, LLM, AGENT, API.
LOG_CATEGORIES: set[str] = {
    "TOOLS",
    "SESSION",
    "LLM",
    "AGENT",
    "API",
    "CHAT",
    "PROJECTS",
    "UI",  # browser-side activity — buttons, dialogs, htmx requests; see main.py's /api/debug/client-event
    "SUBAGENT",  # delegate_to_subagent lifecycle + a delegated subagent's own LLM turns/tool calls — split out from AGENT so it renders in its own console color
    "PLAYBOOK",  # cross-session technique capture/lookup/distillation — agent/tools/playbook_store.py + agent/core.py's playbook hooks
    "TOOLKIT",  # native Proxy/Repeater/Decoder/Comparer traffic capture — agent/tools/toolkit_store.py
    "UPDATE",  # git-based update checks/apply + startup check — agent/updater.py
    "TERMINAL",  # standalone PTY terminal tab lifecycle (create/attach/detach/exit) —
    # agent/tools/terminal_manager.py + main.py's /terminal, /api/terminal/*, /ws/terminal/*.
    # Lifecycle events only, deliberately never raw keystrokes/output (see that module's own
    # docstring) — a real operator shell can carry a typed password, which debug.log is not the
    # place for.
    "DESKTOP",  # the Tauri desktop shell's own Rust-side diagnostics (desktop/src-tauri/src/main.rs) —
    # never emitted through this Python logger itself, but declared here so debug.py's
    # CATEGORY_COLORS (the shared source of truth main.rs and scripts/debug_console.ps1 both read)
    # has a real, matching entry for the "[asra.DESKTOP]" lines that file writes directly
    "LIBRARY",  # knowledge-library source upload/normalization/LLM-extraction pipeline —
    # agent/tools/library_store.py
}

_configured: set[str] = set()


def get_logger(category: str) -> logging.Logger:
    """Returns a logger wired to colorized console output + the global debug log (and, when a
    session is active, that session's own project-folder debug log too — see agent/utils/debug.py)
    when DEBUG=true; silent otherwise."""
    if category not in LOG_CATEGORIES:
        raise ValueError(f"Unknown log category: {category!r}. Add it to LOG_CATEGORIES first.")

    logger = logging.getLogger(f"asra.{category}")

    if category not in _configured:
        _configure(logger, category)
        _configured.add(category)

    return logger


def _configure(logger: logging.Logger, category: str) -> None:
    # Logging setup must never crash the agent's main loop, even if the disk is
    # full/read-only or permissions are wrong — degrade to a NullHandler instead.
    try:
        from agent.utils.debug import is_debug_enabled, build_console_handler, build_file_handler

        logger.handlers.clear()
        logger.propagate = False

        if not is_debug_enabled():
            logger.addHandler(logging.NullHandler())
            return

        logger.setLevel(logging.DEBUG)
        logger.addHandler(build_file_handler())
        logger.addHandler(build_console_handler(category))
    except Exception:
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
