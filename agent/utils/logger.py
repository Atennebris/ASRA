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
}

_configured: set[str] = set()


def get_logger(category: str) -> logging.Logger:
    """Returns a logger wired to data/debug.log + colorized console when DEBUG=true, silent otherwise."""
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
