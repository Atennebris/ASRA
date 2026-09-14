"""Shared helper for turning a caught exception into text worth showing a model or an operator."""
from __future__ import annotations


def describe_exception(exc: BaseException, limit: int | None = None) -> str:
    """str(exc) is empty for exceptions raised with no message -- confirmed live: httpx's
    ConnectTimeout()/ReadTimeout() are frequently raised bare (no args at all). A tool result's
    "error" field left as "" gives a model's 1-Step Retry correction nothing to react to, so it
    can only resend the identical failing call — real, confirmed incident this fixes
    (toolkit_repeater.py's send_raw_request against an unreachable host: two identical dispatches,
    one wasted correction round-trip, because the logged/returned error was literally empty).
    Falls back to the exception's own class name, so there is always at least the failure TYPE to
    go on instead of nothing.

    limit=None (the default, and every existing call site's behavior) leaves the text exactly as
    str(exc) produced it. Pass an explicit limit when the caller can plausibly see a MUCH longer
    message than an ordinary exception — real, confirmed incident this fixes: an OpenAI-SDK
    exception's own str() embeds the provider's raw HTTP response body, and one specific provider
    (opencode-zen, hit on a nonexistent /embeddings endpoint) returns a full ~5KB HTML error page
    for that, dumped verbatim into debug.log on every single failed embed() call with no cap at
    all -- same "don't let one error message dominate the log" concern agent/core.py's own
    _LOG_ERROR_CHAR_LIMIT (4000, same truncation shape) already guards tool-result errors against.
    """
    text = str(exc) or type(exc).__name__
    if limit is not None and len(text) > limit:
        return text[:limit] + f"... [truncated, {len(text)} chars total]"
    return text
