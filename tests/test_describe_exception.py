"""agent/utils/errors.py's describe_exception -- str(exc) is empty for exceptions raised with no
message (confirmed live: httpx's ConnectTimeout()/ReadTimeout() are frequently raised bare), which
used to leave a tool result's "error" field/a debug log line literally empty, giving a model's
1-Step Retry correction nothing to react to.
"""
from agent.utils.errors import describe_exception


def test_describe_exception_falls_back_to_the_class_name_when_str_is_empty():
    assert describe_exception(ValueError()) == "ValueError"


def test_describe_exception_keeps_a_real_message_untouched():
    assert describe_exception(ValueError("bad target")) == "bad target"


def test_describe_exception_truncates_only_when_a_limit_is_given():
    long_message = "x" * 10_000
    assert describe_exception(ValueError(long_message)) == long_message  # limit=None, unbounded

    truncated = describe_exception(ValueError(long_message), limit=4000)
    assert len(truncated) < 4100
    assert "truncated" in truncated
    assert "10000 chars total" in truncated


def test_describe_exception_never_truncates_below_the_limit():
    assert describe_exception(ValueError("short"), limit=4000) == "short"
