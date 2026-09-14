"""interpret_permanent_connection_refusal (agent/tools/native.py): registered in
_PERMANENT_ERROR_HINTS["http_request"] so a doomed 1-Step Retry never gets requested for an
outcome no corrected argument could ever fix.

Covers two independent sources of the same "no HTTP-layer negotiation ever started" outcome:
a bare OS-level TCP refusal/unreachable-route errno, and this project's own _with_hard_deadline
wall-clock watchdog timing out because a resolved address is unroutable. Real, confirmed incident
for the second case (a real HackerOne session): 8 hard-deadline timeouts across distinct
trk./link.inbox. subdomains in one phase, at least 4 triggering a wasted 1-Step Retry that resent
the identical host and failed identically ~14-15s later each time.
"""
from agent.tools.native import interpret_permanent_connection_refusal


def test_returns_none_for_a_successful_result():
    assert interpret_permanent_connection_refusal({"status": "ok"}) is None


def test_returns_none_for_an_unrelated_error():
    result = {"status": "error", "error": "httpx.ConnectTimeout: timed out"}
    assert interpret_permanent_connection_refusal(result) is None


def test_flags_errno_111_connection_refused_as_permanent():
    result = {"status": "error", "error": "[Errno 111] Connection refused"}
    hint = interpret_permanent_connection_refusal(result)
    assert hint is not None
    assert "Errno 111" in hint
    assert "retrying the same host:port will fail identically" in hint


def test_flags_errno_113_no_route_to_host_as_permanent():
    result = {"status": "error", "error": "[Errno 113] No route to host"}
    hint = interpret_permanent_connection_refusal(result)
    assert hint is not None
    assert "Errno 113" in hint


def test_flags_hard_deadline_exceeded_unreachable_host_as_permanent():
    result = {
        "status": "error",
        "error": (
            "no response within 15s hard deadline -- host is likely unreachable (a "
            "broken/blackholed route to one of its resolved addresses is the usual cause, not a "
            "slow server)"
        ),
    }
    hint = interpret_permanent_connection_refusal(result)
    assert hint is not None
    assert "host is likely unreachable" in hint
    assert "Retrying the same host:port will fail identically" in hint
