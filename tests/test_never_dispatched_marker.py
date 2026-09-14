"""agent/tools/runner.py's never_dispatched=True marker on a build_command/native_function
exception result -- real, confirmed incident: agent/core.py's _track_host_health counts any
status="error" result toward a host's own consecutive-failure streak, and once that hits
_HOST_DEAD_FAILURE_THRESHOLD (3), _dead_host_blocked skips EVERY further tool call against that
host for the rest of the phase, regardless of which tool. A build_command/native_function
exception (a malformed call -- a missing/misplaced argument) never even attempted to reach the
host at all; it says nothing about whether the host is actually reachable, unlike a real subprocess
timeout or connection failure. Confirmed live: a real session's entire Analyze phase opened with
whatweb/http_request/view_source/api_schema_discovery ALL pre-emptively skipped against the one
host that mattered, after 3 repeats of the exact same discovered-tool argument mistake
(agent/tools/builders/discovered.py's own "target never appears in extra_args" check).
"""
from agent.tools.registry import ToolSpec
from agent.tools.runner import run_tool


def _make_subprocess_spec(build_command):
    return ToolSpec(
        name="fake_subprocess_tool", category="scan", tool_tier=2, executable="python3",
        build_command=build_command, requires_allowed_target=False, installed_by_default=True,
    )


def _make_native_spec(native_function):
    return ToolSpec(
        name="fake_native_tool", category="scan", tool_tier=1, executable="", build_command=None,
        native_function=native_function, requires_allowed_target=False, installed_by_default=True,
    )


def test_build_command_exception_result_carries_never_dispatched():
    def _raise(params):
        raise ValueError("target was never referenced in extra_args")

    spec = _make_subprocess_spec(_raise)
    result = run_tool(spec, {"target": "example.com"})

    assert result["status"] == "error"
    assert result["never_dispatched"] is True


def test_native_function_exception_result_carries_never_dispatched():
    def _raise(params):
        raise KeyError("target")

    spec = _make_native_spec(_raise)
    result = run_tool(spec, {})

    assert result["status"] == "error"
    assert result["never_dispatched"] is True


def test_a_real_dispatch_failure_never_carries_the_marker():
    """Regression guard -- a tool that actually ran (or genuinely tried to) and failed on its own
    terms must NOT be marked never_dispatched, or real host-unreachable detection would be
    silently defeated for every real failure too."""
    def _real_failure(params):
        return {"status": "error", "error": "Connection refused"}

    spec = _make_native_spec(_real_failure)
    result = run_tool(spec, {"target": "example.com"})

    assert result["status"] == "error"
    assert "never_dispatched" not in result
