"""ToolSpec.ok_exit_codes: which real subprocess exit codes count as "ok" (agent/tools/runner.py's
_run_subprocess). Real incident this exists because of: dalfox exits 1 the instant it finds
something (a common CI/CD "non-zero = findings present" convention) — under the old {0}-only
hardcoded rule, the one run that actually found an XSS was the exact run run_tool marked "error"
and skipped handing to its output parser, silently making the tool look broken precisely when it
worked. Uses a real python3 subprocess (not a mocked subprocess.run) — same philosophy as
test_exploit_db_run.py: the real exit-code-to-status mapping is exactly what needs proving
correct, not mocked away.
"""
from agent.tools.registry import ToolSpec
from agent.tools.runner import run_tool


def _spec_exiting_with(code: int, ok_exit_codes: frozenset[int] = frozenset({0})) -> ToolSpec:
    return ToolSpec(
        name="fake_tool",
        category="scan",
        tool_tier=2,
        executable="python3",
        build_command=lambda params: ["python3", "-c", f"import sys; print('hi'); sys.exit({code})"],
        requires_allowed_target=False,
        installed_by_default=True,
        ok_exit_codes=ok_exit_codes,
    )


def test_default_ok_exit_codes_only_accepts_zero():
    assert run_tool(_spec_exiting_with(0), {})["status"] == "ok"
    assert run_tool(_spec_exiting_with(1), {})["status"] == "error"


def test_a_tool_can_widen_ok_exit_codes_to_include_a_findings_present_convention():
    """Same shape as dalfox's real registration: exit 1 also means "ok, ran fine, found
    something" for a tool that uses that convention."""
    spec_with_widened_codes = _spec_exiting_with(1, ok_exit_codes=frozenset({0, 1}))
    result = run_tool(spec_with_widened_codes, {})
    assert result["status"] == "ok"
    assert result["exit_code"] == 1
    assert "hi" in result["stdout"]


def test_a_genuinely_unexpected_exit_code_is_still_an_error_even_with_widened_codes():
    spec_with_widened_codes = _spec_exiting_with(2, ok_exit_codes=frozenset({0, 1}))
    assert run_tool(spec_with_widened_codes, {})["status"] == "error"


def test_dalfox_itself_is_registered_with_the_findings_present_exit_code_included():
    import agent.tools  # noqa: F401 (side effect: populates TOOL_REGISTRY)
    from agent.tools.registry import get_tool

    spec = get_tool("dalfox")
    assert spec.ok_exit_codes == frozenset({0, 1})
