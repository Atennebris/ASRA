"""agent/core.py's _describe_command: the log line shown for a native (tier-1) tool call must
reflect whichever attempt actually produced the given result, not the model's original
pre-retry arguments.

Real incident this fixes (found during a log-review audit of a completed rescan session):
authenticated_request({"identity": "user_a", ...}) failed, 1-Step Retry corrected it to
identity="default", which ALSO failed -- the session log recorded the command with
identity="user_a" right next to the retry's own error, "No credentials configured for identity
'default'". Both facts were individually true (two different, real attempts), but paired together
in one log line they read as if the tool reported the wrong identity for what it was asked to do.
Root cause: _run_tool_with_retry always sets result["used_arguments"] to whichever arguments
actually ran (the retry's, if one happened) -- but _describe_command's fallback branch (native
tools have no result["command"] the way subprocess tools do) built its string from the ORIGINAL
call.arguments instead of ever reading used_arguments.
"""
import asyncio
import json

from agent.core import RunContext, ToolCallRequest, _describe_command, _run_tool_with_retry
from agent.llm_client import LLMResponse
from agent.tools.registry import ToolSpec


def _run(coro):
    return asyncio.run(coro)


class _CorrectingLLM:
    """Always fails: correction messages are a system+user pair produced by _run_tool_with_retry
    itself -- .complete() just returns whatever corrected identity this test wants to simulate."""
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def __init__(self, corrected_arguments: dict):
        self._corrected_arguments = corrected_arguments

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content=json.dumps({"arguments": self._corrected_arguments}), tool_calls=[])


def _make_failing_identity_tool() -> ToolSpec:
    def native_function(args: dict) -> dict:
        identity = args.get("identity")
        return {"status": "error", "error": f"No credentials configured for identity {identity!r} on this project"}

    return ToolSpec(
        name="authenticated_request", category="exploit", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
    )


def test_describe_command_uses_used_arguments_not_the_original_pre_retry_call():
    """Direct unit test of the pure function: even with no LLM/retry involved, used_arguments
    (whenever a caller sets it) must win over the original call.arguments."""
    call = ToolCallRequest(id="1", name="authenticated_request", arguments={"identity": "user_a"})
    result = {"status": "error", "error": "boom", "used_arguments": {"identity": "default"}}

    assert _describe_command(call, result) == 'authenticated_request({"identity": "default"})'


def test_describe_command_falls_back_to_call_arguments_when_used_arguments_is_absent():
    """Backward-compatible default for any result that never went through _run_tool_with_retry."""
    call = ToolCallRequest(id="1", name="authenticated_request", arguments={"identity": "user_a"})
    result = {"status": "error", "error": "boom"}

    assert _describe_command(call, result) == 'authenticated_request({"identity": "user_a"})'


def test_describe_command_prefers_a_real_subprocess_command_list_regardless():
    call = ToolCallRequest(id="1", name="nmap", arguments={"target": "example.com"})
    result = {"status": "ok", "command": ["nmap", "-F", "-sV", "example.com"], "used_arguments": {"target": "example.com"}}

    assert _describe_command(call, result) == "nmap -F -sV example.com"


# --- _describe_command strips server-side-injected fields: real, catastrophic incident ---


def test_describe_command_strips_injected_underscore_prefixed_fields():
    """Real incident this fixes: check_subagent_task/delegate_to_subagent/hydra_start/
    web_login_bruteforce_start/background_job_check all get the REAL, LIVE session dict injected
    as their own "_session" argument (their native functions genuinely need it) -- the logged
    command string must never include it, only the arguments a human/the model actually supplied.
    """
    call = ToolCallRequest(id="1", name="check_subagent_task", arguments={"task_id": "abc123"})
    result = {
        "status": "ok",
        "used_arguments": {"task_id": "abc123", "_session_id": "usr_x", "_session": {"logs": ["a lot of prior state"]}},
    }

    described = _describe_command(call, result)

    assert described == 'check_subagent_task({"task_id": "abc123"})'
    assert "_session" not in described


def test_describe_command_stays_bounded_even_with_a_huge_injected_session():
    """The actual failure mode, reproduced: a real session's own "_session" dict grows every poll
    (each check_subagent_task call embeds it, and that embedded copy lands right back in
    session["logs"] -- see the runtime incident this whole fix set closes). Confirms the fix
    actually breaks that feedback loop, not just that a small example happens to look right.
    """
    huge_session = {"session_id": "usr_x", "logs": [{"command": "x" * 500_000} for _ in range(20)]}
    call = ToolCallRequest(id="1", name="check_subagent_task", arguments={"task_id": "abc123"})
    result = {"status": "ok", "used_arguments": {"task_id": "abc123", "_session_id": "usr_x", "_session": huge_session}}

    described = _describe_command(call, result)

    assert described == 'check_subagent_task({"task_id": "abc123"})'
    assert len(described) < 100  # not the ~10MB it would be if "_session" leaked through


def test_describe_command_keeps_non_underscore_arguments_intact():
    """The filter is scoped to a leading underscore specifically -- a real argument that happens
    to share a substring with an injected field name must never be caught by it."""
    call = ToolCallRequest(id="1", name="authenticated_request", arguments={"identity": "user_a", "session_hint": "not injected"})
    result = {"status": "ok", "used_arguments": {"identity": "user_a", "session_hint": "not injected", "_session": "the real live dict"}}

    described = _describe_command(call, result)

    assert '"identity": "user_a"' in described
    assert '"session_hint": "not injected"' in described
    assert "the real live dict" not in described


def test_end_to_end_retry_with_a_different_identity_logs_the_retrys_own_arguments(tmp_path, monkeypatch):
    """Full path: a real _run_tool_with_retry call whose 1-Step Retry corrects identity="user_a"
    to identity="default", both failing -- the resulting log description must show identity=
    "default" (what the retry that produced this error actually ran), never the original
    "user_a" the model first tried.
    """
    session = {"session_id": "usr_retry_log_test", "logs": []}
    ctx = RunContext(llm=_CorrectingLLM({"identity": "default"}), session=session, session_id=session["session_id"])
    spec = _make_failing_identity_tool()
    call = ToolCallRequest(id="1", name="authenticated_request", arguments={"identity": "user_a"})

    result = _run(_run_tool_with_retry(ctx, spec, call.arguments))

    assert result["status"] == "failed"
    # _run_tool_with_retry injects _session_id server-side for this tool name -- irrelevant to
    # what this test is verifying (the "identity" field's own before/after retry value).
    assert result["used_arguments"]["identity"] == "default"
    assert "identity 'default'" in result["error"]

    description = _describe_command(call, result)
    assert '"identity": "default"' in description
    # The bug this guards against: showing the ORIGINAL identity next to the RETRY's error.
    assert "user_a" not in description
