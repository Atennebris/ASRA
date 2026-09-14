"""agent/core.py's _apply_output_parser: a tool-specific failure hint (agent/tools/builders/
nuclei.py's interpret_nuclei_failure) must actually reach the model through the normal
result["error"]/1-Step-Retry-correction path, not just exist as an unused function.

Real incident this closes: a session guessed at 6+ nonexistent nuclei -tags combinations
(cookies-without-httponly,cookies-without-secure / cookie-security / ...) across many separate
1-Step Retry round-trips, each one only ever seeing nuclei's raw ANSI-colored banner ending in
"[FTL] Could not run nuclei: no templates provided for scan" -- no actionable signal at all.
"""
import asyncio
import json

import agent.core as core
from agent.core import RunContext, _apply_output_parser, _run_tool_with_retry
from agent.llm_client import LLMResponse
from agent.tools.registry import ToolSpec

_REAL_NO_TEMPLATES_STDERR = (
    "[INF] Scan completed in 314.937µs. No results found.\n"
    "[FTL] Could not run nuclei: no templates provided for scan\n"
)


def _run(coro):
    return asyncio.run(coro)


def _make_nuclei_spec() -> ToolSpec:
    return ToolSpec(
        name="nuclei", category="scan", tool_tier=2, executable="nuclei",
        build_command=lambda params: ["nuclei", "-u", params["target"], "-jsonl", "-tags", params.get("tags", "")],
        requires_allowed_target=False, installed_by_default=True,
    )


def test_apply_output_parser_replaces_the_error_with_a_clear_hint_for_a_tag_miss():
    spec = _make_nuclei_spec()
    raw_result = {"status": "error", "tool": "nuclei", "stdout": "", "stderr": _REAL_NO_TEMPLATES_STDERR}

    result = _apply_output_parser(spec, raw_result)

    assert "must exactly match a real template's own tag" in result["error"]
    # The raw stderr is preserved underneath, just no longer what the model/log sees first.
    assert result["stderr"] == _REAL_NO_TEMPLATES_STDERR


def test_apply_output_parser_leaves_an_unrelated_nuclei_failure_alone():
    spec = _make_nuclei_spec()
    raw_result = {"status": "error", "tool": "nuclei", "stdout": "", "stderr": "connection refused"}

    result = _apply_output_parser(spec, raw_result)

    assert result.get("error") is None


def test_apply_output_parser_leaves_a_tool_with_no_registered_hint_unchanged():
    spec = ToolSpec(name="sqlmap", category="exploit", tool_tier=2, executable="sqlmap", build_command=lambda p: [], requires_allowed_target=True, installed_by_default=True)
    raw_result = {"status": "error", "tool": "sqlmap", "stderr": "no templates provided for scan (coincidental unrelated text)"}

    assert _apply_output_parser(spec, raw_result) == raw_result


class _RecordingLLM:
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def __init__(self):
        self.seen_messages = None

    def complete(self, messages, tools=None, stop_check=None):
        self.seen_messages = messages
        return LLMResponse(content=json.dumps({"arguments": {"target": "https://example.com", "tags": "cookie"}}), tool_calls=[])


def test_end_to_end_retry_correction_prompt_contains_the_hint_not_the_raw_banner(monkeypatch):
    session = {"session_id": "usr_nuclei_hint_e2e", "logs": []}
    llm = _RecordingLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_nuclei_spec()

    monkeypatch.setattr(core, "run_tool", lambda spec, args: {
        "status": "error", "tool": "nuclei", "stdout": "",
        "stderr": _REAL_NO_TEMPLATES_STDERR,
        "command": ["nuclei", "-u", args["target"], "-jsonl", "-tags", args.get("tags", "")],
    })

    _run(_run_tool_with_retry(ctx, spec, {"target": "https://example.com", "tags": "cookies-without-httponly"}))

    assert llm.seen_messages is not None
    correction_text = llm.seen_messages[1]["content"]
    assert "must exactly match a real template's own tag" in correction_text
    assert "FTL" not in correction_text  # the raw banner noise never reaches the model anymore
