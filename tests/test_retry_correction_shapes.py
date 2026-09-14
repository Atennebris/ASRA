"""_run_tool_with_retry's 1-Step Retry correction handling: real, confirmed gaps in the same area,
found during cross-project log-review audits.

1. The correction handler required the model's reply to be wrapped as {"arguments": {...}} and
   rejected a validly-corrected-but-unwrapped reply outright as "unparsable" -- confirmed live
   twice independently (a real session usr_c94c8c, and public-firing-range-usr_8eecba), including one
   case where the corrected payload was itself perfectly usable, just not wrapped the way the
   correction prompt asked for.
2. When the retry attempt itself ends in a retryable-but-textless status (a second timeout, most
   commonly), the code overwrote status to "failed" without preserving the original status or
   synthesizing any error text -- confirmed live (a real session, usr_bb205e): the resulting session log
   entry read "status": "failed", "error": null, giving a human reviewing the session zero
   information that this was actually a timeout.
3. A genuinely truncated (not malformed-from-the-start) correction reply used to be discarded
   outright with no repair attempt, unlike 4 other places in this same file that already call
   _repair_json_reply for exactly this shape -- confirmed live (a real rescan session, usr_68238a):
   finish_reason="stop" (a real, complete-as-sent answer), object cut off mid-field.
"""
import asyncio
import json

import agent.core as core
from agent.core import RunContext, _model_visible_arguments, _run_tool_with_retry
from agent.llm_client import LLMResponse
from agent.tools.registry import ToolSpec

# --- _model_visible_arguments: strips server-injected "_"-prefixed fields ---


def test_model_visible_arguments_strips_underscore_prefixed_keys():
    assert _model_visible_arguments({
        "target": "https://example.com", "_session_id": "usr_x", "_session": {"findings": []},
    }) == {"target": "https://example.com"}


def test_model_visible_arguments_keeps_everything_when_nothing_is_injected():
    assert _model_visible_arguments({"target": "https://example.com", "method": "GET"}) == {
        "target": "https://example.com", "method": "GET",
    }


# --- schema grounding: the correction call must see the tool's own real parameter names ---


class _CapturingCorrectionLLM:
    """Records the messages it was actually sent, then replies with a fixed correction --
    verifies WHAT the correction call asks for, not just whether it can parse a reply."""
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def __init__(self, correction_content: str):
        self._correction_content = correction_content
        self.seen_messages: list[dict] | None = None

    def complete(self, messages, tools=None, stop_check=None):
        self.seen_messages = messages
        return LLMResponse(content=self._correction_content, tool_calls=[])


def test_retry_correction_prompt_includes_the_tools_real_parameter_names():
    """Real, confirmed incident this fixes: arjun timed out twice against a WAF-slowed target;
    both retries sent "url" instead of the real required field "target" and failed identically
    both times, costing 58% of a 42-minute Analyze phase -- the correction call had zero schema
    grounding, so a plausible-but-wrong field name couldn't be caught."""
    def native_function(args: dict) -> dict:
        return {"status": "error", "error": "target is required"}

    spec = ToolSpec(
        name="arjun", category="scan", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL to probe for hidden parameters"},
                "method": {"type": "string"},
            },
        },
    )
    llm = _CapturingCorrectionLLM(json.dumps({"arguments": {"target": "https://example.com"}}))
    session = {"session_id": "usr_schema_grounding_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_tool_with_retry(ctx, spec, {"url": "https://example.com"}))

    assert llm.seen_messages is not None
    correction_prompt_text = " ".join(m["content"] for m in llm.seen_messages)
    assert '"target"' in correction_prompt_text
    assert "URL to probe for hidden parameters" not in correction_prompt_text  # names only, not full descriptions -- stays compact


def test_retry_correction_prompt_excludes_server_injected_internal_fields():
    """Real, confirmed incident this fixes (live session Safety-Bug-Bounty-usr_158b31): for a tool
    that gets _session injected (delegate_to_subagent, check_subagent_task, browser_*, ...), the
    correction prompt used to json.dumps() the POST-injection arguments dict verbatim -- including
    _session, the ENTIRE session dict (every finding, every log line, every chat thread). On a
    mature real session this alone blew the prompt past every provider's context limit (285k+
    tokens observed live), which then cascaded through six provider fallbacks over two and a half
    minutes before giving up outright. Only the model's OWN supplied arguments (never a
    "_"-prefixed server-injected one) belong in a prompt shown back to it.
    """
    def native_function(args: dict) -> dict:
        return {"status": "error", "error": "no enabled subagent named 'subdns'"}

    spec = ToolSpec(
        name="delegate_to_subagent", category="post_exploit", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
        parameters_schema={
            "type": "object",
            "properties": {"subagent_name": {"type": "string"}, "task_description": {"type": "string"}},
        },
    )
    llm = _CapturingCorrectionLLM(json.dumps({"arguments": {"subagent_name": "subdns", "task_description": "enumerate one subdomain"}}))
    # A distinctive marker standing in for "a mature real session's worth of findings/logs" --
    # session_id, subagent_name, task_description are all genuinely small; only _session (the
    # server-injected live session dict) could ever carry something this large.
    session = {"session_id": "usr_injection_leak_test", "logs": [], "findings": [{"title": "MARKER_" + ("x" * 500)}]}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_tool_with_retry(ctx, spec, {"subagent_name": "subdns", "task_description": "enumerate one subdomain"}))

    assert llm.seen_messages is not None
    correction_prompt_text = " ".join(m["content"] for m in llm.seen_messages)
    assert "MARKER_" not in correction_prompt_text
    assert "_session" not in correction_prompt_text
    # The model's own real arguments must still be there -- this excludes the injected fields, not
    # everything.
    assert "subdns" in correction_prompt_text


def test_retry_correction_prompt_falls_back_to_real_help_text_for_a_schemaless_tool(monkeypatch):
    """Real, confirmed incident this fixes: a generic/discovered tool (httpx, whatweb, ffuf, ...)
    has no real parameters_schema of its own, so schema_hint above comes out empty -- the
    correction retry had nothing but the tool's bare name to go on, unlike a schema-backed tool
    like arjun. The model DOES see this tool's real --help text on the ORIGINAL call
    (_tool_description already pulls it in) -- this fix threads the same text into the one
    correction retry that matters most, instead of leaving it with nothing."""
    def native_function(args: dict) -> dict:
        return {"status": "error", "error": "flag provided but not defined: -tls-verify"}

    spec = ToolSpec(
        name="httpx", category="scan", tool_tier=1, executable="httpx", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
        parameters_schema=None,
    )
    monkeypatch.setattr(core, "get_tool_help", lambda name, executable, full_description: "Usage: httpx [flags]\n  -sc, -status-code  display response status-code")
    llm = _CapturingCorrectionLLM(json.dumps({"arguments": {"target": "https://example.com"}}))
    session = {"session_id": "usr_help_fallback_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_tool_with_retry(ctx, spec, {"target": "https://example.com", "extra_args": ["-tls-verify"]}))

    assert llm.seen_messages is not None
    correction_prompt_text = " ".join(m["content"] for m in llm.seen_messages)
    assert "-status-code" in correction_prompt_text


def _run(coro):
    return asyncio.run(coro)


class _ScriptedCorrectionLLM:
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def __init__(self, correction_content: str):
        self._correction_content = correction_content

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content=self._correction_content, tool_calls=[])


def _make_tool(native_function) -> ToolSpec:
    return ToolSpec(
        name="dns_lookup", category="recon", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
    )


def test_retry_accepts_a_correction_sent_without_the_arguments_envelope(tmp_path, monkeypatch):
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        if len(calls) == 1:
            return {"status": "error", "error": "domain is required"}
        return {"status": "ok", "resolved": "1.2.3.4"}

    # The model replies with the corrected parameters DIRECTLY, no {"arguments": {...}} wrapper --
    # a real, observed shape this fix tolerates instead of discarding as unparsable.
    llm = _ScriptedCorrectionLLM(json.dumps({"domain": "example.com"}))
    session = {"session_id": "usr_unwrapped_retry_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_tool(native_function)

    result = _run(_run_tool_with_retry(ctx, spec, {}))

    assert result["status"] == "ok"
    assert result["used_arguments"]["domain"] == "example.com"
    assert len(calls) == 2


def test_retry_still_gives_up_on_a_correction_with_no_usable_shape(tmp_path, monkeypatch):
    def native_function(args: dict) -> dict:
        return {"status": "error", "error": "domain is required"}

    # Genuinely empty/unusable replies must still be rejected -- this fix only widens what counts
    # as a usable correction, it doesn't accept literally anything.
    for garbage in ("not json at all", json.dumps({}), json.dumps(None), json.dumps("just a string")):
        llm = _ScriptedCorrectionLLM(garbage)
        session = {"session_id": "usr_garbage_retry_test", "logs": []}
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
        spec = _make_tool(native_function)

        result = _run(_run_tool_with_retry(ctx, spec, {}))

        assert result["status"] == "failed"


def test_retry_prefers_the_wrapped_arguments_shape_when_both_are_plausible():
    """If the model DOES send the proper {"arguments": {...}} envelope, that's used as-is --
    the unwrapped fallback only ever kicks in when "arguments" is genuinely absent."""
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        if len(calls) == 1:
            return {"status": "error", "error": "domain is required"}
        return {"status": "ok"}

    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"domain": "wrapped.example.com"}}))
    session = {"session_id": "usr_wrapped_retry_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_tool(native_function)

    result = _run(_run_tool_with_retry(ctx, spec, {}))

    assert result["status"] == "ok"
    assert result["used_arguments"]["domain"] == "wrapped.example.com"


def test_retry_that_fails_again_with_no_error_text_gets_a_synthesized_reason():
    def native_function(args: dict) -> dict:
        # Both attempts end in a retryable status with no error text at all -- the exact shape a
        # real second timeout produces (status="timeout", exit_code=None, error=None).
        return {"status": "timeout"}

    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"domain": "example.com"}}))
    session = {"session_id": "usr_double_timeout_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_tool(native_function)

    result = _run(_run_tool_with_retry(ctx, spec, {"domain": "x"}))

    assert result["status"] == "failed"
    assert result["error"]
    assert "timeout" in result["error"]


class _TruncatedThenRepairedLLM:
    """First call (the correction itself): a genuinely truncated JSON object -- missing its final
    closing brace, the exact real shape confirmed live. Second call (the repair attempt): a
    complete, valid correction."""
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def __init__(self):
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self.calls_made == 1:
            return LLMResponse(content='{"arguments": {"domain": "example.com"', tool_calls=[])
        return LLMResponse(content=json.dumps({"arguments": {"domain": "example.com"}}), tool_calls=[])


def test_retry_repairs_a_truncated_correction_reply_instead_of_giving_up(tmp_path, monkeypatch):
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        if len(calls) == 1:
            return {"status": "error", "error": "domain is required"}
        return {"status": "ok"}

    llm = _TruncatedThenRepairedLLM()
    session = {"session_id": "usr_truncated_correction_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_tool(native_function)

    result = _run(_run_tool_with_retry(ctx, spec, {}))

    assert llm.calls_made == 2  # the correction call, plus exactly one repair attempt
    assert result["status"] == "ok"
    assert result["used_arguments"]["domain"] == "example.com"


def test_retry_skips_a_second_dispatch_when_timeout_correction_repeats_identical_arguments():
    """Real, confirmed incident this fixes (midnight-usr_24ba7e): nmap timed out against a
    genuinely unresponsive host (TOOL_TIMEOUT_SECONDS=600 in the real .env), and the correction
    call replied with arguments byte-identical to the ones that had just timed out (confirmed live:
    `{"arguments": {"target": "5.252.32.97"}}` -- nmap's own schema exposes only "target", nothing
    else for the model to correct). Re-dispatching burned a second full subprocess timeout for a
    guaranteed-identical result -- duration_ms=1237347 (~2x TOOL_TIMEOUT_SECONDS) for zero benefit,
    then repeated again on the next resume a day later against the same host."""
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        return {"status": "timeout"}

    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"target": "5.252.32.97"}}))
    session = {"session_id": "usr_identical_timeout_retry_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = ToolSpec(
        name="slow_scan_test_tool", category="recon", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
    )

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "5.252.32.97"}))

    assert len(calls) == 1  # the retry was never actually re-dispatched
    assert result["status"] == "failed"
    assert result["retried"] is True
    assert "identical" in result["error"]


def test_retry_still_dispatches_when_timeout_correction_gives_different_arguments():
    """Regression guard for the fix above: a corrected retry with genuinely different arguments
    must still run normally after a timeout -- only a byte-identical correction is skipped."""
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        if len(calls) == 1:
            return {"status": "timeout"}
        return {"status": "ok"}

    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"target": "other-host.example.com"}}))
    session = {"session_id": "usr_different_timeout_retry_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = ToolSpec(
        name="slow_scan_test_tool", category="recon", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
    )

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "5.252.32.97"}))

    assert len(calls) == 2  # a real, different correction still gets dispatched
    assert result["status"] == "ok"


def test_run_tool_with_retry_injects_session_id_for_custom_re_script():
    """Real, confirmed incident this fixes (hcm-usr_15eee7, NinthCircle-crackmes-usr_04a301):
    custom_re_script (agent/tools/__init__.py) reuses custom_exploit_run's own native_function
    wholesale under a second tool name for RE mode, but the injected{} block above only ever
    matched the literal name "custom_exploit_run" -- every custom_re_script call had
    params["_session_id"] come through as None, so native.py's _exploit_scripts_dir always fell
    back to the global app dir instead of the session's own project folder. Confirmed live: 397
    script/log file pairs (~60MB) from real RE sessions accumulated in Documents/ASRA/scripts/
    instead of each session's own folder, even though those same sessions' OTHER RE tools
    (radare2, gdb) correctly wrote their own per-session artifacts the whole time."""
    captured = {}

    def native_function(args: dict) -> dict:
        captured["session_id"] = args.get("_session_id")
        return {"status": "ok"}

    spec = ToolSpec(
        name="custom_re_script", category="re", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
    )
    session = {"session_id": "usr_re_script_scoping_test", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_run_tool_with_retry(ctx, spec, {"source": "print('ok')"}))

    assert captured["session_id"] == "usr_re_script_scoping_test"


def test_run_tool_with_retry_injects_session_id_for_tshark_capture():
    """tshark_capture (agent/tools/builders/tshark.py) keys its saved .pcap's location off
    _session_id the exact same way custom_re_script keys its scripts/ folder off it (test right
    above) -- same injection tuple, same reasoning: without it every capture would fall back to
    the global app dir instead of this session's own project folder. executable="true" (a real,
    instant, side-effect-free binary present on any Linux/WSL2 machine, exit code 0) -- lets
    build_command actually get reached and its status come back "ok" with no real tshark install
    needed and no 1-Step Retry triggered (this test's ctx.llm=None couldn't service one anyway)."""
    captured = {}

    def build_command(params: dict) -> list[str]:
        captured["session_id"] = params.get("_session_id")
        return ["true"]

    spec = ToolSpec(
        name="tshark_capture", category="re", tool_tier=2, executable="true", build_command=build_command,
        requires_allowed_target=False, installed_by_default=True,
    )
    session = {"session_id": "usr_tshark_scoping_test", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    result = _run(_run_tool_with_retry(ctx, spec, {}))

    assert result["status"] == "ok"
    assert captured["session_id"] == "usr_tshark_scoping_test"


def test_retry_that_fails_again_with_real_error_text_keeps_it_unchanged():
    """The synthesized fallback must never overwrite a real error the retry actually produced."""
    def native_function(args: dict) -> dict:
        return {"status": "error", "error": "connection refused"}

    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"domain": "example.com"}}))
    session = {"session_id": "usr_real_error_retry_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_tool(native_function)

    result = _run(_run_tool_with_retry(ctx, spec, {"domain": "x"}))

    assert result["status"] == "failed"
    assert result["error"] == "connection refused"


# --- used_arguments must never carry the injected _session through to the operator/model ---


def _make_session_injected_tool(native_function) -> ToolSpec:
    # hydra_start is one of the names _run_tool_with_retry's own injected{} block gives the full
    # live _session/_session_id to (agent/background_jobs.py mutates the session dict in place),
    # and — unlike delegate_to_subagent/browser_* — still goes through the generic native_function
    # dispatch path, so a plain custom native_function here is enough to exercise it.
    return ToolSpec(
        name="hydra_start", category="exploit", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native_function,
    )


def test_run_tool_with_retry_strips_injected_session_from_used_arguments_on_first_success():
    """Real, confirmed incident this fixes (live session Safety-Bug-Bounty-usr_158b31):
    used_arguments carried the full POST-injection arguments (including the entire live _session --
    every finding, every log line, every chat thread) straight into the tool's own result. Shown to
    the operator as a garbled, character-limit-truncated wall of session data instead of a clean
    result, AND fed back to the model as the next turn's own "tool" role message content."""
    def native_function(args: dict) -> dict:
        return {"status": "ok"}

    spec = _make_session_injected_tool(native_function)
    session = {"session_id": "usr_used_args_leak_test", "logs": [], "findings": [{"title": "MARKER_" + ("x" * 500)}]}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "ssh://example.com"}))

    assert result["status"] == "ok"
    assert "_session" not in result["used_arguments"]
    assert "_session_id" not in result["used_arguments"]
    assert result["used_arguments"]["target"] == "ssh://example.com"
    assert "MARKER_" not in json.dumps(result)


def test_run_tool_with_retry_strips_injected_session_from_used_arguments_on_retry():
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        if len(calls) == 1:
            return {"status": "error", "error": "target is required"}
        return {"status": "ok"}

    spec = _make_session_injected_tool(native_function)
    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"target": "ssh://example.com"}}))
    session = {"session_id": "usr_used_args_leak_retry_test", "logs": [], "findings": [{"title": "MARKER_" + ("x" * 500)}]}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    result = _run(_run_tool_with_retry(ctx, spec, {}))

    assert result["status"] == "ok"
    assert len(calls) == 2
    assert "_session" not in result["used_arguments"]
    assert "MARKER_" not in json.dumps(result)


def test_retry_flags_when_the_correction_silently_swaps_in_a_different_host():
    """Real, confirmed incident this fixes (test-2-again2-usr_2f4db1): a failed
    security_headers_audit against "mail.z8games.com" came back from the correction call
    "fixed" to "z8games.com" -- a completely different host, not a fix to the original call --
    and _run_tool_with_retry logged it as a plain "retried succeeded" with nothing flagging the
    swap. A model or an operator reading the result now sees target_changed_by_retry."""
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        if len(calls) == 1:
            return {"status": "error", "error": "connection refused"}
        return {"status": "ok"}

    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"domain": "z8games.com"}}))
    session = {"session_id": "usr_retry_target_swap_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_tool(native_function)

    result = _run(_run_tool_with_retry(ctx, spec, {"domain": "mail.z8games.com"}))

    assert len(calls) == 2
    assert result["status"] == "ok"
    assert result["target_changed_by_retry"] == {"from": "mail.z8games.com", "to": "z8games.com"}


def test_retry_does_not_flag_a_correction_that_keeps_the_same_host():
    """Regression guard for the fix above: a correction that only changes shape (bare host to a
    full URL for the SAME host) must not be flagged -- only a genuinely different host should be."""
    calls = []

    def native_function(args: dict) -> dict:
        calls.append(dict(args))
        if len(calls) == 1:
            return {"status": "error", "error": "malformed url"}
        return {"status": "ok"}

    llm = _ScriptedCorrectionLLM(json.dumps({"arguments": {"domain": "https://mail.z8games.com/"}}))
    session = {"session_id": "usr_retry_same_host_test", "logs": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    spec = _make_tool(native_function)

    result = _run(_run_tool_with_retry(ctx, spec, {"domain": "mail.z8games.com"}))

    assert len(calls) == 2
    assert result["status"] == "ok"
    assert "target_changed_by_retry" not in result
