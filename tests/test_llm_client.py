"""Unit tests for agent/llm_client.py. Mocking happens via unittest.mock.patch.object on the
exact method that would otherwise hit the network (OpenAI SDK's chat.completions.create, or
models_dev's capability lookup) -- with one deliberate exception: _fetch_local_model_ids uses raw
httpx directly, not the openai SDK client (see that function's own docstring for the real,
confirmed reason), so its own tests mock at the httpx.Client/MockTransport level instead, same
pattern tests/test_web_fetch.py already uses for its own raw-httpx-based tool.
"""
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import openai
import pytest
from openai import Omit

import agent.llm_client as llm_client
from agent.llm_client import (
    EmptyResponseError,
    LLMCallAborted,
    OpenAICompatProvider,
    PROVIDER_REGISTRY,
    _call_with_backoff,
    _create_completion_with_backoff,
    _extract_prompt_tool_calls,
    _inject_tool_instructions,
    _is_retryable,
    _merge_consecutive_system_messages,
    _parse_retry_after,
    _parse_tool_call_arguments,
    get_provider,
)


def _fake_response(content, tool_calls=None, finish_reason="stop"):
    message = SimpleNamespace(content=content, tool_calls=tool_calls or [])
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish_reason)])


def _fake_tool_call(call_id, name, arguments_json):
    return SimpleNamespace(id=call_id, function=SimpleNamespace(name=name, arguments=arguments_json))


def _bad_request_error():
    request = SimpleNamespace(method="POST", url="https://example.test/v1/chat/completions")
    response = SimpleNamespace(status_code=400, headers={}, request=request)
    return openai.BadRequestError("tools not supported", response=response, body=None)


# --- pure functions, no mocking needed ---


def test_merge_consecutive_system_messages_collapses_run():
    messages = [
        {"role": "system", "content": "a"},
        {"role": "system", "content": "b"},
        {"role": "user", "content": "c"},
    ]
    merged = _merge_consecutive_system_messages(messages)
    assert merged == [{"role": "system", "content": "a\n\nb"}, {"role": "user", "content": "c"}]


def test_merge_consecutive_system_messages_leaves_non_consecutive_alone():
    messages = [{"role": "system", "content": "a"}, {"role": "user", "content": "b"}, {"role": "system", "content": "c"}]
    assert _merge_consecutive_system_messages(messages) == messages


@pytest.mark.parametrize(
    "status_code, expected",
    [(429, True), (500, True), (503, True), (400, False), (401, False), (404, False)],
)
def test_is_retryable(status_code, expected):
    exc = SimpleNamespace(status_code=status_code)
    assert _is_retryable(exc) is expected


def test_parse_retry_after_reads_header():
    exc = SimpleNamespace(response=SimpleNamespace(headers={"retry-after": "3.5"}))
    assert _parse_retry_after(exc) == 3.5


def test_parse_retry_after_missing_header_returns_none():
    exc = SimpleNamespace(response=SimpleNamespace(headers={}))
    assert _parse_retry_after(exc) is None


def test_parse_retry_after_non_numeric_header_returns_none():
    exc = SimpleNamespace(response=SimpleNamespace(headers={"retry-after": "not-a-number"}))
    assert _parse_retry_after(exc) is None


def _rate_limited_error(retry_after_header):
    request = SimpleNamespace(method="POST", url="https://example.test/v1/chat/completions")
    response = SimpleNamespace(status_code=429, headers={"retry-after": retry_after_header}, request=request)
    return openai.APIStatusError("rate limited", response=response, body=None)


def _connection_error():
    request = httpx.Request("POST", "https://example.test/v1/chat/completions")
    return openai.APIConnectionError(message="connection dropped", request=request)


def test_call_with_backoff_tags_its_own_debug_lines_with_the_active_session_id(monkeypatch, tmp_path):
    """Real, confirmed gap this closes: with several concurrent LLM calls in flight (the main loop
    plus one or more delegated subagents, all sharing this one module-level logger), their
    retry-attempt debug lines interleaved with no way to tell which call chain a line belonged to --
    confirmed live during a real log-review audit, genuinely misreading two/three independent retry
    sequences as one. Uses the same is_debug_enabled/real-file-handler pattern
    tests/test_verify_all.py's own SESSION-log tests already establish, since asserting on actual
    persisted debug.log content is what proves the tag reaches the real log line, not just that
    logger.debug() was called with some arguments."""
    import logging

    import agent.utils.debug as debug_mod
    import agent.utils.logger as logger_mod

    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)
    monkeypatch.setattr(debug_mod, "is_debug_enabled", lambda: True)
    logging.getLogger("asra.LLM").handlers.clear()
    logger_mod._configured.discard("LLM")
    logger_mod.get_logger("LLM")
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)
    token = debug_mod.current_session_id.set("usr_llm_tag_test")
    try:
        attempts = {"count": 0}

        def request_fn():
            attempts["count"] += 1
            if attempts["count"] == 1:
                raise _rate_limited_error("1")
            return "ok"

        assert _call_with_backoff(request_fn) == "ok"
    finally:
        debug_mod.current_session_id.reset(token)
        logging.getLogger("asra.LLM").handlers.clear()
        logger_mod._configured.discard("LLM")

    log_content = (tmp_path / "debug.log").read_text(encoding="utf-8")
    assert "session=usr_llm_tag_test" in log_content


def test_call_with_backoff_caps_server_retry_after(monkeypatch):
    """A shared/free endpoint under load can send back a Retry-After of many minutes — honoring it
    verbatim blocks the whole request for that long with nothing logged in between (the real
    incident this cap exists for: a scan sat silent for close to an hour on one retryable 429).
    """
    monkeypatch.setenv("LLM_MAX_RETRY_AFTER_SECONDS", "30")
    sleep_calls = []
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    attempts = {"count": 0}

    def request_fn():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise _rate_limited_error("3600")
        return "ok"

    assert _call_with_backoff(request_fn) == "ok"
    assert sleep_calls == [30.0]


def test_call_with_backoff_honors_short_server_retry_after(monkeypatch):
    monkeypatch.setenv("LLM_MAX_RETRY_AFTER_SECONDS", "30")
    sleep_calls = []
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    attempts = {"count": 0}

    def request_fn():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise _rate_limited_error("5")
        return "ok"

    assert _call_with_backoff(request_fn) == "ok"
    assert sleep_calls == [5.0]


def test_call_with_backoff_aborts_promptly_when_stop_check_flips_mid_wait(monkeypatch):
    """Real incident this fixes: an operator's Stop click during a 429 backoff wait sat completely
    ignored until every remaining retry attempt (and its own wait) had run its course, because the
    old time.sleep(wait_seconds) call had no way to be interrupted once started. stop_check is now
    polled every _STOP_POLL_INTERVAL_SECONDS during a wait, so Stop lands within one poll interval
    instead of only between whole retry attempts.
    """
    monkeypatch.setenv("LLM_MAX_RETRY_AFTER_SECONDS", "30")
    monkeypatch.setattr(llm_client, "_STOP_POLL_INTERVAL_SECONDS", 1.0)
    sleep_calls = []
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    def request_fn():
        # A long server-dictated Retry-After (capped at 30s) -- without prompt interruption this
        # would otherwise block for the full 30s before the caller ever gets a chance to notice.
        raise _rate_limited_error("3600")

    def stop_check():
        return len(sleep_calls) >= 2

    with pytest.raises(LLMCallAborted):
        _call_with_backoff(request_fn, stop_check=stop_check)

    # Aborted after two 1s poll chunks -- nowhere near exhausting the full capped 30s wait.
    assert sleep_calls == [1.0, 1.0]


def test_call_with_backoff_stop_check_never_true_behaves_like_no_stop_check(monkeypatch):
    """A stop_check that's always false must not change behavior at all -- same result, same
    sleep total, just polled in smaller slices."""
    monkeypatch.setattr(llm_client, "_STOP_POLL_INTERVAL_SECONDS", 1.0)
    sleep_calls = []
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: sleep_calls.append(seconds))

    attempts = {"count": 0}

    def request_fn():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise _rate_limited_error("2")
        return "ok"

    assert _call_with_backoff(request_fn, stop_check=lambda: False) == "ok"
    assert sum(sleep_calls) == 2.0


def test_call_with_backoff_reports_progress_through_the_context_var_sink(monkeypatch):
    """current_retry_progress_sink (Settings -> Test button's own live-attempt display,
    agent/tools/test_llm_job.py) must see every attempt, including the first one (before any wait
    happens at all) -- a ContextVar, not a parameter threaded through LLMProvider.complete() and
    every concrete implementation, precisely so this stays a no-op everywhere else (the main agent
    loop, subagents, ...) that never sets it."""
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)
    calls = []
    token = llm_client.current_retry_progress_sink.set(
        lambda attempt, total, wait_seconds: calls.append((attempt, total, wait_seconds))
    )

    attempts = {"count": 0}

    def request_fn():
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise _rate_limited_error("1")
        return "ok"

    try:
        assert _call_with_backoff(request_fn) == "ok"
    finally:
        llm_client.current_retry_progress_sink.reset(token)

    # attempt 1 reported up front (no wait yet), then once more per retry actually taken.
    assert calls[0] == (1, 6, 0.0)
    assert [c[0] for c in calls[1:]] == [2, 3]
    assert all(c[2] == 1.0 for c in calls[1:])


def test_call_with_backoff_progress_sink_is_a_noop_when_unset():
    """The normal case (main agent loop, subagents) never sets the sink -- must behave exactly as
    before, no AttributeError from treating an unset ContextVar's default None as callable."""
    assert _call_with_backoff(lambda: "ok") == "ok"


def test_call_with_backoff_accumulates_scheduled_sleep_time(monkeypatch):
    """current_backoff_accumulator (set by agent/core.py for the duration of one delegated
    subagent task) must gain the full scheduled backoff wait -- real, confirmed incident this
    fixes (a real HackerOne rescan session): a subagent's fixed timeout doesn't distinguish real
    work from time spent entirely in provider retry backoff, so a task that spent 43% of its whole
    budget retrying was misread as "slow/inefficient" instead of "provider was flaky"."""
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)
    accumulator: list[float] = [0.0]
    token = llm_client.current_backoff_accumulator.set(accumulator)
    attempts = {"count": 0}

    def request_fn():
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise _rate_limited_error("5")
        return "ok"

    try:
        assert _call_with_backoff(request_fn) == "ok"
    finally:
        llm_client.current_backoff_accumulator.reset(token)

    assert accumulator[0] == pytest.approx(5.0, abs=0.5)


def test_call_with_backoff_accumulates_time_spent_inside_a_doomed_request_too(monkeypatch):
    """Timed separately from the scheduled sleep above -- a request that hangs until IT times out
    (confirmed live: ~60-70s per attempt against a flaky free-tier provider, far longer than the
    scheduled 2/4/8s backoff delays) was the actual bulk of the lost time in the real incident, so
    counting only the explicit sleep would under-report it by an order of magnitude."""
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)
    fake_clock = {"now": 0.0}
    monkeypatch.setattr(llm_client.time, "monotonic", lambda: fake_clock["now"])
    accumulator: list[float] = [0.0]
    token = llm_client.current_backoff_accumulator.set(accumulator)
    attempts = {"count": 0}

    def request_fn():
        attempts["count"] += 1
        if attempts["count"] == 1:
            fake_clock["now"] += 65.0  # the doomed first attempt hangs for 65s before raising
            raise _connection_error()
        return "ok"

    try:
        assert _call_with_backoff(request_fn) == "ok"
    finally:
        llm_client.current_backoff_accumulator.reset(token)

    assert accumulator[0] >= 65.0


def test_call_with_backoff_accumulator_is_a_noop_when_unset():
    """The normal case (main agent loop, chat, Settings Test) never sets this -- must behave
    exactly as before, no AttributeError from treating an unset ContextVar's default None as a
    mutable list."""
    assert _call_with_backoff(lambda: "ok") == "ok"


def test_create_completion_with_backoff_retries_past_an_empty_choices_response(monkeypatch):
    """Real incident this fixes: opencode-zen's nemotron-3-ultra-free model returned an outright
    200 OK with choices=None (no error status at all), and the bare response.choices[0] that
    followed every completion call crashed the whole session on an unhandled TypeError."""
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)
    calls = {"count": 0}
    real_response = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="ok", tool_calls=[]), finish_reason="stop")])

    def create_call():
        calls["count"] += 1
        if calls["count"] == 1:
            return SimpleNamespace(choices=None)
        return real_response

    result = _create_completion_with_backoff(create_call)

    assert result is real_response
    assert calls["count"] == 2


def test_create_completion_with_backoff_retries_past_a_finish_reason_error_choice(monkeypatch):
    """Real incident this fixes: openrouter's own free nemotron routing returned a genuine 200 OK
    with a real choice present, but finish_reason="error" and no content/tool_calls at all -- no
    exception the openai SDK itself raises, so this used to be silently accepted as a normal (if
    empty) completion, surfacing downstream as a generic "couldn't extract structured fields" with
    no hint the provider itself had failed to generate anything."""
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)
    calls = {"count": 0}
    real_response = _fake_response("ok")

    def create_call():
        calls["count"] += 1
        if calls["count"] == 1:
            return _fake_response(None, finish_reason="error")
        return real_response

    result = _create_completion_with_backoff(create_call)

    assert result is real_response
    assert calls["count"] == 2


def test_create_completion_with_backoff_keeps_a_finish_reason_error_choice_with_real_content(monkeypatch):
    """finish_reason="error" alongside actual content/tool_calls is never observed in practice, but
    if it ever happens, real content must not be thrown away over a label alone."""
    response = _fake_response("partial but real content", finish_reason="error")
    assert _create_completion_with_backoff(lambda: response) is response


def test_create_completion_with_backoff_raises_when_choices_stay_empty(monkeypatch):
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)

    def create_call():
        return SimpleNamespace(choices=[])

    with pytest.raises(EmptyResponseError):
        _create_completion_with_backoff(create_call)


def test_extract_prompt_tool_calls_parses_well_formed_block():
    content = 'before <tool_call>{"name": "nmap", "arguments": {"target": "x"}}</tool_call> after'
    calls = _extract_prompt_tool_calls(content)
    assert len(calls) == 1
    assert calls[0].name == "nmap"
    assert calls[0].arguments == {"target": "x"}


def test_extract_prompt_tool_calls_ignores_malformed_json():
    content = "<tool_call>{not valid json}</tool_call>"
    assert _extract_prompt_tool_calls(content) == []


def test_extract_prompt_tool_calls_no_block_returns_empty():
    assert _extract_prompt_tool_calls("just plain text, no tool call") == []


def test_extract_prompt_tool_calls_tolerates_a_dsml_flavored_closing_tag():
    """Real incident this covers: deepseek-v4-flash-free (via opencode-zen, once fallen back to
    prompt-based tool-calling) inconsistently closed an otherwise well-formed <tool_call>{...}
    block with </｜DSML｜tool_call> instead of </tool_call> -- the strict closer used to silently
    discard a real, fully-committed tool call over nothing more than the closing tag's spelling."""
    content = '<tool_call>{"name": "http_request", "arguments": {"target": "x"}}</｜DSML｜tool_call>'
    calls = _extract_prompt_tool_calls(content)
    assert len(calls) == 1
    assert calls[0].name == "http_request"
    assert calls[0].arguments == {"target": "x"}


def test_extract_prompt_tool_calls_tolerates_a_plural_dsml_flavored_closing_tag():
    """Real, confirmed incident this covers: the exact same model/fallback shape as the singular
    case above, but closing with </｜DSML｜tool_calls> (plural AND DSML-prefixed) across one whole
    real session -- the singular-only closer silently discarded 8 correct, fully-committed calls,
    falling back to a generic "no parseable decision" for 6 of that session's 10 findings."""
    content = '<tool_call>{"name": "http_request", "arguments": {"target": "x"}}</｜DSML｜tool_calls>'
    calls = _extract_prompt_tool_calls(content)
    assert len(calls) == 1
    assert calls[0].name == "http_request"
    assert calls[0].arguments == {"target": "x"}


def test_extract_prompt_tool_calls_falls_back_to_the_native_dsml_invoke_dialect():
    """Real incident this covers: the same model sometimes reverts entirely to its own native
    special-token tool-call dialect instead of the <tool_call>{json}</tool_call> wrapper the
    prompt injection asks for -- confirmed live, this cost one real session 9 separate wasted
    round-trips across a single Exploit phase."""
    content = (
        "I'll check both.\n\n"
        '<｜DSML｜tool_calls>\n'
        '<｜DSML｜invoke name="cors_check">\n'
        '<｜DSML｜parameter name="target" string="true">https://example.com/</｜DSML｜parameter>\n'
        '</｜DSML｜invoke>\n'
        '<｜DSML｜invoke name="record_exploit_decision">\n'
        '<｜DSML｜parameter name="action" string="true">skipped_no_suitable_tool</｜DSML｜parameter>\n'
        '<｜DSML｜parameter name="reasoning" string="true">no fitting tool</｜DSML｜parameter>\n'
        '</｜DSML｜invoke>\n'
        '</｜DSML｜tool_calls>\n'
    )
    calls = _extract_prompt_tool_calls(content)
    assert len(calls) == 2
    assert calls[0].name == "cors_check"
    assert calls[0].arguments == {"target": "https://example.com/"}
    assert calls[1].name == "record_exploit_decision"
    assert calls[1].arguments == {"action": "skipped_no_suitable_tool", "reasoning": "no fitting tool"}


# --- _parse_tool_call_arguments: real incident this covers -------------------------------------
# A real bug-bounty session's very first LLM call crashed the ENTIRE session outright with an
# unhandled json.JSONDecodeError ("Extra data: line 1 column 3164"), 15 seconds in, because the
# native tool-calling path used a bare json.loads() with nothing catching a malformed result.


def test_parse_tool_call_arguments_parses_well_formed_json():
    assert _parse_tool_call_arguments('{"target": "example.com"}') == {"target": "example.com"}


def test_parse_tool_call_arguments_defaults_to_empty_dict_for_none():
    assert _parse_tool_call_arguments(None) == {}


def test_parse_tool_call_arguments_recovers_the_real_arguments_from_trailing_extra_data():
    """The exact real incident shape: a fully valid JSON object, followed by extra content the
    provider appended on top (repeated/hallucinated text) -- json.loads() rejects the whole string
    outright ("Extra data"), but the real arguments the model intended are still right there at
    the start and must not be lost."""
    raw = '{"target": "example.com", "extra_args": ["-a", "4"]}TRAILING GARBAGE NOT JSON AT ALL'
    assert _parse_tool_call_arguments(raw) == {"target": "example.com", "extra_args": ["-a", "4"]}


def test_parse_tool_call_arguments_recovers_from_a_duplicated_json_object():
    raw = '{"target": "example.com"}{"target": "example.com"}'
    assert _parse_tool_call_arguments(raw) == {"target": "example.com"}


def test_parse_tool_call_arguments_falls_back_to_empty_dict_for_garbage_from_the_start():
    """Malformed from the very first character (not just trailing extra data) -- raw_decode can't
    recover anything real here either, so this falls back to {} rather than raising, letting the
    call through to the target tool's own validation (e.g. a clear "missing required argument"
    error) instead of crashing the whole session."""
    assert _parse_tool_call_arguments("not json at all") == {}


def test_parse_tool_call_arguments_falls_back_to_empty_dict_when_the_first_value_is_not_an_object():
    assert _parse_tool_call_arguments('"just a string"') == {}
    assert _parse_tool_call_arguments("42") == {}


def test_inject_tool_instructions_appends_to_existing_system_message():
    messages = [{"role": "system", "content": "base prompt"}, {"role": "user", "content": "task"}]
    result = _inject_tool_instructions(messages, tools=[{"function": {"name": "x", "parameters": {}}}])
    assert result[0]["role"] == "system"
    assert result[0]["content"].startswith("base prompt")
    assert "tool_call" in result[0]["content"]
    assert result[1] == {"role": "user", "content": "task"}


def test_inject_tool_instructions_inserts_new_system_message_when_none_exists():
    messages = [{"role": "user", "content": "task"}]
    result = _inject_tool_instructions(messages, tools=[{"function": {"name": "x", "parameters": {}}}])
    assert result[0]["role"] == "system"
    assert result[1] == {"role": "user", "content": "task"}


# --- get_provider(): resolution/validation logic, no network (models_dev mocked out) ---


@pytest.fixture(autouse=True)
def _no_saved_llm_settings(monkeypatch):
    """get_provider() consults data/llm_settings.json (Settings-screen choice) before .env — these
    tests exercise the .env/arg fallback layers specifically, so a real saved-settings file (once
    someone actually uses the Settings UI) must never leak in and change their outcome."""
    monkeypatch.setattr("agent.llm_client.load_llm_settings", lambda: {})


def test_get_provider_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        get_provider("nonexistent-provider")


def test_get_provider_qwen_without_api_key_raises(monkeypatch):
    monkeypatch.delenv("QWEN_API_KEY", raising=False)
    with patch("agent.llm_client.validate_model_known"):
        with pytest.raises(ValueError, match="QWEN_API_KEY"):
            get_provider("qwen")


def test_get_provider_qwen_with_only_the_env_example_placeholder_raises(monkeypatch):
    """Real incident this guards: a fresh .env.example -> .env copy (this project's own documented
    first-setup step) leaves every *_API_KEY line set to its own literal "your_x_api_key_here"
    placeholder text -- a non-empty string, but not a real key. get_provider must treat that
    exactly like an unset key, not silently proceed to call a real API with garbage credentials."""
    monkeypatch.setenv("QWEN_API_KEY", "your_dashscope_api_key_here")
    with patch("agent.llm_client.validate_model_known"):
        with pytest.raises(ValueError, match="QWEN_API_KEY"):
            get_provider("qwen")


def test_get_provider_api_key_treats_a_placeholder_value_as_unset(monkeypatch):
    from agent.llm_client import PROVIDER_REGISTRY, get_provider_api_key
    config = PROVIDER_REGISTRY["openai"]
    monkeypatch.setenv(config.api_key_env, "your_openai_api_key_here")
    assert get_provider_api_key(config) == ""


def test_get_provider_api_key_returns_a_real_looking_value_unchanged(monkeypatch):
    from agent.llm_client import PROVIDER_REGISTRY, get_provider_api_key
    config = PROVIDER_REGISTRY["openai"]
    monkeypatch.setenv(config.api_key_env, "sk-real-looking-key-123")
    assert get_provider_api_key(config) == "sk-real-looking-key-123"


def test_get_provider_opencode_zen_works_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENCODE_ZEN_API_KEY", raising=False)
    with patch("agent.llm_client.validate_model_known"):
        provider = get_provider("opencode-zen")
    assert isinstance(provider, OpenAICompatProvider)


def test_get_provider_defaults_to_env_llm_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "opencode-zen")
    with patch("agent.llm_client.validate_model_known"):
        provider = get_provider()
    assert provider.provider_id == "opencode-zen"


def _clear_all_provider_keys(monkeypatch):
    for config in PROVIDER_REGISTRY.values():
        monkeypatch.delenv(config.api_key_env, raising=False)


def test_configured_provider_choices_always_includes_keyless_builtins(monkeypatch):
    _clear_all_provider_keys(monkeypatch)
    configured_ids = {pid for pid, _ in llm_client.configured_provider_choices()}
    assert "opencode-zen" in configured_ids
    assert "lmstudio" in configured_ids
    assert "ollama" in configured_ids


def test_configured_provider_choices_excludes_a_cloud_provider_with_no_key(monkeypatch):
    _clear_all_provider_keys(monkeypatch)
    configured_ids = {pid for pid, _ in llm_client.configured_provider_choices()}
    assert "qwen" not in configured_ids
    assert "openai" not in configured_ids


def test_configured_provider_choices_includes_a_cloud_provider_with_a_real_key(monkeypatch):
    _clear_all_provider_keys(monkeypatch)
    monkeypatch.setenv("QWEN_API_KEY", "sk-real-looking-key-123")
    configured = dict(llm_client.configured_provider_choices())
    assert configured.get("qwen") == "Qwen"


def test_configured_provider_choices_treats_placeholder_key_as_unconfigured(monkeypatch):
    _clear_all_provider_keys(monkeypatch)
    monkeypatch.setenv("QWEN_API_KEY", "your_dashscope_api_key_here")
    configured_ids = {pid for pid, _ in llm_client.configured_provider_choices()}
    assert "qwen" not in configured_ids


def test_configured_provider_choices_excludes_codex_when_not_signed_in(monkeypatch):
    _clear_all_provider_keys(monkeypatch)
    configured_ids = {pid for pid, _ in llm_client.configured_provider_choices()}
    assert llm_client.CODEX_PROVIDER_ID not in configured_ids
    assert llm_client.COPILOT_PROVIDER_ID not in configured_ids


def test_configured_provider_choices_includes_codex_when_signed_in(monkeypatch):
    from agent import codex_oauth

    _clear_all_provider_keys(monkeypatch)
    codex_oauth.save_tokens({"access": "x", "refresh": "y", "account_id": "acc"})
    configured_ids = {pid for pid, _ in llm_client.configured_provider_choices()}
    assert llm_client.CODEX_PROVIDER_ID in configured_ids


def test_configured_provider_choices_includes_enabled_custom_providers(monkeypatch):
    from agent.custom_providers import create_custom_provider

    _clear_all_provider_keys(monkeypatch)
    create_custom_provider(name="My Instance", base_url="http://localhost:9999/v1", api_key="", model="local")
    configured_names = {name for _, name in llm_client.configured_provider_choices()}
    assert "My Instance" in configured_names


def test_get_provider_uses_saved_settings_over_env(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "opencode-zen")
    monkeypatch.setattr("agent.llm_client.load_llm_settings", lambda: {"provider": "qwen", "model": "qwen-plus"})
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    with patch("agent.llm_client.validate_model_known"):
        provider = get_provider()
    assert provider.provider_id == "qwen"
    assert provider._model == "qwen-plus"


def test_get_provider_explicit_arg_wins_over_saved_settings(monkeypatch):
    monkeypatch.setattr("agent.llm_client.load_llm_settings", lambda: {"provider": "qwen", "model": "qwen-plus"})
    with patch("agent.llm_client.validate_model_known"):
        provider = get_provider("opencode-zen")
    assert provider.provider_id == "opencode-zen"


def test_get_provider_ignores_saved_model_for_a_different_provider(monkeypatch):
    # Saved settings name a model for qwen; resolving opencode-zen must not inherit it.
    monkeypatch.setattr("agent.llm_client.load_llm_settings", lambda: {"provider": "qwen", "model": "qwen-plus"})
    with patch("agent.llm_client.validate_model_known"):
        provider = get_provider("opencode-zen")
    assert provider._model == "big-pickle"


# --- get_fallback_chain_enabled()/get_fallback_chain()/get_next_chain_step(): the operator's own
# opt-in, explicitly-ordered Settings -> Reserve providers chain that replaced the old, always-on
# get_fallback_provider (which silently jumped to whichever OTHER configured provider
# PROVIDER_REGISTRY's own iteration order happened to list next -- including a paid one the
# operator never meant as a fallback for a different provider).


def test_fallback_chain_enabled_defaults_to_false(monkeypatch):
    monkeypatch.setattr("agent.llm_client.load_llm_settings", lambda: {})
    assert llm_client.get_fallback_chain_enabled() is False


def test_fallback_chain_enabled_reads_the_saved_flag(monkeypatch):
    monkeypatch.setattr("agent.llm_client.load_llm_settings", lambda: {"fallback_chain_enabled": True})
    assert llm_client.get_fallback_chain_enabled() is True


def test_get_fallback_chain_defaults_to_empty_list(monkeypatch):
    monkeypatch.setattr("agent.llm_client.load_llm_settings", lambda: {})
    assert llm_client.get_fallback_chain() == []


def test_get_next_chain_step_tries_every_model_on_one_provider_before_the_next_provider(monkeypatch):
    # A flat, ordered list of {"provider", "model"} steps -- Settings -> Reserve providers' own
    # per-row dropdowns produce exactly this shape, one row per step; two rows sharing a provider
    # is how "try this model, then that one" is expressed, no separate grouping.
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    chain = [
        {"provider": "qwen", "model": "qwen-plus"},
        {"provider": "qwen", "model": "qwen-turbo"},
        {"provider": "mistral", "model": "mistral-small-latest"},
    ]
    with patch("agent.llm_client.validate_model_known"):
        first = llm_client.get_next_chain_step(chain, set())
        assert (first.provider_id, first.model) == ("qwen", "qwen-plus")

        second = llm_client.get_next_chain_step(chain, {("qwen", "qwen-plus")})
        assert (second.provider_id, second.model) == ("qwen", "qwen-turbo")

        third = llm_client.get_next_chain_step(chain, {("qwen", "qwen-plus"), ("qwen", "qwen-turbo")})
        assert (third.provider_id, third.model) == ("mistral", "mistral-small-latest")


def test_get_next_chain_step_returns_none_once_every_step_is_tried_or_exhausted(monkeypatch):
    chain = [{"provider": "qwen", "model": "qwen-plus"}]
    all_tried = {("qwen", "qwen-plus")}
    assert llm_client.get_next_chain_step(chain, all_tried) is None
    # An empty chain (never configured) has nothing to try either, with no tried_steps at all.
    assert llm_client.get_next_chain_step([], set()) is None


def test_get_next_chain_step_skips_a_step_missing_its_required_api_key(monkeypatch):
    # qwen requires an API key; unset here -- get_next_chain_step must treat that step as unusable
    # and move on to the next one in the chain instead of returning something that would just fail
    # again for an unrelated, avoidable reason.
    monkeypatch.delenv("QWEN_API_KEY", raising=False)
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    chain = [
        {"provider": "qwen", "model": "qwen-plus"},
        {"provider": "mistral", "model": "mistral-small-latest"},
    ]
    with patch("agent.llm_client.validate_model_known"):
        fallback = llm_client.get_next_chain_step(chain, set())
    assert (fallback.provider_id, fallback.model) == ("mistral", "mistral-small-latest")


def test_get_next_chain_step_reorders_by_health_ranking_when_given(monkeypatch):
    """Real, confirmed motivation (a real HackerOne session log-review): real LLM budget
    repeatedly burned retrying a provider/model pair with a recent history of timeouts/quota
    errors, purely because it sat first in the operator's static Settings row order. A pair with a
    higher cleanliness score must be tried first regardless of row order, when health data exists."""
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    chain = [
        {"provider": "qwen", "model": "qwen-plus"},
        {"provider": "mistral", "model": "mistral-small-latest"},
    ]
    health_ranking = {("qwen", "qwen-plus"): -80.0, ("mistral", "mistral-small-latest"): 90.0}
    with patch("agent.llm_client.validate_model_known"):
        first = llm_client.get_next_chain_step(chain, set(), health_ranking=health_ranking)
    assert (first.provider_id, first.model) == ("mistral", "mistral-small-latest")


def test_get_next_chain_step_health_ranking_none_or_empty_keeps_the_original_order(monkeypatch):
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    chain = [
        {"provider": "qwen", "model": "qwen-plus"},
        {"provider": "mistral", "model": "mistral-small-latest"},
    ]
    with patch("agent.llm_client.validate_model_known"):
        via_none = llm_client.get_next_chain_step(chain, set(), health_ranking=None)
        via_empty = llm_client.get_next_chain_step(chain, set(), health_ranking={})
    assert (via_none.provider_id, via_none.model) == ("qwen", "qwen-plus")
    assert (via_empty.provider_id, via_empty.model) == ("qwen", "qwen-plus")


def test_get_next_chain_step_unscored_pair_defaults_to_neutral_not_penalized(monkeypatch):
    """A pair with no track record yet (never dispatched to, or not enough sessions for
    compute_efficiency_score to have has_data=True) must default to 0.0 -- sorting ahead of a pair
    with a confirmed BAD (negative) score, not behind it just for being unscored."""
    monkeypatch.setenv("QWEN_API_KEY", "test-key")
    monkeypatch.setenv("MISTRAL_API_KEY", "test-key")
    chain = [
        {"provider": "mistral", "model": "mistral-small-latest"},  # confirmed bad
        {"provider": "qwen", "model": "qwen-plus"},  # no data at all
    ]
    health_ranking = {("mistral", "mistral-small-latest"): -50.0}
    with patch("agent.llm_client.validate_model_known"):
        first = llm_client.get_next_chain_step(chain, set(), health_ranking=health_ranking)
    assert (first.provider_id, first.model) == ("qwen", "qwen-plus")


# --- OpenAICompatProvider.complete(): mock chat.completions.create directly, not httpx ---


def _make_provider(**overrides):
    config = PROVIDER_REGISTRY["opencode-zen"]
    kwargs = dict(
        provider_id="opencode-zen",
        models_dev_id=config.models_dev_id,
        base_url=config.base_url_default,
        api_key="",
        model=config.model_default,
    )
    kwargs.update(overrides)
    with patch("agent.llm_client.get_model_capabilities", return_value={"tool_call": True, "context_limit": 128000}):
        return OpenAICompatProvider(**kwargs)


def test_provider_exposes_context_limit_from_capabilities():
    provider = _make_provider()
    assert provider.context_limit == 128000


def test_provider_context_limit_is_none_when_catalog_unreachable():
    config = PROVIDER_REGISTRY["opencode-zen"]
    with patch("agent.llm_client.get_model_capabilities", return_value=None):
        provider = OpenAICompatProvider(
            provider_id="opencode-zen", models_dev_id=config.models_dev_id,
            base_url=config.base_url_default, api_key="", model=config.model_default,
        )
    assert provider.context_limit is None


def test_complete_native_mode_returns_parsed_response():
    provider = _make_provider()
    fake = _fake_response("hello", tool_calls=[_fake_tool_call("call_1", "nmap", '{"target": "x"}')])

    with patch.object(provider._client.chat.completions, "create", return_value=fake) as mock_create:
        result = provider.complete([{"role": "user", "content": "hi"}])

    mock_create.assert_called_once()
    assert result.content == "hello"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "nmap"
    assert result.tool_calls[0].arguments == {"target": "x"}


def test_complete_native_survives_a_malformed_tool_call_arguments_string():
    """Real, live incident: a real bug-bounty session's very first native tool-call turn crashed
    the ENTIRE session with an unhandled json.JSONDecodeError ("Extra data") before a single real
    tool ran -- the provider's own tool_calls[0].function.arguments carried a valid JSON object
    followed by trailing garbage. provider.complete() must recover the real arguments instead of
    raising."""
    provider = _make_provider()
    malformed = '{"target": "example.com"}TRAILING GARBAGE THE PROVIDER APPENDED'
    fake = _fake_response(None, tool_calls=[_fake_tool_call("call_1", "whatweb", malformed)])

    with patch.object(provider._client.chat.completions, "create", return_value=fake):
        result = provider.complete([{"role": "user", "content": "hi"}])

    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].arguments == {"target": "example.com"}


# --- content normalization: real incident this covers ---------------------------------------
# Mistral's own OpenAI-compatible endpoint (mistral-large-latest, native tool-calling mode)
# returned message.content as a LIST of content-block dicts instead of a plain string, with
# tool_calls empty -- core.py's _looks_like_a_refusal(response.content) then called
# _REFUSAL_PATTERN.search() on that list and raised TypeError, killing the whole calling
# coroutine (a delegated subagent's own task, in the real incident) with a bare "status": "error"
# instead of a normal, recoverable turn. LLMResponse.content must always come out str | None,
# regardless of what shape a specific provider's own API happens to return.


def test_normalize_message_content_passes_through_a_plain_string():
    assert llm_client._normalize_message_content("hello") == "hello"


def test_normalize_message_content_passes_through_none():
    assert llm_client._normalize_message_content(None) is None


def test_normalize_message_content_joins_text_blocks_from_a_content_block_list():
    content = [
        {"type": "text", "text": "first part"},
        {"type": "reference", "reference_ids": []},
        {"type": "text", "text": "second part"},
    ]
    assert llm_client._normalize_message_content(content) == "first part\nsecond part"


def test_normalize_message_content_is_none_when_no_text_blocks_exist_at_all():
    content = [{"type": "reference", "reference_ids": []}]
    assert llm_client._normalize_message_content(content) is None


def test_complete_native_survives_a_list_shaped_content_response():
    """Real, confirmed incident this fixes -- the exact response shape Mistral returned live: a
    content-block list with tool_calls=[] (the model expressed its intended tool calls as
    citation-style text instead of the real tool_calls field). provider.complete() must return a
    plain string, not the raw list, so every downstream str-only consumer (core.py's
    _looks_like_a_refusal, _parse_json_response) never sees anything but str | None.
    """
    provider = _make_provider()
    mistral_style_content = [
        {"type": "text", "text": "http_request"},
        {"type": "reference", "reference_ids": []},
        {"type": "text", "text": '{"target": "http://example.com/"}'},
    ]
    fake = _fake_response(mistral_style_content, tool_calls=[])

    with patch.object(provider._client.chat.completions, "create", return_value=fake):
        result = provider.complete([{"role": "user", "content": "hi"}])

    assert isinstance(result.content, str)
    assert result.content == 'http_request\n{"target": "http://example.com/"}'


def test_complete_native_dumps_the_full_response_when_content_exceeds_the_preview_limit(tmp_path, monkeypatch):
    """Real gap this closes: truncate_for_log's own dump-to-disk mechanism (already used for large
    tool stdout) was never actually wired up for LLM response logging -- a response over 500 chars
    that never ends up parsed into a structured field (a failed-to-parse reply, or reasoning
    content a tool-calling turn doesn't otherwise preserve) used to be permanently lossy beyond a
    500-char preview. Confirms the fix: a long response now leaves a full, unabridged dump file."""
    import agent.utils.debug as debug_mod

    monkeypatch.setattr(debug_mod, "_session_folder", lambda: None)
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)

    provider = _make_provider()
    long_content = "x" * 900
    fake = _fake_response(long_content)

    with patch.object(provider._client.chat.completions, "create", return_value=fake):
        result = provider.complete([{"role": "user", "content": "hi"}])

    assert result.content == long_content
    dump_dir = tmp_path / "debug-tool-calls"
    dumps = list(dump_dir.glob("llm_response_*.txt"))
    assert len(dumps) == 1
    assert dumps[0].read_text(encoding="utf-8") == long_content


def test_complete_native_recovers_from_an_empty_choices_response(monkeypatch):
    monkeypatch.setattr(llm_client.time, "sleep", lambda seconds: None)
    provider = _make_provider()
    fake = _fake_response("hello")

    with patch.object(
        provider._client.chat.completions, "create", side_effect=[SimpleNamespace(choices=None), fake]
    ) as mock_create:
        result = provider.complete([{"role": "user", "content": "hi"}])

    assert mock_create.call_count == 2
    assert result.content == "hello"


def test_complete_native_bad_request_falls_back_to_prompt_based():
    provider = _make_provider()
    fallback_response = _fake_response("plain text reply, no tool_call block")

    with patch.object(
        provider._client.chat.completions, "create", side_effect=[_bad_request_error(), fallback_response]
    ) as mock_create:
        result = provider.complete([{"role": "user", "content": "hi"}], tools=[{"function": {"name": "x", "parameters": {}}}])

    assert mock_create.call_count == 2
    assert result.content == "plain text reply, no tool_call block"
    assert provider._tool_mode == "prompt"


def test_complete_omits_auth_header_when_no_api_key():
    provider = _make_provider(api_key="")
    assert provider._omit_auth_header is True


def test_complete_keeps_auth_header_when_api_key_present():
    provider = _make_provider(api_key="real-key")
    assert provider._omit_auth_header is False


# --- OPENCODE_ZEN_MIMIC_CLI: mimics the official opencode CLI's own request fingerprint ----------
# Real, confirmed incident this exists for: a plain anonymous OpenAI-compatible request to
# opencode-zen's free tier got HTTP 429 FreeUsageLimitError, while the real opencode CLI, same
# machine, same moment, same model, succeeded -- reverse-engineered from a third-party project's own
# opencode-zen client (Atennebris/Umbra-Agent) to find the real difference: the CLI sends
# x-opencode-client/x-opencode-session/x-opencode-project/a matching User-Agent, none of which a
# plain openai-SDK request ever sent. Explicit operator opt-in (OPENCODE_ZEN_MIMIC_CLI), off by
# default -- never silently enabled.


def test_mimicry_disabled_by_default_sends_no_opencode_headers(monkeypatch):
    monkeypatch.delenv("OPENCODE_ZEN_MIMIC_CLI", raising=False)
    provider = _make_provider()
    headers = provider._auth_header_override()["extra_headers"]
    assert "x-opencode-client" not in headers
    assert "User-Agent" not in headers


def test_mimicry_enabled_sends_the_real_cli_fingerprint(monkeypatch):
    monkeypatch.setenv("OPENCODE_ZEN_MIMIC_CLI", "true")
    provider = _make_provider()
    headers = provider._auth_header_override()["extra_headers"]
    assert headers["x-opencode-client"] == "cli"
    assert headers["User-Agent"] == "opencode/1.15.3 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13"
    assert headers["x-opencode-session"].startswith("ses_")
    assert len(headers["x-opencode-project"]) == 40
    assert headers["x-opencode-request"].startswith("msg_")


def test_mimicry_enabled_never_applies_to_a_different_provider(monkeypatch):
    """The opt-in only ever affects the opencode-zen provider specifically -- sending these headers
    to an unrelated provider (mistral, openrouter, ...) would be meaningless at best."""
    monkeypatch.setenv("OPENCODE_ZEN_MIMIC_CLI", "true")
    provider = _make_provider(provider_id="mistral")
    headers = provider._auth_header_override().get("extra_headers", {})
    assert "x-opencode-client" not in headers


def test_mimicry_session_and_project_id_stay_stable_across_calls_but_request_id_changes(monkeypatch):
    """Session/project id are generated ONCE per provider instance (mirrors the real CLI's own
    "stable identifier per process" behavior) -- only the per-request id changes call to call."""
    monkeypatch.setenv("OPENCODE_ZEN_MIMIC_CLI", "true")
    provider = _make_provider()
    first = provider._auth_header_override()["extra_headers"]
    second = provider._auth_header_override()["extra_headers"]
    assert first["x-opencode-session"] == second["x-opencode-session"]
    assert first["x-opencode-project"] == second["x-opencode-project"]
    assert first["x-opencode-request"] != second["x-opencode-request"]


def test_mimicry_combines_with_the_auth_omission_override(monkeypatch):
    """Both real incidents this class already handles (no-Authorization-header for a no-key
    provider, and now CLI mimicry) must coexist in the same extra_headers dict, not one silently
    overwriting the other."""
    monkeypatch.setenv("OPENCODE_ZEN_MIMIC_CLI", "true")
    provider = _make_provider(api_key="")
    headers = provider._auth_header_override()["extra_headers"]
    assert isinstance(headers["Authorization"], type(Omit()))
    assert headers["x-opencode-client"] == "cli"


def test_mimicry_end_to_end_request_actually_carries_the_headers(monkeypatch):
    """Real, live-through-the-actual-dispatch-path proof: the headers reach the real
    chat.completions.create(...) call, not just _auth_header_override() in isolation."""
    monkeypatch.setenv("OPENCODE_ZEN_MIMIC_CLI", "true")
    provider = _make_provider()
    response = _fake_response("pong")

    with patch.object(provider._client.chat.completions, "create", return_value=response) as mock_create:
        provider.complete([{"role": "user", "content": "hi"}])

    sent_headers = mock_create.call_args.kwargs["extra_headers"]
    assert sent_headers["x-opencode-client"] == "cli"


# --- _fetch_local_model_ids: raw httpx.Client (not the openai SDK client) + its own short
# discovery timeout -- real incident this covers -------------------------------------------------


_RealHTTPXClient = httpx.Client


def _mock_httpx_client(handler, captured_kwargs=None):
    """_fetch_local_model_ids constructs its own httpx.Client(timeout=...) explicitly (never the
    bare httpx.get() convenience function -- that binds its own internal Client reference at
    httpx's own import time, which a test-side monkeypatch of the top-level httpx.Client attribute
    can never intercept). Patching the Client constructor itself is what actually works, same
    pattern tests/test_web_fetch.py already uses for its own one-off httpx.Client(...) call.
    captured_kwargs, if given, records every constructor kwarg (e.g. timeout=) for assertions.
    """
    def factory(**kwargs):
        if captured_kwargs is not None:
            captured_kwargs.update(kwargs)
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _ok_empty_handler(request):
    return httpx.Response(200, json={"data": []})


def test_fetch_local_model_ids_uses_its_own_short_timeout_not_the_completion_one(monkeypatch):
    """Real, confirmed incident this fixes: reusing LLM_REQUEST_TIMEOUT_SECONDS (120s, sized for a
    real in-use completion call) here meant a not-running local provider (LM Studio/Ollama) added
    its own full connection-failure delay to every single Settings page load (get_model_choices,
    called once per configured provider on every render). Confirmed live: even after first giving
    this its own short timeout, the openai SDK client itself still took ~5.6s to fail despite
    timeout=3.0 -- a raw httpx.Client with the identical timeout against the identical address
    failed in under a second, which is why this function uses httpx directly, not the SDK."""
    captured = {}
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_ok_empty_handler, captured))
    monkeypatch.delenv("LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS", raising=False)

    result = llm_client._fetch_local_model_ids("http://127.0.0.1:1234/v1", "")

    assert result == []
    assert captured["timeout"] == llm_client._DEFAULT_LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS
    assert captured["timeout"] < 30  # never anywhere near the 120s completion-call timeout


def test_fetch_local_model_ids_honors_an_env_override(monkeypatch):
    captured = {}
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_ok_empty_handler, captured))
    monkeypatch.setenv("LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS", "7")

    llm_client._fetch_local_model_ids("http://127.0.0.1:1234/v1", "")

    assert captured["timeout"] == 7.0


def test_fetch_local_model_ids_parses_real_model_ids_from_the_response(monkeypatch):
    def handler(request):
        assert request.url.path == "/v1/models"
        return httpx.Response(200, json={"data": [{"id": "llama-3.2"}, {"id": "qwen-2.5"}]})

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = llm_client._fetch_local_model_ids("http://127.0.0.1:1234/v1", "")

    assert result == ["llama-3.2", "qwen-2.5"]  # sorted, real ids extracted from data[].id


def test_fetch_local_model_ids_empty_on_connection_error(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("connection refused", request=request)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(handler))

    result = llm_client._fetch_local_model_ids("http://127.0.0.1:1234/v1", "")

    assert result == []
