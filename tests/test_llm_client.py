"""Unit tests for agent/llm_client.py. Mocking happens via unittest.mock.patch.object on the
exact method that would otherwise hit the network (OpenAI SDK's chat.completions.create, or
models_dev's capability lookup) — never httpx/transport-level mocking.
"""
from types import SimpleNamespace
from unittest.mock import patch

import openai
import pytest

from agent.llm_client import (
    OpenAICompatProvider,
    PROVIDER_REGISTRY,
    _extract_prompt_tool_calls,
    _inject_tool_instructions,
    _is_retryable,
    _merge_consecutive_system_messages,
    _parse_retry_after,
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


def test_get_provider_unknown_provider_raises():
    with pytest.raises(ValueError, match="Unknown LLM provider"):
        get_provider("nonexistent-provider")


def test_get_provider_qwen_without_api_key_raises(monkeypatch):
    monkeypatch.delenv("QWEN_API_KEY", raising=False)
    with patch("agent.llm_client.validate_model_known"):
        with pytest.raises(ValueError, match="QWEN_API_KEY"):
            get_provider("qwen")


def test_get_provider_opencode_zen_works_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENCODE_ZEN_API_KEY", raising=False)
    with patch("agent.llm_client.validate_model_known"):
        provider = get_provider("opencode-zen")
    assert isinstance(provider, OpenAICompatProvider)


def test_get_provider_defaults_to_env_llm_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "opencode-zen")
    with patch("agent.llm_client.validate_model_known"):
        provider = get_provider()
    assert provider._provider_id == "opencode-zen"


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
    with patch("agent.llm_client.get_model_capabilities", return_value={"tool_call": True}):
        return OpenAICompatProvider(**kwargs)


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
