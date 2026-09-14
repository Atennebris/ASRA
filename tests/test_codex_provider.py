"""agent/codex_provider.py -- the chat/completions <-> Responses API translation (the part with no
reference implementation to copy verbatim from ASRA's own conventions, unlike agent/codex_oauth.py's
login flow) plus CodexOAuthProvider.complete()'s own retry/401-refresh wiring, with every real
network call mocked (httpx.post) so these run at unit-test speed with no live OpenAI dependency.
"""
import time

import httpx
import openai
import pytest

import agent.codex_oauth as codex_oauth
from agent.codex_provider import (
    CodexOAuthProvider,
    _messages_to_codex_input,
    _parse_codex_response,
    _tools_to_codex,
)


def test_messages_to_codex_input_splits_system_into_instructions():
    system, input_items = _messages_to_codex_input([
        {"role": "system", "content": "You are a pentest agent."},
        {"role": "user", "content": "scan example.com"},
    ])
    assert system == "You are a pentest agent."
    assert input_items == [{"role": "user", "content": [{"type": "input_text", "text": "scan example.com"}]}]


def test_messages_to_codex_input_merges_multiple_system_messages():
    system, _ = _messages_to_codex_input([
        {"role": "system", "content": "first"},
        {"role": "system", "content": "second"},
        {"role": "user", "content": "hi"},
    ])
    assert system == "first\n\nsecond"


def test_messages_to_codex_input_translates_assistant_tool_calls_and_tool_results():
    """Mirrors agent/core.py's own real message shape (see _run_llm_tool_loop_impl) -- an
    assistant message with tool_calls uses the standard chat/completions nested
    {"type": "function", "function": {"name", "arguments"}} shape, and a tool-role reply carries
    tool_call_id -- not the Responses API's own flatter shape, which this function must produce.
    """
    messages = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "run nmap"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "nmap_scan", "arguments": '{"target": "1.2.3.4"}'}}],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": '{"status": "ok"}'},
    ]
    _, input_items = _messages_to_codex_input(messages)
    assert input_items == [
        {"role": "user", "content": [{"type": "input_text", "text": "run nmap"}]},
        {"type": "function_call", "call_id": "call_1", "name": "nmap_scan", "arguments": '{"target": "1.2.3.4"}'},
        {"type": "function_call_output", "call_id": "call_1", "output": '{"status": "ok"}'},
    ]


def test_messages_to_codex_input_includes_assistant_text_alongside_tool_calls():
    messages = [{
        "role": "assistant", "content": "Let me check that.",
        "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "x", "arguments": "{}"}}],
    }]
    _, input_items = _messages_to_codex_input(messages)
    assert input_items[0] == {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "Let me check that."}]}


def test_messages_to_codex_input_plain_assistant_reply_no_tool_calls():
    _, input_items = _messages_to_codex_input([{"role": "assistant", "content": "done", "tool_calls": []}])
    assert input_items == [{"role": "assistant", "content": [{"type": "output_text", "text": "done"}]}]


def test_tools_to_codex_flattens_the_nested_function_schema():
    tools = [{"type": "function", "function": {"name": "http_request", "description": "Make a request", "parameters": {"type": "object"}}}]
    assert _tools_to_codex(tools) == [{"type": "function", "name": "http_request", "description": "Make a request", "parameters": {"type": "object"}}]


def test_parse_codex_response_extracts_text_and_tool_calls():
    payload = {
        "status": "completed",
        "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "Found an open port."}]},
            {"type": "function_call", "call_id": "call_9", "name": "nmap_scan", "arguments": '{"target": "1.2.3.4"}'},
        ],
    }
    response = _parse_codex_response(payload)
    assert response.content == "Found an open port."
    assert response.finish_reason == "completed"
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].id == "call_9"
    assert response.tool_calls[0].name == "nmap_scan"
    assert response.tool_calls[0].arguments == {"target": "1.2.3.4"}


def test_parse_codex_response_empty_output_returns_none_content_and_no_tool_calls():
    response = _parse_codex_response({"output": []})
    assert response.content is None
    assert response.tool_calls == []
    assert response.finish_reason == "stop"


def test_parse_codex_response_tolerates_a_malformed_payload():
    assert _parse_codex_response({}).content is None
    assert _parse_codex_response(None).content is None


@pytest.fixture(autouse=True)
def _signed_in():
    codex_oauth.save_tokens({"access": "tok", "refresh": "ref", "expires": time.time() + 3600, "account_id": "acct_1"})
    yield
    codex_oauth.clear_tokens()


def _fake_response(status_code, json_body=None, text=""):
    request = httpx.Request("POST", "https://chatgpt.com/backend-api/codex/responses")
    if json_body is not None:
        return httpx.Response(status_code, request=request, json=json_body)
    return httpx.Response(status_code, request=request, text=text)


def test_complete_happy_path(monkeypatch):
    calls = []
    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, json, headers))
        return _fake_response(200, json_body={"status": "completed", "output": [{"type": "message", "content": [{"type": "output_text", "text": "hi"}]}]})
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CodexOAuthProvider(model="gpt-5.3-codex")
    response = provider.complete([{"role": "user", "content": "hello"}])

    assert response.content == "hi"
    assert len(calls) == 1
    url, body, headers = calls[0]
    assert url == "https://chatgpt.com/backend-api/codex/responses"
    assert body["model"] == "gpt-5.3-codex"
    assert headers["Authorization"] == "Bearer tok"
    assert headers["chatgpt-account-id"] == "acct_1"


def test_complete_includes_tools_when_given(monkeypatch):
    captured = {}
    def fake_post(url, json=None, headers=None, timeout=None):
        captured["body"] = json
        return _fake_response(200, json_body={"output": []})
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CodexOAuthProvider()
    tools = [{"type": "function", "function": {"name": "http_request", "description": "", "parameters": {}}}]
    provider.complete([{"role": "user", "content": "hi"}], tools=tools)

    assert captured["body"]["tools"] == [{"type": "function", "name": "http_request", "description": "", "parameters": {}}]
    assert captured["body"]["tool_choice"] == "auto"


def test_complete_refreshes_once_on_401_then_succeeds(monkeypatch):
    refreshed = {"access": "new-tok", "refresh": "ref2", "expires": time.time() + 3600, "account_id": "acct_1"}
    monkeypatch.setattr(codex_oauth, "refresh_access_token", lambda refresh_token: refreshed)

    calls = []
    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append(headers["Authorization"])
        if len(calls) == 1:
            return _fake_response(401, text="unauthorized")
        return _fake_response(200, json_body={"output": []})
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CodexOAuthProvider()
    provider.complete([{"role": "user", "content": "hi"}])

    assert calls == ["Bearer tok", "Bearer new-tok"]


def test_complete_raises_rate_limit_error_as_an_openai_exception_type(monkeypatch):
    """Must surface as openai.RateLimitError (an APIStatusError subclass), not a bare exception --
    agent/core.py's _llm_complete only catches openai.APIStatusError/APIConnectionError/
    EmptyResponseError for its retry + fallback-chain logic, so anything else would crash the
    whole phase instead of being handled the same way every other provider's failures already are.
    """
    def fake_post(url, json=None, headers=None, timeout=None):
        return _fake_response(429, text="rate limited")
    monkeypatch.setattr(httpx, "post", fake_post)
    # No point retrying through the real backoff schedule (several real seconds of sleep) just to
    # observe the final raised exception type -- shrink it to a single immediate attempt.
    monkeypatch.setattr("agent.llm_client._RETRY_DELAYS_SECONDS", ())

    provider = CodexOAuthProvider()
    with pytest.raises(openai.APIStatusError) as exc_info:
        provider.complete([{"role": "user", "content": "hi"}])
    assert exc_info.value.status_code == 429


def test_complete_non_retryable_4xx_raises_immediately_without_retrying(monkeypatch):
    calls = []
    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append(1)
        return _fake_response(400, text="bad request")
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CodexOAuthProvider()
    with pytest.raises(openai.APIStatusError):
        provider.complete([{"role": "user", "content": "hi"}])
    assert len(calls) == 1  # a 400 is never retried -- see llm_client._is_retryable
