"""agent/copilot_provider.py -- response parsing (_parse_copilot_response, the standard chat/
completions shape, no translation layer needed the way agent/codex_provider.py's Responses-API
shape does) plus CopilotOAuthProvider.complete()'s own retry/401-refresh wiring, with every real
network call mocked (httpx.post) so these run at unit-test speed with no live GitHub Copilot
dependency.
"""
import time

import httpx
import openai
import pytest

import agent.copilot_oauth as copilot_oauth
from agent.copilot_provider import CopilotOAuthProvider, _parse_copilot_response


def test_parse_copilot_response_extracts_text_and_tool_calls():
    payload = {
        "choices": [{
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant", "content": None,
                "tool_calls": [{"id": "call_9", "type": "function", "function": {"name": "nmap_scan", "arguments": '{"target": "1.2.3.4"}'}}],
            },
        }],
    }
    response = _parse_copilot_response(payload)
    assert response.content is None
    assert response.finish_reason == "tool_calls"
    assert len(response.tool_calls) == 1
    assert response.tool_calls[0].id == "call_9"
    assert response.tool_calls[0].name == "nmap_scan"
    assert response.tool_calls[0].arguments == {"target": "1.2.3.4"}


def test_parse_copilot_response_extracts_plain_text_with_no_tool_calls():
    payload = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": "Found an open port."}}]}
    response = _parse_copilot_response(payload)
    assert response.content == "Found an open port."
    assert response.tool_calls == []
    assert response.finish_reason == "stop"


def test_parse_copilot_response_empty_choices_returns_none_content_and_no_tool_calls():
    assert _parse_copilot_response({"choices": []}).content is None


def test_parse_copilot_response_tolerates_a_malformed_payload():
    assert _parse_copilot_response({}).content is None
    assert _parse_copilot_response(None).content is None


@pytest.fixture(autouse=True)
def _signed_in():
    copilot_oauth.save_tokens({"github_token": "gho_1", "copilot_token": "tid=tok", "copilot_expires": time.time() + 3600})
    yield
    copilot_oauth.clear_tokens()


def _fake_response(status_code, json_body=None, text=""):
    request = httpx.Request("POST", "https://api.githubcopilot.com/chat/completions")
    if json_body is not None:
        return httpx.Response(status_code, request=request, json=json_body)
    return httpx.Response(status_code, request=request, text=text)


def test_complete_happy_path(monkeypatch):
    calls = []
    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, json, headers))
        return _fake_response(200, json_body={"choices": [{"finish_reason": "stop", "message": {"content": "hi"}}]})
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CopilotOAuthProvider(model="gpt-4.1")
    response = provider.complete([{"role": "user", "content": "hello"}])

    assert response.content == "hi"
    assert len(calls) == 1
    url, body, headers = calls[0]
    assert url == "https://api.githubcopilot.com/chat/completions"
    assert body["model"] == "gpt-4.1"
    assert body["messages"] == [{"role": "user", "content": "hello"}]
    assert headers["Authorization"] == "Bearer tid=tok"
    assert headers["Copilot-Integration-Id"] == "vscode-chat"


def test_complete_includes_tools_when_given(monkeypatch):
    captured = {}
    def fake_post(url, json=None, headers=None, timeout=None):
        captured["body"] = json
        return _fake_response(200, json_body={"choices": []})
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CopilotOAuthProvider()
    tools = [{"type": "function", "function": {"name": "http_request", "description": "", "parameters": {}}}]
    provider.complete([{"role": "user", "content": "hi"}], tools=tools)

    assert captured["body"]["tools"] == tools
    assert captured["body"]["tool_choice"] == "auto"


def test_complete_refreshes_once_on_401_then_succeeds(monkeypatch):
    monkeypatch.setattr(copilot_oauth, "_fetch_copilot_token", lambda github_token: {"token": "tid=new", "expires": time.time() + 1800})

    calls = []
    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append(headers["Authorization"])
        if len(calls) == 1:
            return _fake_response(401, text="unauthorized")
        return _fake_response(200, json_body={"choices": []})
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CopilotOAuthProvider()
    provider.complete([{"role": "user", "content": "hi"}])

    assert calls == ["Bearer tid=tok", "Bearer tid=new"]


def test_complete_raises_rate_limit_error_as_an_openai_exception_type(monkeypatch):
    """Must surface as openai.RateLimitError (an APIStatusError subclass), not a bare exception --
    agent/core.py's _llm_complete only catches openai.APIStatusError/APIConnectionError/
    EmptyResponseError for its retry + fallback-chain logic."""
    monkeypatch.setattr(httpx, "post", lambda url, json=None, headers=None, timeout=None: _fake_response(429, text="rate limited"))
    monkeypatch.setattr("agent.llm_client._RETRY_DELAYS_SECONDS", ())

    provider = CopilotOAuthProvider()
    with pytest.raises(openai.APIStatusError) as exc_info:
        provider.complete([{"role": "user", "content": "hi"}])
    assert exc_info.value.status_code == 429


def test_complete_non_retryable_4xx_raises_immediately_without_retrying(monkeypatch):
    calls = []
    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append(1)
        return _fake_response(400, text="bad request")
    monkeypatch.setattr(httpx, "post", fake_post)

    provider = CopilotOAuthProvider()
    with pytest.raises(openai.APIStatusError):
        provider.complete([{"role": "user", "content": "hi"}])
    assert len(calls) == 1  # a 400 is never retried -- see llm_client._is_retryable
