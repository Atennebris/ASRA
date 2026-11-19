"""Chat live-typing: OpenAICompatProvider.stream_complete (agent/llm_client.py) streams a reply
token-by-token via on_delta while returning the exact same LLMResponse shape complete() produces,
and agent/chat.py's in-memory draft registry is what main.py's chat_stream SSE overlays as the
typing bubble. complete() itself is untouched -- the autonomous agent never calls the streaming path.
"""
from types import SimpleNamespace
from unittest.mock import patch

from agent.chat import clear_chat_stream_draft, get_chat_stream_draft, set_chat_stream_draft
from agent.llm_client import PROVIDER_REGISTRY, OpenAICompatProvider


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
    with patch("agent.llm_client.get_model_capabilities", return_value={"tool_call": True, "context_limit": 128000}), \
            patch("agent.llm_client.is_model_free", return_value=False):
        return OpenAICompatProvider(**kwargs)


def _text_chunk(content, finish_reason=None):
    return SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content=content, tool_calls=None), finish_reason=finish_reason)],
        usage=None,
    )


def _tool_chunk(index, id_, name, args_fragment, finish_reason=None):
    tc = SimpleNamespace(index=index, id=id_, function=SimpleNamespace(name=name, arguments=args_fragment))
    return SimpleNamespace(
        choices=[SimpleNamespace(delta=SimpleNamespace(content=None, tool_calls=[tc]), finish_reason=finish_reason)],
        usage=None,
    )


def test_stream_complete_accumulates_text_and_emits_each_delta():
    provider = _make_provider()
    chunks = [_text_chunk("Hel"), _text_chunk("lo "), _text_chunk("world", finish_reason="stop")]
    seen = []

    with patch.object(provider._client.chat.completions, "create", return_value=iter(chunks)):
        result = provider.stream_complete([{"role": "user", "content": "hi"}], on_delta=seen.append)

    assert result.content == "Hello world"
    assert result.finish_reason == "stop"
    assert result.tool_calls == []
    # Every fragment reached on_delta in order -- that's what makes the bubble type out live.
    assert seen == ["Hel", "lo ", "world"]


def test_stream_complete_reassembles_tool_calls_from_deltas():
    provider = _make_provider()
    # A tool call arrives split across chunks (id+name first, then the arguments string in pieces),
    # exactly as an OpenAI-compatible stream delivers it.
    chunks = [
        _tool_chunk(0, "call_1", "nmap", '{"tar'),
        _tool_chunk(0, None, None, 'get": "x"}', finish_reason="tool_calls"),
    ]

    with patch.object(provider._client.chat.completions, "create", return_value=iter(chunks)):
        result = provider.stream_complete([{"role": "user", "content": "scan it"}], tools=[{"type": "function"}])

    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].name == "nmap"
    assert result.tool_calls[0].arguments == {"target": "x"}


def test_stream_complete_without_on_delta_still_returns_full_content():
    provider = _make_provider()
    chunks = [_text_chunk("Just "), _text_chunk("text.", finish_reason="stop")]

    with patch.object(provider._client.chat.completions, "create", return_value=iter(chunks)):
        result = provider.stream_complete([{"role": "user", "content": "hi"}])

    assert result.content == "Just text."


def test_stream_draft_registry_set_get_clear():
    set_chat_stream_draft("sess_x", "thread_a", "partial reply so far")
    assert get_chat_stream_draft("sess_x", "thread_a") == "partial reply so far"
    # A thread with nothing streaming reads as empty, never KeyError.
    assert get_chat_stream_draft("sess_x", "thread_b") == ""
    clear_chat_stream_draft("sess_x", "thread_a")
    assert get_chat_stream_draft("sess_x", "thread_a") == ""
    # Clearing an already-absent draft is a no-op, never raises.
    clear_chat_stream_draft("sess_x", "thread_a")
