"""LLMProvider interface, OpenAICompatProvider, PROVIDER_REGISTRY (opencode-zen default, free — Qwen available via LLM_PROVIDER=qwen).

OpenAICompatProvider talks to any OpenAI-compatible chat/completions endpoint — not a coincidence,
most current LLM providers (Mistral, OpenRouter, Groq, DeepSeek, opencode-zen, Qwen/DashScope) use
this same wire format. Anthropic's Messages API is a different format and deliberately not
implemented here: LLMProvider is the seam where a second implementation would plug in later,
without touching prompts.py/core.py.
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Protocol

import openai
from openai import Omit

from agent.providers.models_dev import get_model_capabilities, validate_model_known
from agent.settings import load_llm_settings
from agent.utils.debug import truncate_for_log
from agent.utils.logger import get_logger

logger = get_logger("LLM")

# Public: main.py's web layer reads this to show the configured default in the scan form.
DEFAULT_PROVIDER = "opencode-zen"
# The openai SDK requires a non-empty api_key string even against endpoints that don't check it
# (opencode-zen's free models work with no key at all).
_PLACEHOLDER_API_KEY = "not-needed"

_RETRY_DELAYS_SECONDS = (2, 4, 8)
_TOOL_CALL_PATTERN = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


@dataclass(frozen=True)
class ToolCallRequest:
    id: str
    name: str
    arguments: dict


@dataclass(frozen=True)
class LLMResponse:
    content: str | None
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    finish_reason: str | None = None


class LLMProvider(Protocol):
    context_limit: int | None

    def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse: ...


@dataclass(frozen=True)
class ProviderConfig:
    models_dev_id: str  # provider key in the models.dev catalog, used for capability lookups
    base_url_env: str
    base_url_default: str
    api_key_env: str
    api_key_required: bool
    model_env: str
    model_default: str


# Config table, not code-per-provider: a new OpenAI-compatible provider is a new row here, not a
# new LLMProvider implementation.
PROVIDER_REGISTRY: dict[str, ProviderConfig] = {
    "opencode-zen": ProviderConfig(
        models_dev_id="opencode",
        base_url_env="OPENCODE_ZEN_BASE_URL",
        base_url_default="https://opencode.ai/zen/v1",
        api_key_env="OPENCODE_ZEN_API_KEY",
        api_key_required=False,
        model_env="OPENCODE_ZEN_MODEL",
        model_default="big-pickle",
    ),
    "qwen": ProviderConfig(
        models_dev_id="alibaba",
        base_url_env="QWEN_BASE_URL",
        base_url_default="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        api_key_env="QWEN_API_KEY",
        api_key_required=True,
        model_env="QWEN_MODEL",
        model_default="qwen-plus",
    ),
}


def get_provider(provider_id: str | None = None, model: str | None = None) -> LLMProvider:
    """Builds an LLMProvider from PROVIDER_REGISTRY + env, with the Settings-screen choice
    (data/llm_settings.json) as the default between explicit args and .env. Resolution order,
    most to least specific: explicit provider_id/model arg (a one-off override) > saved Settings
    choice > .env > PROVIDER_REGISTRY's hardcoded default. A saved model is only trusted when it
    was saved for the SAME provider being resolved — otherwise switching providers in Settings
    could leak a stale model name from the previous one.
    """
    saved = load_llm_settings()
    resolved_id = provider_id or saved.get("provider") or os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER)
    config = PROVIDER_REGISTRY.get(resolved_id)
    if config is None:
        raise ValueError(f"Unknown LLM provider {resolved_id!r}. Known providers: {list(PROVIDER_REGISTRY)}")

    base_url = os.getenv(config.base_url_env) or config.base_url_default
    api_key = os.getenv(config.api_key_env) or ""
    if config.api_key_required and not api_key:
        raise ValueError(f"{config.api_key_env} is not set (required for provider {resolved_id!r}).")
    saved_model = saved.get("model") if saved.get("provider") == resolved_id else None
    resolved_model = model or saved_model or os.getenv(config.model_env) or config.model_default

    # Fail fast at startup on a typo'd model name — not mid-session. A models.dev outage is not a
    # reason to fail (validate_model_known() itself no-ops when the catalog is unreachable).
    validate_model_known(config.models_dev_id, resolved_model)

    logger.debug("get_provider: resolved provider=%s model=%s base_url=%s", resolved_id, resolved_model, base_url)
    return OpenAICompatProvider(
        provider_id=resolved_id,
        models_dev_id=config.models_dev_id,
        base_url=base_url,
        api_key=api_key,
        model=resolved_model,
    )


def _merge_consecutive_system_messages(messages: list[dict]) -> list[dict]:
    """Collapses any run of consecutive system-role messages into one. Two system messages in a
    row 400s on some OpenAI-compatible endpoints — this is the one place every outgoing request
    passes through, so callers (prompts.py/core.py) are free to compose system+task separately.
    """
    merged: list[dict] = []
    for message in messages:
        if message["role"] == "system" and merged and merged[-1]["role"] == "system":
            merged[-1] = {**merged[-1], "content": f"{merged[-1]['content']}\n\n{message['content']}"}
        else:
            merged.append(dict(message))
    return merged


def _is_retryable(exc: openai.APIStatusError) -> bool:
    return exc.status_code == 429 or exc.status_code >= 500


def _parse_retry_after(exc: openai.APIStatusError) -> float | None:
    headers = getattr(exc.response, "headers", None)
    header_value = headers.get("retry-after") if headers is not None else None
    if not header_value:
        return None
    try:
        return float(header_value)
    except ValueError:
        return None


def _call_with_backoff(request_fn):
    """Retries only on 429/5xx (transient), never on 401/403/other 4xx (retrying the same bad
    request just burns time). Waits Retry-After if the server sent one, else the fixed backoff
    schedule below.
    """
    last_exc: openai.APIStatusError | None = None
    for attempt, fallback_delay in enumerate((0, *_RETRY_DELAYS_SECONDS)):
        if attempt > 0:
            wait_seconds = _parse_retry_after(last_exc) if last_exc is not None else None
            time.sleep(wait_seconds if wait_seconds is not None else fallback_delay)
        try:
            return request_fn()
        except openai.APIStatusError as exc:
            if not _is_retryable(exc):
                raise
            last_exc = exc
            logger.debug("llm_client: retryable error status=%s attempt=%d", exc.status_code, attempt + 1)
    raise last_exc


def _tool_instructions_text(tools: list[dict]) -> str:
    schemas = [tool["function"] for tool in tools]
    return (
        "You have access to the following tools:\n"
        f"{json.dumps(schemas, indent=2)}\n\n"
        "To call a tool, respond with exactly one line in this exact format:\n"
        '<tool_call>{"name": "<tool name>", "arguments": {<json arguments>}}</tool_call>\n'
        "Only emit a tool_call block when you actually want to call a tool; otherwise respond normally with plain text."
    )


def _inject_tool_instructions(messages: list[dict], tools: list[dict]) -> list[dict]:
    instructions = _tool_instructions_text(tools)
    result = [dict(message) for message in messages]
    if result and result[0]["role"] == "system":
        result[0]["content"] = f"{result[0]['content']}\n\n{instructions}"
    else:
        result.insert(0, {"role": "system", "content": instructions})
    return result


def _extract_prompt_tool_calls(content: str) -> list[ToolCallRequest]:
    tool_calls = []
    for index, match in enumerate(_TOOL_CALL_PATTERN.finditer(content)):
        try:
            payload = json.loads(match.group(1))
        except json.JSONDecodeError:
            logger.debug("llm_client: prompt-based tool_call block failed to parse: %s", match.group(1))
            continue
        tool_calls.append(ToolCallRequest(id=f"prompt_call_{index}", name=payload.get("name", ""), arguments=payload.get("arguments", {})))
    return tool_calls


class OpenAICompatProvider:
    def __init__(self, provider_id: str, models_dev_id: str, base_url: str, api_key: str, model: str):
        self._provider_id = provider_id
        self._model = model
        # Some OpenAI-compatible endpoints (opencode-zen's free tier) 401 on *any* Authorization
        # header, even a placeholder — confirmed by a real request (401 with a dummy Bearer token,
        # 200 with the header dropped entirely). The openai SDK requires a non-empty api_key string
        # to construct at all, so a placeholder is still passed in, but every actual request omits
        # the header when no real key was configured.
        self._omit_auth_header = not api_key
        self._client = openai.OpenAI(base_url=base_url, api_key=api_key or _PLACEHOLDER_API_KEY, max_retries=0)
        capabilities = get_model_capabilities(models_dev_id, model)
        self._tool_mode = self._decide_tool_mode(models_dev_id, model, capabilities)
        # Public: chat.py's compaction budget needs this to size how much history it can
        # send; None (catalog unreachable/model unlisted) means "unknown", callers must not guess.
        self.context_limit: int | None = capabilities["context_limit"] if capabilities else None

    def _auth_header_override(self) -> dict:
        return {"extra_headers": {"Authorization": Omit()}} if self._omit_auth_header else {}

    @staticmethod
    def _decide_tool_mode(models_dev_id: str, model: str, capabilities: dict | None) -> str:
        if capabilities is None:
            # Catalog unreachable or model unlisted: don't guess at startup — try native
            # tool-calling on the first real request and react if the endpoint rejects it.
            logger.debug("llm_client: %s/%s capabilities unknown, deciding tool mode reactively", models_dev_id, model)
            return "native"
        mode = "native" if capabilities["tool_call"] else "prompt"
        logger.debug("llm_client: %s/%s tool mode decided upfront: %s", models_dev_id, model, mode)
        return mode

    def complete(self, messages: list[dict], tools: list[dict] | None = None) -> LLMResponse:
        merged_messages = _merge_consecutive_system_messages(messages)

        if tools and self._tool_mode == "prompt":
            return self._complete_prompt_based(merged_messages, tools)

        try:
            return self._complete_native(merged_messages, tools)
        except openai.BadRequestError as exc:
            if not tools or self._tool_mode != "native":
                raise
            logger.debug("llm_client: native tool-calling rejected (%s), switching to prompt-based for this provider", exc)
            self._tool_mode = "prompt"
            return self._complete_prompt_based(merged_messages, tools)

    def _complete_native(self, messages: list[dict], tools: list[dict] | None) -> LLMResponse:
        request_kwargs = {"model": self._model, "messages": messages}
        if tools:
            request_kwargs["tools"] = tools

        logger.debug(
            "llm_client: request provider=%s model=%s mode=native messages=%d tools=%d",
            self._provider_id, self._model, len(messages), len(tools or []),
        )

        response = _call_with_backoff(
            lambda: self._client.chat.completions.create(**request_kwargs, **self._auth_header_override())
        )

        choice = response.choices[0]
        message = choice.message
        tool_calls = [
            ToolCallRequest(id=call.id, name=call.function.name, arguments=json.loads(call.function.arguments or "{}"))
            for call in (message.tool_calls or [])
        ]

        logger.debug(
            "llm_client: response finish_reason=%s tool_calls=%d content_preview=%s",
            choice.finish_reason, len(tool_calls), truncate_for_log(message.content or ""),
        )
        return LLMResponse(content=message.content, tool_calls=tool_calls, finish_reason=choice.finish_reason)

    def _complete_prompt_based(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        prompted_messages = _inject_tool_instructions(messages, tools)

        logger.debug(
            "llm_client: request provider=%s model=%s mode=prompt messages=%d tools=%d",
            self._provider_id, self._model, len(prompted_messages), len(tools),
        )

        response = _call_with_backoff(
            lambda: self._client.chat.completions.create(
                model=self._model, messages=prompted_messages, **self._auth_header_override()
            )
        )

        choice = response.choices[0]
        content = choice.message.content or ""
        tool_calls = _extract_prompt_tool_calls(content)

        logger.debug(
            "llm_client: response finish_reason=%s tool_calls=%d content_preview=%s",
            choice.finish_reason, len(tool_calls), truncate_for_log(content),
        )
        return LLMResponse(content=content, tool_calls=tool_calls, finish_reason=choice.finish_reason)
