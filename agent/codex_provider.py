"""CodexOAuthProvider -- the LLMProvider implementation for "Sign in with ChatGPT" (see
agent/codex_oauth.py for the login/token half of this feature).

This is NOT another OpenAICompatProvider instance: a ChatGPT-subscription session talks to a
completely different backend (https://chatgpt.com/backend-api/codex/responses, OpenAI's Responses
API shape) than the standard chat/completions wire protocol every other provider in this project
uses -- different request body, different response shape, different auth (a bearer access token +
chatgpt-account-id header, not an API key). agent/llm_client.py's LLMProvider Protocol is the seam
that lets this coexist with OpenAICompatProvider without either one knowing about the other.

Deliberately reuses llm_client's own _call_with_backoff for retry/backoff/stop-check handling
instead of a second implementation of that logic -- _raw_request below raises the exact same
openai.APIStatusError/APIConnectionError exception types every other provider's failures already
surface as, so agent/core.py's _llm_complete (which catches those two types plus EmptyResponseError
for its retry + fallback-chain logic) treats a Codex failure exactly like any other provider's.
"""
from __future__ import annotations

import os
import time
from collections.abc import Callable

import httpx

from agent.codex_oauth import get_valid_access_token
from agent.llm_client import (
    CODEX_PROVIDER_ID,
    LLMResponse,
    ToolCallRequest,
    _call_with_backoff,
    _parse_tool_call_arguments,
)
from agent.utils.debug import truncate_for_log
from agent.utils.lazy_openai import openai
from agent.utils.logger import get_logger

logger = get_logger("LLM")

CODEX_DEFAULT_MODEL = "gpt-5.3-codex"
_CODEX_BASE_URL = "https://chatgpt.com/backend-api"
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 120

# Static, hand-maintained (not from models.dev -- these model ids are Codex/ChatGPT-backend
# specific and models.dev's real "openai" catalog entry doesn't cover them) list for the Settings
# model dropdown and context-window lookups. Mirrors the model set a real "Sign in with ChatGPT"
# integration actually offers today; update here if OpenAI ships a new Codex-backend model.
CODEX_MODELS: dict[str, int] = {
    "gpt-5.5": 272_000,
    "gpt-5.4": 272_000,
    "gpt-5.4-mini": 272_000,
    "gpt-5.3-codex": 272_000,
    "gpt-5.2": 272_000,
}


def _messages_to_codex_input(messages: list[dict]) -> tuple[str, list[dict]]:
    """Translates ASRA's standard chat/completions-shaped message list (agent/core.py's own
    assistant/tool_calls/tool_call_id conventions) into the Responses API's own instructions +
    input-items shape. function_call/function_call_output are the Responses API's own documented
    item types for standard JSON-schema tools (every tool in this project), matching how OpenAI's
    own Codex CLI represents them -- no custom/freeform tool item types needed here.
    """
    system_parts = [m["content"] for m in messages if m["role"] == "system" and m.get("content")]
    input_items: list[dict] = []
    for message in messages:
        role = message["role"]
        if role == "system":
            continue
        if role == "tool":
            input_items.append({
                "type": "function_call_output",
                "call_id": message.get("tool_call_id", ""),
                "output": message.get("content") or "",
            })
        elif role == "assistant":
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                if message.get("content"):
                    input_items.append({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": message["content"]}]})
                for call in tool_calls:
                    fn = call.get("function", {})
                    input_items.append({
                        "type": "function_call",
                        "call_id": call.get("id", ""),
                        "name": fn.get("name", ""),
                        "arguments": fn.get("arguments", "{}"),
                    })
            else:
                input_items.append({"role": "assistant", "content": [{"type": "output_text", "text": message.get("content") or ""}]})
        else:
            input_items.append({"role": "user", "content": [{"type": "input_text", "text": message.get("content") or ""}]})
    return "\n\n".join(system_parts), input_items


def _tools_to_codex(tools: list[dict]) -> list[dict]:
    """The Responses API's own tool schema is flatter than chat/completions' nested
    {"type": "function", "function": {...}} -- name/description/parameters sit directly on the
    tool object."""
    result = []
    for tool in tools:
        fn = tool.get("function", tool)
        result.append({"type": "function", "name": fn.get("name", ""), "description": fn.get("description", ""), "parameters": fn.get("parameters", {})})
    return result


def _parse_codex_response(payload: dict) -> LLMResponse:
    output = payload.get("output") if isinstance(payload, dict) else None
    output = output if isinstance(output, list) else []
    text_parts: list[str] = []
    tool_calls: list[ToolCallRequest] = []

    for item in output:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type")
        if item_type == "message":
            for block in item.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "output_text" and block.get("text"):
                    text_parts.append(block["text"])
        elif item_type == "function_call":
            name = item.get("name") or ""
            call_id = item.get("call_id") or name
            args_raw = item.get("arguments") if isinstance(item.get("arguments"), str) else "{}"
            if name:
                tool_calls.append(ToolCallRequest(id=call_id, name=name, arguments=_parse_tool_call_arguments(args_raw)))
        elif item_type == "custom_tool_call":
            # Not something ASRA's own requests ever ask for (every tool here is a standard
            # function-schema tool, see _tools_to_codex) -- kept as a defensive fallback only, in
            # case the backend ever echoes one back regardless.
            name = item.get("name") or ""
            call_id = item.get("call_id") or item.get("id") or name
            args_raw = item.get("input") if isinstance(item.get("input"), str) else "{}"
            if name:
                tool_calls.append(ToolCallRequest(id=call_id, name=name, arguments=_parse_tool_call_arguments(args_raw)))

    content = "\n".join(text_parts) if text_parts else None
    finish_reason = payload.get("status") if isinstance(payload, dict) else None
    return LLMResponse(content=content, tool_calls=tool_calls, finish_reason=finish_reason or "stop")


class CodexOAuthProvider:
    def __init__(self, model: str | None = None):
        self.provider_id = CODEX_PROVIDER_ID
        self.model = model or CODEX_DEFAULT_MODEL
        self.context_limit = CODEX_MODELS.get(self.model)

    def complete(
        self, messages: list[dict], tools: list[dict] | None = None, stop_check: Callable[[], bool] | None = None
    ) -> LLMResponse:
        system, input_items = _messages_to_codex_input(messages)
        body = {
            "model": self.model,
            "stream": False,
            "store": False,
            "instructions": system,
            "input": input_items,
            "text": {"verbosity": "low"},
        }
        if tools:
            body["tools"] = _tools_to_codex(tools)
            body["tool_choice"] = "auto"

        logger.debug("codex_provider: request model=%s messages=%d tools=%d", self.model, len(messages), len(tools or []))

        payload = _call_with_backoff(lambda: self._raw_request(body), stop_check=stop_check)
        response = _parse_codex_response(payload)

        logger.debug(
            "codex_provider: response finish_reason=%s tool_calls=%d content_preview=%s",
            response.finish_reason, len(response.tool_calls),
            truncate_for_log(response.content or "", step_id=f"codex_response_{int(time.time() * 1000)}"),
        )
        return response

    def _raw_request(self, body: dict) -> dict:
        """One full request/response cycle, including the single 401-triggers-refresh-and-retry
        that _get_token-shaped logic needs (see get_valid_access_token's own docstring) -- this is
        NOT the retry loop for transient failures, that's _call_with_backoff wrapping this whole
        method. Raises the openai SDK's own exception types on failure so that outer retry loop
        (and agent/core.py's fallback-chain logic above it) handles a Codex failure exactly like
        any other provider's, without a parallel implementation of either.
        """
        token = get_valid_access_token()
        response = self._post(body, token)
        if response.status_code == 401:
            logger.debug("codex_provider: got 401, forcing a token refresh and retrying once")
            token = get_valid_access_token(force_refresh=True)
            response = self._post(body, token)

        if response.status_code == 429:
            raise openai.RateLimitError(f"ChatGPT usage limit reached ({response.status_code}).", response=response, body=None)
        if not response.is_success:
            # Any other non-2xx (5xx included) surfaces as a plain APIStatusError -- llm_client's
            # own _is_retryable(status_code >= 500) decides whether _call_with_backoff retries it;
            # a 4xx like 400/403/404 correctly falls straight through without wasting a retry.
            raise openai.APIStatusError(f"Codex backend returned {response.status_code}: {response.text[:300]}", response=response, body=None)
        return response.json()

    @staticmethod
    def _post(body: dict, token: dict) -> httpx.Response:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token['access']}",
            "chatgpt-account-id": token["account_id"],
            "originator": "asra",
            "OpenAI-Beta": "responses=experimental",
        }
        request_timeout = float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", str(_DEFAULT_REQUEST_TIMEOUT_SECONDS)))
        try:
            return httpx.post(f"{_CODEX_BASE_URL}/codex/responses", json=body, headers=headers, timeout=request_timeout)
        except httpx.TimeoutException as exc:
            raise openai.APITimeoutError(request=exc.request) from exc
        except httpx.ConnectError as exc:
            raise openai.APIConnectionError(message=str(exc), request=exc.request) from exc
