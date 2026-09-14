"""CopilotOAuthProvider -- the LLMProvider implementation for "Sign in with GitHub Copilot" (see
agent/copilot_oauth.py for the login/token half of this feature).

Unlike agent/codex_provider.py's ChatGPT backend (a completely different Responses API wire shape),
GitHub Copilot's own chat/completions endpoint (https://api.githubcopilot.com/chat/completions) IS
the standard OpenAI chat/completions request/response shape every other provider in this project's
OpenAICompatProvider already speaks -- no message/tool translation layer needed here, unlike
codex_provider.py's _messages_to_codex_input/_tools_to_codex/_parse_codex_response. This still can't
just BE another OpenAICompatProvider instance, though: a Copilot API token expires roughly every
25-30 minutes (agent/copilot_oauth.py's get_valid_copilot_token), and OpenAICompatProvider's own
openai SDK client is built once, at construction, with a fixed api_key -- it has no way to pick up a
freshly refreshed token mid-session the way this class's own complete() does on every call.

Deliberately reuses llm_client's own _call_with_backoff/_parse_tool_call_arguments/
_normalize_message_content/_content_is_malformed (same reasoning as codex_provider.py's own
docstring: _raw_request below raises the exact same openai.APIStatusError/APIConnectionError
exception types every other provider's failures already surface as, so agent/core.py's
_llm_complete -- which catches those two types plus EmptyResponseError for its retry + fallback-
chain logic -- treats a Copilot failure exactly like any other provider's).

The extra headers below (Copilot-Integration-Id, Editor-Version, ...) are the same publicly
documented, widely reused values every third-party Copilot client sends -- api.githubcopilot.com
rejects requests missing them outright, regardless of how valid the bearer token is.
"""
from __future__ import annotations

import os
import time
from collections.abc import Callable

import httpx

from agent.copilot_oauth import get_valid_copilot_token
from agent.llm_client import (
    COPILOT_PROVIDER_ID,
    LLMResponse,
    ToolCallRequest,
    _call_with_backoff,
    _content_is_malformed,
    _normalize_message_content,
    _parse_tool_call_arguments,
)
from agent.utils.debug import truncate_for_log
from agent.utils.lazy_openai import openai
from agent.utils.logger import get_logger

logger = get_logger("LLM")

COPILOT_DEFAULT_MODEL = "gpt-4.1"
_COPILOT_BASE_URL = "https://api.githubcopilot.com"
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 120
# fetch_copilot_models's own dedicated short timeout, deliberately its own knob -- NOT
# LLM_REQUEST_TIMEOUT_SECONDS above, same "a passive discovery ping fired on every Settings load
# must never inherit a real completion call's own generous timeout" reasoning
# agent/llm_client.py's _DEFAULT_LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS already documents for local
# providers -- reused here (LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS) rather than a new near-duplicate
# env var, since this is the identical kind of call against a different backend.
_DEFAULT_MODEL_DISCOVERY_TIMEOUT_SECONDS = 3

# Static fallback (Settings model dropdown + context-window lookups) for whenever the live /models
# endpoint (fetch_copilot_models below) can't be reached yet -- not signed in, or a transient
# network hiccup. Mirrors the model set a real Copilot Individual/Business subscription commonly
# exposes today; the live endpoint is always preferred when it succeeds, this is only what Settings
# shows before that succeeds even once.
COPILOT_MODELS: dict[str, int] = {
    "gpt-4.1": 128_000,
    "gpt-4o": 128_000,
    "o3-mini": 200_000,
    "claude-sonnet-4.5": 200_000,
    "gemini-2.5-pro": 1_000_000,
}

# Reverse-engineered, publicly documented headers every third-party GitHub Copilot client sends --
# api.githubcopilot.com rejects a request missing these outright (a 403), independent of whether the
# bearer token itself is valid. Same "not a secret, identifies the calling client" status as
# agent/copilot_oauth.py's own _CLIENT_ID.
_REQUIRED_HEADERS = {
    "Content-Type": "application/json",
    "Copilot-Integration-Id": "vscode-chat",
    "Editor-Version": "vscode/1.85.1",
    "Editor-Plugin-Version": "copilot-chat/0.12.0",
    "User-Agent": "GithubCopilot/1.155.0",
    "Openai-Intent": "conversation-panel",
}


def fetch_copilot_models() -> list[str]:
    """Queries Copilot's own live /models endpoint -- unlike agent/codex_provider.py's CODEX_MODELS
    (hand-maintained, no live catalog exists for that backend), a Copilot subscription's actual
    model set genuinely varies per account/plan, and this endpoint is the only source that knows it.
    Empty (never raises) when not signed in or the request fails -- callers already fall back to
    COPILOT_MODELS's static list in that case, same tolerance agent/llm_client.py's own local-
    provider model discovery (_fetch_local_model_ids) already has.
    """
    try:
        token = get_valid_copilot_token()
    except RuntimeError:
        return []
    discovery_timeout = float(os.getenv("LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS", str(_DEFAULT_MODEL_DISCOVERY_TIMEOUT_SECONDS)))
    try:
        with httpx.Client(timeout=discovery_timeout) as client:
            response = client.get(f"{_COPILOT_BASE_URL}/models", headers={**_REQUIRED_HEADERS, "Authorization": f"Bearer {token}"})
        response.raise_for_status()
        return sorted(model["id"] for model in response.json().get("data", []) if model.get("id"))
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        logger.debug("copilot_provider: live model discovery failed: %s", exc)
        return []


def _parse_copilot_response(payload: dict) -> LLMResponse:
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not choices:
        return LLMResponse(content=None, tool_calls=[], finish_reason="stop")
    message = choices[0].get("message") or {}
    raw_content = message.get("content")
    tool_calls = [
        ToolCallRequest(
            id=call.get("id", ""),
            name=(call.get("function") or {}).get("name", ""),
            arguments=_parse_tool_call_arguments((call.get("function") or {}).get("arguments")),
        )
        for call in (message.get("tool_calls") or [])
    ]
    return LLMResponse(
        content=_normalize_message_content(raw_content),
        tool_calls=tool_calls,
        finish_reason=choices[0].get("finish_reason") or "stop",
        content_was_malformed=_content_is_malformed(raw_content),
    )


class CopilotOAuthProvider:
    def __init__(self, model: str | None = None):
        self.provider_id = COPILOT_PROVIDER_ID
        self.model = model or COPILOT_DEFAULT_MODEL
        self.context_limit = COPILOT_MODELS.get(self.model)

    def complete(
        self, messages: list[dict], tools: list[dict] | None = None, stop_check: Callable[[], bool] | None = None
    ) -> LLMResponse:
        body = {"model": self.model, "messages": messages, "stream": False}
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"

        logger.debug("copilot_provider: request model=%s messages=%d tools=%d", self.model, len(messages), len(tools or []))

        payload = _call_with_backoff(lambda: self._raw_request(body), stop_check=stop_check)
        response = _parse_copilot_response(payload)

        logger.debug(
            "copilot_provider: response finish_reason=%s tool_calls=%d content_preview=%s",
            response.finish_reason, len(response.tool_calls),
            truncate_for_log(response.content or "", step_id=f"copilot_response_{int(time.time() * 1000)}"),
        )
        return response

    def _raw_request(self, body: dict) -> dict:
        """One full request/response cycle, including the single 401-triggers-refresh-and-retry
        that get_valid_copilot_token's own docstring describes -- this is NOT the retry loop for
        transient failures, that's _call_with_backoff wrapping this whole method. Raises the openai
        SDK's own exception types on failure so the outer retry loop (and agent/core.py's
        fallback-chain logic above it) handles a Copilot failure exactly like any other provider's.
        """
        token = get_valid_copilot_token()
        response = self._post(body, token)
        if response.status_code == 401:
            logger.debug("copilot_provider: got 401, forcing a token refresh and retrying once")
            token = get_valid_copilot_token(force_refresh=True)
            response = self._post(body, token)

        if response.status_code == 429:
            raise openai.RateLimitError(f"GitHub Copilot rate limit reached ({response.status_code}).", response=response, body=None)
        if not response.is_success:
            raise openai.APIStatusError(f"Copilot backend returned {response.status_code}: {response.text[:300]}", response=response, body=None)
        return response.json()

    @staticmethod
    def _post(body: dict, token: str) -> httpx.Response:
        headers = {**_REQUIRED_HEADERS, "Authorization": f"Bearer {token}"}
        request_timeout = float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", str(_DEFAULT_REQUEST_TIMEOUT_SECONDS)))
        try:
            return httpx.post(f"{_COPILOT_BASE_URL}/chat/completions", json=body, headers=headers, timeout=request_timeout)
        except httpx.TimeoutException as exc:
            raise openai.APITimeoutError(request=exc.request) from exc
        except httpx.ConnectError as exc:
            raise openai.APIConnectionError(message=str(exc), request=exc.request) from exc
