"""LLMProvider interface, OpenAICompatProvider, PROVIDER_REGISTRY (opencode-zen default, free — Qwen available via LLM_PROVIDER=qwen).

OpenAICompatProvider talks to any OpenAI-compatible chat/completions endpoint — not a coincidence,
most current LLM providers (Mistral, OpenRouter, Groq, xAI, Cerebras, NVIDIA, DeepSeek, Moonshot AI,
MiniMax, Zhipu/Z.ai, Google Gemini, Perplexity, Xiaomi MiMo, opencode-zen, Qwen/DashScope) use this
same wire format. Anthropic's Messages API is a different format and deliberately not
implemented here: LLMProvider is the seam where a second implementation would plug in later,
without touching prompts.py/core.py.
"""
from __future__ import annotations

import contextvars
import json
import os
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import httpx
from dotenv import dotenv_values, find_dotenv, set_key, unset_key

from agent.utils.lazy_openai import openai

from agent.custom_providers import (
    CUSTOM_MODELS_DEV_ID,
    get_custom_provider,
    is_custom_provider_id,
    load_custom_providers,
)
from agent.providers.models_dev import get_model_capabilities, list_models, validate_model_known
from agent.settings import is_provider_enabled, load_llm_settings
from agent.utils.debug import current_session_id, truncate_for_log
from agent.utils.errors import describe_exception
from agent.utils.logger import get_logger

logger = get_logger("LLM")

# Public: main.py's web layer reads this to show the configured default in the scan form.
DEFAULT_PROVIDER = "opencode-zen"

# "Sign in with ChatGPT" -- a third provider category alongside PROVIDER_REGISTRY's 8 API-key
# built-ins and custom instances (agent/custom_providers.py): a ChatGPT Plus/Pro/Team subscription
# session, authenticated via OAuth instead of an API key. See agent/codex_provider.py's own module
# docstring for why this needs a real second LLMProvider implementation (a different backend/wire
# protocol entirely) rather than another PROVIDER_REGISTRY row. Defined here, not there, so this
# module never has to import codex_provider at module scope -- codex_provider.py itself imports
# several small pieces from THIS module (LLMResponse/ToolCallRequest/_call_with_backoff/
# _parse_tool_call_arguments), and importing it back here at the top level would be circular;
# every function below that needs the real CodexOAuthProvider class imports it lazily, inside the
# function body, once this module has already finished loading.
CODEX_PROVIDER_ID = "openai-chatgpt"
CODEX_DISPLAY_NAME = "OpenAI (ChatGPT sign-in)"
# "Sign in with GitHub Copilot" -- the GitHub-Copilot counterpart of CODEX_PROVIDER_ID above, same
# reasoning (a real subscription session via OAuth, not an API key, needs its own LLMProvider
# because the wire protocol/auth mechanics don't fit a plain PROVIDER_REGISTRY row). See
# agent/copilot_provider.py's own module docstring for why Copilot's chat/completions endpoint,
# despite being OpenAI-compatible, still can't just be another OpenAICompatProvider instance.
COPILOT_PROVIDER_ID = "github-copilot"
COPILOT_DISPLAY_NAME = "GitHub Copilot (sign-in)"
# The openai SDK requires a non-empty api_key string even against endpoints that don't check it
# (opencode-zen's free models work with no key at all).
_PLACEHOLDER_API_KEY = "not-needed"

# Real, confirmed incident this fixes: a 429 with NO Retry-After header only got 3 real retries
# totalling ~14s of wait (2+4+8) before _call_with_backoff gave up and let RateLimitError propagate
# all the way out of run_session -- confirmed live to kill an entire 2h45m session outright, one
# call after the model had already produced a complete, correct final analysis summary (24 real
# findings already recorded). The SAME kind of 429 burst, but WITH a Retry-After header, got up to
# ~90s of total wait across the same 3 retries (each capped at _DEFAULT_MAX_RETRY_AFTER_SECONDS)
# and recovered every single time that session, including from a header value asking for over
# 10000s. A headerless 429 deserves the same real recovery window, not a much thinner one just
# because the server didn't say how long to wait -- extended to reach the same 30s ceiling by the
# last attempt (2+4+8+16+30 = 60s total across 5 retries) while keeping every individual wait
# short enough to stay visible/interruptible (_interruptible_sleep already polls stop_check during
# each one), not a return to the multi-minute silent-hang shape _DEFAULT_MAX_RETRY_AFTER_SECONDS
# itself exists to prevent.
_RETRY_DELAYS_SECONDS = (2, 4, 8, 16, 30)
# The closing tag optionally tolerates a "｜DSML｜" prefix (U+FF5C fullwidth pipes, the same
# special-token convention DeepSeek's own tokenizer uses elsewhere, e.g. <｜User｜>/<｜Assistant｜>)
# -- confirmed live: deepseek-v4-flash-free, once its own native tool-calling got rejected and this
# project fell back to prompt-based mode, inconsistently closed an otherwise well-formed
# <tool_call>{...} block with </｜DSML｜tool_call> instead of </tool_call>, and the strict version of
# this pattern silently discarded the entire call (a real, fully-committed tool call the model had
# already written out correctly) instead of just accepting the differently-spelled closer.
#
# The closing tag ALSO optionally tolerates a plural "tool_calls" -- a second, separate real
# incident: the exact same model/fallback shape closed with </｜DSML｜tool_calls> (plural AND
# DSML-prefixed) across one whole session, and the singular-only "tool_call" literal here silently
# discarded 8 correct, fully-committed calls, falling back to a generic "no parseable decision" for
# 6 of that session's 10 findings. Confirmed live the opening tag stays singular ("<tool_call>")
# even when the model pluralizes the close, so only the closing side needs the tolerance.
_TOOL_CALL_PATTERN = re.compile(r"<tool_call>\s*(\{.*?\})\s*</(?:｜DSML｜)?tool_calls?>", re.DOTALL)
# The same model also sometimes reverts entirely to this native special-token dialect instead of
# the <tool_call>{json}</tool_call> wrapper the prompt injection below asks for --
# <｜DSML｜invoke name="..."><｜DSML｜parameter name="...">value</｜DSML｜parameter></｜DSML｜invoke>.
# Confirmed live: across one real session's Exploit phase, this exact format (plus the mismatched-
# closer variant above) cost 9 separate wasted round-trips -- a parse failure, then a repair
# attempt that itself often failed the same way again -- every one of them a real, well-formed tool
# call the model had already fully committed to, just wrapped in the wrong syntax.
_DSML_INVOKE_PATTERN = re.compile(r"<｜DSML｜invoke name=\"([^\"]+)\">(.*?)</｜DSML｜invoke>", re.DOTALL)
_DSML_PARAMETER_PATTERN = re.compile(r"<｜DSML｜parameter name=\"([^\"]+)\"[^>]*>(.*?)</｜DSML｜parameter>", re.DOTALL)
# A DSML artifact can also leak into a tool argument's own string VALUE, not just the wrapper
# syntax the two patterns above tolerate -- confirmed live: opencode-zen's "big-pickle" model glued
# a stray closing pseudo-tag plus a fragment of a DIFFERENT DSML parameter onto the end of a
# record_hypothesis "evidence" string, e.g. ...real evidence text</evidence>\n<｜DSML｜parameter
# name="source_tool" string="true">wayback_urls. The surrounding JSON stayed syntactically valid
# (it's just extra characters inside a string), so nothing crashed -- the garbage just made it into
# stored data unnoticed. Matches from an optional stray closing tag through to end-of-string since
# every real occurrence has been trailing garbage, never a marker embedded before real content.
_DSML_STRING_ARTIFACT_PATTERN = re.compile(r"(?:</[A-Za-z_]\w*>)?\s*<｜DSML｜.*", re.DOTALL)


def _sanitize_dsml_string_artifacts(arguments: dict) -> dict:
    sanitized = {}
    for key, value in arguments.items():
        if isinstance(value, str):
            match = _DSML_STRING_ARTIFACT_PATTERN.search(value)
            sanitized[key] = value[: match.start()].rstrip() if match else value
        else:
            sanitized[key] = value
    return sanitized
# Without an explicit timeout the openai SDK falls back to its own 600s default, which turns a
# single slow/stuck request into a ~10-minute hang before anything even gets a chance to retry.
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 120
# _fetch_local_model_ids's own timeout, deliberately its own short knob -- NOT
# LLM_REQUEST_TIMEOUT_SECONDS above. That one is sized for a real, in-use completion call (which can
# legitimately take a while); this one is a passive "is a local server even running" discovery
# check fired on every single Settings page load (get_model_choices, once per configured provider).
# Real, confirmed incident: on this project's own WSL2 launch path, a connection attempt to a local
# provider's port with NOTHING actually listening (LM Studio/Ollama not started) took ~5.8s to fail
# -- not because the app waited that long on purpose, but because that's how long the underlying
# network stack itself took to report "nothing there". A live-and-slow-to-answer local server is a
# real possibility this still tolerates (a few seconds is plenty for a genuine /models list); a
# server that's simply not running should be treated as "no models yet" fast, not silently added to
# the operator's own page-load time. Repeat Settings loads no longer pay this probe at all (results
# are cached, see get_model_choices below), so this cap now only bounds the first/cold probe -- a
# genuine local server on loopback answers in milliseconds, well inside it.
_DEFAULT_LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS = 2
# A 429 response's Retry-After header is the server's own number, not ours — a shared/free
# endpoint under heavy load can send back a value of several minutes, and honoring it verbatim
# blocks this call's whole background thread (asyncio.to_thread) for that long with nothing
# logged in between, which reads exactly like a hang (real incident: a scan sat silent for
# close to an hour on a single retryable 429 before Ctrl+C surfaced anything). Capped here so a
# server-dictated wait can never exceed what's still a reasonable, visible retry cadence.
_DEFAULT_MAX_RETRY_AFTER_SECONDS = 30
# A backoff wait is the one place a retry loop blocks for many seconds with no real work
# happening -- real incident: an operator's Stop click during a 429 backoff sat completely
# ignored until every remaining retry attempt (and its own wait) had run its course, because
# core.py's stop-event check only happens before a call starts, not during a sleep already in
# progress inside this thread. Sleeping in small slices and re-checking stop_check() between them
# is what actually makes Stop responsive mid-wait instead of only between whole LLM calls.
_STOP_POLL_INTERVAL_SECONDS = 1.0


@dataclass(frozen=True)
class ToolCallRequest:
    id: str
    name: str
    arguments: dict

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", _sanitize_dsml_string_artifacts(self.arguments))


@dataclass(frozen=True)
class LLMResponse:
    content: str | None
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    finish_reason: str | None = None
    # True when the raw provider response's own message.content was NOT the promised str | None
    # shape (see _normalize_message_content's docstring for the real incident) -- content itself
    # is always a safe, already-normalized string here regardless, but this flag is what lets
    # agent/core.py's tool loop tell "the model genuinely produced plain text with 0 tool calls"
    # apart from "the model tried to express tool calls in some non-standard shape and it got
    # silently flattened to text", which look identical once normalized but deserve different
    # handling -- the former is a real answer, the latter is lost work worth one reinforcement
    # retry, same "give it one explicit nudge" pattern already applied to a refusal-shaped reply.
    content_was_malformed: bool = False
    # {"prompt_tokens": int, "completion_tokens": int} straight off the raw provider response's own
    # `usage` field, or None when that provider didn't report it at all (some OpenAI-compatible
    # endpoints omit `usage` entirely, especially free tiers) -- see _extract_usage's own docstring.
    # Feeds agent/core.py's per-provider usage/cost tracking (compute_llm_usage_summary); nothing in
    # this module's own request/response handling reads it back.
    usage: dict | None = None


class LLMProvider(Protocol):
    context_limit: int | None
    # core.py's _llm_complete reads provider_id+model together to track which (provider, model)
    # fallback-chain steps have already been tried for the current run (get_next_chain_step).
    provider_id: str
    model: str

    def complete(
        self, messages: list[dict], tools: list[dict] | None = None, stop_check: Callable[[], bool] | None = None
    ) -> LLMResponse: ...


@dataclass(frozen=True)
class ProviderConfig:
    models_dev_id: str  # provider key in the models.dev catalog, used for capability lookups
    display_name: str  # human-facing label — Settings renders this, never the raw registry key
    base_url_env: str
    base_url_default: str
    api_key_env: str
    api_key_required: bool
    model_env: str
    model_default: str
    # True for a provider whose server runs on the operator's own machine (LM Studio, Ollama).
    # Its model set is whatever that person happens to have pulled/loaded locally -- disjoint from
    # any hosted catalog -- so get_provider() skips models.dev validate_model_known() for it, and
    # get_model_choices() below queries the local server itself for the Settings dropdown instead
    # of trusting models.dev's static (and largely irrelevant) sample list for it.
    is_local: bool = False


# Config table, not code-per-provider: a new OpenAI-compatible provider is a new row here, not a
# new LLMProvider implementation.
PROVIDER_REGISTRY: dict[str, ProviderConfig] = {
    "opencode-zen": ProviderConfig(
        models_dev_id="opencode",
        display_name="opencode-zen",
        base_url_env="OPENCODE_ZEN_BASE_URL",
        base_url_default="https://opencode.ai/zen/v1",
        api_key_env="OPENCODE_ZEN_API_KEY",
        api_key_required=False,
        model_env="OPENCODE_ZEN_MODEL",
        model_default="big-pickle",
    ),
    "qwen": ProviderConfig(
        models_dev_id="alibaba",
        display_name="Qwen",
        base_url_env="QWEN_BASE_URL",
        base_url_default="https://dashscope-intl.aliyuncs.com/compatible-mode/v1",
        api_key_env="QWEN_API_KEY",
        api_key_required=True,
        model_env="QWEN_MODEL",
        model_default="qwen-plus",
    ),
    "mistral": ProviderConfig(
        models_dev_id="mistral",
        display_name="Mistral",
        base_url_env="MISTRAL_BASE_URL",
        base_url_default="https://api.mistral.ai/v1",
        api_key_env="MISTRAL_API_KEY",
        api_key_required=True,
        model_env="MISTRAL_MODEL",
        model_default="mistral-small-latest",
    ),
    "openrouter": ProviderConfig(
        models_dev_id="openrouter",
        display_name="OpenRouter",
        base_url_env="OPENROUTER_BASE_URL",
        base_url_default="https://openrouter.ai/api/v1",
        api_key_env="OPENROUTER_API_KEY",
        api_key_required=True,
        model_env="OPENROUTER_MODEL",
        # openrouter/auto lets OpenRouter itself pick a suitable model per-request rather than
        # this registry hardcoding a preference for one vendor behind OpenRouter's 300+ models.
        model_default="openrouter/auto",
    ),
    "openai": ProviderConfig(
        models_dev_id="openai",
        display_name="OpenAI",
        base_url_env="OPENAI_BASE_URL",
        base_url_default="https://api.openai.com/v1",
        api_key_env="OPENAI_API_KEY",
        api_key_required=True,
        model_env="OPENAI_MODEL",
        model_default="gpt-5-mini",
    ),
    "moonshot": ProviderConfig(
        models_dev_id="moonshotai",
        display_name="Moonshot AI",
        base_url_env="MOONSHOT_BASE_URL",
        base_url_default="https://api.moonshot.ai/v1",
        api_key_env="MOONSHOT_API_KEY",
        api_key_required=True,
        model_env="MOONSHOT_MODEL",
        model_default="kimi-k2.5",
    ),
    "minimax": ProviderConfig(
        models_dev_id="minimax",
        display_name="MiniMax",
        base_url_env="MINIMAX_BASE_URL",
        # NOT models.dev's own catalog "api" field for this provider (.../anthropic/v1) -- that's
        # MiniMax's Anthropic-compatible endpoint, not the OpenAI-compatible one this whole file
        # requires (OpenAICompatProvider, per this module's own docstring). Confirmed against
        # MiniMax's own docs (platform.minimax.io/docs/guides/quickstart): "Compatible OpenAI API"
        # explicitly sets OPENAI_BASE_URL=https://api.minimax.io/v1, a different path entirely.
        base_url_default="https://api.minimax.io/v1",
        api_key_env="MINIMAX_API_KEY",
        api_key_required=True,
        model_env="MINIMAX_MODEL",
        model_default="MiniMax-M2",
    ),
    "zai": ProviderConfig(
        models_dev_id="zai",
        display_name="Zhipu AI (Z.ai / GLM)",
        base_url_env="ZAI_BASE_URL",
        base_url_default="https://api.z.ai/api/paas/v4",
        api_key_env="ZAI_API_KEY",
        api_key_required=True,
        model_env="ZAI_MODEL",
        model_default="glm-4.6",
    ),
    "gemini": ProviderConfig(
        models_dev_id="google",
        display_name="Google Gemini",
        base_url_env="GEMINI_BASE_URL",
        # Google's own official OpenAI-SDK compatibility layer (ai.google.dev/gemini-api/docs/openai)
        # -- Vertex AI (Google Cloud's separate ML platform, GCP project + service account/OAuth
        # instead of a bearer API key) is a different, much larger integration deliberately not
        # implemented here -- would need its own LLMProvider like CodexOAuthProvider, not a registry row.
        base_url_default="https://generativelanguage.googleapis.com/v1beta/openai/",
        api_key_env="GEMINI_API_KEY",
        api_key_required=True,
        model_env="GEMINI_MODEL",
        model_default="gemini-2.5-flash",
    ),
    "perplexity": ProviderConfig(
        models_dev_id="perplexity",
        display_name="Perplexity",
        base_url_env="PERPLEXITY_BASE_URL",
        base_url_default="https://api.perplexity.ai",
        api_key_env="PERPLEXITY_API_KEY",
        api_key_required=True,
        model_env="PERPLEXITY_MODEL",
        model_default="sonar-pro",
    ),
    "xiaomi": ProviderConfig(
        models_dev_id="xiaomi",
        display_name="Xiaomi MiMo",
        base_url_env="XIAOMI_BASE_URL",
        base_url_default="https://api.xiaomimimo.com/v1",
        api_key_env="XIAOMI_API_KEY",
        api_key_required=True,
        model_env="XIAOMI_MODEL",
        model_default="mimo-v2.5",
    ),
    "groq": ProviderConfig(
        models_dev_id="groq",
        display_name="Groq",
        base_url_env="GROQ_BASE_URL",
        base_url_default="https://api.groq.com/openai/v1",
        api_key_env="GROQ_API_KEY",
        api_key_required=True,
        model_env="GROQ_MODEL",
        model_default="llama-3.3-70b-versatile",
    ),
    "xai": ProviderConfig(
        models_dev_id="xai",
        display_name="xAI (Grok)",
        base_url_env="XAI_BASE_URL",
        base_url_default="https://api.x.ai/v1",
        api_key_env="XAI_API_KEY",
        api_key_required=True,
        model_env="XAI_MODEL",
        model_default="grok-4.6",
    ),
    "cerebras": ProviderConfig(
        models_dev_id="cerebras",
        display_name="Cerebras",
        base_url_env="CEREBRAS_BASE_URL",
        base_url_default="https://api.cerebras.ai/v1",
        api_key_env="CEREBRAS_API_KEY",
        api_key_required=True,
        model_env="CEREBRAS_MODEL",
        model_default="gpt-oss-120b",
    ),
    "nvidia": ProviderConfig(
        models_dev_id="nvidia",
        display_name="NVIDIA",
        base_url_env="NVIDIA_BASE_URL",
        base_url_default="https://integrate.api.nvidia.com/v1",
        api_key_env="NVIDIA_API_KEY",
        api_key_required=True,
        model_env="NVIDIA_MODEL",
        model_default="nvidia/llama-3.3-nemotron-super-49b-v1",
    ),
    "deepseek": ProviderConfig(
        models_dev_id="deepseek",
        display_name="DeepSeek",
        base_url_env="DEEPSEEK_BASE_URL",
        base_url_default="https://api.deepseek.com",
        api_key_env="DEEPSEEK_API_KEY",
        api_key_required=True,
        model_env="DEEPSEEK_MODEL",
        model_default="deepseek-chat",
    ),
    # Anthropic's real native wire protocol (the Messages API) is NOT OpenAI-compatible -- this
    # entire file deliberately only ever implements OpenAICompatProvider, per its own module
    # docstring. This works anyway because Anthropic itself ships a real, officially documented
    # OpenAI-SDK compatibility layer at this exact base_url (not a third-party shim) -- basic chat
    # completions and tool calling work through it; Anthropic's own docs note a couple of gaps
    # (strict JSON-schema function-calling mode, prompt caching) that don't affect this project's
    # own tool-calling usage.
    "anthropic": ProviderConfig(
        models_dev_id="anthropic",
        display_name="Anthropic",
        base_url_env="ANTHROPIC_BASE_URL",
        base_url_default="https://api.anthropic.com/v1",
        api_key_env="ANTHROPIC_API_KEY",
        api_key_required=True,
        model_env="ANTHROPIC_MODEL",
        model_default="claude-sonnet-5",
    ),
    # Local providers below -- no cloud account, no API key, talk to a server the operator runs on
    # their own machine. Grouped last (and flagged is_local=True) so the Settings screen can render
    # them in their own block instead of mixing them into the cloud-provider list.
    "lmstudio": ProviderConfig(
        models_dev_id="lmstudio",
        display_name="LM Studio",
        base_url_env="LMSTUDIO_BASE_URL",
        base_url_default="http://127.0.0.1:1234/v1",
        api_key_env="LMSTUDIO_API_KEY",
        api_key_required=False,
        model_env="LMSTUDIO_MODEL",
        # Only used if LM Studio's own /v1/models can't be reached yet (see get_model_choices) --
        # replace with whatever model is actually loaded in LM Studio.
        model_default="local-model",
        is_local=True,
    ),
    "ollama": ProviderConfig(
        models_dev_id="ollama-cloud",  # closest models.dev entry; local Ollama has no catalog of
        # its own there, so capability lookups for it are best-effort and routinely miss (handled
        # gracefully -- see get_model_capabilities's None contract).
        display_name="Ollama",
        base_url_env="OLLAMA_BASE_URL",
        base_url_default="http://localhost:11434/v1",
        api_key_env="OLLAMA_API_KEY",
        api_key_required=False,
        model_env="OLLAMA_MODEL",
        # Only used if Ollama's own /v1/models can't be reached yet (see get_model_choices) --
        # replace with whatever model is actually pulled in Ollama (`ollama pull <name>`).
        model_default="llama3.2",
        is_local=True,
    ),
}


def _looks_like_env_example_placeholder(value: str) -> bool:
    """True for a value that's still literally .env.example's own unfilled template text (every
    *_API_KEY line in that file follows the exact "your_x_api_key_here" convention -- confirmed
    across all 15 cloud built-ins there) rather than a real credential. Pattern-based, not a
    hardcoded per-provider string list -- catches a future provider's own placeholder for free, no
    edit needed here when PROVIDER_REGISTRY grows (this project's own "no hardcoding" rule).

    Real incident this fixes: this project's own env-sync discipline (a var missing from the real
    .env gets added immediately, copied verbatim from .env.example, including a
    your_x_api_key_here-style placeholder) means a var that's merely MISSING from an operator's
    real .env gets that literal
    placeholder text copied in as a stopgap -- but every "is this provider actually configured"
    check downstream (get_provider_api_key below, and every call site that used to read
    os.getenv(config.api_key_env) directly) only ever tested truthiness, so the copied-but-never-
    filled-in placeholder read as a real, working key. Confirmed live: a fresh .env.example -> .env
    copy (the project's own documented first-setup step) shows every one of those 13 providers as
    "Configured" in Settings before the operator has touched a single field -- not one operator's
    own mistake, a bug that reproduces for literally anyone who follows the setup instructions.
    """
    return value.startswith("your_") and value.endswith("_here")


def get_provider_api_key(config: ProviderConfig) -> str:
    """The one place every "does this provider have a real, usable API key" check in this project
    should read from, instead of a bare os.getenv(config.api_key_env) -- see
    _looks_like_env_example_placeholder's own docstring for why a raw truthiness check on that isn't
    enough. Empty string (never None) for both "unset" and "still the example's own placeholder",
    the same "no key" signal every existing caller already treats identically.
    """
    value = os.getenv(config.api_key_env) or ""
    return "" if _looks_like_env_example_placeholder(value) else value


def _get_custom_provider(provider_id: str, model: str | None, saved: dict) -> LLMProvider:
    """The custom-provider counterpart of get_provider()'s own PROVIDER_REGISTRY branch below --
    split out purely to keep that function's own resolution-order docstring readable, not because
    the two paths share meaningfully different logic. A custom instance carries its OWN base_url/
    api_key directly (no .env involved, since an arbitrary number of these can exist and a fixed
    env var name can't scale to that) — see agent/custom_providers.py's own module docstring.
    """
    custom = get_custom_provider(provider_id)
    if custom is None:
        raise ValueError(f"Unknown LLM provider {provider_id!r}. Known providers: {list(PROVIDER_REGISTRY)} plus any custom provider added in Settings.")
    if not custom.get("enabled", True):
        raise ValueError(f"Custom provider {custom['name']!r} is disabled.")

    saved_model = saved.get("model") if saved.get("provider") == provider_id else None
    resolved_model = model or saved_model or custom.get("model") or ""
    if not resolved_model:
        raise ValueError(f"No model specified for custom provider {custom['name']!r}.")

    # No models.dev entry can ever exist for an arbitrary custom endpoint -- same "skip catalog
    # validation, the model name is whatever the operator says it is" treatment get_provider()'s
    # own is_local branch already gives local providers, for the identical reason.
    logger.debug("get_provider: %s is a custom provider, skipping models.dev validation for model=%s", provider_id, resolved_model)
    logger.debug("get_provider: resolved custom provider=%s model=%s base_url=%s", provider_id, resolved_model, custom["base_url"])
    return OpenAICompatProvider(
        provider_id=provider_id,
        models_dev_id=CUSTOM_MODELS_DEV_ID,
        base_url=custom["base_url"],
        api_key=custom.get("api_key") or "",
        model=resolved_model,
    )


def _get_codex_provider(model: str | None, saved: dict) -> LLMProvider:
    """The "Sign in with ChatGPT" counterpart of _get_custom_provider above -- split out for the
    same reason. Raises ValueError (not codex_oauth's own RuntimeError) when nobody has signed in
    yet, so this behaves exactly like every other "not configured" provider from every caller's
    point of view -- in particular get_next_chain_step's own `except ValueError: skip this step`
    handling, which would NOT catch a bare RuntimeError and would instead crash the whole fallback
    walk on the first unconfigured Codex step in someone's chain.
    """
    from agent.codex_oauth import is_signed_in
    from agent.codex_provider import CODEX_DEFAULT_MODEL, CodexOAuthProvider

    if not is_signed_in():
        raise ValueError('Not signed in to ChatGPT. Go to Settings and click "Sign in with ChatGPT" first.')
    saved_model = saved.get("model") if saved.get("provider") == CODEX_PROVIDER_ID else None
    resolved_model = model or saved_model or CODEX_DEFAULT_MODEL
    logger.debug("get_provider: resolved openai-chatgpt (Codex OAuth) model=%s", resolved_model)
    return CodexOAuthProvider(model=resolved_model)


def _get_copilot_provider(model: str | None, saved: dict) -> LLMProvider:
    """The "Sign in with GitHub Copilot" counterpart of _get_codex_provider above -- same reasoning,
    same ValueError-not-RuntimeError contract for get_next_chain_step's own fallback-chain handling.
    """
    from agent.copilot_oauth import is_signed_in
    from agent.copilot_provider import COPILOT_DEFAULT_MODEL, CopilotOAuthProvider

    if not is_signed_in():
        raise ValueError('Not signed in to GitHub Copilot. Go to Settings and click "Sign in with GitHub Copilot" first.')
    saved_model = saved.get("model") if saved.get("provider") == COPILOT_PROVIDER_ID else None
    resolved_model = model or saved_model or COPILOT_DEFAULT_MODEL
    logger.debug("get_provider: resolved github-copilot (Copilot OAuth) model=%s", resolved_model)
    return CopilotOAuthProvider(model=resolved_model)


def get_provider(provider_id: str | None = None, model: str | None = None) -> LLMProvider:
    """Builds an LLMProvider from PROVIDER_REGISTRY + env, with the Settings-screen choice
    (data/llm_settings.json) as the default between explicit args and .env. Resolution order,
    most to least specific: explicit provider_id/model arg (a one-off override) > saved Settings
    choice > .env > PROVIDER_REGISTRY's hardcoded default. A saved model is only trusted when it
    was saved for the SAME provider being resolved — otherwise switching providers in Settings
    could leak a stale model name from the previous one.

    A provider_id shaped like a custom-provider id (agent/custom_providers.py's own "custom-"
    prefix) is resolved from there instead — see _get_custom_provider above. CODEX_PROVIDER_ID
    ("Sign in with ChatGPT") is resolved via _get_codex_provider, and COPILOT_PROVIDER_ID
    ("Sign in with GitHub Copilot") via _get_copilot_provider, same idea.
    """
    saved = load_llm_settings()
    resolved_id = provider_id or saved.get("provider") or os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER)
    if is_custom_provider_id(resolved_id):
        return _get_custom_provider(resolved_id, model, saved)
    if resolved_id == CODEX_PROVIDER_ID:
        return _get_codex_provider(model, saved)
    if resolved_id == COPILOT_PROVIDER_ID:
        return _get_copilot_provider(model, saved)

    config = PROVIDER_REGISTRY.get(resolved_id)
    if config is None:
        raise ValueError(f"Unknown LLM provider {resolved_id!r}. Known providers: {list(PROVIDER_REGISTRY)}")

    base_url = os.getenv(config.base_url_env) or config.base_url_default
    api_key = get_provider_api_key(config)
    if config.api_key_required and not api_key:
        raise ValueError(f"{config.api_key_env} is not set (required for provider {resolved_id!r}).")
    saved_model = saved.get("model") if saved.get("provider") == resolved_id else None
    resolved_model = model or saved_model or os.getenv(config.model_env) or config.model_default

    if config.is_local:
        # A local model name is whatever the operator happened to pull/load on their own machine
        # -- never in any hosted catalog, so checking it against models.dev would reject every
        # legitimate local model as a "typo".
        logger.debug("get_provider: %s is local, skipping models.dev validation for model=%s", resolved_id, resolved_model)
    else:
        # Fail fast at startup on a typo'd model name — not mid-session. A models.dev outage is not
        # a reason to fail (validate_model_known() itself no-ops when the catalog is unreachable).
        validate_model_known(config.models_dev_id, resolved_model)

    logger.debug("get_provider: resolved provider=%s model=%s base_url=%s", resolved_id, resolved_model, base_url)
    return OpenAICompatProvider(
        provider_id=resolved_id,
        models_dev_id=config.models_dev_id,
        base_url=base_url,
        api_key=api_key,
        model=resolved_model,
    )


def all_provider_choices() -> list[tuple[str, str]]:
    """(provider_id, display_name) for every selectable provider -- the built-ins
    (PROVIDER_REGISTRY, definition order), then "Sign in with ChatGPT" (CODEX_PROVIDER_ID -- listed
    regardless of whether anyone has actually signed in yet, same as an API-key built-in is listed
    before its key is ever set), then every ENABLED custom instance (creation order). The one list
    every provider-picking dropdown in this app (Settings' own AI Provider & Model picker, Reserve
    providers' chain rows, a subagent profile's own picker) renders from, so a newly added custom
    provider shows up everywhere at once instead of each dropdown needing to be taught about it
    separately. CODEX_PROVIDER_ID and COPILOT_PROVIDER_ID are inserted right after the cloud
    built-ins and before the local (is_local=True) ones -- a plain append would land them after
    Ollama, visually mixed into the local-provider group they have nothing to do with.
    """
    cloud = [(pid, cfg.display_name) for pid, cfg in PROVIDER_REGISTRY.items() if not cfg.is_local and is_provider_enabled(pid)]
    local = [(pid, cfg.display_name) for pid, cfg in PROVIDER_REGISTRY.items() if cfg.is_local and is_provider_enabled(pid)]
    choices = [*cloud, (CODEX_PROVIDER_ID, CODEX_DISPLAY_NAME), (COPILOT_PROVIDER_ID, COPILOT_DISPLAY_NAME), *local]
    choices += [(p["id"], p["name"]) for p in load_custom_providers() if p.get("enabled", True)]
    return choices


def configured_provider_choices() -> list[tuple[str, str]]:
    """Same universe as all_provider_choices() above, narrowed to providers actually USABLE right
    now -- a real saved API key (or none needed at all: opencode-zen/LM Studio/Ollama), or an
    actual signed-in OAuth session for Codex/Copilot. Real motivation: Reserve providers/Secondary
    verification are both "pick one to actually fall back to / cross-check with" pickers, where an
    unconfigured entry is worse than useless -- it LOOKS like a real, pickable option, and picking
    it just gets silently skipped at scan time (get_next_chain_step's own "not usable" tolerance) --
    confirmed live operator confusion. Custom instances aren't filtered further (already limited to
    ENABLED ones by all_provider_choices() itself, and creating one already requires typing its
    endpoint, so "created" already implies "configured" for that shape unlike a maybe-blank key).

    Local providers (LM Studio/Ollama) are always included here despite having no key to check --
    whether the local server is actually reachable right now is a live-probe question these
    pickers already handle separately (Reserve providers' own per-row on-demand model lookup), not
    something this static, non-network-calling function can answer.
    """
    from agent.codex_oauth import is_signed_in as codex_is_signed_in
    from agent.copilot_oauth import is_signed_in as copilot_is_signed_in

    configured = []
    for provider_id, display_name in all_provider_choices():
        if provider_id == CODEX_PROVIDER_ID:
            if codex_is_signed_in():
                configured.append((provider_id, display_name))
            continue
        if provider_id == COPILOT_PROVIDER_ID:
            if copilot_is_signed_in():
                configured.append((provider_id, display_name))
            continue
        config = PROVIDER_REGISTRY.get(provider_id)
        if config is None:
            configured.append((provider_id, display_name))  # a custom instance -- see docstring
            continue
        if not config.api_key_required or get_provider_api_key(config):
            configured.append((provider_id, display_name))
    return configured


def is_known_provider_id(provider_id: str) -> bool:
    return (
        provider_id in PROVIDER_REGISTRY
        or provider_id in (CODEX_PROVIDER_ID, COPILOT_PROVIDER_ID)
        or get_custom_provider(provider_id) is not None
    )


def get_fallback_chain_enabled() -> bool:
    """Settings -> Reserve providers' own on/off switch (data/llm_settings.json), off by default.

    Real incident this whole mechanism (this function + get_fallback_chain/get_next_chain_step
    below) replaces: the previous get_fallback_provider always ran automatically the instant a
    provider's retry budget was exhausted, silently switching to the first OTHER configured
    provider in PROVIDER_REGISTRY's own fixed iteration order — including a PAID provider the
    operator had a key for but never meant to be used as a fallback for a different one, spending
    real tokens/money with no explicit opt-in. Off (the safe default) means _llm_complete raises
    the original failure immediately instead, exactly as if only one provider were configured at
    all — no implicit cross-provider jumping. On means the operator has explicitly built their own
    ordered chain below and accepted the warning shown when enabling it in Settings.
    """
    return bool(load_llm_settings().get("fallback_chain_enabled"))


def get_fallback_chain() -> list[dict]:
    """The operator's own ordered reserve list (Settings -> Reserve providers) — a flat, ordered
    list of {"provider": provider_id, "model": model} steps, one per dropdown row on that screen
    (main.py's save_fallback_chain route). Several rows sharing a provider is how "try these models
    on this provider in order" is expressed — no separate per-provider grouping, get_next_chain_step
    below just walks this list directly. Empty when never configured, same "nothing set -> no
    behavior change" default every other optional Settings field in this project already follows.
    """
    chain = load_llm_settings().get("fallback_chain")
    return chain if isinstance(chain, list) else []


def get_next_chain_step(
    chain: list[dict], tried_steps, health_ranking: dict[tuple[str, str], float] | None = None,
) -> LLMProvider | None:
    """The first not-yet-tried (provider, model) step in the operator's own configured chain, for
    core.py's _llm_complete once the currently active provider/model's own retry budget
    (_call_with_backoff) is exhausted and get_fallback_chain_enabled() is True. Walks the list in
    the operator-arranged order by default — never PROVIDER_REGISTRY's own iteration order. Skips
    a step whose provider isn't actually usable right now (e.g. its required API key was never
    set) rather than giving up on the rest of the chain — same recoverability contract the old
    get_fallback_provider already had. None once every step has been tried or none are usable.

    health_ranking, when given (agent/core.py's own _cached_provider_health_ranking, derived from
    compute_efficiency_score's cross-session cleanliness data per (provider, model) pair), reorders
    the still-untried candidates by descending score first -- real, confirmed motivation: this
    session's own log-review audit found real LLM budget repeatedly burned retrying a provider/
    model pair with a recent history of timeouts/quota errors, purely because it happened to sit
    first in the operator's static list. A pair with no score yet (never dispatched to, or not
    enough sessions for compute_efficiency_score to have has_data=True) defaults to 0.0 -- neither
    preferred over nor penalized below a pair with a confirmed track record either way. None (the
    default) leaves today's exact operator-arranged order untouched, and an empty dict behaves
    identically to None (Python's sort is stable, so an all-equal-key sort is a no-op reorder) --
    this module has no opinion on where health data comes from or whether any exists yet, it only
    ever reorders when explicitly handed real scores.
    """
    candidates = [
        (entry.get("provider"), entry.get("model")) for entry in chain
    ]
    candidates = [(p, m) for p, m in candidates if p and m and (p, m) not in tried_steps]
    if health_ranking:
        candidates.sort(key=lambda step: health_ranking.get(step, 0.0), reverse=True)
    for provider_id, model in candidates:
        try:
            return get_provider(provider_id, model)
        except ValueError:
            logger.debug("get_next_chain_step: %s/%s not usable as a fallback step (not configured)", provider_id, model)
    return None


# Anchored once to the same .env agent/__init__.py's bare load_dotenv() already found at process
# start (find_dotenv(usecwd=True) mirrors load_dotenv()'s own upward search from CWD), falling back
# to the repo-root path only for a fresh clone where .env doesn't exist yet.
_ENV_PATH = find_dotenv(usecwd=True) or str(Path(__file__).resolve().parent.parent / ".env")


def _test_openai_compatible_connection(base_url: str, api_key: str) -> dict:
    """Shared body of check_api_key (a PROVIDER_REGISTRY built-in) and test_custom_provider below
    (an arbitrary custom instance) -- both ultimately just need "does this base_url/api_key pair
    authenticate", the provider-lookup step around it is the only part that differs between the
    two callers. Deliberately not a .complete() call (that's /api/settings/test-llm's job, and it
    genuinely costs tokens); this calls the OpenAI-compatible models-list endpoint instead, free on
    every provider. Reuses the same "omit Authorization entirely when no key is set" logic
    OpenAICompatProvider already needed for opencode-zen's free tier (a placeholder Bearer token
    401s there even though no header at all succeeds) -- a second, independent client-construction
    path here would silently reproduce that exact bug for the empty-key case.
    """
    request_timeout = float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", str(_DEFAULT_REQUEST_TIMEOUT_SECONDS)))
    client = openai.OpenAI(
        base_url=base_url, api_key=api_key or _PLACEHOLDER_API_KEY, max_retries=0, timeout=request_timeout,
    )
    extra_headers = {"extra_headers": {"Authorization": openai.Omit()}} if not api_key else {}

    try:
        client.models.list(**extra_headers)
        if not api_key:
            # Real incident this fixes: an optional-key provider (opencode-zen) with an empty
            # field reaches this same success path (no Authorization header needed at all) and
            # used to report "Key accepted." — misleading, since no credential was tested or even
            # sent. Only a genuinely non-empty api_key earns that message.
            return {"ok": True, "message": "No key needed for this provider — reached the endpoint successfully."}
        return {"ok": True, "message": "Key accepted."}
    except openai.AuthenticationError:
        return {"ok": False, "message": "Rejected: authentication failed."}
    except openai.PermissionDeniedError:
        return {"ok": False, "message": "Rejected: permission denied."}
    except openai.NotFoundError:
        # This base_url doesn't expose a models-list route at all -- inconclusive, not proof the
        # key itself is bad. Never report an inconclusive result as a failure.
        return {"ok": True, "message": "Reached the provider (it doesn't support listing models, so the key wasn't fully verified, but there was no auth error)."}
    except openai.APIConnectionError:
        return {"ok": False, "message": "Could not reach the provider."}
    except openai.APIStatusError as exc:
        # Never forward exc's raw text: some providers echo the submitted key back inside an
        # error body on malformed-auth responses, which would leak it into the page the
        # masking in Settings is supposed to protect.
        return {"ok": False, "message": f"Test failed (HTTP {exc.status_code})."}


def check_api_key(provider_id: str, api_key: str, base_url: str | None = None) -> dict:
    """The Settings page's per-key Test button for a PROVIDER_REGISTRY built-in. base_url, when
    given, overrides .env/the registry default -- lets Settings test a custom endpoint override
    (a self-hosted gateway, a non-default local port) the moment it's typed, before it's ever
    saved, same "try before you commit" philosophy as test_llm's own model Test button.
    """
    config = PROVIDER_REGISTRY.get(provider_id)
    if config is None:
        return {"ok": False, "message": "Unknown provider."}
    base_url = base_url or os.getenv(config.base_url_env) or config.base_url_default
    return _test_openai_compatible_connection(base_url, api_key)


def test_custom_provider_connection(base_url: str, api_key: str) -> dict:
    """The Reserve providers/LLM Providers screen's own Test button for a custom instance (Add
    Provider modal, or an existing one's own row) -- same underlying check as check_api_key, just
    without a PROVIDER_REGISTRY lookup since base_url/api_key are already known directly."""
    return _test_openai_compatible_connection(base_url, api_key)


def _fetch_local_model_ids(base_url: str, api_key: str) -> list[str]:
    """Queries a local OpenAI-compatible server's own /models endpoint -- the only source that
    actually knows what's loaded/pulled on THIS machine right now. models.dev's static catalog has
    no way to know that (it lists a handful of illustrative example models, not a live inventory),
    so local providers can't be answered from it the way hosted ones are via list_models(). Empty
    (not an error) when the local server isn't running yet -- that's this feature's normal state
    before the operator starts LM Studio/Ollama, not a bug.

    A raw httpx GET, deliberately NOT the openai SDK client every other call in this module uses --
    real, confirmed live incident: the openai SDK client's own timeout=<short value> was NOT
    actually honored for a connection to a port with nothing listening (measured live: 5.6s to fail
    despite timeout=3.0 passed to its constructor), while a bare httpx.get() with the identical
    timeout against the identical address failed in under a second. Whatever the SDK does
    internally that makes this specific failure mode ignore its own configured timeout, plain httpx
    does not have the same problem -- and this endpoint's response shape (OpenAI's own
    {"data": [{"id": ...}, ...]} list-models format) is simple enough not to need the SDK's request/
    response modeling anyway.
    """
    discovery_timeout = float(os.getenv(
        "LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS", str(_DEFAULT_LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS),
    ))
    models_url = base_url.rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        # httpx.Client(...).get(...), not the bare httpx.get() convenience function -- the latter
        # binds its own internal Client reference at httpx's own import time (from ._client import
        # Client inside httpx's own api.py), which a test-side monkeypatch of the top-level
        # httpx.Client attribute can never intercept. An explicit Client here also matches this
        # project's own established pattern for every other one-off httpx call (native.py's
        # web_fetch/dns_lookup/...).
        with httpx.Client(timeout=discovery_timeout) as client:
            response = client.get(models_url, headers=headers)
        response.raise_for_status()
        return sorted(model["id"] for model in response.json().get("data", []))
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        logger.debug("llm_client: local model discovery failed for base_url=%s: %s", base_url, exc)
        return []


# Short-TTL cache for get_model_choices(). The Settings screen calls it once per provider on every
# render, and for local/custom endpoints (and Copilot) each call is a live network probe -- so an
# uncached Settings load paid that probe cost on every single load. Caching makes repeat loads
# instant; a mutation that can change a provider's model set clears the relevant entry (see
# invalidate_model_choices_cache callers) so edits still show up at once, not only after the TTL.
_MODEL_CHOICES_CACHE_TTL_SECONDS = float(os.getenv("MODEL_CHOICES_CACHE_TTL_SECONDS", "30"))
_model_choices_cache: dict[str, tuple[float, list[str]]] = {}
_model_choices_cache_lock = threading.Lock()


def invalidate_model_choices_cache(provider_id: str | None = None) -> None:
    """Drop cached model lists so the next get_model_choices() refetches live. Call after any change
    that can alter a provider's real model set (endpoint/key edit, custom-provider CRUD, a provider
    sign-in/out). provider_id=None clears the whole cache."""
    with _model_choices_cache_lock:
        if provider_id is None:
            _model_choices_cache.clear()
        else:
            _model_choices_cache.pop(provider_id, None)
    logger.debug("invalidate_model_choices_cache: provider=%s", provider_id or "*")


def get_model_choices(provider_id: str) -> list[str]:
    """Cached wrapper over _get_model_choices_uncached (TTL: MODEL_CHOICES_CACHE_TTL_SECONDS). See
    invalidate_model_choices_cache for how a provider edit bypasses the TTL."""
    now = time.monotonic()
    with _model_choices_cache_lock:
        cached = _model_choices_cache.get(provider_id)
        if cached is not None and now - cached[0] < _MODEL_CHOICES_CACHE_TTL_SECONDS:
            return cached[1]
    choices = _get_model_choices_uncached(provider_id)
    with _model_choices_cache_lock:
        _model_choices_cache[provider_id] = (now, choices)
    return choices


def _get_model_choices_uncached(provider_id: str) -> list[str]:
    """Model-dropdown source for the Settings screen. Local providers (is_local=True) and every
    custom provider instance are queried live -- their real model set has no models.dev entry to
    read from at all (a self-hosted/local server, or an arbitrary custom endpoint models.dev has
    never heard of) -- every other (built-in, cloud) provider comes from the shared models.dev
    catalog via list_models(). Empty (never raises) when nothing is known yet; callers already
    fall back to just the current model in that case, same as list_models() itself.
    """
    if is_custom_provider_id(provider_id):
        custom = get_custom_provider(provider_id)
        if custom is None:
            return []
        return _fetch_local_model_ids(custom["base_url"], custom.get("api_key") or "")

    if provider_id == CODEX_PROVIDER_ID:
        from agent.codex_provider import CODEX_MODELS
        return list(CODEX_MODELS.keys())

    if provider_id == COPILOT_PROVIDER_ID:
        from agent.copilot_provider import COPILOT_MODELS, fetch_copilot_models
        return fetch_copilot_models() or list(COPILOT_MODELS.keys())

    config = PROVIDER_REGISTRY.get(provider_id)
    if config is None:
        return []
    if config.is_local:
        base_url = os.getenv(config.base_url_env) or config.base_url_default
        api_key = get_provider_api_key(config)
        return _fetch_local_model_ids(base_url, api_key)
    return list_models(config.models_dev_id)


def save_provider_api_key(provider_id: str, api_key: str) -> None:
    """Writes a provider's key into .env and immediately mirrors it into the running process's
    os.environ -- agent/__init__.py's load_dotenv() only ever runs once at process start, so
    without the mirror a newly-saved key wouldn't take effect until a manual app restart. A
    read-back after the write (not trusting the write blindly) confirms the file actually holds
    what was just submitted before reporting success. Never logs the key value itself.
    """
    config = PROVIDER_REGISTRY[provider_id]
    set_key(_ENV_PATH, config.api_key_env, api_key)
    os.environ[config.api_key_env] = api_key
    if dotenv_values(_ENV_PATH).get(config.api_key_env) != api_key:
        raise RuntimeError(f"Wrote {config.api_key_env} to .env but the read-back didn't match -- refusing to report success.")
    logger.debug("save_provider_api_key: provider=%s written to %s", provider_id, _ENV_PATH)
    invalidate_model_choices_cache(provider_id)


def clear_provider_api_key(provider_id: str) -> None:
    config = PROVIDER_REGISTRY[provider_id]
    if os.path.exists(_ENV_PATH):
        unset_key(_ENV_PATH, config.api_key_env)
    os.environ.pop(config.api_key_env, None)
    logger.debug("clear_provider_api_key: provider=%s removed from %s", provider_id, _ENV_PATH)
    invalidate_model_choices_cache(provider_id)


def save_provider_base_url(provider_id: str, base_url: str) -> None:
    """Writes a provider's endpoint override into .env (same read-back-verified write + os.environ
    mirror as save_provider_api_key) -- lets an operator point a provider at something other than
    its registry default (a self-hosted OpenAI-compatible gateway, a corporate proxy, a non-default
    local port for LM Studio/Ollama) from Settings, without hand-editing .env. Unlike an API key,
    a base_url is never masked in the UI, so an intentionally-blanked field is unambiguous: it
    means "go back to the registry default", not "the operator didn't type anything" -- clearing
    the override is exactly that case, not a separate action the way clearing a secret is.
    """
    config = PROVIDER_REGISTRY[provider_id]
    if not base_url.strip():
        clear_provider_base_url(provider_id)
        return
    set_key(_ENV_PATH, config.base_url_env, base_url.strip())
    os.environ[config.base_url_env] = base_url.strip()
    if dotenv_values(_ENV_PATH).get(config.base_url_env) != base_url.strip():
        raise RuntimeError(f"Wrote {config.base_url_env} to .env but the read-back didn't match -- refusing to report success.")
    logger.debug("save_provider_base_url: provider=%s written to %s", provider_id, _ENV_PATH)
    invalidate_model_choices_cache(provider_id)


def clear_provider_base_url(provider_id: str) -> None:
    config = PROVIDER_REGISTRY[provider_id]
    if os.path.exists(_ENV_PATH):
        unset_key(_ENV_PATH, config.base_url_env)
    os.environ.pop(config.base_url_env, None)
    logger.debug("clear_provider_base_url: provider=%s removed from %s", provider_id, _ENV_PATH)
    invalidate_model_choices_cache(provider_id)


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


def _parse_tool_call_arguments(raw: str | None) -> dict:
    """Some providers occasionally emit valid JSON for a tool call's own arguments string, followed
    by extra trailing content (repeated/hallucinated text, a stray duplicate of the same object,
    ...) -- confirmed live: a real bug-bounty session's very first LLM call crashed the ENTIRE
    session outright with an unhandled json.JSONDecodeError ("Extra data: line 1 column 3164"), 15
    seconds in, before a single real tool call ever ran, because this call site used a bare
    json.loads() with nothing catching a malformed result. json.loads() requires the WHOLE string
    to be valid JSON with nothing left over; json.JSONDecoder().raw_decode() parses just the first
    complete JSON value and tells you where it ended, tolerating whatever comes after -- since the
    real incident's own error was specifically "Extra data" (a fully valid JSON object came first),
    the arguments the model actually intended were fully recoverable this way, not lost. Falls back
    to an empty dict only when the string is malformed from the very start (not just trailing
    garbage) or the first value isn't even a JSON object -- that still lets the call through to the
    target tool's own validation (e.g. a clear "missing required argument" error, same as any other
    incomplete tool call already produces there), a normal, retryable outcome instead of an
    unrecoverable crash.
    """
    raw = raw or "{}"
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        try:
            obj, _ = json.JSONDecoder().raw_decode(raw)
        except json.JSONDecodeError:
            obj = None
    if not isinstance(obj, dict):
        logger.debug("llm_client: tool call arguments are not valid JSON even after raw_decode, treating as empty: %s", truncate_for_log(raw))
        return {}
    return obj


def _normalize_message_content(content) -> str | None:
    """Every downstream caller of complete() (LLMResponse.content: str | None, core.py's
    _looks_like_a_refusal/_parse_json_response, this file's own truncate_for_log call) assumes
    plain text -- but the OpenAI SDK's own response typing only PROMISES message.content is
    str | None, and a real provider can return something else. Real, confirmed incident: Mistral's
    own OpenAI-compatible endpoint (mistral-large-latest, native tool-calling mode, tool_calls=[])
    returned message.content as a LIST of content-block dicts (a mix of {"type": "text", "text":
    ...} and {"type": "reference", "reference_ids": [...]} blocks -- the model appears to have
    tried to express several tool calls as citation-style text instead of using the real
    tool_calls field) -- core.py's _looks_like_a_refusal(response.content) then called
    _REFUSAL_PATTERN.search(content) on that list, raising TypeError: expected string or
    bytes-like object, got 'list', which killed the whole calling coroutine (a delegated
    subagent's own task, in the real incident) with a bare, uninformative "status": "error"
    instead of a normal, recoverable turn. Joins every "text"-shaped block's own text (the same
    tolerant "extract what we can, keep going" discipline this file already applies to tool-call
    arguments above), silently drops anything else (a citation/reference block carries no plain-
    text content any downstream code here reads anyway) -- never raises, str/None pass through
    completely unchanged.
    """
    if content is None or isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [block.get("text", "") for block in content if isinstance(block, dict) and block.get("type") == "text"]
        return "\n".join(part for part in parts if part) or None
    return str(content)


def _extract_usage(response) -> dict | None:
    """`response.usage` on the openai SDK's own ChatCompletion type is itself optional (some
    OpenAI-compatible endpoints -- confirmed on more than one free/budget tier -- omit it entirely
    rather than send zeros), so this must degrade to None, never raise or fabricate a 0/0 count that
    would read as "confirmed free" instead of "unknown". Only the two fields agent/core.py's
    per-provider cost estimate actually needs are pulled out here -- total_tokens is redundant
    (prompt+completion) and everything else on the usage object (reasoning_tokens, cached_tokens,
    ...) has no real per-provider pricing hook in this project yet.
    """
    usage = getattr(response, "usage", None)
    if usage is None:
        return None
    prompt_tokens = getattr(usage, "prompt_tokens", None)
    completion_tokens = getattr(usage, "completion_tokens", None)
    if prompt_tokens is None and completion_tokens is None:
        return None
    return {"prompt_tokens": prompt_tokens or 0, "completion_tokens": completion_tokens or 0}


def _content_is_malformed(raw_content) -> bool:
    """True when the raw provider response's own message.content wasn't the promised str | None
    shape -- see _normalize_message_content's own docstring for the real incident (Mistral's
    mistral-large-latest returning a list of text/reference blocks instead of using its real
    tool_calls field). Checked on the RAW value, before _normalize_message_content's own str
    conversion -- that function already makes `content` safe to use everywhere downstream, this
    is purely a signal for agent/core.py's tool loop to tell "the model genuinely produced plain
    text with 0 tool calls" apart from "the model tried to call tools in some non-standard shape
    and it got silently flattened to text", which read identically post-normalization but deserve
    different handling.
    """
    return raw_content is not None and not isinstance(raw_content, str)


def _is_retryable(exc: openai.APIStatusError) -> bool:
    return exc.status_code == 429 or exc.status_code >= 500


class EmptyResponseError(Exception):
    """Raised when a chat completion comes back as an outright 200 OK with no usable choice at
    all -- confirmed live on a real scan: opencode-zen's nemotron-3-ultra-free free model returned
    choices=None with no error status whatsoever, and the bare `response.choices[0]` that follows
    every completion call crashed the whole session on an unhandled TypeError. Treated the same as
    any other transient provider hiccup: retried by _call_with_backoff, and agent/core.py's
    _llm_complete swaps to the fallback provider if every retry still comes back empty.

    Also raised for the sibling case, confirmed live a second time (openrouter routing to the same
    free nemotron model): a real CHOICE is present, but the provider's own finish_reason on it is
    literally "error", with an empty message and no tool_calls -- still a 200 OK, still no exception
    the openai SDK itself would ever raise, so this was previously accepted as a normal (if content-
    less) completion. agent/tools/bugbounty_import.py's own _parse_json_response(None) surfaced this
    as a generic "couldn't extract structured fields" with no hint that the real cause was the
    provider silently failing to generate anything at all, retryable exactly like the empty-choices
    case above.
    """


class LLMCallAborted(Exception):
    """Raised from _call_with_backoff when stop_check() reports true during a backoff wait --
    agent/core.py catches this and turns it into the same SessionStopRequested an operator's Stop
    click already produces at the top of _llm_complete, so a Stop mid-retry is now honored within
    one poll interval instead of only once every remaining retry attempt has run its course.
    """


# ContextVar rather than a parameter threaded through LLMProvider.complete() and every concrete
# implementation (OpenAICompatProvider, Codex/Copilot's own) -- same reasoning agent/utils/debug.py's
# current_session_id already documents for this pattern: a purely cross-cutting, optional concern
# (only Settings' own Test button ever sets this) has no business changing every provider's own
# method signature. Set for the duration of one llm.complete() call by whoever wants live progress
# (Settings -> Test, see main.py's _run_test_llm_job), read here where a retry wait is about to
# happen; None everywhere else (the main agent loop, subagents, ...) is the normal, silent case.
current_retry_progress_sink: contextvars.ContextVar[Callable[[int, int, float], None] | None] = (
    contextvars.ContextVar("current_retry_progress_sink", default=None)
)

# Same ContextVar pattern as current_retry_progress_sink right above, for a different consumer:
# agent/core.py sets this to a fresh single-element list at the top of a delegated subagent's own
# isolated coroutine (same "set inside the fresh asyncio.Task's own context copy" idiom
# current_session_id already establishes), and every backoff wait _call_with_backoff takes during
# that subagent's whole lifetime adds its own wait_seconds to accumulator[0] -- a plain float
# instead of a one-element list couldn't be mutated in place across this ContextVar boundary.
# Real, confirmed incident this fixes (a real HackerOne rescan session): a subagent's fixed
# SUBAGENT_TASK_TIMEOUT_SECONDS deadline doesn't distinguish genuine work from time spent entirely
# inside provider retry/fallback backoff -- one real task spent 43% of its whole budget (~13 of 30
# minutes) waiting through repeated APITimeoutError/provider-switch backoff before being killed by
# its own deadline mid-productive-work, which then read as "this subagent is slow/inefficient" to
# a log-review pass when the real cause was upstream provider flakiness. Read back by
# agent/tools/subagent_tasks.py's _synthesize_partial_result once a task ends, so its summary can
# honestly attribute lost time to provider backoff instead of leaving that misattribution in place.
# None everywhere else (the main phase loop, chat) is the normal, silent case -- deliberately not
# used to extend the deadline itself: the timeout ceiling stays a hard, predictable safety bound,
# this only fixes what the after-the-fact summary blames it on.
current_backoff_accumulator: contextvars.ContextVar[list[float] | None] = (
    contextvars.ContextVar("current_backoff_accumulator", default=None)
)


def _parse_retry_after(exc: openai.APIStatusError) -> float | None:
    headers = getattr(exc.response, "headers", None)
    header_value = headers.get("retry-after") if headers is not None else None
    if not header_value:
        return None
    try:
        return float(header_value)
    except ValueError:
        return None


def _interruptible_sleep(seconds: float, stop_check) -> None:
    if stop_check is None:
        time.sleep(seconds)
        return
    remaining = seconds
    while remaining > 0:
        if stop_check():
            raise LLMCallAborted("stop requested during backoff wait")
        chunk = min(_STOP_POLL_INTERVAL_SECONDS, remaining)
        time.sleep(chunk)
        remaining -= chunk


def _record_backoff_time(seconds: float) -> None:
    """Adds to the current subagent task's current_backoff_accumulator, if one is set -- see that
    ContextVar's own docstring. A no-op (main loop, chat, Settings Test) whenever none is set."""
    accumulator = current_backoff_accumulator.get()
    if accumulator is not None:
        accumulator[0] += seconds


def _call_with_backoff(request_fn, stop_check=None):
    """Retries on 429/5xx, on timeouts/connection drops, and on an outright empty response (all
    transient), never on 401/403/other 4xx (retrying the same bad request just burns time). Waits
    Retry-After if the server sent one (capped at LLM_MAX_RETRY_AFTER_SECONDS — see that constant's
    docstring), else the fixed backoff schedule below. APITimeoutError is a subclass of
    APIConnectionError, so catching the latter covers both.

    stop_check, when given, is polled every _STOP_POLL_INTERVAL_SECONDS during a wait so an
    operator's Stop takes effect within one poll interval instead of only between whole retry
    attempts -- see LLMCallAborted's docstring for the real incident this fixes.
    """
    # current_session_id.get() (agent/utils/debug.py) tags every debug line below with which
    # session this retry sequence belongs to -- real, confirmed gap this closes: with several
    # concurrent LLM calls in flight (the main loop plus one or more delegated subagents, all
    # sharing this one module-level `logger`), their retry-attempt lines interleaved with no way to
    # tell which call chain a given line belonged to, genuinely misleading a real log-review pass
    # into misreading two/three independent retry sequences as one. A ContextVar (not a parameter
    # threaded through every LLMProvider implementation) is what lets this work here with no change
    # to the LLMProvider interface itself -- it survives the asyncio.to_thread hop this function is
    # always called through (copied into the worker thread's own context automatically), same
    # guarantee debug.py's own module docstring already relies on for _SessionAwareFileHandler.
    session_tag = current_session_id.get() or "-"
    max_retry_after = float(os.getenv("LLM_MAX_RETRY_AFTER_SECONDS", str(_DEFAULT_MAX_RETRY_AFTER_SECONDS)))
    total_attempts = len((0, *_RETRY_DELAYS_SECONDS))
    last_exc: Exception | None = None
    sink = current_retry_progress_sink.get()
    if sink is not None:
        sink(1, total_attempts, 0.0)  # first attempt starts immediately, no wait to report
    for attempt, fallback_delay in enumerate((0, *_RETRY_DELAYS_SECONDS)):
        if attempt > 0:
            retry_after = _parse_retry_after(last_exc) if isinstance(last_exc, openai.APIStatusError) else None
            wait_seconds = min(retry_after, max_retry_after) if retry_after is not None else fallback_delay
            logger.debug("llm_client: session=%s waiting %.1fs before retry attempt=%d (server retry-after=%s)", session_tag, wait_seconds, attempt + 1, retry_after)
            if sink is not None:
                sink(attempt + 1, total_attempts, wait_seconds)
            _interruptible_sleep(wait_seconds, stop_check)
            _record_backoff_time(wait_seconds)
        # Timed separately from the scheduled backoff sleep above -- a doomed request that hangs
        # until it times out (confirmed live: ~60-70s per attempt against a flaky free-tier
        # provider, far longer than the 2/4/8s scheduled backoff delays themselves) is just as much
        # "not real subagent work" as the sleep is, and was the actual bulk of the lost time in the
        # incident current_backoff_accumulator's own docstring describes -- counting only the
        # explicit sleep would have under-reported it by an order of magnitude.
        attempt_started = time.monotonic()
        try:
            return request_fn()
        except openai.APIStatusError as exc:
            if not _is_retryable(exc):
                raise
            last_exc = exc
            _record_backoff_time(time.monotonic() - attempt_started)
            logger.debug("llm_client: session=%s retryable error status=%s attempt=%d", session_tag, exc.status_code, attempt + 1)
        except openai.APIConnectionError as exc:
            last_exc = exc
            _record_backoff_time(time.monotonic() - attempt_started)
            logger.debug("llm_client: session=%s retryable %s attempt=%d", session_tag, type(exc).__name__, attempt + 1)
        except EmptyResponseError as exc:
            last_exc = exc
            _record_backoff_time(time.monotonic() - attempt_started)
            # str(exc), not a hardcoded "(no choices)" -- EmptyResponseError has two distinct raise
            # sites (_create_completion_with_backoff: "response had no choices" vs.
            # "finish_reason='error' with no content or tool_calls"), and a hardcoded message here
            # previously always claimed the first regardless of which one actually fired. Confirmed
            # live during a real log-review audit: this genuinely misled the read of a real crash,
            # where the final exception was the finish_reason='error' variant but every retry-attempt
            # debug line up to it claimed "(no choices)".
            logger.debug("llm_client: session=%s retryable empty response (%s) attempt=%d", session_tag, exc, attempt + 1)
    raise last_exc


def _create_completion_with_backoff(create_call, stop_check=None):
    """Wraps a chat.completions.create(...) call with _call_with_backoff's retry, plus a check
    that the response actually has a usable choice -- see EmptyResponseError's own docstring for
    why this can't just trust response.choices[0] to always work.
    """
    def request_fn():
        response = create_call()
        if not response.choices:
            raise EmptyResponseError("response had no choices")
        choice = response.choices[0]
        if choice.finish_reason == "error" and not choice.message.content and not choice.message.tool_calls:
            raise EmptyResponseError("response choice reported finish_reason='error' with no content or tool_calls")
        return response
    return _call_with_backoff(request_fn, stop_check=stop_check)


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


def _extract_dsml_tool_calls(content: str) -> list[ToolCallRequest]:
    """Fallback parser for the native special-token tool-call dialect described above this
    module's _DSML_INVOKE_PATTERN -- only ever tried once the normal <tool_call>{json}</tool_call>
    pattern found nothing, never merged with it (no real response has been observed mixing both
    formats). Every parameter value is treated as a plain string -- the only variant actually
    observed live, via each parameter's own string="true" attribute -- so a future numeric/bool-
    shaped parameter in this format would still arrive as a string: a smaller, more survivable
    failure than today's "completely unparseable" one.
    """
    tool_calls = []
    for index, invoke_match in enumerate(_DSML_INVOKE_PATTERN.finditer(content)):
        name = invoke_match.group(1)
        arguments = {
            param_match.group(1): param_match.group(2).strip()
            for param_match in _DSML_PARAMETER_PATTERN.finditer(invoke_match.group(2))
        }
        tool_calls.append(ToolCallRequest(id=f"dsml_call_{index}", name=name, arguments=arguments))
    return tool_calls


_TOOL_CALL_OPEN_PATTERN = re.compile(r"<tool_call>")


def _extract_unclosed_tool_calls(content: str) -> list[ToolCallRequest]:
    """Fallback for a real, well-formed <tool_call>{json} block that never got a closing tag at
    all -- confirmed live: nemotron-3-ultra-free in prompt mode emitted a complete, valid JSON
    object right after the opening tag and then just stopped, no </tool_call>/</tool_calls> of any
    spelling anywhere in the response. _TOOL_CALL_PATTERN's non-greedy match needs that closer to
    terminate, so it silently matched zero times across every single prompt-mode call for an entire
    session, taking skeptical_verification's real evidence-gathering calls down with it. Only tried
    once the strict pattern and the DSML dialect both find nothing -- raw_decode reads however much
    valid JSON is there and simply stops at the first complete object, so it can't accidentally
    swallow trailing prose the way a greedy regex would.
    """
    tool_calls = []
    decoder = json.JSONDecoder()
    for index, open_match in enumerate(_TOOL_CALL_OPEN_PATTERN.finditer(content)):
        pos = open_match.end()
        while pos < len(content) and content[pos].isspace():
            pos += 1
        try:
            payload, _ = decoder.raw_decode(content, pos)
        except json.JSONDecodeError:
            logger.debug("llm_client: unclosed tool_call block failed to parse: %s", content[pos : pos + 200])
            continue
        tool_calls.append(ToolCallRequest(id=f"prompt_call_unclosed_{index}", name=payload.get("name", ""), arguments=payload.get("arguments", {})))
    return tool_calls


def _extract_prompt_tool_calls(content: str) -> list[ToolCallRequest]:
    tool_calls = []
    for index, match in enumerate(_TOOL_CALL_PATTERN.finditer(content)):
        try:
            payload = json.loads(match.group(1))
        except json.JSONDecodeError:
            logger.debug("llm_client: prompt-based tool_call block failed to parse: %s", match.group(1))
            continue
        tool_calls.append(ToolCallRequest(id=f"prompt_call_{index}", name=payload.get("name", ""), arguments=payload.get("arguments", {})))
    if not tool_calls:
        tool_calls = _extract_dsml_tool_calls(content)
    if not tool_calls and "<tool_call>" in content:
        tool_calls = _extract_unclosed_tool_calls(content)
    return tool_calls


# Confirmed live: opencode.ai's own public "zen" free-tier endpoint applies a visibly harsher rate
# limit to plain OpenAI-compatible API traffic than to the official opencode CLI's own requests --
# a bare, anonymous request (no special headers, exactly what this provider sent before this) got
# HTTP 429 FreeUsageLimitError while the real CLI, hitting the identical endpoint/model from the
# same machine at the same moment, succeeded. Reverse-engineered from a third-party project's own
# opencode-zen client (Atennebris/Umbra-Agent, src/providers/provider-client.ts's
# buildZenClientFetcher) rather than guessed: the CLI marks its own requests with
# `x-opencode-client: cli` plus a User-Agent matching its real client string and a stable per-
# process session/project id pair, and the free tier evidently treats that combination as
# better-treated first-party usage rather than generic third-party API access.
#
# This is a deliberate operator opt-in (OPENCODE_ZEN_MIMIC_CLI, default false), never silently
# enabled -- it makes ASRA's traffic represent itself as the official opencode CLI, which is not
# necessarily within opencode.ai's own free-tier terms, and carries some real risk of the account/IP
# being treated more harshly if the provider ever specifically detects and penalizes this. Off by
# default so cloning this project never opts a new operator into that risk without them explicitly
# choosing it for their own account, the same "explicit, off-by-default opt-in for anything with a
# real external-facing consequence" posture authorize_exploit/enumerate_subdomains already establish.
_OPENCODE_ZEN_PROVIDER_ID = "opencode-zen"
_OPENCODE_CLI_USER_AGENT = "opencode/1.15.3 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.13"


def _opencode_zen_cli_mimicry_enabled() -> bool:
    return os.getenv("OPENCODE_ZEN_MIMIC_CLI", "false").strip().lower() in ("1", "true", "yes")


def _make_zen_compact_id(prefix: str) -> str:
    """Mirrors makeZenCompactId in Umbra-Agent's own provider-client.ts (a random hex id, not
    anything derived from real ASRA/session data) -- a fresh, opaque per-process identifier, never
    anything that could leak real target/session information to a third-party service."""
    return f"{prefix}{secrets.token_hex(16)}"


class OpenAICompatProvider:
    def __init__(self, provider_id: str, models_dev_id: str, base_url: str, api_key: str, model: str):
        # Public: core.py's _llm_complete reads provider_id+model together to track already-tried
        # fallback-chain steps (get_next_chain_step). self._model below is the same value, kept
        # private for every OTHER internal use in this class (request_kwargs, log lines) — this
        # public copy exists purely so external callers never need to reach into a private attr.
        self.provider_id = provider_id
        self.model = model
        self._model = model
        # Some OpenAI-compatible endpoints (opencode-zen's free tier) 401 on *any* Authorization
        # header, even a placeholder — confirmed by a real request (401 with a dummy Bearer token,
        # 200 with the header dropped entirely). The openai SDK requires a non-empty api_key string
        # to construct at all, so a placeholder is still passed in, but every actual request omits
        # the header when no real key was configured.
        self._omit_auth_header = not api_key
        # See _opencode_zen_cli_mimicry_enabled's own docstring above for the real incident and the
        # explicit-opt-in reasoning. Session/project id generated ONCE per provider instance
        # (mirroring Umbra-Agent's own "stable identifiers per process instance"), not per request.
        self._mimic_opencode_cli = provider_id == _OPENCODE_ZEN_PROVIDER_ID and _opencode_zen_cli_mimicry_enabled()
        if self._mimic_opencode_cli:
            self._zen_session_id = _make_zen_compact_id("ses_")
            self._zen_project_id = (_make_zen_compact_id("") + _make_zen_compact_id(""))[:40]
        request_timeout = float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", str(_DEFAULT_REQUEST_TIMEOUT_SECONDS)))
        self._client = openai.OpenAI(
            base_url=base_url, api_key=api_key or _PLACEHOLDER_API_KEY, max_retries=0, timeout=request_timeout
        )
        capabilities = get_model_capabilities(models_dev_id, model)
        self._tool_mode = self._decide_tool_mode(models_dev_id, model, capabilities)
        # Public: chat.py's compaction budget needs this to size how much history it can
        # send; None (catalog unreachable/model unlisted) means "unknown", callers must not guess.
        self.context_limit: int | None = capabilities["context_limit"] if capabilities else None

    def _auth_header_override(self) -> dict:
        """Despite the name (kept for the smallest possible diff at both real call sites), this is
        now every extra header this request needs: the Authorization-omission override for a
        no-key provider (opencode-zen's free tier 401s on any Authorization header, even a
        placeholder), plus the opencode-CLI-mimicking headers when that opt-in is active for this
        exact provider instance (see _opencode_zen_cli_mimicry_enabled's own docstring)."""
        headers: dict[str, object] = {}
        if self._omit_auth_header:
            headers["Authorization"] = openai.Omit()
        if self._mimic_opencode_cli:
            headers["x-opencode-client"] = "cli"
            headers["x-opencode-session"] = self._zen_session_id
            headers["x-opencode-project"] = self._zen_project_id
            # Fresh per request, unlike session/project above -- mirrors Umbra-Agent's own
            # buildZenClientFetcher, which mints a new requestId on every attempt.
            headers["x-opencode-request"] = _make_zen_compact_id("msg_")
            headers["User-Agent"] = _OPENCODE_CLI_USER_AGENT
        return {"extra_headers": headers} if headers else {}

    def embed(self, texts: list[str], model: str | None = None) -> list[list[float]] | None:
        """Best-effort embeddings via THIS provider's own OpenAI-compatible /embeddings endpoint --
        same base_url / key / extra-headers as complete(), so the playbook's semantic search uses
        exactly the provider the agent (or, in interactive/chat, the chat thread) is already on, no
        separate config. Returns one vector per input, or None on ANY failure (a provider with no
        embeddings endpoint, an unknown model, a network error) so callers fall back to the keyword
        matching. The embedding model name is env-resolved (PLAYBOOK_EMBEDDING_MODEL, default a
        common OpenAI-compatible one) since a chat model can't itself embed -- the connection is the
        active provider's, the model is a sensible default."""
        if not texts:
            return []
        model = model or os.getenv("PLAYBOOK_EMBEDDING_MODEL", "text-embedding-3-small")
        try:
            resp = self._client.embeddings.create(model=model, input=texts, **self._auth_header_override())
            return [item.embedding for item in resp.data]
        except Exception as exc:
            # describe_exception(exc, limit=4000) -- real, confirmed incident: an OpenAI-SDK
            # exception's own str() embeds the provider's raw HTTP response body; opencode-zen has
            # no real /embeddings endpoint and returns a full ~5KB HTML error page for it, logged
            # here verbatim (no cap at all) on every single failed embed() call.
            logger.debug(
                "llm_client: %s embeddings unavailable via model=%s (%s) -- playbook semantic search falls back to keyword",
                self.provider_id, model, describe_exception(exc, limit=4000),
            )
            return None

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

    def complete(
        self, messages: list[dict], tools: list[dict] | None = None, stop_check: Callable[[], bool] | None = None
    ) -> LLMResponse:
        merged_messages = _merge_consecutive_system_messages(messages)

        if tools and self._tool_mode == "prompt":
            return self._complete_prompt_based(merged_messages, tools, stop_check)

        try:
            return self._complete_native(merged_messages, tools, stop_check)
        except openai.BadRequestError as exc:
            if not tools or self._tool_mode != "native":
                raise
            logger.debug("llm_client: native tool-calling rejected (%s), switching to prompt-based for this provider", exc)
            self._tool_mode = "prompt"
            return self._complete_prompt_based(merged_messages, tools, stop_check)

    def _complete_native(
        self, messages: list[dict], tools: list[dict] | None, stop_check: Callable[[], bool] | None = None
    ) -> LLMResponse:
        request_kwargs = {"model": self._model, "messages": messages}
        if tools:
            request_kwargs["tools"] = tools

        logger.debug(
            "llm_client: request provider=%s model=%s mode=native messages=%d tools=%d",
            self.provider_id, self._model, len(messages), len(tools or []),
        )

        response = _create_completion_with_backoff(
            lambda: self._client.chat.completions.create(**request_kwargs, **self._auth_header_override()),
            stop_check=stop_check,
        )

        choice = response.choices[0]
        message = choice.message
        content = _normalize_message_content(message.content)
        tool_calls = [
            ToolCallRequest(id=call.id, name=call.function.name, arguments=_parse_tool_call_arguments(call.function.arguments))
            for call in (message.tool_calls or [])
        ]

        # step_id (not just a bare truncate) so a response over the preview limit gets a full dump
        # on disk, same as a large tool stdout already does -- without it, a response that never
        # ends up parsed into any structured field (a failed-to-parse reply, or reasoning content
        # a tool-calling turn doesn't otherwise preserve) is permanently lossy beyond this preview.
        usage = _extract_usage(response)
        logger.debug(
            "llm_client: response finish_reason=%s tool_calls=%d usage=%s content_preview=%s",
            choice.finish_reason, len(tool_calls), usage,
            truncate_for_log(content or "", step_id=f"llm_response_{int(time.time() * 1000)}"),
        )
        return LLMResponse(
            content=content, tool_calls=tool_calls, finish_reason=choice.finish_reason,
            content_was_malformed=_content_is_malformed(message.content), usage=usage,
        )

    def _complete_prompt_based(
        self, messages: list[dict], tools: list[dict], stop_check: Callable[[], bool] | None = None
    ) -> LLMResponse:
        prompted_messages = _inject_tool_instructions(messages, tools)

        logger.debug(
            "llm_client: request provider=%s model=%s mode=prompt messages=%d tools=%d",
            self.provider_id, self._model, len(prompted_messages), len(tools),
        )

        response = _create_completion_with_backoff(
            lambda: self._client.chat.completions.create(
                model=self._model, messages=prompted_messages, **self._auth_header_override()
            ),
            stop_check=stop_check,
        )

        choice = response.choices[0]
        content = _normalize_message_content(choice.message.content) or ""
        tool_calls = _extract_prompt_tool_calls(content)

        usage = _extract_usage(response)
        logger.debug(
            "llm_client: response finish_reason=%s tool_calls=%d usage=%s content_preview=%s",
            choice.finish_reason, len(tool_calls), usage,
            truncate_for_log(content, step_id=f"llm_response_{int(time.time() * 1000)}"),
        )
        return LLMResponse(
            content=content, tool_calls=tool_calls, finish_reason=choice.finish_reason,
            content_was_malformed=_content_is_malformed(choice.message.content), usage=usage,
        )
