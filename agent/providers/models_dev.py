"""get_model_capabilities(): grounds tool-calling/reasoning/context-limit decisions in the real
https://models.dev/api.json catalog instead of guessing. A models.dev outage must never block the
agent from starting or running — every function here degrades to None on failure, callers decide
what that means (llm_client.py reacts to it by deciding tool-calling mode reactively instead of
upfront).
"""
from __future__ import annotations

import os

import httpx

from agent.tools.cache import cache_get, cache_set
from agent.utils.logger import get_logger

logger = get_logger("LLM")

_CATALOG_URL = "https://models.dev/api.json"
_CACHE_TOOL_NAME = "models_dev"
_CACHE_QUERY = "catalog"
_HTTP_TIMEOUT_SECONDS = 15.0
_DEFAULT_CATALOG_TTL_SECONDS = 86400


def _catalog_ttl_seconds() -> int:
    return int(os.getenv("MODELS_DEV_CACHE_TTL_SECONDS", str(_DEFAULT_CATALOG_TTL_SECONDS)))


def _fetch_catalog() -> dict | None:
    cached = cache_get(_CACHE_TOOL_NAME, _CACHE_QUERY, ttl_seconds=_catalog_ttl_seconds())
    if cached is not None:
        return cached

    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            response = client.get(_CATALOG_URL)
            response.raise_for_status()
            catalog = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.debug("models_dev: catalog fetch failed, degrading gracefully: %s", exc)
        return None

    cache_set(_CACHE_TOOL_NAME, _CACHE_QUERY, catalog)
    return catalog


def get_model_capabilities(provider_id: str, model_id: str) -> dict | None:
    """Returns {"tool_call": bool, "reasoning": bool, "context_limit": int | None, "modalities":
    dict} for a models.dev provider/model pair. Returns None if the catalog is unreachable or the
    pair isn't listed — callers must treat None as "unknown", not as "no capabilities".
    """
    catalog = _fetch_catalog()
    if catalog is None:
        return None

    model = catalog.get(provider_id, {}).get("models", {}).get(model_id)
    if model is None:
        logger.debug("models_dev: %s/%s not found in catalog", provider_id, model_id)
        return None

    capabilities = {
        "tool_call": bool(model.get("tool_call", False)),
        "reasoning": bool(model.get("reasoning", False)),
        "context_limit": model.get("limit", {}).get("context"),
        "modalities": model.get("modalities", {}),
    }
    logger.debug("models_dev: %s/%s capabilities=%s", provider_id, model_id, capabilities)
    return capabilities


def list_models(provider_id: str) -> list[str]:
    """Every model id the catalog lists under a provider — powers the Settings model dropdown
    (populated per-provider, not a fixed list). Empty (not an error) if the catalog is
    unreachable or the provider isn't in it; callers fall back to just the one .env-configured
    model in that case."""
    catalog = _fetch_catalog()
    if catalog is None:
        return []
    return sorted(catalog.get(provider_id, {}).get("models", {}))


def validate_model_known(provider_id: str, model_id: str) -> None:
    """Startup fail-fast: raises ValueError if the catalog was reachable but doesn't list this
    provider/model pair (almost always a typo in the configured model name). Silently returns if
    the catalog itself is unreachable — a third-party outage must not block the agent from
    starting.
    """
    catalog = _fetch_catalog()
    if catalog is None:
        return

    if catalog.get(provider_id, {}).get("models", {}).get(model_id) is None:
        raise ValueError(
            f"Model {model_id!r} not found in the models.dev catalog under provider {provider_id!r}. "
            "Check the configured model name for typos."
        )
