"""get_model_capabilities(): grounds tool-calling/reasoning/context-limit decisions in the real
https://models.dev/api.json catalog instead of guessing. A models.dev outage must never block the
agent from starting or running — every function here degrades to None on failure, callers decide
what that means (llm_client.py reacts to it by deciding tool-calling mode reactively instead of
upfront).
"""
from __future__ import annotations

import os
import time

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


# In-process memo on top of the on-disk TTL cache below -- real, confirmed incident this fixes:
# the on-disk catalog file is a real ~4.9 MB JSON document (Documents/ASRA/data/cache/models_dev/),
# and every _fetch_catalog() call re-read and re-parsed the WHOLE file from disk, even when nothing
# had changed since the last call a moment ago. get_model_cost() calls this once per SESSION inside
# agent/core.py's compute_portfolio_summary/compute_provider_leaderboard (main.py's /dashboard) --
# with 134 real projects on disk, that's 134 full re-reads of the same 4.9 MB file per function,
# measured directly at ~2.1s and ~1.85s respectively (matching a real, observed ~3.9s /dashboard
# load in debug.log almost exactly). get_model_capabilities() is called once per LLM provider
# instance (agent/llm_client.py) too, so this same tax hit provider construction, not just the
# Dashboard. Memoized for the SAME ttl_seconds the disk cache already uses (default 24h, real-world
# catalog data that barely changes) -- this only removes REDUNDANT reads within that window, never
# changes what data is considered fresh. No lock: a benign race (two threads both missing the memo
# and both reading/parsing once) costs the exact same one-time work this used to pay on every single
# call, never anything worse.
_catalog_memo: dict | None = None
_catalog_memo_at: float = 0.0


def _fetch_catalog() -> dict | None:
    global _catalog_memo, _catalog_memo_at
    ttl = _catalog_ttl_seconds()
    if _catalog_memo is not None and (time.monotonic() - _catalog_memo_at) < ttl:
        return _catalog_memo

    cached = cache_get(_CACHE_TOOL_NAME, _CACHE_QUERY, ttl_seconds=ttl)
    if cached is not None:
        _catalog_memo, _catalog_memo_at = cached, time.monotonic()
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
    _catalog_memo, _catalog_memo_at = catalog, time.monotonic()
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


def get_model_cost(provider_id: str, model_id: str) -> dict | None:
    """Returns {"input": float, "output": float} -- USD per 1M tokens, straight off the catalog's own
    `cost` field -- for a models.dev provider/model pair, or None when the catalog is unreachable,
    the pair isn't listed, or that entry simply carries no cost data (a free-tier/local model, or a
    provider models.dev hasn't priced yet). Same graceful-degrade contract as
    get_model_capabilities: callers must treat None as "unknown, don't estimate a cost", never as
    "confirmed free" -- agent/core.py's compute_llm_usage_summary relies on that distinction to avoid
    silently reporting $0.00 for a model that's actually just unpriced in the catalog.
    """
    catalog = _fetch_catalog()
    if catalog is None:
        return None

    model = catalog.get(provider_id, {}).get("models", {}).get(model_id)
    if model is None:
        return None

    cost = model.get("cost")
    if not cost or cost.get("input") is None or cost.get("output") is None:
        return None
    return {"input": cost["input"], "output": cost["output"]}


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
