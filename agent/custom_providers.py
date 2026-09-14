"""User-created custom LLM provider instances (Settings -> LLM Providers -> Add Provider) — on top
of PROVIDER_REGISTRY's 6 built-in providers (agent/llm_client.py), any number of arbitrary,
operator-named, OpenAI-compatible endpoints can be added here. Unlike a built-in (one .env-backed
slot each — a fixed env var name like QWEN_API_KEY), an unbounded number of these can exist, so
they're persisted as a JSON list (data/custom_providers.json, gitignored — each entry carries its
own real API key in plain JSON) instead.

agent/llm_client.py is the only other module that imports from here (get_provider/get_model_choices
recognize a custom provider id the same way they already recognize a PROVIDER_REGISTRY one) — this
module itself never imports llm_client, so there's no circular import.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("API")

# Global app data (Documents/ASRA/data, see projects/paths.py) -- each entry carries a real API
# key, no business living inside the git checkout's own repo-relative data/ folder.
CUSTOM_PROVIDERS_PATH = resolve_global_app_dir() / "data" / "custom_providers.json"

# models.dev's real catalog never lists a provider under this id (a plain English word, not a real
# vendor slug) — used as every custom instance's own models_dev_id so capability/model-list lookups
# against that catalog degrade gracefully to "unknown" (get_model_capabilities returns None, never
# raises) instead of either crashing or accidentally matching a real vendor's data.
CUSTOM_MODELS_DEV_ID = "custom"

# Every custom-provider id carries this prefix so it can never collide with a PROVIDER_REGISTRY key
# (all short bare words like "qwen"/"mistral") and so is_known_provider_id() below can tell the two
# apart without needing to load the custom-providers file first.
_ID_PREFIX = "custom-"

# Add Provider form presets -- purely a UI convenience (pre-fills base_url, shows a recognizable
# badge on the card) picked at creation time and stored on the entry's own "type" field; nothing
# downstream (get_provider/get_model_choices) branches on it, every custom instance is dispatched
# as a plain OpenAI-compatible endpoint regardless of which preset built it.
#
# "universal" is the ONLY preset, deliberately -- a custom instance is for a genuinely arbitrary,
# not-already-built-in OpenAI-compatible endpoint (a self-hosted gateway, a corporate proxy). Real
# incident this exists because of: this dict used to also carry one preset per PROVIDER_REGISTRY
# built-in (opencode-zen, Qwen, Mistral, OpenRouter, OpenAI, LM Studio, Ollama), reasoned as "a
# second, differently-named key for the same service" -- but Settings -> "+ Add Provider" is one
# single Type dropdown, and an operator picking e.g. "opencode-zen" from it (reasonably expecting
# it to configure the REAL opencode-zen row) instead got a brand new, separate "Custom" card
# confusingly ALSO labeled "opencode-zen", duplicating the built-in's name with none of its
# behavior. A genuine "second key for the same built-in service" use case, if ever needed again,
# belongs in its OWN dedicated mechanism (e.g. letting a built-in provider carry more than one
# saved key) -- not smuggled in as a same-named Custom entry that looks identical to the real one.
# Settings -> "+ Add Provider" now activates one of the 8 real built-ins directly (main.py's
# add_custom_provider_route, using PROVIDER_REGISTRY -- not this file at all) when that's what the
# operator picks; this module and its "universal" type is reached ONLY for a genuinely custom
# endpoint from here on.
CUSTOM_PROVIDER_TYPE_PRESETS: dict[str, dict] = {
    "universal": {"label": "Universal (OpenAI-compatible)", "default_base_url": ""},
}


def load_custom_providers() -> list[dict]:
    if not CUSTOM_PROVIDERS_PATH.exists():
        return []
    try:
        with CUSTOM_PROVIDERS_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("custom_providers: unreadable (%s) — treating as empty", exc)
        return []
    return data if isinstance(data, list) else []


def _write_custom_providers(providers: list[dict]) -> None:
    CUSTOM_PROVIDERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CUSTOM_PROVIDERS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(providers, f, indent=2)
    os.replace(tmp_path, CUSTOM_PROVIDERS_PATH)


def get_custom_provider(provider_id: str) -> dict | None:
    return next((p for p in load_custom_providers() if p["id"] == provider_id), None)


def create_custom_provider(name: str, base_url: str, api_key: str = "", model: str = "", type: str = "universal") -> dict:
    providers = load_custom_providers()
    entry = {
        "id": f"{_ID_PREFIX}{uuid.uuid4().hex[:10]}",
        "name": name,
        "type": type if type in CUSTOM_PROVIDER_TYPE_PRESETS else "universal",
        "base_url": base_url,
        "api_key": api_key,
        "model": model,
        "enabled": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    providers.append(entry)
    _write_custom_providers(providers)
    logger.debug("custom_providers: created id=%s name=%s base_url=%s", entry["id"], name, base_url)
    return entry


def update_custom_provider(provider_id: str, **fields) -> dict | None:
    """Only keys already present on the stored entry may be overwritten (name/base_url/api_key/
    model/enabled) — silently ignores anything else rather than letting an unexpected kwarg grow
    the schema by accident."""
    providers = load_custom_providers()
    for entry in providers:
        if entry["id"] != provider_id:
            continue
        for key, value in fields.items():
            if key in entry and key != "id":
                entry[key] = value
        _write_custom_providers(providers)
        logger.debug("custom_providers: updated id=%s fields=%s", provider_id, {k: v for k, v in fields.items() if k != "api_key"})
        return entry
    return None


def delete_custom_provider(provider_id: str) -> bool:
    providers = load_custom_providers()
    remaining = [p for p in providers if p["id"] != provider_id]
    if len(remaining) == len(providers):
        return False
    _write_custom_providers(remaining)
    logger.debug("custom_providers: deleted id=%s", provider_id)
    return True


def is_custom_provider_id(provider_id: str) -> bool:
    return provider_id.startswith(_ID_PREFIX)
