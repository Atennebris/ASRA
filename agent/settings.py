"""Global app settings (LLM provider/model choice), persisted to data/llm_settings.json.

Separate from .env: .env is the deploy-time default (and the fallback when this file doesn't
exist yet, or when it names a provider/model that's since disappeared from PROVIDER_REGISTRY).
This file is the runtime choice made from the Settings screen, and takes precedence once someone
has actually set it there — applies everywhere get_provider() is called with no explicit
override (new scans, chat), see agent/llm_client.py.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from agent.utils.logger import get_logger

logger = get_logger("API")

SETTINGS_PATH = Path("data/llm_settings.json")


def load_llm_settings() -> dict:
    if not SETTINGS_PATH.exists():
        return {}
    try:
        with SETTINGS_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("llm_settings: unreadable (%s) — treating as unset", exc)
        return {}
    return data if isinstance(data, dict) else {}


def save_llm_settings(provider: str, model: str) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SETTINGS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump({"provider": provider, "model": model}, f, indent=2)
    os.replace(tmp_path, SETTINGS_PATH)
    logger.debug("llm_settings: saved provider=%s model=%s", provider, model)
