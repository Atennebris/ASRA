"""Global app settings (LLM provider/model choice, the Reserve providers fallback chain),
persisted to data/llm_settings.json.

Separate from .env: .env is the deploy-time default (and the fallback when this file doesn't
exist yet, or when it names a provider/model that's since disappeared from PROVIDER_REGISTRY).
This file is the runtime choice made from the Settings screen, and takes precedence once someone
has actually set it there — applies everywhere get_provider() is called with no explicit
override (new scans, chat), see agent/llm_client.py.
"""
from __future__ import annotations

import json
import os

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("API")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
SETTINGS_PATH = resolve_global_app_dir() / "data" / "llm_settings.json"


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


def _write_llm_settings(data: dict) -> None:
    """Shared by save_llm_settings/save_fallback_chain_settings below — provider/model and the
    Reserve providers chain are edited from two separate Settings forms but share this one JSON
    file, so every write here MERGES onto whatever's already on disk (via each caller's own
    load_llm_settings() read first) rather than clobbering the other form's own saved keys."""
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SETTINGS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, SETTINGS_PATH)


def save_llm_settings(provider: str, model: str) -> None:
    existing = load_llm_settings()
    existing["provider"] = provider
    existing["model"] = model
    _write_llm_settings(existing)
    logger.debug("llm_settings: saved provider=%s model=%s", provider, model)


def get_disabled_providers() -> set[str]:
    """Built-in providers (PROVIDER_REGISTRY) the operator has explicitly toggled off from Settings
    -- same JSON file as the rest of this module, a plain list of provider ids. Absence from this
    set is the default (enabled) -- a provider nobody has ever touched the toggle for is enabled,
    same "nothing set -> no behavior change" default every other optional field here follows."""
    disabled = load_llm_settings().get("disabled_providers")
    return set(disabled) if isinstance(disabled, list) else set()


def is_provider_enabled(provider_id: str) -> bool:
    return provider_id not in get_disabled_providers()


def set_provider_enabled(provider_id: str, enabled: bool) -> None:
    """Settings -> Providers row toggle. Disabling a built-in provider does NOT touch its saved API
    key/endpoint (that's the separate, explicit Delete action) and does not block it from still
    being resolved if something explicitly names it (get_provider(provider_id=...), or it's still
    the saved main provider/model) -- same "toggle only controls what gets OFFERED, not what still
    works if explicitly chosen" rule agent/custom_providers.py's own enabled flag already follows.
    It's filtered out of agent.llm_client.all_provider_choices() (and therefore the Reserve
    providers chain and every subagent's own provider picker), the one place this flag actually
    changes behavior.
    """
    existing = load_llm_settings()
    disabled = set(existing.get("disabled_providers") or [])
    if enabled:
        disabled.discard(provider_id)
    else:
        disabled.add(provider_id)
    existing["disabled_providers"] = sorted(disabled)
    _write_llm_settings(existing)
    logger.debug("llm_settings: provider=%s enabled=%s", provider_id, enabled)


def get_added_providers() -> set[str]:
    """Built-in providers (PROVIDER_REGISTRY) the operator has explicitly added from Settings ->
    "+ Add Provider" -- same JSON file, a plain list of provider ids. Real incident this exists to
    fix: every built-in used to render as a full row unconditionally, the instant the app was
    installed -- including ones the operator had never touched at all (no key, no override, not
    the active provider), reading as "already added" when nothing had actually happened. Absence
    from this set does NOT automatically mean "hide it" on its own -- the caller (main.py) also
    treats a provider as visible when it already has a real saved key, is the currently active
    provider, or has a real endpoint override, so upgrading an existing install with providers
    already configured before this set existed never silently hides them.
    """
    added = load_llm_settings().get("added_providers")
    return set(added) if isinstance(added, list) else set()


def add_provider_to_list(provider_id: str) -> None:
    existing = load_llm_settings()
    added = set(existing.get("added_providers") or [])
    added.add(provider_id)
    existing["added_providers"] = sorted(added)
    _write_llm_settings(existing)
    logger.debug("llm_settings: provider=%s added", provider_id)


def remove_provider_from_list(provider_id: str) -> None:
    """The row-level Delete/"Remove provider" action's own bookkeeping half -- the caller (main.py)
    also clears this provider's saved key and base_url override in the same request, so this isn't
    "temporarily hide" (that's the separate enable/disable Toggle), it's a full reset back to
    "never added" -- the row disappears again until explicitly added a second time."""
    existing = load_llm_settings()
    added = set(existing.get("added_providers") or [])
    added.discard(provider_id)
    existing["added_providers"] = sorted(added)
    _write_llm_settings(existing)
    logger.debug("llm_settings: provider=%s removed", provider_id)


def get_secondary_verification_provider() -> dict | None:
    """Settings -> Secondary verification provider (optional) -- when set, Skeptical Verification
    (agent/core.py's _run_skeptical_verification) independently re-checks each Critical/High
    "verified" finding with a SECOND, genuinely different provider/model instead of trusting one
    model's own possible blind spot alone (real, confirmed incident this addresses: this project's
    own log-review audit once found the DEFAULT skeptical pass nearly downgrade a real, twice-
    confirmed finding to a false positive over a client-side TLS-library quirk the same model
    itself didn't know to account for). Disagreement between the two surfaces on the finding
    explicitly, never silently resolved by picking one. None (the default) leaves today's
    single-model behavior unchanged — this is an opt-in EXTRA cost (a whole second LLM pass per
    Critical/High finding), never silently turned on.
    """
    existing = load_llm_settings()
    provider = existing.get("secondary_verification_provider")
    model = existing.get("secondary_verification_model")
    if not provider or not model:
        return None
    return {"provider": provider, "model": model}


def save_secondary_verification_provider(provider: str | None, model: str | None) -> None:
    """provider/model both blank clears the setting (feature off) -- same "empty input removes the
    override" convention as every other optional Settings field in this module."""
    existing = load_llm_settings()
    if provider and model:
        existing["secondary_verification_provider"] = provider
        existing["secondary_verification_model"] = model
    else:
        existing.pop("secondary_verification_provider", None)
        existing.pop("secondary_verification_model", None)
    _write_llm_settings(existing)
    logger.debug("llm_settings: saved secondary_verification_provider=%s model=%s", provider, model)


def save_fallback_chain_settings(enabled: bool, chain: list[dict]) -> None:
    """`chain` is an ordered, flat list of {"provider": provider_id, "model": model} steps —
    exactly the shape agent.llm_client.get_next_chain_step() already walks, and exactly what
    Settings -> Reserve providers' own dropdown-per-row UI produces (each row IS one step; several
    rows sharing a provider is how "try these models on this provider in order" is expressed, no
    separate grouping needed on either side)."""
    existing = load_llm_settings()
    existing["fallback_chain_enabled"] = enabled
    existing["fallback_chain"] = chain
    _write_llm_settings(existing)
    logger.debug("llm_settings: saved fallback_chain_enabled=%s chain=%s", enabled, chain)
