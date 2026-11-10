"""Move the owner's own ASRA settings from one of their machines to another (Settings -> General ->
Transfer settings).

One payload, two interchangeable carriers: a single pasteable "ASRA1:<base64url(zlib(json))>" code,
or the same JSON as a file. Both go through exactly the same decode -> validate -> preview -> apply
path, so there is no "file-only" or "code-only" behavior to drift apart.

Design rules that matter more than the feature list:
- WHITELIST, never a dump. Every exportable thing is an entry in SECTIONS (loader, saver, allowed keys,
  which keys are sensitive). A loader may return more than the registry allows -- the engine drops
  every key the registry does not name, so a store growing a new field never leaks into an export by
  accident.
- Everything is read and written through each store's own public load_*/save_* functions, never by
  touching their files or .env directly -- those functions already own atomic writes, read-back
  verification and cache invalidation.
- An import is validated completely (version, size, sections, keys, types) BEFORE the first write; any
  problem rejects the whole payload and changes nothing. Only then is it applied section by section,
  each section restored to its previous values if its own write fails midway.
- Sensitive values (API keys, the sudo password) are exported only on the owner's explicit opt-in. With
  a passphrase they are sealed with Fernet (PBKDF2-HMAC-SHA256, random salt stored in the payload);
  without one they are included in clear text and the UI says so. There is deliberately no home-made
  "obfuscation": without the `cryptography` package the passphrase option is simply unavailable.

Machine-specific values are never exported even in sensitive mode (absolute paths, APP_DATA_DIR,
installed-tool locations, session/project ids, OAuth sign-in tokens, allowed-target scope) -- each
exclusion is explained next to the registry entry that would otherwise have carried it.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from agent import updater
from agent.custom_providers import (
    CUSTOM_PROVIDER_TYPE_PRESETS,
    load_custom_providers,
    update_custom_provider,
    upsert_custom_provider,
)
from agent.intro_settings import LAUNCH_SCREENS, load_launch_screen, save_launch_screen
from agent.llm_client import (
    CODEX_PROVIDER_ID,
    COPILOT_PROVIDER_ID,
    OPENCODE_LOCAL_PROVIDER_ID,
    PROVIDER_REGISTRY,
    get_provider_api_key,
    save_provider_api_key,
    save_provider_base_url,
)
from agent.settings import (
    add_provider_to_list,
    get_added_providers,
    get_disabled_providers,
    load_llm_settings,
    remove_provider_from_list,
    save_fallback_chain_settings,
    save_llm_settings,
    save_secondary_verification_provider,
    set_free_models_only,
    set_provider_enabled,
)
from agent.sound_settings import (
    SOUND_EVENTS,
    SOUND_PROFILES,
    load_sound_settings,
    save_master_sound_enabled,
    save_sound_event,
)
from agent.timezone_settings import (
    CLOCK_STYLES,
    display_timezone_choices,
    load_clock_show_date,
    load_clock_show_time,
    load_clock_show_zone_label,
    load_clock_style,
    load_display_timezone,
    save_clock_show_date,
    save_clock_show_time,
    save_clock_show_zone_label,
    save_clock_style,
    save_display_timezone,
)
from agent.tools.capability_install import get_sudo_password, save_sudo_password
from agent.tools.chat_settings_store import load_chat_settings, save_chat_settings, save_last_chat_llm
from agent.tools.subagent_store import import_profiles, load_subagent_profiles
from agent.tools.tool_api_keys import TOOL_API_KEY_SPECS, get_tool_api_key, save_tool_api_key
from agent.tools.toolkit_settings_store import BOOL_KEYS as TOOLKIT_BOOL_KEYS
from agent.tools.toolkit_settings_store import load_toolkit_agent_settings, save_toolkit_agent_settings
from agent.tools.wordlist_catalog import list_all_wordlists
from agent.tools.wordlist_store import ASSIGNABLE_ROLES, load_wordlist_store, set_assignment
from agent.utils.logger import get_logger

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    ENCRYPTION_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only on installs without the package
    ENCRYPTION_AVAILABLE = False

logger = get_logger("API")

VERSION_FIELD = "asra_settings_version"
SETTINGS_VERSION = 1
CODE_PREFIX = "ASRA1:"
# Caps sit just under Starlette's 1 MiB limit for a single form field, so an over-size paste is
# rejected here with a readable message instead of a bare 400 from the multipart parser. The
# decompressed cap is what actually bounds memory: a tiny hostile code can inflate enormously.
MAX_CODE_CHARS = 1_000_000
MAX_PAYLOAD_BYTES = 1_000_000
KDF_NAME = "pbkdf2-hmac-sha256"
KDF_ITERATIONS = 600_000
# Bounds on what an imported payload may ask for: too low weakens the seal, too high is a CPU-burn
# request hidden inside a file the owner pasted.
KDF_MIN_ITERATIONS = 100_000
KDF_MAX_ITERATIONS = 2_000_000
KDF_SALT_BYTES = 16
MAX_SECRET_CHARS = 4096
MAX_TEXT_CHARS = 200
MAX_LONG_TEXT_CHARS = 100_000
MAX_URL_CHARS = 2000
MAX_LIST_ITEMS = 500

_TOP_LEVEL_FIELDS = frozenset({VERSION_FIELD, "app", "created_at", "sections", "sensitive"})
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_CUSTOM_ID = re.compile(r"^custom-[A-Za-z0-9_-]{1,40}$")


class SettingsTransferError(ValueError):
    """A problem the owner can act on (bad code, wrong passphrase, unsupported version). The message
    is shown verbatim in the UI, so it never contains a payload value -- those may be secrets."""


# --------------------------------------------------------------------------------------------------
# Value checks. Each returns a plain bool; the engine reports "section.key" on failure and never the
# value itself.
# --------------------------------------------------------------------------------------------------

Check = Callable[[Any], bool]


def _flag(value: Any) -> bool:
    return isinstance(value, bool)


def _text(max_len: int = MAX_TEXT_CHARS, allow_empty: bool = False) -> Check:
    def check(value: Any) -> bool:
        return (
            isinstance(value, str) and (allow_empty or value != "") and len(value) <= max_len
            and not _CONTROL_CHARS.search(value)
        )
    return check


def _long_text(value: Any) -> bool:
    # Subagent instructions are multi-line prose; only NUL is refused.
    return isinstance(value, str) and len(value) <= MAX_LONG_TEXT_CHARS and "\x00" not in value


def _secret(value: Any) -> bool:
    # Control characters are refused outright because these values end up in .env through set_key():
    # a newline inside a "key" would otherwise let a crafted payload append its own KEY=value lines.
    return _text(MAX_SECRET_CHARS)(value)


def _file_name(value: Any) -> bool:
    # A bare file name only -- a path separator would smuggle a machine-specific (or traversal) path
    # through a field that is supposed to be re-resolved on the receiving machine.
    return _text(255)(value) and "/" not in value and "\\" not in value


def _http_url(value: Any) -> bool:
    if not _text(MAX_URL_CHARS)(value):
        return False
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _optional(check: Check) -> Check:
    return lambda value: value is None or check(value)


def _one_of(options) -> Check:
    allowed = tuple(options)
    return lambda value: isinstance(value, str) and value in allowed


def _list_of(item_check: Check, max_items: int = MAX_LIST_ITEMS) -> Check:
    return lambda value: isinstance(value, list) and len(value) <= max_items and all(item_check(item) for item in value)


def _map_of(key_check: Check, value_check: Check, max_items: int = MAX_LIST_ITEMS) -> Check:
    return lambda value: (
        isinstance(value, dict) and len(value) <= max_items
        and all(key_check(k) and value_check(v) for k, v in value.items())
    )


def _record(fields: dict[str, Check], required: tuple[str, ...] = ()) -> Check:
    """An object with only the listed keys, each passing its own check -- an unknown key fails."""
    return lambda value: (
        isinstance(value, dict) and set(value) <= set(fields) and set(required) <= set(value)
        and all(fields[key](item) for key, item in value.items())
    )


def _is_provider_id(value: Any) -> bool:
    if not _text(64)(value):
        return False
    return (
        value in PROVIDER_REGISTRY
        or value in (CODEX_PROVIDER_ID, COPILOT_PROVIDER_ID, OPENCODE_LOCAL_PROVIDER_ID)
        or bool(_CUSTOM_ID.match(value))
    )


def _is_builtin_provider_id(value: Any) -> bool:
    return isinstance(value, str) and value in PROVIDER_REGISTRY


def _is_custom_provider_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_CUSTOM_ID.match(value))


# --------------------------------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class KeySpec:
    check: Check
    sensitive: bool = False


Saver = Callable[[dict], "list[str] | None"]


@dataclass(frozen=True)
class Section:
    id: str
    label: str
    keys: dict[str, KeySpec]
    loader: Callable[[], dict]
    # Receives only the keys present in the payload; absent keys mean "leave the target as it is".
    # May return human-readable notes (e.g. a wordlist that does not exist on this machine).
    saver: Saver


def _count(values: dict) -> int:
    return sum(len(item) if isinstance(item, (list, dict)) else 1 for item in values.values())


# ---- LLM provider choice, free-only switch, secondary verification, Reserve chain ----

_LLM_KEYS = {
    "provider": KeySpec(_optional(_is_provider_id)),
    "model": KeySpec(_optional(_text(MAX_TEXT_CHARS))),
    "free_models_only": KeySpec(_flag),
    "disabled_providers": KeySpec(_list_of(_is_provider_id)),
    "added_providers": KeySpec(_list_of(_is_provider_id)),
    "secondary_verification_provider": KeySpec(_is_provider_id),
    "secondary_verification_model": KeySpec(_text(MAX_TEXT_CHARS)),
    "secondary_verification_free_only": KeySpec(_flag),
    "fallback_chain_enabled": KeySpec(_flag),
    "fallback_chain": KeySpec(_list_of(_record(
        {"provider": _is_provider_id, "model": _text(MAX_TEXT_CHARS), "free_only": _flag}, required=("provider", "model"),
    ), max_items=100)),
}


def _load_llm() -> dict:
    return load_llm_settings()


def _sync_provider_set(current: set[str], wanted: list[str], apply: Callable[[str, bool], None]) -> None:
    for provider_id in sorted(set(wanted) - current):
        apply(provider_id, True)
    for provider_id in sorted(current - set(wanted)):
        apply(provider_id, False)


def _save_llm(values: dict) -> None:
    if isinstance(values.get("provider"), str) and isinstance(values.get("model"), str):
        save_llm_settings(values["provider"], values["model"])
    if "free_models_only" in values:
        set_free_models_only(values["free_models_only"])
    if "disabled_providers" in values:
        _sync_provider_set(get_disabled_providers(), values["disabled_providers"], lambda pid, present: set_provider_enabled(pid, not present))
    if "added_providers" in values:
        _sync_provider_set(
            get_added_providers(), values["added_providers"],
            lambda pid, present: add_provider_to_list(pid) if present else remove_provider_from_list(pid),
        )
    if "secondary_verification_provider" in values and "secondary_verification_model" in values:
        save_secondary_verification_provider(
            values["secondary_verification_provider"], values["secondary_verification_model"],
            values.get("secondary_verification_free_only", False),
        )
    if "fallback_chain_enabled" in values or "fallback_chain" in values:
        current = load_llm_settings()
        save_fallback_chain_settings(
            values.get("fallback_chain_enabled", bool(current.get("fallback_chain_enabled"))),
            values.get("fallback_chain", current.get("fallback_chain") or []),
        )


# ---- Custom (operator-added) LLM providers; the API key is the sensitive part ----

_CUSTOM_PROVIDER_FIELDS = {
    "id": _is_custom_provider_id,
    "name": _text(MAX_TEXT_CHARS),
    "type": _one_of(CUSTOM_PROVIDER_TYPE_PRESETS),
    "base_url": _http_url,
    "model": _text(MAX_TEXT_CHARS, allow_empty=True),
    "enabled": _flag,
}


def _load_custom_providers() -> dict:
    providers = load_custom_providers()
    return {
        "providers": [{k: p[k] for k in _CUSTOM_PROVIDER_FIELDS if k in p} for p in providers if isinstance(p, dict)],
        "api_keys": {p["id"]: p["api_key"] for p in providers if isinstance(p, dict) and p.get("id") and p.get("api_key")},
    }


def _save_custom_providers(values: dict) -> None:
    # Created_at is not carried: it records when THIS machine created the entry.
    for entry in values.get("providers", []):
        upsert_custom_provider(entry)
    for provider_id, api_key in values.get("api_keys", {}).items():
        update_custom_provider(provider_id, api_key=api_key)


# ---- Built-in provider endpoints (public) and API keys (sensitive) ----


def _load_builtin_providers() -> dict:
    base_urls: dict[str, str] = {}
    api_keys: dict[str, str] = {}
    for provider_id, config in PROVIDER_REGISTRY.items():
        url = (os.getenv(config.base_url_env) or "").strip()
        # Only a real override: .env.example pre-fills the registry default, which carries no choice.
        if url and url != config.base_url_default:
            base_urls[provider_id] = url
        key = get_provider_api_key(config)
        if key:
            api_keys[provider_id] = key
    return {"base_urls": base_urls, "api_keys": api_keys}


def _save_builtin_providers(values: dict) -> None:
    for provider_id, url in values.get("base_urls", {}).items():
        save_provider_base_url(provider_id, url)
    for provider_id, api_key in values.get("api_keys", {}).items():
        save_provider_api_key(provider_id, api_key)


# ---- Per-tool API keys (WPScan, OTX, urlscan, GitHub, HIBP) -- every key here is sensitive ----


def _load_tool_api_keys() -> dict:
    return {"api_keys": {name: key for name in TOOL_API_KEY_SPECS if (key := get_tool_api_key(name))}}


def _save_tool_api_keys(values: dict) -> None:
    for tool_name, api_key in values.get("api_keys", {}).items():
        save_tool_api_key(tool_name, api_key)


# ---- Sudo password -- sensitive ----


def _load_sudo() -> dict:
    password = get_sudo_password()
    return {"sudo_password": password} if password else {}


def _save_sudo(values: dict) -> None:
    if "sudo_password" in values:
        save_sudo_password(values["sudo_password"])


# ---- Display: timezone and sidebar clock ----


def _load_display() -> dict:
    return {
        "timezone": load_display_timezone(), "show_clock": load_clock_show_time(),
        "show_zone_label": load_clock_show_zone_label(), "show_date": load_clock_show_date(),
        "clock_style": load_clock_style(),
    }


def _save_display(values: dict) -> None:
    if "timezone" in values:
        save_display_timezone(values["timezone"])
    if "show_clock" in values:
        save_clock_show_time(values["show_clock"])
    if "show_zone_label" in values:
        save_clock_show_zone_label(values["show_zone_label"])
    if "show_date" in values:
        save_clock_show_date(values["show_date"])
    if "clock_style" in values:
        save_clock_style(values["clock_style"])


# ---- Sounds ----

_SOUND_EVENT_IDS = tuple(event["id"] for event in SOUND_EVENTS)


def _load_sounds() -> dict:
    return load_sound_settings()


def _save_sounds(values: dict) -> None:
    if "master_enabled" in values:
        save_master_sound_enabled(values["master_enabled"])
    for event_id, event in values.get("events", {}).items():
        save_sound_event(event_id, event["enabled"], event["sound"])


# ---- Launch screen and update-check switch ----


def _load_launch_screen() -> dict:
    return {"screen": load_launch_screen()}


def _save_launch_screen(values: dict) -> None:
    if "screen" in values:
        save_launch_screen(values["screen"])


def _load_updates() -> dict:
    return {"check_on_startup": updater.load_update_check_on_startup()}


def _save_updates(values: dict) -> None:
    if "check_on_startup" in values:
        updater.save_update_check_on_startup(values["check_on_startup"])


# ---- Chat panel toggles and last pick ----


def _load_chat() -> dict:
    # Returns the whole store on purpose: quick_chat_session_id is dropped by the registry filter, not
    # by this loader, which keeps the exclusion in one visible place (the key list below).
    return load_chat_settings()


def _save_chat(values: dict) -> None:
    current = load_chat_settings()
    toggles = ("web_fetch_enabled", "browser_enabled", "subagents_enabled", "dork_engine_enabled")
    if any(key in values for key in toggles):
        save_chat_settings(**{key: values.get(key, current[key]) for key in toggles})
    if any(key in values for key in ("last_provider", "last_model", "last_free_only")):
        save_last_chat_llm(
            values.get("last_provider", current["last_provider"]), values.get("last_model", current["last_model"]),
            values.get("last_free_only", current["last_free_only"]),
        )


# ---- Native toolkit access for the agent ----


def _load_toolkit_agent() -> dict:
    return load_toolkit_agent_settings()


def _save_toolkit_agent(values: dict) -> None:
    save_toolkit_agent_settings({**load_toolkit_agent_settings(), **values})


# ---- Subagent profiles ----

_SUBAGENT_FIELDS = {
    "id": _text(64), "name": _text(MAX_TEXT_CHARS), "allowed_tools": _list_of(_text(MAX_TEXT_CHARS)),
    "instructions": _long_text, "provider": _optional(_is_provider_id), "model": _optional(_text(MAX_TEXT_CHARS)),
    "icon": _optional(_text(64)), "icon_color": _optional(_text(32)),
}
_SUBAGENT_PROFILE = _record(_SUBAGENT_FIELDS, required=("name",))


def _load_subagents() -> dict:
    # "enabled" is not carried: the existing import path always lands profiles disabled so the owner
    # reviews tools/provider on the new machine before the agent can delegate to them.
    profiles = [{k: p[k] for k in _SUBAGENT_FIELDS if k in p} for p in load_subagent_profiles()["profiles"] if isinstance(p, dict)]
    return {"profiles": [p for p in profiles if _SUBAGENT_PROFILE(p)]}


def _save_subagents(values: dict) -> None:
    import_profiles({"profiles": values.get("profiles", [])}, source_label="settings transfer")


# ---- Wordlist assignments, carried by file NAME ----


def _load_wordlists() -> dict:
    # The store holds absolute paths, which differ per machine. Export the wordlist's name instead and
    # let the receiving machine look it up in its own catalog.
    name_by_path = {entry["path"]: entry["name"] for entry in list_all_wordlists()}
    assignments = load_wordlist_store()["assignments"]
    return {"assignments": {
        role: name_by_path.get(path) or Path(path).name
        for role, path in assignments.items() if role in ASSIGNABLE_ROLES and isinstance(path, str)
    }}


def _save_wordlists(values: dict) -> list[str]:
    path_by_name: dict[str, str] = {}
    for entry in list_all_wordlists():
        path_by_name.setdefault(entry["name"], entry["path"])
    notes: list[str] = []
    for role, name in values.get("assignments", {}).items():
        path = path_by_name.get(name)
        if path is None:
            notes.append(f"wordlist '{name}' (for {role}) is not on this machine, skipped")
            continue
        set_assignment(role, path)
    return notes


# Order matters on apply: providers must exist before the sections that reference them by id.
SECTIONS: tuple[Section, ...] = (
    Section("custom_providers", "Custom LLM providers", {
        "providers": KeySpec(_list_of(_record(_CUSTOM_PROVIDER_FIELDS, required=("id", "name", "base_url")), max_items=100)),
        "api_keys": KeySpec(_map_of(_is_custom_provider_id, _secret, max_items=100), sensitive=True),
    }, _load_custom_providers, _save_custom_providers),
    Section("builtin_providers", "Built-in provider endpoints and API keys", {
        "base_urls": KeySpec(_map_of(_is_builtin_provider_id, _http_url)),
        "api_keys": KeySpec(_map_of(_is_builtin_provider_id, _secret), sensitive=True),
    }, _load_builtin_providers, _save_builtin_providers),
    Section("llm", "LLM provider, model and Reserve chain", _LLM_KEYS, _load_llm, _save_llm),
    Section("tool_api_keys", "Tool API keys", {
        "api_keys": KeySpec(_map_of(_one_of(TOOL_API_KEY_SPECS), _secret), sensitive=True),
    }, _load_tool_api_keys, _save_tool_api_keys),
    Section("sudo", "Sudo password", {"sudo_password": KeySpec(_secret, sensitive=True)}, _load_sudo, _save_sudo),
    Section("chat", "Chat panel settings", {
        "web_fetch_enabled": KeySpec(_flag), "browser_enabled": KeySpec(_flag), "subagents_enabled": KeySpec(_flag),
        "dork_engine_enabled": KeySpec(_flag), "last_provider": KeySpec(_optional(_is_provider_id)),
        "last_model": KeySpec(_optional(_text(MAX_TEXT_CHARS))), "last_free_only": KeySpec(_flag),
        # quick_chat_session_id is intentionally NOT listed: it is the id of a project folder that
        # exists only on the machine that created it.
    }, _load_chat, _save_chat),
    Section("toolkit_agent", "Native toolkit access", {key: KeySpec(_flag) for key in TOOLKIT_BOOL_KEYS},
            _load_toolkit_agent, _save_toolkit_agent),
    Section("subagents", "Subagent profiles", {"profiles": KeySpec(_list_of(_SUBAGENT_PROFILE, max_items=200))},
            _load_subagents, _save_subagents),
    Section("wordlists", "Wordlist assignments", {
        "assignments": KeySpec(_map_of(_one_of(ASSIGNABLE_ROLES), _file_name)),
    }, _load_wordlists, _save_wordlists),
    Section("display", "Timezone and clock", {
        "timezone": KeySpec(lambda v: isinstance(v, str) and v in display_timezone_choices()),
        "show_clock": KeySpec(_flag), "show_zone_label": KeySpec(_flag), "show_date": KeySpec(_flag),
        "clock_style": KeySpec(_one_of(CLOCK_STYLES)),
    }, _load_display, _save_display),
    Section("sounds", "Sound notifications", {
        "master_enabled": KeySpec(_flag),
        "events": KeySpec(_map_of(_one_of(_SOUND_EVENT_IDS), _record(
            {"enabled": _flag, "sound": _one_of(SOUND_PROFILES)}, required=("enabled", "sound"),
        ))),
    }, _load_sounds, _save_sounds),
    Section("launch_screen", "Launch screen", {"screen": KeySpec(_one_of(LAUNCH_SCREENS))},
            _load_launch_screen, _save_launch_screen),
    Section("updates", "Update check", {"check_on_startup": KeySpec(_flag)}, _load_updates, _save_updates),
)
SECTIONS_BY_ID: dict[str, Section] = {section.id: section for section in SECTIONS}

# Deliberately not transferable, so nobody re-adds them "for completeness":
# - OAuth sign-ins (ChatGPT/Codex, GitHub Copilot tokens): bound to this machine's login session.
# - Allowed-targets scope and credentials: engagement scope and loot, not preferences.
# - Installed-tool locations (capability paths), nuclei template packs, custom-tools root, downloaded
#   wordlist files: absolute paths and binaries that only exist on the machine that made them.
# - Sessions/projects and the Terminal tab's in-memory flag (never persisted by design).


# --------------------------------------------------------------------------------------------------
# Code / file encoding
# --------------------------------------------------------------------------------------------------


def encode_code(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    packed = base64.urlsafe_b64encode(zlib.compress(raw, 9)).decode("ascii").rstrip("=")
    return CODE_PREFIX + packed


def decode_code(code: str) -> dict:
    compact = "".join(code.split())
    if not compact.startswith(CODE_PREFIX):
        raise SettingsTransferError("That is not an ASRA settings code (it should start with 'ASRA1:').")
    if len(compact) > MAX_CODE_CHARS:
        raise SettingsTransferError("That code is too large to be an ASRA settings export.")
    body = compact[len(CODE_PREFIX):]
    try:
        compressed = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        inflater = zlib.decompressobj()
        raw = inflater.decompress(compressed, MAX_PAYLOAD_BYTES + 1)
    except (binascii.Error, ValueError, zlib.error):
        raise SettingsTransferError("The code is damaged or incomplete (copy the whole string and try again).") from None
    if len(raw) > MAX_PAYLOAD_BYTES or inflater.unconsumed_tail:
        raise SettingsTransferError("The decoded settings are larger than the allowed size.")
    return _parse_json(raw)


def _parse_json(raw: bytes | str) -> dict:
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise SettingsTransferError("That is not valid ASRA settings data (the JSON could not be read).") from None
    if not isinstance(payload, dict):
        raise SettingsTransferError("That is not ASRA settings data (expected a JSON object).")
    return payload


def parse_input(text: str) -> dict:
    """A pasted code or the contents of an exported .json file -- the two interchangeable carriers."""
    stripped = (text or "").strip()
    if not stripped:
        raise SettingsTransferError("Paste a settings code or choose an exported file first.")
    if not stripped.startswith(("{", "[")):
        return decode_code(stripped)
    if len(stripped.encode("utf-8")) > MAX_PAYLOAD_BYTES:
        raise SettingsTransferError("That file is larger than the allowed size for a settings export.")
    return _parse_json(stripped)


# --------------------------------------------------------------------------------------------------
# Sensitive block sealing
# --------------------------------------------------------------------------------------------------


def _derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def _seal(secrets: dict, passphrase: str | None) -> dict:
    if not passphrase:
        return {"encrypted": False, "data": secrets}
    if not ENCRYPTION_AVAILABLE:
        raise SettingsTransferError("A passphrase needs the 'cryptography' package, which is not installed here.")
    salt = os.urandom(KDF_SALT_BYTES)
    token = Fernet(_derive_key(passphrase, salt, KDF_ITERATIONS)).encrypt(json.dumps(secrets).encode("utf-8"))
    return {
        "encrypted": True, "kdf": KDF_NAME, "iterations": KDF_ITERATIONS,
        "salt": base64.urlsafe_b64encode(salt).decode("ascii"), "token": token.decode("ascii"),
    }


def _check_sealed_envelope(block: Any) -> dict:
    """Structure only -- the ciphertext is not touched, so a preview can say 'encrypted' without a passphrase."""
    if not isinstance(block, dict) or not isinstance(block.get("encrypted"), bool):
        raise SettingsTransferError("The sensitive-data block in this payload is malformed.")
    if not block["encrypted"]:
        if set(block) != {"encrypted", "data"} or not isinstance(block["data"], dict):
            raise SettingsTransferError("The sensitive-data block in this payload is malformed.")
        return block
    iterations = block.get("iterations")
    well_formed = (
        set(block) == {"encrypted", "kdf", "iterations", "salt", "token"} and block["kdf"] == KDF_NAME
        and isinstance(iterations, int) and not isinstance(iterations, bool)
        and KDF_MIN_ITERATIONS <= iterations <= KDF_MAX_ITERATIONS
        and isinstance(block["salt"], str) and isinstance(block["token"], str)
    )
    if not well_formed:
        raise SettingsTransferError("The encrypted block in this payload is malformed or uses unsupported settings.")
    return block


def _unseal(block: dict, passphrase: str | None) -> dict:
    if not block["encrypted"]:
        return block["data"]
    if not passphrase:
        raise SettingsTransferError("The API keys and sudo password in this code are encrypted: enter the passphrase.")
    if not ENCRYPTION_AVAILABLE:
        raise SettingsTransferError("Decrypting needs the 'cryptography' package, which is not installed here.")
    try:
        salt = base64.urlsafe_b64decode(block["salt"])
        key = _derive_key(passphrase, salt, block["iterations"])
        decrypted = json.loads(Fernet(key).decrypt(block["token"].encode("ascii")))
    except (InvalidToken, binascii.Error, ValueError, UnicodeError):
        raise SettingsTransferError("Wrong passphrase, or the encrypted block was modified.") from None
    if not isinstance(decrypted, dict):
        raise SettingsTransferError("The encrypted block does not contain settings data.")
    return decrypted


# --------------------------------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------------------------------


def _split_section(section: Section, include_sensitive: bool) -> tuple[dict, dict]:
    """(public, secret) values of one section, restricted to the registry's keys and to values that
    would pass import validation -- a stale or odd stored value is dropped here rather than producing
    an export the owner's own other machine would then refuse."""
    try:
        values = section.loader()
    except Exception as exc:  # one unreadable store must not block exporting everything else
        logger.debug("settings_transfer: section %s could not be read (%s) -- left out", section.id, type(exc).__name__)
        return {}, {}
    public: dict = {}
    secret: dict = {}
    for key, spec in section.keys.items():
        if key not in values or not spec.check(values[key]):
            continue
        if not spec.sensitive:
            public[key] = values[key]
        elif include_sensitive and values[key]:
            secret[key] = values[key]
    return public, secret


def export_settings(*, include_sensitive: bool = False, passphrase: str | None = None) -> dict:
    """The payload dict. Sensitive values are included only when include_sensitive is True, and sealed
    only when a passphrase is also given."""
    if passphrase and not include_sensitive:
        passphrase = None  # nothing to seal; never let a stray field imply protection that is not there
    sections: dict[str, dict] = {}
    secrets: dict[str, dict] = {}
    for section in SECTIONS:
        public, secret = _split_section(section, include_sensitive)
        if any(value not in ([], {}) for value in public.values()):  # skip a section that only carries empty lists
            sections[section.id] = public
        if secret:
            secrets[section.id] = secret
    payload: dict[str, Any] = {
        VERSION_FIELD: SETTINGS_VERSION, "app": "ASRA",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "sections": sections,
    }
    if secrets:
        payload["sensitive"] = _seal(secrets, passphrase)
    logger.debug(
        "settings_transfer: exported sections=%s sensitive=%s encrypted=%s",
        sorted(sections), bool(secrets), bool(secrets and passphrase),
    )
    return payload


def export_summary(payload: dict) -> list[dict]:
    return [
        {"id": section_id, "label": SECTIONS_BY_ID[section_id].label, "count": _count(values)}
        for section_id, values in payload.get("sections", {}).items()
    ]


# --------------------------------------------------------------------------------------------------
# Validation and preview
# --------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ValidatedPayload:
    created_at: str | None
    sections: dict[str, dict]
    secrets: dict[str, dict]
    sensitive_present: bool
    sensitive_encrypted: bool
    sensitive_readable: bool


def _validate_values(section_id: str, values: Any, *, sensitive: bool) -> dict:
    section = SECTIONS_BY_ID.get(section_id)
    if section is None:
        raise SettingsTransferError(f"Unknown settings section '{section_id}' -- this payload is not from a compatible ASRA.")
    if not isinstance(values, dict):
        raise SettingsTransferError(f"Section '{section_id}' is malformed.")
    for key, value in values.items():
        spec = section.keys.get(key)
        # A sensitive key in the public block (or the reverse) is refused: that split is what lets the
        # preview and the "without sensitive data" promise mean something.
        if spec is None or spec.sensitive != sensitive:
            raise SettingsTransferError(f"Unknown setting '{section_id}.{key}' -- nothing was imported.")
        if not spec.check(value):
            raise SettingsTransferError(f"Invalid value for '{section_id}.{key}' -- nothing was imported.")
    return values


def _referenced_custom_provider_ids(sections: dict[str, dict]) -> set[str]:
    refs: set[str] = set()
    llm, chat = sections.get("llm", {}), sections.get("chat", {})
    refs.update(filter(None, (llm.get("provider"), llm.get("secondary_verification_provider"), chat.get("last_provider"))))
    refs.update(llm.get("disabled_providers", []))
    refs.update(llm.get("added_providers", []))
    refs.update(step["provider"] for step in llm.get("fallback_chain", []))
    refs.update(p["provider"] for p in sections.get("subagents", {}).get("profiles", []) if p.get("provider"))
    return {ref for ref in refs if _is_custom_provider_id(ref)}


def _check_custom_provider_references(sections: dict[str, dict]) -> None:
    """A custom-provider id that exists neither in this payload nor on this machine would leave the
    main provider (or a chain step) pointing at nothing, which fails at the next agent start."""
    known = {p["id"] for p in sections.get("custom_providers", {}).get("providers", [])}
    known.update(p.get("id") for p in load_custom_providers() if isinstance(p, dict))
    if _referenced_custom_provider_ids(sections) - known:
        raise SettingsTransferError(
            "These settings refer to a custom LLM provider that is not part of the payload and not on this machine "
            "-- nothing was imported."
        )


def validate_payload(payload: dict, *, passphrase: str | None = None, want_sensitive: bool = True) -> ValidatedPayload:
    """Everything that can be wrong with a payload, checked before any write. want_sensitive=False
    ignores the sensitive block's contents (it is still structure-checked) so a preview needs no
    passphrase."""
    if not isinstance(payload, dict):
        raise SettingsTransferError("That is not ASRA settings data.")
    if VERSION_FIELD not in payload:
        raise SettingsTransferError("That is not an ASRA settings export (no version field).")
    version = payload[VERSION_FIELD]
    if isinstance(version, bool) or version != SETTINGS_VERSION:
        raise SettingsTransferError(
            f"Unsupported settings version {version!r}; this ASRA reads version {SETTINGS_VERSION}."
        )
    unknown = set(payload) - _TOP_LEVEL_FIELDS
    if unknown:
        raise SettingsTransferError(f"Unexpected field '{sorted(unknown)[0]}' in the payload -- nothing was imported.")
    created_at = payload.get("created_at")
    if created_at is not None and not _text(64)(created_at):
        raise SettingsTransferError("The payload's created_at field is malformed.")
    if "app" in payload and not _text(32)(payload["app"]):
        raise SettingsTransferError("The payload's app field is malformed.")

    raw_sections = payload.get("sections")
    if not isinstance(raw_sections, dict):
        raise SettingsTransferError("The payload has no settings sections.")
    sections = {sid: _validate_values(sid, values, sensitive=False) for sid, values in raw_sections.items()}

    secrets: dict[str, dict] = {}
    block = _check_sealed_envelope(payload["sensitive"]) if "sensitive" in payload else None
    readable = False
    if block is not None and want_sensitive and (not block["encrypted"] or passphrase):
        data = _unseal(block, passphrase)
        secrets = {sid: _validate_values(sid, values, sensitive=True) for sid, values in data.items()}
        readable = True
    elif block is not None and want_sensitive and block["encrypted"]:
        raise SettingsTransferError("The API keys and sudo password in this code are encrypted: enter the passphrase.")

    _check_custom_provider_references(sections)
    return ValidatedPayload(
        created_at=created_at, sections=sections, secrets=secrets, sensitive_present=block is not None,
        sensitive_encrypted=bool(block and block["encrypted"]), sensitive_readable=readable,
    )


def preview(validated: ValidatedPayload) -> dict:
    sections = [
        {"id": sid, "label": SECTIONS_BY_ID[sid].label, "count": _count(values)}
        for sid, values in validated.sections.items()
    ]
    sensitive = [
        {"id": sid, "label": SECTIONS_BY_ID[sid].label, "count": _count(values)}
        for sid, values in validated.secrets.items()
    ] if validated.sensitive_readable else None
    return {
        "version": SETTINGS_VERSION, "created_at": validated.created_at, "sections": sections,
        "has_sensitive": validated.sensitive_present, "sensitive_encrypted": validated.sensitive_encrypted,
        "sensitive_sections": sensitive,
    }


# --------------------------------------------------------------------------------------------------
# Apply
# --------------------------------------------------------------------------------------------------


def preview_input(text: str, passphrase: str | None = None) -> dict:
    """Decode + fully validate + summarise, writing nothing. An encrypted sensitive block is only
    opened when a passphrase was typed; otherwise the preview just reports that it is there."""
    payload = parse_input(text)
    block = payload.get("sensitive")
    sealed_and_locked = isinstance(block, dict) and block.get("encrypted") is True and not passphrase
    return preview(validate_payload(payload, passphrase=passphrase or None, want_sensitive=not sealed_and_locked))


def apply_input(text: str, passphrase: str | None = None, *, include_sensitive: bool = False) -> list[dict]:
    """Decode + fully validate + apply. Raises SettingsTransferError before any write if anything is
    wrong; returns per-section results otherwise."""
    validated = validate_payload(parse_input(text), passphrase=passphrase or None, want_sensitive=include_sensitive)
    return apply_settings(validated, include_sensitive=include_sensitive)


def _apply_section(section: Section, values: dict) -> dict:
    result = {"id": section.id, "label": section.label}
    try:
        before = section.loader()
    except Exception:
        before = {}  # nothing readable to restore; a failure below then reports the unrestored state
    try:
        notes = section.saver(values) or []
    except Exception as exc:
        # Only the exception class is surfaced/logged: store errors can echo the value being written.
        logger.debug("settings_transfer: section %s failed (%s) -- restoring previous values", section.id, type(exc).__name__)
        if not before:
            return {**result, "status": "failed", "detail": f"{type(exc).__name__}; there were no earlier values to restore"}
        try:
            section.saver({k: v for k, v in before.items() if k in section.keys})
        except Exception as restore_exc:
            logger.debug("settings_transfer: restoring %s also failed (%s)", section.id, type(restore_exc).__name__)
            return {**result, "status": "failed", "detail": f"{type(exc).__name__}; the previous values could not be fully restored"}
        return {**result, "status": "failed", "detail": f"{type(exc).__name__}; the previous values were restored"}
    detail = "; ".join(notes) if notes else "applied"
    return {**result, "status": "applied", "detail": detail}


def apply_settings(validated: ValidatedPayload, *, include_sensitive: bool) -> list[dict]:
    """Per-section results, in registry order. Sensitive values are written only when include_sensitive
    is True AND they were readable in the validated payload."""
    use_secrets = include_sensitive and validated.sensitive_readable
    results: list[dict] = []
    for section in SECTIONS:
        values = dict(validated.sections.get(section.id, {}))
        if use_secrets:
            values.update(validated.secrets.get(section.id, {}))
        if not values:
            continue
        results.append(_apply_section(section, values))
    logger.debug(
        "settings_transfer: applied %d section(s), failed=%s, sensitive=%s",
        len(results), [r["id"] for r in results if r["status"] == "failed"], use_secrets,
    )
    return results
