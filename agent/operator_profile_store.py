"""Persistent, cross-project "operator profile" for the MAIN agent (the one that actually drives
Recon -> Analyze -> Exploit -> Validate) -- NOT subagents, which keep their own named profiles
(agent/tools/subagent_store.py), and NOT the default provider/model (agent/settings.py), which this
deliberately does not touch.

The problem this solves: today the only place to tell the main agent "I care most about IDOR/broken
auth", "stay quiet on WAF-protected targets", or "write findings simpler, my English isn't native"
is the New Project form's one-off "Custom instructions" field (session["custom_instructions"]),
which applies to ONE project and has to be re-typed every time. This store is the layer BELOW that:
a standing profile applied to every new project by default, with the per-project field still
layered on top as the more-specific override (agent/core.py's _operator_profile_task_addendum is
appended BEFORE _custom_instructions_task_addendum at every call site, so the project-specific text
reads as the final, more-specific refinement).

Scope is deliberately STYLE/PRIORITIES only -- never allowlist targets, credentials, or anything
security-critical (those stay in data/allowed_targets.json, data/credentials/). A single flat
profile per installation, not a list of named profiles: the "this project is different" case is
already covered by the per-project override above, so there's no second mechanism to build here.

Same on-disk convention as agent/settings.py / agent/tools/wordlist_store.py (load/_write pair,
atomic tmp-file + os.replace, empty/corrupt file treated as "nothing configured yet" rather than an
error). Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/
folder.
"""
from __future__ import annotations

import json
import os

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("PROFILE")

OPERATOR_PROFILE_PATH = resolve_global_app_dir() / "data" / "operator_profile.json"

# Bumped only when the on-disk shape changes incompatibly. Stamped into every written file so a
# future field addition/rename can migrate an old file in load_operator_profile() instead of needing
# a manual one-off migration -- cheap insurance taken now precisely so the "one flat profile"
# decision never has to be painted into a corner (e.g. a later move to named profiles).
SCHEMA_VERSION = 1

# The free-text fields, all plain strings. communication_style is the one constrained field (see
# _VALID_COMMUNICATION_STYLES) -- everything else is whatever the operator typed.
_TEXT_FIELDS = ("standing_instructions", "focus_classes")

# "" (unset -> no behavior change, the default) or one of these. A verbosity preference for how
# chatty the agent's live step-by-step narration is -- NOT the final report's depth.
_VALID_COMMUNICATION_STYLES = ("", "concise", "detailed")

# Severity tiers, highest-first -- the canonical order approval_severities is normalized/stored in,
# and the valid set for it. Matches agent/core.py's own finding severities (_VALID_FINDING_SEVERITIES
# / _SEVERITY_RANK), kept lowercase here since that's how the gate compares them.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _normalize_severities(values: object) -> list[str]:
    """Coerces any iterable of severity names into a clean, deduplicated, canonical-order lowercase
    list, dropping anything not a real severity. Non-iterable / unexpected input -> empty list, never
    raises (same lenient contract as the text fields)."""
    if not isinstance(values, (list, tuple, set)):
        return []
    lowered = {str(v).strip().lower() for v in values}
    return [s for s in _SEVERITY_ORDER if s in lowered]


def _default_profile() -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        # Standing, cross-project instructions/priorities -- the core field. The same kind of text as
        # a project's one-off custom_instructions, but permanent and general to every new project.
        "standing_instructions": "",
        # Vulnerability classes the operator cares about most, free text. Fed to the prompt only (it
        # nudges what the agent investigates first on limited time); deliberately NOT a deterministic
        # ranking key -- this project already forbids fuzzy-matching a finding against free-text
        # rules (see agent/core.py's _exploit_priority_key / _warn_if_scope_rules_went_unused).
        "focus_classes": "",
        # "" | "concise" | "detailed" -- how verbose the agent's live narration is in the chat/log.
        "communication_style": "",
        # Severities (lowercase subset of _SEVERITY_ORDER) that require a human approval click before
        # the agent exploits a finding of that severity -- the one NON-prompt field here: it's read
        # directly by the real approval gate (agent/core.py's _exploit_requires_approval), never
        # emitted into any prompt. Empty (the default) -> gating is governed solely by
        # EXPLOIT_REQUIRE_APPROVAL exactly as before. This ADDS gating on top of that env switch
        # (strictest wins), it never removes it.
        "approval_severities": [],
    }


def _coerce(loaded: dict) -> dict:
    """Fills every field from a possibly-partial/old on-disk object onto a full default, dropping
    anything unexpected. A missing/invalid field falls back to its default rather than raising, same
    "nothing set -> no behavior change" contract every other store here follows."""
    profile = _default_profile()
    for field in _TEXT_FIELDS:
        value = loaded.get(field)
        if isinstance(value, str):
            profile[field] = value
    style = loaded.get("communication_style")
    if isinstance(style, str) and style in _VALID_COMMUNICATION_STYLES:
        profile["communication_style"] = style
    profile["approval_severities"] = _normalize_severities(loaded.get("approval_severities"))
    return profile


def load_operator_profile() -> dict:
    """Always returns a full profile dict with every field present (defaults when unset), so callers
    and templates never have to guard a missing key. An absent/unreadable/non-object file is treated
    as "nothing configured yet" -> all-empty defaults, never an error."""
    if not OPERATOR_PROFILE_PATH.exists():
        return _default_profile()
    try:
        with OPERATOR_PROFILE_PATH.open("r", encoding="utf-8") as f:
            loaded = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("operator_profile.json unreadable (%s) — treating as empty profile", exc)
        return _default_profile()
    if not isinstance(loaded, dict):
        logger.debug("operator_profile.json does not contain an object — treating as empty profile")
        return _default_profile()
    return _coerce(loaded)


def _write_operator_profile(data: dict) -> None:
    OPERATOR_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = OPERATOR_PROFILE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, OPERATOR_PROFILE_PATH)


def save_operator_profile(
    standing_instructions: str = "",
    focus_classes: str = "",
    communication_style: str = "",
    approval_severities: object = None,
) -> dict:
    """Writes the whole profile at once (the Settings form submits every field together). Text
    fields are stripped; an unknown communication_style is coerced to "" (unset) and unknown
    severities are dropped, so a stale/unexpected value can never wedge the form. Returns the saved
    profile."""
    style = communication_style if communication_style in _VALID_COMMUNICATION_STYLES else ""
    profile = {
        "schema_version": SCHEMA_VERSION,
        "standing_instructions": (standing_instructions or "").strip(),
        "focus_classes": (focus_classes or "").strip(),
        "communication_style": style,
        "approval_severities": _normalize_severities(approval_severities),
    }
    _write_operator_profile(profile)
    logger.debug(
        "operator_profile: saved standing=%d chars focus=%d chars communication_style=%r approval_severities=%s",
        len(profile["standing_instructions"]), len(profile["focus_classes"]),
        profile["communication_style"], profile["approval_severities"],
    )
    return profile


def get_approval_severities() -> set[str]:
    """The severities (lowercase) the operator wants to personally approve before exploitation, read
    straight from the saved profile -- the single reader agent/core.py's approval gate wires against.
    Empty set (the default) means "no per-severity gating configured", so the gate falls back to
    EXPLOIT_REQUIRE_APPROVAL alone, exactly as before this field existed."""
    return set(load_operator_profile().get("approval_severities") or [])


def operator_profile_is_empty(profile: dict | None = None) -> bool:
    """True when nothing meaningful is configured -- the agent then behaves exactly as before this
    feature existed. Loads the profile itself when not handed one."""
    if profile is None:
        profile = load_operator_profile()
    if profile.get("approval_severities"):
        return False
    return not any(
        (profile.get(field) or "").strip() for field in (*_TEXT_FIELDS, "communication_style")
    )
