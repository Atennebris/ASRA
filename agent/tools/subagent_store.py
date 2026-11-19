"""Persistent storage for Subagent profiles -- named, pre-configured worker profiles (own
allowed-tool list, own instructions/personality, own LLM provider/model) the main agent can
delegate a bounded sub-task to via agent/tools/subagent_tasks.py's delegate_to_subagent, without
blocking its own work. Same on-disk convention as agent/tools/wordlist_store.py (load/_write pair,
atomic tmp-file + os.replace, empty/corrupt file treated as "nothing stored yet" rather than an
error) -- app-level state (spans every session/project), not tied to one session's own schema.

Ships with a built-in roster (the original generic "Default Subagent" plus a fleet of focused
specialists -- recon, brute-force, SQLi/XSS verification, secrets, reverse-engineering, OSINT,
report writing), every one DISABLED, so the Subagents settings tab is never empty on a fresh
install yet nothing is silently active before the operator reviews it. It only actually gets
written to data/subagent_profiles.json once the operator makes a real change (add/update/delete);
until then, load_subagent_profiles() returns this seed roster from memory alone.
"""
from __future__ import annotations

import json
import os
import uuid

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("SUBAGENT")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
SUBAGENT_STORE_PATH = resolve_global_app_dir() / "data" / "subagent_profiles.json"

def _seed_profile(
    profile_id: str, name: str, instructions: str, allowed_tools: list[str],
    icon: str, icon_color: str, free_only: bool = False,
) -> dict:
    """One built-in roster entry. Always starts disabled -- same safety convention as
    import_profiles: an entry's allowed_tools/provider may not match what's actually installed or
    configured on THIS machine, so the operator reviews and turns on what they want, it is never
    silently active on a fresh install. free_only pre-selects the profile's own "Free models only"
    switch (subagents.html) -- persisted so it survives a reload, same "a toggle remembers its own
    position" rule every switch in the app follows. Set True for the high-volume drudge specialists
    (recon/enumeration/OSINT) that shouldn't burn an expensive model, left False for the ones whose
    whole value is judgment (verification, reverse-engineering, report writing)."""
    return {
        "id": profile_id,
        "name": name,
        "enabled": False,
        "allowed_tools": list(allowed_tools),
        "instructions": instructions,
        "provider": None,
        "model": None,
        "icon": icon,
        "icon_color": icon_color,
        "free_only": free_only,
    }


# Built-in roster seeded for every install. Lives here as a module constant -- exactly like the
# single default profile did before -- because it is built-in DEFAULT CONTENT, not per-run config:
# the "No hardcoding" rule targets things that vary per engagement (targets/ports/models/paths),
# which these deliberately don't (provider/model stay None so each follows the session's own
# choice). Each specialist's allowed_tools are real registered ToolSpec names (agent/tools/
# registry.py) so _profile_capability_hint resolves a real tool-domain for the delegating model;
# report_subagent_result is NOT listed -- the subagent runner appends it as the terminal tool.
_SEED_PROFILES: list[dict] = [
    _seed_profile(
        "default", "Default Subagent",
        "", [], "robot", "#60a5fa",
    ),
    _seed_profile(
        "seed-recon-scout", "Recon-Scout",
        "You are a reconnaissance specialist. Enumerate and rank the attack surface of the ONE "
        "host or domain named in your task -- subdomains, live services, tech stack, exposed paths "
        "-- and report a ranked surface summary. Favour breadth and signal over depth; do not "
        "attempt exploitation. Say plainly if the host is unreachable or clearly out of scope "
        "instead of guessing.",
        ["subfinder", "amass_enum", "whatweb", "nmap", "nuclei", "dns_lookup", "crt_sh_lookup",
         "wayback_urls", "security_headers_audit", "rank_attack_surface"],
        "compass", "#34d399", free_only=True,
    ),
    _seed_profile(
        "seed-bruteforce-enum", "Bruteforce-Enum",
        "You are a brute-force and enumeration specialist for a single secondary host. Run content "
        "discovery, parameter discovery and credential checks, and report exactly what resolved -- "
        "paths, parameters, any working credentials -- with the evidence for each. This is "
        "high-volume drudge work; be thorough and do not editorialise.",
        ["ffuf", "arjun", "hydra_start", "web_login_bruteforce_start", "default_creds_check"],
        "gear", "#f59e0b", free_only=True,
    ),
    _seed_profile(
        "seed-sqli-verifier", "SQLi-Verifier",
        "You are a SQL-injection verification specialist. Your task names ONE endpoint/parameter "
        "and ONE hypothesis. Confirm OR disprove it with real requests -- never call a tool's own "
        "'success' proof on its own; show the concrete differential/extracted evidence, or state "
        "clearly that it could not be confirmed. Stay on the one target you were given.",
        ["sqlmap", "send_raw_request", "diff_requests", "intruder_run", "authenticated_request"],
        "puzzle", "#a78bfa",
    ),
    _seed_profile(
        "seed-xss-hunter", "XSS/DOM-Hunter",
        "You are a cross-site-scripting verification specialist. For the ONE URL/parameter in your "
        "task, confirm a reflected or DOM-based XSS with a real, rendered proof-of-concept (actual "
        "script execution in the browser, not just a reflected string). Report the exact payload, "
        "injection point and observed execution, or state plainly that it did not fire.",
        ["dalfox", "browser_navigate", "browser_snapshot", "browser_evaluate", "browser_fill",
         "browser_click", "send_raw_request"],
        "drone", "#f472b6",
    ),
    _seed_profile(
        "seed-secrets-exposure", "Secrets-Exposure",
        "You are an exposure specialist. Sweep the JavaScript bundles, public repositories and "
        "storage of the ONE domain in your task for leaked secrets, API keys and vulnerable "
        "dependencies. Report each hit with where it was found and why it matters; do not report a "
        "match you could not locate concretely.",
        ["trufflehog", "js_bundle_graph", "osv_scanner", "github_code_search", "cloud_bucket_scan",
         "semgrep"],
        "node", "#22d3ee", free_only=True,
    ),
    _seed_profile(
        "seed-re-binary", "RE-Binary",
        "You are a reverse-engineering specialist. Perform a static and dynamic triage of the ONE "
        "binary in your task -- metadata, strings, control flow, interesting calls, runtime "
        "behaviour under emulation/tracing -- and report what it does and any exploitable weakness "
        "found, with the concrete evidence. Do not wander beyond the given binary.",
        ["radare2", "gdb", "ghidra", "frida_trace", "frida_ps", "qiling_emulate", "strace_run",
         "binwalk", "native_binary_metadata", "custom_re_script"],
        "cpu", "#818cf8",
    ),
    _seed_profile(
        "seed-osint-threatintel", "OSINT-ThreatIntel",
        "You are an OSINT and threat-intelligence specialist. Run a passive-only intelligence sweep "
        "on the ONE domain/organisation in your task -- WHOIS, DNS and certificate history, passive "
        "URLs, exposed code, breach data -- and report the actionable findings. Passive only: do "
        "not touch the live target with active scans.",
        ["whois_lookup", "dns_lookup", "crt_sh_lookup", "otx_passive_dns", "urlscan_search",
         "common_crawl_urls", "wayback_urls", "github_code_search", "hibp_breach_check",
         "geoip_lookup"],
        "brain", "#e879f9", free_only=True,
    ),
    _seed_profile(
        "seed-reporter", "Reporter",
        "You are a report-writing specialist. You receive an ALREADY-CONFIRMED finding with its "
        "evidence and turn it into a clear, bounty-payable writeup: accurate title, impact, "
        "reproduction steps, severity reasoning. You deliberately have NO tools -- you do not "
        "re-test and you cannot persist findings yourself (only the main agent does that); write "
        "your whole report in your result summary, working only from the evidence you are given, "
        "and flag it plainly if that evidence is too thin to write up honestly.",
        [],
        "wrench", "#fbbf24",
    ),
]


def _seed_profiles() -> list[dict]:
    """Fresh deep copies of the built-in roster -- never the module constant itself, so a caller
    mutating a returned profile (add_profile appending to the list, a later update) can never alter
    the seed every subsequent fresh-install load depends on."""
    return [dict(profile) for profile in _SEED_PROFILES]


def load_subagent_profiles() -> dict:
    if not SUBAGENT_STORE_PATH.exists():
        return {"profiles": _seed_profiles()}

    try:
        with SUBAGENT_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("subagent_profiles.json unreadable (%s) — treating as the default seed", exc)
        return {"profiles": _seed_profiles()}

    if not isinstance(data, dict):
        logger.debug("subagent_profiles.json does not contain an object — treating as the default seed")
        return {"profiles": _seed_profiles()}

    profiles = data.get("profiles")
    if not isinstance(profiles, list):
        return {"profiles": _seed_profiles()}
    # Return the whole stored dict, not a fresh {"profiles": ...}, so top-level keys other than
    # profiles (e.g. builtin_seed_version, the one-time-migration marker) survive the load -> mutate
    # -> _write round trip every CRUD op goes through. Dropping them here silently reset the marker
    # on the next add/update/delete, which made the fleet migration re-run and resurrect a built-in
    # the operator had deleted -- the exact bug this preserves against.
    data["profiles"] = profiles
    return data


def _write_subagent_profiles(data: dict) -> None:
    SUBAGENT_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = SUBAGENT_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, SUBAGENT_STORE_PATH)


def add_profile(
    name: str, allowed_tools: list[str], instructions: str, provider: str | None, model: str | None,
    icon: str | None = None, icon_color: str | None = None, free_only: bool = False,
) -> dict:
    store = load_subagent_profiles()
    profile = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "enabled": False,
        "allowed_tools": list(allowed_tools),
        "instructions": instructions,
        "provider": provider,
        "model": model,
        "icon": icon,
        "icon_color": icon_color,
        "free_only": bool(free_only),
    }
    store["profiles"].append(profile)
    _write_subagent_profiles(store)
    logger.debug("subagent_store: added profile id=%s name=%r", profile["id"], name)
    return store


def update_profile(profile_id: str, **fields) -> dict:
    """fields may include any of name/enabled/allowed_tools/instructions/provider/model/icon/
    icon_color -- unrecognized keys are ignored rather than raising, same tolerance as the rest of
    this project's "accept a real-world variant" discipline (a caller passing an extra, harmless
    key shouldn't have to know this function's exact whitelist to avoid an error)."""
    allowed_fields = {"name", "enabled", "allowed_tools", "instructions", "provider", "model", "icon", "icon_color", "free_only"}
    store = load_subagent_profiles()
    for profile in store["profiles"]:
        if profile["id"] == profile_id:
            for key, value in fields.items():
                if key in allowed_fields:
                    profile[key] = value
            break
    else:
        raise ValueError(f"unknown subagent profile id {profile_id!r}")
    _write_subagent_profiles(store)
    logger.debug("subagent_store: updated profile id=%s fields=%s", profile_id, sorted(fields))
    return store


def delete_profile(profile_id: str) -> dict:
    store = load_subagent_profiles()
    store["profiles"] = [p for p in store["profiles"] if p["id"] != profile_id]
    _write_subagent_profiles(store)
    logger.debug("subagent_store: deleted profile id=%s", profile_id)
    return store


def get_enabled_profiles(allowed_ids: list[str] | None = None) -> list[dict]:
    """Every globally-enabled Subagent profile (Subagents settings tab), optionally narrowed to
    just the ids one specific project chose to grant access to (New Project form's per-project
    picker, session["enabled_subagent_ids"] -- see sessions/store.py's create_session docstring
    for that field). allowed_ids=None means no restriction at all -- every caller that predates
    the per-project picker (and every session created before it existed) keeps seeing every
    globally-enabled profile exactly as before. An explicit (possibly empty) list means a specific
    project narrowed it down -- checked against enabled profiles only, so a profile disabled
    globally after a project picked it never comes back just because that project's own list still
    names its id."""
    profiles = [p for p in load_subagent_profiles()["profiles"] if p.get("enabled")]
    if allowed_ids is None:
        return profiles
    allowed = set(allowed_ids)
    return [p for p in profiles if p.get("id") in allowed]


def get_profile_by_name(name: str, allowed_ids: list[str] | None = None) -> dict | None:
    """delegate_to_subagent's own lookup key is the operator-chosen name, not the internal id --
    the model names the subagent it wants by the same name shown to it, never an id it never saw.
    allowed_ids is the same per-project narrowing get_enabled_profiles() takes -- a subagent must
    be both globally enabled AND (when the project restricts it) in that project's own allowlist
    to ever be delegated to."""
    return next((p for p in get_enabled_profiles(allowed_ids) if p.get("name") == name), None)


def import_profiles(incoming: dict, source_label: str = "import") -> int:
    """Merges an exported/portable profile pack ({"profiles": [profile, ...]}) into the store,
    appending only profiles whose id isn't already present -- same "dedup by id, re-importing never
    duplicates" discipline as playbook_store.import_entries. Malformed shapes are skipped, never
    raised -- an operator's own upload shouldn't be able to crash the app.

    Every imported profile lands disabled regardless of what the source file says, exactly like a
    freshly hand-added one (add_profile) -- an imported profile's allowed_tools/provider may not
    match what's actually installed/configured on THIS machine, so it must be reviewed and
    explicitly turned on here, never silently active the moment the import completes."""
    if not isinstance(incoming, dict):
        return 0
    profiles = incoming.get("profiles")
    if not isinstance(profiles, list):
        return 0
    store = load_subagent_profiles()
    existing_ids = {p.get("id") for p in store["profiles"]}
    added = 0
    for profile in profiles:
        if not isinstance(profile, dict) or not str(profile.get("name", "")).strip():
            continue
        pid = str(profile.get("id") or uuid.uuid4().hex[:12])
        if pid in existing_ids:
            continue
        store["profiles"].append({
            "id": pid,
            "name": str(profile.get("name", "")).strip(),
            "enabled": False,
            "allowed_tools": list(profile.get("allowed_tools") or []),
            "instructions": str(profile.get("instructions") or ""),
            "provider": profile.get("provider") or None,
            "model": profile.get("model") or None,
            "icon": profile.get("icon") or None,
            "icon_color": profile.get("icon_color") or None,
        })
        existing_ids.add(pid)
        added += 1
    if added:
        _write_subagent_profiles(store)
    logger.debug("subagent_store: imported %d profile(s) from %s", added, source_label)
    return added


# Bump this whenever a NEW built-in specialist is added to _SEED_PROFILES, so already-migrated
# stores pick the newcomer up on their next startup (ensure_builtin_specialists_migrated re-runs
# once per new version). Does NOT re-add a built-in the operator deleted at an EARLIER version --
# only ids missing when THIS version's merge runs are added.
# v2: also scrubs subagent-disallowed tools out of already-stored profiles (the first Reporter seed
# shipped record_* tools a subagent can never use -- see _SUBAGENT_DISALLOWED_TOOLS below).
_BUILTIN_SEED_VERSION = 2


# Tools a subagent can never actually use: stripped from any subagent's toolset at delegation time
# (agent/core.py's _delegate_to_subagent_impl) and never offered in the Subagents editor (main.py's
# _subagent_unofferable_tools) -- a subagent calling one gets "status": "ok" while the real effect
# (persisting a finding, ending a phase) silently never happens. Duplicated here on purpose: both
# source lists are local constants, not importable, and importing agent.core here would be the
# circular import subagent_tasks.py's own docstring warns about. Keep in sync with those two by hand.
_SUBAGENT_DISALLOWED_TOOLS = {
    "report_subagent_result", "delegate_to_subagent", "check_subagent_task",
    "record_finding", "record_target", "record_hypothesis", "resolve_hypothesis",
    "record_exploit_decision", "record_chain_result", "record_reverification_result",
    "record_skeptical_verification_result",
}


def restore_builtin_specialists() -> int:
    """Merges any built-in roster profile (_SEED_PROFILES) not already present by id into the store,
    disabled -- same dedup-by-id, lands-disabled convention as import_profiles. Returns how many
    were added. The explicit "operator asked for them back" primitive (a Settings 'restore built-in
    specialists' action), separate from the automatic one-time migration below: this one ignores the
    version marker on purpose, so re-adding a deleted built-in is exactly what the operator gets when
    they deliberately ask for it. Existing profiles are never touched."""
    store = load_subagent_profiles()
    existing_ids = {p.get("id") for p in store["profiles"]}
    added = 0
    for seed in _SEED_PROFILES:
        if seed["id"] not in existing_ids:
            store["profiles"].append(dict(seed))
            added += 1
    if added:
        _write_subagent_profiles(store)
    logger.debug("subagent_store: restore_builtin_specialists added %d profile(s)", added)
    return added


def ensure_builtin_specialists_migrated() -> int:
    """One-time startup migration so stores created BEFORE the built-in specialist fleet existed get
    it too -- exactly once per _BUILTIN_SEED_VERSION, and WITHOUT resurrecting a built-in the
    operator later deleted (the persisted marker records that this version's merge already ran, so a
    subsequent deliberate delete sticks). A no-op when no store file exists yet (the fresh-install
    seed in load_subagent_profiles already includes the fleet) or when the marker is already current.
    Called once from main.py's startup sweep, next to the other orphan/migration passes."""
    if not SUBAGENT_STORE_PATH.exists():
        return 0
    try:
        with SUBAGENT_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return 0  # a corrupt/unreadable file already falls back to the full seed on load
    if not isinstance(data, dict) or not isinstance(data.get("profiles"), list):
        return 0
    if int(data.get("builtin_seed_version", 0) or 0) >= _BUILTIN_SEED_VERSION:
        return 0
    existing_ids = {p.get("id") for p in data["profiles"]}
    added = 0
    for seed in _SEED_PROFILES:
        if seed["id"] not in existing_ids:
            data["profiles"].append(dict(seed))
            added += 1
    # Scrub subagent-disallowed tools out of every already-stored profile -- pure hygiene (the
    # runtime strips them anyway), fixing the misleading tool badge for the first Reporter seed and
    # any operator-made profile that happened to pick one. Never removes a tool that actually works.
    for profile in data["profiles"]:
        tools = profile.get("allowed_tools")
        if isinstance(tools, list):
            profile["allowed_tools"] = [t for t in tools if t not in _SUBAGENT_DISALLOWED_TOOLS]
    # Persist the marker even when nothing was added, so this check stops re-running every startup.
    data["builtin_seed_version"] = _BUILTIN_SEED_VERSION
    _write_subagent_profiles(data)
    logger.debug(
        "subagent_store: builtin-specialist migration v%d added %d profile(s)",
        _BUILTIN_SEED_VERSION, added,
    )
    return added
