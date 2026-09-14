"""Persistent, cross-session baseline of a target's known asset surface -- subdomains, open
ports/services, endpoints, GraphQL operation names, or any other free-form category a session
chooses to track. Keyed by host (the "target" value the caller passes, e.g. a program's apex
domain), global across every project/session -- deliberately not tied to one project folder, so
re-scanning the same real-world target from a brand-new project still diffs against what was found
last time, the same reasoning agent/tools/playbook_store.py already applies to technique reuse.

Same on-disk convention as playbook_store.py/wordlist_store.py (load/_write pair, atomic tmp-file +
os.replace, empty/corrupt file treated as "nothing stored yet" rather than an error).

Why this exists: ASRA's session model is one-shot -- Recon through Validate, then done. The
highest-leverage lead in real bug-bounty hunting is usually not deeper analysis of a target that's
been scanned repeatedly (by this agent and by every other researcher/scanner), it's catching
something NEW since the last pass -- a freshly added subdomain, a newly exposed port, an endpoint
that didn't exist before. Nothing survived a session's end to make that possible until this module;
see [[project_playbook_memory]] for the sibling mechanism this generalizes the same idea from
(confirmed techniques instead of raw asset presence).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Global app data (Documents/ASRA/data, see projects/paths.py) -- real subdomain/port/endpoint
# data against real targets, no business living inside the git checkout's own data/ folder.
ASSET_BASELINE_STORE_PATH = resolve_global_app_dir() / "data" / "asset_baseline" / "assets.json"


def load_asset_baseline_store() -> dict:
    if not ASSET_BASELINE_STORE_PATH.exists():
        return {}

    try:
        with ASSET_BASELINE_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("assets.json unreadable (%s) — treating as empty store", exc)
        return {}

    if not isinstance(data, dict):
        logger.debug("assets.json does not contain an object — treating as empty store")
        return {}

    return {
        target: categories for target, categories in data.items()
        if isinstance(target, str) and isinstance(categories, dict)
    }


def _write_asset_baseline_store(store: dict) -> None:
    ASSET_BASELINE_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = ASSET_BASELINE_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, ASSET_BASELINE_STORE_PATH)


def diff_and_update(target: str, category: str, current_assets: list[str]) -> dict:
    """Loads the stored baseline for (target, category), computes new/removed against
    current_assets, persists current_assets as the new baseline for next time, and returns the
    diff. The stored list is fully REPLACED with current_assets each call (not merged/unioned) --
    the baseline always reflects "what was actually seen as of the last scan", which is what makes
    removed_assets meaningful at all; a union would never let anything look removed.
    """
    store = load_asset_baseline_store()
    host_entry = store.setdefault(target, {})
    category_entry = host_entry.get(category)

    current_set = {a.strip() for a in current_assets if a and a.strip()}
    now = datetime.now(timezone.utc).isoformat()

    # On a genuine first scan there is nothing to diff against -- reporting every current asset as
    # "new" would be misleading (it isn't newly discovered relative to a real prior baseline, there
    # simply wasn't one), so both come back empty and this call's only real effect is seeding the
    # baseline for next time.
    if category_entry is None:
        first_scan = True
        new_assets: list[str] = []
        removed_assets: list[str] = []
        first_seen = now
    else:
        first_scan = False
        previous_set = set(category_entry.get("assets", []))
        new_assets = sorted(current_set - previous_set)
        removed_assets = sorted(previous_set - current_set)
        first_seen = category_entry.get("first_seen", now)

    host_entry[category] = {
        "assets": sorted(current_set),
        "first_seen": first_seen,
        "last_updated": now,
    }
    _write_asset_baseline_store(store)

    logger.debug(
        "diff_and_update: target=%r category=%r first_scan=%s new=%d removed=%d total=%d",
        target, category, first_scan, len(new_assets), len(removed_assets), len(current_set),
    )
    return {
        "first_scan": first_scan,
        "new_assets": new_assets,
        "removed_assets": removed_assets,
        "total_known_assets": len(current_set),
    }


def _asset_baseline_enabled() -> bool:
    return os.getenv("ASSET_BASELINE_ENABLED", "true").strip().lower() == "true"


def asset_diff_check(params: dict) -> dict:
    if not _asset_baseline_enabled():
        return {"status": "disabled"}

    target = params["target"]
    category = params["category"]
    current_assets = params.get("current_assets") or []
    if not isinstance(current_assets, list):
        return {"status": "error", "error": "current_assets must be a list of strings"}

    result = diff_and_update(target, category, [str(a) for a in current_assets])
    return {"status": "ok", **result}
