"""Operator-registered custom tools -- Settings -> Tools -> "Custom tools" section. A binary the
operator has on disk (usually surfaced via TOOLS_CUSTOM_ROOT's own "Test path" discovery,
agent/tools/custom_tools_root.py) that ASRA's registry doesn't know about at all -- no builder, no
schema, nothing. Registering one here is what turns it into a real, named, model-callable tool
(agent/tools/custom_tool_runtime.py mints the actual ToolSpec from each ENABLED record here).

Same load/_write atomic-tmp-file-+-os.replace shape as agent/tools/wordlist_store.py and
agent/tools/allowed_targets.py -- not a third persistence pattern. Nothing in here is secret
(filesystem paths + operator-written notes), but it's still under resolve_global_app_dir(), outside
the git tree, same public-safety discipline every other data/*.json runtime file in this project
already gets.

Record shape: {id, name, path, enabled, description, requires_target, category, added_at}. `name`
is always the executable's own basename, never independently renamed -- agent/tools/
custom_tools_root.py's own discovery step already filters OUT any candidate whose name collides
with a KNOWN registry tool's executable before it's ever offered, so a registered record's name
can never collide with a real builtin tool by construction; add_custom_tool below additionally
guards against two DIFFERENT custom records landing on the same name (two distinct paths that
happen to share a basename).
"""
from __future__ import annotations

import json
import os
import time
import uuid

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Global app data (Documents/ASRA/data, see projects/paths.py), not a repo-relative data/ folder.
CUSTOM_TOOLS_STORE_PATH = resolve_global_app_dir() / "data" / "custom_tools.json"

# What the operator picks when adding a candidate -- the real registry categories a custom tool can
# be made visible under, plus "custom" for "not sure which bucket fits" (translated at mint time,
# agent/tools/custom_tool_runtime.py, into every ordinary web-pentest category at once rather than
# a new literal value the rest of the registry would have to understand).
#
# Deliberately NOT "post_exploit" -- real, confirmed trap this avoids: unlike recon/scan/exploit/re,
# nothing anywhere in agent/core.py or agent/chat.py ever calls get_tools_by_category("post_exploit")
# directly (that category is used in THIS codebase specifically to keep a handful of bookkeeping
# tools -- record_chain_result, update_plan, ... -- OUT of every ordinary category sweep, added back
# in only by exact name at each phase's own assembly point). A custom tool registered under a bare
# "post_exploit" choice would be silently unreachable from every single phase/subagent forever, with
# no error anywhere to reveal that -- picking "custom" already covers the "I'm not sure" case via
# _category_for's own recon+scan+exploit+post_exploit expansion, which (unlike this single-category
# choice) IS found through the recon/scan/exploit sweeps that are actually queried.
CUSTOM_TOOL_CATEGORIES = ("recon", "scan", "exploit", "re", "custom")
_DEFAULT_CATEGORY = "custom"


def load_custom_tools() -> list[dict]:
    if not CUSTOM_TOOLS_STORE_PATH.exists():
        return []
    try:
        with CUSTOM_TOOLS_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("custom_tools_store: unreadable (%s) -- treating as empty store", exc)
        return []
    return data if isinstance(data, list) else []


def _write_custom_tools(records: list[dict]) -> None:
    CUSTOM_TOOLS_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CUSTOM_TOOLS_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)
    os.replace(tmp_path, CUSTOM_TOOLS_STORE_PATH)


def get_custom_tool(tool_id: str) -> dict | None:
    return next((r for r in load_custom_tools() if r["id"] == tool_id), None)


def custom_tool_name_exists(name: str) -> bool:
    return any(r["name"] == name for r in load_custom_tools())


def add_custom_tool(*, name: str, path: str, description: str, requires_target: bool, category: str) -> dict:
    """Registers a newly-confirmed candidate -- never called from discovery alone (see this
    module's own docstring: discovery only ever SHOWS candidates, nothing is added until the
    operator explicitly confirms one in the UI). Starts enabled -- the confirm click itself is the
    explicit action; a toggle to turn it back off is always available afterward, same "add =
    active, with an easy undo" convention the New Project form's allowlist entries already use.
    """
    if custom_tool_name_exists(name):
        raise ValueError(f"a custom tool named {name!r} is already registered -- remove it first, or this is the same binary already added.")
    if category not in CUSTOM_TOOL_CATEGORIES:
        raise ValueError(f"category must be one of {CUSTOM_TOOL_CATEGORIES}, got {category!r}")

    record = {
        "id": uuid.uuid4().hex[:12],
        "name": name,
        "path": path,
        "enabled": True,
        "description": description,
        "requires_target": requires_target,
        "category": category,
        "added_at": time.time(),
    }
    records = load_custom_tools()
    records.append(record)
    _write_custom_tools(records)
    logger.debug("custom_tools_store: registered %r (path=%r, category=%s, requires_target=%s)", name, path, category, requires_target)
    return record


def set_custom_tool_enabled(tool_id: str, enabled: bool) -> dict | None:
    records = load_custom_tools()
    for record in records:
        if record["id"] == tool_id:
            record["enabled"] = enabled
            _write_custom_tools(records)
            logger.debug("custom_tools_store: %r enabled=%s", record["name"], enabled)
            return record
    return None


def update_custom_tool(tool_id: str, *, description: str | None = None, requires_target: bool | None = None, category: str | None = None) -> dict | None:
    if category is not None and category not in CUSTOM_TOOL_CATEGORIES:
        raise ValueError(f"category must be one of {CUSTOM_TOOL_CATEGORIES}, got {category!r}")
    records = load_custom_tools()
    for record in records:
        if record["id"] == tool_id:
            if description is not None:
                record["description"] = description
            if requires_target is not None:
                record["requires_target"] = requires_target
            if category is not None:
                record["category"] = category
            _write_custom_tools(records)
            logger.debug("custom_tools_store: %r updated", record["name"])
            return record
    return None


def remove_custom_tool(tool_id: str) -> bool:
    records = load_custom_tools()
    remaining = [r for r in records if r["id"] != tool_id]
    if len(remaining) == len(records):
        return False
    _write_custom_tools(remaining)
    logger.debug("custom_tools_store: removed id=%s", tool_id)
    return True


def registered_custom_tool_paths() -> set[str]:
    """Every path already registered (enabled or not) -- discovery (custom_tools_root.py) uses
    this to stop re-offering a candidate the operator already added."""
    return {r["path"] for r in load_custom_tools()}
