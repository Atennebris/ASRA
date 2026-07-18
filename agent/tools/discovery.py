"""KNOWN_TOOLS autodiscovery + custom_tools.yaml manual registration."""
from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from agent.tools.builders.discovered import make_generic_discovered_command
from agent.tools.registry import Category, ToolSpec
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Flat list of well-known binaries per category — extend as needed, this is a seed list,
# not an exhaustive one. Only binaries actually found via shutil.which()
# at startup get registered; nothing here is installed automatically.
KNOWN_TOOLS: dict[Category, list[str]] = {
    "recon": ["subfinder", "amass", "dnsx", "httpx"],
    "scan": ["nikto", "whatweb", "wpscan"],
    "exploit": ["hydra", "gobuster", "ffuf"],
}

CUSTOM_TOOLS_PATH = Path("custom_tools.yaml")


def discover_known_tools() -> list[ToolSpec]:
    """Registers any KNOWN_TOOLS binary that's actually installed and on PATH — zero config needed."""
    discovered = []
    for category, names in KNOWN_TOOLS.items():
        for name in names:
            if shutil.which(name) is None:
                continue
            discovered.append(
                ToolSpec(
                    name=name,
                    category=category,
                    tool_tier=2,
                    executable=name,
                    build_command=make_generic_discovered_command(name),
                    requires_allowed_target=category in ("exploit", "post_exploit"),
                    installed_by_default=False,
                )
            )
            logger.debug("discover_known_tools: found %s (category=%s)", name, category)
    return discovered


def load_custom_tools(path: Path = CUSTOM_TOOLS_PATH) -> list[ToolSpec]:
    """Registers tools listed in custom_tools.yaml — personal scripts, never in KNOWN_TOOLS."""
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as f:
        entries = yaml.safe_load(f) or []

    tools = []
    for entry in entries:
        name = entry["id"]
        executable = entry["executable"]
        tools.append(
            ToolSpec(
                name=name,
                category=entry["category"],
                tool_tier=2,
                executable=executable,
                build_command=make_generic_discovered_command(executable),
                requires_allowed_target=entry.get("requires_allowed_target", False),
                installed_by_default=False,
                full_description=entry.get("full_description"),
            )
        )
        logger.debug("load_custom_tools: registered %s from custom_tools.yaml", name)
    return tools
