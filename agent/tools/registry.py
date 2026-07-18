"""ToolSpec and TOOL_REGISTRY: the extensible tool registry core."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

Category = Literal["recon", "scan", "exploit", "post_exploit"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    category: Category
    tool_tier: int  # 1 = small native Python function, 2 = external subprocess binary
    executable: str
    build_command: Callable[[dict], list[str]] | None
    requires_allowed_target: bool
    installed_by_default: bool
    # tool_tier=1 only: called directly instead of subprocess, no health-check/
    # timeout wrapper — the function owns its own timeout (e.g. httpx.Client(timeout=...)). Returns
    # a result dict shaped like run_tool()'s tier-2 output ({"status": ..., ...}).
    native_function: Callable[[dict], dict] | None = None
    # Optional: same tool, different risk depending on args (e.g. nmap -sV vs -sS).
    # Returns a free-form risk label; run_tool() logs it when it's above "default".
    classify_risk: Callable[[dict], str] | None = None
    # Optional, discovered/custom tools only: a hand-written description used
    # instead of running `<executable> --help` to learn the tool's capabilities — for scripts with
    # no standard --help output. Hardcoded tools (nmap/nuclei/exploit/sqlmap) leave this None.
    full_description: str | None = None

    # requires_allowed_target=True is the default expectation for exploit/post_exploit tools,
    # but not an absolute rule: msf_module_search is category="exploit"
    # yet requires_allowed_target=False — it only reads Metasploit's module list, no action runs
    # against a target. Deliberately not enforced here; each registration owns that call.

    def __post_init__(self) -> None:
        if self.tool_tier == 1 and self.native_function is None:
            raise ValueError(f"ToolSpec {self.name!r}: tool_tier=1 requires native_function.")
        if self.tool_tier == 2 and self.build_command is None:
            raise ValueError(f"ToolSpec {self.name!r}: tool_tier=2 requires build_command.")


TOOL_REGISTRY: list[ToolSpec] = []


def register_tool(spec: ToolSpec) -> ToolSpec:
    """Adds a ToolSpec to the registry, guarding against accidental duplicate names."""
    if any(existing.name == spec.name for existing in TOOL_REGISTRY):
        raise ValueError(f"Tool {spec.name!r} is already registered.")
    TOOL_REGISTRY.append(spec)
    return spec


def get_tool(name: str) -> ToolSpec | None:
    return next((spec for spec in TOOL_REGISTRY if spec.name == name), None)


def get_tools_by_category(category: Category) -> list[ToolSpec]:
    return [spec for spec in TOOL_REGISTRY if spec.category == category]
