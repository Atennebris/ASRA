"""ToolSpec and TOOL_REGISTRY: the extensible tool registry core."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal

# "toolkit" (native Proxy/Repeater/Decoder/Comparer/Intruder/Sequencer tools, see
# agent/tools/toolkit_agent_tools.py) is like "post_exploit" -- deliberately never queried by any
# phase's own get_tools_by_category()
# call, so it can't silently leak into a normal phase toolset. Availability is entirely settings-
# toggle-driven instead (agent/core.py's _toolkit_tool_extras, agent/tools/toolkit_settings_store.py),
# explicitly appended at each phase's own tool_specs assembly, same pattern as subagent_tools.
#
# "re" (radare2/gdb/slither/heimdall/pyevmasm/semgrep, Reverse Engineering project mode) follows
# the exact same "toolkit" precedent: no ordinary web-pentest phase's get_tools_by_category call
# ever passes "re" (they all hardcode "recon"/"scan"/"exploit"/"post_exploit" literally), so these
# tools can never leak into a normal Agent/Interactive session. Only agent/core.py's
# run_re_triage and agent/chat.py's mode=="reverse_engineering" branch query this category.
Category = Literal["recon", "scan", "exploit", "post_exploit", "toolkit", "re"]


@dataclass(frozen=True)
class ToolSpec:
    name: str
    # A tuple, not just a single Category, for the rare tool genuinely useful in more than one
    # phase's toolset (e.g. http_request: a read-only verification call Analyze already relies on,
    # and Exploit needs the exact same thing to check one more specific detail instead of
    # guessing/giving up — real incident this exists because of: exploit-phase turns that stalled
    # on "I have no HTTP request tool to verify X" when the identical tool already existed one
    # phase over). Use categories_of(spec) below to read this, never spec.category directly --
    # that always returns whatever was actually passed in, single value or tuple.
    category: Category | tuple[Category, ...]
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
    # LLM-facing function-calling metadata. description: short one-liner shown to the model;
    # left "" for autodiscovered/custom tools, whose schema builder (agent/core.py) fetches a
    # live --help instead (get_tool_help) since no one hand-wrote a summary for them.
    description: str = ""
    # OpenAI function-calling "parameters" JSON schema. None falls back to the generic
    # {target, extra_args} shape every autodiscovered/custom tool uses (2.5.2 in the project plan).
    parameters_schema: dict | None = None
    # tool_tier=2 only: which real subprocess exit codes count as "ok" (run its own output parser,
    # let the model see structured findings) rather than "error". {0} for every ordinary tool. Real
    # incident this exists because of: dalfox uses the common CI/CD convention of exiting 1 to mean
    # "scan completed, findings were present" (confirmed live — 0 for a clean scan, 1 the instant a
    # real XSS is found, even 0 for a target-unreachable/DNS-failure case since that's reported
    # inside its own JSON, not via exit code) — under the {0}-only default, run_tool would mark the
    # exact run that actually found something as "error" and never even hand its JSON to the output
    # parser, silently making the tool look broken precisely when it worked.
    ok_exit_codes: frozenset[int] = field(default_factory=lambda: frozenset({0}))
    # tool_tier=2 only, optional: a tool that can come back "ok" (real exit code, no error) while
    # still silently degraded in a way the tool's own output already names a fix for — nmap's host
    # discovery ping getting blocked by a firewall/CDN (extremely common: ICMP is routinely
    # dropped) is the case this exists for. nmap doesn't fail when that happens (exit_code 0), it
    # just skips ALL port scanning and prints "Host seems down... try -Pn" — there is nothing for
    # the normal 1-Step Retry (agent/core.py's _run_tool_with_retry) to correct, since that only
    # fires on a genuine error/timeout status. Given (the just-executed command, the result dict),
    # returns a corrected command to run ONE more time (never looped further), or None if this
    # result doesn't need it. runner.py's _run_subprocess is what actually re-dispatches.
    retry_command_on_result: Callable[[list[str], dict], list[str] | None] | None = None
    # tool_tier=2 only, optional: a tool whose command carries an optional flag that can turn a
    # genuine subprocess timeout into a second guaranteed-identical one — the normal 1-Step Retry
    # (agent/core.py's _run_tool_with_retry) cannot help here, since runner.py's own timeout path
    # returns no stdout/stderr/exit_code for the correction call to react to (see that function's
    # own comment), so the model's "corrected" arguments routinely come back byte-identical to the
    # ones that just timed out. Given the just-timed-out command, returns a corrected command to run
    # ONE more time (never looped further, and only on the FIRST dispatch's own timeout — a second
    # timeout after this correction is reported as-is), or None if nothing about this command can be
    # deterministically softened.
    retry_command_on_timeout: Callable[[list[str]], list[str] | None] | None = None
    # True only for a tool whose whole point requires more than one real call for the SAME finding
    # (authenticated_request/idor_probe: a real IDOR comparison needs at least two identities
    # queried) — core.py's _run_exploit_for_finding one-shot-per-finding cap checks this instead of
    # a hardcoded tool-name tuple, so a new multi-call tool is data on the tool itself, not a
    # growing list to remember to update elsewhere. False (one real attempt, like sqlmap/msf) for
    # everything else, including a from-scratch custom exploit script.
    allows_repeated_attempts: bool = False
    # Optional override for tool_is_installed() (agent/tools/runner.py): a tool_tier=1 (native
    # Python) tool is normally ALWAYS reported installed -- true for ordinary native tools, but not
    # for one whose real dependency is an external download the Python code doesn't itself carry
    # (the browser_* tools' Playwright-managed Chromium binary). None (the default, every existing
    # tier-1 tool) keeps the old always-True behavior unchanged; set this to a cheap, cached
    # zero-argument predicate to make availability reflect reality instead.
    availability_check: Callable[[], bool] | None = None
    # tool_tier=2 only, optional: a memoization key for a tool whose output is a pure, deterministic
    # function of its inputs, so re-running the identical command on an unchanged input file is
    # provably wasted work. Given (the just-built command, params), returns a cache key string, or
    # None to skip caching THIS call (e.g. a write/mutating invocation whose result must never be
    # served from cache). runner.py's _run_subprocess consults agent/tools/cache.py with this key
    # before dispatching and stores the result after. The case this exists for: radare2 re-runs a
    # full `aaa` analysis (~2m30s on a large obfuscated binary) on every single call, and a real RE
    # pass issued the exact same `aaa; aflj`/`aaa; pdgj @ entry0` several times over -- each a
    # 2-3 minute re-analysis producing byte-identical output. The key MUST capture everything that
    # changes the output (the full command AND the input file's mtime), so a modified target busts
    # it automatically.
    result_cache_key: Callable[[list[str], dict], str | None] | None = None

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


def categories_of(spec: ToolSpec) -> tuple[Category, ...]:
    """Normalizes a ToolSpec's category field (a single value, the common case, or a tuple for a
    tool registered in more than one phase) into a tuple — the one place that distinction is
    handled, so every consumer checks membership the same way instead of each guessing whether
    .category is scalar or already a tuple."""
    return spec.category if isinstance(spec.category, tuple) else (spec.category,)


def get_tools_by_category(category: Category) -> list[ToolSpec]:
    return [spec for spec in TOOL_REGISTRY if category in categories_of(spec)]
