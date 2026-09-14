"""Registry + persistence for tool-level API keys -- flags like WPScan's --api-token that improve
a scan's own results (a fresher/larger vulnerability database, higher rate limits, ...) when the
operator has one, but the tool still works fine without it. Same on-disk convention as LLM
provider keys (agent/llm_client.py's save_provider_api_key/clear_provider_api_key): written
straight to .env as a real env var, never a separate JSON store, so DEBUG=true/.env.example
tooling and the operator's own shell both see the exact same value with no second source of truth.

Adding a new tool here is the entire integration on the settings side: register its spec below,
then have that tool's own build_command() read params.get("_api_key") and append its own flag when
present -- see agent/tools/builders/wpscan.py. agent/core.py's _run_tool_with_retry injects
"_api_key" into any tool call whose spec.name has an entry here, exactly the way it already
injects "_user_agent"/"_extra_headers" for every HTTP-capable tool.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import dotenv_values, find_dotenv, set_key, unset_key

from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_ENV_PATH = find_dotenv(usecwd=True) or str(Path(__file__).resolve().parent.parent.parent / ".env")


@dataclass(frozen=True)
class ToolApiKeySpec:
    tool_name: str  # native ToolSpec.name (agent/tools/registry.py), e.g. "wpscan"
    env_var: str  # .env variable name this key is read from/written to
    label: str  # Settings UI display name
    help_text: str  # short "what this unlocks" shown under the field in Settings
    help_url: str | None = None  # where to actually generate a key, if any


TOOL_API_KEY_SPECS: dict[str, ToolApiKeySpec] = {
    "wpscan": ToolApiKeySpec(
        tool_name="wpscan",
        env_var="WPSCAN_API_KEY",
        label="WPScan",
        help_text=(
            "WPScan Vulnerability Database API token -- passed as --api-token. WPScan still runs "
            "and enumerates the WordPress core/plugin/theme versions without it, but won't cross-"
            "reference them against known CVEs."
        ),
        help_url="https://wpscan.com/profile",
    ),
    # otx_passive_dns/urlscan_search (agent/tools/native.py) are plain native (non-subprocess) HTTP
    # tools, not a build_command()-based one like wpscan above -- the injected "_api_key" reaches
    # them the exact same way regardless (agent/core.py's _run_tool_with_retry injects it into
    # `arguments` before dispatch, for ANY tool with a spec here, native or subprocess alike), they
    # just read params.get("_api_key") directly instead of appending a CLI flag.
    "otx_passive_dns": ToolApiKeySpec(
        tool_name="otx_passive_dns",
        env_var="OTX_API_KEY",
        label="AlienVault OTX",
        help_text=(
            "AlienVault OTX (Open Threat Exchange) API key -- passive DNS history for a domain "
            "(historical hostname/IP associations, useful for finding old/related infrastructure) "
            "plus threat-intel context. OTX has no meaningful anonymous access, so this tool is "
            "disabled entirely without a key -- free to create, no payment required."
        ),
        help_url="https://otx.alienvault.com/api",
    ),
    "urlscan_search": ToolApiKeySpec(
        tool_name="urlscan_search",
        env_var="URLSCAN_API_KEY",
        label="urlscan.io",
        help_text=(
            "urlscan.io API key -- searches its own history of previously-scanned pages for a "
            "domain (real URLs/IPs/ASNs actually seen live, sometimes surfacing a forgotten page). "
            "Works without a key too, on urlscan's own shared/lower public rate limit; a free key "
            "raises that limit and includes results from scans made under your own account."
        ),
        help_url="https://urlscan.io/user/profile/",
    ),
    "github_code_search": ToolApiKeySpec(
        tool_name="github_code_search",
        env_var="GITHUB_API_KEY",
        label="GitHub Code Search",
        help_text=(
            "A GitHub personal access token (classic) with ZERO scopes checked -- it only proves "
            "\"a real account\", searching public code needs no actual permissions. GitHub rejects "
            "an anonymous /search/code call outright, so this tool is disabled entirely without a "
            "token. Finds a target's own leaked keys/hostnames sitting in a public repo -- neither "
            "a web search nor GitHub's own logged-out UI can search code content reliably."
        ),
        help_url="https://github.com/settings/tokens/new",
    ),
    "hibp_breach_check": ToolApiKeySpec(
        tool_name="hibp_breach_check",
        env_var="HIBP_API_KEY",
        label="Have I Been Pwned",
        help_text=(
            "Have I Been Pwned API key -- checks whether an email address appears in a known data "
            "breach, the industry-reference breach-notification service. HIBP has no anonymous "
            "email-search access at all (a paid subscription), so this tool is disabled entirely "
            "without a key. The fully free xposedornot_check covers the same kind of check with no "
            "key needed at all; this is a second, independently-sourced, more widely-recognized "
            "confirmation worth adding once a key is available."
        ),
        help_url="https://haveibeenpwned.com/API/Key",
    ),
}


def get_tool_api_key(tool_name: str) -> str | None:
    """None when this tool has no registered API-key spec, or has one but no key is currently
    saved -- either way, the caller (agent/core.py) simply doesn't inject "_api_key" for this call,
    same as a tool with no such spec at all."""
    spec = TOOL_API_KEY_SPECS.get(tool_name)
    if spec is None:
        return None
    return os.getenv(spec.env_var) or None


def save_tool_api_key(tool_name: str, api_key: str) -> None:
    spec = TOOL_API_KEY_SPECS[tool_name]
    set_key(_ENV_PATH, spec.env_var, api_key)
    os.environ[spec.env_var] = api_key
    if dotenv_values(_ENV_PATH).get(spec.env_var) != api_key:
        raise RuntimeError(f"Wrote {spec.env_var} to .env but the read-back didn't match -- refusing to report success.")
    logger.debug("save_tool_api_key: tool=%s written to %s", tool_name, _ENV_PATH)


def clear_tool_api_key(tool_name: str) -> None:
    spec = TOOL_API_KEY_SPECS[tool_name]
    if os.path.exists(_ENV_PATH):
        unset_key(_ENV_PATH, spec.env_var)
    os.environ.pop(spec.env_var, None)
    logger.debug("clear_tool_api_key: tool=%s removed from %s", tool_name, _ENV_PATH)


def redact_secrets_in_command(command: list[str]) -> list[str]:
    """Returns a copy of `command` with any currently-configured tool API key value replaced by a
    fixed placeholder -- never the real command actually dispatched (agent/tools/runner.py keeps
    that in its own separate, unredacted local variable; only the copy that ends up in
    result["command"] needs this), which fans out to three real destinations: session.json's own
    persisted logs (shown in the UI transcript), debug.log's own command=%s lines, and the tool
    result JSON sent straight to the LLM provider (agent/core.py's json.dumps(result) at the
    "role": "tool" message).

    Real risk this closes: WPScan's --api-token takes its value as a literal argv element (WPScan
    has no alternative, same as an operator running it by hand from a terminal) -- without this, a
    fresh copy of that same real secret would otherwise be written to all three destinations above
    on every single wpscan call the operator has a key configured for, including straight out to a
    third-party LLM API.
    """
    secret_values = {value for value in (get_tool_api_key(name) for name in TOOL_API_KEY_SPECS) if value}
    if not secret_values:
        return command
    return ["***REDACTED***" if token in secret_values else token for token in command]
