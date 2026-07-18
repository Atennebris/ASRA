"""Composition root: registers the built-in tool catalog into TOOL_REGISTRY on import."""
from agent.tools.builders.exploit import build_exploit_command, build_msf_module_search_command
from agent.tools.builders.nmap import build_nmap_command
from agent.tools.builders.nuclei import build_nuclei_command
from agent.tools.builders.sqlmap import build_sqlmap_command
from agent.tools.discovery import discover_known_tools, load_custom_tools
from agent.tools.native import (
    common_exposure_scan,
    crt_sh_lookup,
    cve_lookup,
    default_creds_check,
    dns_lookup,
    exploit_db_lookup,
    favicon_hash,
    http_request,
    jwt_decode,
    security_headers_audit,
    ssl_cert_info,
    tcp_port_check,
    view_source,
    wayback_urls,
    whois_lookup,
)
from agent.tools.registry import TOOL_REGISTRY, ToolSpec, register_tool
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

register_tool(
    ToolSpec(
        name="nmap",
        category="recon",
        tool_tier=2,
        executable="nmap",
        build_command=build_nmap_command,
        requires_allowed_target=False,
        installed_by_default=True,
    )
)

register_tool(
    ToolSpec(
        name="nuclei",
        category="scan",
        tool_tier=2,
        executable="nuclei",
        build_command=build_nuclei_command,
        requires_allowed_target=False,
        installed_by_default=True,
    )
)

register_tool(
    ToolSpec(
        name="exploit",
        category="exploit",
        tool_tier=2,
        executable="msfconsole",
        build_command=build_exploit_command,
        requires_allowed_target=True,
        installed_by_default=True,
    )
)

register_tool(
    ToolSpec(
        name="msf_module_search",
        category="exploit",
        tool_tier=2,
        executable="msfconsole",
        build_command=build_msf_module_search_command,
        requires_allowed_target=False,  # read-only module lookup, no action against a target
        installed_by_default=True,
    )
)

register_tool(
    ToolSpec(
        name="sqlmap",
        category="exploit",
        tool_tier=2,
        executable="sqlmap",
        build_command=build_sqlmap_command,
        requires_allowed_target=True,
        installed_by_default=True,
    )
)

# Tier-1 native tools: plain Python functions, no subprocess/binary needed.
_NATIVE_RECON_TOOLS = {
    "crt_sh_lookup": crt_sh_lookup,
    "wayback_urls": wayback_urls,
    "whois_lookup": whois_lookup,
    "dns_lookup": dns_lookup,
}
_NATIVE_SCAN_TOOLS = {
    "http_request": http_request,
    "tcp_port_check": tcp_port_check,
    "ssl_cert_info": ssl_cert_info,
    "common_exposure_scan": common_exposure_scan,
    "favicon_hash": favicon_hash,
    "security_headers_audit": security_headers_audit,
    "jwt_decode": jwt_decode,
    "exploit_db_lookup": exploit_db_lookup,
    "cve_lookup": cve_lookup,
    "view_source": view_source,
}

for _name, _fn in _NATIVE_RECON_TOOLS.items():
    register_tool(
        ToolSpec(
            name=_name,
            category="recon",
            tool_tier=1,
            executable="",
            build_command=None,
            native_function=_fn,
            requires_allowed_target=False,
            installed_by_default=True,
        )
    )

for _name, _fn in _NATIVE_SCAN_TOOLS.items():
    register_tool(
        ToolSpec(
            name=_name,
            category="scan",
            tool_tier=1,
            executable="",
            build_command=None,
            native_function=_fn,
            requires_allowed_target=False,
            installed_by_default=True,
        )
    )

# Not tier-1 by risk despite being native code: same guardrail as Metasploit.
register_tool(
    ToolSpec(
        name="default_creds_check",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=default_creds_check,
        requires_allowed_target=True,
        installed_by_default=True,
    )
)

_existing_names = {spec.name for spec in TOOL_REGISTRY}
for spec in discover_known_tools() + load_custom_tools():
    if spec.name in _existing_names:
        logger.debug("skip registering %s: name already taken by a core tool", spec.name)
        continue
    register_tool(spec)
    _existing_names.add(spec.name)
