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
    record_finding,
    record_target,
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
        description="Fast TCP port scan with service/version detection (-F -sV) against a host.",
        parameters_schema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Hostname or IP to scan"}},
            "required": ["target"],
        },
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
        description=(
            "Runs Nuclei vulnerability templates against a URL/host — active checks, not just "
            "passive banner matching (default tags: cve,vuln,exposure,rce,misconfig)."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or host to scan"},
                "tags": {
                    "type": "string",
                    "description": "Comma-separated Nuclei tags to run; omit to use the default active-check set",
                },
            },
            "required": ["target"],
        },
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
        description=(
            "Runs a real Metasploit module against a target: opens a session, optionally runs one "
            "confirmation command in it to capture proof, then closes it. Requires the target to be "
            "in the exploitation allowlist and the session to be human-approved."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "RHOSTS value — the target host/IP"},
                "module": {
                    "type": "string",
                    "description": (
                        "Metasploit module path, e.g. exploit/unix/ftp/vsftpd_234_backdoor — must be "
                        "one actually returned by msf_module_search, never guessed from memory"
                    ),
                },
                "options": {
                    "type": "object",
                    "description": "Extra module options as key/value pairs (e.g. RPORT, PAYLOAD)",
                    "additionalProperties": {"type": "string"},
                },
                "confirm_command": {
                    "type": "string",
                    "description": "One harmless command to run in the opened session to capture proof (e.g. id, whoami)",
                },
            },
            "required": ["target", "module"],
        },
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
        description="Searches Metasploit's real module database by CVE ID, service, or keyword — use before picking a module for the exploit tool.",
        parameters_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "description": "CVE ID, service name, or keyword to search for"}},
            "required": ["query"],
        },
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
        description=(
            "Tests a URL/parameter for SQL injection and lists databases if confirmed (or dumps a "
            "specific table if dump_table/database are given). Requires the target to be in the "
            "exploitation allowlist and the session to be human-approved."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Full target URL, including path and query string if relevant"},
                "data": {
                    "type": "string",
                    "description": "POST body to send (e.g. a JSON login payload) if the injection point is in the request body",
                },
                "headers": {"type": "string", "description": "Extra HTTP headers, one per line"},
                "test_parameter": {"type": "string", "description": "Name of the specific parameter to test (-p)"},
                "level": {"type": "integer", "description": "sqlmap test level 1-5"},
                "risk": {"type": "integer", "description": "sqlmap risk level 1-3"},
                "dump_table": {"type": "string", "description": "Table name to dump (second-pass call only, after injection is confirmed)"},
                "database": {"type": "string", "description": "Database name, required together with dump_table"},
            },
            "required": ["target"],
        },
    )
)

# Live-recording tools: the LLM calls these the instant it identifies something, not batched
# into a final answer — agent/core.py's execute_tool closures (_run_recon/_run_analyze) persist
# the result into the session file immediately, so a target/finding survives a crash the moment
# it's reported, not just once the whole sub-phase finishes.
register_tool(
    ToolSpec(
        name="record_target",
        category="recon",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_target,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Records one discovered target (host/port/service/version) the moment you confirm "
            "it — call this as soon as you find something, do not wait until recon is done to "
            "report everything at once."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP"},
                "port": {"type": "integer", "description": "Port number, if applicable"},
                "service": {"type": "string", "description": "Service name, e.g. http, ssh"},
                "version": {"type": "string", "description": "Service/software version string, if known"},
            },
            "required": ["host"],
        },
    )
)

register_tool(
    ToolSpec(
        name="record_finding",
        category="scan",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_finding,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Records one vulnerability finding the moment you're confident enough to report it "
            "— call this as soon as you find something, do not wait until you're done analyzing "
            "to report everything at once."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short descriptive title of the vulnerability"},
                "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low"]},
                "description": {"type": "string", "description": "What the issue is and why it matters"},
                "verification": {
                    "type": "string",
                    "enum": ["verified", "inferred", "needs_verification"],
                    "description": (
                        "verified: an active check confirmed it. inferred: guessed from a "
                        "banner/version. needs_verification: not yet confirmed either way."
                    ),
                },
                "evidence_ref": {"type": "string", "description": "Supporting tool output detail, or omit if none"},
            },
            "required": ["title", "severity", "description"],
        },
    )
)

# Tier-1 native tools: plain Python functions, no subprocess/binary needed. Each entry is
# (function, description, parameters_schema) — every one of these is hand-written Python, so
# unlike autodiscovered/custom tools there's no --help to fall back on; a schema is mandatory.
_DOMAIN_SCHEMA = {
    "type": "object",
    "properties": {"domain": {"type": "string", "description": "Domain name, e.g. example.com"}},
    "required": ["domain"],
}
_URL_TARGET_SCHEMA = {
    "type": "object",
    "properties": {"target": {"type": "string", "description": "Full URL to request"}},
    "required": ["target"],
}

_NATIVE_RECON_TOOLS = {
    "crt_sh_lookup": (
        crt_sh_lookup,
        "Finds subdomains via Certificate Transparency logs (crt.sh, falls back to certspotter.com) for a domain.",
        _DOMAIN_SCHEMA,
    ),
    "wayback_urls": (
        wayback_urls,
        "Finds historical URLs for a domain via the Wayback Machine CDX API — can reveal forgotten endpoints.",
        _DOMAIN_SCHEMA,
    ),
    "whois_lookup": (whois_lookup, "Raw WHOIS lookup for a domain.", _DOMAIN_SCHEMA),
    "dns_lookup": (dns_lookup, "Resolves a domain to its IP addresses.", _DOMAIN_SCHEMA),
}
_NATIVE_SCAN_TOOLS = {
    "http_request": (
        http_request,
        "Makes a GET request to a URL and returns status code, security headers, and a body preview.",
        _URL_TARGET_SCHEMA,
    ),
    "tcp_port_check": (
        tcp_port_check,
        "Checks whether a specific TCP port on a host is open.",
        {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host to check"},
                "port": {"type": "integer", "description": "TCP port number"},
                "timeout": {"type": "number", "description": "Connect timeout in seconds, default 5"},
            },
            "required": ["target", "port"],
        },
    ),
    "ssl_cert_info": (
        ssl_cert_info,
        "Fetches and parses the TLS certificate presented by a host.",
        {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Host to connect to"},
                "port": {"type": "integer", "description": "TLS port, default 443"},
            },
            "required": ["target"],
        },
    ),
    "common_exposure_scan": (
        common_exposure_scan,
        "Checks a base URL for commonly exposed sensitive paths (.git/config, .env, backups, etc.).",
        _URL_TARGET_SCHEMA,
    ),
    "favicon_hash": (
        favicon_hash,
        "Fetches a site's favicon and computes its mmh3 hash (Shodan-style fingerprint) to help identify the CMS/framework.",
        _URL_TARGET_SCHEMA,
    ),
    "security_headers_audit": (
        security_headers_audit,
        "Checks which standard security headers (CSP, HSTS, X-Frame-Options, etc.) a URL sends.",
        _URL_TARGET_SCHEMA,
    ),
    "jwt_decode": (
        jwt_decode,
        "Decodes a JWT's header and payload (no signature verification) to inspect its claims/algorithm.",
        {
            "type": "object",
            "properties": {"token": {"type": "string", "description": "The JWT string to decode"}},
            "required": ["token"],
        },
    ),
    "exploit_db_lookup": (
        exploit_db_lookup,
        "Searches a local Exploit-DB metadata index by product/CVE/keyword — returns EDB-ID, title, CVE, PoC path. Never executes any PoC code.",
        {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Product name, CVE ID, or keyword to search for"}},
            "required": ["query"],
        },
    ),
    "cve_lookup": (
        cve_lookup,
        "Looks up known CVE IDs for a product/vendor via a public CVE database.",
        {
            "type": "object",
            "properties": {
                "product": {"type": "string", "description": "Product name, e.g. vsftpd"},
                "vendor": {"type": "string", "description": "Vendor name; defaults to the product name if omitted"},
            },
            "required": ["product"],
        },
    ),
    "view_source": (
        view_source,
        "Fetches a page's raw HTML and extracts comments, hidden inputs, script/link paths, and meta tags — good for finding forgotten endpoints/notes.",
        _URL_TARGET_SCHEMA,
    ),
}

for _name, (_fn, _description, _schema) in _NATIVE_RECON_TOOLS.items():
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
            description=_description,
            parameters_schema=_schema,
        )
    )

for _name, (_fn, _description, _schema) in _NATIVE_SCAN_TOOLS.items():
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
            description=_description,
            parameters_schema=_schema,
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
        description=(
            "Tries a short list of default username/password pairs against a login endpoint (POST JSON). "
            "Requires the target to be in the exploitation allowlist and the session to be human-approved."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Login endpoint URL"},
                "username_field": {"type": "string", "description": "JSON field name for the username, default 'email'"},
                "password_field": {"type": "string", "description": "JSON field name for the password, default 'password'"},
            },
            "required": ["target"],
        },
    )
)

_existing_names = {spec.name for spec in TOOL_REGISTRY}
for spec in discover_known_tools() + load_custom_tools():
    if spec.name in _existing_names:
        logger.debug("skip registering %s: name already taken by a core tool", spec.name)
        continue
    register_tool(spec)
    _existing_names.add(spec.name)
