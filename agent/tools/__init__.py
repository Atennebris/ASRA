"""Composition root: registers the built-in tool catalog into TOOL_REGISTRY on import."""
import sys

from agent.tools.amass_runner import amass_available, amass_enum
from agent.tools.builders.apktool import build_apktool_command
from agent.tools.builders.binwalk import build_binwalk_command
from agent.tools.builders.qiling import build_qiling_command, qiling_available
from agent.tools.builders.dalfox import build_dalfox_command
from agent.tools.builders.exploit import build_exploit_command, build_msf_module_search_command
from agent.tools.builders.ffuf import build_ffuf_command
from agent.tools.builders.frida import build_frida_ps_command, build_frida_trace_command
from agent.tools.builders.gdb import build_gdb_command
from agent.tools.builders.heimdall import build_heimdall_command
from agent.tools.builders.ilspycmd import build_ilspycmd_command
from agent.tools.builders.jadx import build_jadx_command
from agent.tools.builders.mythril import build_mythril_command
from agent.tools.builders.nikto import build_nikto_command
from agent.tools.builders.nmap import (
    build_nmap_command,
    retry_nmap_with_pn_if_host_seemed_down,
    retry_nmap_without_os_detection_on_timeout,
)
from agent.tools.builders.nuclei import build_nuclei_command
from agent.tools.builders.osv_scanner import build_osv_scanner_command
from agent.tools.builders.radare2 import build_radare2_command, radare2_result_cache_key
from agent.tools.builders.radiff2 import build_radiff2_command
from agent.tools.builders.semgrep import build_semgrep_command
from agent.tools.builders.slither import build_slither_command
from agent.tools.builders.sqlmap import build_sqlmap_command
from agent.tools.builders.strace import run_strace, strace_available
from agent.tools.builders.subfinder import build_subfinder_command
from agent.tools.builders.tshark import build_tshark_capture_command, build_tshark_read_pcap_command
from agent.tools.builders.trufflehog import build_trufflehog_command
from agent.tools.builders.upx import build_upx_command
from agent.tools.builders.whatweb import build_whatweb_command
from agent.tools.builders.wpscan import build_wpscan_command
from agent.tools.discovery import discover_known_tools, load_custom_tools
from agent.tools.dork_engine import SEARCH_ENGINES as _DORK_SEARCH_ENGINES
from agent.tools.dork_engine import dork_search_native, list_dork_categories
from agent.tools.memscan_manager import (
    SCAN_MODES,
    VALUE_TYPES,
    memscan_attach,
    memscan_detach,
    memscan_list,
    memscan_scan,
    memscan_write,
)
from agent.tools.native import (
    afl_fuzz_start,
    api_schema_discovery,
    arjun_probe,
    authenticated_crawl,
    authenticated_request,
    authz_diff_sweep,
    background_job_check,
    check_subagent_task,
    cloud_bucket_scan,
    common_crawl_urls,
    common_exposure_scan,
    cors_check,
    cors_credentialed_check,
    crt_sh_lookup,
    custom_exploit_run,
    cve_lookup,
    default_creds_check,
    disassemble_evm_bytecode,
    dns_lookup,
    exploit_db_fetch,
    exploit_db_lookup,
    exploit_db_run,
    favicon_hash,
    forge_poc_run,
    geoip_lookup,
    github_code_search,
    hibp_breach_check,
    hibp_password_check,
    http_request,
    hydra_start,
    graphql_authz_probe,
    graphql_batching_probe,
    idor_probe,
    ipa_extract,
    js_bundle_scan,
    jwt_decode,
    oob_generate,
    oob_poll,
    otx_passive_dns,
    record_chain_result,
    record_exploit_decision,
    record_finding,
    record_host_relationship,
    record_hypothesis,
    record_reverification_result,
    record_skeptical_verification_result,
    record_target,
    report_subagent_result,
    resolve_hypothesis,
    security_headers_audit,
    shodan_internetdb_lookup,
    ssl_cert_info,
    subdomain_enum,
    tcp_port_check,
    temp_email_check_inbox,
    temp_email_create,
    update_plan,
    urlscan_search,
    view_source,
    wayback_urls,
    web_fetch,
    web_login_bruteforce_start,
    web_self_register,
    whois_lookup,
    xposedornot_check,
)
from agent.tools.browser import (
    _browser_click_native,
    _browser_close_session_native,
    _browser_evaluate_native,
    _browser_fill_native,
    _browser_go_back_native,
    _browser_navigate_native,
    _browser_press_key_native,
    _browser_select_option_native,
    _browser_snapshot_native,
)
from agent.tools.browser_manager import _chromium_installed
from agent.tools.registry import TOOL_REGISTRY, ToolSpec, register_tool
from agent.tools.toolkit_agent_tools import (
    DECODE_VALUE_SCHEMA,
    DIFF_REQUESTS_SCHEMA,
    INTRUDER_RUN_SCHEMA,
    LIST_CAPTURED_TRAFFIC_SCHEMA,
    RACER_RUN_SCHEMA,
    SEND_RAW_REQUEST_SCHEMA,
    SEQUENCER_ANALYZE_SCHEMA,
    _decode_value_native,
    _diff_requests_native,
    _intruder_run_native,
    _list_captured_traffic_native,
    _racer_run_native,
    _send_raw_request_native,
    _sequencer_analyze_native,
)
from agent.tools.asset_baseline_store import asset_diff_check
from agent.tools.surface_ranking import rank_attack_surface
from agent.tools.smuggling import smuggling_probe
from agent.tools.waf_evasion import waf_evasion_probe
from agent.tools.wp_batch_rce import (
    wp_batch_rce,
    wp_batch_root_prereq,
    wp_batch_scan,
    wp_batch_shell,
    wp_batch_sqli_check,
    wp_batch_sqli_read,
)
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Real, confirmed incident this fixes: whatweb/nikto/wpscan all left parameters_schema=None so the
# model still sees each tool's own live --help text for its real flags (aggression level, -Tuning,
# --enumerate, ...) instead of a fixed one-liner — but None falls all the way back to
# agent/core.py's _GENERIC_DISCOVERED_SCHEMA, whose "target" field description was written for the
# OTHER kind of None-schema tool (a genuinely generic/autodiscovered one, agent/tools/builders/
# discovered.py's make_generic_discovered_command, which really does require the model to place the
# target into extra_args itself). whatweb/nikto/wpscan graduated off that path and each place the
# target on the command line themselves (build_whatweb_command, build_nikto_command,
# build_wpscan_command) — the generic schema's "you must ALSO put it into extra_args yourself" text
# is simply false for them, and confirmed live to actively cause it: a session's wpscan calls
# duplicated the target across --url and a model-added -u (WPScan then rejects the command
# outright, "url option must be unique"), and one whatweb call carried a dangling, valueless -u.
# An explicit parameters_schema here overrides only the "parameters" JSON schema sent to the model
# (_tool_to_openai_schema) — description still falls through to the tool's live --help text exactly
# as before, since that lookup is independent (_tool_description checks spec.description, not this).
_AUTO_TARGET_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "Target host/URL — this tool's own build_command already places it on the command "
                "line itself, using whichever flag this specific tool actually needs. Do NOT also "
                "put it into extra_args; unlike a truly generic/autodiscovered tool, doing so here "
                "duplicates the target and the real command will likely be rejected outright."
            ),
        },
        "extra_args": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Extra CLI flags for this tool, based on its --help text below — for anything "
                "besides the target itself, which is already placed for you (see \"target\" above)."
            ),
        },
    },
    "required": ["target"],
}

register_tool(
    ToolSpec(
        name="nmap",
        category="recon",
        tool_tier=2,
        executable="nmap",
        build_command=build_nmap_command,
        retry_command_on_result=retry_nmap_with_pn_if_host_seemed_down,
        retry_command_on_timeout=retry_nmap_without_os_detection_on_timeout,
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
        name="subfinder",
        category="recon",
        tool_tier=2,
        executable="subfinder",
        build_command=build_subfinder_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Passive subdomain enumeration aggregating many independent OSINT sources at once "
            "(certificate transparency, DNS datasets, search engines — no active requests against "
            "the target itself). Broader than crt_sh_lookup (which only ever sees a subdomain with "
            "its own TLS certificate) and subdomain_enum (a short fixed prefix list) — use this "
            "first for a wildcard-scope target (*.example.com), then dns_lookup any result you "
            "actually want to act on to get a real, confirmed IP before scanning it."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain to enumerate, e.g. example.com"},
                "extra_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional extra subfinder CLI flags (e.g. ['-all'] to use every configured source, not just the fast defaults)",
                },
            },
            "required": ["domain"],
        },
    )
)

register_tool(
    ToolSpec(
        name="amass_enum",
        category="recon",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=amass_enum,
        availability_check=amass_available,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Active subdomain brute-force + recursion + name-alteration via OWASP Amass, WITH "
            "wildcard-DNS detection -- what subfinder (passive-only) and subdomain_enum (a plain "
            "wordlist, no wildcard filtering or recursion) don't do. Use after subfinder for a "
            "wildcard-scope target (*.example.com) when you need the subdomains that never got a "
            "TLS cert or a passive-source mention at all. Slower than subfinder (real active DNS "
            "brute-force, internally time-bounded) -- run it once per domain, not per phase."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Base domain to brute-force, e.g. example.com"},
            },
            "required": ["domain"],
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
            "passive banner matching (default tags: cve,vuln,exposure,rce,misconfig,takeover,"
            "default-login,xss,ssrf,waf-detect). If the operator has installed extra template "
            "packs (Tools tab), the official set plus any small pack (e.g. geeknik) is always "
            "included automatically; a large WordPress-specific pack (Wordfence intel, ~81k "
            "templates) only activates when tags includes wordpress/wp-core/wp-plugin/wp-theme — "
            "add one of those explicitly once you know or suspect the target runs WordPress, "
            "rather than leaving it on the default set. That pack takes real extra time to load "
            "(confirmed: several minutes) when it activates, so only ask for it when it's actually "
            "likely to be relevant."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "URL or host to scan"},
                "tags": {
                    "type": "string",
                    "description": "Comma-separated Nuclei tags to run; omit to use the default active-check set. Add wordpress/wp-core/wp-plugin/wp-theme to also pull in the WordPress template pack, if installed.",
                },
            },
            "required": ["target"],
        },
    )
)

# Real incident this exists because of: the only XSS signal available before this was nuclei's
# reflected-payload-in-response-text check, which cannot tell "the payload text is in the HTML"
# apart from "the payload actually ran as JavaScript" -- indistinguishable in a finding's own
# evidence, and a real scan correctly self-flagged its own XSS lead as a false
# positive for exactly that reason, having no better tool to reach for. Dalfox actually confirms
# execution in a real parsed DOM (its own "V" = Verified type) instead of only matching text, and
# separately reports AST-detected DOM-XSS ("A") and a genuinely different scan mode for stored XSS
# (--sxss, build_dalfox_command's "mode": "stored") -- category=("scan","exploit") since both
# Analyze's first pass and a later Exploit confirmation on the same finding need it.
# requires_allowed_target=False matches nuclei's own precedent for this exact vulnerability class:
# a real, active payload-based check, but a detection/confirmation step, not a further
# exploitation action past that — general scope enforcement (_out_of_scope_target) still applies
# unconditionally regardless of this flag.
register_tool(
    ToolSpec(
        name="dalfox",
        category=("scan", "exploit"),
        tool_tier=2,
        executable="dalfox",
        build_command=build_dalfox_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # Confirmed live: dalfox exits 1 the instant it finds something, 0 for a clean scan (and
        # even 0 for a target-unreachable/DNS-failure case, reported inside its own JSON instead)
        # — without this, the one run that actually finds an XSS would be the one run.tool marks
        # "error" and never hands to parse_dalfox_output at all.
        ok_exit_codes=frozenset({0, 1}),
        description=(
            "Scans a URL for XSS and reports whether it actually confirmed the payload executing "
            "in a real parsed DOM ('verified_dom_execution' — the strong, screenshot-of-alert()-"
            "grade proof), only saw it reflected in the response text without confirming execution "
            "('reflected_unconfirmed' — weaker, do not report this as confirmed XSS), or found a "
            "DOM-XSS source/sink pair via static JS analysis ('dom_based_ast'). For a suspected "
            "stored XSS (payload submitted somewhere, expected to fire on a DIFFERENT page later — "
            "a comment, a profile field, an admin-reviewed submission), set mode='stored' and "
            "sxss_url to that other page; this is a genuinely different scan mode, not a flag on "
            "top of the normal one."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": (
                        "URL to scan — include the injectable parameter and a placeholder value, "
                        "e.g. https://example.com/search?q=a. Do NOT embed a custom XSS payload "
                        "here yourself (e.g. .../search?q=<svg onload=...>) — dalfox generates and "
                        "tries its own payloads for the parameter(s) named in `param`, and a "
                        "hand-crafted payload in `target` will just be rejected as an unsafe/"
                        "malformed URL, wasting a scan and a retry for no new information."
                    ),
                },
                "mode": {
                    "type": "string",
                    "enum": ["reflected_dom", "stored"],
                    "description": "reflected_dom (default): normal reflected/DOM-based XSS scan of `target` itself. stored: submit at `target`, then check sxss_url for the payload firing there instead.",
                },
                "sxss_url": {
                    "type": "string",
                    "description": "Only used with mode='stored' — the page where the submitted payload is expected to later render/fire",
                },
                "param": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Specific parameter name(s) to test — strongly recommended whenever you already know "
                        "an injectable parameter (from Analyze, a previous scan, etc). Omitting this lets Dalfox "
                        "discover parameters itself by crawling the whole page, which is dramatically slower "
                        "(confirmed live: 600s+ timeout scanning without -p vs 6-10s scanning one known "
                        "parameter) and can time out entirely on a real site. Only omit this for genuine "
                        "open-ended discovery when no candidate parameter is already known."
                    ),
                },
                "cookie": {
                    "type": "string",
                    "description": "Cookie header value for an authenticated scan, e.g. 'session=abc123' — use an identity's real session, never a guessed one",
                },
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="arjun",
        category="scan",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=arjun_probe,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Discovers hidden HTTP parameters on a URL that already exists — a real GET/POST/JSON "
            "field the target's own frontend never sends but its backend still accepts, exactly "
            "the surface many IDOR/SSRF/mass-assignment bugs live on. Complements ffuf (which "
            "discovers hidden PATHS, not parameters on a known one). Known limitation: crashes "
            "outright (a genuine upstream bug, not this project's) on a target that returns HTTP "
            "400/413/418/429/503 to its very first probe request — common on WAF-protected or "
            "strict-validation endpoints; that just reports as a normal tool error, not a session "
            "crash. Also has no graceful early-stop — a run that hits this project's own tool "
            "timeout loses its entire result, not just what it hadn't reached yet."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Full URL to probe for hidden parameters"},
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "XML", "JSON"],
                    "description": "Request method/body shape to test — omit for GET",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to a custom parameter-name wordlist — omit to use Arjun's own bundled default",
                },
                "threads": {"type": "integer", "description": "Concurrent requests — omit for a moderate, non-aggressive default"},
                "stable": {"type": "boolean", "description": "Prefer stability over speed against a fragile/rate-limited target"},
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="ffuf",
        category="scan",
        tool_tier=2,
        executable="ffuf",
        build_command=build_ffuf_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Brute-forces hidden content against a URL with a real wordlist — directories, files, "
            "backup/config files, API routes, old versions — nothing else in this registry actively "
            "discovers a path that isn't already linked somewhere or on a short fixed list. Include "
            "the literal marker FUZZ in `target` where the wordlist should be substituted (e.g. "
            "https://example.com/FUZZ or https://example.com/api/FUZZ); if omitted, FUZZ is appended "
            "as a new path segment. A hit is a candidate to investigate further (with http_request/"
            "whatweb/authenticated_request), not itself proof of a real vulnerability."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "URL containing the literal marker FUZZ where the wordlist is substituted, e.g. https://example.com/FUZZ",
                },
                "wordlist": {
                    "type": "string",
                    "description": "Path to a wordlist file on this machine — omit to use the project's own default content-discovery wordlist",
                },
                "extensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "File extensions to also try appended to each word, e.g. ['.php', '.bak', '.zip', '.old']",
                },
                "match_status_codes": {
                    "type": "string",
                    "description": "Comma-separated HTTP status codes to report as hits — omit to use a sensible default (200,204,301,302,307,401,403,405,500)",
                },
                "threads": {"type": "integer", "description": "Concurrent requests — omit for a moderate, non-aggressive default"},
                "extra_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional extra ffuf CLI flags not covered above (e.g. ['-recursion'] for recursive directory discovery)",
                },
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="whatweb",
        category="scan",
        tool_tier=2,
        executable="whatweb",
        build_command=build_whatweb_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # description left "" (default) on purpose — same live-`--help`-driven path as an
        # autodiscovered tool (agent/core.py's _tool_description), because WhatWeb has real,
        # useful flags (aggression level, --plugins, --no-errors, ...) worth showing the model, not
        # a fixed one-liner. build_whatweb_command still reliably places the target and the
        # injected custom User-Agent itself rather than leaving that to the model's extra_args —
        # parameters_schema is _AUTO_TARGET_SCHEMA (not the generic one) precisely so the model is
        # told that, see its own docstring above for the real incident this fixes.
        parameters_schema=_AUTO_TARGET_SCHEMA,
    )
)

register_tool(
    ToolSpec(
        name="nikto",
        category="scan",
        tool_tier=2,
        executable="nikto",
        build_command=build_nikto_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # Same reasoning as whatweb just above: description left at its default so the model still
        # sees nikto's real --Help output for tuning flags (-Tuning, -evasion, ...), but
        # build_nikto_command now places -host itself, so getting the target right no longer
        # depends on the model reading and correctly using that text — parameters_schema is
        # _AUTO_TARGET_SCHEMA so the model is actually told that instead of the opposite.
        parameters_schema=_AUTO_TARGET_SCHEMA,
    )
)

register_tool(
    ToolSpec(
        name="wpscan",
        category="scan",
        tool_tier=2,
        executable="wpscan",
        build_command=build_wpscan_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # Same reasoning as whatweb above: live --help, so the model can see and use wpscan's real
        # enumeration flags (--enumerate p/t/u, --api-token, ...). The actual guardrail against
        # firing this blind at a non-WordPress target is deterministic, not prompt-only — see
        # agent/core.py's _wpscan_cms_not_confirmed, checked in _run_tool_with_retry before this
        # ever reaches a real subprocess call. parameters_schema is _AUTO_TARGET_SCHEMA (not the
        # generic one) — see its own docstring above for the real incident this fixes (repeated
        # duplicate --url/-u calls across a real session, WPScan rejecting every one of them).
        parameters_schema=_AUTO_TARGET_SCHEMA,
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
            "specific table if dump_table/database are given). If a WAF/protection is already known "
            "for this host (recon_result['protections'] context) or a plain attempt gets blocked "
            "(403/406, no real injection signal), retry once with tamper scripts before giving up. "
            "Requires the target to be in the exploitation allowlist and the session to be "
            "human-approved."
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
                "tamper": {
                    "type": "string",
                    "description": (
                        "Comma-separated sqlmap tamper script names to evade a WAF/filter on the payload itself "
                        "(e.g. 'space2comment,charencode,randomcase,between' — common starting points; sqlmap "
                        "ships many more). Only worth trying once a WAF/protection is actually known to be present."
                    ),
                },
                "dump_table": {"type": "string", "description": "Table name to dump (second-pass call only, after injection is confirmed)"},
                "database": {"type": "string", "description": "Database name, required together with dump_table"},
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="hydra_start",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=hydra_start,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Starts a REAL credential brute-force run against a network service (ssh/ftp/telnet/"
            "mysql/postgres/rdp/smb) or a web login form (http-post-form/http-get-form) — genuinely "
            "takes minutes, so this returns a job_id immediately instead of blocking; keep working "
            "on other things and poll hydra_check(job_id) later for the real result. For a web "
            "form, give login_path/username_field/password_field/failure_string (or success_string) "
            "as separate fields here — never hand-write Hydra's own module syntax. A real empirical "
            "preflight (a few deliberately wrong logins, checking for a genuine lockout/CAPTCHA/"
            "rate-limit signal in the actual response) runs automatically for web forms before the "
            "real attempt; if the target shows active defenses, this returns "
            "{\"status\": \"skipped\", \"reason\": ...} instead of ever starting it. Known limitation "
            "carried over from Hydra itself: it can't refresh a per-request CSRF token, so a form "
            "requiring one won't work reliably here — use web_login_bruteforce_start for that case "
            "instead. Poll the result with background_job_check(job_id). Requires the target to be "
            "in the exploitation allowlist and the session to be human-approved, same as msf/sqlmap."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Host/IP for a network protocol, or the base URL (scheme://host[:port]) for http-post-form/http-get-form",
                },
                "protocol": {
                    "type": "string",
                    "enum": ["ssh", "ftp", "telnet", "mysql", "postgres", "rdp", "smb", "http-post-form", "http-get-form"],
                    "description": "Which service/form shape to attack",
                },
                "port": {"type": "integer", "description": "Override the protocol's default port"},
                "username": {"type": "string", "description": "A single username to test — omit if using username_list"},
                "username_list": {"type": "array", "items": {"type": "string"}, "description": "Multiple usernames to try — omit to use a sensible default list"},
                "password": {"type": "string", "description": "A single password to test — omit if using password_list"},
                "password_list": {"type": "array", "items": {"type": "string"}, "description": "Multiple passwords to try — omit to use a sensible default list"},
                "threads": {"type": "integer", "description": "Concurrent connection attempts — omit for a moderate, non-aggressive default"},
                "login_path": {"type": "string", "description": "Required for http-post-form/http-get-form — the page the login form posts to, e.g. /login"},
                "username_field": {"type": "string", "description": "Form field name for the username — omit to use 'username'"},
                "password_field": {"type": "string", "description": "Form field name for the password — omit to use 'password'"},
                "extra_fields": {
                    "type": "object",
                    "additionalProperties": {"type": "string"},
                    "description": "Any additional static form fields the login POST needs, as key/value pairs",
                },
                "failure_string": {"type": "string", "description": "A literal substring that appears in the response ONLY on a failed login — required unless success_string is given"},
                "success_string": {"type": "string", "description": "A literal substring that appears in the response ONLY on a successful login — required unless failure_string is given"},
            },
            "required": ["target", "protocol"],
        },
    )
)

register_tool(
    ToolSpec(
        name="web_login_bruteforce_start",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=web_login_bruteforce_start,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Real, CSRF-aware credential brute-force against a web login form — starts in the "
            "background (same as hydra_start), poll with background_job_check(job_id). Use this "
            "instead of hydra_start's http-post-form/http-get-form specifically when the form "
            "requires a per-request CSRF token (hydra's static request body gets rejected by any "
            "such form, every single attempt) — this maintains a real cookie jar and re-fetches the "
            "login page before every attempt to pick up a fresh token (common field names handled "
            "automatically: csrf_token, csrfmiddlewaretoken, _token, authenticity_token, _csrf, "
            "__RequestVerificationToken, or a custom name via csrf_field). Same structured-fields "
            "contract as hydra_start's web-form mode, and the same automatic real preflight check "
            "for active lockout/CAPTCHA/rate-limit defenses before ever starting. Slower than "
            "hydra_start (sequential, not multi-threaded) — only worth it specifically for the CSRF "
            "case; use hydra_start for a form with no CSRF protection. Requires the target to be in "
            "the exploitation allowlist and the session to be human-approved, same as msf/sqlmap."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL (scheme://host[:port]) the login form lives on"},
                "login_path": {"type": "string", "description": "The page the login form posts to, e.g. /login"},
                "username": {"type": "string", "description": "A single username to test — omit if using username_list"},
                "username_list": {"type": "array", "items": {"type": "string"}, "description": "Multiple usernames to try — omit to use a sensible default list"},
                "password": {"type": "string", "description": "A single password to test — omit if using password_list"},
                "password_list": {"type": "array", "items": {"type": "string"}, "description": "Multiple passwords to try — omit to use a sensible default list"},
                "username_field": {"type": "string", "description": "Form field name for the username — omit to use 'username'"},
                "password_field": {"type": "string", "description": "Form field name for the password — omit to use 'password'"},
                "csrf_field": {"type": "string", "description": "Form field name for the CSRF token, if it doesn't match a common convention this tool already recognizes"},
                "failure_string": {"type": "string", "description": "A literal substring that appears in the response ONLY on a failed login — required unless success_string is given"},
                "success_string": {"type": "string", "description": "A literal substring that appears in the response ONLY on a successful login — required unless failure_string is given"},
            },
            "required": ["target", "login_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="background_job_check",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=background_job_check,
        requires_allowed_target=False,  # read-only status poll of an already-started job, no new action against a target
        installed_by_default=True,
        description=(
            "Polls a background job started by hydra_start or web_login_bruteforce_start, by its "
            "job_id. {\"status\": \"running\"} means it's genuinely still going — check other "
            "findings, call other tools, and come back to this later; it's fine to poll more than "
            "once. Any other status (ok/error/timeout/killed/interrupted) means it's actually done, "
            "with credentials (if any were found) in result."
        ),
        parameters_schema={
            "type": "object",
            "properties": {"job_id": {"type": "string", "description": "The job_id returned by hydra_start or web_login_bruteforce_start"}},
            "required": ["job_id"],
        },
    )
)

register_tool(
    ToolSpec(
        name="exploit_db_lookup",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=exploit_db_lookup,
        requires_allowed_target=False,  # read-only metadata search, no action against a target
        installed_by_default=True,
        description=(
            "Searches a local Exploit-DB metadata index by product/CVE/keyword — returns EDB-ID, "
            "title, CVE, PoC path for each match. Multi-word queries match as AND (every word must "
            "appear somewhere in the entry, in any order) — not one exact phrase, so 'wordpress sql "
            "injection plugin' finds real entries even if none of them contain that literal phrase. "
            "Never executes any PoC code. Call this BEFORE exploit_db_fetch/exploit_db_run — real "
            "incident this fixes: without a way to search, the model had to guess exploit_db_fetch's "
            "edb_id outright (e.g. '12345', '524356'), almost always landing on a completely "
            "unrelated PoC and wasting the one real attempt."
        ),
        parameters_schema={
            "type": "object",
            "properties": {"query": {"type": "string", "description": "Product name, CVE ID, or keyword(s) to search for — space-separated words all must match, any order"}},
            "required": ["query"],
        },
    )
)

register_tool(
    ToolSpec(
        name="exploit_db_fetch",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=exploit_db_fetch,
        requires_allowed_target=False,  # read-only source fetch, no action against a target
        installed_by_default=True,
        description=(
            "Fetches the real PoC source code for one Exploit-DB entry (by EDB-ID, from "
            "exploit_db_lookup's results) without running it. Every PoC has its own argument "
            "convention — read it here before calling exploit_db_run, to see what it actually "
            "needs and whether it's even a runnable script (some entries are just a write-up)."
        ),
        parameters_schema={
            "type": "object",
            "properties": {"edb_id": {"type": "string", "description": "The edb_id from an exploit_db_lookup match"}},
            "required": ["edb_id"],
        },
    )
)

register_tool(
    ToolSpec(
        name="exploit_db_run",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=exploit_db_run,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Actually runs a real Exploit-DB PoC (by EDB-ID) against the target — real, unreviewed "
            "third-party code from a public database, not written or vetted by this project, run with "
            "whatever interpreter its file extension implies (.py/.sh/.pl/.rb only — anything else is "
            "refused). Requires the target to be in the exploitation allowlist and the session to be "
            "human-approved, same as the exploit/sqlmap tools. Call exploit_db_fetch first: every PoC "
            "has its own argument order, there is no standard, guessing wastes the one real attempt."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "edb_id": {"type": "string", "description": "The edb_id from an exploit_db_lookup match"},
                "target": {"type": "string", "description": "The target host/URL — checked against the exploitation allowlist"},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Full CLI argument list for the script, in the exact order/form it expects (learned from exploit_db_fetch) — must include the target in whatever form the script itself wants it",
                },
            },
            "required": ["edb_id", "target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="custom_exploit_run",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=custom_exploit_run,
        requires_allowed_target=True,
        installed_by_default=True,
        # Unlike exploit_db_run (a fixed, pre-existing PoC — one real attempt, same as sqlmap/msf),
        # this script is written fresh by the model itself: real exploitation is inherently
        # iterative (try -> observe the target's actual response -> adjust -> retry), and a
        # one-shot cap here would waste the entire point of being able to write custom code by
        # forcing the first attempt to be perfect. Still bounded by the same stall-detection
        # (identical repeated calls) and phase wall-clock limit every exploit-phase loop already
        # enforces — this only lifts the one-attempt-per-finding cap, not every other guardrail.
        allows_repeated_attempts=True,
        description=(
            "Writes and runs a real Python script against the target — the last resort for a "
            "vulnerability class none of the purpose-built tools (msf/sqlmap/nikto/dalfox/wpscan/"
            "exploit_db_run) fit: a bespoke protocol interaction (raw FTP/SMTP/IMAP via ftplib/"
            "smtplib/imaplib/socket) or parsing a format no other tool understands. stdlib plus "
            "httpx (prefer this — the HTTP client this project actually depends on) and requests "
            "are available. dnspython (the 'dns' module, e.g. dns.resolver) is NOT installed — for "
            "A/AAAA records use socket.getaddrinfo/socket.gethostbyname (stdlib); for anything else "
            "(MX/TXT/NS/SOA) use DNS-over-HTTPS instead of shelling out — urllib.request.urlopen a "
            "GET to https://dns.google/resolve?name=<domain>&type=<TYPE> (Accept: application/"
            "dns-json) and read the JSON Answer array. subprocess+dig/nslookup/host may or may not "
            "be on PATH depending on this machine's own setup — confirmed to repeatedly fail with "
            "FileNotFoundError on a fresh install; do not spend a retry guessing at them, go "
            "straight to DNS-over-HTTPS instead. grpc/grpcio is NOT installed either — for a gRPC target use raw "
            "sockets or subprocess+grpcurl (if present on the host) instead, never `import grpc`. "
            "More generally: this runs in a read-only sandboxed filesystem, so `pip install "
            "<anything>` will ALWAYS fail (OSError, read-only file system) no matter what the "
            "package is — never spend a retry attempt trying to self-install a missing module for "
            "ANY library, only stdlib/httpx/requests are genuinely available. Same execution shape "
            "and risk class as exploit_db_run (real code, no "
            "sandboxing) except you write the source "
            "yourself. Requires the target to be in the exploitation allowlist and the session to "
            "be human-approved, same as the exploit/sqlmap tools — but unlike those, calling this "
            "more than once for the same finding is expected: adjust the script based on the "
            "target's real response and retry, the same way authenticated_request/idor_probe do."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "The full Python source to run, as one script"},
                "target": {"type": "string", "description": "The target host/URL — checked against the exploitation allowlist"},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional CLI arguments (sys.argv[1:]) to pass the script",
                },
            },
            "required": ["source", "target"],
        },
    )
)

# Reuses custom_exploit_run's own native_function wholesale -- it never actually reads "target" for
# anything besides the allowlist gate (see that function's own docstring: "target is only used for
# the allowlist/approval check"), and _check_guardrail (agent/tools/runner.py) skips the whole
# check outright when requires_allowed_target=False, so a second registration under a new name,
# category="re", with no target parameter and its own RE-flavored description is the entire
# difference here -- no new implementation needed. RE mode's own "exploit-dev" gap: crafting a real
# ROP chain/format-string/heap-primitive exploit against a local crackme/vulnerable binary needs
# genuine scripting (pwntools' own process()/ELF()/context primitives), not a single fixed CLI
# tool the way radare2/gdb/mythril each are.
register_tool(
    ToolSpec(
        name="custom_re_script",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=custom_exploit_run,
        requires_allowed_target=False,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Writes and runs a real Python script for exploit-primitive/PoC work against a LOCAL "
            "binary/contract -- crafting a ROP chain, a format-string exploit, a heap primitive, "
            "driving a crackme's own process to test a recovered algorithm, or anything else no "
            "fixed RE tool covers. pwntools is installed (`from pwn import *` -- process()/ELF()/"
            "context/p32/p64/cyclic/... all available) alongside stdlib and httpx. Runs in a "
            "read-only sandboxed filesystem -- `pip install <anything>` will ALWAYS fail (OSError, "
            "read-only file system); only stdlib/httpx/pwntools are genuinely available, never "
            "spend a retry trying to self-install a missing module. /tmp is ALSO read-only here -- "
            "if the script needs to write a real file (a copy of the target, a shimmed config, a "
            "log), write it to the script's own current working directory (Python's default cwd, "
            "e.g. `open('fkc.dll', 'wb')`, not `open('/tmp/fkc.dll', 'wb')`) instead. No "
            "exploitation allowlist check here (there is no network target in RE mode) -- calling "
            "this more than once is expected: adjust the script based on the real output and retry."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "source": {"type": "string", "description": "The full Python source to run, as one script"},
                "args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional CLI arguments (sys.argv[1:]) to pass the script",
                },
            },
            "required": ["source"],
        },
    )
)

# CVE-2026-63030 (REST /batch/v1 route confusion) chained with CVE-2026-60137 (author__not_in
# blind SQLi) -- unauthenticated-to-RCE against WordPress core 6.8.x/6.9.x/7.0.x/7.1-beta before
# 6.8.6/6.9.5/7.0.2/7.1-beta2, in CISA KEV. See agent/tools/wp_batch_rce.py's module docstring for
# why this is ASRA's own implementation rather than a wrapped third-party script.
register_tool(
    ToolSpec(
        name="wp_batch_scan",
        category="scan",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=wp_batch_scan,
        requires_allowed_target=False,  # non-destructive: version fingerprint + route reachability only, no exploit payload
        installed_by_default=True,
        description=(
            "Non-destructive exposure check for the WordPress REST /batch/v1 route-confusion + "
            "author__not_in SQLi chain (CVE-2026-63030 / CVE-2026-60137, in CISA KEV): fingerprints "
            "the WordPress core version and confirms the batch route is reachable. No exploit "
            "payload sent — safe to run on any WordPress target. Run this before "
            "wp_batch_sqli_check/wp_batch_rce to know whether the target is even a candidate."
        ),
        parameters_schema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target host/URL"}},
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="wp_batch_sqli_check",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=wp_batch_sqli_check,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Confirms blind time-based SQLi in the wp_batch_scan-flagged chain via a harmless "
            "differential probe (1=0 vs 1=1 timing) — no data read, no DB write. Requires the "
            "target to be in the exploitation allowlist and the session to be human-approved, same "
            "as sqlmap, even though the payloads themselves are inert."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/URL"},
                "delay": {"type": "number", "description": "Injected SLEEP seconds for the timing oracle (default 0.15)"},
                "repeats": {"type": "integer", "description": "Median over N probes (raise on a noisy/high-jitter link, default 1)"},
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="wp_batch_sqli_read",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=wp_batch_sqli_read,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Extracts one scalar value via the same blind SQLi wp_batch_sqli_check confirms — "
            "read-only, no DB write, no admin forged. Use preset='users' to recover the lowest-ID "
            "account's login:password-hash (near-always the first admin) for offline cracking, then "
            "feed a cracked password into wp_batch_shell. Other presets: version, database, "
            "db_user, siteurl — or pass a raw SQL scalar expression via expr. Requires the "
            "exploitation allowlist + session approval, same as sqlmap."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/URL"},
                "preset": {"type": "string", "enum": ["version", "database", "db_user", "users", "siteurl"], "description": "Built-in target (default 'users')"},
                "expr": {"type": "string", "description": "Raw SQL scalar expression to extract — overrides preset"},
                "prefix": {"type": "string", "description": "DB table prefix (default 'wp_')"},
                "delay": {"type": "number", "description": "Injected SLEEP seconds for the timing oracle (default 0.15)"},
                "repeats": {"type": "integer", "description": "Median over N probes (raise on a noisy/high-jitter link, default 1)"},
                "max_len": {"type": "integer", "description": "Maximum extracted string length (default 128)"},
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="wp_batch_rce",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=wp_batch_rce,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Credential-less pre-auth RCE: confirms the blind SQLi timing oracle, forges its own "
            "administrator account through it (oEmbed -> changeset -> re-entrant parse_request), "
            "deploys a self-cleaning webshell, runs ONE command, then removes the webshell (the "
            "forged admin account itself is left in place, since removing it needs the same write "
            "primitive again and it may still be useful for follow-up access). Real, substantial "
            "state change on the target — requires the exploitation allowlist and a human-approved "
            "session, same tier as sqlmap/msfconsole. Call wp_batch_scan first to confirm the "
            "target is actually a candidate."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/URL"},
                "cmd": {"type": "string", "description": "Command to run on the target (default 'id')"},
                "sleep": {"type": "number", "description": "Injected SLEEP seconds for pre-auth SQLi detection (default 4)"},
                "rounds": {"type": "integer", "description": "Median over N probes for detection (default 3)"},
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="wp_batch_shell",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=wp_batch_shell,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Authenticated RCE via a KNOWN admin password (recover one with "
            "wp_batch_sqli_read(preset='users') and crack the hash offline) — logs in, uploads a "
            "token-gated plugin, runs ONE command, cleans up. Same allowlist + approval gate as "
            "sqlmap. Use wp_batch_rce instead if no credential is available yet."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/URL"},
                "admin_user": {"type": "string", "description": "Admin username to log in as (default 'admin')"},
                "admin_password": {"type": "string", "description": "Plaintext admin password (required — crack the hash from wp_batch_sqli_read)"},
                "cmd": {"type": "string", "description": "Command to run on the target (default 'id')"},
            },
            "required": ["target", "admin_password"],
        },
    )
)

register_tool(
    ToolSpec(
        name="wp_batch_root_prereq",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=wp_batch_root_prereq,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Benign shell-to-root prerequisite check — runs read-only diagnostics (uid, kernel, "
            "arch, Python runtime, setuid-root binaries, container indicators) through the same "
            "authenticated webshell wp_batch_shell uses. Never runs a local privilege-escalation "
            "exploit itself, only reports whether the prerequisites for one appear present. Same "
            "allowlist + approval gate as sqlmap."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target host/URL"},
                "admin_user": {"type": "string", "description": "Admin username to log in as (default 'admin')"},
                "admin_password": {"type": "string", "description": "Plaintext admin password (required — crack the hash from wp_batch_sqli_read)"},
            },
            "required": ["target", "admin_password"],
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

# Same "no single phase category fits" reasoning as update_plan just below — record_hypothesis is
# offered in recon+analyze (agent/core.py explicitly appends it there), resolve_hypothesis in
# analyze+exploit, so category="post_exploit" here means the same thing it means for update_plan:
# "not offered by any bare get_tools_by_category() call, each phase opts in explicitly."
register_tool(
    ToolSpec(
        name="record_hypothesis",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_hypothesis,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Records a SUSPECTED vulnerability or attack angle from raw evidence you haven't "
            "confirmed yet — weaker than record_finding (no proof yet), stronger than a passing "
            "thought (it survives into Analyze/Exploit's hands as a real, structured lead instead "
            "of only living in this turn's own reasoning). Use it the moment something in the raw "
            "data looks worth someone following up on later — an odd exposed path, a version that "
            "rings a bell for a CVE family, a service on an unusual port — even though you can't "
            "act on it right now yourself."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "The suspected vulnerability/attack angle, in one concrete sentence"},
                "evidence": {"type": "string", "description": "The specific raw fact (banner, path, header, response detail) that triggered this suspicion"},
                "source_tool": {
                    "type": "string",
                    "description": "Optional: the single tool (as it appears in your own tool list) whose output actually raised this suspicion — e.g. 'nuclei_scan', 'whatweb'. Omit if nothing specific triggered it.",
                },
                "host": {
                    "type": "string",
                    "description": (
                        "Optional: the exact host/IP this suspicion is about, same value you'd pass as a "
                        "tool's own target -- lets the Map tab's attack-surface graph place it on the "
                        "right host node. Omit if it isn't tied to one specific host."
                    ),
                },
            },
            "required": ["text"],
        },
    )
)

register_tool(
    ToolSpec(
        name="resolve_hypothesis",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=resolve_hypothesis,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Closes out an earlier record_hypothesis once you've actually investigated it — "
            "\"confirmed\" if it held up (also call record_finding for the real thing if you "
            "haven't yet — this only marks the LEAD itself settled) or \"ruled_out\" if it doesn't "
            "(explain the real check you ran in 'note', not just 'unclear')."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "hypothesis_text": {"type": "string", "description": "The hypothesis's own text, exactly (or closely) as it was originally recorded"},
                "status": {"type": "string", "enum": ["confirmed", "ruled_out"]},
                "note": {"type": "string", "description": "What you actually checked and found — required context, not optional flavor text"},
                "resolving_tool": {
                    "type": "string",
                    "description": "Optional: the single tool (as it appears in your own tool list) whose output actually settled this — e.g. 'sqlmap', 'authenticated_request'. Omit if nothing specific settled it.",
                },
            },
            "required": ["hypothesis_text", "status"],
        },
    )
)

# category="post_exploit" is deliberate, same "one Category value no phase's bare
# get_tools_by_category(...) call ever queries" reasoning as record_reverification_result/
# record_chain_result/delegate_to_subagent below — this tool needs to be callable from EVERY
# phase (recon/analyze/exploit/chain/reverify), not just one, so it can't live under any single
# category the way record_target ("recon") or record_finding ("scan") do; each phase's own
# tool_specs assembly (agent/core.py) explicitly appends it instead.
register_tool(
    ToolSpec(
        name="update_plan",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=update_plan,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Creates or refines your own working plan for this whole session — call it once at the "
            "start of Recon to lay out what you intend to check phase by phase, then call it again "
            "any time a real fact changes what's actually worth doing next (a confirmed technology, "
            "CVE, plugin, or version — not a guess; a couple of recon steps finishing and telling "
            "you something concrete is exactly the moment to update this). Three levels: a phase "
            "has TASKS (a real unit of work, e.g. 'Enumerate the attack surface'), and each task has "
            "SUBTASKS (the actual concrete steps that realize it, e.g. 'WHOIS lookup', 'DNS "
            "resolution') — tools and status only ever belong on a subtask, never on the task or "
            "phase directly, both of those are derived automatically from their subtasks' own "
            "status once you submit. For every subtask, actually weigh your full available tool "
            "list for this phase against what that one concrete step needs — don't default to the "
            "first plausible-sounding tool or repeat the same one out of habit; name the one that "
            "genuinely fits best, and change it on a later call if a fact you learn makes a "
            "different tool the better fit. Always resubmits the FULL current plan (every phase you "
            "care about, not a diff) — this replaces whatever was recorded before."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "phases": {
                    "type": "array",
                    "description": "The whole plan, one entry per phase you have something to say about.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "phase": {"type": "string", "enum": ["recon", "analyze", "exploit"]},
                            "rationale": {"type": "string", "description": "Why this phase's tasks are shaped this way, given what's actually been confirmed so far. Keep it to 1-2 sentences — a long rationale is more likely to get truncated mid-JSON by weaker models."},
                            "tasks": {
                                "type": "array",
                                "description": "Real units of work for this phase — each one broken down into its own concrete subtasks below.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "text": {"type": "string", "description": "A concrete, specific task — not a vague aspiration."},
                                        "subtasks": {
                                            "type": "array",
                                            "description": "The concrete steps that realize this task — at least one, even for a simple task. This is where status and recommended_tools actually live.",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "text": {"type": "string", "description": "One concrete, specific step."},
                                                    "status": {
                                                        "type": "string", "enum": ["pending", "active", "done", "blocked"],
                                                        "description": "\"blocked\" is for a step you genuinely cannot complete right now for a real external reason (the target went down, a dependency you need is unavailable, scope/auth blocks it) — say why in this task's own text or the phase rationale. Never use \"done\" for a step you gave up on or couldn't actually finish; that's what \"blocked\" is for.",
                                                    },
                                                    "recommended_tools": {
                                                        "type": "array",
                                                        "items": {"type": "string"},
                                                        "description": "Real tool name(s) (as they appear in your own tool list) that genuinely fit THIS step best — weighed against your full toolset, not a guess.",
                                                    },
                                                },
                                                "required": ["text"],
                                            },
                                        },
                                    },
                                    "required": ["text", "subtasks"],
                                },
                            },
                        },
                        "required": ["phase", "tasks"],
                    },
                },
            },
            "required": ["phases"],
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
                "severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    "description": "Info is for a notable observation/disclosure with no direct security "
                    "impact of its own (an exposed banner, a discovered endpoint, a fingerprinted "
                    "technology) -- not a real vulnerability. Use Low instead for a genuine, if minor, "
                    "weakness.",
                },
                "description": {"type": "string", "description": "What the issue is and why it matters"},
                "technology": {
                    "type": "string",
                    "description": "The specific product/plugin/library + version this finding is actually in, "
                    "from a real banner/header/response — 'unknown' only if nothing identifies it",
                },
                "reproduction_steps": {
                    "type": "string",
                    "description": "Concrete steps (including the literal payload/request, if the vulnerability "
                    "class has one) a human could run right now to reproduce this alone, actively or passively "
                    "— not an attack that needs a victim to act (phishing/MITM/social engineering); say so "
                    "explicitly instead if this finding genuinely is that kind",
                },
                "verification": {
                    "type": "string",
                    "enum": ["verified", "inferred", "needs_verification"],
                    "description": (
                        "verified: an active check confirmed it. inferred: guessed from a "
                        "banner/version. needs_verification: not yet confirmed either way."
                    ),
                },
                "evidence_ref": {"type": "string", "description": "Supporting tool output detail, or omit if none"},
                "host": {
                    "type": "string",
                    "description": (
                        "The exact host/IP this finding is actually on -- the same value you'd pass as a "
                        "tool's own target (e.g. 'api.example.com', '203.0.113.7'). Lets the Map tab's "
                        "attack-surface graph place this finding on the right host node. Omit only if this "
                        "finding genuinely isn't tied to one specific host."
                    ),
                },
                "evidence_entry_id": {
                    "type": "string",
                    "description": (
                        "Optional: the id of a specific captured-traffic entry (from list_captured_traffic, or "
                        "the id send_raw_request/intruder_run/racer_run return) this finding's evidence actually "
                        "came from -- gives the report a precise link to the exact request/response, alongside "
                        "(never instead of) the evidence/evidence_ref text above. Omit if the evidence isn't tied "
                        "to one specific captured entry."
                    ),
                },
                "exploitation_scenario": {
                    "type": "string",
                    "enum": ["remote_direct", "mitm_active", "mitm_passive", "victim_interaction", "local_only"],
                    "description": (
                        "How an attacker would actually have to use this, not how bad it is: "
                        "remote_direct = attacker can go straight at it over the network, no victim and no "
                        "special network position needed (RCE, SQLi, exposed admin panel, weak creds, ...). "
                        "mitm_active = attacker must be actively positioned on the network path and manipulate "
                        "traffic (a protocol downgrade/handshake attack). mitm_passive = attacker only needs to "
                        "passively observe traffic already flowing, no manipulation (e.g. a session cookie sent "
                        "unencrypted). victim_interaction = needs the target user to click/open/visit something "
                        "attacker-controlled (phishing, reflected XSS, clickjacking). local_only = requires "
                        "already having local or authenticated access on the target."
                    ),
                },
                "qualifies_for_bounty": {
                    "type": "string",
                    "enum": ["qualifying", "non_qualifying", "unclear"],
                    "description": (
                        "Only set this when the task explicitly gave you this project's Qualifying/"
                        "Non-qualifying vulnerabilities scope rules — omit entirely otherwise. "
                        "'qualifying' if this finding's class clearly matches the program's own "
                        "Qualifying list, 'non_qualifying' if it clearly matches the Non-qualifying "
                        "list, 'unclear' if scope rules exist but don't clearly cover this class."
                    ),
                },
                "false_positive_reason": {
                    "type": "string",
                    "description": (
                        "Omit for a real, live lead. Set this ONLY when you're recording the finding "
                        "purely for audit-trail completeness but already have concrete evidence it "
                        "isn't actually exploitable here — e.g. a CVE whose affected-version range you "
                        "confirmed does NOT include this target's actual installed version, or a "
                        "vulnerability class that structurally cannot apply to what you observed. "
                        "One concise sentence stating the real evidence for why — never a vague guess."
                    ),
                },
                "exploited": {
                    "type": "boolean",
                    "description": (
                        "Omit entirely for the normal case — Recon/Analyze recording a lead that a "
                        "later Exploit pass will confirm or disprove. Only set this to true when you "
                        "are recording a finding you have ALREADY, in this same call, proven with real "
                        "exploitation evidence and there is no later phase left to confirm it (e.g. a "
                        "Chain-phase finding — Chain runs after Exploit, so nothing downstream will "
                        "ever fill this in otherwise). evidence is required whenever this is true."
                    ),
                },
                "evidence": {
                    "type": "string",
                    "description": (
                        "Required when exploited=true, otherwise omit. The actual proof of "
                        "exploitation — a real request/response, command output, or session replay you "
                        "just got from a real tool call — never a restatement of the claim."
                    ),
                },
                "remediation_advice": {
                    "type": "string",
                    "description": (
                        "Optional: a concrete, no-fluff 'what to actually do about this' for the "
                        "finding you just proved. Omit if you have nothing more specific to add than "
                        "the general category advice."
                    ),
                },
                "discovery_tool": {
                    "type": "string",
                    "description": "Optional: the single tool (as it appears in your own tool list) whose output actually led you to this finding — e.g. 'nuclei_scan', 'nmap_scan'. Omit if nothing specific led you here.",
                },
            },
            "required": ["title", "severity", "description", "exploitation_scenario"],
        },
    )
)

# Exploit's real final answer, submitted as a tool call instead of free-text JSON — see
# agent/core.py's _run_llm_tool_loop "terminal_tool" mechanism. Real incident this replaces: the
# old free-text contract failed to parse on a large fraction of exploit-phase turns (a weak/free
# model routinely wrapped its JSON in prose or dropped a field), each failure costing one extra
# LLM round-trip (_repair_json_reply) on top of nearly every finding evaluated.
register_tool(
    ToolSpec(
        name="record_exploit_decision",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_exploit_decision,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Call this with your final answer once you're done evaluating this finding — the ONLY "
            "way to end your turn. Never describe your conclusion as plain text instead; if you're "
            "not calling an exploitation tool, the honest answer is still a call to this tool with "
            "the matching skipped_* action, not a prose summary."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["exploit_attempted", "skipped_needs_verification", "skipped_no_suitable_tool"],
                    "description": (
                        "exploit_attempted: you actually called a real exploitation tool this turn and are "
                        "reporting its real result. skipped_needs_verification: verification isn't 'verified' "
                        "yet. skipped_no_suitable_tool: nothing in this registry fits this finding's class."
                    ),
                },
                "tool": {"type": "string", "description": "Name of the tool actually used, or omit/null if none was"},
                "exploitation_scenario": {
                    "type": "string",
                    "enum": ["remote_direct", "mitm_active", "mitm_passive", "victim_interaction", "local_only", "unchanged"],
                    "description": (
                        "A genuine re-check based on what you actually found this pass, not a copy of the "
                        "finding's existing value — UNLESS action is a skip (skipped_no_suitable_tool or "
                        "skipped_needs_verification) and nothing new was actually learned about HOW this would "
                        "be exploited: answer 'unchanged' then, instead of guessing one of the five real values "
                        "just to satisfy this field. Not a valid answer when action is exploit_attempted — a "
                        "real attempt always has a real result to base this on."
                    ),
                },
                "reasoning": {
                    "type": "string",
                    "description": (
                        "Concrete and specific — what was actually achieved, or why nothing more could be. "
                        "For a skip on a web-class finding, explain the real-world impact in plain language "
                        "a bug-bounty beginner would understand, not just 'no tool fits'."
                    ),
                },
                "confirmed_tech_fact": {
                    "type": "string",
                    "description": (
                        "Optional. Only when this pass established a durable fact about the target's actual "
                        "software identity/version that other findings on this SAME technology stack would "
                        "benefit from knowing (e.g. 'this host runs Mailcow's bundled Dovecot Community "
                        "Edition, not Dovecot Pro — advisories scoped to Pro don't apply'). Omit for anything "
                        "specific to just this one finding — most findings have nothing reusable to report here."
                    ),
                },
                "corrected_severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    "description": (
                        "Optional — set ONLY when your own reasoning above genuinely contradicts this "
                        "finding's CURRENT severity, most commonly on a skip (e.g. you just concluded no "
                        "tool here can demonstrate real impact, but severity is still set at a level that "
                        "assumes it can). Omit whenever your conclusion doesn't actually change it — the "
                        "overwhelmingly common case. Not needed for exploit_attempted — that path has its "
                        "own separate confirmation step for this."
                    ),
                },
                "corrected_qualifies_for_bounty": {
                    "type": "string",
                    "enum": ["qualifying", "non_qualifying", "unclear"],
                    "description": (
                        "Same idea as corrected_severity, for qualifies_for_bounty specifically. Set this "
                        "when your own reasoning above shows this finding's class doesn't actually meet the "
                        "program's own Qualifying bar (e.g. its rules say 'CORS with real security impact' "
                        "and you just explained impact can't be demonstrated here) even though the field is "
                        "currently set differently. Only meaningful when this project actually has Qualifying/"
                        "Non-qualifying scope rules — omit entirely otherwise, and omit whenever your "
                        "conclusion doesn't actually change the qualification."
                    ),
                },
                "corrected_false_positive_reason": {
                    "type": "string",
                    "description": (
                        "Optional — set ONLY when your own reasoning above concludes this finding isn't real "
                        "(e.g. the installed version turns out to be outside a CVE's affected range, or the "
                        "vulnerable condition it describes doesn't actually hold for this target) but this "
                        "finding doesn't already show a false-positive banner. A short, concrete reason "
                        "(what you checked, what it showed) — never invent one just to fill this in; omit "
                        "entirely for a real, still-standing finding, which is the overwhelmingly common case."
                    ),
                },
                "remediation_advice": {
                    "type": "string",
                    "description": (
                        "Concrete, no-fluff advice on what to actually DO to fix this — required for every "
                        "real, still-standing finding regardless of action (exploit_attempted or a skip alike; "
                        "omit only for a finding you're marking a false positive via corrected_false_positive_"
                        "reason above, which has nothing left to fix). Specific to what this exact finding is "
                        "(e.g. 'set HttpOnly and Secure on the NSC_TEMP/NSC_PERS cookies', 'upgrade Dovecot "
                        "past 2.3.19', 'strip the jwt-token hidden field from the rendered page and rotate "
                        "the leaked secret'), not a generic restatement like 'follow security best practices'."
                    ),
                },
            },
            "required": ["action", "exploitation_scenario", "reasoning"],
        },
    )
)

# Rescanned project's real final answer for one carried-over finding — same terminal_tool shape as
# record_exploit_decision, used by agent/core.py's _run_reverify. category="post_exploit" is
# deliberate, not arbitrary: it's the one Category value no phase's get_tools_by_category(...) call
# actually queries today (recon/scan/exploit are the only ones any phase assembles its toolset
# from) — registering this under "scan" would leak it into Analyze's and deep-dive's toolsets
# (a dead-end tool call there, confusing the model with no real effect), under "exploit" would leak
# it into every normal exploit-phase finding's toolset too. _run_reverify builds its own tool list
# explicitly rather than relying on this category alone, but the category still has to be one
# nothing else's get_tools_by_category(...) call will ever pick up.
register_tool(
    ToolSpec(
        name="record_reverification_result",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_reverification_result,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Call this with your final answer once you're done checking whether this one "
            "carried-over finding from a prior scan is still real right now — the ONLY way to end "
            "your turn for this finding. A rubber-stamp 'still present' without actually using a "
            "tool to check is worse than useless; if you didn't verify it, say so honestly."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "verification_outcome": {
                    "type": "string",
                    "enum": ["confirmed_present", "confirmed_fixed", "inconclusive"],
                    "description": (
                        "confirmed_present: you just confirmed the bug still exists with a real tool call this turn. "
                        "confirmed_fixed: a real tool call this turn shows it's actually gone (endpoint changed, "
                        "vulnerable behavior no longer reproduces). "
                        "inconclusive: you could not reach a real yes/no this turn (blocked, timed out, tool "
                        "unavailable) — use this instead of guessing confirmed_fixed. The finding stays in the "
                        "report flagged for a future re-check rather than being silently dropped."
                    ),
                },
                "reasoning": {
                    "type": "string",
                    "description": "Concrete and specific — what you actually checked, what tool you used, and what it showed.",
                },
                "evidence_ref": {
                    "type": "string",
                    "description": "Required when verification_outcome is confirmed_present: the fresh proof from a tool call made just now, not a copy of the old finding's evidence_ref.",
                },
                "corrected_severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    "description": (
                        "Optional — set ONLY when your own reasoning above genuinely contradicts this "
                        "finding's CURRENT severity (e.g. you just confirmed_fixed something that was Critical, "
                        "or your confirmed_present check turned up materially weaker impact than first assumed). "
                        "Omit whenever your conclusion doesn't actually change it — the overwhelmingly common case. "
                        "If this would RAISE severity above the prior scan's value, you must also fill in "
                        "escalation_justification below with what's genuinely new — simply reproducing the same "
                        "bug again is not new evidence."
                    ),
                },
                "corrected_qualifies_for_bounty": {
                    "type": "string",
                    "enum": ["qualifying", "non_qualifying", "unclear"],
                    "description": (
                        "Same idea as corrected_severity, for qualifies_for_bounty specifically. Set this when "
                        "your own reasoning above shows this finding's class no longer meets (or never met) the "
                        "program's own Qualifying bar. Only meaningful when this project actually has Qualifying/"
                        "Non-qualifying scope rules — omit entirely otherwise. If this would RAISE it to "
                        "\"qualifying\" from something less than that, you must also fill in escalation_justification "
                        "below."
                    ),
                },
                "escalation_justification": {
                    "type": "string",
                    "description": (
                        "Required when corrected_severity or corrected_qualifies_for_bounty would RAISE this "
                        "finding above what the prior scan recorded — describe what's genuinely NEW (broader "
                        "impact you just demonstrated, a stronger exploitation path, something the original scan "
                        "never showed). Simply reproducing the same behavior again is NOT new evidence — omit the "
                        "corrected_* fields entirely if reproduction is all you have."
                    ),
                },
                "corrected_false_positive_reason": {
                    "type": "string",
                    "description": (
                        "Optional — set ONLY when your own reasoning above concludes this finding isn't real "
                        "(confirmed_fixed, or your own re-check disproves the original claim) but it doesn't "
                        "already show a false-positive banner. A short, concrete reason — never invent one just "
                        "to fill this in."
                    ),
                },
            },
            "required": ["verification_outcome", "reasoning"],
        },
    )
)

# The Skeptical Verifier's own final answer (agent/core.py's _run_skeptical_verification) -- same
# "one Category value nothing else's get_tools_by_category picks up" reasoning as
# record_reverification_result just above.
register_tool(
    ToolSpec(
        name="record_skeptical_verification_result",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_skeptical_verification_result,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Call this with your final answer once you're done independently checking this claim — "
            "the ONLY way to end your turn. You were never shown how this finding was originally "
            "investigated; agreeing because the recipe reads plausibly is worthless — only your OWN "
            "real tool call this turn counts."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["confirmed", "refuted", "inconclusive"],
                    "description": (
                        "confirmed: a real tool call YOU made this turn reproduced the claim. "
                        "refuted: a real tool call YOU made this turn genuinely contradicts the claim. "
                        "inconclusive: you could not reach a real yes/no this turn (blocked, timed out, tool "
                        "unavailable, missing prerequisite) — use this instead of guessing either way."
                    ),
                },
                "reasoning": {
                    "type": "string",
                    "description": "Concrete and specific — what you actually checked, what tool you used, and what it showed.",
                },
                "evidence_ref": {
                    "type": "string",
                    "description": "Required when verdict is confirmed or refuted: the fresh proof from your own tool call made just now, never a copy of the recipe you were given.",
                },
                "corrected_severity": {
                    "type": "string",
                    "enum": ["Critical", "High", "Medium", "Low", "Info"],
                    "description": (
                        "Optional — set ONLY when your own independent re-check genuinely contradicts this "
                        "finding's CURRENT severity (most commonly on a 'refuted' verdict — e.g. you just proved "
                        "a claimed additional host doesn't even resolve, undercutting the impact the current "
                        "severity assumes). Omit whenever your conclusion doesn't actually change it."
                    ),
                },
                "corrected_qualifies_for_bounty": {
                    "type": "string",
                    "enum": ["qualifying", "non_qualifying", "unclear"],
                    "description": (
                        "Same idea as corrected_severity, for qualifies_for_bounty specifically — set this when "
                        "a 'refuted' verdict means this finding's class no longer meets the program's own "
                        "Qualifying bar. Only meaningful when this project actually has Qualifying/Non-qualifying "
                        "scope rules — omit entirely otherwise."
                    ),
                },
                "corrected_false_positive_reason": {
                    "type": "string",
                    "description": (
                        "Optional — set ONLY when your 'refuted' verdict means this finding isn't real at all, "
                        "but it doesn't already show a false-positive banner. A short, concrete reason — never "
                        "invent one just to fill this in."
                    ),
                },
            },
            "required": ["verdict", "reasoning"],
        },
    )
)

# Chain phase's real final answer, same "one Category value nothing else's get_tools_by_category
# picks up" reasoning as record_reverification_result just above — agent/core.py's _run_chain
# builds its own explicit tool list (exploit-category tools + record_finding + this one) rather
# than relying on category alone, but "post_exploit" still has to be a value no other phase's
# toolset assembly will ever pick up on its own.
register_tool(
    ToolSpec(
        name="record_chain_result",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_chain_result,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Call this with your final answer once you're done looking for a real attack chain "
            "across this session's findings — the ONLY way to end your turn. A plausible-sounding "
            "chain with no real tool call behind it is worthless; if you didn't prove it, the "
            "honest answer is no_chain_found, not a narrated chain_confirmed."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["chain_confirmed", "no_chain_found"],
                    "description": "chain_confirmed requires real proof (see the other fields); no_chain_found is a complete, valid result on its own.",
                },
                "finding_titles": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Required for chain_confirmed: every finding involved, by its real title.",
                },
                "evidence_quotes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Required for chain_confirmed: the real evidence_ref/evidence value quoted from each finding named above — not a paraphrase.",
                },
                "tool_call_proof": {
                    "type": "string",
                    "description": "Required for chain_confirmed: which tool you called, with what arguments, and what it actually returned.",
                },
                "impact_scenario": {
                    "type": "string",
                    "description": (
                        "Required for chain_confirmed: a concrete, submission-ready paragraph describing what an "
                        "attacker can now actually DO with this chain — not a restatement of reasoning/tool_call_proof. "
                        "Say what was concretely reached (an admin panel, another user's data, an authenticated "
                        "action) and how a bounty triager can reproduce it themselves from the reproduction "
                        "material already on the finding(s). Write it the way you'd write the Impact section of a "
                        "real report: what happened, not what could theoretically happen — never 'could potentially "
                        "lead to...'. Never describe or suggest a destructive action (deleting/modifying another "
                        "user's real data, a denial-of-service) as part of the proof — reaching and observing "
                        "privileged access is proof enough on its own."
                    ),
                },
                "reasoning": {
                    "type": "string",
                    "description": "Always required — what you checked and why you reached this conclusion.",
                },
                "reverified_findings": {
                    "type": "array",
                    "description": (
                        "Optional. If a real tool call you made THIS pass re-tested an EXISTING finding's own "
                        "vulnerability (not a new chain — the same bug, checked again) and got a fresh result, "
                        "report it here so that finding's own record gets updated instead of staying stale. Real "
                        "incident this exists for: a finding's exploit-phase pass had left an advisory_note saying "
                        "'no real exploitation attempt was made this pass — re-run X to confirm', and this chain "
                        "pass then actually did re-run X and got a fresh confirmation — but that confirmation never "
                        "reached the finding's own record, so the final report kept telling the operator to do "
                        "something already done. Omit entirely if nothing you did this pass re-tested an existing "
                        "finding's own evidence."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string", "description": "The exact, real title of the existing finding being re-verified."},
                            "evidence_ref": {
                                "type": "string",
                                "description": "Required: the fresh proof from a real tool call made THIS pass, not a copy of the finding's old evidence_ref.",
                            },
                            "exploited": {
                                "type": "boolean",
                                "description": "Optional: updates the finding's own exploited flag to match what this fresh check actually showed.",
                            },
                            "note": {
                                "type": "string",
                                "description": "Optional: a short replacement for the finding's advisory_note reflecting this fresh check.",
                            },
                        },
                        "required": ["title", "evidence_ref"],
                    },
                },
            },
            "required": ["action", "reasoning"],
        },
    )
)

# category="exploit" (not "post_exploit" like record_chain_result right above) is deliberate: this
# needs to reach get_tools_by_category("exploit")'s every real consumer -- Exploit's own tool list,
# Chain's (built FROM the exploit category, agent/core.py's _run_chain), and interactive/chat mode
# -- not just Chain, since a real pivot is just as provable mid-Exploit as it is during a dedicated
# Chain pass. Deliberately no terminal_tool wiring anywhere (see record_host_relationship's own
# docstring) -- this is a plain mid-turn tool call, not a phase's own final-answer contract.
register_tool(
    ToolSpec(
        name="record_host_relationship",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=record_host_relationship,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Call this whenever you've PROVEN a real pivot/relationship between two hosts in this "
            "session's own scope -- leaked credentials that also work on a second host, an SSRF/open "
            "redirect that reaches an internal host, a shared session token, or any other concrete "
            "mechanism you actually demonstrated with a real tool call. This is what draws a labeled "
            "line between the two hosts on the operator's own Map tab (the Attack Surface graph's "
            "attack_path edges) -- never call it for a guess or a theoretical relationship, only one "
            "you actually confirmed with real evidence."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "source_host": {
                    "type": "string",
                    "description": "The host/IP you pivoted FROM -- use the exact identity (hostname or IP) already known from recon/findings.",
                },
                "target_host": {
                    "type": "string",
                    "description": "The host/IP you reached from source_host.",
                },
                "mechanism": {
                    "type": "string",
                    "description": "Short, concrete label for HOW you pivoted (e.g. 'leaked credentials', 'SSRF', 'internal redirect', 'shared session token') -- not a restatement of evidence.",
                },
                "evidence": {
                    "type": "string",
                    "description": "The real tool call and its actual result that proves this pivot -- not a narrated claim.",
                },
            },
            "required": ["source_host", "target_host", "mechanism", "evidence"],
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
_IP_SCHEMA = {
    "type": "object",
    "properties": {"ip": {"type": "string", "description": "IPv4 address to look up"}},
    "required": ["ip"],
}
_EMAIL_SCHEMA = {
    "type": "object",
    "properties": {"email": {"type": "string", "description": "Email address to check, e.g. person@example.com"}},
    "required": ["email"],
}
_PASSWORD_SCHEMA = {
    "type": "object",
    "properties": {"password": {"type": "string", "description": "The password to check -- never sent in full, only its SHA-1 hash's first 5 hex characters leave this machine"}},
    "required": ["password"],
}
_CLOUD_BUCKET_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "The bucket/container's own full https URL, e.g. https://<bucket>.s3.amazonaws.com, "
                "https://s3.amazonaws.com/<bucket>, https://storage.googleapis.com/<bucket>, or "
                "https://<account>.blob.core.windows.net/<container>."
            ),
        },
        "test_write": {
            "type": "boolean",
            "description": (
                "Default false. When true, additionally uploads a small labeled test object and "
                "immediately deletes it to confirm anonymous WRITE access -- a real, target-"
                "affecting action, only set this when write-permission proof is actually needed."
            ),
        },
    },
    "required": ["target"],
}
# github_code_search's own schema, not _DOMAIN_SCHEMA -- it takes a real GitHub search query
# (qualifiers like in:file/filename:/org: apply), not a bare domain name.
_GITHUB_CODE_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {
            "type": "string",
            "description": (
                "A real GitHub code-search query, e.g. 'target.com in:file' or "
                "'\"AKIA\" filename:.env' -- GitHub's own search qualifiers (in:, filename:, "
                "extension:, org:, path:) all apply here, this is not just a bare keyword."
            ),
        },
    },
    "required": ["query"],
}
# wayback_urls' own schema, not the shared _DOMAIN_SCHEMA (defined further down, with the other
# tier-1 native tool schemas) -- timeout is meaningful for this one tool specifically (its own
# web.archive.org CDX query has been measured to genuinely take ~38s on a real query, unlike every
# other _DOMAIN_SCHEMA tool), so it doesn't belong on the schema every domain-lookup tool shares,
# which would misleadingly imply they all respect it too.
_WAYBACK_URLS_SCHEMA = {
    "type": "object",
    "properties": {
        "domain": {"type": "string", "description": "Domain name, e.g. example.com"},
        "timeout": {
            "type": "number",
            "description": "HTTP timeout in seconds for the web.archive.org query (default 45 — its CDX API has been measured to genuinely take ~38s on a real query).",
        },
    },
    "required": ["domain"],
}
# common_crawl_urls' own schema, same shape/reasoning as _WAYBACK_URLS_SCHEMA right above -- a
# genuinely independent second historical-URL archive, not the shared _DOMAIN_SCHEMA, since
# "timeout" is meaningful for this one CDX-query tool specifically.
_COMMON_CRAWL_URLS_SCHEMA = {
    "type": "object",
    "properties": {
        "domain": {"type": "string", "description": "Domain name, e.g. example.com"},
        "timeout": {
            "type": "number",
            "description": "HTTP timeout in seconds for the Common Crawl CDX query (default 45).",
        },
    },
    "required": ["domain"],
}
# dork_search's own schema -- category/engine enums are built FROM the catalog
# (agent/tools/dork_engine.py's list_dork_categories/SEARCH_ENGINES) rather than hand-copied here,
# so a new catalog entry is automatically offered to the model without a second edit in this file.
_DORK_SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": "Domain, IP, URL, or \"*.example.com\" wildcard entry to dork. Required "
                            "unless custom_dork is fully self-contained (no {target} needed).",
        },
        "category": {
            "type": "string",
            "enum": [c.id for c in list_dork_categories()],
            "description": "A catalog dork category. Omit to send only custom_dork as a raw query. "
                            + " | ".join(f"{c.id}: {c.label}" for c in list_dork_categories()),
        },
        "custom_dork": {
            "type": "string",
            "description": "A free-form dork/query string. Combined with target as "
                            "\"site:{target} {custom_dork}\" when both are given; used verbatim otherwise.",
        },
        "engine": {
            "type": "string",
            "enum": sorted(_DORK_SEARCH_ENGINES),
            "description": "Search engine for a search_lead category or custom_dork (default google). "
                            "Irrelevant for native_tool/external_link/direct_url categories.",
        },
    },
    "required": [],
}
# http_request's own schema, not the shared _URL_TARGET_SCHEMA above -- follow_redirects is
# meaningful for this one tool specifically (native.py's http_request is the only consumer that
# actually reads and honors it), so it doesn't belong on the schema every other _URL_TARGET_SCHEMA
# tool shares, which would misleadingly imply they all respect it too.
_HTTP_REQUEST_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Full URL to request"},
        "follow_redirects": {
            "type": "boolean",
            "description": (
                "Whether to follow HTTP redirects before returning a result (default true). Set "
                "false when you specifically need to see the raw redirect response itself (e.g. "
                "proving an open-redirect PoC) instead of wherever the chain eventually leads —"
                " otherwise the redirect target's own response replaces the one you actually asked for."
            ),
        },
        "timeout": {
            "type": "number",
            "description": (
                "HTTP timeout in seconds (default 10). Raise this for a call you already expect to "
                "be slow through no fault of the target — e.g. a web.archive.org CDX search query "
                "with a broad wildcard, which routinely takes 20-60s to respond even when it will "
                "eventually succeed. Leave unset for a normal request against the actual scan target."
            ),
        },
        "headers": {
            "type": "object",
            "description": (
                "Extra HTTP headers to send, e.g. {\"Host\": \"example.com\"}. Required whenever you "
                "target a bare IP instead of a domain (a host went unreachable and you resolved its "
                "IP yourself, or you're comparing a domain against its IP) — a CDN/WAF-fronted target "
                "serves multiple sites off one shared IP (virtual hosting), so a request to the IP "
                "with no Host header lands on whatever the default vhost is, not the site you meant. "
                "Without a Host header matching the original domain, an IP-based request is not a "
                "valid substitute for testing that domain."
            ),
        },
    },
    "required": ["target"],
}
# web_fetch's own schema, not http_request's -- "timeout" here is documented against a slow
# third-party research page (a GitHub raw file, a slow advisory CMS), not the scan target itself.
_WEB_FETCH_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "Full URL of a page on the general internet to read (a CVE advisory, GitHub "
                "PoC/issue, vendor bulletin, security write-up) -- never the assessment target "
                "itself, use http_request for that."
            ),
        },
        "timeout": {
            "type": "number",
            "description": "HTTP timeout in seconds (default 10). Raise it for a page you already expect to load slowly.",
        },
    },
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
        "Finds historical URLs for a domain via the Wayback Machine CDX API — can reveal forgotten endpoints. "
        "The returned list is already decluttered (near-duplicate paths like /product/1, /product/2 collapsed "
        "to one representative; static assets dropped); see interesting_urls for ones carrying a parameter "
        "name commonly tied to LFI/RCE/redirect/SSRF/SQLi bugs, worth checking first.",
        _WAYBACK_URLS_SCHEMA,
    ),
    "common_crawl_urls": (
        common_crawl_urls,
        "Finds historical URLs for a domain via Common Crawl's own CDX index — a second, independently-crawled "
        "archive alongside wayback_urls (fully free, no API key/account, unlike Shodan/Censys/urlscan.io); "
        "each catches URLs the other sometimes misses, worth running both. Decluttered the same way as "
        "wayback_urls — see its own description for what that means.",
        _COMMON_CRAWL_URLS_SCHEMA,
    ),
    "whois_lookup": (whois_lookup, "Raw WHOIS lookup for a domain.", _DOMAIN_SCHEMA),
    "dns_lookup": (dns_lookup, "Resolves a domain to its IP addresses.", _DOMAIN_SCHEMA),
    "shodan_internetdb_lookup": (
        shodan_internetdb_lookup,
        "Free, keyless passive lookup (Shodan InternetDB) of open ports, CPEs, hostnames, tags and "
        "known CVEs Shodan has observed for a single IPv4 -- no account or subscription needed, "
        "unlike a full Shodan search. Data is refreshed weekly, so it's a passive enrichment signal, "
        "not a live scan.",
        _IP_SCHEMA,
    ),
    "otx_passive_dns": (
        otx_passive_dns,
        "AlienVault OTX passive DNS history for a domain — every hostname/IP pairing OTX has ever observed, with "
        "first/last-seen dates; can surface an old subdomain no certificate/archive-based source ever caught, or a "
        "stale DNS record worth checking for takeover. Requires a free OTX API key (Settings -> Tool API Keys) — "
        "returns a clear error, never a raw 403, when none is configured.",
        _DOMAIN_SCHEMA,
    ),
    "urlscan_search": (
        urlscan_search,
        "Searches urlscan.io's own history of previously-scanned pages for a domain — real URLs/IPs/ASNs actually "
        "seen live at scan time, a different signal than a certificate/archive-based subdomain source. Works with "
        "no key at all (shared public rate limit); a free key (Settings -> Tool API Keys) raises that limit.",
        _DOMAIN_SCHEMA,
    ),
    "xposedornot_check": (
        xposedornot_check,
        "Free, keyless breach-exposure lookup for a single email address (XposedOrNot's public API) — flags an "
        "employee/contact email that has appeared in a known data breach, a real credential-stuffing/password-"
        "reuse risk signal. Works with no account or key at all. Pair with hibp_breach_check for a second, "
        "independently-sourced confirmation once an HIBP key is configured.",
        _EMAIL_SCHEMA,
    ),
    "hibp_breach_check": (
        hibp_breach_check,
        "Have I Been Pwned breach-exposure lookup for a single email address — the industry-reference breach-"
        "notification service, carries more external credibility in a report than a lesser-known source alone. "
        "Requires a paid HIBP API key (Settings -> Tool API Keys) — returns a clear error, not a raw 401, when "
        "none is configured. Use xposedornot_check first/instead when no key is set up.",
        _EMAIL_SCHEMA,
    ),
    "hibp_password_check": (
        hibp_password_check,
        "Free, keyless check of whether a specific password has appeared in a known breach corpus (HIBP's "
        "k-anonymity Pwned Passwords API — only the first 5 hex chars of its SHA-1 hash ever leave this machine, "
        "the full password never does). Use this on a discovered/cracked/default credential to turn 'this looks "
        "weak' into 'this exact password is a KNOWN breached password, seen N times' — real, citable proof for a "
        "weak-credential finding. Not a target-facing check at all.",
        _PASSWORD_SCHEMA,
    ),
    "github_code_search": (
        github_code_search,
        "Searches PUBLIC GitHub repositories' own file contents (GitHub's real code-search syntax — in:file, "
        "filename:, org:, extension: — not just a bare keyword) for a target's own leaked keys/hostnames sitting "
        "in a forgotten repo. Requires a GitHub personal access token with ZERO scopes needed (Settings -> Tool "
        "API Keys) — GitHub rejects anonymous code search outright, so this is disabled with a clear error "
        "without one. Rate-limited hard by GitHub itself (10/minute) regardless of token.",
        _GITHUB_CODE_SEARCH_SCHEMA,
    ),
    "subdomain_enum": (
        subdomain_enum,
        "Actively resolves a wordlist of common subdomain prefixes (www, api, admin, staging, vpn, "
        "...) against a base domain via DNS — the active counterpart to crt_sh_lookup's passive "
        "certificate-transparency search. Use this whenever the scope is a wildcard "
        "(a target written as *.example.com) to actually find what's under it, not just the apex.",
        _DOMAIN_SCHEMA,
    ),
    "dork_search": (
        dork_search_native,
        "Dork Engine: builds a search-engine dork or third-party OSINT lookup for a target from a "
        "curated catalog (agent/tools/dork_engine.py), or dispatches to one of ASRA's own passive "
        "recon tools (crt.sh/Wayback/Common Crawl/WHOIS/DNS/OTX/urlscan/security-headers) under the "
        "same catalog. A search_lead/external_link/direct_url category returns status=\"lead\" (a "
        "constructed query/URL, NOT fetched here — most search engines CAPTCHA-gate automated "
        "traffic) for you to follow up with web_fetch/browser_navigate yourself if you choose to, or "
        "to hand the operator; a native_tool category actually runs and returns real results.",
        _DORK_SEARCH_SCHEMA,
    ),
}
_NATIVE_SCAN_TOOLS = {
    "http_request": (
        http_request,
        "Makes a GET request to a URL and returns status code, security headers, and a body preview.",
        _HTTP_REQUEST_SCHEMA,
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
    "api_schema_discovery": (
        api_schema_discovery,
        "Checks common GraphQL/OpenAPI paths for a base URL — a live GraphQL introspection query "
        "or an exposed swagger/openapi spec leaks the entire real API surface (every mutation, "
        "type, field, endpoint) at once, instead of guessing routes one at a time. Each GraphQL "
        "endpoint's queryable_fields/mutations (name + arg names) is real material for building a "
        "targeted graphql_authz_probe/graphql_batching_probe call — read it before writing a query by hand.",
        _URL_TARGET_SCHEMA,
    ),
    "cors_check": (
        cors_check,
        "Deterministic CORS boundary test: fires the same request with a same-domain-suffix "
        "Origin and with a completely unrelated Origin, and reports which ones actually got "
        "reflected in Access-Control-Allow-Origin. Call this before describing any CORS finding "
        "as 'reflects any origin' — reflecting only the same-suffix origin is a narrower, often "
        "intentional pattern, and record_finding will reject 'qualifying' for a host this "
        "already showed that pattern for.",
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
    "web_fetch": (
        web_fetch,
        "Reads a page from the general internet as plain readable text (title + extracted body) -- "
        "a CVE advisory, GitHub PoC/issue, vendor bulletin, security write-up. Use this on "
        "cve_lookup's own reference URLs, or any other research link, to actually read what it "
        "says instead of guessing from the CVE ID/title alone. Never point this at the assessment "
        "target itself -- use http_request for that.",
        _WEB_FETCH_SCHEMA,
    ),
    "view_source": (
        view_source,
        "Fetches a page's raw HTML and extracts comments, hidden inputs, script/link paths, and meta tags — good for finding forgotten endpoints/notes.",
        _URL_TARGET_SCHEMA,
    ),
    "js_bundle_scan": (
        js_bundle_scan,
        "Fetches a JS file (e.g. one of view_source's own script_src results) and scans it for "
        "endpoint-shaped string literals and a small set of well-known secret-key formats (name "
        "only, never the matched text — but each match's own character offset into the file is "
        "returned in secret_pattern_offsets, so you can aim a follow-up fetch at roughly the right "
        "place in a large bundle instead of only seeing the first couple thousand characters). If a "
        ".map sourcemap is exposed, also fetches and scans ITS content the same way "
        "(sourcemap_secret_patterns_matched / sourcemap_secret_pattern_offsets) — a sourcemap "
        "commonly contains the full unminified original source, a more likely place for a real "
        "secret to actually appear than the minified bundle itself. SPA bundles hide real API "
        "routes no HTML page ever links to as text.",
        _URL_TARGET_SCHEMA,
    ),
    "oob_generate": (
        oob_generate,
        "Registers a real out-of-band (OOB) interaction domain (via interactsh) and returns it. Inject "
        "the returned domain into a payload for a class of finding no other tool here can confirm at "
        "all: blind SSRF (a URL/webhook/callback/import-from-url parameter), blind XSS (a payload that "
        "fires somewhere you can't see the response, e.g. an admin-reviewed field), blind command or "
        "XXE injection (an out-of-band DNS/HTTP fetch as the proof, e.g. `curl <domain>` or an XXE "
        "external entity pointing at it). Call oob_poll with the same token afterward — a real hit "
        "there is hard, remote_direct proof, not an inference.",
        {"type": "object", "properties": {}},
    ),
    "oob_poll": (
        oob_poll,
        "Checks a token from a prior oob_generate call for any real DNS/HTTP interaction logged against "
        "it since then. Call this only after whatever used the payload had a real chance to actually "
        "run — not immediately after oob_generate.",
        {
            "type": "object",
            "properties": {"token": {"type": "string", "description": "The token returned by oob_generate"}},
            "required": ["token"],
        },
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

# category=("recon", "scan"), not the _NATIVE_RECON_TOOLS loop above (which hardcodes category=
# "recon" for every entry) -- IP geolocation/ASN attribution is exactly as useful while reasoning
# about an attack surface during Analyze (get_tools_by_category("scan")) as it is during Recon
# itself, same "genuinely useful in more than one phase" case http_request already is (see
# ToolSpec.category's own docstring). Also feeds agent/core.py's own automatic _update_ip_intel
# enrichment hook directly (called as a plain function there, not through this registration at
# all) — this ToolSpec only governs the MODEL's own ability to call it explicitly on demand.
register_tool(
    ToolSpec(
        name="geoip_lookup",
        category=("recon", "scan"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=geoip_lookup,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Free, keyless IP geolocation + ASN/ISP/org attribution (ip-api.com) — country, city, "
            "lat/lon, and the ISP/org/AS-number that IP is actually registered to. The single "
            "best passive signal for telling a CDN/WAF edge node or generic cloud/shared hosting "
            "apart from a target's own likely origin server — most of this session's own resolved "
            "IPs are already enriched automatically (Recon tab's Geopolitical Map), call this "
            "directly for one you want to check on demand (e.g. an IP found mid-Analyze that "
            "wasn't part of the original recon sweep)."
        ),
        parameters_schema=_IP_SCHEMA,
    )
)

# Read-only verification tools genuinely useful during Exploit too, not just Analyze — listed
# here instead of duplicating each ToolSpec under a second name (ToolSpec.category, a tuple for
# exactly this case). Real incident this exists because of: exploit-phase turns that stalled on
# "I have no HTTP request tool to check X" / "no verification tool available" when the identical
# tool already existed one phase over. Deliberately narrow — a handful of proven-needed tools, not
# the whole scan toolset, to keep Exploit's own tool list focused on what it actually needs.
#
# Widened by a real log-review audit: findings whose whole class is "missing header"/"exposed
# config"/"weak TLS"/"known-CVE version"-shaped had NO way to be re-confirmed by Exploit at all —
# record_exploit_decision's own action enum only offers "skipped_no_suitable_tool" for exactly this
# case, and the model correctly took it every time (EXPLOIT_PROMPT explicitly told it to). Real,
# confirmed incident this fixes (see the same audit that added cors_credentialed_check to `exploit`
# below): three CORS findings stayed "qualifying" because no tool could re-check the claim during
# Exploit — the fix there was adding a matching confirmation tool to this set, just never extended
# to these sibling read-only checks. Deliberately NOT widened with the heavier discovery/enumeration
# tools (nuclei/nikto/wpscan/whatweb/ffuf/arjun) — those find NEW things, they don't confirm a
# specific already-recorded finding, so Exploit's own toolset stays focused on confirmation.
_ALSO_EXPLOIT_CATEGORY = {
    "http_request", "oob_generate", "oob_poll", "tcp_port_check", "web_fetch",
    "cors_check", "ssl_cert_info", "security_headers_audit", "cve_lookup", "favicon_hash",
    "jwt_decode", "js_bundle_scan", "api_schema_discovery", "view_source", "common_exposure_scan",
}

for _name, (_fn, _description, _schema) in _NATIVE_SCAN_TOOLS.items():
    register_tool(
        ToolSpec(
            name=_name,
            category=("scan", "exploit") if _name in _ALSO_EXPLOIT_CATEGORY else "scan",
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
            "Tries default username/password pairs against a login endpoint (POST JSON). Pass 'vendor' when "
            "nmap -sV/whatweb/a CVE lookup has already identified what's actually running (e.g. a Hikvision "
            "camera, a Tomcat manager, a Jenkins/Grafana/RabbitMQ dashboard) to try that vendor's own real "
            "known defaults first (cirt.net's public Default Password Database, 531 vendors), before the "
            "generic list. Requires the target to be in the exploitation allowlist and the session to be "
            "human-approved."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Login endpoint URL"},
                "username_field": {"type": "string", "description": "JSON field name for the username, default 'email'"},
                "password_field": {"type": "string", "description": "JSON field name for the password, default 'password'"},
                "vendor": {
                    "type": "string",
                    "description": (
                        "Optional product/vendor name to try real known defaults for first (e.g. 'hikvision', "
                        "'tomcat', 'jenkins', 'mikrotik', 'grafana', 'cisco') — matched case/punctuation-"
                        "insensitively against cirt.net's own vendor names, with a substring fallback. Omit to "
                        "only try the generic list."
                    ),
                },
            },
            "required": ["target"],
        },
    )
)

# Third-party mail providers, never the assessment target -- not exploit-tier, not gated by the
# exploitation allowlist, same posture as crt_sh_lookup/hibp_breach_check. Registered in the
# "exploit" category anyway (not "recon") since the only real reason to call these is right before/
# after web_self_register, which lives there.
register_tool(
    ToolSpec(
        name="temp_email_create",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=temp_email_create,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Creates a real, receivable disposable email inbox -- for a signup flow "
            "(web_self_register) that requires a working email address to complete "
            "verification, when no configured identity/real address is available. Tries several "
            "independent free providers in order and returns the first that works; poll "
            "temp_email_check_inbox afterward for the verification message it actually receives. "
            "If every provider fails, the result names a browser_navigate-driven fallback (open a "
            "temp-mail site's own web UI directly) instead of a dead end."
        ),
        parameters_schema={"type": "object", "properties": {}},
    )
)

register_tool(
    ToolSpec(
        name="temp_email_check_inbox",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=temp_email_check_inbox,
        requires_allowed_target=False,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Polls a disposable inbox created by temp_email_create for real received messages -- "
            "returns each one's real sender/subject/plain-text body so you can find and quote a "
            "verification link/code directly from actual evidence, never invent one. Fine to call "
            "more than once while waiting for a signup's verification email to arrive."
        ),
        parameters_schema={
            "type": "object",
            "properties": {"email": {"type": "string", "description": "Which temp_email_create address to check -- omit to use the most recently created one"}},
        },
    )
)

# Same exploit-tier gating as default_creds_check just above (a real, persistent write against the
# target's own infrastructure, not passive recon) -- for the opposite case: no existing account to
# try defaults against or crack, just create a fresh one via the target's own signup flow.
register_tool(
    ToolSpec(
        name="web_self_register",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=web_self_register,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Attempts a real, single-shot self-registration against a target's own signup/"
            "registration form — for authenticated testing when no existing account is available "
            "at all, and the program's own rules allow creating one. Structured fields only "
            "(username_field/password_field/registration_path/success_string or failure_string), "
            "never raw request-building — same contract as web_login_bruteforce_start. On success "
            "the new account is immediately usable via authenticated_request/idor_probe's own "
            "identity= lookup (check this call's own result / this session's asset_graph "
            "credentials for the assigned identity_name). No CAPTCHA/email-verification/OTP "
            "handling — a signup form gated behind either genuinely can't be completed this way, "
            "and this reports an honest no-match result instead of guessing. Pass login_path when "
            "the signup flow doesn't auto-login the new account, so this can perform one real "
            "login POST right after registering. Requires the target to be in the exploitation "
            "allowlist and the session to be human-approved, same as default_creds_check/msf/sqlmap."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Base URL (scheme://host[:port]) the signup form lives on"},
                "registration_path": {"type": "string", "description": "The page the signup form posts to, e.g. /register or /signup"},
                "login_path": {"type": "string", "description": "Optional — the login endpoint, e.g. /login. When given, this logs in as the just-created account right after a successful registration so the returned identity is already authenticated."},
                "username": {"type": "string", "description": "Username to register — omit to auto-generate one (asra_<random>)"},
                "password": {"type": "string", "description": "Password to register — omit to auto-generate a strong one"},
                "email": {"type": "string", "description": "Email to register — omit to auto-generate one, only if email_field is also given"},
                "username_field": {"type": "string", "description": "Form field name for the username — omit to use 'username'"},
                "password_field": {"type": "string", "description": "Form field name for the password — omit to use 'password'"},
                "confirm_password_field": {"type": "string", "description": "Form field name for a password-confirmation field, if the form has one"},
                "email_field": {"type": "string", "description": "Form field name for the email, if the form requires one"},
                "extra_fields": {"type": "object", "description": "Any other static form fields the signup page requires (e.g. a terms-of-service checkbox), as {field_name: value}"},
                "csrf_field": {"type": "string", "description": "Form field name for the CSRF token, if it doesn't match a common convention this tool already recognizes"},
                "failure_string": {"type": "string", "description": "A literal substring that appears in the response ONLY on a failed registration — required unless success_string is given"},
                "success_string": {"type": "string", "description": "A literal substring that appears in the response ONLY on a successful registration — required unless failure_string is given"},
            },
            "required": ["target", "registration_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="cloud_bucket_scan",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=cloud_bucket_scan,
        requires_allowed_target=True,
        installed_by_default=True,
        description=(
            "Active anonymous read/write permission probe for an AWS S3 / GCS / Azure Blob bucket or container "
            "(CloudSpecter-style: actually connects and tests, not just a dork lead). Reports a severity rating "
            "(CRITICAL: anonymous read+write, HIGH: anonymous read only, INFO: not readable) — a public, "
            "anonymously-writable bucket is a common, well-paid bug-bounty finding on its own. test_write=true "
            "performs a real (immediately cleaned-up) write against the target's own infrastructure. Requires "
            "the target to be in the exploitation allowlist and the session to be human-approved."
        ),
        parameters_schema=_CLOUD_BUCKET_SCHEMA,
    )
)

register_tool(
    ToolSpec(
        name="authenticated_request",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=authenticated_request,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Makes an HTTP request as one of this project's configured identities (user_a/user_b), "
            "reusing that identity's logged-in session/cookie jar across calls. The tool for testing "
            "authenticated endpoints and IDOR/broken access control specifically: act as one identity "
            "to create or note a resource's real ID, then request that SAME id as the OTHER identity — "
            "if it can read or modify it, that's confirmed, remote_direct proof. Only usable for a "
            "project that actually has identities configured (New Project form); returns an error "
            "naming the missing identity otherwise. Requires the target to be in the exploitation "
            "allowlist and the session to be human-approved, like exploit/sqlmap — but calling this "
            "more than once for the same finding is expected (a real IDOR comparison needs at least "
            "two calls), unlike those tools."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "identity": {"type": "string", "description": "Which configured identity to act as, e.g. 'user_a' or 'user_b'"},
                "target": {"type": "string", "description": "Full request URL, including path and query string"},
                "method": {"type": "string", "description": "HTTP method, default GET"},
                "data": {"type": "string", "description": "Request body, if any"},
                "headers": {
                    "type": "object",
                    "description": "Extra request headers as key/value pairs",
                    "additionalProperties": {"type": "string"},
                },
            },
            "required": ["identity", "target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="cors_credentialed_check",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=cors_credentialed_check,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "The real, deterministic proof step for a CORS finding cors_check already flagged "
            "verdict='reflects_any_origin' AND allows_credentials=True for: replays the exact "
            "cross-origin request a victim's browser would make (the same unrelated test Origin "
            "cors_check uses) with `identity`'s REAL logged-in session attached, and reports "
            "whether the real response actually grants a credentialed cross-origin read — no "
            "headless browser needed, that decision is a deterministic function of the response's "
            "own headers. confirmed_credentialed_cross_origin_read=True with a real body_preview "
            "is concrete PoC evidence, not an inference. Calling this before cors_check confirmed "
            "both prerequisites for the same host can only ever come back False — check its "
            "verdict/allows_credentials first. Only usable for a project that actually has "
            "identities configured (New Project form); returns an error naming the missing "
            "identity otherwise, same as authenticated_request. Requires the target to be in the "
            "exploitation allowlist and the session to be human-approved, like authenticated_request "
            "— this is a real request using a real test account's real session, not a passive probe."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Same URL cors_check was called with — the CORS-vulnerable endpoint"},
                "identity": {"type": "string", "description": "Which configured identity to act as, e.g. 'user_a' or 'user_b'"},
            },
            "required": ["target", "identity"],
        },
    )
)

register_tool(
    ToolSpec(
        name="authenticated_crawl",
        # Widened into Exploit's own toolset too, same reasoning as _ALSO_EXPLOIT_CATEGORY just
        # above (registered separately here since this ToolSpec isn't built from the
        # _NATIVE_SCAN_TOOLS loop that constant otherwise drives) — Exploit re-confirming a
        # finding needs the same crawl capability Analyze used to first discover it.
        category=("scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=authenticated_crawl,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Logs in as a configured identity (user_a/user_b) and walks same-origin links/forms "
            "breadth-first from a starting URL, returning real observed endpoints with real status "
            "codes — use this before guessing paths like /admin or /api, and specifically to find "
            "numeric-ID-bearing routes (an order, a profile, an inventory item) to hand to "
            "idor_probe or authenticated_request next. Omit identity to crawl anonymously."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "identity": {"type": "string", "description": "Configured identity to crawl as, e.g. 'user_a'; omit to crawl unauthenticated"},
                "start_url": {"type": "string", "description": "URL to start crawling from"},
                "max_pages": {"type": "integer", "description": "Max pages to visit, default 20, hard-capped at 40"},
            },
            "required": ["start_url"],
        },
    )
)

register_tool(
    ToolSpec(
        name="idor_probe",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=idor_probe,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Requests the exact same resource URL as two identities in one call and returns a "
            "deterministic comparison (status codes, body length, body-similarity ratio, and a "
            "likely_idor verdict) instead of requiring two separate authenticated_request calls "
            "compared by eye. Omit identity_b to compare identity_a against a fully unauthenticated "
            "request. Requires the target to be in the exploitation allowlist and the session to be "
            "human-approved, like authenticated_request — and is exempt from the one-shot-attempt "
            "cap for the same reason (a real IDOR comparison needs at least one full call)."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Full resource URL to request as both identities"},
                "identity_a": {"type": "string", "description": "First configured identity, e.g. 'user_a'"},
                "identity_b": {"type": "string", "description": "Second configured identity, e.g. 'user_b'; omit to compare against unauthenticated"},
            },
            "required": ["target", "identity_a"],
        },
    )
)

register_tool(
    ToolSpec(
        name="authz_diff_sweep",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=authz_diff_sweep,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Bulk IDOR/broken-access-control sweep over traffic ALREADY captured this session (the "
            "Proxy's Site Map) — the batch counterpart to idor_probe. Replays every already-observed, "
            "resource-shaped (numeric/UUID id in path or query), authenticated request as identity_b "
            "in one call and diffs each against the response already captured for it, instead of the "
            "model picking one URL at a time. Covers real endpoints authenticated_crawl's HTML-link "
            "walk cannot see at all — a single-page app's own fetch/XHR API calls, which only ever "
            "show up in real captured network traffic. Only replays GET/HEAD by default — pass "
            "include_mutating=True to also replay state-changing methods (risks a duplicate "
            "real-world side effect, e.g. a second purchase/delete, so off unless deliberately "
            "wanted). Every swept entry gets a compact row (status codes, similarity, likely_idor); "
            "a full body_preview is only attached for entries actually flagged likely_idor, so "
            "raising max_candidates to sweep more of a large site map costs time, not context. "
            "Requires the target to be in the exploitation allowlist and the session to be "
            "human-approved, same as idor_probe — and each individual candidate URL pulled from the "
            "Site Map is checked against that same allowlist again before being replayed, so "
            "out-of-scope captured traffic (a third-party asset, a discovered-but-not-approved host) "
            "is skipped, not swept."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "The project's target/domain this sweep covers — must be in the exploitation allowlist, same as idor_probe's target"},
                "identity_b": {"type": "string", "description": "Configured identity to replay every candidate request as, e.g. 'user_b'"},
                "include_mutating": {"type": "boolean", "description": "Also replay POST/PUT/DELETE/PATCH candidates, not just GET/HEAD. Default false."},
                "max_candidates": {"type": "integer", "description": "Max captured entries to actually replay in this call, default 50, hard-capped at 150"},
            },
            "required": ["target", "identity_b"],
        },
    )
)

register_tool(
    ToolSpec(
        name="graphql_authz_probe",
        category=("scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=graphql_authz_probe,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Fires the SAME GraphQL query/mutation you already wrote as two identities in one call "
            "(GraphQL-aware idor_probe — reads the response's own errors/data, never status code "
            "alone, since GraphQL almost always returns 200 whether an operation was denied or not). "
            "Covers two classes with the same mechanism: a mutation/query that should require an "
            "elevated role (field-level broken access control), or a query with a nested selection "
            "keyed by another identity's ID, e.g. 'user(id: 5) { orders { total } }' (nested-query "
            "IDOR). Build the query from api_schema_discovery's queryable_fields/mutations, not a "
            "guess. Omit identity_b to compare identity_a against a fully unauthenticated request."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "The GraphQL endpoint URL (e.g. https://api.example.com/graphql)"},
                "query": {"type": "string", "description": "The full GraphQL query/mutation document to send as both identities, e.g. '{ user(id: 5) { orders { total } } }'"},
                "variables": {"type": "object", "description": "Optional GraphQL variables object for the query above"},
                "identity_a": {"type": "string", "description": "First configured identity, e.g. 'user_a'"},
                "identity_b": {"type": "string", "description": "Second configured identity, e.g. 'user_b'; omit to compare against unauthenticated"},
            },
            "required": ["target", "query", "identity_a"],
        },
    )
)

register_tool(
    ToolSpec(
        name="graphql_batching_probe",
        category=("scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=graphql_batching_probe,
        requires_allowed_target=True,
        installed_by_default=True,
        allows_repeated_attempts=True,
        description=(
            "Builds ONE GraphQL request containing several ALIASED copies of the same query/"
            "mutation field call and fires it as a SINGLE HTTP request — real evidence for whether "
            "a per-request rate limiter (a login form, coupon redemption, an OTP check) can be "
            "bypassed by batching many operations into one call. count is capped at 10 (same "
            "concurrent-request DoS-safety limit as a custom_exploit_run race-condition test) — one "
            "real request either way, never a flood. Build field_name/arguments from "
            "api_schema_discovery's queryable_fields/mutations, not a guess."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "The GraphQL endpoint URL"},
                "operation_type": {"type": "string", "enum": ["query", "mutation"], "description": "Defaults to 'mutation' — use 'query' for a read-only field"},
                "field_name": {"type": "string", "description": "The query/mutation field to call repeatedly, e.g. 'login' or 'redeemCoupon'"},
                "arguments": {"type": "object", "description": "Scalar (string/number/boolean/null) arguments for the field, e.g. {\"username\": \"admin\", \"password\": \"x\"}"},
                "selection": {"type": "string", "description": "What to select back from each call, e.g. 'token' or 'success'. Defaults to '__typename'."},
                "count": {"type": "integer", "description": "How many aliased copies to batch into the one request (1-10, default 5)"},
                "identity": {"type": "string", "description": "Optional configured identity to send the batch as; omit for an unauthenticated request"},
            },
            "required": ["target", "field_name"],
        },
    )
)

# delegate_to_subagent's own conversation loop needs agent.core's RunContext/_run_llm_tool_loop/
# get_provider -- but agent.core imports this whole package (agent.tools) at its own module level
# to populate TOOL_REGISTRY, so a module-top-level "from agent.core import ..." here would be a
# real circular import (agent.tools -> agent.core -> agent.tools, mid-load). In practice this
# native_function is never actually called: agent/core.py's _dispatch_tool bypasses the generic
# run_tool/asyncio.to_thread path entirely for this one tool name (asyncio.create_task() needs a
# running event loop in the calling thread, which a plain to_thread-dispatched function never
# has) and calls agent.core._delegate_to_subagent_impl directly instead. Kept as a real, working
# fallback rather than a bare stub in case that bypass check is ever itself the thing that's
# broken -- a clear error beats a silent no-op or a crash.
def _delegate_to_subagent_native(params: dict) -> dict:
    return {
        "status": "error",
        "error": "delegate_to_subagent must be dispatched via agent.core._dispatch_tool's async bypass, not the generic native-tool path",
    }


# Real work is a genuinely concurrent asyncio.Task (a subagent's own _run_llm_tool_loop
# conversation), not a subprocess -- see agent/tools/subagent_tasks.py's own module docstring for
# why this needed its own tracking mechanism distinct from agent/tools/background_jobs.py's.
register_tool(
    ToolSpec(
        name="delegate_to_subagent",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_delegate_to_subagent_native,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Hand off a bounded, self-contained sub-task to a pre-configured Subagent while you "
            "keep working on something more important yourself — returns immediately with a "
            "task_id, never blocks. The subagent pushes its own result back into this "
            "conversation automatically once it finishes (you'll see it as a "
            "\"[Subagent '<name>' finished]\" message on your next turn); check_subagent_task is "
            "only a fallback if you want to check sooner or that push somehow didn't happen. Only "
            "available when at least one Subagent is enabled in the Subagents settings tab."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "subagent_name": {"type": "string", "description": "Exact name of an enabled Subagent profile (see the Subagents settings tab)"},
                "task_description": {"type": "string", "description": "A concrete, self-contained sub-task — everything the subagent needs to know, since it has no visibility into your own conversation"},
            },
            "required": ["subagent_name", "task_description"],
        },
    )
)

register_tool(
    ToolSpec(
        name="check_subagent_task",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=check_subagent_task,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Explicit fallback check on a task_id from delegate_to_subagent — you normally don't "
            "need this, since a finished subagent pushes its own result to you automatically. Use "
            "this only if you want to check earlier, or suspect the automatic delivery didn't happen. "
            "If you have no other useful work left and are only waiting on a delegated subagent, do "
            "NOT poll this in a loop — the system automatically waits for every still-running "
            "subagent before the phase actually concludes, at no extra cost to you. Just move on to "
            "wrapping up the phase instead."
        ),
        parameters_schema={
            "type": "object",
            "properties": {"task_id": {"type": "string", "description": "The task_id returned by delegate_to_subagent"}},
            "required": ["task_id"],
        },
    )
)

# check_disclosed_reports's real implementation (agent/tools/bugbounty_import.py's
# check_disclosed_reports) opens a real Playwright browser session -- same "async, needs a real
# event loop, can't go through the generic asyncio.to_thread(run_tool, ...) path" reasoning as
# delegate_to_subagent/browser_* above, plus bugbounty_import.py itself imports FROM agent.core
# (agent.core -> agent.tools -> agent.tools.bugbounty_import -> agent.core would be circular at
# module-load time), so agent/core.py's _dispatch_tool bypass reaches it via a LAZY import inside
# its own function body instead of a module-top-level one. This native_function is never actually
# called in practice -- kept as a real, working fallback rather than a bare stub in case that
# bypass check is ever itself the thing that's broken.
def _check_disclosed_reports_native(params: dict) -> dict:
    return {
        "status": "error",
        "error": "check_disclosed_reports must be dispatched via agent.core._dispatch_tool's async bypass, not the generic native-tool path",
    }


register_tool(
    ToolSpec(
        name="check_disclosed_reports",
        category="exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_check_disclosed_reports_native,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Checks a bug-bounty program's own PUBLIC disclosed-reports feed (HackerOne Hacktivity, "
            "Bugcrowd CrowdStream, or -- best-effort, sitewide-only -- YesWeHack) for already-disclosed "
            "reports, before you spend real effort confirming a finding that may already be a known, "
            "previously-paid duplicate. program_url is the program's own page (e.g. "
            "https://hackerone.com/<handle> or https://bugcrowd.com/<handle>) — use the exact URL if you "
            "know it (from this session's own goal/custom instructions), otherwise your best guess at "
            "the handle from the target's own name (usually the company/product name) — a wrong guess "
            "just 404s harmlessly, costing nothing but the one check. Returns an already-summarized "
            "list of report titles (\"reports\") plus a \"coverage_note\" on how complete that list is — "
            "read those directly, no need to re-parse the raw page text yourself."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "program_url": {
                    "type": "string",
                    "description": "The bug-bounty program's own HackerOne page URL, e.g. https://hackerone.com/acme",
                },
            },
            "required": ["program_url"],
        },
    )
)

# A delegated subagent's own terminal_tool (agent/core.py's _delegate_to_subagent_impl) — same
# "one Category value nothing else's get_tools_by_category picks up" reasoning as
# record_reverification_result/record_chain_result above. Never appended to a normal phase's own
# tool_specs list; only ever present in a subagent's own, explicitly-built tool list.
register_tool(
    ToolSpec(
        name="report_subagent_result",
        category="post_exploit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=report_subagent_result,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Call this with your final answer once you're done with the task you were delegated — "
            "the ONLY way to end your turn. Never describe your conclusion as plain text instead."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "summary": {"type": "string", "description": "Concrete, specific account of what you actually found/did — this is what the main agent sees"},
                "details": {"type": "string", "description": "Optional: longer evidence/detail the main agent can ask about later"},
            },
            "required": ["summary"],
        },
    )
)

# The 9 browser_* tools -- a real, JS-executing headless Chromium (agent/tools/browser_manager.py)
# instead of the raw-HTTP-only view every other tool is limited to. Registered like
# delegate_to_subagent above (native_function is a bypass stub, real dispatch happens in
# agent/core.py's _dispatch_tool via _dispatch_browser_tool, never through the normal
# asyncio.to_thread(run_tool, ...) path) because a browser session must persist ACROSS separate
# LLM tool calls (navigate now, click later, read state later) -- see browser_manager.py's own
# module docstring for the full reasoning.
#
# category=("recon", "scan", "exploit"), same multi-category precedent as http_request's own
# registration below -- genuinely useful in all three: Recon needs it for SPA-rendered links/API
# routes invisible to subdomain_enum/wayback_urls (both httpx-based, blind to client-side
# routing); Analyze needs it for DOM-XSS/client-rendered-form detection; Exploit needs it to
# actually drive a login flow or trigger a live PoC. requires_allowed_target=True on all 9 -- NOT
# for the exploitation-allowlist check (agent/tools/runner.py's _check_guardrail, which only runs
# for tools dispatched through the normal run_tool() path these bypass entirely, same as
# delegate_to_subagent's own requires_allowed_target=False for the identical reason) but for the
# separate, real effect this flag has inside Exploit/hypothesis_verification/chain's own per-tool
# executors (agent/core.py, "if not spec.requires_allowed_target: skip the approval wait"):
# interactive browser actions taken during an actual exploitation attempt should require the same
# human-approval gate every other exploit-tier tool already does. Harmless during Recon/Analyze,
# which never consult this flag at all. allows_repeated_attempts=True on all 9 is NOT optional --
# Exploit's per-finding one-shot-attempt cap (agent/core.py's _run_exploit_for_finding) would
# otherwise silently skip every browser_click/fill/... call after the first browser_navigate for a
# given finding, since browser interaction is inherently multi-call by nature.
#
# Only browser_navigate's schema names a "target" field -- this is what gets it
# agent/core.py's _out_of_scope_target/_loopback_or_link_local_target coverage (_run_tool_with_retry
# checks any "target"-shaped argument unconditionally, independent of requires_allowed_target) for
# the INITIAL navigation. The other 8 tools act on the already-open, already-once-validated page
# and take no target argument at all; browser_manager.py's own post-action page.url re-check is
# what protects against the page itself drifting out of scope mid-session (a redirect, a clicked
# link) -- a risk class no existing stateless tool has, since none of them persist a page across
# calls.
_BROWSER_RISK_NOTE = (
    "Real headless Chromium, real JS execution -- not a simulation. Downloads are disabled, JS "
    "dialogs (alert/confirm/prompt) are captured as evidence then always auto-dismissed, popups/"
    "new tabs are auto-closed and logged rather than tracked. If Chromium isn't installed on this "
    "machine, fall back to http_request/view_source instead -- this only adds JS-rendering "
    "capability, it doesn't replace them."
)
_BROWSER_SNAPSHOT_NOTE = (
    "Every call returns a fresh ref-addressable snapshot (e.g. `button \"Login\" [ref=e3]`) of the "
    "page's current interactive elements -- refs from an EARLIER snapshot are invalid the instant "
    "anything could have changed the page; always use the ref from the most recent result, never "
    "one from a prior call."
)
# Real, confirmed incident this note exists for: landing on a Cloudflare Turnstile interstitial
# (a real HackerOne rescan session, usr_b0ea17, 2026-08-16), the model never once called
# browser_snapshot/browser_click on the visible "Verify you are human" checkbox -- it reasoned
# "bypassing the Cloudflare challenge... this toolset cannot do" and reported every finding behind
# that host inconclusive, an assumption it never actually tested even though browser_click was
# available in its own toolset the whole time. Nothing anywhere told it to try.
_BROWSER_CHALLENGE_NOTE = (
    "If the page you land on is a Cloudflare/bot-challenge interstitial (a 'Just a moment...' page, "
    "a visible 'Verify you are human' Turnstile checkbox) instead of the real target, do not "
    "conclude the target is unreachable from that alone -- call browser_snapshot to see whether a "
    "checkbox/button is actually present, browser_click it, then browser_snapshot again a few "
    "seconds later to see whether the real page loaded. This sometimes clears the challenge outright "
    "and sometimes doesn't (Turnstile scores browser behavior/fingerprint, not just the click) -- "
    "either way, only report the target as blocked/inconclusive after actually trying this, not "
    "before."
)

register_tool(
    ToolSpec(
        name="browser_navigate",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_navigate_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description=(
            "Opens (or reuses) this session's own headless-browser page and navigates it to a URL "
            "a real browser would render -- the only way to see DOM-rendered content, client-side "
            "routing, and the real XHR/fetch calls a JS app (Angular/React/Vue) makes at runtime, "
            "all invisible to http_request's raw-HTML-only view. Returns the page's real HTTP "
            "status, title, and a snapshot of its interactive elements. " + _BROWSER_RISK_NOTE + " " + _BROWSER_SNAPSHOT_NOTE
            + " " + _BROWSER_CHALLENGE_NOTE + " Pass identity to browse as one of this project's configured "
            "identities (user_a/user_b) instead of anonymously — this session's browser then carries that "
            "identity's real logged-in cookies/Authorization header, the same login authenticated_request/"
            "idor_probe already use, letting you walk a real multi-step UI workflow (clicks/forms, not just a "
            "known URL) as one identity, then again with the other identity, and diff_requests the two "
            "captured requests — this is how to test role-based/BOLA access control for actions that only "
            "exist behind a JS-driven workflow, not a plain link. Switching identity replaces this session's "
            "cookies/headers entirely (never mixes two identities at once)."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "The full URL to navigate to — checked against this project's scope the same way every other target-taking tool is"},
                "identity": {"type": "string", "description": "Optional — configured identity to browse as, e.g. 'user_a'; omit to keep this session's current identity (or stay anonymous if none was ever set)"},
                "wait_until": {
                    "type": "string", "enum": ["load", "domcontentloaded", "networkidle"], "default": "domcontentloaded",
                    "description": "When to consider navigation finished. Default 'domcontentloaded' — the DOM is ready, which is all a snapshot/interaction needs. 'load' can hang for the full timeout on a Cloudflare/bot-challenge-fronted site (confirmed live: platform.openai.com and openai.com's own apex both never fire a 'load' event, only 'domcontentloaded') — only ask for it if you specifically need every subresource finished. 'networkidle' waits for the SPA's own background XHR/fetch calls to settle, useful when those calls ARE what you're trying to observe.",
                },
            },
            "required": ["target"],
        },
    )
)

register_tool(
    ToolSpec(
        name="browser_snapshot",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_snapshot_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description=(
            "Re-reads the CURRENT state of this session's already-open browser page -- no "
            "navigation, just a fresh look. Use this after something might have changed the page "
            "without a full navigation (a client-side route change, an XHR response rendering new "
            "content) instead of assuming an earlier snapshot is still accurate. " + _BROWSER_SNAPSHOT_NOTE
        ),
        parameters_schema={"type": "object", "properties": {}},
    )
)

register_tool(
    ToolSpec(
        name="browser_click",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_click_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description="Clicks an interactive element from the most recent snapshot, by its ref. " + _BROWSER_SNAPSHOT_NOTE,
        parameters_schema={
            "type": "object",
            "properties": {"ref": {"type": "string", "description": "The element's ref from the most recent browser_navigate/browser_snapshot/browser_* result, e.g. 'e3'"}},
            "required": ["ref"],
        },
    )
)

register_tool(
    ToolSpec(
        name="browser_fill",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_fill_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description="Types text into a textbox/textarea from the most recent snapshot, by its ref (replaces its current value). " + _BROWSER_SNAPSHOT_NOTE,
        parameters_schema={
            "type": "object",
            "properties": {
                "ref": {"type": "string", "description": "The input element's ref from the most recent snapshot"},
                "text": {"type": "string", "description": "The text to type into it"},
            },
            "required": ["ref", "text"],
        },
    )
)

register_tool(
    ToolSpec(
        name="browser_select_option",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_select_option_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description="Picks an option in a <select> dropdown from the most recent snapshot, by the select element's ref and the option's value. " + _BROWSER_SNAPSHOT_NOTE,
        parameters_schema={
            "type": "object",
            "properties": {
                "ref": {"type": "string", "description": "The <select> element's ref from the most recent snapshot"},
                "value": {"type": "string", "description": "The option's value attribute to select"},
            },
            "required": ["ref", "value"],
        },
    )
)

register_tool(
    ToolSpec(
        name="browser_press_key",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_press_key_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description="Presses a single key on this session's already-open page (whatever currently has focus) -- e.g. 'Enter' to submit a form, 'Escape', 'Tab'. " + _BROWSER_SNAPSHOT_NOTE,
        parameters_schema={
            "type": "object",
            "properties": {"key": {"type": "string", "description": "Key name, e.g. 'Enter', 'Escape', 'Tab', 'ArrowDown'"}},
            "required": ["key"],
        },
    )
)

register_tool(
    ToolSpec(
        name="browser_evaluate",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_evaluate_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description=(
            "Runs arbitrary JavaScript in this session's already-open page and returns the result "
            "(JSON-serialized; anything that can't be serialized comes back as its string form) -- "
            "same trust tier as custom_exploit_run, real code with real effects in the page. Use "
            "this to inspect client-side state a snapshot can't show (window globals, "
            "localStorage/sessionStorage/cookies via document.cookie, exposed debug flags) or to "
            "actively test for DOM-based XSS/prototype pollution by triggering a sink directly. " + _BROWSER_SNAPSHOT_NOTE
        ),
        parameters_schema={
            "type": "object",
            "properties": {"expression": {"type": "string", "description": "A JavaScript expression or statement to evaluate in the page's own context"}},
            "required": ["expression"],
        },
    )
)

register_tool(
    ToolSpec(
        name="browser_go_back",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_go_back_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description="Navigates this session's browser page back one step in its own history. " + _BROWSER_SNAPSHOT_NOTE,
        parameters_schema={"type": "object", "properties": {}},
    )
)

register_tool(
    ToolSpec(
        name="browser_close_session",
        category=("recon", "scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_browser_close_session_native,
        requires_allowed_target=False,
        installed_by_default=True,
        availability_check=_chromium_installed,
        description=(
            "Explicitly closes this session's browser page/context now, freeing its slot for "
            "another session -- optional; it's also closed automatically once this scan finishes "
            "(or after a period of inactivity), this just does it early when you're genuinely done "
            "with it before then."
        ),
        parameters_schema={"type": "object", "properties": {}},
    )
)

# Payload/signature-level WAF evasion -- see agent/tools/waf_evasion.py's own module docstring for
# the full reasoning (a real session, usr_136b4c: a WAF blocked every injection attempt outright and
# nothing tried a bypass before giving up). requires_allowed_target=True is the same real gate
# sqlmap/authenticated_request already get (agent/tools/runner.py's allowlist check +
# agent/core.py's exploit-approval wait) -- no need for anything stricter than sqlmap gets for a
# tool that sends far fewer real requests per call than sqlmap's own single run does.
register_tool(
    ToolSpec(
        name="waf_evasion_probe",
        category=("scan", "exploit"),
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=waf_evasion_probe,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        description=(
            "Sends a SMALL, FIXED set of encoding/case/whitespace/HTTP-shape mutations of ONE "
            "payload (~12 requests total, ~400ms apart -- deliberately not a fuzzer) and reports "
            "which mutation(s) got a materially different response than a clean baseline, as leads "
            "for a real confirmation with sqlmap/dalfox/http_request -- never itself a confirmed "
            "finding. Closes the CHEAP/COMMON detection tier only: naive signature/keyword WAF "
            "rules and naively-trusted proxy headers, not a guarantee against a determined system "
            "(Cloudflare Turnstile-grade behavioral/IP-reputation checks are a separate, harder "
            "problem this doesn't address). Check recon_result['protections'] first -- only worth "
            "trying once a WAF/rate-limit is actually known to be blocking real attempts. Requires "
            "the target to be in the exploitation allowlist and the session to be human-approved, "
            "same as sqlmap."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Full base URL, including path — the injection point's own param is added separately, not embedded here"},
                "param_name": {"type": "string", "description": "Query/body parameter name to inject the payload into"},
                "payload": {"type": "string", "description": "Raw payload value being tested (e.g. an XSS, SQLi, or command-injection string) — mutated automatically, give the plain unencoded form"},
                "method": {"type": "string", "description": "GET or POST for the payload's own primary request (default GET) — one mutation automatically also tries the opposite method"},
            },
            "required": ["target", "param_name", "payload"],
        },
    )
)

# Cross-session asset baseline diff -- see agent/tools/asset_baseline_store.py's own module
# docstring for the full reasoning (the highest-leverage lead in real bug-bounty hunting is usually
# what's NEW since the last scan of a target, not deeper analysis of something scanned repeatedly
# by everyone). category="recon" (not "scan"/"exploit"): this never touches the real target at all,
# it only diffs strings the model already gathered against a local JSON store.
register_tool(
    ToolSpec(
        name="asset_diff_check",
        category="recon",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=asset_diff_check,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Compares a list of assets discovered THIS session (subdomains, open ports/services, "
            "endpoints, GraphQL operations -- any free-form category you choose) against a "
            "persistent, cross-session baseline for this same target, then updates that baseline to "
            "the current list. first_scan=true means there was no prior baseline for this "
            "target+category -- nothing to diff yet, this call just seeds it for next time. "
            "Otherwise new_assets is the freshest attack surface -- a subdomain/port/endpoint that "
            "wasn't there last time is far more likely to still have an unpatched or "
            "not-yet-crowded bug than something scanned repeatedly by everyone since -- call it out "
            "explicitly. removed_assets means something present last time wasn't seen this pass "
            "(possibly decommissioned, possibly just not encountered this run -- not proof it's "
            "gone). Call once per meaningful asset category near the end of Recon, using the SAME "
            "target value (the root host/program identity) across every scan of this same program "
            "so the diff actually lines up."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Root host/program identity to key the baseline under (e.g. the apex domain) — use the SAME value across scans of the same program"},
                "category": {"type": "string", "description": "Free-form label for what kind of asset this list is, e.g. 'subdomains', 'open_ports', 'endpoints', 'graphql_operations' — each category diffed independently"},
                "current_assets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Everything found in this category during THIS session's recon — the full current list, not just new items",
                },
            },
            "required": ["target", "category", "current_assets"],
        },
    )
)

register_tool(
    ToolSpec(
        name="rank_attack_surface",
        category="recon",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=rank_attack_surface,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Re-reads THIS session's own already-collected recon data (recon_result technologies/"
            "protections/host reachability, plus a best-effort match against current findings) and "
            "returns hosts ranked by an explainable score -- every host comes with its own reasons "
            "list (e.g. \"hostname contains 'admin'\", \"detected technology matches 'jenkins'\") so "
            "you can judge the score yourself instead of trusting it blindly. Purely a prioritization "
            "aid over a large host list -- never makes a network request itself, never required "
            "before deciding what to look at next. Best used mid/late Recon once technologies have "
            "actually been collected for at least some hosts; with nothing recorded yet it just says so."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max hosts to return, highest-scored first — omit for a sensible default"},
            },
        },
    )
)

# HTTP request smuggling / desync (timing technique) -- see agent/tools/smuggling.py's own
# module docstring for the full reasoning. requires_allowed_target=False, unlike waf_evasion_probe
# above: exactly 3 single-use raw connections (never more, matching the same bounded-request-count
# discipline as every other probe-shaped native tool here), and the technique only ever affects the
# attacker's OWN request/connection -- it never desyncs a real second/victim request the way the
# differential-response smuggling technique would, so it's shaped like an ordinary passive Analyze
# detector (nuclei, the native SQLi/XSS/redirect checks), not like an exploitation attempt.
register_tool(
    ToolSpec(
        name="smuggling_probe",
        category="scan",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=smuggling_probe,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Sends exactly 3 raw HTTP requests (1 clean baseline, then one CL.TE and one TE.CL "
            "malformed-framing request) and reports whether either malformed variant took materially "
            "longer to respond than the baseline, or never responded within the read window -- the "
            "PortSwigger 'timing' technique for HTTP request smuggling/desync detection. A positive "
            "result (candidate_desync_variants non-empty) is a LEAD that the front-end and back-end "
            "disagree about request body framing, worth a manual write-up -- not itself proof of "
            "impact, since confirming real impact (queue poisoning, response splitting) needs a "
            "second/victim request this tool deliberately never sends, to avoid disturbing real "
            "traffic on shared infrastructure. Most useful the moment recon shows a reverse "
            "proxy/CDN/load balancer in front of the real origin (a front-end/back-end pair is a "
            "precondition for this class of bug to exist at all)."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Full base URL (scheme + host + optional path) to probe"},
            },
            "required": ["target"],
        },
    )
)

# Native toolkit (Proxy/Repeater/Decoder/Comparer) -- category="toolkit" so these never leak into
# any phase's own get_tools_by_category() base toolset (same reasoning as category="post_exploit"
# for record_finding/record_chain_result). Availability is entirely settings-toggle-driven instead:
# agent/core.py's _toolkit_tool_extras reads agent/tools/toolkit_settings_store.py's independent
# booleans and explicitly appends whichever of these are currently enabled, same pattern as
# _subagent_delegation_extras' subagent_tools. The manual UI (main.py's own /toolkit routes) never
# consults these toggles at all -- it always works, regardless of whether the model has been given
# access.
register_tool(
    ToolSpec(
        name="send_raw_request",
        category="toolkit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_send_raw_request_native,
        # Same allowlist gate sqlmap/waf_evasion_probe get -- an arbitrary attacker-chosen
        # method/headers/body sent to the real target is exploit-shaped, unlike http_request's
        # fixed GET-only, no-body/no-custom-headers shape (requires_allowed_target=False).
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        description=(
            "Sends one raw HTTP request (any method/headers/body you choose) to the target and "
            "returns the real response -- the same engine the operator's own manual Repeater tab "
            "uses. Use this to resend a captured request with a modified parameter/header/body "
            "(e.g. testing a payload, an IDOR identity swap, a modified Content-Type) when "
            "http_request's fixed GET-only shape doesn't fit. The full request/response is also "
            "recorded into this session's own captured-traffic history (see list_captured_traffic), "
            "so a later diff_requests call can compare it against the original."
        ),
        parameters_schema=SEND_RAW_REQUEST_SCHEMA,
    )
)

register_tool(
    ToolSpec(
        name="list_captured_traffic",
        category="toolkit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_list_captured_traffic_native,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Lists this session's own captured HTTP traffic (from the agent's own browser, and "
            "any prior send_raw_request calls), newest first -- method, URL, status, id, and any "
            "passive-detector flags (sql_error/open_redirect/command_injection/reflected_payload, "
            "computed automatically for every entry, no extra call needed). Pass `query` "
            "(HTTPQL-lite, see its own parameter description) to pull a precise slice instead of "
            "paging through everything by eye -- e.g. `flags.cont:sql_error` for every flagged "
            "response, or `method.eq:POST AND req.body.cont:password` for every POST whose body "
            "contains a password field. Use an entry's id with diff_requests to compare two of "
            "them, or to know what to resend a modified version of via send_raw_request."
        ),
        parameters_schema=LIST_CAPTURED_TRAFFIC_SCHEMA,
    )
)

register_tool(
    ToolSpec(
        name="decode_value",
        category="toolkit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_decode_value_native,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Encodes or decodes a string through a common webapp scheme (base64, URL, HTML "
            "entities, hex, gzip) -- e.g. reading a base64-encoded token, or building a URL-encoded "
            "payload. Pure text transformation, no network/session involved."
        ),
        parameters_schema=DECODE_VALUE_SCHEMA,
    )
)

register_tool(
    ToolSpec(
        name="diff_requests",
        category="toolkit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_diff_requests_native,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Diffs the request or response of two captured traffic entries (see "
            "list_captured_traffic for their ids) line by line, in a git-diff-style format ('-' "
            "removed, '+' added). Use this to spot exactly what changed between two similar "
            "requests/responses -- a session token, a status code, a subtly different error message."
        ),
        parameters_schema=DIFF_REQUESTS_SCHEMA,
    )
)

# Same allowlist gate as send_raw_request above (requires_allowed_target=True): an Intruder run
# sends a whole SWEEP of attacker-chosen payloads
# to the real target, at minimum as exploit-shaped as one send_raw_request call.
# allows_repeated_attempts=True (same as waf_evasion_probe/authenticated_request) -- a first sweep
# with one payload set legitimately motivates a second call with a different set/template, not a
# single one-shot action.
register_tool(
    ToolSpec(
        name="intruder_run",
        category="toolkit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_intruder_run_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        description=(
            "Runs an automated payload-substitution attack against a request template -- wrap "
            "each attack position in §...§ (e.g. 'id=§1§') anywhere in the URL/headers/body, pick "
            "sniper (one payload set attacks each position in turn) or pitchfork (one payload set "
            "PER position, stepped together), and give the payload set as payload_text. Every real "
            "attempt is recorded into this session's own captured-traffic history (see "
            "list_captured_traffic/diff_requests) as it completes. Use this for a systematic sweep "
            "-- a wordlist of usernames against a login endpoint, a set of IDOR candidate ids, a "
            "set of injection payloads across one parameter -- where send_raw_request would mean "
            "dozens of manual calls."
        ),
        parameters_schema=INTRUDER_RUN_SCHEMA,
    )
)

# Added in a later log-review-audit follow-up -- the real analysis engine
# (agent/tools/toolkit_sequencer.py) and the manual UI route for it existed first, but this
# agent-facing tool wasn't registered until this follow-up pass.
# requires_allowed_target=False at the ToolSpec level (unlike send_raw_request/intruder_run above)
# because this tool has TWO collection modes and only one needs a target at all: mode="stored" is a
# pure local read off already-captured traffic, no network call, nothing to gate. mode="live" fires
# real repeated requests and IS gated the same way intruder_run is -- see
# _sequencer_analyze_native's own docstring for why that gate is applied manually inside the
# function instead of via this flag (a single ToolSpec can't express "required only for one mode").
register_tool(
    ToolSpec(
        name="sequencer_analyze",
        category="toolkit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_sequencer_analyze_native,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Entropy/predictability analysis of a token (session id, CSRF token, password-reset "
            "token, ...) across several real samples of it -- per-character-position Shannon "
            "entropy plus exact-duplicate detection, enough to catch a weak PRNG or a token "
            "generator that repeats values. mode='stored' (default) analyzes the token across "
            "traffic already captured this session, no network call needed; mode='live' fires "
            "fresh repeated requests at a target and extracts the token from each response. Use "
            "this when a session/reset/CSRF token's own VALUE looks worth checking for weak "
            "randomness, not just its presence/absence (which security_headers_audit and similar "
            "checks already cover)."
        ),
        parameters_schema=SEQUENCER_ANALYZE_SCHEMA,
    )
)

# Same allowlist gate as send_raw_request/intruder_run above (requires_allowed_target=True): a race
# run fires several real, attacker-chosen requests at the target, concentrated on one endpoint at
# effectively one instant -- at minimum as exploit-shaped as one send_raw_request call, arguably more
# concentrated in its real-world impact than an Intruder sweep spread over time.
register_tool(
    ToolSpec(
        name="racer_run",
        category="toolkit",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=_racer_run_native,
        requires_allowed_target=True,
        allows_repeated_attempts=True,
        installed_by_default=True,
        description=(
            "Race-condition testing: fires the SAME request several times concurrently, using "
            "last-byte synchronization (default strategy='last_byte') -- opens every connection "
            "first, sends everything but each request's final byte, then releases all of them at "
            "once, so the server sees them arrive within a fraction of a millisecond of each other. "
            "This is the technique real race-condition PoCs need (limit overrun, coupon/voucher "
            "reuse, double-spend, redeeming a one-time discount twice, a TOCTOU auth bug) -- far "
            "tighter than firing requests concurrently through send_raw_request/intruder_run, which "
            "can't get anywhere near this synchronized. strategy='sequential' sends the same "
            "requests one after another with no synchronization, as a baseline: if a bug only shows "
            "up under last_byte and never sequential, that confirms it's genuinely timing-dependent. "
            "Returns how many attempts got each response status -- e.g. two 200s where only one "
            "should have been possible is the signal a race actually happened; inspect individual "
            "attempts afterward with list_captured_traffic (source.eq:racer) or diff_requests."
        ),
        parameters_schema=RACER_RUN_SCHEMA,
    )
)

# --- Reverse Engineering project mode (agent/core.py's run_re_triage, agent/chat.py's
# mode=="reverse_engineering" chat loop) -- category="re" is never queried by any ordinary
# web-pentest phase, see registry.py's own Category comment. requires_allowed_target=False across
# the board: these tools act on a local file/folder/bytecode string, never a network target, so
# the exploitation allowlist (agent/tools/allowed_targets.py) doesn't apply. ---
register_tool(
    ToolSpec(
        name="radare2",
        category="re",
        tool_tier=2,
        executable="radare2",
        build_command=build_radare2_command,
        # Every read analysis re-runs a full `aaa` (~2m30s on a large binary); the identical command
        # on an unchanged file is byte-identical, so memoize it (write/hex_patch opts itself out).
        result_cache_key=radare2_result_cache_key,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Static analysis of a local binary (ELF/PE/Mach-O): file info, imports/exports, "
            "strings, symbols, sections/segments, entrypoints, function list, per-function "
            "disassembly, per-function pseudo-C "
            "decompilation (via the r2ghidra plugin), cross-references to a function/address, a "
            "raw hex+ASCII byte dump (hex_view), a whole-file byte-pattern search (hex_search -- "
            "finds every offset a given hex byte sequence occurs at, e.g. a magic number or known "
            "signature, without needing to already know an address), an in-place hex patch "
            "(hex_patch -- writes raw replacement bytes at an address), and an in-place assembly "
            "patch (hex_patch_asm -- writes a real instruction, e.g. \"jmp 0x401050\" or \"nop\", "
            "letting r2's own assembler compute the correct machine code instead of hand-crafting "
            "hex bytes yourself; prefer this over hex_patch for anything beyond a trivial NOP). "
            "Both patch modes write real bytes to the file on disk; a one-time .asra-bak backup of "
            "the original is made automatically the first time this session patches a given file."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local binary to analyze."},
                "analysis": {
                    "type": "string",
                    "enum": ["info", "imports", "exports", "strings", "symbols", "sections", "entrypoint", "functions", "disassemble_function", "decompile_function", "xrefs_to", "hex_view", "hex_search", "hex_patch", "hex_patch_asm"],
                    "description": "Which analysis to run.",
                },
                "address": {
                    "type": "string",
                    "description": "Function name or address -- required for disassemble_function/decompile_function/xrefs_to/hex_patch/hex_patch_asm. Optional for hex_view, which defaults to the program's entry point when omitted. Ignored otherwise.",
                },
                "length": {
                    "type": "integer",
                    "description": "hex_view only: how many bytes to dump starting at address. Defaults to 256 if omitted.",
                },
                "hex_bytes": {
                    "type": "string",
                    "description": "hex_patch only: the raw replacement bytes as a hex string with no 0x prefix (e.g. \"9090\" to write two x86 NOP bytes).",
                },
                "hex_pattern": {
                    "type": "string",
                    "description": "hex_search only: the byte sequence to search for across the whole file, as a hex string with no 0x prefix (e.g. \"4d5a\" for the PE \"MZ\" magic). Returns every offset it occurs at.",
                },
                "instruction": {
                    "type": "string",
                    "description": "hex_patch_asm only: a real assembly instruction to assemble and write at address (e.g. \"jmp 0x401050\", \"nop\", \"mov eax, 1\") -- letters/digits/a plain space/,+-*[]:. only (no tabs/newlines/`#`/`;`/other shell-ish characters). On ARM, write the immediate WITHOUT the \"#\" prefix (e.g. \"mov r0, 1\", not \"mov r0, #1\") -- r2's own command parser treats \"#\" as a comment marker and silently truncates the rest of the instruction.",
                },
            },
            "required": ["file_path", "analysis"],
        },
    )
)

register_tool(
    ToolSpec(
        name="gdb",
        category="re",
        tool_tier=2,
        executable="gdb",
        build_command=build_gdb_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Batch-mode dynamic debugging of a local binary: set one or more breakpoints (function "
            "names or addresses), run, and inspect registers/backtrace/disassembly at each stop -- "
            "plus, via `reads`, arbitrary memory at any address you choose (a decrypted string, raw "
            "hex bytes, or disassembly not at the current PC). With `stops` > 1 it continues to the "
            "next breakpoint hit and inspects again, so you can watch state change across several "
            "points in one call. Never a live interactive session (no back-and-forth judgment mid-run) "
            "-- everything is decided up front and run as one fixed batch, one report at the end."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local binary to run under gdb."},
                "break_at": {
                    "oneOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}],
                    "description": (
                        "One function name/address to break at, or a list of up to 5 (default: \"main\"). "
                        "gdb stops whenever execution reaches ANY of them, in whichever order the program "
                        "actually takes -- not the order you list them."
                    ),
                },
                "run_args": {"type": "string", "description": "Optional command-line arguments to pass to the program on run."},
                "stops": {
                    "type": "integer",
                    "description": (
                        "How many breakpoint hits to inspect before quitting (default 1, max 5). Each stop "
                        "after the first is reached via `continue` -- use this to watch how state changes "
                        "across several hits of the same breakpoint(s), e.g. successive loop iterations or "
                        "successive calls to a function."
                    ),
                },
                "reads": {
                    "type": "array",
                    "description": (
                        "Extra memory reads to run at EVERY stop, beyond the always-included registers/"
                        "backtrace/10-instructions-at-$pc. Use this to read what a register actually points "
                        "to -- e.g. a decrypted string GDB's own registers dump never shows on its own."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "address": {
                                "type": "string",
                                "description": (
                                    "A bare register (\"$rax\", \"$pc\", \"$rsi\"), a hex/decimal address "
                                    "(\"0x401000\"), or one of those plus/minus a simple offset "
                                    "(\"$rax+0x8\"). No parentheses or function-call syntax."
                                ),
                            },
                            "type": {
                                "type": "string",
                                "enum": ["string", "hex", "instructions"],
                                "description": (
                                    "\"string\" reads a NUL-terminated string (use this for a decrypted "
                                    "verdict/license string a pointer register points at), \"hex\" reads raw "
                                    "bytes, \"instructions\" disassembles at that address."
                                ),
                            },
                            "count": {
                                "type": "integer",
                                "description": "How many units (strings/bytes/instructions) to read (default 8, max 64).",
                            },
                        },
                        "required": ["address"],
                    },
                },
            },
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="strace_run",
        category="re",
        # tier-1 native_function, not a build_command()-based tier-2 tool -- a via_wine=true call
        # needs its own offscreen-display handling (start_offscreen_display) around the real
        # subprocess dispatch, which runner.py's generic tier-2 path has no hook for. See
        # agent/tools/builders/strace.py's own module docstring for the real incident this fixes.
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=run_strace,
        availability_check=strace_available,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Behavioral triage: runs a local binary under strace and reports the real syscalls it "
            "makes as it actually executes -- files opened/read/written, network connections, "
            "processes spawned, signals. This is the 'what does it actually touch when it runs' step "
            "(a ProcMon/Process Hacker-style sandbox pass) -- run it EARLY, before or alongside "
            "static analysis, not just when something else fails to answer a question. For a Windows "
            "PE (.exe), set via_wine=true -- wine translates its Windows API calls into real host "
            "syscalls (a registry read becomes a real file open under its own prefix), an honest "
            "proxy for behavior, not a perfectly faithful native Windows trace."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local binary to run under strace."},
                "via_wine": {
                    "type": "boolean",
                    "description": "Set true for a Windows PE (.exe) target -- runs it as `wine <file_path>` so its translated syscalls are visible.",
                },
                "run_args": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional command-line arguments to pass to the program itself.",
                },
                "trace_categories": {
                    "type": "string",
                    "description": (
                        "Comma-separated strace category names to trace (default \"file,network,process\"). "
                        "Allowed: desc, file, ipc, memory, network, process, signal."
                    ),
                },
            },
            "required": ["file_path"],
        },
    )
)

# wine_debug_run (agent/tools/wine_debug.py) is deliberately NOT registered here -- see that
# module's own docstring for the full, honest status. Built to close the "gdb can't touch a Windows
# PE" gap via winedbg's own --gdb proxy mode; the connect/attach/inspect/detach half was confirmed
# live and genuinely works (a real gdb client reading real state -- e.g. stopped at DbgBreakPoint in
# ntdll.dll, correct symbol resolution), but `continue` (resuming the debuggee after the initial
# stop) hangs indefinitely in this project's real WSL2 environment, confirmed even after granting
# wineserver64 cap_sys_ptrace (setup_tools.sh's install_wine) -- root cause not found. Registering a
# tool the model can call that then hangs for its own full timeout budget is worse than not having
# it at all (the exact "wastes the operator's time" complaint this whole audit pass started from) --
# left unregistered, with the module intact, until continue's real hang cause is diagnosed.

register_tool(
    ToolSpec(
        name="qiling_emulate",
        category="re",
        # Runs the emulation in agent/tools/qiling_runner.py as its own python subprocess -- tier-2
        # (subprocess) even though qiling is a library, to keep it out of the server process, get
        # runner.py's hard timeout, and hold the same RE arsenal slot the old cdb tool did. See
        # agent/tools/builders/qiling.py's own docstring for the full reasoning.
        tool_tier=2,
        executable=sys.executable,
        build_command=build_qiling_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # The `qiling` package is an optional external dependency the running code doesn't itself
        # carry -- availability reflects whether it's actually importable, not a bare which() on the
        # python interpreter (which is always present). Same pattern the browser tools use.
        availability_check=qiling_available,
        description=(
            "Cross-platform dynamic triage of a binary by full CPU emulation (Qiling Framework, on "
            "Unicorn) -- runs a Windows PE (.exe/.dll), Linux ELF, or macOS Mach-O under an emulated "
            "CPU with a faked OS layer, so a WINDOWS .exe can be executed and inspected on this "
            "Linux/WSL host with NO real Windows and NO wine (the cross-platform capability the old "
            "cdb tool could not provide). Reports the emulated OS/arch, entry point, how many "
            "instructions ran, and why it stopped. Needs the `qiling` package installed AND a Qiling "
            "rootfs (system libraries for the target OS, e.g. Windows DLLs) -- set QILING_ROOTFS in "
            ".env or pass rootfs. NOT 100% faithful on complex real-world programs: an early "
            "'emulation stopped' can just mean an unimplemented API, not a real defect -- for a "
            "faithful native Windows run when emulation falls short, a real Windows/WinDbg host is "
            "still the only complete answer. One-shot: one load, one emulated run, one report."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local binary to emulate (Windows PE, Linux ELF, or macOS Mach-O)."},
                "rootfs": {"type": "string", "description": "Path to the Qiling rootfs (system libraries for the target OS). Defaults to the QILING_ROOTFS env var."},
                "args": {"type": "array", "items": {"type": "string"}, "description": "Optional command-line arguments to pass to the emulated program."},
                "max_instructions": {"type": "integer", "description": "Stop after this many emulated instructions (guards against a tight infinite loop). Defaults to QILING's built-in cap."},
            },
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="slither",
        category="re",
        tool_tier=2,
        executable="slither",
        build_command=build_slither_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Solidity static analyzer -- runs Slither's full detector suite against a .sol file or a source directory, requires available Solidity source.",
        parameters_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to a .sol file or a directory containing Solidity source."}},
            "required": ["path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="heimdall_decompile",
        category="re",
        tool_tier=2,
        executable="heimdall",
        build_command=build_heimdall_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Decompiles raw EVM bytecode into readable pseudocode -- for a smart contract with no available Solidity source.",
        parameters_schema={
            "type": "object",
            "properties": {"bytecode_or_path": {"type": "string", "description": "Hex EVM bytecode (with or without a leading 0x) or a path to a local file containing it."}},
            "required": ["bytecode_or_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="disassemble_evm_bytecode",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=disassemble_evm_bytecode,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Disassembles raw EVM bytecode into its opcode sequence (pure-Python, no external binary) -- lower-level than heimdall_decompile's pseudocode output.",
        parameters_schema={
            "type": "object",
            "properties": {"bytecode_or_path": {"type": "string", "description": "Hex EVM bytecode (with or without a leading 0x) or a path to a local file containing it."}},
            "required": ["bytecode_or_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="upx",
        category="re",
        tool_tier=2,
        executable="upx",
        build_command=build_upx_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # upx -t's own exit code on a genuinely non-UPX file isn't confirmed reliable across every
        # version (see upx.py's own parser comment) -- permissive here, same "don't let a real,
        # meaningful non-zero exit get misreported as a broken tool call" reasoning dalfox's own
        # ok_exit_codes entry documents, since the text itself (parsed by parse_upx_output) is the
        # real signal either way.
        ok_exit_codes=frozenset({0, 1}),
        description="Detects whether a binary is UPX-packed (mode='detect', the default) or unpacks it into a new file next to the original (mode='unpack') -- run this before radare2/gdb on a binary that looks packed, since a packed binary's real logic is invisible until unpacked.",
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local binary to check/unpack."},
                "mode": {"type": "string", "enum": ["detect", "unpack"], "description": "detect (default): test if the file is UPX-packed. unpack: decompress it into a new file."},
            },
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="mythril",
        category="re",
        tool_tier=2,
        executable="myth",
        build_command=build_mythril_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Symbolic-execution analysis of a smart contract (Solidity source or raw EVM bytecode) -- a genuinely different technique from slither's pattern-based detectors, finds bug classes slither's own static patterns can miss (slower, but complementary, not redundant).",
        parameters_schema={
            "type": "object",
            "properties": {"bytecode_or_path": {"type": "string", "description": "Path to a Solidity file, or hex EVM bytecode (with or without a leading 0x)."}},
            "required": ["bytecode_or_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="forge_poc_run",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=forge_poc_run,
        requires_allowed_target=False,
        installed_by_default=True,
        allows_repeated_attempts=True,
        # Confirmed live: forge test's own exit code on a genuine assertion failure is NOT reliably
        # 1 across every invocation shape tested (seen both 0 and 1 for the identical failing-PoC
        # source, direct vs. sandboxed) -- forge_poc_run itself never branches on exit_code for
        # exactly this reason (its "tests" key present/absent in the parsed --json is the real,
        # observed-reliable signal). ok_exit_codes is irrelevant in practice here anyway (this is a
        # native tool -- exit-code gating only applies to tier-2 build_command tools) but {0, 1} is
        # kept here, not the {0}-only default, so this row never misleadingly implies a stricter
        # contract than the code actually relies on.
        ok_exit_codes=frozenset({0, 1}),
        description=(
            "Compiles and RUNS a real Foundry test (source: the full .t.sol file content, extending "
            "forge-std's `Test` contract) against a smart contract -- an actually-executed PoC, the "
            "dynamic complement to slither/mythril's static analysis. Fork REAL chain state from "
            "inside the Solidity source itself via forge-std's vm.createSelectFork(rpcUrl[, "
            "blockNumber]) cheatcode (no separate fork/RPC parameters here -- write the whole test, "
            "same as custom_exploit_run/custom_re_script); assert the exploit's real effect with a "
            "normal Solidity assert/require. Only ever runs `forge test` (never `forge script "
            "--broadcast`) -- no real transaction can ever reach the actual network through this "
            "tool, only a local, throwaway fork simulation. A passing test is real, executed proof "
            "an exploit works, not a pattern match -- use this to confirm a slither/mythril finding "
            "for real before reporting it."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "description": "The full Solidity test file (.t.sol) source, extending forge-std's Test contract. Fork real chain state with vm.createSelectFork(rpcUrl) or vm.createSelectFork(rpcUrl, blockNumber) inside a test function or setUp().",
                },
            },
            "required": ["source"],
        },
    )
)

register_tool(
    ToolSpec(
        name="osv_scanner",
        category="re",
        tool_tier=2,
        executable="osv-scanner",
        build_command=build_osv_scanner_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # osv-scanner exits non-zero the instant it finds ANY known vulnerability -- the same
        # "CI convention: 0 for clean, 1 for real findings, not a broken tool" shape dalfox's own
        # ok_exit_codes entry above already documents for the identical reason.
        ok_exit_codes=frozenset({0, 1}),
        description="Software composition analysis (SCA) -- scans a source tree's own dependency lockfiles (package-lock.json, requirements.txt, Cargo.lock, go.sum, ...) against the OSV vulnerability database. Covers whatever ecosystems it finds lockfiles for, no per-language tool or install/resolve step needed first.",
        parameters_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to the source directory to scan for dependency lockfiles."}},
            "required": ["path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="trufflehog",
        category="re",
        tool_tier=2,
        executable="trufflehog",
        build_command=build_trufflehog_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Secrets scanning over a source tree -- scans the FULL git commit history (not just the current files) when the target is a git repo, so a credential leaked and later removed is still found. Attempts live verification of what it finds (e.g. checks whether a matched AWS key is actually live) by default.",
        parameters_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to the source directory (or git repo) to scan."}},
            "required": ["path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="apktool",
        category="re",
        tool_tier=2,
        executable="apktool",
        build_command=build_apktool_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Decompiles an Android APK's resources and DEX bytecode into smali (disassembly) in a new directory next to the APK -- a preparation step for reading/analyzing the app's real structure and manifest, not a finding-producing scanner by itself.",
        parameters_schema={
            "type": "object",
            "properties": {"file_path": {"type": "string", "description": "Path to the local .apk file to decompile."}},
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="jadx",
        category="re",
        tool_tier=2,
        executable="jadx",
        build_command=build_jadx_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Decompiles an Android APK/DEX/JAR into readable Java source (unlike apktool's own smali disassembly) in a new directory next to the file -- read the decompiled source directly, or point semgrep at the output directory afterward.",
        parameters_schema={
            "type": "object",
            "properties": {"file_path": {"type": "string", "description": "Path to the local .apk/.dex/.jar file to decompile."}},
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="ipa_extract",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=ipa_extract,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Extracts a local iOS .ipa archive (a plain ZIP under the hood) and reports the embedded app's real Info.plist metadata (bundle id, version, main executable) plus the extracted Mach-O executable's own path -- iOS's mobile-RE preparation step, mirroring apktool/jadx for Android. Run radare2/gdb/r2ghidra/frida_trace directly against the returned executable_path afterward, same as any other local binary (all format-agnostic, already handle Mach-O).",
        parameters_schema={
            "type": "object",
            "properties": {"file_path": {"type": "string", "description": "Path to the local .ipa file to extract."}},
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="binwalk",
        category="re",
        tool_tier=2,
        executable="binwalk",
        build_command=build_binwalk_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Firmware/embedded-image analysis -- identifies (mode=\"scan\", the default) or extracts (mode=\"extract\") files/filesystems/compressed data embedded INSIDE a binary blob (a firmware dump, a bootloader, an update package). Nothing else here looks for what's packed alongside/inside a file the way this does.",
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local firmware/binary blob to scan."},
                "mode": {"type": "string", "enum": ["scan", "extract"], "description": "scan (default): identify embedded signatures. extract: pull out recognized files into a new directory next to the input."},
            },
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="radiff2",
        category="re",
        tool_tier=2,
        executable="radiff2",
        build_command=build_radiff2_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Binary diffing between two files (already installed alongside radare2, no separate package) -- n-day analysis (diff a patched binary against the pre-patch version) or variant/family comparison. mode=\"similarity\" (default): a quick 0-1 similarity score. mode=\"changes\": the actual byte-level differences.",
        parameters_schema={
            "type": "object",
            "properties": {
                "file_a": {"type": "string", "description": "Path to the first (e.g. older/original) local file."},
                "file_b": {"type": "string", "description": "Path to the second (e.g. newer/patched) local file."},
                "mode": {"type": "string", "enum": ["similarity", "changes"], "description": "similarity (default): a quick 0-1 score. changes: the actual byte-level diff."},
            },
            "required": ["file_a", "file_b"],
        },
    )
)

register_tool(
    ToolSpec(
        name="frida_trace",
        category="re",
        tool_tier=2,
        executable="frida-trace",
        build_command=build_frida_trace_command,
        requires_allowed_target=False,
        installed_by_default=True,
        # Confirmed live: frida-trace's own exit code is NOT a reliable success/failure signal --
        # the exact same spawn+trace call (a genuinely successful trace, real output captured)
        # returned 0 run directly in a shell but 1 through this project's own subprocess dispatch,
        # timing-dependent (dynamic instrumentation racing the spawned process's own startup, not
        # a broken invocation). The real signal is the trace output itself, always present either
        # way -- same "don't let a real, meaningful exit code get misreported as a broken tool
        # call" reasoning upx/osv-scanner's own ok_exit_codes entries already document.
        ok_exit_codes=frozenset({0, 1}),
        description="Dynamic instrumentation -- spawns a LOCAL binary and traces every call to functions matching function_pattern (a name glob, e.g. \"open*\", \"*licence*\", \"strcmp\"), showing real arguments/return values as they happen. The runtime complement to radare2/gdb's static-only analysis -- often the fastest way to find a serial-check/licensing/certificate-pinning routine without reading disassembly line by line. Naturally exits once the spawned process exits on its own (a short-lived CLI target, the common case) -- a long-running/server-shaped target would hit the tool timeout and lose its output entirely, an honest limitation of this tool specifically.",
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local binary to spawn and trace."},
                "function_pattern": {"type": "string", "description": "A function-name glob to trace calls to, e.g. \"open*\", \"strcmp\", \"*licence*\"."},
                "args": {"type": "array", "items": {"type": "string"}, "description": "Optional CLI arguments to pass the spawned binary."},
            },
            "required": ["file_path", "function_pattern"],
        },
    )
)

register_tool(
    ToolSpec(
        name="frida_ps",
        category="re",
        tool_tier=2,
        executable="frida-ps",
        build_command=build_frida_ps_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Lists locally running processes (pid + name) -- useful context before attaching Frida to something already running, rather than spawning fresh.",
        parameters_schema={"type": "object", "properties": {}, "required": []},
    )
)

register_tool(
    ToolSpec(
        name="tshark_capture",
        category="re",
        tool_tier=2,
        executable="tshark",
        build_command=build_tshark_capture_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Live, time-boxed packet capture (Wireshark's CLI) -- captures on a network interface "
            "(default \"any\") for duration_seconds (capped by TSHARK_CAPTURE_MAX_SECONDS), "
            "optionally narrowed with a BPF capture filter (e.g. \"tcp port 443\", \"udp\"), and "
            "returns a per-packet summary (timing, src/dst, TCP/UDP ports, DNS query name, HTTP "
            "host/method/path, TLS SNI). The raw .pcap is also saved into this session's own "
            "project folder for later re-reading (tshark_read_pcap) or manual inspection -- the "
            "exact path appears right after -w in this call's own \"command\" field. WSL2 caveat: "
            "this only sees traffic reachable from THIS Linux/WSL2 environment -- a native "
            "Windows-side process (a game launched directly on Windows, not inside WSL2) needs WSL2's "
            "mirrored networking mode (a one-time .wslconfig setting on the operator's own machine) "
            "before its traffic is visible here at all; a Linux-side target or genuinely remote host "
            "captures normally either way."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "interface": {"type": "string", "description": "Network interface to capture on, e.g. \"eth0\", \"lo\". Default \"any\" captures every interface at once."},
                "duration_seconds": {"type": "integer", "description": "How long to capture, in seconds. Capped by TSHARK_CAPTURE_MAX_SECONDS regardless of what's requested here."},
                "bpf_filter": {"type": "string", "description": "Optional BPF capture filter (tshark/tcpdump syntax), e.g. \"tcp port 443\", \"host 10.0.0.5\", \"udp\"."},
            },
            "required": [],
        },
    )
)

register_tool(
    ToolSpec(
        name="tshark_read_pcap",
        category="re",
        tool_tier=2,
        executable="tshark",
        build_command=build_tshark_read_pcap_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Reads an already-captured .pcap file (from tshark_capture, or supplied from an "
            "external sandbox/tool) with no live capture at all -- no elevated capability needed. "
            "Same per-packet summary shape as tshark_capture. An optional Wireshark display filter "
            "(different syntax from tshark_capture's BPF filter, e.g. \"http.request\", "
            "\"dns.flags.response == 0\", \"ip.addr == 10.0.0.5\") narrows which already-captured "
            "packets are shown, without re-capturing anything."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "pcap_path": {"type": "string", "description": "Path to the local .pcap/.pcapng file to read."},
                "display_filter": {"type": "string", "description": "Optional Wireshark display filter syntax, e.g. \"http.request\", \"dns\", \"ip.addr == 10.0.0.5\"."},
            },
            "required": ["pcap_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="ilspycmd",
        category="re",
        tool_tier=2,
        executable="ilspycmd",
        build_command=build_ilspycmd_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Decompiles a .NET assembly (.dll/.exe compiled from C#/VB.NET/F#) into readable C#. mode=\"list\" (default, cheap): every class/interface/struct/delegate/enum by fully qualified name -- the safe first step. mode=\"type\": decompile ONE specific type_name in full (the common case once \"list\" has pointed at something worth reading). mode=\"full\": decompile the WHOLE assembly to stdout -- only for a genuinely small one, a large assembly will get cut off by the generic tool-result size limit.",
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local .NET assembly (.dll/.exe)."},
                "mode": {"type": "string", "enum": ["list", "type", "full"], "description": "list (default): every type by name. type: decompile one type_name in full. full: decompile the whole assembly (small assemblies only)."},
                "type_name": {"type": "string", "description": "Required when mode=\"type\" -- the fully qualified type name from mode=\"list\"'s own output."},
            },
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="afl_fuzz_start",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=afl_fuzz_start,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Starts a real AFL++ dumb-mode fuzzing run against a local binary IN THE BACKGROUND -- "
            "returns a job_id immediately, call background_job_check with it later to get the "
            "result (crash/hang counts + file paths). Genuinely different from every other RE tool "
            "here: fuzzing takes minutes, not seconds, so it never blocks you -- keep working on "
            "something else and check back. Dumb mode (no coverage feedback, works on any black-box "
            "binary with no source needed) -- an honest limitation, not full coverage-guided "
            "fuzzing, which would need the target recompiled with AFL instrumentation or a working "
            "QEMU mode neither of which this environment has. duration_seconds bounds the real "
            "fuzzing time (10-1800s). input_mode=\"file\" (default) for a binary that takes a file "
            "argument, \"stdin\" for one that reads from stdin."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path to the local binary to fuzz."},
                "input_mode": {"type": "string", "enum": ["file", "stdin"], "description": "file (default): the binary takes a file path argument. stdin: the binary reads its input from stdin."},
                "duration_seconds": {"type": "integer", "description": "How long to fuzz for, in seconds (10-1800). Defaults to 120."},
            },
            "required": ["file_path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="semgrep",
        category="re",
        tool_tier=2,
        executable="semgrep",
        build_command=build_semgrep_command,
        requires_allowed_target=False,
        installed_by_default=True,
        description="SAST scan of an available source tree using semgrep's community rule sets (--config auto) -- language-agnostic, works on any source repo regardless of a binary being involved at all.",
        parameters_schema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to the source file or directory to scan."}},
            "required": ["path"],
        },
    )
)

register_tool(
    ToolSpec(
        name="memscan_attach",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=memscan_attach,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Attaches to an already-running LOCAL process (by pid -- see frida_ps to find one) for live memory scanning, the classic \"Cheat Engine\" technique: search a running process's memory for a value, narrow across repeated scans as it visibly changes, then patch it to confirm you found the real address -- not a decoy/cached copy. Useful both to study how a value is stored (anti-cheat/licensing research), to verify a decompiled guess against real runtime state, and to find a decrypted string (a license/verdict message an obfuscator only decrypts at runtime) directly in the process's own live memory. Returns a scan_id -- pass it to memscan_scan/memscan_list/memscan_write/memscan_detach. Only a directly-scanned address is found (no pointer-chain/static-offset resolution), and nothing here survives a target restart.",
        parameters_schema={
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID of the already-running local target (see frida_ps)."},
                "scan_data_type": {
                    "type": "string",
                    "enum": sorted(VALUE_TYPES),
                    "description": (
                        "What kind of value you're looking for. int32 (default) covers most integer "
                        "game/app values; float32/float64 for a fractional value. \"string\" searches "
                        "for exact text (e.g. a decrypted verdict/license string) -- pair with "
                        "memscan_scan mode=\"exact\". \"bytearray\" searches for a raw byte pattern "
                        "(hex pairs, \"??\" as a per-byte wildcard, e.g. \"FF ?? EE\")."
                    ),
                },
            },
            "required": ["pid"],
        },
    )
)

register_tool(
    ToolSpec(
        name="memscan_scan",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=memscan_scan,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Searches (or narrows a previous search on) an attached memscan_attach session's target memory. mode=\"exact\" (requires value): find/narrow to matches equal to a specific known number, string, or byte pattern (whichever memscan_attach's scan_data_type was set to). mode=\"unknown\": snapshot the ENTIRE process state as candidates when you don't know the value yet -- narrow it afterward with a comparison mode once the operator reports the value changed in the running target. mode=\"increased\"/\"decreased\"/\"changed\"/\"unchanged\": narrow existing matches by how they moved since the last scan (optionally by a specific NUMBER via value -- these two comparisons only apply to numeric scan_data_types, string/bytearray sessions use them with no value at all, or use mode=\"exact\" instead). Returns match_count -- once it's small (ideally 1), call memscan_list to see the actual address(es).",
        parameters_schema={
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "The scan_id returned by memscan_attach."},
                "mode": {"type": "string", "enum": sorted(SCAN_MODES), "description": "exact: search/narrow to a known value/string/byte-pattern. unknown: snapshot everything (first scan, value not known yet). increased/decreased (numeric scan_data_types only)/changed/unchanged: narrow by how matches moved since the last scan."},
                "value": {
                    "type": ["string", "number"],
                    "description": (
                        "Required for mode=\"exact\". For a numeric scan_data_type, a plain number. "
                        "For scan_data_type=\"string\", the literal text to search for. For "
                        "scan_data_type=\"bytearray\", space-separated hex byte pairs (\"??\" wildcard "
                        "allowed), e.g. \"FF ?? EE\". Optional for increased/decreased/changed/unchanged "
                        "on a NUMERIC scan_data_type (an exact delta/target instead of \"any change\") -- "
                        "omit it entirely for those modes on a string/bytearray session. Unused for mode=\"unknown\"."
                    ),
                },
            },
            "required": ["scan_id", "mode"],
        },
    )
)

register_tool(
    ToolSpec(
        name="memscan_list",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=memscan_list,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Lists the current candidate matches for a memscan_attach session (refreshed to their real, current live value first) -- address, region, value, type, and the list_index memscan_write needs. Capped at 50 entries with an honest total_count/truncated flag if there are more; keep narrowing with memscan_scan first to bring the count down to something worth reading one by one.",
        parameters_schema={
            "type": "object",
            "properties": {"scan_id": {"type": "string", "description": "The scan_id returned by memscan_attach."}},
            "required": ["scan_id"],
        },
    )
)

register_tool(
    ToolSpec(
        name="memscan_write",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=memscan_write,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Writes a new value into the live target process's memory at one specific match from your last memscan_list call (by list_index -- never a raw address, so you can only ever write to something this session's own scan already found) -- the real proof step: if the operator sees the effect they'd expect (health/ammo/a displayed value actually changes), you've confirmed the real address, not a decoy. A genuine, in-place write to a real running process -- only do this once memscan_list has narrowed to a specific match you actually mean to test.",
        parameters_schema={
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "The scan_id returned by memscan_attach."},
                "list_index": {"type": "integer", "description": "The index (from memscan_list's own output) of the match to overwrite."},
                "value": {"type": "number", "description": "The new value to write."},
            },
            "required": ["scan_id", "list_index", "value"],
        },
    )
)

register_tool(
    ToolSpec(
        name="memscan_detach",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=memscan_detach,
        requires_allowed_target=False,
        installed_by_default=True,
        description="Detaches a memscan_attach session and stops the underlying scanmem process. Call this once you're done with a target rather than leaving it attached for the rest of the conversation.",
        parameters_schema={
            "type": "object",
            "properties": {"scan_id": {"type": "string", "description": "The scan_id returned by memscan_attach."}},
            "required": ["scan_id"],
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
