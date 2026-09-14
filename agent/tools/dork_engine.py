"""Dork Engine: a catalog of search-engine dorks and third-party OSINT lookups, addressed to a
single normalized target, plus the one native tool (dork_search) that builds/runs them.

Two genuinely different things live under one catalog here, on purpose, so the operator and the
model both get ONE place to reach for "dork this target" instead of two disconnected systems:

- Google/Bing/DuckDuckGo/Yandex boolean dorks (kind="search_lead") and third-party OSINT service
  links (kind="external_link", kind="direct_url") can never be fetched automatically here --
  scraping a search engine's results page is unreliable (CAPTCHA-gated) and against most engines'
  own terms of service. build_dork_result() only ever CONSTRUCTS the query/URL and hands it back
  as a labeled "lead" (status="lead", never "ok") -- the caller (the model, via its own web_fetch/
  browser_navigate tool, or the operator via the manual Dorks tab) decides whether to actually open
  it. This mirrors the one working model BigBountyRecon (github.com/Viralmaniar/BigBountyRecon, the
  reference this catalog's dork templates were adapted from) itself uses: build the query, a human
  (or here, optionally the model's own browser tool) follows it up.

- Several of BigBountyRecon's own "dorks" (crt.sh, Wayback, Common Crawl, WHOIS, DNS, passive DNS,
  urlscan, security-headers) duplicate ASRA native tools that already exist, are already cached,
  and already have real fallback handling (crt_sh_lookup/wayback_urls/common_crawl_urls/
  whois_lookup/dns_lookup/otx_passive_dns/urlscan_search/security_headers_audit, all in
  agent/tools/native.py). Rather than re-implement a second, worse copy of each, kind="native_tool"
  categories here just DISPATCH to that existing function and return its real, fetched result
  (status="ok"/"error" exactly as that tool itself would report) -- the catalog's job for these is
  purely "same normalized target, one consistent menu", not a second implementation.

list_dork_categories() is the single source of truth consumed by both dork_search's own JSON
schema (the `category` enum, agent/tools/__init__.py) and the manual Dorks tab's quick-button grid
(main.py/templates/dorks_standalone.html) -- so the two can never drift apart the way a second,
hand-copied button list would.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal
from urllib.parse import quote

from agent.tools.allowed_targets import extract_hostname
from agent.tools.native import (
    common_crawl_urls,
    crt_sh_lookup,
    dns_lookup,
    otx_passive_dns,
    security_headers_audit,
    urlscan_search,
    wayback_urls,
    whois_lookup,
)
from agent.tools.tool_api_keys import get_tool_api_key

DorkKind = Literal["search_lead", "external_link", "direct_url", "native_tool"]

# Base search URL per engine, `{query}` is a pre-quoted query string. All four understand the
# `site:`/`inurl:`/`intext:`/`ext:`-or-`filetype:` boolean syntax these dork templates use closely
# enough to be worth offering as alternatives to Google specifically because Google is the most
# aggressive about CAPTCHA-gating automated-looking traffic -- an operator hitting that wall can
# just switch engines from the same dork instead of being stuck.
SEARCH_ENGINES: dict[str, str] = {
    "google": "https://www.google.com/search?q={query}",
    "bing": "https://www.bing.com/search?q={query}",
    "duckduckgo": "https://duckduckgo.com/html/?q={query}",
    "yandex": "https://yandex.com/search/?text={query}",
}
DEFAULT_ENGINE = "google"


@dataclass(frozen=True)
class DorkCategory:
    id: str
    label: str
    kind: DorkKind
    description: str
    # search_lead only: boolean query text, `{target}` placeholder, engine picked separately.
    query_template: str | None = None
    # external_link / direct_url only: URL template. external_link's `{target}` is the bare host
    # (a third-party service's own search path); direct_url's `{origin}` is a full scheme://host
    # (a path being appended to the target's own site).
    url_template: str | None = None
    # native_tool only: the existing agent/tools/native.py function to dispatch to, and which
    # params key it expects the normalized host under (every wrapped tool here takes "domain"
    # except security_headers_audit, which takes a full URL under "target").
    native_fn: Callable[[dict], dict] | None = None
    native_param_key: str | None = None
    # native_tool only: this function's own ToolSpec.name in TOOL_REGISTRY (agent/tools/__init__.py
    # registers it separately under its OWN name too, e.g. "crt_sh_lookup") -- used to look up any
    # saved Tool API Key for it (Settings -> Tool API Keys), since that injection normally keys off
    # the OUTER tool call's own name (agent/core.py) and a call arriving through dork_search's own
    # name would otherwise never see a key the operator already saved for the underlying tool.
    native_tool_spec_name: str | None = None


_CATALOG: list[DorkCategory] = [
    # -- search_lead: classic boolean dorks, adapted from BigBountyRecon's own Form1.cs --
    DorkCategory("dir_listing", "Open directory listing", "search_lead",
                 "Finds an exposed Apache/nginx directory index page.",
                 query_template="site:{target} intitle:index.of"),
    DorkCategory("config_files", "Config & credential files", "search_lead",
                 "Config/registry/RDP/INI-style files that shouldn't be web-reachable.",
                 query_template="site:{target} (ext:xml OR ext:conf OR ext:cnf OR ext:reg OR ext:inf OR ext:rdp OR ext:cfg OR ext:txt OR ext:ora OR ext:ini)"),
    DorkCategory("db_dumps", "Database dumps", "search_lead",
                 "SQL/DBF/MDB database export files.",
                 query_template="site:{target} (ext:sql OR ext:dbf OR ext:mdb)"),
    DorkCategory("wordpress_paths", "WordPress paths", "search_lead",
                 "wp-content/plugins/uploads/themes paths a WordPress site exposes.",
                 query_template="site:{target} (inurl:wp- OR inurl:wp-content OR inurl:plugins OR inurl:uploads OR inurl:themes OR inurl:download)"),
    DorkCategory("log_files", "Log files", "search_lead",
                 "Indexed .log files, often leaking paths/IPs/stack traces.",
                 query_template="site:{target} ext:log"),
    DorkCategory("backup_files", "Backup files", "search_lead",
                 "Old/backup/bak-style file extensions left web-reachable.",
                 query_template="site:{target} (ext:bkf OR ext:bkp OR ext:bak OR ext:old OR ext:backup)"),
    DorkCategory("login_pages", "Login / auth pages", "search_lead",
                 "Indexed login/signin/auth entry points.",
                 query_template="site:{target} (inurl:login OR inurl:signin OR intitle:login OR inurl:auth)"),
    DorkCategory("leaked_documents", "Leaked documents", "search_lead",
                 "Indexed office documents/PDFs that may contain internal info.",
                 query_template="site:{target} (ext:doc OR ext:docx OR ext:pdf OR ext:xls OR ext:xlsx OR ext:ppt OR ext:pptx OR ext:csv OR ext:rtf)"),
    DorkCategory("phpinfo", "phpinfo() exposure", "search_lead",
                 "A live phpinfo() page, leaking server config/paths/loaded extensions.",
                 query_template='site:{target} ext:php intitle:phpinfo "published by the PHP Group"'),
    DorkCategory("shells_creds", "Webshells & credential files", "search_lead",
                 "Indexed webshell/backdoor filenames and classic *nix credential filenames.",
                 query_template="site:{target} (inurl:shell OR inurl:backdoor OR inurl:wso OR inurl:cmd OR shadow OR passwd OR boot.ini)"),
    DorkCategory("readme_setup", "Readme / setup / install files", "search_lead",
                 "Leftover install/setup/readme/license files a deploy should have removed.",
                 query_template="site:{target} (inurl:readme OR inurl:license OR inurl:install OR inurl:setup OR inurl:config)"),
    DorkCategory("sql_errors", "SQL error disclosure", "search_lead",
                 "Indexed pages showing a raw SQL/DB error message.",
                 query_template='site:{target} (intext:"sql syntax near" OR intext:"Warning: mysql_connect()" OR intext:"Warning: mysql_query()" OR intext:"Warning: pg_connect()" OR intext:"unexpected end of SQL command")'),
    DorkCategory("open_redirect", "Open redirect parameters", "search_lead",
                 "URL parameters shaped like an unvalidated redirect target.",
                 query_template="site:{target} (inurl:redir OR inurl:url OR inurl:redirect OR inurl:return OR inurl:src=http OR inurl:r=http)"),
    DorkCategory("struts_ext", "Apache Struts action/do endpoints", "search_lead",
                 "*.action/*.do/*.struts endpoints -- historically a common Struts RCE surface.",
                 query_template="site:{target} (ext:action OR ext:struts OR ext:do)"),
    DorkCategory("sharepoint_webpart", "SharePoint WebPart RCE surface", "search_lead",
                 "The _vti_bin/webpartpages/asmx endpoint some older SharePoint RCE chains use.",
                 query_template="site:{target} inurl:_vti_bin/webpartpages/asmx -docs -msdn -mdsec"),
    DorkCategory("apache_config", "Apache config exposure", "search_lead",
                 "Indexed files whose content matches an Apache config file.",
                 query_template='site:{target} filetype:config "apache"'),
    DorkCategory("dot_git", "Exposed .git directory", "search_lead",
                 "A publicly reachable .git directory (source disclosure, sometimes secrets in history).",
                 query_template='site:{target} inurl:"/.git" -github'),
    DorkCategory("traefik_dashboard", "Traefik dashboard exposure", "search_lead",
                 "An exposed Traefik reverse-proxy admin dashboard.",
                 query_template="site:{target} intitle:traefik inurl:8080/dashboard"),
    DorkCategory("htaccess_phpinfo", ".htaccess / phpinfo.php paths", "search_lead",
                 "Indexed .htaccess files or a phpinfo.php path specifically.",
                 query_template='site:{target} (inurl:"/phpinfo.php" OR inurl:".htaccess")'),
    DorkCategory("subdomains_indexed", "Indexed subdomains", "search_lead",
                 "Every subdomain of the target Google has indexed -- a cheap first pass before "
                 "crt_transparency/passive_dns's own more thorough (but slower) sources.",
                 query_template="site:*.{target}"),
    DorkCategory("wp_content_includes", "wp-content / wp-includes", "search_lead",
                 "Narrower WordPress-path sweep than wordpress_paths, wp-content/wp-includes only.",
                 query_template="site:{target} (inurl:wp-content OR inurl:wp-includes)"),
    DorkCategory("flash_swf", "Flash / SWF files", "search_lead",
                 "Old Flash (.swf) files -- a source of historical DOM-based XSS findings.",
                 query_template="site:{target} ext:swf"),
    DorkCategory("wsdl_soap", "WSDL / SOAP endpoints", "search_lead",
                 "Indexed WSDL/SOAP service descriptors, useful for mapping a legacy SOAP API surface.",
                 query_template="site:{target} (filetype:wsdl OR ext:svc OR inurl:wsdl OR inurl:asmx?wsdl OR inurl:jws?wsdl)"),
    DorkCategory("pastebin_mentions", "Pastebin mentions", "search_lead",
                 "The target mentioned on pastebin.com -- a common place for leaked creds/configs.",
                 query_template="site:pastebin.com {target}"),
    DorkCategory("throwbin_mentions", "Throwbin mentions", "search_lead",
                 "The target mentioned on throwbin.io, a second paste-style service.",
                 query_template="site:throwbin.io {target}"),
    DorkCategory("code_sharing_sites", "Code-sharing / paste sites", "search_lead",
                 "The target mentioned across several smaller code/paste-sharing sites at once.",
                 query_template='(site:ideone.com OR site:codebeautify.org OR site:codeshare.io OR site:codepen.io OR site:repl.it OR site:justpaste.it OR site:jsfiddle.net OR site:trello.com) "{target}"'),
    DorkCategory("atlassian_bitbucket", "Atlassian / Bitbucket", "search_lead",
                 "The target mentioned on an *.atlassian.net site or bitbucket.org.",
                 query_template='(site:*.atlassian.net OR site:bitbucket.org) "{target}"'),
    DorkCategory("gitlab_instances", "GitLab instances", "search_lead",
                 "Pages whose URL contains 'gitlab' alongside the target -- a self-hosted GitLab instance.",
                 query_template='inurl:gitlab "{target}"'),
    DorkCategory("stackoverflow_mentions", "StackOverflow mentions", "search_lead",
                 "The target mentioned in a StackOverflow question/answer -- sometimes real internal "
                 "code/config pasted in while asking for help.",
                 query_template='site:stackoverflow.com "{target}"'),
    DorkCategory("s3_buckets", "AWS S3 buckets", "search_lead",
                 "Indexed s3.amazonaws.com URLs mentioning the target -- a possible open/misconfigured bucket. "
                 "This only surfaces a LEAD (a bucket name mentioned somewhere); once you have a real "
                 "https://<bucket>.s3.amazonaws.com URL from here (or from subdomain/CT-log recon), run "
                 "cloud_bucket_scan against it to actually test anonymous read/write access, not just note it.",
                 query_template='site:.s3.amazonaws.com "{target}"'),
    DorkCategory("digitalocean_spaces", "DigitalOcean Spaces", "search_lead",
                 "Same idea as s3_buckets, for DigitalOcean's own object-storage service -- also just a lead, "
                 "not a permission test.",
                 query_template='site:digitaloceanspaces.com "{target}"'),
    DorkCategory("linkedin_employees", "LinkedIn employees", "search_lead",
                 "LinkedIn profiles mentioning the target as an employer -- useful for phishing-"
                 "pretext/social-engineering scoping, or just mapping who works there.",
                 query_template='site:linkedin.com/in employees "{target}"'),

    # -- direct_url: a path on the TARGET's own site, handed back for the model's own
    # web_fetch/http_request tool to actually fetch (this catalog never fetches it itself).
    DorkCategory("robots_txt", "robots.txt", "direct_url",
                 "The target's own robots.txt -- disallowed paths are a cheap map of what the site "
                 "doesn't want indexed, which is sometimes exactly what's worth looking at.",
                 url_template="{origin}/robots.txt"),
    DorkCategory("crossdomain_xml", "crossdomain.xml", "direct_url",
                 "A Flash-era cross-domain policy file -- an overly permissive one is a real, still-"
                 "seen misconfiguration on older sites.",
                 url_template="{origin}/crossdomain.xml"),

    # -- external_link: a third-party OSINT service's own search URL, not a search-engine dork.
    DorkCategory("reverse_ip", "Reverse IP lookup (ViewDNS)", "external_link",
                 "Other domains hosted on the same IP as the target.",
                 url_template="https://viewdns.info/reverseip/?host={target}&t=1"),
    DorkCategory("source_code_search", "Source-code search (PublicWWW)", "external_link",
                 "Full-text search across indexed HTML/JS/CSS source for the target's own string.",
                 url_template='https://publicwww.com/websites/%22{target}%22/'),
    DorkCategory("similar_domains", "Similar / typosquat domains (DomainEye)", "external_link",
                 "Domains that look similar to the target -- typosquats/phishing lookalikes.",
                 url_template="https://domaineye.com/similar/{target}"),
    DorkCategory("cms_fingerprint", "CMS fingerprint (WhatCMS)", "external_link",
                 "Third-party CMS/technology fingerprint for the target.",
                 url_template="https://whatcms.org/?s={target}"),
    DorkCategory("reddit_mentions", "Reddit mentions", "external_link",
                 "The target mentioned in a Reddit post/comment -- sometimes an employee complaint "
                 "or an outage/incident discussion with real internal detail.",
                 url_template="https://www.reddit.com/search/?q={target}"),
    DorkCategory("youtube_mentions", "YouTube mentions", "external_link",
                 "Videos mentioning the target -- product demos/conference talks sometimes show "
                 "internal tooling or architecture on screen.",
                 url_template="https://www.youtube.com/results?search_query={target}"),
    DorkCategory("openbugbounty_history", "OpenBugBounty history", "external_link",
                 "Past publicly-disclosed reports against this domain on OpenBugBounty.",
                 url_template="https://www.openbugbounty.org/search/?search={target}"),
    DorkCategory("wayback_snapshots_ui", "Wayback snapshots (browsable UI)", "external_link",
                 "The Wayback Machine's own human-browsable calendar/snapshot UI for the target -- "
                 "wayback_archive below is the machine-readable CDX equivalent for the model itself.",
                 url_template="https://web.archive.org/web/*/{target}/*"),

    # -- native_tool: dispatches to an existing ASRA native tool, real fetch, real result.
    DorkCategory("crt_transparency", "Certificate Transparency (crt.sh)", "native_tool",
                 "Subdomains observed in public TLS certificates -- same as ASRA's own crt_sh_lookup tool.",
                 native_fn=crt_sh_lookup, native_param_key="domain", native_tool_spec_name="crt_sh_lookup"),
    DorkCategory("wayback_archive", "Wayback Machine URLs", "native_tool",
                 "Historical URLs from the Wayback Machine's CDX API -- same as ASRA's own wayback_urls tool.",
                 native_fn=wayback_urls, native_param_key="domain", native_tool_spec_name="wayback_urls"),
    DorkCategory("common_crawl", "Common Crawl URLs", "native_tool",
                 "Historical URLs from Common Crawl's own independent index -- same as ASRA's own common_crawl_urls tool.",
                 native_fn=common_crawl_urls, native_param_key="domain", native_tool_spec_name="common_crawl_urls"),
    DorkCategory("whois", "WHOIS", "native_tool",
                 "Raw WHOIS record for the target -- same as ASRA's own whois_lookup tool.",
                 native_fn=whois_lookup, native_param_key="domain", native_tool_spec_name="whois_lookup"),
    DorkCategory("dns_resolve", "DNS resolution", "native_tool",
                 "Resolves the target to its IP addresses -- same as ASRA's own dns_lookup tool.",
                 native_fn=dns_lookup, native_param_key="domain", native_tool_spec_name="dns_lookup"),
    DorkCategory("passive_dns", "Passive DNS (OTX)", "native_tool",
                 "Historical hostname/IP pairings from AlienVault OTX -- same as ASRA's own "
                 "otx_passive_dns tool; requires a free OTX API key (Settings -> Tool API Keys).",
                 native_fn=otx_passive_dns, native_param_key="domain", native_tool_spec_name="otx_passive_dns"),
    DorkCategory("urlscan_history", "urlscan.io history", "native_tool",
                 "Previously-submitted urlscan.io scans of the target -- same as ASRA's own urlscan_search tool.",
                 native_fn=urlscan_search, native_param_key="domain", native_tool_spec_name="urlscan_search"),
    DorkCategory("security_headers", "Security headers audit", "native_tool",
                 "Live HTTP security-header check on the target -- same as ASRA's own security_headers_audit tool.",
                 native_fn=security_headers_audit, native_param_key="target", native_tool_spec_name="security_headers_audit"),
]

_CATALOG_BY_ID: dict[str, DorkCategory] = {c.id: c for c in _CATALOG}


def list_dork_categories() -> list[DorkCategory]:
    """Single source of truth for both dork_search's own JSON schema (`category` enum,
    agent/tools/__init__.py) and the manual Dorks tab's quick-button grid."""
    return list(_CATALOG)


def get_dork_category(category_id: str) -> DorkCategory | None:
    return _CATALOG_BY_ID.get(category_id)


def normalize_dork_target(raw: str) -> tuple[str, str] | tuple[None, None]:
    """Turns whatever the operator/model typed (a bare domain, an IP, a full URL, or a
    "*.example.com" bug-bounty-style wildcard entry -- the same shapes the New Project form's own
    Target(s) field accepts) into (host, origin): `host` is the bare hostname/IP (what the
    domain-keyed native tools and every `site:{target}` dork want); `origin` is a full
    "scheme://host" (what security_headers_audit and the direct_url categories want). Returns
    (None, None) for anything extract_hostname itself can't make sense of."""
    raw = raw.strip()
    if raw.startswith("*."):
        raw = raw[2:]
    host = extract_hostname(raw)
    if not host:
        return None, None
    if "://" in raw:
        scheme = raw.split("://", 1)[0].lower()
        origin = f"{scheme}://{host}"
    else:
        origin = f"https://{host}"
    return host, origin


def build_dork_result(*, target: str | None, category_id: str | None, custom_dork: str | None, engine: str) -> dict:
    """Core of the dork_search native tool -- also used directly by the manual Dorks tab's own
    /api/dorks/build route (main.py) so the tab and the agent tool build byte-identical URLs from
    the same code, never two hand-maintained copies."""
    if engine not in SEARCH_ENGINES:
        return {"status": "error", "error": f"unknown engine {engine!r} -- choose one of {sorted(SEARCH_ENGINES)}"}

    host = origin = None
    if target:
        host, origin = normalize_dork_target(target)
        if host is None:
            return {"status": "error", "error": f"couldn't parse {target!r} as a host, IP, or URL"}

    category = _CATALOG_BY_ID.get(category_id) if category_id else None
    if category_id and category is None:
        return {"status": "error", "error": f"unknown dork category {category_id!r} -- see list_dork_categories()"}

    if category and category.kind == "native_tool":
        if host is None:
            return {"status": "error", "error": f"category {category_id!r} requires a target"}
        sub_params = {category.native_param_key: origin if category.native_param_key == "target" else host}
        api_key = get_tool_api_key(category.native_tool_spec_name)
        if api_key:
            sub_params["_api_key"] = api_key
        result = category.native_fn(sub_params)
        result["dork_category"] = category_id
        return result

    if category and category.kind in ("external_link", "direct_url"):
        if host is None:
            return {"status": "error", "error": f"category {category_id!r} requires a target"}
        url = category.url_template.format(
            target=quote(host, safe=""),
            origin=origin,
        )
        return {
            "status": "lead",
            "kind": category.kind,
            "dork_category": category_id,
            "label": category.label,
            "url": url,
            "note": "Not fetched automatically -- pass this URL to your own web_fetch/browser tool if you "
                    "want to follow it up, or hand it to the operator as a lead.",
        }

    # search_lead, or a bare custom_dork with no matching/given category.
    if category:
        if host is None:
            return {"status": "error", "error": f"category {category_id!r} requires a target"}
        query = category.query_template.format(target=host)
    elif custom_dork and host:
        query = f"site:{host} {custom_dork}"
    elif custom_dork:
        query = custom_dork
    else:
        return {"status": "error", "error": "provide a target and/or category, or a custom_dork"}

    url = SEARCH_ENGINES[engine].format(query=quote(query, safe=""))
    return {
        "status": "lead",
        "kind": "search_lead",
        "dork_category": category_id,
        "engine": engine,
        "query": query,
        "url": url,
        "note": "A search-engine query, not a fetched result -- most engines rate-limit/CAPTCHA "
                "automated hits. Use your own web_fetch/browser tool on this URL if you want to try, "
                "or report it to the operator as a manual lead.",
    }


def dork_search_native(params: dict) -> dict:
    """ToolSpec.native_function for "dork_search" (agent/tools/__init__.py). See build_dork_result
    for the actual logic -- this just unpacks the model-facing params dict into its keywords."""
    return build_dork_result(
        target=params.get("target"),
        category_id=params.get("category"),
        custom_dork=params.get("custom_dork"),
        engine=params.get("engine") or DEFAULT_ENGINE,
    )
