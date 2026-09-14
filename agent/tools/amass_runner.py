"""amass_enum: OWASP Amass (github.com/owasp-amass/amass) active subdomain brute-force + recursion,
run as a real external subprocess but wrapped as one tier-1 native tool -- not a builders/*.py
tier-2 ToolSpec, because Amass v5's own CLI genuinely needs two separate invocations to get a plain
list of discovered names back (confirmed live against v5.1.1, not assumed from older docs):

    amass enum -d <domain> -brute [-w <wordlist>] -timeout <minutes> -silent -dir <tmpdir>
    amass subs -names -nocolor -d <domain> -dir <tmpdir>

`enum` populates a local graph datastore under -dir and prints NOTHING itself even without
-silent; `subs -names` is the separate query step that actually reads that datastore back out as
plain hostnames (or the literal line "No names were discovered"). agent/tools/runner.py's generic
tier-2 runner only ever dispatches ONE command per ToolSpec, so this two-step flow is orchestrated
here in Python instead -- same "compound tool with a real external binary underneath" precedent as
agent/tools/wp_batch_rce.py.

Real gap this closes: neither crt_sh_lookup (needs a TLS cert) nor subfinder (passive OSINT
aggregation only) nor subdomain_enum (even with a large assigned wordlist -- see native.py) does
active brute-force WITH wildcard-DNS detection, recursive re-brute-forcing of found names, and
name-alteration/permutation generation (dev-api from api, api-v2 from api-v1, ...) -- Amass's own
job specifically, not a bigger wordlist's.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

from agent.tools.wordlist_store import get_assigned_wordlist
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_ENUM_TIMEOUT_MINUTES = int(os.getenv("AMASS_ENUM_TIMEOUT_MINUTES", "2"))
# Buffer over the -timeout value amass itself is told to respect -- amass's own internal deadline
# fires first in the normal case; this is only a backstop for the rare case it doesn't (a hung DNS
# resolver, a wedged data source) so the subprocess call itself is still guaranteed to return.
_ENUM_SUBPROCESS_TIMEOUT_SECONDS = _ENUM_TIMEOUT_MINUTES * 60 + 60
# amass subs -names only reads the local graph datastore enum just wrote -- no network calls of its
# own, so a short fixed timeout (not a separate env var) is appropriate, same as otx_passive_dns's
# own hardcoded 20.0s client timeout for a comparably small, bounded lookup.
_SUBS_SUBPROCESS_TIMEOUT_SECONDS = 30


def _resolve_amass_path() -> str | None:
    # Same {TOOL}_PATH override convention as runner.py's _resolve_executable (NMAP_PATH,
    # HTTPX_PATH, ...) -- kept independent of that tier-2-only helper since this tool dispatches
    # its own subprocess calls directly rather than going through run_tool().
    override = os.getenv("AMASS_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    return shutil.which("amass")


def amass_available() -> bool:
    """ToolSpec.availability_check for amass_enum -- same reasoning as the browser_* tools' own
    Playwright-Chromium check (registry.py's ToolSpec docstring): a tier-1 native tool whose real
    dependency is an external binary the Python code doesn't itself carry must not report
    "always installed" like an ordinary tier-1 tool would."""
    return _resolve_amass_path() is not None


def _parse_amass_subs_output(stdout: str, domain: str) -> list[str]:
    text = stdout.strip()
    if not text or "No names were discovered" in text:
        return []
    names: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        candidate = line.split()[0].strip().rstrip(".")
        if domain in candidate:
            names.add(candidate)
    return sorted(names)


def amass_enum(params: dict) -> dict:
    domain = params["domain"].strip()
    if not domain:
        return {"status": "error", "error": "domain must not be empty."}

    amass_path = _resolve_amass_path()
    if amass_path is None:
        return {"status": "tool_unavailable", "tool": "amass_enum"}

    wordlist_path = get_assigned_wordlist("subdomain_enum")
    tmp_dir = tempfile.mkdtemp(prefix="asra-amass-")
    try:
        enum_command = [
            amass_path, "enum", "-d", domain, "-brute",
            "-timeout", str(_ENUM_TIMEOUT_MINUTES), "-silent", "-dir", tmp_dir,
        ]
        if wordlist_path:
            enum_command += ["-w", wordlist_path]

        logger.debug("amass_enum: domain=%s wordlist=%s timeout_minutes=%d", domain, wordlist_path or "(amass built-in)", _ENUM_TIMEOUT_MINUTES)
        try:
            enum_result = subprocess.run(
                enum_command, capture_output=True, text=True,
                timeout=_ENUM_SUBPROCESS_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            logger.debug("amass_enum: domain=%s enum step timed out after %ss", domain, _ENUM_SUBPROCESS_TIMEOUT_SECONDS)
            return {"status": "timeout", "tool": "amass_enum", "domain": domain}

        if enum_result.returncode != 0:
            logger.debug("amass_enum: domain=%s enum step failed rc=%d stderr=%s", domain, enum_result.returncode, enum_result.stderr[:500])
            return {"status": "error", "tool": "amass_enum", "error": enum_result.stderr.strip() or f"amass enum exited {enum_result.returncode}"}

        subs_command = [amass_path, "subs", "-names", "-nocolor", "-d", domain, "-dir", tmp_dir]
        try:
            subs_result = subprocess.run(
                subs_command, capture_output=True, text=True,
                timeout=_SUBS_SUBPROCESS_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            logger.debug("amass_enum: domain=%s subs step timed out after %ss", domain, _SUBS_SUBPROCESS_TIMEOUT_SECONDS)
            return {"status": "timeout", "tool": "amass_enum", "domain": domain}

        subdomains = _parse_amass_subs_output(subs_result.stdout, domain)
        logger.debug("amass_enum: domain=%s found=%d", domain, len(subdomains))
        return {"status": "ok", "domain": domain, "subdomains": subdomains, "wordlist": wordlist_path or "(amass built-in default)"}
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
