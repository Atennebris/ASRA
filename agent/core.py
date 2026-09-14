"""ReAct-cycle orchestrator: Recon -> Analyze -> Exploit -> Validate.

Each sub-phase is one LLM<->tools conversation (_run_llm_tool_loop): the model gets a system
prompt (agent/prompts.py) plus whatever tools its registry category exposes, and calls tools
until it's done. Tool selection is by category, never by a hardcoded name — a new registry entry
(built-in, autodiscovered, or from custom_tools.yaml) is picked up automatically the next time
its category is used.

Recon/Analyze report structured data live: record_target/record_finding tool calls persist into
session["recon_result"]/session["findings"] the instant the model reports them (see the execute
closures in _run_recon/_run_analyze), not batched into a final JSON answer at phase end — a
process crash mid-phase loses nothing already found. Exploit mutates each finding's schema
fields (exploited/evidence/poc_command/advisory_note) in place, persisted right after that one
finding is resolved — no parallel "exploit_records" structure to reconcile later. Validate runs
once at the end purely to deduplicate; it is no longer the sole creator of finding data, so a
session that never reaches Validate (crash, budget cutoff) still ends with real, schema-complete
findings, just not deduplicated.

entry_point (run_session's parameter) picks where a run starts — "recon" (default, full
pipeline), "analyze" (skips Recon, needs session["recon_result"] already present), or "exploit"
(skips Recon+Analyze, needs session["findings"] already present). It's chosen once at the start
of a run, not a live state machine — after entering at that point, the remaining sub-phases still
run in their normal order.

Every LLM call in a session (sub-phase conversations, exploit-approval-gated calls, 1-step
retry corrections, exploit-result confirmation) goes through RunContext/_llm_complete, the single
choke point that counts and logs them — no cap on the total, and no cap on tool-calling rounds
within a phase either. A fixed count cap (either one) has the same flaw regardless of where it
sits: it cuts off legitimate work the moment a scope is big enough to need more calls than
whatever number seemed reasonable in isolation — a scan covering many subdomains/targets can
legitimately need far more tool calls than one covering a single host, and a count cap can't tell
the difference between "still making progress" and "actually stuck". _run_llm_tool_loop instead
detects an actual stall directly: the same tool call (name + arguments) repeated identically
_STALL_REPEAT_THRESHOLD times in a row ends that phase — real, distinct work never trips it no
matter how much of it there is. A generous, non-configurable wall-clock backstop per phase
(_PHASE_WALLCLOCK_LIMIT_SECONDS) exists purely as a last-resort safety valve for a genuine bug
that produces endless non-repeating garbage; it is not meant to be reachable by legitimate use.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import fnmatch
import ipaddress
import json
import os
import re
import time
import unicodedata
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Awaitable, Callable

from agent.llm_client import (
    PROVIDER_REGISTRY,
    EmptyResponseError,
    LLMCallAborted,
    LLMProvider,
    LLMResponse,
    ProviderConfig,
    ToolCallRequest,
    current_backoff_accumulator,
    get_fallback_chain,
    get_fallback_chain_enabled,
    get_next_chain_step,
    get_provider,
)
from agent.providers.models_dev import get_model_cost
from agent.settings import get_secondary_verification_provider, load_llm_settings
from agent.prompts import (
    ANALYZE_PROMPT,
    CHAIN_PROMPT,
    CONFIRM_EXPLOIT_PROMPT,
    DEEP_DIVE_ADDENDUM,
    DETECTION_SECOND_OPINION_PROMPT,
    EXPLOIT_PROMPT,
    HYPOTHESIS_STRUCTURING_PROMPT,
    HYPOTHESIS_VERIFICATION_PROMPT,
    PLAYBOOK_DISTILLATION_PROMPT,
    PLAYBOOK_STRATEGY_PROMPT,
    RECON_PROMPT,
    RE_CHAT_PROMPT,
    RE_EXPERIENCE_LEVEL_ADDENDA,
    RE_TRIAGE_PROMPT,
    REVERIFY_PROMPT,
    SKEPTICAL_VERIFICATION_PROMPT,
    VALIDATE_PROMPT,
)
from agent.tools.allowed_targets import authorize_exploit_targets, extract_hostname, is_target_allowed, is_target_out_of_scope
from agent.tools.background_jobs import await_all_running_jobs, kill_all_running_jobs
from agent.tools.browser_manager import get_browser_manager, interpret_browser_navigate_permanent_failure
from agent.tools import subagent_tasks
from agent.tools.subagent_store import get_enabled_profiles, get_profile_by_name
from agent.tools.builders.apktool import parse_apktool_output
from agent.tools.builders.binwalk import parse_binwalk_output
from agent.tools.builders.qiling import parse_qiling_output
from agent.tools.builders.dalfox import parse_dalfox_output
from agent.tools.builders.validators import validate_scope_entry
from agent.tools.builders.discovered import get_tool_help
from agent.tools.builders.exploit import parse_exploit_output, parse_msf_module_search
from agent.tools.builders.ffuf import interpret_ffuf_failure, parse_ffuf_output
from agent.tools.builders.frida import parse_frida_ps_output, parse_frida_trace_output
from agent.tools.builders.gdb import parse_gdb_output
from agent.tools.builders.heimdall import parse_heimdall_output
from agent.tools.builders.ilspycmd import parse_ilspycmd_output
from agent.tools.builders.jadx import parse_jadx_output
from agent.tools.builders.mythril import parse_mythril_output
from agent.tools.builders.nmap import parse_nmap_output
from agent.tools.builders.nuclei import interpret_nuclei_failure, parse_nuclei_output
from agent.tools.builders.osv_scanner import parse_osv_scanner_output
from agent.tools.builders.radare2 import parse_radare2_output
from agent.tools.builders.radiff2 import parse_radiff2_output
from agent.tools.builders.semgrep import parse_semgrep_output
from agent.tools.builders.slither import parse_slither_output
from agent.tools.builders.sqlmap import parse_sqlmap_output
from agent.tools.builders.subfinder import parse_subfinder_output
from agent.tools.builders.trufflehog import parse_trufflehog_output
from agent.tools.builders.tshark import parse_tshark_capture_output, parse_tshark_read_pcap_output
from agent.tools.builders.upx import interpret_upx_not_packed, parse_upx_output
from agent.tools.builders.whatweb import interpret_whatweb_degraded_ok, interpret_whatweb_timeout, parse_whatweb_output
from agent.tools.builders.wpscan import interpret_wpscan_timeout, parse_wpscan_output
from agent.tools.cache import cache_get, cache_set
from agent.tools.discovery import interpret_httpx_failure
from agent.tools.js_fingerprint import run_js_fingerprint
from agent.tools.native import _derive_plan_status, _VALID_SEVERITIES, classify_ip_role, geoip_lookup, interpret_arjun_crash, interpret_arjun_failure, interpret_github_code_search_permanent_failure, interpret_missing_identity, interpret_permanent_connection_refusal, interpret_ssl_cert_info_failure, register_discovered_credential, version_is_ruled_out
from agent.tools.notifications import notify_high_severity_finding, notify_session_ended
from agent.tools import playbook_store, tool_memory_store

# Importing agent.tools.registry forces Python to first fully run agent/tools/__init__.py (the
# composition root that populates TOOL_REGISTRY) — spelled out explicitly rather than relied on
# implicitly, since it's easy to miss that package-init side effect on a later refactor.
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools.registry import ToolSpec, categories_of, get_tool, get_tools_by_category, register_tool
from agent.tools.runner import _loggable_params, current_subprocess_registry, run_tool
from agent.tools.tool_api_keys import get_tool_api_key
from agent.tools.toolkit_settings_store import load_toolkit_agent_settings
from agent.utils.debug import current_session_id, current_subagent_label
from agent.utils.lazy_openai import openai
from agent.utils.logger import get_logger
from sessions.store import create_session, get_session_folder, list_session_summaries, load_session, reset_plan_for_new_pass, save_session
from sessions.store import reload_merge_save as _reload_merge_save

logger = get_logger("AGENT")
# Everything specific to the Subagent-delegation lifecycle (delegate/reject/finish, plus a
# delegated subagent's own LLM turns — see _llm_complete) logs through this instead of the plain
# "AGENT" logger above, so it renders in its own color in the debug console (agent/utils/debug.py's
# CATEGORY_COLORS) instead of blending into the main agent's own, much larger volume of AGENT logs.
_subagent_logger = get_logger("SUBAGENT")
# Cross-session technique capture/lookup/distillation (agent/tools/playbook_store.py's own
# read/write logs already use this category too) — same "own category, own color" reasoning as
# _subagent_logger above.
_playbook_logger = get_logger("PLAYBOOK")
# _dispatch_browser_tool bypasses run_tool() entirely (see its own docstring), so without this the
# 9 browser_* tools got zero TOOLS-category debug coverage at all -- confirmed live: this was
# discovered as a real gap during a log-review that specifically needed to see why browser_evaluate
# calls looked like they weren't returning results, and there was nothing in debug.log to check.
_tools_logger = get_logger("TOOLS")


def _log_agent_debug(ctx: RunContext, msg: str, *args) -> None:
    """Routes a debug line through _subagent_logger (with subagent name/task_id inserted right
    after session=%s, same shape as every other SUBAGENT-category line) when ctx belongs to a
    delegated subagent's own RunContext, or plain `logger` otherwise. `msg` must NOT include its
    own "core: session=%s " prefix -- this helper supplies it (and, for a subagent, the
    subagent=%r task=%s that goes with it) so every call site stays consistent automatically
    instead of hand-rolling the same branch.

    Real, confirmed incident this fixes: _run_tool_with_retry's own ~10 debug lines (skip/retry/
    failure logging, used by both the main loop and every delegated subagent's own tool calls)
    never applied this routing at all -- only the "llm call N" line a few lines below did. A
    session with an active subagent produced debug.log output where a retry/failure line for the
    SUBAGENT's own tool call was visually indistinguishable from the main loop's, genuinely
    misleading a real log-review audit until traced through the source.
    """
    if ctx.subagent_name:
        _subagent_logger.debug(
            "core: session=%s subagent=%r task=%s " + msg, ctx.session_id, ctx.subagent_name, ctx.subagent_task_id, *args,
        )
    else:
        logger.debug("core: session=%s " + msg, ctx.session_id, *args)


_TOOL_RESULT_CHAR_LIMIT = 8000
# Loop/stall protection for _run_llm_tool_loop — see the module docstring for why this replaced
# a fixed per-phase call-count cap.
_STALL_REPEAT_THRESHOLD = 6
# A narrower, earlier guard than _STALL_REPEAT_THRESHOLD above -- that one only stops a phase once
# the exact same call repeats _STALL_REPEAT_THRESHOLD times literally BACK TO BACK (any different
# call in between resets it to zero), which is deliberately strict so real, varied work never
# trips it. Real incident this misses: a session called dns_lookup on the same non-resolving
# domain 8 times total across an ~30-minute recon phase, in two separate bursts of 3 and 5 (a
# different call landed in between the bursts) -- both bursts stayed under the 6-in-a-row bar, so
# neither ever tripped it, and every one of the 8 independently failed with the identical error
# (each already having gone through its own internal 1-Step Retry too, so 8 top-level failures was
# really ~16 real dispatches underneath). Lowering _STALL_REPEAT_THRESHOLD itself to catch this
# would risk cutting off a legitimately varied session that happens to retry the same call a few
# times for good reason. Keying this second guard off FAILURE specifically avoids that risk instead
# of trading it for a different one: a call that keeps failing with identical arguments is not
# going to start succeeding without different arguments, so blocking a further identical attempt
# once it's already failed this many times has no legitimate case it could be wrongly cutting off
# — unlike a call that keeps SUCCEEDING with identical arguments (a deliberate poll, a periodic
# recheck), which this guard never touches at all.
_MAX_IDENTICAL_FAILURES_PER_PHASE = 2
# A third, still narrower guard than both of the above -- keyed by TOOL NAME alone, not by call
# signature, for a failure class that keeps varying its own arguments so neither
# _STALL_REPEAT_THRESHOLD (needs a byte-identical call) nor _MAX_IDENTICAL_FAILURES_PER_PHASE (keyed
# by the exact, ever-changing signature) ever sees the same key twice. Real, confirmed incident
# (NinthCircle-crackmes-usr_04a301): a fallback-tier subagent model burned its entire
# SUBAGENT_TASK_TIMEOUT_SECONDS budget re-guessing radare2's `analysis` enum with 9 different
# invalid r2-command strings over 25+ minutes -- each one correctly caught and 1-Step-Retry-corrected
# on its own (build_command's own ValueError, runner.py's never_dispatched marker), but the
# correction is a stateless side-channel that never carries forward into the task's own conversation,
# so the model never "learned" not to keep guessing at this tool's shape. Only ever counted for a
# never_dispatched failure specifically -- a real dispatch that happened to fail says nothing about
# schema comprehension and doesn't belong in this counter.
_MAX_SCHEMA_VIOLATIONS_PER_PHASE = 3
_PHASE_WALLCLOCK_LIMIT_SECONDS = 7200
# _run_reverify's own cross-rescan memory (session["past_reverification_outcomes"]) -- bounded per
# TITLE, not overall, so a long-lived engagement rescanned many times keeps each finding's own
# recent trend without one heavily-rescanned title crowding out every other title's history.
_MAX_PAST_REVERIFICATION_ENTRIES_PER_TITLE = 3
# session["past_hypothesis_outcomes"]'s own cross-rescan memory (_resolve_hypothesis) -- same
# per-key cap, keyed by hypothesis text instead of finding title.
_MAX_PAST_HYPOTHESIS_OUTCOMES_PER_TEXT = 3
# _run_reverify effort-calibration thresholds: once a title's trailing verdicts in
# past_reverification_outcomes agree this many times in a row, the reverify pass for it gets a
# tighter (but still non-zero) tool-call budget -- see _stable_outcome_streak/_run_reverify. Soft
# calibration only, never a skip: terminal_tool="record_reverification_result" already guarantees
# at least one real tool call happens before a verdict is possible, this only tightens the ceiling.
_REVERIFY_STABLE_TREND_MIN_STREAK = 3
_REVERIFY_CALIBRATED_MAX_TOOL_CALLS = 3

# Tool calls whose SUCCESS means the pass produced real, durable state a resume/report can build on
# -- the only kind of progress a "no-progress stall" guard should count. A phase that keeps
# dispatching read-only analysis tool after tool without ever recording one of these is spinning:
# it produces nothing that survives the pass, nothing a resumed run inherits, nothing the operator
# reads. Real incident this exists for: an RE baseline pass ran 93 tool calls over 1h46m across two
# runs and recorded ZERO findings/hypotheses (only 4 target-profile facts, all in the first ~16
# calls) -- the back-to-back-only _STALL_REPEAT_THRESHOLD never tripped (every call differed
# slightly), so nothing stopped it until the operator killed it by hand.
_PROGRESS_RECORDING_TOOLS = frozenset(
    {"record_finding", "record_target_profile", "record_hypothesis", "resolve_hypothesis", "record_technique"}
)

# Tool-result fields that mean "a deterministic check in agent/tools/native.py already confirmed a
# real vulnerability" (see http_request's detectors) — any one of these firing gets a loud hint
# injected into the tool result, not just left for the model to maybe notice on its own.
_DETERMINISTIC_DETECTION_FIELDS = (
    "reflected_payload_detected",
    "sql_error_detected",
    "open_redirect_detected",
    "command_injection_detected",
)

_GENERIC_DISCOVERED_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "Target host/URL this call is about — required for scope tracking, but unlike "
                "most other tools it is NOT automatically added to the actual command line for "
                "you. You must ALSO put it into extra_args yourself, using whichever flag this "
                "specific tool's own --help text below documents for its target (commonly -u, -l, "
                "-h, or a bare positional argument) — every tool's own convention differs."
            ),
        },
        "extra_args": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Extra CLI flags/arguments for this tool, based on its --help text below — this is where the target itself has to go too, see \"target\" above.",
        },
    },
    "required": ["target"],
}

# Structured parsers for the hand-written subprocess tools (agent/tools/builders/*) — reused as-is
# rather than asking the LLM to re-derive them from raw, ANSI-laden CLI output.
# Autodiscovered/custom tools deliberately have no entry here: their raw stdout goes to the model
# unparsed, by design (agent/tools/builders/discovered.py).
_OUTPUT_PARSERS: dict[str, Callable[[str], object]] = {
    "nmap": parse_nmap_output,
    "nuclei": parse_nuclei_output,
    "dalfox": parse_dalfox_output,
    "exploit": parse_exploit_output,
    "msf_module_search": parse_msf_module_search,
    "sqlmap": parse_sqlmap_output,
    "whatweb": parse_whatweb_output,
    "wpscan": parse_wpscan_output,
    "ffuf": parse_ffuf_output,
    "subfinder": parse_subfinder_output,
    "radare2": parse_radare2_output,
    "gdb": parse_gdb_output,
    "qiling_emulate": parse_qiling_output,
    "slither": parse_slither_output,
    "heimdall_decompile": parse_heimdall_output,
    "ilspycmd": parse_ilspycmd_output,
    "semgrep": parse_semgrep_output,
    "osv_scanner": parse_osv_scanner_output,
    "trufflehog": parse_trufflehog_output,
    "upx": parse_upx_output,
    "mythril": parse_mythril_output,
    "apktool": parse_apktool_output,
    "jadx": parse_jadx_output,
    "binwalk": parse_binwalk_output,
    "radiff2": parse_radiff2_output,
    "frida_trace": parse_frida_trace_output,
    "frida_ps": parse_frida_ps_output,
    "tshark_capture": parse_tshark_capture_output,
    "tshark_read_pcap": parse_tshark_read_pcap_output,
}

# Same registration shape as _OUTPUT_PARSERS above, for the opposite case: a tool-specific failure
# whose raw stderr/stdout gives the model nothing actionable to work with (confirmed live: nuclei's
# own "no templates provided for scan" FTL error, buried in an ANSI-colored banner, cost one session
# 6+ wasted 1-Step Retry round-trips guessing at nonexistent tag names). Applied in
# _apply_output_parser, same checkpoint every tool result already passes through.
_ERROR_HINTS: dict[str, Callable[[dict], str | None]] = {
    "nuclei": interpret_nuclei_failure,
    "ffuf": interpret_ffuf_failure,
    "httpx": interpret_httpx_failure,
    "wpscan": interpret_wpscan_timeout,
    "whatweb": interpret_whatweb_timeout,
    "arjun": interpret_arjun_failure,
    "ssl_cert_info": interpret_ssl_cert_info_failure,
}

# A NARROWER sibling of _ERROR_HINTS above, for a failure that isn't just low-signal but
# genuinely, deterministically unfixable by ANY corrected argument -- a good hint alone still lets
# _run_tool_with_retry pay for one real 1-Step Retry round-trip anyway, since _RETRYABLE_STATUSES
# only checks the result's status ("error"/"timeout"), never whether _ERROR_HINTS already told the
# model this exact failure can't be fixed. Confirmed live (a real YesWeHack session, usr_45dd32): Arjun's
# known upstream initialize() crash (interpret_arjun_crash below, already correctly identified and
# wired into _ERROR_HINTS["arjun"] above) still cost a real ~25-44s LLM round-trip on the
# guaranteed-to-fail correction call, because a hint was all _ERROR_HINTS could ever offer -- it has
# no way to also skip the retry itself. Checked FIRST in _apply_output_parser, before _ERROR_HINTS:
# when a permanent hint fires, the result's own status flips to "failed" (not in
# _RETRYABLE_STATUSES) so _run_tool_with_retry short-circuits straight past the correction call,
# same "don't pay for a call you already know is doomed" family as guardrail rejections using
# "skipped" instead of "error". Deliberately NOT interpret_arjun_failure (the combined dispatcher
# _ERROR_HINTS["arjun"] uses) -- only the crash half is genuinely argument-independent; the timeout
# half (interpret_arjun_timeout) is NOT permanent, a retry that actually drops --stable can still
# succeed, so it must keep going through the normal one-retry path unchanged.
_PERMANENT_ERROR_HINTS: dict[str, Callable[[dict], str | None]] = {
    "arjun": interpret_arjun_crash,
    "upx": interpret_upx_not_packed,
    # All seven share the exact same underlying check (_get_authenticated_client /
    # get_identity_browser_creds in agent/tools/native.py) and therefore the exact same
    # "permanent, deterministic condition for this project" error text interpret_missing_identity
    # matches on -- see that function's own docstring for the confirmed incident.
    "cors_credentialed_check": interpret_missing_identity,
    "authenticated_request": interpret_missing_identity,
    "authenticated_crawl": interpret_missing_identity,
    "idor_probe": interpret_missing_identity,
    "graphql_authz_probe": interpret_missing_identity,
    "graphql_batching_probe": interpret_missing_identity,
    "browser_navigate": interpret_browser_navigate_permanent_failure,
    "github_code_search": interpret_github_code_search_permanent_failure,
    # See interpret_permanent_connection_refusal's own docstring for the confirmed incident
    # (a real HackerOne session: 19 doomed 1-Step Retries against the same refused/unreachable
    # host:port during subdomain enumeration).
    "http_request": interpret_permanent_connection_refusal,
}

# A third sibling of _ERROR_HINTS/_PERMANENT_ERROR_HINTS above, for the opposite direction: a
# result that came back status="ok" (no retry ever triggers) but whose own stderr shows it was
# actually degraded mid-run — see interpret_whatweb_degraded_ok's own docstring for the confirmed
# incident. Applied in _apply_output_parser's "ok" branch as a NOTE attached to the result, never
# a status change (the call genuinely did complete) — this is about visibility, not retryability.
_DEGRADED_OK_HINTS: dict[str, Callable[[dict], str | None]] = {
    "whatweb": interpret_whatweb_degraded_ok,
}

# A tool call ending in one of these can plausibly be fixed by different arguments (bad flag,
# malformed target, wrong module name) — worth the one corrective retry. "skipped" (guardrail
# decision) and "tool_unavailable" (missing binary) are not fixable by different arguments, so
# they're deliberately excluded.
_RETRYABLE_STATUSES = {"error", "timeout"}

# _run_tool_with_retry's own bookkeeping fields — never part of a tool's real output, so a
# terminal_tool result (where the whole dict becomes the phase's final answer, see
# _run_llm_tool_loop) must strip these too, not just "status".
_TOOL_RETRY_BOOKKEEPING_KEYS = {"status", "retried", "used_arguments", "schema_violation_corrected"}

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# The session schema (sessions/store.py) promises every finding has all of these keys.
# Analyze's own output only carries a subset (title/severity/description/verification/
# evidence_ref) — normally Validate fills in the rest, but a session can end early (an unhandled
# error, a parse failure) before Validate ever runs. Without this, downstream consumers
# (the export/UI) would hit missing keys instead of a real, if incomplete, finding.
_CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_VALID_FINDING_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_VALID_EXPLOITATION_SCENARIOS = {"remote_direct", "mitm_active", "mitm_passive", "victim_interaction", "local_only"}

_FINDING_DEFAULTS = {
    "title": "Untitled finding",
    "severity": "Low",
    "description": "",
    "technology": None,
    "reproduction_steps": None,
    "poc_command": None,
    "exploited": False,
    "evidence": None,
    "verification": "needs_verification",
    "advisory_note": None,
    "found_at": None,
    "exploitation_scenario": None,
    # Set by record_finding's own optional cvss_vector (a model-derived vector, only when it's
    # confident in every metric) or deterministically by the cve_lookup auto-record path below when
    # the underlying CVE record itself carried a real NVD/CIRCL CVSS vector -- None for a finding
    # with no CVSS data attached at all, never a fabricated placeholder.
    "cvss_vector": None,
    # Set by record_finding's own optional "host" (main.py's Map tab attack-surface graph places a
    # finding on its host node by this field) -- None for a finding recorded before this field
    # existed, or one the model genuinely didn't tie to a specific host; renders as "unlocated"
    # rather than erroring.
    "host": None,
    # Set once, only when exploit confirmation proves the title's own host/target claim was wrong
    # (_apply_corrected_title below) — the pre-correction title, kept for audit trail rather than
    # silently overwritten, same "never discard, flag distinctly" discipline false_positive_reason
    # already follows.
    "original_title": None,
    # Set once exploit confirmation proves a real success AND the trace actually yielded a
    # concrete, reusable artifact (a credential pair, a cracked hash, a session token/cookie) --
    # real operator complaint this fixes: a successfully-exploited finding's own card looked
    # exactly like an unexploitable one, just a wall of raw evidence/reproduction-steps text with
    # no visual distinction and no short answer to "what did I actually get, and what do I do with
    # it." Both null whenever exploitation succeeded without producing a standalone artifact (e.g.
    # an XSS PoC proving script execution has no credential/token to extract) or didn't succeed at
    # all -- never fabricated, only ever a direct quote from the same real trace evidence already
    # comes from.
    "extracted_artifact": None,
    "artifact_usage_hint": None,
    # Set by record_exploit_decision's own optional remediation_advice (_apply_remediation_advice)
    # once Exploit concludes, regardless of whether exploitation was attempted or skipped — a
    # concrete, no-fluff "what do I actually do about this" for the finding card, not a restatement
    # of the description. None for a finding that hasn't reached Exploit yet, or an older session
    # from before this field existed.
    "remediation_advice": None,
    # Set once _run_skeptical_verification (the blind, independent second-opinion pass, run_session's
    # own final step before "completed") actually checks a "verified" finding. None means it never
    # ran on this finding at all (not the same as "inconclusive" -- that means it DID run and
    # genuinely couldn't reach a real yes/no). "refuted" is the one outcome that also downgrades
    # this finding's own "verification" field back to "needs_verification" -- see that function's
    # own docstring for why the finding is never silently dropped, only honestly relabeled.
    "skeptical_verification": None,
    "skeptical_verification_note": None,
    # Set once Exploit resolves this finding one way or another — distinguishes a real negative
    # test ("exploit_attempted", tool ran, didn't succeed) from every "never actually tested" skip
    # reason ("skipped_no_suitable_tool", "skipped_needs_verification", "skipped_operator",
    # "skipped_ruled_out", "skipped_out_of_scope", "skipped_no_target", "skipped_unspecified").
    # Real operator complaint this fixes: exploited=False alone collapsed all of these into one
    # indistinguishable "Not exploitable" badge — a genuinely tested-and-disproven finding looked
    # identical to one Exploit never had a tool to even attempt. None means Exploit hasn't reached
    # this finding yet at all.
    "exploit_outcome": None,
}


def _normalize_findings(findings: list[dict]) -> list[dict]:
    return [{**_FINDING_DEFAULTS, **finding} for finding in findings]

# Bookkeeping/meta tool calls that don't represent real security-tool provenance -- excluded from
# the mechanical tool_timeline extraction below so a finding/hypothesis's own timeline only ever
# names the real tools that did the work, never ASRA's own record-keeping calls.
_TOOL_TIMELINE_EXCLUDED_NAMES = {
    "record_finding", "record_exploit_decision", "record_hypothesis", "resolve_hypothesis",
    "update_plan", "record_target",
}


def _extract_tool_timeline_entries(trace: list[dict], stage: str) -> list[dict]:
    """Distinct real tool names from a phase's own tool-call trace, first-use order -- mechanical,
    sourced from what the trace shows actually ran, never model-narrated text that could invent or
    misremember a tool name. `stage` labels where in the finding's lifecycle these calls happened
    (e.g. "exploitation") so the card can render "nmap_scan — exploitation" instead of a bare list.
    """
    seen: set[str] = set()
    entries = []
    for step in trace:
        name = step.get("tool")
        if not name or name in _TOOL_TIMELINE_EXCLUDED_NAMES or name in seen:
            continue
        seen.add(name)
        entries.append({"tool": name, "stage": stage})
    return entries


def _append_tool_timeline(entity: dict, entries: list[dict]) -> None:
    """Appends new (tool, stage) entries to a finding/hypothesis's own tool_timeline, deduped
    against what's already there -- safe to call repeatedly (e.g. a re-run deep dive) without
    piling up duplicates. Deliberately NOT a key in _FINDING_DEFAULTS -- a mutable [] default there
    would be the same list object shared across every finding missing the key, and appending to one
    would silently pollute all the others; setdefault here always creates a fresh list scoped to
    THIS one dict instead.
    """
    if not entries:
        return
    existing = entity.setdefault("tool_timeline", [])
    existing_keys = {(e["tool"], e["stage"]) for e in existing}
    existing.extend(e for e in entries if (e["tool"], e["stage"]) not in existing_keys)

_JSON_FENCE_PATTERN = re.compile(r"```(?:json)?\s*(\{.*\})\s*```", re.DOTALL)

# Module-level per-session approval signal: set by the web layer's approve-exploit endpoint,
# waited on here. Lives here rather than in main.py since core.py owns the
# wait/timeout mechanics; the web layer only ever needs to call .set() on it.
_approval_events: dict[str, asyncio.Event] = {}


def get_approval_event(session_id: str) -> asyncio.Event:
    return _approval_events.setdefault(session_id, asyncio.Event())


class SessionStopRequested(Exception):
    """Raised from _llm_complete's choke point (and from _await_exploit_approval's own wait, for
    a session paused on a human decision) once the operator confirms a Stop request -- main.py's
    /interrupt route. Unwinds cleanly to run_session's/run_focused_exploit's own handling, which
    persists status="interrupted" with a computed resume point: the same outcome a real
    asyncio.CancelledError already gets on a process-level Ctrl+C/shutdown, just requested
    deliberately from inside the running app instead.

    `reason` distinguishes WHY this was raised -- "operator" (the overwhelmingly common case, an
    explicit /interrupt click) vs "time_budget_expired" (_llm_complete's own mid-pass budget check,
    see _time_budget_expired) -- so run_session's own handler can persist which one it was
    (session["stopped_reason"]) and the UI can offer the right follow-up (Resume vs. Add time /
    Continue without a timer) instead of a single generic "stopped" state for both.
    """

    def __init__(self, reason: str = "operator") -> None:
        super().__init__(reason)
        self.reason = reason


# Same pattern as _approval_events immediately above, for a different signal: "stop the whole
# session at the next safe checkpoint" rather than "a human decided on one pending exploit". A
# session file write from the interrupt route itself would race run_session's own read-modify-
# write cycle over that same file (see _instruction_queues below for the identical reasoning) --
# this in-memory event is the only safe way to reach a live run from an HTTP request.
_stop_events: dict[str, asyncio.Event] = {}


def get_stop_event(session_id: str) -> asyncio.Event:
    return _stop_events.setdefault(session_id, asyncio.Event())


def request_session_stop(session_id: str) -> None:
    """main.py's /interrupt route calls this once the operator has confirmed the warning dialog.
    Also wakes up an in-progress exploit-approval wait (_await_exploit_approval) -- a session
    paused there isn't calling _llm_complete at all, so without this the request would sit
    unnoticed until that wait's own timeout.
    """
    get_stop_event(session_id).set()
    get_approval_event(session_id).set()


# RE-triage-only: Stop and Pause both halt run_re_triage's tool loop through the exact same
# request_session_stop/get_stop_event mechanism above -- there's no separate "pause" signal, just a
# different INTENT behind the same halt, recorded here so run_re_triage's own except branch knows
# which status to land on ("interrupted" for a deliberate Stop, "paused" for a deliberate Pause). A
# real process crash never goes through this at all -- request_session_stop is never called, so
# there's no intent to read, and the existing main.py startup orphan-sweep (_mark_orphaned_sessions_
# interrupted) keeps landing crashes on "interrupted" exactly as it always has, unchanged.
_re_stop_intent: dict[str, str] = {}


def set_re_stop_intent(session_id: str, intent: str) -> None:
    _re_stop_intent[session_id] = intent


def pop_re_stop_intent(session_id: str) -> str:
    return _re_stop_intent.pop(session_id, "stop")


# Same in-memory, keyed-by-session_id pattern as _stop_events/_approval_events above, for a
# different signal: which (provider_id, model) reserve-chain steps are already PROVEN exhausted
# this run. Real, confirmed incident this fixes: _llm_complete's own fallback loop used to build
# its "already tried" set fresh, local to that ONE call -- once ctx.llm fell back to a step that
# LATER also failed (on some future turn), the walk restarted from the top of the operator's
# configured chain and re-attempted an earlier step already proven dead this run, paying its full
# ~90-150s backoff cost again for a guaranteed-to-fail retry (a free-tier account-wide quota
# doesn't refill mid-session). Confirmed live across two real, concurrent sessions hitting the
# same opencode-zen account: a step exhausted early in the run got re-attempted three more times
# over the run's final ~5 minutes before the session finally gave up. Cleared once the whole run
# genuinely ends (see run_session's own SessionStopRequested/except-Exception handling below,
# same reasoning as get_stop_event's own clear() -- a stale exhaustion must not survive into a
# later RESUMED run, since real time passing is exactly what might let a quota refresh).
#
# Real, confirmed follow-up incident this same set's own lack of an in-run TTL caused: a real
# session (rev-retest-rescan-usr_8ba29f) configured a 7-step chain where 2 steps were permanently
# dead (a lapsed Mistral subscription, HTTP 402 -- not a quota that ever refills) alongside 5
# genuinely transient free-tier steps. Three concurrent subagent tasks independently hit their own
# temporary rate limits at nearly the same time and walked the ENTIRE shared chain, marking all 7
# steps exhausted within about 5 minutes -- including the 5 merely-transient ones, which a real
# operator would expect to recover given a few more minutes. When the main loop's own active step
# then hit a routine rate limit ~5 minutes later, get_next_chain_step found every step already
# marked dead and returned None immediately, crashing the whole session (58 minutes of real work,
# 7 findings) instead of recovering. _TimestampedStepSet below gives each exhausted step its own
# cooldown (_LLM_CHAIN_COOLDOWN_SECONDS) instead of "dead for the rest of this run" -- a step that
# was only ever transiently rate-limited becomes retryable again once the cooldown passes, while a
# step that's genuinely, repeatedly dead (like the 402s here) just gets re-marked exhausted the
# next time something tries it and fails again, at the cost of one more attempt every cooldown
# window -- a small, bounded price for not needlessly killing an otherwise-recoverable run.
_LLM_CHAIN_COOLDOWN_SECONDS = float(os.getenv("LLM_CHAIN_COOLDOWN_SECONDS", "300"))


class _TimestampedStepSet(set):
    """A set of (provider_id, model) chain steps that also remembers WHEN each one was added, so a
    step can expire back out of "exhausted" after _LLM_CHAIN_COOLDOWN_SECONDS instead of staying
    dead for the rest of the run (see _exhausted_chain_steps' own docstring for the real incident).
    Subclassing set (not wrapping it) is deliberate -- every existing `.add()`/`.discard()`/`in`/`|`
    call site across this file and llm_client.py keeps working completely unchanged; only this
    class's own two overrides and prune_expired() are new."""

    def __init__(self) -> None:
        super().__init__()
        self._added_at: dict[tuple[str, str], float] = {}

    def add(self, step: tuple[str, str]) -> None:
        super().add(step)
        self._added_at[step] = time.monotonic()

    def discard(self, step: tuple[str, str]) -> None:
        super().discard(step)
        self._added_at.pop(step, None)

    def prune_expired(self, cooldown_seconds: float) -> None:
        now = time.monotonic()
        expired = [step for step, added_at in self._added_at.items() if now - added_at >= cooldown_seconds]
        for step in expired:
            self.discard(step)


_exhausted_chain_steps: dict[str, _TimestampedStepSet] = {}

# Same shape as _exhausted_chain_steps, for a distinct signal: which steps are currently IN FLIGHT
# (picked as a fallback by some _llm_complete call that hasn't resolved yet), as opposed to PROVEN
# dead. Real gap this closes: two concurrent callers sharing one session_id (the main loop and an
# active subagent, or two subagents) can both hit exhaustion on their own current step at nearly
# the same instant, both snapshot get_exhausted_chain_steps() BEFORE either one's own fallback
# attempt has resolved, and both independently pick the SAME next untried step -- doubling the
# request rate right at the moment of switching to a fresh reserve (confirmed plausible, not yet
# proven live: a real cross-project audit found exactly this concurrency shape present in a real
# session, `usr_dd5aef`, though that specific session predates this fix so the race
# itself wasn't directly observed there). A step must never be excluded here just because it's
# claimed -- only PROVEN dead belongs in _exhausted_chain_steps -- so this is deliberately a
# separate set: a step a concurrent caller is still trying (and might succeed with) must remain
# available to whichever caller resolves next, not get treated as permanently exhausted.
_claimed_chain_steps: dict[str, set[tuple[str, str]]] = {}


def get_exhausted_chain_steps(session_id: str) -> set[tuple[str, str]]:
    steps = _exhausted_chain_steps.setdefault(session_id, _TimestampedStepSet())
    steps.prune_expired(_LLM_CHAIN_COOLDOWN_SECONDS)
    return steps


def get_claimed_chain_steps(session_id: str) -> set[tuple[str, str]]:
    return _claimed_chain_steps.setdefault(session_id, set())


def _clear_exhausted_chain_steps(session_id: str) -> None:
    _exhausted_chain_steps.pop(session_id, None)
    _claimed_chain_steps.pop(session_id, None)


async def _close_browser_session_safely(session_id: str) -> None:
    """Called from run_session/run_focused_exploit's own finally blocks, alongside
    get_stop_event(...).clear()/_clear_exhausted_chain_steps(...) above -- a run ending is exactly
    when this session's own browser_* context (if it ever opened one) should be torn down, freeing
    its concurrency-capped slot for the next session. A no-op for the overwhelmingly common case
    (this run never touched the browser_* tools at all -- BrowserSessionManager.close_session is
    itself a no-op then). Never allowed to crash the run's own cleanup -- a real close failure is
    logged and swallowed, same as every other best-effort teardown in this project (e.g.
    background_jobs.py's own kill_background_job).
    """
    try:
        await get_browser_manager().close_session(session_id)
    except Exception as exc:
        logger.debug("core: session=%s error closing browser session during cleanup (%s) -- ignored", session_id, exc)


# Same pattern and same honest tradeoff as _approval_events above, for a different purpose: chat
# (agent/chat.py) queues short operator directives here instead of writing them into
# the session file — run_session() already owns that file's read-modify-write cycle, a second
# writer would race it. In-memory only, so a directive queued right as the process dies is lost —
# acceptable, since it is a live nudge, not data (findings/recon stay durable regardless).
_instruction_queues: dict[str, asyncio.Queue] = {}


def get_instruction_queue(session_id: str) -> asyncio.Queue:
    return _instruction_queues.setdefault(session_id, asyncio.Queue())


def _drain_pending_guidance(session_id: str) -> list[str]:
    """Non-blocking drain of any add_guidance directives the chat layer queued for this
    session — checked at the top of every tool-loop iteration, the natural point between LLM
    turns to inject one. skip_finding directives are left in the queue (put back below) — those
    are matched separately, per finding title, at the per-finding boundary in _run_exploit
    (a title not yet reached in the exploit loop must survive to be seen on a later finding).
    """
    queue = get_instruction_queue(session_id)
    guidance: list[str] = []
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if instruction.get("type") == "add_guidance":
            guidance.append(instruction["text"])
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return guidance


async def _drain_pending_hypotheses(ctx: RunContext, phase: str) -> list[dict]:
    """Non-blocking drain of any add_hypothesis/prioritize_hypothesis directives an operator
    submitted live (main.py's /api/session/{id}/hypotheses route, live branch) — same queue, same
    per-turn drain point as _drain_pending_guidance right above, and deliberately unconditional (not
    guarded behind `if not is_subagent`) for the same reason that one is: a hypothesis is
    semantically an operator note aimed at whatever's actively running right now, not a result
    belonging exclusively to the main loop's own bookkeeping the way _drain_subagent_results' queue
    is. async (unlike its sibling above it) because structuring a fresh submission needs a real LLM
    call — see _structure_hypothesis_text.

    Two instruction shapes, both surfaced to the caller as hypothesis-shaped dicts to remind the
    model about (same {text, evidence, ...} shape either way, so the caller's own reminder-message
    loop doesn't need to know which happened):
    - add_hypothesis (raw_text): a brand-new operator submission — structured via one quick LLM
      call, then deterministically PERSISTED into session["hypotheses"] here, not just mentioned in
      a message, so it becomes a real, later-enforceable entry (_run_hypothesis_resolution_gate)
      regardless of whether this turn's own model bothers to resolve_hypothesis it immediately.
    - prioritize_hypothesis (hypothesis_id): "Investigate now" clicked on an EXISTING open
      hypothesis while this session happens to be live — no new entry, just a same-turn nudge
      pointing the model at it. Silently skipped if the id doesn't match anything still open (a
      stale click after it was already resolved some other way).
    """
    queue = get_instruction_queue(ctx.session_id)
    to_add: list[dict] = []
    to_prioritize: list[dict] = []
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        instruction_type = instruction.get("type")
        if instruction_type == "add_hypothesis":
            to_add.append(instruction)
        elif instruction_type == "prioritize_hypothesis":
            to_prioritize.append(instruction)
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)

    surfaced: list[dict] = []
    for instruction in to_add:
        structured = await _structure_hypothesis_text(ctx, instruction.get("raw_text", ""))
        if not structured["text"]:
            continue
        _persist_new_hypothesis(ctx, structured, phase, source="user")
        surfaced.append(ctx.session["hypotheses"][-1])
    for instruction in to_prioritize:
        existing = next((h for h in ctx.session.get("hypotheses", []) if h.get("id") == instruction.get("hypothesis_id")), None)
        # Clear the "Queued" button state (main.py's submit_hypothesis set it) now that the model is
        # actually being pointed at this hypothesis this turn — the operator's click has landed, the
        # card can offer the affordance again. Cleared even for an already-resolved/stale id so a
        # greyed button can never get stuck on forever.
        if existing is not None:
            existing.pop("priority_requested", None)
        if existing is not None and existing.get("status") == "unconfirmed":
            surfaced.append(existing)
    return surfaced


async def _drain_pending_recon_notes(ctx: RunContext, phase: str) -> list[dict]:
    """Non-blocking drain of any add_recon_item directives an operator submitted live (main.py's
    /api/session/{id}/recon/add route, live branch) — same queue, same per-turn drain point, same
    shape as _drain_pending_hypotheses right above (deliberately unconditional for the same reason
    that one is: a target/note is an operator instruction aimed at whatever's actively running right
    now). async because classifying a fresh submission may need a real LLM call
    (_classify_and_record_recon_item's free-text path).
    """
    queue = get_instruction_queue(ctx.session_id)
    to_add: list[dict] = []
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if instruction.get("type") == "add_recon_item":
            to_add.append(instruction)
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)

    surfaced: list[dict] = []
    for instruction in to_add:
        recorded = await _classify_and_record_recon_item(ctx, instruction.get("raw_text", ""), phase)
        if recorded is not None:
            surfaced.append(recorded)
    return surfaced


def _push_subagent_result(session_id: str, profile_name: str, result: dict, task_id: str) -> None:
    """Called once a delegated subagent's asyncio.Task actually finishes (its done-callback) --
    this IS the primary delivery path (the operator was explicit: the subagent must push its
    result, not wait to be polled). Reuses the SAME per-session queue _drain_pending_guidance
    already proves works for injecting a message between LLM turns, just a different instruction
    type -- no new queue/plumbing needed. task_id rides along so whichever live turn actually
    drains this (_run_llm_tool_loop_impl below) can mark THIS specific subagent_tasks entry
    delivered=True -- see that entry's own docstring in subagent_tasks.register_task."""
    get_instruction_queue(session_id).put_nowait({"type": "subagent_result", "profile_name": profile_name, "result": result, "task_id": task_id})


def _drain_subagent_results(session_id: str) -> list[dict]:
    """Non-blocking drain of any finished-subagent pushes -- same filter-and-requeue shape as
    _drain_pending_guidance. Only ever called from the MAIN phase loop's own iteration (see the
    is_subagent guard in _run_llm_tool_loop_impl below) -- a subagent's own loop must never drain
    this, or it could consume a result meant for the main agent (or a sibling subagent)."""
    queue = get_instruction_queue(session_id)
    results: list[dict] = []
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if instruction.get("type") == "subagent_result":
            results.append(instruction)
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return results


def _requeue_undelivered_subagent_results(session_id: str, session: dict) -> None:
    """Re-primes the in-memory instruction queue (_push_subagent_result/_drain_subagent_results)
    with any subagent task that finished (any terminal status, not "running") but was never
    actually delivered into a live conversation -- called once, near the top of run_session, before
    that run's own phase dispatch begins.

    Real, confirmed incident this closes (a real YesWeHack session, usr_57af40): the main session
    crashed (LLM fallback chain fully exhausted) while two subagent tasks were still running; one
    of them went on to confirm a real CORS vulnerability and called report_subagent_result 6-9
    minutes AFTER the crash. Its done-callback (_on_subagent_task_done) ran exactly as designed and
    pushed the result into the shared instruction queue -- but the phase loop that would have drained
    it had already exited, so it just sat there. The result itself was safely durable the whole time
    (subagent_tasks.register_task/_reap both call save_session), but nothing ever automatically
    revisited it -- an operator would only ever see it by manually opening session.json's raw
    subagent_tasks blob. Chat-routed tasks (entry["chat_thread_id"] set) are deliberately excluded
    here -- deliver_subagent_result_to_chat writes directly into session["chat_threads"], an
    already-durable destination with no queue/listener race to begin with, so they never need this.

    Idempotent by construction: a task already marked delivered=True (either because a live turn
    genuinely drained it, or because THIS function already re-queued it once this run) is never
    re-queued a second time, so calling this on every run_session entry (fresh or resumed alike) is
    always safe -- the overwhelmingly common case (nothing pending) is a fast, empty no-op.
    """
    for task_id, entry in session.get("subagent_tasks", {}).items():
        if entry.get("status") in (None, "running") or entry.get("delivered") or entry.get("chat_thread_id"):
            continue
        _subagent_logger.debug(
            "core: session=%s task=%s re-queuing undelivered subagent %r result from a prior run",
            session_id, task_id, entry.get("profile_name"),
        )
        _push_subagent_result(session_id, entry.get("profile_name", "?"), {"outcome": entry["status"], "result": entry.get("result")}, task_id)


def _profile_capability_hint(profile: dict) -> str:
    """One short, derived-not-hand-maintained clause naming a subagent profile's real tool-category
    domain (e.g. "re tools: radare2, gdb, custom_re_script, ... — 9 tools") so the delegating model
    can judge fit before calling delegate_to_subagent, not after. Falls back to the profile's own
    instructions text when it has zero resolvable tools (a profile with every allowed_tools entry
    since renamed/removed) rather than showing an empty, useless "() " parenthetical."""
    names = [name for name in (profile.get("allowed_tools") or [])]
    specs = [get_tool(name) for name in names]
    specs = [spec for spec in specs if spec is not None]
    if not specs:
        return (profile.get("instructions") or "no tools configured").strip()
    cats = sorted({cat for spec in specs for cat in categories_of(spec)})
    sample = ", ".join(spec.name for spec in specs[:8])
    more = f", +{len(specs) - 8} more" if len(specs) > 8 else ""
    return f"{'/'.join(cats)} tools: {sample}{more} — {len(specs)} total"


def _subagent_delegation_extras(session: dict) -> tuple[list[ToolSpec], str]:
    """Single source of truth for delegate_to_subagent's availability THIS call: returns the
    tool_specs to append AND the matching task-text addendum together, both derived from the same
    ONE get_enabled_profiles() snapshot. Deliberately not two separate functions each calling
    get_enabled_profiles() independently -- a Subagent getting toggled enabled/disabled via the
    Settings UI in the narrow window between two separate reads (each phase call site used to call
    it twice: once for the tool list, once for the addendum text) could otherwise make the tool
    list and the text describing it disagree, e.g. the addendum naming a profile that's no longer
    actually in tool_specs. One snapshot removes that race entirely, by construction, rather than
    relying on the window being "usually" too narrow to matter.

    Appended to every phase's own tool_specs/task (recon/analyze/exploit/chain/reverify) --
    delegate_to_subagent/check_subagent_task only ever appear in the model's tool schema, and the
    addendum only ever gets written, when at least one Subagent profile is actually enabled --
    never a permanently-present pair/paragraph the model has to learn to ignore on every session
    that doesn't use this feature at all. Without the addendum specifically, delegate_to_subagent
    sits in the schema with zero strategic framing, just one more entry in a list of 8-25 others
    with no hint of WHEN it's worth using -- confirmed live across multiple real scans (an enabled
    profile, the tool present in the schema on every single phase) with zero delegate_to_subagent
    calls across entire sessions. Names the actually-enabled profile(s) explicitly in the addendum
    so the model never has to guess a valid subagent_name -- delegate_to_subagent already rejects
    an unknown/typo'd one outright.
    """
    profiles = get_enabled_profiles(session.get("enabled_subagent_ids"))
    if not profiles:
        return [], ""

    # Filtered, not a bare [get_tool(...), get_tool(...)] -- same defensive pattern already used
    # for record_finding_spec/record_chain_result_spec just below in _run_chain: get_tool()
    # returning None (an unregistered name) must never silently plant a None into tool_specs,
    # where it would crash the very next step (_tool_to_openai_schema(None), or
    # specs_by_name = {spec.name: ...} reading .name off it) instead of just offering one fewer
    # tool. Both names are registered unconditionally at import time (agent/tools/__init__.py) so
    # this can't currently happen -- kept as a real backstop, not a hypothetical worth skipping.
    tools = [spec for spec in (get_tool("delegate_to_subagent"), get_tool("check_subagent_task")) if spec is not None]

    # Each profile's own instructions text alone is not enough for the model to pick the RIGHT
    # one -- confirmed live (NinthCircle-crackmes-usr_04a301): an RE-mode chat repeatedly delegated
    # a binary-analysis task to "Default Subagent - helper" (zero RE tools in its own allowed_tools
    # -- pure web-pentest toolset) purely because its instructions ("the right hand for the main
    # agent, helps him in everything") sounded generically capable, wasting the whole task on a
    # subagent that could only report back "I have no way to do this." Naming each profile's own
    # tool-category domain here (derived straight from its allowed_tools' own ToolSpec categories,
    # never hand-maintained) lets the model judge fit BEFORE delegating, not discover the mismatch
    # only after a wasted round trip.
    names = ", ".join(f"'{p['name']}' ({_profile_capability_hint(p)})" for p in profiles)
    max_concurrent = int(os.getenv("SUBAGENT_MAX_CONCURRENT_TASKS", "0"))
    concurrency_line = (
        "There is no fixed cap on how many subagent tasks can run at once — delegate as many "
        "genuinely independent pieces of work as you actually have (check_subagent_task or the "
        "session's own subagent log tells you how many are currently running)."
        if max_concurrent <= 0 else
        f"Up to {max_concurrent} subagent tasks can genuinely run at once (check_subagent_task "
        "or the session's own subagent log tells you how many are currently running)."
    )
    addendum = (
        "\n\nYou can delegate a bounded, self-contained sub-task to a Subagent via "
        f"delegate_to_subagent (enabled right now: {names}) and keep working on something more "
        "important yourself while it runs in the background — it reports its result back "
        "automatically once done, you never have to wait for it. Genuinely useful when you have "
        "independent work that doesn't need your own next decision to proceed (e.g. brute-forcing "
        "or enumerating a secondary host while you keep working the primary one, an OSINT sweep on "
        "a side domain). Not mandatory, and not a fit for anything that depends on your own next "
        "step or a shared, evolving picture of the target — most turns have nothing worth "
        f"delegating, so don't force it just because it's available. {concurrency_line} This "
        "applies in every phase you're in, not just Recon: if you have several independent pieces "
        "of work at the same time (one host to keep investigating yourself, a different host or a "
        "smaller side-check to hand off), delegate all of them rather than only ever delegating "
        "once per session. EVERY delegate_to_subagent call starts a completely fresh subagent with "
        "its own clean context — it knows nothing about any earlier subagent task's own outcome, "
        "good or bad. An earlier delegation turning out low-value (e.g. what it found was out of "
        "scope) says nothing about whether THIS new, different, independent task is worth "
        "delegating — judge each one on its own, not by how the last one went. If you run out of "
        "your OWN useful work and are only waiting on a still-running subagent, do NOT poll "
        "check_subagent_task in a loop to pass the time — the system automatically waits for every "
        "still-running subagent before this phase actually concludes, at no cost to you. Just wrap "
        "up the phase (update_plan noting what's still pending, then your terminal tool) instead of "
        "repeatedly re-checking."
    )
    return tools, addendum


# tool name -> which toolkit_settings_store.py toggle gates it. Kept as one small mapping here
# rather than repeated `if settings[...]: names.append(...)` branches, matching the count-and-shape
# of the real capabilities (Proxy/Repeater/Decoder/Comparer/Intruder/Sequencer/Racer) rather than
# growing awkwardly as more get added.
_TOOLKIT_TOOL_TOGGLE_KEYS = {
    "list_captured_traffic": "toolkit_proxy_enabled",
    "send_raw_request": "toolkit_repeater_enabled",
    "decode_value": "toolkit_decoder_enabled",
    "diff_requests": "toolkit_comparer_enabled",
    "intruder_run": "toolkit_intruder_enabled",
    "sequencer_analyze": "toolkit_sequencer_enabled",
    "racer_run": "toolkit_racer_enabled",
}


def _toolkit_tool_extras() -> list[ToolSpec]:
    """The native toolkit's own tools (send_raw_request/list_captured_traffic/decode_value/
    diff_requests/intruder_run/sequencer_analyze/racer_run) currently enabled via
    data/toolkit_agent_settings.json's seven independent toggles -- appended to every phase's own
    tool_specs, same "extras alongside the phase's own category-based base toolset" pattern
    _subagent_delegation_extras already establishes for delegate_to_subagent/check_subagent_task.
    category="toolkit" is deliberately never queried by any phase's own get_tools_by_category()
    call (agent/tools/registry.py's own Category comment), so without this explicit append these
    tools are never offered to the model at all, regardless of the toggles -- the manual UI never
    calls this function and so never depends on it: hand-driven Site Map/Repeater/Decoder/Comparer/
    Intruder/Sequencer/Racer access never depends on whether the model's own agent-tool toggle is
    on.
    """
    settings = load_toolkit_agent_settings()
    names = [name for name, toggle_key in _TOOLKIT_TOOL_TOGGLE_KEYS.items() if settings[toggle_key]]
    return [spec for spec in (get_tool(name) for name in names) if spec is not None]


def _build_subagent_system_prompt(profile: dict) -> str:
    parts = [
        f"You are '{profile['name']}', a specialized subagent working inside ASRA, an autonomous "
        "security research pipeline. The main agent delegated you a bounded task while it "
        "continues its own more important work in parallel — focus only on what you were asked, "
        "then call report_subagent_result with a clear, concrete summary once you're done. This "
        "is a real, pre-authorized security assessment against a live, in-scope target. You do not "
        "have record_finding/record_target — you cannot record anything into the final report "
        "directly, only the main agent can. Put every concrete finding (what it is, where, and "
        "the real evidence you saw) into report_subagent_result's own summary/details — the main "
        "agent will record it from there once it reads your report."
    ]
    instructions = (profile.get("instructions") or "").strip()
    if instructions:
        parts.append(instructions)
    return "\n\n".join(parts)


def _initial_llm_for_subagent(session_id: str, profile: dict) -> LLMProvider:
    """Picks the LLM a NEW subagent task starts on — normally just the profile's own configured
    provider/model, EXCEPT when that exact step is already known-exhausted for this session (some
    earlier caller, the main loop or a sibling subagent sharing the same session_id, already proved
    it dead this run). Without this check, a fresh subagent always starts at the profile's own
    step regardless of what the shared get_exhausted_chain_steps(session_id) state already knows,
    independently re-paying that step's own multi-minute retry-exhaustion budget before it can even
    reach _llm_complete's own fallback-chain walk.

    Real, confirmed incident this fixes (rev-retest-rescan-usr_8ba29f): one subagent proved
    `openrouter/nvidia-nemotron` dead at 22:19:48; a second subagent, delegated 4 minutes later in
    the same process with the same shared session_id, still started at the identical step and
    burned its own full ~5-minute retry-exhaustion sequence before switching — a second,
    independently-timed rediscovery of a fact the process already knew. Falls back to the profile's
    own step unchanged whenever the fallback chain is disabled, empty, or has nothing better to
    offer — this only ever SKIPS a step already proven dead, it never changes behavior otherwise.
    """
    provider_id, model = profile.get("provider"), profile.get("model")
    own_step = (provider_id, model)
    if get_fallback_chain_enabled() and own_step in get_exhausted_chain_steps(session_id):
        chain = get_fallback_chain()
        tried = get_exhausted_chain_steps(session_id) | get_claimed_chain_steps(session_id)
        fallback = get_next_chain_step(chain, tried, health_ranking=_cached_provider_health_ranking())
        if fallback is not None:
            _subagent_logger.debug(
                "core: session=%s subagent's own configured step (%s/%s) already known exhausted this run — starting on reserve %s/%s instead",
                session_id, provider_id, model, fallback.provider_id, fallback.model,
            )
            return fallback
    return get_provider(provider_id, model)


async def _delegate_to_subagent_impl(arguments: dict) -> dict:
    """The real implementation behind the delegate_to_subagent tool (called directly by
    _dispatch_tool, never through asyncio.to_thread — see that function's own docstring for why).
    Fires the subagent's own _run_llm_tool_loop as a genuinely concurrent asyncio.Task and returns
    immediately with a task_id; the caller never blocks on it here. Delivery of the eventual result
    back to the main agent is the auto-push queue (_push_subagent_result/_drain_subagent_results),
    wired up via the task's own done-callback below — check_subagent_task is only an explicit
    fallback for when that push somehow didn't happen.
    """
    session_id = arguments.get("_session_id")
    session = arguments.get("_session")
    subagent_name = arguments.get("subagent_name")
    task_description = arguments.get("task_description")
    if not subagent_name or not task_description:
        return {"status": "error", "error": "subagent_name and task_description are both required"}

    profile = get_profile_by_name(subagent_name, session.get("enabled_subagent_ids"))
    if profile is None:
        # The single most likely real troubleshooting scenario for this whole feature (a typo'd
        # name, or a profile that's configured but never actually enabled) -- worth its own
        # explicit line in debug.log rather than only ever showing up inside the tool result
        # payload, which session.json (not the chronological debug.log stream) is what stores.
        _subagent_logger.debug("core: session=%s delegate_to_subagent: no enabled subagent named %r", session_id, subagent_name)
        return {"status": "error", "error": f"no enabled subagent named {subagent_name!r} — check the Subagents settings tab"}

    tasks = session.setdefault("subagent_tasks", {})
    running_count = sum(1 for t in tasks.values() if t.get("status") == "running")
    max_concurrent = int(os.getenv("SUBAGENT_MAX_CONCURRENT_TASKS", "0"))
    # 0 (or any non-positive value) means no cap at all -- explicit operator choice
    # (SUBAGENT_MAX_CONCURRENT_TASKS=0 in .env), not a bug: a positive value still enforces a real
    # limit exactly as before for anyone who wants one.
    if max_concurrent > 0 and running_count >= max_concurrent:
        return {
            "status": "skipped",
            "reason": (
                f"{running_count} subagent task(s) already running for this session (max "
                f"{max_concurrent}) — wait for one to finish (or check_subagent_task) before delegating another"
            ),
        }

    # report_subagent_result is the subagent's terminal_tool -- always appended below regardless
    # of what's stored in allowed_tools, so it's excluded here too (a profile saved before the
    # Subagents UI started rendering it as a fixed, disabled checkbox could still have it recorded
    # in allowed_tools; without this filter it would end up in tool_specs twice).
    #
    # delegate_to_subagent/check_subagent_task are excluded unconditionally too -- a real, confirmed
    # incident: a delegated subagent (blocked by a since-fixed httpx validation bug, see
    # _track_host_health's never_dispatched fix) used its OWN delegate_to_subagent call to spawn a
    # SECOND, nested subagent task rather than just reporting back "I couldn't do this, tools are
    # blocked" -- contributing to that one delegation running 85 LLM turns / 81 tool calls instead
    # of the small, bounded task it was meant to be. The whole point of delegation is one bounded
    # unit of work reported back to the main agent (which is what actually keeps the main loop
    # informed and in control) -- a subagent recursively delegating creates exactly the deep,
    # hard-to-follow chains the operator's own "why doesn't it do a small task and report back"
    # complaint was about. This is deliberately NOT left to an operator's own Subagents-page
    # checklist choice (main.py's _subagent_context/subagents.html's tool_checklist also excludes
    # these two from the checkbox list itself, so this is defense-in-depth, not the only guard) --
    # a profile saved before that exclusion existed could still have one recorded in its own
    # allowed_tools, and this filter is what actually makes that harmless.
    # record_finding/record_target and the six phase-terminal "recording" tools below are all
    # excluded for the same structural reason as the three tools above, just a subtler failure
    # mode: every one of them is a regular tier-1 native_function that validates and returns
    # {"status": "ok", ...} just fine when dispatched, but its actual real-world effect — persisting
    # into session["findings"]/session["recon_result"]["targets"], or ending a phase's own
    # _run_llm_tool_loop via the terminal_tool mechanism — only ever happens inside that PHASE's own
    # execute()/terminal_tool handling in THIS file (_persist_new_finding, _apply_skip_outcome,
    # _apply_chain_reverifications, _run_reverify's/_run_skeptical_verification's own result
    # handling, ...). A subagent's own _run_llm_tool_loop call above passes no execute_tool and a
    # fixed terminal_tool="report_subagent_result", so any of these getting dispatched falls through
    # to the bare _run_tool_with_retry path with no persistence/termination hook whatsoever — a
    # silent, confusing no-op the model has no way to detect from its own "status": "ok" result.
    # Real, confirmed incident (record_finding/record_target specifically): a subagent called
    # record_finding 7 times, got "status": "ok" every time, and none of the 7 ever reached the
    # final report — it timed out before it could summarize them back to the main agent (the
    # actually-supported way for a subagent to report a finding), and by then there was no
    # realistic way for the main agent to notice and re-record them itself. record_hypothesis/
    # resolve_hypothesis/record_exploit_decision/record_chain_result/record_reverification_result/
    # record_skeptical_verification_result share the exact same structural gap (each is offered as
    # a checkbox in a profile's own allowed_tools, agent/tools/subagent_store.py's installed-tool
    # list) but were missed when the record_finding/record_target fix landed.
    _subagent_disallowed_tools = {
        "report_subagent_result", "delegate_to_subagent", "check_subagent_task",
        "record_finding", "record_target",
        "record_hypothesis", "resolve_hypothesis", "record_exploit_decision",
        "record_chain_result", "record_reverification_result", "record_skeptical_verification_result",
    }
    tool_specs = [get_tool(name) for name in (profile.get("allowed_tools") or []) if name not in _subagent_disallowed_tools]
    tool_specs = [spec for spec in tool_specs if spec is not None]
    # A profile's own allowed_tools checklist (subagents.html) offers every installed tool,
    # including the toolkit ones (they're always "installed", tool_tier=1) -- but a subagent must
    # never get a wider toolkit toolset than the operator's own data/toolkit_agent_settings.json
    # toggles currently grant the main agent/chat: subagents don't get their own separate toolkit
    # access, independent of the operator's settings. Filtered here rather than never offered as a
    # checkbox at all (unlike delegate_to_subagent/record_finding above) because toggling toolkit
    # access back on later should immediately apply to an already-saved profile's checklist, not
    # require re-saving it.
    _enabled_toolkit_names = {spec.name for spec in _toolkit_tool_extras()}
    tool_specs = [
        spec for spec in tool_specs
        if spec.name not in _TOOLKIT_TOOL_TOGGLE_KEYS or spec.name in _enabled_toolkit_names
    ]
    report_tool = get_tool("report_subagent_result")
    if report_tool is not None:
        tool_specs.append(report_tool)

    llm = _initial_llm_for_subagent(session_id, profile)
    task_id = uuid.uuid4().hex[:12]
    # subagent_task_id/subagent_name tag every log entry this dedicated RunContext produces (see
    # RunContext's own docstring) — a separate instance per delegation, sharing the same session
    # dict, is what lets _append_log distinguish "this subagent's own step" from the main phase's,
    # even with several subagents (or several delegations to the same one) running concurrently.
    subagent_ctx = RunContext(llm=llm, session=session, session_id=session_id, subagent_task_id=task_id, subagent_name=profile["name"])
    system_prompt = _build_subagent_system_prompt(profile)
    # Server-injected override, same underscore-prefixed convention as _session_id/_session/
    # _triggered_by -- never part of delegate_to_subagent's own model-visible schema. Lets
    # _auto_delegate_recon_overflow ask for a longer budget when it batches several hosts into one
    # task (see that function's own call site) without changing the flat default every ordinary,
    # model-triggered single-task delegation still gets.
    timeout_seconds = int(arguments.get("_timeout_seconds") or os.getenv("SUBAGENT_TASK_TIMEOUT_SECONDS", "900"))
    # Owned by THIS function, not _run_llm_tool_loop's own default -- passed in via external_trace
    # so the list survives asyncio.wait_for() cancelling _run() on timeout (the coroutine's local
    # state is gone at that point, but this same list object, already registered with
    # subagent_tasks below, still holds every real tool call made before the cutoff).
    trace: list[dict] = []
    # Same "survives cancellation because it's a reference captured from outside" reasoning as
    # `trace` above, for current_backoff_accumulator (agent/llm_client.py) -- a plain float set
    # inside _run()'s own coroutine would vanish with the rest of its local state once
    # asyncio.wait_for() cancels it on timeout; this one-element list, registered with
    # subagent_tasks below, keeps accumulating right up to the cutoff.
    backoff_accumulator: list[float] = [0.0]

    async def _run() -> tuple[dict | None, list[dict]]:
        # Set inside this coroutine (not before asyncio.create_task below) so it only ever applies
        # to THIS subagent's own fresh context copy, never leaking into the main loop's — same
        # "set at the very top of an isolated task" idiom current_session_id.set already uses in
        # run_session/run_focused_exploit. See current_subagent_label's own docstring for why this
        # exists (agent/tools/runner.py's TOOLS-category debug lines).
        current_subagent_label.set(f"subagent={profile['name']!r} task={task_id}")
        current_backoff_accumulator.set(backoff_accumulator)
        return await _run_llm_tool_loop(
            subagent_ctx, system_prompt, task_description, tool_specs, "subagent",
            expect_json_final=False, terminal_tool="report_subagent_result", is_subagent=True,
            external_trace=trace,
        )

    task = asyncio.create_task(asyncio.wait_for(_run(), timeout=timeout_seconds))
    # Server-injected, same underscore-prefixed convention as _session_id/_session above -- never
    # part of delegate_to_subagent's own model-visible schema, so a model can never spoof "this
    # was really auto-triggered". Defaults to "model" (the tool's own ordinary calling path);
    # _auto_delegate_recon_overflow's call site below sets it explicitly to "auto_overflow".
    triggered_by = arguments.get("_triggered_by", "model")
    # Server-injected by agent/chat.py's own _run_chat_tool_loop, same underscore-prefixed
    # convention -- never part of delegate_to_subagent's own model-visible schema. Threaded through
    # to subagent_tasks.register_task so _on_subagent_task_done can route this task's eventual
    # result back into that same chat thread once it finishes (see register_task's own docstring).
    chat_thread_id = arguments.get("_chat_thread_id")
    subagent_tasks.register_task(
        session_id, session, task_id, profile["name"], task, deadline=time.time() + timeout_seconds,
        trace=trace, triggered_by=triggered_by, chat_thread_id=chat_thread_id,
        backoff_accumulator=backoff_accumulator,
    )
    task.add_done_callback(lambda t: _on_subagent_task_done(session_id, session, task_id, profile["name"], t))
    _subagent_logger.debug("core: session=%s delegated task=%s to subagent=%r triggered_by=%r", session_id, task_id, subagent_name, triggered_by)
    return {"status": "ok", "task_id": task_id}


def _on_subagent_task_done(session_id: str, session: dict, task_id: str, profile_name: str, task: asyncio.Task) -> None:
    """The task's own done-callback (asyncio's native completion hook, fired via call_soon on the
    event loop the instant the task resolves) — this is what makes delivery a real PUSH rather
    than something only ever noticed the next time someone happens to poll. Runs synchronously,
    same as every other in-place session mutation in this project (no await needed/possible here).

    Two mutually exclusive delivery paths, chosen by whether THIS task was delegated from a chat
    thread (entry["chat_thread_id"], set by subagent_tasks.register_task off the model's own
    delegate_to_subagent call) or from a live scan phase (chat_thread_id is None, the ordinary
    "model" or "auto_overflow" path): a chat-delegated result goes straight into that chat thread
    (agent/chat.py's own deliver_subagent_result_to_chat) and ONLY there -- it must never also land
    in _push_subagent_result's shared instruction queue, which only a live phase loop drains
    (_drain_subagent_results, gated on `not is_subagent` in _run_llm_tool_loop_impl); chat itself
    never drains that queue. Real, confirmed incident this fixes: a chat-triggered delegation ran
    to completion for real (visible in debug.log — actual tool calls, a real report_subagent_result
    call) but the chat panel never showed anything beyond the initial "was delegated" acknowledgment
    -- the result was pushed into a queue nothing was ever listening to. Routing it into the queue
    INSTEAD of skipping it would create a second, worse bug: if a real scan phase happened to be
    running concurrently for the same session_id, an operator's own ad-hoc chat investigation would
    silently leak into that unrelated scan's own reasoning.

    Uses a local import (not a module-level one) specifically to avoid a circular import --
    agent/chat.py already imports several names from agent.core at ITS OWN module level, so the
    reverse import must stay deferred to call time, same escape hatch agent/llm_client.py already
    uses for agent.codex_provider.
    """
    entry = session.get("subagent_tasks", {}).get(task_id)
    if entry is None:
        return
    subagent_tasks._reap(session_id, session, task_id, entry)
    _subagent_logger.debug("core: session=%s task=%s subagent=%r finished outcome=%s", session_id, task_id, profile_name, entry["status"])
    chat_thread_id = entry.get("chat_thread_id")
    if chat_thread_id:
        _subagent_logger.debug("core: session=%s task=%s delivering to chat thread=%s (chat-triggered delegation)", session_id, task_id, chat_thread_id)
        from agent.chat import deliver_subagent_result_to_chat
        deliver_subagent_result_to_chat(session_id, chat_thread_id, profile_name, {"outcome": entry["status"], "result": entry.get("result")})
    else:
        _subagent_logger.debug("core: session=%s task=%s pushed to the main phase loop's own instruction queue", session_id, task_id)
        _push_subagent_result(session_id, profile_name, {"outcome": entry["status"], "result": entry.get("result")}, task_id)


def _pop_skip_instruction(session_id: str, finding_title: str) -> bool:
    """Non-blocking check: was exactly this finding queued to be skipped? Consumes only a
    matching instruction — everything else (skip_finding for a different, not-yet-reached
    finding; any add_guidance) goes back into the queue untouched for a later drain to see.
    """
    queue = get_instruction_queue(session_id)
    matched = False
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if not matched and instruction.get("type") == "skip_finding" and instruction.get("finding_title") == finding_title:
            matched = True
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return matched


def _pop_clear_time_budget_instruction(session_id: str) -> bool:
    """Non-blocking: did the operator ask (Overview tab's "Stop timer" button, while this session
    is actually live) to remove the configured time budget without stopping the whole run? Same
    queue-based pattern as _pop_skip_instruction/_pop_deep_dive_instruction just above, for the
    identical reason — a second concurrent writer to the same session file while run_session()'s
    own loop is live is a real race, so this is the only safe way to reach a live run from an HTTP
    request. Consumed at _llm_complete's own choke point (every phase, every turn), same place the
    budget itself is checked, so "stop the timer" takes effect essentially immediately rather than
    waiting for the next full pass boundary.
    """
    queue = get_instruction_queue(session_id)
    matched = False
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if not matched and instruction.get("type") == "clear_time_budget":
            matched = True
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return matched


def _pop_deep_dive_instruction(session_id: str) -> str | None:
    """Non-blocking: was a "focus on this finding now" directive queued (the finding-detail
    modal's Deep dive button, main.py's /deep-dive route, for a session that's already live)?
    Unlike skip_finding this isn't matched against a specific title by the caller — _run_exploit
    checks it once per loop iteration and reorders its own remaining work, so whichever finding
    was most recently requested (if any) always wins the reorder. Consumed either way once
    popped, same as add_guidance — a stale request for a finding already processed just no-ops.
    """
    queue = get_instruction_queue(session_id)
    found_title: str | None = None
    deferred: list[dict] = []
    while not queue.empty():
        instruction = queue.get_nowait()
        if instruction.get("type") == "deep_dive":
            found_title = instruction.get("finding_title")
        else:
            deferred.append(instruction)
    for instruction in deferred:
        queue.put_nowait(instruction)
    return found_title


@dataclass
class RunContext:
    """Shared, mutable state for one run_session() call — threaded through every sub-phase
    instead of passing (llm, session, session_id) separately everywhere. iteration_count is a
    running total for logging only (see _llm_complete) — no budget attached to it.
    current_finding_title is set for the duration of one finding's exploit attempt
    (_run_exploit_for_finding) so _append_log can tag that finding's log entries — lets the UI
    show a per-finding scoped log instead of just the whole session's undifferentiated stream.
    current_hypothesis_id is the same idea for a hypothesis-verification pass (set by
    run_hypothesis_verification) — used by _record_missing_capability to link a missing-capability
    entry back to the specific hypothesis being investigated when it happened.
    subagent_task_id/subagent_name are the same idea, one level further out: set for the whole
    lifetime of a delegated subagent's own RunContext (_delegate_to_subagent_impl builds a
    separate RunContext per delegation, sharing the same session dict) so every log entry that
    subagent's own _run_llm_tool_loop produces carries which delegation it belongs to — lets the
    UI group a subagent's own steps into one block instead of a flat stream interleaved by
    wall-clock time with whatever the main agent was doing concurrently.
    """

    llm: LLMProvider
    session: dict
    session_id: str
    iteration_count: int = field(default=0)
    current_finding_title: str | None = field(default=None)
    current_hypothesis_id: str | None = field(default=None)
    subagent_task_id: str | None = field(default=None)
    subagent_name: str | None = field(default=None)
    # Set by _run_llm_tool_loop when a phase ends on a SAFEGUARD (wall-clock backstop, progress
    # stall, back-to-back repeat) rather than the model finishing on its own. None means a natural
    # end. A caller like run_re_triage reads this to record an honest end-reason — so a pass that
    # merely ran out of time with zero findings never looks identical to one that genuinely finished.
    last_stop_reason: str | None = field(default=None)
    # True when this run's provider_id (the caller's own get_provider() argument, e.g.
    # session["llm_provider"]) was None at RunContext creation -- meaning this session follows
    # whatever's saved in Settings -> AI Provider & Model LIVE, not a per-session pin. Gates
    # _llm_complete's own live-Settings-Save check below: an explicit per-session override must
    # never be silently overridden by an unrelated Settings edit, same "explicit arg > saved
    # settings" precedence agent.llm_client.get_provider()'s own docstring already establishes.
    follows_global_settings: bool = field(default=False)
    # The (provider, model) read from Settings' own saved choice the LAST time this run actually
    # synced to it -- at RunContext creation, and again every time the live-Settings-Save check
    # below applies a change. Deliberately NOT compared against ctx.llm.provider_id/model directly
    # (see that check's own docstring): ctx.llm legitimately drifts away from the saved choice on
    # its own, every time the Reserve-providers chain fails over mid-run, and that automatic
    # drift must never be mistaken for a fresh operator Save and reverted.
    configured_provider: str | None = field(default=None)
    configured_model: str | None = field(default=None)


def _new_run_context(session: dict, session_id: str, provider_id: str | None) -> RunContext:
    """Every run_session/run_focused_exploit/run_re_triage/... entry point builds its RunContext
    the same way -- get_provider(provider_id) for the LLM, plus (since this project's own
    live-review found saving new Settings mid-run had no effect on an already-running session)
    a snapshot of the saved provider/model this run should keep following if provider_id is None,
    for _llm_complete's own live-Settings-Save check to compare fresh reads against later."""
    saved = load_llm_settings() if provider_id is None else None
    return RunContext(
        llm=get_provider(provider_id),
        session=session,
        session_id=session_id,
        follows_global_settings=provider_id is None,
        configured_provider=saved.get("provider") if saved else None,
        configured_model=saved.get("model") if saved else None,
    )


async def _llm_complete(ctx: RunContext, messages: list[dict], tools: list[dict] | None) -> LLMResponse:
    """The single choke point every LLM call in a session goes through — sub-phase conversations,
    1-step retry corrections, all of it. No cap here: loop/stall protection lives in
    _run_llm_tool_loop's stall detector instead, which stops a phase on genuine repetition
    without capping how much distinct work a whole scan can do overall.

    Also the single checkpoint an operator-requested Stop (main.py's /interrupt route) is noticed
    at — every phase reaches here on every turn, so one check here covers Recon/Analyze/Exploit/
    Validate/Chain/Reverify alike without sprinkling the same check through each of them.

    Deliberately does NOT clear() the stop event itself on the way out (unlike earlier versions of
    this function) -- get_stop_event(session_id) is keyed only by session_id, and a delegated
    Subagent task's own conversation (_delegate_to_subagent_impl's subagent_ctx) runs as a genuinely
    concurrent asyncio.Task sharing that SAME session_id and hitting this SAME checkpoint. Confirmed
    live in a real session: the operator clicked Stop while a subagent task was still polling, and
    the SUBAGENT's own _llm_complete call happened to reach this check microseconds before the MAIN
    session loop's next call did -- it consumed (cleared) the flag for itself, ended its own task
    with a swallowed SessionStopRequested (surfaced only as a mundane subagent "error" status), and
    the main loop's very next _llm_complete call then found the flag already clear and sailed
    straight through into the next phase, completely oblivious a Stop was ever requested. The
    operator had to click Stop a second time (11 seconds later, once the subagent task was no
    longer competing for it) before it actually took effect. Fixed by making is_set() checks
    everywhere non-destructive -- every concurrent consumer (main loop, every subagent task, every
    fallback-provider retry below) independently sees and raises on the same still-set flag, so no
    single racing checker can silently steal it from the others. The ONE place that actually owns
    clearing it is run_session's/run_focused_exploit's own top-level SessionStopRequested handler,
    once the whole session (including every subagent) has genuinely finished stopping -- see those
    functions for why a stale "still set" flag must not survive into a later resumed run.
    """
    if get_stop_event(ctx.session_id).is_set():
        raise SessionStopRequested()

    # Overview tab's "Stop timer" button (main.py's /stop-time-budget route) queues this instead of
    # writing session.json directly, for the same live-run race reason skip_finding/deep_dive
    # already queue instead of writing directly -- consumed here, every turn, so it takes effect
    # essentially immediately rather than waiting for the next full-pass boundary.
    if _pop_clear_time_budget_instruction(ctx.session_id):
        ctx.session["time_budget_seconds"] = None
        logger.debug("core: session=%s time budget cleared at the operator's request (Stop timer) — session keeps running with no limit", ctx.session_id)

    # Real incident this closes: session["time_budget_seconds"] (New Project form's "Time budget")
    # was only ever checked BETWEEN full pipeline passes (the while-loop's own continuation check,
    # near the bottom of run_session) -- if a single pass's own recon/analyze/exploit work took
    # longer than the configured budget (easy on a real target), the deadline silently passed WHILE
    # that pass was still running, and nothing noticed until it eventually finished on its own,
    # potentially hours late. This is the same choke point the operator Stop check just above
    # already proves reaches every phase on every turn -- reusing it here means a budget expiry now
    # stops at the next safe checkpoint (the current tool call finishing), exactly like a manual
    # Stop click already does, instead of only ever being noticed after the fact.
    if _time_budget_expired(ctx.session):
        raise SessionStopRequested(reason="time_budget_expired")

    # Passed down into ctx.llm.complete so a Stop click that lands mid-backoff-wait (inside the
    # worker thread below, potentially tens of seconds into a 429/5xx retry sequence) is noticed
    # within one poll interval instead of only the next time this function is entered fresh — see
    # LLMCallAborted's docstring for the real incident (Stop silently ignored for minutes) this
    # closes. is_set() is a plain attribute read, safe to call from the worker thread it runs in.
    stop_check = lambda: get_stop_event(ctx.session_id).is_set()  # noqa: E731

    # Real, confirmed operator request: saving a NEW provider/model in Settings -> AI Provider &
    # Model while a session is actively running (even one currently sitting on a Reserve-providers
    # fallback step) should switch to it the instant the in-flight call finishes, not only on the
    # next fresh session. ctx.llm is otherwise resolved once, at RunContext creation
    # (_new_run_context), and never revisited. Gated on follows_global_settings -- an explicit
    # per-session provider pin (session["llm_provider"] set) must never be silently overridden by
    # an unrelated Settings edit meant for other sessions.
    #
    # Compared against ctx.configured_provider/model (the snapshot taken at the last sync), never
    # against ctx.llm.provider_id/model directly -- ctx.llm legitimately differs from the saved
    # choice on its own, every time the Reserve-providers chain below fails over mid-run, and that
    # automatic drift must not be mistaken for a fresh operator Save and reverted, which would
    # fight the fallback chain (bouncing straight back to the very step that just proved dead on
    # every subsequent call instead of staying on the reserve that's actually working).
    if ctx.follows_global_settings:
        live_saved = load_llm_settings()
        live_provider, live_model = live_saved.get("provider"), live_saved.get("model")
        if live_provider and live_model and (live_provider, live_model) != (ctx.configured_provider, ctx.configured_model):
            try:
                live_llm = get_provider(live_provider, live_model)
            except Exception as exc:  # noqa: BLE001 -- a mid-edit/half-saved Settings choice must not kill an in-progress run
                logger.debug(
                    "core: session=%s live Settings save (provider=%s model=%s) not usable yet (%s) — staying on %s/%s",
                    ctx.session_id, live_provider, live_model, exc, ctx.llm.provider_id, ctx.llm.model,
                )
            else:
                _log_agent_debug(
                    ctx, "operator saved a new provider/model in Settings mid-run — switching from %s/%s to %s/%s",
                    ctx.llm.provider_id, ctx.llm.model, live_llm.provider_id, live_llm.model,
                )
                ctx.llm = live_llm
            # Synced either way -- a provider/model that failed to resolve just now (e.g. the
            # operator hasn't finished saving both fields yet) shouldn't be retried on every single
            # subsequent call; it'll be picked up again once IT changes to something new.
            ctx.configured_provider, ctx.configured_model = live_provider, live_model

    # Pre-flight check, mirroring _initial_llm_for_subagent's own reasoning but for a call on an
    # ALREADY-ASSIGNED ctx.llm rather than a subagent's starting step: without this, a step some
    # OTHER concurrent caller (a sibling subagent, or an earlier call in this same loop) already
    # proved dead this run is dispatched to anyway and only discovered dead reactively, after
    # paying that step's own multi-minute retry-exhaustion budget all over again. Confirmed live
    # (rev-retest-rescan-usr_8ba29f): two subagents independently proved openrouter/nvidia-nemotron
    # dead by 22:24; the main loop's own reverify-phase call still dispatched to that same step six
    # minutes later and burned ~9.5 more minutes rediscovering it. If there's nothing better to
    # switch to, this is a no-op and the call proceeds to fail through the normal except-block
    # fallback walk below, same terminal outcome either way.
    if get_fallback_chain_enabled() and (ctx.llm.provider_id, ctx.llm.model) in get_exhausted_chain_steps(ctx.session_id):
        chain = get_fallback_chain()
        tried = get_exhausted_chain_steps(ctx.session_id) | get_claimed_chain_steps(ctx.session_id)
        fallback = get_next_chain_step(chain, tried, health_ranking=_cached_provider_health_ranking())
        if fallback is not None:
            _log_agent_debug(
                ctx, "LLM provider/model (%s/%s) already known exhausted this run — switching to reserve %s/%s before dispatch",
                ctx.llm.provider_id, ctx.llm.model, fallback.provider_id, fallback.model,
            )
            ctx.llm = fallback

    ctx.iteration_count += 1
    # ctx.subagent_name is only set on a delegated subagent's own RunContext (see RunContext's
    # docstring) — routing through _subagent_logger here, not just at delegation start/finish, is
    # what makes a subagent's own turns actually distinguishable in the debug console while
    # they're running, not just at the two lifecycle endpoints.
    _log_agent_debug(ctx, "llm call %d", ctx.iteration_count)
    call_started = time.monotonic()
    try:
        response = await asyncio.to_thread(ctx.llm.complete, messages, tools, stop_check=stop_check)
        _record_llm_usage_event(ctx.session, ctx.llm.provider_id, ctx.llm.model, time.monotonic() - call_started, response.usage)
        return response
    except LLMCallAborted:
        # Not cleared here either -- same non-destructive-checkpoint reasoning as the pre-call check
        # above.
        raise SessionStopRequested()
    except (openai.APIStatusError, openai.APIConnectionError, EmptyResponseError) as exc:
        # Reached only once ctx.llm's own retry budget (llm_client._call_with_backoff, ~8 minutes)
        # is already exhausted — a provider outage/hang this deep would otherwise fail the whole
        # session outright (real incident: an opencode-zen hang mid-validate killed a session with
        # 21 already-processed findings).
        #
        # Safe default: no automatic cross-provider/model switching at all. An EARLIER version of
        # this always ran (get_fallback_provider, since removed) — it silently jumped to whichever
        # OTHER configured provider PROVIDER_REGISTRY happened to list next, including a PAID
        # provider the operator had a key for but never meant to be used this way, spending real
        # tokens/money with no explicit opt-in. The operator now has to explicitly build their own
        # ordered reserve chain in Settings (and accept the warning shown when enabling it) before
        # any of this loop below ever runs — get_fallback_chain_enabled()'s own docstring has the
        # full incident writeup.
        last_exc: Exception = exc
        if not get_fallback_chain_enabled():
            raise last_exc

        # Every step in the operator's own chain gets one real attempt before the whole call
        # actually fails, walked in the exact order they configured (provider, then every model
        # listed for it, then the next provider) — never PROVIDER_REGISTRY's own iteration order.
        # Swaps ctx.llm for the rest of this run rather than falling back per-call, so a
        # now-proven-dead step isn't retried (and its own ~8 minute budget re-paid) on every
        # subsequent call too.
        #
        # exhausted/claimed are both read straight from shared, session-keyed state on every loop
        # iteration (never a local snapshot) — see get_claimed_chain_steps' own docstring for the
        # real concurrency gap a local snapshot (the previous "tried_steps = set(exhausted)" copy)
        # left open: two concurrent callers (main loop + an active subagent, or two subagents)
        # sharing one session_id could both hit exhaustion at nearly the same instant, both
        # snapshot BEFORE either one's own fallback attempt had resolved, and both independently
        # pick the SAME next untried step — doubling the request rate right at the moment of
        # switching to a fresh reserve. Reading `exhausted | claimed` fresh each iteration, with no
        # await between the read and the claim.add() a few lines below, closes that: the pick and
        # the claim happen back-to-back with no yield point in between, so a second concurrent
        # caller can never observe "not yet claimed" for a step this one is about to claim.
        chain = get_fallback_chain()
        exhausted = get_exhausted_chain_steps(ctx.session_id)
        exhausted.add((ctx.llm.provider_id, ctx.llm.model))
        claimed = get_claimed_chain_steps(ctx.session_id)
        while True:
            fallback = get_next_chain_step(chain, exhausted | claimed, health_ranking=_cached_provider_health_ranking())
            if fallback is None:
                # Every configured reserve step has now failed -- this is a fully expected outcome
                # (bad keys/no balance/rate limits, not a code bug) but the raw exception below reads
                # as an unhandled traceback in debug.log with no summary of what was actually tried.
                # One clear line here, right before the same exception still propagates unchanged,
                # is what lets a log-review pass tell "provider config problem" apart from "LLM call
                # crashed" at a glance instead of reconstructing the whole exhausted-chain walk from
                # scattered per-step warnings above.
                logger.error(
                    "core: session=%s LLM fallback chain fully exhausted (%d step(s) tried: %s) — last error: %s",
                    ctx.session_id, len(exhausted), sorted(exhausted), last_exc,
                )
                raise last_exc
            _log_agent_debug(
                ctx, "LLM provider/model (%s/%s) exhausted its retries (%s) — switching to reserve %s/%s for the rest of this run",
                ctx.llm.provider_id, ctx.llm.model, last_exc, fallback.provider_id, fallback.model,
            )
            ctx.llm = fallback
            fallback_step = (fallback.provider_id, fallback.model)
            # Claimed the instant it's picked, not only once it fails -- a step still in flight
            # (might yet succeed) must be excluded from OTHER concurrent callers' own picks without
            # being treated as permanently exhausted; released in `finally` regardless of outcome,
            # then re-added to `exhausted` specifically on failure a few lines below.
            claimed.add(fallback_step)
            fallback_started = time.monotonic()
            try:
                try:
                    response = await asyncio.to_thread(ctx.llm.complete, messages, tools, stop_check=stop_check)
                    _record_llm_usage_event(ctx.session, ctx.llm.provider_id, ctx.llm.model, time.monotonic() - fallback_started, response.usage)
                    return response
                except LLMCallAborted:
                    # Not cleared here either -- same non-destructive-checkpoint reasoning as the
                    # pre-call check at the top of this function.
                    raise SessionStopRequested()
                except (openai.APIStatusError, openai.APIConnectionError, EmptyResponseError) as fallback_exc:
                    exhausted.add(fallback_step)
                    last_exc = fallback_exc
                    continue
            finally:
                claimed.discard(fallback_step)


def _apply_output_parser(spec: ToolSpec, result: dict) -> dict:
    if result.get("status") == "ok":
        degraded_hint_fn = _DEGRADED_OK_HINTS.get(spec.name)
        note = degraded_hint_fn(result) if degraded_hint_fn is not None else None
        note_update = {"note": note} if note else {}

        parser = _OUTPUT_PARSERS.get(spec.name)
        if parser is None:
            return {**result, **note_update} if note_update else result
        parsed = parser(result["stdout"])
        # Real, confirmed incident this fixes (ffuf against a large wordlist): raw stdout can run
        # to hundreds of KB, and it sits BEFORE "parsed" in this dict — the final
        # json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT] truncation (this module's own message-append
        # and _log_output) cut the whole result off inside that raw dump, so the parser's own
        # structured output never survived into what the model or session.json actually saw. Once
        # a parser has successfully extracted structured data, the raw stdout is redundant — same
        # "cap what's handed to the model" discipline this codebase already uses for
        # native.py's body_preview, applied here so "parsed" always fits within the truncation
        # budget instead of being silently squeezed out by whatever ran ahead of it.
        stdout = result["stdout"]
        capped_stdout = stdout if len(stdout) <= 2000 else stdout[:2000] + f"... [{len(stdout)} chars total, see 'parsed' for the structured result]"
        return {**result, "stdout": capped_stdout, "parsed": parsed, **note_update}

    permanent_hint_fn = _PERMANENT_ERROR_HINTS.get(spec.name)
    if permanent_hint_fn is not None:
        permanent_hint = permanent_hint_fn(result)
        if permanent_hint is not None:
            # status="failed" is deliberately NOT in _RETRYABLE_STATUSES -- this is what actually
            # skips the doomed-to-fail 1-Step Retry round-trip, not just a better-worded message on
            # a retry that still happens anyway. See _PERMANENT_ERROR_HINTS' own docstring.
            return {**result, "status": "failed", "error": permanent_hint}

    hint_fn = _ERROR_HINTS.get(spec.name)
    if hint_fn is None:
        return result
    hint = hint_fn(result)
    if hint is None:
        return result
    # result["error"] (not "stderr") is what _log_error/the 1-Step Retry correction prompt reads
    # first -- setting it here is what actually gets this hint in front of the model, without
    # discarding the real raw stderr underneath it (still there for anyone reading the full log).
    return {**result, "error": hint}


def _tool_description(spec: ToolSpec) -> str:
    if spec.description:
        return spec.description
    # Autodiscovered/custom tools carry no hand-written description — pull their real --help
    # text (cached after the first fetch) so the model knows how to call them at all.
    help_text = get_tool_help(spec.name, spec.executable, spec.full_description)
    return help_text[:4000] if help_text else f"Tool {spec.name!r} (no description available)."


def _tool_to_openai_schema(spec: ToolSpec) -> dict:
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": _tool_description(spec),
            "parameters": spec.parameters_schema or _GENERIC_DISCOVERED_SCHEMA,
        },
    }


def _parse_json_response(content: str | None) -> dict | None:
    if not content:
        return None
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    match = _JSON_FENCE_PATTERN.search(content)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    logger.debug("core: failed to parse JSON from LLM response: %s", content[:500])
    return None


def _json_parse_error_detail(content: str | None) -> str | None:
    """Best-effort json.JSONDecodeError message for a reply that failed to parse, mirroring
    _parse_json_response's own fenced-code fallback -- used only to put a concrete hint in front
    of the model during repair, since _parse_json_response itself swallows the exception.
    """
    if not content:
        return None
    text = content
    match = _JSON_FENCE_PATTERN.search(content)
    if match:
        text = match.group(1)
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        return str(exc)
    return None


async def _repair_json_reply(ctx: RunContext, prior_messages: list[dict], failed_content: str | None) -> dict | None:
    """One repair attempt when a reply that was supposed to be a JSON contract didn't parse —
    a real decision (e.g. a completed exploit attempt) getting silently discarded as "no
    parseable result" because the model wrapped it in prose or the object got cut off mid-field
    is a worse outcome than one extra call asking it to resend just the JSON.
    """
    # Real, confirmed incident this fixes: a weak model's repair attempt reproduced the exact same
    # bracket-mismatch error byte-for-byte, because "resend valid JSON" alone gave it no clue what
    # was actually wrong the first time. Pointing at the concrete parse error gives it something to
    # actually fix instead of blindly resending the same broken structure.
    detail = _json_parse_error_detail(failed_content)
    hint = f" Specifically, it failed to parse with: {detail} — check bracket/brace matching around that point." if detail else ""
    repair_messages = [
        *prior_messages,
        {"role": "assistant", "content": failed_content or ""},
        {"role": "user", "content": f"That reply did not parse as valid JSON.{hint} Resend ONLY the JSON object — no prose, no markdown fences, complete and well-formed."},
    ]
    repaired = await _llm_complete(ctx, repair_messages, None)
    parsed = _parse_json_response(repaired.content)
    if parsed is None:
        logger.debug("core: JSON repair attempt also failed to parse: %s", (repaired.content or "")[:500])
    return parsed


async def _repair_terminal_tool_reply(
    ctx: RunContext,
    messages: list[dict],
    tools_schema: list[dict],
    terminal_tool: str,
    specs_by_name: dict[str, ToolSpec],
    execute_tool: Callable[[ToolSpec, dict], Awaitable[dict]] | None,
    trace: list[dict],
    phase: str,
) -> dict | None:
    """One repair attempt when the model was supposed to call terminal_tool but replied with
    something else instead (no tool call, or non-JSON text) -- unlike _repair_json_reply's generic
    "resend the JSON" prompt (fine when the expected shape was already spelled out in the system
    prompt's own text, e.g. Validate), a terminal_tool's shape was NEVER given as text, only as a
    structured tool schema. Stripping that away (tools=None, _repair_json_reply's own contract)
    leaves a model with nothing to recall the shape from, so it falls back to whatever text-based
    function-call syntax it happens to have memorized from its own training -- confirmed live: a
    Llama-style `<function=X><parameter=Y>` block that can never parse as JSON, burning two wasted
    calls and then silently defaulting a reverify verdict to "no longer present" even though the
    finding was never actually re-checked at all. Retrying WITH the real tool schema still attached
    gives the model a genuine second chance to emit a proper tool call instead of guessing a format.
    """
    messages.append({"role": "user", "content": f"Reply with a real call to {terminal_tool} now — no prose, no other format."})
    response = await _llm_complete(ctx, messages, tools_schema)
    call = next((c for c in response.tool_calls if c.name == terminal_tool), None)
    if call is None:
        logger.debug("core: terminal_tool repair attempt still didn't call %r: %s", terminal_tool, (response.content or "")[:500])
        return None
    spec = specs_by_name[terminal_tool]
    dispatch_started = time.monotonic()
    result = await execute_tool(spec, call.arguments) if execute_tool is not None else await _run_tool_with_retry(ctx, spec, call.arguments)
    duration_ms = (time.monotonic() - dispatch_started) * 1000
    trace.append({"tool": call.name, "arguments": call.arguments, "result": result})
    _append_log(ctx, phase, response.content, _describe_command(call, result), _log_status(result), _log_error(result), duration_ms, _log_output(result))
    if result.get("status") != "ok":
        return None
    return {k: v for k, v in result.items() if k not in _TOOL_RETRY_BOOKKEEPING_KEYS}


def _describe_command(call: ToolCallRequest, result: dict) -> str:
    command = result.get("command")
    if isinstance(command, list):
        return " ".join(command)
    # used_arguments (set by _run_tool_with_retry for every native tier-1 call) reflects whichever
    # attempt actually produced this result -- a corrected retry can send different arguments than
    # the model's original call, and falling back to call.arguments here would pair the WRONG
    # (pre-retry) arguments with THIS result's own error/status. Real incident this fixes: a retry
    # that changed identity="user_a" to identity="default" left the log line reading
    # `authenticated_request({"identity": "user_a", ...})` right next to
    # "No credentials configured for identity 'default'" -- technically two true facts from two
    # different attempts, but read together they look like the tool reported the wrong identity.
    arguments = result.get("used_arguments", call.arguments)
    # Server-side-injected fields (leading underscore, _run_tool_with_retry's own "injected" dict)
    # never belong in a human-readable log line -- catastrophic real incident this fixes:
    # check_subagent_task/delegate_to_subagent/hydra_start/web_login_bruteforce_start/
    # background_job_check all get the REAL, LIVE ctx.session dict injected as their own
    # "_session" argument (their native functions genuinely need it -- they mutate session state
    # directly). Before this filter, that whole session dict -- including this SAME logs list,
    # which this exact log entry was about to be appended to -- got serialized into the "command"
    # string, so a session doing several check_subagent_task polls saw each one embed a full copy
    # of every previous one, snowballing a session.json from a few hundred KB into 364 MB (and
    # debug.log similarly, via run_tool()'s own params=%s line -- see that file's matching fix)
    # within a couple dozen poll calls. Only the loggable, non-injected arguments a human actually
    # needs ever reach this string; the real dispatch (which DOES need the injected fields to
    # function) reads `arguments`/call.arguments directly and is untouched by this filter.
    loggable_arguments = {k: v for k, v in arguments.items() if not k.startswith("_")}
    described = f"{call.name}({json.dumps(loggable_arguments)})"
    if call.name == "delegate_to_subagent" and result.get("task_id"):
        # Otherwise this line shows only the request (which subagent, what task) with no way to
        # tell which of that subagent's own later phase="subagent" log entries it actually
        # produced — the Subagent log UI section groups by task_id, so this is what makes the
        # main log and that section visually correlatable at all.
        described += f" -> task_id={result['task_id']}"
    return described


def _log_status(result: dict) -> str:
    status = result.get("status", "error")
    return "success" if status == "ok" else status


# A tool's own error/stderr/reason field was previously passed through here completely raw, with
# no size cap at all -- safe for the overwhelming majority of tools (a short CLI error message),
# but a real, confirmed incident (orrery-usr_38e422) shows why that's not safe in general:
# strace_run's own `stderr` IS its real, useful payload (the actual syscall trace, potentially very
# large when tracing wine's own startup with -f following forks) -- when it failed, this
# untruncated text went straight into _run_tool_with_retry's own 1-Step-Retry correction prompt
# (this module's own f"Error: {_log_error(result)}\n") with NO truncation there either, producing a
# single LLM call of 1,063,415 tokens that exhausted the ENTIRE 8-model fallback chain in a row and
# failed the whole chat turn outright (Error code: 402). None of this function's OTHER callers
# (session["logs"]' own _log_error entry, _track_host_health's last_error) need the FULL text
# either -- a human/LLM diagnosing "what went wrong" needs a representative excerpt, not a
# megabyte dump; the tool's own full raw output is still available via dump_large_payload/the
# debug-tool-calls dump for anyone who genuinely needs all of it.
_LOG_ERROR_CHAR_LIMIT = 4000


def _log_error(result: dict) -> str | None:
    if result.get("status") == "ok":
        return None
    text = result.get("error") or result.get("stderr") or result.get("reason")
    if text is None:
        return None
    text = str(text)
    if len(text) > _LOG_ERROR_CHAR_LIMIT:
        return text[:_LOG_ERROR_CHAR_LIMIT] + f"... [truncated, {len(text)} chars total]"
    return text


def _log_output(result: dict) -> str | None:
    """Human-readable dump of a tool call's actual result payload for session["logs"] — the same
    level of detail Interactive/chat mode already shows for every one of its own tool calls (its
    "output" segment field, agent/chat.py's _run_chat_tool_loop / templates/partials/
    chat_messages.html). Before this, the autonomous phase loop's own Logs tab only ever showed the
    call's arguments (_describe_command) and, on failure, one error string (_log_error) — never
    what the tool actually returned on success, so reconstructing "what did nmap/ffuf/whatweb
    actually find here" meant leaving the web UI and grepping session.json or debug.log by hand.
    Bookkeeping/injected fields excluded (_TOOL_RETRY_BOOKKEEPING_KEYS, leading-underscore) — same
    filter _describe_command already applies to a call's own arguments, for the same reason:
    nothing internal-only belongs in what a human reads back. Truncated to _TOOL_RESULT_CHAR_LIMIT,
    the same cap already used for what this exact result gets fed back to the LLM as (the "role":
    "tool" message right after each _append_log call below) — keeps one verbose tool result (a
    large nmap/ffuf dump) from bloating session.json unbounded.
    """
    loggable = {k: v for k, v in result.items() if k not in _TOOL_RETRY_BOOKKEEPING_KEYS and not k.startswith("_")}
    if not loggable:
        return None
    return json.dumps(loggable, ensure_ascii=False)[:_TOOL_RESULT_CHAR_LIMIT]


# A terminal tool's own success must never be built on a subagent result the model never actually
# observed finishing. Real incident: record_reverification_result cited a subagent task_id as
# proof ("the subagent has now reported back: OpenSSH 8.9p1...") when the only status this same
# trace had ever actually observed for that task_id was "running" -- the model invented a version
# number and scanner verdict that turned out to be false once the real result eventually arrived.
_RESOLVED_SUBAGENT_STATUSES = {"done", "timeout", "error"}


def _unresolved_subagent_task_ids(trace: list[dict]) -> set[str]:
    """Task ids delegated/polled within this trace whose last status THIS trace actually observed
    is still "running" -- i.e. this loop never saw them finish, so citing one as settled evidence
    would be reporting a result nobody here has actually seen yet."""
    last_status: dict[str, str] = {}
    for entry in trace:
        tool = entry.get("tool")
        result = entry.get("result") or {}
        if tool == "delegate_to_subagent" and result.get("task_id"):
            last_status.setdefault(result["task_id"], "running")
        elif tool == "check_subagent_task":
            task_id = (entry.get("arguments") or {}).get("task_id")
            status = result.get("status")
            if task_id and status:
                last_status[task_id] = status
    return {task_id for task_id, status in last_status.items() if status not in _RESOLVED_SUBAGENT_STATUSES}


def _cited_unresolved_subagent_task(call_arguments: dict, unresolved_task_ids: set[str]) -> str | None:
    """Substring match, not exact-field parsing -- the model cites a task_id in free-text reasoning/
    evidence_ref, not a dedicated structured field, so this has to look at the whole call the same
    way a human reviewer would."""
    if not unresolved_task_ids:
        return None
    haystack = json.dumps(call_arguments)
    for task_id in unresolved_task_ids:
        if task_id in haystack:
            return task_id
    return None


def _append_log(
    ctx: RunContext, phase: str, thought: str | None, command: str | None, status: str, error: str | None,
    duration_ms: float | None = None, output: str | None = None,
) -> None:
    ctx.session["logs"].append(
        {
            "step": len(ctx.session["logs"]) + 1,
            "phase": phase,
            # Stored in full, not truncated — this is often the model's own final reasoning/summary
            # for a phase or an exploit decision, real content a human needs to actually read, not
            # a preview. The collapsed log-entry summary line (session_fragment.html) still shows
            # only a one-line CSS-truncated preview; expanding it now reveals the whole thing
            # instead of cutting off mid-sentence with no indication anything was missing.
            "thought": thought or None,
            "command": command,
            "status": status,
            "error": error,
            # The tool's own result payload (_log_output) — None whenever this entry has no real
            # tool dispatch behind it (a plain LLM JSON turn, a synthetic refusal/failure record).
            # Interactive/chat mode has shown this same detail per tool call from the start (its
            # own segments' "output" field); this brings the autonomous phase loop's Logs tab up to
            # the same level instead of leaving success results invisible outside session.json.
            "output": output,
            "finding_title": ctx.current_finding_title,
            # None for a step with no real tool dispatch (a duplicate-in-batch skip, an unknown
            # tool, a plain free-text turn) — only set where real wall-clock time around the actual
            # dispatch (execute_tool/_run_tool_with_retry) was measured, by the caller. Previously
            # the only way to tell a legitimately slow tool (a long ffuf/nikto run) apart from
            # something actually stuck was eyeballing the gap between two consecutive entries' own
            # "at" timestamps by hand — that gap also includes the next LLM turn's own thinking
            # time, so it was never more than an approximation.
            "duration_ms": round(duration_ms) if duration_ms is not None else None,
            # Set only while ctx is a delegated subagent's own RunContext (see RunContext's
            # docstring) — None for every main-phase entry. Lets the UI group a subagent's own
            # steps by which delegation produced them instead of a flat, wall-clock-interleaved
            # stream shared with whatever the main agent was doing at the same time.
            "subagent_task_id": ctx.subagent_task_id,
            "subagent_name": ctx.subagent_name,
            # Same "at" key debug.py's _record_approval already uses for a timestamped session
            # event — without this, correlating one specific step to a real point in time (was
            # this during a provider outage? how long did this phase actually take?) meant manually
            # grepping debug.log for matching text and reading its timestamp off a completely
            # separate file. A log-review pass now gets this for free from session.json alone.
            "at": datetime.now(timezone.utc).isoformat(),
        }
    )
    save_session(ctx.session_id, ctx.session)


_TARGET_SHAPED_ARGUMENT_KEYS = ("target", "host", "domain")


def _retry_target_changed(arguments: dict, retry_arguments: dict) -> tuple[str, str] | None:
    """Returns (original_hostname, corrected_hostname) when a 1-Step Retry's own "corrected"
    arguments swapped a target-shaped argument to a genuinely different host, or None when it's
    the same host (the overwhelmingly common case: a syntax/argument-name fix, not a different
    target). Compared by hostname, not exact string — a corrected call substituting a full URL
    for the same bare host is still the same real target, same reasoning as
    allowed_targets.py's own hostname-based matching.

    Real, confirmed incident this flags: a failed security_headers_audit against
    "mail.z8games.com" came back from the correction call "fixed" to "z8games.com" — a
    completely different host, not a fix to the original call — and nothing noticed;
    _run_tool_with_retry logged it as a plain "retried succeeded". Deliberately does not block
    the retry (a legitimate typo/host-name fix in a correction is common and useful) — only
    flags it, so it stays visible in the debug log and the result itself instead of silently
    looking like an ordinary successful correction.
    """
    for key in _TARGET_SHAPED_ARGUMENT_KEYS:
        before, after = arguments.get(key), retry_arguments.get(key)
        if isinstance(before, list):
            before = before[0] if before else None
        if isinstance(after, list):
            after = after[0] if after else None
        if not isinstance(before, str) or not before.strip() or not isinstance(after, str) or not after.strip():
            continue
        before_host = (extract_hostname(before.strip()) or before.strip()).lower()
        after_host = (extract_hostname(after.strip()) or after.strip()).lower()
        if before_host != after_host:
            return before_host, after_host
    return None

# ANALYZE_PROMPT's own hostname-shape rule names these same prefixes — kept as one real regex
# instead of restating the list, since a bare "the model should notice this" nudge wasn't enough
# on its own (real incident: auth./data./analytics. subdomains on a real scan got nothing beyond a
# banner grab because nothing concrete ever pointed the model at them — see
# _app_shaped_hostnames_task_addendum below). Extended after a second real incident: a scan against
# a marketplace target had seller./ads. subdomains (a seller portal, an ad platform — real app
# surfaces) that this list didn't cover yet; authenticated_crawl still got called that time, but
# only via the model's own general judgment, not this deterministic trigger. Add a new prefix here
# the moment a real scan shows a gap like this, the same way these two were added.
_APP_SHAPED_HOSTNAME_PATTERN = re.compile(
    r"^(auth|api|admin|app|portal|dashboard|data|analytics|seller|ads|merchant|partner|vendor|"
    r"account|accounts|console|my)\.",
    re.IGNORECASE,
)


def _out_of_scope_target(session: dict, arguments: dict) -> str | None:
    """Returns the matched out-of-scope entry when this call's target-shaped argument
    (target/host/domain — every built-in tool's own param name for what it acts on) hits one of
    the operator's exclusions (session["out_of_scope"], New Project form), None when it's clear.
    Checked before every real tool call, recon included — not just exploitation's allowlist gate —
    a deterministic guarantee the model can't override, not just a prompt suggestion it could
    ignore; see also _out_of_scope_task_addendum, which tells the model about the exclusion list
    up front so a skipped call isn't a silent mystery it keeps retrying."""
    out_of_scope = session.get("out_of_scope") or []
    if not out_of_scope:
        return None
    for key in _TARGET_SHAPED_ARGUMENT_KEYS:
        value = arguments.get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, str) and value.strip() and is_target_out_of_scope(value.strip(), out_of_scope):
            return value.strip()
    return None


def _loopback_or_link_local_target(arguments: dict) -> str | None:
    """Returns the literal loopback/link-local address a call's target-shaped argument names, or
    None when it's neither. Real incident this fixes: a model chasing a cPanel-origin lead called
    tcp_port_check with target="127.0.0.1" instead of the real host — it silently "succeeded",
    probing the agent's own machine and telling the model nothing about the actual scan target.
    127.0.0.0/8 (and ::1) can never legitimately BE the pentest target — it always means "this
    agent's own host" — and 169.254.0.0/16 (link-local, includes the 169.254.169.254 cloud-metadata
    address) has no legitimate reason to be a web-application scan target either. Deliberately does
    NOT block RFC1918 private ranges (10.x/172.16-31.x/192.168.x) — those can be a real, in-scope
    target for an internal-network engagement, unlike a loopback or link-local address, which never
    is. Checked only against the literal argument value, same as _out_of_scope_target above — never
    resolves a hostname just to test this.
    """
    for key in _TARGET_SHAPED_ARGUMENT_KEYS:
        value = arguments.get(key)
        if isinstance(value, list):
            value = value[0] if value else None
        if not isinstance(value, str) or not value.strip():
            continue
        hostname = extract_hostname(value.strip()) or value.strip()
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local:
            return value.strip()
    return None


# Tool name -> technology tokens (case-insensitive substring match against whatweb's own
# recon_result["technologies"] tokens for that host) that must be confirmed before the tool is
# allowed to run at all. Generalizes what started as a single hand-written wpscan-only check
# (_wpscan_cms_not_confirmed) — seeded with just that one real migration for now (YAGNI: the
# registry's other tools are either login-shape-generic, useful against any service, not gated on
# one specific tech, or general-purpose scanners whose applicability isn't a single tech token —
# hard-gating those would be the "exclude a tool the model might still legitimately need" mistake
# this project's own rules explicitly warn against). Add a table entry, not a new hand-written gate
# function, the next time a genuinely CMS/tech-specific tool joins the registry.
_TECH_GATED_TOOLS: dict[str, tuple[str, ...]] = {
    "wpscan": ("wordpress",),
}


def _tech_gate_blocked(session: dict, tool_name: str, arguments: dict) -> bool:
    """True when tool_name is about to run against a host with none of its required technology
    tokens (_TECH_GATED_TOOLS) confirmed yet — running a tech-specific enumerator against something
    never confirmed to be that tech burns a real tool call/timeout for a result that was always
    going to be empty. False immediately for any tool not in the table at all. The only accepted
    evidence is agent/core.py's own deterministic whatweb technologies auto-merge
    (recon_result["technologies"], populated in _run_analyze's execute() regardless of whether the
    model also transcribes it anywhere) — not a claim in the model's own reasoning, which is
    exactly the kind of unverified badge/claim this gate exists to prevent.
    """
    required_tokens = _TECH_GATED_TOOLS.get(tool_name)
    if not required_tokens:
        return False
    target = arguments.get("target")
    if isinstance(target, list):
        target = target[0] if target else None
    if not isinstance(target, str) or not target.strip():
        return False  # let build_command's own validation surface the real error instead
    target_lower = target.strip().lower()
    technologies_by_host = session.get("recon_result", {}).get("technologies", {})
    return not any(
        host and host.lower() in target_lower and any(token in tech.lower() for tech in techs for token in required_tokens)
        for host, techs in technologies_by_host.items()
    )


# The browser_* tools' own async-bypass names (agent/tools/browser.py's stubs, agent/tools/
# __init__.py's registrations) -- same reason delegate_to_subagent bypasses run_tool/to_thread
# below: a Playwright browser session must persist across separate LLM tool calls (navigate now,
# click later, read state later), which needs the SAME event loop that created its async API
# objects, not a fresh worker thread `to_thread` doesn't guarantee is even the same OS thread
# twice in a row.
_BROWSER_TOOL_NAMES = {
    "browser_navigate", "browser_snapshot", "browser_click", "browser_fill",
    "browser_select_option", "browser_press_key", "browser_evaluate",
    "browser_go_back", "browser_close_session",
}


async def _dispatch_browser_tool(name: str, arguments: dict) -> dict:
    """The browser_* tools' real dispatch target, called directly from _dispatch_tool's own
    bypass, never through run_tool/to_thread. session_id/session come from the SAME server-side-
    injected _session_id/_session keys _run_tool_with_retry already adds for hydra_start/
    background_job_check/delegate_to_subagent (outside every browser_* tool's own JSON schema, so
    the model can neither see nor override them) -- get_browser_manager() is what actually owns
    the persistent Playwright state across separate calls, this function only unpacks arguments
    and routes to its matching method.
    """
    manager = get_browser_manager()
    session_id = arguments.get("_session_id")
    session = arguments.get("_session") or {}
    out_of_scope_entries = session.get("out_of_scope") or []

    _tools_logger.debug("browser tool start: tool=%s params=%s", name, _loggable_params(arguments))
    result = await _dispatch_browser_tool_impl(name, arguments, manager, session_id, out_of_scope_entries)
    _tools_logger.debug("browser tool finished: tool=%s status=%s", name, result.get("status") if isinstance(result, dict) else "?")
    return result


async def _dispatch_browser_tool_impl(
    name: str, arguments: dict, manager, session_id: str | None, out_of_scope_entries: list,
) -> dict:
    if name == "browser_navigate":
        # "domcontentloaded", not "load" -- real, confirmed incident: a Cloudflare/bot-challenge-
        # fronted site (platform.openai.com, and openai.com's own apex) never fires "load" at all,
        # so every browser_navigate call omitting wait_until burned a full
        # BROWSER_ACTION_TIMEOUT_SECONDS timeout + a wasted LLM retry round-trip before the model
        # corrected it to "domcontentloaded" itself -- 4 separate times in one real session. The
        # DOM being ready is all a snapshot/interaction actually needs; "load"/"networkidle" are
        # still available as an explicit choice (see this tool's own parameters_schema) for the
        # rarer case that genuinely needs every subresource finished.
        return await manager.navigate(session_id, arguments.get("target", ""), arguments.get("wait_until", "domcontentloaded"), out_of_scope_entries, arguments.get("identity"))
    if name == "browser_snapshot":
        return await manager.snapshot(session_id, out_of_scope_entries)
    if name == "browser_click":
        return await manager.click(session_id, arguments.get("ref", ""), out_of_scope_entries)
    if name == "browser_fill":
        return await manager.fill(session_id, arguments.get("ref", ""), arguments.get("text", ""), out_of_scope_entries)
    if name == "browser_select_option":
        return await manager.select_option(session_id, arguments.get("ref", ""), arguments.get("value", ""), out_of_scope_entries)
    if name == "browser_press_key":
        return await manager.press_key(session_id, arguments.get("key", ""), out_of_scope_entries)
    if name == "browser_evaluate":
        return await manager.evaluate(session_id, arguments.get("expression", ""), out_of_scope_entries)
    if name == "browser_go_back":
        return await manager.go_back(session_id, out_of_scope_entries)
    # browser_close_session
    await manager.close_session(session_id)
    return {"status": "ok"}


async def _dispatch_tool(spec: ToolSpec, arguments: dict) -> dict:
    """Almost every tool call runs in a worker thread (asyncio.to_thread(run_tool, ...)) --
    native_function bodies are plain sync code with no event loop of their own (see
    agent/tools/runner.py's own docstring). delegate_to_subagent and the browser_* tools are the
    exceptions: spawning a subagent's own asyncio.Task requires a REAL running event loop in the
    calling thread (asyncio.create_task() raises RuntimeError otherwise), and a Playwright browser
    session must stay on the exact event loop that created its async API objects across separate
    calls (see _dispatch_browser_tool's own docstring) -- both alone bypass run_tool/to_thread
    entirely and call their real async implementation directly, still on the main event loop,
    never routed through a worker thread. check_subagent_task needs no such trick (it only
    inspects an already-tracked asyncio.Task's state -- .done()/.result()/.exception() are plain,
    thread-safe reads, no event loop required), so it stays a normal tier-1 native_function in
    agent/tools/native.py, dispatched the ordinary way.
    """
    if spec.name == "delegate_to_subagent":
        return await _delegate_to_subagent_impl(arguments)
    if spec.name in _BROWSER_TOOL_NAMES:
        return await _dispatch_browser_tool(spec.name, arguments)
    if spec.name == "check_disclosed_reports":
        # Lazy import, not a module-top-level one -- agent.tools.bugbounty_import itself imports
        # FROM agent.core (_parse_json_response), so importing it at THIS module's own top level
        # would be circular (agent.core -> agent.tools -> agent.tools.bugbounty_import ->
        # agent.core, mid-load). By the time this function actually runs, both modules are fully
        # loaded, so the cycle only exists at import time, not at call time.
        #
        # Unlike every other tool class, this one bypasses run_tool/to_thread entirely (see this
        # function's own docstring), so it gets NEITHER a subprocess timeout (runner.py's
        # TOOL_TIMEOUT_SECONDS -- there's no subprocess here) NOR a subagent-style asyncio.wait_for
        # deadline. Its own internal LLM call (_run_extraction_with_reserve_chain, bugbounty_import.py)
        # walks the operator's full reserve-provider chain, retrying up to 6 times per provider with
        # a backoff schedule (2/4/8/16/30s) that assumes each attempt fails FAST -- confirmed live
        # (a real HackerOne session, usr_cda43e, 2026-09-08) that assumption doesn't hold against a real
        # free-tier provider stuck behind OpenRouter's own upstream queue: three consecutive attempts
        # each took ~600s (a normal, non-timeout completion with finish_reason="error", not an
        # APITimeoutError -- httpx's per-chunk read timeout keeps getting reset by the provider's own
        # keep-alive bytes, so LLM_REQUEST_TIMEOUT_SECONDS=120 never actually bounded it) -- worst
        # case (3 reserve providers x 6 attempts x ~600s) is several HOURS with the entire exploit
        # phase blocked on this one best-effort duplicate-report check, zero findings, zero progress,
        # zero visibility. This is best-effort enrichment, not core scan correctness -- bounding it
        # here guarantees the phase moves on regardless of how badly the nested retry/reserve-chain
        # logic misbehaves against a given provider.
        from agent.tools.bugbounty_import import check_disclosed_reports
        timeout_seconds = float(os.getenv("DISCLOSED_REPORTS_TIMEOUT_SECONDS", "300"))
        try:
            return await asyncio.wait_for(check_disclosed_reports(arguments.get("program_url", "")), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            logger.debug("core: check_disclosed_reports timed out after %.0fs, continuing without it", timeout_seconds)
            return {"status": "error", "error": f"Duplicate-report check timed out after {timeout_seconds:.0f}s (slow/rate-limited LLM reserve chain) — continuing without it."}
    # See runner.current_subprocess_registry's own docstring for the real incident this closes —
    # a subagent's own asyncio.wait_for timeout (or a user-triggered session stop) cancelling THIS
    # coroutine while its worker thread is still blocked inside a live subprocess call otherwise
    # leaves that real OS process running, orphaned, with nothing left to ever collect its result.
    live_processes: set = set()
    registry_token = current_subprocess_registry.set(live_processes)
    try:
        return await asyncio.to_thread(run_tool, spec, arguments)
    except asyncio.CancelledError:
        for process in list(live_processes):
            try:
                process.kill()
            except ProcessLookupError:
                pass
        raise
    finally:
        current_subprocess_registry.reset(registry_token)


async def _dispatch_tool_interruptible(ctx: RunContext, spec: ToolSpec, arguments: dict) -> dict:
    """_dispatch_tool, raced against the operator's Stop signal (get_stop_event) so a slow/hung
    subprocess-backed tool call can actually be killed the instant Stop is clicked, instead of only
    being noticed once that call finishes on its own or hits its own internal subprocess timeout —
    TOOL_TIMEOUT_SECONDS/EXPLOIT_TIMEOUT_SECONDS later, up to 600s in this project's own .env.

    Real, confirmed incident this fixes (NinthCircle-crackmes-usr_573a1e): a radare2 decompile_
    function call hung; the operator clicked RE mode's Stop button 19 seconds in, and the session
    kept polling as "processing" for 80+ more real seconds with zero effect, forcing the operator to
    kill the whole process by hand. get_stop_event is only a cooperative in-memory asyncio.Event —
    request_session_stop (main.py's /interrupt and /re-triage/stop routes) does nothing but set it,
    and _run_tool_with_retry's own dispatch of _dispatch_tool was previously a bare `await` with no
    checkpoint of it at all. _dispatch_tool ALREADY kills any live subprocess it started the moment
    its own asyncio.Task is cancelled (current_subprocess_registry, right above) — that machinery
    just needed something to actually call .cancel() on a Stop signal instead of only ever being
    reached from a subagent's own asyncio.wait_for timeout. Any status this raced dispatch would
    have returned is discarded once Stop wins the race — a stopped session persists status=
    "interrupted"/"paused" via SessionStopRequested below, not a half-finished tool result.
    """
    stop_event = get_stop_event(ctx.session_id)
    if stop_event.is_set():
        raise SessionStopRequested()
    tool_task = asyncio.ensure_future(_dispatch_tool(spec, arguments))
    stop_wait_task = asyncio.ensure_future(stop_event.wait())
    try:
        done, _pending = await asyncio.wait({tool_task, stop_wait_task}, return_when=asyncio.FIRST_COMPLETED)
        if tool_task in done:
            return tool_task.result()
        tool_task.cancel()
        try:
            await tool_task
        except asyncio.CancelledError:
            pass
        raise SessionStopRequested()
    finally:
        if not stop_wait_task.done():
            stop_wait_task.cancel()


# This many real failures IN A ROW (reset by any success — see _dead_host_blocked/_track_host_health
# below) against the same host -> treated as confirmed unreachable for the rest of the session, not
# retried further. Real incident this fixes: a real session hit the SAME dead hosts
# (several subdomains of the same target, portal./forum./...) with http_request/whatweb/tcp_port_check dozens of
# times across Analyze AND Exploit, every single attempt failing, with nothing ever recognizing
# "this host is dead, stop spending real attempts on it" the way _tech_gate_blocked already does for
# a confirmed-absent technology. Only applies once 2+ DISTINCT tools have failed against the host --
# see _dead_host_blocked's own docstring for why (the httpx-CLI-flag-guessing incident this
# 2-tool requirement itself exists for).
_HOST_DEAD_FAILURE_THRESHOLD = 3
# A HIGHER bar for the single-tool case (only one tool has ever failed against this host in the
# current streak) -- real, confirmed incident this fixes: send_raw_request tried 33 cosmetically
# different wrappers (http://, ssh://, telnet://, bare host:port, GET/CONNECT) against the same
# dead SSH port over ~29 minutes (rev-retest-rescan-usr_8ba29f) -- every single one a genuine
# connection/protocol failure, never a CLI-flag-guessing mistake the 2-tool rule was built to
# tolerate, yet _dead_host_blocked never fired because consecutive_failure_tools never grew past
# length 1 (send_raw_request itself, every time). A single tool guessing DIFFERENT arguments for a
# genuine reason (the httpx incident) self-corrects within a handful of attempts; a streak this
# much longer from just one tool is no longer plausibly "still guessing" and is itself real,
# sufficient host-level evidence on its own.
_HOST_DEAD_FAILURE_THRESHOLD_SINGLE_TOOL = 8
_HOST_HEALTH_TRACKED_STATUSES = {"ok", "error", "timeout", "failed"}


def _extract_target_host(arguments: dict) -> str | None:
    target = arguments.get("target")
    if isinstance(target, list):
        target = target[0] if target else None
    if not isinstance(target, str) or not target.strip():
        return None
    return extract_hostname(target) or target.strip()


def _dead_host_blocked(session: dict, arguments: dict) -> str | None:
    """True (a real skip reason) when this host has failed its last
    _HOST_DEAD_FAILURE_THRESHOLD+ real attempts IN A ROW this session — the exact "already failed N
    times, stop retrying it" backstop _MAX_IDENTICAL_FAILURES_PER_PHASE already gives an EXACT call
    signature, generalized to the host itself (a different path/method against the same dead host
    is still the same dead host). Scoped to any call that actually names a "target" argument at all
    (_extract_target_host returns None otherwise) — deliberately NOT spec.requires_allowed_target,
    which means something unrelated (exploit-tier approval gating, registry.py's own docstring) and
    would have missed the exact tools that caused the real incident this whole mechanism exists for
    (http_request/whatweb/tcp_port_check/nmap all have requires_allowed_target=False). Every
    third-party-service tool (crt_sh_lookup, cve_lookup, exploit_db_lookup, ...) takes a
    "domain"/"product"/"query" argument instead of "target", so this naturally never applies to any
    of them.

    Keyed on the CURRENT streak of consecutive failures (reset to 0 by any success), not lifetime
    totals — a real incident this fixes: a host that succeeds once early on and then goes on to
    fail every subsequent attempt for the rest of the session (a route flapped, a WAF kicked in
    mid-scan) used to stay permanently exempt from blocking forever after that one success,
    confirmed live wasting calls against one target's subdomain (4 failures/1 success) all the way
    through the session's very last phase. A host that's genuinely just flaky (intermixed
    successes and failures throughout) still never accumulates a long enough consecutive streak to
    trip this, so that legitimate case stays untouched.

    With 2+ DISTINCT tools in the streak, _HOST_DEAD_FAILURE_THRESHOLD (3) is enough to conclude the
    HOST itself is the problem — real, confirmed incident this fixes: httpx worked completely fine
    multiple times early in a real session (real 200 responses, real page content), then the model
    started guessing a flag that doesn't exist ("-response-in-json") and got 3 real, genuine
    failures in a row from THAT SAME TOOL's own CLI argument parser — nothing about the host itself,
    every other tool would have worked fine against it. The ORIGINAL incident this whole mechanism
    was built for (see this docstring's own history) was several DIFFERENT tools (http_request/
    whatweb/tcp_port_check) all failing against the same genuinely-dead host — a single tool
    repeatedly tripping over its own bad arguments was never the case this needed to cover, and
    blocking every OTHER tool from a demonstrably-reachable host over one tool's own mistake made an
    entire real session's primary target unreachable to everything for the rest of it.

    With only 1 distinct tool in the streak, the bar is instead _HOST_DEAD_FAILURE_THRESHOLD_SINGLE_
    TOOL (8, not 3) — see that constant's own docstring for the real incident this closes: 33
    cosmetically different send_raw_request calls (http://, ssh://, telnet://, bare host:port) all
    genuinely failed against the same dead SSH port over ~29 minutes, and the plain 2-distinct-tools
    gate above never let this whole mechanism recognize it at all, no matter how many times it
    failed. A host that's actually dead still trips this either way, since a real network failure
    affects every tool that tries it, not just one — the only question is how much evidence from how
    many distinct sources it takes to conclude that with confidence.
    """
    host = _extract_target_host(arguments)
    if host is None:
        return None
    entry = session.get("recon_result", {}).get("host_health", {}).get(host)
    if entry is None:
        return None
    consecutive_failures = entry.get("consecutive_failures", 0)
    distinct_tools = len(entry.get("consecutive_failure_tools") or [])
    if distinct_tools >= 2:
        threshold = _HOST_DEAD_FAILURE_THRESHOLD
    elif distinct_tools == 1:
        threshold = _HOST_DEAD_FAILURE_THRESHOLD_SINGLE_TOOL
    else:
        return None
    if consecutive_failures < threshold:
        return None
    return (
        f"{host!r} has failed its last {consecutive_failures} real attempt(s) in a row this session "
        f"(last error: {entry.get('last_error')}) — treated as unreachable and not retried further. "
        "If you genuinely believe this is wrong, try a different host or path, not the same one again."
    )


def _track_host_health(ctx: RunContext, arguments: dict, result: dict) -> None:
    """Deterministic per-host success/failure tally (session["recon_result"]["host_health"]) fed by
    every real dispatch against the actual scan target — never trusts the model to notice or report
    a dead host itself, the same "derive it in code, don't rely on the model to remember" discipline
    _derive_plan_status/_apply_updated_plan already apply one layer up. Feeds both
    _dead_host_blocked above (stop wasting real attempts on a confirmed-dead host) and the Recon
    tab's own "Unreachable hosts" summary — one source of truth for both. Scoped to any call naming
    a "target" argument (see _dead_host_blocked's own docstring for why that's the right
    discriminator, not spec.requires_allowed_target) and to real dispatch OUTCOMES
    ("ok"/"error"/"timeout"/"failed") — a tool that ran fine but simply found nothing interesting in
    its own output (e.g. nmap's own "0 hosts up" line) isn't tracked here, that's a different,
    tool-specific signal already visible in its own raw output, not a dispatch-level connectivity
    failure.

    consecutive_failures resets to 0 on any success and increments on any failure — the recency
    signal _dead_host_blocked keys on, kept alongside the lifetime failures/successes totals (still
    used by the Recon tab's own summary). entry.get(..., 0) rather than a bare subscript so an
    entry already persisted in an older session file (predating this field) self-heals from its
    very next real dispatch instead of raising a KeyError.
    """
    if result.get("status") not in _HOST_HEALTH_TRACKED_STATUSES:
        return
    if result.get("never_dispatched"):
        # runner.py's own build_command exception marker — a malformed call (bad/missing
        # arguments) that never even attempted to reach the host at all says nothing about
        # whether the host is actually reachable, unlike a real dispatch failure. Counting it here
        # let 3 repeats of the SAME argument mistake permanently blacklist the session's own
        # primary target host from every other tool for the rest of the phase — see runner.py's
        # own comment on this flag for the real incident.
        return
    host = _extract_target_host(arguments)
    if host is None:
        return
    # Mutated on ctx.session's own in-memory dict first (not just computed locally) -- this same
    # object is what _dead_host_blocked reads for the REST of this run, so the "3 consecutive
    # failures blacklists a host" behavior needs the update visible in-process immediately, not only
    # after a round-trip through disk.
    health = ctx.session.setdefault("recon_result", {}).setdefault("host_health", {})
    entry = health.setdefault(host, {"failures": 0, "successes": 0, "consecutive_failures": 0, "last_error": None, "consecutive_failure_tools": []})
    if result["status"] == "ok":
        entry["successes"] += 1
        entry["consecutive_failures"] = 0
        entry["consecutive_failure_tools"] = []
    else:
        entry["failures"] += 1
        entry["consecutive_failures"] = entry.get("consecutive_failures", 0) + 1
        entry["last_error"] = _log_error(result) or entry["last_error"]
        # Which distinct tools contributed to the CURRENT streak -- _dead_host_blocked requires 2+
        # before concluding the host itself (not just this one tool) is the problem. entry.get(...,
        # []) rather than a bare subscript so an entry persisted before this field existed
        # self-heals from its very next real failure instead of raising a KeyError.
        tools_in_streak = entry.get("consecutive_failure_tools") or []
        tool_name = result.get("tool")
        if tool_name and tool_name not in tools_in_streak:
            tools_in_streak.append(tool_name)
        entry["consecutive_failure_tools"] = tools_in_streak
    # Real wall-clock anchor -- sessions/store.py's reset_host_health_streaks_for_new_pass is what
    # actually prevents a stale block from carrying into a new rescan pass unattempted; this
    # timestamp is telemetry for the Recon tab (when was this host last actually touched), not itself
    # a staleness/expiry mechanism.
    entry["last_updated_at"] = datetime.now(timezone.utc).isoformat()
    # Reload-merge-save (not a blind save_session(ctx.session_id, ctx.session)) -- this fires on
    # essentially every real tool dispatch, including ones made mid-chat-turn, where ctx.session can
    # be a long-lived stale snapshot loaded many minutes earlier while a concurrently-running
    # phase/reverify pass keeps saving fresher state to disk. Real, confirmed incident this fixes: a
    # RE-mode chat turn's own call into this function blind-saved its stale snapshot over a
    # concurrently-finished "Re-verify all findings" pass's own status="completed" save, permanently
    # reverting the session to status="processing" with nothing left to ever correct it. Only this
    # one host's own updated entry is merged onto whatever's freshest on disk right now.
    _reload_merge_save(ctx.session_id, lambda s: s.setdefault("recon_result", {}).setdefault("host_health", {}).__setitem__(host, entry))


def _track_tool_memory(ctx: RunContext, result: dict) -> None:
    """Best-effort cross-session memory of which SCAN tool actually got dispatched against a target
    with this session's current tech/WAF fingerprint (agent/tools/tool_memory_store.py) -- rides
    along the exact same real dispatch outcomes _track_host_health already tracks, one hook further.
    Scoped to tool_tier=2 "scan"-category tools only (self-maintaining coverage as new scan tools get
    registered, no hardcoded tool-name list) -- tier-1 native helpers and non-scan tools don't answer
    "which scanner is worth reaching for on a similar stack" at all.

    A successful ("ok") dispatch is recorded as outcome="empty" by default -- NOT "productive": a
    tool running cleanly says nothing about whether it actually found anything worth reporting
    (parsing that out per-tool would be fragile, tool-specific, and easy to get wrong). Real credit
    only ever comes from _credit_tool_memory_for_finding, once a finding backed by this tool's own
    tool_timeline is actually recorded -- the same two-phase deferred-credit shape playbook_store
    already uses for injected_count/led_to_finding_count.
    """
    if result.get("status") not in _HOST_HEALTH_TRACKED_STATUSES:
        return  # "skipped"/"tool_unavailable"/etc -- not a real attempt, nothing to remember
    tool_name = result.get("tool")
    if not tool_name:
        return
    spec = get_tool(tool_name)
    if spec is None or spec.tool_tier != 2 or "scan" not in categories_of(spec):
        return
    outcome = "empty" if result["status"] == "ok" else "failed"
    try:
        fingerprint_key = _playbook_fingerprint_key(*_current_target_fingerprint(ctx.session))
        tool_memory_store.record_tool_run(fingerprint_key, tool_name, outcome, ctx.session_id, error=_log_error(result) if outcome == "failed" else None)
    except Exception:
        # Best-effort bookkeeping, same discipline as _track_host_health just above -- a transient
        # disk read/write failure here must never take down an otherwise-healthy scan over a
        # telemetry side-channel. Guarded internally (rather than at each of this function's several
        # call sites) since every call site shares the identical disk-I/O risk.
        logger.debug("core: session=%s _track_tool_memory failed, skipping this update", ctx.session_id, exc_info=True)


_ASSET_GRAPH_CREDENTIAL_TOOLS = frozenset({"default_creds_check", "web_self_register", "background_job_check"})
# Tools whose background job produces a genuinely structured {username, password} pair with zero
# LLM interpretation -- same set _update_asset_graph's own background_job_check branch already
# restricted itself to, pulled out here so _auto_record_cracked_credentials_finding below can share
# the exact same "is this even a credential-cracking job" gate without duplicating it.
_CREDENTIAL_CRACKING_JOB_TOOLS = frozenset({"hydra", "web_login_bruteforce"})


def _credentials_from_finished_background_job(session: dict, job_id: str | None, result: dict) -> tuple[dict | None, list[dict]]:
    """Pulls (job, credential_pairs) out of a background_job_check result for a hydra/
    web_login_bruteforce job -- the one place that knows how to read that job's own structured
    {username/login, password, host?} shape, shared by _update_asset_graph's cross-host-reuse
    tracking and _auto_record_cracked_credentials_finding's deterministic finding below so both read
    the exact same data the exact same way. (job, []) for a real job of the wrong tool with no
    credentials; (None, []) when job_id doesn't resolve to any tracked job at all.
    """
    job = session.get("background_jobs", {}).get(job_id) if job_id else None
    if job is None or job.get("tool") not in _CREDENTIAL_CRACKING_JOB_TOOLS:
        return None, []
    job_target = job.get("target")
    creds: list[dict] = []
    for pair in (result.get("result") or {}).get("credentials") or []:
        username = pair.get("username") or pair.get("login")
        password = pair.get("password")
        host = pair.get("host") or job_target
        if username is not None and password is not None and host:
            creds.append({
                "username": username, "password": password,
                "found_on_host": extract_hostname(host) or host,
                "source_tool": job["tool"], "login_url": None,
            })
    return job, creds


async def _auto_record_cracked_credentials_finding(ctx: RunContext, job_id: str | None, result: dict) -> None:
    """Deterministic Critical finding for a background brute-force job (hydra/web_login_bruteforce)
    that came back with real, tool-verified credentials -- same "a structured positive result
    doesn't need an LLM's permission to become a finding" reasoning as cve_lookup's own auto-record
    path further down this file, just for a background job's eventual result instead of a
    synchronous lookup's. Guarded by background_jobs[job_id]["_credential_finding_recorded"] so a
    job checked more than once (a live poll during Exploit, then again via
    _harvest_completed_background_jobs's own end-of-run safety sweep) is never double-recorded.

    Real, confirmed incident this exists because of: a live hydra RDP brute-force got cut off from
    the only phase polling it by the stall detector (a background_job_check poll of a still-
    "running" job tripped the identical-call-repeat guard), succeeded with 6 valid credentials a few
    minutes later once its own subprocess actually finished, and nothing downstream ever turned that
    into a finding -- the raw result sat in session["background_jobs"] indefinitely, never rendered
    anywhere in the UI, surfaced only by a manual log-review long after the scan itself "finished".
    Calling this from every place a background job's status is ever observed (the live tool-dispatch
    path below, AND the safety-net sweep after await_all_running_jobs) makes that class of loss
    structurally impossible: a credential a background job actually proves valid always becomes a
    real, visible finding, regardless of what happened to the phase that started the job.

    Severity/verification/exploited are NOT a flat "trust the tool" claim -- confirmed live, on the
    SAME real finding this whole mechanism exists because of: Hydra's own "success" for its rdp
    module specifically has a real, community-documented false-positive history (NLA/CredSSP
    negotiation ambiguity can read as a successful login when it genuinely was not one), unlike
    ssh/ftp/mysql/postgres/smb/http-form, which complete a real protocol-level accept/reject and are
    treated as reliable. Manually re-tried against the real target immediately after this session's
    own audit: all 6 "confirmed" RDP credential pairs failed a real mstsc logon, with account
    lockout, typos, and any actual password rotation all independently ruled out -- meaning Hydra's
    own rdp module reported false positives here, not that this pipeline mis-recorded a real one.
    `job["protocol"] == "rdp"` (hydra_start's own extra_metadata, agent/tools/native.py) is the one
    deterministic signal available to tell which module produced a hit -- gates a materially weaker
    claim for that one case, never claiming more confidence than the underlying tool actually earned.
    """
    if not job_id or result.get("status") != "ok":
        return
    job, new_creds = _credentials_from_finished_background_job(ctx.session, job_id, result)
    if job is None or not new_creds or job.get("_credential_finding_recorded"):
        return
    host = new_creds[0]["found_on_host"]
    target = job.get("target") or host
    cred_lines = "\n".join(f"- {c['username']}:{c['password']}" for c in new_creds)
    is_unreliable_rdp_module = job["tool"] == "hydra" and job.get("protocol") == "rdp"
    if is_unreliable_rdp_module:
        recorded = {
            "title": f"Possible credentials via hydra (rdp) on {host} ({len(new_creds)} candidate login{'s' if len(new_creds) != 1 else ''}) -- needs manual confirmation",
            "severity": "High",
            "description": (
                f"hydra's rdp module reported {len(new_creds)} candidate credential pair(s) against "
                f"{target}:\n{cred_lines}\n\nNOT treated as confirmed: Hydra's rdp module has a real, "
                "known false-positive history (NLA/CredSSP negotiation ambiguity can read as a "
                "successful login when it was not), unlike its other protocol modules. Manually "
                "confirm with a real RDP client (mstsc.exe /v:<host>, or xfreerdp) before treating "
                "this as proven access -- if the actual logon fails with correct credentials, no "
                "typos, and no account lockout, this candidate was a Hydra false positive, not a "
                "real vulnerability."
            ),
            "technology": target,
            "reproduction_steps": f"Manually connect with a real RDP client to {target} using any pair above and confirm a real interactive logon succeeds -- do not treat Hydra's own report alone as proof for this module.",
            "verification": "inferred",
            "exploited": False,
            "evidence_ref": f"hydra (rdp) background job {job_id}, UNCONFIRMED -- manual verification required: {cred_lines}",
            "exploitation_scenario": "remote_direct",
        }
    else:
        recorded = {
            "title": f"Valid credentials confirmed via {job['tool']} on {host} ({len(new_creds)} working login{'s' if len(new_creds) != 1 else ''})",
            "severity": "Critical",
            "description": (
                f"{job['tool']} ran a real brute-force/credential-stuffing pass against {target} and "
                f"authenticated successfully with {len(new_creds)} credential pair(s):\n{cred_lines}\n\n"
                "These are live, tool-verified logins -- the tool itself completed authentication with "
                "each one, this is not an unconfirmed wordlist hit."
            ),
            "technology": target,
            "reproduction_steps": f"Authenticate against {target} with any pair above (source: {job['tool']} background job {job_id}).",
            "verification": "verified",
            "exploited": True,
            "evidence_ref": f"{job['tool']} background job {job_id}: {cred_lines}",
            "exploitation_scenario": "remote_direct",
        }
    conflict = await _persist_new_finding(ctx, recorded)
    if conflict is None:
        job["_credential_finding_recorded"] = True
        _reload_merge_save(
            ctx.session_id,
            lambda s: s.setdefault("background_jobs", {}).setdefault(job_id, {}).__setitem__("_credential_finding_recorded", True),
        )
        logger.debug(
            "core: session=%s auto-recorded credential finding for background job=%s (%d pair(s))",
            ctx.session_id, job_id, len(new_creds),
        )


async def _harvest_completed_background_jobs(ctx: RunContext) -> None:
    """Safety-net sweep, called right after every await_all_running_jobs -- reaping a job directly
    (background_jobs.py's own await_all_running_jobs/_reap) never goes through this file's
    tool-dispatch path, so nothing would otherwise ever call _auto_record_cracked_credentials_finding
    for a job that only ever finishes AFTER the phase that started it has already moved on (stopped
    polling, hit its own wall-clock backstop, or the model simply concluded that pass first). Cheap
    no-op for every job _auto_record_cracked_credentials_finding has already recorded or that isn't
    a finished credential-cracking job at all.
    """
    for job_id, job in list(ctx.session.get("background_jobs", {}).items()):
        if job.get("status") == "ok":
            await _auto_record_cracked_credentials_finding(ctx, job_id, {"status": "ok", "result": job.get("result")})


def _update_asset_graph(ctx: RunContext, spec: ToolSpec, arguments: dict, result: dict) -> None:
    """Deterministic (no LLM involved) credential-reuse tracking — real attack chains (a credential
    leaked/cracked on host A never re-tried on host B) need STATE, not a single end-of-scan LLM pass
    hoping to remember every credential it ever saw (_run_chain, which only ever looks at findings
    against each other/recon facts, has no notion of "have I tried this exact pair everywhere yet").
    Whenever default_creds_check/web_self_register (synchronously) or a background_job_check on a
    finished hydra_start/web_login_bruteforce_start job produces a real, structured credential
    pair, this checks it against every OTHER host this session has discovered
    (session["recon_result"]["targets"]) and is actually exploit-eligible (is_target_allowed) — any
    host not yet suggested for THIS credential gets a real, deterministic record_hypothesis-
    equivalent entry via _persist_new_hypothesis, no LLM call needed. This only ever produces a
    LEAD, same as any other hypothesis — resolve_hypothesis still requires a real tool call to
    confirm it, nothing here claims a chain is proven.

    Deliberately scoped to these three tools only: they're the only ones that hand back a genuinely
    structured {username, password} pair with zero LLM interpretation. record_finding's own
    extracted_artifact field (an exploit's leftover credential/token) is free text with no host
    field at all — parsing it heuristically would fight this project's own anti-fabrication/
    evidence-quoting discipline, so it's a documented v1 gap, not silently handled.

    Also mutates `result` in place (result["credential_identity_names"]) whenever a credential this
    call processes has a registered identity_name — the model otherwise has no way to learn the
    identity_name this function/register_discovered_credential just assigned (it happens AFTER the
    tool's own native_function already returned its result), which would leave a freshly discovered
    or self-registered credential structurally unusable via authenticated_request/idor_probe's own
    identity= lookup for the rest of the run.
    """
    if spec.name not in _ASSET_GRAPH_CREDENTIAL_TOOLS or result.get("status") != "ok":
        return

    new_creds: list[dict] = []
    if spec.name in ("default_creds_check", "web_self_register"):
        host = arguments.get("target")
        if host:
            for pair in result.get("successful_credentials") or []:
                username, password = pair.get("username"), pair.get("password")
                if username is not None and password is not None:
                    new_creds.append({
                        "username": username, "password": password,
                        "found_on_host": extract_hostname(host) or host,
                        "source_tool": spec.name,
                        # web_self_register hands back its OWN login_url/cookie (None when it
                        # never separately logged in -- see that tool's own docstring for why a
                        # missing login_url there is expected, not a bug); default_creds_check has
                        # neither concept, its login_url is simply the endpoint it already tested.
                        "login_url": result.get("login_url") if spec.name == "web_self_register" else host,
                        "cookie": result.get("cookie") if spec.name == "web_self_register" else None,
                    })
    else:  # background_job_check
        _job, new_creds = _credentials_from_finished_background_job(ctx.session, arguments.get("job_id"), result)
        if _job is None:
            return

    if not new_creds:
        return

    graph = ctx.session.setdefault("asset_graph", {}).setdefault("credentials", [])
    other_hosts = sorted({t["host"] for t in ctx.session.get("recon_result", {}).get("targets", []) if t.get("host")})

    _IDENTITY_NAME_PREFIXES = {"default_creds_check": "discovered", "web_self_register": "self_registered"}

    changed = False
    for cred in new_creds:
        existing = next(
            (c for c in graph if c["username"] == cred["username"] and c["password"] == cred["password"] and c["found_on_host"] == cred["found_on_host"]),
            None,
        )
        if existing is None:
            identity_name = None
            if cred["source_tool"] in _IDENTITY_NAME_PREFIXES:
                identity_name = f"{_IDENTITY_NAME_PREFIXES[cred['source_tool']]}_{len(graph) + 1}"
                register_discovered_credential(
                    ctx.session_id, identity_name, cred["username"], cred["password"], cred.get("login_url"),
                    cookie=cred.get("cookie"),
                )
            existing = {
                "id": uuid.uuid4().hex[:12],
                "username": cred["username"], "password": cred["password"],
                "found_on_host": cred["found_on_host"], "source_tool": cred["source_tool"],
                "identity_name": identity_name,
                "discovered_at": datetime.now(timezone.utc).isoformat(),
                "suggested_hosts": [],
            }
            graph.append(existing)
            changed = True
            logger.debug("core: session=%s asset_graph: new credential recorded, source=%s found_on=%s identity=%s", ctx.session_id, existing["source_tool"], existing["found_on_host"], identity_name)

        if existing["identity_name"]:
            result.setdefault("credential_identity_names", {})[f"{cred['username']}:{cred['password']}"] = existing["identity_name"]

        for other_host in other_hosts:
            if other_host == existing["found_on_host"] or other_host in existing["suggested_hosts"] or not is_target_allowed(other_host):
                continue
            existing["suggested_hosts"].append(other_host)
            changed = True
            if existing["identity_name"]:
                text = (
                    f"Credential discovered via {existing['source_tool']} on {existing['found_on_host']} "
                    f"(registered as identity={existing['identity_name']}) has not been tried against "
                    f"{other_host}, also discovered this session — try authenticated_request/idor_probe "
                    f"with identity={existing['identity_name']} against it."
                )
            else:
                text = (
                    f"Credential {existing['username']}:{existing['password']} discovered via "
                    f"{existing['source_tool']} on {existing['found_on_host']} has not been tried "
                    f"against {other_host}, also discovered this session — worth attempting there too."
                )
            _persist_new_hypothesis(
                ctx, {"text": text, "evidence": f"found on {existing['found_on_host']} via {existing['source_tool']}"},
                "asset_graph", source="agent",
            )
            logger.debug("core: session=%s asset_graph: suggested credential id=%s against host=%r", ctx.session_id, existing["id"], other_host)

    if changed:
        # Reload-merge-save (not a blind save_session(ctx.session_id, ctx.session)) -- same fix
        # class as _track_host_health just above: this fires as a side effect of a single tool
        # call (default_creds_check/background_job_check), reachable mid-chat-turn where
        # ctx.session can be a long-lived stale snapshot while a concurrently-running phase/reverify
        # pass keeps saving fresher state. `graph` already reflects this run's own complete,
        # deduplicated credential list (built in-place on ctx.session above, so a LATER call within
        # this same run still sees earlier entries) -- merged onto disk as one field, not the whole
        # session. The hypothesis side (_persist_new_hypothesis above) already merge-saves itself.
        _reload_merge_save(ctx.session_id, lambda s: s.setdefault("asset_graph", {}).__setitem__("credentials", graph))


def _record_agent_relationship(ctx: RunContext, spec: ToolSpec, result: dict) -> None:
    """Persists record_host_relationship's own real tool call into session["agent_relationships"]
    -- main.py's _build_attack_surface_graph reads this list to draw a high-fidelity attack_path
    edge on the Map tab, the same edge kind chain_attempts-derived pivots already use but with a
    real mechanism label and evidence attached directly by the model, at the moment it proved the
    pivot, not reconstructed after an entire Chain pass concludes. Deliberately not deduplicated
    against an existing entry (unlike _update_asset_graph's own credential list) -- a real pivot
    proven twice, via two different mechanisms, is two genuinely different facts worth keeping,
    not a repeat to collapse.
    """
    if spec.name != "record_host_relationship" or result.get("status") != "ok":
        return
    entry = {
        "id": uuid.uuid4().hex[:12],
        "source_host": result["source_host"],
        "target_host": result["target_host"],
        "mechanism": result["mechanism"],
        "evidence": result["evidence"],
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    ctx.session.setdefault("agent_relationships", []).append(entry)
    _reload_merge_save(ctx.session_id, lambda s: s.setdefault("agent_relationships", []).append(entry))
    logger.debug(
        "core: session=%s agent_relationship: %s -> %s via %s",
        ctx.session_id, entry["source_host"], entry["target_host"], entry["mechanism"],
    )


def _record_tls_cert_info(ctx: RunContext, spec: ToolSpec, arguments: dict, result: dict) -> None:
    """Deterministic bookkeeping for ssl_cert_info's own real TLS handshake -- captures the fetched
    certificate's subject_alt_names into session["recon_result"]["tls_sans"][host] the moment a
    real cert is read, same "capture it here, don't rely on the model separately transcribing it
    into a structured field" reasoning os_guesses (nmap -O) and dns_map already use above for their
    own tools. main.py's _build_attack_surface_graph folds this into its shared_surface signal set
    -- two hosts presenting overlapping SAN entries (a shared wildcard cert, a multi-domain cert)
    are exactly the kind of "these two share real infrastructure" fact that signal already exists
    for, and a shared certificate is a stronger signal than a shared WhatWeb token.
    """
    if spec.name != "ssl_cert_info" or result.get("status") != "ok":
        return
    host = arguments.get("target")
    sans = result.get("subject_alt_names")
    if not host or not sans:
        return
    tls_sans = ctx.session.setdefault("recon_result", {}).setdefault("tls_sans", {})
    merged = sorted(set(tls_sans.get(host, [])) | set(sans))
    if merged == tls_sans.get(host):
        return
    tls_sans[host] = merged
    _reload_merge_save(ctx.session_id, lambda s: s.setdefault("recon_result", {}).setdefault("tls_sans", {}).__setitem__(host, merged))
    logger.debug("core: session=%s recon: tls_sans[%r] = %s", ctx.session_id, host, merged)


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _all_known_ips(session: dict) -> set[str]:
    """Every IP this session's own recon state already knows about, from every source that can
    reveal one -- dns_map's own resolved-IP lists (dns_lookup/subdomain_enum) and any recon target
    whose own host field is itself a bare IP (record_target/nmap against a raw IP scope entry).
    Single source of truth for _update_ip_intel's own "what's actually new" diff below.
    """
    recon_result = session.get("recon_result", {})
    ips: set[str] = set()
    for resolved in recon_result.get("dns_map", {}).values():
        ips.update(resolved)
    for target in recon_result.get("targets", []):
        host = target.get("host")
        if host and _is_ip_address(host):
            ips.add(host)
    return ips


def _hostnames_for_ip(session: dict, ip: str) -> list[str]:
    """Reverse lookup against dns_map (hostname -> resolved IPs) -- classify_ip_role needs to know
    which hostname(s), if any, resolve to a given IP so it can check THEIR OWN
    recon_result["protections"] entries (a WhatWeb/nuclei-fingerprinted CDN/WAF product is a
    stronger signal than an ASN-name guess alone)."""
    return [host for host, ips in session.get("recon_result", {}).get("dns_map", {}).items() if ip in ips]


# geoip_lookup is a real third-party HTTP call (agent/tools/native.py, ip-api.com) with its own
# soft rate limit (45/min) -- a single subdomain_enum burst can reveal dozens of new IPs in one
# tool dispatch, so this caps how many get looked up per single call rather than risking a pile of
# 429s (or several seconds of added latency) on one turn. dns_map/targets only ever grow, never
# shrink, so a deferred IP is picked up on a LATER tool call through this exact same hook, never
# permanently skipped.
_IP_INTEL_MAX_LOOKUPS_PER_CALL = 15
_IP_INTEL_TRIGGER_TOOLS = frozenset({
    "dns_lookup", "subdomain_enum", "record_target", "nmap", "tcp_port_check",
    "ssl_cert_info", "shodan_internetdb_lookup",
})


def _update_ip_intel(ctx: RunContext, spec: ToolSpec) -> None:
    """Deterministic (no LLM) IP geolocation + role classification -- automatically enriches every
    NEW distinct IP this session's recon state reveals (agent/core.py's own _all_known_ips), the
    moment it appears, regardless of which specific tool surfaced it, into
    session["recon_result"]["ip_intel"][ip]. Real motivation (see geoip_lookup/classify_ip_role's
    own docstrings, agent/tools/native.py): a domain's resolved IP is routinely mistaken for "the
    target's own server" when it's actually a CDN/WAF edge node, shared/cloud hosting, or something
    else unrelated to the real origin -- this makes that distinction visible on the Recon tab's
    Geopolitical Map automatically, instead of depending on a human's own whois/browser habit to
    catch it (or not) during Recon AND Analyze alike, since this fires from the same universal
    per-tool-call dispatch site _track_host_health/_update_asset_graph already use, not from a
    single phase's own local closure.
    """
    if spec.name not in _IP_INTEL_TRIGGER_TOOLS:
        return
    ip_intel = ctx.session.setdefault("recon_result", {}).setdefault("ip_intel", {})
    new_ips = sorted(_all_known_ips(ctx.session) - set(ip_intel))[:_IP_INTEL_MAX_LOOKUPS_PER_CALL]
    if not new_ips:
        return

    protections = ctx.session.get("recon_result", {}).get("protections", {})
    changed = False
    for ip in new_ips:
        geo = geoip_lookup({"ip": ip})
        if geo.get("status") != "ok":
            continue
        hostnames = _hostnames_for_ip(ctx.session, ip)
        detected_products = sorted({p for h in hostnames for p in protections.get(h, [])})
        role_info = classify_ip_role(geo, detected_products)
        ip_intel[ip] = {**geo, **role_info, "hostnames": hostnames}
        changed = True
        logger.debug(
            "core: session=%s ip_intel[%s] country=%s role=%s (%s)",
            ctx.session_id, ip, geo.get("country_code"), role_info["role"], role_info["confidence"],
        )
    if changed:
        _reload_merge_save(ctx.session_id, lambda s: s.setdefault("recon_result", {}).setdefault("ip_intel", {}).update(ip_intel))


def _record_missing_capability(ctx: RunContext, spec: ToolSpec, result: dict) -> None:
    """Durable record of "the agent needed X (an interpreter/compiler), it wasn't on this machine"
    -- generic over whatever X turns out to be (python2 today, a C/C++ compiler or anything else
    later), not a python2-specific mechanism. A tool opts into this simply by putting a
    "capability" key (the installable thing's id, e.g. "python2") on a tool_unavailable result --
    exploit_db_run does this for a missing interpreter; arjun/oob_generate's own unrelated
    tool_unavailable cases don't set it and are untouched here. Surfaced in the Summary tab
    (session_fragment.html) so the operator can install it via Settings and retry, instead of the
    gap only ever being visible as one hard-to-search line buried in the tool-call log.

    Linked to whichever finding/hypothesis was actively being worked when this happened
    (ctx.current_finding_title / ctx.current_hypothesis_id, same threading _log_agent_debug already
    relies on) so the Summary card can point at the exact existing Deep-dive/"Investigate now"
    button for it -- no new retrigger mechanism needed, those two already do "reprocess this one
    item from scratch".
    """
    capability = result.get("capability")
    if result.get("status") != "tool_unavailable" or not capability:
        return

    entry = {
        "id": uuid.uuid4().hex[:12],
        "capability": capability,
        "needed_for": result.get("error") or f"{spec.name} needed {capability!r}",
        "tool_name": spec.name,
        "finding_title": ctx.current_finding_title,
        "hypothesis_id": ctx.current_hypothesis_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    ctx.session.setdefault("missing_capabilities", []).append(entry)
    # Reload-merge-save (not a blind save_session(ctx.session_id, ctx.session)) -- same fix class as
    # _track_host_health above: this fires as a side effect of a single tool call, reachable
    # mid-chat-turn where ctx.session can be a long-lived stale snapshot. Only this one new entry is
    # merged onto whatever's freshest on disk right now.
    _reload_merge_save(ctx.session_id, lambda s: s.setdefault("missing_capabilities", []).append(entry))
    logger.debug(
        "core: session=%s missing_capability recorded: capability=%s tool=%s finding=%r hypothesis=%r",
        ctx.session_id, capability, spec.name, entry["finding_title"], entry["hypothesis_id"],
    )


def _model_visible_arguments(arguments: dict) -> dict:
    """Strips server-injected internal fields (this codebase's own "_"-prefixed convention --
    _session/_session_id/_user_agent/_extra_headers/_timeout_seconds/_triggered_by, see
    _run_tool_with_retry's own injected{} block) before an arguments dict is shown to the model or
    the operator -- never their business, and for the tools that get the full live _session
    injected (delegate_to_subagent, check_subagent_task, browser_*, hydra_start, ...) leaving it in
    would dump the ENTIRE session (every finding, every log line, every chat thread) into a single
    tool result/prompt. Real, confirmed incident this fixes (live session
    Safety-Bug-Bounty-usr_158b31): result["used_arguments"] carried this straight through into the
    tool_call segment shown to the operator (a garbled, character-limit-truncated wall of the
    entire session) AND into the next turn's own tool-result message fed back to the model, which
    then had to guess at what had actually happened from a cut-off JSON fragment instead of the
    small, clean error it should have received. Callers reading target/domain/host back out of
    used_arguments (asset_graph tracking etc.) are unaffected -- those are never underscore-
    prefixed keys.
    """
    return {k: v for k, v in arguments.items() if not k.startswith("_")}


async def _run_tool_with_retry(ctx: RunContext, spec: ToolSpec, arguments: dict) -> dict:
    """1-Step Retry: runs a tool once; on a genuine failure, asks the model for exactly one
    corrected set of arguments and retries once more. A second failure is marked "failed" and
    left alone — no open-ended retry loop. Applies uniformly to every tool, exploit calls
    included; it fixes a broken invocation, it does not grant a second exploitation attempt
    (that's state["attempted"] in _run_exploit_for_finding, a separate rule).
    """
    out_of_scope_hit = _out_of_scope_target(ctx.session, arguments)
    if out_of_scope_hit is not None:
        _log_agent_debug(ctx, "tool=%s skipped, target=%r matches an out-of-scope entry", spec.name, out_of_scope_hit)
        return {"status": "skipped", "tool": spec.name, "reason": f"target {out_of_scope_hit!r} is explicitly out of scope for this project"}

    loopback_hit = _loopback_or_link_local_target(arguments)
    if loopback_hit is not None:
        _log_agent_debug(ctx, "tool=%s skipped, target=%r is a loopback/link-local address, never a real scan target", spec.name, loopback_hit)
        return {
            "status": "skipped",
            "tool": spec.name,
            "reason": (
                f"target {loopback_hit!r} is a loopback or link-local address — this can never be "
                "the real pentest target (it names this agent's own host/network interface, not the "
                "target's), so this call was not run. Use the real target hostname/IP instead."
            ),
        }

    dead_host_reason = _dead_host_blocked(ctx.session, arguments)
    if dead_host_reason is not None:
        _log_agent_debug(ctx, "tool=%s skipped, %s", spec.name, dead_host_reason)
        return {"status": "skipped", "tool": spec.name, "reason": dead_host_reason}

    if _tech_gate_blocked(ctx.session, spec.name, arguments):
        required = "/".join(_TECH_GATED_TOOLS[spec.name])
        _log_agent_debug(
            ctx, "tool=%s skipped, target=%r has no confirmed %s detection yet",
            spec.name, arguments.get("target"), required,
        )
        return {
            "status": "skipped",
            "tool": spec.name,
            "reason": (
                f"{spec.name} was not run: this target has no confirmed {required} detection yet. "
                f"Call whatweb against it first — {spec.name} only unlocks once whatweb (or another "
                f"real signal) actually shows a {required} technology token for this host."
            ),
        }

    # Server-side-injected fields — never exposed in any tool's JSON schema, so the model can
    # neither see nor override them, and applied again below to the corrected retry call so a
    # 1-Step Retry can't silently drop them a second time.
    injected = {}
    if spec.name in ("authenticated_request", "authenticated_crawl", "idor_probe", "cors_credentialed_check"):
        # These are the tools whose credential lookup (native.py's _load_credentials) is keyed by
        # session_id. Letting the model supply its own session_id would mean a wrong/malicious
        # value could read a different project's stored credentials.
        injected["_session_id"] = ctx.session_id
    if spec.name in ("wayback_urls", "common_crawl_urls"):
        # Persists these tools' own discovered-but-never-requested URLs into
        # session["recon_result"]["candidate_urls"] (native.py's _persist_candidate_urls) so the
        # Map tab's Site Map Tree (main.py's _build_site_map_tree) can show them as unconfirmed
        # leaves -- real, confirmed gap this fixes: before this, a wayback_urls/common_crawl_urls
        # result existed nowhere but a truncated JSON blob inside one session["logs"] entry
        # (agent/core.py's own _append_log), invisible to that tree, which read as "the map only
        # shows what actually got requested" rather than "what's known about this site". Only
        # _session_id, not the live ctx.session dict itself -- native.py's own persistence helper
        # uses sessions.store's reload_merge_save (same fix class as background_jobs.py's own
        # saves) instead of trusting a long-lived in-memory session snapshot that a concurrent
        # phase/subagent/chat turn may have already moved past.
        injected["_session_id"] = ctx.session_id
    if spec.name in (
        "memscan_attach", "memscan_scan", "memscan_list", "memscan_write", "memscan_detach",
    ):
        # agent/tools/memscan_manager.py's own module-level session dict is keyed by session_id --
        # letting the model supply its own would let it read/write a different project's live
        # scanmem sessions (or none at all, since the dict simply wouldn't have an entry for a
        # made-up id). Only _session_id, not the live ctx.session dict itself -- unlike
        # background_jobs.py's tools, this manager never mutates session.json.
        injected["_session_id"] = ctx.session_id
    if spec.name in ("custom_exploit_run", "exploit_db_run", "custom_re_script", "tshark_capture"):
        # agent/tools/native.py's own _exploit_scripts_dir keys the script's persisted location
        # off this -- without it, every run would fall back to the global app dir instead of this
        # session's own project folder, defeating the point of persisting it per-engagement.
        # Real, confirmed incident this fixes: custom_re_script (agent/tools/__init__.py) reuses
        # custom_exploit_run's own native_function wholesale under a second tool name for RE mode,
        # but this tuple only ever matched the literal name "custom_exploit_run" -- every single
        # custom_re_script call, in every RE-mode session ever run, had params["_session_id"] come
        # through as None, so _exploit_scripts_dir always fell back to the global app dir. Confirmed
        # live (hcm-usr_15eee7, NinthCircle-crackmes-usr_04a301): 397 script/log file pairs (~60MB)
        # from real RE sessions accumulated in Documents/ASRA/scripts/ instead of each session's own
        # project folder, even though those same sessions' OTHER tools (radare2, gdb) correctly wrote
        # their own per-session artifacts right next to session.json the whole time. tshark_capture
        # (agent/tools/builders/tshark.py's own _captures_dir) needs the identical session_id-keyed
        # "this engagement's own project folder, not the global app dir" placement for its saved
        # .pcap files -- same reasoning, different artifact type.
        injected["_session_id"] = ctx.session_id
    if spec.name in ("send_raw_request", "list_captured_traffic", "diff_requests", "intruder_run", "sequencer_analyze"):
        # agent/tools/toolkit_store.py's captured-traffic file is keyed by session_id -- letting
        # the model supply its own would let it read/send-into/diff a different project's traffic.
        # sequencer_analyze's own stored mode reads that same file (collect_stored_samples) and its
        # live mode records into it exactly like send_raw_request does. decode_value needs no
        # session_id at all (pure text transform, agent/tools/toolkit_agent_tools.py), so it's
        # deliberately not in this list.
        injected["_session_id"] = ctx.session_id
    if spec.name in (
        "hydra_start", "web_login_bruteforce_start", "background_job_check", "afl_fuzz_start",
        "delegate_to_subagent", "check_subagent_task", "record_target_profile", "rank_attack_surface",
        "nuclei",
        *_BROWSER_TOOL_NAMES,
    ):
        # agent/tools/background_jobs.py / agent/tools/subagent_tasks.py both mutate the session
        # dict in place and call save_session themselves -- they need the SAME live ctx.session
        # object reference every other part of this run already shares, not a value the model
        # could ever supply (there is no sane "session" shape for a tool schema to expose). The
        # browser_* tools need the same session_id (agent/tools/browser_manager.py's per-session
        # BrowserContext registry is keyed by it) plus the live session dict itself (for its own
        # "out_of_scope" list, checked against the page's own URL after every action -- see
        # _dispatch_browser_tool/BrowserSessionManager._bundle's own docstrings). record_target_profile
        # (re_record_target_profile, this module) is the same "mutates session directly, calls
        # save_session itself" shape as background_jobs.py's own tools. rank_attack_surface
        # (agent/tools/surface_ranking.py) and nuclei (agent/tools/builders/nuclei.py) are the
        # read-only exceptions in this group -- neither mutates or saves, they just need the same
        # live recon_result/findings every other part of this run already has (nuclei specifically:
        # recon_result["technologies"][target], to auto-activate a heavy template pack like
        # wordfence-cve when recon already confirmed the relevant tech, without relying on the model
        # remembering to name it in -tags), which (same as above) no tool schema could sanely expose
        # as a model-supplied argument.
        injected["_session_id"] = ctx.session_id
        injected["_session"] = ctx.session
    if spec.name in ("query_playbook", "playbook_strategy", "record_technique"):
        # re_query_playbook/re_playbook_strategy/re_record_technique (this module) need the active
        # provider for embeddings (semantic search) and, for playbook_strategy, a real synthesis
        # call -- there is no sane "llm" shape for a tool schema to expose, and letting the model
        # somehow choose one would be meaningless anyway (it's always THIS run's own provider).
        # record_technique also needs session_id purely for source_session_ids attribution.
        injected["_llm"] = ctx.llm
        injected["_session_id"] = ctx.session_id
    custom_user_agent = (ctx.session.get("custom_user_agent") or "").strip()
    if custom_user_agent:
        # A bug-bounty program's own required User-Agent string (New Project form) has to land on
        # every real HTTP request this session makes, not just the ones the model remembers to add
        # it to. Tools that don't make HTTP requests (nmap, whois, cve_lookup, ...) simply ignore
        # the extra key, same as any other native_function does with an argument it doesn't use.
        injected["_user_agent"] = custom_user_agent
    custom_headers = _parse_custom_headers(ctx.session.get("custom_headers"))
    if custom_headers:
        # Same reasoning as _user_agent above, for the New Project form's "Custom HTTP Headers"
        # field (e.g. a HackerOne-required "X-HackerOne-Research: <handle>" attribution header) —
        # a real header on every real request, not just something the model is told about.
        injected["_extra_headers"] = custom_headers
    tool_api_key = get_tool_api_key(spec.name)
    if tool_api_key:
        # Settings -> Tool API Keys (agent/tools/tool_api_keys.py) -- an operator-wide credential
        # (e.g. WPScan's --api-token), not something the model can see or choose, same server-side-
        # injected convention as _user_agent/_extra_headers above. Only reaches this dict when the
        # operator has actually saved a key for THIS tool (get_tool_api_key returns None otherwise),
        # so a tool with no key configured, or no registered spec at all, is completely unaffected.
        injected["_api_key"] = tool_api_key
    arguments = {**arguments, **injected}

    # msf_module_search's real cost is the ~2-3s of spinning up a whole msfconsole process per
    # call, and Exploit routinely re-runs the exact same product-level query (e.g. "openssh")
    # once per finding when several auto-recorded CVEs share a technology — confirmed live: one
    # session ran the literal query "openssh" six times across a single exploit phase. Its result
    # is a local, static module-database lookup (same query -> same rows within a session, unlike
    # a live scan of the actual target), so it's safe to reuse exactly like exploit_db_lookup and
    # cve_lookup already do via this same cache.
    msf_search_query = arguments.get("query") if spec.name == "msf_module_search" else None
    if msf_search_query is not None:
        cached = cache_get("msf_module_search", str(msf_search_query))
        if cached is not None:
            _log_agent_debug(ctx, "tool=msf_module_search cache hit for query=%r", msf_search_query)
            return cached

    result = _apply_output_parser(spec, await _dispatch_tool_interruptible(ctx, spec, arguments))
    # Callers that key bookkeeping (dns_map, technologies, os_guesses) off the tool's target/domain
    # argument must use the arguments actually run, not the pre-retry ones passed in — a corrected
    # retry below can send a different domain/target than the one that failed.
    result["used_arguments"] = _model_visible_arguments(arguments)
    if msf_search_query is not None and result.get("status") == "ok":
        cache_set("msf_module_search", str(msf_search_query), result)
    if result.get("status") not in _RETRYABLE_STATUSES:
        try:
            _track_host_health(ctx, arguments, result)
        except Exception:
            # Best-effort bookkeeping (host-health tally for the Recon tab / dead-host
            # blacklisting), not core scan correctness -- a transient disk read failure here
            # (see load_session's own docstring for the confirmed incident) must never take down
            # an otherwise-healthy multi-hour run over a telemetry side-channel.
            logger.debug("core: session=%s _track_host_health failed, skipping this update", ctx.session_id, exc_info=True)
        _track_tool_memory(ctx, result)
        _update_asset_graph(ctx, spec, arguments, result)
        _record_agent_relationship(ctx, spec, result)
        _record_tls_cert_info(ctx, spec, arguments, result)
        try:
            _update_ip_intel(ctx, spec)
        except Exception:
            # Best-effort enrichment (Geopolitical Map country/role labels), not core scan
            # correctness -- a transient geoip_lookup network hiccup here must never take down an
            # otherwise-healthy run, same posture as _track_host_health's own try/except above.
            logger.debug("core: session=%s _update_ip_intel failed, skipping this update", ctx.session_id, exc_info=True)
        if spec.name == "background_job_check":
            await _auto_record_cracked_credentials_finding(ctx, arguments.get("job_id"), result)
        _record_missing_capability(ctx, spec, result)
        return result

    # Captured before the retry dispatch below can overwrite `result` -- a successful correction
    # produces a fresh result dict from a real dispatch (never_dispatched wouldn't apply to it, that
    # flag means the opposite: nothing was dispatched), so this is the only place that still knows
    # the ORIGINAL attempt was a schema violation, not just an ordinary error. Propagated onto
    # whatever this function ultimately returns below (see "schema_violation_corrected") so
    # _run_llm_tool_loop_impl's own never_dispatched_counts can still count it even when the retry
    # itself goes on to succeed cleanly.
    original_never_dispatched = bool(result.get("never_dispatched"))
    model_visible_arguments = _model_visible_arguments(arguments)
    # Real, confirmed incident this fixes (ttttt-usr_573a1e): the correction call below is a
    # plain-text JSON reply (tools=None, see its own comment just below for why), which means a
    # multi-line argument (custom_re_script/custom_exploit_run's "source" -- a whole Python script,
    # with its own quotes/backslashes/newlines) has to be hand-escaped into a JSON string literal by
    # the model. That reliably fails on weaker models: 5/5 correction attempts in this session
    # failed to parse, even after _repair_json_reply's own one extra chance, burning 2 wasted LLM
    # calls each time before the step was marked failed anyway. Skipping straight to failed here
    # doesn't change the outcome for this shape (it never succeeds), just removes the dead work --
    # the main tool loop's own next turn still gets a fresh chance via native tool-calling, which
    # handles the escaping correctly (that's how this class of tool actually recovers today).
    if any(isinstance(v, str) and "\n" in v for v in model_visible_arguments.values()):
        _log_agent_debug(
            ctx, "tool=%s failed (%s) with a multi-line argument -- skipping the plain-text "
            "corrected retry (it can't escape this reliably), marking failed", spec.name, result.get("status"),
        )
        failed_result = {**result, "status": "failed"}
        _track_host_health(ctx, arguments, failed_result)
        _track_tool_memory(ctx, failed_result)
        return failed_result
    _log_agent_debug(ctx, "tool=%s failed (%s), requesting one corrected retry", spec.name, result.get("status"))
    # Real, confirmed incident this fixes: this correction call used to carry zero schema
    # grounding — the model had nothing but the tool's NAME to go on, so a plausible-but-wrong
    # field-name guess (e.g. "url" instead of arjun's real "target") couldn't be caught, and the
    # identical wrong guess got resent on this one and only retry chance. Real parameter schema
    # here, not the full openai tool-calling `tools=` mechanism (which would switch the response
    # into native tool_calls and require an entirely different parsing path below) — this stays a
    # plain-text JSON reply, just an informed one.
    schema_properties = (spec.parameters_schema or {}).get("properties", {})
    schema_hint = json.dumps(sorted(schema_properties.keys()))
    # Real, confirmed incident this fixes: a generic/discovered tool (httpx, whatweb, ffuf, ...) has
    # no real parameters_schema of its own -- schema_hint above comes out empty, giving the model
    # nothing to correct a wrong CLI flag against (e.g. httpx's real flags vs. the model's guessed
    # -tls-verify/-include). The model DID see this tool's real --help text on the ORIGINAL call
    # (_tool_description already pulls it in for exactly this class of tool) -- just never again
    # here on the one correction retry that matters most. Same get_tool_help cache _tool_description
    # itself uses, so this costs nothing beyond the first real fetch per tool.
    help_hint_line = ""
    if not schema_properties:
        help_text = get_tool_help(spec.name, spec.executable, spec.full_description)
        if help_text:
            help_hint_line = f"\nThis tool's real --help output (use its actual flags, not a guess):\n{help_text[:2000]}"
    # `arguments` at this point is the POST-injection dict (line ~1804's `{**arguments,
    # **injected}`) -- _model_visible_arguments strips the server-injected internal fields
    # (_session above all -- see that function's own docstring for the real incident this
    # correction prompt specifically triggered) before they reach this prompt. Computed once,
    # above, so the multi-line-argument check can see it too.
    correction_messages = [
        {
            "role": "system",
            "content": 'You correct one failed security-tool invocation. Reply with ONLY this JSON: {"arguments": {<corrected arguments for the same tool>}}',
        },
        {
            "role": "user",
            "content": (
                f"Tool {spec.name!r} failed with these arguments: {json.dumps(model_visible_arguments)}\n"
                f"Error: {_log_error(result)}\n"
                f"This tool's real parameter names (use these exact names, nothing else): {schema_hint}"
                f"{help_hint_line}\n"
                "Provide corrected arguments for the same tool."
            ),
        },
    ]
    response = await _llm_complete(ctx, correction_messages, None)
    corrected = _parse_json_response(response.content)
    if corrected is None:
        # Real, confirmed incident this fixes (a real rescan session): the model's correction
        # reply was genuinely truncated mid-object (finish_reason="stop", not "length" -- a real,
        # complete-as-sent-but-cut-short answer, not a logging artifact), and this path used to give
        # up immediately even though _repair_json_reply exists for exactly this shape and is already
        # wired into 4 other terminal-decision call sites. One repair attempt here too, before
        # burning the tool's only correction chance on a parse failure the model could likely fix.
        corrected = await _repair_json_reply(ctx, correction_messages, response.content)
    if isinstance(corrected, dict) and isinstance(corrected.get("arguments"), dict):
        corrected_arguments = corrected["arguments"]
    elif isinstance(corrected, dict) and corrected and "arguments" not in corrected:
        # Real, confirmed incident: the model sometimes sends the corrected parameters directly,
        # without the {"arguments": {...}} envelope the system prompt above asks for — a fully
        # valid, well-formed correction was being discarded outright as "unparsable" just because
        # it wasn't wrapped. Tolerate it the same way this codebase already tolerates other
        # real-world variant shapes (nuclei's CSV-vs-array tags, update_plan's phases-as-a-JSON-
        # string) instead of throwing away a correction that would otherwise have worked.
        corrected_arguments = corrected
    else:
        _log_agent_debug(ctx, "tool=%s retry correction unparsable even after a repair attempt, giving up", spec.name)
        failed_result = {**result, "status": "failed"}
        _track_host_health(ctx, arguments, failed_result)
        _track_tool_memory(ctx, failed_result)
        return failed_result

    retry_arguments = {**corrected_arguments, **injected}
    retarget = _retry_target_changed(arguments, retry_arguments)
    if retarget is not None:
        _log_agent_debug(
            ctx, "tool=%s retry correction changed target host from %r to %r", spec.name, retarget[0], retarget[1],
        )
    retry_out_of_scope_hit = _out_of_scope_target(ctx.session, retry_arguments)
    if retry_out_of_scope_hit is not None:
        # The model's own "corrected" retry arguments can name a different target than the
        # original failed call — same guarantee as the first-call check above, not just applied
        # once and assumed to still hold.
        _log_agent_debug(ctx, "tool=%s retry skipped, target=%r matches an out-of-scope entry", spec.name, retry_out_of_scope_hit)
        return {"status": "skipped", "tool": spec.name, "reason": f"target {retry_out_of_scope_hit!r} is explicitly out of scope for this project", "retried": True}

    # Real, confirmed incident this fixes (midnight-usr_24ba7e): a bare "timeout" status
    # (runner.py's own subprocess.TimeoutExpired path, {"status": "timeout", ...} with no stdout/
    # stderr/exit_code at all -- unlike "error", there is nothing diagnostic here for a correction
    # call to react to) against a genuinely unresponsive host got a correction reply with arguments
    # BYTE-IDENTICAL to the ones that had just timed out (`{"target": "5.252.32.97"}` verbatim) --
    # there was nothing to correct, nmap's own schema exposes only `target` (see
    # retry_nmap_with_pn_if_host_seemed_down's own docstring), so the model had no lever to pull at
    # all. Re-dispatching the identical command against the same dead host burned a second full
    # TOOL_TIMEOUT_SECONDS (confirmed live: duration_ms=1237347, ~2x the real .env's
    # TOOL_TIMEOUT_SECONDS=600) for a guaranteed-identical second timeout. Skip the re-dispatch (not
    # the correction call itself -- a genuinely different corrected target/arguments is still worth
    # running) whenever the original failure was a timeout AND the "corrected" arguments came back
    # unchanged; any other retryable status (a real "error" with actual stderr to react to) or any
    # real argument change still goes through the normal retry dispatch below.
    if result.get("status") == "timeout" and retry_arguments == arguments:
        _log_agent_debug(
            ctx, "tool=%s retry arguments identical to the ones that just timed out — skipping a "
            "second, guaranteed-identical timeout wait instead of re-dispatching", spec.name,
        )
        failed_result = {
            **result,
            "status": "failed",
            "error": "1-Step Retry gave identical arguments after a bare timeout (nothing to correct) — not re-run to avoid a second, guaranteed-identical timeout wait",
            "retried": True,
        }
        _track_host_health(ctx, retry_arguments, failed_result)
        _track_tool_memory(ctx, failed_result)
        return failed_result

    retry_result = _apply_output_parser(spec, await _dispatch_tool_interruptible(ctx, spec, retry_arguments))
    if retry_result.get("status") in _RETRYABLE_STATUSES:
        original_retry_status = retry_result.get("status")
        _log_agent_debug(ctx, "tool=%s retry failed again, marking step failed", spec.name)
        if not retry_result.get("error"):
            # Real, confirmed incident this fixes: a retry that itself ends in a retryable-but-
            # textless status (a second timeout, most commonly) got silently overwritten to
            # status="failed" with error still None — a human reviewing the session log (this
            # exact kind of audit) had zero information the retry was actually a timeout, since
            # _log_error's own fallback chain (error/stderr/reason) had nothing left to read.
            retry_result["error"] = f"retry attempt itself ended with status={original_retry_status!r}"
        retry_result["status"] = "failed"
    else:
        _log_agent_debug(ctx, "tool=%s retry succeeded", spec.name)
    retry_result["retried"] = True
    if retarget is not None:
        retry_result["target_changed_by_retry"] = {"from": retarget[0], "to": retarget[1]}
    retry_result["used_arguments"] = _model_visible_arguments(retry_arguments)
    if original_never_dispatched:
        retry_result["schema_violation_corrected"] = True
    _track_host_health(ctx, retry_arguments, retry_result)
    _track_tool_memory(ctx, retry_result)
    _update_asset_graph(ctx, spec, retry_arguments, retry_result)
    _record_agent_relationship(ctx, spec, retry_result)
    _record_tls_cert_info(ctx, spec, retry_arguments, retry_result)
    if spec.name == "background_job_check":
        await _auto_record_cracked_credentials_finding(ctx, retry_arguments.get("job_id"), retry_result)
    _record_missing_capability(ctx, spec, retry_result)
    return retry_result


_REFUSAL_PATTERN = re.compile(
    r"\bI (?:cannot|can't|won't|will not) (?:assist|help)\b"
    r"|\bI'?m (?:not able|unable) to (?:help|assist|comply)\b"
    r"|\bagainst my guidelines\b"
    r"|\bI must decline\b"
    r"|\bcannot provide (?:assistance|help) (?:for|with)\b"
    r"|\bI don'?t feel comfortable\b",
    re.IGNORECASE,
)

_REFUSAL_REINFORCEMENT_MESSAGE = (
    "This is a pre-authorized, explicitly scoped security assessment against a target the operator "
    "owns or has legitimate permission to test — not an unauthorized attack. Continue the task using "
    "the tools you were given. If, after actually trying, there is genuinely nothing more to check, "
    "say so plainly and specifically — do not decline the task itself."
)


def _looks_like_a_refusal(text: str | None) -> bool:
    """Detects a safety-refusal-shaped final reply (e.g. "I cannot assist with hacking or
    unauthorized access to computer systems...") — a real, observed failure mode: a real session
    had a phase "complete" with zero tool calls made on that turn and get silently treated as a
    genuine "nothing to find" result, when what actually happened is the model declined the task
    outright partway through, despite RECON_PROMPT/ANALYZE_PROMPT/EXPLOIT_PROMPT all already
    framing this as pre-authorized. Deliberately narrow/phrase-based (not "any sentence containing
    the word 'cannot'") so a legitimate analysis conclusion like "cannot confirm this is
    exploitable without further access" never trips it — that's a real finding, not a refusal.
    """
    return bool(text and _REFUSAL_PATTERN.search(text))


# Real reply length in a genuinely corrupted turn observed live (see _looks_like_garbled_output's
# own docstring) was well under this -- a real "nothing to report" or analysis wrap-up reply is
# essentially always longer, so this stays narrow enough that truncating it would only ever risk
# missing a real corruption case, never flagging a legitimate long answer.
_GARBLED_OUTPUT_MAX_CHARS = 200
# A real reply from this project's own models is English (prompts) or Russian (chat) prose, so its
# alphabetic characters are Latin/Cyrillic -- anything else appearing in a SHORT reply (see the
# length gate above) is essentially never a legitimate word choice, just tokenizer-level corruption.
_ALLOWED_ALPHA_SCRIPT_PREFIXES = ("LATIN", "CYRILLIC")


def _looks_like_garbled_output(text: str | None) -> bool:
    """Detects a short, syntactically-valid-string reply that is linguistically incoherent --
    tokenizer-level corruption, not a real answer. Real, confirmed incident this fixes
    (a real HackerOne session, usr_b0f9b9, nemotron-3.5-lightning-free via opencode-zen): a phase-ending
    turn came back with tool_calls=0 and content=`"There\\t\\n\\n, -չêubyt (, bildete"` -- a valid
    Python str (so llm_client.py's own content_was_malformed structural check, which only catches a
    list-of-blocks shape, never fires) with no refusal phrasing either (so _looks_like_a_refusal
    never fires), and got silently treated as this phase's real "nothing found" final answer,
    indistinguishable downstream from a genuine clean result. Deliberately narrow (short replies
    only, and only flags an UNEXPECTED alphabetic script appearing at all) so a legitimate long
    analysis conclusion in English or Russian never trips it -- same "narrow enough that a real
    answer can never look like this" philosophy _looks_like_a_refusal's own docstring establishes.
    """
    if not text:
        return False
    stripped = text.strip()
    if not stripped or len(stripped) > _GARBLED_OUTPUT_MAX_CHARS:
        return False
    for ch in stripped:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue  # unnamed/control codepoint alone isn't enough signal to flag on its own
        if not name.startswith(_ALLOWED_ALPHA_SCRIPT_PREFIXES):
            return True
    return False


# A stated intent to keep going, with no tool call behind it -- the model narrates what it's about
# to do next instead of actually doing it. Real, confirmed incident this fixes
# (a real HackerOne session, usr_b0f9b9): after recording one of two live recon targets, the model
# replied tool_calls=0, content="Let me continue recording the other confirmed targets." -- and
# the phase ended right there, treating that as the real final answer; the second, already-
# nmap-confirmed target never got recorded. Anchored at the END of the reply (a real analysis
# turn can legitimately mention "continue" mid-explanation without this being its actual
# conclusion) and requires a concrete next action verb, not just "continue" alone, to stay narrow
# the same way _looks_like_a_refusal/_looks_like_garbled_output do.
_DECLARED_CONTINUATION_PATTERN = re.compile(
    r"\b(?:let me|now let me|i'?ll|next,? i'?ll)\b[^.!?]*\b(?:continue|record|scan|check|test|verify|investigate)\b[^.!?]*[.!?]?\s*$",
    re.IGNORECASE,
)


def _looks_like_a_declared_continuation(text: str | None) -> bool:
    """Detects a reply that ENDS by stating intent to keep working ("Let me continue recording the
    other targets") instead of a real tool call or a genuine wrap-up -- see
    _DECLARED_CONTINUATION_PATTERN's own comment for the live incident this catches."""
    return bool(text and _DECLARED_CONTINUATION_PATTERN.search(text.strip()))


def _record_llm_usage_event(session: dict, provider_id: str, model: str, latency_seconds: float, usage: dict | None) -> None:
    """Accumulates one real, successful LLM completion into session["llm_usage"] -- the actual
    (provider_id, model) dispatched to, not just the operator's configured llm_provider intent (see
    that field's own docstring in sessions/store.py's create_session for why they can differ: a
    Reserve-providers fallback switch mid-run). Called from _llm_complete's two success points
    (the primary call and the fallback-chain retry loop) -- the same choke point
    _log_phase_efficiency_summary's own docstring already establishes every phase's calls pass
    through, just one level lower (per LLM call, not per phase).

    Deliberately a plain in-memory mutation of the CALLER's own session dict, no reload-merge-save
    disk round trip of its own (unlike _log_phase_efficiency_summary below, which does pay for one)
    -- this fires on every single _llm_complete call, an order of magnitude more often than a
    phase-boundary summary does, and every other in-loop session mutation in this hot path (findings,
    logs, plan updates) already accepts the same "rides along in whatever this ctx's own next natural
    save_session call flushes" contract rather than a dedicated write per event. A live session saves
    after essentially every tool call already (see _run_llm_tool_loop_impl), so this is never more
    than one real tool call stale on disk.
    """
    entries = session.setdefault("llm_usage", [])
    entry = next((e for e in entries if e["provider_id"] == provider_id and e["model"] == model), None)
    if entry is None:
        entry = {
            "provider_id": provider_id, "model": model, "calls": 0,
            "total_latency_seconds": 0.0, "prompt_tokens": 0, "completion_tokens": 0,
            "calls_with_usage": 0,
        }
        entries.append(entry)
    entry["calls"] += 1
    entry["total_latency_seconds"] += latency_seconds
    if usage is not None:
        entry["calls_with_usage"] += 1
        entry["prompt_tokens"] += usage.get("prompt_tokens", 0)
        entry["completion_tokens"] += usage.get("completion_tokens", 0)


# check_subagent_task/check_background_job don't share the tier-2 tool convention of returning
# {"status": "ok"} on success -- they pass through their OWN task/job lifecycle status instead
# ("running" while still in flight, "done"/"ok" once finished, "error"/"timeout"/"killed"/
# "orphaned"/"stopped" only for genuine terminal failures). Without this allowlist, every single
# legitimate poll -- including one that lands on a task the operator's own docs tell the model to
# delegate to and NOT poll in a tight loop -- got counted as a phase failure by the generic
# `status != "ok"` check below. Confirmed live (a real HackerOne session): an analyze phase
# logged "6 ended not-ok" when only 3 were real errors; the other 4 were check_subagent_task calls
# that correctly found the delegated task still "running". non_ok/failure_rate carries double the
# weight of retried/duplicate in compute_efficiency_score, so this silently tanked the visible
# efficiency score of every session that used subagent delegation as intended.
_NON_FAILURE_POLL_STATUSES: dict[str, frozenset[str]] = {
    "check_subagent_task": frozenset({"running", "done"}),
    # Real tool name is "background_job_check" (agent/tools/__init__.py's own registration) -- this
    # key used to read "check_background_job", which never matches any real call.name, so every
    # single "running" poll of a real background job (hydra/web_login_bruteforce/afl_fuzz) was
    # silently falling through to the generic `status != "ok"` check below and counting as a phase
    # failure the whole time this allowlist existed, exactly the bug this whole comment block
    # describes fixing for check_subagent_task -- just never actually applied to its sibling.
    "background_job_check": frozenset({"running"}),
}


def _log_phase_efficiency_summary(ctx: RunContext, phase: str, trace: list[dict], is_subagent: bool = False) -> None:
    """One summary line per phase run — total tool calls, how many needed a 1-Step Retry, how many
    ended anything other than "ok", and how many were an EXACT repeat of an earlier call in this
    same phase run. Real, confirmed pattern this makes visible at a glance instead of requiring a
    manual grep-and-count across a whole session during a log-review audit: a session guessed at
    6+ nonexistent nuclei tag combinations across separate 1-Step Retry round-trips, and separately
    repeated identical dns_lookup calls for domains that had already just failed — scattered widely
    enough across the phase that stall detection's own back-to-back-only threshold never caught
    either one. Debug-logged unconditionally; ALSO persisted (accumulated, never overwritten) into
    session["phase_efficiency"] for compute_efficiency_score below — this is the one real choke
    point every _run_llm_tool_loop call already passes through in its own finally block, so it's
    where the score's raw counts get collected rather than re-deriving them from raw logs later.

    Bucketed by is_subagent (never mixed with the main agent's own phase="subagent" tag some log
    entries carry) rather than literal phase name — Exploit calls this once PER FINDING (a fresh
    _run_llm_tool_loop each time, phase="exploit" every time), so accumulation into session[...]
    ["exploit"] across multiple calls is deliberate, not a bug: exploit's real efficiency is the sum
    across every finding it evaluated this session, not just the last one.
    """
    if not trace:
        return
    seen_signatures: set[str] = set()
    duplicate_count = 0
    retried_count = 0
    non_ok_count = 0
    for call in trace:
        signature = f"{call['tool']}:{json.dumps(call['arguments'], sort_keys=True, default=str)}"
        if signature in seen_signatures:
            duplicate_count += 1
        seen_signatures.add(signature)
        result = call.get("result") or {}
        if result.get("retried"):
            retried_count += 1
        status = result.get("status")
        if status != "ok" and status not in _NON_FAILURE_POLL_STATUSES.get(call["tool"], ()):
            non_ok_count += 1
    logger.debug(
        "core: session=%s %s phase summary: %d tool call(s), %d retried, %d ended not-ok "
        "(error/timeout/skipped), %d exact repeat(s) of an earlier call this phase",
        ctx.session_id, phase, len(trace), retried_count, non_ok_count, duplicate_count,
    )
    bucket_key = "subagent" if is_subagent else phase
    stats = ctx.session.setdefault("phase_efficiency", {}).setdefault(
        bucket_key, {"tool_calls": 0, "retried": 0, "non_ok": 0, "duplicates": 0},
    )
    stats["tool_calls"] += len(trace)
    stats["retried"] += retried_count
    stats["non_ok"] += non_ok_count
    stats["duplicates"] += duplicate_count
    # Reload-merge-save, never a blind save_session(ctx.session_id, ctx.session) of this whole
    # (possibly stale) in-memory dict -- ctx.session here can be a delegated Subagent's own
    # RunContext, loaded once back when delegate_to_subagent started it. A long-running subagent
    # task reaching this exact point AFTER the main loop already persisted newer writes elsewhere
    # (e.g. a chat-recorded finding) would otherwise silently overwrite session.json with its own
    # stale snapshot, wiping those writes. Real incident this fixes: two record_finding calls landed
    # on disk (findings=1, then findings=2), then a subagent task running since before them finished
    # afterward and reached here with a pre-delegation session snapshot -- the OLD blind save wrote
    # that snapshot's findings=0 straight over both. Only this call's own phase_efficiency delta is
    # applied to a FRESH reload instead, so it can never clobber a field it didn't itself compute.
    try:
        fresh_session = load_session(ctx.session_id)
    except Exception:
        # This whole block only persists a debug-visible efficiency stat -- already logged above
        # unconditionally -- not anything the agent's own reasoning depends on; a transient disk
        # read failure here (see load_session's own docstring for the confirmed incident) must
        # never take down the phase that just finished successfully.
        logger.debug("core: session=%s phase_efficiency persist skipped for phase=%s", ctx.session_id, phase, exc_info=True)
        return
    if fresh_session is None:
        return
    fresh_stats = fresh_session.setdefault("phase_efficiency", {}).setdefault(
        bucket_key, {"tool_calls": 0, "retried": 0, "non_ok": 0, "duplicates": 0},
    )
    fresh_stats["tool_calls"] += len(trace)
    fresh_stats["retried"] += retried_count
    fresh_stats["non_ok"] += non_ok_count
    fresh_stats["duplicates"] += duplicate_count
    save_session(ctx.session_id, fresh_session)


async def _run_llm_tool_loop(
    ctx: RunContext,
    system_prompt: str,
    task_content: str,
    tool_specs: list[ToolSpec],
    phase: str,
    execute_tool: Callable[[ToolSpec, dict], Awaitable[dict]] | None = None,
    expect_json_final: bool = True,
    terminal_tool: str | None = None,
    is_subagent: bool = False,
    plan_phase: str | None = None,
    external_trace: list[dict] | None = None,
    wallclock_limit_seconds: int | None = None,
    progress_stall_threshold: int | None = None,
    max_tool_calls: int | None = None,
) -> tuple[dict | None, list[dict]]:
    """Drives one LLM<->tools conversation for a sub-phase until the model stops calling tools.
    Returns (parsed_json_or_None, raw_tool_call_trace). Thin wrapper around
    _run_llm_tool_loop_impl purely so the phase-efficiency summary log line fires exactly once
    per phase run regardless of which of that function's several return points was actually taken
    (a try/finally around one call site here, rather than duplicating the log call at every
    return or re-indenting that whole function's body into one).

    is_subagent=True for a delegated Subagent's own conversation (agent/core.py's
    _start_subagent_task) -- it must never drain _drain_subagent_results itself (that queue
    belongs to the MAIN agent's own loop; a subagent draining it could steal a result meant for
    the main agent or a sibling subagent), and its per-step log entries stay out of the main
    "phase" bucket the operator-facing session log groups by. It also skips the wait-for-subagents
    step below entirely -- a subagent concluding its OWN task must never block on some other,
    unrelated delegation this session happens to have in flight.

    The operator was explicit about when the main agent may block on a still-running delegated
    subagent: never, EXCEPT right before concluding a phase and producing that phase's own final
    verdict. This one choke point -- after _run_llm_tool_loop_impl returns its real answer, before
    handing it back to whichever phase called this -- is exactly that moment, for every phase that
    goes through here, without needing to repeat the same wait at each phase's own call site (and
    risk missing one on a later phase). It only runs on the normal, successful-return path: a Stop/
    cancellation still exits straight through the finally below without waiting on anything --
    kill_all_running_subagent_tasks (wired into run_session's own Stop/cancel handling) is what
    owns that case instead.

    plan_phase (one of "recon"/"analyze"/"exploit", or None): which of session["plan"]'s own phase
    keys _apply_plan_recommendations should reorder tool_specs against, re-applied at the TOP OF
    EVERY TURN inside _run_llm_tool_loop_impl (not computed once here and reused for the whole
    conversation) -- a plan update_plan call makes mid-phase, itself just one of several tool calls
    in the same turn, must be visible to the VERY NEXT turn's own tool schema, not just to a later
    phase's separate call into this function. None (the default) means this phase doesn't
    participate in plan-driven reordering at all (Validate, a subagent's own conversation) -- reverify
    and chain both pass "exploit" here despite their own `phase` string being "reverify"/"chain",
    since neither has a separate plan phase key of its own.

    external_trace: pass a caller-owned list to have this function mutate THAT list in place
    instead of a private one — used by _delegate_to_subagent_impl so a subagent's real progress
    survives being cut off by its own asyncio.wait_for() deadline (agent/tools/subagent_tasks.py's
    _LIVE_TRACES/_synthesize_partial_result). None (the default) behaves exactly as before.

    wallclock_limit_seconds: overrides _PHASE_WALLCLOCK_LIMIT_SECONDS (7200s, sized for a whole
    Recon/Analyze/Exploit phase) for a call that's a much smaller unit of work than a full phase —
    run_hypothesis_verification/_run_hypothesis_resolution_gate pass HYPOTHESIS_PASS_TIMEOUT_SECONDS
    here rather than silently inheriting the full phase-sized budget. None (the default) behaves
    exactly as before for every existing call site.

    progress_stall_threshold: stop the phase once this many tool calls in a row produce no new
    durable state (no successful _PROGRESS_RECORDING_TOOLS call) -- a "spinning without recording
    anything" guard the back-to-back-only _STALL_REPEAT_THRESHOLD can't catch. None (the default)
    disables it for every phase that legitimately does long read-only stretches before recording
    (Recon's enumeration); only a bounded, record-then-stop pass (RE triage) opts in.

    max_tool_calls: stop the phase once this many tool calls have been dispatched in total across
    the whole pass, regardless of wall-clock time or whether progress is being made -- a real,
    confirmed gap this closes: RE triage previously had only a 1800s wall-clock backstop and a
    progress-stall guard, neither of which caps a pass that keeps making DIFFERENT, individually
    successful calls indefinitely (chat's own CHAT_MAX_TOOL_ITERATIONS caps a turn's calls the same
    way, via a separate mechanism in agent/chat.py -- this is the equivalent for a phase run
    through this shared loop). None (the default) disables it for every phase that legitimately
    needs an open-ended number of calls (Recon/Analyze/Exploit's own wall-clock backstop already
    bounds those).
    """
    trace: list[dict] = external_trace if external_trace is not None else []
    try:
        result = await _run_llm_tool_loop_impl(
            ctx, system_prompt, task_content, tool_specs, phase, trace, execute_tool, expect_json_final, terminal_tool, is_subagent, plan_phase,
            wallclock_limit_seconds, progress_stall_threshold, max_tool_calls,
        )
        if not is_subagent:
            await subagent_tasks.await_all_running_subagent_tasks(
                ctx.session_id, ctx.session, stop_check=lambda: get_stop_event(ctx.session_id).is_set(),
            )
            # A stop_check-triggered early return above means this wait was cut short with a
            # subagent potentially still running — the exact case the module-level docstring
            # above already says this function deliberately exits straight through, without
            # waiting on anything, so kill_all_running_subagent_tasks (run_session's own Stop/
            # cancel handling) is what actually stops it. Raising here is what lets that happen —
            # without it, this would silently return a normal result as if nothing had happened.
            if get_stop_event(ctx.session_id).is_set():
                raise SessionStopRequested()
        return result
    finally:
        _log_phase_efficiency_summary(ctx, phase, trace, is_subagent)


async def _run_llm_tool_loop_impl(
    ctx: RunContext,
    system_prompt: str,
    task_content: str,
    tool_specs: list[ToolSpec],
    phase: str,
    trace: list[dict],
    execute_tool: Callable[[ToolSpec, dict], Awaitable[dict]] | None = None,
    expect_json_final: bool = True,
    terminal_tool: str | None = None,
    is_subagent: bool = False,
    plan_phase: str | None = None,
    wallclock_limit_seconds: int | None = None,
    progress_stall_threshold: int | None = None,
    max_tool_calls: int | None = None,
) -> tuple[dict | None, list[dict]]:
    """expect_json_final=True (Validate): the final non-tool-call reply must be the sub-phase's
    JSON contract — a reply that doesn't parse is logged as an error. Recon/Analyze pass False:
    their real output already landed via record_target/record_finding tool calls (see their
    execute closures), so the final reply is just an optional wrap-up sentence, not something to
    parse or complain about.

    terminal_tool (Exploit): the phase's final answer is a real tool call to this name instead of
    free-text JSON — native/prompt-mode tool-calling is a provider-enforced contract the model
    rarely misses, "reply in this exact JSON shape as plain text" is not. Real incident this
    replaces: _repair_json_reply existed almost entirely to paper over the free-text contract
    failing on a large fraction of Exploit's own turns (a weak/free model routinely wrapped its
    JSON in prose, dropped a field, or answered in the wrong language mid-reasoning) — one extra
    LLM round-trip paid on top of nearly every finding evaluated. The free-text JSON path stays as
    a fallback for the rare turn where the model answers in prose instead of calling the tool.
    """
    messages: list[dict] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": task_content},
    ]
    recent_call_signatures: list[str] = []
    # Same name+arguments signature as recent_call_signatures/batch_signatures, counted across the
    # WHOLE phase (not just one turn or one strict back-to-back streak) but only for calls that
    # actually FAILED -- see _MAX_IDENTICAL_FAILURES_PER_PHASE's own comment for why this is a
    # separate, narrower guard than the stall detector below.
    failed_call_counts: dict[str, int] = {}
    # Same phase-wide counting shape as failed_call_counts above, but keyed by tool name alone --
    # see _MAX_SCHEMA_VIOLATIONS_PER_PHASE's own comment for the failure class this specifically
    # catches (identical-signature guards above never trip when every violation uses a different
    # invalid value).
    never_dispatched_counts: dict[str, int] = {}
    # Counts tool calls since the last durable-progress record (see _PROGRESS_RECORDING_TOOLS) --
    # only consulted when progress_stall_threshold is set. Reset to 0 the moment one of those tools
    # succeeds, so a pass that keeps recording real state never trips it no matter how many calls it
    # takes; it only fires on a genuine record-nothing spin.
    calls_since_progress = 0
    # Only consulted when max_tool_calls is set -- counts every dispatched tool call across the
    # WHOLE pass (unlike recent_call_signatures' stall detection, which only cares about identical
    # back-to-back repeats). See max_tool_calls' own docstring on _run_llm_tool_loop for the real
    # gap this closes.
    tool_calls_made = 0
    phase_started_at = time.monotonic()
    effective_wallclock_limit_seconds = wallclock_limit_seconds if wallclock_limit_seconds is not None else _PHASE_WALLCLOCK_LIMIT_SECONDS
    stop_reason: str | None = None
    # Exactly one reinforcement attempt per phase run, same "1-Step Retry" philosophy as
    # _run_tool_with_retry's own single corrected retry — a bounded second chance, not an
    # open-ended loop the model could keep refusing through.
    refusal_reinforced = False
    # Same one-shot philosophy, for a different failure shape — see the malformed_content branch
    # below for the real incident this guards against.
    malformed_content_reinforced = False
    # Same one-shot philosophy again, for a third distinct failure shape — see the garbled-output
    # branch below (_looks_like_garbled_output) for the real incident this guards against.
    garbled_reinforced = False
    # Same one-shot philosophy again, for a fourth distinct failure shape — see the
    # declared-continuation branch below (_looks_like_a_declared_continuation) for the real
    # incident this guards against.
    continuation_reinforced = False

    while True:
        elapsed = time.monotonic() - phase_started_at
        if elapsed > effective_wallclock_limit_seconds:
            stop_reason = f"exceeded the {effective_wallclock_limit_seconds}s wall-clock backstop"
            break

        for hint in _drain_pending_guidance(ctx.session_id):
            messages.append({"role": "user", "content": f"[Operator note] {hint}"})
            logger.debug("core: session=%s %s phase: operator guidance applied: %r", ctx.session_id, phase, hint)

        for added_hypothesis in await _drain_pending_hypotheses(ctx, phase):
            messages.append({
                "role": "user",
                "content": (
                    f"[User hypothesis] {added_hypothesis['text']}"
                    + (f" (evidence: {added_hypothesis['evidence']})" if added_hypothesis.get("evidence") else "")
                    + " — a real lead the operator wants checked, not proven yet. Call resolve_hypothesis "
                    "once you've actually investigated it (\"confirmed\" plus a record_finding for the real "
                    "thing, or \"ruled_out\" with what you actually checked)."
                ),
            })
            logger.debug("core: session=%s %s phase: live operator hypothesis applied: %r", ctx.session_id, phase, added_hypothesis["text"])

        for added_recon_item in await _drain_pending_recon_notes(ctx, phase):
            messages.append({
                "role": "user",
                "content": (
                    f"[Operator added target/note] {added_recon_item['text']}"
                    + (f" (evidence: {added_recon_item['evidence']})" if added_recon_item.get("evidence") else "")
                    + " — investigate using your available tools. Call resolve_hypothesis once you've "
                    "actually investigated it (\"confirmed\" plus a record_finding for the real thing, "
                    "or \"ruled_out\" with what you actually checked)."
                ),
            })
            logger.debug("core: session=%s %s phase: live operator recon item applied: %r", ctx.session_id, phase, added_recon_item["text"])

        if not is_subagent:
            for finished in _drain_subagent_results(ctx.session_id):
                # Capped the same way a live tool result already is (messages.append below, "role":
                # "tool") -- defense-in-depth on top of subagent_tasks.py's own _capped_trace, which
                # already bounds the timeout-salvage path this normally guards against. This second
                # cap exists so a FUTURE, different way for finished["result"] to grow large (e.g. an
                # uncapped model-authored "details" field on a normal, non-timeout completion) can
                # never again silently blow up every remaining LLM call in this phase the way an
                # uncapped 4.46MB salvaged trace once did in a real session.
                messages.append({
                    "role": "user",
                    "content": (
                        f"[Subagent '{finished['profile_name']}' finished] "
                        f"{json.dumps(finished['result'])[:_TOOL_RESULT_CHAR_LIMIT]}\n\n"
                        "This is real reconnaissance data, not a status update to just acknowledge — a "
                        "subagent has no recording tools of its own, so anything concrete it found (a "
                        "confirmed host/service, an exposed path, a technology fact) only becomes part of "
                        "this scan if YOU call record_target/record_finding for it now, the same as if "
                        "you'd found it yourself."
                    ),
                })
                _subagent_logger.debug(
                    "core: session=%s %s phase: subagent %r result auto-delivered",
                    ctx.session_id, phase, finished["profile_name"],
                )
                # Marks THIS specific task delivered so _requeue_undelivered_subagent_results never
                # re-injects it into a later phase -- entry.get(..., not a bare subscript) so a task
                # pushed before this field existed (an in-flight upgrade) self-heals instead of
                # raising a KeyError, same "not a hard requirement" tolerance _dead_host_blocked's
                # own consecutive_failures field already established.
                delivered_entry = ctx.session.get("subagent_tasks", {}).get(finished.get("task_id"))
                if delivered_entry is not None:
                    delivered_entry["delivered"] = True

        # Recomputed every turn, not once before the loop -- an update_plan call made THIS turn
        # (one of several tool calls in the same batch) must already reorder what the VERY NEXT
        # turn is offered, not wait for some later, separate phase call into this same function.
        # tool_specs itself (the base list) never changes across turns, only which of its entries
        # get promoted/labeled, so this is cheap (a plain reorder over an already-small list).
        current_tool_specs = _apply_plan_recommendations(tool_specs, ctx.session, plan_phase) if plan_phase else tool_specs
        tools_schema = [_tool_to_openai_schema(spec) for spec in current_tool_specs]
        specs_by_name = {spec.name: spec for spec in current_tool_specs}

        # The wall-clock backstop at the top of this loop only fires BETWEEN turns -- a single
        # model call that hangs (a dead/rate-limited free provider retrying internally for many
        # minutes) would otherwise blow straight past the phase budget, since nothing re-checks the
        # clock while we're awaiting one call. Cap each call at whatever budget actually remains so
        # a stuck provider can never run the phase past its own wall-clock limit, and a genuinely
        # dead one is caught instead of hanging the whole run. remaining is always > 0 here (the
        # top-of-loop check already broke out at <= 0).
        remaining_budget = effective_wallclock_limit_seconds - (time.monotonic() - phase_started_at)
        try:
            response = await asyncio.wait_for(_llm_complete(ctx, messages, tools_schema), timeout=remaining_budget)
        except asyncio.TimeoutError:
            stop_reason = (
                f"exceeded the {effective_wallclock_limit_seconds}s wall-clock backstop "
                "(a single model call ran past the remaining budget without returning)"
            )
            logger.debug("core: session=%s %s phase: LLM call exceeded remaining wall-clock budget (%.0fs) -- stopping", ctx.session_id, phase, remaining_budget)
            break

        if not response.tool_calls and _looks_like_a_refusal(response.content) and not refusal_reinforced:
            # Real incident this fixes: a phase "completed" with zero tool calls on this turn and
            # got silently recorded as "0 targets found" / "nothing to report" — genuinely
            # indistinguishable, downstream, from a real clean result — when what actually
            # happened was the model declining the (already pre-authorized) task outright. One
            # explicit reminder before treating a refusal-shaped reply as a real answer.
            refusal_reinforced = True
            logger.debug(
                "core: session=%s %s phase: response looks like a safety refusal, giving one explicit "
                "authorization reminder before treating it as a real result: %r",
                ctx.session_id, phase, (response.content or "")[:200],
            )
            messages.append({"role": "assistant", "content": response.content or ""})
            messages.append({"role": "user", "content": _REFUSAL_REINFORCEMENT_MESSAGE})
            continue

        if not response.tool_calls and response.content_was_malformed and not malformed_content_reinforced:
            # Real, confirmed incident this fixes: a subagent turn came back with tool_calls=0 and
            # message.content as a list of text/reference blocks instead of the promised str | None
            # (llm_client.py's _normalize_message_content/_content_is_malformed — Mistral's
            # mistral-large-latest apparently tried to express several tool calls as citation-style
            # text instead of using the real tool_calls field). Before that normalization existed,
            # this crashed the whole task outright (TypeError inside _looks_like_a_refusal); now it
            # no longer crashes, but treating it as this turn's real, final, zero-tool-calls answer
            # still silently drops whatever the model was actually trying to do — confirmed live: a
            # subagent task handling 3 real hosts ended after exactly this turn, its actual work
            # never delivered. One explicit nudge to use the real tool-calling mechanism, same
            # bounded "one reinforcement attempt" shape as the refusal branch just above, gives the
            # model a real chance to redo it correctly instead of the turn being silently lost.
            malformed_content_reinforced = True
            logger.debug(
                "core: session=%s %s phase: response content came back in a non-standard shape "
                "(0 tool calls) — giving one explicit nudge to use real tool-calling before "
                "treating this turn as a final answer: %r",
                ctx.session_id, phase, (response.content or "")[:200],
            )
            messages.append({"role": "assistant", "content": response.content or ""})
            messages.append({
                "role": "user",
                "content": (
                    "That reply didn't come through as a normal tool call — if you intended to call "
                    "one or more tools, use the actual tool-calling mechanism (not plain text "
                    "describing what you'd call), one real tool call per action. If you didn't intend "
                    "to call any tool, just reply normally."
                ),
            })
            continue

        if not response.tool_calls and not garbled_reinforced and _looks_like_garbled_output(response.content):
            # Real, confirmed incident this fixes — see _looks_like_garbled_output's own docstring
            # for the exact live example. Neither the refusal check nor the malformed_content check
            # above catches this: the reply is a normal, well-typed string, just linguistically
            # incoherent (tokenizer-level corruption from a free-tier model under load). Same bounded
            # "one reinforcement attempt" shape as the two branches above, giving the model one real
            # chance to answer coherently instead of a corrupted burst silently becoming this phase's
            # permanent "nothing found" verdict.
            garbled_reinforced = True
            logger.debug(
                "core: session=%s %s phase: response looks like corrupted/incoherent text, giving "
                "one explicit reminder to answer coherently before treating it as a real result: %r",
                ctx.session_id, phase, (response.content or "")[:200],
            )
            messages.append({"role": "assistant", "content": response.content or ""})
            messages.append({
                "role": "user",
                "content": (
                    "That reply came through as garbled/corrupted text, not a coherent answer. "
                    "Please try again: either make a real tool call, or give a clear, well-formed "
                    "text answer."
                ),
            })
            continue

        if not response.tool_calls and not continuation_reinforced and _looks_like_a_declared_continuation(response.content):
            # Real, confirmed incident this fixes — see _looks_like_a_declared_continuation's own
            # docstring for the exact live example. The reply isn't a refusal, isn't malformed,
            # isn't garbled -- it's a normal, coherent sentence stating what the model is ABOUT to
            # do next, with zero tool calls behind it. Same bounded "one reinforcement attempt"
            # shape as the branches above: give it one real chance to actually make the call it
            # just said it would, instead of the stated intent silently becoming this phase's final
            # answer with the described action never happening.
            continuation_reinforced = True
            logger.debug(
                "core: session=%s %s phase: response states intent to continue but made no tool "
                "call — giving one explicit nudge to actually make the call before treating this "
                "as a final answer: %r",
                ctx.session_id, phase, (response.content or "")[:200],
            )
            messages.append({"role": "assistant", "content": response.content or ""})
            messages.append({
                "role": "user",
                "content": (
                    "You said you'd continue, but didn't actually make a tool call. Make the real "
                    "tool call now for whatever you just described, or if there's genuinely nothing "
                    "more to do, say so plainly instead."
                ),
            })
            continue

        if not response.tool_calls:
            refused_again = _looks_like_a_refusal(response.content)
            if refused_again:
                logger.debug(
                    "core: session=%s %s phase: model declined the task even after an explicit "
                    "authorization reminder — treating this as a real failure, not a silent "
                    "'nothing found' result",
                    ctx.session_id, phase,
                )
            if terminal_tool is not None:
                # Safety net only -- the model was supposed to call terminal_tool and didn't call
                # anything at all. Try the free-text-JSON path first (a model that just forgot to
                # wrap valid JSON in a tool call), then a real schema-backed retry -- see
                # _repair_terminal_tool_reply's docstring for why the generic tools=None repair
                # alone reliably produces unparseable garbage for a terminal_tool's own contract.
                parsed = _parse_json_response(response.content)
                if parsed is None:
                    parsed = await _repair_terminal_tool_reply(
                        ctx, messages, tools_schema, terminal_tool, specs_by_name, execute_tool, trace, phase,
                    )
                if refused_again:
                    reason = "model declined this finding's task even after an explicit authorization reminder — not a real 'no fitting tool' conclusion"
                elif parsed is None:
                    reason = f"model replied as text instead of calling {terminal_tool!r}, and the text didn't parse as JSON either"
                else:
                    reason = None
                _append_log(ctx, phase, response.content, None, "error" if (refused_again or parsed is None) else "success", reason)
                return parsed, trace
            if not expect_json_final:
                # Real output already landed via record_target/record_finding tool calls — this
                # reply is just a free-text wrap-up, never attempt to parse it as JSON (that would
                # log a misleading "failed to parse" line for completely normal operation).
                reason = (
                    "model declined this phase's task even after an explicit authorization "
                    "reminder — any 'nothing found' result from this phase does not reflect a "
                    "real, completed recon/analysis pass"
                    if refused_again else None
                )
                _append_log(ctx, phase, response.content, None, "error" if refused_again else "success", reason)
                return None, trace
            parsed = _parse_json_response(response.content)
            if parsed is None:
                parsed = await _repair_json_reply(ctx, messages, response.content)
            _append_log(
                ctx, phase, response.content, None,
                "success" if parsed is not None else "error",
                None if parsed is not None else "could not parse a final JSON response from the model",
            )
            return parsed, trace

        messages.append(
            {
                "role": "assistant",
                "content": response.content or "",
                "tool_calls": [
                    {"id": c.id, "type": "function", "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                    for c in response.tool_calls
                ],
            }
        )

        terminal_result: dict | None = None
        # Same-turn duplicate guard -- a model batching several tool calls in one turn
        # occasionally repeats the exact same name+arguments two or more times (confirmed live: a
        # real session issued the identical http_request four times within under a second, one
        # turn). _STALL_REPEAT_THRESHOLD below only stops a genuine stuck loop at
        # _STALL_REPEAT_THRESHOLD repeats in a row; a same-turn burst of 2-5 slips under that and
        # just burns tool budget for zero new information. Real work already happened for the
        # first occurrence this turn, so every later identical call in the same batch is a
        # costless no-op instead of a second real dispatch.
        batch_signatures: set[str] = set()
        for call_index, call in enumerate(response.tool_calls):
            signature = f"{call.name}:{json.dumps(call.arguments, sort_keys=True)}"
            duration_ms: float | None = None
            if signature in batch_signatures:
                result = {
                    "status": "skipped",
                    "reason": f"duplicate of an earlier {call.name!r} call with identical arguments in this same turn — see that result instead",
                }
            else:
                batch_signatures.add(signature)
                # Repeated-identical-failure guard -- see _MAX_IDENTICAL_FAILURES_PER_PHASE's own
                # comment for why this is scoped to failures specifically, not repeats in general.
                if failed_call_counts.get(signature, 0) >= _MAX_IDENTICAL_FAILURES_PER_PHASE:
                    result = {
                        "status": "skipped",
                        "reason": (
                            f"this exact {call.name!r} call with identical arguments already failed "
                            f"{failed_call_counts[signature]} times this phase with the same error — "
                            "stop retrying it verbatim, try different arguments or move on to something else"
                        ),
                    }
                elif never_dispatched_counts.get(call.name, 0) >= _MAX_SCHEMA_VIOLATIONS_PER_PHASE:
                    result = {
                        "status": "skipped",
                        "reason": (
                            f"{call.name!r} has now been called with arguments that violate its own "
                            f"parameter schema {never_dispatched_counts[call.name]} times this phase, each "
                            "time with a different invalid value — stop guessing at this tool's parameter "
                            "shape, re-read its schema/description carefully before calling it again, or "
                            "move on to a different approach entirely"
                        ),
                    }
                else:
                    spec = specs_by_name.get(call.name)
                    if spec is None:
                        result = {"status": "error", "error": f"unknown tool {call.name!r}"}
                    else:
                        dispatch_started = time.monotonic()
                        if execute_tool is not None:
                            result = await execute_tool(spec, call.arguments)
                        else:
                            result = await _run_tool_with_retry(ctx, spec, call.arguments)
                        duration_ms = (time.monotonic() - dispatch_started) * 1000
                    if result.get("status") in ("failed", "error"):
                        failed_call_counts[signature] = failed_call_counts.get(signature, 0) + 1
                    if result.get("never_dispatched") or result.get("schema_violation_corrected"):
                        # Counted whether or not the 1-Step Retry above went on to correct the call
                        # successfully -- see _MAX_SCHEMA_VIOLATIONS_PER_PHASE's own comment for why
                        # a per-violation correction that never carries forward into the model's own
                        # conversation still needs a phase-wide guard against repeating the mistake.
                        never_dispatched_counts[call.name] = never_dispatched_counts.get(call.name, 0) + 1

            if terminal_tool is not None and call.name == terminal_tool and result.get("status") == "ok":
                unresolved_task_ids = _unresolved_subagent_task_ids(trace)
                cited_task_id = _cited_unresolved_subagent_task(call.arguments, unresolved_task_ids)
                if cited_task_id:
                    result = {
                        "status": "error",
                        "error": (
                            f"this reply cites subagent task {cited_task_id!r} as evidence, but the last "
                            "status you actually observed for it in this conversation was still 'running' — "
                            "you never saw it finish. Call check_subagent_task again (or wait for its result "
                            "to arrive) and report what it ACTUALLY found once it's done, not what you expect "
                            "or assume it will find."
                        ),
                    }
                elif unresolved_task_ids:
                    # A NARROWER sibling of the citation guard above: even when this reply doesn't
                    # cite the unfinished task as evidence (the honest case — e.g. an "inconclusive"/
                    # "skipped" verdict admitting it couldn't get an answer), concluding at all while
                    # a subagent YOU delegated this same pass is still genuinely running short-changes
                    # it — it may well have a real, definitive answer only a few more minutes away.
                    # Real, confirmed incident this fixes (rev-retest-rescan-usr_8ba29f): reverify
                    # delegated a subagent to grab an SSH banner, then concluded
                    # verification_outcome="inconclusive" only 26 seconds / 5 polls later, reasoning
                    # "the subagent has been running for several minutes" -- false at the time it was
                    # written. The subagent's own real answer arrived 6m45s later, well within its own
                    # bounded SUBAGENT_TASK_TIMEOUT_SECONDS budget (900s default) -- this guard can
                    # never hang forever, since that task is guaranteed to reach a resolved status
                    # (done/timeout/error) on its own regardless of what this loop does. Deliberately
                    # NOT applied to the stall-forced "final answer" path a few lines below (mirroring
                    # the citation guard's own identical scope) -- if the model just polls
                    # check_subagent_task identically enough times to trip stall detection, that
                    # escape valve must still work, or this and the stall detector would deadlock
                    # each other.
                    unresolved_task_id = next(iter(unresolved_task_ids))
                    result = {
                        "status": "error",
                        "error": (
                            f"subagent task {unresolved_task_id!r}, delegated earlier in this same pass, is "
                            "still running — you have not actually seen it finish yet. Call check_subagent_task "
                            "again (it's fine to poll more than once) or keep doing other real work and come "
                            "back to it, but do not conclude yet just because it hasn't answered within a few "
                            "seconds — it can genuinely take several minutes for real reconnaissance work."
                        ),
                    }

            trace.append({"tool": call.name, "arguments": call.arguments, "result": result})
            # response.content (the model's reasoning for this whole turn) belongs to the TURN, not
            # to each of its several tool calls -- attach it once, to the first entry of the batch,
            # instead of copying the identical thought onto every entry (pure session.json bloat and
            # log-review noise: a 4-call turn used to store the same paragraph 4 times).
            _append_log(ctx, phase, response.content if call_index == 0 else None, _describe_command(call, result), _log_status(result), _log_error(result), duration_ms, _log_output(result))
            messages.append({"role": "tool", "tool_call_id": call.id, "content": json.dumps(result)[:_TOOL_RESULT_CHAR_LIMIT]})

            if progress_stall_threshold is not None:
                if call.name in _PROGRESS_RECORDING_TOOLS and result.get("status") == "ok":
                    calls_since_progress = 0
                else:
                    calls_since_progress += 1
                    if calls_since_progress >= progress_stall_threshold:
                        stop_reason = (
                            f"{progress_stall_threshold} tool calls in a row without recording any new "
                            "finding, hypothesis, or target-profile fact"
                        )
                        ctx.session.setdefault("stall_events", []).append({
                            "phase": phase, "tool": "no_progress", "at": datetime.now(timezone.utc).isoformat(),
                        })
                        save_session(ctx.session_id, ctx.session)

            if max_tool_calls is not None:
                tool_calls_made += 1
                if tool_calls_made >= max_tool_calls:
                    stop_reason = f"reached the {max_tool_calls}-call budget for this pass"

            if terminal_tool is not None and call.name == terminal_tool and result.get("status") == "ok":
                # Convention: a terminal tool's success result IS the final answer, internal
                # bookkeeping stripped — keeps this loop generic (it doesn't need to know
                # record_exploit_decision's specific field names, just that "ok" means "done").
                terminal_result = {k: v for k, v in result.items() if k not in _TOOL_RETRY_BOOKKEEPING_KEYS}

            # Stall detection, not a work-count cap: only the exact same call (name + arguments)
            # repeated back-to-back trips this — any different call in between resets progress
            # toward the threshold, so a scan doing real, varied work across many targets never
            # comes close no matter how many tool calls that legitimately takes.
            #
            # background_job_check polling a job that is still genuinely "running" is deliberately
            # exempt from this counter -- unlike check_subagent_task (which has its own escape-valve
            # error message for exactly this situation, deliberately still allowed to trip stall
            # detection so that valve fires), background_job_check has no such mechanism, and the job
            # it's waiting on is an independent OS-level subprocess with its own deadline
            # (background_jobs.py's start_background_job/_reap) -- ending the phase here doesn't stop
            # the job, it just abandons whatever result it goes on to produce, unseen, forever. Real,
            # confirmed incident this fixes: a live hydra RDP brute-force (900s deadline) got cut off
            # from the only phase polling it after 6 checks in 18 seconds, then quietly succeeded
            # with 6 valid credentials minutes later -- see _auto_record_cracked_credentials_finding
            # for the other half of this fix. The moment result["status"] stops being "running" (the
            # job hit its own deadline, or genuinely finished/errored) this exemption stops applying
            # and normal stall detection resumes immediately, so a job that never actually completes
            # still can't spin this loop forever -- it's bounded by the job's own deadline and this
            # phase's own wall-clock backstop either way.
            if call.name == "background_job_check" and result.get("status") == "running":
                pass
            else:
                recent_call_signatures.append(signature)
                del recent_call_signatures[:-_STALL_REPEAT_THRESHOLD]
                if len(recent_call_signatures) == _STALL_REPEAT_THRESHOLD and len(set(recent_call_signatures)) == 1:
                    stop_reason = f"{call.name!r} called identically {_STALL_REPEAT_THRESHOLD} times in a row"
                    # Persisted (not just debug-logged like the stop itself, a few lines below) so
                    # compute_efficiency_score can weigh a genuine stuck-loop stop as the heavy,
                    # real-time-wasting event it is — a whole phase forced to a stop, not just one bad
                    # call. Never cleared/reset; a session's own stall history is permanent audit data.
                    ctx.session.setdefault("stall_events", []).append({
                        "phase": phase, "tool": call.name, "at": datetime.now(timezone.utc).isoformat(),
                    })
                    save_session(ctx.session_id, ctx.session)

        if terminal_result is not None:
            return terminal_result, trace

        if stop_reason:
            break

    # Only reachable via a safeguard break above (wall-clock backstop, progress stall, back-to-back
    # repeat) -- a model that finishes on its own returns from inside the loop with stop_reason
    # still None, never touching this. Surfaced on ctx so a caller (run_re_triage) can record an
    # honest end-reason instead of presenting a timed-out pass as a clean success.
    ctx.last_stop_reason = stop_reason

    if not expect_json_final and terminal_tool is None:
        logger.debug("core: session=%s %s phase stopped: %s", ctx.session_id, phase, stop_reason)
        # A safeguard break used to just discard whatever the model had learned mid-pass -- real,
        # confirmed operator complaint this fixes: RE triage could burn its whole wall-clock/call
        # budget with real tool calls behind it and produce nothing but a bare safeguard note
        # (session["triage_end_reason"]), no actual takeaway. One more forced call, same
        # "tools=None, must answer in plain text" shape agent/chat.py's own budget-exhausted exit
        # uses (_run_chat_tool_loop), asks the model to say what it actually found/confirmed before
        # the pass truly ends -- logged as a normal log entry (same _append_log shape the natural,
        # no-safeguard free-text wrap-up just below already uses) so it shows up in the
        # operator-facing Logs/Triage view like any other step, not silently dropped.
        messages.append({
            "role": "user",
            "content": (
                f"This pass is being stopped now (reason: {stop_reason}). Do not attempt another "
                "tool call. In a few sentences, summarize plainly what you actually found/confirmed "
                "so far from the tool calls you already made, and what -- if anything -- is still "
                "unresolved or worth a follow-up in chat."
            ),
        })
        try:
            summary_response = await _llm_complete(ctx, messages, None)
            summary_text = (summary_response.content or "").strip()
        except Exception as exc:
            logger.debug("core: session=%s %s phase: safeguard-stop summary call itself failed (%s)", ctx.session_id, phase, exc)
            summary_text = ""
        if summary_text:
            _append_log(ctx, phase, summary_text, None, "success", None)
        return None, trace

    logger.debug("core: session=%s %s phase stopped: %s — forcing a final answer", ctx.session_id, phase, stop_reason)
    if terminal_tool is not None:
        messages.append({"role": "user", "content": f"Stop calling any other tool now and call {terminal_tool} with your final answer."})
        response = await _llm_complete(ctx, messages, tools_schema)
        call = next((c for c in response.tool_calls if c.name == terminal_tool), None)
        if call is not None:
            spec = specs_by_name.get(call.name)
            dispatch_started = time.monotonic()
            result = await execute_tool(spec, call.arguments) if execute_tool is not None else await _run_tool_with_retry(ctx, spec, call.arguments)
            duration_ms = (time.monotonic() - dispatch_started) * 1000
            trace.append({"tool": call.name, "arguments": call.arguments, "result": result})
            _append_log(ctx, phase, response.content, _describe_command(call, result), _log_status(result), _log_error(result), duration_ms, _log_output(result))
            if result.get("status") == "ok":
                return {k: v for k, v in result.items() if k not in _TOOL_RETRY_BOOKKEEPING_KEYS}, trace
        parsed = _parse_json_response(response.content)
        if parsed is None:
            parsed = await _repair_terminal_tool_reply(
                ctx, messages, tools_schema, terminal_tool, specs_by_name, execute_tool, trace, phase,
            )
        return parsed, trace

    messages.append({"role": "user", "content": "Stop calling tools now and reply with the final JSON only."})
    response = await _llm_complete(ctx, messages, None)
    parsed = _parse_json_response(response.content)
    if parsed is None:
        parsed = await _repair_json_reply(ctx, messages, response.content)
    return parsed, trace


def _has_wildcard_scope(target: str) -> bool:
    return any(entry.strip().startswith("*.") for entry in target.split(","))


def _is_recon_target_grounded(session: dict, nmap_target: str, original_target: str) -> bool:
    """True when nmap_target has a real basis to be actively scanned this recon run — either the
    literal scope the operator typed, a subdomain of a wildcard-scoped entry, or a hostname/IP a
    real discovery tool (crt_sh_lookup/subdomain_enum/dns_lookup, tracked in
    recon_result["dns_map"]) already surfaced. False for a hostname the model just guessed from
    its own general knowledge.

    Real incident this guards against: a scan authorized only for "example.ru" had the model
    directly nmap "example.com" and "forum.example.com" — a completely different registrable
    domain — purely from its own inference about what other domains the same site "probably" also
    uses, with zero recon tool ever having mentioned either one first. Both happened to resolve to
    something real (Cloudflare), which is exactly what made the guess look indistinguishable from
    a genuine finding for the rest of that scan — nothing about "it resolved to something" is
    proof it's actually related to the authorized target.
    """
    hostname = (extract_hostname(nmap_target) or nmap_target).lower().strip()

    for entry in (t.strip() for t in original_target.split(",") if t.strip()):
        entry_lower = entry.lower()
        if entry.startswith("*."):
            base = entry[2:].lower()
            if hostname == base or hostname.endswith("." + base):
                return True
        # Any OTHER placement of "*" (validate_scope_entry() accepts "prod-*.example.com",
        # "*-eu.example.com", etc. -- see that function's own docstring) is matched as a real glob
        # pattern, the same fnmatchcase-on-lower-cased-strings approach allowed_targets.py's
        # _matches_scope_entries uses for the identical reason -- without this, a host legitimately
        # covered by one of these newer wildcard shapes would pass scope validation and allowlist
        # matching but still get silently refused active nmap scanning here, an accepted-but-
        # doesn't-actually-work gap for exactly the entries this was just made to accept.
        elif "*" in entry and fnmatch.fnmatchcase(hostname, entry_lower):
            return True
        elif hostname == (extract_hostname(entry) or entry).lower():
            return True

    dns_map = session.get("recon_result", {}).get("dns_map", {})
    if hostname in dns_map:
        return True
    return any(hostname in resolved_ips for resolved_ips in dns_map.values())


async def _maybe_refresh_program_check(ctx: RunContext) -> None:
    """Best-effort, per-phase freshness ping for session["program_url"] -- called once at the top
    of _run_recon/_run_analyze/_run_exploit below. The real work (agent/tools/bugbounty_import.py's
    refresh_program_check) is itself TTL-gated (BUGBOUNTY_IMPORT_HACKTIVITY_REFRESH_SECONDS), so
    every call after the first in a session is a cheap no-op read until that window elapses -- this
    is the "fully automatic, periodic" freshness behavior, not a per-phase re-extraction.

    Local import, not a module-level one: agent/tools/bugbounty_import.py itself imports
    agent.core (_parse_json_response) at its own module top, so a module-level import here would
    be circular -- the same reason _dispatch_tool's own check_disclosed_reports bypass already
    imports that module locally instead. Swallows any unexpected exception (refresh_program_check
    itself is already documented as never-raising, but a phase transition must never fail because
    of this best-effort side check regardless).
    """
    program_url = ctx.session.get("program_url")
    if not program_url:
        return
    from agent.tools.bugbounty_import import refresh_program_check
    try:
        await refresh_program_check(ctx.session_id, program_url)
    except Exception as exc:
        logger.debug("core: session=%s program_url refresh raised unexpectedly (%s)", ctx.session_id, exc)


async def _run_recon(ctx: RunContext, target: str) -> dict:
    _mark_phase_started(ctx.session, "recon")
    await _maybe_refresh_program_check(ctx)
    subagent_tools, subagent_addendum = _subagent_delegation_extras(ctx.session)
    tools = get_tools_by_category("recon") + subagent_tools + _toolkit_tool_extras()
    # Two independent ways to turn subdomain enumeration on: a per-entry "*.example.com" marker
    # in the scope itself, or the New Project form's "Enumerate subdomains" checkbox (a
    # project-wide equivalent that doesn't need typing "*." on every entry — off by default,
    # sessions/store.py's create_session()). Either is enough on its own.
    has_wildcard_entry = _has_wildcard_scope(target)
    enumeration_enabled = has_wildcard_entry or bool(ctx.session.get("enumerate_subdomains"))
    if not enumeration_enabled:
        # subdomain_enum/subfinder/crt_sh_lookup all actively go looking for hostnames the
        # operator never explicitly put in scope — fine, expected, even required when enumeration
        # is enabled, but not offered at all otherwise: a plain "example.com" target with the
        # checkbox off (and no *.example.com entry) means exactly that one host is authorized, not
        # "and whatever else you can find under it". Not offering the tools is a real, code-level
        # guarantee the model can't call them there — not just a prompt suggestion it could ignore.
        # Real incident this fixes: only subdomain_enum was ever actually excluded here -- subfinder
        # (its own description literally says "use this first for a wildcard-scope target", yet
        # nothing enforced that) and crt_sh_lookup (whose sole purpose is finding subdomains via
        # certificate transparency) both stayed in the tool list unconditionally, so a session with
        # the checkbox off and no wildcard entry could still discover and (via dns_lookup grounding
        # them into recon_result["dns_map"]) actively nmap-scan hosts the operator never authorized.
        tools = [spec for spec in tools if spec.name not in ("subdomain_enum", "subfinder", "crt_sh_lookup")]
    # update_plan is registered under category="post_exploit" specifically so it never leaks in
    # via get_tools_by_category("recon") above — appended explicitly here, same convention
    # record_reverification_result/record_chain_result already use for a tool that must be
    # available regardless of category. plan_phase="recon" below (not a call to
    # _apply_plan_recommendations here) is what actually reorders tools per the model's own
    # current plan — done fresh every turn inside _run_llm_tool_loop_impl, not once here.
    update_plan_spec = get_tool("update_plan")
    if update_plan_spec is not None:
        tools.append(update_plan_spec)
    record_hypothesis_spec = get_tool("record_hypothesis")
    if record_hypothesis_spec is not None:
        tools.append(record_hypothesis_spec)
    logger.debug(
        "core: session=%s starting recon phase (%d tools available, subdomain enumeration=%s)",
        ctx.session_id, len(tools), enumeration_enabled,
    )
    ctx.session.setdefault("recon_result", {"targets": [], "cves": []})
    ctx.session["recon_result"].setdefault("cves", [])
    # host -> resolved IPs, filled in from dns_lookup/subdomain_enum tool results as recon runs.
    # Purely additive display data (session_fragment.html/proof_report.html show it next to a
    # domain host in the Asset Info table) — never consulted for scope/allowlist decisions, those
    # stay keyed off the host string the model actually recorded.
    ctx.session["recon_result"].setdefault("dns_map", {})
    # host -> best-effort OS guess string (nmap -O, agent/tools/builders/nmap.py's
    # parse_nmap_output) — captured here deterministically the moment nmap returns it, same
    # reasoning as recon_result["cves"] below: whether the model also transcribes it into a
    # record_target call is not reliable enough to promise every scanned host gets one.
    ctx.session["recon_result"].setdefault("os_guesses", {})

    existing_targets = ctx.session["recon_result"]["targets"]

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        if spec.name == "nmap":
            nmap_target = arguments.get("target")
            if isinstance(nmap_target, list):
                nmap_target = nmap_target[0] if nmap_target else None
            if isinstance(nmap_target, str) and nmap_target.strip() and not _is_recon_target_grounded(ctx.session, nmap_target, target):
                logger.debug(
                    "core: session=%s recon: rejected nmap against ungrounded target=%r "
                    "(not in scope, not resolved by a real recon tool this run)",
                    ctx.session_id, nmap_target,
                )
                return {
                    "status": "error",
                    "error": (
                        f"{nmap_target!r} has no real basis to be scanned yet — it is not the literal "
                        "target you were given, not covered by a wildcard scope entry, and no "
                        "crt_sh_lookup/subdomain_enum/dns_lookup result has resolved it this run. Never "
                        "scan a hostname just because it seems plausible from general knowledge about "
                        "this target. If you believe it's real and in scope, call dns_lookup (or "
                        "crt_sh_lookup/subdomain_enum for a whole guessed suffix) on it first to get "
                        "real evidence, then nmap it."
                    ),
                }
        result = await _run_tool_with_retry(ctx, spec, arguments)
        # A corrected 1-Step Retry can send a different target/domain than the one the model
        # originally called with — bookkeeping below must key off what actually ran, not the
        # pre-retry arguments (real incident: a failed dns_lookup for one host got "corrected" to
        # a different, already-known-good host, and the result was recorded under the FAILED
        # host's name, silently fabricating a DNS resolution that was never actually confirmed).
        used_arguments = result.get("used_arguments", arguments)
        if spec.name == "nmap" and result.get("status") == "ok":
            os_guess = (result.get("parsed") or {}).get("os_guess")
            host = used_arguments.get("target")
            if isinstance(host, list):
                host = host[0] if host else None
            if os_guess and isinstance(host, str) and host.strip():
                ctx.session["recon_result"]["os_guesses"][host.strip()] = os_guess
                save_session(ctx.session_id, ctx.session)
                logger.debug("core: session=%s recon: os_guesses[%r] = %r", ctx.session_id, host.strip(), os_guess)
        if spec.name == "record_target" and result.get("status") == "ok" and "recorded" in result:
            recorded = result["recorded"]
            already_recorded = any(
                t.get("host") == recorded.get("host") and t.get("port") == recorded.get("port")
                for t in existing_targets
            )
            if already_recorded:
                # A resumed recon phase (see the resume addendum below) is explicitly told what's
                # already known, but nothing stops the model from calling record_target for it
                # again anyway — silently dropping the duplicate keeps the Asset Info table (and a
                # resumed run's real tool-call cost) from doubling up on the exact same host:port.
                logger.debug("core: session=%s recon: skipped duplicate target host=%r port=%s", ctx.session_id, recorded.get("host"), recorded.get("port"))
            else:
                # Real-clock timestamp, captured here deterministically the moment a genuinely NEW
                # target is recorded (never on a duplicate skip above) -- the Map tab's own timeline
                # scrubber (attack_surface_graph.js) is the actual consumer, letting an operator
                # replay roughly the order recon actually found things in. Same "capture it here,
                # don't rely on the model separately transcribing it" reasoning os_guesses/dns_map
                # already use above; record_target's own native function stays a pure, deterministic
                # transform with no wall-clock dependency of its own.
                recorded["discovered_at"] = datetime.now(timezone.utc).isoformat()
                existing_targets.append(recorded)
                save_session(ctx.session_id, ctx.session)
                logger.debug("core: session=%s recon: recorded target host=%r", ctx.session_id, recorded.get("host"))
        elif spec.name == "dns_lookup" and result.get("status") == "ok" and result.get("ips"):
            domain = used_arguments.get("domain")
            if domain:
                dns_map = ctx.session["recon_result"]["dns_map"]
                dns_map[domain] = sorted(set(dns_map.get(domain, [])) | set(result["ips"]))
                save_session(ctx.session_id, ctx.session)
                logger.debug("core: session=%s recon: dns_map[%r] = %s", ctx.session_id, domain, dns_map[domain])
        elif spec.name == "subdomain_enum" and result.get("status") == "ok" and result.get("found"):
            dns_map = ctx.session["recon_result"]["dns_map"]
            updated = 0
            for entry in result["found"]:
                host, ips = entry.get("host"), entry.get("ips")
                if host and ips:
                    dns_map[host] = sorted(set(dns_map.get(host, [])) | set(ips))
                    updated += 1
            if updated:
                save_session(ctx.session_id, ctx.session)
                logger.debug("core: session=%s recon: dns_map updated for %d host(s) from subdomain_enum", ctx.session_id, updated)
        elif spec.name == "update_plan" and result.get("status") == "ok" and "recorded" in result:
            _apply_updated_plan(ctx, result["recorded"], "recon")
        elif spec.name == "record_hypothesis" and result.get("status") == "ok" and "recorded" in result:
            _persist_new_hypothesis(ctx, result["recorded"], "recon")
        return result

    # "target" can be a comma-separated scope (multiple URLs/hosts/IPs from the New Project
    # form) — phrased as free text here on purpose, no special-casing needed: the model reads
    # "a, b, c" as a multi-host scope and record_target already supports recording many.
    task = f"Target(s): {target}\nGather recon data using the tools available to you."
    dns_map = ctx.session["recon_result"]["dns_map"]
    if existing_targets or dns_map:
        # A resumed recon phase (entry_point="recon" on a session that already has partial
        # recon_result — see resume_session/main.py) starts a brand-new tool-calling conversation
        # with no memory of the earlier attempt; without this, it would blindly redo every
        # dns_lookup/nmap call the interrupted attempt already paid for. Telling the model what's
        # already recorded (the dedup guard above is the hard backstop, this is what avoids the
        # wasted tool calls in the first place) lets it pick up with whatever's left instead.
        # Real, confirmed incident: a session interrupted before the model ever called
        # record_target (recon can run many steps — CT/subfinder/DNS/whois/wayback/shodan — before
        # the model explicitly "commits" a target) resumed with existing_targets still empty, so
        # this addendum never fired even though dns_map already held 5+ resolved hosts from
        # dns_lookup/subdomain_enum — the resumed run redid crt_sh_lookup/subfinder/subdomain_enum
        # and every dns_lookup call from scratch. dns_map is checked here too since it's filled in
        # deterministically from every dns_lookup/subdomain_enum result regardless of whether the
        # model ever calls record_target for it.
        already = ", ".join(
            f"{t.get('host')}:{t.get('port')}" if t.get("port") is not None else str(t.get("host"))
            for t in existing_targets if t.get("host")
        )
        task += (
            "\n\nThis is a resumed recon phase — an earlier, interrupted attempt already made "
            "progress, don't redo the same tool calls unless something looks incomplete."
        )
        if already:
            task += f" Recorded targets: {already}."
        if dns_map:
            known_hosts = ", ".join(f"{host} -> {', '.join(ips)}" for host, ips in dns_map.items())
            task += (
                f" Subdomain enumeration/DNS resolution already ran this session and resolved: "
                f"{known_hosts} — don't repeat crt_sh_lookup/subfinder/subdomain_enum/dns_lookup for "
                "these unless coverage looks incomplete."
            )
        task += " Continue with whatever in scope hasn't been covered yet."
    if enumeration_enabled and not has_wildcard_entry:
        # The model only sees the "*." convention explained for scope entries that actually carry
        # it (RECON_PROMPT) — when it's the checkbox that turned this on instead, spell out the
        # same expectation here so the tool being present isn't a mystery.
        task += (
            "\n\nSubdomain enumeration is enabled for this project (a project-level toggle, "
            "independent of any *.domain scope entry) — actively enumerate subdomains for every "
            "target listed above via crt_sh_lookup and subdomain_enum, then treat everything they "
            "turn up as part of this scan, the same as you would for a *.domain.com entry."
        )
    task += _out_of_scope_task_addendum(ctx.session)
    task += _out_of_scope_notes_task_addendum(ctx.session)
    task += _custom_instructions_task_addendum(ctx.session)
    task += _goal_task_addendum(ctx.session)
    task += _program_url_task_addendum(ctx.session)
    task += _custom_user_agent_task_addendum(ctx.session)
    task += _custom_headers_task_addendum(ctx.session)
    task += _plan_task_addendum(ctx.session, "recon")
    task += _open_hypotheses_task_addendum(ctx.session)
    task += _previously_resolved_hypotheses_task_addendum(ctx.session)
    task += subagent_addendum
    await _run_llm_tool_loop(ctx, RECON_PROMPT, task, tools, "recon", execute_tool=execute, expect_json_final=False, plan_phase="recon")
    recon_result = ctx.session["recon_result"]
    logger.debug("core: session=%s recon phase found %d target(s)", ctx.session_id, len(recon_result["targets"]))
    _mark_phase_finished(ctx.session, "recon")
    return recon_result


# Deliberately plain module constants, not env vars -- same tuning-knob precedent as
# _STALL_REPEAT_THRESHOLD/_MAX_IDENTICAL_FAILURES_PER_PHASE above, not every dial in this file
# needs to be externally configurable.
_AUTO_DELEGATE_HOST_THRESHOLD = 4  # fewer discovered "overflow" hosts than this -> not worth the delegation overhead
_AUTO_DELEGATE_MAX_HOSTS = 10  # a bound on one subagent task's own scope, not a truncation of real recon data -- the rest just isn't auto-delegated this pass
# A real timeout budget, unlike the count-based dials above -- env-configurable like every other
# tool/LLM timeout in this project. Real incident this fixes: a 6-host auto-delegated batch got the
# same flat SUBAGENT_TASK_TIMEOUT_SECONDS (900s default) a single-host, model-triggered delegation
# gets, and hit that deadline after 29 genuinely successful tool calls with no final report ever
# produced -- 900s split six ways is not a realistic per-host budget for a whatweb+ffuf+wayback_urls
# +ssl_cert_info sweep of each. Scaled by len(batch) at the one call site that actually batches
# multiple hosts into a single task (_delegate_to_subagent_impl's own default stays exactly 900s
# for every ordinary, single-task delegation, which was never the problem).
_AUTO_DELEGATE_TIMEOUT_PER_HOST_SECONDS = int(os.getenv("SUBAGENT_AUTO_OVERFLOW_TIMEOUT_PER_HOST_SECONDS", "300"))


def _dedupe_hosts_by_dns_identity(hosts: list[str], dns_map: dict) -> list[str]:
    """Collapses a host list so a hostname and its own resolved IP never count as two DISTINCT
    hosts, using the same dns_map (hostname -> resolved IP list, agent/core.py's _run_recon) the
    Recon tab template already relies on for its own hostname<->IP reverse lookup. Keeps the
    FIRST occurrence of each real, distinct host in `hosts`' own order.

    Real, confirmed incident this fixes: recon_result["targets"] can record the same physical host
    twice under two different identifiers (a hostname from a whatweb/httpx probe, its own resolved
    IP from nmap's own IP-based output) -- both `_auto_delegate_recon_overflow` and
    `_auto_delegate_analyze_overflow` deduped their own candidate host list by literal string only,
    so this counted as two "secondary hosts" worth splitting off to a subagent instead of one.
    Confirmed live: a real target's hostname and its own dns_map-confirmed resolved IP were both handed
    to a subagent this way -- its first action was to re-run the identical nmap scan Recon had
    already just run against the same physical target, and the resulting burst of near-simultaneous
    requests is a plausible trigger for the WAF/rate-limit cascade the rest of that session then
    spent its remaining budget fighting.
    """
    claimed: set[str] = set()
    kept: list[str] = []
    for host in hosts:
        identity = {host}
        resolved_ips = dns_map.get(host)
        if resolved_ips:
            identity.update(resolved_ips)
        else:
            for hostname, ips in dns_map.items():
                if host in ips:
                    identity.add(hostname)
                    break
        if identity & claimed:
            continue
        claimed.update(identity)
        kept.append(host)
    return kept


async def _auto_delegate_recon_overflow(ctx: RunContext, target: str, recon_result: dict) -> None:
    """Deterministic auto-delegation, not a suggestion the model has to notice and choose to act
    on: once Recon finishes, hand a deeper OSINT sweep of whatever it discovered BEYOND the
    operator's own literally-typed scope (in-scope only via a wildcard entry or "Enumerate
    subdomains") to an enabled Subagent, without asking the model.

    Real incident this replaces: a soft prompt-level nudge (_subagent_delegation_extras) confirmed
    present in the task text and confirmed available in the tool schema, across two real
    production sessions with an enabled profile — zero delegate_to_subagent calls either time. The
    model's own judgment on whether to use this feature turned out not to be reliable enough to
    depend on, so this one specific, well-bounded case (secondary discovered hosts that only ever
    got a basic port/service scan, needing a deeper look while the main agent moves on to Analyze
    on the primary ones) no longer waits for that judgment at all.

    "Overflow" hosts are real["targets"] entries whose host is neither one of the operator's own
    typed scope entries (extract_hostname match) nor already auto-delegated this session
    (session["auto_delegated_hosts"], so a later resume of an already-auto-delegated recon never
    redoes it) — and, as a hard backstop, only ever a host is_target_allowed() itself already
    considers in scope (the exact same check every real tool dispatch is gated on; this reuses it
    rather than re-deriving its own notion of "in scope").

    Reuses _delegate_to_subagent_impl directly — same concurrency cap, same task tracking, same
    auto-push delivery an operator-triggered delegation already gets — just triggered by code
    instead of waiting for a model tool call. A no-op (returns immediately) when no profile is
    enabled, or fewer than _AUTO_DELEGATE_HOST_THRESHOLD real overflow hosts exist — the common
    case for a small scan is this does nothing at all.
    """
    # session["auto_delegate_note"] (Plan tab, Stage 2 of the UX overhaul) is the operator-facing
    # answer to "why didn't a subagent get delegated" -- every return path below sets it, not just
    # the success path, since a silent no-op here is exactly the kind of invisible behavior the
    # operator originally flagged as confusing about this whole feature.
    profiles = get_enabled_profiles(ctx.session.get("enabled_subagent_ids"))
    if not profiles:
        ctx.session["auto_delegate_note"] = "No Subagent profile is enabled — auto-delegation of overflow hosts never runs without one (Subagents settings tab)."
        save_session(ctx.session_id, ctx.session)
        return

    already_delegated = ctx.session.setdefault("auto_delegated_hosts", [])
    literal_scope_hosts = {extract_hostname(entry.strip()) or entry.strip() for entry in target.split(",") if entry.strip()}

    seen: set[str] = set()
    candidates: list[str] = []
    for entry in recon_result.get("targets", []):
        host = entry.get("host")
        if not host or host in seen or host in already_delegated or host in literal_scope_hosts:
            continue
        seen.add(host)
        if is_target_allowed(host):
            candidates.append(host)

    candidates = _dedupe_hosts_by_dns_identity(candidates, recon_result.get("dns_map", {}))

    if len(candidates) < _AUTO_DELEGATE_HOST_THRESHOLD:
        ctx.session["auto_delegate_note"] = (
            f"Only {len(candidates)} discovered host(s) outside the literal scope so far — "
            f"auto-delegation needs at least {_AUTO_DELEGATE_HOST_THRESHOLD} before it's worth the overhead."
        )
        save_session(ctx.session_id, ctx.session)
        return

    batch = candidates[:_AUTO_DELEGATE_MAX_HOSTS]
    profile_name = profiles[0]["name"]
    task_description = (
        f"Recon already confirmed these {len(batch)} secondary hosts are in scope but only got a "
        f"basic port/service scan, nothing deeper: {', '.join(batch)}\n\n"
        "Run a real OSINT/fingerprinting sweep on each: identify the actual technology stack "
        "(whatweb), check for exposed directories/files worth a closer look (ffuf, only if a "
        "fitting wordlist is available), pull historical URLs that might reveal old/forgotten "
        "endpoints (wayback_urls), and check the TLS certificate for anything notable "
        "(ssl_cert_info, e.g. an unexpected SAN naming yet another host). Report concretely, per "
        "host, what you actually found — the main agent has no recording tools available to you, "
        "so put every real fact in your summary; vague summaries aren't useful."
    )

    result = await _delegate_to_subagent_impl({
        "subagent_name": profile_name,
        "task_description": task_description,
        "_session_id": ctx.session_id,
        "_session": ctx.session,
        "_triggered_by": "auto_overflow",
        "_timeout_seconds": len(batch) * _AUTO_DELEGATE_TIMEOUT_PER_HOST_SECONDS,
    })
    if result.get("status") == "ok":
        already_delegated.extend(batch)
        ctx.session["auto_delegate_note"] = f"Auto-delegated {len(batch)} overflow host(s) to {profile_name!r}: {', '.join(batch)}."
        save_session(ctx.session_id, ctx.session)
        _subagent_logger.debug(
            "core: session=%s auto-delegated %d overflow host(s) to subagent=%r task=%s",
            ctx.session_id, len(batch), profile_name, result.get("task_id"),
        )
    else:
        ctx.session["auto_delegate_note"] = (
            f"{len(batch)} overflow host(s) qualified, but delegation didn't start: "
            f"{result.get('reason') or result.get('error')}"
        )
        save_session(ctx.session_id, ctx.session)
        _subagent_logger.debug(
            "core: session=%s auto-delegation of %d overflow host(s) did not start: %s",
            ctx.session_id, len(batch), result.get("reason") or result.get("error"),
        )


_CORS_RELATED_KEYWORDS = ("cors", "cross-origin", "cross origin", "access-control-allow-origin")

# Real, actionable escape hatch — not just words in the rejection message that the gate itself
# never actually honors. A finding whose own evidence already documents a genuine subdomain
# takeover (the one thing that would make a same-suffix-only trust pattern exploitable after
# all) is allowed to keep "qualifying" instead of being rejected forever in a loop the model can
# never satisfy. Narrow, keyword-based — a human still reviews before submitting either way —
# but it means the promise made in the rejection text below is one the model can actually meet.
_TAKEOVER_EVIDENCE_KEYWORDS = ("takeover", "dangling", "unclaimed", "not configured", "nxdomain", "no such")


def _cors_qualifying_conflict(session: dict, finding: dict) -> str | None:
    """Deterministic gate, not a silent correction: real, observed incident — a model tested CORS
    reflection only via nuclei's cors-misconfig template (which only ever generates a random
    label under the TARGET'S OWN domain), then wrote up "reflects any arbitrary origin" and
    marked it qualifying, on evidence that only ever proved the narrower "trusts its own
    subdomains" pattern. cors_check (native.py) is the real, deterministic check for this — it
    fires one request with a same-suffix origin and one with a genuinely unrelated one, and its
    verdict is tracked here per hostname (session["cors_check_verdicts"]).

    Whitelist, not blacklist — closes a real gap the earlier blacklist version had: a model that
    simply never calls cors_check at all (still entirely possible; ANALYZE_PROMPT/DEEP_DIVE_ADDENDUM
    only recommend it, nothing forces the call) used to sail straight through with no verdict on
    record at all. Now "qualifying" on a CORS finding requires POSITIVE proof — cors_check's
    verdict for a host this finding is about must actually be reflects_any_origin, or the finding's
    own evidence must document a real subdomain takeover — not just "nothing contradicts it yet".
    same-suffix-only, no-reflection, inconclusive, AND never-checked-at-all are all treated the
    same here: none of them is proof of a wildcard bug, so none of them earns "qualifying".

    Returns a concrete, actionable error string (not None) whenever a finding is actually about
    CORS (a separate keyword check from the hostname match below — a finding merely mentioning a
    host cors_check happened to run against, but about something else entirely, e.g. an unrelated
    SQLi on the same host, must never get caught by this) AND claims
    qualifies_for_bounty="qualifying" without that positive proof. The caller returns this as a
    tool error instead of persisting the finding — record_finding itself is not blocked, only this
    one claim is; the model's very next call (e.g. the same finding with qualifies_for_bounty
    "unclear" instead) succeeds immediately, no loop, nothing else in the session is touched.

    None whenever there's no real conflict: qualifies_for_bounty isn't "qualifying"; the finding
    isn't CORS-related at all; cors_check already confirmed reflects_any_origin for a host this
    finding is about; or the finding's own evidence already documents a real subdomain takeover.
    """
    if finding.get("qualifies_for_bounty") != "qualifying":
        return None
    haystack_full = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('technology', '')}".lower()
    if not any(keyword in haystack_full for keyword in _CORS_RELATED_KEYWORDS):
        return None
    evidence_haystack = f"{finding.get('evidence_ref', '')} {finding.get('description', '')} {finding.get('reproduction_steps', '')}".lower()
    if any(keyword in evidence_haystack for keyword in _TAKEOVER_EVIDENCE_KEYWORDS):
        return None

    verdicts = session.get("cors_check_verdicts") or {}
    matching_hosts = [hostname for hostname in verdicts if hostname and hostname.lower() in haystack_full]
    if any(verdicts[hostname] == "reflects_any_origin" for hostname in matching_hosts):
        return None  # a genuinely unrelated origin was actually, definitively reflected — real proof

    if not matching_hosts:
        return (
            "This CORS finding claims qualifies_for_bounty=\"qualifying\", but cors_check has not "
            "been run yet for any host it mentions — a scanner's own same-suffix test (e.g. "
            "nuclei's cors-misconfig) never proves \"reflects any origin\" by itself. Call "
            "cors_check for the relevant host, then call record_finding again with the real "
            "verdict (or qualifies_for_bounty \"unclear\"/\"non_qualifying\" if it doesn't confirm "
            "a genuinely unrelated origin)."
        )
    return (
        f"cors_check's last verdict for {', '.join(matching_hosts)} does not confirm a genuinely "
        "unrelated origin is reflected (same-suffix-only, no reflection, or inconclusive — none of "
        "those proves a wildcard CORS bug), so this cannot be \"qualifying\" yet. Call "
        "record_finding again: rewrite it with qualifies_for_bounty \"unclear\" or "
        "\"non_qualifying\", re-run cors_check if the target's behavior may have changed, or, if "
        "you have separately confirmed a real, working subdomain takeover, describe it explicitly "
        "in evidence_ref."
    )


# Matches agent/tools/native.py's _VALID_PLAN_PHASES membership (a set there, since that only
# ever needs "is this a real phase name" — this tuple is the real pipeline order for DISPLAY,
# used by _apply_updated_plan below to keep the Plan tab in a stable recon -> analyze -> exploit
# order regardless of which order phase entries actually get written in.
_PLAN_PHASE_ORDER = ("recon", "analyze", "exploit")


def _mark_phase_started(session: dict, phase_name: str) -> None:
    """Deterministic phase-level timing for the Plan tab's duration display (session["phase_timings"],
    a plain phase_name -> {started_at, finished_at} dict, independent of whether/when the model ever
    calls update_plan at all -- unlike task/subtask-level timing, which can only ever be a best-effort
    guess from the model's own irregular reporting, a PHASE's start/end is a fact this file's own
    control flow already knows with certainty, at the exact moment _run_recon/_run_analyze/_run_exploit
    actually begins/ends. setdefault, not overwrite: a resumed phase (interrupted, then continued)
    keeps its original start time, same "don't reset on resume" convention run_session's own
    session["started_at"] already established for the whole session.
    """
    timings = session.setdefault("phase_timings", {})
    timings.setdefault(phase_name, {}).setdefault("started_at", datetime.now(timezone.utc).isoformat())


def _mark_phase_finished(session: dict, phase_name: str) -> None:
    """Companion to _mark_phase_started -- always overwrites (the LAST real completion of this
    phase wins, e.g. a deep-dive re-entering exploit after the session already finished once)."""
    timings = session.setdefault("phase_timings", {})
    phase_timing = timings.setdefault(phase_name, {})
    finished_at = datetime.now(timezone.utc)
    # A genuinely non-monotonic system clock (confirmed live: the machine's own local clock
    # stepped backward by just over a second mid-session) makes finished_at come out EARLIER than
    # this same phase's own started_at -- format_duration_between's max(0, ...) clamp then silently
    # shows "0s" for what could be a much longer real phase on a bigger clock step, with nothing
    # anywhere flagging that the underlying timestamps are actually inconsistent. Not fixable here
    # (there's no retroactive way to know what the "real" elapsed time should have been once the
    # clock has already lied), but at least made observable in debug.log instead of silently
    # masquerading as a suspiciously fast phase.
    started_at_raw = phase_timing.get("started_at")
    if started_at_raw:
        try:
            started_at = datetime.fromisoformat(started_at_raw)
        except ValueError:
            started_at = None
        if started_at is not None and finished_at < started_at:
            logger.debug(
                "core: session=%s phase=%s finished_at (%s) is EARLIER than its own started_at (%s) "
                "-- the system clock appears to have stepped backward mid-session; this phase's "
                "shown duration will be clamped to 0 rather than reflecting real elapsed time",
                session.get("session_id"), phase_name, finished_at.isoformat(), started_at_raw,
            )
    phase_timing["finished_at"] = finished_at.isoformat()


def _currently_active_phase(session: dict) -> str | None:
    """Which phase was genuinely in flight at this exact moment -- the one with a real started_at
    (_mark_phase_started, code-driven and exact) but no finished_at yet. None only if a crash
    happens before _run_recon ever calls _mark_phase_started at all (effectively never in
    practice, since that's the very first thing run_session's own try block does).

    Built specifically for run_session's own except-Exception handler, which used to log a crash
    against session["resumable_from"] instead -- that field answers a different question
    (compute_resume_entry_point: "where should a RESUMED run start"), and is very often a LATER
    phase than the one that actually crashed. Real incident this fixes: Analyze crashed mid-phase
    (an LLM provider outage) after already recording 10 findings via record_finding -- resumable_from
    correctly came out "exploit" (there ARE findings to exploit now), but the failure log entry then
    read "[exploit] failed: APIConnectionError", flatly misattributing an Analyze-phase crash to a
    phase that hadn't even started yet. Iterates phase_timings.items() rather than a fixed phase
    order -- session_timings covers recon/analyze/exploit/chain/validate, more phases than
    _PLAN_PHASE_ORDER's three, and these phases run strictly sequentially in run_session, so at
    most one is ever genuinely "started but not finished" at a time regardless of dict order.
    """
    timings = session.get("phase_timings") or {}
    for phase, timing in timings.items():
        if timing.get("started_at") and not timing.get("finished_at"):
            return phase
    return None


def _stamp_task_timings(new_tasks: list[dict], previous_tasks: list[dict], phase_started_at: str | None = None) -> None:
    """Best-effort start/finish timestamps for individual tasks/subtasks (Plan tab display),
    mutating new_tasks in place. Unlike phase-level timing (_mark_phase_started/_mark_phase_
    finished, code-driven and exact), this can only ever be a guess derived from the model's own
    irregular update_plan submissions — it doesn't reliably mark a subtask "active" the moment it
    actually starts working on it (same "voluntary reporting is unreliable" gap _phase_has_started
    already covers one level up).

    Real incident this fixes: the first version of this function set BOTH started_at and
    finished_at to the exact same "now" for anything first observed already "done" — an honest
    intent ("we don't know exactly when it started"), but the resulting UI showed a literal "0s"
    next to real work that took real minutes, which reads as "this did nothing" or "this was
    skipped", not "timing unknown" — a real, confirmed operator complaint, and a strictly worse
    outcome than a genuine (if approximate) number. This version never collapses to a zero-width
    window: a task/subtask's own started_at is anchored to the LATEST real boundary already known
    before it (the previous task's own finished_at, or phase_started_at for the very first one) —
    a real, non-fabricated lower bound, never later than when it's actually observed done. Several
    subtasks that all resolve together in the exact same update_plan call (the common case: the
    model reports a whole batch of steps done at once) would otherwise all collapse to that same
    single instant even with a shared lower bound — evenly splitting the known [boundary, now]
    window across however many resolve together in that call turns that into real, distinct,
    still fully real (bounded by two true timestamps) numbers instead of N more "0s"s.

    Matched by TEXT against the previously-persisted task/subtask of the same name — there's no
    stable id, so a task the model rewords between revisions loses its prior timing rather than
    ever misattributing it to the wrong task (a safe degradation, not a crash). Neither timestamp
    is ever overwritten once set, so a later resubmission doesn't reset an already-known time.
    """
    now_dt = datetime.now(timezone.utc)
    now = now_dt.isoformat()
    previous_by_text = {t.get("text"): t for t in previous_tasks}

    def _parse(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    task_boundary = _parse(phase_started_at)
    for task in new_tasks:
        prev_task = previous_by_text.get(task.get("text")) or {}
        if prev_task.get("started_at"):
            task["started_at"] = prev_task["started_at"]
        elif task.get("status") != "pending":
            task["started_at"] = (task_boundary or now_dt).isoformat()
        if prev_task.get("finished_at"):
            task["finished_at"] = prev_task["finished_at"]
        elif task.get("status") == "done":
            task["finished_at"] = now

        prev_subtasks_by_text = {s.get("text"): s for s in (prev_task.get("subtasks") or [])}
        subtasks = task.get("subtasks") or []
        window_start = _parse(task.get("started_at")) or task_boundary or now_dt
        newly_resolving = [
            s for s in subtasks
            if s.get("status") != "pending" and not (prev_subtasks_by_text.get(s.get("text")) or {}).get("started_at")
        ]
        span_seconds = max(0.0, (now_dt - window_start).total_seconds())
        step = span_seconds / len(newly_resolving) if newly_resolving else 0.0
        slot = 0
        for subtask in subtasks:
            prev_subtask = prev_subtasks_by_text.get(subtask.get("text")) or {}
            is_newly_resolving = subtask in newly_resolving
            if prev_subtask.get("started_at"):
                subtask["started_at"] = prev_subtask["started_at"]
            elif subtask.get("status") != "pending":
                subtask["started_at"] = (window_start + timedelta(seconds=step * slot)).isoformat()
            if prev_subtask.get("finished_at"):
                subtask["finished_at"] = prev_subtask["finished_at"]
            elif subtask.get("status") == "done":
                subtask["finished_at"] = (window_start + timedelta(seconds=step * (slot + 1))).isoformat() if step else now
            if is_newly_resolving:
                slot += 1

        if task.get("finished_at"):
            task_boundary = _parse(task["finished_at"]) or task_boundary


def _phase_has_started(session: dict, phase_name: str) -> bool:
    """Whether phase_name's own real work has actually begun -- the same deterministic signal
    status_badge's phase suffix already trusts (session["logs"]'s own entries are tagged by the
    real phase they ran in, agent/core.py's _run_llm_tool_loop). _apply_updated_plan uses this
    (not "does a plan entry already exist") to decide whether an earlier phase may still freely
    re-seed this phase's own forward-looking sketch -- a forward-seed's mere existence was never
    the danger the original cross-phase-mislabeling incident needed protecting against; a phase
    that's already doing its own real work is.
    """
    return any(log.get("phase") == phase_name for log in session.get("logs", []))


def _apply_updated_plan(ctx: RunContext, recorded: dict, plan_phase: str) -> None:
    """Persists a validated update_plan submission (agent/tools/native.py's own return value —
    validation already happened there, this only persists) into session["plan"]. Called from every
    phase's execute() closure the tool is offered in, same "validate in the native tool, persist in
    agent/core.py" split record_target/_persist_new_finding above already follow.

    plan_phase is the REAL, deterministic phase this call is actually running in (the same literal
    already passed to _run_llm_tool_loop's own plan_phase= argument at this exact call site) — NOT
    trusted from whatever "phase" string the model put inside its own submitted phases[] entries.
    Real incident this fixes, confirmed live: a session's Analyze-phase update_plan call submitted
    its own new tasks (whatweb/nuclei/authenticated_crawl — all Analyze-tool-phase work) mislabeled
    as phase="recon" — because update_plan's contract is "resubmit the whole plan, not a diff", this
    silently OVERWROTE and destroyed the real, already-accurate recon-phase plan from three earlier
    calls, and the exploit phase later never got a plan entry at all since nothing ever called
    update_plan with phase="exploit" for real. Trusting the model's own free-text phase field for
    something this destructive turned out exactly as reliable as every other "the model has to keep
    a duplicated field in sync on its own" case this project has already hit (see
    _derive_plan_status's own docstring for the same lesson one level down).

    Fix: this call's own phase entry (matching plan_phase, the real calling context) always
    replaces whatever was there before — that part is unconditional, same as ever. A submitted
    entry for a DIFFERENT phase is a forward-seed, not a correction — but "accepted only the first
    time" (this function's own earlier version) turned out to be too strict a reading of the same
    protection: RECON_PROMPT explicitly asks the model to keep revising Analyze/Exploit's own
    sketches every time a new fact lands, not just once at the very start, and it genuinely tries
    to — confirmed live, a real session submitted a full [recon, analyze, exploit] update 6 times
    across one run, and every single non-first attempt to touch analyze/exploit from within recon
    was silently dropped, even though analyze/exploit had never actually started running yet. The
    real distinction the original incident needed was never "does an entry already exist" (a
    forward-seed's own existence isn't the danger) — it's "has that phase's own real work already
    begun" (_phase_has_started below, keyed off session["logs"], the same deterministic signal
    status_badge's phase suffix already trusts). A not-yet-started phase's forward-seed can be
    freely re-seeded as many times as an earlier phase learns something new about it; the instant
    that phase's own real work starts, only a call running in THAT phase's own context may ever
    touch it again, exactly the same non-negotiable protection the original incident fix
    established — this only widens WHEN a forward-seed is still allowed, never who's allowed to
    correct an already-started phase.
    """
    plan = ctx.session.setdefault("plan", {"phases": [], "version": 0, "updated_at": None})
    submitted_by_phase = {entry["phase"]: entry for entry in recorded["phases"]}
    own_entry = submitted_by_phase.get(plan_phase)
    existing_by_phase = {entry.get("phase"): entry for entry in plan["phases"]}

    seeded_phases: list[str] = []
    ignored_phases: list[str] = []
    for phase_name, entry in submitted_by_phase.items():
        if phase_name == plan_phase:
            continue
        if _phase_has_started(ctx.session, phase_name):
            ignored_phases.append(phase_name)
            continue
        existing_by_phase[phase_name] = entry
        seeded_phases.append(phase_name)

    if own_entry is not None:
        previous_own_entry = existing_by_phase.get(plan_phase) or {}
        phase_started_at = (ctx.session.get("phase_timings", {}).get(plan_phase, {}) or {}).get("started_at")
        _stamp_task_timings(own_entry.get("tasks") or [], previous_own_entry.get("tasks") or [], phase_started_at)
        existing_by_phase[plan_phase] = own_entry

    # The Plan tab always shows the real pipeline order (recon -> analyze -> exploit), regardless
    # of which order phases were actually WRITTEN in — dict insertion order alone got this wrong
    # the instant forward-seeding landed: Recon's own first call seeds analyze/exploit (added to
    # existing_by_phase INSIDE the loop above) before its own recon entry is set via own_entry
    # right after that loop, so a plain list(existing_by_phase.values()) put analyze/exploit BEFORE
    # recon — confirmed live: a real session's persisted plan["phases"] came out
    # ['analyze', 'exploit', 'recon']. Sorting by the fixed pipeline order on every write, rather
    # than trusting whatever order entries happened to land in, makes this correct unconditionally.
    existing_by_phase = {phase: existing_by_phase[phase] for phase in _PLAN_PHASE_ORDER if phase in existing_by_phase}
    plan["phases"] = list(existing_by_phase.values())
    plan["version"] = plan.get("version", 0) + 1
    plan["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_session(ctx.session_id, ctx.session)

    if seeded_phases:
        logger.debug(
            "core: session=%s update_plan: phase=%r forward-seeded initial plan entr%s for %s "
            "(no entry existed yet for %s)",
            ctx.session_id, plan_phase, "y" if len(seeded_phases) == 1 else "ies", sorted(seeded_phases), sorted(seeded_phases),
        )
    if ignored_phases:
        logger.debug(
            "core: session=%s update_plan: ignored submitted phase(s) %s — this call is running in "
            "plan_phase=%r and those phases already have their own real entry; only a call running "
            "in that phase's own context may update it",
            ctx.session_id, sorted(ignored_phases), plan_phase,
        )
    dropped = recorded.get("_dropped_tool_names")
    if dropped:
        logger.debug("core: session=%s update_plan: dropped unknown tool name(s) %s from recommended_tools", ctx.session_id, dropped)
    logger.debug("core: session=%s update_plan: plan now has %d phase(s), version=%d", ctx.session_id, len(plan["phases"]), plan["version"])


def _sync_exploit_plan_from_findings(ctx: RunContext, current_title: str | None = None) -> None:
    """Auto-derives the Plan tab's "exploit" phase entry directly from the real findings list,
    instead of waiting on the model to voluntarily call update_plan for this phase the way Recon/
    Analyze do. Real incident this fixes: confirmed live across every real session reviewed so
    far, the Exploit phase's own plan entry was ALWAYS EMPTY, despite Exploit routinely being the
    single most tool-call-intensive phase of the whole pipeline (243 of 407 logged calls in one
    real session) — EXPLOIT_PROMPT's own update_plan mention is conditional ("if this finding
    taught you something worth remembering"), a much weaker nudge than RECON_PROMPT's forceful
    "call it once near the start of this phase", and in practice the model never once acted on it.
    Whether a finding is resolved is already a fully deterministic fact the code independently
    knows for certain — the exact same `exploited or advisory_note is not None` check
    `_run_exploit`'s own resume logic already uses — so there's no reason this should ever depend
    on the model remembering to report it. Same "only ever replace the ONE phase entry matching
    plan_phase" discipline _apply_updated_plan already established, so a model-submitted Recon/
    Analyze plan is never touched by this.

    A session that legitimately has nothing to exploit (Analyze recorded 0 findings at all) used to
    leave this phase's plan entry exactly as Recon's own initial multi-phase sketch guessed at —
    forward-seeded, "pending" — forever: _run_exploit's own while-loop never runs a single iteration
    when findings is empty, and this function was only ever called from inside that loop, so the
    0-findings case had no code path that ever marked the phase done, even once the whole session
    completed (confirmed live: a real session's Plan tab showed "Exploit 0/1", unchecked, while
    session.status was already "completed"). _run_exploit now calls this once, unconditionally,
    right when it starts — the branch below handles the empty case explicitly instead of bailing
    out with nothing recorded.
    """
    findings = ctx.session.get("findings") or []
    if findings:
        tasks = []
        # Real, confirmed incident this fixes: this list used to stay in raw findings-recording
        # order (whatever order Analyze happened to record them in), while _run_exploit's real
        # work loop processes sorted(findings, key=_exploit_priority_key) (qualifying-first, then
        # severity) -- a Medium finding recorded LAST by Analyze but processed THIRD by Exploit
        # showed up last in the Plan tab, and _stamp_task_timings' own array-order-adjacent
        # anchoring then produced genuinely wrong, overlapping timestamps for it and its
        # neighbors (two "simultaneous" exploit attempts that never actually ran at the same
        # time). Sorting here the exact same way _run_exploit's loop itself does makes the
        # displayed order — and the timing anchored to it — match what actually happened.
        for finding in sorted(findings, key=_exploit_priority_key):
            title = finding.get("title") or "Untitled finding"
            resolved = bool(finding.get("exploited")) or finding.get("advisory_note") is not None
            status = "done" if resolved else ("active" if title == current_title else "pending")
            tasks.append({
                "text": title,
                "status": status,
                "subtasks": [{
                    "text": f"Attempt exploitation ({finding.get('severity', 'Unknown')})",
                    "status": status,
                    "recommended_tools": [],
                }],
            })
    else:
        tasks = [{
            "text": "No exploit work needed",
            "status": "done",
            "subtasks": [{
                "text": "No findings were recorded for this target — nothing to exploit.",
                "status": "done",
                "recommended_tools": [],
            }],
        }]
    previous_exploit_entry = next(
        (p for p in (ctx.session.get("plan") or {}).get("phases", []) if p.get("phase") == "exploit"), {},
    )
    exploit_phase_started_at = (ctx.session.get("phase_timings", {}).get("exploit", {}) or {}).get("started_at")
    _stamp_task_timings(tasks, previous_exploit_entry.get("tasks") or [], exploit_phase_started_at)
    entry = {
        "phase": "exploit",
        "rationale": "Auto-tracked from the real findings list, one task per finding — not model-submitted.",
        "status": _derive_plan_status([t["status"] for t in tasks]),
        "tasks": tasks,
    }

    plan = ctx.session.setdefault("plan", {"phases": [], "version": 0, "updated_at": None})
    existing_by_phase = {p.get("phase"): p for p in plan["phases"]}
    existing_by_phase["exploit"] = entry
    # Same canonical recon -> analyze -> exploit ordering _apply_updated_plan enforces on every
    # write — not relied on as an invariant established elsewhere, since this function can run
    # before Recon/Analyze ever call update_plan at all (e.g. a resumed session entering straight
    # into Exploit).
    existing_by_phase = {phase: existing_by_phase[phase] for phase in _PLAN_PHASE_ORDER if phase in existing_by_phase}
    plan["phases"] = list(existing_by_phase.values())
    plan["version"] = plan.get("version", 0) + 1
    plan["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_session(ctx.session_id, ctx.session)


# (session_id, phase) -> the promoted tool-name set last actually logged for it, so
# _apply_plan_recommendations' debug line only fires again when that set changes, not on every
# single turn it's called (it's called once per turn for as long as the phase runs).
_LAST_LOGGED_PLAN_RECOMMENDATIONS: dict[tuple[str | None, str], frozenset[str]] = {}


def _apply_plan_recommendations(tool_specs: list[ToolSpec], session: dict, phase: str) -> list[ToolSpec]:
    """Reorders tool_specs so tools the model's own current plan (session["plan"]) already
    recommended for phase's still-open tasks come first, with their description prefixed so the
    model notices without needing to cross-reference the plan text itself. Never removes a tool —
    only reorders and labels ones already present, matching this project's own rule that a tool the
    model might still legitimately need is never hidden for efficiency alone (that's reserved for
    a real scope/safety boundary — the subdomain-tools-when-not-enumerated exclusion in
    _run_recon, or _tech_gate_blocked's hard skip for a confirmed-absent technology). A plan
    recommendation is a steer, not a gate. A recommendation naming a tool that isn't in tool_specs
    at all (out of this phase's category, or a name update_plan already dropped as unknown) is a
    safe no-op — nothing to reorder, no error.

    Race condition, by design not by oversight: this reads session["plan"] fresh every call, so if
    update_plan runs mid-turn (one of several tool calls in the same batch), the tool_specs already
    handed to THIS turn's remaining dispatches is stale — the next turn simply rebuilds from
    scratch and picks up the change, the same latency every other *_task_addendum already tolerates
    for a fact landing mid-turn. Never attempts to hot-swap an in-flight LLM call's own schema.

    recommended_tools only ever lives on a SUBTASK (agent/tools/native.py's update_plan) — a task
    itself never carries tools directly, so this reads phase_entry["tasks"][*]["subtasks"][*], not
    the task level.
    """
    phases = (session.get("plan") or {}).get("phases") or []
    recommended: set[str] = set()
    for phase_entry in phases:
        if phase_entry.get("phase") != phase:
            continue
        for task in phase_entry.get("tasks") or []:
            for subtask in task.get("subtasks") or []:
                if subtask.get("status") == "done":
                    continue  # a finished subtask's own recommendation no longer needs pushing forward
                recommended.update(subtask.get("recommended_tools") or [])
    if not recommended:
        return tool_specs

    promoted = [replace(spec, description=f"[Plan-recommended] {spec.description}") for spec in tool_specs if spec.name in recommended]
    rest = [spec for spec in tool_specs if spec.name not in recommended]
    if promoted:
        promoted_names = frozenset(spec.name for spec in promoted)
        cache_key = (session.get("session_id"), phase)
        # Log only when the promoted set actually changes for this session+phase, not on every
        # single turn -- real, confirmed incident (a real HackerOne session, usr_295047): the same 8-tool
        # recommendation logged 48 identical times across 12 minutes with zero new information
        # between repeats, the same "don't log trivial things" violation already fixed once for
        # await_all_running_subagent_tasks's own polling line (see that fix's own comment).
        if _LAST_LOGGED_PLAN_RECOMMENDATIONS.get(cache_key) != promoted_names:
            _LAST_LOGGED_PLAN_RECOMMENDATIONS[cache_key] = promoted_names
            logger.debug(
                "core: session=%s plan recommends %d tool(s) for phase=%s: %s",
                session.get("session_id"), len(promoted), phase, [spec.name for spec in promoted],
            )
    return promoted + rest


def _plan_task_addendum(session: dict, phase: str) -> str:
    """Empty until the model has actually called update_plan at least once for THIS phase
    (session["plan"]["phases"], sessions/store.py's create_session() default: empty list) — shows
    the phase's own current task/subtask tree back to the model before it acts, the same "read your
    own prior persisted state before continuing" shape _reconfirmed_findings_task_addendum already
    gives for a different kind of state. Appended at every phase's task-text assembly (recon,
    analyze, exploit-per-finding, chain, reverify) — chain and reverify both read phase="exploit"'s
    own plan tasks, there being no separate plan phase key for either of those exploit-side
    sub-flows.
    """
    phases = (session.get("plan") or {}).get("phases") or []
    matching = [p for p in phases if p.get("phase") == phase]
    if not matching:
        return ""
    lines: list[str] = []
    for phase_entry in matching:
        rationale = phase_entry.get("rationale")
        if rationale:
            lines.append(f"Rationale: {rationale}")
        for task in phase_entry.get("tasks") or []:
            lines.append(f"- [{task.get('status', 'pending')}] {task.get('text')}")
            for subtask in task.get("subtasks") or []:
                tools = ", ".join(subtask.get("recommended_tools") or []) or "none suggested"
                lines.append(f"  - [{subtask.get('status', 'pending')}] {subtask.get('text')} (tools: {tools})")
    if not lines:
        return ""
    return (
        "\n\nYour own current plan for this phase — call update_plan again to refine it as you "
        "learn more, don't just leave it stale once a fact changes what's actually worth doing "
        "next (a couple of steps finishing and telling you something concrete is exactly the "
        "moment to revise recommended_tools and add/adjust subtasks below):\n" + "\n".join(lines)
    )


async def _structure_hypothesis_text(ctx: RunContext, raw_text: str) -> dict:
    """Splits an operator's single free-text hypothesis submission (session_fragment.html's
    Hypotheses tab form -- one box, not the earlier separate text+evidence field pair) into a
    clean {text, evidence} pair via one quick, tool-less LLM call — same "small, focused JSON-
    extraction, no tools needed" shape as _repair_json_reply, not the full _run_llm_tool_loop
    machinery. Real requirement this exists for: an operator wants to paste a whole write-up
    copied from a DIFFERENT scan (a finding's own title, evidence, severity, whatever they had) and
    have it become a clean hypothesis, not have to manually pre-split it into two fields themselves.

    Never loses the operator's own input: any failure (empty/unparseable response, a genuinely
    empty raw_text) falls back to using raw_text verbatim as `text` with empty `evidence` — the
    same "extract what we can, never discard the user's real input" discipline this project already
    applies to malformed tool-call JSON elsewhere (agent/llm_client.py).
    """
    raw_text = raw_text.strip()
    if not raw_text:
        return {"text": "", "evidence": ""}
    messages = [
        {"role": "system", "content": HYPOTHESIS_STRUCTURING_PROMPT},
        {"role": "user", "content": raw_text},
    ]
    try:
        response = await _llm_complete(ctx, messages, None)
    except (SessionStopRequested, asyncio.CancelledError):
        raise
    except Exception as exc:
        logger.debug("core: session=%s hypothesis structuring call failed (%s), falling back to raw text", ctx.session_id, exc)
        return {"text": raw_text, "evidence": ""}
    parsed = _parse_json_response(response.content)
    if not isinstance(parsed, dict) or not parsed.get("text"):
        logger.debug("core: session=%s hypothesis structuring produced no usable JSON, falling back to raw text", ctx.session_id)
        return {"text": raw_text, "evidence": ""}
    return {"text": str(parsed["text"]), "evidence": str(parsed.get("evidence") or "")}


def _persist_new_hypothesis(ctx: RunContext, recorded: dict, phase: str, source: str = "agent") -> None:
    """Appends a record_hypothesis result to session["hypotheses"] — a suspected-but-unconfirmed
    lead, distinct from both record_target (a bare fact) and record_finding (a proven issue).
    Shared shape/id convention with subagent task_id (uuid4 hex, short) so a hypothesis can be
    referenced/matched later without needing a human-typed identifier.

    source="agent" (default) for every existing call site (the model's own record_hypothesis tool
    call) — unchanged. source="user" is the operator's own submission (New Project form's
    pre-scan hints, a live hypothesis drained by _drain_pending_hypotheses, or a post-completion
    verification request), distinguished in the UI so an operator can tell their own leads apart
    from ones the agent found on its own.
    """
    hypotheses = ctx.session.setdefault("hypotheses", [])
    entry = {
        "id": uuid.uuid4().hex[:12],
        "text": recorded["text"],
        "evidence": recorded.get("evidence") or "",
        "source_phase": phase,
        "source": source,
        "status": "unconfirmed",
        "resolution_note": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "resolved_at": None,
    }
    source_tool = recorded.get("source_tool")
    if source_tool:
        _append_tool_timeline(entry, [{"tool": source_tool, "stage": "discovery"}])
    hypotheses.append(entry)
    # Reload-merge-save (_reload_merge_save, sessions/store.py), not a blind save_session(
    # ctx.session_id, ctx.session) -- same fix as _persist_new_finding just below: ctx.session can
    # be a long-lived stale snapshot (a chat turn, or _update_asset_graph firing off the shared
    # per-tool-call path) that predates a concurrent writer's own fresher save. Only THIS one new
    # hypothesis is merged onto whatever's freshest on disk right now; ctx.session's own in-memory
    # hypotheses list (appended above) still stays current for the rest of THIS run's own reads
    # (resolve_hypothesis, the end-of-run hypothesis-resolution gate).
    _reload_merge_save(ctx.session_id, lambda s: s.setdefault("hypotheses", []).append(entry))
    logger.debug("core: session=%s %s: recorded hypothesis id=%s source=%s text=%r", ctx.session_id, phase, entry["id"], source, entry["text"])


async def _classify_and_record_recon_item(ctx: RunContext, raw_text: str, phase: str) -> dict | None:
    """Classifies a single operator-submitted Recon tab text-box entry (session_fragment.html's
    "Add target or note" form) as either a new scope target or a free-text idea/lead, and persists
    it as a real hypothesis entry either way — no new investigation logic of its own, the normal
    hypothesis machinery (run_hypothesis_verification / the live drain loop, both of which already
    have full recon+scan+exploit tool access — see _hypothesis_verification_tool_specs) takes it
    from there. Returns the persisted hypothesis dict, or None if raw_text was empty/unusable.

    Comma-split, each piece run through validate_scope_entry — the EXACT same validation the New
    Project form's own Target(s) field uses (agent/tools/builders/validators.py), not a
    reimplementation. Only when EVERY piece validates cleanly is this treated as a target
    submission; a single piece of prose anywhere in the input (even alongside otherwise clean
    targets) falls through to the free-text path instead, on the theory that a real sentence
    mixed with a domain name is an idea to structure, not a scope list to append to verbatim.
    """
    raw_text = raw_text.strip()
    if not raw_text:
        return None

    pieces = [p.strip() for p in raw_text.split(",") if p.strip()]
    clean_targets: list[str] = []
    all_target_shaped = bool(pieces)
    for piece in pieces:
        try:
            clean_targets.append(validate_scope_entry(piece))
        except ValueError:
            all_target_shaped = False
            break

    if all_target_shaped:
        in_scope_targets = [t for t in clean_targets if not is_target_out_of_scope(t, ctx.session.get("out_of_scope", []))]
        skipped = [t for t in clean_targets if t not in in_scope_targets]
        for skipped_target in skipped:
            logger.debug("core: session=%s %s: operator-added target %r is out of scope, skipped", ctx.session_id, phase, skipped_target)

        if in_scope_targets:
            existing = [t.strip() for t in ctx.session.get("target", "").split(",") if t.strip()]
            for target in in_scope_targets:
                if target not in existing:
                    existing.append(target)
            ctx.session["target"] = ", ".join(existing)
            # Reload-merge-save, not left to ride along on _persist_new_hypothesis's own save below
            # -- that helper now merge-saves only the one hypothesis field it owns (see its own
            # docstring), not this whole ctx.session, so a "target" change made here needs its own
            # explicit persistence or it's silently lost the moment a concurrent writer's fresher
            # session gets loaded for the hypothesis merge. Mirrors ctx.session's own in-memory
            # value, already updated above, onto whatever's freshest on disk right now.
            _reload_merge_save(ctx.session_id, lambda s: s.__setitem__("target", ctx.session["target"]))
            if ctx.session.get("authorize_exploit"):
                authorize_exploit_targets(in_scope_targets, bool(ctx.session.get("enumerate_subdomains")))
            joined = ", ".join(in_scope_targets)
            skipped_note = f" ({len(skipped)} entry(ies) skipped, already out of scope)" if skipped else ""
            structured = {
                "text": f"Operator added new target(s) mid-session: {joined} — investigate for recon findings/vulnerabilities.{skipped_note}",
                "evidence": "",
            }
        else:
            # Every entry was out of scope -- deterministic note, no LLM call needed, and the
            # operator's own submission still isn't silently dropped.
            structured = {
                "text": f"Operator tried to add target(s) already excluded from this session's scope: {', '.join(clean_targets)}",
                "evidence": raw_text,
            }
        _persist_new_hypothesis(ctx, structured, phase, source="user")
        return ctx.session["hypotheses"][-1]

    # Free text -- exact same LLM-structuring path the Hypotheses tab already uses.
    structured = await _structure_hypothesis_text(ctx, raw_text)
    if not structured["text"]:
        return None
    _persist_new_hypothesis(ctx, structured, phase, source="user")
    return ctx.session["hypotheses"][-1]


def _resolve_hypothesis(ctx: RunContext, resolved: dict, phase: str, target_hypothesis_id: str | None = None) -> None:
    """Matches resolve_hypothesis's own hypothesis_text against session["hypotheses"] and closes
    the match out. Matched loosely (case-insensitive substring, either direction) rather than exact
    string equality — the model is asked to reuse the hypothesis's own original text, but "closely"
    is the realistic bar, same tolerance record_chain_result's reverified_findings matching already
    applies to finding titles. The FIRST still-open ("unconfirmed") match wins; a hypothesis already
    resolved is left alone rather than re-resolved by a second, looser match. No match at all is a
    silent no-op (logged, not errored) — a typo/paraphrase here shouldn't cost the whole tool call,
    same "don't fail over one bad sub-field" tolerance this project already applies elsewhere.

    target_hypothesis_id, when given, means the caller already knows exactly which hypothesis this
    pass is about (run_hypothesis_verification investigates exactly one, by id) — matched by id
    directly instead of the fuzzy "unconfirmed" text search above, which otherwise could never
    re-resolve a hypothesis that isn't "unconfirmed" anymore (the whole point of re-checking an
    already-confirmed/ruled-out one). The gate's own multi-hypothesis pass (several open hypotheses
    investigated in one shared trace, no single target) never passes this, so its existing
    fuzzy/unconfirmed-only behavior is unchanged.
    """
    hypotheses = ctx.session.setdefault("hypotheses", [])
    if target_hypothesis_id is not None:
        match = next((h for h in hypotheses if h.get("id") == target_hypothesis_id), None)
    else:
        needle = resolved["hypothesis_text"].strip().lower()
        match = next(
            (h for h in hypotheses if h.get("status") == "unconfirmed" and (needle in h.get("text", "").lower() or h.get("text", "").lower() in needle)),
            None,
        )
    if match is None:
        logger.debug("core: session=%s %s: resolve_hypothesis found no open match for %r — skipped", ctx.session_id, phase, resolved["hypothesis_text"])
        return
    match["status"] = resolved["status"]
    match["resolution_note"] = resolved.get("note") or None
    match["resolved_at"] = datetime.now(timezone.utc).isoformat()
    resolving_tool = resolved.get("resolving_tool")
    if resolving_tool:
        _append_tool_timeline(match, [{"tool": resolving_tool, "stage": "verification"}])
    # session["past_hypothesis_outcomes"] is this lineage's own cross-rescan memory of hypotheses,
    # the counterpart to _run_reverify's past_reverification_outcomes -- never reset, carried forward
    # by every one of main.py's rescan routes, read back by
    # _previously_resolved_hypotheses_task_addendum so a hypothesis re-raised by a later rescan isn't
    # investigated as a totally fresh unknown. Capped per hypothesis TEXT, same reasoning as the
    # findings ledger's per-title cap.
    ledger = ctx.session.setdefault("past_hypothesis_outcomes", [])
    ledger.append({
        "text": match["text"],
        "status": match["status"],
        "resolution_note": match["resolution_note"],
        "resolved_at": match["resolved_at"],
    })
    kept_for_text = [e for e in ledger if e.get("text") == match["text"]][-_MAX_PAST_HYPOTHESIS_OUTCOMES_PER_TEXT:]
    ctx.session["past_hypothesis_outcomes"] = [e for e in ledger if e.get("text") != match["text"]] + kept_for_text
    # A Chain pass may have built a finding on this exact hypothesis while it was still open (see
    # based_on_hypothesis_ids, set in _run_chain_pass's own execute() closure) -- if it just got
    # ruled_out, that finding's premise no longer holds and nothing else in the pipeline ever
    # revisits it on its own. Flagged, never silently downgraded/removed: only a human (or a real
    # re-check) should decide whether the finding still stands on other grounds, same "never
    # discard, flag distinctly" discipline false_positive_reason already follows elsewhere.
    if match["status"] == "ruled_out":
        for finding in ctx.session.get("findings", []):
            if match["id"] in (finding.get("based_on_hypothesis_ids") or []):
                finding["needs_reverification"] = True
                note = (
                    f"Built in part on the hypothesis {match['text']!r}, which was later ruled out "
                    f"({match['resolution_note'] or 'no reason given'}) — recommend re-verifying "
                    "this finding still holds on its own remaining evidence."
                )
                finding["advisory_note"] = f"{finding['advisory_note']}\n\n{note}" if finding.get("advisory_note") else note
                logger.debug("core: session=%s %s: flagged finding=%r for reverification, based on ruled-out hypothesis id=%s", ctx.session_id, phase, finding.get("title"), match["id"])
    save_session(ctx.session_id, ctx.session)
    logger.debug("core: session=%s %s: resolved hypothesis id=%s status=%s", ctx.session_id, phase, match["id"], match["status"])


def _open_hypotheses_task_addendum(session: dict) -> str:
    """Shows still-unconfirmed hypotheses (usually recon's own leads, but any phase's) to whichever
    phase is about to run, so Analyze/Exploit can actually act on a lead instead of it only ever
    existing in session["hypotheses"] with nothing pointing the next phase at it. Empty when there
    are none open — the common case for a session that never used this mechanism at all.
    """
    open_hypotheses = [h for h in session.get("hypotheses", []) if h.get("status") == "unconfirmed"]
    if not open_hypotheses:
        return ""
    lines = [
        f"- {h['text']} (evidence: {h['evidence']})" if h.get("evidence") else f"- {h['text']}"
        for h in open_hypotheses
    ]
    return (
        "\n\nUnconfirmed hypotheses from earlier this session — real leads worth checking, not "
        "proven yet. Call resolve_hypothesis once you've actually investigated one (\"confirmed\" "
        "plus a record_finding for the real thing, or \"ruled_out\" with what you actually checked):\n"
        + "\n".join(lines)
    )


def _previously_resolved_hypotheses_task_addendum(session: dict) -> str:
    """The hypotheses counterpart to _previously_ruled_out_task_addendum: session["hypotheses"]
    used to be silently dropped on a brand-new /rescan (main.py's rescan_session), and even where it
    IS carried forward (in-place rescans, same session object), a resolved hypothesis is only ever
    shown to the phase that resolved it -- _open_hypotheses_task_addendum above only surfaces
    status=="unconfirmed" entries, so a later phase/rescan re-raising the same lead had no way to
    know it was already checked. session["past_hypothesis_outcomes"] (_resolve_hypothesis, never
    reset, carried forward by every rescan route) is what remembers it.

    Unlike findings (where "confirmed_fixed" just means the finding no longer exists to re-surface),
    a hypothesis can usefully calibrate in BOTH directions -- "already proven true, don't
    re-investigate as if it were new" is just as real a time-saver as "already ruled out". This never
    tells the model to skip investigating a rediscovered lead, only gives it the same history a human
    operator re-reading their own notes would have, so it can right-size effort instead of treating a
    repeat as a total unknown.
    """
    seen: dict[str, dict] = {}
    for entry in session.get("past_hypothesis_outcomes", []):
        text = entry.get("text")
        if not text or entry.get("status") not in ("confirmed", "ruled_out"):
            continue
        seen[text] = entry  # last write wins -- ledger is append-ordered oldest to newest
    if not seen:
        return ""
    lines = [f"- {text!r}: {entry['status']}" + (f" ({entry['resolution_note']})" if entry.get("resolution_note") else "") for text, entry in seen.items()]
    return (
        "\n\nThese hypotheses were already investigated and resolved on a prior pass/rescan of this "
        "same target — if the same lead comes up again, use this as real context to right-size "
        "effort (a quick reconfirmation may be enough for a stable result), but still verify with a "
        "real check this pass, don't assume the old resolution automatically still holds:\n"
        + "\n".join(lines)
    )


async def _persist_new_finding(ctx: RunContext, recorded: dict) -> dict | None:
    """Appends a record_finding result to session["findings"] with the CORS-conflict guard and
    found_at stamping every persistence site needs. Shared by _run_analyze, _run_exploit_for_finding's
    deep dive, and _run_reverify (plus a few narrower callers — run_focused_exploit,
    run_hypothesis_verification, run_re_reverify — that all funnel through this same choke point) —
    a genuinely new finding reported mid-loop must never be silently dropped just because one
    phase's execute closure forgot to persist it. Real incident this guards against: a real
    session had findings accidentally deleted during an unrelated cleanup; this is the same class
    of "the data existed for a moment and then quietly didn't" risk, just at creation time instead
    of deletion time. Returns an error dict on a CORS conflict (caller returns this to the model
    instead of "ok" — record_finding itself isn't blocked, only this one claim is), or None on
    success.

    async (not sync, like every other mutation here) purely for the possible_duplicate check
    below — everything else in this function is still plain synchronous dict bookkeeping.
    """
    conflict = _cors_qualifying_conflict(ctx.session, recorded)
    if conflict:
        return {"status": "error", "error": conflict}
    # Deterministic exact-title dedup -- narrow on purpose (this cannot catch two DIFFERENT
    # LLM-generated titles describing the same real bug, e.g. Reverify carrying a carried-over
    # finding forward under its old title while Analyze's own fresh pass independently rediscovers
    # and re-titles the same issue in its own words -- that broader case still relies on Validate's
    # own semantic dedup pass, the same as before). This only closes the narrower, fully safe case:
    # an EXACT title match against a finding already in this session almost certainly means the same
    # issue is being reported a second time, not a coincidence -- real, confirmed incident this
    # guards against: a rescan whose Reverify pass already reconfirmed a finding under its original
    # title, with Analyze's own subsequent pass then recording a second card under that identical
    # title, left both sitting side by side (possibly with different verdicts) with nothing but
    # Validate's best-effort LLM dedup -- documented in its own code as "not a guarantee, falls back
    # to keeping everything unchanged on any parse failure" -- standing between that and the final
    # report showing the same bug twice.
    existing_titles = {f.get("title") for f in ctx.session["findings"]}
    if recorded.get("title") and recorded["title"] in existing_titles:
        return {
            "status": "error",
            "error": (
                f"A finding titled {recorded['title']!r} is already recorded this session — this is "
                "the same issue, not a new one. Fresh evidence for an existing finding (a "
                "reconfirmation, a corrected severity/qualification) belongs on that finding's own "
                "record via record_exploit_decision's/resolve_hypothesis's corrected_* fields, not a "
                "second record_finding call under the same title."
            ),
        }
    # is_ungrounded_cve_lookup's own docstring claims "no finding recorded by the current code can
    # ever be ungrounded" -- true for cve_lookup's own auto-record execute() closure (which refuses
    # to create a finding at all without a confirmed installed version), but that gate has zero
    # reach over a plain record_finding call the model makes directly, naming a CVE ID from its own
    # training data with no real evidence_ref behind it at all -- a genuine, unenforced fabrication
    # gap the auto-record path's own grounding check was never wired to close. Deliberately narrow
    # (empty evidence_ref only, not evidence_ref "not shaped like a cve_lookup call") to avoid a
    # false positive against a real finding grounded by a different tool (nuclei's own CVE-tagged
    # template match, for one) -- reuses the existing ungrounded_cve_lookup badge/filter
    # (is_ungrounded_cve_lookup, already wired into every report format and session_fragment.html)
    # rather than blocking the record_finding call outright, since a real CVE-mentioning finding
    # with genuine evidence of some other real shape must never be rejected on this heuristic alone.
    if not recorded.get("evidence_ref") and _CVE_ID_PATTERN.search(f"{recorded.get('title', '')} {recorded.get('description', '')}"):
        recorded["ungrounded_cve_lookup"] = True
    # ANALYZE_PROMPT tells the model "qualifies_for_bounty is optional — only set it when the task
    # message actually gave you this project's own Qualifying/Non-qualifying scope rules ... if
    # the task gave you no scope rules at all, omit this field entirely" — but that's a prompt
    # instruction, not an enforced contract, and a real session (scope_rules left blank on the New
    # Project form) confirmed the model sets "qualifying" anyway despite being told not to. Stripped
    # here, deterministically, the same way _cors_qualifying_conflict above already refuses to trust
    # the model's own "qualifying" claim on faith — a badge implying a real program's rules were
    # checked, when none were ever given, is misleading regardless of how confidently worded. Also
    # cleans up a carried-over finding flowing through _run_reverify's verbatim-copy path if the
    # original session (scanned before this check existed) already has the bad value baked in.
    scope_rules = ctx.session.get("scope_rules") or {}
    if not (scope_rules.get("qualifying") or scope_rules.get("non_qualifying")):
        recorded["qualifies_for_bounty"] = None
    # Stamped here, not asked of the model — a timestamp is a fact about when ASRA recorded it,
    # not something the LLM has any business guessing at.
    recorded["found_at"] = datetime.now(timezone.utc).isoformat()
    # discovery_tool is model-self-reported (same trust level as description/technology, both also
    # self-reported on this same call) -- there's no single scoped tool-call trace for Analyze's
    # shared discovery loop the way Exploit has one per finding, so unlike the exploitation-stage
    # entries added below (mechanical, from a real trace), this one can't be derived automatically.
    discovery_tool = recorded.pop("discovery_tool", None)
    if discovery_tool:
        _append_tool_timeline(recorded, [{"tool": discovery_tool, "stage": "discovery"}])
    # Best-effort duplicate check against this program's own cached disclosed-reports feed
    # (_maybe_refresh_program_check keeps program_check["disclosed_reports_text"] warm per phase) --
    # reads the cache only, never fetches it here, so recording a finding is never blocked on a
    # network/LLM call. Pure added signal: the finding is recorded either way, badge or not (the
    # operator's own explicit answer when this feature was designed — never a gate).
    recorded["possible_duplicate"] = None
    disclosed_reports_text = (ctx.session.get("program_check") or {}).get("disclosed_reports_text") if ctx.session.get("program_url") else ""
    if disclosed_reports_text:
        from agent.tools.bugbounty_import import match_finding_against_disclosed_reports
        try:
            match = await match_finding_against_disclosed_reports(disclosed_reports_text, recorded.get("title") or "", recorded.get("description") or "")
        except Exception as exc:
            logger.debug("core: session=%s hacktivity duplicate-match raised unexpectedly (%s)", ctx.session_id, exc)
            match = {"is_duplicate": False}
        if match.get("is_duplicate") and match.get("confidence") != "low":
            recorded["possible_duplicate"] = {
                "matched_title": match.get("matched_title") or "",
                "confidence": match.get("confidence"),
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
    ctx.session["findings"].append(recorded)
    _notify_storage_reward(
        ctx.session_id, kind="finding", label="New finding recorded", delta=1,
        total=len(ctx.session["findings"]), total_label="this session", detail=recorded.get("title") or "",
    )
    if recorded.get("severity") in ("Critical", "High"):
        # This is the ONE real choke point every record_finding persistence path (Analyze, a deep
        # dive, Reverify's carry-over/reconfirmation, Chain) already funnels through -- covers all
        # of them from a single call site, not eight separate ones. Real-time, not just the
        # session-completion notification (agent/core.py's run_session) -- a Critical/High finding
        # is worth knowing about the moment it lands, not only once the whole scan finishes, which
        # can be hours later on a long/fleet-queued session.
        notify_high_severity_finding(
            ctx.session.get("name") or ctx.session_id, ctx.session.get("target") or "",
            recorded.get("title") or "Untitled finding", recorded["severity"],
        )
    # A real finding landed -- credit whatever playbook leads were surfaced this session, so their
    # success_rate (attribution) rises and ranking/pruning learn which leads actually pay off.
    _credit_playbook_for_finding(ctx.session)
    _maybe_capture_playbook_entry(ctx, recorded)
    _credit_tool_memory_for_finding(ctx, recorded)
    # Reload-merge-save (_reload_merge_save above), not a blind save_session(ctx.session_id,
    # ctx.session) -- ctx.session can be a long-lived in-memory snapshot (a whole RE triage pass, a
    # deep dive) that predates a concurrent writer's own fresh-load-append-save (e.g. the session's
    # own chat panel recording a different finding mid-pass). Real, confirmed incident this fixes:
    # an RE triage session had a chat-recorded record_finding land on disk correctly, then the
    # triage pass's own later save (this same function, a later call, or its finally block) wrote
    # its stale in-memory snapshot straight over it -- the finding fired its reward toast and then
    # silently vanished, on reload too, because it was never actually on disk by the time the pass
    # ended. Only THIS finding is merged onto whatever's freshest on disk right now.
    _reload_merge_save(ctx.session_id, lambda s: s.setdefault("findings", []).append(recorded))
    return None


def _track_cors_check_verdict(ctx: RunContext, result: dict) -> None:
    """Records a cors_check verdict by hostname (session["cors_check_verdicts"]) so a later
    record_finding call — possibly several tool calls afterward, possibly in a completely separate
    phase or deep dive reloading this same session from disk — still has the real verdict to check
    itself against (_cors_qualifying_conflict). Also mutates `result` in place with a same-turn
    hint for whichever phase just called cors_check. Shared by _run_analyze, _run_exploit_for_finding's
    deep dive, and _run_reverify.

    Separately tracks session["cors_check_credentials"] (hostname -> allows_credentials) — a NEW,
    additive field, never merged into cors_check_verdicts itself, specifically so
    _cors_qualifying_conflict's existing string comparison against "reflects_any_origin" (and every
    other consumer of cors_check_verdicts) needs zero changes and keeps working exactly as before.
    """
    verdicts = ctx.session.setdefault("cors_check_verdicts", {})
    verdicts[result["hostname"]] = result["verdict"]
    ctx.session.setdefault("cors_check_credentials", {})[result["hostname"]] = result.get("allows_credentials")
    save_session(ctx.session_id, ctx.session)
    if result["verdict"] == "reflects_own_subdomains_only":
        result["hint"] = (
            f"{result['hostname']} reflected the same-suffix origin "
            f"({result['same_suffix_origin_tested']!r}) but NOT the genuinely unrelated "
            f"one ({result['unrelated_origin_tested']!r}) — this is a same-subdomain-trust "
            "pattern, not \"reflects any origin\". record_finding will reject "
            "qualifies_for_bounty=\"qualifying\" for this host on that claim alone."
        )
    elif result["verdict"] == "reflects_any_origin":
        if result.get("allows_credentials"):
            result["hint"] = (
                f"{result['hostname']} reflected the genuinely unrelated origin "
                f"({result['unrelated_origin_tested']!r}) AND sent Access-Control-Allow-"
                "Credentials: true — a real, broad CORS misconfiguration that CAN expose "
                "credentialed (cookie/session) data to a cross-origin reader. If this project "
                "has identity credentials configured (user_a/user_b), call "
                "cors_credentialed_check for a real, confirmed credentialed-read PoC instead of "
                "just inferring impact from these headers."
            )
        else:
            result["hint"] = (
                f"{result['hostname']} reflected the genuinely unrelated origin "
                f"({result['unrelated_origin_tested']!r}) — a real, broad CORS misconfiguration, "
                "confirmed. But it did NOT also send Access-Control-Allow-Credentials: true — a "
                "real browser will only ever expose NON-credentialed (public) responses to a "
                "cross-origin reader here, not cookies/session-based data. Session/token theft is "
                "not possible via this specific misconfiguration unless the response itself "
                "contains other sensitive data reachable without authentication — if that's the "
                "only real-world impact you can point to, set corrected_severity/"
                "corrected_qualifies_for_bounty on record_exploit_decision to match."
            )


_PRODUCT_VERSION_GAP_CHARS = 10


def _confirmed_versions_for_product(session: dict, product: str) -> list[tuple[str, str]]:
    """Every place this session has already confirmed a real host running `product`, paired with
    a free-text version string for it — two independent sources, not just Recon's own target list.
    Real incident this exists because of: a Jenkins version genuinely confirmed via record_finding
    directly (not record_target) — "Jenkins 2.445" in that finding's own technology field — never
    reached cve_lookup's grounding check here, so real High-severity CVEs tied to that exact
    confirmed version got treated as ungrounded noise. Both sources of "we already know this"
    existed side by side in the same session the whole time, just never cross-referenced.
    """
    confirmed = [
        (t.get("host"), t["version"])
        for t in session.get("recon_result", {}).get("targets", [])
        if t.get("version") and product.lower() in t["version"].lower()
    ]
    # Looks for the product name followed shortly by a dotted version number (e.g. "Jenkins 2.445"
    # inside "Jenkins 2.445 (LTS), Hudson 1.395, nginx/1.23.3...") rather than just the first dotted
    # number anywhere in the string, so a technology field naming several products doesn't grab the
    # wrong one's version.
    version_near_product = re.compile(re.escape(product) + rf"\D{{0,{_PRODUCT_VERSION_GAP_CHARS}}}(\d+(?:\.\d+)+)", re.IGNORECASE)
    for finding in session.get("findings", []):
        if finding.get("verification") != "verified":
            continue
        match = version_near_product.search(finding.get("technology") or "")
        if match:
            confirmed.append((finding.get("title", "a verified finding"), match.group(0)))
    # Third source: recon_result["technology_details"] (_merge_technology_details below) -- built
    # deterministically from real WhatWeb/js_fingerprint detections, not from the model remembering
    # to transcribe a version into record_target. Real reasoning this closes: a client-side JS/DOM
    # probe (or WhatWeb itself) can confirm an exact version with real confidence long before the
    # model ever calls record_target for that host -- without this source, cve_lookup's grounding
    # check here silently depended on that transcription happening, even though the version was
    # already known with certainty. certainty >= 80 only -- a low-confidence heuristic match (e.g.
    # a bare cookie-name guess) isn't strong enough evidence to rule a CVE in or out by itself.
    for host, techs in session.get("recon_result", {}).get("technology_details", {}).items():
        for name, details in (techs or {}).items():
            version = details.get("version")
            certainty = details.get("certainty") or 0
            if version and certainty >= 80 and product.lower() in name.lower():
                confirmed.append((host, version))
    return confirmed


_AUTO_DELEGATE_ANALYZE_HOST_THRESHOLD = 2  # fewer confirmed hosts than this -> the main agent alone covers it, not worth the delegation overhead
_AUTO_DELEGATE_ANALYZE_MAX_HOSTS = 5  # a bound on one subagent task's own batch, not a truncation of real recon data -- the rest is just worked by the main agent itself
_AUTO_DELEGATE_ANALYZE_TIMEOUT_PER_HOST_SECONDS = int(os.getenv("SUBAGENT_AUTO_ANALYZE_TIMEOUT_PER_HOST_SECONDS", "300"))


# Ports whatweb/http_request/security_headers_audit/nuclei/ssl_cert_info can actually say anything
# useful about -- deliberately narrow (the common HTTP(S) ports), not an attempt at a full service
# taxonomy; a host confirmed on any of these still counts as HTTP-shaped even if it ALSO runs
# something else on another port.
_HTTP_SHAPED_PORTS = {80, 443, 8000, 8080, 8443, 8888, 3000}


def _host_confirmed_non_http_only(host: str, recon_result: dict) -> bool:
    """True only when at least one recon_result["targets"] entry recorded for this host carries
    REAL evidence (a port and/or service actually set) AND every entry with real evidence names a
    clearly non-HTTP service/port (e.g. only port 25/smtp) — False (never excludes) when no entry
    exists yet for this host, every entry is empty of real port/service info (record_target only
    requires "host" — a bare recon_note-style entry with port=None/service=None carries no
    evidence either way), at least one entry looks HTTP-shaped, or a port/service is ambiguous.
    Real, confirmed incident this guards against (again-tests-usr_73fe2f):
    _auto_delegate_analyze_overflow handed the full HTTP toolset (security_headers_audit/
    http_request/whatweb/nuclei/ssl_cert_info) to hosts recon had only ever confirmed on port 25
    (SMTP) — 3 of 5 delegated hosts in that batch turned out to have zero HTTP successes / 3
    consecutive failures each, a real subagent budget spent on a service class none of its tools
    can meaningfully probe.
    """
    entries = [entry for entry in recon_result.get("targets", []) if entry.get("host") == host]
    saw_real_evidence = False
    for entry in entries:
        port = entry.get("port")
        service = (entry.get("service") or "").lower()
        if port is None and not service:
            continue  # this entry carries no real port/service info either way
        saw_real_evidence = True
        if port in _HTTP_SHAPED_PORTS or "http" in service:
            return False
    return saw_real_evidence


async def _auto_delegate_analyze_overflow(ctx: RunContext, target: str, recon_result: dict) -> None:
    """Deterministic auto-delegation for Analyze — same reasoning _auto_delegate_recon_overflow's
    and _auto_delegate_exploit_overflow's own docstrings already established: a soft prompt-level
    nudge (_subagent_delegation_extras) isn't reliable enough to depend on, confirmed live for
    Recon and Exploit both. Recon (secondary discovered hosts) and Exploit (lower-priority
    findings) already have their own version of this — this is Analyze's, closing the gap the
    operator explicitly flagged: subagent delegation has to be available on EVERY phase where
    genuinely independent work exists and current concurrency allows it, not just Exploit.

    Unlike Exploit, Analyze runs as ONE continuous conversation (not one fresh LLM loop per unit of
    work) — a delegated subagent's own summary reaches the main agent through the normal auto-push
    queue (_push_subagent_result/_drain_subagent_results) straight into that SAME ongoing
    conversation, and the main agent decides for itself whether/how to turn what the subagent found
    into a real record_finding call, exactly as if it had investigated that host itself.
    record_finding's own validation (the CORS-qualifying-conflict gate, etc.) still gates whatever
    the main agent decides to actually record either way — no special "don't let the subagent
    decide" carve-out is needed here the way Exploit's own version needed one.

    Delegates deeper vulnerability probing of the SECONDARY confirmed hosts (everything except the
    first one, which the main agent naturally starts on itself) once there are enough of them to be
    worth splitting. A no-op when there's only one confirmed host, or no profile enabled.
    """
    profiles = get_enabled_profiles(ctx.session.get("enabled_subagent_ids"))
    if not profiles:
        return

    already_delegated = ctx.session.setdefault("auto_delegated_analyze_hosts", [])
    seen: set[str] = set()
    hosts: list[str] = []
    for entry in recon_result.get("targets", []):
        host = entry.get("host")
        if not host or host in seen or host in already_delegated:
            continue
        if _host_confirmed_non_http_only(host, recon_result):
            continue
        seen.add(host)
        hosts.append(host)

    hosts = _dedupe_hosts_by_dns_identity(hosts, recon_result.get("dns_map", {}))

    if len(hosts) < _AUTO_DELEGATE_ANALYZE_HOST_THRESHOLD:
        return

    # Everything but the first -- the main agent naturally starts investigating that one itself;
    # the rest is genuinely independent work worth splitting off.
    batch = hosts[1:1 + _AUTO_DELEGATE_ANALYZE_MAX_HOSTS]
    if not batch:
        return
    profile_name = profiles[0]["name"]
    task_description = (
        f"The main agent is actively analyzing {hosts[0]} on {target} itself. While it does, "
        f"actively probe these {len(batch)} other confirmed in-scope host(s) for real "
        f"vulnerabilities, using whichever scan tools you have available (security headers, TLS "
        f"config, exposed endpoints/files, injection points, known CVEs for any confirmed "
        f"service/version): {', '.join(batch)}\n\n"
        "Report concretely, per host, exactly what you found — the real request/response evidence, "
        "not just a claim. The main agent has no visibility into your own conversation, so a vague "
        "summary is not useful. Never fabricate a finding you didn't actually verify."
    )

    result = await _delegate_to_subagent_impl({
        "subagent_name": profile_name,
        "task_description": task_description,
        "_session_id": ctx.session_id,
        "_session": ctx.session,
        "_triggered_by": "auto_overflow",
        "_timeout_seconds": len(batch) * _AUTO_DELEGATE_ANALYZE_TIMEOUT_PER_HOST_SECONDS,
    })
    if result.get("status") == "ok":
        already_delegated.extend(batch)
        save_session(ctx.session_id, ctx.session)
        _subagent_logger.debug(
            "core: session=%s auto-delegated %d secondary host(s) to subagent=%r task=%s for analyze",
            ctx.session_id, len(batch), profile_name, result.get("task_id"),
        )
    else:
        _subagent_logger.debug(
            "core: session=%s auto-delegation of %d secondary host(s) for analyze did not start: %s",
            ctx.session_id, len(batch), result.get("reason") or result.get("error"),
        )


# Nuclei's own template-id for the one real "waf-detect"-tagged template in this project's tag
# set (agent/tools/builders/nuclei.py's _DEFAULT_TAGS, re-verified live: exactly one template).
_NUCLEI_WAF_TEMPLATE_ID = "global-waf-detect"

# WhatWeb plugin names (lowercased, as WhatWeb itself spells them) that are WAF/CDN/bot-mitigation
# products, not generic tech-stack facts -- confirmed real incident this exists for: these end up
# buried in recon_result["technologies"] as just another unlabeled token today (e.g.
# "CloudFlare[nginx]" reads identically to "jQuery[1.8.2]"), so an operator (or the agent itself)
# has no way to tell "this host runs jQuery" apart from "this host is actively defended" without
# already knowing WhatWeb's own plugin catalogue by heart. Deliberately a static allowlist, not a
# guess from the plugin name's shape (a false "IS a WAF" label would be worse than a missed one —
# the agent would wrongly soften a scan against a host that was never actually defended).
_WHATWEB_WAF_CDN_PLUGIN_NAMES = {
    "cloudflare", "incapsula", "sucuri-cloudproxy-waf", "sucuri", "akamai", "akamaighost",
    "f5-big-ip-apm", "big-ip", "bigip", "barracuda", "modsecurity", "awselb", "aws-alb",
    "ddos-guard", "fortiweb", "citrix-netscaler", "netscaler", "airlock", "wallarm",
    "cloudfront", "distil", "sitelock", "stackpath", "aws-waf", "azure-application-gateway",
    "fastly", "imperva", "perimeterx", "datadome", "reblaze", "signalsciences", "cachefly",
}


def _merge_protection_detection(ctx: RunContext, spec: ToolSpec, result: dict, arguments: dict) -> None:
    """Deterministic, code-driven merge into recon_result["protections"][host] -- the same "derive
    it from a real tool's real output, never trust the model to remember to report it" discipline
    recon_result["technologies"]/["os_guesses"] already use. Two independent sources:

    - nuclei's global-waf-detect match (see _NUCLEI_WAF_TEMPLATE_ID above) -- its own "matcher_name"
      (agent/tools/builders/nuclei.py's parse_nuclei_output) is the actual product name.
    - WhatWeb's own plugin tokens, checked against the static _WHATWEB_WAF_CDN_PLUGIN_NAMES
      allowlist above -- the exact same recon_result["technologies"] tokens already collected,
      just also cross-checked against a known-WAF/CDN name instead of only ever surfacing as an
      indistinguishable generic "technology". Checked BOTH ways: the token's own plugin name
      ("CloudFlare[nginx]") AND each of its bracketed values ("HTTPServer[cloudflare]") -- WhatWeb
      commonly reports a CDN/WAF vendor as the plain Server-header VALUE of its generic "HTTPServer"
      plugin rather than via its own dedicated per-vendor plugin, and a name-only check silently
      missed that shape entirely. Real, confirmed incident: a live Cloudflare-fronted host (cf-ray/
      cf-cache-status/alt-svc/nel/report-to all present in its own UncommonHeaders) never got a
      Protection entry at all -- WhatWeb had only ever caught it as "HTTPServer[cloudflare]", never
      as its own "CloudFlare" plugin.

    Called from every execute() closure whose toolset can include nuclei/whatweb (Analyze,
    Reverify, Exploit deep-dive) -- a no-op whenever spec.name is neither, or the call didn't
    succeed, or nothing in this specific result matched a known protection signature.
    """
    if result.get("status") != "ok":
        return
    host = result.get("used_arguments", arguments).get("target")
    if isinstance(host, list):
        host = host[0] if host else None
    if not isinstance(host, str) or not host.strip():
        return
    host = host.strip()

    labels: list[str] = []
    if spec.name == "nuclei":
        for match in result.get("parsed") or []:
            if match.get("template_id") != _NUCLEI_WAF_TEMPLATE_ID:
                continue
            product = (match.get("matcher_name") or "").strip()
            labels.append(f"{product} (WAF, nuclei global-waf-detect)" if product else "Unidentified WAF (nuclei global-waf-detect)")
    elif spec.name == "whatweb":
        # Per-plugin certainty (agent/tools/builders/whatweb.py's own parse_whatweb_output, from
        # WhatWeb's JSON-Verbose log) -- absent entirely when the parsed result predates this field
        # or genuinely carried none, in which case the label just omits it rather than claiming a
        # confidence that was never actually reported.
        certainty_by_name = (result.get("parsed") or {}).get("technology_certainty") or {}
        for token in (result.get("parsed") or {}).get("technologies") or []:
            name, _, bracketed = token.strip().partition("[")
            name = name.strip()
            certainty = certainty_by_name.get(name)
            suffix = f", {certainty}% certainty" if isinstance(certainty, (int, float)) else ""
            if name.lower() in _WHATWEB_WAF_CDN_PLUGIN_NAMES:
                labels.append(f"{name} (WAF/CDN, whatweb{suffix})")
                continue
            values = [v.strip() for v in bracketed.removesuffix("]").split(",") if v.strip()]
            for value in values:
                if value.lower() in _WHATWEB_WAF_CDN_PLUGIN_NAMES:
                    labels.append(f"{value} (WAF/CDN, whatweb, via {name}{suffix})")

    if not labels:
        return
    protections = ctx.session.setdefault("recon_result", {}).setdefault("protections", {})
    existing = set(protections.get(host, []))
    new_labels = [label for label in labels if label not in existing]
    if not new_labels:
        return
    protections.setdefault(host, []).extend(new_labels)
    save_session(ctx.session_id, ctx.session)
    logger.debug("core: session=%s protections[%r] += %r (tool=%s)", ctx.session_id, host, new_labels, spec.name)


# Matches a dotted version number (e.g. "1.18.0") inside a WhatWeb token's bracketed value list --
# used only as a best-effort backfill (below) when js_fingerprint's own client-side probe didn't
# find a version for a technology WhatWeb also reported by the same name.
_VERSION_LIKE_PATTERN = re.compile(r"\d+(?:\.\d+){1,3}")


def _merge_technology_details(ctx: RunContext, host: str, js_dom_results: list[dict]) -> None:
    """Folds agent/tools/js_fingerprint.py's client-side (JS/DOM-executed) detections into
    recon_result for one host, two ways at once:

    1. Synthesizes tokens in WhatWeb's own flat "Name[value]" format and appends them into
       recon_result["technologies"][host] -- every existing consumer of that exact shape
       (main.py's group_tech_tokens/tech_icon_meta, _merge_protection_detection,
       agent/tools/nuclei_template_packs.py's recon_triggered_tags, _tech_gate_blocked below)
       picks up the new data for free, with zero changes to any of them. Deliberately NOT a schema
       migration of that flat format -- too many independent consumers depend on its exact shape
       for the benefit here.
    2. Writes recon_result["technology_details"][host][name] = {version, categories, certainty,
       sources} -- a new, parallel, STRUCTURED map that's the canonical source for (a) the Recon
       tab's richer per-tech display (version/category/"confirmed client-side" badge) and (b)
       _confirmed_versions_for_product's now-deterministic third source above, so a confirmed
       version actually grounds cve_lookup even when the model never transcribes it into
       record_target itself.

    No-op when js_dom_results is empty (the common case: js_fingerprint found nothing new, or was
    disabled/unavailable) -- WhatWeb's own technologies/technology_certainty entries are untouched.
    """
    if not js_dom_results:
        return
    recon_result = ctx.session.setdefault("recon_result", {})
    technologies = recon_result.setdefault("technologies", {})
    certainty_by_host = recon_result.setdefault("technology_certainty", {})
    details_by_host = recon_result.setdefault("technology_details", {})

    existing_tokens = technologies.setdefault(host, [])
    existing_names = {token.split("[", 1)[0].strip().lower() for token in existing_tokens}
    host_certainty = certainty_by_host.setdefault(host, {})
    host_details = details_by_host.setdefault(host, {})

    added_tokens: list[str] = []
    for detection in js_dom_results:
        name = (detection.get("name") or "").strip()
        if not name:
            continue
        version = detection.get("version")
        confidence = detection.get("confidence") or 0
        categories = detection.get("categories") or []

        # Best-effort backfill: WhatWeb reported this same name but js_fingerprint found no
        # version itself -- try to pull one out of WhatWeb's own bracketed values instead of
        # leaving technology_details with no version at all when one is sitting right there.
        if not version:
            for token in existing_tokens:
                token_name, _, bracketed = token.partition("[")
                if token_name.strip().lower() != name.lower():
                    continue
                match = _VERSION_LIKE_PATTERN.search(bracketed)
                if match:
                    version = match.group(0)
                break

        if name.lower() not in existing_names:
            token = f"{name}[{version}]" if version else name
            added_tokens.append(token)
            existing_names.add(name.lower())

        host_certainty[name] = max(confidence, host_certainty.get(name, 0))

        prior = host_details.get(name, {})
        sources = set(prior.get("sources") or [])
        sources.add("js_dom")
        if name.lower() in {t.split("[", 1)[0].strip().lower() for t in existing_tokens}:
            sources.add("whatweb")
        host_details[name] = {
            "version": version or prior.get("version"),
            "categories": categories or prior.get("categories") or [],
            "certainty": max(confidence, prior.get("certainty", 0)),
            "sources": sorted(sources),
        }

    if added_tokens:
        existing_tokens.extend(added_tokens)
    save_session(ctx.session_id, ctx.session)
    logger.debug(
        "core: session=%s technology_details[%r] updated from %d js_fingerprint detection(s), %d new token(s)",
        ctx.session_id, host, len(js_dom_results), len(added_tokens),
    )


def _protection_task_addendum(session: dict) -> str:
    """Empty when nothing in recon_result["protections"] has been detected yet this session (the
    common case at the start of a phase, before whatweb/nuclei have run against anything) --
    _merge_protection_detection populates it deterministically as real scans come in, this just
    surfaces whatever's already known so far. Concrete behavioral guidance, not just a fact dump:
    this project has hit real, confirmed incidents of an
    aggressive scan flag hanging the full subprocess timeout against exactly this kind of target
    (whatweb -a 4, wpscan --plugins-detection aggressive, arjun --stable) and of a WAF's blocked/
    403/challenge response being wrongly read as a dead host — both are avoidable once the agent
    actually knows a WAF is there instead of discovering it the hard way per attempt.
    """
    protections = session.get("recon_result", {}).get("protections") or {}
    if not protections:
        return ""
    lines = "\n".join(f"- {host}: {', '.join(labels)}" for host, labels in protections.items())
    return (
        "\n\nProtective system(s) already identified this session (deterministic, from a real "
        f"tool match — not a guess):\n{lines}\n"
        "Adjust how you work these hosts accordingly: prefer default/lower-aggression flags over "
        "maximum ones (a WAF-fronted target is exactly the case those hang against, wasting the "
        "full subprocess timeout for nothing); expect and correctly interpret 403/429/challenge-"
        "page responses as the WAF acting, not a dead or misconfigured host; and if the WAF "
        "materially limits what you can actually verify, say so explicitly in your finding's "
        "advisory_note/description instead of silently reporting an inconclusive result."
    )


async def _run_analyze(ctx: RunContext, target: str, recon_result: dict) -> list[dict]:
    _mark_phase_started(ctx.session, "analyze")
    await _maybe_refresh_program_check(ctx)
    subagent_tools, subagent_addendum = _subagent_delegation_extras(ctx.session)
    tools = get_tools_by_category("scan") + subagent_tools + _toolkit_tool_extras()
    # See _run_recon's identical block for why update_plan (category="post_exploit") has to be
    # appended explicitly rather than picked up by get_tools_by_category — plan_phase="analyze" on
    # the _run_llm_tool_loop call below is what actually reorders tools, fresh every turn.
    update_plan_spec = get_tool("update_plan")
    if update_plan_spec is not None:
        tools.append(update_plan_spec)
    for hypothesis_tool_name in ("record_hypothesis", "resolve_hypothesis"):
        hypothesis_spec = get_tool(hypothesis_tool_name)
        if hypothesis_spec is not None:
            tools.append(hypothesis_spec)
    logger.debug("core: session=%s starting analyze phase (%d tools available)", ctx.session_id, len(tools))
    ctx.session.setdefault("findings", [])
    # cve_lookup is a "scan"-category tool (get_tools_by_category("scan") above) — Analyze is the
    # only phase that actually has it available, matching ANALYZE_PROMPT's own instruction to use
    # it ("a service+version string calls for a CVE lookup"). It used to be hooked in _run_recon's
    # execute() instead, where the model never had this tool in its schema at all and so could
    # never trigger the hook — moved here to where it's actually reachable. setdefault here too,
    # not just in _run_recon: an entry_point="analyze" resume skips recon entirely and builds its
    # own recon_result fallback (run_session) without a "cves" key.
    ctx.session.setdefault("recon_result", {"targets": [], "cves": []})
    ctx.session["recon_result"].setdefault("cves", [])
    ctx.session["recon_result"].setdefault("dns_map", {})
    # host -> list of raw WhatWeb technology tokens (agent/tools/builders/whatweb.py's
    # parse_whatweb_output) — captured here deterministically the instant whatweb returns them,
    # same reasoning as recon_result["cves"]/["os_guesses"]: this is also the one source of truth
    # _wpscan_cms_not_confirmed checks before letting wpscan run at all, so it can't depend on the
    # model reliably transcribing it anywhere else first.
    ctx.session["recon_result"].setdefault("technologies", {})
    # host -> {plugin_name: best certainty 0-100} (agent/tools/builders/whatweb.py's own
    # parse_whatweb_output, sourced from WhatWeb's JSON-Verbose log, absent from its old
    # human-readable brief report entirely) -- kept as its own parallel dict rather than folded
    # into the "technologies" token strings themselves, so nothing that already keys off that
    # list's exact string shape (_tech_gate_blocked, _merge_protection_detection, the Recon tab's
    # own group_tech_tokens) needs to change to tolerate a new suffix appearing inside it.
    ctx.session["recon_result"].setdefault("technology_certainty", {})
    # host -> {tech_name: {version, categories, certainty, sources}} -- the structured, canonical
    # counterpart to the flat "technologies" tokens above, built by _merge_technology_details from
    # agent/tools/js_fingerprint.py's client-side (JS/DOM-executed) detections (best-effort
    # backfilled with a version from WhatWeb's own tokens when js_fingerprint didn't find one
    # itself). See _confirmed_versions_for_product's third source and the Recon tab's own
    # version/"confirmed client-side" rendering, both of which read this map.
    ctx.session["recon_result"].setdefault("technology_details", {})
    # Hosts js_fingerprint has already probed this session -- guards against relaunching a real
    # browser context on every single whatweb call against the same host (retries, repeated Analyze
    # passes); a host only ever needs one client-side probe per session.
    ctx.session["recon_result"].setdefault("js_fingerprint_hosts_done", [])
    await _auto_delegate_analyze_overflow(ctx, target, recon_result)

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        result = await _run_tool_with_retry(ctx, spec, arguments)
        if spec.name == "whatweb" and result.get("status") == "ok":
            parsed = result.get("parsed") or {}
            technologies = parsed.get("technologies") or []
            # Keyed off what actually ran, not the pre-retry target — see the matching comment in
            # _run_recon's execute() for why a corrected retry can change this argument.
            host = result.get("used_arguments", arguments).get("target")
            if isinstance(host, list):
                host = host[0] if host else None
            if technologies and isinstance(host, str) and host.strip():
                stripped_host = host.strip()
                ctx.session["recon_result"]["technologies"][stripped_host] = technologies
                ctx.session["recon_result"]["technology_certainty"][stripped_host] = parsed.get("technology_certainty") or {}
                save_session(ctx.session_id, ctx.session)
                logger.debug(
                    "core: session=%s analyze: technologies[%r] = %d token(s), detected_cms=%r",
                    ctx.session_id, stripped_host, len(technologies), parsed.get("detected_cms"),
                )
                # Client-side (JS/DOM-executed) enrichment -- catches technologies/versions that
                # only ever prove themselves after JS renders, invisible to WhatWeb's own static-
                # HTML/header fingerprinting above. Automatic, not a separate tool the model has to
                # think to call (see js_fingerprint.py's own docstring); a no-op (empty result) on
                # any failure -- Chromium missing, JS_FINGERPRINT_ENABLED=false, navigation/
                # evaluate error, timeout -- never blocks or fails this whatweb result.
                done_hosts = ctx.session["recon_result"]["js_fingerprint_hosts_done"]
                if stripped_host not in done_hosts:
                    done_hosts.append(stripped_host)
                    js_dom_results = await run_js_fingerprint(
                        f"jsfp-{ctx.session_id}-{stripped_host}", stripped_host, ctx.session.get("out_of_scope"),
                    )
                    _merge_technology_details(ctx, stripped_host, js_dom_results)
                    if js_dom_results:
                        # Surfaced back on THIS whatweb tool response, not only in
                        # recon_result["technology_details"] for later phases to read — the model
                        # sees the exact client-confirmed version/certainty the moment it's found,
                        # in the same turn, rather than only via a later Chain/second-opinion pass.
                        result["client_side_technologies"] = js_dom_results
        _merge_protection_detection(ctx, spec, result, arguments)
        if spec.name == "record_finding" and result.get("status") == "ok" and "recorded" in result:
            conflict_result = await _persist_new_finding(ctx, result["recorded"])
            if conflict_result is not None:
                logger.debug("core: session=%s analyze: rejected record_finding, cors_check conflict for %r", ctx.session_id, result["recorded"].get("title"))
                return conflict_result
            logger.debug("core: session=%s analyze: recorded finding title=%r", ctx.session_id, result["recorded"].get("title"))
        elif spec.name == "cors_check" and result.get("status") == "ok":
            _track_cors_check_verdict(ctx, result)
        elif spec.name == "cve_lookup" and result.get("status") == "ok" and result.get("cve_ids"):
            details = result.get("details", {})
            product = arguments.get("product", "Unknown product")
            # cve_lookup is a bare product-name search against a public CVE database — it has no
            # idea whether this target runs that product at all. A real installed version already
            # confirmed for this exact product, from either Recon's own target list or an already
            # -verified finding's technology field (_confirmed_versions_for_product), is the one
            # piece of ground truth that separates "a real lead on this target" from "this product
            # name exists somewhere in a CVE database" — without it, every CVE ID this call
            # returned describes a technology this scan never found a single trace of.
            confirmed_versions = _confirmed_versions_for_product(ctx.session, product)
            if not confirmed_versions:
                # Real incident this exists because of: a scan that speculatively cve_lookup'd
                # Jenkins/Grafana/Confluence with zero evidence any of them run anywhere in scope
                # ended up with 18 High/Medium "finding" cards that read exactly like discovered
                # holes, indistinguishable on sight from the 3 findings that were actually real —
                # every one of the 18 turned out unconfirmable because there was never a target to
                # begin with. Nothing gets recorded here — not a Findings card, not even the CVE
                # chip (agent/core.py's own comment used to justify auto-recording specifically to
                # avoid "a chip with no backing card"; the fix for that gap is not creating either
                # one until there's real ground to stand on, not creating both regardless). The
                # model is still free to call cve_lookup for its own reasoning — the result just
                # never becomes session-visible data on the strength of a name match alone.
                logger.debug(
                    "core: session=%s analyze: cve_lookup(%s) returned %d CVE(s) but no confirmed host runs %s — discarded, not recorded",
                    ctx.session_id, product, len(result["cve_ids"]), product,
                )
                result["hint"] = (
                    f"No host in this scan's Recon results is confirmed to run {product} — these CVE IDs "
                    f"were not recorded (there is no real target for them yet). Confirm {product} is "
                    "actually running somewhere in scope first (a real banner/version from nmap/whatweb/"
                    "http_request), then call cve_lookup again once you have that."
                )
                return result

            existing = set(ctx.session["recon_result"]["cves"])
            new_ids = [cve_id for cve_id in result["cve_ids"] if cve_id not in existing]
            existing.update(result["cve_ids"])
            ctx.session["recon_result"]["cves"] = sorted(existing)

            # Whether the model also calls record_finding for a given CVE is not reliable enough
            # to promise "every confirmed CVE gets a card", so this guarantees it deterministically
            # — but only for a CVE ID no existing finding already covers (skip it if the model
            # already wrote a better, more specific finding mentioning the same CVE).
            covered_cve_ids = {
                cve_id
                for finding in ctx.session["findings"]
                for cve_id in _CVE_ID_PATTERN.findall(f"{finding.get('title', '')} {finding.get('description', '')}")
            }
            for cve_id in new_ids:
                if cve_id in covered_cve_ids:
                    continue
                info = details.get(cve_id, {})
                severity = info.get("severity")
                scenario = info.get("exploitation_scenario")
                affected_versions = info.get("affected_versions")
                affected_version_bounds = info.get("affected_version_bounds")
                references = info.get("references") or []

                ruled_out_by = [
                    (host, version) for host, version in confirmed_versions
                    if version_is_ruled_out(version, affected_version_bounds)
                ]
                # Only a real, positive exclusion for every single confirmed instance of this
                # product counts — one un-ruled-out host (in range, or a version we couldn't even
                # parse) means this CVE still might apply somewhere in scope, so it's treated
                # exactly as before: a real, un-flagged lead worth a human's attention.
                false_positive_reason = None
                if len(ruled_out_by) == len(confirmed_versions):
                    where = "; ".join(f"{host} ({version})" for host, version in ruled_out_by)
                    false_positive_reason = (
                        f"Recon confirmed the actual installed version at {where}, which falls outside "
                        f"this CVE's affected range ({affected_versions or 'checked via structured version data'}) "
                        "— not applicable to this target. Kept for audit-trail completeness only, not a live lead."
                    )

                installed_str = "; ".join(f"{host} ({version})" for host, version in confirmed_versions)

                repro_lines = [
                    f"1. This scan's Recon already confirmed {product} running at: {installed_str}.",
                    f"2. Compare against the affected range ({affected_versions or 'see structured version data'})"
                    + (" — already checked: outside the range, see false_positive_reason." if false_positive_reason
                       else " to confirm applicability before treating this as more than an inferred lead."),
                ]
                if references:
                    repro_lines.append("3. Technical detail and any public PoC: " + "; ".join(references))
                else:
                    repro_lines.append(f"3. Technical detail: https://nvd.nist.gov/vuln/detail/{cve_id}")

                ctx.session["findings"].append(
                    {
                        "title": f"{product} — {cve_id}",
                        "severity": severity if severity in _VALID_FINDING_SEVERITIES else "Medium",
                        "description": info.get("description")
                        or f"{cve_id} was found to affect {product} by a CVE lookup; the lookup itself returned no further description.",
                        "technology": f"{product} — confirmed installed at {installed_str}",
                        "reproduction_steps": "\n".join(repro_lines),
                        "verification": "inferred",
                        "evidence_ref": f"cve_lookup({arguments.get('vendor', product)}/{product}) returned {cve_id}",
                        "found_at": datetime.now(timezone.utc).isoformat(),
                        # Derived straight from the CVE's own CVSS AV/UI vector (native.py's
                        # _exploitation_scenario_from_cvss_vector) — None only when the record
                        # carried no CVSS vector at all; Exploit still gets a chance to pin this
                        # down for real once it actually probes the finding.
                        "exploitation_scenario": scenario if scenario in _VALID_EXPLOITATION_SCENARIOS else None,
                        # Real vector straight from the CVE record itself (native.py's
                        # _summarize_cve_record) -- never fabricated, None whenever the record
                        # carried no CVSS data at all.
                        "cvss_vector": info.get("cvss_vector"),
                        "false_positive_reason": false_positive_reason,
                    }
                )
                covered_cve_ids.add(cve_id)
                if false_positive_reason:
                    logger.debug("core: session=%s analyze: auto-recorded %s as ruled-out (false_positive_reason set)", ctx.session_id, cve_id)
                else:
                    logger.debug("core: session=%s analyze: auto-recorded finding for %s (no existing finding mentioned it)", ctx.session_id, cve_id)
                    if severity in ("Critical", "High"):
                        # This deterministic cve_lookup auto-recording path is a SEPARATE append
                        # site from _persist_new_finding's own model-driven record_finding path
                        # (this dict is appended directly above, never through that function) --
                        # needs its own notification call, not covered by _persist_new_finding's.
                        notify_high_severity_finding(
                            ctx.session.get("name") or ctx.session_id, ctx.session.get("target") or "",
                            f"{product} — {cve_id}", severity,
                        )

            save_session(ctx.session_id, ctx.session)
            logger.debug("core: session=%s analyze: cve_lookup returned %s, total known now %d", ctx.session_id, result["cve_ids"], len(existing))
        elif spec.name == "dalfox" and result.get("status") == "ok":
            # Same "a model can see a signal and still not act on it" gap _DETERMINISTIC_DETECTION_
            # FIELDS closes below, just for a list-shaped result (dalfox's "parsed" findings) that
            # flat-field membership check can't see into. Only "verified_dom_execution" gets the
            # loud nudge — a "reflected_unconfirmed"/"dom_based_ast" hit is real evidence too, but
            # weaker, and shouldn't read as loudly as a payload actually confirmed executing.
            verified_hits = [f for f in (result.get("parsed") or []) if f.get("xss_type") == "verified_dom_execution"]
            if verified_hits:
                params = ", ".join(sorted({f.get("param") or "?" for f in verified_hits}))
                result["hint"] = (
                    f"Dalfox confirmed the payload actually executed in a real parsed DOM (param(s): {params}) "
                    "— call record_finding for it now with verification=\"verified\", before calling any other tool."
                )
        elif spec.name == "update_plan" and result.get("status") == "ok" and "recorded" in result:
            _apply_updated_plan(ctx, result["recorded"], "analyze")
        elif spec.name == "record_hypothesis" and result.get("status") == "ok" and "recorded" in result:
            _persist_new_hypothesis(ctx, result["recorded"], "analyze")
        elif spec.name == "resolve_hypothesis" and result.get("status") == "ok" and "resolved" in result:
            _resolve_hypothesis(ctx, result["resolved"], "analyze")
        else:
            fired = [field for field in _DETERMINISTIC_DETECTION_FIELDS if field in result]
            if fired:
                # A model can see a signal buried in a result dict and still not act on it in the
                # same turn, especially deep in a long tool-call conversation — a loud, adjacent
                # hint closes that gap without auto-recording anything (the model still decides).
                result["hint"] = (
                    f"{', '.join(fired)} confirms a real vulnerability — call record_finding for it now, "
                    "before calling any other tool."
                )
        return result

    task = (
        f"Target: {target}\n"
        f"Recon results:\n{json.dumps(recon_result)}\n\n"
        "Analyze these for vulnerabilities using the tools available to you."
    )
    task += _scope_rules_task_addendum(ctx.session)
    task += _out_of_scope_task_addendum(ctx.session)
    task += _out_of_scope_notes_task_addendum(ctx.session)
    task += _custom_instructions_task_addendum(ctx.session)
    task += _goal_task_addendum(ctx.session)
    task += _program_url_task_addendum(ctx.session)
    task += _custom_user_agent_task_addendum(ctx.session)
    task += _custom_headers_task_addendum(ctx.session)
    task += _reconfirmed_findings_task_addendum(ctx.session)
    task += _previously_ruled_out_task_addendum(ctx.session)
    task += _app_shaped_hostnames_task_addendum(recon_result)
    task += _protection_task_addendum(ctx.session)
    delegated_hosts_addendum = _analyze_delegated_hosts_task_addendum(ctx.session, recon_result)
    if delegated_hosts_addendum:
        logger.debug(
            "core: session=%s analyze: told the main agent to skip %d subagent-delegated host(s)",
            ctx.session_id, len(ctx.session.get("auto_delegated_analyze_hosts") or []),
        )
    task += delegated_hosts_addendum
    task += _plan_task_addendum(ctx.session, "analyze")
    task += _open_hypotheses_task_addendum(ctx.session)
    task += _previously_resolved_hypotheses_task_addendum(ctx.session)
    task += _playbook_task_addendum(ctx.session, track_injections=True, llm=ctx.llm)
    task += _tool_memory_task_addendum(ctx.session)
    task += subagent_addendum
    await _run_llm_tool_loop(ctx, ANALYZE_PROMPT, task, tools, "analyze", execute_tool=execute, expect_json_final=False, plan_phase="analyze")
    findings = ctx.session["findings"]
    logger.debug("core: session=%s analyze phase found %d finding(s)", ctx.session_id, len(findings))
    await _run_detection_second_opinion(ctx, target, ctx.session["recon_result"])
    _mark_phase_finished(ctx.session, "analyze")
    return findings


async def _run_detection_second_opinion(ctx: RunContext, target: str, recon_result: dict) -> None:
    """A genuine second opinion on DETECTION itself, not just on an already-confirmed finding's
    reproduction (that's _run_skeptical_verification's own ensemble check, further down this same
    pipeline) — both gated on the same Settings -> Secondary verification provider (None by
    default, so a no-op unless the operator explicitly configured one). Real motivation: the
    primary Analyze pass is one model's single read of the recon evidence — a vulnerability class
    it simply never thinks to check for looks identical, from the outside, to one that genuinely
    isn't there. A second, distinct model reviewing the SAME evidence with fresh reasoning catches
    a different set of blind spots than the primary model has.

    Deliberately review-only, no scan/exploit tool access: re-running live scan tools here would
    double real network traffic against the actual target on every configured session — a real
    operational cost (rate-limiting, WAF tripping) this project has no reason to pay twice for, on
    top of the extra LLM spend the operator already opted into by configuring this setting.
    DETECTION_SECOND_OPINION_PROMPT forbids verification="verified" for exactly this reason — the
    strongest honest claim from a no-tool-access review is "inferred"/"needs_verification", and
    _run_exploit already gives every non-exploited, non-ruled-out finding (that tier included) a
    real tool-backed attempt next, the same path a primary-Analyze "inferred" finding already
    takes. Downgraded defensively below too, in case the secondary model claims "verified" anyway.
    """
    secondary_config = get_secondary_verification_provider()
    if secondary_config is None:
        return
    try:
        secondary_llm = get_provider(secondary_config["provider"], secondary_config["model"])
    except ValueError:
        logger.debug(
            "core: session=%s detection_second_opinion: configured secondary provider %s/%s not usable, skipping",
            ctx.session_id, secondary_config["provider"], secondary_config["model"],
        )
        return

    record_finding_spec = get_tool("record_finding")
    record_hypothesis_spec = get_tool("record_hypothesis")
    tool_specs = [spec for spec in (record_finding_spec, record_hypothesis_spec) if spec is not None]
    if not tool_specs:
        return

    already_found = [
        {"title": f.get("title"), "severity": f.get("severity"), "technology": f.get("technology"), "verification": f.get("verification")}
        for f in ctx.session.get("findings", [])
    ]
    evidence = {
        "targets": recon_result.get("targets", []),
        "technologies": recon_result.get("technologies", {}),
        # See _run_chain_pass's identical addition for why this is included explicitly rather than
        # left buried inside "technologies" token brackets -- exact version/certainty/source per
        # technology, from agent/tools/js_fingerprint.py + WhatWeb.
        "technology_details": recon_result.get("technology_details", {}),
        "confirmed_cves": recon_result.get("cves", []),
        "dns_map": recon_result.get("dns_map", {}),
    }
    task = (
        f"Target(s): {target}\n\n"
        f"Recon/analysis evidence gathered so far:\n{json.dumps(evidence)}\n\n"
        f"Already found by the primary analysis pass:\n{json.dumps(already_found)}\n\n"
        "Independently review this SAME evidence for anything the primary pass may have missed."
    )

    secondary_ctx = replace(ctx, llm=secondary_llm)
    logger.debug(
        "core: session=%s detection_second_opinion: starting review pass with %s/%s (%d already-found finding(s) shown)",
        ctx.session_id, secondary_config["provider"], secondary_config["model"], len(already_found),
    )

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        result = await _run_tool_with_retry(secondary_ctx, spec, arguments)
        if spec.name == "record_finding" and result.get("status") == "ok" and "recorded" in result:
            recorded = result["recorded"]
            if recorded.get("verification") == "verified":
                # No live tool access this pass -- never trust a "verified" self-claim it has no
                # real check behind (same "don't take the model's word for it" discipline as
                # _persist_new_finding's own qualifies_for_bounty stripping just below this).
                recorded["verification"] = "needs_verification"
            recorded["detected_by_secondary_opinion"] = True
            recorded["ensemble_secondary_provider"] = f"{secondary_config['provider']}/{secondary_config['model']}"
            conflict_result = await _persist_new_finding(ctx, recorded)
            if conflict_result is not None:
                return conflict_result
            logger.debug(
                "core: session=%s detection_second_opinion: secondary provider flagged a missed finding, title=%r",
                ctx.session_id, recorded.get("title"),
            )
        elif spec.name == "record_hypothesis" and result.get("status") == "ok" and "recorded" in result:
            _persist_new_hypothesis(ctx, result["recorded"], "detection_second_opinion")
        return result

    try:
        await _run_llm_tool_loop(
            secondary_ctx, DETECTION_SECOND_OPINION_PROMPT, task, tool_specs, "detection_second_opinion",
            execute_tool=execute, expect_json_final=False,
        )
    except Exception as exc:
        # A bonus safety net, not a required step -- a crash in the SECONDARY pass (misconfigured
        # provider, transient outage) must never take down the primary Analyze phase that already
        # completed successfully. Same tolerance _run_skeptical_verification's own ensemble check
        # already applies to its equivalent secondary-provider call.
        logger.debug("core: session=%s detection_second_opinion: crashed (%s), skipping", ctx.session_id, exc)


async def _upgrade_stall_forced_reverify_verdict(
    ctx: RunContext, verdict: dict | None, trace: list[dict], task: str, tool_specs: list[ToolSpec],
    execute: Callable[[ToolSpec, dict], Awaitable[dict]],
) -> dict | None:
    """A reverify pass that stalled polling a still-running delegated subagent task is forced to
    answer "inconclusive" (_run_llm_tool_loop_impl's stall-forced final-answer path) -- but by the
    time _run_llm_tool_loop returns to its caller, its own await_all_running_subagent_tasks call has
    already waited out that same task, so the real result usually already exists in
    session["subagent_tasks"] by the time this runs. The phase pays that wait either way; this makes
    sure the answer it waited for actually gets used instead of thrown away.

    Only fires for exactly that situation: an "inconclusive" verdict whose own trace shows a subagent
    task still "running" as of this pass's last observation (the only way the stall-forced path can
    be reached at all -- the normal loop path can never successfully terminate while a task is
    unresolved, see the unresolved_task_ids guard a few hundred lines up), and that task is now
    actually resolved. A genuinely-reached inconclusive (no subagent involved, or still not resolved)
    is returned completely untouched. The one extra pass this runs reuses the same terminal-tool
    contract as any normal reverify pass -- if the model still can't do better with the real result in
    hand, "inconclusive" is exactly what it reports again, no worse than today.
    """
    if (verdict or {}).get("verification_outcome") != "inconclusive":
        return verdict
    stalled_task_id = next(iter(_unresolved_subagent_task_ids(trace)), None)
    if stalled_task_id is None:
        return verdict
    resolved = ctx.session.get("subagent_tasks", {}).get(stalled_task_id)
    if resolved is None or resolved.get("status") not in _RESOLVED_SUBAGENT_STATUSES or resolved.get("result") is None:
        return verdict
    logger.debug(
        "core: session=%s reverify: subagent task=%s resolved (status=%s) after this pass already forced "
        "inconclusive -- reconsidering with the real result", ctx.session_id, stalled_task_id, resolved["status"],
    )
    upgrade_task = (
        task
        + "\n\n[Subagent finished after this pass already had to conclude without it] "
        + json.dumps({"outcome": resolved["status"], "result": resolved["result"]})[:_TOOL_RESULT_CHAR_LIMIT]
        + "\n\nYour previous attempt at this same finding had to answer verification_outcome=\"inconclusive\" "
        "before this delegated subagent task finished. It has now finished — the real result is above. Use "
        "it to give an actual verdict now if it lets you; answer inconclusive again only if it genuinely "
        "still doesn't settle this."
    )
    upgraded_verdict, _ = await _run_llm_tool_loop(
        ctx, REVERIFY_PROMPT, upgrade_task, tool_specs, "reverify", execute_tool=execute,
        terminal_tool="record_reverification_result", plan_phase="exploit",
    )
    if upgraded_verdict is not None:
        logger.debug(
            "core: session=%s reverify: task=%s upgrade pass produced verification_outcome=%r (was inconclusive)",
            ctx.session_id, stalled_task_id, upgraded_verdict.get("verification_outcome"),
        )
    return upgraded_verdict if upgraded_verdict is not None else verdict


def _stable_outcome_streak(prior_outcomes: list[dict]) -> tuple[str, int] | None:
    """Returns (outcome, streak_len) when the TRAILING entries of `prior_outcomes` (already ordered
    oldest-to-newest, same order session["past_reverification_outcomes"] is appended to) all agree on
    the same verification_outcome, for at least _REVERIFY_STABLE_TREND_MIN_STREAK entries in a row --
    else None. Pure/side-effect-free so _run_reverify's own tests can exercise it directly without a
    full session/LLM-loop fixture.
    """
    if len(prior_outcomes) < _REVERIFY_STABLE_TREND_MIN_STREAK:
        return None
    trailing = prior_outcomes[-_REVERIFY_STABLE_TREND_MIN_STREAK:]
    outcomes = {e.get("verification_outcome") for e in trailing}
    if len(outcomes) != 1:
        return None
    outcome = trailing[-1]["verification_outcome"]
    # Count the FULL trailing run (not just the last _REVERIFY_STABLE_TREND_MIN_STREAK), so a
    # longer streak is reported accurately even though the minimum to trigger calibration is fixed.
    streak = 0
    for entry in reversed(prior_outcomes):
        if entry.get("verification_outcome") != outcome:
            break
        streak += 1
    return (outcome, streak)


async def _run_reverify(ctx: RunContext) -> None:
    """Re-checks each carried-over finding from a rescanned project's prior scan against the
    target's CURRENT state — real tool calls, never a blind trust of the old verification. A
    rescan's whole point is to benefit from whatever changed since the last scan (a bug in ASRA
    itself getting fixed, or the target getting patched) — that only works if the old findings are
    actually re-proven, not copy-pasted forward. A true no-op for every normal (non-rescan)
    session: session["carried_over_findings"] is only ever set by main.py's rescan route.

    Idempotent per finding, deliberately NOT gated on run_session()'s entry_point — an interrupted/
    resumed rescan must never silently strand an unprocessed carried-over finding.
    compute_resume_entry_point() has no idea carried_over_findings exists, so a crash mid-reverify
    can resume at "analyze" (recon_result already has targets) or "exploit" (a finding already
    exists) just as easily as "recon" — this function is called from every one of those points in
    run_session() below, and is a cheap/instant no-op once nothing is left pending, which is what
    makes calling it more than once per run safe.
    """
    carried_over = ctx.session.get("carried_over_findings") or []
    if not carried_over:
        return  # a normal, non-rescan session — reverify categorically doesn't apply, no phase card for it

    history = ctx.session.setdefault("reverification_history", [])
    already_checked = {entry["title"] for entry in history}
    pending = [f for f in carried_over if f.get("title") not in already_checked]
    if not pending:
        return  # already fully reverified (this run or an earlier one) — nothing new to time

    # Marked only around real work, not the two no-op returns above: unlike chain/validate (which
    # run once, near session end, so even their own no-op case is one real, meaningful data point),
    # this function is deliberately called from every one of run_session()'s several resume entry
    # points and is safely re-invocable as a no-op once nothing is pending (see this function's own
    # docstring) — marking phase timing on every such idempotent re-check would keep pushing
    # finished_at forward on a resumed session that did no new reverify work, and would add a
    # confusing zero-duration "reverify" phase card to every normal (non-rescan) session that can
    # never have any real work to show. Real, confirmed gap this still closes: a genuine 52m47s
    # block of real reverify work (10 carried-over findings re-checked with fresh tool calls) was
    # completely invisible in session["phase_timings"], so Session time (started_at -> finished_at)
    # came out visibly bigger than every other phase's own shown duration added together, with
    # nothing in the UI explaining the gap — the same class of bug already fixed once for
    # chain/validate not being tracked at all.
    _mark_phase_started(ctx.session, "reverify")

    # Explicit assembly, not category-membership alone: get_tools_by_category("scan") is also what
    # _run_analyze and the exploit phase's deep-dive widened toolset consume, so
    # record_reverification_result is registered under "post_exploit" (a category nothing else's
    # get_tools_by_category(...) call queries) specifically so it can't leak into either of those —
    # it only ever reaches the model through this explicit list.
    subagent_tools, subagent_addendum = _subagent_delegation_extras(ctx.session)
    tool_specs = get_tools_by_category("scan") + [get_tool("record_reverification_result")] + subagent_tools + _toolkit_tool_extras()
    update_plan_spec = get_tool("update_plan")
    if update_plan_spec is not None:
        tool_specs.append(update_plan_spec)
    logger.debug(
        "core: session=%s starting reverify phase, %d carried-over finding(s) pending (%d tools available)",
        ctx.session_id, len(pending), len(tool_specs),
    )

    for old_finding in pending:
        title = old_finding.get("title")
        # past_reverification_outcomes (unlike `history`/reverification_history just above, which
        # resets every rescan purely to make THIS pass idempotent on resume) is never reset --
        # main.py's rescan routes carry it forward across every rescan of this same lineage. Real,
        # confirmed operator complaint this addresses: a finding re-proven "still there"/"can't
        # tell" pass after pass, rescan after rescan, with zero memory of that trend, reads as
        # pointless repeated churn ("уже 2-3 раза проверяли") even though each individual re-check
        # is doing exactly its job (never trust a stale verdict). Surfacing the actual trend lets
        # the model calibrate effort (a stable multi-rescan "still there" only needs reconfirming,
        # not re-discovering from scratch) without this ever skipping the real tool-call check
        # itself -- the model still decides, same as _run_reverify's own docstring promises.
        prior_outcomes = [e for e in ctx.session.get("past_reverification_outcomes", []) if e.get("title") == title]
        prior_history_note = (
            "\n\nThis exact finding's history across prior rescans of this same target: "
            f"{json.dumps([{k: e[k] for k in ('verification_outcome', 'checked_at')} for e in prior_outcomes])}. "
            "If your fresh evidence matches that trend, a quick reconfirmation is enough -- but still base "
            "your verdict on a real tool call this pass, never on the trend alone."
            if prior_outcomes else ""
        )
        # Soft effort calibration for a long-stable trend -- never a skip, only a tighter tool-call
        # ceiling. terminal_tool="record_reverification_result" below still requires a real tool call
        # before a verdict is possible either way; this only shrinks the budget for a title that's
        # come back with the identical verdict several rescans running, so a truly stable false
        # positive/fixed finding stops costing the same open-ended budget as a genuinely fresh lead.
        stable_streak = _stable_outcome_streak(prior_outcomes)
        calibrated_max_tool_calls = None
        if stable_streak is not None:
            stable_outcome, streak_len = stable_streak
            calibrated_max_tool_calls = _REVERIFY_CALIBRATED_MAX_TOOL_CALLS
            prior_history_note += (
                f" This finding has come back {stable_outcome!r} on the last {streak_len} consecutive "
                "rescans in a row -- a fast, targeted reconfirmation is enough this pass, but you must "
                "still make a real tool call before answering."
            )

        async def execute(spec: ToolSpec, arguments: dict) -> dict:
            result = await _run_tool_with_retry(ctx, spec, arguments)
            _merge_protection_detection(ctx, spec, result, arguments)
            # record_finding is in this phase's toolset (it's "scan"-category) — if the model
            # spots something genuinely different while re-checking the old claim, it must
            # actually persist, same as Analyze/deep-dive (agent/core.py's _persist_new_finding).
            # Skipping this here would silently drop a real new finding, the exact class of bug
            # already hit once this session.
            if spec.name == "record_finding" and result.get("status") == "ok" and "recorded" in result:
                conflict_result = await _persist_new_finding(ctx, result["recorded"])
                if conflict_result is not None:
                    logger.debug("core: session=%s reverify: rejected record_finding, cors_check conflict for %r", ctx.session_id, result["recorded"].get("title"))
                    return conflict_result
                logger.debug("core: session=%s reverify: recorded new (unrelated) finding title=%r while re-checking %r", ctx.session_id, result["recorded"].get("title"), title)
            elif spec.name == "cors_check" and result.get("status") == "ok":
                _track_cors_check_verdict(ctx, result)
            elif spec.name == "update_plan" and result.get("status") == "ok" and "recorded" in result:
                _apply_updated_plan(ctx, result["recorded"], "exploit")
            return result

        task = (
            f"A prior scan of this same target recorded this finding:\n{json.dumps(old_finding)}\n\n"
            "Check whether it is STILL real, right now — do not assume the old evidence still holds."
        )
        task += prior_history_note
        task += _out_of_scope_task_addendum(ctx.session)
        task += _out_of_scope_notes_task_addendum(ctx.session)
        task += _custom_instructions_task_addendum(ctx.session)
        task += _goal_task_addendum(ctx.session)
        task += _program_url_task_addendum(ctx.session)
        task += _custom_user_agent_task_addendum(ctx.session)
        task += _custom_headers_task_addendum(ctx.session)
        task += _protection_task_addendum(ctx.session)
        task += _plan_task_addendum(ctx.session, "exploit")
        task += subagent_addendum

        ctx.current_finding_title = title
        try:
            verdict, _trace = await _run_llm_tool_loop(
                ctx, REVERIFY_PROMPT, task, tool_specs, "reverify", execute_tool=execute, terminal_tool="record_reverification_result",
                plan_phase="exploit",  # reverify shares "exploit"'s own plan phase, no separate key of its own
                max_tool_calls=calibrated_max_tool_calls,
            )
            verdict = await _upgrade_stall_forced_reverify_verdict(ctx, verdict, _trace, task, tool_specs, execute)
        finally:
            ctx.current_finding_title = None

        # A no-verdict pass (loop ended without ever calling the terminal tool -- a stall, an
        # exhausted budget) gets the same honest "inconclusive" treatment as a model-reported one,
        # not silently folded into "confirmed fixed" -- both are really "we don't actually know".
        outcome = (verdict or {}).get("verification_outcome") or "inconclusive"
        reasoning = (verdict or {}).get("reasoning") or "No conclusive verdict reached this pass — kept in the report for a future re-check rather than assumed fixed."
        history.append({
            "title": title,
            "verification_outcome": outcome,
            "reasoning": reasoning,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        })
        # Same entry, also into the never-reset ledger prior_history_note above reads from --
        # capped per-title (not just overall) so a finding re-checked across dozens of rescans over
        # a long-lived engagement can't grow this list unboundedly while older rescans' trend for
        # OTHER titles gets pushed out first.
        ledger = ctx.session.setdefault("past_reverification_outcomes", [])
        ledger.append(history[-1])
        kept_for_title = [e for e in ledger if e.get("title") == title][-_MAX_PAST_REVERIFICATION_ENTRIES_PER_TITLE:]
        ctx.session["past_reverification_outcomes"] = [e for e in ledger if e.get("title") != title] + kept_for_title
        save_session(ctx.session_id, ctx.session)

        # Removes the _carried_over_pending_reverify placeholder main.py's rescan_session_in_place
        # seeded session["findings"] with for this exact title (see that route's own docstring) --
        # this finding just got a real verdict, so the "still showing last scan's stale answer
        # while this is re-checked" placeholder's job is done, regardless of which of the three
        # outcomes below follows: confirmed_present/inconclusive replace it with a freshly-persisted
        # entry a few lines down, confirmed_fixed removes it and persists nothing (the bug's gone).
        # A no-op for a brand-new /rescan (a different project, findings starts genuinely empty) and
        # for a normal non-rescan session (carried_over_findings never set, this loop never runs).
        ctx.session["findings"] = [f for f in ctx.session["findings"] if not (f.get("title") == title and f.get("_carried_over_pending_reverify"))]

        if outcome == "confirmed_present":
            reconfirmed = {
                key: old_finding.get(key)
                for key in ("title", "severity", "technology", "exploitation_scenario", "qualifies_for_bounty", "description", "reproduction_steps")
            }
            reconfirmed["verification"] = "verified"
            reconfirmed["evidence_ref"] = (verdict or {}).get("evidence_ref") or old_finding.get("evidence_ref")
            reconfirmed["carried_over_from"] = ctx.session.get("rescanned_from")
            reconfirmed["first_found_at"] = old_finding.get("found_at")
            # Same corrected_* pattern as record_exploit_decision/record_skeptical_verification_result
            # — a reverify pass can just as easily discover the old severity/qualification no longer
            # matches what the fresh re-check actually showed.
            _apply_reverify_correction(reconfirmed, old_finding, verdict, ctx.session_id)
            _apply_corrected_false_positive_reason(reconfirmed, (verdict or {}).get("corrected_false_positive_reason"))
            conflict_result = await _persist_new_finding(ctx, reconfirmed)
            if conflict_result is not None:
                logger.debug("core: session=%s reverify: reconfirmed finding %r rejected on persist, cors_check conflict", ctx.session_id, title)
            else:
                logger.debug("core: session=%s reverify: %r reconfirmed still present, carried forward for exploit", ctx.session_id, title)
        elif outcome == "inconclusive":
            # Real, confirmed incident this fixes: a finding the model explicitly said it "cannot
            # verify either way" (WAF-blocked every attempt) used to vanish from the report with no
            # trace, because the old boolean contract had no room for anything but true/false. Carry
            # the OLD finding forward as-is (never fabricate fresher evidence than actually exists),
            # flagged needs_verification so the report shows it as unresolved, not silently dropped.
            carried = dict(old_finding)
            carried["verification"] = "needs_verification"
            carried["advisory_note"] = f"Reverify could not confirm or refute this: {reasoning}"
            carried["carried_over_from"] = ctx.session.get("rescanned_from")
            carried["first_found_at"] = old_finding.get("found_at")
            _apply_reverify_correction(carried, old_finding, verdict, ctx.session_id)
            _apply_corrected_false_positive_reason(carried, (verdict or {}).get("corrected_false_positive_reason"))
            conflict_result = await _persist_new_finding(ctx, carried)
            if conflict_result is not None:
                logger.debug("core: session=%s reverify: inconclusive finding %r rejected on persist, cors_check conflict", ctx.session_id, title)
            else:
                logger.debug("core: session=%s reverify: %r inconclusive, carried forward flagged needs_verification — %s", ctx.session_id, title, reasoning)
        else:
            # Nothing to persist (the bug's gone) — but the placeholder removal a few lines up still
            # needs flushing to disk now, same as the other two outcomes get via _persist_new_finding's
            # own save_session call, so an operator watching the Findings tab mid-reverify sees this
            # one actually disappear promptly instead of only on whatever save happens to come next.
            save_session(ctx.session_id, ctx.session)
            logger.debug("core: session=%s reverify: %r confirmed fixed, no longer present — %s", ctx.session_id, title, reasoning)

    _mark_phase_finished(ctx.session, "reverify")


async def _run_skeptical_verification(ctx: RunContext) -> None:
    """The last check before a finding ships in the final report as "verified" — a genuinely blind
    second opinion, real motivation: the existing anti-fabrication guard
    (_hypothesis_resolved_without_real_investigation) only checks structure ("was a real tool call
    made"), it cannot catch "a real tool call was made, but the model misread its own output." This
    hands each "verified" finding's claim + reproduction recipe (never the original reasoning/tool
    trace) to a fresh pass of SKEPTICAL_VERIFICATION_PROMPT and requires it to independently
    reproduce or explicitly refute — never a rubber stamp of the original narrative.

    Deliberately NOT built on delegate_to_subagent's own profile system: every subagent profile is
    entirely operator-configured (data/subagent_profiles.json) and can be disabled from Settings at
    any time, and delegation itself is fire-and-forget/async — the wrong shape for something that
    must always run and must block for a real verdict before the session completes. This is instead
    the same direct, synchronous _run_llm_tool_loop call every other real phase (_run_chain,
    _run_reverify) already is. Subagent delegation is deliberately NOT offered here for the same
    reason — it's fire-and-forget/async, the wrong shape for a pass that must always run and block
    for a real verdict before the session can complete.

    The native toolkit's own tools (send_raw_request/list_captured_traffic/decode_value/
    diff_requests/intruder_run), on the other hand, ARE offered here (via _toolkit_tool_extras(),
    same as every other real phase) — unlike the subagent-delegation exclusion above, there was
    never any actual reasoning for leaving them out; this phase's whole point is "independently
    reproduce or explicitly refute" a claim, and send_raw_request/intruder_run are exactly the kind
    of manual, exact-reproduction tools a genuinely blind second opinion benefits from most. Simply
    missing from this phase's own tool_specs assembly until this was flagged in a log-review audit.

    Scoped to verification=="verified" findings only — the one tier that's supposed to already mean
    "an active check actually confirmed it," exactly the claim worth double-checking; a finding still
    at "inferred"/"needs_verification" was never claimed solid in the first place. Only wired into
    run_session's own completion path (see that function) — not into run_focused_exploit/
    run_hypothesis_verification's own later re-validation passes, which are explicit, operator-
    triggered actions on an already-completed session, not the automated pipeline's own end-of-scan
    confidence check.
    """
    findings = ctx.session["findings"]
    to_check = [f for f in findings if f.get("verification") == "verified"]
    if not to_check:
        return
    _mark_phase_started(ctx.session, "skeptical_verification")

    base = (
        get_tools_by_category("recon") + get_tools_by_category("scan") + get_tools_by_category("exploit")
        + _toolkit_tool_extras()
    )
    tool_specs = list({spec.name: spec for spec in base}.values())
    record_result_spec = get_tool("record_skeptical_verification_result")
    if record_result_spec is not None:
        tool_specs.append(record_result_spec)
    logger.debug(
        "core: session=%s starting skeptical_verification phase, %d 'verified' finding(s) to independently check",
        ctx.session_id, len(to_check),
    )

    def _make_execute(active_ctx: RunContext) -> Callable[[ToolSpec, dict], Awaitable[dict]]:
        # A factory, not one shared closure -- the ensemble second-opinion pass below needs its
        # OWN corrected-retry calls to go through the SECONDARY model too (_run_tool_with_retry
        # reads ctx.llm for that), not silently fall back to the primary model's own corrections
        # for a pass that's supposed to be a genuinely independent second opinion throughout.
        async def execute(spec: ToolSpec, arguments: dict) -> dict:
            return await _run_tool_with_retry(active_ctx, spec, arguments)
        return execute

    execute = _make_execute(ctx)

    for finding in to_check:
        title = finding.get("title")
        # Deliberately narrow: only the claim + its reproduction recipe, never advisory_note,
        # never the exploit/chain phase's own "reasoning" — this is what makes the check blind
        # rather than a rubber stamp of the original narrative.
        claim = {
            "title": title,
            "description": finding.get("description"),
            "technology": finding.get("technology"),
            "evidence_ref": finding.get("evidence_ref"),
            "evidence": finding.get("evidence"),
            "reproduction_steps": finding.get("reproduction_steps"),
            "poc_command": finding.get("poc_command"),
        }
        task = f"A finding from this scan claims:\n{json.dumps(claim)}\n\nIndependently confirm or refute this."

        ctx.current_finding_title = title
        try:
            verdict, _trace = await _run_llm_tool_loop(
                ctx, SKEPTICAL_VERIFICATION_PROMPT, task, tool_specs, "skeptical_verification",
                execute_tool=execute, terminal_tool="record_skeptical_verification_result",
            )
        finally:
            ctx.current_finding_title = None

        # A no-verdict pass (loop ended without ever calling the terminal tool) gets the same
        # honest "inconclusive" treatment as a model-reported one -- both really mean "we don't
        # actually know", never silently treated as a pass.
        result = (verdict or {}).get("verdict") or "inconclusive"
        reasoning = (verdict or {}).get("reasoning") or "No conclusive verdict reached this pass."
        finding["skeptical_verification"] = result
        finding["skeptical_verification_note"] = reasoning
        # Real incident this fixes: a "refuted" verdict downgraded verification but left
        # severity/qualifies_for_bounty exactly as Analyze's first guess set them — a finding whose
        # own core claim (e.g. a named host that turned out not to even resolve) was just disproven
        # could still sit in the report as "Medium"/"qualifying". Same corrected_* pattern
        # record_exploit_decision's skip path already applies, just never extended to this sibling
        # terminal tool.
        _apply_corrected_qualification(finding, (verdict or {}).get("corrected_severity"), (verdict or {}).get("corrected_qualifies_for_bounty"))
        _apply_corrected_false_positive_reason(finding, (verdict or {}).get("corrected_false_positive_reason"))
        if result == "refuted":
            # Never silently drop the finding -- same "honestly relabel, don't discard" discipline
            # Reverify's own "inconclusive" carry-forward already follows. An operator still sees
            # it, now correctly flagged as needing another real look instead of standing as
            # trusted "verified" evidence that didn't actually hold up.
            finding["verification"] = "needs_verification"
            logger.debug("core: session=%s skeptical_verification: %r REFUTED, downgraded to needs_verification — %s", ctx.session_id, title, reasoning)
        else:
            logger.debug("core: session=%s skeptical_verification: %r %s — %s", ctx.session_id, title, result, reasoning)

        # Ensemble second opinion -- opt-in (Settings -> Secondary verification provider, None by
        # default), Critical/High only (the two tiers where a wrong verdict either way costs the
        # most: a wrongly-refuted real Critical, or a wrongly-confirmed one shipped to a report).
        # Skipped when the primary verdict was itself "inconclusive" -- nothing decisive yet to
        # cross-check. Real motivation: this session's own log-review audit found the DEFAULT
        # skeptical pass nearly downgrade a real, twice-confirmed Critical finding over a
        # client-side TLS-library quirk the SAME model didn't know to account for -- a genuinely
        # different model/vendor doesn't share that exact blind spot.
        secondary_config = get_secondary_verification_provider() if finding.get("severity") in ("Critical", "High") else None
        if secondary_config is not None and result != "inconclusive":
            try:
                secondary_llm = get_provider(secondary_config["provider"], secondary_config["model"])
            except ValueError:
                secondary_llm = None
                logger.debug(
                    "core: session=%s skeptical_verification: configured secondary provider %s/%s not usable, skipping ensemble check for %r",
                    ctx.session_id, secondary_config["provider"], secondary_config["model"], title,
                )
            if secondary_llm is not None:
                secondary_ctx = replace(ctx, llm=secondary_llm, current_finding_title=title)
                try:
                    secondary_verdict, _secondary_trace = await _run_llm_tool_loop(
                        secondary_ctx, SKEPTICAL_VERIFICATION_PROMPT, task, tool_specs, "skeptical_verification",
                        execute_tool=_make_execute(secondary_ctx), terminal_tool="record_skeptical_verification_result",
                    )
                except Exception as exc:
                    # An ensemble check is a bonus safety net, not a required step -- a crash in
                    # the SECONDARY pass (a misconfigured provider, a transient outage) must never
                    # take down the whole skeptical_verification phase over a finding the PRIMARY
                    # pass already resolved.
                    logger.debug("core: session=%s skeptical_verification: ensemble check for %r crashed (%s), skipping", ctx.session_id, title, exc)
                    secondary_verdict = None

                secondary_result = (secondary_verdict or {}).get("verdict") or "inconclusive"
                secondary_reasoning = (secondary_verdict or {}).get("reasoning") or "No conclusive verdict reached this pass."
                decisive = {"confirmed", "refuted"}
                disagreement = result in decisive and secondary_result in decisive and result != secondary_result
                finding["ensemble_secondary_provider"] = f"{secondary_config['provider']}/{secondary_config['model']}"
                finding["ensemble_secondary_verdict"] = secondary_result
                finding["ensemble_secondary_note"] = secondary_reasoning
                finding["ensemble_disagreement"] = disagreement
                if disagreement:
                    logger.debug(
                        "core: session=%s skeptical_verification: ENSEMBLE DISAGREEMENT on %r -- primary=%s secondary=%s",
                        ctx.session_id, title, result, secondary_result,
                    )
        save_session(ctx.session_id, ctx.session)

    _mark_phase_finished(ctx.session, "skeptical_verification")


def _severity_key(finding: dict) -> int:
    return _SEVERITY_RANK.get(str(finding.get("severity", "")).lower(), len(_SEVERITY_RANK))


def _exploit_priority_key(finding: dict) -> tuple[int, int]:
    # Qualifying-vulnerability findings (session["scope_rules"] set + the model self-reported a
    # match via record_finding's qualifies_for_bounty) get worked before anything else, regardless
    # of severity — the entire point of telling the agent which classes the program actually pays
    # for is to spend its limited exploit-phase budget on those first.
    #
    # A genuinely unset qualifies_for_bounty (None -- nobody has judged it either way yet, e.g. a
    # cve_lookup auto-recorded finding, agent/core.py's own auto-CVE-record loop, which never asks
    # the model for this judgment at all) is deliberately ranked ahead of a KNOWN non_qualifying/
    # unclear one, not lumped in with it -- an unclassified finding could still turn out to be the
    # program's #1 qualifying class, while non_qualifying/unclear already reflects an actual, if
    # negative, judgment call. Never guesses the real classification itself (this project already
    # has a documented, incident-driven rule against fuzzy-matching a finding against free-text
    # scope rules deterministically -- see _warn_if_scope_rules_went_unused's own docstring); this
    # only fixes the ORDER unclassified vs. actively-ruled-out findings get worked in, using a
    # signal (whether a judgment was ever made at all) the finding dict already carries for free.
    if finding.get("qualifies_for_bounty") == "qualifying":
        qualifies_first = 0
    elif finding.get("qualifies_for_bounty") is None:
        qualifies_first = 1
    else:
        qualifies_first = 2
    return (qualifies_first, _severity_key(finding))


def _custom_instructions_task_addendum(session: dict) -> str:
    """Empty when the New Project form's "Custom instructions for this program" field was left
    blank — the agent then behaves exactly as it always has (session["custom_instructions"],
    sessions/store.py's create_session()). Appended to every phase's task message (recon, analyze,
    exploit — see _run_recon/_run_analyze/_run_exploit_for_finding), not just Analyze like
    _scope_rules_task_addendum below: a program's own rules commonly constrain HOW to scan (testing
    windows, required test accounts, out-of-scope paths) as much as which vuln classes pay out.
    """
    custom_instructions = (session.get("custom_instructions") or "").strip()
    if not custom_instructions:
        return ""
    return (
        "\n\nThis project's own custom instructions from the operator — follow these as real "
        f"constraints/priorities, not suggestions:\n{custom_instructions}"
    )


def _goal_task_addendum(session: dict) -> str:
    """Empty when the New Project form's "Goal for this engagement" field was left blank
    (session["goal"], sessions/store.py's create_session()). Distinct from
    _custom_instructions_task_addendum above: a goal is an ASPIRATION to prioritize toward
    ("deepen an existing foothold", "reach the admin panel", "full compromise"), not a constraint
    on how to scan — appended at the exact same call sites as custom_instructions since what the
    operator is ultimately trying to achieve should shape every phase's own prioritization, not
    just one.
    """
    goal = (session.get("goal") or "").strip()
    if not goal:
        return ""
    return (
        "\n\nThe operator's own stated goal for this engagement — let this genuinely shape what "
        f"you prioritize investigating/chaining/exploiting toward, not just background color:\n{goal}"
    )


def _program_url_task_addendum(session: dict) -> str:
    """Empty when session["program_url"] is blank (sessions/store.py's create_session — set by the
    New Project wizard's "Study program page" button, or added/edited later via the Overview tab's
    own "Program URL" field, main.py's update_program_url). Appended at the same call sites as
    _goal_task_addendum above: the agent should know which bug-bounty program this engagement
    belongs to at every phase, not just once at creation, since check_disclosed_reports (an
    already agent-callable tool, category "exploit") needs the URL as an argument and the model
    otherwise has to guess it from context.

    Deliberately does NOT dump the program's own current scope/rules text here — that would bloat
    every single task message with a large page excerpt on every phase transition. The model
    already has its own browser tools to read the page live whenever it actually needs to, and
    _maybe_refresh_program_check above keeps a cheap Hacktivity cache warm in the background for
    the one thing that's checked automatically (a new finding's own duplicate check, see
    _persist_new_finding) — this addendum only needs to make the model aware the option exists.
    """
    program_url = (session.get("program_url") or "").strip()
    if not program_url:
        return ""
    return (
        "\n\nThis engagement is for the bug-bounty/VDP program at "
        f"{program_url}. You may open this page with your own browser tools at any time to check "
        "its current scope/rules, and you may call check_disclosed_reports(program_url=" f"{program_url!r}) "
        "to check that platform's own public disclosed-reports feed for a likely duplicate before "
        "spending real time confirming something that may already be a known, previously-paid "
        "finding — this is a real capability, not a suggestion to ignore."
    )


def _re_experience_level_addendum(session: dict) -> str:
    """Reverse Engineering mode only — session["re_experience_level"] ("novice"/"hobbyist"/
    "professional", sessions/store.py's create_session, main.py's start_re). Appended to the
    SYSTEM prompt (RE_TRIAGE_PROMPT/RE_CHAT_PROMPT), not the task/user message like most other
    addenda in this file — this shapes the model's own persona/tone for the whole conversation,
    not one turn's task framing. "hobbyist" (the default) is genuinely empty (RE_EXPERIENCE_LEVEL_
    ADDENDA, agent/prompts.py) since the base RE prompts already target that tier directly. An
    unrecognized/missing value falls back to that same empty string rather than raising, so a
    pre-existing session from before this field existed behaves exactly as it always has.
    """
    return RE_EXPERIENCE_LEVEL_ADDENDA.get(session.get("re_experience_level") or "hobbyist", "")


def _reconfirmed_findings_task_addendum(session: dict) -> str:
    """Empty for a normal (non-rescan) session, or a rescan session where _run_reverify hasn't
    reconfirmed anything yet. Tells Analyze which findings _run_reverify (which always runs before
    Analyze on a rescan — see run_session()'s sequencing) already re-proved real this pass, so it
    doesn't independently rediscover the identical bug as a second, duplicate finding — the final
    _run_validate dedup pass is a backstop for this, not a guarantee (it falls back to keeping
    everything unchanged on any parse failure), so this is a real signal, not the only one.
    """
    reconfirmed_titles = [f["title"] for f in session.get("findings", []) if f.get("carried_over_from") and f.get("title")]
    if not reconfirmed_titles:
        return ""
    return (
        "\n\nThese findings from a prior scan of this same target were already re-confirmed still "
        "real this pass, before you started — do not independently re-report the same bug as a new "
        f"finding: {json.dumps(reconfirmed_titles)}"
    )


def _previously_ruled_out_task_addendum(session: dict) -> str:
    """The counterpart to _reconfirmed_findings_task_addendum for the OPPOSITE outcome: a finding
    _run_reverify confirmed fixed on some earlier rescan is removed from session["findings"]
    entirely (see that function's own else-branch), so unlike a still-present reconfirmed finding
    it leaves the CURRENT session with nothing pointing back at it — carried_over_findings for the
    NEXT rescan is read straight from the current findings list, so it drops out of that pipeline
    for good. If Recon/Analyze detection later re-flags the same signature anyway (a version banner
    that never changed even after the actual bug got patched, say), Analyze had no way to know this
    exact title was already investigated and ruled fixed before — it looked identical to a genuinely
    fresh lead, real, confirmed operator complaint ("finds the same old vuln, checks it again,
    removes it again as outdated, every single rescan"). session["past_reverification_outcomes"]
    (accumulated across every rescan of this lineage, unlike reverification_history which resets
    each rescan for its own idempotency) is what still remembers it. This never tells the model to
    skip investigating a rediscovered lead -- only gives it the same history a human operator
    re-reading their own last report would have, so it can right-size effort instead of treating a
    repeat as a total unknown.
    """
    fixed_titles = sorted({
        e["title"] for e in session.get("past_reverification_outcomes", [])
        if e.get("verification_outcome") == "confirmed_fixed" and e.get("title")
    })
    if not fixed_titles:
        return ""
    return (
        "\n\nThese exact findings were investigated and confirmed FIXED/not reproducible on a "
        "prior rescan of this same target — if detection flags one of them again, it likely means "
        "the underlying signature (e.g. a version banner) didn't change even though the real bug "
        f"did get fixed; verify normally, don't assume it's automatically still broken: {json.dumps(fixed_titles)}"
    )


def _app_shaped_hostnames_task_addendum(recon_result: dict) -> str:
    """Deterministic trigger for ANALYZE_PROMPT's hostname-shape rule: a Recon-confirmed host
    whose name looks like a real app/API is named explicitly here rather than left for the model
    to notice unprompted on its own in a large recon_result dump."""
    hosts = {t.get("host") for t in recon_result.get("targets", []) if t.get("host")}
    matched = sorted(h for h in hosts if _APP_SHAPED_HOSTNAME_PATTERN.match(h))
    if not matched:
        return ""
    return (
        "\n\nApp-shaped hostname(s) Recon confirmed — call authenticated_crawl from each of these "
        f"before relying on generic guessed paths: {', '.join(matched)}"
    )


def _analyze_delegated_hosts_task_addendum(session: dict, recon_result: dict) -> str:
    """Tells the main agent which confirmed hosts _auto_delegate_analyze_overflow already handed to
    a subagent THIS pass, so its own natural "work through every host from recon_result" behavior
    actually skips them instead of independently re-scanning the exact same hosts.

    Real incident this fixes: _auto_delegate_analyze_overflow's own docstring assumes "the main
    agent naturally starts on [the first host] itself" and stays there while the subagent covers the
    rest -- but nothing in ANALYZE_PROMPT or the task text ever told the main agent that, so it just
    kept working through the FULL host list from recon_result on its own regardless. Confirmed live:
    api.github.com and classroom.github.com were each independently, fully re-scanned by BOTH the
    main agent and the subagent with the identical deep-scan tool set (security_headers_audit,
    ssl_cert_info, common_exposure_scan, nuclei, api_schema_discovery) -- 9 fully duplicate tool
    calls across just those two hosts, real wall-clock and provider-call budget spent twice for zero
    new information. Called once, right where the task text is built at the top of the phase (after
    _auto_delegate_analyze_overflow has already run and populated auto_delegated_analyze_hosts) --
    empty when nothing was delegated this pass, so a session with no enabled Subagent profile (the
    common case) sees no change at all.

    A SECOND, separately confirmed real incident lived right in this function's own final
    sentence: it named `delegated` itself as "the remaining hosts... focus your own effort on" --
    the exact hosts JUST handed to a subagent, not what's actually left. Confirmed live
    (a real session, usr_71c723): the main agent's own tool calls targeted precisely the two
    hosts this sentence told it to "focus on", while a subagent ran the identical deep-scan tool
    set against those same two hosts concurrently -- the real duplication this whole addendum
    exists to prevent, caused by this function itself. Fixed by computing the actual remaining
    (non-delegated) hosts from recon_result, the same distinct-host extraction
    _auto_delegate_analyze_overflow already uses to build its own candidate list.
    """
    delegated = session.get("auto_delegated_analyze_hosts") or []
    if not delegated:
        return ""
    delegated_set = set(delegated)
    seen: set[str] = set()
    remaining: list[str] = []
    for entry in recon_result.get("targets", []):
        host = entry.get("host")
        if not host or host in seen or host in delegated_set:
            continue
        seen.add(host)
        remaining.append(host)
    preamble = (
        "\n\nA subagent is already running a full deep vulnerability scan of these confirmed "
        "host(s) in parallel, right now — do not duplicate that work yourself (no "
        "security_headers_audit/ssl_cert_info/common_exposure_scan/nuclei/api_schema_discovery/etc. "
        "against them again from you); its findings will reach this conversation once it reports "
        f"back: {', '.join(delegated)}"
    )
    if not remaining:
        return (
            f"{preamble}\n\nEvery other confirmed host is already covered by that delegation — "
            "there is nothing else of yours to start independently against a NEW host right now."
        )
    return f"{preamble}\n\nFocus your own effort on the remaining host(s) instead: {', '.join(remaining)}"


def _out_of_scope_task_addendum(session: dict) -> str:
    """Empty when the New Project form's "Out of scope" field was left blank
    (session["out_of_scope"], sessions/store.py's create_session()). The real enforcement is
    _out_of_scope_target/_run_tool_with_retry's deterministic per-call skip — this addendum only
    tells the model up front so a skipped call reads as an expected outcome of a known exclusion,
    not a mystery worth repeatedly retrying against the same excluded host."""
    out_of_scope = session.get("out_of_scope") or []
    if not out_of_scope:
        return ""
    return (
        "\n\nExplicitly OUT OF SCOPE for this project — do not scan, request, or exploit anything "
        f"matching these (enforced automatically; a tool call against one of these is skipped, not "
        f"a bug): {', '.join(out_of_scope)}"
    )


def _out_of_scope_notes_task_addendum(session: dict) -> str:
    """Empty when the New Project form's "Out of scope" field had nothing that failed to parse
    as a concrete host/domain/URL/wildcard (session["out_of_scope_notes"], sessions/store.py's
    create_session()). Real bug-bounty scope tables often phrase an exclusion as a qualifying
    sentence instead of (or alongside) a literal host — e.g. "All domains or subdomains not
    listed in the above list of Scopes" — that can't be pattern-matched against a live tool-call
    target the way session["out_of_scope"] is, so there is no deterministic gate for this one;
    it's the model's own judgment call, same trust level as custom_instructions.
    """
    notes = session.get("out_of_scope_notes") or []
    if not notes:
        return ""
    return (
        "\n\nThis project's own scope table also specifies these out-of-scope qualifiers in "
        "plain language (not a literal host/domain list, so nothing enforces this automatically "
        f"— apply it yourself, the same way you would custom instructions): {'; '.join(notes)}"
    )


def _custom_user_agent_task_addendum(session: dict) -> str:
    """Empty when the New Project form's "Custom User-Agent header" field was left blank
    (session["custom_user_agent"], sessions/store.py's create_session()). agent/core.py's
    _run_tool_with_retry already injects this string as every tool call's params["_user_agent"]
    server-side, and native.py/the nuclei/sqlmap builders already apply it deterministically on
    their own — this addendum exists only for the one gap that deterministic injection can't
    reach: a "discovered" tool (nikto, a custom_tools.yaml entry) whose entire command line is
    free-form text the model composes itself from --help output (agent/tools/builders/discovered.py's
    make_generic_discovered_command doesn't parse structured params at all), so the model has to be
    told to actually add that tool's own User-Agent flag itself.
    """
    custom_user_agent = (session.get("custom_user_agent") or "").strip()
    if not custom_user_agent:
        return ""
    return (
        f"\n\nThis bug-bounty program requires this exact User-Agent string on all test traffic: "
        f'"{custom_user_agent}" — already applied automatically to http_request, nuclei, sqlmap, and '
        "every other structured tool, nothing to do for those. For any tool whose command line you "
        "compose freely from its --help text (e.g. nikto's -useragent flag, or a custom tool's own "
        "equivalent), you must add that flag yourself with this exact string."
    )


def _parse_custom_headers(raw: str | None) -> dict[str, str]:
    """Parses the New Project form's "Custom HTTP Headers" textarea (session["custom_headers"],
    one "Name: Value" pair per line) into a plain dict, the shape every consumer below actually
    wants (an httpx headers dict, or a "Name: Value" CLI flag built per line). A line with no ":"
    is skipped rather than raising -- a human types this field, not the model, and rejecting the
    whole project over one malformed line would lose every other well-formed header on it too.
    """
    headers: dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        name, separator, value = line.partition(":")
        if not separator:
            logger.debug("core: custom_headers line skipped, no ':' separator: %r", line)
            continue
        name = name.strip()
        if not name:
            logger.debug("core: custom_headers line skipped, empty header name: %r", line)
            continue
        headers[name] = value.strip()
    return headers


def _custom_headers_task_addendum(session: dict) -> str:
    """Empty when the New Project form's "Custom HTTP Headers" field was left blank
    (session["custom_headers"], sessions/store.py's create_session()). Same shape as
    _custom_user_agent_task_addendum right above -- agent/core.py's _run_tool_with_retry already
    injects the parsed headers as every tool call's params["_extra_headers"] server-side, and
    native.py/the structured builders already apply them deterministically on their own; this
    addendum only covers the same gap that leaves: a "discovered" tool whose entire command line
    is free-form text the model composes itself from --help output, so the model has to be told to
    add that tool's own header flag(s) itself.
    """
    custom_headers = _parse_custom_headers(session.get("custom_headers"))
    if not custom_headers:
        return ""
    header_lines = "; ".join(f'"{name}: {value}"' for name, value in custom_headers.items())
    return (
        f"\n\nThis bug-bounty program requires these exact extra HTTP headers on all test traffic: "
        f"{header_lines} — already applied automatically to http_request, nuclei, sqlmap, and every "
        "other structured tool, nothing to do for those. For any tool whose command line you compose "
        "freely from its --help text (e.g. nikto, or a custom tool's own equivalent), you must add "
        "these headers yourself with their exact names and values."
    )


# Coarse product-name signal for matching a finding's `technology` field against previously
# confirmed facts about the same stack this session (see _confirmed_tech_facts_task_addendum
# below) — e.g. "Dovecot" in one finding's technology string and another's. Deliberately crude
# (lowercased word split, no stemming/NLP): technology strings here are short, human-written
# product names (agent/tools/native.py's record_finding), not prose worth parsing carefully — a
# false-negative miss (no shared fact surfaced) just means a finding investigates from scratch
# like it always has, never a wrong result; a stray match at worst surfaces an irrelevant note the
# model is already told to independently verify before relying on.
_TECH_KEYWORD_MIN_LENGTH = 4
# _run_analyze's own recon-confirmation boilerplate ("<Product> — confirmed installed at <host>
# (<service>)") appears verbatim in every finding's technology field regardless of product —
# without excluding it, two completely unrelated products (e.g. Dovecot vs Postfix) share enough
# of these words to look like the same stack. Real bug this fixes: caught by a test asserting two
# different products' findings must NOT share a fact, which failed until this list existed.
_TECH_KEYWORD_STOPWORDS = {
    "confirmed", "installed", "host", "hosts", "target", "targets",
    "service", "services", "version", "versions", "from",
}


def _technology_keywords(text: str) -> set[str]:
    return {
        word for word in re.findall(r"[a-z0-9]+", text.lower())
        if len(word) >= _TECH_KEYWORD_MIN_LENGTH and word not in _TECH_KEYWORD_STOPWORDS
    }


def _record_confirmed_tech_fact(session: dict, finding: dict, fact: str) -> None:
    """Called once an exploit-phase pass over one finding reports a durable fact about the
    target's actual software identity/version (record_exploit_decision's optional
    confirmed_tech_fact argument) — e.g. "this host runs Mailcow's bundled Dovecot Community
    Edition, not Dovecot Pro". Real incident this exists for: a scan recorded 5 separate Dovecot
    CVE findings from one blind product-name lookup; the first one exploit-evaluated discovered
    the CE-vs-Pro mismatch at real LLM/tool cost, but the other 4 had no way to learn that same
    fact without independently re-discovering it from scratch.
    """
    keywords = sorted(_technology_keywords(finding.get("technology") or finding.get("title") or ""))
    if not keywords:
        return
    session.setdefault("confirmed_tech_facts", []).append({
        "technology_keywords": keywords,
        "fact": fact,
        "source_finding": finding.get("title"),
    })


def _confirmed_tech_facts_task_addendum(session: dict, finding: dict) -> str:
    """Empty when nothing recorded so far this session overlaps with this finding's own
    `technology` field — the common case (most findings are the first word on their stack, or the
    session has no shared-stack findings at all). Surfaces a *lead* to check, never an answer to
    blindly inherit — the model is still required to reach its own independent conclusion for this
    specific finding (a different CVE on the same product can easily have different preconditions).
    """
    facts = session.get("confirmed_tech_facts") or []
    if not facts:
        return ""
    finding_keywords = _technology_keywords(finding.get("technology") or finding.get("title") or "")
    if not finding_keywords:
        return ""
    matches = [fact for fact in facts if finding_keywords & set(fact.get("technology_keywords") or [])]
    if not matches:
        return ""
    lines = "\n".join(f"- (from finding {fact['source_finding']!r}): {fact['fact']}" for fact in matches)
    return (
        "\n\nAlready confirmed earlier in this same session, about this same technology stack — "
        "check whether it also applies here before repeating the same discovery work from "
        f"scratch, but still reach your own independent conclusion for THIS finding:\n{lines}"
    )


def _playbook_enabled() -> bool:
    return os.getenv("PLAYBOOK_ENABLED", "true").strip().lower() == "true"


def _playbook_max_injected_entries() -> int:
    return int(os.getenv("PLAYBOOK_MAX_INJECTED_ENTRIES", "5"))


def _playbook_prune_min_injections() -> int:
    """Auto-prune threshold: an entry surfaced this many times as a lead that never once preceded a
    confirmed finding is dropped as proven noise (playbook_store.prune_low_value, run in the
    distillation pass). 0 disables pruning entirely."""
    return int(os.getenv("PLAYBOOK_PRUNE_MIN_INJECTIONS", "8"))


# Matches the vendor name back out of _merge_protection_detection's own label strings (e.g.
# "Cloudflare (WAF, nuclei global-waf-detect)", "sucuri (WAF/CDN, whatweb)") -- "WAF" is a prefix
# of "WAF/CDN" too, so matching just "WAF" right after the opening paren covers both label shapes.
_WAF_LABEL_VENDOR_RE = re.compile(r"^(.*?)\s*\(WAF")


def _waf_vendors_from_protections(session: dict) -> frozenset[str]:
    """Session-wide (not per-host — record_finding carries no host field to key a single one out
    by, see _finding_fingerprint below) set of WAF/CDN vendor names already deterministically
    identified this session via _merge_protection_detection's real nuclei/whatweb matches. Never a
    guess: "Unidentified WAF" matches (no product name in the underlying tool's own output) are
    dropped rather than fingerprinted as a fake vendor name.
    """
    protections = session.get("recon_result", {}).get("protections") or {}
    vendors: set[str] = set()
    for labels in protections.values():
        for label in labels or []:
            # _merge_protection_detection's own "no product name" case reads "Unidentified WAF
            # (nuclei global-waf-detect)" -- note the parenthetical there starts with "nuclei", not
            # "WAF", so it never matches _WAF_LABEL_VENDOR_RE at all; caught here explicitly instead
            # of relying on the regex to (accidentally) not match it.
            if label.lower().startswith("unidentified waf"):
                continue
            match = _WAF_LABEL_VENDOR_RE.match(label)
            name = (match.group(1) if match else label).strip().lower()
            if name:
                vendors.add(name)
    return frozenset(vendors)


def _finding_fingerprint(session: dict, finding: dict) -> tuple[frozenset[str], frozenset[str]]:
    """The playbook's own fingerprint primitive (tech_keywords, waf_vendors) -- reuses
    _technology_keywords verbatim (the same keyword-set already proven for
    _confirmed_tech_facts_task_addendum's same-session version of this same idea) for the
    CMS/framework/backend-language half, plus _waf_vendors_from_protections for the WAF half. Both
    halves are derived from real tool output, never from asking the model to restate the stack.
    """
    tech_keywords = frozenset(_technology_keywords(finding.get("technology") or finding.get("title") or ""))
    return tech_keywords, _waf_vendors_from_protections(session)


def _playbook_fingerprint_key(tech_keywords: frozenset[str], waf_vendors: frozenset[str]) -> str:
    return json.dumps({"tech": sorted(tech_keywords), "waf": sorted(waf_vendors)}, sort_keys=True)


def _current_target_fingerprint(session: dict) -> tuple[frozenset[str], frozenset[str]]:
    """tool_memory_store's own fingerprint primitive -- same two building blocks as
    _finding_fingerprint (_technology_keywords, _waf_vendors_from_protections), but sourced from the
    SESSION as a whole rather than one finding: at tool-dispatch time no finding exists yet for the
    tool that's about to run, so this reads whatever technology signal recon_result["technologies"]
    (host -> [tech tokens]) already carries session-wide, real tool output either way.
    """
    technologies = session.get("recon_result", {}).get("technologies") or {}
    tech_tokens = [tok for toks in technologies.values() if isinstance(toks, list) for tok in toks] if isinstance(technologies, dict) else []
    tech_keywords = frozenset(_technology_keywords(" ".join(tech_tokens)))
    return tech_keywords, _waf_vendors_from_protections(session)


def _playbook_notes_path(session_id: str) -> Path | None:
    """The project-local half of the two-tier memory — None for a session with no real on-disk
    project folder (legacy pre-project-folder sessions, see get_session_folder's own docstring)."""
    folder = get_session_folder(session_id)
    return Path(folder) / "playbook_notes.md" if folder else None


def _append_playbook_note(session_id: str, line: str) -> None:
    path = _playbook_notes_path(session_id)
    if path is None:
        return
    with path.open("a", encoding="utf-8") as f:
        f.write(line.rstrip("\n") + "\n")


def _notify_storage_reward(session_id: str, *, kind: str, label: str, delta: int, total: int, total_label: str, detail: str) -> None:
    """Drops a small gamified "+N" reward into this session's active chat thread whenever something
    worth remembering lands in storage (a new finding, a captured playbook technique) -- so an
    operator watching the chat sees the run's real progress accrue live, in BOTH agent and
    interactive mode. Local import (agent/chat.py imports FROM this module at its own top level, so
    the reverse must stay deferred, same escape hatch _on_subagent_task_done already uses). Best-
    effort by construction: a notification failing must never break the scan that produced the
    reward -- the storage write itself already happened by the time this runs."""
    try:
        from agent.chat import deliver_storage_reward_to_chat
        deliver_storage_reward_to_chat(
            session_id, kind=kind, label=label, delta=delta, total=total, total_label=total_label, detail=detail,
        )
    except Exception as exc:
        _playbook_logger.debug("core: session=%s storage-reward notification failed (%s) -- ignored", session_id, exc)


def _credit_tool_memory_for_finding(ctx: RunContext, finding: dict) -> None:
    """The tool_memory_store counterpart to _credit_playbook_for_finding above -- reuses whatever
    tool_timeline a finding has already accumulated (via _append_tool_timeline, real dispatched tool
    names only) to credit each of those tools as "productive" against this session's current
    fingerprint. Called alongside _maybe_capture_playbook_entry below at every site that touches a
    finding, since tool_timeline genuinely grows over a finding's lifecycle (a discovery_tool credit
    at Analyze-persist time, more exploitation-stage tools once Exploit confirms it) -- crediting at
    each of those points lets whichever tools actually contributed get real, incremental credit
    rather than only whatever was in tool_timeline at one single fixed moment.
    """
    tool_names = {entry.get("tool") for entry in (finding.get("tool_timeline") or []) if entry.get("tool")}
    if not tool_names:
        return
    try:
        fingerprint_key = _playbook_fingerprint_key(*_current_target_fingerprint(ctx.session))
        tool_memory_store.credit_tool_run(fingerprint_key, tool_names)
    except Exception:
        logger.debug("core: session=%s _credit_tool_memory_for_finding failed, skipping this update", ctx.session_id, exc_info=True)


def _maybe_capture_playbook_entry(ctx: RunContext, finding: dict) -> None:
    """Called once a finding is genuinely proven (exploited=True with real evidence) — captures it
    into the cross-session playbook (agent/tools/playbook_store.py) keyed by its fingerprint, and
    appends a plain-language line to this project's own playbook_notes.md (the "local, target-
    specific" half of the memory). Deliberately NOT triggered by resolve_hypothesis(status=
    "confirmed") — that tool's own description already tells the model to also call record_finding
    for the real thing, so this hook already captures it there; a bare hypothesis has no
    poc_command/evidence structure to capture anyway.
    """
    if not _playbook_enabled():
        return
    if not finding.get("exploited") or not finding.get("evidence"):
        return

    tech_keywords, waf_vendors = _finding_fingerprint(ctx.session, finding)
    if not tech_keywords:
        _playbook_logger.debug(
            "core: session=%s playbook capture skipped for finding=%r — no technology keywords to key on",
            ctx.session_id, finding.get("title"),
        )
        return

    fingerprint_key = _playbook_fingerprint_key(tech_keywords, waf_vendors)
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": uuid.uuid4().hex[:12],
        "technique": finding.get("title") or "",
        "vuln_class": finding.get("exploitation_scenario"),
        "payload_or_command": finding.get("poc_command"),
        # CVEs this technique names (auto-extracted) -- threat-intel (KEV/EPSS) keys off these.
        "cves": playbook_store.extract_cves(finding.get("title") or "", finding.get("poc_command") or "", finding.get("evidence") or "", finding.get("description") or ""),
        "evidence_ref": (finding.get("evidence") or "")[:500],
        "tech_keywords": sorted(tech_keywords),
        "waf_vendors": sorted(waf_vendors),
        # "worked" vs "failed" -- the autonomous capture only ever fires on a genuinely proven
        # finding, so it's always "worked" here; the chat's own record_technique tool (agent/chat.py)
        # is what feeds "failed" dead-end knowledge in. _playbook_task_addendum surfaces the two
        # separately (leads to try vs. known dead-ends to skip). Existing pre-outcome entries read as
        # "worked" by default wherever this field is consumed.
        "outcome": "worked",
        "times_confirmed": 1,
        # Attribution counters (populated by the Unit-2 feedback loop): how often this entry was
        # surfaced as a lead, and how often a confirmed finding followed in a session it was surfaced
        # in. success_rate = led_to_finding_count / injected_count drives ranking + auto-pruning.
        "injected_count": 0,
        "led_to_finding_count": 0,
        # Kill-chain link: the technique captured just before this one this session (if any). Lets
        # the addendum resurface multi-step recipes (foothold -> escalation -> RCE), not just lone
        # payloads. Only set on a genuinely new entry; a dedup keeps whatever chain it already had.
        "chained_from_ids": _playbook_chain_predecessor(ctx.session),
        "last_seen": now,
        # When this technique last actually WORKED -- drives staleness decay (a bypass proven a year
        # ago is worth less than one proven last week; WAF vendors patch fast). Set here (an
        # autonomous capture only fires on a real success).
        "last_confirmed_at": now,
        "source_session_ids": [ctx.session_id],
        # A real, exploited-with-evidence finding -- this IS field proof, the standing every
        # library-extracted (source_type="extracted") entry is still waiting to earn. Also what
        # lets record_technique's own dedup branch auto-confirm a matching unreviewed entry.
        "source_type": "live",
        "confidence": "confirmed",
    }
    recorded_id = playbook_store.record_technique(fingerprint_key, entry)
    _track_playbook_chain(ctx.session, recorded_id)
    # Embed the freshly captured technique for semantic search (best-effort, via the active provider).
    if recorded_id:
        _embed_playbook_entries(ctx.llm, [{**entry, "id": recorded_id}])
    _notify_storage_reward(
        ctx.session_id, kind="technique", label="New technique captured", delta=1,
        total=playbook_store.count_techniques(), total_label="in playbook", detail=entry["technique"],
    )
    touched = ctx.session.setdefault("playbook_touched_keys", [])
    if fingerprint_key not in touched:
        touched.append(fingerprint_key)

    _append_playbook_note(ctx.session_id, f"- {entry['technique']}: {entry['evidence_ref'][:200]}")
    _playbook_logger.debug(
        "core: session=%s playbook captured finding=%r under key=%r",
        ctx.session_id, finding.get("title"), fingerprint_key,
    )


def _playbook_chain_predecessor(session: dict) -> list[str]:
    """The id of the technique captured just before this one in the SAME session, if any -- the
    kill-chain link a newly captured technique records as its predecessor (chained_from_ids). Two
    techniques proven in sequence against one target are usually a real chain (foothold -> escalation
    -> RCE), so recording that order lets the addendum resurface multi-step recipes, not just
    isolated payloads."""
    recorded = session.get("playbook_recorded_ids") or []
    return [recorded[-1]] if recorded else []


def _track_playbook_chain(session: dict, technique_id: str | None) -> None:
    """Appends the just-captured technique's id to this session's ordered chain, so the NEXT capture
    can link back to it. Deduped against the immediate predecessor so re-confirming the same
    technique twice in a row doesn't create a self-link."""
    if not technique_id:
        return
    recorded = session.setdefault("playbook_recorded_ids", [])
    if not recorded or recorded[-1] != technique_id:
        recorded.append(technique_id)


def _embed_playbook_entries(llm, entries: list[dict]) -> int:
    """Best-effort: embed the given technique entries via the ACTIVE provider (llm.embed) and cache
    the vectors for semantic search. Returns how many were embedded (0 if the provider has no
    embeddings endpoint -- llm.embed returns None -- or lacks the method entirely). Never raises into
    the capture path; when it returns 0, everything just falls back to keyword matching."""
    if not entries or not _playbook_enabled():
        return 0
    embed = getattr(llm, "embed", None)
    if embed is None:
        return 0
    ids = [e.get("id") for e in entries]
    texts = [playbook_store.build_embedding_text(e) for e in entries]
    try:
        model = playbook_store.embedding_model()
        vectors = embed(texts, model=model)
    except Exception as exc:
        _playbook_logger.debug("core: playbook embed failed (%s) -- ignored, keyword search still works", exc)
        return 0
    if not vectors:
        return 0
    mapping = {tid: vec for tid, vec in zip(ids, vectors) if tid and isinstance(vec, list)}
    if mapping:
        playbook_store.store_embeddings(mapping, model)
        _playbook_logger.debug("core: embedded %d playbook technique(s) for semantic search", len(mapping))
    return len(mapping)


def _embed_playbook_query(llm, text: str) -> list[float] | None:
    """Embed a search query (the target's fingerprint text, or a natural-language query_playbook
    call) via the active provider. None means keyword-only search (no provider, no embeddings, or an
    error) -- the caller degrades gracefully."""
    if not (text or "").strip() or not _playbook_enabled():
        return None
    embed = getattr(llm, "embed", None)
    if embed is None:
        return None
    try:
        vectors = embed([text], model=playbook_store.embedding_model())
    except Exception:
        return None
    return vectors[0] if vectors else None


def _re_playbook_technique_block(matches: list[dict]) -> str:
    """Renders retrieved techniques (outcome/stale flags, payload) for re_playbook_strategy's own
    synthesis prompt -- same shape as agent/chat.py's own _strategy_technique_block, duplicated for
    the same module-boundary reason every other playbook helper here is (see re_query_playbook's
    own docstring)."""
    lines = []
    for m in matches:
        flags = ["DEAD-END"] if m.get("outcome") == "failed" else ["works"]
        if m.get("outcome") != "failed" and playbook_store.is_stale(m):
            flags.append("STALE")
        line = f"- [{', '.join(flags)}] {m.get('technique')}"
        if m.get("payload_or_command"):
            line += f"\n    payload/command: {m['payload_or_command']}"
        lines.append(line)
    return "\n".join(lines)


def re_query_playbook(params: dict) -> dict:
    """query_playbook for Reverse Engineering mode's own toolset (category="re") -- a natural-
    language, read-only, on-demand search over the cross-session playbook. Real, confirmed gap
    this closes: RE mode's own run_re_triage/run_re_reverify (agent/core.py) had ZERO playbook
    access at all before this -- their tool list was always just get_tools_by_category("re") plus
    whatever terminal tool the pass needed, never any of the three playbook tools chat.py's own
    CHAT_PROMPT/INTERACTIVE_CHAT_PROMPT sessions have always had. This is a parallel, RE-scoped
    counterpart to agent/chat.py's own _apply_chat_query_playbook -- genuinely duplicated rather
    than shared, because chat.py imports FROM this module (agent.core) at module level, so the
    reverse import here would be circular; the SAME accepted duplication already exists for
    _technology_keywords/_embed_playbook_query themselves (chat.py keeps its own near-identical
    copies for this exact reason). Unlike chat's own version, this returns structured data (the
    native-tool convention every other function in this module/native.py follows -- see
    agent/tools/native.py's cve_lookup for the same status/structured-fields shape) rather than a
    single prose confirmation string, since this is dispatched through the generic native-tool
    path (_run_tool_with_retry), not chat.py's own result.get("confirmation") handling.

    `_llm` is server-injected (see _run_tool_with_retry's own injected-fields block) -- the model
    never supplies it, the same convention _session/_session_id already use for tools that need
    live context no JSON schema could sanely expose.
    """
    llm = params.get("_llm")
    query = (params.get("query") or "").strip()
    if not query:
        return {"status": "error", "error": "query is required"}
    tech = frozenset(_technology_keywords(" ".join(str(t) for t in (params.get("tech_keywords") or []))))
    waf = frozenset(str(w).strip().lower() for w in (params.get("waf_vendors") or []) if str(w).strip())
    vec = _embed_playbook_query(llm, query) if llm is not None else None
    if vec is None and not tech:
        tech = frozenset(_technology_keywords(query))
    matches = playbook_store.find_similar_techniques(set(tech), set(waf), 6, query_embedding=vec)
    search_mode = "semantic" if vec is not None else "keyword"
    return {
        "status": "ok",
        "search_mode": search_mode,
        "matches": [
            {
                "technique": m.get("technique"),
                "outcome": m.get("outcome", "worked"),
                "payload_or_command": m.get("payload_or_command"),
                "vuln_class": m.get("vuln_class"),
                "times_confirmed": m.get("times_confirmed", 1),
            }
            for m in matches
        ],
    }


def re_playbook_strategy(params: dict) -> dict:
    """playbook_strategy for Reverse Engineering mode's own toolset -- composes retrieved
    techniques into ONE concrete, ordered plan via a focused LLM synthesis pass, the RE-scoped
    counterpart to agent/chat.py's own _apply_chat_playbook_strategy (same duplication reasoning
    as re_query_playbook's own docstring above). Sync, not async -- llm.complete/llm.embed are
    both plain sync methods (confirmed against agent/chat.py's own asyncio.to_thread(llm.complete,
    ...) wrapping, which exists specifically to run a SYNC blocking call off the event loop's own
    thread, not because llm.complete is itself async), and every native_function in this codebase
    (agent/tools/native.py) is a plain sync `def`, dispatched via runner.py's own _run_native
    inside a worker thread (asyncio.to_thread(run_tool, ...), agent/core.py) -- no async plumbing
    needed here at all."""
    llm = params.get("_llm")
    query = (params.get("query") or "").strip()
    if not query:
        return {"status": "error", "error": "query is required"}
    tech = frozenset(_technology_keywords(" ".join(str(t) for t in (params.get("tech_keywords") or []))))
    waf = frozenset(str(w).strip().lower() for w in (params.get("waf_vendors") or []) if str(w).strip())
    vec = _embed_playbook_query(llm, query) if llm is not None else None
    if vec is None and not tech:
        tech = frozenset(_technology_keywords(query))
    matches = playbook_store.find_similar_techniques(set(tech), set(waf), 8, query_embedding=vec)
    search_mode = "semantic" if vec is not None else "keyword"
    if not matches:
        return {
            "status": "ok",
            "confirmation": f"No stored techniques match that target ({search_mode} search) -- nothing to build a strategy from yet.",
        }
    technique_block = _re_playbook_technique_block(matches)
    task = f"Target:\n{query}\n\nRetrieved techniques ({search_mode} search):\n{technique_block}"
    messages = [
        {"role": "system", "content": PLAYBOOK_STRATEGY_PROMPT},
        {"role": "user", "content": task},
    ]
    strategy = ""
    if llm is not None:
        try:
            response = llm.complete(messages, None)
            strategy = (response.content or "").strip()
        except Exception as exc:
            logger.debug("core: re_playbook_strategy synthesis failed (%s) -- returning raw matches", exc)
    if not strategy:
        return {
            "status": "ok",
            "confirmation": f"Retrieved techniques ({search_mode} search), couldn't compose a plan:\n{technique_block}",
        }
    return {
        "status": "ok",
        "confirmation": f"Attack strategy composed from {len(matches)} playbook technique(s):\n\n{strategy}",
    }


def re_record_technique(params: dict) -> dict:
    """record_technique for Reverse Engineering mode's own toolset -- saves a reusable technique
    (or confirmed DEAD-END, worked=false) into the cross-session playbook, keyed by tech_keywords/
    waf_vendors exactly like the autonomous web-pentest pipeline's own _maybe_capture_playbook_entry
    already does, so an RE-mode-recorded entry and a web-pentest-recorded one are retrievable
    through the exact same find_similar_techniques lookup. RE-scoped counterpart to agent/chat.py's
    own _apply_chat_record_technique (same duplication reasoning as re_query_playbook's docstring).
    `_llm`/`_session_id` are server-injected, never supplied by the model."""
    llm = params.get("_llm")
    session_id = params.get("_session_id")
    technique = (params.get("technique") or "").strip()
    if not technique:
        return {"status": "error", "error": "technique is required"}

    raw_keywords = params.get("tech_keywords") or []
    tech_keywords = frozenset(_technology_keywords(" ".join(str(t) for t in raw_keywords)))
    if not tech_keywords:
        tech_keywords = frozenset(_technology_keywords(technique))
    waf_vendors = frozenset(str(w).strip().lower() for w in (params.get("waf_vendors") or []) if str(w).strip())

    worked = params.get("worked", True)
    outcome = "worked" if worked else "failed"
    key = playbook_store.make_fingerprint_key(tech_keywords, waf_vendors)
    now = datetime.now(timezone.utc).isoformat()
    entry = {
        "id": uuid.uuid4().hex[:12],
        "technique": technique,
        "vuln_class": (params.get("vuln_class") or "").strip() or None,
        "payload_or_command": (params.get("payload_or_command") or "").strip() or None,
        "cves": playbook_store.extract_cves(technique, str(params.get("payload_or_command") or "")),
        "evidence_ref": "",
        "tech_keywords": sorted(tech_keywords),
        "waf_vendors": sorted(waf_vendors),
        "outcome": outcome,
        "times_confirmed": 1,
        "injected_count": 0,
        "led_to_finding_count": 0,
        "chained_from_ids": [],
        "last_seen": now,
        "last_confirmed_at": now if worked else None,
        "source_session_ids": [session_id] if session_id else [],
        "source_type": "live",
        "confidence": "confirmed",
    }
    recorded_id = playbook_store.record_technique(key, entry)
    if llm is not None and recorded_id:
        _embed_playbook_entries(llm, [{**entry, "id": recorded_id}])
    total = playbook_store.count_techniques()
    logger.debug("core: session=%s re_record_technique outcome=%s key=%r total=%d", session_id, outcome, key, total)
    return {
        "status": "ok",
        "confirmation": f"Saved a {'working technique' if worked else 'dead-end'} to the playbook -- {total} technique(s) stored now.",
        "total_techniques": total,
    }


# category="re" so get_tools_by_category("re") -- already called by both run_re_triage and
# run_re_reverify -- picks these up automatically, no extra wiring needed at either call site.
# Registered directly here (not agent/tools/__init__.py, where every other ToolSpec lives) because
# these three native_functions are defined in THIS module and depend on other core.py-only helpers
# (_technology_keywords/_embed_playbook_query/_embed_playbook_entries/playbook_store) -- moving
# them into agent/tools/__init__.py would need that file to import FROM agent.core, which is
# already imported BY agent.tools (agent/core.py's own `from agent.tools... import` lines), a
# genuine circular import. register_tool() just appends to registry.py's own module-level
# TOOL_REGISTRY list -- calling it from here operates on the exact same shared list every other
# registration already populated, since Python only ever executes a module once regardless of
# which other module first imports it. Deliberately excluded from chat.py's own RE-mode tool list
# (_chat_tool_specs's own category="re" append) -- chat already has query_playbook/
# playbook_strategy/record_technique under those exact names via its own _CHAT_TOOLS_SCHEMA
# (always included, every mode); registering these here too would put two same-named tool
# definitions in the schema sent to the model for an RE-mode chat turn.
register_tool(
    ToolSpec(
        name="query_playbook",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=re_query_playbook,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Search the cross-session playbook for reverse-engineering techniques relevant to what "
            "you're about to try -- a natural-language question ('how did we get past this UPX-style "
            "packer before?', 'reentrancy pattern in a proxy contract') matches by MEANING, not just "
            "keywords, surfacing prior wins (and confirmed dead-ends to avoid) even when worded "
            "differently. Use it before re-deriving an approach from scratch."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What you're looking for, in plain language"},
                "tech_keywords": {"type": "array", "items": {"type": "string"}, "description": "Optional: narrow to a stack, e.g. [\"rust\", \"pe32\"] or [\"solidity\", \"proxy\"]"},
                "waf_vendors": {"type": "array", "items": {"type": "string"}, "description": "Optional, rarely relevant to RE work -- left over from this field's own web-pentest origin, only fill it if a genuinely comparable gate/protection applies here"},
            },
            "required": ["query"],
        },
    )
)

register_tool(
    ToolSpec(
        name="playbook_strategy",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=re_playbook_strategy,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Compose a concrete, ordered PLAN for approaching this target out of the cross-session "
            "playbook, instead of just listing matches. Describe the target (binary/contract/source "
            "shape, what you want to achieve) and it retrieves the relevant proven techniques -- "
            "recipes, dead-ends to avoid, stale ones to re-verify -- then synthesizes them into "
            "step-by-step guidance. Use it when planning HOW to approach something end-to-end; use "
            "query_playbook instead for a quick lookup."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "The target and goal, in plain language, e.g. 'Rust PE32+ crackme, want the serial-check algorithm'"},
                "tech_keywords": {"type": "array", "items": {"type": "string"}, "description": "Optional: the target's own stack, e.g. [\"rust\", \"pe32\"]"},
                "waf_vendors": {"type": "array", "items": {"type": "string"}, "description": "Optional, rarely relevant to RE work"},
            },
            "required": ["query"],
        },
    )
)

register_tool(
    ToolSpec(
        name="record_technique",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=re_record_technique,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Save a reusable reverse-engineering technique (or a confirmed DEAD-END) into the "
            "cross-session playbook -- the accumulating knowledge that surfaces as a lead the next "
            "time a similarly fingerprinted target shows up (same packer, same language/architecture, "
            "same contract pattern), so future sessions don't re-derive it from scratch. Call this the "
            "moment you actually CONFIRM something reusable: how a specific packer/obfuscation was "
            "defeated, a decompilation trick that worked around a missing plugin, a way to recover a "
            "serial/key-generation algorithm, a smart-contract vulnerability pattern -- OR, just as "
            "valuable, that a plausible approach definitively did NOT work (worked=false), so it's not "
            "retried later. Only record genuinely confirmed, generalizable knowledge, not a guess."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "technique": {"type": "string", "description": "The reusable insight, in one or two sentences (what to do / what was observed)"},
                "payload_or_command": {"type": "string", "description": "The concrete command, script, or byte pattern, if there is one"},
                "tech_keywords": {"type": "array", "items": {"type": "string"}, "description": "The target shape it applies to, e.g. [\"rust\",\"pe32\",\"upx\"] or [\"solidity\",\"proxy\",\"reentrancy\"] -- used to key + retrieve it. Include at least one."},
                "waf_vendors": {"type": "array", "items": {"type": "string"}, "description": "Rarely relevant to RE work -- left over from this field's own web-pentest origin, optional"},
                "vuln_class": {"type": "string", "description": "Vulnerability/technique class, e.g. reentrancy / integer_overflow / anti_debug_bypass / packer_unwrap -- optional"},
                "worked": {"type": "boolean", "description": "true = it worked (a lead for next time); false = a confirmed dead-end (skip it next time). Defaults to true."},
            },
            "required": ["technique"],
        },
    )
)


def re_record_target_profile(params: dict) -> dict:
    """Records or updates one fact about THIS target into session["target_profile"] -- a per-
    project (not cross-session like the playbook above) running summary of what's actually been
    established about it: language, compiler/toolchain, obfuscator/packer, platform/architecture,
    version, or any other detail worth keeping in view without re-deriving it from scratch every
    turn. Real, confirmed gap this closes: an RE chat session repeatedly re-discovered "this is Go,
    not Rust" and "compiled with garble" across several separate turns/subagent delegations because
    nothing durable held that fact once established -- each fresh turn's own context had no memory
    of it beyond whatever happened to still be in the chat transcript.

    One fact per call (`label`+`value`), same one-record-per-call convention record_finding/
    record_technique already use -- a label that already exists (case-insensitive match) gets its
    value UPDATED in place rather than duplicated, so re-confirming or refining an earlier fact
    (e.g. "Compiler: unknown" -> "Compiler: go1.22, inferred from runtime strings") never leaves a
    stale duplicate entry sitting alongside the corrected one. Surfaced to the operator in the
    Reserved pane next to Findings (templates/partials/target_profile.html) and to every future
    chat turn via _session_snapshot's own "target_profile" field (agent/chat.py) -- the whole point
    is that once a fact lands here, the model never has to re-derive or re-ask for it again.
    """
    session_id = params.get("_session_id")
    session = params.get("_session")
    if not session_id or session is None:
        return {"status": "error", "error": "record_target_profile requires session context"}
    label = (params.get("label") or "").strip()
    value = (params.get("value") or "").strip()
    if not label:
        return {"status": "error", "error": "label is required"}
    if not value:
        return {"status": "error", "error": "value is required"}
    profile = session.setdefault("target_profile", [])
    existing = next((fact for fact in profile if str(fact.get("label", "")).lower() == label.lower()), None)
    if existing is not None:
        existing["value"] = value
    else:
        profile.append({"label": label, "value": value})
    save_session(session_id, session)
    return {"status": "ok", "recorded": {"label": label, "value": value}}


register_tool(
    ToolSpec(
        name="record_target_profile",
        category="re",
        tool_tier=1,
        executable="",
        build_command=None,
        native_function=re_record_target_profile,
        requires_allowed_target=False,
        installed_by_default=True,
        description=(
            "Record or update one durable fact about THIS target -- language, compiler/toolchain, "
            "obfuscator/packer, platform/architecture, version, or any other detail worth keeping in "
            "view without re-deriving it every turn. One fact per call; calling again with a label "
            "that already exists updates its value instead of duplicating it. Call this the moment "
            "you actually establish something concrete (e.g. from real runtime strings, a compiler "
            "signature, a header) -- not a guess. Shown to the operator alongside Findings and kept "
            "in view for every later turn of this same session."
        ),
        parameters_schema={
            "type": "object",
            "properties": {
                "label": {"type": "string", "description": "Short fact name, e.g. \"Language\", \"Compiler\", \"Obfuscator\", \"Platform\", \"Architecture\", \"Packer\""},
                "value": {"type": "string", "description": "The fact itself, e.g. \"Go (not Rust) -- confirmed via runtime strings\""},
            },
            "required": ["label", "value"],
        },
    )
)


def _record_playbook_injections(session: dict, matches: list[dict]) -> None:
    """Attribution's injection half: the moment a technique is actually surfaced as a lead, note it
    (once per session per technique) and bump its injected_count in the global store, so success_rate
    = led_to_finding_count / injected_count has a real denominator. Tracked on the session
    (playbook_injected_ids) both to dedupe the bump and to know, when a finding later lands, which
    techniques were in play to credit (_credit_playbook_for_finding). Best-effort -- an accounting
    failure must never break prompt building."""
    injected = session.setdefault("playbook_injected_ids", [])
    new_ids = {m.get("id") for m in matches if m.get("id") and m.get("id") not in injected}
    if not new_ids:
        return
    injected.extend(sorted(new_ids))
    try:
        playbook_store.bump_injected(new_ids)
    except Exception as exc:
        _playbook_logger.debug("core: session=%s playbook injection accounting failed (%s) -- ignored", session.get("session_id"), exc)


def _credit_playbook_for_finding(session: dict) -> None:
    """Attribution's success half: a confirmed finding landed, so credit every technique surfaced as
    a lead this session (once each, deduped via playbook_credited_ids). Coarse but honest -- the
    surfaced leads were, by construction, relevant to THIS session's own fingerprint (that's why
    find_similar_techniques returned them), and a real finding followed. Over many sessions this
    makes success_rate track "how often being shown this actually preceded a win", which ranking and
    pruning both key off. Best-effort."""
    injected = session.get("playbook_injected_ids") or []
    if not injected:
        return
    credited = session.setdefault("playbook_credited_ids", [])
    to_credit = {i for i in injected if i not in credited}
    if not to_credit:
        return
    credited.extend(sorted(to_credit))
    try:
        playbook_store.bump_led_to_finding(to_credit)
    except Exception as exc:
        _playbook_logger.debug("core: session=%s playbook credit accounting failed (%s) -- ignored", session.get("session_id"), exc)


def _playbook_task_addendum(session: dict, finding: dict | None = None, track_injections: bool = False, llm=None) -> str:
    """Surfaces prior-session techniques that worked against a similarly fingerprinted stack — same
    "lead to check, never an answer to blindly inherit" framing as
    _confirmed_tech_facts_task_addendum, just sourced across sessions instead of within one. Empty
    when playbook is disabled, nothing was ever captured for an overlapping stack, or (finding=None,
    the Analyze-phase call shape) recon hasn't found any technology yet to key on.

    When `llm` is supplied, the current target's context is embedded via that provider and the
    retrieval goes HYBRID (semantic + keyword), so a technique whose wording differs from this
    target's but whose meaning matches still surfaces. No provider / no embeddings -> keyword-only,
    exactly as before.
    """
    if not _playbook_enabled():
        return ""
    if finding is not None:
        tech_keywords, waf_vendors = _finding_fingerprint(session, finding)
    else:
        technologies: list[str] = []
        for tokens in (session.get("recon_result", {}).get("technologies") or {}).values():
            technologies.extend(tokens)
        tech_keywords = frozenset(_technology_keywords(" ".join(technologies)))
        waf_vendors = _waf_vendors_from_protections(session)
    if not tech_keywords:
        return ""

    query_vuln_class = finding.get("exploitation_scenario") if finding else None
    # A finding's own words carry far more meaning to embed than bare tech tokens do.
    if finding is not None:
        query_text = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('technology', '')}"
    else:
        query_text = " ".join(sorted(tech_keywords) + sorted(waf_vendors))
    query_embedding = _embed_playbook_query(llm, query_text) if llm is not None else None
    matches = playbook_store.find_similar_techniques(
        set(tech_keywords), set(waf_vendors), _playbook_max_injected_entries(),
        vuln_class=query_vuln_class, query_embedding=query_embedding,
    )
    if not matches:
        return ""

    # Only the autonomous pipeline (track_injections=True at its analyze/exploit call sites, where
    # the session is live and reliably saved) records the injection for attribution -- chat's own
    # call leaves this off, since its session copy is reloaded fresh on save and its findings credit
    # through a different path.
    if track_injections:
        _record_playbook_injections(session, matches)

    # Split into what WORKED (leads to try) and what's a known DEAD-END (skip, don't waste the
    # operator's time re-deriving a bypass that's already failed against this stack). Entries
    # predating the outcome field read as "worked" -- the only kind the autonomous capture ever
    # produced before dead-ends existed.
    worked_lines, dead_end_lines, unreviewed_lines = [], [], []
    for match in matches:
        line = f"- {match.get('technique')}"
        if match.get("payload_or_command"):
            line += f" (payload/command: {match['payload_or_command']})"
        # A generalized {{slot}} template (Unit 4) is more reusable than the one-target payload above --
        # surface it so the model adapts the proven payload to THIS target instead of re-deriving it.
        if match.get("payload_template"):
            line += f" [reusable template: {match['payload_template']}]"
        # Library-extracted, not yet reviewed (agent/tools/library_store.py) -- surfaced as its OWN
        # third bucket below, never counted as "seen Nx before" (it hasn't been -- an LLM's own
        # reading of a document isn't a confirmed use), and never silently folded into worked_lines
        # where it would read as field-proven.
        if match.get("confidence") == "unreviewed":
            source = match.get("source_title") or "an uploaded source"
            if match.get("source_ref"):
                source += f", {match['source_ref']}"
            line += f" (from {source}) — UNVERIFIED: try it, but don't assume it works until it's actually confirmed"
            unreviewed_lines.append(line)
            continue
        line += f" — seen {match.get('times_confirmed', 1)}x before"
        # Threat-intel flag (stamped on the entry by refresh_threat_intel, no network here): a CVE in
        # CISA KEV or with a high EPSS is actively exploited in the wild -- prioritize it.
        intel = []
        if match.get("kev"):
            intel.append("in CISA KEV")
        if isinstance(match.get("epss_max"), (int, float)) and match["epss_max"] >= 0.5:
            intel.append(f"EPSS {round(match['epss_max'] * 100)}%")
        if intel:
            line += f" [ACTIVELY EXPLOITED: {', '.join(intel)}{' — ' + ', '.join(match['cves']) if match.get('cves') else ''}]"
        # Staleness (Unit 3): a worked technique not confirmed in a long while may be patched -- tell
        # the model to re-verify rather than trust it blindly.
        if match.get("outcome") != "failed" and playbook_store.is_stale(match):
            line += " [STALE — verify it still works before relying on it]"
        (dead_end_lines if match.get("outcome") == "failed" else worked_lines).append(line)

    recipe_lines = _playbook_recipe_lines(matches)

    _playbook_logger.debug(
        "core: session=%s playbook addendum: %d worked + %d dead-end match(es) + %d recipe(s) injected",
        session.get("session_id"), len(worked_lines), len(dead_end_lines), len(recipe_lines),
    )
    parts = []
    if worked_lines:
        parts.append(
            "Known techniques that WORKED before against a similarly fingerprinted stack (from "
            "earlier sessions, not proof for THIS target — verify before relying on it):\n"
            + "\n".join(worked_lines)
        )
    if dead_end_lines:
        parts.append(
            "Known DEAD-ENDS against a similarly fingerprinted stack — these did NOT work before, so "
            "don't burn time re-trying them unless you have a genuinely new angle:\n"
            + "\n".join(dead_end_lines)
        )
    if unreviewed_lines:
        parts.append(
            "⚠ UNVERIFIED leads from an uploaded library source — extracted by an LLM reading the "
            "document, never actually tested against a real target. Worth trying, but treat as a "
            "hypothesis, not a fact — if it works here, record_finding/record_technique will "
            "automatically confirm it for future sessions:\n"
            + "\n".join(unreviewed_lines)
        )
    if recipe_lines:
        parts.append(
            "Proven RECIPES (multi-step chains that worked end-to-end before against a similar stack "
            "— each arrow is a step that unlocked the next; consider replaying the whole sequence):\n"
            + "\n".join(recipe_lines)
        )
    return "\n\n" + "\n\n".join(parts) if parts else ""


def _tool_memory_task_addendum(session: dict, finding: dict | None = None) -> str:
    """agent/tools/tool_memory_store.py's read side -- the tool-SELECTION counterpart to
    _playbook_task_addendum's technique-selection leads. Empty when nothing's stored for an exact
    match on this session's current tech/WAF fingerprint. Same "lead to check, never an instruction
    to skip" framing as every other cross-rescan calibration addendum in this file: a tool that came
    back empty here before is still worth a light check, not written off outright.
    """
    tech_keywords, waf_vendors = (
        _finding_fingerprint(session, finding) if finding is not None else _current_target_fingerprint(session)
    )
    if not tech_keywords:
        return ""
    history = tool_memory_store.find_tool_history(_playbook_fingerprint_key(tech_keywords, waf_vendors))
    if not history:
        return ""

    productive_entries = [e for e in history if e.get("outcome") == "productive"]
    productive = sorted(
        e["tool"] + (" [may be outdated — re-verify]" if tool_memory_store.is_stale(e) else "")
        for e in productive_entries
    )
    quiet = sorted((
        e["tool"] for e in history
        if e.get("outcome") != "productive" and int(e.get("times_run") or 0) >= 1
    ))
    if not productive and not quiet:
        return ""
    parts = []
    if productive:
        parts.append(
            "Scan tools that actually PRODUCED SIGNAL before against a similarly fingerprinted "
            "stack (worth reaching for here, not proof by itself): " + ", ".join(productive)
        )
    if quiet:
        parts.append(
            "Scan tools already tried before against a similarly fingerprinted stack that came back "
            "empty — still worth a light check (the target may have changed, or this specific host "
            "may differ), just don't over-invest if it comes back empty again: " + ", ".join(quiet)
        )
    return "\n\n" + "\n\n".join(parts)


def _playbook_recipe_lines(matches: list[dict]) -> list[str]:
    """Reconstructs the full multi-step kill-chain behind every surfaced technique that's part of one,
    then renders only the MAXIMAL chains (a shorter chain that's just a prefix of a longer surfaced
    one is dropped, so the recipe shows once, complete) as numbered "1) ... → 2) ... → 3) ..." lines.
    Empty when none of the surfaced techniques are chained."""
    chained_ids = [m.get("id") for m in matches if m.get("chained_from_ids") and m.get("id")]
    if not chained_ids:
        return []
    chains = playbook_store.get_technique_chains(chained_ids)
    candidates = [
        (tuple(c.get("id") for c in chain), chain)
        for chain in chains.values() if len(chain) >= 2
    ]
    lines, rendered_sigs = [], set()
    for sig, chain in candidates:
        # Drop a chain that's a strict prefix of another candidate (the longer one is the full recipe).
        if any(other != sig and other[: len(sig)] == sig for other, _ in candidates):
            continue
        if sig in rendered_sigs:
            continue
        rendered_sigs.add(sig)
        steps = " → ".join(f"{i}) {c.get('technique')}" for i, c in enumerate(chain, 1))
        lines.append(f"- {steps}")
    return lines


def _cors_credential_task_addendum(session: dict, finding: dict) -> str:
    """Empty when this finding isn't CORS-related, or no cors_check verdict is tracked yet for a
    host it's about — the common case. Surfaces the ALREADY-KNOWN allows_credentials fact
    (session["cors_check_credentials"], _track_cors_check_verdict) directly into Exploit's own
    task text, so the model doesn't have to re-discover or re-run cors_check to learn something
    this session already established, and gets pointed at cors_credentialed_check (a real proof
    step) when the anonymous prerequisites are already met.

    Real incident this closes: three High/"qualifying" CORS findings all got
    skipped_no_suitable_tool with reasoning that never even considered whether Access-Control-
    Allow-Credentials was set — nothing had ever checked it (cors_check didn't track it at all
    before this), let alone told Exploit the answer. Same hostname-matching approach as
    _cors_qualifying_conflict (a finding merely mentioning a checked host, but about something
    else entirely, must never get this addendum).
    """
    haystack = f"{finding.get('title', '')} {finding.get('description', '')} {finding.get('technology', '')}".lower()
    if not any(keyword in haystack for keyword in _CORS_RELATED_KEYWORDS):
        return ""
    credentials = session.get("cors_check_credentials") or {}
    matching_hosts = [hostname for hostname in credentials if hostname and hostname.lower() in haystack]
    if not matching_hosts:
        return ""

    lines = []
    for hostname in matching_hosts:
        allows = credentials[hostname]
        if allows is True:
            lines.append(
                f"- {hostname}: cors_check already confirmed Access-Control-Allow-Credentials: "
                "true alongside the reflected Origin — a real credentialed cross-origin read IS "
                "possible per browser rules. If this project has identity credentials configured "
                "(user_a/user_b), call cors_credentialed_check(target=..., identity=...) for a "
                "real, confirmed PoC before settling for skipped_no_suitable_tool."
            )
        elif allows is False:
            lines.append(
                f"- {hostname}: cors_check already confirmed Access-Control-Allow-Credentials was "
                "NOT set — a real browser only ever exposes non-credentialed (public) data "
                "cross-origin here, session/token theft is not possible via this specific "
                "misconfiguration. If that's the only real-world impact this finding's own "
                "reasoning can point to, that likely calls for corrected_severity/"
                "corrected_qualifies_for_bounty on your record_exploit_decision call."
            )
    if not lines:
        return ""
    return "\n\nAlready established this session by cors_check, about a host this finding is about:\n" + "\n".join(lines)


def _scope_rules_task_addendum(session: dict) -> str:
    """Empty when the New Project form's Qualifying/Non-qualifying fields were left blank — the
    agent then scans exactly as it always has, with no extra constraint (session["scope_rules"],
    sessions/store.py's create_session()). Non-empty only steers priority; it never limits which
    tools/targets are available, that's still the allowlist/approval gate's job."""
    scope_rules = session.get("scope_rules") or {}
    qualifying = (scope_rules.get("qualifying") or "").strip()
    non_qualifying = (scope_rules.get("non_qualifying") or "").strip()
    if not qualifying and not non_qualifying:
        return ""

    lines = ["\n\nThis project's own bug-bounty scope rules — take these as real priorities:"]
    if qualifying:
        lines.append(
            f"- Qualifying vulnerabilities (the program actually pays for these — prioritize "
            f"finding them, and mark any matching finding's qualifies_for_bounty as \"qualifying\"): "
            f"{qualifying}"
        )
    if non_qualifying:
        lines.append(
            f"- Non-qualifying vulnerabilities (the program explicitly will NOT pay for these — "
            f"don't spend your effort chasing them once one is confirmed to be one of these; still "
            f"record it if you already found it, but mark it qualifies_for_bounty=\"non_qualifying\" "
            f"and move on): {non_qualifying}"
        )
    lines.append(
        "Only set qualifies_for_bounty when a finding clearly matches one of these two lists — "
        "leave it unset if it's genuinely unclear which list (if either) it falls under."
    )
    return "\n".join(lines)


def _warn_if_scope_rules_went_unused(session: dict) -> None:
    """Real, confirmed incident this fixes (a real session, usr_194956): the New Project form's
    Qualifying field held "The page https://hackerone.com/example-program shows that it is qualified"
    -- a pointer to where the real rules live, not the rules themselves. Analyze correctly declined
    to guess (every finding's qualifies_for_bounty stayed unset) rather than fabricate a judgment
    against text with nothing to actually match — the right call, but nothing anywhere told the
    operator their own scope text couldn't be used the way they probably intended, so this only
    ever surfaced later, in a manual log review. Deliberately narrow: only fires when qualifying
    text was actually provided (an operator who left it blank made no promise this should catch)
    and genuinely zero findings got tagged either way (a real, if lopsided, "every finding happened
    to be qualifying" outcome must never trip this).
    """
    scope_rules = session.get("scope_rules") or {}
    qualifying = (scope_rules.get("qualifying") or "").strip()
    findings = session.get("findings") or []
    if not qualifying or not findings:
        return
    if any(f.get("qualifies_for_bounty") for f in findings):
        return
    session["scope_rules_warning"] = (
        "Scope rules were provided, but no finding ended up tagged qualifying/non-qualifying — the "
        "text may describe where to find the real rules rather than listing the actual vulnerability "
        "classes (e.g. a link to the program's policy page instead of its contents)."
    )


def _record_approval(ctx: RunContext, finding: dict, outcome: str) -> None:
    ctx.session.setdefault("approvals", []).append(
        {
            "finding_title": finding.get("title"),
            "outcome": outcome,
            "at": datetime.now(timezone.utc).isoformat(),
        }
    )


async def _await_exploit_approval(ctx: RunContext, finding: dict) -> bool:
    """Waits for a human to approve exploitation this session (see get_approval_event — the
    web layer's approve-exploit endpoint sets that event). Approval is per session, not per finding:
    once granted (session["exploit_approved"]), later findings in the same session skip the wait
    entirely; a timeout never sets that flag, so the next finding asks again. Every outcome
    (approved, denied, timed out, or auto-approved) is recorded in session["approvals"] — the audit
    trail Export Proof relies on to show whether exploitation was a deliberate human decision or the
    autonomous default.

    EXPLOIT_REQUIRE_APPROVAL (.env, default false) gates whether this wait happens at all: an
    unattended/autonomous run has nobody watching for the UI prompt, so the default is to record an
    "auto_approved" outcome and return immediately without ever pausing the session. Set it to true
    to get the interactive human-in-the-loop gate back.
    """
    if ctx.session.get("exploit_approved"):
        return True

    if os.getenv("EXPLOIT_REQUIRE_APPROVAL", "false").strip().lower() != "true":
        ctx.session["exploit_approved"] = True
        _record_approval(ctx, finding, "auto_approved")
        save_session(ctx.session_id, ctx.session)
        logger.debug("core: session=%s exploit auto-approved (EXPLOIT_REQUIRE_APPROVAL=false)", ctx.session_id)
        return True

    ctx.session["status"] = "awaiting_approval"
    save_session(ctx.session_id, ctx.session)
    logger.debug("core: session=%s awaiting exploit approval", ctx.session_id)

    timeout_seconds = int(os.getenv("EXPLOIT_APPROVAL_TIMEOUT_SECONDS", "300"))
    event = get_approval_event(ctx.session_id)
    try:
        await asyncio.wait_for(event.wait(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.debug("core: session=%s exploit approval timed out after %ds", ctx.session_id, timeout_seconds)
        ctx.session["status"] = "processing"
        _record_approval(ctx, finding, "timeout")
        save_session(ctx.session_id, ctx.session)
        return False

    # request_session_stop() wakes this same event up to unstick a session paused right here — it
    # must be checked before exploit_denied/exploit_approved below, or a Stop request racing an
    # approval wait could get misread as a real approve/deny decision instead of the full-session
    # stop it actually is.
    if get_stop_event(ctx.session_id).is_set():
        # Deliberately does NOT clear the stop event here -- see _llm_complete's own docstring for
        # why: it's a session-wide flag a concurrent subagent task could equally be checking, and
        # only run_session's/run_focused_exploit's own top-level handler is the true single owner
        # of clearing it, once the whole session has actually finished stopping. event.clear() is
        # the SEPARATE, per-wait approval event -- clearing that one is still correct and necessary,
        # or a later finding's own approval wait would instantly (mis)read this same already-fired
        # event as its own answer.
        event.clear()
        logger.debug("core: session=%s exploit approval wait interrupted by an operator stop request", ctx.session_id)
        raise SessionStopRequested()

    ctx.session["status"] = "processing"
    # A denial reuses the same event (the deny-exploit route sets exploit_denied then .set()s it,
    # same signal the approve route uses) so this wait_for wakes up either way — the flag decides
    # which outcome it actually was. Only the "approved" outcome sets exploit_approved permanently
    # (later findings this session skip the wait entirely, see the check above); a denial must not
    # do that — clearing the event here means the NEXT finding that needs approval gets its own
    # fresh wait instead of instantly reading this same already-fired event as its answer too.
    if ctx.session.pop("exploit_denied", False):
        event.clear()
        _record_approval(ctx, finding, "denied")
        save_session(ctx.session_id, ctx.session)
        logger.debug("core: session=%s exploit denied", ctx.session_id)
        return False

    ctx.session["exploit_approved"] = True
    _record_approval(ctx, finding, "approved")
    save_session(ctx.session_id, ctx.session)
    logger.debug("core: session=%s exploit approved", ctx.session_id)
    return True


async def _run_exploit_for_finding(
    ctx: RunContext, target: str, finding: dict, exploit_tools: list[ToolSpec], deep_dive: bool = False
) -> tuple[dict | None, list[dict]]:
    # "attempted" enforces exactly one real exploitation attempt per finding (independent of how
    # many tool calls the model makes in this conversation, and independent of 1-Step Retry —
    # a retried invocation of the *same* attempt doesn't count as a second one); "verified" gates
    # that attempt behind at least one prior tool call when the finding wasn't already
    # verification="verified" coming in from Analyze — an approximation of "run a real
    # verification step first", not a semantic check of what that call actually confirmed, but
    # it's enough to stop a same-turn blind shot.
    state = {"attempted": False, "verified": finding.get("verification") == "verified"}

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        if not spec.requires_allowed_target:
            result = await _run_tool_with_retry(ctx, spec, arguments)
            state["verified"] = True
            _merge_protection_detection(ctx, spec, result, arguments)
            # A deep dive's widened toolset (see below) includes record_finding — without this,
            # the tool would report "ok" back to the model (which then honestly describes a new
            # finding in its reasoning) while nothing was actually ever persisted to
            # session["findings"], a silent-data-loss trap worse than not offering the tool at
            # all. Same persistence _run_analyze already does for a first-pass finding (shared
            # helper, agent/core.py's _persist_new_finding).
            if spec.name == "record_finding" and result.get("status") == "ok" and "recorded" in result:
                conflict_result = await _persist_new_finding(ctx, result["recorded"])
                if conflict_result is not None:
                    logger.debug("core: session=%s deep-dive: rejected record_finding, cors_check conflict for %r", ctx.session_id, result["recorded"].get("title"))
                    return conflict_result
                logger.debug("core: session=%s deep-dive: recorded new finding title=%r", ctx.session_id, result["recorded"].get("title"))
            elif spec.name == "cors_check" and result.get("status") == "ok":
                # Same tracking _run_analyze's execute() does — a deep dive commonly re-runs
                # cors_check on a host Analyze already checked (or checks it for the first time,
                # if Analyze never had reason to), and either way this finding's own retry of
                # record_finding just below needs the current verdict, not a stale one.
                _track_cors_check_verdict(ctx, result)
            elif spec.name == "update_plan" and result.get("status") == "ok" and "recorded" in result:
                _apply_updated_plan(ctx, result["recorded"], "exploit")
            elif spec.name == "resolve_hypothesis" and result.get("status") == "ok" and "resolved" in result:
                _resolve_hypothesis(ctx, result["resolved"], "exploit")
            return result

        if not state["verified"]:
            return {"status": "skipped", "reason": "finding is not verification=verified yet — call a verification tool first"}
        # authenticated_request/idor_probe (and any future tool registered the same way) are
        # exempt from the one-shot cap below: a real IDOR/broken-access comparison inherently
        # needs multiple calls (act as identity A, then as identity B, then compare) — capping it
        # at one call the same way a single Metasploit/sqlmap firing gets capped would make the
        # whole feature unusable. Data on the ToolSpec itself (registry.py's
        # allows_repeated_attempts), not a hardcoded name list here. Still gated by the same
        # allowlist check (run_tool()) and the same one-time-per-session approval wait just below.
        is_multi_call_tool = spec.allows_repeated_attempts
        if state["attempted"] and not is_multi_call_tool:
            return {"status": "skipped", "reason": "one exploitation attempt already used for this finding"}

        approved = await _await_exploit_approval(ctx, finding)
        if not is_multi_call_tool:
            state["attempted"] = True
        if not approved:
            return {"status": "skipped", "reason": "exploit not approved in time"}
        return await _run_tool_with_retry(ctx, spec, arguments)

    task = (
        f"Target: {target}\n"
        f"Finding to evaluate:\n{json.dumps(finding)}\n\n"
        "If the finding is verified and a fitting tool is available, call that tool now through "
        "function-calling and report its real result — do not just describe what you would do. "
        "The allowlist/approval gates are enforced automatically on the call itself; if it comes "
        "back skipped, that is a real, valid outcome to report, but you only find out by actually "
        "calling it. Only answer skipped_needs_verification/skipped_no_suitable_tool without "
        "calling a tool if that's genuinely the situation (not verified yet, or nothing fits)."
    )
    task += _out_of_scope_task_addendum(ctx.session)
    task += _out_of_scope_notes_task_addendum(ctx.session)
    task += _custom_instructions_task_addendum(ctx.session)
    task += _goal_task_addendum(ctx.session)
    task += _program_url_task_addendum(ctx.session)
    task += _custom_user_agent_task_addendum(ctx.session)
    task += _custom_headers_task_addendum(ctx.session)
    task += _confirmed_tech_facts_task_addendum(ctx.session, finding)
    task += _protection_task_addendum(ctx.session)
    task += _cors_credential_task_addendum(ctx.session, finding)
    task += _plan_task_addendum(ctx.session, "exploit")
    task += _open_hypotheses_task_addendum(ctx.session)
    task += _previously_resolved_hypotheses_task_addendum(ctx.session)
    task += _playbook_task_addendum(ctx.session, finding, track_injections=True, llm=ctx.llm)
    task += _tool_memory_task_addendum(ctx.session, finding)
    subagent_tools, subagent_addendum = _subagent_delegation_extras(ctx.session)
    task += subagent_addendum
    # A deep-dive re-attempt hands the model the full scan-category toolset alongside the
    # exploit-category one (not just the latter, same as a normal first pass) — otherwise a
    # second run of the exact same tool set against the exact same prompt is deterministic and
    # reaches the exact same "skipped_no_suitable_tool" conclusion every time, which is what
    # made deep dive look like it "does nothing" for any finding class the 4 exploit tools were
    # never going to fit in the first place (header/cookie/TLS hygiene findings, mainly).
    tool_specs = exploit_tools
    if deep_dive:
        exploit_names = {spec.name for spec in exploit_tools}
        tool_specs = exploit_tools + [spec for spec in get_tools_by_category("scan") if spec.name not in exploit_names]
        task += DEEP_DIVE_ADDENDUM
    tool_specs = tool_specs + subagent_tools + _toolkit_tool_extras()
    update_plan_spec = get_tool("update_plan")
    if update_plan_spec is not None:
        tool_specs = tool_specs + [update_plan_spec]
    resolve_hypothesis_spec = get_tool("resolve_hypothesis")
    if resolve_hypothesis_spec is not None:
        tool_specs = tool_specs + [resolve_hypothesis_spec]

    # Tag every log entry this finding's attempt produces with its title, so the UI can show a
    # scoped log for this one finding — reset in finally so a later finding never inherits it.
    ctx.current_finding_title = finding.get("title")
    try:
        return await _run_llm_tool_loop(
            ctx, EXPLOIT_PROMPT, task, tool_specs, "exploit", execute_tool=execute, terminal_tool="record_exploit_decision",
            plan_phase="exploit",
        )
    finally:
        ctx.current_finding_title = None


def is_ungrounded_cve_lookup(finding: dict) -> bool:
    """Legacy-data detector, not something current code ever produces: _run_analyze's cve_lookup
    auto-record now refuses to create a finding at all when no host was ever confirmed running
    that product (see the early-return in execute() above) — so no finding recorded by the
    current code can ever be "ungrounded". This only exists to recognize the same situation in a
    session saved by an older build, before that gate existed: evidence_ref always starts with
    "cve_lookup(...)" for the auto-record path, and technology only ever says "confirmed installed
    at" when Recon actually had a real host to name. Honors an explicit "ungrounded_cve_lookup"
    flag if an even-older session still carries one. Public (no leading underscore): used as a
    Jinja filter (main.py) so a leftover old-style card can still flag itself as unconfirmed
    instead of looking identical to a real, verified finding.
    """
    flag = finding.get("ungrounded_cve_lookup")
    if flag is not None:
        return bool(flag)
    evidence_ref = finding.get("evidence_ref") or ""
    technology = finding.get("technology") or ""
    return evidence_ref.startswith("cve_lookup(") and "confirmed installed at" not in technology


def _apply_skip_outcome(finding: dict, action: dict, *, default_outcome: str = "skipped_unspecified") -> None:
    """Deterministic, no LLM call needed: exploit was never actually attempted for this
    finding (skipped for lack of a fitting tool, missing verification, allowlist, or approval
    timeout) — there is no real tool output to judge, so there's nothing for an LLM to confirm.

    `default_outcome` is only used when `action` has no real `action` value of its own (every
    deterministic, non-LLM call site below) — record_exploit_decision's own action enum
    ("skipped_no_suitable_tool"/"skipped_needs_verification") is preferred whenever present, since
    it's a genuine model judgment, not a guess.
    """
    finding["exploited"] = False
    finding["evidence"] = None
    finding["exploit_outcome"] = action.get("action") or default_outcome
    finding.setdefault("poc_command", None)
    reason = action.get("reasoning")
    if reason:
        finding["advisory_note"] = reason
    # A genuine re-check, not Analyze's first guess carried forever — only overwrite when Exploit
    # actually gave one (a deterministic operator skip/chat skip has no such re-check to offer).
    scenario = action.get("exploitation_scenario")
    if scenario in _VALID_EXPLOITATION_SCENARIOS:
        finding["exploitation_scenario"] = scenario
    # Real incident this fixes: a skipped_no_suitable_tool decision whose own "reasoning" concluded
    # a High/"qualifying" CORS finding's impact could never actually be demonstrated (no tool in
    # the registry simulates a victim's authenticated browser) left qualifies_for_bounty at
    # "qualifying" anyway — this correction path previously only ran for exploit_attempted (via
    # _confirm_exploit_result), never for a skip, even though a skip's own reasoning is exactly as
    # capable of contradicting Analyze's first guess as a real attempt's confirmation is.
    _apply_corrected_qualification(finding, action.get("corrected_severity"), action.get("corrected_qualifies_for_bounty"))
    _apply_corrected_false_positive_reason(finding, action.get("corrected_false_positive_reason"))


def _apply_corrected_title(finding: dict, corrected_title: str | None) -> None:
    """Exploit confirmation (CONFIRM_EXPLOIT_PROMPT's optional corrected_title) occasionally
    proves the finding's own title named the wrong host — real incident this fixes: a finding
    titled "...on app.kiwi.com" turned out, once actually tested, to only reproduce against a
    completely different host sharing the same CDN/cache layer. Left uncorrected, a report copied
    straight to a bug-bounty platform would name one host in the title and a different one in the
    PoC command. The pre-correction title is kept (original_title), never silently overwritten —
    setdefault so a second correction (a later deep-dive) can't clobber the TRUE original with an
    already-corrected intermediate title.
    """
    if not corrected_title or not isinstance(corrected_title, str):
        return
    corrected_title = corrected_title.strip()
    if not corrected_title or corrected_title == finding.get("title"):
        return
    finding.setdefault("original_title", finding.get("title"))
    finding["title"] = corrected_title


_VALID_QUALIFICATIONS = {"qualifying", "non_qualifying", "unclear"}


def _apply_corrected_qualification(finding: dict, corrected_severity, corrected_qualifies_for_bounty) -> None:
    """Exploit confirmation's optional corrected_severity/corrected_qualifies_for_bounty
    (CONFIRM_EXPLOIT_PROMPT) occasionally proves Analyze's first-guess severity/qualification no
    longer matches what confirmation's own evidence actually showed — real incident this fixes: a
    CORS finding whose own advisory_note concluded "no meaningful cross-origin exfiltration
    possible" (no credentialed session available, ACAO=*+credentials is blocked by the browser
    itself) stayed at Medium severity with qualifies_for_bounty left "unclear" instead of being
    corrected to match that same conclusion — the advisory_note said one thing, the structured
    fields a human would actually triage by said another. Same setdefault-original pattern as
    _apply_corrected_title: the pre-correction values are kept (original_severity/
    original_qualifies_for_bounty), never silently overwritten, so a second correction (a later
    deep-dive) can't clobber the TRUE original with an already-corrected intermediate value.
    Case-insensitive against the known valid set for severity, same normalization discipline
    record_finding's own severity validation already applies.
    """
    if isinstance(corrected_severity, str):
        normalized = next(
            (candidate for candidate in _VALID_SEVERITIES if candidate.lower() == corrected_severity.strip().lower()),
            None,
        )
        if normalized is not None and normalized != finding.get("severity"):
            finding.setdefault("original_severity", finding.get("severity"))
            finding["severity"] = normalized

    if isinstance(corrected_qualifies_for_bounty, str):
        normalized = corrected_qualifies_for_bounty.strip().lower()
        if normalized in _VALID_QUALIFICATIONS and normalized != finding.get("qualifies_for_bounty"):
            finding.setdefault("original_qualifies_for_bounty", finding.get("qualifies_for_bounty"))
            finding["qualifies_for_bounty"] = normalized


def _apply_reverify_correction(finding: dict, old_finding: dict, verdict: dict | None, session_id: str) -> None:
    """Reverify-only guard in front of _apply_corrected_qualification: a rescan's reverify pass
    merely reproducing an already-known finding is not, by itself, evidence that its severity or
    qualification should go UP from what the prior scan recorded -- unlike confirm_exploit's own
    corrected_* (a genuine first-time exploitation attempt within the same scan backs those), a
    reverify verdict of "confirmed_present" can be reached with nothing more than the same repro
    steps that already produced the OLD severity in the first place. Any corrected_* value that
    would RAISE severity or qualification above old_finding's current value is dropped unless the
    model also filled in escalation_justification (record_reverification_result's own schema) --
    downgrades and non-escalating corrections pass through to _apply_corrected_qualification
    untouched, exactly as before this guard existed.
    """
    verdict = verdict or {}
    corrected_severity = verdict.get("corrected_severity")
    corrected_qualifies_for_bounty = verdict.get("corrected_qualifies_for_bounty")
    justification = verdict.get("escalation_justification")
    has_justification = isinstance(justification, str) and justification.strip()

    withheld: list[str] = []

    safe_severity = corrected_severity
    if isinstance(corrected_severity, str):
        normalized = next(
            (candidate for candidate in _VALID_SEVERITIES if candidate.lower() == corrected_severity.strip().lower()),
            None,
        )
        if normalized is not None and not has_justification:
            old_rank = _SEVERITY_RANK.get(str(old_finding.get("severity", "")).lower(), len(_SEVERITY_RANK))
            new_rank = _SEVERITY_RANK.get(normalized.lower(), len(_SEVERITY_RANK))
            if new_rank < old_rank:  # lower rank number == more severe
                safe_severity = None
                withheld.append(f"severity ({old_finding.get('severity')} -> {normalized})")

    safe_qualifies = corrected_qualifies_for_bounty
    if isinstance(corrected_qualifies_for_bounty, str):
        normalized_q = corrected_qualifies_for_bounty.strip().lower()
        if normalized_q == "qualifying" and old_finding.get("qualifies_for_bounty") != "qualifying" and not has_justification:
            safe_qualifies = None
            withheld.append(f"qualifies_for_bounty ({old_finding.get('qualifies_for_bounty')} -> qualifying)")

    _apply_corrected_qualification(finding, safe_severity, safe_qualifies)

    if withheld:
        note = (
            f"Reverify proposed raising {', '.join(withheld)} on reproduction alone with no new "
            "evidence stated; kept at prior value pending human review."
        )
        finding["escalation_withheld_note"] = note
        logger.info("core: session=%s reverify: escalation withheld for %r -- %s", session_id, finding.get("title"), note)


def _apply_corrected_false_positive_reason(finding: dict, corrected_false_positive_reason) -> None:
    """Sibling to _apply_corrected_qualification, same "your own reasoning proved something the
    structured fields don't reflect yet" family — but this one only ever FILLS a gap, never
    overwrites: false_positive_reason is normally either unset (a real, still-open finding) or
    already set with a real, substantiated reason (Analyze's own auto-CVE-record due-diligence
    check, version_is_ruled_out below) — if it's already set, that's at least as authoritative as
    a later pass's own conclusion, so there's nothing to correct. Shared by both the skip path
    (_apply_skip_outcome, via record_exploit_decision's own schema) and the exploit_attempted
    confirmation path (_confirm_exploit_result, via CONFIRM_EXPLOIT_PROMPT) — real, confirmed
    incident this closes: several findings whose own advisory_note explicitly disproved them
    ("no in-scope host is confirmed vulnerable...") during a SKIP kept no false_positive_reason at
    all, so proof_report.html's "Likely false positive" banner never rendered for them even though
    Exploit itself had already, independently concluded they weren't real.
    """
    if isinstance(corrected_false_positive_reason, str) and corrected_false_positive_reason.strip() and not finding.get("false_positive_reason"):
        finding["false_positive_reason"] = corrected_false_positive_reason.strip()


def _apply_remediation_advice(finding: dict, remediation_advice) -> None:
    """record_exploit_decision's own optional remediation_advice — unlike the corrected_* fields
    above, this isn't about revising Analyze's first guess, it applies the same regardless of
    whether exploitation was attempted or skipped (a skipped-for-lack-of-a-tool finding is exactly
    as real and exactly as fixable as an actively exploited one). Set unconditionally at the one
    shared choke point both _run_exploit and run_focused_exploit already read action["confirmed_tech_fact"]
    from, right alongside it — never overwritten with nothing if a later pass (a rescan, a deep
    dive) genuinely has nothing new to add here.
    """
    if isinstance(remediation_advice, str) and remediation_advice.strip():
        finding["remediation_advice"] = remediation_advice.strip()


async def _confirm_exploit_result(ctx: RunContext, finding: dict, action: dict, trace: list[dict]) -> dict:
    """The one case that does need an LLM judgment call: exploit reported "exploit_attempted",
    so a human-readable read of the real tool trace decides whether it actually succeeded and
    what the real evidence was (catches a model that claims success with no real tool call
    behind it).
    """
    messages = [
        {"role": "system", "content": CONFIRM_EXPLOIT_PROMPT},
        {
            "role": "user",
            "content": (
                f"Finding:\n{json.dumps(finding)}\n\n"
                f"Exploit phase action:\n{json.dumps(action)}\n\n"
                f"Real tool call trace from the attempt:\n{json.dumps(trace)}"
            ),
        },
    ]
    response = await _llm_complete(ctx, messages, None)
    parsed = _parse_json_response(response.content)
    if parsed is None:
        parsed = await _repair_json_reply(ctx, messages, response.content)
    if parsed is None:
        logger.debug("core: session=%s confirm-exploit produced no parseable result for finding=%r", ctx.session_id, finding.get("title"))
        return {"exploited": False, "evidence": None, "poc_command": None, "advisory_note": "Could not parse exploit confirmation"}
    return parsed


_AUTO_DELEGATE_EXPLOIT_FINDING_THRESHOLD = 3  # fewer findings than this -> the main agent alone is fine, not worth the delegation overhead
_AUTO_DELEGATE_EXPLOIT_MAX_FINDINGS = 3  # a bound on one subagent task's own batch, not a truncation of real findings -- the rest is just worked by the main agent itself
_AUTO_DELEGATE_EXPLOIT_TIMEOUT_PER_FINDING_SECONDS = int(os.getenv("SUBAGENT_AUTO_EXPLOIT_TIMEOUT_PER_FINDING_SECONDS", "300"))


async def _auto_delegate_exploit_overflow(ctx: RunContext, target: str, findings: list[dict]) -> None:
    """Deterministic auto-delegation for Exploit -- same reasoning _auto_delegate_recon_overflow's
    own docstring already established (a soft prompt-level nudge, _subagent_delegation_extras, is
    confirmed live not reliable enough to depend on): a real 46-minute Exploit phase working
    through 7 largely-independent findings sequentially made exactly zero manual
    delegate_to_subagent calls, despite an enabled profile and real independent work available the
    entire time. Recon's own overflow-host version of this exists for exactly this class of gap;
    this is the Exploit-phase equivalent.

    Deliberately does NOT hand the actual exploited=True/False DECISION to a subagent -- that needs
    _run_exploit_for_finding's own validation/CORS-gate/qualification pipeline
    (_confirm_exploit_result, _apply_corrected_qualification, _cors_qualifying_conflict, etc.);
    bypassing all of that for a bare subagent's own report_subagent_result summary would be a real
    regression in decision quality, not a shortcut worth taking. Instead this hands a subagent
    fresh EVIDENCE-GATHERING legwork for the LOWER-priority tail of findings (the main agent
    already works top-down by severity via _exploit_priority_key, so this is exactly the batch it
    would reach last) while the main agent keeps working the higher-priority ones itself -- real
    parallel work. The subagent's summary reaches the main agent through the exact same auto-push
    queue every other delegation already uses (_push_subagent_result/_drain_subagent_results):
    informative context for whichever finding's own turn is running when it lands, never a
    structured decision the pipeline has to trust blindly.

    A no-op when no profile is enabled, or fewer than _AUTO_DELEGATE_EXPLOIT_FINDING_THRESHOLD
    findings remain undelegated -- the common case for a small scan is this does nothing at all.
    Tracks already-delegated titles in session["auto_delegated_exploit_findings"] so a resumed
    exploit phase never re-delegates the same findings a second time.
    """
    profiles = get_enabled_profiles(ctx.session.get("enabled_subagent_ids"))
    if not profiles:
        return

    already_delegated = ctx.session.setdefault("auto_delegated_exploit_findings", [])
    candidates = [f for f in sorted(findings, key=_exploit_priority_key) if f.get("title") not in already_delegated]
    if len(candidates) < _AUTO_DELEGATE_EXPLOIT_FINDING_THRESHOLD:
        return

    # The tail end -- lowest priority, exactly what the main agent's own top-down loop reaches
    # last -- never the front, which the main agent is about to start on itself immediately.
    batch = candidates[-_AUTO_DELEGATE_EXPLOIT_MAX_FINDINGS:]
    batch_titles = [f.get("title") or "Untitled finding" for f in batch]
    profile_name = profiles[0]["name"]
    findings_block = "\n\n".join(
        f"- {f.get('title')} ({f.get('severity', 'Unknown')}): {f.get('description') or 'no description recorded'}"
        for f in batch
    )
    task_description = (
        f"The main agent is working through the higher-priority findings on {target} itself. "
        f"While it does, gather fresh exploitability evidence for these {len(batch)} lower-priority "
        f"findings already recorded this session:\n\n{findings_block}\n\n"
        "For each one: confirm it still reproduces right now (a fresh request/response, not just "
        "trusting the earlier description), and note the concrete proof (exact request made, "
        "response snippet, status code). Do NOT decide whether it counts as successfully "
        "exploited -- that decision stays with the main agent, which has the full session context "
        "and the proper recording tool. Just report what you actually found, per finding, "
        "concretely -- vague summaries aren't useful."
    )

    result = await _delegate_to_subagent_impl({
        "subagent_name": profile_name,
        "task_description": task_description,
        "_session_id": ctx.session_id,
        "_session": ctx.session,
        "_triggered_by": "auto_overflow",
        "_timeout_seconds": len(batch) * _AUTO_DELEGATE_EXPLOIT_TIMEOUT_PER_FINDING_SECONDS,
    })
    if result.get("status") == "ok":
        already_delegated.extend(batch_titles)
        save_session(ctx.session_id, ctx.session)
        _subagent_logger.debug(
            "core: session=%s auto-delegated %d lower-priority finding(s) to subagent=%r task=%s",
            ctx.session_id, len(batch), profile_name, result.get("task_id"),
        )
    else:
        _subagent_logger.debug(
            "core: session=%s auto-delegation of %d lower-priority finding(s) did not start: %s",
            ctx.session_id, len(batch), result.get("reason") or result.get("error"),
        )


async def _run_exploit(ctx: RunContext, target: str) -> None:
    findings = ctx.session["findings"]
    if os.getenv("ENABLE_EXPLOIT", "true").lower() != "true":
        logger.debug("core: session=%s ENABLE_EXPLOIT=false, skipping exploit phase entirely (%d findings)", ctx.session_id, len(findings))
        return

    _mark_phase_started(ctx.session, "exploit")
    await _maybe_refresh_program_check(ctx)
    exploit_tools = get_tools_by_category("exploit")
    logger.debug(
        "core: session=%s starting exploit phase, %d finding(s) by descending severity (%d exploit tools available)",
        ctx.session_id, len(findings), len(exploit_tools),
    )
    if not findings:
        # Nothing for the while-loop below to ever iterate over -- without this, the Plan tab's
        # exploit entry is left exactly as Recon's own forward-seeded sketch guessed at, forever,
        # even once the whole session completes (see _sync_exploit_plan_from_findings's docstring).
        _sync_exploit_plan_from_findings(ctx)
        _mark_phase_finished(ctx.session, "exploit")
        return
    await _auto_delegate_exploit_overflow(ctx, target, findings)
    # A plain "for finding in sorted(...)" can't react to a deep_dive request that arrives
    # mid-phase (the finding-detail modal's Deep dive button, for a session that's already live)
    # — remaining is a real mutable work queue instead, checked for a reorder before every pop,
    # so "prioritize this one now" actually jumps the queue instead of only taking effect next
    # time exploit runs from scratch. Whatever's left keeps going in its normal order afterward.
    remaining = sorted(findings, key=_exploit_priority_key)
    pending_deep_dive_title: str | None = None
    while remaining:
        deep_dive_title = _pop_deep_dive_instruction(ctx.session_id)
        if deep_dive_title:
            match = next((f for f in remaining if f.get("title") == deep_dive_title), None)
            if match:
                remaining.remove(match)
                remaining.insert(0, match)
                pending_deep_dive_title = deep_dive_title
                logger.debug("core: session=%s operator instruction applied: deep_dive(%r) — prioritized next", ctx.session_id, deep_dive_title)
            else:
                logger.debug("core: session=%s deep_dive(%r) requested but not in the remaining queue — ignoring", ctx.session_id, deep_dive_title)

        finding = remaining.pop(0)
        title = finding.get("title")
        _sync_exploit_plan_from_findings(ctx, current_title=title)
        if _pop_skip_instruction(ctx.session_id, title):
            logger.debug("core: session=%s operator instruction applied: skip_finding(%r)", ctx.session_id, title)
            _apply_skip_outcome(finding, {"reasoning": "Skipped at the operator's request via chat."}, default_outcome="skipped_operator")
            save_session(ctx.session_id, ctx.session)
            _sync_exploit_plan_from_findings(ctx)
            continue

        is_deep_dive = title == pending_deep_dive_title
        if is_deep_dive:
            pending_deep_dive_title = None

        # Resuming an interrupted session rebuilds `remaining` from every finding again — skip
        # ones a previous (interrupted) run of this same exploit phase already fully resolved,
        # rather than repeating the same LLM+tool investigation for no new information. A finding
        # genuinely still needs this pass exactly when it's never been touched at all: the schema
        # default is advisory_note=None and exploited=False (agent/tools/native.py's
        # _FINDING_DEFAULTS), and every real resolution path (_apply_skip_outcome, or a completed
        # exploit_attempted verdict) always sets one or the other. A finding that was only
        # *started* before an interruption (a tool call or two, no final verdict) never reached
        # either, so it correctly still looks untouched and gets a real pass below — this only
        # skips work that's actually done, never work that was merely interrupted mid-flight.
        if not is_deep_dive and (finding.get("exploited") or finding.get("advisory_note") is not None):
            logger.debug("core: session=%s exploit: skipping finding=%r, already resolved by a previous pass (resume)", ctx.session_id, title)
            continue

        # Analyze already proved this one isn't applicable here (agent/core.py's cve_lookup
        # auto-record, e.g. a CVE whose affected-version range is confirmed not to include the
        # actual installed version) — spending real exploit-phase LLM/tool budget re-discovering
        # that same conclusion (msfconsole searches that were always going to return nothing) is
        # exactly the wasted effort this flag exists to prevent. A deep-dive request is an explicit
        # human override of that automatic call, so it still gets a real pass.
        if finding.get("false_positive_reason") and not is_deep_dive:
            logger.debug("core: session=%s exploit: skipping finding=%r, already ruled out during analyze", ctx.session_id, title)
            _apply_skip_outcome(finding, {"reasoning": finding["false_positive_reason"]}, default_outcome="skipped_ruled_out")
            save_session(ctx.session_id, ctx.session)
            _sync_exploit_plan_from_findings(ctx)
            continue

        # A leftover finding from before _run_analyze's cve_lookup gate existed (is_ungrounded_
        # cve_lookup above) — current scans can no longer create one of these at all, but an
        # already-completed session resumed into exploit can still have one sitting in its
        # findings list. No host Recon ever confirmed running that product means no target for any
        # exploit tool to aim at, and exploit phase does no fresh recon of its own to change that —
        # every single one of these was independently confirmed unworkable by the LLM in testing
        # (msf/exploit-db searches, allowlist rejections on guessed hostnames), at the cost of
        # several tool calls and an LLM round-trip each. Skip the same deterministic conclusion
        # without spending that budget; deep_dive still forces a real look if a human disagrees.
        if finding.get("verification") == "inferred" and is_ungrounded_cve_lookup(finding) and not is_deep_dive:
            logger.debug(
                "core: session=%s exploit: skipping finding=%r, ungrounded cve_lookup lead with no confirmed host to target",
                ctx.session_id, title,
            )
            _apply_skip_outcome(finding, {
                "reasoning": "Skipped exploitation — this finding came from a product-name CVE lookup, and "
                "this scan's Recon never confirmed any host/service actually running that product, so there "
                "is no real target for any exploit tool to aim at. Use Deep dive to force a real attempt "
                "anyway if you believe the target exists (e.g. found manually, outside this scan's scope "
                "rules for automated discovery).",
            }, default_outcome="skipped_no_target")
            save_session(ctx.session_id, ctx.session)
            _sync_exploit_plan_from_findings(ctx)
            continue

        # Only reachable when this project actually set Qualifying/Non-qualifying scope rules
        # (qualifies_for_bounty is left unset otherwise, agent/prompts.py's ANALYZE_PROMPT) — the
        # model already self-reported this finding's class as one the program explicitly will NOT
        # pay for. A full exploit attempt (msfconsole/sqlmap runs, real requests against a live
        # target) spent proving something with zero payout value is exactly the wasted effort the
        # scope rules were given to prevent — deep_dive is still the human's way to override this
        # for a specific finding they disagree with.
        if finding.get("qualifies_for_bounty") == "non_qualifying" and not is_deep_dive:
            logger.debug("core: session=%s exploit: skipping finding=%r, marked non_qualifying by this program's own scope rules", ctx.session_id, title)
            _apply_skip_outcome(finding, {
                "reasoning": "Skipped exploitation — this finding's class is on this program's own "
                "Non-qualifying vulnerabilities list, so a real exploit attempt would have zero bounty "
                "value. Use Deep dive to force a real attempt anyway if you disagree with this classification.",
            }, default_outcome="skipped_out_of_scope")
            save_session(ctx.session_id, ctx.session)
            _sync_exploit_plan_from_findings(ctx)
            continue
        logger.debug(
            "core: session=%s exploit: evaluating finding=%r severity=%s verification=%s deep_dive=%s",
            ctx.session_id, finding.get("title"), finding.get("severity"), finding.get("verification"), is_deep_dive,
        )
        action, trace = await _run_exploit_for_finding(ctx, target, finding, exploit_tools, deep_dive=is_deep_dive)
        if action and action.get("confirmed_tech_fact"):
            _record_confirmed_tech_fact(ctx.session, finding, action["confirmed_tech_fact"])
        if action:
            _apply_remediation_advice(finding, action.get("remediation_advice"))

        if action and action.get("action") == "exploit_attempted":
            confirmed = await _confirm_exploit_result(ctx, finding, action, trace)
            finding["exploited"] = confirmed.get("exploited", False)
            finding["evidence"] = confirmed.get("evidence")
            finding["poc_command"] = confirmed.get("poc_command")
            finding["advisory_note"] = confirmed.get("advisory_note")
            finding["extracted_artifact"] = confirmed.get("extracted_artifact")
            finding["artifact_usage_hint"] = confirmed.get("artifact_usage_hint")
            finding["exploit_outcome"] = "exploit_attempted"
            scenario = confirmed.get("exploitation_scenario")
            if scenario in _VALID_EXPLOITATION_SCENARIOS:
                finding["exploitation_scenario"] = scenario
            _apply_corrected_title(finding, confirmed.get("corrected_title"))
            _apply_corrected_qualification(finding, confirmed.get("corrected_severity"), confirmed.get("corrected_qualifies_for_bounty"))
            _apply_corrected_false_positive_reason(finding, confirmed.get("corrected_false_positive_reason"))
            _append_tool_timeline(finding, _extract_tool_timeline_entries(trace, "exploitation"))
            _maybe_capture_playbook_entry(ctx, finding)
            _credit_tool_memory_for_finding(ctx, finding)
        else:
            _apply_skip_outcome(finding, action or {"reasoning": "Exploit phase produced no parseable decision"})

        # finding is the same dict object living inside ctx.session["findings"] (sorted()
        # reorders references, it doesn't copy them) — mutating it above already updated the
        # session in memory; this just makes it durable before moving to the next finding.
        save_session(ctx.session_id, ctx.session)
        _sync_exploit_plan_from_findings(ctx)
        logger.debug(
            "core: session=%s exploit: finding=%r resolved exploited=%s",
            ctx.session_id, finding.get("title"), finding.get("exploited"),
        )
    _mark_phase_finished(ctx.session, "exploit")


def format_duration_between(started_at: str | None, finished_at: str | None) -> str:
    """Shared by format_session_duration (whole-session) and format_phase_duration (one phase) --
    both are exactly the same calculation over a {started_at, finished_at} pair, just reading it
    from a different place. Also registered directly as its own Jinja filter (main.py) for the
    Plan tab's per-task/subtask duration display (_stamp_task_timings's own started_at/finished_at
    fields), which has no single owning object to read a pair of timestamps off of the way a
    session or a phase does. Empty string when started_at was never set (nothing to show); counts
    up to right now (not frozen) while finished_at is still unset, so an in-progress phase/session
    shows a live, growing duration rather than looking stuck at 0.
    """
    if not started_at:
        return ""
    try:
        start = datetime.fromisoformat(started_at)
    except ValueError:
        return ""
    if finished_at:
        try:
            end = datetime.fromisoformat(finished_at)
        except ValueError:
            end = datetime.now(timezone.utc)
    else:
        end = datetime.now(timezone.utc)

    total_seconds = max(0, int((end - start).total_seconds()))
    return _format_seconds(total_seconds)


def _format_seconds(total_seconds: int) -> str:
    """Shared d/h/m/s formatting, factored out of format_duration_between so a total that was
    never a clean started_at/finished_at SPAN in the first place (e.g. accumulated_duration below)
    can still render with the exact same shape."""
    total_seconds = max(0, total_seconds)
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def format_accumulated_duration(seconds: float | None) -> str:
    """For a phase that can legitimately run in several separate, far-apart passes within the same
    session (hypothesis_verification: one pass per operator-submitted hunch, possibly hours apart)
    -- a naive started_at->finished_at SPAN (what format_duration_between computes) would count the
    idle time between passes as if it were real work, the exact reconciliation bug already fixed
    once for chain+validate. Real work time is summed per-pass instead (run_hypothesis_verification
    adds its own elapsed time to phase_timings["hypothesis_verification"]["accumulated_seconds"]
    every time it finishes), so this renders only the real total. Empty string when nothing's run
    yet -- same "nothing to show" convention as format_duration_between.
    """
    if not seconds:
        return ""
    return _format_seconds(int(seconds))


def format_session_duration(session: dict) -> str:
    """Total wall-clock elapsed time, from session["started_at"] to session["finished_at"] if the
    run actually completed, or to right now otherwise — the same calculation main.py's own
    session_duration template filter uses for display (that filter now just calls this), reused
    here so run_session/run_focused_exploit can log the real total duration once a run actually
    ends, instead of that number only ever existing as something a human computes by hand from two
    raw timestamps in session.json. Empty string when started_at was never set (nothing to show).
    """
    return format_duration_between(session.get("started_at"), session.get("finished_at"))


def format_phase_duration(session: dict, phase_name: str) -> str:
    """Same calculation as format_session_duration, scoped to one phase's own
    session["phase_timings"][phase_name] entry (_mark_phase_started/_mark_phase_finished) -- the
    Plan tab's own per-phase duration display (session_fragment.html), registered as a Jinja
    filter (main.py) the same way session_duration already is. Empty string (nothing rendered)
    for a phase that hasn't started yet, exactly like format_session_duration's own convention.
    """
    timing = (session.get("phase_timings") or {}).get(phase_name) or {}
    return format_duration_between(timing.get("started_at"), timing.get("finished_at"))


# Penalty-per-100%-rate constants for compute_efficiency_score below -- each factor subtracts
# independently from a starting score of 100, deliberately NOT a weighted average of bounded [0,1]
# rates (an earlier version of this formula tried that, and it had a real, checked-by-hand flaw: a
# session where literally every dispatched call failed still scored +20, because no single factor's
# own weight could reach the full -100..100 range alone -- diluting one very bad signal by requiring
# every OTHER signal to also be maximally bad before the score could go meaningfully negative). Here,
# a 100% failure rate ALONE (nothing else wrong) already drives the score to -60 -- clearly, honestly
# bad -- and any real combination of failures/retries/duplicates/stalls on top of that reaches -100
# well before every factor needs to be simultaneously maxed. Failure gets the steepest slope (an
# outright failed/error/skipped call is the most unambiguous waste); retries/duplicates are real but
# smaller per-unit costs (a retry DID eventually succeed; a duplicate at least skipped a correction
# round-trip); stalls are a flat per-event penalty, not rate-based, since a single genuine stuck-loop
# stop force-ends a whole phase -- a rare but severe event, not something to normalize by call count.
_EFFICIENCY_PENALTY_PER_FAILURE_RATE = 160
_EFFICIENCY_PENALTY_PER_RETRY_RATE = 80
_EFFICIENCY_PENALTY_PER_DUPLICATE_RATE = 80
_EFFICIENCY_PENALTY_PER_STALL = 25


def compute_efficiency_score(session: dict) -> dict:
    """A PROCESS-efficiency score, not a results/yield score, by deliberate design: it answers "did
    the agent waste real tool-call budget and wall-clock on failures/retries/duplicate work/stuck
    loops", never "did it find much" -- a scan that correctly, cleanly concludes a hardened target
    has nothing to report should score exactly as well as one that found ten real bugs just as
    cleanly. Conflating the two would make a legitimately clean-but-empty scan of a hardened program
    (github.com, a mature bug-bounty perimeter) read as "inefficient" for a reason that has nothing
    to do with how the agent actually behaved -- the same confusion a real log-review already
    mistook for a bug once this session, before checking the data.

    Inputs are exactly the deterministic counts _log_phase_efficiency_summary already accumulates
    into session["phase_efficiency"] (per real _run_llm_tool_loop call, main agent AND subagents
    both) plus session["stall_events"] (the stall detector's own force-stops) -- nothing here is
    re-derived from raw logs or guessed from free text, the same "compute it in code from what the
    pipeline already tracked deterministically" discipline this project's Plan-tab/timing fixes
    already established.

    +100 is a session with zero failures/retries/duplicates/stalls; -100 is the floor, reached by
    any sufficiently bad combination (not only "everything simultaneously maxed" -- see the penalty
    constants' own comment for why a single very bad factor is already enough on its own to land
    firmly negative). has_data=False (score left at 0, but flagged distinctly) for a session with no
    real tool calls recorded yet -- nothing to score, not a claim that it scored perfectly.
    """
    phase_efficiency = session.get("phase_efficiency") or {}
    total_calls = sum(bucket.get("tool_calls", 0) for bucket in phase_efficiency.values())
    if total_calls == 0:
        return {
            "score": 0, "has_data": False, "total_tool_calls": 0,
            "failure_rate": 0.0, "retry_rate": 0.0, "duplicate_rate": 0.0, "stall_count": 0,
        }

    total_non_ok = sum(bucket.get("non_ok", 0) for bucket in phase_efficiency.values())
    total_retried = sum(bucket.get("retried", 0) for bucket in phase_efficiency.values())
    total_duplicates = sum(bucket.get("duplicates", 0) for bucket in phase_efficiency.values())
    stall_count = len(session.get("stall_events") or [])

    failure_rate = total_non_ok / total_calls
    retry_rate = total_retried / total_calls
    duplicate_rate = total_duplicates / total_calls

    score = 100
    score -= _EFFICIENCY_PENALTY_PER_FAILURE_RATE * failure_rate
    score -= _EFFICIENCY_PENALTY_PER_RETRY_RATE * retry_rate
    score -= _EFFICIENCY_PENALTY_PER_DUPLICATE_RATE * duplicate_rate
    score -= _EFFICIENCY_PENALTY_PER_STALL * stall_count
    score = max(-100, min(100, round(score)))

    return {
        "score": score, "has_data": True, "total_tool_calls": total_calls,
        "failure_rate": failure_rate, "retry_rate": retry_rate, "duplicate_rate": duplicate_rate,
        "stall_count": stall_count,
    }


# A command repeated at least this many times, each individually succeeding, before it's worth a
# note -- low enough to catch a real, sustained pattern (the confirmed incident below was 22), high
# enough that an ordinary handful of legitimate repeat checks (e.g. a few check_subagent_task
# polls while a genuinely slow subagent finishes) never triggers a false alarm.
_EFFICIENCY_NOTE_REPEAT_THRESHOLD = 5


def compute_efficiency_notes(session: dict) -> list[str]:
    """Deterministic, rule-based efficiency notes -- a standing, automatic version of the manual
    log-review pass this project's own workflow otherwise needs a human to run
    by hand. Reuses compute_efficiency_score's own aggregate rates for the broad-strokes checks,
    plus one new structural detector for a class of waste those rates can't see at all: a command
    repeated many times that succeeds EVERY time (non_ok/retried/duplicates only count failures and
    exact-signature repeats within the stall detector's own narrower back-to-back window -- a
    successful poll repeated with other calls interleaved between each one, the exact
    real-session shape this detector is modeled on, is invisible to all three).

    Returns an empty list for a genuinely clean session -- never a fabricated "everything's fine"
    note just to have something to show.
    """
    notes: list[str] = []
    eff = compute_efficiency_score(session)
    if eff["has_data"]:
        if eff["failure_rate"] > 0.3:
            notes.append(f"High failure rate: {eff['failure_rate']:.0%} of tool calls did not return status=ok.")
        if eff["retry_rate"] > 0.3:
            notes.append(f"High retry rate: {eff['retry_rate']:.0%} of tool calls needed a corrected retry.")
        if eff["duplicate_rate"] > 0.15:
            notes.append(f"High duplicate rate: {eff['duplicate_rate']:.0%} of tool calls repeated an already-seen exact call.")
        if eff["stall_count"] > 0:
            notes.append(f"{eff['stall_count']} phase(s) were force-stopped by stall detection (the same tool call repeated back-to-back).")

    command_counts: dict[tuple[str, str], int] = {}
    for entry in session.get("logs") or []:
        command = entry.get("command")
        if not command or entry.get("status") != "ok":
            continue
        key = (entry.get("phase") or "?", command)
        command_counts[key] = command_counts.get(key, 0) + 1
    for (phase, command), count in sorted(command_counts.items(), key=lambda item: -item[1]):
        if count >= _EFFICIENCY_NOTE_REPEAT_THRESHOLD:
            tool_name = command.split("(", 1)[0]
            notes.append(
                f"{phase}: {tool_name!r} was called {count} times with identical arguments, each "
                "succeeding — likely a polling/waiting pattern rather than genuinely new work."
            )
    return notes


def _estimate_cost_usd(config: ProviderConfig | None, model: str, prompt_tokens: int, completion_tokens: int) -> float | None:
    """Shared by compute_llm_usage_summary/compute_provider_leaderboard below -- None whenever
    models.dev has no pricing for this exact provider/model pair (get_model_cost's own graceful-
    degrade contract, e.g. a free/local/unpriced model) or literally zero tokens were ever reported
    for it, never fabricated as $0.00 either way."""
    if config is None or not (prompt_tokens or completion_tokens):
        return None
    cost = get_model_cost(config.models_dev_id, model)
    if cost is None:
        return None
    return (prompt_tokens / 1_000_000) * cost["input"] + (completion_tokens / 1_000_000) * cost["output"]


def compute_llm_usage_summary(session: dict) -> list[dict]:
    """Per-session breakdown of which (provider_id, model) pairs were ACTUALLY dispatched to (see
    _record_llm_usage_event) -- distinct from session["llm_provider"], the operator's CONFIGURED
    intent, which a Reserve-providers fallback switch can diverge from mid-run. Sorted by call count
    descending, so index 0 is what the Summary tab calls "this session's provider" whenever exactly
    one entry exists (the overwhelmingly common case).

    estimated_cost_usd is None whenever models.dev has no pricing for that pair -- never fabricated
    as $0.00 (see _estimate_cost_usd). cost_is_partial is True when some of this entry's calls never
    reported usage at all (LLMResponse.usage's own docstring has the real incidents this guards
    against) -- the estimate then only covers the calls that did, so it's a floor, not the true total.
    """
    result = []
    for entry in session.get("llm_usage") or []:
        provider_id, model, calls = entry["provider_id"], entry["model"], entry["calls"]
        config = PROVIDER_REGISTRY.get(provider_id)
        result.append({
            "provider_id": provider_id,
            "model": model,
            "display_name": config.display_name if config else provider_id,
            "calls": calls,
            "avg_latency_seconds": entry["total_latency_seconds"] / calls if calls else None,
            "prompt_tokens": entry["prompt_tokens"],
            "completion_tokens": entry["completion_tokens"],
            "estimated_cost_usd": _estimate_cost_usd(config, model, entry["prompt_tokens"], entry["completion_tokens"]),
            "cost_is_partial": entry["calls_with_usage"] < calls,
        })
    result.sort(key=lambda e: e["calls"], reverse=True)
    return result


def compute_provider_leaderboard() -> list[dict]:
    """Cross-session "which provider is actually working best" ranking, built entirely from
    sessions.store.list_session_summaries()'s already-cached, already-cheap index -- never a fresh
    load_session() per project (see sessions/store.py's _build_summary docstring for why that
    matters on a Summary tab live sessions re-render every few seconds).

    Each session is attributed to its single DOMINANT provider -- whichever (provider_id, model) in
    its own llm_usage handled the most calls -- not split across every provider it fell back to;
    exactly one entry is the overwhelmingly common case (Reserve-providers fallback is the
    exception, not the rule). A session with no llm_usage at all (created before this feature
    existed, or genuinely made no real LLM call yet) contributes nothing.

    Four independent metrics per provider, deliberately never blended into one fake-precision number
    (see compute_efficiency_score's own docstring for why conflating "worked cleanly" with "found a
    lot" is actively misleading):
      - avg_cleanliness_score: mean compute_efficiency_score(...)["score"] (has_data sessions only)
        across every session attributed to this provider -- this project's own existing process-
        efficiency definition, reused rather than reinvented.
      - avg_latency_seconds: mean per-call response time across every attributed session.
      - avg_cost_per_session_usd: mean estimated $ spent per session (sessions with no cost data at
        all are excluded from that average, never treated as $0).
      - findings_per_100_calls: a YIELD metric -- total findings recorded across every attributed
        session per 100 total LLM calls. Explicitly separate from avg_cleanliness_score: a provider
        finding more real bugs isn't the same thing as one that wastes less budget getting there.

    Sorted by avg_cleanliness_score descending (providers with no has_data session at all sort
    last) since that's this project's own pre-existing "efficiency" definition -- the UI is expected
    to show all four columns, not just the sort key, so a reader isn't stuck trusting one blended
    number they can't see the components of.
    """
    provider_records: dict[str, list[tuple[dict, dict]]] = {}
    for summary in list_session_summaries():
        usage_entries = summary.get("llm_usage") or []
        if not usage_entries:
            continue
        dominant = max(usage_entries, key=lambda e: e["calls"])
        provider_records.setdefault(dominant["provider_id"], []).append((summary, dominant))

    leaderboard = []
    for provider_id, records in provider_records.items():
        config = PROVIDER_REGISTRY.get(provider_id)
        cleanliness_scores, latencies, costs = [], [], []
        total_findings = total_calls = 0
        for summary, dominant in records:
            eff = compute_efficiency_score(summary)
            if eff["has_data"]:
                cleanliness_scores.append(eff["score"])
            calls = dominant["calls"]
            total_calls += calls
            total_findings += summary.get("findings_count", 0)
            if calls:
                latencies.append(dominant["total_latency_seconds"] / calls)
            cost = _estimate_cost_usd(config, dominant["model"], dominant["prompt_tokens"], dominant["completion_tokens"])
            if cost is not None:
                costs.append(cost)

        leaderboard.append({
            "provider_id": provider_id,
            "display_name": config.display_name if config else provider_id,
            "sessions_count": len(records),
            "total_calls": total_calls,
            "avg_cleanliness_score": round(sum(cleanliness_scores) / len(cleanliness_scores)) if cleanliness_scores else None,
            "avg_latency_seconds": sum(latencies) / len(latencies) if latencies else None,
            "avg_cost_per_session_usd": sum(costs) / len(costs) if costs else None,
            "findings_per_100_calls": (total_findings / total_calls * 100) if total_calls else None,
        })

    leaderboard.sort(key=lambda e: (e["avg_cleanliness_score"] is None, -(e["avg_cleanliness_score"] or 0)))
    return leaderboard


def compute_portfolio_summary() -> dict:
    """Cross-session totals for the standalone Dashboard page (main.py's /dashboard) -- the same
    list_session_summaries() index compute_provider_leaderboard already reads, grouped by
    target/program instead of by provider, plus whole-portfolio totals. Never a fresh
    load_session() per project, same reasoning as compute_provider_leaderboard's own docstring.

    Deliberately a SEPARATE function rather than folding this into compute_provider_leaderboard --
    that one's own grouping key (provider_id) and this one's (target) answer different operator
    questions ("which provider is working" vs. "which program is worth my time"), and blending
    both into one return shape would make each harder to read than two small, single-purpose ones.
    """
    summaries = list_session_summaries()
    total_findings = 0
    total_cost_usd = 0.0
    any_cost_data = False
    programs: dict[str, dict] = {}

    for summary in summaries:
        target = summary.get("target") or "(unknown target)"
        program = programs.setdefault(target, {
            "target": target, "sessions_count": 0, "findings_count": 0,
            "cost_usd": 0.0, "has_cost_data": False, "_cleanliness_scores": [],
        })
        program["sessions_count"] += 1
        findings_count = summary.get("findings_count", 0)
        program["findings_count"] += findings_count
        total_findings += findings_count

        eff = compute_efficiency_score(summary)
        if eff["has_data"]:
            program["_cleanliness_scores"].append(eff["score"])

        usage_entries = summary.get("llm_usage") or []
        if usage_entries:
            dominant = max(usage_entries, key=lambda e: e["calls"])
            config = PROVIDER_REGISTRY.get(dominant["provider_id"])
            cost = _estimate_cost_usd(config, dominant["model"], dominant["prompt_tokens"], dominant["completion_tokens"])
            if cost is not None:
                program["cost_usd"] += cost
                program["has_cost_data"] = True
                total_cost_usd += cost
                any_cost_data = True

    program_list = []
    for entry in programs.values():
        scores = entry.pop("_cleanliness_scores")
        entry["avg_cleanliness_score"] = round(sum(scores) / len(scores)) if scores else None
        if not entry.pop("has_cost_data"):
            entry["cost_usd"] = None
        program_list.append(entry)
    program_list.sort(key=lambda e: e["findings_count"], reverse=True)

    return {
        "total_sessions": len(summaries),
        "total_findings": total_findings,
        "total_estimated_cost_usd": total_cost_usd if any_cost_data else None,
        "programs": program_list,
    }


def _provider_model_health_ranking() -> dict[tuple[str, str], float]:
    """Per-(provider_id, model) cleanliness score (compute_efficiency_score's own definition,
    averaged across every session where that exact pair was the dominant one this session's
    llm_usage) -- finer-grained than compute_provider_leaderboard's own provider-only attribution,
    which is deliberately kept separate rather than widening that function's own grouping key
    (its UI consumers, the Summary/Plan tabs' provider comparison card, are specifically about
    comparing PROVIDERS, not individual models within one).

    Feeds get_next_chain_step's own optional health_ranking parameter (agent/llm_client.py) so a
    fallback-chain walk gets reordered by which (provider, model) pairs have actually behaved
    cleanly recently — real, confirmed motivation: this session's own log-review audit found real
    LLM budget repeatedly burned on APITimeoutError/quota-exhausted retries against a pair with a
    recent history of exactly that, purely because it happened to sit first in the operator's
    static Settings list. A pair with no has_data session yet contributes nothing (never a
    fabricated score) — get_next_chain_step's own default-0.0 lookup covers that case.
    """
    scores_by_pair: dict[tuple[str, str], list[float]] = {}
    for summary in list_session_summaries():
        usage_entries = summary.get("llm_usage") or []
        if not usage_entries:
            continue
        eff = compute_efficiency_score(summary)
        if not eff["has_data"]:
            continue
        dominant = max(usage_entries, key=lambda e: e["calls"])
        key = (dominant["provider_id"], dominant["model"])
        scores_by_pair.setdefault(key, []).append(eff["score"])
    return {key: sum(scores) / len(scores) for key, scores in scores_by_pair.items()}


# Cross-session data that changes slowly (a fallback-chain walk inside one busy retry loop can
# call _cached_provider_health_ranking several times within a few seconds — agent/llm_client.py's
# own while-True claim loop, for one) — a short TTL cache avoids re-scanning every session's
# summary on each of those calls without ever staying stale for more than a minute.
_PROVIDER_HEALTH_RANKING_TTL_SECONDS = 60.0
_provider_health_ranking_cache: tuple[float, dict[tuple[str, str], float]] | None = None


def _cached_provider_health_ranking() -> dict[tuple[str, str], float]:
    global _provider_health_ranking_cache
    now = time.time()
    if _provider_health_ranking_cache is not None and now - _provider_health_ranking_cache[0] < _PROVIDER_HEALTH_RANKING_TTL_SECONDS:
        return _provider_health_ranking_cache[1]
    ranking = _provider_model_health_ranking()
    _provider_health_ranking_cache = (now, ranking)
    return ranking


async def run_focused_exploit(session_id: str, finding_title: str, provider_id: str | None = None, rerun_chain: bool = True) -> bool:
    """The Deep dive button's path for a session that ISN'T currently live (main.py's
    /deep-dive route) — a bounded, single-finding re-attempt safe to run as its own
    BackgroundTask precisely because nothing else is touching this session file at the same
    time (the live case instead queues a deep_dive instruction for the already-running loop to
    pick up — see _pop_deep_dive_instruction/_run_exploit — rather than risking two writers).
    Reuses _run_exploit_for_finding/_confirm_exploit_result unchanged, same as a normal exploit
    pass would for this one finding; everything else in the session is left exactly as it was.
    Returns whether this finding materially changed (see finding_materially_changed below) —
    run_all_findings_verification's own bulk loop uses this to decide whether ITS OWN single,
    end-of-batch Chain pass is worth running at all.

    rerun_chain=True (the default, standalone Deep-dive-button case) also re-runs _run_chain —
    real, confirmed incident this fixes: a Deep dive only ever gave the model ONE finding's own
    exploit tools (_run_exploit_for_finding's own task construction), never the cross-finding
    escalation view Chain provides — so an operator who deep-dived a finding into genuinely new,
    stronger evidence (or verify-all reconfirmed several) got that evidence sitting there UNUSED
    for exactly the "does this now unlock a hop into something bigger" question Chain exists to
    answer, and the operator saw only the same finding re-confirmed, never a fresh escalation
    attempt against the enlarged evidence set. run_session's own pipeline always runs
    Exploit -> Chain -> Validate together; this path used to run Exploit then jump straight to
    Validate, skipping Chain entirely. rerun_chain=False (run_all_findings_verification's own
    per-finding calls) defers Chain to a single end-of-batch pass instead — seeing every changed
    finding's updated evidence at once is both cheaper (one Chain pass instead of up to N) and
    strictly better material for Chain to reason over than any single finding's own delta alone.

    Also runs the same _run_validate dedup pass run_session's own pipeline always ends with —
    a deep dive's widened toolset includes record_finding (see _run_exploit_for_finding), and a
    harder pass at an already-known finding routinely re-records the same underlying issue under
    a new title ("...(Confirmed with multiple arbitrary origins)", then "...(5 independent
    origins confirmed)", etc. — a real, observed incident, not a hypothetical). run_session's own
    path always follows Exploit with Validate before saving; this path used to skip straight to
    save, which is the actual reason those near-duplicates piled up instead of ever being
    collapsed. Only worth the extra LLM call when a new finding actually got recorded — the
    common case (exploit attempted/skipped, no new record_finding call) still exits at 1 finding
    or fewer changed, exactly as cheap as before.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_focused_exploit: unknown session %r", session_id)
        return False

    matching = [f for f in session.get("findings", []) if f.get("title") == finding_title]
    if not matching:
        logger.debug("run_focused_exploit: session=%s no finding titled %r", session_id, finding_title)
        return False
    finding = matching[0]
    # Snapshot BEFORE _run_exploit_for_finding touches it -- exploited/evidence are the two fields
    # a genuine escalation (a header-only finding suddenly getting a real PoC, or vice versa were
    # that ever possible) always changes, even when it doesn't also add a brand-new finding to the
    # list. See finding_materially_changed below for how this and findings_before together decide
    # whether Chain has anything new worth looking at.
    exploited_before = finding.get("exploited")
    evidence_before = finding.get("evidence")

    resume_status = session["status"]
    session["status"] = "processing"
    # A deep dive re-opens an already-"completed" (finished_at set) session — same started_at/
    # finished_at contract as run_session: never reset started_at, but the session isn't actually
    # done again until this pass resolves below.
    session.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    session.pop("finished_at", None)
    save_session(session_id, session)
    logger.debug("run_focused_exploit: session=%s target=%s finding=%r starting", session_id, session["target"], finding_title)

    ctx = _new_run_context(session, session_id, provider_id)
    exploit_tools = get_tools_by_category("exploit")
    session_context_token = current_session_id.set(session_id)
    stopped = False
    crashed = False
    finding_materially_changed = False
    try:
        findings_before = len(ctx.session["findings"])
        action, trace = await _run_exploit_for_finding(ctx, session["target"], finding, exploit_tools, deep_dive=True)
        if action and action.get("confirmed_tech_fact"):
            _record_confirmed_tech_fact(ctx.session, finding, action["confirmed_tech_fact"])
        if action:
            _apply_remediation_advice(finding, action.get("remediation_advice"))
        if action and action.get("action") == "exploit_attempted":
            confirmed = await _confirm_exploit_result(ctx, finding, action, trace)
            finding["exploited"] = confirmed.get("exploited", False)
            finding["evidence"] = confirmed.get("evidence")
            finding["poc_command"] = confirmed.get("poc_command")
            finding["advisory_note"] = confirmed.get("advisory_note")
            finding["extracted_artifact"] = confirmed.get("extracted_artifact")
            finding["artifact_usage_hint"] = confirmed.get("artifact_usage_hint")
            finding["exploit_outcome"] = "exploit_attempted"
            scenario = confirmed.get("exploitation_scenario")
            if scenario in _VALID_EXPLOITATION_SCENARIOS:
                finding["exploitation_scenario"] = scenario
            _apply_corrected_title(finding, confirmed.get("corrected_title"))
            _apply_corrected_qualification(finding, confirmed.get("corrected_severity"), confirmed.get("corrected_qualifies_for_bounty"))
            _apply_corrected_false_positive_reason(finding, confirmed.get("corrected_false_positive_reason"))
            _append_tool_timeline(finding, _extract_tool_timeline_entries(trace, "exploitation"))
            _maybe_capture_playbook_entry(ctx, finding)
            _credit_tool_memory_for_finding(ctx, finding)
        else:
            _apply_skip_outcome(finding, action or {"reasoning": "Deep dive produced no parseable decision"})
        logger.debug("run_focused_exploit: session=%s finding=%r resolved exploited=%s", session_id, finding_title, finding.get("exploited"))

        # A NEW finding recorded (record_finding is available alongside the exploit tools here) OR
        # THIS finding's own exploited/evidence state actually moved -- either is real, fresh
        # material Chain didn't have before. Gated (not unconditional) for the same reason the old
        # validate-only check was: the overwhelmingly common case (attempt/skip, nothing new) has
        # nothing new for Chain to look at, so it must stay exactly as cheap as before.
        # Truthy-transition checks, not a bare != -- _apply_skip_outcome unconditionally normalizes
        # exploited/evidence to False/None even when nothing was ever attempted before either (a
        # finding with no prior exploited/evidence key at all reads as None, which != False/None
        # would wrongly flag as "changed" on every single skip, defeating the whole point of this
        # gate). Only a genuine NEW positive signal -- became exploited when it wasn't, or gained
        # real (truthy) evidence it didn't have -- counts; a finding staying/becoming unexploited
        # is not escalation material regardless of its exact None/False representation before.
        finding_materially_changed = (
            len(ctx.session["findings"]) > findings_before
            or (finding.get("exploited") and not exploited_before)
            or (finding.get("evidence") and finding.get("evidence") != evidence_before)
        )
        # Same Exploit -> Chain -> Validate order run_session's own pipeline always uses. Skipped
        # entirely when rerun_chain=False (run_all_findings_verification defers to its own single
        # end-of-batch pass instead — see this function's own docstring for why that's both cheaper
        # and gives Chain strictly better material than any one finding's own delta alone).
        if rerun_chain and finding_materially_changed:
            ctx.session["findings"] = await _run_chain(ctx)
            ctx.session["findings"] = await _run_validate(ctx)
            ctx.session["findings"] = _normalize_findings(ctx.session["findings"])
    except (SessionStopRequested, asyncio.CancelledError) as exc:
        # Unlike run_session, this path is always scheduled as its own bare background task
        # (main.py's /deep-dive route) with no _run_session_task-style wrapper above it to
        # swallow an already-handled exception -- swallow right here instead (not re-raised), or
        # this reaches Starlette's background-task runner as a raw, unhandled traceback for what
        # is, on a Stop request or shutdown, an expected outcome, not a crash.
        stopped = True
        logger.debug("run_focused_exploit: session=%s finding=%r stopped (%s)", session_id, finding_title, type(exc).__name__)
    except Exception as exc:
        # Real, confirmed incident this fixes: an LLM fallback-chain exhaustion (or any other
        # genuine failure) raised from inside the try block above used to reach neither this
        # except (it only caught Stop/Cancel) nor any handling below -- it fell straight through
        # to the finally block's own "else" branch, which unconditionally marked the session
        # completed/resume_status and saved that BEFORE the same exception kept propagating
        # upward into main.py's bare background_tasks.add_task (no _run_session_task-style
        # wrapper catches it there either) -- so the crash left zero trace in debug.log or
        # session["logs"], and the operator had no way to tell a genuinely resolved finding
        # apart from one cut short by a dead LLM provider. Mirrors run_session's own except
        # Exception handling (status="failed", resumable_from, a real _append_log entry) instead
        # of silently reporting success.
        crashed = True
        logger.debug("run_focused_exploit: session=%s finding=%r failed", session_id, finding_title, exc_info=True)
        _append_log(ctx, phase="exploit", thought=None, command=None, status="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        # This run has now genuinely ended, one way or another -- the one right place to clear the
        # stop flag (see _llm_complete's own docstring for the real incident this fixes: none of the
        # individual per-call checkpoints clear it anymore, since a concurrent subagent task sharing
        # this same session_id could otherwise silently steal the signal from the main loop).
        # Idempotent -- clearing an already-clear asyncio.Event is a no-op.
        get_stop_event(session_id).clear()
        # Same "this run has now genuinely ended" reasoning, for get_exhausted_chain_steps -- a
        # step proven dead in THIS run must not silently blacklist a later resumed run, since real
        # time passing (the operator resuming later, e.g. after a daily quota refreshes) is
        # exactly the case that fix needs to allow retrying again.
        _clear_exhausted_chain_steps(session_id)
        await _close_browser_session_safely(session_id)
        if stopped:
            session["status"] = "interrupted"
            session["resumable_from"] = compute_resume_entry_point(session)
            session.pop("last_focused_pass_ok", None)
        elif crashed:
            session["status"] = "failed"
            session["resumable_from"] = compute_resume_entry_point(session)
            session.pop("last_focused_pass_ok", None)
        else:
            session["status"] = resume_status if resume_status in ("completed", "failed", "interrupted") else "completed"
            if session["status"] == "completed":
                session["finished_at"] = datetime.now(timezone.utc).isoformat()
                # A deep dive is genuinely more exploit-phase work against an already-completed
                # session -- without this, the extra real time it takes (a real incident: ~11
                # minutes on one real session) counted toward session["finished_at"] (and so
                # inflated the displayed Session time) with nothing in the Plan tab's own Exploit
                # duration to show for it, leaving Session time silently bigger than the sum of
                # every phase card shown, with no visible explanation. _mark_phase_finished always
                # overwrites (the LAST real completion wins), so this correctly extends exploit's
                # own duration to cover the deep dive too.
                _mark_phase_finished(session, "exploit")
                session.pop("last_focused_pass_ok", None)
            else:
                # status stayed at its pre-existing terminal value (failed/interrupted) because
                # THIS pass ran fine but the session as a whole still hasn't finished its pipeline
                # (see resume_status above) -- session_fragment.html's "Scan failed" banner reads
                # this to soften its wording instead of implying THIS deep dive itself failed, the
                # actual incident an operator flagged after a clean re-verify still showed "Scan
                # failed" with no distinction from a fresh crash.
                session["last_focused_pass_ok"] = True
        save_session(session_id, session)
        logger.debug(
            "run_focused_exploit: session=%s finding=%r ended status=%s total session duration=%s",
            session_id, finding_title, session["status"], format_session_duration(session),
        )
        current_session_id.reset(session_context_token)
    return finding_materially_changed


# RE triage is meant to be a SHORT, ONE-TIME pass (identify the target, run the fitting baseline
# analysis, record findings, stop), NOT the full multi-phase agent loop. It therefore gets its own
# much tighter budget than the 7200s whole-pipeline backstop _PHASE_WALLCLOCK_LIMIT_SECONDS gives:
# a real pass that recorded ZERO findings ran ~1h46m before the operator killed it, just short of
# that 2h backstop. 1800s (30 min) is a generous ceiling for a genuine baseline pass while still
# cutting a runaway an order of magnitude sooner. Env-overridable for a deliberately deeper local
# target (a large firmware image, a big source tree) that legitimately needs more.
_DEFAULT_RE_TRIAGE_WALLCLOCK_SECONDS = 1800
# Consecutive tool calls with nothing recorded before the pass is treated as spinning (see
# _PROGRESS_RECORDING_TOOLS). 25 is generous for a real pass -- the first genuine baseline call
# chain (info -> imports -> strings -> a decompile or two) records a target-profile fact well
# inside that -- while still catching the record-nothing grind that ran ~46 calls straight without
# a single record here.
_DEFAULT_RE_TRIAGE_PROGRESS_STALL = 25
# A real, confirmed pass (hcm-usr_15eee7's dynamic-then-static baseline chain) legitimately used
# ~35-40 calls end to end for a single obfuscated-binary target; 50 gives real multi-stage passes
# (static + one dynamic run + a devirtualization attempt) headroom while still being well short of
# "tens of minutes of spinning with no result" -- the exact complaint this closes. Env-overridable
# for a deliberately deeper target the same way the wall-clock/stall knobs above already are.
_DEFAULT_RE_TRIAGE_MAX_TOOL_CALLS = 50


def _re_triage_wallclock_seconds() -> int:
    return int(os.getenv("RE_TRIAGE_WALLCLOCK_SECONDS", str(_DEFAULT_RE_TRIAGE_WALLCLOCK_SECONDS)))


def _re_triage_progress_stall_threshold() -> int:
    return int(os.getenv("RE_TRIAGE_PROGRESS_STALL", str(_DEFAULT_RE_TRIAGE_PROGRESS_STALL)))


def _re_triage_max_tool_calls() -> int:
    return int(os.getenv("RE_TRIAGE_MAX_TOOL_CALLS", str(_DEFAULT_RE_TRIAGE_MAX_TOOL_CALLS)))


def _re_triage_end_reason_message(stop_reason: str | None) -> str | None:
    """Translate the loop's internal stop_reason into a short, operator-facing note for the control
    bar. None (a natural, model-decided finish) stays None -- nothing to explain. Everything else is
    a SAFEGUARD stop, so the operator learns the pass was cut short (and may be incomplete) rather
    than reading a bare "completed" as proof it fully finished."""
    if not stop_reason:
        return None
    if "wall-clock backstop" in stop_reason:
        return "hit its time limit before finishing on its own — it may be incomplete. Re-scan continues where it left off."
    if "call budget" in stop_reason:
        return "reached its tool-call budget before finishing on its own — see the Logs/Triage view for a summary of what it found so far. Re-scan continues where it left off."
    if "without recording" in stop_reason or "in a row" in stop_reason:
        return "stopped early after a run of tool calls that recorded nothing new — it may be incomplete. Re-scan continues where it left off."
    return "stopped on a safeguard before finishing on its own — it may be incomplete. Re-scan continues where it left off."


# The magic-byte signatures that make a file a compiled executable a binary tool (radare2/gdb/
# qiling_emulate) can actually load -- PE ("MZ"), ELF, and the four Mach-O variants (32/64-bit,
# each in either endianness). Kept as raw bytes so _re_directory_target_hint below can sniff a
# file's real first bytes instead of trusting an extension a crackme may well not have.
_EXECUTABLE_MAGIC_PREFIXES = (
    b"MZ",                       # PE / DOS (.exe/.dll)
    b"\x7fELF",                  # ELF
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",  # Mach-O 32/64 big-endian
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",  # Mach-O 32/64 little-endian
)


def _re_directory_target_hint(target: str) -> str:
    """When an RE target is a DIRECTORY, hand the model a ready-made listing of what's inside and
    name the file(s) that actually sniff as loadable executables -- so it targets the real binary
    on its first move instead of feeding the directory path straight to radare2 (which just returns
    empty analysis over and over). Returns "" for a non-directory target (the normal single-file
    case), or when nothing inside sniffs as an executable (a genuine source-code repo, which the
    system prompt already knows how to triage as a repo -- deliberately NOT forced toward a binary).

    Purely a deterministic pre-hint appended to the task text: it never picks FOR the model, only
    surfaces what a directory listing plus a first-bytes sniff already make obvious, so any model --
    including a weak one that would otherwise waste its whole budget rediscovering this -- starts
    from solid ground.
    """
    try:
        if not os.path.isdir(target):
            return ""
        entries = sorted(os.listdir(target))
    except OSError as exc:
        logger.debug("run_re_triage: could not list directory target %r: %s", target, exc)
        return ""

    executables: list[str] = []
    for name in entries:
        full = os.path.join(target, name)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "rb") as handle:
                head = handle.read(4)
        except OSError:
            continue
        if any(head.startswith(prefix) for prefix in _EXECUTABLE_MAGIC_PREFIXES):
            executables.append(name)

    if not entries:
        return ""
    listing = ", ".join(entries[:50]) + (" ..." if len(entries) > 50 else "")
    hint = (
        f"\n\nNote: the target is a DIRECTORY, not a single file. Its contents are: {listing}. "
        "Point your tools at a specific file inside it (e.g. "
        f"{os.path.join(target, entries[0])}), never at the directory path itself -- radare2/gdb/"
        "qiling_emulate cannot analyze a directory and will just return empty results."
    )
    if executables:
        exec_paths = ", ".join(os.path.join(target, name) for name in executables)
        hint += f" Loadable executable(s) detected inside (by file signature): {exec_paths}."
    logger.debug("run_re_triage: directory target %r -> %d entries, executables=%r", target, len(entries), executables)
    return hint


# memscan_* (agent/tools/memscan_manager.py) is category="re", genuinely offered by a bare
# get_tools_by_category("re") call -- but its real CE-style workflow (attach, scan, wait for the
# operator to report the value changed in the running target, narrow, repeat) needs a human in the
# loop between calls, which only RE chat's turn-by-turn interactive shape can provide. Both
# run_re_triage and run_re_reverify below are bounded, non-interactive autonomous passes with no
# operator present mid-run to trigger that change -- attaching there would just time out uselessly.
# Excluded from both tool lists explicitly; still fully available in agent/chat.py's own RE tool
# list (that one is never filtered this way, since chat's own bare get_tools_by_category("re") call
# is exactly where a persistent attach across separate turns is supposed to live).
_MEMSCAN_TOOL_NAMES = frozenset({"memscan_attach", "memscan_scan", "memscan_list", "memscan_write", "memscan_detach"})


async def run_re_triage(session_id: str, provider_id: str | None = None, is_resume: bool = False) -> None:
    """The Reverse Engineering mode's Start-button entry point (main.py's Start route branches
    here instead of run_session when session["mode"] == "reverse_engineering") — a single,
    bounded baseline-triage pass, never the recon/analyze/exploit/chain/validate loop run_session
    drives (RE has no WAF/scope-rule complexity to justify that shape). See RE_TRIAGE_PROMPT
    (agent/prompts.py) for what "bounded" means here: identify the target shape (binary, smart
    contract with/without source, or source repo), run the fitting static analysis once, record
    real findings, stop. Follow-up investigation happens in the session's own chat panel
    afterward (agent/chat.py's mode=="reverse_engineering" branch), not by re-running this
    function — same standalone-background-function shape as run_focused_exploit above, not
    run_session's multi-phase while-loop.

    is_resume=True (main.py's /re-triage/resume and /re-triage/rescan routes): same "informed
    restart" pattern _run_recon already uses for its own resume (see that function's own
    "resumed recon phase" task addendum) -- a brand-new LLM conversation, but explicitly told what
    session["target_profile"]/session["findings"] already established, so it doesn't blindly redo
    work an earlier paused/interrupted/failed/completed pass already paid for. Never clears
    findings/target_profile/logs itself -- record_finding/record_target_profile already dedupe
    (by title/label) on their own, so a resumed pass re-confirming something already known is a
    harmless no-op, not a duplicate.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_re_triage: unknown session %r", session_id)
        return

    session["status"] = "processing"
    session.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    session.pop("finished_at", None)
    save_session(session_id, session)
    logger.debug("run_re_triage: session=%s target=%s starting", session_id, session["target"])

    ctx = _new_run_context(session, session_id, provider_id)
    # record_finding is category="scan" (agent/tools/__init__.py), invisible to a bare
    # get_tools_by_category("re") call — appended explicitly, same pattern _run_recon uses for
    # update_plan/record_hypothesis above. background_job_check is category="exploit" for the
    # SAME reason (it's the main Agent pipeline's own hydra/web_login_bruteforce poll tool) --
    # appended here too, or afl_fuzz_start (category="re", genuinely offered by the bare
    # get_tools_by_category("re") call above) would have no way to ever be checked on within
    # this same pass, a real, confirmed-live gap found testing afl_fuzz_start end-to-end.
    # memscan_* tools excluded from this bare category="re" sweep -- see _MEMSCAN_TOOL_NAMES'
    # own comment: they need a human in the loop between scans, which a bounded autonomous pass
    # like this one can never provide.
    tools = [spec for spec in get_tools_by_category("re") if spec.name not in _MEMSCAN_TOOL_NAMES]
    for extra_name in ("record_finding", "background_job_check"):
        extra_spec = get_tool(extra_name)
        if extra_spec is not None:
            tools.append(extra_spec)

    session_context_token = current_session_id.set(session_id)
    stopped = False
    try:
        async def execute(spec: ToolSpec, arguments: dict) -> dict:
            result = await _run_tool_with_retry(ctx, spec, arguments)
            if spec.name == "record_finding" and result.get("status") == "ok" and "recorded" in result:
                conflict_result = await _persist_new_finding(ctx, result["recorded"])
                if conflict_result is not None:
                    return conflict_result
                logger.debug("core: session=%s re_triage: recorded finding title=%r", ctx.session_id, result["recorded"].get("title"))
            return result

        task = f"Target: {session['target']}\nRun the baseline triage pass described in your system prompt."
        if is_resume:
            profile_facts = session.get("target_profile") or []
            finding_titles = [f.get("title") for f in session.get("findings", []) if f.get("title")]
            # Open hypotheses are durable progress too -- an earlier pass that got as far as "reads
            # operator ID then serial from stdin; serial is uppercase hex XXXXXXXX-..." but never
            # promoted it to a finding still recorded real ground a resume must not re-derive from
            # scratch. Carried the same way as findings/profile facts (a compact state summary,
            # never the raw prior conversation).
            hypothesis_texts = [h.get("text") for h in session.get("hypotheses", []) if h.get("text") and h.get("status") not in ("ruled_out",)]
            if profile_facts or finding_titles or hypothesis_texts:
                # Same "tell the model what's already known instead of redoing it" pattern as
                # _run_recon's own resumed-phase addendum (see that function's own comment) --
                # never the raw prior conversation, just a durable-state summary.
                already_bits = [f"{fact.get('label')}: {fact.get('value')}" for fact in profile_facts if fact.get("label")]
                task += "\n\nThis is a resumed/re-run baseline triage — an earlier pass on this same target already established:"
                if already_bits:
                    task += "\n- " + "\n- ".join(already_bits)
                if finding_titles:
                    task += "\n\nFindings already recorded: " + ", ".join(finding_titles)
                if hypothesis_texts:
                    task += "\n\nOpen leads already noted (verify/build on these, don't rediscover them): " + "; ".join(hypothesis_texts)
                task += "\n\nDon't redo the same analysis unless something looks incomplete or wrong — continue with whatever's left."
        task += _re_directory_target_hint(session["target"])
        task += _custom_instructions_task_addendum(session)
        task += _scope_rules_task_addendum(session)
        task += _goal_task_addendum(session)

        system_prompt = RE_TRIAGE_PROMPT + _re_experience_level_addendum(session)
        await _run_llm_tool_loop(
            ctx, system_prompt, task, tools, "re_triage", execute_tool=execute, expect_json_final=False,
            wallclock_limit_seconds=_re_triage_wallclock_seconds(),
            progress_stall_threshold=_re_triage_progress_stall_threshold(),
            max_tool_calls=_re_triage_max_tool_calls(),
        )
    except (SessionStopRequested, asyncio.CancelledError) as exc:
        stopped = True
        logger.debug("run_re_triage: session=%s stopped (%s)", session_id, type(exc).__name__)
    finally:
        get_stop_event(session_id).clear()
        # Real, confirmed gap this closes: run_session's own completion path has always waited for
        # (or killed, on stop) any real background job (afl_fuzz_start, ...) it started before
        # declaring itself done -- run_re_triage never had the same protection, so an AFL++ fuzzing
        # run started during triage could be left running, completely untracked, the moment this
        # pass finished (nothing else in RE mode's own request cycle ever calls check on it again
        # unless the operator's own follow-up chat happens to). Same "wait if genuinely done,
        # kill if the operator asked to stop" split run_session already applies.
        if stopped:
            kill_all_running_jobs(session)
            # "pause" (operator-initiated, wants to continue later) vs "stop" (operator-initiated,
            # no intent recorded either way defaults to "stop") -- a real process crash never sets
            # any intent at all (request_session_stop is never called), so it never reaches this
            # branch in the first place; main.py's startup orphan-sweep is what marks THAT case
            # "interrupted", unchanged.
            session["status"] = "paused" if pop_re_stop_intent(session_id) == "pause" else "interrupted"
            # An operator pause/stop already speaks for itself in the control bar; a stale safeguard
            # reason from a prior pass would only confuse it, so clear it here.
            session["triage_end_reason"] = None
        else:
            await await_all_running_jobs(session_id, session)
            await _harvest_completed_background_jobs(ctx)
            session["status"] = "completed"
            session["finished_at"] = datetime.now(timezone.utc).isoformat()
            # Honest end-reason: a pass that hit a safeguard (ran out of wall-clock, or stalled with
            # nothing new recorded) is still status="completed", but must NOT read to the operator
            # exactly like a pass that genuinely finished on its own -- that indistinguishability is
            # the real "completed, but 0 results and I don't understand why" complaint. None here
            # means a clean, natural finish; the control bar phrases the rest.
            session["triage_end_reason"] = _re_triage_end_reason_message(ctx.last_stop_reason)
            if ctx.last_stop_reason:
                logger.debug("run_re_triage: session=%s hit safeguard end-reason: %s", session_id, ctx.last_stop_reason)
        # Reload-merge-save (_reload_merge_save above), not a blind save_session(session_id, session)
        # of this whole function's own start-of-pass in-memory snapshot -- `session` was loaded once
        # at the top of this function and never refreshed since, so a concurrent writer (the session's
        # own chat panel calling record_finding mid-pass) that landed a real write on disk in the
        # meantime would otherwise be silently overwritten by this stale copy the instant the pass
        # ends. Real, confirmed incident this fixes: exactly that -- a chat-recorded finding fired its
        # reward toast, then vanished (empty on the Findings tab, still empty after reload) because
        # this exact save ran after and wiped it. Only the fields THIS function actually owns --
        # status/finished_at, and background_jobs (kill_all_running_jobs/await_all_running_jobs just
        # mutated it in place on this same in-memory `session`) -- are merged onto whatever's freshest
        # on disk right now; findings/target_profile/hypotheses are left exactly as the fresher copy
        # already has them.
        def _apply_re_triage_end_state(fresh: dict) -> None:
            fresh["status"] = session["status"]
            fresh["background_jobs"] = session.get("background_jobs", fresh.get("background_jobs", {}))
            fresh["triage_end_reason"] = session.get("triage_end_reason")
            if "finished_at" in session:
                fresh["finished_at"] = session["finished_at"]
            else:
                fresh.pop("finished_at", None)
        _reload_merge_save(session_id, _apply_re_triage_end_state)
        logger.debug("run_re_triage: session=%s ended status=%s end_reason=%r", session_id, session["status"], session.get("triage_end_reason"))
        current_session_id.reset(session_context_token)


async def run_re_reverify(session_id: str, finding_titles: list[str] | None = None, provider_id: str | None = None) -> None:
    """Re-checks whether one or more already-recorded Reverse Engineering findings still hold,
    using the same category="re" toolset run_re_triage uses — the RE-mode analog of Agent-mode's
    Deep dive (run_focused_exploit), but framed as verification rather than exploitation: a
    decompiled function or a detected supply-chain pattern isn't "a vulnerability to exploit" the
    same way a web finding is, so reusing EXPLOIT_PROMPT/CONFIRM_EXPLOIT_PROMPT's attack framing
    would be a poor fit — this reuses RE_CHAT_PROMPT's own "confirm using real tool output"
    discipline instead. Also deliberately does NOT reuse agent/core.py's own _run_reverify — that
    function is tightly coupled to the rescan/carried_over_findings pipeline (replaces/removes
    findings against a PRIOR scan's own snapshot), not a realistic fit for one ad-hoc re-check of
    an existing finding in place. record_reverification_result (agent/tools/native.py) IS reused
    as the terminal tool, though — its own data shape (verification_outcome/reasoning/
    evidence_ref/corrected_*) is already fully generic; only its docstring's rescan framing doesn't
    apply here, not its actual fields.

    finding_titles=None re-verifies every current finding (the findings panel's "Re-verify all"
    button); a non-empty list re-verifies just those (the single-finding "Re-verify" button).
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_re_reverify: unknown session %r", session_id)
        return

    resume_status = session["status"]
    session["status"] = "processing"
    # Same started_at/finished_at contract as run_re_triage/run_session/run_focused_exploit above
    # -- real, confirmed incident this fixes: this was the one status="processing" entry point that
    # never cleared finished_at, so a session whose earlier pass had already set it could end up
    # with the nonsensical combination "status=processing, finished_at=<stale timestamp>" on disk
    # if this pass's own result was ever clobbered before it could set its own finished_at (see
    # _track_host_health's own reload_merge_save fix for the actual clobbering bug this compounded).
    session.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    session.pop("finished_at", None)
    save_session(session_id, session)
    logger.debug("run_re_reverify: session=%s finding_titles=%s starting", session_id, finding_titles)

    ctx = _new_run_context(session, session_id, provider_id)
    # memscan_* tools excluded here too -- same reasoning as run_re_triage's own tool-list
    # construction just above (see _MEMSCAN_TOOL_NAMES' own comment).
    tools = [spec for spec in get_tools_by_category("re") if spec.name not in _MEMSCAN_TOOL_NAMES]
    reverify_tool = get_tool("record_reverification_result")
    if reverify_tool is not None:
        tools = [*tools, reverify_tool]
    # background_job_check is category="exploit", invisible to the bare get_tools_by_category("re")
    # call above -- appended here so afl_fuzz_start (offered by that same call, category="re") can
    # actually be checked on within this pass, same fix as run_re_triage's own tool list just above.
    job_check_tool = get_tool("background_job_check")
    if job_check_tool is not None:
        tools = [*tools, job_check_tool]

    session_context_token = current_session_id.set(session_id)
    stopped = False
    crashed = False
    try:
        async def execute(spec: ToolSpec, arguments: dict) -> dict:
            return await _run_tool_with_retry(ctx, spec, arguments)

        targets = [f for f in list(ctx.session.get("findings", [])) if finding_titles is None or f.get("title") in finding_titles]
        for finding in targets:
            title = finding.get("title")
            ctx.current_finding_title = title
            task = (
                "A previous pass recorded this finding:\n"
                + json.dumps({k: finding.get(k) for k in ("title", "severity", "description", "evidence_ref", "evidence")})
                + f"\n\nTarget: {ctx.session.get('target')}\n"
                "Re-check whether it is STILL real, right now, using your own tools — do not assume "
                "the old evidence still holds. If you confirm it (verification_outcome="
                "\"confirmed_present\"), your reasoning must be concrete, numbered, step-by-step "
                "instructions the operator can follow THEMSELVES to reproduce this and see the "
                "impact with their own eyes — the exact tool calls/commands, the exact function/"
                "address/offset, in order — not a description of what you personally did. This "
                "becomes the finding's own reproduction guide, not just an internal note."
            )
            try:
                verdict, _trace = await _run_llm_tool_loop(
                    ctx, RE_CHAT_PROMPT, task, tools, "re_reverify",
                    execute_tool=execute, terminal_tool="record_reverification_result",
                )
            finally:
                ctx.current_finding_title = None

            outcome = (verdict or {}).get("verification_outcome") or "inconclusive"
            reasoning = (verdict or {}).get("reasoning") or "No conclusive verdict reached this pass."

            def _apply_reverify_result(fresh: dict, outcome=outcome, reasoning=reasoning, verdict=verdict, title=title) -> None:
                # Bound as default-arg values (not closed over the loop variable) so each iteration's
                # own outcome/title is what actually gets applied -- a plain closure over a `for`
                # loop's variables would see whatever the NEXT iteration left them as by the time this
                # runs, the classic late-binding trap.
                if outcome == "confirmed_fixed":
                    fresh["findings"] = [f for f in fresh.get("findings", []) if f.get("title") != title]
                    return
                for f in fresh.get("findings", []):
                    if f.get("title") != title:
                        continue
                    f["verification"] = "verified" if outcome == "confirmed_present" else "needs_verification"
                    f["advisory_note"] = reasoning
                    if outcome == "confirmed_present":
                        f["evidence_ref"] = (verdict or {}).get("evidence_ref") or f.get("evidence_ref")
                        # The task above asked specifically for step-by-step reproduction guidance
                        # when confirming -- promoted into reproduction_steps (the same field the
                        # rich findings card's own "Full evidence / reproduction detail" section
                        # already renders) so it's the operator's own actionable how-to, not buried
                        # in an internal-sounding "advisory_note". Only overwritten on a fresh
                        # confirmation, never on "needs_verification"/inconclusive -- the ORIGINAL
                        # reproduction guidance (if the triage pass wrote one) survives a pass that
                        # couldn't re-confirm anything either way.
                        f["reproduction_steps"] = reasoning
                    _apply_reverify_correction(f, f, verdict, session_id)
                    _apply_corrected_false_positive_reason(f, (verdict or {}).get("corrected_false_positive_reason"))

            # Reload-merge-save (_reload_merge_save above, same fix as run_re_triage/_persist_new_
            # finding), not a blind save_session(ctx.session_id, ctx.session) -- this loop can run for
            # a while (one LLM tool-loop pass per finding), during which the session's own chat panel
            # is free to record something new; a blind save here would silently wipe that. ctx.session
            # is kept in sync afterward purely so the rest of THIS function still sees an accurate
            # picture if anything below ever reads it again.
            fresh_after = _reload_merge_save(ctx.session_id, _apply_reverify_result)
            if fresh_after is not None:
                ctx.session["findings"] = fresh_after["findings"]
            logger.debug("core: session=%s re_reverify: %r outcome=%s", ctx.session_id, title, outcome)
    except (SessionStopRequested, asyncio.CancelledError) as exc:
        stopped = True
        logger.debug("run_re_reverify: session=%s stopped (%s)", session_id, type(exc).__name__)
    except Exception as exc:
        # Same reasoning/fix as run_focused_exploit's own except Exception -- an LLM
        # fallback-chain exhaustion (or any other real failure) used to fall straight through to
        # the "else" branch below, silently reporting completed/resume_status with zero trace of
        # the failure. _append_log below writes onto this function's own local `session` snapshot
        # only (ctx.session is that same object) -- the merge-save closure just below re-attaches
        # just this one new entry onto the freshest on-disk logs list rather than overwriting it
        # wholesale, same non-clobbering discipline the rest of this function's own per-finding
        # reload-merge-save calls already follow.
        crashed = True
        logger.debug("run_re_reverify: session=%s failed", session_id, exc_info=True)
        _append_log(ctx, phase="re_reverify", thought=None, command=None, status="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        get_stop_event(session_id).clear()
        # Same real, confirmed gap run_re_triage's own finally block above just got fixed for --
        # a re-verify pass can call afl_fuzz_start too (it shares the exact same category="re"
        # toolset), and this function had no protection against leaving that background job
        # running once the pass itself ends.
        if stopped:
            kill_all_running_jobs(session)
        else:
            await await_all_running_jobs(session_id, session)
            await _harvest_completed_background_jobs(ctx)
        if stopped:
            session["status"] = "interrupted"
            session.pop("last_focused_pass_ok", None)
        elif crashed:
            session["status"] = "failed"
            session.pop("last_focused_pass_ok", None)
        else:
            session["status"] = resume_status if resume_status in ("completed", "failed", "interrupted") else "completed"
            if session["status"] in ("failed", "interrupted"):
                # See run_focused_exploit's own comment on this same marker -- this pass itself
                # ran fine, only the session's pre-existing terminal status was preserved, so the
                # "Scan failed" banner should read as a preserved state, not a fresh crash here.
                session["last_focused_pass_ok"] = True
            else:
                session.pop("last_focused_pass_ok", None)
        # Reload-merge-save, same fix and same reason as run_re_triage's own finally block above --
        # only the fields this function actually owns (status, background_jobs, last_focused_pass_ok,
        # and — only when this pass itself crashed — one appended error log entry) are merged onto
        # whatever's freshest on disk, so ending the pass can never clobber a finding the per-loop
        # reload-merge-save above (or a concurrent chat turn) already landed.
        def _apply_re_reverify_end_state(fresh: dict) -> None:
            fresh["status"] = session["status"]
            fresh["background_jobs"] = session.get("background_jobs", fresh.get("background_jobs", {}))
            if "last_focused_pass_ok" in session:
                fresh["last_focused_pass_ok"] = session["last_focused_pass_ok"]
            else:
                fresh.pop("last_focused_pass_ok", None)
            if crashed and session.get("logs"):
                crash_entry = dict(session["logs"][-1])
                crash_entry["step"] = len(fresh.get("logs", [])) + 1
                fresh.setdefault("logs", []).append(crash_entry)
        _reload_merge_save(session_id, _apply_re_reverify_end_state)
        logger.debug("run_re_reverify: session=%s ended status=%s", session_id, session["status"])
        current_session_id.reset(session_context_token)


def _hypothesis_verification_tool_specs() -> list[ToolSpec]:
    """A hypothesis might need reconnaissance, not just exploitation (e.g. "the old /api/v1
    endpoints might still be reachable" needs a fresh probe, not an exploit attempt against
    something not yet confirmed to exist) — broader than run_focused_exploit's plain exploit-only
    toolset. Deduped by name (a ToolSpec registered under more than one category, e.g. via
    categories_of's tuple case, would otherwise appear twice in what the model sees). record_finding/
    record_hypothesis/resolve_hypothesis are category="post_exploit" (agent/tools/__init__.py),
    invisible to a bare get_tools_by_category call — same explicit-append pattern already used for
    Exploit's own resolve_hypothesis (agent/core.py's _run_exploit tool-list assembly) and Chain's
    own record_finding/record_chain_result assembly just below.
    """
    base = get_tools_by_category("recon") + get_tools_by_category("scan") + get_tools_by_category("exploit")
    deduped = list({spec.name: spec for spec in base}.values())
    for name in ("record_finding", "record_hypothesis", "resolve_hypothesis"):
        spec = get_tool(name)
        if spec is not None and spec.name not in {s.name for s in deduped}:
            deduped.append(spec)
    return deduped


_HYPOTHESIS_PASS_BOOKKEEPING_TOOLS = {"record_hypothesis", "resolve_hypothesis"}


def _hypothesis_resolved_without_real_investigation(trace: list[dict]) -> bool:
    """A proportionate, not airtight, anti-fabrication check for a resolve_hypothesis call about to
    succeed — proportionate the same way record_finding/record_exploit_decision aren't airtight
    against fabrication either, just structural+evidence requirements, not a full attribution
    system. True when NOTHING in the trace so far (this pass, up to but not including the current
    call) is a real investigative tool call — only record_hypothesis/resolve_hypothesis bookkeeping,
    or nothing at all. Deliberately pass-wide, not per-hypothesis: several hypotheses can be open in
    one pass, and reliably attributing which specific earlier tool call served which specific
    hypothesis isn't inferable from a flat trace — this only catches the degenerate case of
    resolving something with zero investigation of ANY kind yet.
    """
    return not any(entry.get("tool") not in _HYPOTHESIS_PASS_BOOKKEEPING_TOOLS for entry in trace)


def _make_hypothesis_verification_executor(
    ctx: RunContext, trace: list[dict] | None = None, target_hypothesis_id: str | None = None,
) -> Callable[[ToolSpec, dict], Awaitable[dict]]:
    """Builds the execute_tool closure for both run_hypothesis_verification (one hypothesis,
    triggered by an operator against an idle/completed session) and _run_hypothesis_resolution_gate
    (every still-open hypothesis, run automatically before a session concludes) — same
    persistence/approval shape Chain's own execute() closure already establishes (_run_chain), plus
    resolve_hypothesis handling since that's this pass's actual terminal action. A factory (not a
    plain module-level function taking ctx as an argument) because _run_llm_tool_loop always calls
    execute_tool as execute_tool(spec, arguments) — exactly 2 args, no ctx — so ctx (and, for the
    gate's own anti-fabrication check, trace) has to be captured by closure, the same reason Chain's
    own execute() is defined as a nested function rather than a free one.

    trace, when given, enables the anti-fabrication guard on resolve_hypothesis: rejects (returns a
    retryable {"status": "error", ...} instead of persisting) a resolve attempt if nothing in the
    trace so far was a real investigative tool call — see
    _hypothesis_resolved_without_real_investigation's own docstring for what this does and does not
    catch. None (run_hypothesis_verification's own single-hypothesis pass) skips the guard entirely
    — a targeted, operator-triggered investigation of one specific hypothesis has a narrower failure
    mode than the gate's own broader, unattended, multi-hypothesis sweep.

    target_hypothesis_id, when given, is forwarded to _resolve_hypothesis so it matches that exact
    hypothesis by id — see that function's own docstring for why: run_hypothesis_verification's
    single-target pass already knows exactly which hypothesis it's investigating, and needs that
    certainty to correctly RE-resolve one that isn't "unconfirmed" anymore (an operator re-checking
    an already-confirmed/ruled-out hypothesis), which the gate's own fuzzy/unconfirmed-only text
    match can never do. None (the gate's own multi-hypothesis pass) keeps that fuzzy match unchanged.
    """
    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        if spec.name == "record_finding":
            result = await _run_tool_with_retry(ctx, spec, arguments)
            if result.get("status") == "ok" and "recorded" in result:
                conflict_result = await _persist_new_finding(ctx, result["recorded"])
                if conflict_result is not None:
                    return conflict_result
            return result
        if spec.name == "record_hypothesis":
            result = await _run_tool_with_retry(ctx, spec, arguments)
            if result.get("status") == "ok" and "recorded" in result:
                _persist_new_hypothesis(ctx, result["recorded"], "hypothesis_verification")
            return result
        if spec.name == "resolve_hypothesis":
            if trace is not None and _hypothesis_resolved_without_real_investigation(trace):
                return {
                    "status": "error",
                    "error": (
                        "no real investigative tool call has happened yet this pass — resolve_hypothesis "
                        "needs an actual check behind it (confirmed: a real record_finding; ruled_out: a "
                        "real probe that came back negative), not a resolution with nothing backing it."
                    ),
                }
            result = await _run_tool_with_retry(ctx, spec, arguments)
            if result.get("status") == "ok" and "resolved" in result:
                _resolve_hypothesis(ctx, result["resolved"], "hypothesis_verification", target_hypothesis_id=target_hypothesis_id)
            return result
        if not spec.requires_allowed_target:
            return await _run_tool_with_retry(ctx, spec, arguments)
        approved = await _await_exploit_approval(ctx, {"title": "hypothesis verification"})
        if not approved:
            return {"status": "skipped", "reason": "exploit not approved in time"}
        return await _run_tool_with_retry(ctx, spec, arguments)

    return execute


def _hypothesis_pass_wallclock_limit_seconds() -> int:
    # Its own, smaller budget than _PHASE_WALLCLOCK_LIMIT_SECONDS (7200s, sized for a whole
    # Recon/Analyze/Exploit phase) -- a single hypothesis (or even a handful in the end-of-session
    # gate) is a much smaller unit of work. Same order of magnitude/precedent as
    # SUBAGENT_TASK_TIMEOUT_SECONDS (900s default, .env.example).
    return int(os.getenv("HYPOTHESIS_PASS_TIMEOUT_SECONDS", "900"))


async def run_hypothesis_verification(
    session_id: str, raw_text: str = "",
    hypothesis_id: str | None = None, provider_id: str | None = None,
) -> None:
    """Investigates ONE hypothesis against a session that ISN'T currently live — the idle-session
    path for both a fresh operator-submitted hint (main.py's /api/session/{id}/hypotheses route,
    completed-session branch, raw_text from the Hypotheses tab's single free-text box) and an
    "Investigate now" re-check of an already-open hypothesis (the same route, called with
    hypothesis_id instead of fresh text). Mirrors run_focused_exploit's own structure (status/
    timing handling, SessionStopRequested/CancelledError swallowing, since this too is scheduled as
    a bare BackgroundTask with nothing else to catch them) — see that function's own docstring for
    why the live case instead queues an instruction for the running loop (_drain_pending_hypotheses)
    rather than risking two writers on the same session file.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_hypothesis_verification: unknown session %r", session_id)
        return

    if hypothesis_id is not None:
        matching = [h for h in session.get("hypotheses", []) if h.get("id") == hypothesis_id]
        if not matching:
            logger.debug("run_hypothesis_verification: session=%s no hypothesis id=%r", session_id, hypothesis_id)
            return
        hypothesis = matching[0]
    else:
        if not raw_text.strip():
            logger.debug("run_hypothesis_verification: session=%s empty hypothesis text, nothing to do", session_id)
            return
        hypothesis = None  # structured + persisted below, once ctx exists

    resume_status = session["status"]
    session["status"] = "processing"
    session.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    session.pop("finished_at", None)
    save_session(session_id, session)

    ctx = _new_run_context(session, session_id, provider_id)
    if hypothesis is None:
        # Structured (raw operator paste -> clean {text, evidence}) and persisted BEFORE the loop
        # runs, not after -- if the pass never reaches a resolve_hypothesis call (times out,
        # crashes), the operator's own submitted lead must still survive as a real, visible,
        # still-open hypothesis rather than being silently lost.
        structured = await _structure_hypothesis_text(ctx, raw_text)
        _persist_new_hypothesis(ctx, structured, "post_completion", source="user")
        hypothesis = ctx.session["hypotheses"][-1]
    # Lets _record_missing_capability link a missing-capability entry back to this hypothesis, same
    # role current_finding_title plays for a finding's own exploit attempt.
    ctx.current_hypothesis_id = hypothesis["id"]
    logger.debug("run_hypothesis_verification: session=%s target=%s hypothesis id=%s text=%r starting", session_id, session["target"], hypothesis["id"], hypothesis["text"])
    _mark_phase_started(ctx.session, "hypothesis_verification")
    # This phase can legitimately run in several separate passes hours apart (one per
    # operator-submitted hunch) -- _mark_phase_started's setdefault keeps started_at pinned at the
    # FIRST pass, so a naive started_at->finished_at span would count all the idle time between
    # passes as if it were real work (the exact reconciliation bug already fixed once for
    # chain+validate, see run_session's own comment there). Tracking this pass's own real elapsed
    # time and summing it below is what format_accumulated_duration actually renders instead.
    pass_started_at = datetime.now(timezone.utc)

    session_context_token = current_session_id.set(session_id)
    stopped = False
    crashed = False
    try:
        findings_before = len(ctx.session["findings"])
        resolved_at_before = hypothesis.get("resolved_at")
        existing_findings_summary = [
            {"title": f.get("title"), "severity": f.get("severity"), "technology": f.get("technology")}
            for f in ctx.session["findings"]
        ]
        # A re-check of an already-resolved hypothesis (bulk "verify/recheck all", or a future
        # single-item re-check) shows the model its own prior conclusion instead of presenting it as
        # a fresh, never-looked-at lead -- it can then either confirm that conclusion still holds or
        # actually overturn it, rather than blindly repeating whatever reasoning produced it before.
        prior_resolution = (
            f" (previously resolved {hypothesis['status']}: {hypothesis['resolution_note']})"
            if hypothesis.get("status") != "unconfirmed" and hypothesis.get("resolution_note") else ""
        )
        task = (
            f"Hypothesis to investigate{prior_resolution}:\n"
            f"- {hypothesis['text']}" + (f" (evidence so far: {hypothesis['evidence']})" if hypothesis.get("evidence") else "") + "\n\n"
            f"Existing findings from this scan (don't duplicate one of these):\n{json.dumps(existing_findings_summary)}"
        )
        task += _custom_instructions_task_addendum(ctx.session)
        task += _goal_task_addendum(ctx.session)
        task += _program_url_task_addendum(ctx.session)
        task += _scope_rules_task_addendum(ctx.session)

        await _run_llm_tool_loop(
            ctx, HYPOTHESIS_VERIFICATION_PROMPT, task, _hypothesis_verification_tool_specs(), "hypothesis_verification",
            execute_tool=_make_hypothesis_verification_executor(ctx, target_hypothesis_id=hypothesis["id"]), expect_json_final=False,
            wallclock_limit_seconds=_hypothesis_pass_wallclock_limit_seconds(),
        )

        if len(ctx.session["findings"]) > findings_before:
            ctx.session["findings"] = await _run_validate(ctx)
            ctx.session["findings"] = _normalize_findings(ctx.session["findings"])

        # resolve_hypothesis only ever moves a hypothesis to "confirmed"/"ruled_out"
        # (agent/tools/__init__.py's _VALID_HYPOTHESIS_STATUSES) -- it can never set status back to
        # "unconfirmed", so resolution_note is otherwise always None here. A pass that genuinely
        # investigated (real tool calls happened) but never reached a firm verdict -- inconclusive
        # evidence, the anti-fabrication guard correctly withholding a call, or the wallclock limit
        # cutting the loop short -- used to leave the card showing nothing but the bare "Unconfirmed"
        # badge, with no way for the operator to tell "actually looked at, still unclear" apart from
        # "never looked at yet". Same honest "we don't know yet" treatment _run_reverify's own
        # inconclusive branch already gives an unresolved carried-over finding.
        if hypothesis.get("status") == "unconfirmed" and hypothesis.get("resolved_at") == resolved_at_before:
            hypothesis["resolution_note"] = (
                "Investigated this pass but reached no firm verdict — insufficient evidence to "
                "confirm or rule out. Still open for a future re-check."
            )
    except (SessionStopRequested, asyncio.CancelledError) as exc:
        # Same reasoning as run_focused_exploit: a bare BackgroundTask, nothing else to catch this.
        stopped = True
        logger.debug("run_hypothesis_verification: session=%s hypothesis id=%s stopped (%s)", session_id, hypothesis["id"], type(exc).__name__)
    except Exception as exc:
        # Same reasoning/fix as run_focused_exploit's own except Exception -- an LLM
        # fallback-chain exhaustion (or any other real failure) used to fall straight through to
        # the finally block's "else" branch below, silently reporting completed/resume_status
        # with zero trace of the failure.
        crashed = True
        logger.debug("run_hypothesis_verification: session=%s hypothesis id=%s failed", session_id, hypothesis["id"], exc_info=True)
        _append_log(ctx, phase="hypothesis_verification", thought=None, command=None, status="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        ctx.current_hypothesis_id = None
        # This idle pass has now actually investigated the hypothesis, so drop the "Queued" button
        # state (main.py's submit_hypothesis set it) — if the pass resolved it the card's button is
        # gone anyway, and if it's still unconfirmed the operator can prioritize it again.
        hypothesis.pop("priority_requested", None)
        get_stop_event(session_id).clear()
        _clear_exhausted_chain_steps(session_id)
        await _close_browser_session_safely(session_id)
        # Real time genuinely spent this pass, regardless of how it ended -- an interrupted pass
        # still burned real wall-clock time actually investigating, same "count it" logic every
        # other _run_tool_with_retry call's duration tracking already applies.
        pass_elapsed_seconds = (datetime.now(timezone.utc) - pass_started_at).total_seconds()
        hv_timing = session.setdefault("phase_timings", {}).setdefault("hypothesis_verification", {})
        hv_timing["accumulated_seconds"] = hv_timing.get("accumulated_seconds", 0) + pass_elapsed_seconds
        if stopped:
            session["status"] = "interrupted"
            session["resumable_from"] = compute_resume_entry_point(session)
            session.pop("last_focused_pass_ok", None)
        elif crashed:
            session["status"] = "failed"
            session["resumable_from"] = compute_resume_entry_point(session)
            session.pop("last_focused_pass_ok", None)
        else:
            session["status"] = resume_status if resume_status in ("completed", "failed", "interrupted") else "completed"
            if session["status"] == "completed":
                session["finished_at"] = datetime.now(timezone.utc).isoformat()
                _mark_phase_finished(session, "hypothesis_verification")
                session.pop("last_focused_pass_ok", None)
            else:
                # See run_focused_exploit's own comment on this same marker -- this pass itself
                # ran fine, only the session's pre-existing terminal status (failed/interrupted)
                # was preserved, so the "Scan failed" banner should read as a preserved state, not
                # a fresh crash from this pass.
                session["last_focused_pass_ok"] = True
        save_session(session_id, session)
        logger.debug(
            "run_hypothesis_verification: session=%s hypothesis id=%s ended status=%s",
            session_id, hypothesis["id"], session["status"],
        )
        current_session_id.reset(session_context_token)


async def run_recon_note_investigation(session_id: str, raw_text: str, provider_id: str | None = None) -> None:
    """The Recon tab's "Add and investigate now" button (main.py's /api/session/{id}/recon/add
    route, idle branch) — classifies the operator's submission (_classify_and_record_recon_item,
    the exact same classifier the live drain path uses) then immediately hands the freshly
    persisted hypothesis to run_hypothesis_verification's own full, already-built investigation
    pipeline (recon+scan+exploit tool access, per-call scope/allowlist enforcement, all of it
    already there — see _hypothesis_verification_tool_specs) rather than writing a second one. This
    is what makes "even after the scan is done" work with almost no new logic of its own.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_recon_note_investigation: unknown session %r", session_id)
        return
    if not raw_text.strip():
        logger.debug("run_recon_note_investigation: session=%s empty submission, nothing to do", session_id)
        return

    session_context_token = current_session_id.set(session_id)
    try:
        ctx = _new_run_context(session, session_id, provider_id)
        recorded = await _classify_and_record_recon_item(ctx, raw_text, "operator_recon_note")
        if recorded is None:
            logger.debug("run_recon_note_investigation: session=%s classification produced nothing usable", session_id)
            return
        logger.debug("run_recon_note_investigation: session=%s recorded hypothesis id=%s, handing off to run_hypothesis_verification", session_id, recorded["id"])
    finally:
        current_session_id.reset(session_context_token)

    await run_hypothesis_verification(session_id, hypothesis_id=recorded["id"], provider_id=provider_id)


async def run_all_hypotheses_verification(session_id: str, provider_id: str | None = None) -> None:
    """The Hypotheses tab's "Verify/recheck all" button — every hypothesis currently on the
    session, first to last, not just the still-"unconfirmed" ones (an operator explicitly asking to
    recheck everything wants a real second look at an already-confirmed/ruled-out one too, not just
    the leftovers _run_hypothesis_resolution_gate never got through). Reuses
    run_hypothesis_verification unchanged, once per hypothesis, sequentially — not one shared
    multi-hypothesis pass like the gate, so each hypothesis gets its own full investigation instead
    of competing for the same trace/tool-call budget, and a real, confirmed root cause is never
    misattributed to the wrong one the way the gate's own pass-wide anti-fabrication check can be
    (see _hypothesis_resolved_without_real_investigation's docstring).

    Real, confirmed incident this exists for: a session whose "Hypotheses to check" field had a
    whole bug-bounty policy document pasted into it (19 pre_scan hypotheses that were never actual
    security claims) hit the gate's anti-fabrication guard on every single one, twice, then gave up
    — left all 19 permanently "Unconfirmed" with no way to close them except the single-item
    "Investigate now" button, one click and one full LLM pass at a time. This is that same
    single-item mechanism, just looped, so clearing (or genuinely rechecking) a whole batch doesn't
    require an operator to sit and click through every entry by hand.

    A snapshot of ids taken up front, not a live re-read of session["hypotheses"] each iteration —
    the loop must cover exactly what was open when the operator clicked the button, not accidentally
    pick up a hypothesis record_hypothesis itself adds mid-run (that one gets its own turn the NEXT
    time this button is used). Stops early if the operator hits Stop mid-pass (checked once per
    hypothesis, between items — run_hypothesis_verification's own per-item try/except already
    handles a stop mid-investigation) rather than plowing through the rest of the list regardless.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_all_hypotheses_verification: unknown session %r", session_id)
        return
    hypothesis_ids = [h["id"] for h in session.get("hypotheses", [])]
    if not hypothesis_ids:
        logger.debug("run_all_hypotheses_verification: session=%s no hypotheses to verify", session_id)
        return

    # Real, confirmed incident this fixes: this wrapper's OWN log lines (the two below, "queued"
    # and "finished") landed only in the GLOBAL debug.log, never this session's own project-folder
    # one -- current_session_id is only ever set INSIDE each looped run_hypothesis_verification
    # call (and reset again in ITS OWN finally before this loop's next line runs), so at the exact
    # moments this wrapper logs its own bookkeeping (before the loop starts, after it ends) the
    # ContextVar is back to unset. Every other top-level entry point (run_session,
    # run_focused_exploit, run_hypothesis_verification itself) sets this around its own whole body
    # for exactly this reason; this wrapper never did.
    session_context_token = current_session_id.set(session_id)
    try:
        logger.debug("core: session=%s verify-all hypotheses: %d hypothesis(es) queued", session_id, len(hypothesis_ids))
        checked = 0
        for hypothesis_id in hypothesis_ids:
            await run_hypothesis_verification(session_id, hypothesis_id=hypothesis_id, provider_id=provider_id)
            checked += 1
            current = load_session(session_id)
            if current is not None and current.get("status") == "interrupted":
                logger.debug("core: session=%s verify-all hypotheses: stopped by operator after %d/%d", session_id, checked, len(hypothesis_ids))
                return
        logger.debug("core: session=%s verify-all hypotheses: finished, %d/%d checked", session_id, checked, len(hypothesis_ids))
    finally:
        current_session_id.reset(session_context_token)


async def run_all_findings_verification(session_id: str, provider_id: str | None = None) -> None:
    """The Findings tab's "Verify/recheck all" button — every finding currently on the session,
    first to last, mirroring run_all_hypotheses_verification's own shape but built on Deep dive's
    existing per-finding mechanism (run_focused_exploit) instead: unlike hypotheses, a finding's
    verification isn't gated by its current state at all (run_focused_exploit already re-attempts
    exploitation/verification against ANY finding regardless of its current verification/exploited
    value), so no matching companion fix to run_focused_exploit itself was needed here.

    A snapshot of titles taken up front, same reasoning as run_all_hypotheses_verification's own id
    snapshot -- a deep dive can legitimately rename/merge a finding via _run_validate's own dedup
    pass, so a later title in this snapshot may no longer resolve to anything by the time its turn
    comes; run_focused_exploit already treats that as a silent, logged no-op rather than an error,
    same tolerance this loop inherits unchanged.
    """
    session = load_session(session_id)
    if session is None:
        logger.debug("run_all_findings_verification: unknown session %r", session_id)
        return
    finding_titles = [f["title"] for f in session.get("findings", [])]
    if not finding_titles:
        logger.debug("run_all_findings_verification: session=%s no findings to verify", session_id)
        return

    # Same fix, same reasoning as run_all_hypotheses_verification's own current_session_id.set --
    # confirmed live (Safety-Bug-Bounty-rescan-usr_e6c98c): this wrapper's own "queued"/"finished"
    # lines were only ever in the global debug.log, never the session's own one.
    session_context_token = current_session_id.set(session_id)
    try:
        logger.debug("core: session=%s verify-all findings: %d finding(s) queued", session_id, len(finding_titles))
        checked = 0
        any_changed = False
        for finding_title in finding_titles:
            # rerun_chain=False -- see run_focused_exploit's own docstring: Chain runs once, here,
            # over the WHOLE batch's combined evidence once the loop finishes, not once per finding.
            changed = await run_focused_exploit(session_id, finding_title, provider_id=provider_id, rerun_chain=False)
            any_changed = any_changed or changed
            checked += 1
            current = load_session(session_id)
            if current is not None and current.get("status") == "interrupted":
                logger.debug("core: session=%s verify-all findings: stopped by operator after %d/%d", session_id, checked, len(finding_titles))
                return
        logger.debug("core: session=%s verify-all findings: finished, %d/%d checked, any_changed=%s", session_id, checked, len(finding_titles), any_changed)
        if any_changed:
            await _run_post_verify_all_chain_pass(session_id, provider_id)
    finally:
        current_session_id.reset(session_context_token)


async def _run_post_verify_all_chain_pass(session_id: str, provider_id: str | None) -> None:
    """run_all_findings_verification's own single, end-of-batch Chain pass -- real, confirmed
    incident this fixes (a real "Verify/recheck all" workflow): reconfirming every
    finding one at a time never gave Chain a single fresh look at the combined result, so an
    operator who ran this saw every finding individually re-verified and nothing more, even when
    two or more of them together now had exactly the kind of escalation Chain exists to find. Mirrors
    run_focused_exploit's own session-reopen/close bookkeeping (see that function), scoped to just
    this one extra Chain+Validate pass rather than a full finding re-attempt.
    """
    session = load_session(session_id)
    if session is None:
        return
    resume_status = session["status"]
    session["status"] = "processing"
    session.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    session.pop("finished_at", None)
    save_session(session_id, session)
    logger.debug("core: session=%s verify-all findings: running end-of-batch chain pass", session_id)

    ctx = _new_run_context(session, session_id, provider_id)
    stopped = False
    crashed = False
    try:
        ctx.session["findings"] = await _run_chain(ctx)
        ctx.session["findings"] = await _run_validate(ctx)
        ctx.session["findings"] = _normalize_findings(ctx.session["findings"])
    except (SessionStopRequested, asyncio.CancelledError) as exc:
        stopped = True
        logger.debug("core: session=%s verify-all findings: end-of-batch chain pass stopped (%s)", session_id, type(exc).__name__)
    except Exception as exc:
        # Same reasoning/fix as run_focused_exploit's own except Exception -- an LLM
        # fallback-chain exhaustion (or any other real failure) used to fall straight through to
        # the "else" branch below, silently reporting completed/resume_status with zero trace of
        # the failure.
        crashed = True
        logger.debug("core: session=%s verify-all findings: end-of-batch chain pass failed", session_id, exc_info=True)
        _append_log(ctx, phase="exploit", thought=None, command=None, status="failed", error=f"{type(exc).__name__}: {exc}")
    finally:
        get_stop_event(session_id).clear()
        _clear_exhausted_chain_steps(session_id)
        if stopped:
            ctx.session["status"] = "interrupted"
            ctx.session["resumable_from"] = compute_resume_entry_point(ctx.session)
            ctx.session.pop("last_focused_pass_ok", None)
        elif crashed:
            ctx.session["status"] = "failed"
            ctx.session["resumable_from"] = compute_resume_entry_point(ctx.session)
            ctx.session.pop("last_focused_pass_ok", None)
        else:
            ctx.session["status"] = resume_status if resume_status in ("completed", "failed", "interrupted") else "completed"
            if ctx.session["status"] == "completed":
                ctx.session["finished_at"] = datetime.now(timezone.utc).isoformat()
                _mark_phase_finished(ctx.session, "exploit")
                ctx.session.pop("last_focused_pass_ok", None)
            else:
                # See run_focused_exploit's own comment on this same marker -- this pass itself
                # ran fine, only the session's pre-existing terminal status (failed/interrupted)
                # was preserved, so the "Scan failed" banner should read as a preserved state, not
                # a fresh crash from this pass.
                ctx.session["last_focused_pass_ok"] = True
        save_session(session_id, ctx.session)
        logger.debug("core: session=%s verify-all findings: end-of-batch chain pass ended status=%s", session_id, ctx.session["status"])


_CHAIN_MAX_HOPS = int(os.getenv("CHAIN_MAX_HOPS", "3"))


def _finding_needs_escalation(finding: dict) -> bool:
    """True for a finding that -- on its own -- is exactly the "real, but no demonstrated impact"
    case a bug-bounty triager rejects: Low/Medium severity (including no severity recorded at all),
    or explicitly non_qualifying/unclear. Chain uses this both to tell the model which findings are
    worth its effort (CHAIN_PROMPT's own needs_escalation material below) and to decide, after a
    confirmed chain, whether the finding it just produced still needs another hop or has already
    reached something that stands on its own.

    False whenever false_positive_reason is already set -- that means this exact finding has already
    been proven NOT a real lead (Analyze's own auto-CVE-record due-diligence for an out-of-range
    version, or Exploit's skipped_ruled_out path), so there is nothing left to escalate. Real,
    confirmed incident this fixes: those auto-recorded CVE findings never get qualifies_for_bounty
    set and are often Medium severity, so without this guard they kept qualifying as
    needs_escalation=true and CHAIN_PROMPT tells the model to "spend your effort on these FIRST" --
    burning a real LLM+tool-call pass re-litigating something already marked "not a live lead".
    """
    if finding.get("false_positive_reason"):
        return False
    if finding.get("severity") in ("Low", "Medium", None):
        return True
    return finding.get("qualifies_for_bounty") in ("non_qualifying", "unclear")


async def _run_chain(ctx: RunContext) -> list[dict]:
    """Final pass across every finding, recon fact, and hypothesis this session recorded, looking
    for a real way to escalate what's already here — either a chain connecting two or more findings
    (a secret/credential one finding leaked unlocking an endpoint another finding named), or a
    single finding escalated against recon facts/hypotheses that never became findings of their own
    (a confirmed technology+version worth a fresh cve_lookup). Both are structurally impossible
    during Exploit itself, since _run_exploit_for_finding hands the model only ONE finding at a time
    (see that function's task construction) with no visibility into anything else recorded this
    session. Same anti-fabrication discipline as the CVE-existence rule added to EXPLOIT_PROMPT
    earlier: a claimed chain must quote real evidence and be proven by an actual tool call, never
    accepted as narrated plausibility alone — enforced deterministically in record_chain_result,
    not just requested in the prompt.

    Runs up to _CHAIN_MAX_HOPS passes in a row, not just one: the whole point of chaining is turning
    a finding that won't get paid alone (a WAF bypass, a CORS reflection, an info-disclosure — see
    _finding_needs_escalation) into something with real, demonstrable impact, and that often takes
    more than one hop (bypass -> hidden endpoint -> weak auth -> admin access). Each hop re-reads
    ctx.session["findings"] fresh, so a finding a hop just created is automatically part of the next
    hop's own material -- no extra wiring needed. Stops the moment a pass finds nothing, creates
    nothing new, or the newest finding it created no longer needs_escalation -- never forces a hop
    that has nothing real left to build on.
    """
    _mark_phase_started(ctx.session, "chain")
    if not ctx.session["findings"]:
        _mark_phase_finished(ctx.session, "chain")
        return ctx.session["findings"]  # nothing to escalate at all

    for hop in range(_CHAIN_MAX_HOPS):
        findings_before = len(ctx.session["findings"])
        chain_result = await _run_chain_pass(ctx, hop_index=hop)
        if chain_result is None or chain_result.get("action") != "chain_confirmed":
            break
        newly_created = ctx.session["findings"][findings_before:]
        if not newly_created or not any(_finding_needs_escalation(f) for f in newly_created):
            break  # nothing new, or already reached something that stands on its own

    _mark_phase_finished(ctx.session, "chain")
    return ctx.session["findings"]


async def _run_chain_pass(ctx: RunContext, hop_index: int) -> dict | None:
    """One real Chain pass — see _run_chain's own docstring for why it can run several times in a
    row. hop_index is 0 for the first pass; a later hop tells the model (via the task text below)
    which finding the PRIOR hop this same call just produced, so it can push specifically on that
    one instead of re-discovering the same connection.
    """
    findings = ctx.session["findings"]
    # Real, confirmed incident this widening fixes: a session with exactly one Low finding (an
    # info-disclosure on scim.openai.com) never got a Chain pass at all under the old `<= 1` bail-
    # out, even though a single finding can still genuinely escalate against recon facts (a
    # confirmed technology+version worth a fresh cve_lookup/exploit_db_lookup) or hypotheses
    # (including ruled_out ones — still real, previously-checked facts) that were never findings of
    # their own. Chain now always runs whenever there is at least one finding; the prompt itself
    # (CHAIN_PROMPT) covers both the classic finding-to-finding case and this single-finding case.
    recon_result = ctx.session.get("recon_result", {})
    recon_technologies = recon_result.get("technologies", {})
    recon_cves = recon_result.get("cves", [])
    recon_material = {
        "technologies": recon_technologies,
        # Structured version/certainty/source per technology (agent/tools/js_fingerprint.py +
        # WhatWeb, merged by _merge_technology_details) -- included explicitly, not just buried
        # inside a "technologies" token's own brackets, so an escalation pass actually sees exact
        # confirmed versions/confidence instead of having to re-parse them out of raw tokens.
        "technology_details": recon_result.get("technology_details", {}),
        "cves": recon_cves,
        "targets": [t.get("host") for t in recon_result.get("targets", []) if t.get("host")],
    }
    # ALL statuses, not just unconfirmed -- a ruled_out hypothesis is still a real, previously-
    # checked fact (only its own truth value was settled, not its relevance to a chain), and a
    # confirmed one may itself be the other half of a chain that was never recorded as its own
    # finding.
    hypotheses_material = [
        {"id": h.get("id"), "text": h.get("text"), "evidence": h.get("evidence"), "status": h.get("status")}
        for h in ctx.session.get("hypotheses", [])
    ]
    # Only OPEN ("unconfirmed") hypotheses need reconciliation later -- confirmed/ruled_out ones are
    # already-settled facts by the time Chain runs (CHAIN_PROMPT's own docstring on this), so citing
    # one of those is citing something already independently checked, nothing to revisit.
    open_hypotheses_by_id = {h.get("id"): h for h in ctx.session.get("hypotheses", []) if h.get("status") == "unconfirmed" and h.get("id")}

    async def execute(spec: ToolSpec, arguments: dict) -> dict:
        if spec.name == "record_finding":
            result = await _run_tool_with_retry(ctx, spec, arguments)
            if result.get("status") == "ok" and "recorded" in result:
                conflict_result = await _persist_new_finding(ctx, result["recorded"])
                if conflict_result is not None:
                    logger.debug("core: session=%s chain: rejected record_finding, cors_check conflict for %r", ctx.session_id, result["recorded"].get("title"))
                    return conflict_result
                # CHAIN_PROMPT requires the model to quote an open hypothesis's own raw evidence
                # field verbatim (never just its text/title) whenever a chain leans on one -- reused
                # here as a real, deterministic signal: any open hypothesis whose evidence text
                # actually appears in this new finding's own evidence_ref/description is genuinely
                # the hypothesis this finding was built on, not a guess. Recorded so _resolve_
                # hypothesis can flag this finding if that same hypothesis later gets ruled out --
                # real gap this closes: a chain built on a still-open hypothesis had no way for a
                # LATER pass (the hypothesis-gate, which runs right after Chain) disproving that same
                # hypothesis to ever flow back to the finding chain built on top of it; the finding
                # shipped as an ordinary "confirmed" record with no trace its premise had collapsed.
                haystack = f"{result['recorded'].get('evidence_ref', '')} {result['recorded'].get('description', '')}"
                cited_ids = [
                    hid for hid, h in open_hypotheses_by_id.items()
                    if h.get("evidence") and len(h["evidence"]) > 15 and h["evidence"] in haystack
                ]
                if cited_ids:
                    result["recorded"]["based_on_hypothesis_ids"] = cited_ids
                # Same transient freshness marker _apply_chain_reverifications sets on an EXISTING
                # finding it just reverified — a finding created fresh right here, in this same
                # Chain pass, is by definition at least as fresh (it didn't exist before this
                # moment). Real, confirmed incident this closes: Chain built a genuinely proven
                # attack chain (a reflected XSS -> cookie read -> OOB-confirmed exfiltration, 3
                # clean iterations) and recorded it via this exact path — Validate, running
                # immediately after, kept an older and strictly weaker duplicate instead, because
                # only reverified_findings' pre-existing-title path ever set this marker, never a
                # finding record_finding created mid-pass. Without it, Validate's dedup summary
                # (_run_validate below) has no way to know this one is the newest evidence in the
                # room, same gap _apply_chain_reverifications' own docstring already documents for
                # the sibling case.
                result["recorded"]["_reverified_this_pass"] = True
                logger.debug("core: session=%s chain: recorded new chained finding title=%r", ctx.session_id, result["recorded"].get("title"))
            return result
        if spec.name == "update_plan":
            result = await _run_tool_with_retry(ctx, spec, arguments)
            if result.get("status") == "ok" and "recorded" in result:
                _apply_updated_plan(ctx, result["recorded"], "exploit")
            return result
        if not spec.requires_allowed_target:
            return await _run_tool_with_retry(ctx, spec, arguments)
        # Same allowlist/approval gate every exploit tool call goes through — approval is
        # per-session (see _await_exploit_approval), so a scan that already approved exploitation
        # during Exploit itself doesn't ask again here.
        approved = await _await_exploit_approval(ctx, {"title": "chaining pass"})
        if not approved:
            return {"status": "skipped", "reason": "exploit not approved in time"}
        return await _run_tool_with_retry(ctx, spec, arguments)

    # Full evidence, not _run_validate's slim dedup summary below — a chain claim has to quote
    # real evidence_ref/evidence values, so the model needs them in context to quote from at all.
    # needs_escalation (see _finding_needs_escalation) is the signal CHAIN_PROMPT uses to prioritize
    # "real but won't get paid alone" findings over ones that already stand on their own.
    summaries = [
        {
            "title": f.get("title"),
            "severity": f.get("severity"),
            "technology": f.get("technology"),
            "evidence_ref": f.get("evidence_ref"),
            "evidence": f.get("evidence"),
            "exploited": f.get("exploited"),
            "needs_escalation": _finding_needs_escalation(f),
        }
        for f in findings
    ]
    task = f"Findings from this completed scan:\n{json.dumps(summaries)}"
    if recon_material["technologies"] or recon_material["cves"] or recon_material["targets"]:
        task += f"\n\nRecon facts from this same scan (never findings of their own, but real, confirmed material to escalate a finding with):\n{json.dumps(recon_material)}"
    if hypotheses_material:
        task += f"\n\nHypotheses from this same scan, every status including ruled_out (a ruled-out one is still a real, previously-checked fact):\n{json.dumps(hypotheses_material)}"
    if hop_index > 0:
        prior_finding = findings[-1] if findings else None
        prior_title = prior_finding.get("title") if prior_finding else None
        task += (
            f"\n\nThis is an additional escalation pass (hop {hop_index + 1}) right after an earlier "
            f"pass in this same session confirmed a chain that produced the finding {prior_title!r} "
            "above — it still needs_escalation itself. Don't just re-report the connection that "
            "already proved it; look specifically at whether THAT finding is itself the missing "
            "piece for something further. If nothing real supports another hop, say so honestly in "
            "no_chain_found rather than stretching for one."
        )
    task += _plan_task_addendum(ctx.session, "exploit")
    subagent_tools, subagent_addendum = _subagent_delegation_extras(ctx.session)
    task += subagent_addendum

    # Explicit tool list, not get_tools_by_category("post_exploit") — record_chain_result is
    # registered under that unused category specifically so no other phase's toolset assembly
    # picks it up (same reasoning as record_reverification_result), so it has to be added here by
    # name instead.
    tool_specs = list(get_tools_by_category("exploit"))
    record_finding_spec = get_tool("record_finding")
    if record_finding_spec is not None:
        tool_specs.append(record_finding_spec)
    record_chain_result_spec = get_tool("record_chain_result")
    if record_chain_result_spec is not None:
        tool_specs.append(record_chain_result_spec)
    tool_specs += subagent_tools + _toolkit_tool_extras()
    update_plan_spec = get_tool("update_plan")
    if update_plan_spec is not None:
        tool_specs.append(update_plan_spec)

    ctx.current_finding_title = "chaining pass"
    try:
        chain_result, _trace = await _run_llm_tool_loop(
            ctx, CHAIN_PROMPT, task, tool_specs, "chain", execute_tool=execute, terminal_tool="record_chain_result",
            plan_phase="exploit",  # chain shares "exploit"'s own plan phase, see _plan_task_addendum's call above
        )
    finally:
        ctx.current_finding_title = None
    _apply_chain_reverifications(ctx, chain_result)
    _persist_chain_attempt(ctx, chain_result, {
        "findings": len(findings),
        "recon_technologies": len(recon_material["technologies"]),
        "hypotheses": len(hypotheses_material),
    }, hop_index=hop_index)
    return chain_result


def _persist_chain_attempt(ctx: RunContext, chain_result: dict | None, material_counts: dict, hop_index: int = 0) -> None:
    """Appends one record to session["chain_attempts"] for every real Chain pass, "no_chain_found"
    included — without this, an operator has no way to tell "Chain ran and genuinely found nothing"
    apart from "Chain never ran at all" (both look identical: no new finding appeared). Surfaced on
    the session page's own Chain tab. Real trace given below is what backs the claim
    (evidence_quotes/tool_call_proof/impact_scenario), never re-derived or paraphrased here.
    hop_index is 0-based (see _run_chain) -- stored 1-based ("hop": 1, 2, ...) so the Chain tab can
    show "hop 2 of this pass" without off-by-one arithmetic in the template.
    """
    if not chain_result:
        return
    attempt = {
        "ran_at": datetime.now(timezone.utc).isoformat(),
        "hop": hop_index + 1,
        "outcome": chain_result.get("action", "no_chain_found"),
        "finding_titles": chain_result.get("finding_titles") or [],
        "reasoning": chain_result.get("reasoning") or "",
        "evidence_quotes": chain_result.get("evidence_quotes") or [],
        "tool_call_proof": chain_result.get("tool_call_proof"),
        "impact_scenario": chain_result.get("impact_scenario"),
        "reverified_finding_titles": [
            entry.get("title") for entry in (chain_result.get("reverified_findings") or []) if isinstance(entry, dict) and entry.get("title")
        ],
        "material_considered": material_counts,
    }
    ctx.session.setdefault("chain_attempts", []).append(attempt)
    save_session(ctx.session_id, ctx.session)
    logger.debug("core: session=%s chain: attempt recorded hop=%d outcome=%s material=%s", ctx.session_id, attempt["hop"], attempt["outcome"], material_counts)


def _apply_chain_reverifications(ctx: RunContext, chain_result: dict | None) -> None:
    """record_chain_result's optional reverified_findings field is the write-back path for a real
    gap: the chain phase routinely re-tests an EXISTING finding's own vulnerability while looking
    for chains (it has every finding's evidence_ref in context, and the same tools Exploit already
    used) — real incident this fixes: an XSS finding's exploit-phase pass had (correctly) flagged
    itself as exploited=false with an advisory_note saying "no real Dalfox call backed this claim —
    re-run it to confirm", and this same chain pass then genuinely DID re-run Dalfox and got a fresh
    verified_dom_execution result — but that confirmation had no path back to the finding's own
    record, so the final report kept telling the operator to do something already done, minutes
    earlier, in the same session. Titles are matched exactly (the model already has to quote them
    verbatim for chain_confirmed's own finding_titles field, same discipline); an entry naming a
    title that doesn't match any real finding is silently skipped rather than erroring the whole
    chain result, since a title typo here shouldn't cost the whole phase's real conclusion.
    """
    if not chain_result or not isinstance(chain_result.get("reverified_findings"), list):
        return
    # setdefault, not a plain dict comprehension: new findings are always appended (never inserted
    # earlier), so on a title collision this keeps the FIRST (pre-existing) finding under that title
    # instead of a finding this very pass's own record_finding call just created under the same
    # title moments later — a real, confirmed incident: a plain comprehension let the freshly
    # created finding silently absorb reverification data meant for the older one, leaving the
    # actual reverified finding's evidence stale while a brand-new, unrelated record got the update.
    findings_by_title: dict[str | None, dict] = {}
    for f in ctx.session["findings"]:
        findings_by_title.setdefault(f.get("title"), f)
    changed = False
    for entry in chain_result["reverified_findings"]:
        if not isinstance(entry, dict):
            continue
        finding = findings_by_title.get(entry.get("title"))
        evidence_ref = entry.get("evidence_ref")
        if finding is None or not evidence_ref:
            continue
        finding["evidence_ref"] = evidence_ref
        if isinstance(entry.get("exploited"), bool):
            finding["exploited"] = entry["exploited"]
            finding["exploit_outcome"] = "exploit_attempted"
        if entry.get("note"):
            finding["advisory_note"] = entry["note"]
        # Transient marker, never part of the finding schema _FINDING_DEFAULTS promises — read by
        # _run_validate's own summary (right below) and stripped again before that phase returns.
        # Real incident this exists for: Validate's dedup pass runs IMMEDIATELY after chain and only
        # ever sees a slim title/severity/verification/technology/found_at/description_preview
        # summary (never evidence_ref/advisory_note), so it had no way to know one duplicate
        # candidate had JUST been reverified with fresher, more complete evidence than the other —
        # confirmed live: a finding this function had just reverified (fresh evidence covering BOTH
        # an HTTP and an HTTPS check) got deduped away by Validate moments later in favor of a newer,
        # narrower-evidenced finding chain's own record_finding call had created, with nobody the
        # wiser. This marker is Validate's only way to see "this one was just re-confirmed."
        finding["_reverified_this_pass"] = True
        changed = True
        logger.debug("core: session=%s chain: reverified existing finding title=%r", ctx.session_id, finding.get("title"))
    if changed:
        save_session(ctx.session_id, ctx.session)


def _clear_reverified_markers(findings: list[dict]) -> None:
    """Strips _apply_chain_reverifications's transient "_reverified_this_pass" marker (never part
    of the finding schema _FINDING_DEFAULTS promises, only meant to inform THIS validate pass's own
    dedup choice) before returning — every _run_validate return path goes through this, not just
    the success path, so the marker never survives into session.json regardless of how validate
    concluded."""
    for finding in findings:
        finding.pop("_reverified_this_pass", None)


async def _run_validate(ctx: RunContext) -> list[dict]:
    _mark_phase_started(ctx.session, "validate")
    findings = ctx.session["findings"]
    logger.debug("core: session=%s starting validate phase (%d findings)", ctx.session_id, len(findings))
    if len(findings) <= 1:
        _clear_reverified_markers(findings)
        _mark_phase_finished(ctx.session, "validate")
        return findings  # nothing to deduplicate

    # A slim, index-keyed summary, not the full finding objects — VALIDATE_PROMPT's contract only
    # asks for which indices to keep, so the model never has to echo back (and risk truncating or
    # silently rewriting) bulky fields like reproduction_steps/evidence_ref. Real incident this
    # replaced: sending the full findings list as one uncapped json.dumps(findings) message was the
    # one place in this whole codebase not capped the way every tool result already is
    # (_TOOL_RESULT_CHAR_LIMIT) — a large enough findings list made this the heaviest single
    # request of a run, and a slow/unresponsive provider timed out on exactly this call.
    #
    # reverified_this_pass surfaces _apply_chain_reverifications's own marker — real incident this
    # fixes: this summary used to carry NO evidence-freshness signal at all, so when chain's own
    # reverified_findings had JUST refreshed a finding's evidence moments earlier, this dedup pass
    # (running immediately after chain) had no way to know that and could — and did, live — drop
    # the freshly-reverified finding in favor of an older/less-evidenced duplicate, silently
    # discarding the fresher evidence along with the finding it belonged to.
    #
    # false_positive_reason/qualifies_for_bounty are the same class of blind spot, just for a
    # DIFFERENT freshness signal: without them, two near-duplicate summaries (one already proven not
    # a real lead -- Analyze's own out-of-range auto-CVE record, or Exploit's skipped_ruled_out --
    # the other still a live, unproven lead) look identical to this pass, so it has no way to prefer
    # keeping the live one over the already-disproven duplicate. Same root cause the needs_escalation
    # fix in _finding_needs_escalation closes for Chain's own prioritization, just reachable through
    # Validate's separate dedup pass instead.
    summaries = [
        {
            "index": i,
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "verification": finding.get("verification"),
            "technology": finding.get("technology"),
            "found_at": finding.get("found_at"),
            "description_preview": (finding.get("description") or "")[:300],
            "reverified_this_pass": bool(finding.get("_reverified_this_pass")),
            "already_proven_not_a_real_lead": bool(finding.get("false_positive_reason")),
            "qualifies_for_bounty": finding.get("qualifies_for_bounty"),
        }
        for i, finding in enumerate(findings)
    ]
    task = f"Findings:\n{json.dumps(summaries)}"
    messages = [
        {"role": "system", "content": VALIDATE_PROMPT},
        {"role": "user", "content": task},
    ]
    response = await _llm_complete(ctx, messages, None)
    parsed = _parse_json_response(response.content)
    if parsed is None:
        parsed = await _repair_json_reply(ctx, messages, response.content)
    _append_log(
        ctx, "validate", response.content, None,
        "success" if parsed is not None else "error",
        None if parsed is not None else "could not parse a final JSON response from the model",
    )
    if parsed is None or not isinstance(parsed.get("keep"), list):
        logger.debug("core: session=%s validate phase produced no parseable result, keeping pre-dedup findings", ctx.session_id)
        _clear_reverified_markers(findings)
        _mark_phase_finished(ctx.session, "validate")
        return findings
    # Real finding objects, looked up by the index the model chose to keep — never anything the
    # model itself echoed back, so full fidelity (every field, including ones never shown above) is
    # guaranteed regardless of what the model actually did with its answer.
    keep_indices = sorted({i for i in parsed["keep"] if isinstance(i, int) and 0 <= i < len(findings)})
    if not keep_indices:
        logger.debug("core: session=%s validate phase kept zero valid indices, keeping pre-dedup findings", ctx.session_id)
        _clear_reverified_markers(findings)
        _mark_phase_finished(ctx.session, "validate")
        return findings
    kept = [findings[i] for i in keep_indices]
    _clear_reverified_markers(kept)
    _mark_phase_finished(ctx.session, "validate")
    return kept


async def _run_hypothesis_resolution_gate(ctx: RunContext) -> None:
    """The deterministic "hard block" run_session's own completion checkpoint calls right before
    flipping session["status"] to "completed" — a session must not silently report itself done
    while a real, still-open suspicion (the agent's own, or an operator's) never got a real check.
    Zero cost for the overwhelmingly common case (no open hypotheses at all), same "cheap early
    exit" shape as _run_chain's own `if len(findings) <= 1: return`.

    Bounded, not an infinite block: one shared _run_llm_tool_loop pass covering every open
    hypothesis at once (not one loop per hypothesis, which would multiply the time budget by N),
    capped by HYPOTHESIS_PASS_TIMEOUT_SECONDS (_hypothesis_pass_wallclock_limit_seconds) — already
    enforced inside the loop engine itself, no extra while-loop needed here. Whatever's still
    unconfirmed once the pass ends (resolved everything, or ran out of budget/ideas) is left exactly
    as-is; the session still completes either way — this gate makes a real, forced attempt, it does
    not guarantee every hypothesis ends up resolved.
    """
    open_hypotheses = [h for h in ctx.session.get("hypotheses", []) if h.get("status") == "unconfirmed"]
    if not open_hypotheses:
        return

    _mark_phase_started(ctx.session, "hypothesis_gate")
    logger.debug("core: session=%s hypothesis_gate: %d open hypothesis(es) to resolve before completing", ctx.session_id, len(open_hypotheses))

    existing_findings_summary = [
        {"title": f.get("title"), "severity": f.get("severity"), "technology": f.get("technology")}
        for f in ctx.session["findings"]
    ]
    hypotheses_summary = [{"text": h["text"], "evidence": h.get("evidence") or ""} for h in open_hypotheses]
    task = (
        f"Open hypotheses to resolve, every one, before this scan is considered done:\n{json.dumps(hypotheses_summary)}\n\n"
        f"Existing findings from this scan (don't duplicate one of these):\n{json.dumps(existing_findings_summary)}"
    )
    task += _custom_instructions_task_addendum(ctx.session)
    task += _goal_task_addendum(ctx.session)
    task += _program_url_task_addendum(ctx.session)
    task += _scope_rules_task_addendum(ctx.session)

    trace: list[dict] = []
    try:
        await _run_llm_tool_loop(
            ctx, HYPOTHESIS_VERIFICATION_PROMPT, task, _hypothesis_verification_tool_specs(), "hypothesis_gate",
            execute_tool=_make_hypothesis_verification_executor(ctx, trace=trace), expect_json_final=False,
            external_trace=trace, wallclock_limit_seconds=_hypothesis_pass_wallclock_limit_seconds(),
        )
    finally:
        _mark_phase_finished(ctx.session, "hypothesis_gate")
        still_open = sum(1 for h in ctx.session.get("hypotheses", []) if h.get("status") == "unconfirmed")
        logger.debug("core: session=%s hypothesis_gate: finished, %d hypothesis(es) still unconfirmed", ctx.session_id, still_open)


def _playbook_distill_enabled() -> bool:
    return os.getenv("PLAYBOOK_DISTILL_ENABLED", "true").strip().lower() == "true"


async def _run_playbook_distillation_pass(ctx: RunContext) -> None:
    """One short, tool-less LLM call at the very end of a session — scoped ONLY to the fingerprint
    keys THIS session actually wrote to (ctx.session["playbook_touched_keys"], set by
    _maybe_capture_playbook_entry), bounded cost, no drift risk on the rest of the global playbook —
    merges near-duplicate entries under the same fingerprint into tighter wording, and cleans up
    this session's own local playbook_notes.md. Same "small, focused JSON-extraction, no tools
    needed" shape as _structure_hypothesis_text/_confirm_exploit_result.

    Failure-safe: the deterministic entries _maybe_capture_playbook_entry already wrote are already
    correct on their own (just possibly slightly duplicated) — a failed/unparseable LLM call here
    leaves them exactly as-is, never blocks session completion.
    """
    if not _playbook_enabled() or not _playbook_distill_enabled():
        return
    touched_keys = ctx.session.get("playbook_touched_keys") or []
    if not touched_keys:
        return

    store = playbook_store.load_playbook_store()
    groups = {key: store.get(key, []) for key in touched_keys if store.get(key)}
    if not groups:
        return

    notes_path = _playbook_notes_path(ctx.session_id)
    local_notes = notes_path.read_text(encoding="utf-8") if notes_path and notes_path.exists() else ""

    task = (
        f"Fingerprint groups from this session:\n{json.dumps(groups, indent=2)}\n\n"
        f"This session's own local notes:\n{local_notes or '(none)'}"
    )
    messages = [
        {"role": "system", "content": PLAYBOOK_DISTILLATION_PROMPT},
        {"role": "user", "content": task},
    ]
    try:
        response = await _llm_complete(ctx, messages, None)
    except (SessionStopRequested, asyncio.CancelledError):
        raise
    except Exception as exc:
        _playbook_logger.debug("core: session=%s playbook distillation call failed (%s), leaving entries as-is", ctx.session_id, exc)
        return

    parsed = _parse_json_response(response.content)
    if parsed is None:
        parsed = await _repair_json_reply(ctx, messages, response.content)
    if not isinstance(parsed, dict):
        _playbook_logger.debug("core: session=%s playbook distillation produced no usable JSON, leaving entries as-is", ctx.session_id)
        return

    for merge in parsed.get("merges") or []:
        key = merge.get("fingerprint_key")
        keep_id = merge.get("keep_id")
        merge_ids = set(merge.get("merge_ids") or [])
        technique = merge.get("technique")
        if key not in groups or not keep_id or not merge_ids or not technique:
            continue
        entries = groups[key]
        keep_entry = next((e for e in entries if e.get("id") == keep_id), None)
        if keep_entry is None:
            continue
        merged_away = [e for e in entries if e.get("id") in merge_ids and e.get("id") != keep_id]
        if not merged_away:
            continue
        keep_entry["technique"] = str(technique)
        keep_entry["times_confirmed"] = int(keep_entry.get("times_confirmed", 1)) + sum(int(e.get("times_confirmed", 1)) for e in merged_away)
        source_sessions = keep_entry.setdefault("source_session_ids", [])
        for merged_entry in merged_away:
            for session_id in merged_entry.get("source_session_ids") or []:
                if session_id not in source_sessions:
                    source_sessions.append(session_id)
        remaining = [e for e in entries if e is keep_entry or e.get("id") not in merge_ids]
        groups[key] = remaining
        playbook_store.replace_technique_entries(key, remaining)
        _playbook_logger.debug("core: session=%s playbook distillation merged %d entr(y/ies) under key=%r", ctx.session_id, len(merged_away), key)

    # Reusable payload templates the distillation generalized from concrete payloads -- stamped onto
    # the entry so a future session gets a drop-in {{slot}} template, not just a one-target payload.
    # Built after merges so it indexes the post-merge entries.
    entry_by_id = {e.get("id"): (key, e) for key, entries in groups.items() for e in entries}
    template_keys: set[str] = set()
    for tpl in parsed.get("templates") or []:
        entry_id = tpl.get("id")
        template = tpl.get("payload_template")
        if not entry_id or not isinstance(template, str) or not template.strip():
            continue
        target = entry_by_id.get(entry_id)
        if target is None:
            continue
        key, entry = target
        entry["payload_template"] = template.strip()
        template_keys.add(key)
    for key in template_keys:
        playbook_store.replace_technique_entries(key, groups[key])
        _playbook_logger.debug("core: session=%s playbook distillation set payload template(s) under key=%r", ctx.session_id, key)

    new_local_notes = parsed.get("local_notes")
    if isinstance(new_local_notes, str) and new_local_notes.strip() and notes_path is not None:
        notes_path.write_text(new_local_notes.strip() + "\n", encoding="utf-8")
        _playbook_logger.debug("core: session=%s playbook distillation rewrote local notes", ctx.session_id)

    # Auto-prune proven-noise entries (surfaced repeatedly, never once preceded a finding) -- the
    # self-improving other half of attribution. Dead-ends are never pruned (prune_low_value). Runs in
    # the same periodic distillation pass so it's amortized, not on every session.
    pruned = playbook_store.prune_low_value(_playbook_prune_min_injections())
    if pruned:
        _playbook_logger.debug("core: session=%s playbook auto-pruned %d low-value entr(y/ies)", ctx.session_id, pruned)


VALID_ENTRY_POINTS = {"recon", "analyze", "exploit"}


def compute_resume_entry_point(session: dict) -> str:
    """Which entry_point a resumed run should start at, purely from what's already durable in the
    session — the same rule main.py's orphaned-session recovery has always used
    (_mark_orphaned_sessions_interrupted), now shared with a "failed" session's own resume path
    (main.py's resume_session) instead of that logic living twice.
    """
    # RE mode has exactly one entry point (run_re_triage); its resume/rescan routes always re-enter
    # there regardless of this value, so the recon/analyze/exploit phase names below (the main Agent
    # pipeline's own vocabulary) are meaningless for it -- an RE session was showing a bare "recon"
    # here, a phase it never runs. Report its real entry point instead.
    if session.get("mode") == "reverse_engineering":
        return "re_triage"
    if session.get("findings"):
        return "exploit"
    if (session.get("recon_result") or {}).get("targets"):
        return "analyze"
    return "recon"


# Below this, a budget is treated as "no meaningful budget" (no different from unset) rather than
# looping on something too short to ever complete even one real pass -- same tolerance every other
# short-timeout knob in this project already applies rather than trusting an arbitrarily small
# operator-entered value at face value.
_TIME_BUDGET_MIN_SECONDS = 60
# Two consecutive full passes producing the EXACT same finding set (nothing new, nothing changed)
# stops the loop early even with real budget time still remaining -- the point of the time budget
# is "keep digging for real additional impact", not "keep burning tokens against a target that has
# provably nothing left to find". A single repeat isn't enough on its own (a pass can legitimately
# reconfirm everything unchanged once and still find something new the very next round once it
# reasons further about what it already has), so this only fires on the SECOND identical repeat.
_TIME_BUDGET_STALL_STREAK_LIMIT = 2


def _time_budget_deadline_timestamp(session: dict) -> float | None:
    """Wall-clock epoch deadline for session["time_budget_seconds"] (New Project form's Time
    budget field), or None when no budget was ever set — the plain, existing "run once, stop the
    moment it's genuinely done" behavior, completely unchanged for every session that doesn't use
    this feature. Computed from started_at — a real wall-clock deadline ("from start to end", the
    operator's own framing), not "N seconds of actual processing time": a session interrupted and
    resumed hours later correctly finds its deadline already passed instead of getting a fresh,
    unrequested budget on top of what already elapsed.
    """
    budget_seconds = session.get("time_budget_seconds")
    if not budget_seconds or budget_seconds < _TIME_BUDGET_MIN_SECONDS:
        return None
    started_at = session.get("started_at")
    if not started_at:
        return None
    try:
        started = datetime.fromisoformat(started_at)
    except ValueError:
        return None
    return started.timestamp() + budget_seconds


def time_budget_deadline_epoch(session: dict) -> float | None:
    """Public wrapper around _time_budget_deadline_timestamp for main.py's own Jinja filter — the
    Overview tab's live countdown (session_fragment.html) needs the same deadline this module's own
    enforcement reads, computed the exact same way, rather than a second, potentially-drifting
    client-side formula.
    """
    return _time_budget_deadline_timestamp(session)


def _time_budget_remaining(session: dict) -> bool:
    deadline = _time_budget_deadline_timestamp(session)
    return deadline is not None and time.time() < deadline


def _time_budget_min_pass_fraction() -> float:
    return float(os.getenv("TIME_BUDGET_MIN_PASS_FRACTION", "0.15"))


def _time_budget_enough_for_another_pass(session: dict) -> bool:
    """Guards the bare deadline check above with a real cost estimate -- a pass that happens to
    finish with only a few minutes left on the clock used to trigger a brand-new
    recon->reverify->...->skeptical_verification cycle every time regardless, which then got killed
    by _time_budget_expired before ever reaching Reverify (the phase that actually repopulates
    session["findings"] from carried_over_findings) -- stranding the operator on an "interrupted"
    session that read as zero findings for a real, hours-long engagement. Confirmed live
    (a real HackerOne rescan session, usr_b0ea17, 2026-08-16): pass 1 finished with 16 real,
    fully-verified findings at 3 minutes to the deadline; pass 2 died after 2 dns_lookup calls,
    never reaching Reverify at all.

    Estimates a new pass's likely cost from this session's own real average pass duration so far
    (total elapsed time / completed passes) rather than trying to predict it exactly -- cheap, no
    new per-phase instrumentation needed, and self-corrects pass over pass on the same target. True
    (never blocks) whenever there isn't enough information yet to estimate anything.
    """
    deadline = _time_budget_deadline_timestamp(session)
    if deadline is None:
        return True
    remaining = deadline - time.time()
    if remaining <= 0:
        return False
    started_at = session.get("started_at")
    passes_completed = int(session.get("time_budget_passes") or 1)
    if not started_at or passes_completed < 1:
        return True
    try:
        started = datetime.fromisoformat(started_at)
    except ValueError:
        return True
    elapsed = time.time() - started.timestamp()
    if elapsed <= 0:
        return True
    avg_pass_seconds = elapsed / passes_completed
    return remaining >= avg_pass_seconds * _time_budget_min_pass_fraction()


def _time_budget_expired(session: dict) -> bool:
    """True only when a real budget was configured AND its deadline has genuinely passed -- unlike
    _time_budget_remaining above, never true for a session with no budget set at all. That
    function's own False conflates "no budget configured" with "budget expired" into the same
    value, which is exactly right for its own use (a loop-continuation gate: no budget just means
    never loop again, immediately) but wrong here, where this distinguishes "stop now" from "never
    had anything to stop for" -- a session with no budget must never be interrupted by this check.
    """
    deadline = _time_budget_deadline_timestamp(session)
    return deadline is not None and time.time() >= deadline


def _time_budget_pass_is_a_repeat(session: dict) -> bool:
    """True when this pass's own final finding set is byte-for-byte the same (by title) as the
    pass immediately before it — the stall signal _TIME_BUDGET_STALL_STREAK_LIMIT above acts on.
    Reads/updates session["_time_budget_prev_finding_titles"], transient bookkeeping for this
    mechanism only, never part of the finding schema itself."""
    current_titles = sorted(f.get("title") for f in session.get("findings") or [] if f.get("title"))
    previous_titles = session.get("_time_budget_prev_finding_titles")
    session["_time_budget_prev_finding_titles"] = current_titles
    return previous_titles is not None and current_titles == previous_titles


def _prepare_next_time_budget_pass(session: dict) -> None:
    """Folds this pass's own findings into carried_over_findings for real re-verification and seeds
    findings with _carried_over_pending_reverify placeholders for a fresh full pass — the exact same
    in-place data prep main.py's rescan_session_in_place route already uses for an operator-triggered
    same-project rescan, reused here since "keep digging with a fresh pass, prior findings actively
    re-verified" is the identical shape either way, just triggered automatically by remaining budget
    time instead of a click. session["hypotheses"]/["recon_result"]["targets"] are deliberately left
    untouched, same reasoning as the manual route.

    Deliberately does NOT reset session["findings"] to [] the way this used to — that made every
    already-proven finding from the pass that just finished invisible the instant a new pass started,
    with no guarantee the new pass would ever get far enough to bring any of them back (confirmed
    live, a real HackerOne rescan session usr_b0ea17 2026-08-16: pass 2 died 2 tool calls into its
    own recon phase, session ended "findings": [] despite 16 real, fully-verified findings sitting
    inert in carried_over_findings the whole time). Seeding findings with the SAME placeholder
    rescan_session_in_place already established (rather than leaving the raw prior findings in
    place) means _run_reverify's own existing removal logic (agent/core.py, "Removes the
    _carried_over_pending_reverify placeholder...") and session_fragment.html's pending-reverify
    badge apply identically regardless of which of the two routes seeded them.
    """
    session["carried_over_findings"] = copy.deepcopy(session.get("findings") or [])
    session["findings"] = [
        {**copy.deepcopy(f), "_carried_over_pending_reverify": True}
        for f in session["carried_over_findings"]
    ]
    session["reverification_history"] = []
    # Same fresh-pass plan reset the operator-triggered in-place rescan uses (main.py's
    # _prepare_in_place_pass) — the pass that just finished left the plan all "done", which would
    # otherwise sit inert for this next budget-funded pass instead of guiding it.
    session["plan"] = reset_plan_for_new_pass(session.get("plan"))
    session["time_budget_passes"] = int(session.get("time_budget_passes") or 1) + 1


async def run_session(
    session_id: str,
    provider_id: str | None = None,
    entry_point: str = "recon",
) -> None:
    if entry_point not in VALID_ENTRY_POINTS:
        raise ValueError(f"Unknown entry_point {entry_point!r}, expected one of {sorted(VALID_ENTRY_POINTS)}")

    session = load_session(session_id)
    if session is None:
        raise ValueError(f"Unknown session {session_id!r}")

    target = session["target"]
    session["status"] = "processing"
    session["entry_point"] = entry_point
    # Set once, on the very first start, never touched again on a later resume — the whole
    # session's displayed duration (main.py's session_duration filter) is measured from this
    # timestamp to session["finished_at"], so an interruption + resume must not reset it.
    session.setdefault("started_at", datetime.now(timezone.utc).isoformat())
    # A resume reopens a session the duration filter would otherwise treat as already finished;
    # cleared here so the displayed duration keeps counting until this run actually completes.
    session.pop("finished_at", None)
    # Stale from a previous failed/interrupted attempt this run is now resuming past — a fresh
    # attempt in progress has nothing to resume from until/unless it fails again itself.
    session.pop("resumable_from", None)
    # Same reasoning as resumable_from just above -- whatever stopped a PREVIOUS attempt (an
    # operator click, an expired time budget) is no longer this attempt's own state until/unless it
    # happens again; a stale "time_budget_expired" surviving into a freshly-started resume would
    # keep showing the "budget expired" follow-up UI for a run that hasn't even reached that point
    # yet (e.g. the operator resumed after extending the budget, or removing it entirely).
    session.pop("stopped_reason", None)
    # A fresh/resumed full pipeline run is about to decide this session's real status on its own
    # merits -- any note left behind by an EARLIER bounded pass (run_focused_exploit and its
    # siblings) about that prior "Scan failed" banner being stale must not silently carry over
    # and soften THIS run's own banner if it fails again for real.
    session.pop("last_focused_pass_ok", None)
    save_session(session_id, session)
    logger.debug("core: session=%s target=%s starting (entry_point=%s)", session_id, target, entry_point)
    # Re-delivers any subagent result stranded by a prior crash/exit before this new run's own
    # phase dispatch begins -- see _requeue_undelivered_subagent_results' own docstring. A cheap,
    # empty no-op for the overwhelmingly common case (nothing pending).
    _requeue_undelivered_subagent_results(session_id, session)

    ctx = _new_run_context(session, session_id, provider_id)

    # Every debug-level log line emitted anywhere during this run also lands in this session's
    # own project folder, not just the global app log — see agent/utils/debug.py's
    # current_session_id/_SessionAwareFileHandler. Reset in finally so a later, unrelated session
    # sharing this same process never inherits a stale value.
    session_context_token = current_session_id.set(session_id)
    try:
        # Runs the whole recon->analyze->exploit->chain->validate->hypothesis-gate->skeptical-
        # verification pipeline once per iteration -- normally exactly once (the loop's own
        # continuation check at the bottom breaks out immediately when session["time_budget_seconds"]
        # was never set, byte-for-byte the original single-pass behavior). With a real time budget
        # still remaining after a natural completion, loops back into another full pass instead of
        # stopping -- see _time_budget_remaining/_prepare_next_time_budget_pass's own docstrings for
        # why "fold this pass's findings into carried_over_findings and go again" is the right shape
        # for "keep digging for real additional impact while budget time remains", not "stop the
        # instant the first pass finds something".
        while True:
            if entry_point == "recon":
                recon_result = await _run_recon(ctx, target)
                await _auto_delegate_recon_overflow(ctx, target, recon_result)
            else:
                recon_result = session.get("recon_result") or {"targets": []}

            if entry_point in ("recon", "analyze"):
                # Runs before Analyze specifically so a reconfirmed carried-over finding can be
                # pointed out to it (_reconfirmed_findings_task_addendum) instead of Analyze
                # independently rediscovering the same bug as a second, duplicate finding. A no-op for
                # every normal (non-rescan) session — see _run_reverify's own docstring.
                await _run_reverify(ctx)
                await _run_analyze(ctx, target, recon_result)
            # entry_point == "exploit": session["findings"] already holds what's already known —
            # nothing to gather, go straight to exploiting it.

            # Unconditional safety-net call, regardless of entry_point: compute_resume_entry_point()
            # has no idea carried_over_findings exists, so a crash mid-reverify on a rescan can just as
            # easily resume straight into entry_point="exploit" as "analyze" — without this second
            # call here, that resume path would skip _run_reverify entirely and silently strand
            # whatever carried-over findings hadn't been processed yet. Idempotent/instant no-op in
            # the normal case, since the call above already cleared everything pending.
            await _run_reverify(ctx)
            await _run_exploit(ctx, target)
            session["findings"] = await _run_chain(ctx)
            session["findings"] = await _run_validate(ctx)
            # Freeze the chain->validate reconciliation span here, once, right after the pipeline's own
            # original back-to-back run of both phases -- session_fragment.html's "Other processing
            # (chain + validate)" line reads THIS, not the live validate finished_at. Real, confirmed
            # incident this fixes: run_focused_exploit/run_hypothesis_verification both legitimately
            # re-call _run_validate later (a dedup pass after fresh deep-dive/hypothesis work), which
            # correctly pushes phase_timings["validate"]["finished_at"] forward for whatever else reads
            # it live -- but that same overwrite made the reconciliation line balloon to "2h 46m" in a
            # real session where the actual chain+validate work took ~10 minutes, silently absorbing
            # unrelated hours-later work under the wrong label.
            validate_timing = session.get("phase_timings", {}).get("validate", {})
            if validate_timing.get("finished_at"):
                validate_timing["reconciled_at"] = validate_timing["finished_at"]

            session["findings"] = _normalize_findings(session["findings"])
            _warn_if_scope_rules_went_unused(session)
            # A scan must never report itself "completed" while a real background attack it started
            # (e.g. a Hydra brute-force run) is still actually running against the target — bounded by
            # that job's own timeout, never an unbounded wait.
            await await_all_running_jobs(session_id, session)
            # Safety net for a credential-cracking job that only finished AFTER whatever phase
            # started it already moved on (see _auto_record_cracked_credentials_finding's own
            # docstring for the real incident this closes) -- reaping via await_all_running_jobs
            # above never goes through the tool-dispatch path that would otherwise catch this.
            await _harvest_completed_background_jobs(ctx)
            # Same reasoning, for a delegated Subagent task -- every _run_llm_tool_loop call already
            # waits at its own return, but this is the same defense-in-depth belt-and-suspenders
            # background_jobs.py's own await_all_running_jobs already gets right above.
            await subagent_tasks.await_all_running_subagent_tasks(
                session_id, session, stop_check=lambda: get_stop_event(session_id).is_set(),
            )
            if get_stop_event(session_id).is_set():
                raise SessionStopRequested()
            await _run_hypothesis_resolution_gate(ctx)
            # _run_chain and the hypothesis gate above can both mint brand-new findings via
            # record_finding, after the single _run_exploit pass at the top of this loop already
            # returned -- confirmed live: a finding created mid-hypothesis_gate shipped in a
            # completed session with exploited=False and advisory_note=None, no exploit attempt
            # ever made, saved only by the operator noticing and clicking Deep dive manually. Safe
            # and cheap to call again unconditionally: _run_exploit's own resume-skip check already
            # no-ops for every finding that already has exploited/advisory_note set, so this only
            # ever does real work for a finding that genuinely still needs a decision.
            await _run_exploit(ctx, target)
            # After the hypothesis gate, not before -- it can itself add new findings via
            # record_finding, and this must cover every finding that will actually ship in the final
            # report, not just the ones that existed before it ran.
            await _run_skeptical_verification(ctx)
            await _run_playbook_distillation_pass(ctx)

            # _time_budget_pass_is_a_repeat has a real side effect (updates the stall-tracking
            # field) -- short-circuit `or` is what keeps it from running at all once time is already
            # exhausted, not just an optimization. Kept as its own statement (not folded into the
            # `or` chain below) so it still always runs exactly when time remains, regardless of what
            # _time_budget_enough_for_another_pass decides.
            if not _time_budget_remaining(session):
                break
            pass_is_a_repeat = _time_budget_pass_is_a_repeat(session)
            if pass_is_a_repeat:
                break
            if not _time_budget_enough_for_another_pass(session):
                logger.debug(
                    "core: session=%s time budget has time left but not enough relative to this "
                    "session's own average pass duration so far -- stopping instead of starting a "
                    "pass likely to be cut off before it can re-verify anything",
                    session_id,
                )
                break
            logger.debug(
                "core: session=%s time budget still has time remaining after pass %d (%d finding(s)) — starting another pass",
                session_id, int(session.get("time_budget_passes") or 1), len(session["findings"]),
            )
            _prepare_next_time_budget_pass(session)
            save_session(session_id, session)
            entry_point = "recon"

        session["status"] = "completed"
        # Freezes the displayed session duration here — "interrupted"/"failed" deliberately don't
        # set this, since those are still-resumable, not-yet-done states (see started_at above).
        session["finished_at"] = datetime.now(timezone.utc).isoformat()
        save_session(session_id, session)
        logger.debug("core: session=%s completed with %d findings", session_id, len(session["findings"]))
    except SessionStopRequested as exc:
        # The operator confirmed a Stop (main.py's /interrupt route), or a configured time budget's
        # deadline genuinely passed mid-pass (_time_budget_expired, checked at _llm_complete's own
        # choke point) — either way, deliberate, already fully handled here, and nothing above this
        # expects it to keep propagating the way a real asyncio.CancelledError's caller does, so it
        # isn't re-raised. session["stopped_reason"] records which one it was so the UI (Overview
        # tab) can offer the right follow-up instead of one generic "stopped" state for both.
        logger.debug("core: session=%s stopped (reason=%s)", session_id, exc.reason)
        # A Stop must actually kill any still-running background job (e.g. Hydra) -- the operator
        # asked everything to stop, not just the LLM loop, leaving a real attack quietly running.
        kill_all_running_jobs(session)
        await subagent_tasks.kill_all_running_subagent_tasks(session)
        session["status"] = "interrupted"
        session["stopped_reason"] = exc.reason
        session["resumable_from"] = compute_resume_entry_point(session)
        save_session(session_id, session)
    except asyncio.CancelledError:
        # A graceful shutdown (Ctrl+C/SIGINT) or explicit task cancellation, not a crash —
        # asyncio.CancelledError is a BaseException, not an Exception, so the except Exception
        # below never sees it. Uncaught here it used to fall straight through main.py's
        # _run_session_task (whose own except Exception has the same blind spot) and surface to
        # Starlette's background-task runner as a raw, unhandled traceback with no useful session
        # state behind it. Persisting "interrupted" immediately (rather than waiting on the next
        # startup's orphaned-session sweep) means the Resume button is correct even if the process
        # is killed outright a moment later.
        logger.debug("core: session=%s cancelled (shutdown/interrupt) mid-run", session_id)
        # The whole process is going down -- a background job's subprocess would otherwise keep
        # running completely untracked once nothing is left to ever call check on it again.
        kill_all_running_jobs(session)
        await subagent_tasks.kill_all_running_subagent_tasks(session)
        session["status"] = "interrupted"
        session["resumable_from"] = compute_resume_entry_point(session)
        save_session(session_id, session)
        raise
    except Exception as exc:
        logger.debug("core: session=%s failed", session_id, exc_info=True)
        session["status"] = "failed"
        # A network blip mid-scan (LLM API unreachable, a lookup timing out) shouldn't mean
        # starting over from zero — whatever recon/findings this run already made durable (see the
        # module docstring: record_target/record_finding persist the instant they're reported, not
        # batched at phase end) is real, resumable progress, computed the same way an orphaned
        # (process-died) session's resume point already is.
        session["resumable_from"] = compute_resume_entry_point(session)
        # session_fragment.html tells the operator to "see the error in Logs above" on a failed
        # session — that was a broken promise until now, since nothing ever wrote the exception
        # itself into session["logs"]; it only ever reached debug.log (exc_info=True above), which
        # the UI never reads. This is the same append_log the rest of the run already uses, so the
        # failure shows up as a normal log entry instead of a separate ad-hoc field.
        # phase= is _currently_active_phase's answer ("which phase was genuinely running when this
        # exception fired"), NOT session["resumable_from"] -- that field answers a different
        # question ("where should a RESUMED run start") and is very often a LATER phase than the
        # one that actually crashed (e.g. Analyze crashing after already recording findings resumes
        # straight into Exploit). Real incident this fixes: a failure log entry read "[exploit]
        # failed: APIConnectionError" for a crash that happened entirely inside Analyze. Falls back
        # to resumable_from only in the practically-unreachable case where no phase ever started.
        failure_phase = _currently_active_phase(session) or session["resumable_from"]
        _append_log(
            ctx,
            phase=failure_phase,
            thought=None,
            command=None,
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
        )
        logger.debug("core: session=%s failed during phase=%s resumable_from=%s", session_id, failure_phase, session["resumable_from"])
        raise
    finally:
        # This run has now genuinely ended, one way or another -- the one right place to clear the
        # stop flag (see _llm_complete's own docstring for the real incident this fixes: none of the
        # individual per-call checkpoints clear it anymore, since a concurrent subagent task sharing
        # this same session_id could otherwise silently steal the signal from the main loop). Covers
        # every exit path uniformly (completed/interrupted/cancelled/failed), including the case
        # where a stop raced a run that was already finishing for an unrelated reason. Idempotent --
        # clearing an already-clear asyncio.Event is a no-op.
        get_stop_event(session_id).clear()
        # Same "this run has now genuinely ended" reasoning, for get_exhausted_chain_steps -- a
        # step proven dead in THIS run (e.g. a free-tier account-wide quota) must not silently
        # blacklist a later resumed run, since real time passing (the operator resuming after the
        # quota refreshes) is exactly the case that fix needs to allow retrying again. Covers the
        # exact same failed-during-provider-exhaustion case this whole mechanism exists for.
        _clear_exhausted_chain_steps(session_id)
        await _close_browser_session_safely(session_id)
        # Single spot covering every exit path above (completed/interrupted/cancelled/failed) --
        # the total elapsed wall-clock time for this run, previously only ever reconstructable by
        # a human manually subtracting session["started_at"] from session["finished_at"] (or, for
        # a still-resumable interrupted/failed run with no finished_at at all, not reconstructable
        # from session.json alone).
        logger.debug(
            "core: session=%s ended status=%s total duration=%s",
            session_id, session.get("status"), format_session_duration(session),
        )
        # Only the two genuinely TERMINAL outcomes -- "interrupted" is very often the operator's
        # own Stop click (they already know), and a resumed run will end here again for real later.
        if session.get("status") in ("completed", "failed"):
            session["efficiency_notes"] = compute_efficiency_notes(session)
            save_session(session_id, session)
            notify_session_ended(session.get("name") or session_id, target, session["status"], len(session.get("findings") or []))
        current_session_id.reset(session_context_token)


def _cli() -> None:
    parser = argparse.ArgumentParser(description="Run one ASRA scan session from the command line.")
    parser.add_argument("--target", default=None, help="Target host/URL to scan. Required unless --session-id is given.")
    parser.add_argument("--provider", default=None, help="Override LLM_PROVIDER for this run.")
    parser.add_argument(
        "--entry-point", default="recon", choices=sorted(VALID_ENTRY_POINTS),
        help="Skip earlier sub-phases, using data already recorded in the session (needs --session-id for anything but 'recon').",
    )
    parser.add_argument("--session-id", default=None, help="Resume an existing session by ID instead of creating a new one.")
    args = parser.parse_args()

    if args.session_id:
        session_id = args.session_id
        if load_session(session_id) is None:
            raise SystemExit(f"Unknown session {session_id!r}")
    else:
        if not args.target:
            raise SystemExit("--target is required unless --session-id is given")
        session_id = create_session(args.target)
        print(f"Session {session_id} started for target {args.target}")

    asyncio.run(run_session(session_id, provider_id=args.provider, entry_point=args.entry_point))

    session = load_session(session_id)
    print(f"Status: {session['status']}")
    print(json.dumps(session["findings"], indent=2))


if __name__ == "__main__":
    _cli()
