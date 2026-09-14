"""Shared run_tool(): health-check, allowlist guardrail, subprocess/native dispatch."""
from __future__ import annotations

import contextvars
import os
import shutil
import subprocess
import time

from agent.tools.allowed_targets import is_target_allowed
from agent.tools.cache import cache_get, cache_set
from agent.tools.registry import ToolSpec, categories_of
from agent.tools.tool_api_keys import redact_secrets_in_command
from agent.utils.debug import current_subagent_label, truncate_for_log
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")


def _debug(msg: str, *args) -> None:
    """logger.debug wrapper for this module's own TOOLS-category lines -- prepends the active
    subagent's own tag (current_subagent_label, set by agent/core.py's subagent-spawn point for
    the duration of a delegated subagent's own conversation, including every tool call it makes)
    when this call happens on the subagent's behalf, plain otherwise. Real, confirmed incident
    this fixes: this module has no RunContext to read (run_tool only ever receives spec/params),
    so unlike agent/core.py's own _log_agent_debug, every one of this file's own debug lines
    carried no subagent/main-loop tag at all -- a concurrent subagent's tool call and the main
    loop's own interleaved within the same debug.log with nothing short of tracing call order by
    hand to tell them apart. current_subagent_label is a plain ContextVar (not a RunContext
    import) specifically so this module never has to import agent.core.
    """
    label = current_subagent_label.get()
    if label:
        logger.debug("[%s] " + msg, label, *args)
    else:
        logger.debug(msg, *args)


# TTL for the deterministic-tool result cache (spec.result_cache_key). Long by design: the key
# already embeds the input file's mtime, so a stale entry is impossible (a changed file produces a
# different key), and an unchanged binary's analysis is just as valid a day later. One env knob,
# separate from the external-API CACHE_TTL_SECONDS (agent/tools/cache.py) whose data genuinely ages.
_RESULT_CACHE_TTL_SECONDS = int(os.getenv("RESULT_CACHE_TTL_SECONDS", "86400"))

# Threaded through asyncio.to_thread's own context-copy behavior (a worker thread it spawns runs
# inside a copy of the calling coroutine's contextvars.Context, same mechanism agent/utils/debug.py's
# current_session_id relies on) — lets whoever dispatches a subprocess call register the live Popen
# handle it just started, so the calling coroutine can kill the real OS process if IT gets cancelled
# while still awaiting the thread. Cancelling an asyncio Task that's awaiting asyncio.to_thread does
# NOT stop the underlying worker thread's blocking call on its own (a documented asyncio/threading
# limitation) — real, confirmed incident: a subagent's own asyncio.wait_for(timeout=900) fired while
# its worker thread was still blocked inside a live nuclei subprocess call; the coroutine was
# correctly marked "timeout", but the real nuclei process kept running for another 86 real seconds,
# finishing (and logging) well after the whole session had already been recorded as completed.
current_subprocess_registry: contextvars.ContextVar[set | None] = contextvars.ContextVar(
    "current_subprocess_registry", default=None
)


def _run_tracked(command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess:
    """subprocess.run()-equivalent (same TimeoutExpired-on-its-own-timeout behavior, same return
    shape) that also registers its live Popen handle in current_subprocess_registry, if the caller
    set one, so an external asyncio-level cancellation — which this call has no way to observe on
    its own, running synchronously in a worker thread — can still reach in and kill the real
    process instead of leaving it to run to completion, orphaned, for nothing."""
    registry = current_subprocess_registry.get()
    # errors="replace" -- real, confirmed incident: httpx fetching a Russian-language site
    # returned a non-UTF-8 byte in its captured output (a windows-1251-encoded page title), and
    # strict decoding (text=True's default) raised UnicodeDecodeError straight out of
    # communicate() -- uncaught anywhere up the call chain, crashing the ENTIRE session instead of
    # failing just that one tool call. A security tool's whole job is capturing arbitrary
    # real-world target output, which routinely isn't valid UTF-8; replacing undecodable bytes
    # with U+FFFD keeps the rest of the output intact and lets the normal retryable-result path
    # handle it like any other tool output, instead of a hard crash.
    #
    # stdin=DEVNULL -- real, confirmed incident: with no stdin= argument, a subprocess inherits
    # this SERVER process's own stdin, whatever that happens to be connected to -- in the real
    # production launch (run.bat opens a genuine console window for the server, not a redirected
    # /dev/null-style launch), that's a live, interactive-capable terminal nobody is typing into.
    # `wpscan` hit exactly this: its local vulnerability database was stale, it printed "Do you
    # want to update now? [Y]es [N]o, default: [N]" and blocked reading stdin for an answer that
    # was never coming -- not a fast EOF-triggered default, a real ~9-minute hang eating almost
    # the entire 600s subprocess timeout before the timeout itself finally killed it, which read
    # to the operator as the whole session silently stuck ("0 activity") for no visible reason.
    # DEVNULL gives ANY tool that ever prompts interactively an immediate EOF on stdin instead --
    # every well-behaved CLI tool treats EOF-with-no-answer the same as its own documented
    # non-interactive default, so this closes the whole class (not just wpscan) with zero downside:
    # nothing this project ever runs is meant to read real interactive input in the first place.
    #
    # Exactly one deliberate exception: a command a tool builder itself prefixed with
    # ["sudo", "-S", ...] (same convention agent/tools/capability_install.py's own install command
    # already uses) -- that prefix is this project's own explicit signal "this specific invocation
    # needs root and knows it" (e.g. agent/tools/builders/nmap.py adding -O only when it can
    # actually use it), never something a target/tool output could produce on its own. sudo -S
    # reads the password from stdin by design, piped from SUDO_PASSWORD (Settings -> Optional
    # interpreters/compilers, empty/unset by default) -- never passed as an argv element (sudo
    # itself refuses that, and it would leak to `ps aux` on this machine). No SUDO_PASSWORD set
    # still hits DEVNULL below like anything else, so sudo -S fails fast on its own missing input
    # rather than hanging -- the same fail-fast guarantee capability_install.py's own sudo -n path
    # gets, just from the interactive prompt's own EOF instead of -n.
    sudo_password = os.getenv("SUDO_PASSWORD") if command[:2] == ["sudo", "-S"] else None
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.PIPE if sudo_password else subprocess.DEVNULL, text=True, errors="replace",
    )
    if registry is not None:
        registry.add(process)
    try:
        stdout, stderr = process.communicate(input=(sudo_password + "\n") if sudo_password else None, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    finally:
        if registry is not None:
            registry.discard(process)
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

_DEFAULT_TOOL_TIMEOUT_SECONDS = 120
_DEFAULT_EXPLOIT_TIMEOUT_SECONDS = 180


def _timeout_for(spec: ToolSpec) -> int:
    # A tool registered in more than one category (categories_of) is exploit-class timeout if
    # EITHER of its categories is -- a read-only verification tool shared with Analyze (e.g.
    # http_request) still deserves Exploit's own timeout budget when called from that phase.
    is_exploit_class = any(c in ("exploit", "post_exploit") for c in categories_of(spec))
    env_var = "EXPLOIT_TIMEOUT_SECONDS" if is_exploit_class else "TOOL_TIMEOUT_SECONDS"
    default = _DEFAULT_EXPLOIT_TIMEOUT_SECONDS if is_exploit_class else _DEFAULT_TOOL_TIMEOUT_SECONDS
    return int(os.getenv(env_var, str(default)))


def _resolve_executable(spec: ToolSpec) -> str | None:
    # Optional per-tool override for a non-PATH install, e.g. NMAP_PATH=/opt/nmap/bin/nmap.
    override = os.getenv(f"{spec.name.upper()}_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    return shutil.which(spec.executable)


def tool_is_installed(spec: ToolSpec) -> bool:
    """Public wrapper around _resolve_executable -- the one real "is this tool actually available
    right now" check in this codebase, reused by agent/tools/tool_inventory.py (the Tools tab +
    the Subagents tab's tool checklist) so both show the SAME live truth _run_subprocess itself
    checks before running a tool, not a second, separately-drifting guess. A tier-1 (native)
    ToolSpec has no real executable to check at all -- it's Python code, always "installed" --
    UNLESS it names its own availability_check (see ToolSpec's own docstring for that field: a
    tier-1 tool with a real external dependency the Python code doesn't itself carry, e.g. the
    browser_* tools' Playwright-managed Chromium download)."""
    if spec.availability_check is not None:
        return spec.availability_check()
    if spec.tool_tier == 1:
        return True
    return _resolve_executable(spec) is not None


def _check_guardrail(spec: ToolSpec, params: dict) -> dict | None:
    """Returns a skip result if the guardrail blocks this call, None if it's clear to proceed.

    is_target_allowed() is a pure, static check (the New Project form's approved exploitation
    scope) — for a given target it can never flip from rejected to accepted mid-session just by
    trying different arguments or source code. Real incident this message wording fixes: a session
    called custom_exploit_run against the same out-of-scope reference URL (www.openssh.com, not the
    assessment target) 4 separate times over ~20 minutes with different Python source each time
    (httpx vs urllib.request, minor URL variants) — the old bare "target not in allowed_targets"
    reason gave no signal that this was a permanent, deterministic rejection rather than something
    fixable by adjusting the call, so nothing discouraged trying again with different code.
    """
    if not spec.requires_allowed_target:
        return None

    target = params.get("target")
    if not target:
        _debug("run_tool: %s skipped, no target provided", spec.name)
        return {"status": "skipped", "tool": spec.name, "reason": "no target provided — this tool requires one"}
    if not is_target_allowed(target):
        _debug("run_tool: %s skipped, target=%r not in allowed_targets", spec.name, target)
        return {
            "status": "skipped",
            "tool": spec.name,
            "reason": (
                f"target {target!r} is not in this project's exploitation allowlist. This is a permanent, "
                "deterministic rejection for this target for the rest of this session — no combination of "
                "arguments or source code will change the outcome, so do not retry this tool against this same "
                "target. For read-only reference material (CVE advisories, release notes, public write-ups) "
                "outside the assessment scope, use http_request instead — it isn't gated by this allowlist."
            ),
        }
    return None


def _describe_tool_exception(exc: Exception) -> str:
    """A bare `params["target"]`-style subscript (the norm across every builder/native_function for
    its own required fields) raises a KeyError that stringifies to just the field name in quotes,
    e.g. "'target'" -- meaningless to the model deciding how to correct a failed call, especially
    after a 1-Step Retry drops or renames the field (confirmed live: a dalfox retry sent "url"
    instead of "target" and the model got back literally "'target'" with no hint what it even
    refers to, burning its one retry chance; the same happened for authenticated_request's
    "identity"). Every other exception type still gets its own real str(exc) -- this only replaces
    the one class that's provably useless as-is.
    """
    if isinstance(exc, KeyError):
        return f"missing required argument: {exc}"
    return str(exc)


def _run_native(spec: ToolSpec, params: dict) -> dict:
    # Tier-1 tools own their own timeout/error handling internally; this is a last-resort net so a
    # bug in one native tool can never take down the agent's main loop.
    try:
        result = spec.native_function(params)
    except Exception as exc:
        _debug("run_tool: %s native call raised %s", spec.name, _describe_tool_exception(exc))
        # never_dispatched=True: same reasoning as the identical marker on _run_subprocess's own
        # build_command exception handler just above -- a bare params["target"]-style KeyError (a
        # missing/malformed argument) means native_function never got to attempt any real work at
        # all, so this says nothing about whether the host is actually reachable. Without this,
        # agent/core.py's _track_host_health would count it toward the same host-wide consecutive-
        # failure streak that eventually blocks EVERY tool from that host, for a mistake that has
        # nothing to do with reachability.
        return {"status": "error", "tool": spec.name, "error": _describe_tool_exception(exc), "never_dispatched": True}

    result.setdefault("tool", spec.name)
    if result.get("status") == "ok":
        _debug("run_tool: %s (native) finished status=ok", spec.name)
    else:
        # Unlike _run_subprocess, a tier-1 tool's own {"status": "error", ...} return (e.g.
        # custom_exploit_run's nonzero exit_code) used to be logged with no detail at all beyond
        # the bare status -- impossible to tell why it failed from the log afterward.
        _debug(
            "run_tool: %s (native) finished status=%s exit_code=%s error=%s stderr_preview=%s",
            spec.name, result.get("status"), result.get("exit_code"), result.get("error"),
            truncate_for_log(result.get("stderr") or ""),
        )
    return result


def _run_subprocess(spec: ToolSpec, params: dict) -> dict:
    resolved_executable = _resolve_executable(spec)
    if resolved_executable is None:
        _debug("run_tool: %s unavailable (executable not found)", spec.name)
        return {"status": "tool_unavailable", "tool": spec.name}

    if spec.classify_risk is not None:
        risk = spec.classify_risk(params)
        if risk != "default":
            _debug("run_tool: %s classified risk=%s params=%s", spec.name, risk, _loggable_params(params))

    try:
        command = spec.build_command(params)
    except Exception as exc:
        # An LLM-supplied argument can violate a builder's expectations in ways the JSON schema
        # alone doesn't stop (e.g. a string field arriving as a list) — build_command() isn't
        # guaranteed exception-safe the way native_function calls already are (_run_native
        # above); without this, one malformed tool call crashes the whole session instead of
        # coming back as a normal, retryable {"status": "error"} result.
        _debug("run_tool: %s build_command raised %s", spec.name, _describe_tool_exception(exc))
        # never_dispatched=True: real, confirmed incident this fixes — agent/core.py's
        # _track_host_health counts any status="error" result toward a host's own consecutive-
        # failure streak, and once that hits _HOST_DEAD_FAILURE_THRESHOLD (3), _dead_host_blocked
        # skips EVERY further tool call against that host for the rest of the phase, regardless of
        # which tool. A build_command exception (a malformed call — a missing/misplaced argument,
        # e.g. discovered.py's own "target never appears in extra_args" check) never even attempted
        # to reach the host at all -- it says nothing whatsoever about whether the host is actually
        # reachable, unlike a real subprocess timeout or connection failure. Without this marker, 3
        # of the SAME argument mistake (an easy thing for a model to repeat, since the tool never
        # even ran to teach it otherwise) permanently blacklisted the session's own PRIMARY target
        # host from every other tool for the rest of the phase — confirmed live, a real session's
        # entire Analyze phase opened with whatweb/http_request/view_source/api_schema_discovery
        # ALL pre-emptively skipped against the one host that mattered, before a single real
        # dispatch was even attempted. _track_host_health checks this flag and skips tracking
        # entirely for a result that never left the model's own argument mistake.
        return {"status": "error", "tool": spec.name, "error": _describe_tool_exception(exc), "never_dispatched": True}

    # Every build_command() (nmap's, dalfox's, make_generic_discovered_command's, ...) puts the
    # bare registered name (spec.executable, e.g. "httpx") in command[0] -- resolved_executable
    # above was computed from that SAME name but through _resolve_executable's override-aware
    # lookup ({TOOL}_PATH env var, falling back to shutil.which). Without this substitution,
    # subprocess.run below does its OWN independent PATH lookup for the bare name and silently
    # ignores resolved_executable entirely -- real incident this fixes: HTTPX_PATH correctly
    # resolved to /usr/local/bin/httpx (confirmed via _resolve_executable directly), the
    # availability check above passed, and the real dispatch STILL ran whatever "httpx" resolves to
    # on PATH inside the activated venv (venv/bin/httpx -- this project's own Python httpx
    # dependency's broken CLI shim), because command[0] was still the bare string. This silently
    # defeated every {TOOL}_PATH override in this codebase (NMAP_PATH, INTERACTSH_CLIENT_PATH, ...)
    # for actual execution -- it only ever gated the "is this tool installed" check above.
    #
    # executable_index=2, not the bare 0, when a builder (nmap's, so far the only one) prefixed its
    # own command with ["sudo", "-S", ...] for a privileged invocation (see _run_tracked's own
    # comment) -- command[0] is "sudo" there, not the tool's own bare name, and overwriting it would
    # corrupt the sudo invocation entirely instead of substituting the tool's own resolved path.
    executable_index = 2 if command[:2] == ["sudo", "-S"] else 0
    command[executable_index] = resolved_executable

    timeout_seconds = _timeout_for(spec)
    step_id = f"{spec.name}_{int(time.time() * 1000)}"

    # Deterministic-output tools (radare2) memoize on (full command + input file mtime): a repeated
    # identical analysis of an unchanged binary is byte-identical and, for radare2, costs a full
    # ~2m30s `aaa` re-analysis every time. A cache hit returns exactly what a fresh run would have,
    # so there is no correctness cost -- only the wasted minutes removed. cache_key returns None to
    # opt a specific call out (a write/mutating invocation), which is never cached or served.
    cache_key = spec.result_cache_key(command, params) if spec.result_cache_key is not None else None
    if cache_key is not None:
        cached = cache_get(spec.name, cache_key, ttl_seconds=_RESULT_CACHE_TTL_SECONDS)
        if cached is not None:
            _debug("run_tool: %s served from result cache (key=%s)", spec.name, cache_key)
            return {**cached, "from_cache": True}

    timeout_retried = False
    try:
        result = _run_tracked(command, timeout_seconds)
    except subprocess.TimeoutExpired:
        _debug("run_tool: %s timed out after %ss command=%s", spec.name, timeout_seconds, redact_secrets_in_command(command))
        retry_command = spec.retry_command_on_timeout(command) if spec.retry_command_on_timeout is not None else None
        if retry_command is None:
            return {"status": "timeout", "tool": spec.name, "command": redact_secrets_in_command(command)}
        _debug("run_tool: %s timeout needs a corrected retry, command=%s", spec.name, redact_secrets_in_command(retry_command))
        try:
            result = _run_tracked(retry_command, timeout_seconds)
        except subprocess.TimeoutExpired:
            _debug("run_tool: %s corrected retry also timed out after %ss command=%s", spec.name, timeout_seconds, redact_secrets_in_command(retry_command))
            return {"status": "timeout", "tool": spec.name, "command": redact_secrets_in_command(retry_command)}
        command = retry_command
        timeout_retried = True

    # The real, fully-resolved argv actually executed -- distinct from "run_tool start"'s own
    # params=%s line above, which is the model's raw pre-build_command arguments (a builder can
    # silently drop/reshape/default fields the model sent, e.g. an unsupported extra key). Without
    # this, the ONLY place the real executed command is ever visible is session.json's own
    # log entry (agent/core.py's _describe_command, built well after the fact) -- confirmed live:
    # this gap is exactly what made a real nuclei retry-succeeded-on-a-seemingly-identical-tag
    # mystery unresolvable from debug.log alone during a session audit.
    _debug(
        "run_tool: %s finished exit_code=%s command=%s stdout_preview=%s stderr_preview=%s",
        spec.name,
        result.returncode,
        redact_secrets_in_command(command),
        truncate_for_log(result.stdout, step_id=step_id),
        # A tool that dies on a fatal argument error (e.g. WPScan's "url option must be unique")
        # commonly writes that to stderr with an empty stdout -- without this, the debug log (and
        # a human auditing it) sees only a blank result and has no way to tell a real argument
        # error apart from a tool that genuinely produced nothing, unlike the tier-1 native path
        # just above, which already logs stderr_preview for exactly this reason.
        truncate_for_log(result.stderr, step_id=step_id),
    )

    result_dict = {
        "status": "ok" if result.returncode in spec.ok_exit_codes else "error",
        "tool": spec.name,
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "command": redact_secrets_in_command(command),
    }
    if timeout_retried:
        result_dict["retried"] = True

    # A tool that came back "ok" (a real exit code, no error) but whose own output already names a
    # known fix for a silent degradation (nmap's "Host seems down... try -Pn") -- see
    # retry_nmap_with_pn_if_host_seemed_down's own docstring for the real incident. Deliberately a
    # plain code-level retry, not routed through agent/core.py's 1-Step Retry (that mechanism only
    # ever fires on a genuine error/timeout status and spends a whole extra LLM call reasoning
    # about corrected arguments neither tool nor operator needs guessed here -- the fix is already
    # fully determined by the tool's own output).
    if spec.retry_command_on_result is not None:
        retry_command = spec.retry_command_on_result(command, result_dict)
        if retry_command is not None:
            _debug("run_tool: %s result needs a corrected retry, command=%s", spec.name, redact_secrets_in_command(retry_command))
            try:
                retry_result = _run_tracked(retry_command, timeout_seconds)
            except subprocess.TimeoutExpired:
                _debug("run_tool: %s corrected retry timed out after %ss command=%s", spec.name, timeout_seconds, redact_secrets_in_command(retry_command))
                return {"status": "timeout", "tool": spec.name, "command": redact_secrets_in_command(retry_command)}
            _debug(
                "run_tool: %s corrected retry finished exit_code=%s command=%s stdout_preview=%s stderr_preview=%s",
                spec.name, retry_result.returncode, redact_secrets_in_command(retry_command),
                truncate_for_log(retry_result.stdout, step_id=step_id), truncate_for_log(retry_result.stderr, step_id=step_id),
            )
            result_dict = {
                "status": "ok" if retry_result.returncode in spec.ok_exit_codes else "error",
                "tool": spec.name,
                "exit_code": retry_result.returncode,
                "stdout": retry_result.stdout,
                "stderr": retry_result.stderr,
                "command": redact_secrets_in_command(retry_command),
                "retried": True,
            }

    # Store for the memoization above -- only a real, completed dispatch reaches here (timeouts
    # returned early and are never cached). Keyed by the ORIGINAL command's key even when a
    # retry_command_on_result correction ran, since that's what a future identical call rebuilds.
    if cache_key is not None:
        cache_set(spec.name, cache_key, result_dict)

    return result_dict


def _loggable_params(params: dict) -> dict:
    """Strips server-side-injected fields (leading underscore -- agent/core.py's
    _run_tool_with_retry own "injected" dict: _session_id, _session, _user_agent, _extra_headers)
    before anything lands in a log line. Real incident this fixes: check_subagent_task/
    delegate_to_subagent/hydra_start/web_login_bruteforce_start/background_job_check all get the
    REAL, LIVE session dict injected as their own "_session" argument (their native functions
    genuinely need it), and this module's own "run_tool start: ... params=%s" debug line used to
    log that raw dict verbatim, unbounded, on every single call -- a session doing several
    check_subagent_task polls (each already containing the previous poll's own session.json log
    entry, itself embedding the session dict from the poll before that) blew debug.log up to
    206 MB within a couple dozen calls. The real dispatch below still receives the full, untouched
    `params` (including the injected fields it actually needs) -- only what reaches a log line is
    filtered.
    """
    return {k: v for k, v in params.items() if not k.startswith("_")}


def run_tool(spec: ToolSpec, params: dict) -> dict:
    _debug("run_tool start: tool=%s category=%s tier=%s params=%s", spec.name, spec.category, spec.tool_tier, _loggable_params(params))

    skip_result = _check_guardrail(spec, params)
    if skip_result is not None:
        return skip_result

    if spec.tool_tier == 1:
        return _run_native(spec, params)
    return _run_subprocess(spec, params)
