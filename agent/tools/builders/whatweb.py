"""build_command() and output parser for WhatWeb — web technology/CMS/plugin fingerprinting."""
from __future__ import annotations

import json

from agent.tools.allowed_targets import extract_hostname
from agent.tools.builders.validators import validate_header_pair, validate_safe_value, validate_target

# -a 3 ("aggressive" plugin checks, still bounded/reasonable) turns up far more of the
# plugin/version detail this tool exists for than the default -a 1; --color=never keeps the
# output free of ANSI codes the parser below would otherwise have to strip.
_DEFAULT_COLOR_ARGS = ["--color=never"]
_DEFAULT_AGGRESSION_ARGS = ["-a", "3"]
# WhatWeb accepts either spelling for the same option (confirmed against its own --help).
_AGGRESSION_FLAG_PREFIXES = ("-a", "--aggression")
# Machine-readable output this project's own recon pipeline actually parses (parse_whatweb_output
# below, agent/core.py's _merge_protection_detection / recon_result["technologies"]) -- WhatWeb's
# own JSON-Verbose log format carries a per-plugin "certainty" (0-100) alongside each match,
# completely absent from the default human-readable "brief" report this builder used to rely on
# (confirmed against a real run: brief output has no confidence figure anywhere). "-" as the FILE
# argument writes that JSON straight to STDOUT (confirmed against a real WhatWeb run) rather than
# a real temp file -- nothing else in this codebase's tool-output pipeline (agent/core.py's
# _OUTPUT_PARSERS) reads a SEPARATE file back after a subprocess exits, every parser here works
# from stdout alone, and this avoids being the first to need that. --quiet suppresses the old
# brief report so stdout carries ONLY these JSON records (one per scanned URL/redirect hop, each
# independently parseable) instead of the two formats interleaved.
_JSON_VERBOSE_FLAG_PREFIXES = ("--log-json-verbose",)
_QUIET_FLAG_PREFIXES = ("--quiet", "-q")
# Same dual-spelling story as aggression above (confirmed against whatweb --help: "--user-agent,
# -U=AGENT"). Real incident this fixes: a session's own extra_args carried --user-agent while this
# builder unconditionally appended its own --user-agent=... from the server-injected _user_agent
# below -- the executed command got the flag TWICE with different spellings/values, and WhatWeb
# hung until the hard 600s subprocess timeout killed it, the same failure mode the aggression dedup
# above already exists to prevent, just for a flag that dedup never covered.
_USER_AGENT_FLAG_PREFIXES = ("--user-agent", "-U")


def interpret_whatweb_timeout(result: dict) -> str | None:
    """WhatWeb's own max aggression level (-a 4, "heavy") probes every plugin signature far more
    thoroughly than this builder's own default (-a 3, already thorough enough for normal use) and
    routinely exceeds the subprocess timeout against a slow or WAF-fronted target. Confirmed live:
    the SAME host, scanned with the default -a 3 elsewhere in the same session, finished in 6-27s
    every time; only -a 4 ever hung -- five times in a row in one real session (~50 of that
    session's 80 total minutes), because each 1-Step Retry only ever corrected the --user-agent
    spelling and kept resending -a 4, the one flag actually causing the hang, since nothing told
    the model that was the cause. Same registration shape as
    agent/tools/builders/wpscan.py's interpret_wpscan_timeout -- None for any status other than a
    genuine timeout.
    """
    if result.get("status") != "timeout":
        return None
    command = result.get("command") or []
    for index, arg in enumerate(command):
        if arg in _AGGRESSION_FLAG_PREFIXES and index + 1 < len(command) and command[index + 1] == "4":
            break
        if arg in ("--aggression=4",):
            break
    else:
        return None
    return (
        "WhatWeb timed out with -a 4 (its own max/heaviest aggression level) -- that level probes "
        "every plugin signature far more thoroughly than the tool's own default (-a 3, already "
        "thorough enough for normal use) and routinely exceeds this budget against a slow or "
        "WAF-fronted target. Retrying with -a 4 still set will very likely time out the same way "
        "again. Drop the aggression override entirely (WhatWeb's own default, -a 3, is meaningfully "
        "faster and still reports plugin/version detail) instead of resending -a 4."
    )


_EXECUTION_EXPIRED_MARKER = "execution expired"


def interpret_whatweb_degraded_ok(result: dict) -> str | None:
    """WhatWeb can hit its OWN internal per-URL timeout on a single slow target mid-scan and still
    exit 0 -- confirmed live (test-2-again2-usr_2f4db1): stderr carried "ERROR Opening: ... -
    execution expired" while exit_code stayed 0 and status="ok", four separate times in one
    session. Since only a non-zero exit / an explicit "timeout" status is ever treated as
    retryable, this reads to the model as a clean, information-free "ok" — indistinguishable from
    a genuine, confirmed "no technology detected" negative. Same "tool reports ok while doing far
    less than it looks like" family as nmap's "Host seems down" silent skip and httpx's own empty-
    target no-op, just never checked for WhatWeb's own internal timeout marker before.

    Returns a NOTE to attach to the "ok" result, not a status change — WhatWeb did complete, and
    whatever it reported before its own internal timeout is still real; only an empty/thin result
    alongside this marker should be read with suspicion.
    """
    if _EXECUTION_EXPIRED_MARKER not in (result.get("stderr") or ""):
        return None
    return (
        "WhatWeb hit its own internal per-URL timeout mid-scan (stderr: \"execution expired\") but "
        "still exited cleanly. Any technologies reported above are real, but an empty/thin result "
        "here is NOT a confirmed negative — it may just mean WhatWeb never got far enough to check "
        "before its own timeout. Consider a slower/more targeted follow-up (a plain http_request, "
        "or a narrower whatweb re-run) before concluding this host has nothing worth reporting."
    )


def build_whatweb_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    extra_args = [validate_safe_value(str(arg)) for arg in params.get("extra_args", [])]
    # Real incident this fixes: the model sometimes redundantly re-includes the target URL itself
    # inside extra_args (confirmed live three times in one real session -- once as the only
    # extra_args entry, twice alongside a real "-a 3" flag) -- since this builder already appends
    # `target` unconditionally below, that duplicate URL got appended a SECOND time, making WhatWeb
    # scan the exact same URL twice in one invocation: double the wall-clock time, and two separate
    # (sometimes differently-IP'd, DNS-round-robin) result blocks in the output for what should
    # have been a single scan -- genuinely confusing to read, not just wasteful.
    #
    # The original exact-string check above missed the actual dominant real-world shape, confirmed
    # live 4 more times in a separate session: `target` was a bare hostname
    # ("design.example.com") while the model's own extra_args entry for the SAME host was scheme-
    # prefixed ("https://design.example.com") -- the two strings never compare equal, so the
    # filter never fired and both landed as separate positional targets on the same invocation.
    # extract_hostname (agent/tools/allowed_targets.py, already used elsewhere in this codebase for
    # exactly this "compare a schemed value against a bare one" problem) compares by the actual
    # hostname instead of the raw string, so a scheme/case/trailing-slash difference no longer
    # defeats the dedup. Falls back to nothing extra when target's own hostname can't be extracted
    # (never happens for a validate_target()-passed target in practice) -- the exact-string check
    # right before it still covers that case regardless.
    target_hostname = extract_hostname(target)
    extra_args = [
        arg for arg in extra_args
        if arg != target and not (target_hostname and extract_hostname(arg) == target_hostname)
    ]
    # Real incident this fixes: a model wanting a HIGHER aggression level passed extra_args=["-a",
    # "4"] on top of this builder's own hardcoded default -- the real, executed command ended up
    # ["-a", "3", ..., "-a", "4"], the same flag given two conflicting values in one invocation,
    # and WhatWeb hung until the hard subprocess timeout killed it (600s, twice — once for the
    # retry) instead of running with either value. Never added when the model already picked its
    # own aggression level, mirroring nikto's own already-established "-maxtime" dedup in this
    # exact codebase (build_nikto_command) -- an explicit model choice has to win outright, not
    # get silently doubled up with this default.
    command = ["whatweb", *_DEFAULT_COLOR_ARGS]
    if not any(arg.startswith(_AGGRESSION_FLAG_PREFIXES) for arg in extra_args):
        command += _DEFAULT_AGGRESSION_ARGS
    if not any(arg.startswith(_QUIET_FLAG_PREFIXES) for arg in extra_args):
        command.append("--quiet")
    if not any(arg.startswith(_JSON_VERBOSE_FLAG_PREFIXES) for arg in extra_args):
        command.append("--log-json-verbose=-")
    command.append(target)
    command += extra_args
    # Server-side injected by agent/core.py's _run_tool_with_retry (New Project form's Custom
    # User-Agent + Custom HTTP Headers fields) — never part of this tool's own params schema, so
    # never model-supplied. WhatWeb's own --header/-H ("Add an HTTP header, eg 'Foo:Bar'") is a
    # real repeatable flag, one occurrence per header. Skipped when the model's own extra_args
    # already set a user-agent — an explicit model choice has to win outright, not get silently
    # doubled up with this default (same reasoning as the aggression dedup above).
    user_agent = params.get("_user_agent")
    if user_agent and not any(arg.startswith(_USER_AGENT_FLAG_PREFIXES) for arg in extra_args):
        command.append(f"--user-agent={validate_safe_value(user_agent)}")
    for name, value in (params.get("_extra_headers") or {}).items():
        name, value = validate_header_pair(name, value)
        command += ["--header", f"{name}:{value}"]
    return command


def _flatten_strings(value: object) -> list[str]:
    """A JSON-Verbose match's "string"/"module" field is sometimes a bare string, sometimes a
    list, sometimes (e.g. HttpOnly's own match shape) a list of one-element lists -- flattens any
    of those into a flat list of strings, in original order, dropping structure entirely."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        flattened: list[str] = []
        for item in value:
            flattened.extend(_flatten_strings(item))
        return flattened
    return [str(value)]


def parse_whatweb_output(stdout: str) -> dict:
    """Parses WhatWeb's own JSON-Verbose log (build_whatweb_command's `--log-json-verbose=-`,
    one JSON array per scanned URL/redirect hop: `[url, http_status, [[plugin_name, [match, ...]],
    ...]]`, each match a dict optionally carrying "string"/"module" values and a "certainty"
    (0-100)) into the same flat "Name[value1,value2]" (or bare "Name") technologies token list
    this project's whole recon pipeline already keys off (agent/core.py's
    _merge_protection_detection / recon_result["technologies"] / _tech_gate_blocked), PLUS a
    parallel technology_certainty {name: best-certainty-seen} map the old brief-text format never
    carried at all. Still kept as literal tokens rather than a clean {name, version} pair for the
    same reason as before: a plugin can carry both a "string" and a "module" value (Country), and
    the literal comma-joined token is still fully readable either way.
    """
    technologies: list[str] = []
    technology_certainty: dict[str, int] = {}
    detected_cms: str | None = None

    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("["):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, list) or len(record) < 3 or not isinstance(record[2], list):
            continue
        for entry in record[2]:
            if not (isinstance(entry, list) and len(entry) == 2):
                continue
            name, matches = entry
            if not isinstance(name, str) or not isinstance(matches, list):
                continue
            name = name.strip()
            if not name:
                continue

            values: list[str] = []
            best_certainty = 0
            for match in matches:
                if not isinstance(match, dict):
                    continue
                values.extend(_flatten_strings(match.get("string")))
                values.extend(_flatten_strings(match.get("module")))
                certainty = match.get("certainty")
                if isinstance(certainty, (int, float)):
                    best_certainty = max(best_certainty, int(certainty))

            token = f"{name}[{','.join(values)}]" if values else name
            technologies.append(token)
            if best_certainty:
                technology_certainty[name] = max(technology_certainty.get(name, 0), best_certainty)
            if detected_cms is None and name.lower() == "wordpress":
                detected_cms = token

    return {
        "technologies": technologies,
        "technology_certainty": technology_certainty,
        "detected_cms": "WordPress" if detected_cms else None,
    }
