"""build_command() for Nikto -- web-server misconfiguration/known-file scanner.

Confirmed live: nikto rejects a bare invocation with no -host flag ("ERROR: No host specified")
and dumps its own usage text instead, exiting 0 -- so leaving target placement to the model's
extra_args (the generic-discovered-tool path every other KNOWN_TOOLS entry still uses) silently
produced zero real scanning in a real session; the model never supplied -host and never noticed
the "success" status was actually a wasted call. whatweb/wpscan already graduated off that path
for the same reason (agent/tools/discovery.py's KNOWN_TOOLS comment) -- nikto follows here.
"""
from __future__ import annotations

import os

from agent.tools.builders.validators import strip_flag_with_value, validate_safe_value, validate_target

# Confirmed live (twice, on the same real target): a thorough nikto pass against a real site can
# run well past this project's own TOOL_TIMEOUT_SECONDS budget, and agent/tools/runner.py's
# subprocess timeout is a hard kill -- every result nikto had already found is lost, not just the
# ones it hadn't gotten to yet. -maxtime makes nikto wrap up and print whatever it has BEFORE that
# kill would land, so a scan against a large/slow site degrades to "fewer checks completed, real
# partial results" instead of "nothing at all, twice, burning the full timeout both times". The
# margin is subtracted, not equal to the external timeout, so nikto's own graceful shutdown (plus
# the final report write) has room to actually finish inside the hard-kill window.
_TIMEOUT_SAFETY_MARGIN_SECONDS = 30
_MIN_MAXTIME_SECONDS = 30
# Mirrors agent/tools/runner.py's own _DEFAULT_TOOL_TIMEOUT_SECONDS default -- not imported (that
# module is the subprocess runner, this is a pure command builder; the two independently agreeing
# on the same env var name and fallback is enough, nikto's own timeout only ever needs to be a
# reasonable margin under whatever the runner is actually configured with, not exactly in sync).
_DEFAULT_EXTERNAL_TIMEOUT_SECONDS = 120
# nikto's own -h/-host/--host are all the same option (confirmed against its own --Help). This
# builder always places -host itself unconditionally below, so any of these arriving via
# extra_args (parameters_schema now tells the model not to -- see agent/tools/__init__.py's
# _AUTO_TARGET_SCHEMA -- but a model can still improvise) has to be stripped, not just detected,
# same "duplicate target flag" bug class already confirmed live for wpscan's --url/-u.
_HOST_FLAG_PREFIXES = ("-h", "-host", "--host")


def build_nikto_command(params: dict) -> list[str]:
    target = validate_target(params["target"])
    extra_args = strip_flag_with_value(
        [validate_safe_value(str(arg)) for arg in params.get("extra_args", [])], _HOST_FLAG_PREFIXES
    )
    # Confirmed live: nikto's -host accepts a full scheme-prefixed URL directly and infers
    # port/SSL from it (https:// -> port 443 + SSL) -- no separate -ssl/-port flags needed for
    # the common case, so nothing extra to compute here.
    command = ["nikto", "-host", target]
    # Never added when the model already picked its own -maxtime -- nikto doesn't reliably merge
    # two occurrences of the same flag, so an explicit model choice has to win outright, not get
    # silently doubled up with this default.
    if not any(arg.startswith("-maxtime") for arg in extra_args):
        configured_timeout = int(os.getenv("TOOL_TIMEOUT_SECONDS", str(_DEFAULT_EXTERNAL_TIMEOUT_SECONDS)))
        maxtime_seconds = max(configured_timeout - _TIMEOUT_SAFETY_MARGIN_SECONDS, _MIN_MAXTIME_SECONDS)
        command += ["-maxtime", f"{maxtime_seconds}s"]
    command += extra_args
    return command
