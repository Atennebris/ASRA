"""build_command() and output parser for sigrok-cli -- logic-signal (digital/analog) capture and
analysis, a class of hardware ASRA had no equivalent for before. Confirmed live against the real
CLI (v0.7.2) before writing anything here, same discipline every other builder in this file follows.

Real, honest limitation this tool has that no other tool in this project's arsenal does: its
useful mode (mode="capture") needs a REAL, physically connected logic analyzer to capture anything
meaningful -- without one, `--scan` still always reports a built-in "demo" pattern-generator
driver (confirmed live: libsigrok ships one unconditionally, present on every machine regardless
of real hardware), so a bare scan result can never be read as proof a real device is attached.
mode="scan" works unconditionally and is genuinely useful on its own (telling the model whether
anything beyond the demo driver is actually connected); mode="capture" against anything other than
"demo" requires real hardware this project has no way to simulate.
"""
from __future__ import annotations

import os

from agent.tools.builders.validators import validate_safe_value

_VALID_MODES = {"scan", "capture"}

# How long a capture runs when neither time_ms nor samples is given -- a real, practical ceiling
# so a capture call can never run indefinitely/until manually killed, same reasoning gdb.py's own
# _MAX_STOPS applies to its own batch size.
_DEFAULT_CAPTURE_TIME_MS = int(os.getenv("SIGROK_DEFAULT_CAPTURE_TIME_MS", "1000"))


def build_sigrok_cli_command(params: dict) -> list[str]:
    mode = params.get("mode", "scan")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown sigrok-cli mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")

    if mode == "scan":
        return ["sigrok-cli", "--scan"]

    driver = str(params.get("driver") or "").strip()
    if not driver:
        raise ValueError(
            "mode='capture' requires a 'driver' parameter -- the driver name a prior mode='scan' "
            "call reported (e.g. 'demo' for the always-present pattern generator, or a real "
            "detected device's own driver string)."
        )
    command = ["sigrok-cli", "-d", validate_safe_value(driver)]

    channels = str(params.get("channels") or "").strip()
    if channels:
        command += ["-C", validate_safe_value(channels)]

    # `is not None`, not bare truthiness -- a real, caught bug in this function's own first draft:
    # `if time_ms:`/`elif samples:` silently treated an explicit 0 (a genuinely invalid value this
    # function is supposed to reject) the same as "not provided at all", falling through to the
    # default time instead of raising. 0 must still reach the positive-value check below.
    time_ms = params.get("time_ms")
    samples = params.get("samples")
    if time_ms is not None and samples is not None:
        raise ValueError("Specify either 'time_ms' or 'samples', not both.")

    if time_ms is not None:
        try:
            time_ms = int(time_ms)
        except (TypeError, ValueError):
            raise ValueError(f"'time_ms' must be an integer, got {time_ms!r}") from None
        if time_ms <= 0:
            raise ValueError("'time_ms' must be a positive number of milliseconds.")
        command += ["--time", str(time_ms)]
    elif samples is not None:
        try:
            samples = int(samples)
        except (TypeError, ValueError):
            raise ValueError(f"'samples' must be an integer, got {samples!r}") from None
        if samples <= 0:
            raise ValueError("'samples' must be a positive sample count.")
        command += ["--samples", str(samples)]
    else:
        command += ["--time", str(_DEFAULT_CAPTURE_TIME_MS)]

    return command


def parse_sigrok_cli_output(stdout: str) -> dict:
    """No JSON/structured output mode exists for either sigrok-cli invocation here -- `--scan`'s
    own device list is plain text, one device per line as "<driver> - <description>" under a "The
    following devices were found:" header (confirmed live); a capture run prints raw per-channel
    sample bitstreams. Scan results are structured here on a best-effort basis (never required --
    raw_output is always present as the honest fallback, same convention radare2.py's own
    parse_radare2_output uses when a command's own output doesn't parse as expected)."""
    stripped = stdout.strip()
    devices = []
    for line in stripped.splitlines():
        lower = line.strip().lower()
        if " - " in line and not lower.startswith(("the following", "no ")):
            driver, _, description = line.partition(" - ")
            devices.append({"driver": driver.strip(), "description": description.strip()})
    result: dict = {"raw_output": stripped}
    if devices:
        result["devices"] = devices
    return result
