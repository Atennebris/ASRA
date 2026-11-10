"""build_command() and output parser for adb -- Android live-device/emulator access (listing
devices, running a shell command, installing an APK, pulling a file, dumping logcat). Confirmed
live against the real CLI (platform-tools 34.0.4) before writing anything here.

Real, honest limitation shared with sigrok_cli.py: every mode here except "devices" needs a real
connected device or running emulator to do anything meaningful -- `adb devices` on a machine with
neither returns a real, valid, EMPTY list (confirmed live, exit code 0), not an error; this is not
a builder bug, it's accurately reporting that nothing is attached.

mode="shell" passes its `command` through largely unrestricted (not an allowlisted sub-language
the way radare2.py/gdb.py restrict THEIR OWN scripting languages) -- deliberate: unlike r2/gdb's
command text, which reaches a LOCAL interpreter this process itself could be compromised by,
`adb shell <command>` passes its argument as ONE argv token straight to the adb client, which
relays it to the remote device's own shell -- there is no local shell this process invokes, so
there's no local injection surface to defend; running an arbitrary command on the connected
device is this mode's entire, legitimate purpose, the same trust model agent/tools/native.py's own
custom_exploit_run already uses for arbitrary Python rather than a restrictive allowlist.
"""
from __future__ import annotations

from agent.tools.builders.validators import validate_safe_value

_VALID_MODES = {"devices", "shell", "install", "pull", "logcat"}


def build_adb_command(params: dict) -> list[str]:
    mode = params.get("mode", "devices")
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown adb mode={mode!r} -- must be one of {sorted(_VALID_MODES)}")

    if mode == "devices":
        return ["adb", "devices", "-l"]

    if mode == "shell":
        command = str(params.get("command") or "").strip()
        if not command:
            raise ValueError("mode='shell' requires a 'command' parameter (the remote shell command to run).")
        return ["adb", "shell", validate_safe_value(command)]

    if mode == "install":
        apk_path = str(params.get("apk_path") or "").strip()
        if not apk_path:
            raise ValueError("mode='install' requires an 'apk_path' parameter (a local .apk file path).")
        command = ["adb", "install"]
        # Opt-in, not a silent default -- replacing an already-installed app changes real device
        # state the model shouldn't do unasked (No hardcoding: behavior is parameter-driven here,
        # never a baked-in -r).
        if params.get("replace"):
            command.append("-r")
        command.append(validate_safe_value(apk_path))
        return command

    if mode == "pull":
        remote_path = str(params.get("remote_path") or "").strip()
        if not remote_path:
            raise ValueError("mode='pull' requires a 'remote_path' parameter (the on-device file/directory path to copy).")
        command = ["adb", "pull", validate_safe_value(remote_path)]
        local_path = str(params.get("local_path") or "").strip()
        if local_path:
            command.append(validate_safe_value(local_path))
        return command

    # mode == "logcat" -- always -d (dump the current buffer and exit); a model-driven call must
    # never start an unbounded live stream with no way to stop it.
    command = ["adb", "logcat", "-d"]
    log_filter = str(params.get("filter") or "").strip()
    if log_filter:
        command.append(validate_safe_value(log_filter))
    return command


def parse_adb_output(stdout: str) -> dict:
    """No structured/JSON output mode exists for any of these -- `devices -l`'s own listing is
    parsed into a simple list on a best-effort basis (one device per non-header line); every
    other mode's raw text output is already what the model needs to read directly, same as
    gdb.py's own parse_gdb_output."""
    stripped = stdout.strip()
    result: dict = {"raw_output": stripped}
    lines = stripped.splitlines()
    if lines and lines[0].strip().lower().startswith("list of devices attached"):
        devices = []
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if parts:
                devices.append({"serial": parts[0], "detail": " ".join(parts[1:])})
        result["devices"] = devices
    return result
