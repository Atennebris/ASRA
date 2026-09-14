"""Tools page -> "Install" button: runs the project's own setup_tools.sh (the full Tier-2 arsenal
provisioner) as a tracked BACKGROUND process, streaming its output to a log file the UI tails live.

Why a background Popen + log file instead of capability_install.py's blocking subprocess.run:
capability_install installs ONE package (seconds), so a blocking call with a 300s cap is fine.
setup_tools.sh provisions the whole arsenal (nmap/nuclei/metasploit/radare2/wine/... + optional
wordlists) and genuinely runs for many minutes -- blocking a FastAPI worker that long is not an
option, and the operator needs to watch progress, not stare at a spinner. So: start it detached,
write combined stdout+stderr to a log in the global app dir, and let the panel poll a "tail the
log" endpoint.

Privilege handling mirrors capability_install.py exactly, one deliberate simplification: rather
than let the script's own many internal sudo calls each need a password (a web request has no TTY
to answer them on), the WHOLE script is run under one `sudo -S bash setup_tools.sh` with the saved
password piped once -- so `id -u` inside the script is already 0 and its own SUDO variable resolves
to empty, no further prompts. Three cases, same order of preference as capability_install:
  1. already root -> `bash setup_tools.sh`, no sudo at all.
  2. SUDO_PASSWORD set -> `sudo -S bash ...`, password piped to stdin once.
  3. passwordless sudo -> `sudo -n bash ...`.
  4. none of the above -> return status="manual" with the exact command to run in a real terminal.

Linux/WSL2 only, same explicit scoping setup_tools.sh itself uses ("not for macOS"): under ASRA's
supported Windows launch path the server already runs inside WSL2 (sys.platform == "linux"), so
this drives the same Linux script it always would. A native-Windows/macOS process cannot run it and
gets status="unsupported" instead of a broken half-run.

The Popen handle lives in memory only -- a server restart mid-install loses the ability to poll/stop
it, but the log file persists so the last output is still shown; the install itself keeps running
under its own process group regardless.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from agent.tools.capability_install import has_sudo_password
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

_SCRIPT_PATH = Path(__file__).resolve().parent.parent.parent / "setup_tools.sh"
_LOG_NAME = "arsenal-install.log"
_LOG_TAIL_LINES = int(os.getenv("ARSENAL_INSTALL_LOG_TAIL_LINES", "400"))
# Descriptive, shown in the confirm warning -- an estimate that legitimately varies by distro and
# whether the optional wordlists are included, so it lives in config, not baked into a template.
_APPROX_GB = os.getenv("ARSENAL_INSTALL_APPROX_GB", "6-8")
_SUDO_PASSWORD_ENV = "SUDO_PASSWORD"

# In-memory only (a live Popen handle is neither JSON-serializable nor meaningful past this
# process's lifetime) -- same reasoning as background_jobs._RUNNING_PROCESSES.
_STATE: dict = {
    "proc": None,      # subprocess.Popen | None
    "log_path": None,  # Path | None
    "started_at": None,
    "command": None,   # human-readable command string
    "wordlists": False,
}


def approx_download_size_gb() -> str:
    return _APPROX_GB


# The standard locations setup_tools.sh actually provisions into -- measured to report a REAL
# on-disk size for this machine instead of a hand-waved estimate. Deliberately NOT the python venv
# (that's run.sh/requirements.txt, not the arsenal). Some (e.g. a root-owned playwright cache) may
# be unreadable to the server's user, so the measured number is an honest floor, not an upper bound.
_ARSENAL_MEASURE_PATHS = (
    "/opt/metasploit-framework", "/usr/share/metasploit-framework",
    "/usr/local", "/usr/lib/x86_64-linux-gnu/wine", "/usr/lib/wine",
    "/opt/jadx", "/usr/share/wordlists", "/usr/share/seclists",
    "/usr/lib/jvm", "/usr/lib/radare2", "/usr/share/radare2",
    "/root/.cache/ms-playwright", "/root/.dotnet", "/root/.foundry",
)
# Below this the arsenal clearly isn't installed yet (a fresh machine) -- fall back to the estimate
# rather than reporting a misleadingly tiny "measured" number.
_MEASURED_FLOOR_MB = 200
_measured_size_cache: str | None | bool = False  # False = not computed yet


def measure_arsenal_size_gb() -> str | None:
    """Real, measured on-disk size (GB, one decimal) of the arsenal's install locations on THIS
    machine, or None when too little is present to be a real install (fresh machine). Cached per
    process -- the arsenal's size doesn't meaningfully change between panel opens, and `du` over
    metasploit/wine/jvm is not free."""
    global _measured_size_cache
    if _measured_size_cache is not False:
        return _measured_size_cache  # type: ignore[return-value]

    total_mb = 0
    for path in _ARSENAL_MEASURE_PATHS:
        if not os.path.exists(path):
            continue
        try:
            proc = subprocess.run(
                ["du", "-sxm", path], capture_output=True, text=True, timeout=20, stdin=subprocess.DEVNULL,
            )
        except (subprocess.TimeoutExpired, OSError):
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                total_mb += int(proc.stdout.split()[0])
            except (ValueError, IndexError):
                continue

    result = None if total_mb < _MEASURED_FLOOR_MB else f"{total_mb / 1024:.1f}"
    logger.debug("measure_arsenal_size_gb: measured=%s MB -> %s", total_mb, result)
    _measured_size_cache = result
    return result


def _log_path() -> Path:
    return resolve_global_app_dir() / _LOG_NAME


# setup_tools.sh colorizes its output with tput (SGR color codes + charset-designator resets like
# ESC(B). Those escape sequences render as garbage boxes in the plain-text <pre> the UI shows them
# in, so strip them before display -- covers CSI sequences (\x1b[...m and friends), charset
# designators (\x1b(B), and other single-char C1 escapes.
_ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|[()][AB0-2]|[@-Z\\-_])")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _tail(path: Path, lines: int) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return _strip_ansi("".join(handle.readlines()[-lines:]))
    except FileNotFoundError:
        return ""


def _is_running() -> bool:
    proc = _STATE.get("proc")
    return proc is not None and proc.poll() is None


def _passwordless_sudo_available() -> bool:
    """`sudo -n true` succeeds only when sudo needs no password (already cached, or NOPASSWD) --
    the honest way to know case 3 applies without triggering a real password prompt on a TTY-less
    web request."""
    if not shutil.which("sudo"):
        return False
    try:
        return subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=5, stdin=subprocess.DEVNULL,
        ).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _resolve_command() -> tuple[list[str] | None, str | None, str]:
    """(argv, stdin_password, display_command). argv is None when no automatic path exists.
    display_command is always the plain, copy-pasteable command for the manual fallback."""
    display = f"bash {_SCRIPT_PATH.name}"
    script = str(_SCRIPT_PATH)
    if os.geteuid() == 0:
        return ["bash", script], None, display
    if has_sudo_password():
        return ["sudo", "-S", "bash", script], os.getenv(_SUDO_PASSWORD_ENV), f"sudo {display}"
    if _passwordless_sudo_available():
        return ["sudo", "-n", "bash", script], None, f"sudo {display}"
    return None, None, f"sudo {display}"


def can_autostart() -> dict:
    """Cheap pre-flight for the confirm panel -- can the button actually run this here, and by which
    path, WITHOUT starting anything. Lets the UI show the honest situation up front instead of only
    discovering it after a click."""
    if sys.platform != "linux":
        return {"ok": False, "reason": "unsupported",
                "message": "Automatic arsenal install only works on Linux/WSL2 "
                           f"(here sys.platform={sys.platform!r})."}
    if not _SCRIPT_PATH.is_file():
        return {"ok": False, "reason": "no_script",
                "message": f"setup_tools.sh not found at {_SCRIPT_PATH}."}
    if not shutil.which("bash"):
        return {"ok": False, "reason": "no_bash", "message": "bash not found on PATH."}
    argv, _, display = _resolve_command()
    if argv is None:
        return {"ok": False, "reason": "manual", "command": display,
                "message": "sudo needs a password and a web request has no terminal to enter it on. "
                           "Set a sudo password in Settings, or run this command yourself:"}
    return {"ok": True, "reason": "root" if argv[0] == "bash" else "sudo", "command": display}


def start_arsenal_install(*, include_wordlists: bool = False) -> dict:
    """Starts setup_tools.sh in the background. include_wordlists passes the script's own
    INSTALL_LARGE_WORDLISTS=true opt-in (rockyou.txt + a couple of SecLists lists, an extra
    ~60-70MB the script otherwise skips). Returns status="running" without starting a second copy
    if one is already in flight."""
    if _is_running():
        logger.debug("arsenal_install: start requested but an install is already running")
        return {"status": "running", **arsenal_install_status()}

    preflight = can_autostart()
    if not preflight["ok"]:
        logger.debug("arsenal_install: cannot autostart (%s)", preflight["reason"])
        return {"status": preflight["reason"], "message": preflight["message"],
                "command": preflight.get("command")}

    argv, stdin_password, display = _resolve_command()
    env = dict(os.environ)
    if include_wordlists:
        env["INSTALL_LARGE_WORDLISTS"] = "true"

    log_path = _log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    header = (f"# ASRA arsenal install started {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"# command: {display}\n"
              f"# include_wordlists: {include_wordlists}\n\n")
    log_path.write_text(header, encoding="utf-8")

    logger.debug("arsenal_install: launching %s (wordlists=%s) -> %s",
                 " ".join(argv), include_wordlists, log_path)
    log_handle = log_path.open("a", encoding="utf-8")
    proc = subprocess.Popen(
        argv, cwd=str(_SCRIPT_PATH.parent), env=env,
        stdin=subprocess.PIPE if stdin_password is not None else subprocess.DEVNULL,
        stdout=log_handle, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,  # own process group -- a server restart never orphans it into ours
    )
    if stdin_password is not None and proc.stdin is not None:
        proc.stdin.write(stdin_password + "\n")
        proc.stdin.close()

    _STATE.update({"proc": proc, "log_path": log_path, "started_at": time.time(),
                   "command": display, "wordlists": include_wordlists})
    logger.debug("arsenal_install: started pid=%s", proc.pid)
    return {"status": "started", **arsenal_install_status()}


def arsenal_install_status() -> dict:
    """Current state + a tail of the log for the polling panel. Works even after a restart lost the
    Popen handle: falls back to whatever the persisted log file still holds."""
    proc = _STATE.get("proc")
    log_path = _STATE.get("log_path") or _log_path()
    running = _is_running()
    returncode = None if running or proc is None else proc.poll()

    if proc is not None:
        state = "running" if running else "finished"
    elif log_path.is_file():
        state = "unknown"  # a prior process's log survives, but not its handle (server restarted)
    else:
        state = "idle"

    return {
        "state": state,
        "running": running,
        "returncode": returncode,
        "succeeded": returncode == 0 if returncode is not None else None,
        "command": _STATE.get("command"),
        "wordlists": _STATE.get("wordlists", False),
        "started_at": _STATE.get("started_at"),
        "log": _tail(log_path, _LOG_TAIL_LINES),
        "log_path": str(log_path),
    }
