"""Settings -> Optional interpreters/compilers -> "Install": actually runs the install command for
one entry in agent/tools/capability_registry.py, mirroring setup_tools.sh's own apt/dnf/pacman
package-manager detection (reimplemented in Python since this runs from FastAPI, not bash) --
Linux/WSL2 only, same explicit scoping setup_tools.sh already uses ("not for macOS").

Three ways this can actually run a privileged install, in order of preference:
1. Already root (os.geteuid() == 0) -- no sudo needed at all.
2. SUDO_PASSWORD is set (Settings -> "Sudo password", optional, empty by default) -- `sudo -S`,
   the password piped into stdin, never passed as an argv element (sudo itself refuses that, and
   it would leak to anyone running `ps aux` on this machine anyway).
3. Neither -- `sudo -n` (non-interactive): a web request has no TTY to answer a password prompt
   on, so a required-but-missing password must fail fast, not hang the request thread.

Any failure (case 3 with no passwordless sudo, case 2 with a wrong/stale saved password, this
distro doesn't package the capability, a network error, anything) comes back with the plain
(no -n/-S) command the operator can run themselves in a real terminal, where they can actually type
a password -- a guaranteed manual path regardless of how sudo/WSL/SUDO_PASSWORD happen to be
configured on their particular machine. Same treatment `setup_tools.sh` itself needs zero of: that
script is always run directly by the operator in their own terminal, real TTY from the start,
nothing about this module changes anything there.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from dotenv import dotenv_values, find_dotenv, set_key, unset_key

from agent.tools.capability_registry import get_capability
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_INSTALL_TIMEOUT_SECONDS = int(os.getenv("CAPABILITY_INSTALL_TIMEOUT_SECONDS", "300"))
_SUDO_PASSWORD_ENV = "SUDO_PASSWORD"
# Same "find the real .env, fall back to the repo-root default" resolution agent/llm_client.py's
# own _ENV_PATH already uses -- duplicated rather than imported since that name is that module's
# own private constant, not a shared export.
_ENV_PATH = find_dotenv(usecwd=True) or str(Path(__file__).resolve().parent.parent.parent / ".env")

_PACKAGE_MANAGER_INSTALL_ARGS = {
    "apt": ["apt-get", "install", "-y"],
    "dnf": ["dnf", "install", "-y"],
    "pacman": ["pacman", "-S", "--noconfirm", "--needed"],
}


def detect_package_manager() -> str | None:
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("pacman"):
        return "pacman"
    return None


def has_sudo_password() -> bool:
    """Read fresh, not cached -- same "can be added/removed from .env between requests" reasoning
    main.py's own provider-key status checks already rely on. Never returns the value itself."""
    return bool(os.getenv(_SUDO_PASSWORD_ENV))


def save_sudo_password(password: str) -> None:
    """Same write-then-verify-read-back pattern agent/llm_client.py's save_provider_api_key already
    uses for provider keys -- writes into .env, mirrors into this process's own os.environ so it
    takes effect immediately (load_dotenv() only ever runs once, at process start), and confirms
    the file actually holds what was just submitted before reporting success. Never logs the
    password value itself. Blank input clears the setting instead (same as save_provider_base_url's
    own "empty means go back to default" convention) -- there is no real default here (unset simply
    means installs fall back to the sudo -n fail-fast path), so clearing is the honest equivalent.
    """
    clean = password.strip()
    if not clean:
        clear_sudo_password()
        return
    set_key(_ENV_PATH, _SUDO_PASSWORD_ENV, clean)
    os.environ[_SUDO_PASSWORD_ENV] = clean
    if dotenv_values(_ENV_PATH).get(_SUDO_PASSWORD_ENV) != clean:
        raise RuntimeError(f"Wrote {_SUDO_PASSWORD_ENV} to .env but the read-back didn't match -- refusing to report success.")
    logger.debug("capability_install: sudo password saved")


def clear_sudo_password() -> None:
    unset_key(_ENV_PATH, _SUDO_PASSWORD_ENV)
    os.environ.pop(_SUDO_PASSWORD_ENV, None)
    logger.debug("capability_install: sudo password cleared")


def build_install_command(capability_id: str, *, with_sudo_flag: bool = True) -> list[str] | None:
    """The real argv to run this capability's install. with_sudo_flag=False (used for the operator-
    facing fallback text) omits `-n`/`-S` -- those are implementation details of the automatic
    attempt, not something a human should type themselves."""
    capability = get_capability(capability_id)
    if capability is None:
        return None
    package_manager = detect_package_manager()
    if package_manager is None:
        return None
    package_name = capability["packages"].get(package_manager)
    if package_name is None:
        return None

    argv = [*_PACKAGE_MANAGER_INSTALL_ARGS[package_manager], package_name]
    if os.geteuid() == 0:
        return argv
    if not with_sudo_flag:
        return ["sudo", *argv]
    return ["sudo", "-S", *argv] if has_sudo_password() else ["sudo", "-n", *argv]


def install_capability(capability_id: str) -> dict:
    fallback_command = build_install_command(capability_id, with_sudo_flag=False)
    if fallback_command is None:
        capability = get_capability(capability_id)
        label = capability["label"] if capability else capability_id
        return {
            "status": "unsupported",
            "command": None,
            "message": f"No automatic install available for {label} on this system (no supported "
            "package manager detected, or this platform isn't covered) -- install it manually.",
        }

    real_command = build_install_command(capability_id, with_sudo_flag=True)
    # input=<password> for sudo -S implies stdin=PIPE on its own -- mutually exclusive with
    # stdin=DEVNULL, and only reached when real_command actually starts with ["sudo", "-S", ...].
    stdin_password = os.getenv(_SUDO_PASSWORD_ENV) if real_command[:2] == ["sudo", "-S"] else None
    logger.debug("capability_install: capability=%s running %s (sudo_password=%s)", capability_id, " ".join(real_command), bool(stdin_password))
    try:
        if stdin_password is not None:
            proc = subprocess.run(
                real_command, input=stdin_password + "\n", capture_output=True, text=True, timeout=_INSTALL_TIMEOUT_SECONDS,
            )
        else:
            proc = subprocess.run(
                real_command, capture_output=True, text=True, timeout=_INSTALL_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
            )
    except subprocess.TimeoutExpired:
        logger.debug("capability_install: capability=%s timed out after %ss", capability_id, _INSTALL_TIMEOUT_SECONDS)
        return {
            "status": "error", "command": " ".join(fallback_command),
            "stdout": "", "stderr": "",
            "message": "Automatic install timed out -- run this yourself in a terminal where you can enter your password:",
        }

    if proc.returncode != 0:
        logger.debug("capability_install: capability=%s failed rc=%s", capability_id, proc.returncode)
        return {
            "status": "error", "command": " ".join(fallback_command),
            # sudo -S echoes its own "[sudo] password for X:" prompt text to stderr even when the
            # password was piped correctly -- harmless, but stripping it keeps this from reading
            # like the install itself complained about a password when a wrong/stale saved
            # password is the real, more specific cause worth calling out explicitly.
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-2000:],
            "message": (
                "Automatic install failed (a saved sudo password was tried and rejected -- check it in Settings) -- "
                if stdin_password is not None else
                "Automatic install failed -- "
            ) + "run this yourself in a terminal where you can enter your password:",
        }

    logger.debug("capability_install: capability=%s installed successfully", capability_id)
    return {"status": "ok", "command": " ".join(fallback_command), "stdout": proc.stdout[-2000:], "stderr": ""}
