"""Where (if anywhere) a USABLE opencode CLI lives on this machine, and a concrete, specific
explanation when there isn't one -- the single source of truth the "opencode (local server)"
provider, Settings, the Tools page's Dependencies row and setup_tools.sh's own `have_native` all
agree with, instead of each calling `shutil.which("opencode")` and disagreeing about what a hit means.

Why a plain `which` is not enough: under this project's supported Windows launch path the agent
runs inside WSL2, and WSL2 appends the Windows PATH to the Linux one -- so `which opencode` happily
resolves a Windows-side npm global install (`/mnt/c/Users/<name>/AppData/Roaming/npm/opencode`).
That copy is useless here (see agent/opencode_local_provider.py: launched through WSL's process
interop it starts too slowly to ever look "ready", and killing the interop stub may not stop the
real Windows process). So "found on PATH" and "usable" are different questions, and the operator
needs to be told WHICH situation they are in -- "you have it on Windows only, nothing inside WSL" is
a very different fix from "you have nothing anywhere" -- rather than one generic failure string.

Deliberately dependency-free (stdlib + logger only): imported by main.py, the provider, chat's error
formatter and the arsenal check, so it must never pull any of them (or an LLM client) back in.
"""
from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

from agent.opencode_install import detect_target
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# A drive mounted by WSL2's automount (/mnt/c, /mnt/d, ...) -- single letter only, so an ordinary
# Linux mount like /mnt/data is never mistaken for the Windows side.
_WINDOWS_MOUNT_RE = re.compile(r"^/mnt/[a-zA-Z](?:/|$)")

# Matched by llm_test_status.html / the settings cards to decide whether to offer the install button.
INSTALL_ACTION = "install_opencode"

STATE_NATIVE = "native"
STATE_WINDOWS_ONLY = "windows_only"
STATE_MISSING = "missing"


def is_windows_mount_path(path: str) -> bool:
    return bool(_WINDOWS_MOUNT_RE.match(path))


def managed_opencode_path() -> Path:
    """Where ASRA's own "Install opencode" puts the CLI (agent/opencode_install.py) -- one fixed,
    ASRA-controlled spot that is the same whoever launched the app, so a copy installed in one launch
    mode (root vs normal user) is found in the other. Ordinary PATH is checked first; this is the
    fallback that makes the one-click install work with no PATH edit, no root and no shell restart."""
    return resolve_global_app_dir() / "tools" / "opencode" / "opencode"


def _split_which(name: str) -> tuple[str | None, str | None]:
    """(native_path, windows_path) for `name`. The Windows path is only reported when NO native copy
    exists -- a machine with both is simply "native", the Windows one is irrelevant then."""
    first = shutil.which(name)
    if first is None:
        return None, None
    if not is_windows_mount_path(first):
        return first, None
    # The Windows copy won the PATH lookup (custom PATH order, or sudo-less root login): look again
    # with every Windows mount removed, in case a real Linux copy is hiding later in PATH.
    linux_only_path = os.pathsep.join(
        entry for entry in os.environ.get("PATH", "").split(os.pathsep)
        if entry and not is_windows_mount_path(entry)
    )
    native = shutil.which(name, path=linux_only_path)
    return native, (None if native else first)


@dataclass(frozen=True)
class OpencodeCliStatus:
    state: str
    native_path: str | None
    windows_path: str | None
    wsl_distro: str | None
    # False only where no official CLI build exists (native Windows, unusual CPUs): there a button
    # could only answer "unsupported", so the operator is told the manual step instead.
    auto_install: bool = True

    @property
    def usable(self) -> bool:
        return self.state == STATE_NATIVE

    @property
    def install_label(self) -> str:
        return "Install opencode in WSL" if self.wsl_distro else "Install opencode"

    @property
    def _where(self) -> str:
        return f"WSL2 ({self.wsl_distro})" if self.wsl_distro else "this machine"

    def explanation(self) -> str:
        """Operator-facing, specific to what was actually found -- empty when nothing is wrong."""
        if self.usable:
            return ""
        if self.auto_install:
            how_to_fix = (
                f"Fix: click \"{self.install_label}\" (shown under the Test result in Settings -> AI Provider "
                "& Model, and in Tools -> Check arsenal -> Dependencies). It downloads the official opencode "
                "CLI (about 75 MB; no Node.js, no admin rights) into ASRA's own folder "
                f"({managed_opencode_path().parent})"
            )
        else:
            how_to_fix = (
                "Fix: install it yourself in a terminal on this machine -- `npm install -g opencode-ai` "
                "(needs Node.js; see https://opencode.ai) -- then try again"
            )
        if self.state == STATE_WINDOWS_ONLY:
            return (
                f"opencode is installed only on the Windows side ({self.windows_path}). ASRA runs inside "
                f"{self._where}, which has no opencode of its own -- the Windows copy is merely visible "
                "there through WSL's PATH interop, and the server it starts is normally unreachable from "
                "inside WSL (WSL2's localhost is not Windows' localhost), so ASRA refuses to run it. "
                f"{how_to_fix}; your Windows install is left untouched."
            )
        windows_note = " and not on the Windows side either" if self.wsl_distro else ""
        return f"opencode is not installed in {self._where}{windows_note}. {how_to_fix}."


def _find_managed_copy() -> str | None:
    path = managed_opencode_path()
    return str(path) if path.is_file() and os.access(path, os.X_OK) else None


def diagnose_opencode_cli() -> OpencodeCliStatus:
    native, windows = _split_which("opencode")
    native = native or _find_managed_copy()
    state = STATE_NATIVE if native else STATE_WINDOWS_ONLY if windows else STATE_MISSING
    status = OpencodeCliStatus(
        state=state, native_path=native, windows_path=windows,
        wsl_distro=os.environ.get("WSL_DISTRO_NAME") or None,
        # Only worth probing (ldd/sysctl) when there is a problem to offer a fix for.
        auto_install=True if native else detect_target() is not None,
    )
    logger.debug("opencode_cli: state=%s native=%s windows=%s distro=%s",
                 state, native, windows, status.wsl_distro)
    return status


def opencode_cli_installed() -> bool:
    return diagnose_opencode_cli().usable


class OpencodeCliUnavailable(ValueError):
    """Raised instead of a bare ValueError so callers can tell "the CLI isn't usable here" (cheap to
    re-check, fixable by the install button, must NOT trigger the server-start failure cooldown)
    apart from "the server we spawned crashed". Still a ValueError: every existing
    `except ValueError` around server startup keeps working unchanged."""

    def __init__(self, status: OpencodeCliStatus):
        super().__init__(status.explanation())
        self.status = status
        self.fix_action = INSTALL_ACTION if status.auto_install else None
        self.fix_label = status.install_label
