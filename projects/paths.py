"""Resolves where per-session project folders live on disk, the same way a normal desktop app
would default to "Documents" — not a directory the user has to go hunting for. Overridable via
PROJECTS_DIR (.env) for anyone who wants a different location; nothing here is hardcoded to a
specific username or OS, it detects and adapts.

WSL2 is a special case: ASRA's Python process runs inside the Ubuntu side, but the user browses
Windows Explorer, not the WSL filesystem — so "Documents" has to mean the *Windows* Documents
folder (visible in Explorer), not /home/<wsl-user>/Documents buried inside the VM. That's the
reason for the cmd.exe round-trip below; WSL2 can invoke Windows executables directly, so this
doesn't need any extra setup beyond what's already required to run the project at all.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

from agent.utils.logger import get_logger

logger = get_logger("PROJECTS")

_PROJECTS_SUBDIR = "ASRA Projects"
_APP_SUBDIR = "ASRA"


def _is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def _windows_path_to_wsl(win_path: str) -> Path:
    drive, rest = win_path.strip().split(":", 1)
    return Path(f"/mnt/{drive.lower()}{rest.replace(chr(92), '/')}")


_WINDOWS_DRIVE_PATH_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")
_WSL_MOUNT_PATH_PATTERN = re.compile(r"^/mnt/([A-Za-z])(/.*)?$")


def _wsl_folder_to_windows_path(folder: Path) -> str:
    """The reverse of _windows_path_to_wsl -- a real path this process can see, back into
    something the operator's own Windows-side file manager can actually open. Project folders
    always resolve through the Windows Documents mount (_wsl_windows_documents_dir below), so the
    common case is the /mnt/<drive>/... -> <drive>:\\... rewrite; a path that lands outside any
    drive mount (a PROJECTS_DIR override pointing at the WSL2-side filesystem itself) still gets a
    real, openable \\\\wsl$\\<distro>\\... UNC path when WSL_DISTRO_NAME is set, rather than a bare
    POSIX string Explorer can't do anything with."""
    posix = str(folder)
    match = _WSL_MOUNT_PATH_PATTERN.match(posix)
    if match:
        drive = match.group(1).upper()
        rest = (match.group(2) or "").replace("/", "\\")
        return f"{drive}:{rest}"
    distro = os.environ.get("WSL_DISTRO_NAME", "").strip()
    if distro:
        return f"\\\\wsl$\\{distro}{posix.replace('/', chr(92))}"
    return posix


def resolve_open_target(path: Path) -> dict:
    """Decides how the operator can actually open `path` (an RE-mode target file/folder,
    session["target"] -- see agent/tools/builders/re_target.py) in a real file manager. A file
    resolves to its own parent folder; a folder is used as-is.

    Deliberately does NOT spawn Windows Explorer from this process under WSL2: a real, confirmed
    incident elsewhere in this project found that handing a URL to
    explorer.exe FROM WSL delivered a stray CTRL_C into this process's own console group and killed
    an already-running ASRA instance. The exact same interop hop (explorer.exe launched from inside
    the WSL2 side) would be needed here too, so the same risk applies -- this returns the real
    Windows-shaped path only, for the operator to open with their own desktop shell or paste into
    Explorer themselves, never spawned from here. Native Linux/macOS has no such interop hop at all
    -- xdg-open/open is launched directly and safely, same as any other desktop integration.

    Returns one of:
    - {"kind": "opened", "folder": str} -- actually launched (native Linux/macOS only).
    - {"kind": "windows_path", "path": str, "folder": str} -- WSL2: nothing launched, the real
      Windows-shaped path for the operator to open or copy themselves.
    - {"kind": "error", "message": str}
    """
    if not path.exists():
        return {"kind": "error", "message": f"Not found on disk: {path}"}
    folder = path if path.is_dir() else path.parent

    if _is_wsl():
        win_path = _wsl_folder_to_windows_path(folder)
        logger.debug("resolve_open_target: WSL2, returning windows path folder=%s -> %s", folder, win_path)
        return {"kind": "windows_path", "path": win_path, "folder": str(folder)}

    if sys.platform == "darwin":
        opener = "open"
    elif sys.platform.startswith("linux"):
        opener = "xdg-open"
    else:
        return {"kind": "error", "message": f"Don't know how to open a file manager on this platform ({sys.platform})."}

    try:
        subprocess.Popen(
            [opener, str(folder)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        logger.debug("resolve_open_target: %s failed for %s (%s)", opener, folder, exc)
        return {"kind": "error", "message": f"Could not launch a file manager: {exc}"}
    logger.debug("resolve_open_target: launched %s for %s", opener, folder)
    return {"kind": "opened", "folder": str(folder)}


def resolve_user_supplied_path(raw: str) -> Path:
    """Translates an operator-typed local path (the Reverse Engineering mode's target field,
    agent/tools/builders/re_target.py) into a path this process can actually open.

    Only relevant under WSL2: the operator sees/types a Windows path (C:\\Users\\... — Explorer's
    own view), but this process runs on the Linux side, so it needs the /mnt/c/... form (reusing
    _windows_path_to_wsl, the exact same translation resolve_projects_base_dir already relies on
    for "Documents"). A path that's already POSIX-shaped (native Linux/macOS, or already
    WSL-style like /mnt/c/...) passes through unchanged on every platform.
    """
    raw = raw.strip()
    if _is_wsl() and _WINDOWS_DRIVE_PATH_PATTERN.match(raw):
        return _windows_path_to_wsl(raw)
    return Path(raw).expanduser()


def _wsl_windows_documents_dir() -> Path | None:
    try:
        result = subprocess.run(
            ["cmd.exe", "/c", "echo %USERPROFILE%"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        profile = result.stdout.strip()
        if not profile or "%USERPROFILE%" in profile:
            return None
        return _windows_path_to_wsl(profile) / "Documents"
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        logger.debug("_wsl_windows_documents_dir: cmd.exe interop failed (%s)", exc)
        return None


def _linux_documents_dir() -> Path:
    try:
        result = subprocess.run(
            ["xdg-user-dir", "DOCUMENTS"],
            capture_output=True, text=True, timeout=5, check=True,
        )
        candidate = result.stdout.strip()
        if candidate:
            return Path(candidate)
    except (OSError, subprocess.SubprocessError):
        pass
    return Path.home() / "Documents"


def _resolve_documents_dir() -> Path:
    """The one piece both resolve_projects_base_dir() and resolve_global_app_dir() share: finding
    the real, user-visible Documents folder for this OS (Windows Documents even from inside
    WSL2, not the Linux-side home directory — see the module docstring)."""
    documents_dir = None
    if _is_wsl():
        documents_dir = _wsl_windows_documents_dir()
        if documents_dir is None:
            logger.debug("_resolve_documents_dir: WSL2 detected but Windows Documents lookup failed, "
                         "falling back to the Linux-side home directory")
    if documents_dir is None:
        if sys.platform == "darwin" or _is_wsl():
            documents_dir = Path.home() / "Documents"
        elif sys.platform.startswith("linux"):
            documents_dir = _linux_documents_dir()
        else:
            documents_dir = Path.home() / "Documents"
    return documents_dir


@lru_cache(maxsize=1)
def resolve_projects_base_dir() -> Path:
    """Where new project folders get created. Computed once per process (env read + possibly a
    subprocess call), not on every session creation."""
    override = os.environ.get("PROJECTS_DIR")
    if override:
        base = Path(override).expanduser()
        logger.debug("resolve_projects_base_dir: using PROJECTS_DIR override=%s", base)
        return base

    base = _resolve_documents_dir() / _PROJECTS_SUBDIR
    logger.debug("resolve_projects_base_dir: resolved base=%s (wsl=%s platform=%s)", base, _is_wsl(), sys.platform)
    return base


@lru_cache(maxsize=1)
def resolve_global_app_dir() -> Path:
    """Where app-level state that isn't tied to one specific pentest project lives — currently
    just the global debug log (agent/utils/debug.py): server startup, UI activity between/before
    scans, anything not scoped to a session_id. Sibling to "ASRA Projects", not inside it — this
    is the app's own data, not one engagement's. Session-scoped debug activity instead lands
    inside that session's own project folder (see debug.py's current_session_id) — deliberately
    not here, so this directory never turns into an ever-growing mix of every past engagement.
    """
    override = os.environ.get("APP_DATA_DIR")
    if override:
        base = Path(override).expanduser()
        logger.debug("resolve_global_app_dir: using APP_DATA_DIR override=%s", base)
        return base

    base = _resolve_documents_dir() / _APP_SUBDIR
    logger.debug("resolve_global_app_dir: resolved base=%s (wsl=%s platform=%s)", base, _is_wsl(), sys.platform)
    return base
