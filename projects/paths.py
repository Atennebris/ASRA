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
import subprocess
import sys
from functools import lru_cache
from pathlib import Path

from agent.utils.logger import get_logger

logger = get_logger("PROJECTS")

_PROJECTS_SUBDIR = "ASRA Projects"


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


@lru_cache(maxsize=1)
def resolve_projects_base_dir() -> Path:
    """Where new project folders get created. Computed once per process (env read + possibly a
    subprocess call), not on every session creation."""
    override = os.environ.get("PROJECTS_DIR")
    if override:
        base = Path(override).expanduser()
        logger.debug("resolve_projects_base_dir: using PROJECTS_DIR override=%s", base)
        return base

    documents_dir = None
    if _is_wsl():
        documents_dir = _wsl_windows_documents_dir()
        if documents_dir is None:
            logger.debug("resolve_projects_base_dir: WSL2 detected but Windows Documents lookup failed, "
                         "falling back to the Linux-side home directory")
    if documents_dir is None:
        if sys.platform == "darwin" or _is_wsl():
            documents_dir = Path.home() / "Documents"
        elif sys.platform.startswith("linux"):
            documents_dir = _linux_documents_dir()
        else:
            documents_dir = Path.home() / "Documents"

    base = documents_dir / _PROJECTS_SUBDIR
    logger.debug("resolve_projects_base_dir: resolved base=%s (wsl=%s platform=%s)", base, _is_wsl(), sys.platform)
    return base
