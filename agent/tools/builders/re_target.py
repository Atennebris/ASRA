"""Resolves and validates the Reverse Engineering mode's target field -- one or more, comma-
separated, local file/folder/archive paths or public GitHub/GitLab repo URLs, never a host/URL/
domain (agent/tools/builders/validators.py's target-shape regex is host/URL-shaped and doesn't
apply to this mode, which has no network-target concept at all). Multiple entries are the normal
case when the operator pruned a program-page scope-table extraction down to the chips they actually
want reviewed (agent/tools/bugbounty_import.py's analyze_re_program) -- same comma-separated-list
convention Agent mode's own Target(s) field already uses, not a new one invented for this mode.

Two distinct operations, deliberately kept apart:
- check_re_target(): the New Project form's live status-dot check (main.py's
  POST /api/re-target/check) -- read-only, safe to call on every debounced keystroke.
- clone_or_stage_re_target(): the real, one-time staging step run once at actual project
  creation (main.py's start_re route) -- this is the only place a git clone or archive
  extraction actually happens.
"""
from __future__ import annotations

import re
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Literal

from agent.utils.logger import get_logger
from projects.paths import resolve_user_supplied_path

logger = get_logger("PROJECTS")

_GIT_HOST_PATTERN = re.compile(r"^https?://(www\.)?(github|gitlab)\.com/", re.IGNORECASE)
_GIT_CHECK_TIMEOUT_SECONDS = 10
_GIT_CLONE_TIMEOUT_SECONDS = 120


def _split_targets(raw: str) -> list[str]:
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def classify_re_target_input(raw: str) -> Literal["git_url", "local_path"]:
    return "git_url" if _GIT_HOST_PATTERN.match(raw.strip()) else "local_path"


def _is_archive_path(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".zip", ".tar.gz", ".tgz"))


def _check_one_re_target(raw: str) -> dict:
    if classify_re_target_input(raw) == "git_url":
        try:
            subprocess.run(
                ["git", "ls-remote", "--exit-code", raw, "HEAD"],
                capture_output=True, text=True, timeout=_GIT_CHECK_TIMEOUT_SECONDS, check=True,
            )
        except FileNotFoundError:
            logger.debug("check_re_target: git not on PATH, cannot verify %r", raw)
            return {"raw": raw, "ok": False, "kind": "git_url", "message": "git is not installed on this machine -- cannot verify or clone repo URLs."}
        except subprocess.TimeoutExpired:
            logger.debug("check_re_target: git ls-remote timed out for %r", raw)
            return {"raw": raw, "ok": False, "kind": "git_url", "message": "Repo did not respond in time -- check the URL and your network."}
        except subprocess.CalledProcessError as exc:
            logger.debug("check_re_target: git ls-remote failed for %r (%s)", raw, (exc.stderr or "").strip() or exc)
            return {"raw": raw, "ok": False, "kind": "git_url", "message": "Repo not reachable -- check the URL is correct and the repo is public."}
        logger.debug("check_re_target: git repo reachable: %r", raw)
        return {"raw": raw, "ok": True, "kind": "git_url", "message": "Public repo reachable -- will be cloned into this project."}

    resolved = resolve_user_supplied_path(raw)
    if not resolved.exists():
        logger.debug("check_re_target: local path does not exist: raw=%r resolved=%s", raw, resolved)
        return {"raw": raw, "ok": False, "kind": "missing", "message": f"Path not found: {resolved}"}
    if resolved.is_dir():
        logger.debug("check_re_target: folder found: %s", resolved)
        return {"raw": raw, "ok": True, "kind": "directory", "message": f"Folder found: {resolved}"}
    if _is_archive_path(resolved):
        logger.debug("check_re_target: archive found: %s", resolved)
        return {"raw": raw, "ok": True, "kind": "archive", "message": f"Archive found: {resolved} (will be extracted)"}
    logger.debug("check_re_target: file found: %s", resolved)
    return {"raw": raw, "ok": True, "kind": "file", "message": f"File found: {resolved}"}


def check_re_target(raw: str) -> dict:
    """Live-check for the New Project form's status dot -- one or more comma-separated entries.
    Never mutates anything, no clone/extract happens here, see clone_or_stage_re_target for the
    real, one-time staging step. A single entry keeps the original flat shape
    ({"ok", "kind", "message"}) for backward compatibility with the simple single-target case;
    two or more entries return {"ok": <all of them>, "kind": "multi", "message": <summary>,
    "entries": [<one of the above per entry>]}."""
    targets = _split_targets(raw)
    if not targets:
        return {"ok": False, "kind": "missing", "message": "Target is empty."}
    if len(targets) == 1:
        return _check_one_re_target(targets[0])

    entries = [_check_one_re_target(t) for t in targets]
    ok_count = sum(1 for e in entries if e["ok"])
    return {
        "ok": ok_count == len(entries),
        "kind": "multi",
        "message": f"{ok_count}/{len(entries)} targets reachable" + ("" if ok_count == len(entries) else " -- see below."),
        "entries": entries,
    }


def _safe_extract_zip(archive: zipfile.ZipFile, dest: Path) -> None:
    """Rejects any member whose resolved path would land outside dest (zip-slip) before
    extracting anything -- an operator-supplied archive is still an archive of unknown origin
    (e.g. downloaded from a bug-bounty program's own asset, not something ASRA generated)."""
    dest = dest.resolve()
    for member in archive.namelist():
        target = (dest / member).resolve()
        if target != dest and dest not in target.parents:
            raise ValueError(f"Archive member escapes destination directory: {member!r}")
    archive.extractall(dest)


def _safe_extract_tar(archive: tarfile.TarFile, dest: Path) -> None:
    dest = dest.resolve()
    for member in archive.getmembers():
        target = (dest / member.name).resolve()
        if target != dest and dest not in target.parents:
            raise ValueError(f"Archive member escapes destination directory: {member.name!r}")
    archive.extractall(dest)


def _clone_or_stage_one_re_target(raw: str, dest_if_staging_needed: Path) -> Path:
    """dest_if_staging_needed is only actually created/used for a git clone or an archive
    extraction -- a plain local file/folder is referenced in place, never copied."""
    if classify_re_target_input(raw) == "git_url":
        logger.debug("clone_or_stage_re_target: cloning %r into %s", raw, dest_if_staging_needed)
        subprocess.run(
            ["git", "clone", "--depth", "1", raw, str(dest_if_staging_needed)],
            capture_output=True, text=True, timeout=_GIT_CLONE_TIMEOUT_SECONDS, check=True,
        )
        return dest_if_staging_needed

    resolved = resolve_user_supplied_path(raw)
    if resolved.is_dir() or not _is_archive_path(resolved):
        return resolved

    dest_if_staging_needed.mkdir(parents=True, exist_ok=True)
    if resolved.name.lower().endswith(".zip"):
        logger.debug("clone_or_stage_re_target: extracting zip %s into %s", resolved, dest_if_staging_needed)
        with zipfile.ZipFile(resolved) as archive:
            _safe_extract_zip(archive, dest_if_staging_needed)
    else:
        logger.debug("clone_or_stage_re_target: extracting tarball %s into %s", resolved, dest_if_staging_needed)
        with tarfile.open(resolved) as archive:
            _safe_extract_tar(archive, dest_if_staging_needed)
    return dest_if_staging_needed


def clone_or_stage_re_target(raw: str, project_dir: Path) -> str:
    """Called once, at real project creation -- never on a live-check keystroke. Returns the
    (comma-joined, if more than one) path string that gets stored as session["target"]. A single
    entry stages into project_dir/re_target directly (unchanged from before multi-target support
    existed); two or more each get their own numbered subfolder
    (project_dir/re_target/1, project_dir/re_target/2, ...) so cloning/extracting one target can
    never collide with or overwrite another's files.
    """
    targets = _split_targets(raw)
    if len(targets) <= 1:
        single = targets[0] if targets else raw.strip()
        return str(_clone_or_stage_one_re_target(single, project_dir / "re_target"))

    resolved_paths = [
        str(_clone_or_stage_one_re_target(target, project_dir / "re_target" / str(i)))
        for i, target in enumerate(targets, start=1)
    ]
    return ", ".join(resolved_paths)
