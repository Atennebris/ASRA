"""Git-based update checks/apply for the ASRA repo (Settings -> Updates + the startup check).

The repo is a git checkout with an origin remote; updates arrive as new commits on the tracked
upstream. This module fetches and compares, and can fast-forward pull. It never force-updates over
local work: a dirty working tree or local-only commits block an auto-apply with a clear reason (the
developer's own machine), while a clean clone (the typical end user) updates cleanly. It touches
only git -- a requirements.txt change reinstalls on the next run.sh launch via its existing hash
check, and a desktop/ (Tauri shell) change is surfaced as "rebuild/update the exe", not applied here.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from agent.utils.logger import get_logger

logger = get_logger("UPDATE")

# Repo root: agent/updater.py -> agent/ -> repo root.
_REPO = Path(__file__).resolve().parent.parent
_GIT_TIMEOUT_SECONDS = 30


@dataclass
class UpdateStatus:
    available: bool = False
    behind: int = 0
    ahead: int = 0
    dirty: bool = False
    current_sha: str = ""
    current_subject: str = ""
    remote_sha: str = ""
    changelog: list[str] = field(default_factory=list)
    deps_changed: bool = False
    shell_changed: bool = False
    upstream: str = ""
    checked: bool = False  # False until a check actually ran (startup cache starts empty)
    error: str | None = None


def _git(*args: str, timeout: int = _GIT_TIMEOUT_SECONDS) -> tuple[int, str, str]:
    """Run a git command in the repo. Returns (returncode, stdout, stderr), never raises."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=_REPO,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except Exception as exc:  # noqa: BLE001 - git missing / timeout / OS error all reported the same way
        return 1, "", str(exc)


def is_git_repo() -> bool:
    code, out, _ = _git("rev-parse", "--is-inside-work-tree")
    return code == 0 and out == "true"


def _upstream() -> str | None:
    code, out, _ = _git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    return out if code == 0 and out else None


def check_for_updates(fetch: bool = True) -> UpdateStatus:
    """Compare the local checkout against its upstream. fetch=True refreshes remote refs first
    (a network round trip); fetch=False compares against already-known refs (cheap)."""
    logger.debug("check_for_updates: fetch=%s", fetch)
    status = UpdateStatus(checked=True)

    if not is_git_repo():
        status.error = "This install is not a git checkout, so it can't self-update."
        logger.debug("check_for_updates: not a git repo")
        return status

    upstream = _upstream()
    if not upstream:
        status.error = "No upstream branch is configured (git has no remote to check)."
        logger.debug("check_for_updates: no upstream")
        return status
    status.upstream = upstream

    if fetch:
        code, _, err = _git("fetch", "--quiet")
        if code != 0:
            status.error = f"Could not reach the remote: {err or 'git fetch failed'}"
            logger.debug("check_for_updates: fetch failed: %s", err)
            # Fall through -- still report local info against whatever refs we already have.

    _, status.current_sha, _ = _git("rev-parse", "--short", "HEAD")
    _, status.current_subject, _ = _git("log", "-1", "--pretty=%s")
    _, status.remote_sha, _ = _git("rev-parse", "--short", upstream)
    _, behind_raw, _ = _git("rev-list", "--count", f"HEAD..{upstream}")
    _, ahead_raw, _ = _git("rev-list", "--count", f"{upstream}..HEAD")
    _, dirty_raw, _ = _git("status", "--porcelain")

    status.behind = int(behind_raw) if behind_raw.isdigit() else 0
    status.ahead = int(ahead_raw) if ahead_raw.isdigit() else 0
    status.dirty = bool(dirty_raw.strip())
    status.available = status.behind > 0

    if status.behind > 0:
        _, log_raw, _ = _git("log", "--pretty=%s", f"HEAD..{upstream}")
        status.changelog = [line for line in log_raw.splitlines() if line.strip()][:20]
        _, files_raw, _ = _git("diff", "--name-only", f"HEAD..{upstream}")
        files = files_raw.splitlines()
        status.deps_changed = "requirements.txt" in files
        status.shell_changed = any(f.startswith("desktop/") for f in files)

    logger.debug(
        "check_for_updates: behind=%d ahead=%d dirty=%s deps=%s shell=%s err=%s",
        status.behind, status.ahead, status.dirty, status.deps_changed, status.shell_changed, status.error,
    )
    return status


def apply_update() -> dict:
    """Fast-forward pull if it's safe to do so. Refuses on a dirty tree or local-ahead commits so
    the operator's own work is never clobbered. Returns {ok, message, notes?, deps_changed?, shell_changed?}."""
    logger.debug("apply_update: start")
    status = check_for_updates(fetch=True)

    if status.error:
        return {"ok": False, "message": status.error}
    if not status.available:
        return {"ok": True, "no_op": True, "message": "Already up to date."}
    if status.dirty:
        return {"ok": False, "message": "You have local uncommitted changes — commit or stash them before updating."}
    if status.ahead > 0:
        return {"ok": False, "message": f"You have {status.ahead} local commit(s) the remote doesn't — a fast-forward update isn't possible."}

    code, out, err = _git("pull", "--ff-only")
    if code != 0:
        logger.debug("apply_update: pull failed: %s", err or out)
        return {"ok": False, "message": f"git pull failed: {err or out}"}

    notes: list[str] = []
    if status.deps_changed:
        notes.append("Dependencies changed — they reinstall automatically on the next launch.")
    if status.shell_changed:
        notes.append("The desktop shell (desktop/) changed — rebuild the exe or update it via the shell updater.")
    logger.debug("apply_update: ok deps=%s shell=%s", status.deps_changed, status.shell_changed)
    return {
        "ok": True,
        "message": "Updated successfully. Restart ASRA to load the new version.",
        "notes": notes,
        "deps_changed": status.deps_changed,
        "shell_changed": status.shell_changed,
    }


# Startup cache: the background check at launch fills this so the Settings page and the sidebar
# indicator can read "is an update available?" without each triggering its own network fetch.
_cached_status: UpdateStatus | None = None


def cached_status() -> UpdateStatus | None:
    return _cached_status


def refresh_cache(fetch: bool = True) -> UpdateStatus:
    global _cached_status
    _cached_status = check_for_updates(fetch=fetch)
    return _cached_status
