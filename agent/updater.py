"""Project code update checks/apply for the ASRA install (Settings -> Updates + the startup check).

Two install shapes exist, and this module covers BOTH so every operator sees an update signal
regardless of how ASRA got onto their machine, not just the git-clone developer case:

- A real git checkout with an origin remote (a developer's `git clone`, or an exe-only operator
  whose bootstrap happened to produce one) -- updates arrive as new commits on the tracked
  upstream. Fetches and compares, and can fast-forward pull. Never force-updates over local work: a
  dirty working tree or local-only commits block an auto-apply with a clear reason, while a clean
  clone (the typical end user) updates cleanly.
- A non-git install with no `.git` at all -- the exe-only "Choose folder & install" bootstrap flow
  (desktop/src-tauri/src/main.rs's bootstrap_full_project) downloads a GitHub source-archive tarball,
  which never contains `.git` metadata (that's how GitHub's own archive endpoint works, not a choice
  made here), so `git fetch`/`git pull` simply cannot apply to it. The ONLY way such an install can
  ever learn it's behind is the version marker bootstrap writes next to it (see _VERSION_MARKER
  below) compared against GitHub Releases' latest tag (agent/update_release_info.py, the same
  lookup agent/desktop_update.py uses for the exe binary itself) -- and the only way to apply an
  update to it is the same tarball-download-and-overwrite bootstrap already used for the first
  install, just re-run in place instead of into a fresh folder.

Either way this module touches only the PROJECT's own files -- a requirements.txt change reinstalls
on the next run.sh launch via its existing hash check, and a desktop/ (Tauri shell) change is
surfaced as "rebuild/update the exe", not applied here (see agent/desktop_update.py for that).
"""
from __future__ import annotations

import io
import subprocess
import tarfile
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from dotenv import dotenv_values, find_dotenv, set_key

from agent.update_release_info import fetch_latest_release, is_version_behind
from agent.utils.logger import get_logger

logger = get_logger("UPDATE")

# Repo root: agent/updater.py -> agent/ -> repo root.
_REPO = Path(__file__).resolve().parent.parent
_GIT_TIMEOUT_SECONDS = 30
_DOWNLOAD_TIMEOUT_SECONDS = 120.0

# Written by bootstrap_full_project (main.rs) right after it extracts the tarball -- the installed
# version string (e.g. "0.3.0"), or "0.0.0" if that bootstrap had to fall back to main's floating
# HEAD (no matching tag existed yet), which always compares as "behind" so that install still shows
# an update signal rather than silently never checking again. Absent entirely for a real git clone.
_VERSION_MARKER = _REPO / ".asra_installed_version"

# Whether main.py's startup hook runs the quiet background check at all (Settings -> Updates'
# "Check for updates at startup" switch). Same .env-backed convention as agent/intro_settings.py --
# read once at process startup, before any JSON-store-backed Settings value would normally be
# consulted, so .env (already the one config surface every launch path agrees on) is simpler here
# than introducing a second on-disk store for a single boolean. Defaults to true when absent, same
# as the existing env var's own .env.example comment already promises.
_UPDATE_CHECK_ON_STARTUP_VAR = "UPDATE_CHECK_ON_STARTUP"
_ENV_PATH = find_dotenv(usecwd=True) or str(_REPO / ".env")


def load_update_check_on_startup() -> bool:
    raw = dotenv_values(_ENV_PATH).get(_UPDATE_CHECK_ON_STARTUP_VAR)
    if raw is None:
        return True
    return raw.strip().lower() in ("true", "1", "yes", "on")


def save_update_check_on_startup(enabled: bool) -> None:
    set_key(_ENV_PATH, _UPDATE_CHECK_ON_STARTUP_VAR, "true" if enabled else "false")
    logger.debug("save_update_check_on_startup: %s=%s", _UPDATE_CHECK_ON_STARTUP_VAR, enabled)


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
    # "git" (the normal path, ahead/behind/dirty all meaningful) or "release" (non-git install,
    # compared against GitHub Releases' latest tag instead -- ahead/dirty/upstream never apply).
    install_kind: str = "git"


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


def _check_release_based_update() -> UpdateStatus:
    """The non-git fallback: compares _VERSION_MARKER's installed version against GitHub
    Releases' latest tag. Only reached when there's no .git at all -- see is_git_repo() in the
    caller below."""
    status = UpdateStatus(checked=True, install_kind="release")
    installed = _VERSION_MARKER.read_text(encoding="utf-8").strip()
    if not installed:
        status.error = "Version marker file is empty -- can't determine the installed version."
        return status
    status.current_sha = installed

    release = fetch_latest_release()
    if release is None:
        status.error = "Could not reach GitHub Releases."
        logger.debug("_check_release_based_update: releases/latest fetch failed")
        return status

    latest = str(release.get("tag_name", "")).lstrip("v")
    status.remote_sha = latest
    status.available = is_version_behind(installed, latest)
    if status.available:
        # No meaningful "N commits behind" count exists for a tagged release -- 1 keeps the
        # existing "{behind} update(s) available" template wording singular/sensible rather than
        # showing a misleading "0 updates available".
        status.behind = 1
        body = str(release.get("body", "")).strip()
        status.changelog = [line for line in body.splitlines() if line.strip()][:20]
    logger.debug(
        "_check_release_based_update: installed=%s latest=%s available=%s",
        installed, latest, status.available,
    )
    return status


def check_for_updates(fetch: bool = True) -> UpdateStatus:
    """Compare the local checkout against its upstream. fetch=True refreshes remote refs first
    (a network round trip); fetch=False compares against already-known refs (cheap)."""
    logger.debug("check_for_updates: fetch=%s", fetch)
    status = UpdateStatus(checked=True)

    if not is_git_repo():
        if _VERSION_MARKER.is_file():
            return _check_release_based_update()
        status.error = "This install is not a git checkout, so it can't self-update."
        logger.debug("check_for_updates: not a git repo and no version marker")
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


def _download_release_tarball(version: str) -> bytes:
    """Mirrors main.rs's own download_and_extract_repo fallback order (exact tag first, then
    main's floating HEAD) so a non-git install's re-update behaves the same way its original
    bootstrap did -- just via httpx instead of curl, since this runs from the already-running
    Python backend, not the Rust shell."""
    urls = [
        f"https://github.com/Atennebris/ASRA/archive/refs/tags/v{version}.tar.gz",
        "https://github.com/Atennebris/ASRA/archive/refs/heads/main.tar.gz",
    ]
    last_error: Exception | None = None
    with httpx.Client(timeout=_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client:
        for url in urls:
            try:
                resp = client.get(url)
                resp.raise_for_status()
                return resp.content
            except Exception as exc:  # noqa: BLE001 - try the next URL, report the last failure
                last_error = exc
    raise RuntimeError(f"could not download the ASRA source archive: {last_error}")


def _apply_release_based_update(status: UpdateStatus) -> dict:
    """Re-runs the same tarball download the original bootstrap (main.rs's
    download_and_extract_repo) did for the first install, just overwriting the existing project
    folder in place instead of a fresh one. Safe to overwrite .py/template files on disk while the
    process using them keeps running -- Linux doesn't lock a file that's merely been read/imported
    (unlike the compiled exe binary itself, which is why THAT update goes through main.rs's
    rename-swap trick instead); the already-imported modules simply stay as they were in memory
    until the operator restarts ASRA, exactly as the "Restart ASRA to load the new version" message
    below already tells them to do."""
    try:
        archive_bytes = _download_release_tarball(status.remote_sha)
    except Exception as exc:  # noqa: BLE001 - network/HTTP errors, same shape as the git path
        logger.debug("_apply_release_based_update: download failed: %s", exc)
        return {"ok": False, "message": f"Download failed: {exc}"}

    try:
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            for member in tar.getmembers():
                # GitHub's archive tarball wraps everything in one top-level "ASRA-<sha>/" folder
                # -- strip it, same as main.rs's own `tar --strip-components=1`, so files land
                # directly at the project root instead of one level too deep.
                parts = member.name.split("/", 1)
                if len(parts) != 2 or not parts[1]:
                    continue
                member.name = parts[1]
                tar.extract(member, path=_REPO, filter="data")
    except Exception as exc:  # noqa: BLE001 - corrupt archive / disk error, same reporting shape
        logger.debug("_apply_release_based_update: extract failed: %s", exc)
        return {"ok": False, "message": f"Extracting the update failed: {exc}"}

    _VERSION_MARKER.write_text(status.remote_sha, encoding="utf-8")
    logger.debug("_apply_release_based_update: ok, now at %s", status.remote_sha)
    return {
        "ok": True,
        "message": "Updated successfully. Restart ASRA to load the new version.",
        "notes": [],
        "deps_changed": True,  # unknown which files changed in a tarball overwrite -- always safe to reinstall
        "shell_changed": False,
    }


def apply_update() -> dict:
    """Fast-forward pull if it's safe to do so (git installs), or re-download-and-overwrite the
    release tarball (non-git installs). Refuses on a dirty tree or local-ahead commits so the
    operator's own work is never clobbered. Returns {ok, message, notes?, deps_changed?, shell_changed?}."""
    logger.debug("apply_update: start")
    status = check_for_updates(fetch=True)

    if status.error:
        return {"ok": False, "message": status.error}
    if not status.available:
        return {"ok": True, "no_op": True, "message": "Already up to date."}

    if status.install_kind == "release":
        return _apply_release_based_update(status)

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
