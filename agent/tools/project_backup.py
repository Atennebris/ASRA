"""Manual + optional-auto tar.gz snapshots of one project's own folder (session.json, debug.log,
findings, screenshots -- everything sessions/store.py's get_session_folder points at). Real
engagement data with no protection today against a crash mid-write, a bad tool run, or an operator
overwriting the wrong thing -- there was no backup/restore anywhere in this project before this.

Deliberately per-project, not a whole-"ASRA Projects"-directory backup: an operator restoring after
a bad run wants THIS engagement's last-good state back, not to roll every other project back too.

Auto-backup (auto_backup_worker_loop) is a slow background poll, same shape and same "local
single-operator tool" reasoning as main.py's own _fleet_worker_loop -- deliberately NOT hooked into
agent/core.py's own save_session/reload-merge-save chain (that code path already carries several
"don't touch this casually" comments of its own). It just periodically notices "this project's
session.json changed since its own last backup" and snapshots it, entirely from the outside --
never on the hot per-turn save path, so it can never slow a running session down.
"""
from __future__ import annotations

import asyncio
import os
import tarfile
import time
from pathlib import Path

from agent.utils.logger import get_logger
from sessions.store import get_session_folder, list_session_summaries

logger = get_logger("SESSION")

_BACKUP_DIRNAME = "backups"
_SESSION_FILENAME = "session.json"
_MAX_BACKUPS = int(os.getenv("PROJECT_BACKUP_MAX_COUNT", "5"))
_AUTO_BACKUP_ENABLED = os.getenv("PROJECT_AUTO_BACKUP_ENABLED", "true").strip().lower() == "true"
_AUTO_BACKUP_INTERVAL_SECONDS = int(os.getenv("PROJECT_AUTO_BACKUP_INTERVAL_SECONDS", "3600"))


def _project_dir(session_id: str) -> Path | None:
    folder = get_session_folder(session_id)
    return Path(folder) if folder else None


def _backup_dir(project_dir: Path) -> Path:
    backup_dir = project_dir / _BACKUP_DIRNAME
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir


def get_max_backup_count() -> int:
    """Public accessor for _MAX_BACKUPS -- templates/partials/project_backups.html needs the real,
    possibly-operator-overridden (PROJECT_BACKUP_MAX_COUNT) rotation count to explain to the operator
    why only the newest few backups are ever listed, without hardcoding "5" into the template."""
    return _MAX_BACKUPS


def list_backups(session_id: str) -> list[dict]:
    """Newest first -- what the UI actually wants to show."""
    project_dir = _project_dir(session_id)
    if project_dir is None or not project_dir.is_dir():
        return []
    backup_dir = _backup_dir(project_dir)
    entries = [
        {"name": path.name, "size_bytes": path.stat().st_size, "created_at": path.stat().st_mtime}
        for path in backup_dir.glob("backup-*.tar.gz")
    ]
    entries.sort(key=lambda e: e["created_at"], reverse=True)
    return entries


def _cleanup_old_backups(backup_dir: Path, max_count: int) -> None:
    backups = sorted(backup_dir.glob("backup-*.tar.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in backups[max_count:]:
        stale.unlink(missing_ok=True)
        logger.debug("project_backup: rotated out old backup=%s", stale)


def create_backup(session_id: str) -> dict:
    """tar.gz snapshot of the whole project folder, excluding its own backups/ subdir (no
    snapshots-of-snapshots). Rotates out anything beyond PROJECT_BACKUP_MAX_COUNT right after."""
    project_dir = _project_dir(session_id)
    if project_dir is None or not project_dir.is_dir():
        return {"status": "error", "message": "Project folder not found."}
    backup_dir = _backup_dir(project_dir)
    # Millisecond suffix, not just the second-resolution strftime -- confirmed live: two creates
    # inside the same second (a fast double-click on "Backup now", or auto-backup ticking right
    # after a manual one) otherwise produce the SAME filename, so the second one silently
    # overwrites the first archive instead of creating a new one, one real backup just vanishing.
    name = f"backup-{time.strftime('%Y%m%d-%H%M%S')}-{int(time.time() * 1000) % 1000:03d}.tar.gz"
    archive_path = backup_dir / name
    try:
        with tarfile.open(archive_path, "w:gz") as tar:
            for item in project_dir.iterdir():
                if item == backup_dir:
                    continue
                tar.add(item, arcname=item.name)
    except OSError as exc:
        logger.debug("project_backup: create failed session_id=%s (%s)", session_id, exc)
        return {"status": "error", "message": str(exc)}
    _cleanup_old_backups(backup_dir, _MAX_BACKUPS)
    size_bytes = archive_path.stat().st_size
    logger.debug("project_backup: created session_id=%s name=%s size=%s", session_id, name, size_bytes)
    return {"status": "ok", "name": name, "size_bytes": size_bytes}


def restore_backup(session_id: str, backup_name: str) -> dict:
    """Extracts a backup back OVER the live project folder -- destructive, operator-confirmed in the
    UI before this is ever called (same warn-then-act shape as the Tools tab's arsenal install
    confirm step). `filter="data"` (stdlib, Python 3.12+) refuses path traversal/absolute-path
    entries -- defense in depth even though these archives are always our own. Never deletes a file
    absent from the archive; a file added since the backup was taken is left alone, ordinary
    tar-extract-over-directory semantics."""
    project_dir = _project_dir(session_id)
    if project_dir is None:
        return {"status": "error", "message": "Project folder not found."}
    archive_path = _backup_dir(project_dir) / backup_name
    if not archive_path.is_file():
        return {"status": "error", "message": f"Backup not found: {backup_name}"}
    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(project_dir, filter="data")
    except (OSError, tarfile.TarError) as exc:
        logger.debug("project_backup: restore failed session_id=%s name=%s (%s)", session_id, backup_name, exc)
        return {"status": "error", "message": str(exc)}
    logger.debug("project_backup: restored session_id=%s name=%s", session_id, backup_name)
    return {"status": "ok"}


def delete_backup(session_id: str, backup_name: str) -> dict:
    project_dir = _project_dir(session_id)
    if project_dir is None:
        return {"status": "error", "message": "Project folder not found."}
    archive_path = _backup_dir(project_dir) / backup_name
    archive_path.unlink(missing_ok=True)
    logger.debug("project_backup: deleted session_id=%s name=%s", session_id, backup_name)
    return {"status": "ok"}


def _needs_auto_backup(project_dir: Path, backup_dir: Path) -> bool:
    session_file = project_dir / _SESSION_FILENAME
    if not session_file.is_file():
        return False
    latest_backup = max(backup_dir.glob("backup-*.tar.gz"), key=lambda p: p.stat().st_mtime, default=None)
    if latest_backup is None:
        return True
    return session_file.stat().st_mtime > latest_backup.stat().st_mtime


async def auto_backup_worker_loop() -> None:
    """Runs for the server's lifetime (started in main.py's _lifespan, cancelled on shutdown, same
    shape as _fleet_worker_loop) -- periodically snapshots any project whose session.json changed
    since its own last backup. Off entirely when PROJECT_AUTO_BACKUP_ENABLED=false; the manual
    'Backup now' button works either way, this only controls the unattended timer."""
    if not _AUTO_BACKUP_ENABLED:
        logger.debug("project_backup: auto-backup disabled (PROJECT_AUTO_BACKUP_ENABLED=false)")
        return
    while True:
        try:
            for summary in list_session_summaries():
                session_id = summary.get("session_id")
                folder = summary.get("folder")
                if not session_id or not folder:
                    continue
                project_dir = Path(folder)
                if not project_dir.is_dir():
                    continue
                backup_dir = _backup_dir(project_dir)
                if _needs_auto_backup(project_dir, backup_dir):
                    # to_thread, not a direct call -- confirmed live: with many real projects on
                    # disk, calling the blocking tar/gzip create_backup() straight from this
                    # coroutine pins the event loop in uninterruptible disk I/O for the whole first
                    # pass (tens of seconds here), during which the server answers NO requests at
                    # all, not even "/". Same fix shape main.py's own _lifespan already uses for
                    # its other slow startup I/O (asyncio.to_thread(updater.refresh_cache, ...)).
                    result = await asyncio.to_thread(create_backup, session_id)
                    logger.debug("project_backup: auto-backup session_id=%s result=%s",
                                 session_id, result.get("status"))
        except Exception as exc:  # noqa: BLE001 -- one bad project folder must never kill this loop for every other project
            logger.debug("project_backup: auto-backup pass failed (%s)", exc)
        await asyncio.sleep(_AUTO_BACKUP_INTERVAL_SECONDS)
