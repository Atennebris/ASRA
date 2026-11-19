"""Move whole projects between machines/people (Projects tab -> Export / Import).

One portable carrier: a plain .zip holding a `manifest.json` plus one `projects/<folder>/` tree per
project -- the same files the project already has on disk (session.json, chat_threads/, scripts/,
and optionally the debug trail), so there is no second serialization format to drift out of sync with
sessions/store.py. A zip (not tar.gz like agent/tools/project_backup.py) because the receiver is
usually on a different OS and double-clicking a .zip works everywhere.

Design rules that matter more than the feature list:
- An archive is untrusted input. Every member path is validated (no absolute paths, no "..", no
  drive letters, no backslash tricks) before anything is written, extraction counts REAL bytes
  against a cap (declared sizes can lie), and a project is only ever unpacked into a fresh staging
  folder next to the projects directory, never straight over a live one.
- Never carry machine-bound state. Identity credentials (data/credentials/<id>.json) are not part of
  a project folder and are never exported; an imported project therefore reports no configured
  identities. OS-process handles (background_jobs) are dropped on import -- another machine's pids
  mean nothing here and must never be reconciled against this machine's unrelated processes.
- A project that was mid-run on the source machine arrives as "interrupted" (resumable), because no
  process on THIS machine is running it.
- Conflicts are the caller's explicit choice (skip / replace / copy), never a silent overwrite.
  Replacing a project that is running right now is refused.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from agent.utils.logger import get_logger
from projects.paths import resolve_projects_base_dir
from sessions import store

logger = get_logger("SESSION")

ARCHIVE_FORMAT = "asra-projects"
ARCHIVE_VERSION = 1
MANIFEST_NAME = "manifest.json"
_PROJECTS_PREFIX = "projects"

# Excluded from every export: auto-backups are a redundant, large copy of the same data and the
# receiver gets a fresh backup history of their own.
_ALWAYS_EXCLUDED_DIRS = {"backups"}
# The debug trail is huge (hundreds of MB on a long scan) and of little use to a collaborator, so it
# is opt-in.
_LOG_ENTRIES = {"debug.log", "debug-tool-calls"}

CONFLICT_SKIP = "skip"
CONFLICT_REPLACE = "replace"
CONFLICT_COPY = "copy"
CONFLICT_MODES = (CONFLICT_SKIP, CONFLICT_REPLACE, CONFLICT_COPY)

_RUNNING_STATUSES = ("processing", "awaiting_approval")
_SESSION_ID_PATTERN = re.compile(r"^usr_[0-9a-f]{6}$")
_COPY_CHUNK_BYTES = 1024 * 1024
_STAGING_PREFIX = ".import-"


class ProjectTransferError(Exception):
    """A problem with the archive or request itself, worded for the operator."""


def _max_unpacked_bytes() -> int:
    return int(os.getenv("PROJECTS_IMPORT_MAX_UNPACKED_MB", "8192")) * 1024 * 1024


def _max_archive_members() -> int:
    return int(os.getenv("PROJECTS_IMPORT_MAX_FILES", "200000"))


# ---------------------------------------------------------------- export

def _project_files(project_dir: Path, include_logs: bool) -> list[Path]:
    """Every file to ship for one project folder, relative-path order. Whole top-level entries are
    skipped by name, so an excluded directory is never even walked."""
    skipped = set(_ALWAYS_EXCLUDED_DIRS)
    if not include_logs:
        skipped |= _LOG_ENTRIES
    files: list[Path] = []
    for top in sorted(project_dir.iterdir()):
        if top.name in skipped:
            continue
        if top.is_dir():
            files.extend(sorted(p for p in top.rglob("*") if p.is_file()))
        elif top.is_file():
            files.append(top)
    return files


def _session_json_bytes(session_file: Path, include_headers: bool) -> bytes:
    raw = session_file.read_bytes()
    if include_headers:
        return raw
    data = json.loads(raw)
    data["custom_headers"] = ""
    return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")


def _exportable_summaries(session_ids: list[str] | None) -> list[dict]:
    summaries = store.list_session_summaries()
    if session_ids is None:
        return summaries
    wanted = set(session_ids)
    chosen = [s for s in summaries if s["session_id"] in wanted]
    if len(chosen) != len(wanted):
        missing = sorted(wanted - {s["session_id"] for s in chosen})
        raise ProjectTransferError(f"Unknown project id(s): {', '.join(missing)}")
    return chosen


def export_projects(
    dest_path: Path,
    session_ids: list[str] | None = None,
    include_logs: bool = False,
    include_headers: bool = False,
) -> dict:
    """Writes the archive to dest_path. session_ids=None exports every project. A legacy project
    with no folder (flat data/sessions/<id>.json) is exported as just its session file.
    Returns {"count", "names", "bytes"}."""
    summaries = _exportable_summaries(session_ids)
    if not summaries:
        raise ProjectTransferError("There are no projects to export.")
    manifest_projects = []
    with zipfile.ZipFile(dest_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
        for summary in summaries:
            session_id = summary["session_id"]
            folder = store.get_session_folder(session_id)
            project_dir = Path(folder) if folder else None
            dirname = project_dir.name if project_dir and project_dir.is_dir() else f"legacy-{session_id}"
            arc_root = f"{_PROJECTS_PREFIX}/{dirname}"
            if project_dir and project_dir.is_dir():
                for path in _project_files(project_dir, include_logs):
                    arcname = f"{arc_root}/{path.relative_to(project_dir).as_posix()}"
                    if path.parent == project_dir and path.name == store._SESSION_FILENAME:
                        archive.writestr(arcname, _session_json_bytes(path, include_headers))
                    else:
                        archive.write(path, arcname)
            else:
                data = store.load_session(session_id) or {}
                if not include_headers:
                    data["custom_headers"] = ""
                archive.writestr(f"{arc_root}/{store._SESSION_FILENAME}", json.dumps(data, indent=2, ensure_ascii=False))
            manifest_projects.append({
                "session_id": session_id,
                "name": summary.get("name", ""),
                "target": summary.get("target", ""),
                "status": summary.get("status", ""),
                "findings_count": summary.get("findings_count", 0),
                "dirname": dirname,
                "source_folder": folder or "",
            })
        manifest = {
            "format": ARCHIVE_FORMAT,
            "version": ARCHIVE_VERSION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "includes_logs": include_logs,
            "includes_headers": include_headers,
            "projects": manifest_projects,
        }
        archive.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2, ensure_ascii=False))
    size = dest_path.stat().st_size
    logger.debug(
        "project export: projects=%d logs=%s headers=%s bytes=%d",
        len(manifest_projects), include_logs, include_headers, size,
    )
    return {"count": len(manifest_projects), "names": [p["name"] for p in manifest_projects], "bytes": size}


# ---------------------------------------------------------------- import

def _read_manifest(archive: zipfile.ZipFile) -> dict:
    try:
        manifest = json.loads(archive.read(MANIFEST_NAME))
    except KeyError:
        raise ProjectTransferError("This is not an ASRA projects archive (manifest.json is missing).") from None
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ProjectTransferError("The archive's manifest.json is not valid JSON.") from None
    if not isinstance(manifest, dict) or manifest.get("format") != ARCHIVE_FORMAT:
        raise ProjectTransferError("This is not an ASRA projects archive.")
    if not isinstance(manifest.get("version"), int) or manifest["version"] > ARCHIVE_VERSION:
        raise ProjectTransferError("This archive was made by a newer ASRA -- update ASRA, then import it again.")
    projects = manifest.get("projects")
    if not isinstance(projects, list) or not projects:
        raise ProjectTransferError("The archive lists no projects.")
    return manifest


def _safe_member_parts(name: str) -> tuple[str, ...]:
    """Path parts of an archive member, or raises. Rejects everything that could land outside the
    staging folder: absolute paths, "..", drive letters, backslashes, empty/odd segments."""
    if "\\" in name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ProjectTransferError(f"Unsafe path in archive: {name!r}")
    parts = PurePosixPath(name).parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ProjectTransferError(f"Unsafe path in archive: {name!r}")
    return parts


def _validate_project_entry(entry: object) -> dict:
    if not isinstance(entry, dict):
        raise ProjectTransferError("The archive manifest is malformed.")
    session_id, dirname = entry.get("session_id"), entry.get("dirname")
    if not isinstance(session_id, str) or not _SESSION_ID_PATTERN.match(session_id):
        raise ProjectTransferError(f"The archive contains an invalid project id: {session_id!r}")
    if not isinstance(dirname, str) or len(_safe_member_parts(dirname)) != 1:
        raise ProjectTransferError(f"The archive contains an invalid project folder name: {dirname!r}")
    return entry


def _member_index(archive: zipfile.ZipFile) -> dict[str, list[zipfile.ZipInfo]]:
    """Members grouped by project dirname; validates every path and the total size/count caps."""
    infos = [info for info in archive.infolist() if not info.is_dir()]
    if len(infos) > _max_archive_members():
        raise ProjectTransferError("The archive contains too many files.")
    if sum(info.file_size for info in infos) > _max_unpacked_bytes():
        raise ProjectTransferError("The archive is larger than the configured import limit (PROJECTS_IMPORT_MAX_UNPACKED_MB).")
    grouped: dict[str, list[zipfile.ZipInfo]] = {}
    for info in infos:
        if info.filename == MANIFEST_NAME:
            continue
        parts = _safe_member_parts(info.filename)
        if parts[0] != _PROJECTS_PREFIX or len(parts) < 3:
            raise ProjectTransferError(f"Unexpected file in archive: {info.filename!r}")
        grouped.setdefault(parts[1], []).append(info)
    return grouped


def inspect_archive(source: BinaryIO) -> list[dict]:
    """What an archive holds and which of its projects already exist here -- for a preview. Writes
    nothing."""
    try:
        with zipfile.ZipFile(source) as archive:
            manifest = _read_manifest(archive)
            _member_index(archive)
            entries = [_validate_project_entry(e) for e in manifest["projects"]]
    except zipfile.BadZipFile:
        raise ProjectTransferError("The file is not a valid .zip archive.") from None
    existing = {s["session_id"] for s in store.list_session_summaries()}
    return [{**entry, "exists_here": entry["session_id"] in existing} for entry in entries]


def _unique_name(name: str, suffix: str) -> str:
    """name + suffix, numbered if even that is taken -- project names are unique case-insensitively
    (sessions.store.name_exists), so an import must not create a duplicate."""
    candidate = f"{name} ({suffix})"
    counter = 2
    while store.name_exists(candidate):
        candidate = f"{name} ({suffix} {counter})"
        counter += 1
    return candidate


def _new_session_id() -> str:
    known = {s["session_id"] for s in store.list_session_summaries()}
    while True:
        candidate = f"usr_{secrets.token_hex(3)}"
        if candidate not in known:
            return candidate


def _extract_project(archive: zipfile.ZipFile, infos: list[zipfile.ZipInfo], staging: Path, budget: list[int]) -> None:
    """Copies one project's members into staging, counting actual bytes written against the shared
    remaining budget (declared sizes in a hostile archive can be wrong)."""
    for info in infos:
        parts = _safe_member_parts(info.filename)[2:]
        target = staging.joinpath(*parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as src, target.open("wb") as dst:
            while chunk := src.read(_COPY_CHUNK_BYTES):
                budget[0] -= len(chunk)
                if budget[0] < 0:
                    raise ProjectTransferError("The archive expanded past the configured import limit.")
                dst.write(chunk)


def _rewrite_session_file(
    session_file: Path, new_id: str, new_name: str | None, source_folder: str, new_folder: Path,
) -> None:
    """Makes the unpacked session.json belong to THIS machine: new id/name when imported as a copy,
    the old absolute project path replaced by the new one (artifact paths recorded in the session
    point inside the project folder), no run state carried over."""
    text = session_file.read_text(encoding="utf-8")
    if source_folder:
        # JSON-escaped form too: a Windows-style source path appears with doubled backslashes.
        for old, new in ((source_folder, str(new_folder)), (json.dumps(source_folder)[1:-1], json.dumps(str(new_folder))[1:-1])):
            text = text.replace(old, new)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ProjectTransferError("A project's session.json in the archive is corrupted.") from exc
    if not isinstance(data, dict) or data.get("mode") == "standalone":
        raise ProjectTransferError("A project in the archive is not importable.")
    data["session_id"] = new_id
    if new_name is not None:
        data["name"] = new_name
    if data.get("status") in (*_RUNNING_STATUSES, "pending"):
        data["status"] = "interrupted"
        data.pop("resumable_from", None)
    data["background_jobs"] = {}
    data["identity_a_configured"] = False
    data["identity_b_configured"] = False
    data["extra_identities_configured"] = 0
    session_file.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _outcome(entry: dict, status: str, message: str, session_id: str | None = None) -> dict:
    return {"name": entry.get("name", ""), "source_id": entry["session_id"], "session_id": session_id, "status": status, "message": message}


def _import_one(archive: zipfile.ZipFile, entry: dict, infos: list[zipfile.ZipInfo], conflict: str, budget: list[int]) -> dict:
    source_id = entry["session_id"]
    summaries = {s["session_id"]: s for s in store.list_session_summaries()}
    exists = source_id in summaries
    if exists and conflict == CONFLICT_SKIP:
        return _outcome(entry, "skipped", "Already exists here.", source_id)
    if exists and conflict == CONFLICT_REPLACE and summaries[source_id].get("status") in _RUNNING_STATUSES:
        return _outcome(entry, "skipped", "Running right now -- stop it first, then import again.", source_id)
    if not any(Path(info.filename).name == store._SESSION_FILENAME and len(PurePosixPath(info.filename).parts) == 3 for info in infos):
        return _outcome(entry, "error", "No session.json in this project's folder.")

    new_id = _new_session_id() if exists and conflict == CONFLICT_COPY else source_id
    name = entry.get("name") or entry.get("target") or "Imported project"
    if exists and conflict == CONFLICT_COPY:
        name = _unique_name(name, "copy")
    elif not exists and store.name_exists(name):
        name = _unique_name(name, "imported")

    base_dir = resolve_projects_base_dir()
    base_dir.mkdir(parents=True, exist_ok=True)
    final_dir = base_dir / f"{store._sanitize_folder_name(name)}-{new_id}"
    staging = base_dir / f"{_STAGING_PREFIX}{secrets.token_hex(4)}"
    try:
        _extract_project(archive, infos, staging, budget)
        _rewrite_session_file(staging / store._SESSION_FILENAME, new_id, name, entry.get("source_folder", ""), final_dir)
        if exists and conflict == CONFLICT_REPLACE:
            store.delete_session(source_id)
        if final_dir.exists():
            raise ProjectTransferError(f"Target folder already exists: {final_dir.name}")
        staging.rename(final_dir)
        store.adopt_project_folder(new_id, final_dir)
    except (OSError, ProjectTransferError) as exc:
        shutil.rmtree(staging, ignore_errors=True)
        logger.debug("project import: failed source_id=%s (%s)", source_id, exc)
        return _outcome(entry, "error", str(exc))
    status = "replaced" if exists and conflict == CONFLICT_REPLACE else ("copied" if exists else "imported")
    logger.debug("project import: %s source_id=%s -> id=%s folder=%s", status, source_id, new_id, final_dir)
    return _outcome(entry, status, "Done.", new_id)


def import_archive(source: BinaryIO, conflict: str = CONFLICT_SKIP) -> list[dict]:
    """Imports every project in the archive; one project failing never stops the rest. Returns one
    outcome per project: {name, source_id, session_id, status, message} with status one of
    imported / replaced / copied / skipped / error."""
    if conflict not in CONFLICT_MODES:
        raise ProjectTransferError(f"Unknown conflict mode: {conflict!r}")
    try:
        with zipfile.ZipFile(source) as archive:
            manifest = _read_manifest(archive)
            grouped = _member_index(archive)
            entries = [_validate_project_entry(e) for e in manifest["projects"]]
            budget = [_max_unpacked_bytes()]
            logger.debug("project import: archive projects=%d conflict=%s", len(entries), conflict)
            return [_import_one(archive, e, grouped.get(e["dirname"], []), conflict, budget) for e in entries]
    except zipfile.BadZipFile:
        raise ProjectTransferError("The file is not a valid .zip archive.") from None
