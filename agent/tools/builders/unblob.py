"""Native (tier-1) runner for unblob -- a modern firmware/container extractor, complementing
binwalk.py (byte-signature carving) rather than replacing it: unblob chains more handlers (7z,
squashfs, cpio, gzip, ubi, jefferson/JFFS2, ...) and recurses automatically into what it extracts
from each identified chunk.

Tier-1, not tier-2 (build_command/parse_output) -- same reason agent/tools/builders/ghidra.py is
tier-1: confirmed live, unblob's own exit code is NOT a reliable "found something" signal (a plain
non-container text file still exits 0, with an empty-but-real "no containers identified" report --
the exact same exit code a genuine successful extraction gets). The real, structured signal is its
own `--report <path>` JSON file, which the generic tier-2 _OUTPUT_PARSERS pipeline (agent/core.py)
has no way to read (its parser signature only ever receives stdout text, never a file path).

Unlike Ghidra's own disposable per-call JSON (pure IPC, no standalone value once parsed), nothing
here is deleted after a run: both the extracted files AND unblob's own report.json are real,
reusable artifacts -- a model following up with radare2/strings/binwalk on one of the extracted
files needs those files to still exist on disk, and the report (offsets, hashes, chunk types) is
itself worth keeping for later reference.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.tools.custom_tools_root import resolve_via_custom_root
from agent.tools.re_evidence import evidence_result
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Deliberately NOT resolve_global_app_dir() (every other tool's own fixed-path convention in this
# project, resolving to the Windows-visible Documents folder under WSL2) -- confirmed live this
# session that unblob's own extraction (Landlock sandboxing, confirmed via its own --no-sandbox
# flag existing at all) fails outright on that drvfs-mounted path: a real "Unhandled exception
# during unblob", no report file produced, even with -p 1 (so not a parallelism issue -- the SAME
# drvfs concurrent-file-I/O quirk this project's own setup_tools.sh/install_radare2 already
# documents for building on /mnt/c, just a different tool tripping over it). A genuinely native
# WSL2 filesystem path is required for unblob specifically. /tmp is accepted here (not resolve_
# global_app_dir()'s usual guarantee of a FIXED path) because this directory's own lifetime need
# is short -- a model extracts, then immediately follows up with another tool call against one of
# the extracted files in the SAME session, unlike Ghidra's own project cache (agent/tools/builders/
# ghidra.py), which specifically needs to survive and be reused ACROSS calls to avoid repeated
# full-analysis cost. Confirmed live this session that /tmp itself can be cleared mid-session on
# this machine -- acceptable here since nothing relies on an unblob extraction surviving that long.
_UNBLOB_RUNS_DIR = Path(os.getenv("UNBLOB_RUNS_DIR", "/tmp/asra-unblob-runs"))

# Same practical ceiling radare2.py's own _MAX_LIST_ENTRIES applies -- an honest total count
# survives even when the list itself is capped, never a silent truncation.
_MAX_LIST_ENTRIES = 50

# Generous by design -- a deeply nested firmware image (unblob's own default recursion depth is
# 10) can take a while to fully unpack; a plain config file or small archive finishes in seconds.
_EXTRACT_TIMEOUT_SECONDS = int(os.getenv("UNBLOB_EXTRACT_TIMEOUT_SECONDS", "300"))


def _resolve_unblob() -> str | None:
    # Same {TOOL}_PATH-then-PATH-then-custom-root convention as agent/tools/builders/ghidra.py's
    # own _resolve_analyzeheadless -- kept independent of runner.py's tier-2-only
    # _resolve_executable since this tool dispatches its own subprocess directly.
    override = os.getenv("UNBLOB_PATH")
    if override:
        return override if shutil.which(override) or os.path.isfile(override) else None
    found_on_path = shutil.which("unblob")
    if found_on_path:
        return found_on_path
    return resolve_via_custom_root("unblob")


def unblob_available() -> bool:
    """ToolSpec.availability_check -- same reasoning as ghidra_available: a tier-1 native tool
    whose real dependency is an external binary the Python code doesn't itself carry must not
    report "always installed" the way an ordinary tier-1 tool would."""
    return _resolve_unblob() is not None


def _extract_chunks(raw_report: object) -> list[dict]:
    """unblob's own --report JSON is a list of {task, reports, subtasks} objects, one per
    identified blob/container at every recursion depth -- a ChunkReport entry inside `reports`
    means unblob recognized a real container format there (its own handler_name, byte offsets).
    Flattened here into one simple list rather than the original nested task/subtask tree, which
    carries unblob's own internal recursion bookkeeping a reverse engineer doesn't actually need."""
    chunks: list[dict] = []
    if not isinstance(raw_report, list):
        return chunks
    for task in raw_report:
        if not isinstance(task, dict):
            continue
        source_path = (task.get("task") or {}).get("path")
        for rep in task.get("reports", []):
            if isinstance(rep, dict) and rep.get("__typename__") == "ChunkReport":
                chunks.append({
                    "source_path": source_path,
                    "handler": rep.get("handler_name"),
                    "start_offset": rep.get("start_offset"),
                    "end_offset": rep.get("end_offset"),
                    "size": rep.get("size"),
                    "is_encrypted": rep.get("is_encrypted"),
                })
    return chunks


def run_unblob(params: dict) -> dict:
    file_path = validate_safe_value(str(params["file_path"]).strip())
    path_obj = Path(file_path)
    if path_obj.is_dir():
        raise ValueError(f"file_path is a directory, not a file: {file_path!r}")
    if not path_obj.is_file():
        raise ValueError(f"file_path does not exist: {file_path!r}")

    executable = _resolve_unblob()
    if executable is None:
        return {"status": "tool_unavailable", "tool": "unblob"}

    # See _UNBLOB_RUNS_DIR's own module-level comment for why this is /tmp-rooted rather than
    # this project's usual resolve_global_app_dir() convention.
    run_id = uuid.uuid4().hex[:12]
    run_dir = _UNBLOB_RUNS_DIR / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    extract_dir = run_dir / "extracted"
    report_path = run_dir / "report.json"

    command = [executable, "-e", str(extract_dir), "--report", str(report_path), "--force", file_path]

    logger.debug("unblob: dispatching file_path=%s extract_dir=%s", file_path, extract_dir)

    try:
        proc = subprocess.run(
            command, capture_output=True, text=True, timeout=_EXTRACT_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        logger.debug("unblob: timed out after %ss, command=%s", _EXTRACT_TIMEOUT_SECONDS, command)
        return {"status": "timeout", "tool": "unblob", "command": command}

    if not report_path.exists():
        error = (proc.stderr or proc.stdout or "").strip()
        logger.debug("unblob: dispatch failed exit_code=%s stderr_preview=%s", proc.returncode, error[:500])
        return {
            "status": "error",
            "tool": "unblob",
            "exit_code": proc.returncode,
            "error": error[-2000:] if error else f"unblob exited {proc.returncode} with no report file",
        }

    try:
        raw_report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("unblob: could not read/parse its own report file %s (%s)", report_path, exc)
        return {"status": "error", "tool": "unblob", "error": f"could not read unblob's own report file: {exc}"}

    all_chunks = _extract_chunks(raw_report)
    total_chunks = len(all_chunks)
    chunks = all_chunks[:_MAX_LIST_ENTRIES]

    extracted_files: list[str] = []
    total_files = 0
    if extract_dir.is_dir():
        for entry in sorted(extract_dir.rglob("*")):
            if entry.is_file():
                total_files += 1
                if total_files <= _MAX_LIST_ENTRIES:
                    extracted_files.append(str(entry))

    unknown: dict[str, str] = {}
    if total_chunks > _MAX_LIST_ENTRIES:
        unknown["chunks_beyond_limit"] = f"{total_chunks - _MAX_LIST_ENTRIES} more identified chunks exist but were not listed (cap of {_MAX_LIST_ENTRIES})"
    if total_files > _MAX_LIST_ENTRIES:
        unknown["files_beyond_limit"] = f"{total_files - _MAX_LIST_ENTRIES} more extracted files exist but were not listed (cap of {_MAX_LIST_ENTRIES}) -- browse {extract_dir} directly for the rest"

    observed = {
        "extract_dir": str(extract_dir),
        "report_path": str(report_path),
        "identified_chunks": chunks,
        "total_identified_chunks": total_chunks,
        "extracted_files": extracted_files,
        "total_extracted_files": total_files,
    }

    logger.debug("unblob: finished status=ok total_chunks=%d total_files=%d", total_chunks, total_files)
    return {"status": "ok", "tool": "unblob", **evidence_result(observed, unknown=unknown)}
