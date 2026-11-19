"""Read-only filesystem inspection tools for Reverse Engineering work: list_dir, read_file, grep.

Real, confirmed gap this closes: jadx/ghidra/apktool all WRITE their output (decompiled Java, a
Ghidra export, extracted resources) to a directory on disk -- and the RE chat/triage agent had no
tool to actually LOOK at any of it. It would flail calling `ls`, `bash`, `directory`, or even
browser_navigate on a file:// path, every one of which came back "unknown tool", wasting whole
turns. These three give it a real, scoped way to walk a decompiled tree and read the source --
exactly the step between "jadx produced a crackme_jadx/ folder" and "here is the license check".

All three are strictly READ-ONLY (no create/modify/delete), native-Python (no external binary), and
return compact, bounded results so a large tree/file can never blow the model's context.
"""
from __future__ import annotations

import re
from pathlib import Path

from agent.tools.builders.re_target import identify_file_type
from agent.tools.builders.validators import validate_safe_value
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_LIST_DIR_MAX_ENTRIES = 300
_READ_FILE_MAX_BYTES = 128 * 1024
_READ_FILE_DEFAULT_MAX_LINES = 600
_GREP_MAX_MATCHES = 200
_GREP_MAX_FILES_SCANNED = 4000
_GREP_MAX_FILE_BYTES = 5 * 1024 * 1024
_GREP_LINE_CLIP = 400

# Extensions worth never trying to read/grep as text -- a compiled/packed blob just wastes the read
# and (for grep) the scan. Not exhaustive; a binary slips through only to be caught by the NUL check.
_BINARY_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".class", ".dex", ".jar", ".war", ".ear",
    ".apk", ".ipa", ".zip", ".gz", ".tgz", ".7z", ".rar", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".pdf", ".wasm", ".jsc", ".pyc", ".woff", ".woff2", ".ttf", ".mp4", ".mp3", ".wav",
})


def _looks_binary(sample: bytes) -> bool:
    return b"\x00" in sample


def run_list_dir(params: dict) -> dict:
    """Lists one directory's immediate contents with each entry's identified type -- the `ls` the RE
    agent kept reaching for and never had. Not recursive (use grep to search a whole tree)."""
    path_raw = params.get("path") or params.get("file_path")
    if not path_raw:
        return {"status": "error", "tool": "list_dir", "error": "path is required."}
    path = Path(validate_safe_value(str(path_raw).strip()))
    if not path.exists():
        return {"status": "error", "tool": "list_dir", "error": f"Path not found: {path}"}
    if not path.is_dir():
        return {"status": "error", "tool": "list_dir", "error": f"Not a directory (use read_file for a file): {path}"}

    try:
        children = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except OSError as exc:
        return {"status": "error", "tool": "list_dir", "error": f"Could not list {path}: {exc}"}

    entries = []
    for child in children[:_LIST_DIR_MAX_ENTRIES]:
        try:
            is_dir = child.is_dir()
            size = child.stat().st_size if not is_dir else None
        except OSError:
            is_dir, size = False, None
        entries.append({
            "name": child.name,
            "is_dir": is_dir,
            "type": "directory" if is_dir else identify_file_type(child),
            "size": size,
        })
    logger.debug("list_dir: %s -> %d entries (of %d)", path, len(entries), len(children))
    return {
        "status": "ok", "tool": "list_dir", "path": str(path),
        "entries": entries, "count": len(children),
        "truncated": len(children) > _LIST_DIR_MAX_ENTRIES,
    }


def run_read_file(params: dict) -> dict:
    """Reads a text file (e.g. a jadx-decompiled .java) with line/byte bounds -- the `cat` the RE
    agent never had. Refuses a binary with a pointer to radare2/hex_view instead of dumping bytes."""
    path_raw = params.get("path") or params.get("file_path")
    if not path_raw:
        return {"status": "error", "tool": "read_file", "error": "path is required."}
    path = Path(validate_safe_value(str(path_raw).strip()))
    if not path.exists():
        return {"status": "error", "tool": "read_file", "error": f"File not found: {path}"}
    if path.is_dir():
        return {"status": "error", "tool": "read_file", "error": f"Path is a directory (use list_dir): {path}"}

    try:
        raw = path.read_bytes()
    except OSError as exc:
        return {"status": "error", "tool": "read_file", "error": f"Could not read {path}: {exc}"}

    if path.suffix.lower() in _BINARY_EXTENSIONS or _looks_binary(raw[:4096]):
        return {
            "status": "error", "tool": "read_file",
            "error": f"{path.name} looks like a binary ({identify_file_type(path)}), not text. "
                     "Analyze it with radare2/ghidra/hex_view, or extract_embedded_binary / jadx first.",
        }

    text = raw.decode("utf-8", errors="replace")
    all_lines = text.splitlines()
    total_lines = len(all_lines)
    try:
        start_line = max(1, int(params.get("start_line") or 1))
    except (TypeError, ValueError):
        start_line = 1
    try:
        max_lines = int(params.get("max_lines") or _READ_FILE_DEFAULT_MAX_LINES)
    except (TypeError, ValueError):
        max_lines = _READ_FILE_DEFAULT_MAX_LINES
    max_lines = max(1, min(max_lines, _READ_FILE_DEFAULT_MAX_LINES * 4))

    window = all_lines[start_line - 1: start_line - 1 + max_lines]
    content = "\n".join(window)
    byte_truncated = False
    if len(content.encode("utf-8", errors="replace")) > _READ_FILE_MAX_BYTES:
        content = content.encode("utf-8", errors="replace")[:_READ_FILE_MAX_BYTES].decode("utf-8", errors="replace")
        byte_truncated = True

    end_line = start_line - 1 + len(window)
    logger.debug("read_file: %s lines %d-%d of %d", path, start_line, end_line, total_lines)
    return {
        "status": "ok", "tool": "read_file", "path": str(path),
        "content": content, "start_line": start_line, "end_line": end_line,
        "total_lines": total_lines,
        "truncated": byte_truncated or end_line < total_lines,
    }


def run_grep(params: dict) -> dict:
    """Searches a regex across a file or (recursively) a directory tree and returns file:line
    matches -- the single most useful move in a decompiled tree ("where is 'license'/'valid'
    checked"). Case-insensitive by default; skips binaries. Bounded in matches and files scanned."""
    pattern_raw = params.get("pattern")
    path_raw = params.get("path") or params.get("file_path")
    if not pattern_raw:
        return {"status": "error", "tool": "grep", "error": "pattern is required."}
    if not path_raw:
        return {"status": "error", "tool": "grep", "error": "path is required."}
    path = Path(validate_safe_value(str(path_raw).strip()))
    if not path.exists():
        return {"status": "error", "tool": "grep", "error": f"Path not found: {path}"}

    flags = 0 if params.get("case_sensitive") else re.IGNORECASE
    try:
        regex = re.compile(str(pattern_raw), flags)
    except re.error as exc:
        return {"status": "error", "tool": "grep", "error": f"Invalid regex {pattern_raw!r}: {exc}"}

    files = [path] if path.is_file() else [p for p in path.rglob("*") if p.is_file()]
    matches: list[dict] = []
    files_scanned = 0
    truncated = False
    for file in files:
        if files_scanned >= _GREP_MAX_FILES_SCANNED:
            truncated = True
            break
        if file.suffix.lower() in _BINARY_EXTENSIONS:
            continue
        try:
            if file.stat().st_size > _GREP_MAX_FILE_BYTES:
                continue
            raw = file.read_bytes()
        except OSError:
            continue
        if _looks_binary(raw[:2048]):
            continue
        files_scanned += 1
        for line_no, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), start=1):
            if regex.search(line):
                matches.append({"file": str(file), "line_no": line_no, "line": line.strip()[:_GREP_LINE_CLIP]})
                if len(matches) >= _GREP_MAX_MATCHES:
                    truncated = True
                    break
        if truncated:
            break

    logger.debug("grep: pattern=%r path=%s -> %d match(es) across %d file(s)", pattern_raw, path, len(matches), files_scanned)
    return {
        "status": "ok", "tool": "grep", "pattern": str(pattern_raw), "path": str(path),
        "matches": matches, "match_count": len(matches), "files_scanned": files_scanned,
        "truncated": truncated,
    }
