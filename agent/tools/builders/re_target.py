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

import json
import re
import shutil
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


# --- detect_target_shape: deterministic, zero-LLM-cost target classification -------------------
#
# Real, confirmed gap this closes: before this, session["target_profile"] stayed empty from
# project creation all the way until the model's own triage pass got around to calling radare2 and
# then record_target_profile -- every single pass re-derived "what even is this file" from
# scratch, at LLM-reasoning cost, even on the most common/obvious shapes. RE_TRIAGE_PROMPT's own
# Step 1 ("identify the target shape") is a ~100-line prose decision tree a model has to correctly
# parse and apply fresh every run; this is that same decision tree as actual code, run once,
# synchronously, at project creation (main.py's start_re), with zero LLM involvement.

# The magic-byte signatures that make a file a compiled executable a binary tool (radare2/gdb/
# qiling_emulate) can actually load -- PE ("MZ"), ELF, and the four Mach-O variants (32/64-bit,
# each in either endianness). Historically lived only in agent/core.py's own
# _re_directory_target_hint; moved here as the one shared source of truth once a second caller
# (detect_target_shape below) needed the exact same sniff -- core.py now imports it back.
_EXECUTABLE_MAGIC_PREFIXES = (
    b"MZ",                       # PE / DOS (.exe/.dll)
    b"\x7fELF",                  # ELF
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",  # Mach-O 32/64 big-endian
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",  # Mach-O 32/64 little-endian
)

# A long bare hex string (no .sol anywhere) -- RE_TRIAGE_PROMPT's own "smart contract with NO
# source" bullet. 64 is deliberately generous (shortest real EVM bytecode runs well past this) --
# only meant to rule out short/incidental hex-looking text, not a tight format check.
_EVM_BYTECODE_RE = re.compile(r"^(0x)?[0-9a-fA-F]{64,}$")

# A large, undifferentiated blob that isn't itself a recognized executable -- RE_TRIAGE_PROMPT's
# own "firmware dump/bootloader/update-package blob... often much bigger than a normal binary"
# bullet, necessarily a heuristic (there is no magic byte for "this is firmware") rather than a
# precise format check; anything smaller just reports as an honestly-unclassified binary blob
# instead of guessing.
_FIRMWARE_BLOB_MIN_SIZE_BYTES = 5 * 1024 * 1024

_SOURCE_CODE_EXTENSIONS = frozenset({
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".java", ".kt", ".rb", ".php", ".cs", ".swift", ".m", ".mm",
})

# Compiled JVM bytecode artifacts -- a .jar/.war/.ear is a ZIP of .class files (PK magic, NOT a
# radare2-loadable native executable), a .dex is Dalvik, a .class is a single compiled unit. jadx
# decompiles every one of these straight to readable Java, so they get their own shape rather than
# falling through to "unknown blob" (which is exactly how a crackme.jar used to read as unsupported).
_JVM_ARTIFACT_EXTENSIONS = frozenset({".jar", ".war", ".ear", ".dex", ".class"})

# First-bytes signatures for best-effort identification of ANY file in a directory listing -- a
# deliberate superset of _EXECUTABLE_MAGIC_PREFIXES (which stays the tight "can radare2 load this"
# check). The point is that the chat/triage can at least NAME what each file is, never go blind on a
# folder just because an extension is unfamiliar.
_ZIP_MAGIC = b"PK\x03\x04"
_JAVA_CLASS_MAGIC = b"\xca\xfe\xba\xbe"   # also Mach-O universal ("fat") -- extension disambiguates
_DEX_MAGIC = b"dex\n"
_PDF_MAGIC = b"%PDF"
_GZIP_MAGIC = b"\x1f\x8b"
_WASM_MAGIC = b"\x00asm"

# Extension -> short human label, for identify_file_type below. Not exhaustive and not meant to be:
# a best-effort "what is this" so an operator/model sees "crackme.jar (Java/JVM archive)" instead of
# a bare filename. Anything not here falls back to a magic-byte sniff, then to text-vs-binary.
_FILE_TYPE_BY_EXTENSION = {
    ".apk": "Android APK", ".ipa": "iOS IPA",
    ".jar": "Java/JVM archive (JAR)", ".war": "Java web archive (WAR)",
    ".ear": "Java enterprise archive (EAR)", ".dex": "Dalvik DEX bytecode",
    ".class": "Java class bytecode",
    ".sol": "Solidity source", ".wasm": "WebAssembly module", ".jsc": "Node/V8 bytecode",
    ".asar": "Electron asar archive",
    ".exe": "Windows PE executable", ".dll": "Windows DLL",
    ".so": "ELF shared library", ".dylib": "Mach-O shared library",
    ".pdf": "PDF document",
    ".zip": "ZIP archive", ".tar": "tar archive", ".gz": "gzip archive", ".tgz": "gzip archive",
    ".7z": "7-Zip archive", ".rar": "RAR archive",
    ".txt": "text", ".md": "text", ".log": "text",
    ".json": "JSON", ".xml": "XML", ".yml": "YAML", ".yaml": "YAML",
    ".ini": "config", ".cfg": "config", ".conf": "config", ".toml": "config",
}

_DIRECTORY_SCAN_MAX_ENTRIES = 500

_RADARE2_INFO_TIMEOUT_SECONDS = 15

# One entry per shape key detect_target_shape can return -- mirrors RE_TRIAGE_PROMPT's own Step
# 1/Step 2 per-shape tool guidance as actual data instead of prose a model has to extract from a
# ~360-line system prompt on every single pass. Does NOT replace that prose (still the deeper
# "how to actually use these tools, what order, what judgment calls" reference for ambiguous/
# multi-shape cases) -- this is the fast, zero-ambiguity "what is this and where do I start" front
# door, surfaced via agent/core.py's _target_shape_task_addendum. A shape with no entry here
# (unknown/unknown_directory/unknown_binary_blob/multi_target) deliberately falls back to the
# model's own judgment, same as today.
RE_TARGET_TOOLSETS: dict[str, dict] = {
    "android_apk": {
        "primary_tools": ["apktool", "jadx"],
        "also_available": ["adb", "frida_trace", "semgrep"],
        "note": "adb only helps once a real device/emulator is connected -- an empty mode=\"devices\" list is valid and just means none is.",
    },
    "ios_ipa": {
        "primary_tools": ["ipa_extract"],
        "also_available": ["radare2", "gdb", "frida_trace"],
        "note": "Extract first -- then treat the recovered Mach-O exactly like a plain binary.",
    },
    "dotnet_assembly": {
        "primary_tools": ["ilspycmd"],
        "also_available": ["native_binary_metadata", "radare2"],
        "note": "If ilspycmd's own listing comes back empty, this is likely AOT-published -- native_binary_metadata mode=\"dotnet_nativeaot\" reads its embedded ReadyToRun directory instead.",
    },
    "electron_app": {
        "primary_tools": ["bundle_runtime_graph", "js_bundle_graph", "electron_surface"],
        "also_available": [],
        "note": "Run bundle_runtime_graph FIRST for orientation before reading any bundled JS directly.",
    },
    "node_bytecode": {
        "primary_tools": ["radare2", "frida_trace"],
        "also_available": [],
        "note": "Bytenode-compiled (.jsc) -- not decompilable here; strings plus a live frida_trace hook recover real behavior instead.",
    },
    "wasm_module": {
        "primary_tools": ["wasm_analyze"],
        "also_available": [],
        "note": "Not radare2 -- WASM is a stack-machine bytecode format it doesn't understand.",
    },
    "firmware_blob": {
        "primary_tools": ["binwalk"],
        "also_available": ["unblob"],
        "note": "Run unblob too if it's in your tool list -- the two use different detection strategies, worth running together.",
    },
    "binary_diff_pair": {
        "primary_tools": ["binary_semantic_diff"],
        "also_available": ["radiff2"],
        "note": "Function/symbol-level diff first -- a byte-level diff alone is noisy the moment a recompile shifts addresses.",
    },
    "smart_contract_source": {
        "primary_tools": ["slither", "mythril"],
        "also_available": ["forge_poc_run"],
        "note": "Run both -- they're complementary detector classes, not redundant.",
    },
    "evm_bytecode": {
        "primary_tools": ["heimdall_decompile", "disassemble_evm_bytecode", "mythril"],
        "also_available": [],
        "note": "",
    },
    "source_repository": {
        "primary_tools": ["semgrep", "osv_scanner", "trufflehog"],
        "also_available": [],
        "note": "",
    },
    "native_binary": {
        "primary_tools": ["radare2", "strace_run"],
        "also_available": ["ghidra", "gdb", "frida_trace", "qiling_emulate", "custom_re_script", "upx"],
        "note": "Run strace_run early, alongside static analysis, not only as a last resort -- cheap, and shows real file/network/process activity static reading alone won't.",
    },
    "directory_with_executable": {
        "primary_tools": ["radare2"],
        "also_available": ["strace_run", "ghidra"],
        "note": "Point tools at the specific executable file found inside, never at the directory path itself.",
    },
    "jvm_bytecode": {
        "primary_tools": ["jadx"],
        "also_available": ["semgrep", "apktool", "extract_embedded_binary"],
        "note": "jadx decompiles a .jar/.war/.dex/.class straight to readable Java source into a new directory next to the file -- read that source directly, then point semgrep at jadx's output directory for a source-level scan. A .jar is just a ZIP of .class files; if jadx struggles on one class, unzip and feed that single .class back to it. If the jar is a NATIVE wrapper (e.g. JGuard -- a Java stub around a native Windows DLL), run extract_embedded_binary to pull the embedded PE/ELF/Mach-O out, then point radare2/ghidra at the extracted native file (ghidra cannot import a .jar as a native binary).",
    },
}


def _looks_like_loadable_executable(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return any(head.startswith(prefix) for prefix in _EXECUTABLE_MAGIC_PREFIXES)


def _sniff_native_binary_facts(path: Path) -> list[dict]:
    """Fixed, ASRA-authored `radare2 -q -c iIj <path>` call -- never model-written, same trust
    tier reasoning agent/tools/builders/ghidra.py's own module docstring already applies to its
    own fixed analyzeHeadless invocation. `info` (`iIj`) is confirmed, via
    agent/tools/builders/radare2.py's own _ALLOWED_ANALYSIS_COMMANDS, to never get the `aaa;`
    prefix every function/xrefs/decompile analysis pays -- it returns in well under a second even
    on a large binary, safe to run synchronously inside the project-creation request. Never
    raises -- a missing radare2 binary, a timeout, or unparseable output all just mean fewer
    facts, never a blocked project creation.
    """
    if shutil.which("radare2") is None:
        return []
    try:
        result = subprocess.run(
            ["radare2", "-q", "-c", "iIj", str(path)],
            capture_output=True, text=True, timeout=_RADARE2_INFO_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("detect_target_shape: radare2 info sniff failed for %s (%s)", path, exc)
        return []
    try:
        info = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        logger.debug("detect_target_shape: radare2 info sniff returned unparseable output for %s", path)
        return []
    if not isinstance(info, dict):
        return []
    field_labels = (
        ("bintype", "Format"), ("arch", "Architecture"), ("bits", "Bits"), ("os", "OS"),
        ("lang", "Language"), ("compiler", "Compiler"), ("canary", "Stack canary"),
        ("nx", "NX"), ("pic", "PIC"), ("static", "Statically linked"), ("stripped", "Stripped"),
    )
    facts = []
    for key, label in field_labels:
        value = info.get(key)
        if value in (None, "", []):
            continue
        facts.append({"label": label, "value": str(value)})
    return facts


def _directory_contains_extension(path: Path, extensions: frozenset[str]) -> bool:
    try:
        for i, entry in enumerate(path.rglob("*")):
            if i >= _DIRECTORY_SCAN_MAX_ENTRIES:
                break
            if entry.is_file() and entry.suffix.lower() in extensions:
                return True
    except OSError:
        pass
    return False


def identify_file_type(path: Path) -> str:
    """Best-effort short label for what a file IS -- extension first, then a first-bytes magic
    sniff, then a crude text-vs-binary check. Deliberately never raises and never claims more than
    it can tell: an unknown file reports "binary data"/"text", not a wrong guess. Used to annotate a
    directory listing so the chat/triage can name every file inside a folder target, not just the
    ones that happen to be a recognized executable."""
    try:
        if path.is_dir():
            return "directory"
    except OSError:
        return "unknown"
    suffix = path.suffix.lower()
    if suffix in _FILE_TYPE_BY_EXTENSION:
        return _FILE_TYPE_BY_EXTENSION[suffix]
    if suffix in _SOURCE_CODE_EXTENSIONS:
        return "source code"
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return "unknown"
    if head.startswith(b"MZ"):
        return "Windows PE executable"
    if head.startswith(b"\x7fELF"):
        return "ELF executable"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O executable"
    if head.startswith(_JAVA_CLASS_MAGIC):
        return "Java class or Mach-O universal binary"
    if head.startswith(_DEX_MAGIC):
        return "Dalvik DEX bytecode"
    if head.startswith(_ZIP_MAGIC):
        return "ZIP-based archive"
    if head.startswith(_PDF_MAGIC):
        return "PDF document"
    if head.startswith(_GZIP_MAGIC):
        return "gzip archive"
    if head.startswith(_WASM_MAGIC):
        return "WebAssembly module"
    if head and all(0x20 <= b <= 0x7e or b in (0x09, 0x0a, 0x0d) for b in head):
        return "text"
    return "binary data"


def _directory_artifact_priority(path: Path) -> int:
    """How worth-analyzing a single file inside a directory target is, highest wins -- so a folder's
    one real binary/package is picked as the primary artifact and a README never is. Mirrors the same
    shape ordering detect_target_shape itself uses; 0 means "not an analysis target on its own"."""
    if _looks_like_loadable_executable(path):
        return 100
    suffix = path.suffix.lower()
    if suffix in (".apk", ".ipa"):
        return 95
    if suffix in _JVM_ARTIFACT_EXTENSIONS:
        return 90
    if suffix == ".wasm":
        return 80
    if suffix == ".sol":
        return 70
    if suffix in (".so", ".dll", ".dylib"):
        return 60
    return 0


def describe_directory_target(target: str | Path) -> dict | None:
    """Lists a DIRECTORY target's top-level contents with each file's identified type and picks the
    single most-worth-analyzing artifact inside -- the shared source of truth behind both the triage
    task hint (agent/core.py's _re_directory_target_hint) and the chat session snapshot. Returns None
    for a non-directory target (the normal single-file case, or a comma-joined multi-target string),
    so a caller can treat "is this a directory worth listing" and the listing itself as one step.
    Never raises; an unreadable directory just returns None."""
    path = Path(target)
    try:
        if not path.is_dir():
            return None
        children = sorted(path.iterdir(), key=lambda p: p.name.lower())
    except OSError:
        return None

    entries: list[dict] = []
    best: Path | None = None
    best_score = 0
    for i, child in enumerate(children):
        if i >= _DIRECTORY_SCAN_MAX_ENTRIES:
            break
        try:
            is_dir = child.is_dir()
        except OSError:
            is_dir = False
        entries.append({
            "name": child.name,
            "type": identify_file_type(child),
            "is_dir": is_dir,
            "loadable_executable": (not is_dir and _looks_like_loadable_executable(child)),
        })
        if not is_dir:
            score = _directory_artifact_priority(child)
            if score > best_score:
                best_score, best = score, child

    return {
        "entries": entries,
        "truncated": len(children) > _DIRECTORY_SCAN_MAX_ENTRIES,
        "primary_artifact": best.name if best is not None else None,
        "primary_artifact_type": identify_file_type(best) if best is not None else None,
    }


def _detect_one_target_shape(path: Path) -> tuple[str, list[dict]]:
    """The single-target half of detect_target_shape below -- see that function's own docstring
    for the full picture. Never raises; an unreadable/missing path just reports "unknown"."""
    if not path.exists():
        return "unknown", []

    if path.is_dir():
        if _directory_contains_extension(path, frozenset({".sol"})):
            return "smart_contract_source", []
        package_json = path / "package.json"
        if package_json.is_file():
            try:
                pkg = json.loads(package_json.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                pkg = {}
            deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})} if isinstance(pkg, dict) else {}
            if "electron" in deps:
                return "electron_app", []
        try:
            if any(path.glob("*.asar")):
                return "electron_app", []
        except OSError:
            pass
        try:
            top_level_files = [p for p in path.iterdir() if p.is_file()]
        except OSError:
            top_level_files = []
        executables = [p for p in top_level_files if _looks_like_loadable_executable(p)]
        if executables:
            return "directory_with_executable", [{"label": "Executable found in directory", "value": executables[0].name}]
        # A JVM artifact / mobile package sitting at the top level is the real thing to analyze even
        # though it doesn't sniff as a radare2-loadable native executable (a .jar is just a ZIP). This
        # is exactly the "folder containing only crackme.jar" case that used to classify as an
        # unknown directory and leave the chat with nothing to point a tool at.
        jvm_artifact = next((p for p in top_level_files if p.suffix.lower() in _JVM_ARTIFACT_EXTENSIONS), None)
        if jvm_artifact is not None:
            return "jvm_bytecode", [{"label": "Primary artifact in directory", "value": jvm_artifact.name}]
        apk = next((p for p in top_level_files if p.suffix.lower() == ".apk"), None)
        if apk is not None:
            return "android_apk", [{"label": "Primary artifact in directory", "value": apk.name}]
        ipa = next((p for p in top_level_files if p.suffix.lower() == ".ipa"), None)
        if ipa is not None:
            return "ios_ipa", [{"label": "Primary artifact in directory", "value": ipa.name}]
        if _directory_contains_extension(path, _SOURCE_CODE_EXTENSIONS):
            return "source_repository", []
        return "unknown_directory", []

    suffix = path.suffix.lower()
    if suffix == ".apk":
        return "android_apk", []
    if suffix == ".ipa":
        return "ios_ipa", []
    if suffix == ".sol":
        return "smart_contract_source", []
    if suffix == ".wasm":
        return "wasm_module", []
    if suffix == ".jsc":
        return "node_bytecode", []
    if suffix == ".asar":
        return "electron_app", []
    if suffix in _JVM_ARTIFACT_EXTENSIONS:
        return "jvm_bytecode", []

    if _looks_like_loadable_executable(path):
        facts = _sniff_native_binary_facts(path)
        lang = next((f["value"] for f in facts if f["label"] == "Language"), "")
        if any(token in lang.lower() for token in ("cil", "dotnet", ".net")):
            return "dotnet_assembly", facts
        return "native_binary", facts

    try:
        head_text = path.read_text(encoding="ascii", errors="strict")[:4096].strip()
    except (OSError, UnicodeDecodeError, ValueError):
        head_text = ""
    if head_text and _EVM_BYTECODE_RE.match(head_text):
        return "evm_bytecode", []

    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    if size > _FIRMWARE_BLOB_MIN_SIZE_BYTES:
        return "firmware_blob", []
    return "unknown_binary_blob", []


def detect_target_shape(resolved_target: str) -> dict:
    """Deterministic, zero-LLM-cost classification of what RE_TRIAGE_PROMPT's own Step 1 calls
    "identify the target shape" -- the exact same extension/magic-byte/directory-composition
    rules that prompt's prose already describes, as actual code, so a fresh project already has
    this answered the instant it's created rather than re-derived via free-form tool calls on
    every single pass. Deliberately the FAST top-level classification only (format/arch/bits for
    a plain binary via one sub-second `radare2 info` call) -- the deeper nested special-cases
    RE_TRIAGE_PROMPT's own Step 2 still covers (Hermes/Flutter/Rust-cargo-auditable detection, UPX
    unpacking, and so on) stay the model's own job once it has this head start; this never
    replaces that judgment, it just removes the "what even is this" guesswork at the very start.

    Called once, synchronously, right after clone_or_stage_re_target resolves the real on-disk
    path(s) at project creation (main.py's start_re) -- never on a live-check keystroke. Returns
    {"shape": <key>, "facts": [{"label", "value"}, ...]}; never raises on its own -- every
    sub-check above degrades to fewer facts/an "unknown*" shape rather than blocking project
    creation, and the caller wraps this call in its own broad except besides.
    """
    paths = _split_targets(resolved_target)
    if not paths:
        return {"shape": "unknown", "facts": []}
    if len(paths) == 1:
        shape, facts = _detect_one_target_shape(Path(paths[0]))
        return {"shape": shape, "facts": facts}

    if len(paths) == 2 and all(Path(p).is_file() for p in paths):
        # RE_TRIAGE_PROMPT's own "two local files given together" bullet -- a before/after
        # binary-diffing pair, not two independent targets to triage separately.
        return {
            "shape": "binary_diff_pair",
            "facts": [{"label": "Target 1", "value": paths[0]}, {"label": "Target 2", "value": paths[1]}],
        }

    combined_facts: list[dict] = []
    for i, p in enumerate(paths, start=1):
        _, facts = _detect_one_target_shape(Path(p))
        combined_facts.extend({"label": f"Target {i} {f['label']}", "value": f["value"]} for f in facts)
    return {"shape": "multi_target", "facts": combined_facts}
