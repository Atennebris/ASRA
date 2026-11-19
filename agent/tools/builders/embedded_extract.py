"""extract_embedded_binary: recover the native executable(s) hidden inside a container so a native
decompiler (radare2/ghidra) can actually be pointed at a real PE/ELF/Mach-O file.

Real, confirmed need this closes: a JGuard-protected crackme.jar is a Java archive that wraps a
native Windows x86-64 DLL. Ghidra imports the .jar as JAVA bytecode and never sees the DLL, and
radare2 only half-works by seeking to a raw offset inside the jar. The right move is to pull the
embedded native binary out into its own file first -- this does exactly that, two ways:

1. ZIP container (.jar/.war/.ear/.apk/.ipa/.zip): extract it (zip-slip-guarded) and report every
   extracted file that is a native binary (by magic or shared-library extension).
2. Raw carve: scan the whole file's bytes for embedded PE/ELF/Mach-O headers that a plain unzip
   would miss (a DLL appended to, or stored raw inside, a non-zip blob) and carve each from its
   magic to the next header / EOF into its own file -- enough for radare2/ghidra to parse the header.

This is a preparation step, not a finding-producing scanner -- same role ipa_extract/jadx play.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from agent.tools.builders.validators import validate_safe_value
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# PE/ELF/Mach-O header signatures -- the formats radare2/ghidra can actually load. Mach-O universal
# ("fat", 0xCAFEBABE/0xBEBAFECA) is deliberately omitted from the raw carve: it collides byte-for-byte
# with a Java .class file, and carving every .class out of a jar as a "native binary" would be pure
# noise. A single-arch Mach-O (feedface/feedfacf and byte-swapped) is unambiguous and kept.
_NATIVE_MAGICS = (
    b"MZ",                                       # PE/DOS (.exe/.dll)
    b"\x7fELF",                                  # ELF
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",    # Mach-O 32/64 big-endian
    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",    # Mach-O 32/64 little-endian
)
_ZIP_EXTENSIONS = frozenset({".jar", ".war", ".ear", ".apk", ".ipa", ".zip", ".aar"})
_NATIVE_LIBRARY_EXTENSIONS = frozenset({".dll", ".so", ".dylib", ".exe"})
# A carve that produces just a few bytes is never a real binary -- skip a magic match that has almost
# nothing after it (e.g. an "MZ" that is really two incidental ASCII bytes in text).
_MIN_CARVE_BYTES = 256
_MAX_CARVED_BINARIES = 20
_READ_CHUNK_FOR_MAGIC = 4


def _looks_native(path: Path) -> bool:
    if path.suffix.lower() in _NATIVE_LIBRARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as handle:
            head = handle.read(_READ_CHUNK_FOR_MAGIC)
    except OSError:
        return False
    return any(head.startswith(magic) for magic in _NATIVE_MAGICS)


def _safe_extract_zip(archive: zipfile.ZipFile, dest: Path) -> None:
    """Rejects any member whose resolved path escapes dest (zip-slip) before extracting -- an
    operator-supplied archive is of unknown origin, same guard re_target.py already applies."""
    dest = dest.resolve()
    for member in archive.namelist():
        target = (dest / member).resolve()
        if target != dest and dest not in target.parents:
            raise ValueError(f"Archive member escapes destination directory: {member!r}")
    archive.extractall(dest)


def _carve_raw_native_binaries(data: bytes, output_dir: Path, stem: str) -> list[dict]:
    """Finds every native-magic offset in `data` and carves from each to the next native-magic
    offset (or EOF) into its own file. Carving to the next header, not a parsed section size, is a
    deliberate best-effort: a loader (radare2/ghidra) parses the header and ignores trailing bytes,
    so an over-long carve still loads correctly, while under-carving would truncate the real code."""
    offsets: list[tuple[int, bytes]] = []
    for magic in _NATIVE_MAGICS:
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx == -1:
                break
            offsets.append((idx, magic))
            start = idx + 1
    offsets.sort()

    carved: list[dict] = []
    for i, (offset, magic) in enumerate(offsets):
        if len(carved) >= _MAX_CARVED_BINARIES:
            break
        end = offsets[i + 1][0] if i + 1 < len(offsets) else len(data)
        if end - offset < _MIN_CARVE_BYTES:
            continue
        kind = "pe" if magic == b"MZ" else "elf" if magic == b"\x7fELF" else "macho"
        out_path = output_dir / f"{stem}_carved_{offset:#x}_{kind}.bin"
        try:
            out_path.write_bytes(data[offset:end])
        except OSError as exc:
            logger.debug("extract_embedded_binary: failed to write carve at %#x: %s", offset, exc)
            continue
        carved.append({"path": str(out_path), "offset": offset, "format": kind, "size": end - offset})
    return carved


def run_extract_embedded_binary(params: dict) -> dict:
    """Extracts/carves the native binary(ies) embedded in a container file. Point radare2/ghidra at
    the returned native_binaries paths afterward, exactly as you would any other local binary."""
    file_path_raw = params.get("file_path")
    if not file_path_raw:
        return {"status": "error", "tool": "extract_embedded_binary", "error": "file_path is required."}
    file_path = validate_safe_value(str(file_path_raw).strip())
    path = Path(file_path)
    if not path.is_file():
        return {"status": "error", "tool": "extract_embedded_binary", "error": f"File not found: {file_path}"}

    output_dir_raw = params.get("output_dir")
    output_dir = Path(validate_safe_value(str(output_dir_raw).strip())) if output_dir_raw else path.parent / f"{path.stem}_extracted"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"status": "error", "tool": "extract_embedded_binary", "error": f"Could not create output dir {output_dir}: {exc}"}

    native_binaries: list[dict] = []
    extracted_files = 0
    unzipped = False

    is_zip = path.suffix.lower() in _ZIP_EXTENSIONS or zipfile.is_zipfile(path)
    if is_zip:
        try:
            with zipfile.ZipFile(path) as archive:
                _safe_extract_zip(archive, output_dir)
            unzipped = True
            for child in sorted(output_dir.rglob("*")):
                if child.is_file():
                    extracted_files += 1
                    if _looks_native(child):
                        native_binaries.append({"path": str(child), "source": "zip_entry", "name": child.name})
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            logger.debug("extract_embedded_binary: zip extraction failed for %s: %s", file_path, exc)

    # Raw carve as well when unzip found no native binary (a DLL stored/appended raw, or a non-zip
    # container) -- skipped when unzip already recovered one, to avoid carving the same stored DLL twice.
    if not native_binaries:
        try:
            data = path.read_bytes()
        except OSError as exc:
            data = b""
            logger.debug("extract_embedded_binary: could not read %s for carving: %s", file_path, exc)
        if data:
            carved = _carve_raw_native_binaries(data, output_dir, path.stem)
            # A file whose native magic is at offset 0 and spans the whole thing is just itself, not
            # an "embedded" binary -- don't report the input back as its own extraction.
            for entry in carved:
                if entry["offset"] == 0 and entry["size"] >= path.stat().st_size:
                    continue
                native_binaries.append({"path": entry["path"], "source": "raw_carve",
                                        "offset": entry["offset"], "format": entry["format"]})

    if native_binaries:
        note = ("Point radare2/ghidra at a native_binaries[].path -- those are real PE/ELF/Mach-O "
                "files now, not the container. For the Java side of the same archive use jadx.")
    elif unzipped:
        note = (f"Unzipped {extracted_files} file(s) into {output_dir}; none were native binaries. "
                "If this is pure JVM bytecode, decompile it with jadx instead.")
    else:
        note = ("No embedded native binary found (not a zip, and no PE/ELF/Mach-O header carved). "
                "If it is a plain native binary already, analyze it directly; if JVM bytecode, use jadx.")

    logger.debug("extract_embedded_binary: %s -> %d native binary(ies), unzipped=%s, extracted=%d",
                 file_path, len(native_binaries), unzipped, extracted_files)
    return {
        "status": "ok",
        "tool": "extract_embedded_binary",
        "output_dir": str(output_dir),
        "unzipped": unzipped,
        "extracted_file_count": extracted_files,
        "native_binaries": native_binaries,
        "note": note,
    }
