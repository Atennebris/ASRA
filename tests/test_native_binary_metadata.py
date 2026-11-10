"""agent/tools/builders/native_binary_metadata.py -- Hermes bytecode / Flutter Dart-AOT snapshot
detection (magic-byte header parsing, no toolchain needed), Rust cargo-auditable dependency
extraction (a hand-rolled minimal ELF section reader, no pyelftools dependency), and .NET
NativeAOT ReadyToRun-directory parsing.

The ELF fixtures here are built purely in Python (struct-packed from scratch, no gcc/objcopy
needed) so this suite has no external-tool dependency at all -- a real gcc+objcopy-built ELF with
a genuine `.dep-v0` section (produced via a real compile + objcopy --add-section round trip) was
used for this module's own live verification outside this test file; this synthetic builder
reproduces the same byte layout (ELF64 little-endian header, null/shstrtab/.dep-v0 section triple)
so the suite stays fast and portable. Likewise, the dotnet_nativeaot fixtures here are hand-built
RTR directory bytes matching the exact layout live-verified (outside this test file) against a
real `dotnet publish -r linux-x64 -p:PublishAot=true` binary -- no .NET SDK needed to run this
suite.
"""
from __future__ import annotations

import struct
import zlib

import pytest

from agent.tools.builders.native_binary_metadata import run_native_binary_metadata

_HERMES_MAGIC = bytes([0xC6, 0x1F, 0xBC, 0x03, 0xC1, 0x03, 0x19, 0x1F])
_FLUTTER_MAGIC = bytes([0xF5, 0xF5, 0xDC, 0xDC])


def _build_minimal_elf64(section_name: bytes | None, section_bytes: bytes) -> bytes:
    """A minimal, valid little-endian ELF64 file with 3 sections: NULL, .shstrtab, and (if
    section_name is given) one named section holding section_bytes. Byte-for-byte matches the
    layout the production module's own _read_elf_section() parses."""
    shstrtab_names = b"\x00.shstrtab\x00"
    name_offset_for_section = len(shstrtab_names)
    if section_name is not None:
        shstrtab_names += section_name + b"\x00"

    ehdr_size = 64
    shdr_size = 64
    shstrtab_offset = ehdr_size
    shstrtab_size = len(shstrtab_names)
    section_data_offset = shstrtab_offset + shstrtab_size
    section_data_size = len(section_bytes)
    shoff = section_data_offset + section_data_size

    num_sections = 3 if section_name is not None else 2

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8  # 64-bit, little-endian, version 1
    ehdr = e_ident
    ehdr += struct.pack("<HHIQQQ", 1, 0x3E, 1, 0, 0, shoff)  # e_type, e_machine, e_version, e_entry, e_phoff, e_shoff
    ehdr += struct.pack("<IHHHHHH", 0, ehdr_size, 0, 0, shdr_size, num_sections, 1)  # e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    assert len(ehdr) == ehdr_size

    def _shdr(name_off, sh_type, offset, size):
        return (
            struct.pack("<II", name_off, sh_type)
            + struct.pack("<Q", 0)  # sh_flags
            + struct.pack("<Q", 0)  # sh_addr
            + struct.pack("<QQ", offset, size)
            + struct.pack("<II", 0, 0)  # sh_link, sh_info
            + struct.pack("<QQ", 1, 0)  # sh_addralign, sh_entsize
        )

    null_shdr = _shdr(0, 0, 0, 0)
    shstrtab_shdr = _shdr(1, 3, shstrtab_offset, shstrtab_size)  # SHT_STRTAB = 3
    shdrs = null_shdr + shstrtab_shdr
    if section_name is not None:
        shdrs += _shdr(name_offset_for_section, 1, section_data_offset, section_data_size)  # SHT_PROGBITS = 1

    return ehdr + shstrtab_names + section_bytes + shdrs


# --- mode validation ---------------------------------------------------------------------------


def test_unknown_mode_rejected():
    with pytest.raises(ValueError, match="Unknown native_binary_metadata mode"):
        run_native_binary_metadata({"mode": "explode", "file_path": "/nonexistent"})


def test_missing_file_path_rejected():
    with pytest.raises(ValueError, match="requires a 'file_path'"):
        run_native_binary_metadata({"mode": "hermes"})


def test_nonexistent_file_errors_cleanly():
    result = run_native_binary_metadata({"mode": "hermes", "file_path": "/does/not/exist/at/all"})
    assert result["status"] == "error"


# --- hermes ------------------------------------------------------------------------------------


def test_hermes_detects_real_magic(tmp_path):
    f = tmp_path / "index.android.bundle"
    f.write_bytes(_HERMES_MAGIC + struct.pack("<I", 96) + b"\x00" * 20)
    result = run_native_binary_metadata({"mode": "hermes", "file_path": str(f)})
    assert result["observed"]["is_hermes_bytecode"] is True
    assert result["observed"]["bytecode_format_version"] == 96
    assert "decompiled_source" in result["unknown"]  # honestly marked as detection-only


def test_hermes_rejects_non_hermes_file(tmp_path):
    f = tmp_path / "plain.js"
    f.write_bytes(b"console.log('hello');")
    result = run_native_binary_metadata({"mode": "hermes", "file_path": str(f)})
    assert result["observed"]["is_hermes_bytecode"] is False
    assert "is_hermes_bytecode" in result["unknown"]


def test_hermes_truncated_header_does_not_crash(tmp_path):
    f = tmp_path / "truncated.bundle"
    f.write_bytes(_HERMES_MAGIC[:4])
    result = run_native_binary_metadata({"mode": "hermes", "file_path": str(f)})
    assert result["observed"]["is_hermes_bytecode"] is False


# --- flutter -----------------------------------------------------------------------------------


def test_flutter_detects_real_magic(tmp_path):
    snapshot_hash = "a1b2c3d4e5f60718293a4b5c6d7e8f90"[:32]
    f = tmp_path / "libapp.so"
    f.write_bytes(_FLUTTER_MAGIC + b"\x00" * 16 + snapshot_hash.encode("ascii") + b"\x00" * 10)
    result = run_native_binary_metadata({"mode": "flutter", "file_path": str(f)})
    assert result["observed"]["is_flutter_dart_aot_snapshot"] is True
    assert result["observed"]["snapshot_hash"] == snapshot_hash
    assert "decompiled_source" in result["unknown"]


def test_flutter_rejects_non_flutter_file(tmp_path):
    f = tmp_path / "libfoo.so"
    f.write_bytes(b"\x7fELF" + b"\x00" * 40)
    result = run_native_binary_metadata({"mode": "flutter", "file_path": str(f)})
    assert result["observed"]["is_flutter_dart_aot_snapshot"] is False


def test_flutter_truncated_hash_reports_unknown(tmp_path):
    f = tmp_path / "truncated_snapshot"
    f.write_bytes(_FLUTTER_MAGIC + b"\x00" * 5)
    result = run_native_binary_metadata({"mode": "flutter", "file_path": str(f)})
    assert result["observed"]["is_flutter_dart_aot_snapshot"] is True
    assert "snapshot_hash" in result["unknown"]


# --- rust cargo-auditable ------------------------------------------------------------------------


def test_rust_cargo_auditable_extracts_real_dep_v0_section(tmp_path):
    manifest = {
        "packages": [
            {"name": "serde", "version": "1.0.210", "kind": "build"},
            {"name": "hello", "version": "0.1.0", "kind": "runtime"},
        ]
    }
    import json

    compressed = zlib.compress(json.dumps(manifest).encode("utf-8"))
    elf_bytes = _build_minimal_elf64(b".dep-v0", compressed)
    f = tmp_path / "hello_auditable"
    f.write_bytes(elf_bytes)

    result = run_native_binary_metadata({"mode": "rust_cargo_auditable", "file_path": str(f)})
    assert result["observed"]["has_cargo_auditable_section"] is True
    assert result["observed"]["dependency_count"] == 2
    assert {"name": "serde", "version": "1.0.210", "kind": "build"} in result["observed"]["dependencies"]


def test_rust_cargo_auditable_no_section_present(tmp_path):
    elf_bytes = _build_minimal_elf64(None, b"")
    f = tmp_path / "hello_plain"
    f.write_bytes(elf_bytes)

    result = run_native_binary_metadata({"mode": "rust_cargo_auditable", "file_path": str(f)})
    assert result["observed"]["has_cargo_auditable_section"] is False
    assert "dependencies" in result["unknown"]


def test_rust_cargo_auditable_non_elf_file_does_not_crash(tmp_path):
    f = tmp_path / "not_elf.bin"
    f.write_bytes(b"this is not an ELF file" * 5)
    result = run_native_binary_metadata({"mode": "rust_cargo_auditable", "file_path": str(f)})
    assert result["observed"]["has_cargo_auditable_section"] is False


def test_rust_cargo_auditable_corrupted_section_reports_unknown(tmp_path):
    elf_bytes = _build_minimal_elf64(b".dep-v0", b"not valid zlib data at all")
    f = tmp_path / "hello_corrupted"
    f.write_bytes(elf_bytes)

    result = run_native_binary_metadata({"mode": "rust_cargo_auditable", "file_path": str(f)})
    assert result["observed"]["has_cargo_auditable_section"] is True
    assert "dependencies" in result["unknown"]


# --- dotnet NativeAOT ----------------------------------------------------------------------------


def _build_rtr_directory(rows: list[tuple[int, int, int, int]], major: int = 9, minor: int = 1, entry_size: int = 24, entry_type: int = 1) -> bytes:
    """rows: list of (type, flags, start, end) -- matches the real 24-byte row layout live-verified
    against a real `dotnet publish -p:PublishAot=true` binary this session."""
    header = struct.pack("<4sHHIHBB", b"RTR\x00", major, minor, 0, len(rows), entry_size, entry_type)
    body = b"".join(struct.pack("<iHHQQ", t, fl, 0, start, end) for (t, fl, start, end) in rows)
    return header + body


def test_dotnet_nativeaot_detects_real_header_and_parses_sections(tmp_path):
    directory = _build_rtr_directory([
        (201, 1, 1409048, 1409584),  # GCStaticRegion-shaped row, has an end
        (204, 0, 1409592, 0),        # ThreadStaticIndex -- single address, flags=0, no end
    ])
    f = tmp_path / "natfix"
    f.write_bytes(b"\x90" * 64 + directory + b"\x90" * 64)  # padding on both sides, like a real binary
    result = run_native_binary_metadata({"mode": "dotnet_nativeaot", "file_path": str(f)})
    assert result["observed"]["has_nativeaot_rtr_directory"] is True
    assert result["observed"]["rtr_major_version"] == 9
    assert result["observed"]["rtr_minor_version"] == 1
    assert result["observed"]["matches_verified_fixture_version"] is True
    assert result["observed"]["section_count"] == 2
    sections = result["observed"]["sections"]
    assert sections[0] == {"type": 201, "flags": 1, "start": 1409048, "end": 1409584}
    assert sections[1] == {"type": 204, "flags": 0, "start": 1409592, "end": None}
    assert result["observed"]["known_section_type_names"] == {"204": "ThreadStaticIndex"}
    assert "method_table_graph" in result["unknown"]  # honestly scoped, not a full decompile


def test_dotnet_nativeaot_rejects_file_without_magic(tmp_path):
    f = tmp_path / "plain_elf"
    f.write_bytes(b"\x7fELF" + b"\x00" * 100)
    result = run_native_binary_metadata({"mode": "dotnet_nativeaot", "file_path": str(f)})
    assert result["observed"]["has_nativeaot_rtr_directory"] is False
    assert "sections" in result["unknown"]


def test_dotnet_nativeaot_rejects_coincidental_magic_with_wrong_entry_size(tmp_path):
    # Real file bytes that happen to start with "RTR\x00" but aren't a real directory (e.g. code
    # bytes) fail the entry_size/entry_type sanity check and must not be mistaken for a real one --
    # the exact false-positive shape hit live against this session's own NativeAOT test fixture.
    bogus = struct.pack("<4sHHIHBB", b"RTR\x00", 0x7275, 0x8948, 0xf3668300, 0x7e04, 0x75, 0x68)
    f = tmp_path / "bogus_magic"
    f.write_bytes(bogus + b"\x00" * 40)
    result = run_native_binary_metadata({"mode": "dotnet_nativeaot", "file_path": str(f)})
    assert result["observed"]["has_nativeaot_rtr_directory"] is False


def test_dotnet_nativeaot_reports_ambiguous_when_two_valid_directories_found(tmp_path):
    one = _build_rtr_directory([(201, 1, 100, 200)])
    two = _build_rtr_directory([(202, 1, 300, 400)])
    f = tmp_path / "two_directories"
    f.write_bytes(one + b"\x00" * 16 + two)
    result = run_native_binary_metadata({"mode": "dotnet_nativeaot", "file_path": str(f)})
    assert result["observed"]["has_nativeaot_rtr_directory"] is True
    assert result["observed"]["ambiguous_candidate_count"] == 2
    assert "sections" in result["unknown"]


def test_dotnet_nativeaot_truncated_rows_not_mistaken_for_a_real_directory(tmp_path):
    directory = _build_rtr_directory([(201, 1, 100, 200), (202, 1, 300, 400)])
    truncated = directory[: -10]  # header claims 2 rows but the file ends mid-second-row
    f = tmp_path / "truncated_rows"
    f.write_bytes(truncated)
    result = run_native_binary_metadata({"mode": "dotnet_nativeaot", "file_path": str(f)})
    assert result["observed"]["has_nativeaot_rtr_directory"] is False


def test_dotnet_nativeaot_non_verified_version_flagged_honestly(tmp_path):
    directory = _build_rtr_directory([(201, 1, 100, 200)], major=10, minor=0)
    f = tmp_path / "future_version"
    f.write_bytes(directory)
    result = run_native_binary_metadata({"mode": "dotnet_nativeaot", "file_path": str(f)})
    assert result["observed"]["has_nativeaot_rtr_directory"] is True
    assert result["observed"]["rtr_major_version"] == 10
    assert result["observed"]["matches_verified_fixture_version"] is False
