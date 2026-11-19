"""extract_embedded_binary (agent/tools/builders/embedded_extract.py): pull the native binary out
of a container so radare2/ghidra can load a real PE/ELF/Mach-O. Motivated by a JGuard-protected
crackme.jar (a Java archive wrapping a native Windows DLL) that Ghidra could not import as native.
"""
import zipfile

from agent.tools.builders.embedded_extract import run_extract_embedded_binary


def test_jar_with_native_dll_is_reported(tmp_path):
    jar = tmp_path / "crackme.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("com/jguard/Loader.class", b"\xca\xfe\xba\xbe" + b"\x00" * 64)  # a Java class, NOT native
        z.writestr("lib/jguard.dll", b"MZ" + b"\x00" * 512)                        # the embedded native DLL
    result = run_extract_embedded_binary({"file_path": str(jar)})

    assert result["status"] == "ok"
    assert result["unzipped"] is True
    names = [b["name"] for b in result["native_binaries"]]
    assert "jguard.dll" in names
    # The .class must NOT be mistaken for a native binary (CAFEBABE collides with Mach-O universal).
    assert all(not n.endswith(".class") for n in names)


def test_jar_of_only_java_reports_none_and_points_to_jadx(tmp_path):
    jar = tmp_path / "pure.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("Main.class", b"\xca\xfe\xba\xbe" + b"\x00" * 64)
        z.writestr("README.txt", b"hello")
    result = run_extract_embedded_binary({"file_path": str(jar)})

    assert result["status"] == "ok"
    assert result["native_binaries"] == []
    assert "jadx" in result["note"]


def test_raw_carves_an_embedded_elf_from_a_non_zip_blob(tmp_path):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"A" * 300 + b"\x7fELF" + b"\x00" * 400)
    result = run_extract_embedded_binary({"file_path": str(blob)})

    assert result["status"] == "ok"
    carved = result["native_binaries"]
    assert len(carved) == 1
    assert carved[0]["source"] == "raw_carve"
    assert carved[0]["offset"] == 300
    assert carved[0]["format"] == "elf"


def test_plain_native_binary_is_not_reported_as_its_own_extraction(tmp_path):
    exe = tmp_path / "prog.exe"
    exe.write_bytes(b"MZ" + b"\x00" * 512)
    result = run_extract_embedded_binary({"file_path": str(exe)})

    assert result["status"] == "ok"
    # The input IS native at offset 0 spanning the whole file -- that is itself, not an embedded binary.
    assert result["native_binaries"] == []


def test_missing_file_errors(tmp_path):
    result = run_extract_embedded_binary({"file_path": str(tmp_path / "nope.jar")})
    assert result["status"] == "error"
