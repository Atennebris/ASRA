"""The RE agent must SEE and identify any file inside a directory target -- and specifically must
recognize Java/JVM bytecode (.jar/.war/.dex/.class) so a crackme.jar is analyzable with jadx instead
of reading as an unsupported "unknown blob".

Real, confirmed incident this covers: a session whose target was a folder containing only
crackme.jar classified as unknown_directory with no recommended tools, and the chat -- given only the
bare folder path, no listing -- asked the operator "which file do you want analyzed?" instead of
looking inside. Root causes: (1) .jar had no shape in detect_target_shape, (2) the chat snapshot
carried no directory listing. Both are fixed here; these pin the fix.
"""
import json

import agent.chat as chat
from agent.tools.builders.re_target import (
    RE_TARGET_TOOLSETS,
    describe_directory_target,
    detect_target_shape,
    identify_file_type,
)
from agent.core import _re_directory_target_hint


# --- single-file JVM bytecode shapes ---------------------------------------------------------

def test_jar_file_is_jvm_bytecode(tmp_path):
    target = tmp_path / "crackme.jar"
    target.write_bytes(b"PK\x03\x04" + b"\x00" * 32)  # a .jar is a ZIP; extension decides the shape
    assert detect_target_shape(str(target))["shape"] == "jvm_bytecode"


def test_war_ear_dex_class_are_jvm_bytecode(tmp_path):
    for name, magic in (("app.war", b"PK\x03\x04"), ("app.ear", b"PK\x03\x04"),
                        ("classes.dex", b"dex\n035\x00"), ("Main.class", b"\xca\xfe\xba\xbe")):
        p = tmp_path / name
        p.write_bytes(magic + b"\x00" * 16)
        assert detect_target_shape(str(p))["shape"] == "jvm_bytecode", name


def test_jvm_bytecode_toolset_recommends_jadx():
    entry = RE_TARGET_TOOLSETS["jvm_bytecode"]
    assert "jadx" in entry["primary_tools"]


# --- directory targets: the file inside is found and named ------------------------------------

def test_directory_with_only_a_jar_is_jvm_bytecode_and_names_it(tmp_path):
    (tmp_path / "crackme.jar").write_bytes(b"PK\x03\x04" + b"\x00" * 32)
    result = detect_target_shape(str(tmp_path))
    assert result["shape"] == "jvm_bytecode"
    assert result["facts"] == [{"label": "Primary artifact in directory", "value": "crackme.jar"}]


def test_directory_with_apk_is_android(tmp_path):
    (tmp_path / "app.apk").write_bytes(b"PK\x03\x04")
    assert detect_target_shape(str(tmp_path))["shape"] == "android_apk"


def test_native_executable_still_wins_over_a_jar_in_the_same_directory(tmp_path):
    (tmp_path / "crackme.jar").write_bytes(b"PK\x03\x04")
    (tmp_path / "loader").write_bytes(b"\x7fELF" + b"\x00" * 60)
    # A radare2-loadable native binary is still the primary analysis target over a packaged .jar.
    assert detect_target_shape(str(tmp_path))["shape"] == "directory_with_executable"


# --- identify_file_type: names ANY common file, never raises ----------------------------------

def test_identify_file_type_covers_common_shapes(tmp_path):
    cases = {
        "crackme.jar": (b"PK\x03\x04", "Java/JVM archive (JAR)"),
        "notes.txt": (b"hello world\n", "text"),
        "prog.exe": (b"MZ\x90\x00", "Windows PE executable"),
        "lib.so": (b"\x7fELF", "ELF shared library"),
    }
    for name, (data, expected) in cases.items():
        p = tmp_path / name
        p.write_bytes(data)
        assert identify_file_type(p) == expected, name


def test_identify_file_type_sniffs_magic_when_extension_is_unknown(tmp_path):
    p = tmp_path / "mystery.weird"
    p.write_bytes(b"\x7fELF" + b"\x00" * 20)
    assert identify_file_type(p) == "ELF executable"


def test_identify_unknown_binary_is_labeled_not_crashed(tmp_path):
    p = tmp_path / "blob.weird"
    p.write_bytes(b"\x01\x02\x03\x04\xff\xfe")
    assert identify_file_type(p) == "binary data"


# --- describe_directory_target: listing + primary artifact ------------------------------------

def test_describe_directory_lists_types_and_picks_primary(tmp_path):
    (tmp_path / "crackme.jar").write_bytes(b"PK\x03\x04")
    (tmp_path / "README.txt").write_text("goal: get the serial")
    desc = describe_directory_target(str(tmp_path))
    assert desc is not None
    names = {e["name"]: e["type"] for e in desc["entries"]}
    assert names["crackme.jar"] == "Java/JVM archive (JAR)"
    assert names["README.txt"] == "text"
    assert desc["primary_artifact"] == "crackme.jar"


def test_describe_directory_returns_none_for_a_file(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"\x00")
    assert describe_directory_target(str(f)) is None


def test_describe_directory_none_for_multi_target_string(tmp_path):
    # A comma-joined multi-target string is not a directory path.
    assert describe_directory_target("a, b, c") is None


# --- directory hint (triage task text) names the jar and its type -----------------------------

def test_directory_hint_names_a_jar_without_flagging_a_loadable_executable(tmp_path):
    (tmp_path / "crackme.jar").write_bytes(b"PK\x03\x04" + b"\x00" * 16)
    (tmp_path / "README.txt").write_text("hi")
    hint = _re_directory_target_hint(str(tmp_path))
    assert "DIRECTORY" in hint
    assert "crackme.jar (Java/JVM archive (JAR))" in hint
    # A .jar is not a radare2-loadable native binary -> no "Loadable executable" call-out ...
    assert "Loadable executable" not in hint
    # ... but it IS named as the primary analyzable artifact so the model starts there.
    assert "Primary analyzable artifact detected inside" in hint


# --- chat snapshot gives the chat the folder listing, so it never asks "which file?" ----------

def test_chat_snapshot_includes_directory_contents(tmp_path):
    (tmp_path / "crackme.jar").write_bytes(b"PK\x03\x04")
    (tmp_path / "hint.txt").write_text("try harder")
    session = {"target": str(tmp_path), "target_shape": "jvm_bytecode"}
    snap = json.loads(chat._session_snapshot(session))
    assert snap["primary_artifact"] == "crackme.jar"
    listed = {e["name"]: e["type"] for e in snap["directory_contents"]}
    assert listed["crackme.jar"] == "Java/JVM archive (JAR)"
    assert "hint.txt" in listed


def test_chat_snapshot_omits_directory_keys_for_a_file_target(tmp_path):
    f = tmp_path / "crackme.exe"
    f.write_bytes(b"MZ")
    session = {"target": str(f), "target_shape": "native_binary"}
    snap = json.loads(chat._session_snapshot(session))
    assert "directory_contents" not in snap
    assert "primary_artifact" not in snap
