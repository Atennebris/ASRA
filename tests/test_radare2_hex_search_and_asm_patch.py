"""radare2's two hex-adjacent analyses added after an operator asked "is hex-editor-style work
actually covered for RE": hex_search (a whole-file byte-pattern search, r2's own `/x`) and
hex_patch_asm (writes a real assembly instruction via r2's own `wa`, instead of requiring the model
to hand-compute raw machine code the way hex_patch alone did). Both confirmed live against a real
radare2 6.2.1 binary before this file existed -- see this session's own audit for the exact
transcripts (`/xj` returning real JSON, `wa nop`/`wa mov eax, 1` correctly assembling and writing).
"""
import os

import pytest

from agent.tools.builders.radare2 import build_radare2_command, radare2_result_cache_key


@pytest.fixture()
def binary(tmp_path):
    path = tmp_path / "target.bin"
    path.write_bytes(b"MZ\x90\x00" * 200)
    return str(path)


# --- hex_search -------------------------------------------------------------------------------

def test_hex_search_builds_the_expected_read_only_search_command(binary):
    command = build_radare2_command({"file_path": binary, "analysis": "hex_search", "hex_pattern": "4d5a"})
    assert command == ["radare2", "-q", "-c", "/xj 4d5a", binary]


def test_hex_search_requires_hex_pattern(binary):
    with pytest.raises(ValueError, match="requires a 'hex_pattern'"):
        build_radare2_command({"file_path": binary, "analysis": "hex_search"})


@pytest.mark.parametrize("bad_pattern", ["zz", "4d5", "4d 5a", "4d5a;", "", "  "])
def test_hex_search_rejects_a_malformed_pattern(binary, bad_pattern):
    with pytest.raises(ValueError):
        build_radare2_command({"file_path": binary, "analysis": "hex_search", "hex_pattern": bad_pattern})


def test_hex_search_is_never_a_write_and_stays_cacheable(binary):
    command = build_radare2_command({"file_path": binary, "analysis": "hex_search", "hex_pattern": "4d5a"})
    assert "-w" not in command
    assert radare2_result_cache_key(command, {"file_path": binary}) is not None


# --- hex_patch_asm ------------------------------------------------------------------------------

def test_hex_patch_asm_builds_the_expected_write_command(binary):
    command = build_radare2_command({
        "file_path": binary, "analysis": "hex_patch_asm", "address": "0x0", "instruction": "nop",
    })
    assert command == ["radare2", "-q", "-w", "-c", "wa nop @ 0x0", binary]


def test_hex_patch_asm_accepts_a_real_multi_operand_instruction(binary):
    command = build_radare2_command({
        "file_path": binary, "analysis": "hex_patch_asm", "address": "entry0", "instruction": "mov eax, 1",
    })
    assert command == ["radare2", "-q", "-w", "-c", "wa mov eax, 1 @ entry0", binary]


def test_hex_patch_asm_requires_instruction(binary):
    with pytest.raises(ValueError, match="requires an 'instruction'"):
        build_radare2_command({"file_path": binary, "analysis": "hex_patch_asm", "address": "0x0"})


@pytest.mark.parametrize("dangerous", [
    "nop; !rm -rf /",           # r2 command chaining + shell-out
    "nop`whoami`",              # command substitution
    "nop $(whoami)",            # command substitution (subshell shape)
    "nop | grep x",             # pipe
    "nop # comment",            # r2 script comment
    "nop\n!id",                 # embedded newline -- a SEPARATE injection vector from `;`, see below
    "nop\nnop",                 # embedded newline alone (no `!`/`;`/etc.) -- proves the newline itself is what's blocked
    "nop\tnop",                 # embedded tab -- same class as newline, not a legitimate mnemonic separator
])
def test_hex_patch_asm_rejects_r2_meta_characters_in_the_instruction(binary, dangerous):
    """The instruction string is glued directly into the same -c "<command>" string every other
    analysis here already goes through -- r2's own `;`/backtick/`$()`/`|`/`#` meta-characters would
    let it chain or shell out (this file's own module docstring), exactly the class of injection
    the fixed-allowlist analysis design otherwise prevents. No real assembly mnemonic needs any of
    these characters, so they're rejected outright rather than trusted to r2's own parser.

    The `\\n`/`\\t` cases are their own real, confirmed-live incident, not just defense-in-depth:
    an early version of this pattern used Python's `\\s` (matches ANY whitespace, including
    newlines/tabs) instead of a literal space, and radare2's own `-c "<command>"` parser treats an
    EMBEDDED NEWLINE as a command separator exactly like `;` -- confirmed live with a raw r2
    invocation (`-c "nop\\n!id"`) actually executing `!id` as a real shell command and printing
    genuine `uid=...` output, despite every OTHER meta-character here already being blocked. The
    newline itself was a fully independent injection path, only closed by this exact test.
    """
    with pytest.raises(ValueError, match="characters no real assembly mnemonic needs"):
        build_radare2_command({
            "file_path": binary, "analysis": "hex_patch_asm", "address": "0x0", "instruction": dangerous,
        })


def test_hex_patch_asm_is_a_write_action_never_cached_and_makes_a_backup(binary):
    command = build_radare2_command({
        "file_path": binary, "analysis": "hex_patch_asm", "address": "0x0", "instruction": "nop",
    })
    assert "-w" in command
    assert radare2_result_cache_key(command, {"file_path": binary}) is None
    backup = binary + ".asra-bak"
    assert os.path.exists(backup)
    with open(backup, "rb") as f:
        assert f.read() == b"MZ\x90\x00" * 200  # the ORIGINAL, pre-patch bytes
