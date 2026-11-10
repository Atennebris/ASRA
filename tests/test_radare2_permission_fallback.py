"""retry_radare2_write_on_permission_denied -- a real, confirmed incident fix (Supratest_RE_a-
usr_ff40fb): a hex_patch write failed twice with a plain OS-level `Permission denied` (a Windows
NTFS file reached through WSL2's drvfs mount, not an argument mistake), and the generic LLM
"corrected retry" in agent/core.py had nothing to fix -- it guessed an unrelated /tmp path, then on
the next attempt corrupted the call's own `analysis` field entirely. See that module's own
module-level fallback docstring for the full incident.
"""
import os

from agent.tools.builders.radare2 import (
    _PATCH_FALLBACK_SENTINEL,
    build_radare2_command,
    parse_radare2_output,
    retry_radare2_write_on_permission_denied,
)
from projects.paths import resolve_global_app_dir


def _binary(tmp_path, name="target.bin"):
    path = tmp_path / name
    path.write_bytes(b"MZ\x90\x00" * 200)
    return str(path)


def test_non_write_command_is_never_retried():
    command = ["radare2", "-q", "-c", "iIj", "/some/file"]
    assert retry_radare2_write_on_permission_denied(command, {"stderr": "Permission denied"}) is None


def test_a_write_failure_unrelated_to_permissions_is_never_retried(tmp_path):
    binary = _binary(tmp_path)
    command = build_radare2_command({"file_path": binary, "analysis": "hex_patch", "address": "0x0", "hex_bytes": "90"})
    assert retry_radare2_write_on_permission_denied(command, {"stderr": "some other r2 error"}) is None


def test_permission_denied_stages_a_writable_scratch_copy_and_patches_that_instead(tmp_path):
    binary = _binary(tmp_path)
    command = build_radare2_command({"file_path": binary, "analysis": "hex_patch", "address": "0x0", "hex_bytes": "90"})
    result = {"stderr": "ERROR: Permission denied\nERROR: Cannot open '%s' for writing" % binary}

    retry_command = retry_radare2_write_on_permission_denied(command, result)
    assert retry_command is not None
    assert retry_command[-1] != binary  # never silently claims the original path was patched
    assert str(resolve_global_app_dir() / "data" / "radare2_patch_scratch") in retry_command[-1]
    assert os.path.exists(retry_command[-1])  # the scratch copy was actually staged on disk
    assert os.access(retry_command[-1], os.W_OK)  # and is genuinely writable, not just copied

    c_index = retry_command.index("-c")
    assert f"echo {_PATCH_FALLBACK_SENTINEL}:" in retry_command[c_index + 1]


def test_retrying_against_the_scratch_copy_itself_never_loops_further(tmp_path):
    binary = _binary(tmp_path)
    command = build_radare2_command({"file_path": binary, "analysis": "hex_patch", "address": "0x0", "hex_bytes": "90"})
    result = {"stderr": "Permission denied"}
    retry_command = retry_radare2_write_on_permission_denied(command, result)

    # Simulate the scratch copy itself somehow also failing -- must give up, not retry forever.
    assert retry_radare2_write_on_permission_denied(retry_command, result) is None


def test_parser_surfaces_the_scratch_path_and_never_claims_the_original_was_patched(tmp_path):
    scratch_path = str(tmp_path / "scratch_copy.bin")
    stdout = f"\n{_PATCH_FALLBACK_SENTINEL}:{scratch_path}\n"

    parsed = parse_radare2_output(stdout)
    assert parsed["patched_copy_path"] == scratch_path
    assert "NOT modified" in parsed["note"]


def test_parser_is_untouched_for_the_overwhelming_majority_of_calls_that_never_hit_the_fallback():
    parsed = parse_radare2_output('{"arch": "x86"}')
    assert "patched_copy_path" not in parsed
