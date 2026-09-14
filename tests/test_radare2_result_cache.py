"""radare2's deterministic-command result cache — memoizes an identical analysis of an unchanged
binary so a real RE pass never pays the same ~2m30s `aaa` re-analysis twice (a pass once ran 13 full
`aaa` re-analyses, several of them byte-identical commands). Plus the RE-mode resume entry point.
"""
import os
import subprocess

import pytest

from agent.core import compute_resume_entry_point
from agent.tools.builders.radare2 import build_radare2_command, radare2_result_cache_key
from agent.tools.registry import ToolSpec


@pytest.fixture()
def binary(tmp_path):
    path = tmp_path / "target.bin"
    path.write_bytes(b"MZ\x90\x00" * 200)
    return str(path)


def test_read_command_key_is_stable_and_write_command_is_never_cached(binary):
    read_cmd = build_radare2_command({"file_path": binary, "analysis": "functions"})
    write_cmd = build_radare2_command({"file_path": binary, "analysis": "hex_patch", "address": "0x0", "hex_bytes": "9090"})

    key = radare2_result_cache_key(read_cmd, {"file_path": binary})
    assert key is not None
    assert radare2_result_cache_key(read_cmd, {"file_path": binary}) == key  # deterministic
    # A write (-w hex_patch) must never be served from or stored in cache.
    assert radare2_result_cache_key(write_cmd, {"file_path": binary}) is None


def test_key_changes_when_the_target_file_changes(binary):
    read_cmd = build_radare2_command({"file_path": binary, "analysis": "info"})
    before = radare2_result_cache_key(read_cmd, {"file_path": binary})
    os.utime(binary, (0, 0))  # mtime is part of the key
    assert radare2_result_cache_key(read_cmd, {"file_path": binary}) != before


def test_missing_file_is_not_cached():
    cmd = build_radare2_command({"file_path": "/no/such/file", "analysis": "info"})
    assert radare2_result_cache_key(cmd, {"file_path": "/no/such/file"}) is None


def test_runner_memoizes_identical_calls(monkeypatch, tmp_path):
    # A tool_tier=2 spec with a fixed cache key: an identical call must reuse the stored result
    # instead of dispatching a second subprocess; a different call still dispatches.
    import agent.tools.cache as cache
    import agent.tools.runner as runner

    monkeypatch.setattr(cache, "CACHE_DIR", tmp_path / "cache")
    dispatches = []

    def fake_tracked(command, timeout_seconds):
        dispatches.append(command)
        return subprocess.CompletedProcess(command, 0, "OUT", "")

    monkeypatch.setattr(runner, "_run_tracked", fake_tracked)
    monkeypatch.setattr(runner, "_resolve_executable", lambda spec: "/bin/echo")

    spec = ToolSpec(
        name="faketool", category="re", tool_tier=2, executable="echo",
        build_command=lambda p: ["echo", p["x"]], requires_allowed_target=False,
        installed_by_default=True, result_cache_key=lambda cmd, p: "k-" + p["x"],
    )

    first = runner._run_subprocess(spec, {"x": "AAA"})
    second = runner._run_subprocess(spec, {"x": "AAA"})   # cache hit
    runner._run_subprocess(spec, {"x": "BBB"})            # distinct -> dispatch

    assert len(dispatches) == 2
    assert first.get("from_cache") is None
    assert second.get("from_cache") is True
    assert second["stdout"] == "OUT"


def test_re_mode_resume_entry_point_is_re_triage():
    assert compute_resume_entry_point({"mode": "reverse_engineering"}) == "re_triage"
    # An RE session that happens to have recorded findings still resumes into triage, not "exploit".
    assert compute_resume_entry_point({"mode": "reverse_engineering", "findings": [{"title": "x"}]}) == "re_triage"
    # Non-RE modes keep their existing phase-based entry point.
    assert compute_resume_entry_point({"mode": "pentest", "findings": [{"title": "x"}]}) == "exploit"
