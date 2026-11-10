"""agent/tools/builders/unblob.py's run_unblob -- unblob wrapped as a tier-1 native tool (see
that module's own docstring for why tier-1: unblob's own exit code is not a reliable success
signal, confirmed live, and the real structured result is a --report JSON file the generic tier-2
pipeline has no way to read).

All of this is tested on mocks -- no real unblob install needed/touched, same discipline as
tests/test_ghidra_builder.py's own run_ghidra tests.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import agent.tools.builders.unblob as unblob_module
from agent.tools.builders.unblob import run_unblob, unblob_available


def _write_report(command, chunks=None, extracted=None, **kwargs):
    """Simulates unblob's own real behavior: writes a --report JSON file (the path right after
    '--report' in argv) and creates any requested extracted files under the -e directory."""
    report_path = command[command.index("--report") + 1]
    extract_dir = Path(command[command.index("-e") + 1])
    report = [{"task": {"path": "/tmp/input.bin"}, "reports": (chunks or [])}]
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f)
    for rel in extracted or []:
        path = extract_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("extracted content")
    return subprocess.CompletedProcess(command, 0, "", "")


_CHUNK = {"__typename__": "ChunkReport", "handler_name": "gzip", "start_offset": 0, "end_offset": 10, "size": 10, "is_encrypted": False}


# --- unblob_available -----------------------------------------------------------------------------


def test_unblob_available_reflects_resolution(monkeypatch):
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: None)
    assert unblob_available() is False
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    assert unblob_available() is True


def test_resolve_unblob_prefers_path_override(monkeypatch):
    monkeypatch.setenv("UNBLOB_PATH", "/opt/unblob/unblob")
    monkeypatch.setattr(unblob_module.shutil, "which", lambda name: "/opt/unblob/unblob")
    assert unblob_module._resolve_unblob() == "/opt/unblob/unblob"


def test_resolve_unblob_falls_back_to_custom_root(monkeypatch):
    monkeypatch.delenv("UNBLOB_PATH", raising=False)
    monkeypatch.setattr(unblob_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(unblob_module, "resolve_via_custom_root", lambda exe: f"/mnt/e/tools/{exe}")
    assert unblob_module._resolve_unblob() == "/mnt/e/tools/unblob"


# --- run_unblob: input validation ------------------------------------------------------------------


def test_run_unblob_rejects_a_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    with pytest.raises(ValueError, match="directory"):
        run_unblob({"file_path": str(tmp_path)})


def test_run_unblob_rejects_a_missing_file(monkeypatch):
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    with pytest.raises(ValueError, match="does not exist"):
        run_unblob({"file_path": "/does/not/exist"})


def test_run_unblob_unavailable_when_not_resolved(tmp_path, monkeypatch):
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: None)
    target = tmp_path / "blob"
    target.write_bytes(b"\x1f\x8b")

    result = run_unblob({"file_path": str(target)})

    assert result["status"] == "tool_unavailable"


# --- run_unblob: dispatch ----------------------------------------------------------------------


def test_run_unblob_native_scratch_dir_is_used_not_the_global_app_dir(tmp_path, monkeypatch):
    """Confirmed live this session: unblob fails outright on the Windows-Documents-mounted
    (drvfs) path resolve_global_app_dir() normally resolves to -- this must stay off that path."""
    monkeypatch.setattr(unblob_module, "_UNBLOB_RUNS_DIR", tmp_path / "native-runs")
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    captured = {}

    def _fake_run(command, **kwargs):
        captured["command"] = command
        return _write_report(command)

    monkeypatch.setattr(unblob_module.subprocess, "run", _fake_run)
    target = tmp_path / "blob"
    target.write_bytes(b"\x1f\x8b")

    run_unblob({"file_path": str(target)})

    assert str(tmp_path / "native-runs") in captured["command"][captured["command"].index("-e") + 1]


def test_run_unblob_ok_result_lists_chunks_and_extracted_files(tmp_path, monkeypatch):
    monkeypatch.setattr(unblob_module, "_UNBLOB_RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    monkeypatch.setattr(
        unblob_module.subprocess, "run",
        lambda command, **kwargs: _write_report(command, chunks=[_CHUNK], extracted=["inner.txt"]),
    )
    target = tmp_path / "blob"
    target.write_bytes(b"\x1f\x8b")

    result = run_unblob({"file_path": str(target)})

    assert result["status"] == "ok"
    assert result["observed"]["total_identified_chunks"] == 1
    assert result["observed"]["identified_chunks"][0]["handler"] == "gzip"
    assert result["observed"]["total_extracted_files"] == 1
    assert result["unknown"] == {}
    assert result["_evidence"]["untrusted_content"] is True


def test_run_unblob_no_containers_found_is_still_ok(tmp_path, monkeypatch):
    """A plain non-container file -- confirmed live unblob itself exits 0 with an empty report,
    not an error. status='ok' with zero chunks/files is the honest, correct outcome."""
    monkeypatch.setattr(unblob_module, "_UNBLOB_RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    monkeypatch.setattr(unblob_module.subprocess, "run", lambda command, **kwargs: _write_report(command))
    target = tmp_path / "plain.txt"
    target.write_text("just text")

    result = run_unblob({"file_path": str(target)})

    assert result["status"] == "ok"
    assert result["observed"]["total_identified_chunks"] == 0
    assert result["observed"]["total_extracted_files"] == 0


def test_run_unblob_caps_long_chunk_and_file_lists(tmp_path, monkeypatch):
    monkeypatch.setattr(unblob_module, "_UNBLOB_RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    many_chunks = [dict(_CHUNK) for _ in range(60)]
    many_files = [f"f{i}.bin" for i in range(60)]
    monkeypatch.setattr(
        unblob_module.subprocess, "run",
        lambda command, **kwargs: _write_report(command, chunks=many_chunks, extracted=many_files),
    )
    target = tmp_path / "blob"
    target.write_bytes(b"\x1f\x8b")

    result = run_unblob({"file_path": str(target)})

    assert len(result["observed"]["identified_chunks"]) == 50
    assert result["observed"]["total_identified_chunks"] == 60
    assert len(result["observed"]["extracted_files"]) == 50
    assert result["observed"]["total_extracted_files"] == 60
    assert "chunks_beyond_limit" in result["unknown"]
    assert "files_beyond_limit" in result["unknown"]


def test_run_unblob_missing_report_file_is_an_error(tmp_path, monkeypatch):
    """A real, confirmed-possible shape: unblob exits nonzero (or even 0) without ever producing
    its own --report file at all (e.g. the drvfs incompatibility confirmed live this session)."""
    monkeypatch.setattr(unblob_module, "_UNBLOB_RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")
    monkeypatch.setattr(
        unblob_module.subprocess, "run",
        lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", "Unhandled exception during unblob"),
    )
    target = tmp_path / "blob"
    target.write_bytes(b"\x1f\x8b")

    result = run_unblob({"file_path": str(target)})

    assert result["status"] == "error"
    assert "Unhandled exception" in result["error"]


def test_run_unblob_malformed_report_json_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(unblob_module, "_UNBLOB_RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")

    def _write_garbage(command, **kwargs):
        report_path = command[command.index("--report") + 1]
        Path(report_path).parent.mkdir(parents=True, exist_ok=True)
        Path(report_path).write_text("not valid json{{{")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(unblob_module.subprocess, "run", _write_garbage)
    target = tmp_path / "blob"
    target.write_bytes(b"\x1f\x8b")

    result = run_unblob({"file_path": str(target)})

    assert result["status"] == "error"
    assert "report file" in result["error"]


def test_run_unblob_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(unblob_module, "_UNBLOB_RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(unblob_module, "_resolve_unblob", lambda: "/usr/local/bin/unblob")

    def _raise_timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=300)

    monkeypatch.setattr(unblob_module.subprocess, "run", _raise_timeout)
    target = tmp_path / "blob"
    target.write_bytes(b"\x1f\x8b")

    result = run_unblob({"file_path": str(target)})

    assert result["status"] == "timeout"
