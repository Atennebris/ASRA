"""agent/tools/builders/go_buildinfo.py's run_go_buildinfo -- reads a Go binary's own embedded
build/module metadata, via `go version -m` when a real toolchain is available, or a pure-Python
fallback scan of the same plain-text blob the binary carries embedded in itself otherwise.

All of this is tested on mocks/synthetic bytes -- no real Go toolchain or real Go binary needed,
same discipline as tests/test_unblob_builder.py's own run_unblob tests.
"""
from __future__ import annotations

import subprocess

import pytest

import agent.tools.builders.go_buildinfo as go_module
from agent.tools.builders.go_buildinfo import run_go_buildinfo

_SAMPLE_VERSION_M_STDOUT = """/tmp/app: go1.21.5
\tpath\texample.com/app
\tmod\texample.com/app\t(devel)\t
\tdep\tgithub.com/some/dep\tv1.2.3\th1:abcdef=
\tdep\tgithub.com/other/dep\tv0.9.0\th1:ghijkl=
\tbuild\t-compiler=gc
\tbuild\tCGO_ENABLED=1
\tbuild\tGOARCH=amd64
\tbuild\tGOOS=linux
"""


def _completed(command, returncode, stdout, stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


# --- run_go_buildinfo: input validation ---------------------------------------------------------


def test_run_go_buildinfo_rejects_a_directory(tmp_path):
    with pytest.raises(ValueError, match="directory"):
        run_go_buildinfo({"file_path": str(tmp_path)})


def test_run_go_buildinfo_rejects_a_missing_file():
    with pytest.raises(ValueError, match="does not exist"):
        run_go_buildinfo({"file_path": "/does/not/exist"})


def test_run_go_buildinfo_rejects_unknown_mode(tmp_path):
    target = tmp_path / "bin"
    target.write_bytes(b"\x00")
    with pytest.raises(ValueError, match="mode"):
        run_go_buildinfo({"file_path": str(target), "mode": "bogus"})


# --- run_go_buildinfo: mode="buildinfo" via go version -m ----------------------------------------


def test_run_go_buildinfo_uses_go_toolchain_when_available(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")
    monkeypatch.setattr(
        go_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 0, _SAMPLE_VERSION_M_STDOUT),
    )
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target)})

    assert result["status"] == "ok"
    assert result["observed"]["is_go_binary"] is True
    assert result["observed"]["go_version"] == "go1.21.5"
    assert result["observed"]["module_path"] == "example.com/app"
    assert result["observed"]["main_module"]["path"] == "example.com/app"
    assert result["observed"]["total_dependencies"] == 2
    assert result["observed"]["dependencies"][0]["path"] == "github.com/some/dep"
    assert result["observed"]["build_settings"]["GOARCH"] == "amd64"
    assert result["observed"]["build_settings"]["CGO_ENABLED"] == "1"
    assert result["observed"]["source"] == "go version -m"
    assert result["_evidence"]["untrusted_content"] is True


def test_run_go_buildinfo_not_a_go_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")
    stdout = "/tmp/plain: not a Go executable\n"
    monkeypatch.setattr(go_module.subprocess, "run", lambda command, **kwargs: _completed(command, 1, stdout))
    target = tmp_path / "plain"
    target.write_bytes(b"not go")

    result = run_go_buildinfo({"file_path": str(target)})

    assert result["status"] == "ok"
    assert result["observed"]["is_go_binary"] is False


def test_run_go_buildinfo_caps_long_dependency_list(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")
    header = "/tmp/app: go1.21.5\n\tpath\texample.com/app\n\tmod\texample.com/app\t(devel)\t\n"
    deps = "".join(f"\tdep\tgithub.com/dep{i}\tv1.0.{i}\th1:xx=\n" for i in range(60))
    monkeypatch.setattr(go_module.subprocess, "run", lambda command, **kwargs: _completed(command, 0, header + deps))
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target)})

    assert len(result["observed"]["dependencies"]) == 50
    assert result["observed"]["total_dependencies"] == 60
    assert "dependencies_beyond_limit" in result["unknown"]


def test_run_go_buildinfo_go_command_error(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")
    monkeypatch.setattr(
        go_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 2, "", "unrecognized flag"),
    )
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target)})

    assert result["status"] == "error"
    assert "unrecognized flag" in result["error"]


def test_run_go_buildinfo_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")

    def _raise_timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=60)

    monkeypatch.setattr(go_module.subprocess, "run", _raise_timeout)
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target)})

    assert result["status"] == "timeout"


# --- run_go_buildinfo: mode="buildinfo" fallback (no go toolchain) -------------------------------


def test_run_go_buildinfo_fallback_scans_embedded_modinfo_blob(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: None)
    blob = (
        b"junk-bytes-before\x00"
        b"go1.20.3-other-junk"
        b"path\texample.com/fallback\n"
        b"mod\texample.com/fallback\t(devel)\t\n"
        b"dep\tgithub.com/some/dep\tv1.2.3\th1:abc=\n"
        b"build\tGOOS=linux\n"
        b"\x00trailing-junk"
    )
    target = tmp_path / "app"
    target.write_bytes(blob)

    result = run_go_buildinfo({"file_path": str(target)})

    assert result["status"] == "ok"
    assert result["observed"]["is_go_binary"] is True
    assert result["observed"]["go_version"] == "go1.20.3"
    assert result["observed"]["module_path"] == "example.com/fallback"
    assert result["observed"]["source"].startswith("raw byte scan")
    assert result["inferred"]["main_module"]["path"] == "example.com/fallback"
    assert result["inferred"]["dependencies"][0]["path"] == "github.com/some/dep"
    assert result["inferred"]["build_settings"]["GOOS"] == "linux"
    assert "confidence_caveat" in result["inferred"]


def test_run_go_buildinfo_fallback_no_modinfo_marker_found(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: None)
    target = tmp_path / "plain"
    target.write_bytes(b"just some random bytes with no go markers at all")

    result = run_go_buildinfo({"file_path": str(target)})

    assert result["status"] == "ok"
    assert result["observed"]["is_go_binary"] is False
    assert "module_metadata" in result["unknown"]


# --- run_go_buildinfo: mode="nm_symbols" ---------------------------------------------------------


def test_run_go_buildinfo_nm_symbols_unavailable_without_go(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: None)
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target), "mode": "nm_symbols"})

    assert result["status"] == "tool_unavailable"


def test_run_go_buildinfo_nm_symbols_parses_output(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")
    stdout = (
        "  445000 T main.main\n"
        "  446000 T main.helper\n"
        "         U runtime.morestack\n"
    )
    monkeypatch.setattr(go_module.subprocess, "run", lambda command, **kwargs: _completed(command, 0, stdout))
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target), "mode": "nm_symbols"})

    assert result["status"] == "ok"
    assert result["observed"]["total_symbols"] == 3
    assert result["observed"]["symbols"][0] == {"address": "445000", "type": "T", "name": "main.main"}
    assert result["observed"]["symbols"][2]["name"] == "runtime.morestack"


def test_run_go_buildinfo_nm_symbols_caps_long_list(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")
    stdout = "".join(f"  {i:06x} T main.fn{i}\n" for i in range(60))
    monkeypatch.setattr(go_module.subprocess, "run", lambda command, **kwargs: _completed(command, 0, stdout))
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target), "mode": "nm_symbols"})

    assert len(result["observed"]["symbols"]) == 50
    assert result["observed"]["total_symbols"] == 60
    assert "symbols_beyond_limit" in result["unknown"]


def test_run_go_buildinfo_nm_symbols_command_error(tmp_path, monkeypatch):
    monkeypatch.setattr(go_module, "_resolve_go", lambda: "/usr/local/go/bin/go")
    monkeypatch.setattr(
        go_module.subprocess, "run",
        lambda command, **kwargs: _completed(command, 1, "", "not a Go object file"),
    )
    target = tmp_path / "app"
    target.write_bytes(b"\x7fELF")

    result = run_go_buildinfo({"file_path": str(target), "mode": "nm_symbols"})

    assert result["status"] == "error"
    assert "not a Go object file" in result["error"]


# --- _resolve_go ----------------------------------------------------------------------------------


def test_resolve_go_prefers_path_override(monkeypatch):
    monkeypatch.setenv("GO_PATH", "/opt/go/bin/go")
    monkeypatch.setattr(go_module.shutil, "which", lambda name: "/opt/go/bin/go")
    assert go_module._resolve_go() == "/opt/go/bin/go"


def test_resolve_go_falls_back_to_custom_root(monkeypatch):
    monkeypatch.delenv("GO_PATH", raising=False)
    monkeypatch.setattr(go_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(go_module, "resolve_via_custom_root", lambda exe: f"/mnt/e/tools/{exe}")
    assert go_module._resolve_go() == "/mnt/e/tools/go"
