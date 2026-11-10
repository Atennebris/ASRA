"""agent/tools/builders/ghidra.py's run_ghidra -- Ghidra's own headless decompiler wrapped as a
tier-1 native tool, dispatched through a persistent per-project server process over a Unix domain
socket (see that module's own docstring for why: a one-shot `analyzeHeadless` subprocess per call
pays JVM+Ghidra-framework startup every time, confirmed live to dominate the real cost once the
heavier full-analysis step is already skipped via -noanalysis).

All of this is tested on mocks -- no real Ghidra install needed/touched, same discipline as
tests/test_strace_builder.py's own run_strace tests. The actual socket protocol/process lifecycle
was live-verified separately against the operator's own real Ghidra (confirmed: ~54s to start a
fresh server including a real -import, then 0.4s-0.6s per subsequent request against the SAME
already-running server; a server killed abruptly (SIGKILL) is correctly detected as dead by the
next call's own liveness probe and a fresh one is started automatically).
"""
from __future__ import annotations

import socket

import pytest

import agent.tools.builders.ghidra as ghidra_module
from agent.tools.builders.ghidra import ghidra_available, run_ghidra


def _stub_lifecycle(monkeypatch, socket_path="/fake/asra.sock", start_server=None):
    """Short-circuits the whole server-lifecycle decision (_ensure_server_running) for tests that
    only care about run_ghidra's own request-building/response-handling -- the lifecycle itself
    (ping/start/lock) gets its own dedicated tests further down."""
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    monkeypatch.setattr(ghidra_module, "_ensure_server_running", lambda *a, **k: socket_path)


# --- _resolve_analyzeheadless / ghidra_available -------------------------------------------------


def test_resolve_prefers_explicit_path_override(monkeypatch):
    monkeypatch.setenv("ANALYZEHEADLESS_PATH", "/opt/ghidra/support/analyzeHeadless")
    monkeypatch.setattr(ghidra_module.shutil, "which", lambda name: "/opt/ghidra/support/analyzeHeadless")
    assert ghidra_module._resolve_analyzeheadless() == "/opt/ghidra/support/analyzeHeadless"


def test_resolve_falls_back_to_path(monkeypatch):
    monkeypatch.delenv("ANALYZEHEADLESS_PATH", raising=False)
    monkeypatch.setattr(ghidra_module.shutil, "which", lambda name: "/usr/local/bin/analyzeHeadless" if name == "analyzeHeadless" else None)
    assert ghidra_module._resolve_analyzeheadless() == "/usr/local/bin/analyzeHeadless"


def test_resolve_falls_back_to_custom_root_when_nothing_else_finds_it(monkeypatch):
    monkeypatch.delenv("ANALYZEHEADLESS_PATH", raising=False)
    monkeypatch.setattr(ghidra_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(ghidra_module, "resolve_via_custom_root", lambda exe: f"/mnt/e/tools/ghidra_12.1.4/support/{exe}")

    resolved = ghidra_module._resolve_analyzeheadless()

    assert resolved == "/mnt/e/tools/ghidra_12.1.4/support/analyzeHeadless"


def test_resolve_returns_none_when_nothing_finds_it(monkeypatch):
    monkeypatch.delenv("ANALYZEHEADLESS_PATH", raising=False)
    monkeypatch.setattr(ghidra_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(ghidra_module, "resolve_via_custom_root", lambda exe: None)
    assert ghidra_module._resolve_analyzeheadless() is None


def test_ghidra_available_reflects_resolution(monkeypatch):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: None)
    assert ghidra_available() is False
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    assert ghidra_available() is True


# --- path helpers: project key / project dir / native scratch dir separation --------------------


def test_project_key_changes_when_the_binary_is_modified(tmp_path):
    """A different mtime must get a fresh key (and therefore a fresh project+server), not silently
    reuse a stale analysis of the OLD content -- same identity radare2_result_cache_key already
    keys its own cache on."""
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    first_key = ghidra_module._project_key_for(str(binary))

    import os
    import time
    binary.write_bytes(b"\x7fELF-modified")
    os.utime(binary, (time.time() + 5, time.time() + 5))
    second_key = ghidra_module._project_key_for(str(binary))

    assert first_key != second_key


def test_project_dir_and_native_scratch_dir_are_genuinely_different_locations(tmp_path, monkeypatch):
    """The real, confirmed-live reason these must never be the same directory: a Unix domain
    socket cannot be created on a drvfs-mounted path (resolve_global_app_dir() resolves there
    under WSL2) -- `SocketException: Operation not supported`, confirmed against the operator's
    own real machine. The project dir and the native scratch dir must resolve to genuinely
    different roots so the socket never ends up back on the unsupported filesystem."""
    monkeypatch.setattr(ghidra_module, "resolve_global_app_dir", lambda: tmp_path / "app_dir")
    monkeypatch.setattr(ghidra_module.Path, "home", staticmethod(lambda: tmp_path / "home_dir"))

    key = "abc123"
    project_dir = ghidra_module._project_dir_for(key)
    native_dir = ghidra_module._native_scratch_dir_for(key)

    assert project_dir != native_dir
    assert str(tmp_path / "app_dir") in str(project_dir)
    assert str(tmp_path / "home_dir") in str(native_dir)
    assert project_dir.is_dir()
    assert native_dir.is_dir()


# --- run_ghidra: input validation -- never reaches the server lifecycle on a bad call ------------


def test_run_ghidra_rejects_a_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    with pytest.raises(ValueError, match="directory"):
        run_ghidra({"file_path": str(tmp_path), "mode": "info"})


def test_run_ghidra_rejects_a_missing_file(monkeypatch):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    with pytest.raises(ValueError, match="does not exist"):
        run_ghidra({"file_path": "/does/not/exist/binary", "mode": "info"})


def test_run_ghidra_rejects_an_unknown_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    with pytest.raises(ValueError, match="Unknown ghidra mode"):
        run_ghidra({"file_path": str(binary), "mode": "explode"})


@pytest.mark.parametrize("mode", [
    "decompile_function", "disassemble_function", "xrefs_to", "cfg", "pcode_def_use",
    "value_flow", "inspect_native_data_type", "set_address_name", "annotate_native_function",
])
def test_run_ghidra_requires_target_for_function_level_modes(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    with pytest.raises(ValueError, match="requires a 'target'"):
        run_ghidra({"file_path": str(binary), "mode": mode})


def test_run_ghidra_fix_no_return_flags_needs_no_target(tmp_path, monkeypatch):
    """Unlike every other mutating/analysis mode, fix_no_return_flags operates on the whole
    program at once -- it must not demand a target the way the function-level modes do."""
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(ghidra_module, "_send_request", lambda *a, **k: {"observed": {}, "unknown": {}})
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "fix_no_return_flags"})

    assert result["status"] == "ok"


@pytest.mark.parametrize("mode", ["set_address_name", "annotate_native_function"])
def test_run_ghidra_write_modes_require_a_value(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    with pytest.raises(ValueError, match="requires a 'value'"):
        run_ghidra({"file_path": str(binary), "mode": mode, "target": "add"})


def test_run_ghidra_unavailable_when_not_resolved(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: None)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "info"})

    assert result["status"] == "tool_unavailable"


# --- run_ghidra: request building + response handling (lifecycle stubbed out) -------------------


def test_run_ghidra_info_and_functions_modes_never_require_a_target(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(ghidra_module, "_send_request", lambda *a, **k: {"observed": {}, "unknown": {}})
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "info"})

    assert result["status"] == "ok"


def test_run_ghidra_sends_the_right_mode_and_target(tmp_path, monkeypatch):
    captured = {}
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(ghidra_module, "_send_request", lambda socket_path, request: captured.update(request) or {"observed": {}, "unknown": {}})
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    run_ghidra({"file_path": str(binary), "mode": "decompile_function", "target": "add"})

    assert captured == {"mode": "decompile_function", "target": "add", "value": "", "dry_run": True}


def test_run_ghidra_ok_result_carries_the_evidence_envelope(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda *a, **k: {"observed": {"function_name": "add", "pseudocode": "int add(int a,int b){return a+b;}"}, "unknown": {}},
    )
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "decompile_function", "target": "add"})

    assert result["status"] == "ok"
    assert result["observed"]["function_name"] == "add"
    assert result["unknown"] == {}
    assert result["_evidence"]["method"] == "static"
    assert result["_evidence"]["untrusted_content"] is True


@pytest.mark.parametrize("mode,observed_key,target", [
    ("cfg", "basic_blocks", "classify"),
    ("pcode_def_use", "pcode_ops", "compute"),
    ("value_flow", "pcode_ops", "compute"),
    ("inspect_native_data_type", "members", "struct timeval"),
])
def test_run_ghidra_newer_modes_round_trip_through_the_server(tmp_path, monkeypatch, mode, observed_key, target):
    captured = {}
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda socket_path, request: captured.update(request) or {"observed": {observed_key: ["x"]}, "unknown": {}},
    )
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": mode, "target": target})

    assert result["status"] == "ok"
    assert captured == {"mode": mode, "target": target, "value": "", "dry_run": True}
    assert result["observed"][observed_key] == ["x"]


@pytest.mark.parametrize("mode,target", [
    ("set_address_name", "sub_401000"),
    ("annotate_native_function", "main"),
])
def test_run_ghidra_write_modes_send_their_value_payload(tmp_path, monkeypatch, mode, target):
    captured = {}
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda socket_path, request: captured.update(request) or {
            "observed": {"verified": True}, "unknown": {},
        },
    )
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": mode, "target": target, "value": "decrypt_payload"})

    assert result["status"] == "ok"
    assert captured == {"mode": mode, "target": target, "value": "decrypt_payload", "dry_run": True}
    assert result["observed"]["verified"] is True


def test_run_ghidra_fix_no_return_flags_round_trips_through_the_server(tmp_path, monkeypatch):
    captured = {}
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda socket_path, request: captured.update(request) or {
            "observed": {"fixed_import_functions": ["malloc"], "fixed_local_functions": [], "total_fixed": 1},
            "unknown": {},
        },
    )
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "fix_no_return_flags"})

    assert result["status"] == "ok"
    assert captured == {"mode": "fix_no_return_flags", "target": "", "value": "", "dry_run": True}
    assert result["observed"]["total_fixed"] == 1


def test_run_ghidra_fix_mips_soft_float_needs_no_target(tmp_path, monkeypatch):
    """Like fix_no_return_flags, this operates on the whole program at once, not one function."""
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(ghidra_module, "_send_request", lambda *a, **k: {"observed": {"applicable": True}, "unknown": {}})
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "fix_mips_soft_float"})

    assert result["status"] == "ok"


def test_run_ghidra_fix_mips_soft_float_defaults_dry_run_to_true(tmp_path, monkeypatch):
    captured = {}
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda socket_path, request: captured.update(request) or {"observed": {"applicable": True, "dry_run": True}, "unknown": {}},
    )
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    run_ghidra({"file_path": str(binary), "mode": "fix_mips_soft_float"})

    assert captured == {"mode": "fix_mips_soft_float", "target": "", "value": "", "dry_run": True}


def test_run_ghidra_fix_mips_soft_float_honors_an_explicit_dry_run_false(tmp_path, monkeypatch):
    captured = {}
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda socket_path, request: captured.update(request) or {
            "observed": {"applicable": True, "dry_run": False, "fixed_functions": 2}, "unknown": {},
        },
    )
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "fix_mips_soft_float", "dry_run": False})

    assert captured == {"mode": "fix_mips_soft_float", "target": "", "value": "", "dry_run": False}
    assert result["observed"]["fixed_functions"] == 2


def test_run_ghidra_fix_mips_soft_float_not_applicable_is_surfaced_in_unknown(tmp_path, monkeypatch):
    """A non-MIPS program: the server bails out cleanly, with no mutation attempted at all --
    this must come back as an ordinary ok result, not an error, with the refusal in 'unknown'."""
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda *a, **k: {
            "observed": {"applicable": False, "processor": "x86", "pointer_size": 8},
            "unknown": {"fix_mips_soft_float": "not applicable: this fix only targets 32-bit MIPS (program is x86, pointer_size=8)"},
        },
    )
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "fix_mips_soft_float"})

    assert result["status"] == "ok"
    assert result["observed"]["applicable"] is False
    assert "fix_mips_soft_float" in result["unknown"]


def test_run_ghidra_server_level_error_response_is_surfaced(tmp_path, monkeypatch):
    """The server's own malformed-request-shaped error (AsraExtract.java's handleOneConnection
    JSON-parse-failure branch) never reaches dispatchRequest() at all, so it has no observed/
    unknown pair -- distinct from a normal mode result, and must not be silently misread as one."""
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(ghidra_module, "_send_request", lambda *a, **k: {"status": "error", "error": "could not parse request"})
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "info"})

    assert result["status"] == "error"
    assert result["error"] == "could not parse request"


def test_run_ghidra_socket_timeout(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)

    def _raise_timeout(*a, **k):
        raise socket.timeout()

    monkeypatch.setattr(ghidra_module, "_send_request", _raise_timeout)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "info"})

    assert result["status"] == "timeout"


def test_run_ghidra_socket_communication_error(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)

    def _raise_oserror(*a, **k):
        raise OSError("Connection refused")

    monkeypatch.setattr(ghidra_module, "_send_request", _raise_oserror)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "info"})

    assert result["status"] == "error"
    assert "Connection refused" in result["error"]


def test_run_ghidra_cannot_start_server_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")

    def _raise_timeout_error(*a, **k):
        raise TimeoutError("did not become ready within 600s")

    monkeypatch.setattr(ghidra_module, "_ensure_server_running", _raise_timeout_error)
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")

    result = run_ghidra({"file_path": str(binary), "mode": "info"})

    assert result["status"] == "error"
    assert "did not become ready" in result["error"]


# --- server lifecycle: _ping_server / _ensure_server_running / _start_server --------------------


def test_ping_server_returns_false_for_a_nonexistent_socket(tmp_path):
    assert ghidra_module._ping_server(tmp_path / "does_not_exist.sock") is False


def test_ping_server_returns_true_only_for_a_real_ok_response(monkeypatch, tmp_path):
    socket_path = tmp_path / "fake.sock"
    socket_path.touch()

    class _FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            pass

        def connect(self, path):
            pass

        def sendall(self, data):
            pass

    monkeypatch.setattr(ghidra_module.socket_module, "socket", lambda *a, **k: _FakeSocket())
    monkeypatch.setattr(ghidra_module, "_read_line", lambda sock: '{"status": "ok"}\n')

    assert ghidra_module._ping_server(socket_path) is True


def test_ping_server_returns_false_on_connection_error(monkeypatch, tmp_path):
    socket_path = tmp_path / "fake.sock"
    socket_path.touch()

    def _raise(*a, **k):
        raise OSError("Connection refused")

    monkeypatch.setattr(ghidra_module.socket_module, "socket", _raise)

    assert ghidra_module._ping_server(socket_path) is False


def test_ensure_server_running_reuses_an_already_alive_server(tmp_path, monkeypatch):
    start_called = {"value": False}
    monkeypatch.setattr(ghidra_module, "_ping_server", lambda socket_path: True)
    monkeypatch.setattr(ghidra_module, "_start_server", lambda *a, **k: start_called.__setitem__("value", True))

    socket_path = ghidra_module._ensure_server_running(
        "/usr/local/bin/analyzeHeadless", tmp_path / "project", tmp_path / "native", tmp_path / "project" / "asra.gpr", "bin", "/tmp/bin",
    )

    assert start_called["value"] is False
    assert socket_path == ghidra_module._socket_path_for(tmp_path / "native")


def test_ensure_server_running_starts_a_fresh_server_when_none_is_alive(tmp_path, monkeypatch):
    (tmp_path / "project").mkdir()
    (tmp_path / "native").mkdir()
    start_calls = []
    monkeypatch.setattr(ghidra_module, "_ping_server", lambda socket_path: False)
    monkeypatch.setattr(ghidra_module, "_start_server", lambda *a, **k: start_calls.append(a))

    ghidra_module._ensure_server_running(
        "/usr/local/bin/analyzeHeadless", tmp_path / "project", tmp_path / "native", tmp_path / "project" / "asra.gpr", "bin", "/tmp/bin",
    )

    assert len(start_calls) == 1


def test_start_server_raises_on_early_process_exit(tmp_path, monkeypatch):
    class _FakeProc:
        returncode = 1

        def poll(self):
            return 1

    monkeypatch.setattr(ghidra_module.subprocess, "Popen", lambda *a, **k: _FakeProc())
    monkeypatch.setattr(ghidra_module, "_ping_server", lambda socket_path: False)

    with pytest.raises(RuntimeError, match="exited early"):
        ghidra_module._start_server("/usr/local/bin/analyzeHeadless", tmp_path, False, "bin", "/tmp/bin", tmp_path / "asra.sock")


def test_start_server_raises_on_timeout(tmp_path, monkeypatch):
    class _FakeProc:
        returncode = None

        def poll(self):
            return None

    monkeypatch.setattr(ghidra_module.subprocess, "Popen", lambda *a, **k: _FakeProc())
    monkeypatch.setattr(ghidra_module, "_ping_server", lambda socket_path: False)
    monkeypatch.setattr(ghidra_module, "_SERVER_START_TIMEOUT_SECONDS", 0)

    with pytest.raises(TimeoutError, match="did not become ready"):
        ghidra_module._start_server("/usr/local/bin/analyzeHeadless", tmp_path, False, "bin", "/tmp/bin", tmp_path / "asra.sock")


def test_start_server_uses_import_for_a_fresh_project(tmp_path, monkeypatch):
    captured = {}

    def _fake_popen(command, **kwargs):
        captured["command"] = command

        class _FakeProc:
            returncode = 0

            def poll(self):
                return None

        return _FakeProc()

    monkeypatch.setattr(ghidra_module.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(ghidra_module, "_ping_server", lambda socket_path: True)  # ready on first poll

    ghidra_module._start_server("/usr/local/bin/analyzeHeadless", tmp_path, False, "bin", "/tmp/bin", tmp_path / "asra.sock")

    assert "-import" in captured["command"]
    assert "/tmp/bin" in captured["command"]
    assert "-process" not in captured["command"]
    assert "--server" in captured["command"]


def test_start_server_uses_process_noanalysis_for_an_existing_project(tmp_path, monkeypatch):
    captured = {}

    def _fake_popen(command, **kwargs):
        captured["command"] = command

        class _FakeProc:
            returncode = 0

            def poll(self):
                return None

        return _FakeProc()

    monkeypatch.setattr(ghidra_module.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(ghidra_module, "_ping_server", lambda socket_path: True)

    ghidra_module._start_server("/usr/local/bin/analyzeHeadless", tmp_path, True, "bin", "/tmp/bin", tmp_path / "asra.sock")

    assert "-process" in captured["command"]
    assert "-noanalysis" in captured["command"]
    assert "bin" in captured["command"]
    assert "-import" not in captured["command"]
