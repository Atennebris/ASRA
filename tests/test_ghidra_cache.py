"""agent/tools/builders/ghidra.py's per-session result cache -- a repeated decompile/disassemble of
the SAME unchanged address must be served from cache instead of paying a fresh ~42s Ghidra analysis
every call (radare2 already dedupes its own identical re-analyses the same way, keyed on file mtime).
Write/mutating modes are never cached AND invalidate the project's cached reads, since they change
the program database. All on mocks -- no real Ghidra install touched, same discipline as
tests/test_ghidra_builder.py.
"""
from __future__ import annotations

import socket

import pytest

import agent.tools.builders.ghidra as ghidra_module
from agent.tools.builders.ghidra import run_ghidra


@pytest.fixture(autouse=True)
def _clear_cache():
    ghidra_module._result_cache.clear()
    yield
    ghidra_module._result_cache.clear()


def _stub_lifecycle(monkeypatch):
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    monkeypatch.setattr(ghidra_module, "_ensure_server_running", lambda *a, **k: "/fake/asra.sock")


def _binary(tmp_path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"\x7fELF")
    return str(binary)


# --- _normalized_target: address forms collapse, names stay verbatim ----------------------------


@pytest.mark.parametrize("a,b", [
    ("0x401000", "fcn.00401000"),
    ("0x401000", "0X401000"),
    ("0x401000", " 0x401000 "),
    ("fcn.00401000", "fcn.00401000"),
])
def test_normalized_target_collapses_address_forms(a, b):
    assert ghidra_module._normalized_target(a) == ghidra_module._normalized_target(b)


def test_normalized_target_keeps_names_verbatim_and_case_sensitive():
    assert ghidra_module._normalized_target("main") == "main"
    # A wrong case-fold would serve the wrong function's cached result -- names must never merge.
    assert ghidra_module._normalized_target("Main") != ghidra_module._normalized_target("main")


def test_normalized_target_leaves_a_type_string_alone():
    assert ghidra_module._normalized_target("struct timeval") == "struct timeval"


# --- read-mode caching ---------------------------------------------------------------------------


def test_identical_decompile_is_served_from_cache(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    calls = {"n": 0}

    def _send(socket_path, request):
        calls["n"] += 1
        return {"observed": {"function_name": "add", "pseudocode": "int add(){}"}, "unknown": {}}

    monkeypatch.setattr(ghidra_module, "_send_request", _send)
    path = _binary(tmp_path)

    first = run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x401000"})
    second = run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x401000"})

    assert calls["n"] == 1  # the server was hit once, not twice
    assert first["status"] == "ok"
    assert "from_cache" not in first
    assert second["from_cache"] is True
    assert second["observed"]["function_name"] == "add"


def test_fcn_and_hex_forms_hit_the_same_cache_entry(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    calls = {"n": 0}
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda s, r: calls.__setitem__("n", calls["n"] + 1) or {"observed": {}, "unknown": {}},
    )
    path = _binary(tmp_path)

    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x401000"})
    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "fcn.00401000"})

    assert calls["n"] == 1


def test_different_targets_are_cached_separately(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    calls = {"n": 0}
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda s, r: calls.__setitem__("n", calls["n"] + 1) or {"observed": {}, "unknown": {}},
    )
    path = _binary(tmp_path)

    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x401000"})
    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x402000"})

    assert calls["n"] == 2


def test_different_modes_on_the_same_target_are_cached_separately(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    calls = {"n": 0}
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda s, r: calls.__setitem__("n", calls["n"] + 1) or {"observed": {}, "unknown": {}},
    )
    path = _binary(tmp_path)

    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x401000"})
    run_ghidra({"file_path": path, "mode": "disassemble_function", "target": "0x401000"})

    assert calls["n"] == 2


# --- write modes: never cached, and they invalidate the project's cached reads ------------------


def test_write_mode_is_not_cached_and_invalidates_prior_reads(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    calls = {"n": 0}
    monkeypatch.setattr(
        ghidra_module, "_send_request",
        lambda s, r: calls.__setitem__("n", calls["n"] + 1) or {"observed": {"verified": True}, "unknown": {}},
    )
    path = _binary(tmp_path)

    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "main"})          # n=1, cached
    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "main"})          # cache hit, n stays 1
    assert calls["n"] == 1

    run_ghidra({"file_path": path, "mode": "set_address_name", "target": "main", "value": "decrypt"})  # n=2, invalidates
    assert calls["n"] == 2

    # The decompile after the rename must recompute, not serve the pre-rename cached result.
    after = run_ghidra({"file_path": path, "mode": "decompile_function", "target": "main"})   # n=3
    assert calls["n"] == 3
    assert "from_cache" not in after


def test_error_results_are_never_cached(tmp_path, monkeypatch):
    _stub_lifecycle(monkeypatch)
    monkeypatch.setattr(ghidra_module, "_send_request", lambda *a, **k: (_ for _ in ()).throw(socket.timeout()))
    path = _binary(tmp_path)

    result = run_ghidra({"file_path": path, "mode": "decompile_function", "target": "main"})

    assert result["status"] == "timeout"
    assert len(ghidra_module._result_cache) == 0


def test_cache_hit_does_not_even_start_the_server(tmp_path, monkeypatch):
    """A cache hit is served before the server lifecycle runs at all -- so a read arriving after
    the resident server idle-timed out never pays a full cold start just to answer it."""
    monkeypatch.setattr(ghidra_module, "_resolve_analyzeheadless", lambda: "/usr/local/bin/analyzeHeadless")
    ensure_calls = {"n": 0}

    def _ensure(*a, **k):
        ensure_calls["n"] += 1
        return "/fake/asra.sock"

    monkeypatch.setattr(ghidra_module, "_ensure_server_running", _ensure)
    monkeypatch.setattr(ghidra_module, "_send_request", lambda s, r: {"observed": {"x": 1}, "unknown": {}})
    path = _binary(tmp_path)

    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x401000"})  # populates cache
    run_ghidra({"file_path": path, "mode": "decompile_function", "target": "0x401000"})  # served from cache

    assert ensure_calls["n"] == 1  # second call never reached _ensure_server_running
