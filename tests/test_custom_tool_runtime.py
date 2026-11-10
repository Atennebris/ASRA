"""agent/tools/custom_tool_runtime.py: minting one real ToolSpec per enabled custom-tool record,
and the one shared executor every minted ToolSpec's native_function wraps."""
import subprocess

import agent.tools.custom_tool_runtime as ctr
from agent.tools import custom_tools_store as cts


def _record(**overrides):
    base = {
        "id": "abc123", "name": "mytool", "path": "/opt/tools/mytool",
        "enabled": True, "description": "does a thing", "requires_target": True,
        "category": "recon", "added_at": 0.0,
    }
    base.update(overrides)
    return base


# --- _category_for --------------------------------------------------------------------------------


def test_category_for_custom_expands_to_every_ordinary_category():
    result = ctr._category_for(_record(category="custom"))
    assert set(result) == {"recon", "scan", "exploit", "post_exploit"}


def test_category_for_a_real_category_stays_a_single_value():
    assert ctr._category_for(_record(category="re")) == "re"


# --- _mint_toolspec --------------------------------------------------------------------------------


def test_mint_toolspec_is_tier_1_not_tier_2():
    """Deliberate: tier-2 dispatches through runner.py's plain, unsandboxed _run_subprocess --
    tier-1 lets native_function own its own execution path through run_sandboxed instead (see
    this module's own header comment)."""
    spec = ctr._mint_toolspec(_record())
    assert spec.tool_tier == 1


def test_mint_toolspec_carries_the_record_own_requires_target():
    spec_true = ctr._mint_toolspec(_record(requires_target=True))
    spec_false = ctr._mint_toolspec(_record(requires_target=False))
    assert spec_true.requires_allowed_target is True
    assert spec_false.requires_allowed_target is False


def test_mint_toolspec_falls_back_to_a_real_description_when_blank():
    spec = ctr._mint_toolspec(_record(description=""))
    assert spec.description  # never empty -- _tool_description's own fallback chain never needed
    assert "mytool" in spec.description


def test_mint_toolspec_availability_check_reflects_real_file_existence(tmp_path):
    real_binary = tmp_path / "mytool"
    real_binary.write_text("#!/bin/sh\n")
    spec = ctr._mint_toolspec(_record(path=str(real_binary)))
    assert spec.availability_check() is True

    missing_spec = ctr._mint_toolspec(_record(path=str(tmp_path / "gone")))
    assert missing_spec.availability_check() is False


def test_mint_toolspec_parameters_schema_is_none_so_it_falls_back_to_the_generic_shape():
    """None -> agent/core.py's _tool_to_openai_schema falls back to _GENERIC_DISCOVERED_SCHEMA
    (target + extra_args), the same shape every autodiscovered tool already uses."""
    spec = ctr._mint_toolspec(_record())
    assert spec.parameters_schema is None


# --- build_dynamic_toolspecs -----------------------------------------------------------------------


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(cts, "CUSTOM_TOOLS_STORE_PATH", tmp_path / "custom_tools.json")


def test_build_dynamic_toolspecs_mints_only_enabled_records(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    enabled = cts.add_custom_tool(name="enabled_tool", path="/opt/a", description="", requires_target=False, category="recon")
    disabled = cts.add_custom_tool(name="disabled_tool", path="/opt/b", description="", requires_target=False, category="recon")
    cts.set_custom_tool_enabled(disabled["id"], False)

    specs = ctr.build_dynamic_toolspecs()

    assert [s.name for s in specs] == [enabled["name"]]


def test_build_dynamic_toolspecs_returns_empty_list_with_no_records(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    assert ctr.build_dynamic_toolspecs() == []


# --- run_registered_custom_tool -------------------------------------------------------------------


def test_run_registered_custom_tool_rejects_a_target_not_referenced_in_extra_args():
    """Reused validation from make_generic_discovered_command -- the same real incident class an
    ordinary autodiscovered tool already had to guard against (a target given but never actually
    placed into the real command line)."""
    result = ctr.run_registered_custom_tool({"target": "https://example.com", "extra_args": ["-v"]}, record=_record())
    assert result["status"] == "error"
    assert "never appears anywhere in extra_args" in result["error"]


def test_run_registered_custom_tool_dispatches_through_run_sandboxed(monkeypatch):
    captured = {}

    def _fake_run_sandboxed(command, scratch_dir, timeout_seconds):
        captured["command"] = command
        captured["timeout"] = timeout_seconds
        return subprocess.CompletedProcess(command, 0, "real output\n", "")

    monkeypatch.setattr(ctr, "run_sandboxed", _fake_run_sandboxed)
    monkeypatch.setattr(ctr, "_scratch_dir_for", lambda session_id: "/tmp")

    result = ctr.run_registered_custom_tool({"target": "", "extra_args": ["-x"]}, record=_record(path="/opt/tools/mytool"))

    assert result["status"] == "ok"
    assert result["stdout"] == "real output\n"
    assert captured["command"] == ["/opt/tools/mytool", "-x"]


def test_run_registered_custom_tool_reports_a_clear_timeout(monkeypatch):
    def _raise_timeout(command, scratch_dir, timeout_seconds):
        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout_seconds)

    monkeypatch.setattr(ctr, "run_sandboxed", _raise_timeout)
    monkeypatch.setattr(ctr, "_scratch_dir_for", lambda session_id: "/tmp")

    result = ctr.run_registered_custom_tool({"target": "", "extra_args": ["-v"]}, record=_record())

    assert result["status"] == "timeout"
    assert "mytool" in result["error"]


def test_run_registered_custom_tool_surfaces_stderr_on_a_nonzero_exit(monkeypatch):
    monkeypatch.setattr(
        ctr, "run_sandboxed",
        lambda command, scratch_dir, timeout_seconds: subprocess.CompletedProcess(command, 1, "", "permission denied\n"),
    )
    monkeypatch.setattr(ctr, "_scratch_dir_for", lambda session_id: "/tmp")

    result = ctr.run_registered_custom_tool({"target": "", "extra_args": ["-v"]}, record=_record())

    assert result["status"] == "error"
    assert result["error"] == "permission denied"
