"""The skill execution gates (agent/tools/skill_runner.execute_skill): a script always goes through
the sandbox, a tampered body / unknown provenance is refused without running, a command may only
invoke a registry-known binary, and run counters move only on real execution. run_sandboxed itself
is stubbed so these tests never spawn a real subprocess."""
import subprocess
import sys

import pytest

from agent.tools import playbook_store, skill_runner


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    monkeypatch.setattr(playbook_store, "PLAYBOOK_EMBEDDINGS_PATH", tmp_path / "playbook" / "embeddings.json")
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(skill_runner, "_scratch_dir", lambda session_id: scratch)


@pytest.fixture
def sandbox_calls(monkeypatch):
    calls = []

    def _fake(cmd, scratch, timeout):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="OUT", stderr="")

    monkeypatch.setattr(skill_runner, "run_sandboxed", _fake)
    return calls


def _technique_with_skill(**skill_kwargs):
    tid = playbook_store.add_manual_technique(technique="t", worked=True)
    skill = playbook_store.build_skill(**skill_kwargs)
    assert skill is not None
    playbook_store.attach_skill(tid, skill)
    return tid


def test_script_skill_runs_through_sandbox_and_bumps_counters(sandbox_calls):
    tid = _technique_with_skill(kind="script", body="print('hi')", interpreter="python")
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "ok"
    assert result["stdout"] == "OUT"
    assert len(sandbox_calls) == 1
    assert sandbox_calls[0][0] == sys.executable  # pinned interpreter, not PATH python3
    skill = playbook_store.get_technique_skill(tid)
    assert skill["runs"] == 1 and skill["run_successes"] == 1


def test_sh_script_runs_via_bash(sandbox_calls):
    tid = _technique_with_skill(kind="script", body="echo hi", interpreter="sh")
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "ok"
    assert sandbox_calls[0][0] == "bash"


def test_tampered_body_is_refused_without_running(sandbox_calls):
    tid = _technique_with_skill(kind="script", body="print(1)", interpreter="python")
    store = playbook_store.load_playbook_store()
    _k, entry = playbook_store._find_entry_by_id(store, tid)
    entry["skill"]["body"] = "print('tampered')"  # body changed, hash not re-pinned
    playbook_store._write_playbook_store(store)
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "error" and "hash" in result["error"]
    assert sandbox_calls == []  # never ran
    assert playbook_store.get_technique_skill(tid)["runs"] == 0


def test_unknown_provenance_is_refused(sandbox_calls):
    tid = _technique_with_skill(kind="script", body="print(1)", interpreter="python")
    store = playbook_store.load_playbook_store()
    _k, entry = playbook_store._find_entry_by_id(store, tid)
    entry["skill"]["provenance"]["derived_from"] = "somewhere_evil"
    playbook_store._write_playbook_store(store)
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "error" and "provenance" in result["error"]
    assert sandbox_calls == []


def test_instructions_are_returned_not_executed(sandbox_calls):
    tid = _technique_with_skill(kind="instructions", body="1. open\n2. patch", interpreter="none")
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "ok" and result["kind"] == "instructions"
    assert "patch" in result["instructions"]
    assert sandbox_calls == []
    assert playbook_store.get_technique_skill(tid)["runs"] == 0  # not an execution


def test_missing_required_param_blocks_run(sandbox_calls):
    tid = _technique_with_skill(
        kind="command", body="nmap {{target}}", interpreter="none",
        params=[{"name": "target", "required": True}],
    )
    result = skill_runner.execute_skill(tid, session_id="s1", params={})
    assert result["status"] == "error" and "target" in result["error"]
    assert sandbox_calls == []


def test_params_render_into_body(monkeypatch, sandbox_calls):
    monkeypatch.setattr(skill_runner, "_allowed_command_binaries", lambda: {"nmap"})
    tid = _technique_with_skill(kind="command", body="nmap {{target}}", interpreter="none")
    result = skill_runner.execute_skill(tid, session_id="s1", params={"target": "10.0.0.1"})
    assert result["status"] == "ok"
    assert sandbox_calls[0] == ["nmap", "10.0.0.1"]


def test_command_skill_rejects_unknown_binary(monkeypatch, sandbox_calls):
    monkeypatch.setattr(skill_runner, "_allowed_command_binaries", lambda: {"nmap"})
    tid = _technique_with_skill(kind="command", body="rm -rf /", interpreter="none")
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "error" and "registry" in result["error"]
    assert sandbox_calls == []


def test_script_syntax_error_caught_before_subprocess(sandbox_calls):
    tid = _technique_with_skill(kind="script", body="def (:", interpreter="python")
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "error" and "SyntaxError" in result["error"]
    assert sandbox_calls == []


def test_no_skill_attached_returns_actionable_error():
    tid = playbook_store.add_manual_technique(technique="bare", worked=True)
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "error" and "no skill" in result["error"]


def test_disabled_skill_is_refused_without_running(sandbox_calls):
    tid = _technique_with_skill(kind="script", body="print(1)", interpreter="python")
    assert playbook_store.set_skill_enabled(tid, False) is True
    result = skill_runner.execute_skill(tid, session_id="s1")
    assert result["status"] == "error" and "switched off" in result["error"]
    assert sandbox_calls == []
    # Re-enabling lets it run again.
    playbook_store.set_skill_enabled(tid, True)
    assert skill_runner.execute_skill(tid, session_id="s1")["status"] == "ok"


def test_allowed_command_binaries_includes_registry_tools():
    # The registry is populated at import; at least one well-known external tool should be present.
    allowed = skill_runner._allowed_command_binaries()
    assert any(b in allowed for b in ("nmap", "radare2", "gdb", "strings"))


def _chain_two_skills(child_kind="instructions", child_body="step2", child_interp="none"):
    """root -> child, both carrying skills; returns (root_id, child_id)."""
    root_id = playbook_store.add_manual_technique(technique="root step", worked=True)
    playbook_store.attach_skill(root_id, playbook_store.build_skill(kind="instructions", body="step1", interpreter="none"))
    child_id = playbook_store.add_manual_technique(technique="child step", worked=True)
    playbook_store.attach_skill(child_id, playbook_store.build_skill(kind=child_kind, body=child_body, interpreter=child_interp))
    store = playbook_store.load_playbook_store()
    _k, child = playbook_store._find_entry_by_id(store, child_id)
    child["chained_from_ids"] = [root_id]
    playbook_store._write_playbook_store(store)
    return root_id, child_id


def test_skill_chain_runs_root_then_child_in_order():
    _root_id, child_id = _chain_two_skills()
    result = skill_runner.execute_skill_chain(child_id, session_id="s1")
    assert result["status"] == "ok"
    assert result["steps_run"] == 2 and result["steps_total"] == 2
    assert result["steps"][0]["technique"] == "root step"
    assert result["steps"][1]["technique"] == "child step"


def test_skill_chain_stops_at_first_failure(sandbox_calls):
    # child is a command skill invoking an unknown binary -> fails; root (instructions) runs first.
    _root_id, child_id = _chain_two_skills(child_kind="command", child_body="totally_unknown_bin x", child_interp="none")
    result = skill_runner.execute_skill_chain(child_id, session_id="s1")
    assert result["status"] == "error"
    assert result["steps_run"] == 2 and result["stopped_at_step"] == 1
    assert result["steps"][1]["result"]["status"] == "error"


def test_skill_chain_empty_when_no_skills_in_chain():
    tid = playbook_store.add_manual_technique(technique="bare", worked=True)
    result = skill_runner.execute_skill_chain(tid, session_id="s1")
    assert result["status"] == "error" and "no runnable skill chain" in result["error"]
