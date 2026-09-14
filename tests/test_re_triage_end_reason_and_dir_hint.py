"""Coverage for the RE-triage log-review fixes:

- A baseline pass that ends on a SAFEGUARD (wall-clock backstop / progress stall) must record an
  honest `triage_end_reason` so a timed-out, zero-finding pass never reads exactly like a clean
  success -- the real "completed, but 0 results and I don't understand why" operator complaint.
- A DIRECTORY target must get a deterministic listing hint (naming the real executable inside) so
  the model never wastes its whole budget feeding the directory path straight to radare2. Real
  incident: NinthCircle-crackmes-usr_a8899a fed a directory to radare2 eight times for empty output.
- radare2's read-only `sections`/`entrypoint` analyses build the right structured-JSON commands, so
  the model has an allowlisted way to get them instead of routing around the tool via a raw
  subprocess.
"""
import asyncio

import pytest

from agent.core import (
    RunContext,
    _re_directory_target_hint,
    _re_triage_end_reason_message,
    _run_llm_tool_loop,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.builders.radare2 import build_radare2_command
from agent.tools.registry import ToolSpec
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


# --- end-reason message ------------------------------------------------------

def test_natural_finish_has_no_end_reason():
    assert _re_triage_end_reason_message(None) is None


def test_wallclock_stop_reads_as_time_limit():
    msg = _re_triage_end_reason_message("exceeded the 1800s wall-clock backstop")
    assert msg is not None
    assert "time limit" in msg
    assert "may be incomplete" in msg


def test_progress_stall_stop_reads_as_stopped_early():
    msg = _re_triage_end_reason_message(
        "25 tool calls in a row without recording any new finding, hypothesis, or target-profile fact"
    )
    assert msg is not None
    assert "stopped early" in msg


# --- last_stop_reason propagation from the loop ------------------------------

class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def _make_tool(name: str) -> ToolSpec:
    return ToolSpec(
        name=name, category="recon", tool_tier=2, executable="true",
        build_command=lambda args: ["true"], requires_allowed_target=False, installed_by_default=True,
    )


async def _noop_execute(spec, arguments):
    return {"status": "ok", "tool": spec.name}


def test_safeguard_stop_sets_last_stop_reason():
    # A progress-stall stop must leave a reason on the context for run_re_triage to record.
    llm = _ScriptedLLM([("dns_lookup", {"domain": f"h{i}.example.com"}) for i in range(20)])
    ctx = RunContext(llm=llm, session={"logs": []}, session_id="usr_reason_test")

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "re_triage",
        execute_tool=_noop_execute, expect_json_final=False, progress_stall_threshold=3,
    ))

    assert ctx.last_stop_reason is not None
    assert "without recording" in ctx.last_stop_reason


def test_natural_finish_leaves_last_stop_reason_none():
    # The model finishing on its own (script runs out -> plain text reply) is a clean end, no reason.
    llm = _ScriptedLLM([("dns_lookup", {"domain": "example.com"})])
    ctx = RunContext(llm=llm, session={"logs": []}, session_id="usr_clean_test")

    _run(_run_llm_tool_loop(
        ctx, "system", "task", [_make_tool("dns_lookup")], "re_triage",
        execute_tool=_noop_execute, expect_json_final=False, progress_stall_threshold=25,
    ))

    assert ctx.last_stop_reason is None


# --- directory-target hint ---------------------------------------------------

def test_single_file_target_gets_no_directory_hint(tmp_path):
    f = tmp_path / "prog.bin"
    f.write_bytes(b"\x7fELF\x02\x01\x01\x00")
    assert _re_directory_target_hint(str(f)) == ""


def test_directory_hint_names_the_executable_inside(tmp_path):
    d = tmp_path / "crackme"
    d.mkdir()
    (d / "NinthCircle.exe").write_bytes(b"MZ\x90\x00" + b"\x00" * 60)
    (d / "README.txt").write_text("goal: derive a serial")

    hint = _re_directory_target_hint(str(d))
    assert "DIRECTORY" in hint
    assert "NinthCircle.exe" in hint
    assert "README.txt" in hint
    # The .exe sniffs as a real PE (MZ magic), so it must be called out as a loadable executable.
    assert "Loadable executable" in hint


def test_directory_of_plain_source_lists_but_flags_no_executable(tmp_path):
    d = tmp_path / "repo"
    d.mkdir()
    (d / "app.py").write_text("print('hi')")
    (d / "utils.py").write_text("x = 1")

    hint = _re_directory_target_hint(str(d))
    assert "DIRECTORY" in hint
    assert "app.py" in hint
    # No file sniffs as an executable -> the "loadable executable" call-out must be absent, so a
    # genuine source repo is never mislabeled as a binary to disassemble.
    assert "Loadable executable" not in hint


# --- radare2 read-only analyses ----------------------------------------------

def test_radare2_sections_builds_structured_json_command(tmp_path):
    f = tmp_path / "b.bin"
    f.write_bytes(b"\x7fELF")
    cmd = build_radare2_command({"file_path": str(f), "analysis": "sections"})
    assert "iSj" in cmd
    # A read-only listing needs no address argument.
    assert "@" not in " ".join(cmd)


def test_radare2_entrypoint_builds_structured_json_command(tmp_path):
    f = tmp_path / "b.bin"
    f.write_bytes(b"\x7fELF")
    cmd = build_radare2_command({"file_path": str(f), "analysis": "entrypoint"})
    assert "iej" in cmd
