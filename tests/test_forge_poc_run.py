"""forge_poc_run: compiles and RUNS a real, model-written Foundry test (extending forge-std's Test
contract) as an actually-executed PoC -- the dynamic complement to slither/mythril's static
analysis. Same execution shape as custom_exploit_run (persisted files + agent/tools/sandbox.py's
run_sandboxed + timeout), plus two extra preconditions custom_exploit_run never needed: forge
itself installed, and the shared forge-std scaffold vendored (agent/tools/native.py's
_foundry_scaffold_dir) -- both mocked here rather than depending on a real Foundry install in CI,
same "mock only the genuinely external dependency" discipline test_custom_exploit_run.py already
established for sys.executable/run_sandboxed.
"""
import subprocess
from pathlib import Path

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.tools import native
from agent.tools.registry import get_tools_by_category
from sessions import store

# Foundry's own documented `forge test --json` schema: keyed by "<path>:<ContractName>", each
# holding "test_results": {"<testSignature>": {"status", "reason", "decoded_logs"}}.
_REAL_SHAPED_PASS_OUTPUT = """{
  "test/PoC.t.sol:ExploitTest": {
    "test_results": {
      "test_exploit()": {
        "status": "Success",
        "reason": null,
        "decoded_logs": ["Attacker balance before: 0", "Attacker balance after: 1000000000000000000"]
      }
    }
  }
}"""

_REAL_SHAPED_FAIL_OUTPUT = """{
  "test/PoC.t.sol:ExploitTest": {
    "test_results": {
      "test_exploit()": {
        "status": "Failure",
        "reason": "assertion failed",
        "decoded_logs": []
      }
    }
  }
}"""


def _fake_installed(monkeypatch, tmp_path, forge_std_present=True):
    """Mocks both preconditions forge_poc_run checks before ever touching disk/subprocess: forge
    on PATH, and the shared forge-std scaffold vendored."""
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/forge" if name == "forge" else None)
    scaffold = tmp_path / "scaffold"
    if forge_std_present:
        (scaffold / "lib" / "forge-std" / "src").mkdir(parents=True)
        (scaffold / "lib" / "forge-std" / "src" / "Test.sol").write_text("// forge-std Test.sol stub")
    monkeypatch.setattr(native, "_foundry_scaffold_dir", lambda: scaffold)
    return scaffold


def test_source_is_required():
    result = native.forge_poc_run({})
    assert result["status"] == "error"
    assert "source" in result["error"]


def test_reports_a_clear_error_when_forge_is_not_installed(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: None)
    result = native.forge_poc_run({"source": "contract ExploitTest {}"})
    assert result["status"] == "error"
    assert "not installed" in result["error"]
    assert "setup_tools.sh" in result["error"]


def test_reports_a_clear_error_when_forge_std_scaffold_is_missing(monkeypatch, tmp_path):
    _fake_installed(monkeypatch, tmp_path, forge_std_present=False)
    result = native.forge_poc_run({"source": "contract ExploitTest {}"})
    assert result["status"] == "error"
    assert "forge-std" in result["error"]
    assert "setup_tools.sh" in result["error"]


def test_never_dispatches_a_subprocess_when_a_precondition_is_missing(monkeypatch):
    def _fail_if_called(*a, **k):
        raise AssertionError("run_sandboxed must not be called when forge itself is missing")

    monkeypatch.setattr(native, "run_sandboxed", _fail_if_called)
    monkeypatch.setattr(native.shutil, "which", lambda name: None)
    native.forge_poc_run({"source": "contract ExploitTest {}"})


def test_a_passing_poc_is_reported_ok_with_structured_test_results(monkeypatch, tmp_path):
    _fake_installed(monkeypatch, tmp_path)
    monkeypatch.setattr(
        native, "run_sandboxed",
        lambda command, scratch_dir, timeout_seconds: subprocess.CompletedProcess(command, 0, stdout=_REAL_SHAPED_PASS_OUTPUT, stderr=""),
    )

    result = native.forge_poc_run({"source": "contract ExploitTest is Test { function test_exploit() public {} }"})

    assert result["status"] == "ok"
    assert result["tests"] == [
        {
            "suite": "test/PoC.t.sol:ExploitTest", "test": "test_exploit()", "status": "Success",
            "reason": None, "logs": ["Attacker balance before: 0", "Attacker balance after: 1000000000000000000"],
        }
    ]


def test_a_failing_poc_is_still_reported_ok_as_a_real_verdict_not_a_tool_error(monkeypatch, tmp_path):
    """A PoC assertion that fails/reverts is a real, useful result (the exploit didn't work, or the
    target isn't vulnerable) -- not the same thing as forge itself being broken. Mirrors dalfox/
    osv-scanner's own "a meaningful non-zero exit is not a broken tool call" precedent."""
    _fake_installed(monkeypatch, tmp_path)
    monkeypatch.setattr(
        native, "run_sandboxed",
        lambda command, scratch_dir, timeout_seconds: subprocess.CompletedProcess(command, 1, stdout=_REAL_SHAPED_FAIL_OUTPUT, stderr=""),
    )

    result = native.forge_poc_run({"source": "contract ExploitTest is Test { function test_exploit() public { assert(false); } }"})

    assert result["status"] == "ok"
    assert result["tests"][0]["status"] == "Failure"


def test_a_compile_error_is_reported_as_a_real_error_not_a_failed_test_verdict(monkeypatch, tmp_path):
    """No structured "tests" data at all (forge prints a plain-text compile error, never valid
    --json) must never be read as a PoC verdict -- there's nothing here to build a finding on."""
    _fake_installed(monkeypatch, tmp_path)
    monkeypatch.setattr(
        native, "run_sandboxed",
        lambda command, scratch_dir, timeout_seconds: subprocess.CompletedProcess(
            command, 1, stdout="Error (5104): No visibility specified.\n --> test/PoC.t.sol:3:5", stderr="",
        ),
    )

    result = native.forge_poc_run({"source": "contract ExploitTest is Test { function test_exploit() {} }"})

    assert result["status"] == "error"
    assert "No visibility specified" in result["error"]


def test_reports_timeout(monkeypatch, tmp_path):
    _fake_installed(monkeypatch, tmp_path)

    def _raise_timeout(command, scratch_dir, timeout_seconds):
        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout_seconds)

    monkeypatch.setattr(native, "run_sandboxed", _raise_timeout)
    result = native.forge_poc_run({"source": "contract ExploitTest is Test {}"})
    assert result["status"] == "timeout"


def test_writes_the_source_and_a_foundry_toml_remapping_into_their_own_isolated_project_dir(monkeypatch, tmp_path):
    """Real, confirmed-live incident this layout fixes: `forge test --match-path` only filters
    which tests RUN, forge still COMPILES every .sol file under the project's own test dir
    regardless -- a shared test/ directory across calls meant one broken/leftover PoC from an
    earlier call broke every later call with an unrelated compile error, forever. Each call must
    get its OWN isolated mini Foundry project (own test/, own foundry.toml), never sharing a
    compilation unit with a sibling call."""
    scaffold = _fake_installed(monkeypatch, tmp_path)
    monkeypatch.setattr(
        native, "run_sandboxed",
        lambda command, scratch_dir, timeout_seconds: subprocess.CompletedProcess(command, 0, stdout=_REAL_SHAPED_PASS_OUTPUT, stderr=""),
    )

    session_id = store.create_session("example.com", name="forge-poc-persist-test")
    source = "contract ExploitTest is Test { function test_exploit() public {} }"
    result = native.forge_poc_run({"source": source, "_session_id": session_id})
    assert result["status"] == "ok"

    foundry_poc_root = Path(store.get_session_folder(session_id)) / "scripts" / "foundry_poc"
    sol_files = list(foundry_poc_root.rglob("*.t.sol"))
    assert len(sol_files) == 1
    assert sol_files[0].name == "PoC.t.sol"
    assert sol_files[0].read_text(encoding="utf-8") == source
    project_dir = sol_files[0].parent.parent  # .../<script_id>/test/PoC.t.sol -> .../<script_id>

    foundry_toml = (project_dir / "foundry.toml").read_text(encoding="utf-8")
    assert str(scaffold / "lib" / "forge-std" / "src") in foundry_toml

    assert (project_dir / "run.log").is_file()


def test_two_calls_use_separate_project_directories_never_sharing_a_compilation_unit(monkeypatch, tmp_path):
    _fake_installed(monkeypatch, tmp_path)
    monkeypatch.setattr(
        native, "run_sandboxed",
        lambda command, scratch_dir, timeout_seconds: subprocess.CompletedProcess(command, 0, stdout=_REAL_SHAPED_PASS_OUTPUT, stderr=""),
    )

    session_id = store.create_session("example.com", name="forge-poc-isolation-test")
    native.forge_poc_run({"source": "contract First is Test {}", "_session_id": session_id})
    native.forge_poc_run({"source": "contract Second is Test {}", "_session_id": session_id})

    foundry_poc_root = Path(store.get_session_folder(session_id)) / "scripts" / "foundry_poc"
    sol_files = list(foundry_poc_root.rglob("*.t.sol"))
    assert len(sol_files) == 2
    assert sol_files[0].parent.parent != sol_files[1].parent.parent
    contents = {f.read_text(encoding="utf-8") for f in sol_files}
    assert contents == {"contract First is Test {}", "contract Second is Test {}"}


def test_the_registered_forge_poc_run_tool_has_the_expected_shape():
    re_tools = {spec.name: spec for spec in get_tools_by_category("re")}
    assert "forge_poc_run" in re_tools
    spec = re_tools["forge_poc_run"]
    assert spec.tool_tier == 1
    assert spec.native_function is native.forge_poc_run
    assert spec.requires_allowed_target is False
    assert spec.allows_repeated_attempts is True


def test_parse_forge_poc_output_falls_back_to_raw_text_for_non_json():
    parsed = native.parse_forge_poc_output("forge: command not found\n")
    assert parsed == {"raw_output": "forge: command not found"}
