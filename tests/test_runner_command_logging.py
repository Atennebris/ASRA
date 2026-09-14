"""agent/tools/runner.py's _run_subprocess must log the REAL, fully-resolved command it actually
executed -- distinct from "run_tool start"'s own params=%s line, which is the model's raw
pre-build_command arguments. A builder can silently drop/reshape/default a field the model sent
(confirmed live: nuclei.py's build_nuclei_command only ever reads "target"/"tags", so an extra key
like "templates" a model adds never reaches the real command at all) -- without logging the real
argv, the only place it's ever visible is session.json's own log entry, built well after the fact.
This gap is exactly what made a real "why did an ostensibly-identical retry succeed" nuclei mystery
unresolvable from debug.log alone during a session audit.
"""
import os
import shutil
import subprocess

import agent.tools.runner as runner
from agent.tools.registry import ToolSpec

# The real, fully-resolved python3 this test's own process is running under -- matches what
# _resolve_executable(spec) will find for executable="python3" below, since run_tool now
# substitutes command[0] with that SAME resolution result (see the "command[0] = resolved_executable"
# fix in _run_subprocess: a bare name in the builder's own command is no longer trusted as-is,
# closing the gap where subprocess.run's own independent PATH lookup could silently pick a
# DIFFERENT binary than the one _resolve_executable (and any {TOOL}_PATH override) resolved).
_RESOLVED_PYTHON3 = shutil.which("python3")


def _make_spec(build_command, ok_exit_codes=frozenset({0})) -> ToolSpec:
    return ToolSpec(
        name="fake_tool", category="scan", tool_tier=2, executable="python3",
        build_command=build_command, requires_allowed_target=False, installed_by_default=True,
        ok_exit_codes=ok_exit_codes,
    )


def test_run_tool_logs_the_real_executed_command_on_success(monkeypatch):
    logged = []
    monkeypatch.setattr(runner.logger, "debug", lambda *args, **kwargs: logged.append(args))

    spec = _make_spec(lambda params: ["python3", "-c", "print('hi')"])
    runner.run_tool(spec, {"unsupported_key_the_builder_ignores": "some value"})

    finished_calls = [a for a in logged if a[0].startswith("run_tool: %s finished")]
    assert len(finished_calls) == 1
    # command=%s is now a positional arg in the finished-log call -- the real argv, not the raw
    # model-supplied params (which included a key the builder never even looked at), and command[0]
    # is the fully-resolved executable, not the builder's own bare "python3" string.
    assert [_RESOLVED_PYTHON3, "-c", "print('hi')"] in finished_calls[0]


def test_run_tool_logs_the_real_command_on_timeout(monkeypatch):
    logged = []
    monkeypatch.setattr(runner.logger, "debug", lambda *args, **kwargs: logged.append(args))

    spec = _make_spec(lambda params: ["python3", "-c", "import time; time.sleep(5)"])
    monkeypatch.setattr(runner, "_timeout_for", lambda spec: 0)
    result = runner.run_tool(spec, {})

    assert result["status"] == "timeout"
    timeout_calls = [a for a in logged if "timed out" in a[0]]
    assert len(timeout_calls) == 1
    assert [_RESOLVED_PYTHON3, "-c", "import time; time.sleep(5)"] in timeout_calls[0]


# --- {TOOL}_PATH override must reach the REAL executed command, not just the availability gate ---
# Real incident this covers: HTTPX_PATH was added specifically to let an operator bypass a broken
# same-named binary shadowing the real one on PATH (this project's own venv/bin/httpx, a pip
# package's CLI shim, ahead of /usr/local/bin/httpx's real ProjectDiscovery tool). _resolve_executable
# correctly honored the override for the "is this tool installed" check, but _run_subprocess's own
# `command = spec.build_command(params)` always put the bare registered name (e.g. "httpx") in
# command[0] -- subprocess.run then did its OWN independent PATH lookup for that bare name and
# silently ran the WRONG binary anyway, completely defeating the override for actual execution.


def test_a_tool_path_override_env_var_is_actually_executed_not_just_checked_for_availability(monkeypatch, tmp_path):
    # Two candidates: a "wrong" one that would win a bare PATH lookup, and the real one the
    # operator points at via the override -- exactly the venv-vs-/usr/local/bin httpx shape.
    wrong = tmp_path / "wrong-binary"
    wrong.write_text("#!/bin/sh\necho WRONG\n")
    wrong.chmod(0o755)
    real = tmp_path / "real-binary"
    real.write_text("#!/bin/sh\necho REAL $@\n")
    real.chmod(0o755)

    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("SOME_TOOL_PATH", str(real))

    spec = ToolSpec(
        name="some_tool", category="scan", tool_tier=2, executable="wrong-binary",
        build_command=lambda params: ["wrong-binary", "-x"],
        requires_allowed_target=False, installed_by_default=True,
    )
    result = runner.run_tool(spec, {})

    assert result["status"] == "ok"
    assert result["stdout"].strip() == "REAL -x"  # the override binary actually ran, not "wrong-binary"


def test_with_no_override_the_resolved_absolute_path_is_what_actually_runs(monkeypatch):
    """Even without an env override, command[0] must be the SAME resolved path _resolve_executable
    (and thus the availability check) used -- not a second, independent PATH lookup left to
    subprocess.run, which could disagree given a PATH ordering ambiguity."""
    monkeypatch.delenv("FAKE_TOOL_PATH", raising=False)
    spec = _make_spec(lambda params: ["python3", "-c", "import sys; print(sys.executable)"])

    result = runner.run_tool(spec, {})

    assert result["status"] == "ok"
    assert result["stdout"].strip() == _RESOLVED_PYTHON3


# --- ToolSpec.retry_command_on_result: a deterministic, code-level one-shot retry for a tool that
# comes back "ok" (no error/timeout status at all) but whose own output already names a fix for a
# silent degradation -- nmap's "Host seems down... try -Pn" is the real incident this exists for.
# Unlike agent/core.py's 1-Step Retry, this never needs (or costs) an LLM call.


def test_retry_command_on_result_reruns_once_with_the_corrected_command():
    spec = ToolSpec(
        name="fake_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", "print('needs retry')"],
        retry_command_on_result=lambda command, result: (
            ["python3", "-c", "print('fixed')"] if "needs retry" in (result.get("stdout") or "") else None
        ),
        requires_allowed_target=False, installed_by_default=True,
    )
    result = runner.run_tool(spec, {})

    assert result["status"] == "ok"
    assert result["stdout"].strip() == "fixed"
    assert result["retried"] is True


def test_retry_command_on_result_is_not_invoked_when_the_hook_returns_none():
    spec = ToolSpec(
        name="fake_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", "print('all good')"],
        retry_command_on_result=lambda command, result: None,
        requires_allowed_target=False, installed_by_default=True,
    )
    result = runner.run_tool(spec, {})

    assert result["status"] == "ok"
    assert result["stdout"].strip() == "all good"
    assert "retried" not in result


# --- ToolSpec.retry_command_on_timeout: a deterministic, code-level one-shot retry for a genuine
# subprocess timeout -- real incident this exists for: nmap's -O/--osscan-guess turning a slow host
# into a guaranteed-twice timeout (midnight-usr_24ba7e), with nothing for agent/core.py's own
# 1-Step Retry to react to (runner's timeout path has no stdout/stderr at all).


def test_retry_command_on_timeout_reruns_once_with_the_corrected_command(monkeypatch):
    calls = []

    def fake_run_tracked(command, timeout_seconds):
        calls.append(list(command))
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(cmd=command, timeout=timeout_seconds)
        return subprocess.CompletedProcess(args=command, returncode=0, stdout="fixed\n", stderr="")

    spec = ToolSpec(
        name="fake_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", "print('slow')"],
        retry_command_on_timeout=lambda command: ["python3", "-c", "print('fixed')"],
        requires_allowed_target=False, installed_by_default=True,
    )
    monkeypatch.setattr(runner, "_run_tracked", fake_run_tracked)
    result = runner.run_tool(spec, {})

    assert result["status"] == "ok"
    assert result["stdout"].strip() == "fixed"
    assert result["retried"] is True
    assert len(calls) == 2


def test_retry_command_on_timeout_is_not_invoked_when_the_hook_returns_none(monkeypatch):
    def fake_run_tracked(command, timeout_seconds):
        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout_seconds)

    spec = ToolSpec(
        name="fake_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", "print('slow')"],
        retry_command_on_timeout=lambda command: None,
        requires_allowed_target=False, installed_by_default=True,
    )
    monkeypatch.setattr(runner, "_run_tracked", fake_run_tracked)
    result = runner.run_tool(spec, {})

    assert result["status"] == "timeout"
    assert "retried" not in result


def test_retry_command_on_timeout_reports_timeout_again_if_the_correction_also_times_out(monkeypatch):
    def fake_run_tracked(command, timeout_seconds):
        raise subprocess.TimeoutExpired(cmd=command, timeout=timeout_seconds)

    spec = ToolSpec(
        name="fake_tool", category="scan", tool_tier=2, executable="python3",
        build_command=lambda params: ["python3", "-c", "print('slow')"],
        retry_command_on_timeout=lambda command: [*command, "-Pn"],
        requires_allowed_target=False, installed_by_default=True,
    )
    monkeypatch.setattr(runner, "_run_tracked", fake_run_tracked)
    result = runner.run_tool(spec, {})

    assert result["status"] == "timeout"
    assert result["command"] == [_RESOLVED_PYTHON3, "-c", "print('slow')", "-Pn"]


# --- run_tool's own "start" debug line strips server-side-injected fields: real, catastrophic
# incident -- check_subagent_task/delegate_to_subagent/etc. get the REAL, LIVE session dict
# injected as their own "_session" argument (agent/core.py's _run_tool_with_retry). Before this
# fix, "run_tool start: ... params=%s" logged that raw dict verbatim and unbounded, on every call,
# blowing a real debug.log up to 206 MB within a couple dozen check_subagent_task polls. ---


def test_loggable_params_strips_underscore_prefixed_keys():
    params = {"task_id": "abc123", "_session_id": "usr_x", "_session": {"logs": ["lots of state"]}}

    loggable = runner._loggable_params(params)

    assert loggable == {"task_id": "abc123"}


def test_loggable_params_keeps_real_arguments_untouched():
    params = {"identity": "user_a", "target": "https://example.com"}

    assert runner._loggable_params(params) == params


def test_run_tool_start_log_line_never_includes_an_injected_session(monkeypatch):
    logged = []
    monkeypatch.setattr(runner.logger, "debug", lambda *args, **kwargs: logged.append(args))
    spec = ToolSpec(
        name="check_subagent_task", category="post_exploit", tool_tier=1, executable="",
        build_command=None, native_function=lambda params: {"status": "ok"},
        requires_allowed_target=False, installed_by_default=True,
    )
    huge_session = {"session_id": "usr_x", "logs": [{"command": "x" * 500_000} for _ in range(20)]}

    runner.run_tool(spec, {"task_id": "abc123", "_session_id": "usr_x", "_session": huge_session})

    start_calls = [a for a in logged if a[0].startswith("run_tool start")]
    assert len(start_calls) == 1
    logged_params = start_calls[0][-1]  # params=%s is the last positional arg
    assert logged_params == {"task_id": "abc123"}
    assert "_session" not in logged_params


def test_run_tool_debug_lines_carry_no_subagent_tag_for_the_main_loop(monkeypatch):
    logged = []
    monkeypatch.setattr(runner.logger, "debug", lambda *args, **kwargs: logged.append(args))

    spec = _make_spec(lambda params: ["python3", "-c", "print('hi')"])
    runner.run_tool(spec, {})

    start_calls = [a for a in logged if str(a[0]).endswith("run_tool start: tool=%s category=%s tier=%s params=%s")]
    assert len(start_calls) == 1
    assert not start_calls[0][0].startswith("[%s] ")  # no subagent context active -- unprefixed


def test_run_tool_debug_lines_are_tagged_when_dispatched_on_a_subagents_behalf(monkeypatch):
    """Real, confirmed incident this fixes (333-usr_fb4459): this module has no RunContext to
    read a subagent's identity off (run_tool only ever gets spec/params), so its own TOOLS-
    category debug lines carried no subagent tag at all -- a concurrent subagent's tool call and
    the main loop's own interleaved in the same debug.log with nothing short of tracing call
    order by hand to tell them apart. current_subagent_label (agent/utils/debug.py) is set for
    the duration of a delegated subagent's own conversation (agent/core.py's
    _delegate_to_subagent_impl inner _run()) via the same asyncio-context-copy mechanism this
    module's own current_subprocess_registry already relies on.
    """
    logged = []
    monkeypatch.setattr(runner.logger, "debug", lambda *args, **kwargs: logged.append(args))

    spec = _make_spec(lambda params: ["python3", "-c", "print('hi')"])
    token = runner.current_subagent_label.set("subagent='Recon Bot' task=abc123")
    try:
        runner.run_tool(spec, {})
    finally:
        runner.current_subagent_label.reset(token)

    start_calls = [a for a in logged if str(a[0]).endswith("run_tool start: tool=%s category=%s tier=%s params=%s")]
    assert len(start_calls) == 1
    # _debug prepends "[%s] " + msg as the format string, with the label as the first %-arg --
    # logger.debug is lazy (%-style), so the label appears as a separate arg, not pre-interpolated.
    assert start_calls[0][0].startswith("[%s] ")
    assert start_calls[0][1] == "subagent='Recon Bot' task=abc123"
