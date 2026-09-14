"""arjun_probe (agent/tools/native.py): hidden HTTP parameter discovery via Arjun, wrapped as a
native tier-1 function rather than the generic tier-2 build_command+parser shape every other
subprocess tool in this registry uses.

Real incident this shape exists because of: Arjun's own -oJ writer opens its output path in 'w+'
mode, which crashes outright ("File or stream is not seekable") the instant that path is a pipe
rather than a real file on disk — confirmed live against a real approved target, exactly what
-oJ /dev/stdout becomes once this project's own subprocess runner captures stdout
(subprocess.run(..., capture_output=True)). A real temp file plus reading it back afterward was
the only way to make this actually work, hence the same tempfile shape exploit_db_run/
custom_exploit_run already use, not a stdout-parsing builder like ffuf/nikto/whatweb.

subprocess.run is mocked throughout (no real arjun binary or network access needed) except where
noted — the mocks simulate Arjun's own real, confirmed-live behavior: writes the -oJ file only
when something was found, never on a clean/empty result.
"""
import asyncio
import subprocess as subprocess_module
from pathlib import Path

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import agent.core as core
from agent.core import RunContext, _apply_output_parser, _run_tool_with_retry
from agent.tools import native, wordlist_store
from agent.tools.registry import ToolSpec, get_tool


def test_arjun_is_registered_as_a_native_tier1_scan_tool():
    spec = get_tool("arjun")
    assert spec.tool_tier == 1
    assert spec.native_function is native.arjun_probe
    assert spec.category == "scan"
    assert spec.requires_allowed_target is False


def test_arjun_probe_rejects_an_invalid_target_without_calling_subprocess(monkeypatch):
    calls = []
    monkeypatch.setattr(native.subprocess, "run", lambda *a, **k: calls.append(a))

    result = native.arjun_probe({"target": "not a valid target \x00"})

    assert result["status"] == "error"
    assert calls == []  # rejected before ever reaching subprocess.run


def test_arjun_probe_reports_tool_unavailable_when_not_on_path(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: None)
    result = native.arjun_probe({"target": "https://example.com/search"})
    assert result["status"] == "tool_unavailable"
    assert result["tool"] == "arjun"


def test_arjun_probe_returns_no_hits_when_arjun_finds_nothing(monkeypatch):
    """Confirmed live: Arjun's own json_export() is only ever called once a hit exists -- a clean
    run leaves the -oJ path completely absent, not an empty file."""
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")

    def fake_run(argv, **kwargs):
        # The -oJ path is deliberately left untouched -- exactly what a real "nothing found" run does.
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    result = native.arjun_probe({"target": "https://example.com/search"})

    assert result["status"] == "ok"
    assert result["hits"] == []


def test_arjun_probe_parses_real_hits_from_the_temp_json_file(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")

    def fake_run(argv, **kwargs):
        json_path = argv[argv.index("-oJ") + 1]
        Path(json_path).write_text(
            '{"https://example.com/search": {"params": ["q", "debug"], "method": "GET", "headers": {}}}',
            encoding="utf-8",
        )
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    result = native.arjun_probe({"target": "https://example.com/search"})

    assert result["status"] == "ok"
    assert result["hits"] == [{"url": "https://example.com/search", "params": ["q", "debug"], "method": "GET"}]


def test_arjun_probe_cleans_up_the_temp_json_file_after_a_hit(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")
    written_path = {}

    def fake_run(argv, **kwargs):
        json_path = argv[argv.index("-oJ") + 1]
        written_path["path"] = json_path
        Path(json_path).write_text('{"https://example.com/": {"params": ["id"], "method": "GET"}}', encoding="utf-8")
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    native.arjun_probe({"target": "https://example.com/"})

    assert written_path and not Path(written_path["path"]).exists()


def test_arjun_probe_reports_the_known_upstream_crash_as_a_normal_error_not_a_python_exception(monkeypatch):
    """Real incident this guards against: Arjun 2.2.7 crashes with an unrelated AttributeError from
    inside its own initialize() whenever the target returns HTTP 400/413/418/429/503 on its first
    stability probe -- confirmed live against a real approved target. Must degrade to a plain
    {"status": "error"}, never propagate as an uncaught exception."""
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")

    def fake_run(argv, **kwargs):
        return subprocess_module.CompletedProcess(
            argv, returncode=1, stdout="",
            stderr="AttributeError: 'dict' object has no attribute 'status_code'",
        )

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    result = native.arjun_probe({"target": "https://example.com/search"})

    assert result["status"] == "error"
    assert "AttributeError" in result["error"]


def test_arjun_probe_reports_timeout_and_cleans_up(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")
    written_path = {}

    def fake_run(argv, **kwargs):
        written_path["path"] = argv[argv.index("-oJ") + 1]
        raise subprocess_module.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    result = native.arjun_probe({"target": "https://example.com/search"})

    assert result["status"] == "timeout"
    assert written_path and not Path(written_path["path"]).exists()
    # The real, executed command must be echoed back on a timeout -- interpret_arjun_timeout (the
    # _ERROR_HINTS entry for this tool) needs it to tell whether --stable was actually set.
    assert result["command"][0] == "/usr/local/bin/arjun"


def test_arjun_probe_timeout_command_includes_stable_flag_when_set(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")

    def fake_run(argv, **kwargs):
        raise subprocess_module.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout", 0))

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    result = native.arjun_probe({"target": "https://example.com/search", "stable": True})

    assert result["status"] == "timeout"
    assert "--stable" in result["command"]


def test_interpret_arjun_timeout_hints_at_stable_mode():
    """Real, confirmed incident: 6+ separate ~580-600s hangs across different real sessions,
    every one with --stable set, and each
    1-Step Retry never dropped the one flag actually causing the hang."""
    result = {"status": "timeout", "command": ["/usr/local/bin/arjun", "-u", "x", "--stable"]}
    hint = native.interpret_arjun_timeout(result)
    assert hint is not None
    assert "--stable" in hint


def test_interpret_arjun_timeout_returns_none_without_stable_mode():
    result = {"status": "timeout", "command": ["/usr/local/bin/arjun", "-u", "x"]}
    assert native.interpret_arjun_timeout(result) is None


def test_interpret_arjun_timeout_returns_none_for_a_real_error_not_a_timeout():
    result = {"status": "error", "command": ["/usr/local/bin/arjun", "-u", "x", "--stable"]}
    assert native.interpret_arjun_timeout(result) is None


def test_interpret_arjun_crash_recognizes_the_known_initialize_attributeerror():
    """Real, confirmed incident this fixes: Arjun 2.2.7 crashes with an AttributeError inside its
    own initialize() whenever the target returns HTTP 400/413/418/429/503 on its very first
    stability probe -- confirmed live, the identical crash fired on both the original call and its
    own 1-Step Retry, ~44s wasted for zero possible gain since no corrected argument could ever
    change an upstream Arjun bug."""
    result = {
        "status": "error", "exit_code": 1,
        "error": (
            "  File \".../arjun/__main__.py\", line 135, in initialize\n"
            "    print('%s Target returned HTTP %i, this may cause problems.' % (bad, request.status_code))\n"
            "AttributeError: 'dict' object has no attribute 'status_code'\n"
        ),
    }
    hint = native.interpret_arjun_crash(result)
    assert hint is not None
    assert "permanent" in hint


def test_interpret_arjun_crash_returns_none_for_an_unrelated_error():
    result = {"status": "error", "exit_code": 1, "error": "connection refused"}
    assert native.interpret_arjun_crash(result) is None


def test_interpret_arjun_crash_returns_none_for_a_timeout():
    result = {"status": "timeout", "command": ["/usr/local/bin/arjun", "-u", "x"]}
    assert native.interpret_arjun_crash(result) is None


def test_interpret_arjun_failure_dispatches_to_whichever_hint_matches():
    """_ERROR_HINTS only allows one callable per tool name -- interpret_arjun_failure is the
    combined entry actually registered for "arjun", so it must reach both known failure shapes."""
    timeout_result = {"status": "timeout", "command": ["/usr/local/bin/arjun", "-u", "x", "--stable"]}
    assert native.interpret_arjun_failure(timeout_result) is not None

    crash_result = {"status": "error", "error": "AttributeError inside initialize(): request.status_code"}
    assert native.interpret_arjun_failure(crash_result) is not None

    unrelated_result = {"status": "error", "error": "connection refused"}
    assert native.interpret_arjun_failure(unrelated_result) is None


def test_apply_output_parser_marks_the_known_arjun_crash_failed_not_error():
    """agent/core.py's _PERMANENT_ERROR_HINTS: a hint alone (_ERROR_HINTS) still lets
    _run_tool_with_retry pay for one doomed 1-Step Retry round-trip, since that gate only checks
    status ("error"/"timeout" are retryable). Confirmed live (a real YesWeHack session, usr_45dd32):
    Arjun's own known upstream initialize() crash cost a real ~25-44s round-trip despite the hint
    already correctly firing. status flips to "failed" (not in _RETRYABLE_STATUSES) specifically so
    the retry never happens at all, not just so the eventual retry has a better message."""
    spec = ToolSpec(
        name="arjun", category="scan", tool_tier=1, executable="", build_command=None,
        native_function=native.arjun_probe, requires_allowed_target=False, installed_by_default=True,
    )
    raw_result = {
        "status": "error", "exit_code": 1,
        "error": "AttributeError inside initialize(): 'dict' object has no attribute 'status_code'",
    }

    result = _apply_output_parser(spec, raw_result)

    assert result["status"] == "failed"
    assert "permanent" in result["error"]


def test_apply_output_parser_leaves_the_arjun_timeout_case_retryable():
    """The permanent-crash fix must not touch the SIBLING --stable timeout case -- that one IS
    fixable by a corrected retry (dropping --stable), so it must keep its normal "timeout" status
    and go through the ordinary one-retry path unchanged."""
    spec = ToolSpec(
        name="arjun", category="scan", tool_tier=1, executable="", build_command=None,
        native_function=native.arjun_probe, requires_allowed_target=False, installed_by_default=True,
    )
    raw_result = {"status": "timeout", "command": ["/usr/local/bin/arjun", "-u", "https://example.com", "--stable"]}

    result = _apply_output_parser(spec, raw_result)

    assert result["status"] == "timeout"
    assert "drop" in result["error"].lower() or "--stable" in result["error"]


def test_run_tool_with_retry_skips_the_correction_round_trip_for_a_known_arjun_crash(monkeypatch):
    """End-to-end proof of the real incident's own fix: the LLM must never even be asked for a
    correction once the known-permanent Arjun crash signature is recognized -- same "prove it
    through the real dispatch path" discipline as test_nuclei_failure_hint.py's own end-to-end test."""
    class _ShouldNeverBeCalledLLM:
        provider_id = "test-provider"
        model = "test-model"
        context_limit = None

        def complete(self, messages, tools=None, stop_check=None):
            raise AssertionError("a known-permanent failure must never trigger a correction LLM call")

    spec = ToolSpec(
        name="arjun", category="scan", tool_tier=1, executable="", build_command=None,
        native_function=native.arjun_probe, requires_allowed_target=False, installed_by_default=True,
    )
    session = {"session_id": "usr_arjun_permanent_test", "logs": []}
    ctx = RunContext(llm=_ShouldNeverBeCalledLLM(), session=session, session_id=session["session_id"])

    monkeypatch.setattr(core, "run_tool", lambda spec, args: {
        "status": "error", "exit_code": 1,
        "error": "AttributeError inside initialize(): 'dict' object has no attribute 'status_code'",
    })

    result = asyncio.run(_run_tool_with_retry(ctx, spec, {"target": "https://example.com"}))

    assert result["status"] == "failed"
    assert "permanent" in result["error"]


def test_arjun_probe_defaults_method_to_get_and_rejects_an_invalid_method(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")
    seen = {}

    def fake_run(argv, **kwargs):
        seen["method"] = argv[argv.index("-m") + 1]
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)

    native.arjun_probe({"target": "https://example.com/search"})
    assert seen["method"] == "GET"

    native.arjun_probe({"target": "https://example.com/search", "method": "made_up_method"})
    assert seen["method"] == "GET"  # invalid enum value silently falls back, not rejected outright

    native.arjun_probe({"target": "https://example.com/search", "method": "post"})
    assert seen["method"] == "POST"  # case-insensitive


def test_arjun_probe_injects_user_agent_header(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")
    seen = {}

    def fake_run(argv, **kwargs):
        seen["headers"] = argv[argv.index("--headers") + 1]
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    native.arjun_probe({"target": "https://example.com/search", "_user_agent": "ASRA-Scanner"})

    assert seen["headers"] == "User-Agent: ASRA-Scanner"


def test_arjun_probe_joins_user_agent_and_extra_headers_with_literal_backslash_n(monkeypatch):
    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")
    seen = {}

    def fake_run(argv, **kwargs):
        seen["headers"] = argv[argv.index("--headers") + 1]
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    native.arjun_probe({
        "target": "https://example.com/search", "_user_agent": "ASRA-Scanner",
        "_extra_headers": {"X-HackerOne-Research": "my_handle"},
    })

    assert seen["headers"] == "User-Agent: ASRA-Scanner\\nX-HackerOne-Research: my_handle"


def test_arjun_probe_uses_the_assigned_wordlist_when_the_model_gives_none(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_store, "WORDLIST_STORE_PATH", tmp_path / "assignments.json")
    assigned = tmp_path / "params.txt"
    assigned.write_text("id\ndebug\n", encoding="utf-8")
    wordlist_store.set_assignment("arjun", str(assigned))

    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")
    seen = {}

    def fake_run(argv, **kwargs):
        seen["wordlist"] = argv[argv.index("-w") + 1]
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    native.arjun_probe({"target": "https://example.com/search"})

    assert seen["wordlist"] == str(assigned)


def test_arjun_probe_explicit_wordlist_wins_over_the_assignment(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlist_store, "WORDLIST_STORE_PATH", tmp_path / "assignments.json")
    assigned = tmp_path / "params.txt"
    assigned.write_text("id\n", encoding="utf-8")
    wordlist_store.set_assignment("arjun", str(assigned))

    monkeypatch.setattr(native.shutil, "which", lambda name: "/usr/local/bin/arjun")
    seen = {}

    def fake_run(argv, **kwargs):
        seen["wordlist"] = argv[argv.index("-w") + 1]
        return subprocess_module.CompletedProcess(argv, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(native.subprocess, "run", fake_run)
    native.arjun_probe({"target": "https://example.com/search", "wordlist": "/custom/params.txt"})

    assert seen["wordlist"] == "/custom/params.txt"
