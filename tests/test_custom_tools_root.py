"""agent/tools/custom_tools_root.py (TOOLS_CUSTOM_ROOT -- Settings -> Tools -> "Custom tools
path") + its wiring into agent/tools/runner.py's own _resolve_executable fallback chain.

One operator-supplied root directory for a pre-existing tool collection never installed through
setup_tools.sh, resolved as the LAST resort after a tool's own {TOOL}_PATH override and the system
PATH have both already failed.
"""
from __future__ import annotations

import stat
import subprocess

import agent.tools.custom_tools_root as custom_tools_root
import agent.tools.runner as runner
from agent.tools import custom_tools_store
from agent.tools.registry import ToolSpec


def _make_executable(path):
    path.write_text("#!/bin/sh\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


# --- translate_windows_path_to_wsl -------------------------------------------------------------


def test_translate_windows_backslash_path_to_wsl_mount_form():
    assert custom_tools_root.translate_windows_path_to_wsl("E:\\tools") == "/mnt/e/tools"


def test_translate_windows_forward_slash_path_to_wsl_mount_form():
    assert custom_tools_root.translate_windows_path_to_wsl("E:/tools/sub") == "/mnt/e/tools/sub"


def test_translate_lowercases_the_drive_letter():
    assert custom_tools_root.translate_windows_path_to_wsl("e:\\tools") == "/mnt/e/tools"


def test_translate_bare_drive_root_with_no_trailing_path():
    assert custom_tools_root.translate_windows_path_to_wsl("E:\\") == "/mnt/e"


def test_translate_leaves_an_already_wsl_path_unchanged():
    assert custom_tools_root.translate_windows_path_to_wsl("/mnt/e/tools") == "/mnt/e/tools"


def test_translate_leaves_a_plain_linux_path_unchanged():
    assert custom_tools_root.translate_windows_path_to_wsl("/opt/tools") == "/opt/tools"


def test_translate_strips_surrounding_whitespace():
    assert custom_tools_root.translate_windows_path_to_wsl("  E:\\tools  ") == "/mnt/e/tools"


# --- get/save/clear (env persistence) -----------------------------------------------------------


def _isolate_env(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"
    env_path.write_text("")
    monkeypatch.setattr(custom_tools_root, "_ENV_PATH", str(env_path))
    monkeypatch.delenv("TOOLS_CUSTOM_ROOT", raising=False)
    return env_path


def test_get_custom_tools_root_is_none_when_unset(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    assert custom_tools_root.get_custom_tools_root() is None


def test_get_custom_tools_root_is_none_for_a_blank_value(monkeypatch):
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", "")
    assert custom_tools_root.get_custom_tools_root() is None


def test_save_custom_tools_root_translates_before_writing(tmp_path, monkeypatch):
    env_path = _isolate_env(tmp_path, monkeypatch)

    custom_tools_root.save_custom_tools_root("E:\\tools")

    assert custom_tools_root.get_custom_tools_root() == "/mnt/e/tools"
    assert "/mnt/e/tools" in env_path.read_text()
    assert "E:\\tools" not in env_path.read_text()


def test_save_custom_tools_root_with_blank_clears_it(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    custom_tools_root.save_custom_tools_root("/mnt/e/tools")

    custom_tools_root.save_custom_tools_root("   ")

    assert custom_tools_root.get_custom_tools_root() is None


def test_clear_custom_tools_root(tmp_path, monkeypatch):
    _isolate_env(tmp_path, monkeypatch)
    custom_tools_root.save_custom_tools_root("/mnt/e/tools")

    custom_tools_root.clear_custom_tools_root()

    assert custom_tools_root.get_custom_tools_root() is None


# --- resolve_via_custom_root ---------------------------------------------------------------------


def test_resolve_via_custom_root_returns_none_when_unset(monkeypatch):
    monkeypatch.delenv("TOOLS_CUSTOM_ROOT", raising=False)
    assert custom_tools_root.resolve_via_custom_root("nmap") is None


def test_resolve_via_custom_root_finds_a_flat_layout_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    _make_executable(tmp_path / "nmap")

    assert custom_tools_root.resolve_via_custom_root("nmap") == str(tmp_path / "nmap")


def test_resolve_via_custom_root_finds_an_install_base_bin_layout_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    (tmp_path / "bin").mkdir()
    _make_executable(tmp_path / "bin" / "nmap")

    assert custom_tools_root.resolve_via_custom_root("nmap") == str(tmp_path / "bin" / "nmap")


def test_resolve_via_custom_root_returns_none_when_neither_layout_has_it(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    assert custom_tools_root.resolve_via_custom_root("nmap") is None


def test_resolve_via_custom_root_finds_a_nested_binary(tmp_path, monkeypatch):
    """Real, confirmed gap this closes: Ghidra's own distribution nests the real binary two levels
    deep (<root>/ghidra_<version>/support/analyzeHeadless), which neither the flat nor the bin/
    layout alone would ever find. Every operator's own collection is organized differently (that's
    why this is a configurable root at all) -- this must find it generically, not via a
    Ghidra-specific special case."""
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    nested = tmp_path / "ghidra_12.1.4" / "support"
    nested.mkdir(parents=True)
    _make_executable(nested / "analyzeHeadless")

    assert custom_tools_root.resolve_via_custom_root("analyzeHeadless") == str(nested / "analyzeHeadless")


def test_resolve_via_custom_root_does_not_descend_past_max_depth(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    monkeypatch.setattr(custom_tools_root, "_MAX_SEARCH_DEPTH", 1)
    too_deep = tmp_path / "a" / "b" / "c"
    too_deep.mkdir(parents=True)
    _make_executable(too_deep / "buriedtool")

    assert custom_tools_root.resolve_via_custom_root("buriedtool") is None


def test_resolve_via_custom_root_rebuilds_the_index_when_the_root_changes(tmp_path, monkeypatch):
    """Not a stale cache keyed on the FIRST root ever seen -- switching TOOLS_CUSTOM_ROOT to a
    different directory mid-process (Settings -> Tools -> Save path, no restart) must see the new
    root's own files, not whatever the previous root's index happened to contain."""
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    _make_executable(second_root / "onlyinsecond")

    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(first_root))
    assert custom_tools_root.resolve_via_custom_root("onlyinsecond") is None

    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(second_root))
    assert custom_tools_root.resolve_via_custom_root("onlyinsecond") == str(second_root / "onlyinsecond")


def test_resolve_via_custom_root_reindexes_after_the_cache_goes_stale(tmp_path, monkeypatch):
    """A file added to an UNCHANGED root after the index was built must still eventually become
    visible (within TOOLS_CUSTOM_ROOT_INDEX_TTL_SECONDS) -- not require a process restart, and not
    require a different root value to trigger a rebuild."""
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    assert custom_tools_root.resolve_via_custom_root("latertool") is None

    _make_executable(tmp_path / "latertool")
    # time.monotonic()'s own baseline isn't guaranteed to be a "large" number (confirmed live: a
    # short-lived process can see it starting near zero) -- 0.0 alone doesn't reliably read as
    # stale. Compute an explicitly-older-than-the-TTL timestamp relative to the real current value
    # instead of assuming anything about where the clock itself starts counting from.
    stale_timestamp = custom_tools_root.time.monotonic() - custom_tools_root._INDEX_CACHE_TTL_SECONDS - 1
    monkeypatch.setattr(custom_tools_root, "_index_cache_built_at", stale_timestamp)

    assert custom_tools_root.resolve_via_custom_root("latertool") == str(tmp_path / "latertool")


def test_test_custom_tools_root_always_sees_a_file_added_after_an_earlier_call(tmp_path, monkeypatch):
    """test_custom_tools_root must never serve a cached/stale answer -- it's the operator's explicit
    "did this just work" check, so it always re-walks live, unlike resolve_via_custom_root's own
    TTL-cached hot path."""
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: ["nmap"])
    first = custom_tools_root.test_custom_tools_root(str(tmp_path))
    assert first["found"] == []

    _make_executable(tmp_path / "nmap")
    second = custom_tools_root.test_custom_tools_root(str(tmp_path))
    assert second["found"] == ["nmap"]


# --- test_custom_tools_root (the "Test path" button's own live check) ---------------------------


def test_test_custom_tools_root_splits_found_and_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: ["nmap", "nuclei"])
    _make_executable(tmp_path / "nmap")

    result = custom_tools_root.test_custom_tools_root(str(tmp_path))

    assert result["found"] == ["nmap"]
    assert result["missing"] == ["nuclei"]


def test_test_custom_tools_root_translates_a_windows_style_candidate(monkeypatch):
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: [])
    result = custom_tools_root.test_custom_tools_root("E:\\tools")
    assert result["path"] == "/mnt/e/tools"


def test_known_external_executables_excludes_native_tier1_tools():
    """Tier-1 (native Python) ToolSpecs always register executable="" (see registry.py) --
    nothing for a filesystem path check to ever look for, so they must never appear here."""
    assert "" not in custom_tools_root._known_external_executables()


def test_known_external_executables_excludes_an_absolute_path_executable():
    """Real, confirmed bug this guards against: qiling_emulate (agent/tools/__init__.py) is
    tier_tier=2 but registers executable=sys.executable (an absolute path, run via THIS process's
    own venv interpreter, never looked up by bare name on PATH at all). Without this exclusion,
    pathlib's `/` operator silently discards the left operand whenever the right one is already
    absolute (Path(root) / "/abs/python" == Path("/abs/python")) -- so the real venv interpreter's
    own existence got reported as "found at this root" for literally ANY root, including an empty
    throwaway test directory with nothing in it."""
    names = custom_tools_root._known_external_executables()
    assert not any("/" in name for name in names)


def test_test_custom_tools_root_never_reports_an_absolute_path_executable_as_found(tmp_path):
    """End-to-end regression for the same bug, against the REAL, unmocked TOOL_REGISTRY: an empty
    directory must never report qiling_emulate (or anything else) as "found" through pathlib's own
    absolute-path shortcut."""
    result = custom_tools_root.test_custom_tools_root(str(tmp_path))
    assert result["found"] == []


# --- wiring into runner.py's _resolve_executable fallback chain ---------------------------------


def _tier2_spec(name="customtool", executable="customtool"):
    return ToolSpec(
        name=name, category="recon", tool_tier=2, executable=executable,
        build_command=lambda params: [executable], requires_allowed_target=False,
        installed_by_default=False,
    )


def test_resolve_executable_falls_back_to_custom_root_when_path_lookup_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("CUSTOMTOOL_PATH", raising=False)
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    _make_executable(tmp_path / "customtool")

    resolved = runner._resolve_executable(_tier2_spec())

    assert resolved == str(tmp_path / "customtool")


def test_resolve_executable_prefers_tool_path_override_over_custom_root(tmp_path, monkeypatch):
    override = tmp_path / "override" / "customtool"
    override.parent.mkdir()
    _make_executable(override)
    monkeypatch.setenv("CUSTOMTOOL_PATH", str(override))
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))  # would also resolve it -- must not be reached
    _make_executable(tmp_path / "customtool")

    resolved = runner._resolve_executable(_tier2_spec())

    assert resolved == str(override)


def test_resolve_executable_prefers_system_path_over_custom_root(tmp_path, monkeypatch):
    monkeypatch.delenv("CUSTOMTOOL_PATH", raising=False)
    monkeypatch.setattr(runner.shutil, "which", lambda name: "/usr/bin/customtool")
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))
    _make_executable(tmp_path / "customtool")  # would also resolve it -- must not be reached

    resolved = runner._resolve_executable(_tier2_spec())

    assert resolved == "/usr/bin/customtool"


def test_resolve_executable_returns_none_when_nothing_resolves(tmp_path, monkeypatch):
    monkeypatch.delenv("CUSTOMTOOL_PATH", raising=False)
    monkeypatch.setattr(runner.shutil, "which", lambda name: None)
    monkeypatch.setenv("TOOLS_CUSTOM_ROOT", str(tmp_path))  # present but empty -- nothing to find

    assert runner._resolve_executable(_tier2_spec()) is None


# --- discover_custom_tool_candidates -------------------------------------------------------------


def _isolate_store(tmp_path, monkeypatch):
    monkeypatch.setattr(custom_tools_store, "CUSTOM_TOOLS_STORE_PATH", tmp_path / "custom_tools.json")


def test_discover_candidates_excludes_known_tool_names(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: ["nmap"])
    _make_executable(tmp_path / "nmap")  # a known tool -- never a "(custom)" candidate
    _make_executable(tmp_path / "mystery_tool")

    candidates = custom_tools_root.discover_custom_tool_candidates(str(tmp_path))

    assert [c["name"] for c in candidates] == ["mystery_tool"]


def test_discover_candidates_excludes_already_registered_paths(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: [])
    binary = tmp_path / "mystery_tool"
    _make_executable(binary)
    custom_tools_store.add_custom_tool(name="mystery_tool", path=str(binary), description="", requires_target=True, category="recon")

    candidates = custom_tools_root.discover_custom_tool_candidates(str(tmp_path))

    assert candidates == []  # already registered -- never re-offered


def test_discover_candidates_ignores_non_executable_files(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: [])
    (tmp_path / "readme.txt").write_text("not a binary")

    assert custom_tools_root.discover_custom_tool_candidates(str(tmp_path)) == []


def test_discover_candidates_checks_both_flat_and_bin_layout(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: [])
    (tmp_path / "bin").mkdir()
    _make_executable(tmp_path / "bin" / "mystery_tool")

    candidates = custom_tools_root.discover_custom_tool_candidates(str(tmp_path))

    assert [c["name"] for c in candidates] == ["mystery_tool"]


def test_discover_candidates_translates_a_windows_style_path(tmp_path, monkeypatch):
    _isolate_store(tmp_path, monkeypatch)
    monkeypatch.setattr(custom_tools_root, "_known_external_executables", lambda: [])
    # No real Windows drive exists under WSL2 in this test environment -- just confirm translation
    # is actually applied (no crash, and a path that genuinely doesn't exist yields no candidates,
    # not an error) rather than the raw "E:\tools" string being used as a literal POSIX path.
    candidates = custom_tools_root.discover_custom_tool_candidates("E:\\definitely-not-a-real-path")
    assert candidates == []


# --- capture_usage_hint ---------------------------------------------------------------------------


def test_capture_usage_hint_returns_help_output(tmp_path, monkeypatch):
    script = tmp_path / "fake_tool"
    script.write_text("#!/bin/sh\necho 'usage: fake_tool [options]'\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    hint = custom_tools_root.capture_usage_hint(str(script))

    assert "usage: fake_tool" in hint


def test_capture_usage_hint_falls_back_to_second_flag(tmp_path, monkeypatch):
    """--help fails (unrecognized option), -h succeeds -- the second flag must still be tried."""
    script = tmp_path / "fake_tool"
    script.write_text("#!/bin/sh\nif [ \"$1\" = \"-h\" ]; then echo 'short usage'; else exit 1; fi\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    hint = custom_tools_root.capture_usage_hint(str(script))

    assert "short usage" in hint


def test_capture_usage_hint_returns_empty_string_on_total_failure(tmp_path):
    assert custom_tools_root.capture_usage_hint(str(tmp_path / "does-not-exist")) == ""


def test_capture_usage_hint_never_hangs_on_a_binary_that_reads_stdin(monkeypatch):
    """The real incident class this guards against (runner.py's own _run_tracked docstring,
    wpscan's interactive prompt) -- stdin=DEVNULL must actually be passed through."""
    captured = {}

    def _fake_run(argv, **kwargs):
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "ok", "")

    monkeypatch.setattr(custom_tools_root.subprocess, "run", _fake_run)
    custom_tools_root.capture_usage_hint("/some/tool")
    assert captured["kwargs"]["stdin"] == subprocess.DEVNULL
