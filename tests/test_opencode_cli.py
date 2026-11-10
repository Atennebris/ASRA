"""agent/opencode_cli.py and everything that now hangs off it: the specific "Windows-side only vs
not installed anywhere" diagnosis, the one-click install wiring (arsenal_install's --opencode-only
run, main.py's routes + partials), and the guarantee that a missing CLI neither triggers nor hides
behind the server-start failure cooldown. Nothing here spawns a real installer or a real opencode.
"""
import pytest
from fastapi.testclient import TestClient

import main
from agent import opencode_cli, opencode_local_provider as provider
from agent.chat import _format_llm_error
from agent.opencode_cli import (
    INSTALL_ACTION,
    OpencodeCliUnavailable,
    diagnose_opencode_cli,
    is_windows_mount_path,
)
from agent.tools import llm_test_job

WINDOWS_COPY = "/mnt/c/Users/rusuc/AppData/Roaming/npm/opencode"


def _fake_which(table, calls=None):
    """shutil.which stand-in: `table` maps (name, path-was-filtered) -> result."""
    def which(name, path=None):
        if calls is not None:
            calls.append((name, path))
        return table.get((name, path is not None))
    return which


@pytest.fixture
def in_wsl(monkeypatch):
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu-24.04")
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/mnt/c/Windows:/mnt/c/Users/rusuc/AppData/Roaming/npm")


# --- diagnosis ----------------------------------------------------------------------------------


@pytest.mark.parametrize("path,expected", [
    ("/mnt/c/Users/x/opencode", True), ("/mnt/d", True), ("/mnt/C/x", True),
    ("/mnt/data/opencode", False), ("/usr/local/bin/opencode", False), ("/mnt", False),
])
def test_windows_mount_detection_only_matches_single_letter_drives(path, expected):
    assert is_windows_mount_path(path) is expected


def test_native_copy_is_usable_and_has_no_explanation(monkeypatch, in_wsl):
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): "/usr/local/bin/opencode"}))
    status = diagnose_opencode_cli()
    assert status.usable and status.native_path == "/usr/local/bin/opencode"
    assert status.explanation() == ""


def test_windows_only_copy_is_diagnosed_as_exactly_that(monkeypatch, in_wsl):
    # First lookup finds the Windows copy; the retry with Windows mounts stripped finds nothing.
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    status = diagnose_opencode_cli()
    assert not status.usable
    assert status.state == opencode_cli.STATE_WINDOWS_ONLY and status.windows_path == WINDOWS_COPY
    text = status.explanation()
    # Specific, not generic: names the actual Windows path, the actual WSL distro, and the fix.
    assert WINDOWS_COPY in text and "Ubuntu-24.04" in text
    assert "no opencode of its own" in text
    assert "Install opencode in WSL" in text and "Windows install is left untouched" in text
    assert status.install_label == "Install opencode in WSL"


def test_native_copy_later_in_path_beats_a_windows_copy_found_first(monkeypatch, in_wsl):
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({
        ("opencode", False): WINDOWS_COPY, ("opencode", True): "/usr/local/bin/opencode",
    }))
    assert diagnose_opencode_cli().native_path == "/usr/local/bin/opencode"


def test_the_retry_lookup_never_searches_a_windows_mount(monkeypatch, in_wsl):
    calls = []
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}, calls))
    diagnose_opencode_cli()
    filtered_path = next(path for _, path in calls if path is not None)
    assert "/mnt/c" not in filtered_path and "/usr/bin" in filtered_path


def test_missing_everywhere_is_diagnosed_as_missing_and_names_wsl(monkeypatch, in_wsl):
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({}))
    status = diagnose_opencode_cli()
    assert status.state == opencode_cli.STATE_MISSING
    assert "not installed in WSL2 (Ubuntu-24.04)" in status.explanation()
    assert "not on the Windows side either" in status.explanation()


def test_missing_on_native_linux_does_not_talk_about_wsl(monkeypatch):
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({}))
    status = diagnose_opencode_cli()
    assert "WSL" not in status.explanation()
    assert status.install_label == "Install opencode"


# --- provider: error type + cooldown ------------------------------------------------------------


def test_resolver_raises_the_typed_error_carrying_the_fix(monkeypatch, in_wsl):
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    with pytest.raises(OpencodeCliUnavailable) as excinfo:
        provider._resolve_opencode_binary()
    assert isinstance(excinfo.value, ValueError)  # every existing `except ValueError` still catches it
    assert excinfo.value.fix_action == INSTALL_ACTION
    assert excinfo.value.fix_label == "Install opencode in WSL"


def test_missing_cli_is_not_masked_by_or_fed_into_the_spawn_failure_cooldown(monkeypatch, in_wsl):
    """After "Install opencode" succeeds the very next call must work -- it must not sit out a
    cooldown recorded by a PREVIOUS failure, and the CLI-missing error must not record one."""
    monkeypatch.setattr(provider, "_shared_server", None)
    monkeypatch.setattr(provider, "_last_failure_at", 0.0)
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({}))
    with pytest.raises(OpencodeCliUnavailable):
        provider._get_shared_server()
    assert provider._last_failure_at == 0.0  # nothing recorded -> no cooldown for the next attempt

    # An older spawn-failure cooldown is still ticking, but the CLI now exists: it must be the
    # cooldown path (not the CLI path) that speaks, i.e. the CLI check passes straight through.
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): "/usr/local/bin/opencode"}))
    monkeypatch.setattr(provider, "_last_failure_at", provider.time.monotonic())
    monkeypatch.setattr(provider, "_last_failure_message", "server crashed")
    with pytest.raises(ValueError, match="server crashed"):
        provider._get_shared_server()


# --- error surfacing ----------------------------------------------------------------------------


def test_chat_error_is_the_specific_message_without_a_generic_prefix(monkeypatch, in_wsl):
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    exc = OpencodeCliUnavailable(diagnose_opencode_cli())
    message = _format_llm_error(exc, "opencode-local", "big-pickle")
    assert message == str(exc)
    assert not message.startswith("Something went wrong")


def test_llm_test_job_exposes_the_fix_action_to_the_ui(monkeypatch, in_wsl):
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    status = diagnose_opencode_cli()

    def boom(provider_id, model):
        raise OpencodeCliUnavailable(status)

    monkeypatch.setattr(llm_test_job, "get_provider", boom)
    llm_test_job.start_test("t-opencode", "opencode-local", "big-pickle")
    llm_test_job._JOBS["t-opencode"]["thread"].join(timeout=5)
    result = llm_test_job.test_status("t-opencode")
    assert result["state"] == "error"
    assert result["action"] == INSTALL_ACTION and result["action_label"] == "Install opencode in WSL"
    assert WINDOWS_COPY in result["message"]


def test_llm_test_job_leaves_action_empty_for_ordinary_failures(monkeypatch):
    def boom(provider_id, model):
        raise RuntimeError("plain failure")

    monkeypatch.setattr(llm_test_job, "get_provider", boom)
    llm_test_job.start_test("t-plain", "x", "y")
    llm_test_job._JOBS["t-plain"]["thread"].join(timeout=5)
    assert llm_test_job.test_status("t-plain")["action"] is None


# --- routes + templates -------------------------------------------------------------------------


def test_install_start_unsupported_platform_shows_the_message(monkeypatch):
    monkeypatch.setattr(main, "start_opencode_install", lambda target_dir: {
        "status": "unsupported", "message": "There is no official opencode CLI build for this platform (win32/AMD64).",
    })
    resp = TestClient(main.app).post("/api/tools/opencode/install/start")
    assert resp.status_code == 200
    assert "no official opencode CLI build" in resp.text and "Install did not start" in resp.text


_RUNNING = {
    "state": "running", "running": True, "returncode": None, "succeeded": None,
    "command": "download the official opencode CLI release from GitHub", "started_at": 0.0,
    "log": "Downloading...", "log_path": None,
}


def test_install_start_running_polls_its_own_status_route_and_carries_the_reload_flag(monkeypatch):
    monkeypatch.setattr(main, "start_opencode_install", lambda target_dir: {"status": "started"})
    monkeypatch.setattr(main, "opencode_install_status", lambda: _RUNNING)
    resp = TestClient(main.app).post("/api/tools/opencode/install/start?reload=true")
    assert "Installing opencode" in resp.text
    assert "/api/tools/opencode/install/status?reload=true" in resp.text
    assert "/api/tools/arsenal/" not in resp.text


def test_finished_install_is_verified_against_the_real_cli_check_not_just_the_exit_code(monkeypatch, in_wsl):
    finished = {**_RUNNING, "state": "finished", "running": False, "returncode": 0, "succeeded": True}
    monkeypatch.setattr(main, "opencode_install_status", lambda: finished)

    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): "/usr/local/bin/opencode"}))
    ok_page = TestClient(main.app).get("/api/tools/opencode/install/status?reload=true").text
    assert "opencode installed (/usr/local/bin/opencode)" in ok_page
    assert "window.location.reload" in ok_page  # Settings stays in step with the new state

    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({}))
    bad_page = TestClient(main.app).get("/api/tools/opencode/install/status").text
    assert "still no usable opencode on PATH" in bad_page
    assert "window.location.reload" not in bad_page
    assert "Install opencode in WSL" in bad_page  # offers a retry


def test_provider_test_failure_shows_the_specific_reason_and_an_install_button(monkeypatch, in_wsl):
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    monkeypatch.setattr("agent.opencode_local_provider.list_opencode_local_models", lambda signal=None: {})
    resp = TestClient(main.app).post("/api/settings/providers/opencode-local/test")
    assert WINDOWS_COPY in resp.text
    assert "/api/tools/opencode/install/start?reload=true" in resp.text
    assert "data-opencode-fix-host" in resp.text


def test_tools_dependencies_row_offers_the_install_button_only_when_not_usable(monkeypatch, in_wsl):
    from agent.tools import arsenal
    monkeypatch.setattr(arsenal, "list_tool_availability", lambda: [])

    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    missing = TestClient(main.app).get("/api/tools/arsenal/check").text
    assert "/api/tools/opencode/install/start" in missing and WINDOWS_COPY in missing

    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): "/usr/local/bin/opencode"}))
    present = TestClient(main.app).get("/api/tools/arsenal/check").text
    assert "/api/tools/opencode/install/start" not in present


def test_settings_card_says_windows_only_and_keeps_the_test_target_outside_the_swap_host(monkeypatch, in_wsl):
    """The install button replaces its [data-opencode-fix-host] with the live panel; that host must be
    INSIDE #opencode-local-test-status, never the element itself, or the card's own Test button
    (hx-target="#opencode-local-test-status") would lose its target after the first install click."""
    from agent.llm_client import OPENCODE_LOCAL_PROVIDER_ID
    from agent.settings import add_provider_to_list

    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    # Reaching the card needs the provider "added"; adding is gated on the CLI, so add it while a
    # native copy looks present, then flip the world back to Windows-only for the render under test.
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): "/usr/local/bin/opencode"}))
    add_provider_to_list(OPENCODE_LOCAL_PROVIDER_ID)
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))

    page = TestClient(main.app).get("/settings").text
    assert "opencode found on Windows only" in page
    card = page[page.index('id="opencode-local-test-status"'):]
    card = card[: card.index("</p>")]
    assert "data-opencode-fix-host" in card and WINDOWS_COPY in card
    assert "/api/tools/opencode/install/start?reload=true" in card


# --- platforms: every platform with an official CLI build gets the one-click install ------------


def test_native_windows_has_no_build_so_it_gets_a_manual_command_and_no_button(monkeypatch):
    monkeypatch.setattr("agent.opencode_install.sys.platform", "win32")
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({}))
    status = diagnose_opencode_cli()
    assert not status.auto_install
    text = status.explanation()
    assert "npm install -g opencode-ai" in text and "click" not in text and "WSL" not in text
    assert OpencodeCliUnavailable(status).fix_action is None  # llm_test_job -> UI shows no install button

    from agent.tools import arsenal
    monkeypatch.setattr(arsenal, "list_tool_availability", lambda: [])
    page = TestClient(main.app).get("/api/tools/arsenal/check").text
    assert "/api/tools/opencode/install/start" not in page


@pytest.mark.parametrize("platform_name,machine", [("darwin", "arm64"), ("darwin", "x86_64"), ("linux", "x86_64"), ("linux", "aarch64")])
def test_mac_and_linux_get_the_same_one_click_install_without_wsl_wording(monkeypatch, platform_name, machine):
    monkeypatch.setattr("agent.opencode_install.sys.platform", platform_name)
    monkeypatch.setattr("agent.opencode_install.platform.machine", lambda: machine)
    monkeypatch.delenv("WSL_DISTRO_NAME", raising=False)
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({}))
    status = diagnose_opencode_cli()
    assert status.auto_install and status.install_label == "Install opencode"
    assert "WSL" not in status.explanation() and "no Node.js" in status.explanation()
    assert OpencodeCliUnavailable(status).fix_action == INSTALL_ACTION


# --- the ASRA-managed copy (what the installer produces) ----------------------------------------


def test_a_managed_copy_counts_as_installed_with_nothing_on_path(monkeypatch, in_wsl, tmp_path):
    managed = tmp_path / "opencode"
    managed.write_text("#!/bin/sh\n")
    managed.chmod(0o755)
    monkeypatch.setattr(opencode_cli, "managed_opencode_path", lambda: managed)
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({}))
    status = diagnose_opencode_cli()
    assert status.usable and status.native_path == str(managed)


def test_a_managed_copy_wins_over_a_windows_only_path_hit(monkeypatch, in_wsl, tmp_path):
    managed = tmp_path / "opencode"
    managed.write_text("#!/bin/sh\n")
    managed.chmod(0o755)
    monkeypatch.setattr(opencode_cli, "managed_opencode_path", lambda: managed)
    monkeypatch.setattr(opencode_cli.shutil, "which", _fake_which({("opencode", False): WINDOWS_COPY}))
    assert diagnose_opencode_cli().native_path == str(managed)


def test_the_managed_location_is_the_same_fixed_spot_regardless_of_who_launched_the_app():
    path = opencode_cli.managed_opencode_path()
    assert path.parts[-3:] == ("tools", "opencode", "opencode")
    assert "/.opencode" not in str(path)  # never the $HOME-relative spot that differs per launch mode
