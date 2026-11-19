"""Release number shown in Settings -> Updates (agent/updater.py's read_project_version) and the
Desktop app card's launcher-vs-code version line (agent/desktop_update.py). The git/network
behavior of both modules is covered in test_updater.py / test_desktop_update.py -- this file proves
the version number itself: where it is read from, and that the two panels actually render it,
including before any check has run.
"""
from fastapi.testclient import TestClient

import main
from agent import desktop_update, updater


def _client():
    return TestClient(main.app)


def _write_cargo(tmp_path, body):
    cargo = tmp_path / "Cargo.toml"
    cargo.write_text(body, encoding="utf-8")
    return cargo


def test_reads_version_from_package_section_only(monkeypatch, tmp_path):
    # A dependency table below [package] carries its own `version =` -- must never be picked up.
    cargo = _write_cargo(tmp_path, '[package]\nname = "asra"\nversion = "0.7.0"\n\n[dependencies.foo]\nversion = "9.9.9"\n')
    monkeypatch.setattr(updater, "_VERSION_SOURCE", cargo)
    assert updater.read_project_version() == "0.7.0"


def test_ignores_dependency_version_when_package_has_none(monkeypatch, tmp_path):
    cargo = _write_cargo(tmp_path, '[package]\nname = "asra"\n\n[dependencies.foo]\nversion = "9.9.9"\n')
    monkeypatch.setattr(updater, "_VERSION_SOURCE", cargo)
    assert updater.read_project_version() == ""


def test_missing_file_gives_empty_version_not_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(updater, "_VERSION_SOURCE", tmp_path / "nope.toml")
    assert updater.read_project_version() == ""


def test_real_cargo_toml_has_a_parseable_version():
    # The real file the Settings panel reads -- guards against a Cargo.toml edit silently breaking it.
    version = updater.read_project_version()
    assert version and all(part.isdigit() for part in version.split("."))


def test_updates_panel_shows_version_before_any_check(monkeypatch):
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.7.0")
    monkeypatch.setattr(updater, "cached_status", lambda: None)
    html = _client().get("/api/updates/status").text
    assert "Current version" in html
    assert "v0.7.0" in html
    assert "Not checked yet" in html


def test_updates_panel_shows_version_and_commit_for_git_install(monkeypatch):
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.7.0")
    status = updater.UpdateStatus(checked=True, current_sha="b5c51cf", current_subject="reverse&update")
    monkeypatch.setattr(updater, "cached_status", lambda: status)
    html = _client().get("/api/updates/status").text
    assert "v0.7.0" in html
    assert "b5c51cf" in html
    assert "reverse&amp;update" in html


def test_updates_panel_release_install_shows_version_once(monkeypatch):
    monkeypatch.setattr(updater, "read_project_version", lambda: "")
    status = updater.UpdateStatus(checked=True, install_kind="release", current_sha="0.6.0")
    monkeypatch.setattr(updater, "cached_status", lambda: status)
    html = _client().get("/api/updates/status").text
    assert html.count("0.6.0") == 1
    assert "v0.6.0" in html


def test_desktop_card_shows_launcher_version_and_check_button_before_any_check(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.5.0")
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.7.0")
    monkeypatch.setattr(desktop_update, "cached_status", lambda: None)
    html = _client().get("/api/desktop-update/status").text
    assert "v0.5.0" in html
    assert "Not checked yet" in html
    # The text tells the operator to click it, so the button must exist in this state too.
    assert "/api/desktop-update/check" in html


def test_desktop_card_explains_launcher_older_than_code(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.5.0")
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.7.0")
    monkeypatch.setattr(desktop_update, "cached_status", lambda: None)
    html = _client().get("/api/desktop-update/status").text
    assert "Older than the ASRA code it runs (v0.7.0)" in html


def test_desktop_card_has_no_older_note_when_versions_match(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.7.0")
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.7.0")
    monkeypatch.setattr(desktop_update, "cached_status", lambda: None)
    html = _client().get("/api/desktop-update/status").text
    assert "v0.7.0" in html
    assert "Older than the ASRA code" not in html


def test_desktop_card_without_desktop_shell_shows_no_version(monkeypatch):
    monkeypatch.delenv("ASRA_DESKTOP_VERSION", raising=False)
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.7.0")
    monkeypatch.setattr(desktop_update, "cached_status", lambda: None)
    html = _client().get("/api/desktop-update/status").text
    assert "Installed desktop app version" not in html
    assert "Older than the ASRA code" not in html


def test_launcher_older_than_code_helper(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.5.0")
    assert desktop_update.launcher_older_than_code("0.7.0") is True
    assert desktop_update.launcher_older_than_code("0.5.0") is False
    monkeypatch.delenv("ASRA_DESKTOP_VERSION")
    assert desktop_update.launcher_older_than_code("0.7.0") is False


# ---- one-flow "Update now": the launcher is staged in the same request when it is behind ----

def _stub_code_update(monkeypatch):
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.8.0")
    monkeypatch.setattr(updater, "apply_update", lambda: {"ok": True, "message": "Updated successfully. Restart ASRA to load the new version."})
    monkeypatch.setattr(updater, "refresh_cache", lambda fetch=True: updater.UpdateStatus(checked=True, current_sha="abc1234"))


def _shell_status(**overrides):
    base = dict(applicable=True, current_version="0.5.0", latest_version="0.8.0", available=True,
                asset_name="asra-desktop-windows-x64.exe", download_url="https://x/y", expected_sha256="ab")
    base.update(overrides)
    return desktop_update.DesktopUpdateStatus(**base)


def test_update_now_stages_the_launcher_and_offers_one_restart(monkeypatch, tmp_path):
    _stub_code_update(monkeypatch)
    monkeypatch.setattr(desktop_update, "refresh_cache", lambda: _shell_status())
    monkeypatch.setattr(desktop_update, "stage_desktop_update", lambda status: {"ok": True, "path": str(tmp_path / "asra-desktop")})
    html = _client().post("/api/updates/apply").text
    assert "Desktop app v0.8.0 is downloaded and verified" in html
    assert "data-desktop-update-apply" in html and "data-auto-apply" in html
    assert "data-staged-path=" in html


def test_update_now_reports_a_failed_launcher_download_without_hiding_the_code_update(monkeypatch):
    _stub_code_update(monkeypatch)
    monkeypatch.setattr(desktop_update, "refresh_cache", lambda: _shell_status())
    monkeypatch.setattr(desktop_update, "stage_desktop_update", lambda status: {"ok": False, "message": "Download failed: boom"})
    html = _client().post("/api/updates/apply").text
    assert "Updated successfully" in html
    assert "could not be prepared: Download failed: boom" in html
    assert "data-desktop-update-apply" not in html


def test_update_now_skips_launcher_when_not_in_the_desktop_app(monkeypatch):
    _stub_code_update(monkeypatch)
    monkeypatch.setattr(desktop_update, "refresh_cache", lambda: desktop_update.DesktopUpdateStatus(applicable=False))
    html = _client().post("/api/updates/apply").text
    assert "Updated successfully" in html
    assert "Desktop app v" not in html and "data-desktop-update-apply" not in html


def test_update_now_skips_launcher_when_already_current(monkeypatch):
    _stub_code_update(monkeypatch)
    monkeypatch.setattr(desktop_update, "refresh_cache", lambda: _shell_status(available=False, current_version="0.8.0"))
    html = _client().post("/api/updates/apply").text
    assert "data-desktop-update-apply" not in html


def test_desktop_card_offers_a_single_update_button_when_available(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.5.0")
    monkeypatch.setattr(updater, "read_project_version", lambda: "0.8.0")
    monkeypatch.setattr(desktop_update, "cached_status", lambda: _shell_status())
    html = _client().get("/api/desktop-update/status").text
    assert "Update desktop app" in html
    assert "/api/desktop-update/stage" in html
    assert "Download &amp; verify" not in html
