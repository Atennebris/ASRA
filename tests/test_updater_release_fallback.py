"""Unit tests for agent/updater.py's non-git fallback -- a bootstrap_full_project install (no
.git at all, see main.rs) is detected via the version marker file it writes, and compared against
GitHub Releases instead of git refs. GitHub Releases API fully mocked via httpx.MockTransport,
same pattern as tests/test_desktop_update.py."""
import httpx

import agent.updater as updater

_RealHTTPXClient = httpx.Client

_RELEASE_JSON = {"tag_name": "v0.3.0", "body": "- feat: a\n- fix: b\n"}


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _releases_handler(request: httpx.Request) -> httpx.Response:
    if "releases/latest" in str(request.url):
        return httpx.Response(200, json=_RELEASE_JSON)
    return httpx.Response(404)


def _not_a_git_repo(monkeypatch):
    monkeypatch.setattr(updater, "_git", lambda *a, timeout=30: (1, "", "fatal: not a git repository"))


def test_no_marker_and_no_git_reports_the_original_error(monkeypatch, tmp_path):
    _not_a_git_repo(monkeypatch)
    monkeypatch.setattr(updater, "_VERSION_MARKER", tmp_path / ".asra_installed_version")

    status = updater.check_for_updates()

    assert status.install_kind == "git"
    assert status.error and "not a git checkout" in status.error


def test_marker_present_reports_available_when_behind_latest_release(monkeypatch, tmp_path):
    _not_a_git_repo(monkeypatch)
    marker = tmp_path / ".asra_installed_version"
    marker.write_text("0.2.0", encoding="utf-8")
    monkeypatch.setattr(updater, "_VERSION_MARKER", marker)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_releases_handler))

    status = updater.check_for_updates()

    assert status.install_kind == "release"
    assert status.error is None
    assert status.available is True
    assert status.current_sha == "0.2.0"
    assert status.remote_sha == "0.3.0"
    assert status.behind == 1
    assert status.changelog == ["- feat: a", "- fix: b"]


def test_marker_present_reports_up_to_date_when_versions_match(monkeypatch, tmp_path):
    _not_a_git_repo(monkeypatch)
    marker = tmp_path / ".asra_installed_version"
    marker.write_text("0.3.0", encoding="utf-8")
    monkeypatch.setattr(updater, "_VERSION_MARKER", marker)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_releases_handler))

    status = updater.check_for_updates()

    assert status.install_kind == "release"
    assert status.available is False


def test_main_fallback_marker_zero_zero_zero_always_reports_available(monkeypatch, tmp_path):
    """The Rust bootstrap writes "0.0.0" when it had to fall back to main's floating HEAD (no
    matching tag existed yet) -- that must always compare as behind, never silently "up to date"."""
    _not_a_git_repo(monkeypatch)
    marker = tmp_path / ".asra_installed_version"
    marker.write_text("0.0.0", encoding="utf-8")
    monkeypatch.setattr(updater, "_VERSION_MARKER", marker)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_releases_handler))

    status = updater.check_for_updates()

    assert status.available is True


def test_releases_fetch_failure_reports_error_not_a_crash(monkeypatch, tmp_path):
    _not_a_git_repo(monkeypatch)
    marker = tmp_path / ".asra_installed_version"
    marker.write_text("0.2.0", encoding="utf-8")
    monkeypatch.setattr(updater, "_VERSION_MARKER", marker)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(lambda req: httpx.Response(500)))

    status = updater.check_for_updates()

    assert status.install_kind == "release"
    assert status.available is False
    assert status.error and "GitHub Releases" in status.error


def test_apply_update_for_release_install_downloads_extracts_and_bumps_marker(monkeypatch, tmp_path):
    _not_a_git_repo(monkeypatch)
    marker = tmp_path / ".asra_installed_version"
    marker.write_text("0.2.0", encoding="utf-8")
    monkeypatch.setattr(updater, "_VERSION_MARKER", marker)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_releases_handler))

    # _apply_release_based_update extracts into _REPO -- redirect that to an isolated scratch dir
    # so this test never touches the real checkout it's running from.
    fake_repo = tmp_path / "install"
    fake_repo.mkdir()
    monkeypatch.setattr(updater, "_REPO", fake_repo)

    import io
    import tarfile

    def fake_download(version):
        assert version == "0.3.0"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            data = b"print('hello')\n"
            info = tarfile.TarInfo(name="ASRA-abc123/main.py")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        return buf.getvalue()

    monkeypatch.setattr(updater, "_download_release_tarball", fake_download)

    result = updater.apply_update()

    assert result["ok"] is True
    assert (fake_repo / "main.py").read_bytes() == b"print('hello')\n"
    assert marker.read_text(encoding="utf-8") == "0.3.0"


def test_apply_update_release_install_reports_download_failure(monkeypatch, tmp_path):
    _not_a_git_repo(monkeypatch)
    marker = tmp_path / ".asra_installed_version"
    marker.write_text("0.2.0", encoding="utf-8")
    monkeypatch.setattr(updater, "_VERSION_MARKER", marker)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_releases_handler))
    monkeypatch.setattr(updater, "_REPO", tmp_path / "install")
    (tmp_path / "install").mkdir()

    def failing_download(version):
        raise RuntimeError("boom")

    monkeypatch.setattr(updater, "_download_release_tarball", failing_download)

    result = updater.apply_update()

    assert result["ok"] is False
    assert "Download failed" in result["message"]
    # Marker must be untouched on failure -- never claim a version was reached when it wasn't.
    assert marker.read_text(encoding="utf-8") == "0.2.0"
