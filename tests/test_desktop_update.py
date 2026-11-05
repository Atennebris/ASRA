"""Unit tests for agent/desktop_update.py -- GitHub Releases API + download fully mocked via
httpx.MockTransport (same pattern as tests/test_wayback_urls.py), no real network."""
import hashlib

import httpx

import agent.desktop_update as desktop_update

_RealHTTPXClient = httpx.Client
_ASSET_BYTES = b"pretend-this-is-a-real-binary"
_ASSET_SHA256 = hashlib.sha256(_ASSET_BYTES).hexdigest()

_RELEASE_JSON = {
    "tag_name": "v0.3.0",
    "assets": [
        {"name": "asra-desktop-windows-x64.exe", "browser_download_url": "https://example.com/asra-desktop-windows-x64.exe"},
        {"name": "asra-desktop-linux-x64", "browser_download_url": "https://example.com/asra-desktop-linux-x64"},
        {"name": "asra-desktop-macos-arm64", "browser_download_url": "https://example.com/asra-desktop-macos-arm64"},
        {"name": "SHA256SUMS.txt", "browser_download_url": "https://example.com/SHA256SUMS.txt"},
    ],
}
_SUMS_TEXT = f"{_ASSET_SHA256}  asra-desktop-windows-x64.exe\n"


def _mock_httpx_client(handler):
    def factory(**kwargs):
        kwargs.pop("transport", None)
        return _RealHTTPXClient(transport=httpx.MockTransport(handler), **kwargs)
    return factory


def _default_handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if "releases/latest" in url:
        return httpx.Response(200, json=_RELEASE_JSON)
    if url.endswith("SHA256SUMS.txt"):
        return httpx.Response(200, text=_SUMS_TEXT)
    if url.endswith("asra-desktop-windows-x64.exe"):
        return httpx.Response(200, content=_ASSET_BYTES)
    return httpx.Response(404)


def test_not_applicable_without_desktop_env_vars(monkeypatch):
    monkeypatch.delenv("ASRA_DESKTOP_VERSION", raising=False)
    monkeypatch.delenv("ASRA_DESKTOP_PLATFORM", raising=False)
    status = desktop_update.check_for_desktop_update()
    assert status.applicable is False


def test_update_available_with_verified_checksum(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_default_handler))

    status = desktop_update.check_for_desktop_update()
    assert status.applicable and status.error is None
    assert status.available is True
    assert status.latest_version == "0.3.0"
    assert status.asset_name == "asra-desktop-windows-x64.exe"
    assert status.expected_sha256 == _ASSET_SHA256


def test_up_to_date_when_versions_match(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.3.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_default_handler))

    status = desktop_update.check_for_desktop_update()
    assert status.available is False


def test_unknown_platform_reports_error(monkeypatch):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "amiga")
    status = desktop_update.check_for_desktop_update()
    assert status.applicable and status.error and "amiga" in status.error


def test_stage_downloads_and_verifies_checksum(monkeypatch, tmp_path):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_default_handler))
    monkeypatch.setattr(desktop_update, "_STAGING_DIR", tmp_path / "staging")

    status = desktop_update.check_for_desktop_update()
    result = desktop_update.stage_desktop_update(status)

    assert result["ok"] is True
    staged = tmp_path / "staging" / "asra-desktop-windows-x64.exe"
    assert staged.read_bytes() == _ASSET_BYTES
    assert result["path"] == str(staged)


def test_stage_refuses_on_checksum_mismatch(monkeypatch, tmp_path):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")

    def bad_sums_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("SHA256SUMS.txt"):
            return httpx.Response(200, text="0" * 64 + "  asra-desktop-windows-x64.exe\n")
        return _default_handler(request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(bad_sums_handler))
    monkeypatch.setattr(desktop_update, "_STAGING_DIR", tmp_path / "staging")

    status = desktop_update.check_for_desktop_update()
    result = desktop_update.stage_desktop_update(status)

    assert result["ok"] is False
    assert "checksum" in result["message"].lower()
    assert not (tmp_path / "staging" / "asra-desktop-windows-x64.exe").exists()


def test_stage_refuses_without_published_checksum(monkeypatch, tmp_path):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")

    def no_sums_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("SHA256SUMS.txt"):
            return httpx.Response(404)
        return _default_handler(request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(no_sums_handler))
    monkeypatch.setattr(desktop_update, "_STAGING_DIR", tmp_path / "staging")

    status = desktop_update.check_for_desktop_update()
    result = desktop_update.stage_desktop_update(status)

    assert result["ok"] is False
    assert "unverifiable" in result["message"].lower()
