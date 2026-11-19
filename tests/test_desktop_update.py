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


def test_stage_refuses_when_content_length_declares_more_than_the_cap(monkeypatch, tmp_path):
    """Real-world equivalent this guards against: a compromised/misbehaving download host sending
    back a huge body -- refused from the declared Content-Length alone, before a single byte of
    the oversized body is written to disk."""
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")
    monkeypatch.setattr(desktop_update, "_MAX_DOWNLOAD_BYTES", 10)

    def oversized_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("asra-desktop-windows-x64.exe"):
            return httpx.Response(200, content=_ASSET_BYTES, headers={"content-length": "999999999"})
        return _default_handler(request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(oversized_handler))
    monkeypatch.setattr(desktop_update, "_STAGING_DIR", tmp_path / "staging")

    status = desktop_update.check_for_desktop_update()
    result = desktop_update.stage_desktop_update(status)

    assert result["ok"] is False
    assert "larger than expected" in result["message"]
    assert not (tmp_path / "staging").exists() or not list((tmp_path / "staging").iterdir())


def test_stage_aborts_mid_download_once_the_running_total_passes_the_cap_even_without_a_header(monkeypatch, tmp_path):
    """The Content-Length check above only catches an HONEST header -- a missing or lied-about one
    must not bypass the cap, so the running total is checked again on every chunk while streaming."""
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")
    monkeypatch.setattr(desktop_update, "_MAX_DOWNLOAD_BYTES", 10)  # _ASSET_BYTES is 29 bytes

    def no_length_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("asra-desktop-windows-x64.exe"):
            # httpx.Response auto-fills a correct Content-Length from `content=` -- overridden
            # here to simulate a missing/untrustworthy one, so this test actually exercises the
            # running-total check, not the (separately tested) upfront header check.
            return httpx.Response(200, content=_ASSET_BYTES, headers={"content-length": ""})
        return _default_handler(request)

    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(no_length_handler))
    monkeypatch.setattr(desktop_update, "_STAGING_DIR", tmp_path / "staging")

    status = desktop_update.check_for_desktop_update()
    result = desktop_update.stage_desktop_update(status)

    assert result["ok"] is False
    assert "cap" in result["message"]
    assert not (tmp_path / "staging" / "asra-desktop-windows-x64.exe.part").exists()


def test_stage_refuses_a_second_concurrent_call_while_one_is_already_in_progress(monkeypatch, tmp_path):
    """Real race this guards against: main.py's api_desktop_update_stage (the card's own manual
    button) and _desktop_follow_up (fired automatically right after a project-code update) both
    call stage_desktop_update, writing to the exact same per-platform staged path -- two FastAPI
    sync routes can genuinely run on different threadpool threads at once."""
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", "windows")
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_default_handler))
    monkeypatch.setattr(desktop_update, "_STAGING_DIR", tmp_path / "staging")

    status = desktop_update.check_for_desktop_update()
    assert desktop_update._stage_lock.acquire(blocking=False)
    try:
        result = desktop_update.stage_desktop_update(status)
    finally:
        desktop_update._stage_lock.release()

    assert result["ok"] is False
    assert "already in progress" in result["message"]


def _check_on(monkeypatch, platform_name, machine):
    monkeypatch.setenv("ASRA_DESKTOP_VERSION", "0.2.0")
    monkeypatch.setenv("ASRA_DESKTOP_PLATFORM", platform_name)
    monkeypatch.setattr(desktop_update.host_platform, "machine", lambda: machine)
    monkeypatch.setattr(httpx, "Client", _mock_httpx_client(_default_handler))
    return desktop_update.check_for_desktop_update()


def test_linux_x86_64_gets_the_linux_asset(monkeypatch):
    status = _check_on(monkeypatch, "linux", "x86_64")
    assert status.error is None
    assert status.asset_name == "asra-desktop-linux-x64"
    assert status.available is True


def test_linux_arm_is_refused_instead_of_getting_an_x64_binary(monkeypatch):
    status = _check_on(monkeypatch, "linux", "aarch64")
    assert status.available is False
    assert "aarch64" in status.error and "build it from source" in status.error
    assert status.download_url == ""


def test_macos_apple_silicon_gets_the_arm64_asset(monkeypatch):
    status = _check_on(monkeypatch, "macos", "arm64")
    assert status.error is None
    assert status.asset_name == "asra-desktop-macos-arm64"


def test_macos_intel_is_refused(monkeypatch):
    status = _check_on(monkeypatch, "macos", "x86_64")
    assert status.available is False
    assert "x86_64" in status.error


def test_windows_is_not_gated_on_cpu_architecture(monkeypatch):
    # x64 build also runs on ARM64 Windows through its own emulation layer.
    status = _check_on(monkeypatch, "windows", "arm64")
    assert status.error is None
    assert status.asset_name == "asra-desktop-windows-x64.exe"
