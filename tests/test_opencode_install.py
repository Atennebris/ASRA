"""agent/opencode_install.py: the Node-free, root-free opencode CLI installer. Never touches the
network or a real opencode -- GitHub's release list and the download are stubbed with a tiny fake
archive holding a shell script that prints a version."""
import hashlib
import io
import sys
import tarfile
import time
import zipfile

import pytest

from agent import opencode_install as oi
from agent.opencode_install import OpencodeInstallError, ReleaseTarget, pick_release

needs_posix = pytest.mark.skipif(sys.platform == "win32", reason="runs a shell-script stand-in for the binary")


def _release(tag, assets, **extra):
    return {"tag_name": tag, "assets": [{"name": n, "browser_download_url": f"https://x/{tag}/{n}", "size": 5, **kw} for n, kw in assets], **extra}


ASSET = "opencode-linux-x64.tar.gz"


# --- which archive fits the machine --------------------------------------------------------------


@pytest.mark.parametrize("target,expected", [
    (ReleaseTarget("linux", "x64", False, False), "opencode-linux-x64.tar.gz"),
    (ReleaseTarget("linux", "x64", True, True), "opencode-linux-x64-baseline-musl.tar.gz"),
    (ReleaseTarget("linux", "arm64", False, False), "opencode-linux-arm64.tar.gz"),
    (ReleaseTarget("darwin", "arm64", False, False), "opencode-darwin-arm64.zip"),
    (ReleaseTarget("darwin", "x64", True, False), "opencode-darwin-x64-baseline.zip"),
])
def test_asset_names_match_the_official_release_naming(target, expected):
    assert target.asset_name == expected


def _fake_machine(monkeypatch, platform_name, machine, avx2=True, musl=False, rosetta=False):
    monkeypatch.setattr(oi.sys, "platform", platform_name)
    monkeypatch.setattr(oi.platform, "machine", lambda: machine)
    monkeypatch.setattr(oi, "_cpu_lacks_avx2", lambda os_name: not avx2)
    monkeypatch.setattr(oi, "_linux_is_musl", lambda: musl)
    monkeypatch.setattr(oi, "_sysctl", lambda name: "1" if (rosetta and name == "sysctl.proc_translated") else "")


@pytest.mark.parametrize("platform_name,machine,kw,expected", [
    ("linux", "x86_64", {}, "opencode-linux-x64.tar.gz"),
    ("linux", "AMD64", {}, "opencode-linux-x64.tar.gz"),
    ("linux", "x86_64", {"avx2": False}, "opencode-linux-x64-baseline.tar.gz"),
    ("linux", "x86_64", {"musl": True}, "opencode-linux-x64-musl.tar.gz"),
    ("linux", "aarch64", {"avx2": False}, "opencode-linux-arm64.tar.gz"),  # baseline is an x64-only concept
    ("darwin", "arm64", {}, "opencode-darwin-arm64.zip"),
    ("darwin", "x86_64", {"rosetta": True}, "opencode-darwin-arm64.zip"),
])
def test_detect_target_follows_the_real_machine(monkeypatch, platform_name, machine, kw, expected):
    _fake_machine(monkeypatch, platform_name, machine, **kw)
    assert oi.detect_target().asset_name == expected


@pytest.mark.parametrize("platform_name,machine", [("win32", "AMD64"), ("linux", "riscv64"), ("freebsd13", "x86_64")])
def test_detect_target_is_none_where_no_official_build_exists(monkeypatch, platform_name, machine):
    _fake_machine(monkeypatch, platform_name, machine)
    assert oi.detect_target() is None


# --- choosing the release ------------------------------------------------------------------------


def test_picks_the_newest_1x_release_and_never_a_2x_one():
    releases = [
        _release("v2.2.6", [(ASSET, {})]),
        _release("v1.19.5", [(ASSET, {"digest": "sha256:abc123"})]),
        _release("v1.19.4", [(ASSET, {})]),
    ]
    release = pick_release(ASSET, releases)
    assert release.version == "1.19.5" and release.sha256 == "abc123"


def test_skips_drafts_prereleases_and_releases_still_missing_the_asset():
    releases = [
        _release("v1.20.0", [(ASSET, {})], draft=True),
        _release("v1.19.9", [(ASSET, {})], prerelease=True),
        _release("v1.19.8", [("opencode-darwin-arm64.zip", {})]),  # still publishing: no linux asset yet
        _release("v1.19.7", [(ASSET, {})]),
    ]
    assert pick_release(ASSET, releases).version == "1.19.7"


def test_a_pinned_version_is_honored_even_when_newer_ones_exist():
    releases = [_release("v1.19.5", [(ASSET, {})]), _release("v1.18.34", [(ASSET, {})])]
    assert pick_release(ASSET, releases, "1.18.34").version == "1.18.34"
    assert pick_release(ASSET, releases, "v1.18.34").version == "1.18.34"


def test_no_matching_release_is_a_clear_error_not_a_crash():
    with pytest.raises(OpencodeInstallError, match="No opencode release asset named opencode-linux-x64.tar.gz"):
        pick_release(ASSET, [_release("v2.0.0", [(ASSET, {})])])


def test_asset_without_a_published_checksum_still_resolves():
    assert pick_release(ASSET, [_release("v1.1.1", [(ASSET, {})])]).sha256 is None


# --- extracting only the executable --------------------------------------------------------------


def _tar_with(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            bundle.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_extract_writes_only_the_executable_and_marks_it_runnable(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(_tar_with({"README.md": b"docs", "bin/opencode": b"BINARY"}))
    destination = tmp_path / "out" / "opencode"
    oi._extract_binary(archive, destination)
    assert destination.read_bytes() == b"BINARY"
    assert destination.stat().st_mode & 0o111
    assert sorted(p.name for p in destination.parent.iterdir()) == ["opencode"]  # no stray .part / README


def test_extract_ignores_hostile_member_paths(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(_tar_with({"../../evil/opencode": b"BINARY"}))
    destination = tmp_path / "safe" / "opencode"
    oi._extract_binary(archive, destination)
    assert destination.read_bytes() == b"BINARY"
    assert not (tmp_path.parent / "evil").exists()  # only ever written to the one destination path


def test_extract_from_a_zip_for_macos(tmp_path):
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("opencode", b"MACBINARY")
    destination = tmp_path / "opencode"
    oi._extract_binary(archive, destination)
    assert destination.read_bytes() == b"MACBINARY"


def test_extract_fails_clearly_when_the_archive_has_no_executable(tmp_path):
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(_tar_with({"README.md": b"docs"}))
    with pytest.raises(OpencodeInstallError, match="contains no 'opencode' executable"):
        oi._extract_binary(archive, tmp_path / "opencode")
    assert not (tmp_path / "opencode").exists()


# --- the whole install, end to end (stubbed network) ---------------------------------------------


def _stub_network(monkeypatch, version="1.19.5", binary=b"#!/bin/sh\necho 1.19.5\n", published_sha=None, asset=ASSET):
    archive_bytes = _tar_with({"opencode": binary})
    sha = published_sha or hashlib.sha256(archive_bytes).hexdigest()
    monkeypatch.setattr(oi, "detect_target", lambda: ReleaseTarget("linux", "x64", False, False))
    monkeypatch.setattr(oi, "_http_get_json", lambda url: [_release(f"v{version}", [(asset, {"digest": f"sha256:{sha}", "size": len(archive_bytes)})])])

    def fake_download(url, destination, expected_size, log):
        destination.write_bytes(archive_bytes)
        return hashlib.sha256(archive_bytes).hexdigest()

    monkeypatch.setattr(oi, "_download", fake_download)


@needs_posix
def test_install_downloads_verifies_extracts_and_proves_the_binary_runs(monkeypatch, tmp_path):
    _stub_network(monkeypatch)
    lines = []
    path = oi.install_opencode(tmp_path / "tools" / "opencode", lines.append)
    assert path == tmp_path / "tools" / "opencode" / "opencode" and path.is_file()
    log = "\n".join(lines)
    assert "Checksum OK" in log and "installed and runs" in log and "1.19.5" in log


@needs_posix
def test_a_checksum_mismatch_refuses_to_install_anything(monkeypatch, tmp_path):
    _stub_network(monkeypatch, published_sha="0" * 64)
    with pytest.raises(OpencodeInstallError, match="does not match the checksum"):
        oi.install_opencode(tmp_path / "opencode-dir", lambda line: None)
    assert not (tmp_path / "opencode-dir" / "opencode").exists()


@needs_posix
def test_a_binary_that_does_not_run_is_reported_not_silently_installed(monkeypatch, tmp_path):
    _stub_network(monkeypatch, binary=b"#!/bin/sh\nexit 3\n")
    with pytest.raises(OpencodeInstallError, match="failed its self-check"):
        oi.install_opencode(tmp_path / "d", lambda line: None)


@needs_posix
def test_a_binary_reporting_the_wrong_version_is_rejected(monkeypatch, tmp_path):
    _stub_network(monkeypatch, binary=b"#!/bin/sh\necho 9.9.9\n")
    with pytest.raises(OpencodeInstallError, match="expected 1.19.5"):
        oi.install_opencode(tmp_path / "d", lambda line: None)


def test_github_being_unreachable_gives_an_operator_message(monkeypatch, tmp_path):
    monkeypatch.setattr(oi, "detect_target", lambda: ReleaseTarget("linux", "x64", False, False))

    def offline(url):
        raise OSError("Name or service not known")

    monkeypatch.setattr(oi, "_http_get_json", offline)
    with pytest.raises(OpencodeInstallError, match="Could not reach GitHub"):
        oi.install_opencode(tmp_path, lambda line: None)


def test_unsupported_platform_says_so_and_gives_the_manual_route(monkeypatch, tmp_path):
    monkeypatch.setattr(oi, "detect_target", lambda: None)
    with pytest.raises(OpencodeInstallError, match="npm install -g opencode-ai"):
        oi.install_opencode(tmp_path, lambda line: None)


# --- the background run behind the button --------------------------------------------------------


def _wait_done(timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not oi.install_status()["running"]:
            return
        time.sleep(0.02)
    raise AssertionError("background install never finished")


def test_background_install_reports_success_with_its_log(monkeypatch, tmp_path):
    monkeypatch.setattr(oi, "detect_target", lambda: ReleaseTarget("linux", "x64", False, False))
    monkeypatch.setattr(oi, "install_opencode", lambda target_dir, log: (log("working"), target_dir / "opencode")[1])
    assert oi.start_install(tmp_path)["status"] == "started"
    _wait_done()
    status = oi.install_status()
    assert status["state"] == "finished" and status["succeeded"] is True and status["returncode"] == 0
    assert "working" in status["log"]


def test_background_install_reports_failure_with_the_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(oi, "detect_target", lambda: ReleaseTarget("linux", "x64", False, False))

    def boom(target_dir, log):
        raise OpencodeInstallError("GitHub is down")

    monkeypatch.setattr(oi, "install_opencode", boom)
    oi.start_install(tmp_path)
    _wait_done()
    status = oi.install_status()
    assert status["succeeded"] is False and "FAILED: GitHub is down" in status["log"]


def test_a_second_start_while_one_runs_does_not_start_another(monkeypatch, tmp_path):
    monkeypatch.setattr(oi, "detect_target", lambda: ReleaseTarget("linux", "x64", False, False))
    release = []
    monkeypatch.setattr(oi, "install_opencode", lambda target_dir, log: (release or time.sleep(0.05), target_dir / "opencode")[1])
    assert oi.start_install(tmp_path)["status"] == "started"
    assert oi.start_install(tmp_path)["status"] == "running"
    _wait_done()


def test_start_on_an_unsupported_platform_returns_unsupported(monkeypatch, tmp_path):
    monkeypatch.setattr(oi, "detect_target", lambda: None)
    result = oi.start_install(tmp_path)
    assert result["status"] == "unsupported" and "npm install -g opencode-ai" in result["message"]
