"""Desktop shell (Tauri binary) self-update check/stage -- a SEPARATE concern from
agent/updater.py's git-based code updater. desktop/bin/*.exe is gitignored (see .gitignore's own
"Parked built shell binaries -- regenerable, never commit" comment), so `git pull` -- and
agent/updater.py's "Update now" button -- never touches it. The ONLY way an operator's installed
shell binary gets newer is this module: checking GitHub Releases (.github/workflows/release.yml's
own output) and staging a verified download for the Rust shell's own apply_desktop_update command
(desktop/src-tauri/src/main.rs) to actually swap into place and relaunch.

Only meaningful when launched via the desktop shell at all -- a browser-tab operator (plain
run.sh/run.bat, no Tauri wrapper) has no exe to update. ASRA_DESKTOP_VERSION/ASRA_DESKTOP_PLATFORM
are set by main.rs's spawn_backend (the same env-injection convention already used for
ASRA_UI_TOKEN) -- simply absent for that operator, and every function here treats that absence as
"not applicable", never an error.

Each GitHub Release ships exactly one self-contained binary per platform (release.yml's own
build-windows/build-linux/build-macos jobs each stage a single file, no installer, no companion
resources) -- so "apply an update" is a single-file swap, never a multi-file sync/diff.
"""
from __future__ import annotations

import hashlib
import os
import platform as host_platform
import threading
from dataclasses import dataclass

import httpx

from agent.update_release_info import HTTP_TIMEOUT_SECONDS, fetch_latest_release, is_version_behind, parse_version
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("UPDATE")

_DOWNLOAD_TIMEOUT_SECONDS = 120.0

# The real asra-desktop.exe is ~13MB today -- 300MB is generous headroom for future growth while
# still refusing a runaway/malicious response that would otherwise write until the disk is full.
# Real incident this guards against (CLAUDE.md's own "Build junk" section): an unrelated Rust
# build cache once filled a 234GB drive to 100% and broke session saves -- an unbounded download
# write is the same failure mode, just a different source. Checked twice: against the response's
# own Content-Length header up front (skips the download entirely for an obviously-oversized
# asset), and again against the running total while streaming (a missing or dishonest header
# must not bypass the cap).
_MAX_DOWNLOAD_BYTES = 300 * 1024 * 1024

# Only one download/stage at a time -- main.py's api_desktop_update_stage (the card's own button)
# and _desktop_follow_up (fired automatically right after a project-code update, api_updates_apply)
# both ultimately call stage_desktop_update, and both write to the exact same per-platform dest/tmp
# path (status.asset_name never varies for a given machine). Two FastAPI sync routes can genuinely
# run on different threadpool threads at once, so without this a manual click racing the automatic
# follow-up (or two browser tabs) could interleave writes into the same .part file.
_stage_lock = threading.Lock()

# std::env::consts::OS on the Rust side (main.rs) yields exactly these three strings -- matched
# here 1:1, not re-derived from sys.platform: under Windows' supported WSL2 launch path this
# Python process's own sys.platform is always "linux", which would pick the WRONG asset for a
# Windows operator if used here instead.
#
# Each entry is (release asset, CPU architectures that binary actually runs on; None = any). The
# Windows build is x64-only but runs on ARM64 Windows through its built-in x64 emulation, so it is
# not gated. The Linux/macOS builds have no such fallback: swapping in the wrong architecture would
# leave the install with an exe that cannot start at all, so those refuse instead of guessing.
_ASSET_BY_SHELL_PLATFORM = {
    "windows": ("asra-desktop-windows-x64.exe", None),
    "linux": ("asra-desktop-linux-x64", frozenset({"x86_64", "amd64"})),
    "macos": ("asra-desktop-macos-arm64", frozenset({"arm64", "aarch64"})),
}

_STAGING_DIR = resolve_global_app_dir() / "data" / "desktop_update_staging"


@dataclass
class DesktopUpdateStatus:
    applicable: bool = False  # False = not launched via the desktop shell -- nothing to check
    current_version: str = ""
    latest_version: str = ""
    available: bool = False
    asset_name: str = ""
    download_url: str = ""
    expected_sha256: str = ""
    error: str | None = None


def running_launcher_version() -> str:
    """Version of the exe that launched this backend ("" in a plain browser/run.sh launch). It is
    baked into the binary at build time, so a code-only update (git pull / tarball overwrite)
    never changes it -- only installing a newer exe does."""
    return os.environ.get("ASRA_DESKTOP_VERSION", "").strip()


def launcher_older_than_code(code_version: str) -> bool:
    """True when the running exe is a lower version than the code it launched -- the normal state
    after a code-only update, surfaced in Settings so a stale "File version" in Explorer's exe
    properties is explained rather than mistaken for the agent itself being old."""
    return is_version_behind(running_launcher_version(), code_version)


def check_for_desktop_update() -> DesktopUpdateStatus:
    """Compares the running desktop shell's own version (reported by main.rs at launch) against
    the latest tagged GitHub Release. Never raises -- network/HTTP/JSON errors all land in
    status.error, same convention as agent/updater.py's check_for_updates."""
    current_version = running_launcher_version()
    platform = os.environ.get("ASRA_DESKTOP_PLATFORM", "").strip()
    if not current_version or not platform:
        logger.debug("check_for_desktop_update: not launched via the desktop shell -- skipping")
        return DesktopUpdateStatus(applicable=False)

    status = DesktopUpdateStatus(applicable=True, current_version=current_version)
    entry = _ASSET_BY_SHELL_PLATFORM.get(platform)
    if not entry:
        status.error = f"Unknown desktop shell platform '{platform}'."
        logger.debug("check_for_desktop_update: %s", status.error)
        return status
    asset_name, machines = entry
    machine = host_platform.machine().lower()
    if machines and machine not in machines:
        status.error = (
            f"No prebuilt {platform} desktop app is published for {machine or 'this CPU'} -- "
            "build it from source (cargo build --release in desktop/src-tauri)."
        )
        logger.debug("check_for_desktop_update: %s", status.error)
        return status
    status.asset_name = asset_name

    release = fetch_latest_release()
    if release is None:
        status.error = "Could not reach GitHub Releases."
        logger.debug("check_for_desktop_update: releases/latest fetch failed")
        return status

    tag_name = str(release.get("tag_name", ""))
    status.latest_version = tag_name.lstrip("v")
    assets = {a.get("name"): a.get("browser_download_url") for a in release.get("assets", [])}
    status.download_url = assets.get(asset_name) or ""

    if not status.download_url:
        status.error = f"Latest release ({tag_name or 'unknown'}) has no {asset_name} asset."
        logger.debug("check_for_desktop_update: %s", status.error)
        return status

    sums_url = assets.get("SHA256SUMS.txt")
    if sums_url:
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS) as client:
                sums_resp = client.get(sums_url)
                sums_resp.raise_for_status()
            for line in sums_resp.text.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].strip() == asset_name:
                    status.expected_sha256 = parts[0].strip().lower()
                    break
        except Exception as exc:  # noqa: BLE001 - checksum lookup failing is not fatal to detection
            logger.debug("check_for_desktop_update: SHA256SUMS.txt fetch failed: %s", exc)

    current_parsed = parse_version(current_version)
    latest_parsed = parse_version(status.latest_version)
    status.available = bool(current_parsed and latest_parsed and latest_parsed > current_parsed)
    logger.debug(
        "check_for_desktop_update: current=%s latest=%s available=%s platform=%s",
        current_version, status.latest_version, status.available, platform,
    )
    return status


def stage_desktop_update(status: DesktopUpdateStatus) -> dict:
    """Downloads the asset check_for_desktop_update already resolved, verifying it against the
    release's published SHA256SUMS.txt before returning its path -- never hands back an
    unverified file. Returns {ok: True, path} or {ok: False, message}. The path is this process's
    own filesystem view; callers that need to hand it to the Rust shell must translate it first via
    projects.paths.resolve_path_for_windows_shell (WSL2's /mnt/c/... is not something a native
    Windows process can open directly)."""
    if not status.available or not status.download_url:
        return {"ok": False, "message": "No verified update to stage."}
    if not status.expected_sha256:
        return {
            "ok": False,
            "message": "The release has no published SHA256SUMS.txt entry for this asset -- refusing to stage an unverifiable download.",
        }

    if not _stage_lock.acquire(blocking=False):
        return {"ok": False, "message": "An update download is already in progress -- wait for it to finish."}
    try:
        _STAGING_DIR.mkdir(parents=True, exist_ok=True)
        dest = _STAGING_DIR / status.asset_name
        tmp = dest.with_name(dest.name + ".part")
        try:
            with httpx.Client(timeout=_DOWNLOAD_TIMEOUT_SECONDS, follow_redirects=True) as client, \
                    client.stream("GET", status.download_url) as resp:
                resp.raise_for_status()
                try:
                    content_length = int(resp.headers.get("content-length", ""))
                except ValueError:
                    content_length = None
                if content_length is not None and content_length > _MAX_DOWNLOAD_BYTES:
                    logger.debug("stage_desktop_update: declared size %d exceeds cap", content_length)
                    return {"ok": False, "message": "Release asset is larger than expected -- refusing to download."}
                digest = hashlib.sha256()
                downloaded = 0
                with tmp.open("wb") as f:
                    for chunk in resp.iter_bytes():
                        downloaded += len(chunk)
                        if downloaded > _MAX_DOWNLOAD_BYTES:
                            raise ValueError(f"downloaded past the {_MAX_DOWNLOAD_BYTES}-byte cap -- aborting")
                        f.write(chunk)
                        digest.update(chunk)
        except Exception as exc:  # noqa: BLE001 - any download failure, same shape
            tmp.unlink(missing_ok=True)
            logger.debug("stage_desktop_update: download failed: %s", exc)
            return {"ok": False, "message": f"Download failed: {exc}"}

        if digest.hexdigest().lower() != status.expected_sha256:
            tmp.unlink(missing_ok=True)
            logger.debug("stage_desktop_update: checksum mismatch for %s", status.asset_name)
            return {"ok": False, "message": "Downloaded file's checksum doesn't match the published SHA256SUMS.txt -- discarded, not staged."}

        os.replace(tmp, dest)
        if os.name != "nt":
            dest.chmod(dest.stat().st_mode | 0o111)
        logger.debug("stage_desktop_update: staged %s (%d bytes, checksum verified)", dest, dest.stat().st_size)
        return {"ok": True, "path": str(dest)}
    finally:
        _stage_lock.release()


# Startup cache -- same convention as agent/updater.py's own _cached_status, so the sidebar
# indicator can show "a new exe is available" immediately on load instead of only after the
# operator happens to open Settings (that round trip is still what populates the Settings panel's
# own detail card; this cache just backs the lightweight sidebar dot).
_cached_status: DesktopUpdateStatus | None = None


def cached_status() -> DesktopUpdateStatus | None:
    return _cached_status


def refresh_cache() -> DesktopUpdateStatus:
    global _cached_status
    _cached_status = check_for_desktop_update()
    return _cached_status
