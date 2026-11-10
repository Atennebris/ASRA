"""Installs the opencode CLI (the thing `opencode serve` is, which agent/opencode_local_provider.py
drives) by downloading the project's own official release archive straight from GitHub -- no Node.js,
no npm, no root/sudo, no shell script, and the same code path on Linux, WSL2 and macOS.

Why this and not `npm install -g opencode-ai`: that package is only a delivery vehicle for the very
same release binary, so it needs Node.js (a large dependency nothing else in ASRA uses) just to fetch
a file. The release archive IS the CLI (`opencode-<os>-<arch>.tar.gz|zip` from the project's GitHub
releases -- the same files opencode.ai's own install script and the npm package pull); it is NOT the
separate desktop app, which ships under different asset names this module never selects.

Where it installs: an ASRA-controlled folder (see agent/opencode_cli.py's managed_opencode_path), not
`$HOME/.opencode` (which differs between the root and non-root launch modes -- a copy installed under
one mode would be invisible under the other) and not a system directory (which would need root). One
fixed location the app itself looks in, identical whoever launched it.

Version line: newest 1.x release. The provider was built against the 1.x session API; opencode 2.x
(a separate `@opencode/cli` line) answers differently and demands a server password, so it is never
picked automatically. OPENCODE_INSTALL_VERSION pins an exact version when that has to change.

Stdlib only on purpose: importable and testable with no third-party package installed.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

_RELEASE_REPO = "anomalyco/opencode"
_RELEASES_API = f"https://api.github.com/repos/{_RELEASE_REPO}/releases"
_SUPPORTED_VERSION_RE = re.compile(r"^v1\.\d+\.\d+$")
_BINARY_NAME = "opencode"
_PINNED_VERSION_ENV = "OPENCODE_INSTALL_VERSION"
_TIMEOUT_ENV = "OPENCODE_INSTALL_TIMEOUT_SECONDS"
_DEFAULT_TIMEOUT_SECONDS = 120
_PROGRESS_STEP_PERCENT = 10
_LOG_TAIL_LINES = 200


class OpencodeInstallError(RuntimeError):
    """A failure with a message already written for the operator (shown verbatim in the panel)."""


def _timeout_seconds() -> float:
    return float(os.getenv(_TIMEOUT_ENV, str(_DEFAULT_TIMEOUT_SECONDS)))


# --- which release archive fits this machine -----------------------------------------------------


@dataclass(frozen=True)
class ReleaseTarget:
    """The archive name pieces for this machine, e.g. linux-x64-baseline-musl + tar.gz."""
    os_name: str
    arch: str
    baseline: bool
    musl: bool

    @property
    def archive_ext(self) -> str:
        return "tar.gz" if self.os_name == "linux" else "zip"

    @property
    def asset_name(self) -> str:
        parts = [self.os_name, self.arch] + (["baseline"] if self.baseline else []) + (["musl"] if self.musl else [])
        return f"{_BINARY_NAME}-{'-'.join(parts)}.{self.archive_ext}"


def _sysctl(name: str) -> str:
    try:
        result = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def _linux_is_musl() -> bool:
    if Path("/etc/alpine-release").exists():
        return True
    try:
        result = subprocess.run(["ldd", "--version"], capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return "musl" in (result.stdout + result.stderr).lower()


def _cpu_lacks_avx2(os_name: str) -> bool:
    """The release ships a "baseline" build for x64 CPUs without AVX2 -- the default build would
    die with an illegal-instruction error there, so the choice must follow the real CPU."""
    if os_name == "linux":
        try:
            return not re.search(r"\bavx2\b", Path("/proc/cpuinfo").read_text(errors="replace"))
        except OSError:
            return False
    return _sysctl("hw.optional.avx2_0") != "1"


def detect_target() -> ReleaseTarget | None:
    """None on a platform with no official CLI archive (native Windows, other CPUs) -- the caller
    then gives the operator the manual route instead of a button that cannot work."""
    os_name = {"linux": "linux", "darwin": "darwin"}.get(sys.platform)
    arch = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine().lower())
    if os_name is None or arch is None:
        return None
    if os_name == "darwin" and arch == "x64" and _sysctl("sysctl.proc_translated") == "1":
        arch = "arm64"  # an x64 Python under Rosetta on Apple Silicon: the machine can run the native build
    baseline = arch == "x64" and _cpu_lacks_avx2(os_name)
    return ReleaseTarget(os_name, arch, baseline, musl=os_name == "linux" and _linux_is_musl())


# --- finding + downloading the release -----------------------------------------------------------


@dataclass(frozen=True)
class Release:
    version: str
    url: str
    size: int
    sha256: str | None


def _http_get_json(url: str):
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "asra-opencode-install"})
    with urllib.request.urlopen(request, timeout=_timeout_seconds()) as response:  # noqa: S310 -- fixed https GitHub API URL
        return json.load(response)


def pick_release(asset_name: str, releases: list[dict], pinned_version: str = "") -> Release:
    """Newest supported-line release that actually carries `asset_name` (a release still publishing
    its assets is skipped, not failed on). `releases` is GitHub's list, newest first."""
    wanted_tag = f"v{pinned_version.lstrip('v')}" if pinned_version else ""
    for release in releases:
        tag = release.get("tag_name", "")
        if release.get("draft") or release.get("prerelease"):
            continue
        if wanted_tag and tag != wanted_tag:
            continue
        if not wanted_tag and not _SUPPORTED_VERSION_RE.match(tag):
            continue
        for asset in release.get("assets", []):
            if asset.get("name") == asset_name:
                digest = asset.get("digest") or ""
                return Release(
                    version=tag.lstrip("v"), url=asset["browser_download_url"], size=int(asset.get("size", 0)),
                    sha256=digest.split(":", 1)[1] if digest.startswith("sha256:") else None,
                )
    scope = f"version {pinned_version}" if pinned_version else "any 1.x release"
    raise OpencodeInstallError(f"No opencode release asset named {asset_name} was found for {scope} on github.com/{_RELEASE_REPO}.")


def _download(url: str, destination: Path, expected_size: int, log: Callable[[str], None]) -> str:
    """Streams to `destination`, logging every 10%; returns the sha256 of what was written."""
    digest = hashlib.sha256()
    request = urllib.request.Request(url, headers={"User-Agent": "asra-opencode-install"})
    received, next_report = 0, _PROGRESS_STEP_PERCENT
    with urllib.request.urlopen(request, timeout=_timeout_seconds()) as response, destination.open("wb") as out:  # noqa: S310 -- https release URL from the GitHub API
        total = expected_size or int(response.headers.get("Content-Length") or 0)
        while chunk := response.read(1024 * 256):
            out.write(chunk)
            digest.update(chunk)
            received += len(chunk)
            if total and received * 100 // total >= next_report:
                log(f"  downloaded {received * 100 // total}% ({received // (1024 * 1024)} MB)")
                next_report += _PROGRESS_STEP_PERCENT
    return digest.hexdigest()


def _extract_binary(archive: Path, destination: Path) -> None:
    """Writes just the `opencode` executable from the archive to `destination` (atomically, via a
    sibling temp file) -- never extracts the archive's own paths, so a hostile entry name can't
    escape the install folder."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = destination.with_name(destination.name + ".part")
    try:
        if archive.name.endswith(".zip"):
            with zipfile.ZipFile(archive) as bundle:
                member = next((m for m in bundle.namelist() if Path(m).name == _BINARY_NAME and not m.endswith("/")), None)
                if member is None:
                    raise OpencodeInstallError(f"The downloaded archive contains no '{_BINARY_NAME}' executable.")
                with bundle.open(member) as source, staging.open("wb") as out:
                    shutil.copyfileobj(source, out)
        else:
            with tarfile.open(archive, "r:gz") as bundle:
                member = next((m for m in bundle.getmembers() if m.isfile() and Path(m.name).name == _BINARY_NAME), None)
                source = bundle.extractfile(member) if member else None
                if source is None:
                    raise OpencodeInstallError(f"The downloaded archive contains no '{_BINARY_NAME}' executable.")
                with source, staging.open("wb") as out:
                    shutil.copyfileobj(source, out)
        staging.chmod(0o755)
        os.replace(staging, destination)
    finally:
        staging.unlink(missing_ok=True)


def _verify_runs(binary: Path, version: str) -> str:
    """The real proof the install worked: the file runs on THIS machine and reports a version."""
    try:
        result = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OpencodeInstallError(f"The installed opencode does not run on this machine: {exc}") from exc
    reported = result.stdout.strip()
    if result.returncode != 0 or not reported:
        raise OpencodeInstallError(f"The installed opencode failed its self-check (exit {result.returncode}): {(result.stderr or reported)[:300]}")
    if version not in reported:
        raise OpencodeInstallError(f"The installed opencode reports version '{reported}', expected {version}.")
    return reported


def install_opencode(target_dir: Path, log: Callable[[str], None]) -> Path:
    """Downloads, verifies and installs the CLI into `target_dir`; returns the executable's path.
    Raises OpencodeInstallError with an operator-ready message on any failure -- the previous
    installed copy (if any) is only replaced once the new one is fully written."""
    target = detect_target()
    if target is None:
        raise OpencodeInstallError(
            f"There is no official opencode CLI build for this platform ({sys.platform}/{platform.machine()}). "
            "Install it yourself: `npm install -g opencode-ai` (see https://opencode.ai).")
    log(f"Platform: {target.os_name}/{target.arch}{' (baseline CPU build)' if target.baseline else ''}{' (musl)' if target.musl else ''}")

    log(f"Looking up the newest opencode release on github.com/{_RELEASE_REPO} ...")
    try:
        releases = _http_get_json(f"{_RELEASES_API}?per_page=100")
    except OSError as exc:
        raise OpencodeInstallError(f"Could not reach GitHub to look up the release ({exc}). Check the internet connection and try again.") from exc
    release = pick_release(target.asset_name, releases, os.getenv(_PINNED_VERSION_ENV, "").strip())
    log(f"Found opencode {release.version}: {target.asset_name} ({release.size // (1024 * 1024)} MB)")

    work_dir = Path(tempfile.mkdtemp(prefix="asra-opencode-install-"))
    try:
        archive = work_dir / target.asset_name
        log(f"Downloading {release.url}")
        try:
            actual_sha = _download(release.url, archive, release.size, log)
        except OSError as exc:
            raise OpencodeInstallError(f"The download failed ({exc}). Try again.") from exc
        if release.sha256 and actual_sha != release.sha256:
            raise OpencodeInstallError("The downloaded file does not match the checksum GitHub published for it -- refusing to install it.")
        log("Checksum OK." if release.sha256 else "GitHub published no checksum for this asset; skipping the check.")

        destination = target_dir / _BINARY_NAME
        log(f"Installing to {destination}")
        _extract_binary(archive, destination)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    reported = _verify_runs(destination, release.version)
    log(f"opencode {reported} installed and runs: {destination}")
    return destination


# --- background run for the UI button (same status shape the arsenal install panel uses) ---------


_LOCK = threading.Lock()
_STATE: dict = {"thread": None, "lines": deque(maxlen=_LOG_TAIL_LINES), "started_at": None, "error": None, "finished": False}


def _append(line: str) -> None:
    with _LOCK:
        _STATE["lines"].append(line)
    logger.debug("opencode_install: %s", line)


def start_install(target_dir: Path) -> dict:
    """Starts the install in a background thread (a ~75 MB download -- far too long for a request).
    status: "started" | "running" (one already in flight) | "unsupported" (no build for this OS/CPU)."""
    with _LOCK:
        thread = _STATE["thread"]
        if thread is not None and thread.is_alive():
            return {"status": "running"}
    if detect_target() is None:
        return {"status": "unsupported",
                "message": f"There is no official opencode CLI build for this platform ({sys.platform}/{platform.machine()}). "
                           "Install it yourself: `npm install -g opencode-ai` (see https://opencode.ai)."}

    def run() -> None:
        try:
            install_opencode(target_dir, _append)
        except OpencodeInstallError as exc:
            _append(f"FAILED: {exc}")
            with _LOCK:
                _STATE["error"] = str(exc)
        except Exception as exc:  # noqa: BLE001 -- a background thread must report, never die silently
            logger.exception("opencode_install: unexpected failure")
            _append(f"FAILED: unexpected error: {exc}")
            with _LOCK:
                _STATE["error"] = str(exc)
        finally:
            with _LOCK:
                _STATE["finished"] = True

    with _LOCK:
        _STATE.update(lines=deque(maxlen=_LOG_TAIL_LINES), started_at=time.time(), error=None, finished=False)
        _STATE["thread"] = threading.Thread(target=run, name="asra-opencode-install", daemon=True)
        _STATE["thread"].start()
    logger.debug("opencode_install: started -> %s", target_dir)
    return {"status": "started"}


def install_status() -> dict:
    """Same keys partials/opencode_install.html renders for any install (state/running/returncode/
    succeeded/command/log/log_path)."""
    with _LOCK:
        thread, finished, error = _STATE["thread"], _STATE["finished"], _STATE["error"]
        running = thread is not None and thread.is_alive() and not finished
        state = "running" if running else "finished" if thread is not None else "idle"
        returncode = None if running or thread is None else (1 if error else 0)
        return {
            "state": state, "running": running, "returncode": returncode,
            "succeeded": None if returncode is None else returncode == 0,
            "command": "download the official opencode CLI release from GitHub" if thread is not None else None,
            "started_at": _STATE["started_at"], "log": "\n".join(_STATE["lines"]), "log_path": None,
        }
