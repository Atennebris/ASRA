"""TOOLS_CUSTOM_ROOT: one operator-supplied root directory for a whole pre-existing set of tools
already on disk (not installed through setup_tools.sh/any future heavy installer at all -- e.g.
carried over from another machine/distro). Settings -> Tools -> "Custom tools path" -> "Test path"
+ "Save path".

Resolution order (agent/tools/runner.py's _resolve_executable): {TOOL}_PATH override, if set -> the
system PATH (shutil.which) -> a bounded-depth recursive search under this root for a file with the
tool's exact executable name, last resort -> "not installed". Purely additive: never overrides a
{TOOL}_PATH override or an already-working PATH lookup, only fills in what neither of those found.

Real, confirmed gap this recursive search fixes (not a flat lookup, which this module originally
shipped with): an operator's own pre-existing tool collection routinely nests the real binary
several directories deep rather than flat at the root or root/bin -- confirmed concretely with
Ghidra's own distribution layout (<root>/ghidra_<version>/support/analyzeHeadless). Every operator's
own collection is organized differently (that's the entire reason this is a configurable root, not
a hardcoded path), so this can't special-case Ghidra specifically -- it has to find ANY known tool
name wherever it actually sits under the root, generically.

Same write-then-verify-read-back .env persistence agent/tools/capability_install.py's own
save_sudo_password already uses. Empty value = disabled, same "blank means go back to default
behavior" convention as every other optional override in this project.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from dotenv import dotenv_values, find_dotenv, set_key, unset_key

from agent.tools.custom_tools_store import registered_custom_tool_paths
from agent.tools.registry import TOOL_REGISTRY
from agent.utils.logger import get_logger

logger = get_logger("TOOLS")

# Best-effort usage-hint capture for a brand-new "(custom)" candidate (Settings -> Tools -> Custom
# tools): a short timeout + stdin=DEVNULL, same defensive pair capability_install.py/
# arsenal_install.py already use everywhere a subprocess could misbehave -- a binary that prints a
# prompt and blocks reading stdin for an answer that never comes (same real incident class
# agent/tools/runner.py's own _run_tracked docstring describes for wpscan) must never hang this.
_USAGE_HINT_TIMEOUT_SECONDS = int(os.getenv("CUSTOM_TOOL_USAGE_HINT_TIMEOUT_SECONDS", "5"))
_USAGE_HINT_MAX_CHARS = 2000
_USAGE_HINT_FLAGS = ("--help", "-h")

_ENV_VAR = "TOOLS_CUSTOM_ROOT"
_ENV_PATH = find_dotenv(usecwd=True) or str(Path(__file__).resolve().parent.parent.parent / ".env")

# A bare Windows drive-letter prefix ("E:\" or "E:/") -- the operator naturally types the path the
# way they see it in Windows Explorer (e.g. "E:\tools"), not the WSL2 mount form their own agent
# process actually needs ("/mnt/e/tools"). Checked by prefix, not a full path-shape validation --
# anything that doesn't start this way (including an already-correct "/mnt/..." path) passes
# through untouched below.
_WINDOWS_DRIVE_PREFIX = re.compile(r"^([A-Za-z]):[\\/]")


def translate_windows_path_to_wsl(path: str) -> str:
    """"E:\\tools" -> "/mnt/e/tools" (standard WSL2 drive mount, lowercase drive letter). Anything
    that doesn't start with a bare "<letter>:\\" or "<letter>:/" prefix (including an already-WSL
    "/mnt/..." path, or a plain Linux/macOS path) is returned unchanged -- this only ever translates
    the one specific shape Windows Explorer produces, never guesses at anything else."""
    clean = path.strip()
    match = _WINDOWS_DRIVE_PREFIX.match(clean)
    if not match:
        return clean
    drive = match.group(1).lower()
    rest = clean[match.end():].replace("\\", "/")
    return f"/mnt/{drive}/{rest}" if rest else f"/mnt/{drive}"


def get_custom_tools_root() -> str | None:
    """The saved root, or None if unset/blank (disabled). Already in WSL2 form -- translation
    happens once, at save time (see save_custom_tools_root), not on every read."""
    return os.getenv(_ENV_VAR) or None


def save_custom_tools_root(path: str) -> None:
    """Translates a Windows-shaped path to its WSL2 mount form, then writes it into .env (mirrored
    into this process's own os.environ immediately, read back to confirm the write actually took --
    same pattern as capability_install.py's save_sudo_password). Blank input clears the setting."""
    clean = translate_windows_path_to_wsl(path)
    if not clean:
        clear_custom_tools_root()
        return
    set_key(_ENV_PATH, _ENV_VAR, clean)
    os.environ[_ENV_VAR] = clean
    if dotenv_values(_ENV_PATH).get(_ENV_VAR) != clean:
        raise RuntimeError(f"Wrote {_ENV_VAR} to .env but the read-back didn't match -- refusing to report success.")
    logger.debug("custom_tools_root: saved %r", clean)


def clear_custom_tools_root() -> None:
    if os.path.exists(_ENV_PATH):
        unset_key(_ENV_PATH, _ENV_VAR)
    os.environ.pop(_ENV_VAR, None)
    logger.debug("custom_tools_root: cleared")


# How many directory levels under the custom root a search will descend looking for an exact
# executable-name match -- deep enough for a realistic nested distribution (Ghidra's own two
# levels, <root>/ghidra_<version>/support/analyzeHeadless) without walking an effectively
# unbounded tree if the operator's root happens to be a very large, deeply-nested folder.
_MAX_SEARCH_DEPTH = int(os.getenv("TOOLS_CUSTOM_ROOT_MAX_DEPTH", "6"))

# Cache TTL for resolve_via_custom_root's own index -- the hot path (agent/tools/runner.py's
# _resolve_executable, called on every tool's own availability check) must not re-walk a
# multi-gigabyte real tool collection on every single call, but a freshly-added file under an
# unchanged root should still become visible without requiring a server restart. test_custom_
# tools_root below deliberately does NOT use this cache (see its own comment) -- an explicit
# "Test path" click must always see the live, current state of the filesystem.
_INDEX_CACHE_TTL_SECONDS = int(os.getenv("TOOLS_CUSTOM_ROOT_INDEX_TTL_SECONDS", "300"))

_index_cache: dict[str, str] = {}
_index_cache_root: str | None = None
_index_cache_built_at: float = 0.0


def _build_root_index(root: str) -> dict[str, str]:
    """One bounded-depth walk of `root`, mapping each file's exact basename to the first path it
    was found at. First-found (not necessarily shallowest) wins on a genuine basename collision --
    an edge case real enough to note, not worth a more elaborate shallowest-wins pass for."""
    index: dict[str, str] = {}
    root_path = Path(root)
    if not root_path.is_dir():
        return index
    root_depth = len(root_path.parts)
    for dirpath, dirnames, filenames in os.walk(root_path):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= _MAX_SEARCH_DEPTH:
            dirnames[:] = []  # prune -- don't descend any further from here
            continue
        for filename in filenames:
            index.setdefault(filename, os.path.join(dirpath, filename))
    return index


def _cached_root_index(root: str) -> dict[str, str]:
    global _index_cache, _index_cache_root, _index_cache_built_at
    now = time.monotonic()
    stale = (now - _index_cache_built_at) > _INDEX_CACHE_TTL_SECONDS
    if _index_cache_root != root or stale:
        _index_cache = _build_root_index(root)
        _index_cache_root = root
        _index_cache_built_at = now
        logger.debug("custom_tools_root: (re)indexed %r -- %d files found within %d levels", root, len(_index_cache), _MAX_SEARCH_DEPTH)
    return _index_cache


def resolve_via_custom_root(executable: str) -> str | None:
    """The one real fallback lookup -- agent/tools/runner.py's _resolve_executable calls this only
    after {TOOL}_PATH and the system PATH have both already failed. Looks up `executable` in a
    cached, bounded-depth index of the whole custom root (see _cached_root_index), so it finds a
    tool wherever it actually sits under the root, not only directly in it or in its own bin/."""
    root = get_custom_tools_root()
    if not root:
        return None
    return _cached_root_index(root).get(executable)


def _known_external_executables() -> list[str]:
    """Deduplicated, sorted executable NAMES (never a path) for every tier-2 (external subprocess)
    ToolSpec that is actually looked up by bare name on PATH. Two exclusions, both deliberate:
    tier-1 (native Python) tools always register executable="" (nothing to look for on disk); and
    a tier-2 tool that already names its own absolute interpreter path (qiling_emulate's
    executable=sys.executable, agent/tools/__init__.py -- it runs via THIS process's own venv
    Python, never looked up on PATH at all) is excluded too. Real, confirmed bug this fixes: without
    it, pathlib's own `/` operator silently discards the left operand whenever the right one is
    already absolute (Path("/any/root") / "/mnt/e/ASRA/venv/bin/python" == Path("/mnt/e/ASRA/venv/
    bin/python"), NOT a path under the tested root) -- so "Test path" reported qiling_emulate as
    "found" at EVERY root ever tried, including an empty throwaway test directory, because the
    check was silently re-verifying the real venv interpreter's own existence instead of anything
    about the root actually being tested.
    """
    names = {
        spec.executable for spec in TOOL_REGISTRY
        if spec.tool_tier == 2 and spec.executable and "/" not in spec.executable
    }
    return sorted(names)


def test_custom_tools_root(path: str) -> dict:
    """Live "what would resolve through this path" check against the CANDIDATE value in the input
    field -- not the already-saved one, so the operator sees the real answer before committing to
    "Save path" (same human-in-the-loop principle as capability_install's own path fields).
    Deliberately builds a FRESH index (never _cached_root_index) -- an explicit "Test path" click
    is an infrequent, deliberate action, not the hot per-tool-check path resolve_via_custom_root
    is, so it always reflects the real, current filesystem rather than up to
    TOOLS_CUSTOM_ROOT_INDEX_TTL_SECONDS of staleness. Searches the same bounded-depth tree as the
    real resolver (see _build_root_index), not just a flat/bin layout, so this shows the same
    answer the agent will actually get at runtime. Returns {"path": <translated candidate>,
    "found": [...], "missing": [...]} -- an honest, itemized answer, never a bare true/false."""
    translated = translate_windows_path_to_wsl(path)
    index = _build_root_index(translated)
    found: list[str] = []
    missing: list[str] = []
    for name in _known_external_executables():
        (found if name in index else missing).append(name)
    logger.debug("custom_tools_root: test path=%r -> found=%d missing=%d", translated, len(found), len(missing))
    return {"path": translated, "found": found, "missing": missing}


def discover_custom_tool_candidates(path: str) -> list[dict]:
    """Executables directly under the (translated) path, or its bin/ subfolder, whose name matches
    NO known ToolSpec -- real candidates for a brand-new "(custom)" tool registration. Already-
    registered paths are excluded too (enabled or not), so re-running "Test path" never re-offers
    something the operator already added. Never registers anything on its own -- purely a list for
    the UI to show, same "nothing is included without an explicit operator confirmation" principle
    test_custom_tools_root above already follows. Returns [{"name", "path"}, ...], sorted by name.
    """
    translated = translate_windows_path_to_wsl(path)
    root = Path(translated)
    known_names = set(_known_external_executables())
    already_registered = registered_custom_tool_paths()

    candidates: list[dict] = []
    for directory in (root, root / "bin"):
        if not directory.is_dir():
            continue
        for entry in directory.iterdir():
            if entry.name in known_names or not entry.is_file() or not os.access(entry, os.X_OK):
                continue
            if str(entry) in already_registered:
                continue
            candidates.append({"name": entry.name, "path": str(entry)})
    candidates.sort(key=lambda c: c["name"])
    logger.debug("custom_tools_root: discovered %d unregistered candidate(s) under %r", len(candidates), translated)
    return candidates


def capture_usage_hint(path: str) -> str:
    """Best-effort `<path> --help` (falling back to `-h`) output, truncated -- the PROPOSED
    description text for a new custom-tool registration (the operator can edit/replace it before
    or after confirming "Add", never saved silently as-is). Empty string on any failure (binary
    doesn't support either flag, times out, isn't executable, ...) -- the UI then just starts with
    a blank description field instead of a fabricated one.
    """
    for flag in _USAGE_HINT_FLAGS:
        try:
            proc = subprocess.run(
                [path, flag], capture_output=True, text=True,
                timeout=_USAGE_HINT_TIMEOUT_SECONDS, stdin=subprocess.DEVNULL,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("custom_tools_root: usage-hint capture for %r failed (%s)", path, exc)
            continue
        output = (proc.stdout or proc.stderr).strip()
        if output:
            return output[:_USAGE_HINT_MAX_CHARS]
    return ""
