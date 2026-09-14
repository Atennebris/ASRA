"""Optional, opt-in nuclei template packs beyond the official set nuclei already keeps up to date
on its own (confirmed live: nuclei checks/updates its own default `~/nuclei-templates` on every
run unless `-duc` is passed, which agent/tools/builders/nuclei.py never does -- there is no gap to
fix there).

What this covers instead: third-party GitHub repos of extra templates (a WordPress-CVE-focused
pack, an experimental exploit-class pack, ...) an operator may want on top of the official set.
Ships with NOTHING enabled by default -- an empty agent stays empty until the operator picks
something in the Tools tab, same "ask before adding weight" discipline as agent/tools/arsenal.py.

No git-clone/vendoring code here at all -- nuclei has its own built-in mechanism for exactly this
(confirmed live): `GITHUB_TEMPLATE_REPO=<owner>/<repo> nuclei -update-templates` clones that repo
into a `github/<owner>/<repo>` subfolder of nuclei's own templates directory, and `-t
github/<owner>/<repo>` then runs it. That's the entire install mechanism -- respects each pack's
own upstream license (nothing is copied into this repo, nuclei fetches straight from GitHub), and
never goes stale on its own the way a vendored copy would. That templates directory is pinned to a
fixed, ASRA-controlled path via `-update-template-dir` (see `_TEMPLATES_DIR` below) rather than left
at nuclei's own `$HOME`-relative default -- the operator's "Run the agent as root" launch toggle
changes which OS user (and therefore which `$HOME`) this process runs as between launches, and an
ambient `$HOME`-relative path would silently point somewhere different (and invisible to the other
mode) depending on which one was last used.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from agent.tools.registry import get_tool
from agent.tools.runner import tool_is_installed
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Each entry vetted by hand (license + real template count/severity, not just "sounds relevant")
# before being added here -- see the operator conversation this shipped from. `repo` is the exact
# "owner/name" GITHUB_TEMPLATE_REPO expects. Add more here as they're vetted; nothing here is
# fetched until the operator clicks Install for that specific pack.
#
# `trigger_tags`: real, confirmed-live constraint -- nuclei loads/compiles EVERY template file under
# a `-t` path before it ever applies `-tags` filtering (confirmed live: pointing `-t` at the 81,528-
# template Wordfence pack alone took several minutes of real CPU time just to load, independent of
# which tags were requested or the target). A pack this large can't be included in every nuclei_scan
# call the way the small geeknik pack safely is -- doing so would silently make EVERY scan (WordPress
# or not) take minutes just to start. trigger_tags (non-empty) means installed_template_args() only
# adds this pack's path to -t when the CALLER's own requested tags actually include one of these --
# every real Wordfence template's own tags field already includes one (confirmed live: a sampled
# template carries `tags: cve,wordpress,wp-core,high,production`), so this is a real, accurate gate,
# not a guess. Empty trigger_tags (geeknik) means "small enough to always include, no gate needed".
PACKS: list[dict] = [
    {
        "key": "wordfence-cve",
        "label": "WordPress CVEs (Wordfence intel)",
        "repo": "topscoder/nuclei-wordfence-cve",
        "license": "MIT",
        "trigger_tags": ("wordpress", "wp-core", "wp-plugin", "wp-theme"),
        "description": (
            "~81k templates covering WordPress core/plugins/themes, generated daily from Wordfence's "
            "own vulnerability intel. Real severity spread (7.8k critical / 13.5k high, not just "
            "info-level fingerprinting) -- auth bypass and RCE-class checks, not only version disclosure. "
            "HEAVY: only loaded when a scan's own tags include wordpress/wp-core/wp-plugin/wp-theme -- "
            "confirmed live, loading this pack's ~81k templates takes several real minutes on its own, "
            "so it's gated out of every other scan rather than silently slowing all of them down."
        ),
    },
    {
        "key": "geeknik",
        "label": "geeknik/the-nuclei-templates (mixed, experimental)",
        "repo": "geeknik/the-nuclei-templates",
        "license": "MIT",
        "trigger_tags": (),
        "description": (
            "General-purpose exploit-class templates (auth bypass, cache poisoning, SSRF, websocket "
            "abuse) the author calls a mix of real bounty hitters and work-in-progress/experimental "
            "checks -- expect a higher false-positive rate than the official set or the Wordfence pack. "
            "Small (~224 templates) -- always included once installed, negligible load time."
        ),
    },
]

_PACKS_BY_KEY = {pack["key"]: pack for pack in PACKS}
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_LOG_TAIL_LINES = int(os.getenv("NUCLEI_PACK_INSTALL_LOG_TAIL_LINES", "200"))

# Same "in-memory only, keyed by what's running" shape as arsenal_install._STATE -- a live Popen
# handle isn't JSON-serializable and only means anything within this process's own lifetime; the
# log file on disk is what survives a restart. Keyed per pack so installing one pack doesn't block
# checking another's status.
_STATE: dict[str, dict] = {}


def nuclei_installed() -> bool:
    return tool_is_installed(get_tool("nuclei"))


# Fixed, ASRA-controlled location -- deliberately NOT Path.home()/"nuclei-templates" (nuclei's own
# ambient default). Real, confirmed incident this fixes: the desktop launcher's "Run the agent as
# root" toggle changes which OS user this whole process runs as between launches,
# so Path.home() resolves to /root one run and /home/<user> the next -- a pack installed under one
# mode was completely invisible (no error, just silently absent) to a scan run under the other. This
# path lives under resolve_global_app_dir() (Documents/ASRA/...), which is itself already resolved
# independently of which OS user is running (see projects/paths.py), so it's the same location
# every launch mode, passed explicitly to nuclei via -update-template-dir (both here and in
# builders/nuclei.py) rather than left to nuclei's own $HOME-relative default.
_TEMPLATES_DIR = resolve_global_app_dir() / "nuclei-templates"


def _custom_github_dir() -> Path:
    return _TEMPLATES_DIR / "github"


def _official_templates_dir() -> Path:
    return _TEMPLATES_DIR


def update_template_dir_args() -> list[str]:
    """`["-update-template-dir", "<fixed path>"]` -- append to EVERY nuclei invocation (pack
    installs here, and every real scan in builders/nuclei.py), not just when a pack is installed.
    Official templates need the same pinning: without it, root and non-root launches would each
    keep their own separate, independently-self-updating official template cache under their own
    $HOME, doubling disk use and never agreeing on what's actually installed."""
    return ["-update-template-dir", str(_TEMPLATES_DIR)]


def _pack_dir(repo: str) -> Path:
    return _custom_github_dir() / repo


def _log_path(key: str) -> Path:
    return resolve_global_app_dir() / f"nuclei-pack-install-{key}.log"


def _is_running(key: str) -> bool:
    state = _STATE.get(key)
    proc = state.get("proc") if state else None
    return proc is not None and proc.poll() is None


def list_packs() -> list[dict]:
    """Static registry + live installed/running state, for the Tools tab. `installed` is a real
    directory check (survives a server restart), not remembered install-button state."""
    return [
        {
            **pack,
            "installed": _pack_dir(pack["repo"]).is_dir(),
            "running": _is_running(pack["key"]),
        }
        for pack in PACKS
    ]


def pack_status(key: str) -> dict:
    """Status + log tail for the polling install view, same shape as arsenal_install_status()."""
    pack = _PACKS_BY_KEY[key]
    state = _STATE.get(key, {})
    proc = state.get("proc")
    running = _is_running(key)
    returncode = None if running or proc is None else proc.poll()
    log_path = state.get("log_path") or _log_path(key)
    try:
        log = log_path.read_text(encoding="utf-8", errors="replace")
        log = "\n".join(log.splitlines()[-_LOG_TAIL_LINES:])
    except FileNotFoundError:
        log = ""
    return {
        "key": key,
        "label": pack["label"],
        "running": running,
        "returncode": returncode,
        "succeeded": (returncode == 0 and _pack_dir(pack["repo"]).is_dir()) if returncode is not None else None,
        "log": log,
        "log_path": str(log_path),
        "installed": _pack_dir(pack["repo"]).is_dir(),
    }


def install_pack(key: str) -> dict:
    """Starts `GITHUB_TEMPLATE_REPO=<repo> nuclei -update-templates` in the background, log
    streamed to disk for the polling UI. Returns immediately; poll pack_status(key)."""
    if key not in _PACKS_BY_KEY:
        return {"status": "error", "message": f"Unknown template pack: {key!r}"}
    if not nuclei_installed():
        return {"status": "error",
                "message": "nuclei isn't installed. Install it from the Tools tab's Arsenal section first."}
    if _is_running(key):
        return {"status": "running", **pack_status(key)}

    pack = _PACKS_BY_KEY[key]
    repo = pack["repo"]
    if not _REPO_RE.match(repo):
        # Defensive only -- repo values are hardcoded in PACKS above, never user input, but a
        # malformed value here would otherwise land straight in a subprocess env var.
        return {"status": "error", "message": f"Malformed pack repo: {repo!r}"}

    log_path = _log_path(key)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    header = (f"# ASRA nuclei template pack install started {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
              f"# pack: {pack['label']} ({repo})\n\n")
    log_path.write_text(header, encoding="utf-8")

    env = dict(os.environ)
    env["GITHUB_TEMPLATE_REPO"] = repo
    logger.debug("nuclei_template_packs: installing pack=%s repo=%s -> %s", key, repo, log_path)
    log_handle = log_path.open("a", encoding="utf-8")
    proc = subprocess.Popen(
        ["nuclei", "-update-templates", *update_template_dir_args()], env=env,
        stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT, text=True,
        start_new_session=True,
    )
    _STATE[key] = {"proc": proc, "log_path": log_path, "started_at": time.time()}
    logger.debug("nuclei_template_packs: started pid=%s for pack=%s", proc.pid, key)
    return {"status": "started", **pack_status(key)}


def uninstall_pack(key: str) -> dict:
    """Removes the pack's synced directory -- the same real-directory check list_packs() reads, so
    this is the actual "disable" mechanism, no separate enabled/disabled flag to drift from reality."""
    if key not in _PACKS_BY_KEY:
        return {"status": "error", "message": f"Unknown template pack: {key!r}"}
    if _is_running(key):
        return {"status": "error", "message": "Install is still running -- wait for it to finish first."}
    pack_dir = _pack_dir(_PACKS_BY_KEY[key]["repo"])
    if pack_dir.is_dir():
        import shutil
        shutil.rmtree(pack_dir, ignore_errors=True)
        logger.debug("nuclei_template_packs: removed pack=%s dir=%s", key, pack_dir)
    return {"status": "ok", **pack_status(key)}


def _recon_technology_tokens(session: dict, target: str) -> list[str]:
    technologies = ((session or {}).get("recon_result") or {}).get("technologies") or {}
    if target in technologies:
        return technologies[target]
    # `target` is nuclei's own full URL/host argument; recon_result["technologies"] is keyed by
    # whatever host string _run_analyze's whatweb call actually used -- the two aren't guaranteed
    # byte-identical (scheme, trailing slash, ...), so fall back to a substring match rather than
    # silently missing real recon evidence over a formatting difference.
    for host, tokens in technologies.items():
        if host and (host in target or target in host):
            return tokens
    return []


def recon_triggered_tags(session: dict | None, target: str) -> set[str]:
    """Real recon evidence (WhatWeb technology tokens THIS session already collected for `target`,
    e.g. a literal "WordPress" token) that matches a heavy pack's own trigger_tags -- lets a pack
    activate because recon actually found the relevant tech, not because the model remembered to
    ask for it by name. build_nuclei_command only ever ADDS this to whatever tags the model already
    requested (for the purpose of deciding which packs to include in -t) -- it never touches the
    model's own -tags filter, so this can't override or narrow what the model deliberately asked to
    run, only make an already-relevant pack available instead of silently absent."""
    tokens = [str(t).lower() for t in _recon_technology_tokens(session or {}, target)]
    if not tokens:
        return set()
    triggered: set[str] = set()
    for pack in PACKS:
        for trigger in pack.get("trigger_tags") or ():
            if any(trigger in token for token in tokens):
                triggered.add(trigger)
    return triggered


def installed_template_args(requested_tags: str = "") -> list[str]:
    """`["-t", "<official-dir>,github/<repo1>,..."]` for every currently-installed pack that's
    actually relevant to `requested_tags` (the same tags string this scan is about to filter on),
    or `[]` when none apply -- appended as-is to nuclei's argv, alongside update_template_dir_args()
    (builders/nuclei.py adds both together on every scan) so the `github/<repo>` shorthand always
    resolves against the same fixed _TEMPLATES_DIR this module itself uses, regardless of which OS
    user is running this particular launch.

    A pack with empty `trigger_tags` (small ones, e.g. geeknik) is always included once installed.
    A pack with real `trigger_tags` (heavy ones, e.g. wordfence-cve) is included ONLY when at least
    one of its trigger_tags appears in requested_tags -- see the PACKS registry's own comment for
    why this gate exists (nuclei loads/compiles every file under a `-t` path regardless of tags, so
    an 81k-template pack in every call's `-t` would silently slow down EVERY scan, not just
    WordPress-relevant ones).

    Empty by default (no packs installed, or no heavy pack's trigger tag requested) so an operator
    who never opens the Tools tab gets byte-identical nuclei behavior to before this module existed
    (build_nuclei_command already runs a `-tags` filter on top of whatever `-t` resolves to, so
    combining the official dir with extra packs here still applies that same filter across all of
    them -- confirmed live: `-t <dir> -tags <tag>` filters within `<dir>`, not just the default)."""
    requested = {t.strip().lower() for t in requested_tags.split(",") if t.strip()}

    def _applies(pack: dict) -> bool:
        trigger_tags = pack.get("trigger_tags") or ()
        return not trigger_tags or any(t in requested for t in trigger_tags)

    installed = [pack for pack in PACKS if _pack_dir(pack["repo"]).is_dir() and _applies(pack)]
    if not installed:
        return []
    paths = [str(_official_templates_dir())] + [f"github/{pack['repo']}" for pack in installed]
    return ["-t", ",".join(paths)]
