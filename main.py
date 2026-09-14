"""FastAPI app entrypoint: wraps the already-working agent (agent/core.py) in a web UI.

Every route is a thin layer over sessions/store.py (file-based session state) and agent.core
(the ReAct loop that mutates that state). No business logic lives here beyond request
validation and template rendering.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import math
import os
import re
import secrets
import shutil
import subprocess
import time
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import ipaddress

import bleach
import jinja2
import markdown
import markupsafe
from markupsafe import Markup

from agent import updater
from agent.chat import (
    _find_thread,
    _get_active_thread,
    append_pending_chat_message,
    cancel_queued_chat_message,
    compact_chat_thread,
    delete_chat_thread,
    list_chat_threads,
    reconcile_orphaned_chat_threads,
    rename_chat_thread,
    request_chat_stop,
    run_chat_turn_background,
    set_chat_thread_color,
    start_new_chat_thread,
    switch_chat_thread,
)
from agent.core import (
    VALID_ENTRY_POINTS,
    _WHATWEB_WAF_CDN_PLUGIN_NAMES,
    _embed_playbook_entries,
    compute_efficiency_score,
    compute_llm_usage_summary,
    compute_portfolio_summary,
    compute_provider_leaderboard,
    compute_resume_entry_point,
    format_accumulated_duration,
    format_duration_between,
    format_phase_duration,
    format_session_duration,
    get_approval_event,
    get_instruction_queue,
    is_ungrounded_cve_lookup,
    request_session_stop,
    run_all_findings_verification,
    run_all_hypotheses_verification,
    run_focused_exploit,
    run_hypothesis_verification,
    run_re_reverify,
    run_re_triage,
    run_recon_note_investigation,
    run_session,
    set_re_stop_intent,
    time_budget_deadline_epoch,
)
from agent.tools.background_jobs import reconcile_orphaned_background_jobs
from agent.tools.browser_manager import get_browser_manager
from agent.tools.memscan_manager import shutdown_all as shutdown_memscan_sessions
from agent.tools.bugbounty_import import (
    _normalize_url,
    analyze_bugbounty_program,
    analyze_re_program,
    check_disclosed_reports,
    prepare_target_only,
    refresh_program_check,
)
from agent.tools.capability_install import has_sudo_password, install_capability, save_sudo_password
from agent.tools.capability_paths import get_capability_status, load_tool_paths, save_tool_path
from agent.tools.capability_registry import OPTIONAL_CAPABILITIES, get_capability
from agent.tools.chat_settings_store import load_chat_settings, save_chat_settings, save_quick_chat_session_id
from agent.tools.dork_engine import SEARCH_ENGINES as DORK_SEARCH_ENGINES
from agent.tools.dork_engine import DEFAULT_ENGINE as DORK_DEFAULT_ENGINE
from agent.tools.dork_engine import build_dork_result, list_dork_categories
from agent.tools.llm_test_job import cancel_test, start_test, test_status
from agent.tools.toolkit_settings_store import BOOL_KEYS as TOOLKIT_AGENT_SETTINGS_FIELDS
from agent.tools.toolkit_settings_store import load_toolkit_agent_settings, save_toolkit_agent_settings
from agent.tools import fleet_store
from agent.tools import subagent_icons
from agent.tools.subagent_store import add_profile, delete_profile, get_enabled_profiles, import_profiles, load_subagent_profiles, update_profile
from agent.tools.subagent_tasks import reconcile_orphaned_subagent_tasks
from agent.tools import terminal_manager
from agent.tools import terminal_settings
from agent.tools.tool_inventory import list_tool_availability
from agent.tools.arsenal import summarize_arsenal
from agent.tools.arsenal_install import (
    approx_download_size_gb,
    arsenal_install_status,
    can_autostart,
    measure_arsenal_size_gb,
    start_arsenal_install,
)
from agent.tools.project_backup import (
    auto_backup_worker_loop,
    create_backup as create_project_backup,
    delete_backup as delete_project_backup,
    get_max_backup_count as get_project_backup_max_count,
    list_backups as list_project_backups,
    restore_backup as restore_project_backup,
)
from agent.tools.nuclei_template_packs import (
    install_pack as install_nuclei_pack,
    list_packs as list_nuclei_packs,
    pack_status as nuclei_pack_status,
    uninstall_pack as uninstall_nuclei_pack,
)
from agent.tools.toolkit_comparer import diff_entries
from agent.tools.toolkit_decoder import SCHEMES as DECODER_SCHEMES
from agent.tools.toolkit_decoder import run_codec
from agent.tools import library_store
from agent.tools import playbook_store
from agent.tools import toolkit_intruder
from projects import icons as project_icons
from projects.paths import resolve_open_target
from agent.tools.toolkit_proxy import get_toolkit_proxy_manager
from agent.tools.toolkit_query import QuerySyntaxError, compile_query
from agent.tools import toolkit_racer
from agent.tools import toolkit_variables
from agent.tools.toolkit_repeater import send_raw_request
from agent.tools import toolkit_sequencer
from agent.tools.toolkit_store import format_header_lines as _format_header_lines
from agent.tools.toolkit_store import delete_traffic_entry, get_traffic_entry, load_traffic_entries
from agent.tools.toolkit_store import load_matching_traffic_entries
from agent.tools.toolkit_store import traffic_file_mtime_ns
from agent.tools.toolkit_store import parse_header_lines as _parse_header_lines
from agent.tools.wordlist_catalog import list_all_wordlists
from agent.tools.wordlist_download import download_wordlist
from agent.tools.wordlist_store import ASSIGNABLE_ROLES, get_assigned_wordlist, set_assignment
from agent.custom_providers import (
    CUSTOM_PROVIDER_TYPE_PRESETS,
    create_custom_provider,
    delete_custom_provider,
    get_custom_provider,
    is_custom_provider_id,
    load_custom_providers,
    update_custom_provider,
)
from agent.llm_client import (
    CODEX_DISPLAY_NAME,
    CODEX_PROVIDER_ID,
    COPILOT_DISPLAY_NAME,
    COPILOT_PROVIDER_ID,
    DEFAULT_PROVIDER,
    PROVIDER_REGISTRY,
    all_provider_choices,
    check_api_key,
    clear_provider_api_key,
    clear_provider_base_url,
    configured_provider_choices,
    get_model_choices,
    get_provider,
    get_provider_api_key,
    invalidate_model_choices_cache,
    is_known_provider_id,
    save_provider_api_key,
    save_provider_base_url,
    test_custom_provider_connection,
)
from agent.codex_oauth import clear_tokens as clear_codex_tokens
from agent.codex_oauth import get_login_status as get_codex_login_status
from agent.codex_oauth import get_valid_access_token as get_valid_codex_access_token
from agent.codex_oauth import load_tokens as load_codex_tokens
from agent.codex_oauth import start_login_flow as start_codex_login_flow
from agent.codex_provider import CODEX_DEFAULT_MODEL, CODEX_MODELS
from agent.copilot_oauth import clear_tokens as clear_copilot_tokens
from agent.copilot_oauth import get_login_status as get_copilot_login_status
from agent.copilot_oauth import get_valid_copilot_token
from agent.copilot_oauth import load_tokens as load_copilot_tokens
from agent.copilot_oauth import start_login_flow as start_copilot_login_flow
from agent.copilot_provider import COPILOT_MODELS
from agent.intro_settings import (
    load_intro_enabled,
    load_intro_sound_enabled,
    save_intro_enabled,
    save_intro_sound_enabled,
)
from agent.sound_settings import (
    SOUND_EVENTS,
    SOUND_PROFILES,
    load_sound_settings,
    save_master_sound_enabled,
    save_sound_event,
)
from agent.timezone_settings import (
    CLOCK_STYLES,
    display_timezone_choices,
    load_clock_show_date,
    load_clock_show_time,
    load_clock_show_zone_label,
    load_clock_style,
    load_display_timezone,
    save_clock_show_date,
    save_clock_show_time,
    save_clock_show_zone_label,
    save_clock_style,
    save_display_timezone,
)
from agent.tools.tool_api_keys import TOOL_API_KEY_SPECS, clear_tool_api_key, get_tool_api_key, save_tool_api_key
from agent.settings import (
    add_provider_to_list,
    get_added_providers,
    get_secondary_verification_provider,
    is_provider_enabled,
    load_llm_settings,
    remove_provider_from_list,
    save_fallback_chain_settings,
    save_llm_settings,
    save_secondary_verification_provider,
    set_provider_enabled,
)
from agent.tools.allowed_targets import _matches_scope_entries, authorize_exploit_targets
from agent.tools.builders.validators import classify_target_type, expand_target_alternation, validate_scope_entry
from agent.tools.native import (
    _CREDENTIALS_DIR,
    list_identity_field_presence,
    register_discovered_credential,
    reveal_identity_field,
    save_identity_credentials,
)
from agent.utils import lazy_openai
from agent.utils.debug import current_session_id, is_debug_enabled
from agent.utils.logger import get_logger
from agent.utils.report_export import (
    EXPORT_FORMATS,
    build_report_data,
    render_doc,
    render_docx,
    render_md,
    render_pdf,
    render_txt,
    render_zip,
)
from sessions.store import (
    create_session,
    delete_all_sessions,
    delete_session,
    get_session_folder,
    get_session_revision,
    list_session_summaries,
    load_session,
    name_exists,
    reload_merge_save,
    reset_host_health_streaks_for_new_pass,
    reset_plan_for_new_pass,
    save_session,
)
from agent.tools.builders.re_target import check_re_target, clone_or_stage_re_target

logger = get_logger("API")


class _SuppressCancelledAsgiNoise(logging.Filter):
    """Silences a log record whose own exception is CancelledError/KeyboardInterrupt (regardless of
    what's chained onto it via __context__) -- these fire for genuinely harmless, expected cases: a
    browser's own SSE connection (a session page's live-updating view) still open when the server
    shuts down, or a second Ctrl+C forcing a shutdown that was already gracefully in progress.
    Neither is a real application bug -- the connection/process still closes down correctly either
    way, only the noisy traceback is silenced.

    Real incident this fixes, in two layers: (1) uvicorn's own "Exception in ASGI application" log
    for an in-flight request's CancelledError -- confirmed live, a normal Ctrl+C shutdown with a
    session page's SSE connection still open in a browser tab dumped ~40 lines of uvicorn/uvloop
    internals that read exactly like a crash, even though the server had already logged a clean
    "Shutting down" moments before. (2) A SECOND, separate traceback confirmed live on the exact same
    kind of shutdown: uvicorn's own capture_signals() re-delivers a second real Ctrl+C via
    signal.raise_signal() once its own graceful-shutdown scope exits, asyncio.Runner's own _on_sigint
    turns that into a raw KeyboardInterrupt -> CancelledError chain (asyncio/runners.py), and
    asyncio's own default "unhandled exception" reporting logs the whole chain -- through a DIFFERENT
    logger ("asyncio", not "uvicorn.error") than case (1), which is why this filter is attached to
    both that logger AND logging.lastResort (Python's own fallback when no handler exists anywhere
    up a logger's ancestor chain -- confirmed live to be exactly where case (2) was actually landing,
    since neither "asyncio" nor root has a configured handler by default).
    """

    def filter(self, record: logging.LogRecord) -> bool:
        exc_info = record.exc_info
        if exc_info and exc_info[0] is not None and issubclass(exc_info[0], (asyncio.CancelledError, KeyboardInterrupt)):
            logger.debug(
                "uvicorn/asyncio: suppressed a %s from an in-flight request or a second Ctrl+C during "
                "shutdown -- harmless", exc_info[0].__name__,
            )
            return False
        return True


_suppress_cancelled_asgi_noise = _SuppressCancelledAsgiNoise()
logging.getLogger("uvicorn.error").addFilter(_suppress_cancelled_asgi_noise)
logging.getLogger("asyncio").addFilter(_suppress_cancelled_asgi_noise)
logging.lastResort.addFilter(_suppress_cancelled_asgi_noise)

# Keeps a reference to fire-and-forget startup tasks so they aren't garbage-collected mid-run.
_startup_bg_tasks: set = set()

_FLEET_POLL_INTERVAL_SECONDS = float(os.getenv("FLEET_POLL_INTERVAL_SECONDS", "5"))


async def _fleet_worker_loop() -> None:
    """Runs for the whole lifetime of the server (started in _lifespan below, cancelled on
    shutdown) -- the single place that actually starts a fleet-queued session, respecting
    FLEET_MAX_CONCURRENT_SESSIONS. Deliberately simple polling, not an event-driven queue: this is
    a local, single-operator tool, not a distributed job system, and a session's own lifetime
    (minutes to hours) makes a multi-second poll interval's own latency irrelevant in practice.

    "Active" is the same _ORPHANABLE_STATUSES ("processing"/"awaiting_approval") plus "pending"
    (queued-to-start, not yet actually running its first phase) every other capacity-aware check
    in this file already uses (see e.g. verify_all_findings' own gate) -- a session manually
    Started by the operator counts against the same cap a fleet-queued one does, since both
    compete for the same real LLM-request/tool-execution capacity underneath.
    """
    while True:
        try:
            active_count = sum(
                1 for s in list_session_summaries()
                if s["status"] in _ORPHANABLE_STATUSES or s["status"] == "pending"
            )
            session_id = fleet_store.pop_next_runnable_session(active_count)
            if session_id is not None:
                session = load_session(session_id)
                if session is not None and session.get("status") == "created":
                    session["status"] = "pending"
                    save_session(session_id, session)
                    logger.debug("api: fleet worker starting queued session_id=%s (active=%d)", session_id, active_count)
                    task = asyncio.create_task(_run_session_task(session_id, session.get("llm_provider")))
                    _startup_bg_tasks.add(task)
                    task.add_done_callback(_startup_bg_tasks.discard)
                else:
                    # Claimed from the queue but no longer actually runnable (deleted, or started
                    # some other way in the meantime) -- already popped off the queue by
                    # pop_next_runnable_session, nothing further to do; just don't silently retry
                    # it forever.
                    logger.debug(
                        "api: fleet worker skipped session_id=%s (no longer runnable, status=%s)",
                        session_id, session.get("status") if session else "missing",
                    )
        except Exception:
            # A single bad tick (a transient file-lock hiccup, an unexpected exception) must never
            # kill the whole worker loop -- the next tick just tries again.
            logger.debug("api: fleet worker tick failed", exc_info=True)
        await asyncio.sleep(_FLEET_POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """Server startup/shutdown, replacing the two deprecated @app.on_event handlers FastAPI now
    warns about on every boot (and will eventually drop, silently disabling both halves). Startup:
    reconcile any session/chat state left dangling by a process that died mid-run. Shutdown: the
    process-wide backstop that closes whatever headless Chromium and mitmproxy instances are still
    open at the exact moment the whole server stops -- per-run cleanup (agent/core.py's run_*
    finally blocks) already handles a session's own context the moment ITS run ends; this covers
    everything still open when the server itself goes down, so a graceful shutdown never leaves an
    orphaned browser/proxy process behind (invisible to session.json-based orphan recovery)."""
    _startup_progress("Recovering any interrupted sessions...")
    _mark_orphaned_sessions_interrupted()
    _reconcile_orphaned_chat_threads_sweep()
    library_store.reconcile_orphaned_analyses()
    # Quiet background update check at startup (git fetch is network I/O -> off the event loop, and
    # never blocks the server coming up). Result is cached for the Settings page + sidebar indicator.
    if os.getenv("UPDATE_CHECK_ON_STARTUP", "true").strip().lower() in ("true", "1", "yes"):
        _task = asyncio.create_task(asyncio.to_thread(updater.refresh_cache, True))
        _startup_bg_tasks.add(_task)
        _task.add_done_callback(_startup_bg_tasks.discard)
    # Off the request path on purpose -- see lazy_openai.warm_up's own docstring for the real
    # incident (a first Settings "Test" click eating the SDK's full ~10-15s import cost) this avoids.
    _openai_warm_task = asyncio.create_task(asyncio.to_thread(lazy_openai.warm_up))
    _startup_bg_tasks.add(_openai_warm_task)
    _openai_warm_task.add_done_callback(_startup_bg_tasks.discard)
    # Long-lived, not fire-and-forget like the two tasks above -- runs for the server's whole
    # lifetime, cancelled explicitly on shutdown below (never added to _startup_bg_tasks, which is
    # only for one-shot startup tasks that clean themselves out of that set on completion).
    fleet_worker_task = asyncio.create_task(_fleet_worker_loop())
    # Same long-lived shape as fleet_worker_task just above -- auto_backup_worker_loop no-ops
    # immediately and returns if PROJECT_AUTO_BACKUP_ENABLED=false, so this is always safe to start.
    backup_worker_task = asyncio.create_task(auto_backup_worker_loop())
    _startup_progress(f"Ready — open http://127.0.0.1:{os.getenv('PORT', '8000')}")
    yield
    fleet_worker_task.cancel()
    backup_worker_task.cancel()
    await get_browser_manager().shutdown()
    # Same backstop as the browser_manager line above, for memscan_*'s own live scanmem processes
    # (agent/tools/memscan_manager.py) -- plain sync cleanup, no await needed.
    shutdown_memscan_sessions()
    await get_toolkit_proxy_manager().shutdown()
    # Same backstop, for the standalone Terminal tab's own real PTY child processes -- a graceful
    # shutdown must never leave an orphaned shell running (agent/tools/terminal_manager.py).
    terminal_manager.shutdown_all()


app = FastAPI(title="ASRA", lifespan=_lifespan)


# Desktop-shell UI lock. When the Tauri desktop shell starts the backend in desktop mode it injects
# a per-launch secret via the ASRA_UI_TOKEN env var -- deliberately NOT stored in .env (run.sh's
# `source .env` would clobber a caller-provided value, and it is a shell->backend handshake, not user
# config). While that token is set, every request must carry it (the asra_ui_token cookie, or a
# __asra query param on the first navigation which then sets the cookie), so a plain browser on the
# same machine gets 403 and the UI is reachable only from the desktop window. When the var is
# empty/unset (web mode, run.bat, plain run.sh) there is no gate and browser access works as before.
@app.middleware("http")
async def _desktop_ui_token_gate(request: Request, call_next):
    token = os.getenv("ASRA_UI_TOKEN")
    if not token:
        return await call_next(request)
    provided = request.cookies.get("asra_ui_token") or request.query_params.get("__asra") or ""
    if not secrets.compare_digest(provided, token):
        return Response("Forbidden — open ASRA from its desktop window.", status_code=403)
    response = await call_next(request)
    if request.query_params.get("__asra") == token and request.cookies.get("asra_ui_token") != token:
        response.set_cookie("asra_ui_token", token, httponly=True, samesite="lax", path="/")
    return response


def _desktop_ui_token_ok(websocket: WebSocket) -> bool:
    """The WebSocket-route counterpart to _desktop_ui_token_gate above -- Starlette's
    @app.middleware("http") decorator, despite the name, is HTTP-only and is never invoked for a
    WebSocket connection at all, confirmed against Starlette's own routing (no framework bug, just
    a gap this project's routes previously never had to care about). Without this explicit check
    repeated inside every WS handler, a WebSocket route would silently bypass the desktop-mode lock
    entirely -- for the Terminal tab specifically that means a plain browser on the same machine
    getting a real, unauthenticated shell. Same token/cookie/query-param shape as the HTTP gate, so
    a browser that's already passed that gate (holds the asra_ui_token cookie) needs nothing extra."""
    token = os.getenv("ASRA_UI_TOKEN")
    if not token:
        return True
    provided = websocket.cookies.get("asra_ui_token") or websocket.query_params.get("__asra") or ""
    return secrets.compare_digest(provided, token)


app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
# Force every render to re-read the .html from disk instead of serving a compiled cached copy.
# auto_reload alone isn't enough here: it decides "reload?" from the file's mtime, and this project
# runs inside WSL2 with the repo on a Windows drive mounted at /mnt/c, where mtime
# updates propagate unreliably across the 9p mount — so an edited template kept serving its stale
# cached version until a full server restart. The server is launched with uvicorn.run(app) (no
# --reload, see the __main__ block), which makes that especially painful: nothing else picks the
# change up either. Setting cache = None disables the compiled-template cache entirely, so the
# loader re-reads the file on every render — a negligible cost for a local single-operator tool, and
# template edits now show up on a plain browser refresh with no restart. (This FastAPI/Starlette
# Jinja2Templates only accepts a pre-built env, not env kwargs, so it's configured after creation.)
templates.env.auto_reload = True
templates.env.cache = None

# The exact asymmetry the comment above describes -- templates hot-reload, this file (and every
# Python module it imports) does NOT, since uvicorn.run(app) below runs with no --reload -- has a
# real, confirmed failure mode of its own: editing main.py (a new route, a new
# templates.env.filters[...] registration) AND a template that now calls it, while an OLDER
# instance of this same process is still running, makes that instance's templates immediately
# serve the NEW markup (hot-reloaded) while its own Python code still lacks whatever new
# route/filter that markup now expects -- an opaque, traceback-free "Internal Server Error" on the
# very next render, with no restart of its own to ever fix it. Made worse by _existing_asra_is_
# serving() below silently REUSING that exact stale-but-still-"healthy" process on the next
# launch instead of ever flagging it. Recorded once here, at import time, so a FRESH process
# checking a port it's about to reuse (see that function) can tell "this running instance's code
# predates my own current copy of main.py" apart from "this running instance is healthy and
# current" -- exposed via /api/system-health's own X-ASRA-Source-Mtime response header.
_SOURCE_MTIME_AT_STARTUP = os.path.getmtime(__file__)

# How often the SSE stream re-reads the session file and checks whether it changed.
_SSE_POLL_INTERVAL_SECONDS = 1.0

# Settings' provider picker needs these — Jinja globals, not per-route context, since they're
# static config (PROVIDER_REGISTRY itself never changes at runtime), not per-request state.
# Split cloud vs. local so local providers (LM Studio, Ollama) render as their own block instead
# of mixing flatly into the cloud-provider list.
templates.env.globals["cloud_provider_ids"] = [pid for pid, cfg in PROVIDER_REGISTRY.items() if not cfg.is_local]
templates.env.globals["local_provider_ids"] = [pid for pid, cfg in PROVIDER_REGISTRY.items() if cfg.is_local]
templates.env.globals["provider_display_names"] = {pid: cfg.display_name for pid, cfg in PROVIDER_REGISTRY.items()}
# The "Open terminal here" quick-launch link (session.html/session_fragment.html) needs a
# session's own project folder to build /terminal?cwd=... -- registered as a plain Jinja global
# (not threaded through every session-page context dict) since it's a pure lookup with no request
# state of its own, same spirit as the provider-picker globals above.
templates.env.globals["get_session_folder"] = get_session_folder
# Same reasoning as get_session_folder just above -- partials/project_backups.html (included from
# session_fragment.html) needs each render's current backup list, but session_fragment.html is
# re-rendered from many different routes (interrupt/stop/findings/hypotheses/...) that would each
# otherwise need to remember to thread a "backups" context key through by hand.
templates.env.globals["list_project_backups"] = list_project_backups
templates.env.globals["project_backup_max_count"] = get_project_backup_max_count()
# Same "pure lookup, no request state" reasoning as get_session_folder/list_project_backups above --
# session_fragment.html's own Techniques tab needs this session's own playbook captures on every
# re-render (interrupt/stop/findings/hypotheses/...) without threading a context key through by hand.
templates.env.globals["list_session_techniques"] = playbook_store.list_techniques_for_session
# Same reasoning as get_session_folder just above -- the session-page terminal drawer (session.html)
# needs the standalone Terminal page's own close-confirm preference, but has no route context of its
# own carrying it (unlike GET /terminal, which passes it explicitly). A plain global lookup avoids
# threading it through every session-page route handler just for this one embedded panel.
templates.env.globals["terminal_skip_close_confirm"] = lambda: terminal_settings.load_terminal_settings()["skip_close_confirm"]
# Same reasoning as terminal_skip_close_confirm just above -- chat_panel.html (rendered from
# session.html/chat.html, neither of which has Settings' own route context) needs to know whether
# the chat_settings.json "Subagent delegation" toggle is on, to decide whether its own Subagents
# header button/dialog (partials/chat_subagents_panel.html) should even be offered for an "agent"/
# "standalone" session (interactive/reverse_engineering always offer it regardless, same rule
# agent/chat.py's _chat_tool_specs already applies).
templates.env.globals["chat_subagents_delegation_enabled"] = lambda: load_chat_settings()["subagents_enabled"]
templates.env.globals["provider_is_local"] = {pid: cfg.is_local for pid, cfg in PROVIDER_REGISTRY.items()}
templates.env.globals["provider_key_required"] = {pid: cfg.api_key_required for pid, cfg in PROVIDER_REGISTRY.items()}
templates.env.globals["provider_base_url_default"] = {pid: cfg.base_url_default for pid, cfg in PROVIDER_REGISTRY.items()}
templates.env.globals["llm_provider_default"] = os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER)
# Read once at startup (matches every other env-derived setting here) — base.html uses this to
# decide whether to even load static/js/debug_events.js's click/htmx tracking at all, so there's
# zero extra network traffic from it in normal, non-debug use.
templates.env.globals["debug_enabled"] = is_debug_enabled()
# Unlike the static values above, this is registered as the CALLABLE itself, not its result — the
# New Project form (templates/partials/new_project_form.html) is {% include %}'d straight into
# base.html's own always-present modal, reachable from every page, so there's no single route
# handler whose own context dict this could be injected into once. Jinja invokes a callable global
# fresh at render time, same as any filter already does, so enabling/disabling a subagent shows up
# immediately without needing a server restart.
templates.env.globals["get_enabled_subagent_profiles"] = get_enabled_profiles
# Same "callable global, invoked fresh at render time" reasoning as get_enabled_subagent_profiles
# right above -- the Recon tab's Credentials card (session_fragment.html) needs to know WHICH
# fields each configured identity actually has, to draw a mask placeholder for each, without the
# real values ever entering this (or any other) Jinja render context at all. session_fragment.html
# itself is rendered from many different call sites (_render_fragment, session.html's own direct
# {% include %}) -- a global avoids threading one more parameter through every one of them.
templates.env.globals["identity_field_presence"] = list_identity_field_presence
# Same "callable global, invoked fresh at render time" reasoning as get_enabled_subagent_profiles
# above -- base.html's own header clock (every page, not just settings.html) needs the operator's
# saved Settings -> Timezone choice, and there's no single route handler whose own context dict
# this could be injected into once. A Save from Settings shows up in the clock on the very next
# render, no server restart needed, same as the toggle above.
templates.env.globals["load_display_timezone"] = load_display_timezone
# Same reasoning as load_display_timezone above -- the clock's own show/hide and zone-label
# toggles (Settings -> Timezone) also render into base.html's sidebar footer on every page.
templates.env.globals["load_clock_show_time"] = load_clock_show_time
templates.env.globals["load_clock_show_zone_label"] = load_clock_show_zone_label
templates.env.globals["load_clock_show_date"] = load_clock_show_date
templates.env.globals["load_clock_style"] = load_clock_style
# Same "callable global, invoked fresh at render time" reasoning as load_display_timezone above --
# base.html emits window.ASRA_SOUND_SETTINGS from this on every page (not just settings.html), since
# static/js/sound_events.js's own event watchers (new finding, session done, ...) need to fire from
# session.html, not only from the Settings screen that edits them.
templates.env.globals["load_sound_settings"] = load_sound_settings
# Project-icon pools -- shared by the New Project picker (macros/project_icons.html's icon_picker)
# and sessions/store.py's own random default, one source of truth (projects/icons.py).
templates.env.globals["PROJECT_ICON_NAMES"] = project_icons.ICON_NAMES
templates.env.globals["PROJECT_ICON_COLORS"] = project_icons.ICON_COLORS
# Subagent-icon pool -- shared by the New/Edit Subagent picker (macros/subagent_icons.html's own
# subagent_icon_picker) and this file's own create_subagent_route/update_subagent_route random
# default, one source of truth (agent/tools/subagent_icons.py). Deliberately a separate pool from
# the project one above, not a shared list -- see that module's own docstring for why.
templates.env.globals["SUBAGENT_ICON_NAMES"] = subagent_icons.SUBAGENT_ICON_NAMES


def _human_dt(value: str | None) -> str:
    """Renders a stored ISO 8601 timestamp (e.g. finding.found_at) as something a human can
    read at a glance instead of the raw microsecond-precision string — falls back to the raw
    value for anything that doesn't parse, rather than hiding a real (if oddly shaped) value.

    Converted to Settings -> Timezone's saved display zone (agent/timezone_settings.py), never
    hardcoded UTC — real, confirmed incident this fixes: every finding/hypothesis/approval/
    credential timestamp used to read hours off from the operator's own wall clock with no way to
    change it. Every value passed in here is real UTC on disk (datetime.now(timezone.utc)) — this
    only changes how it's DISPLAYED, never what's stored.
    """
    if not value:
        return ""
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    localized = parsed.astimezone(ZoneInfo(load_display_timezone()))
    return localized.strftime("%d %b %Y, %H:%M %Z")


templates.env.filters["human_dt"] = _human_dt


# The card "Copy" buttons (session_fragment.html) copy a normalized, structured plain-text block
# instead of whatever the rendered DOM happens to contain — an operator pasting a finding/hypothesis/
# chain into a bug-bounty report, a note, or a chat wants clean labelled sections, not a run-together
# scrape of every span on the card. Built server-side from the real session fields (the same data the
# card renders visually) so the copied text stays correct regardless of which sub-blocks the card
# currently shows. Each builder emits Markdown-ish sections and drops any field that isn't set, so a
# sparse finding never copies a wall of empty headers.
def _copy_section(lines: list[str], heading: str, body: str | None) -> None:
    """Appends a '## heading' block for a non-empty body, blank-line separated — a no-op otherwise."""
    if body and str(body).strip():
        if lines:
            lines.append("")
        lines.append(f"## {heading}")
        lines.append(str(body).strip())


def _finding_copy_text(finding: dict) -> str:
    title = (finding.get("title") or "").strip()
    lines: list[str] = [f"# Finding: {title}" if title else "# Finding"]

    meta: list[str] = []
    if finding.get("severity"):
        meta.append(f"Severity: {finding['severity']}")
    if finding.get("verification"):
        verification = f"Verification: {finding['verification']}"
        if finding.get("exploited"):
            verification += " (exploited)"
        meta.append(verification)
    if finding.get("qualifies_for_bounty"):
        meta.append("Qualifies for bounty: yes")
    if meta:
        lines.append(" · ".join(meta))
    if finding.get("technology"):
        lines.append(f"Technology: {finding['technology']}")
    cves = _extract_cves(f"{finding.get('title', '')} {finding.get('description', '')}")
    if cves:
        lines.append(f"CVEs: {', '.join(cves)}")

    _copy_section(lines, "Description", finding.get("description"))
    _copy_section(lines, "Reproduction / Payload", finding.get("reproduction_steps"))
    _copy_section(lines, "Confirmed PoC command", finding.get("poc_command"))
    _copy_section(lines, "Evidence", finding.get("evidence"))
    _copy_section(lines, "How to fix", finding.get("remediation_advice"))
    if not finding.get("exploited"):
        _copy_section(lines, "Advisory", finding.get("advisory_note"))
    _copy_section(lines, "False positive", finding.get("false_positive_reason"))

    if finding.get("found_at"):
        lines.append("")
        lines.append(f"Found: {_human_dt(finding['found_at'])}")
    return "\n".join(lines)


_HYPOTHESIS_STATUS_LABELS = {"unconfirmed": "Unconfirmed", "confirmed": "Confirmed", "ruled_out": "Ruled out"}


def _hypothesis_copy_text(hypothesis: dict, ref: str = "") -> str:
    status_label = _HYPOTHESIS_STATUS_LABELS.get(hypothesis.get("status"), hypothesis.get("status") or "")
    header = f"# Hypothesis {ref}".strip() + (f": {status_label}" if status_label else "")
    lines: list[str] = [header, (hypothesis.get("text") or "").strip()]

    _copy_section(lines, "Evidence", hypothesis.get("evidence"))
    _copy_section(lines, "Resolution", hypothesis.get("resolution_note"))

    origin = "Your hypothesis" if hypothesis.get("source") == "user" else "Agent-found lead"
    provenance = [origin]
    if hypothesis.get("source_phase"):
        provenance.append(hypothesis["source_phase"])
    if hypothesis.get("created_at"):
        provenance.append(_human_dt(hypothesis["created_at"]))
    lines.append("")
    lines.append("Source: " + " · ".join(provenance))
    return "\n".join(lines)


def _chain_copy_text(attempt: dict) -> str:
    outcome = "Chain confirmed" if attempt.get("outcome") == "chain_confirmed" else "No chain found"
    hop_suffix = f" (hop {attempt['hop']})" if attempt.get("hop") and attempt["hop"] > 1 else ""
    lines: list[str] = [f"# Chain result: {outcome}{hop_suffix}"]
    if attempt.get("ran_at"):
        lines.append(f"Ran: {_human_dt(attempt['ran_at'])}")
    if attempt.get("finding_titles"):
        lines.append(f"Findings involved: {', '.join(attempt['finding_titles'])}")

    _copy_section(lines, "Reasoning", attempt.get("reasoning"))
    _copy_section(lines, "Impact", attempt.get("impact_scenario"))
    if attempt.get("evidence_quotes"):
        lines.append("")
        lines.append("## Evidence quoted")
        lines.extend(f"- {quote}" for quote in attempt["evidence_quotes"])
    _copy_section(lines, "Tool-call proof", attempt.get("tool_call_proof"))
    if attempt.get("reverified_finding_titles"):
        lines.append("")
        lines.append(f"Reverified: {', '.join(attempt['reverified_finding_titles'])}")
    return "\n".join(lines)


def _credential_copy_text(cred: dict) -> str:
    lines: list[str] = ["# Discovered credential", f"{cred.get('username', '')}:{cred.get('password', '')}"]
    if cred.get("source_tool"):
        lines.append(f"Source tool: {cred['source_tool']}")
    if cred.get("found_on_host"):
        lines.append(f"Found on: {cred['found_on_host']}")
    if cred.get("identity_name"):
        lines.append(f"Identity: {cred['identity_name']}")
    if cred.get("suggested_hosts"):
        lines.append(f"Suggested on: {', '.join(cred['suggested_hosts'])}")
    if cred.get("discovered_at"):
        lines.append(f"Discovered: {_human_dt(cred['discovered_at'])}")
    return "\n".join(lines)


def _technique_copy_text(entry: dict) -> str:
    lines: list[str] = [f"# Technique: {entry.get('technique', '')}"]
    lines.append(f"Outcome: {'Worked' if entry.get('outcome') != 'failed' else 'Failed / dead-end'}")
    if entry.get("vuln_class"):
        lines.append(f"Purpose / vuln class: {entry['vuln_class']}")
    when = entry.get("last_confirmed_at") or entry.get("last_seen")
    if when:
        lines.append(f"When: {_human_dt(when)}")
    if entry.get("payload_or_command"):
        lines.append(f"Command/payload: {entry['payload_or_command']}")
    _copy_section(lines, "Evidence", entry.get("evidence_ref"))
    if entry.get("cves"):
        lines.append(f"CVEs: {', '.join(entry['cves'])}")
    return "\n".join(lines)


templates.env.filters["finding_copy_text"] = _finding_copy_text
templates.env.filters["hypothesis_copy_text"] = _hypothesis_copy_text
templates.env.filters["chain_copy_text"] = _chain_copy_text
templates.env.filters["credential_copy_text"] = _credential_copy_text
templates.env.filters["technique_copy_text"] = _technique_copy_text

# Starlette's Jinja2Templates wraps a plain jinja2.Environment -- unlike Flask, it never registers
# a "tojson" filter, even though Jinja2 itself depends on MarkupSafe (already installed transitively,
# no new dependency). Settings' Reserve providers row-builder JS (settings.html) needs its
# provider/model data embedded as real JSON inside a <script> tag, not as a Python dict's repr().
# Escapes the same characters Flask's own tojson implementation does (not just "&quot;"-style HTML
# entities, which would corrupt the JSON syntax itself) so the JSON can never accidentally close the
# surrounding <script> tag or get mangled by the autoescaper -- wrapped in Markup() specifically so
# Jinja's autoescape leaves this pre-escaped output alone instead of re-escaping it a second time.
_JSON_SCRIPT_ESCAPES = {"<": "\\u003c", ">": "\\u003e", "&": "\\u0026", "'": "\\u0027"}


def _tojson_filter(value: object) -> Markup:
    # A route that renders settings.html without passing every context key this page can reference
    # (an error re-render on a DIFFERENT form on the same page, e.g. the wordlist-download error
    # path, which has no reason to know about Reserve providers' own data) leaves Jinja's own
    # Undefined sentinel here instead of a real value -- json.dumps() raises TypeError on it with no
    # graceful fallback of its own. Treating it as None (renders as JSON null) is the same tolerance
    # every {% if %}/{{ }} already gets from Jinja's own default Undefined class for free; this
    # filter is the one place that needed to be taught it explicitly.
    if isinstance(value, jinja2.Undefined):
        value = None
    dumped = json.dumps(value)
    for char, escape in _JSON_SCRIPT_ESCAPES.items():
        dumped = dumped.replace(char, escape)
    return Markup(dumped)


templates.env.filters["tojson"] = _tojson_filter


# Chat replies are free-text model output that commonly includes markdown formatting (**bold**,
# "- " lists, code fences) -- shown as raw literal syntax characters before this filter existed
# (chat_panel.html used to just {{ msg.content }} it, plain-escaped). A small, explicit allowlist,
# not "whatever markdown.markdown() happens to produce" -- content can echo back session-derived
# facts through the LLM's reply (a finding title, a reflected payload string from the target), so
# raw model output is still never trusted as literal HTML; bleach.clean's allowlist is what makes
# wrapping the result in Markup() safe here specifically, not an exception to that rule.
_CHAT_MARKDOWN_ALLOWED_TAGS = [
    "p", "strong", "em", "code", "pre", "ul", "ol", "li", "a", "blockquote", "br",
    # "tables" extension output (python-markdown) -- without these, bleach would strip a table
    # down to its own bare cell text with no structure at all, one long unreadable paragraph.
    "table", "thead", "tbody", "tr", "th", "td",
]
_CHAT_MARKDOWN_ALLOWED_ATTRS = {"a": ["href"]}

# Real, confirmed operator complaint: a "[F3] ..." reference tag (chat_panel.html's own
# asraDiscussInChat inserts exactly this shape, see that function's own comment; agent/chat.py's
# _session_snapshot stamps the identical F#/H#/R# id onto the matching finding/hypothesis/
# recon_target) rendered as flat, unstyled text in the chat bubble -- indistinguishable from a
# stray pair of brackets the operator might have typed for any other reason, with nothing marking
# it as "this is a real, resolvable pointer to a specific card". Matched on the ALREADY
# markdown+bleach-cleaned HTML (never on raw content before that pass), so this never has to worry
# about markdown reinterpreting a bracket as link syntax -- it only ever sees literal text bleach
# already decided was safe to keep. \1/\2 are matched by these two fixed patterns alone (a
# known-good digit or command-name shape), never by arbitrary operator text, so building this
# span's own markup by string substitution carries no injection risk beyond what bleach already
# cleared.
_CHAT_REF_TAG_RE = re.compile(r"\[([FHR]\d+)\]")
# Matches a real slash command token anywhere in the text (chat_panel.html's own client-side
# interception only ever fires on this exact word as the message's first word -- a slash command
# named mid-sentence, e.g. "I typed /compact but nothing happened", still gets sent as a normal
# message and deserves the same visual treatment once it lands in history). (?<![\w/]) keeps this
# from matching mid-token (a URL path segment, "a/compact/b") -- only a slash genuinely starting a
# word counts.
_CHAT_SLASH_CMD_RE = re.compile(r"(?<![\w/])(/(?:new|resume|compact))\b")
_CHAT_TOKEN_PILL_CLASSES = "inline-flex items-center px-1 rounded font-mono text-[0.85em] font-semibold text-accent bg-accent/10"


def _render_chat_markdown(content: str) -> Markup:
    # Cyrillic/other non-ASCII text needs no special handling here -- markdown/bleach/Jinja2 are
    # all unicode-safe by default; confirmed live, not just assumed. "tables" is python-markdown's
    # own built-in GFM-style table extension (pipe syntax, a |---|---| separator row).
    html = markdown.markdown(content or "", extensions=["fenced_code", "tables"])
    cleaned = bleach.clean(
        html, tags=_CHAT_MARKDOWN_ALLOWED_TAGS, attributes=_CHAT_MARKDOWN_ALLOWED_ATTRS,
        protocols=["http", "https"], strip=True,
    )
    highlighted = _CHAT_REF_TAG_RE.sub(rf'<span class="{_CHAT_TOKEN_PILL_CLASSES}">[\1]</span>', cleaned)
    highlighted = _CHAT_SLASH_CMD_RE.sub(rf'<span class="{_CHAT_TOKEN_PILL_CLASSES}">\1</span>', highlighted)
    return Markup(highlighted)


templates.env.filters["render_chat_markdown"] = _render_chat_markdown


# Same calculation agent/core.py's run_session/run_focused_exploit now log to debug.log once a
# run actually ends, reused here (not duplicated) for the UI's own display of the same number.
templates.env.filters["session_duration"] = format_session_duration
# Plan tab's per-phase duration display (session["phase_timings"], agent/core.py's
# _mark_phase_started/_mark_phase_finished) — same calculation as session_duration, scoped to one
# phase instead of the whole session.
templates.env.filters["phase_duration"] = format_phase_duration
# Plan tab's per-task/subtask duration display (agent/core.py's _stamp_task_timings) — no single
# owning object to read a {started_at, finished_at} pair off of the way session_duration/
# phase_duration have, so this takes the two timestamps directly.
templates.env.filters["duration_between"] = format_duration_between
# hypothesis_verification's own card (session_fragment.html) -- that phase can legitimately run in
# several separate passes hours apart, so it reads a pre-summed real-work total instead of a naive
# started_at/finished_at span (which would count the idle time between passes as work).
templates.env.filters["accumulated_duration"] = format_accumulated_duration
# Overview tab's live time-budget countdown (session_fragment.html) -- same deadline formula
# agent/core.py's own mid-pass enforcement check reads, so the UI never shows a different number
# than what's actually being enforced.
templates.env.filters["time_budget_deadline_epoch"] = time_budget_deadline_epoch


def _is_ip_address(value: str) -> bool:
    """True for a literal IPv4/IPv6 address — the Asset Info table (session_fragment.html,
    proof_report.html) uses this to decide whether a recon_result target's host is a domain worth
    showing its resolved IP(s) next to (from recon_result["dns_map"], agent/core.py's _run_recon)
    or already an IP with nothing to add."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


templates.env.filters["is_ip"] = _is_ip_address

_CVE_ID_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _extract_cves(text: str | None) -> list[str]:
    """Pulls CVE IDs out of free text (a finding's title/description) so a card can show its own
    CVE badge without the model having to also fill in a separate structured field for it."""
    if not text:
        return []
    return sorted({match.upper() for match in _CVE_ID_PATTERN.findall(text)})


templates.env.filters["extract_cves"] = _extract_cves
# A finding card must never look identical to a real, verified High-severity finding when it's
# actually just a speculative cve_lookup product-name match with no host Recon ever confirmed —
# real incident this exists because of: exactly that confusion, three "High" cards that read as
# live holes but had zero target behind any of them. session_fragment.html's unconfirmed_badge().
templates.env.filters["is_ungrounded_cve_lookup"] = is_ungrounded_cve_lookup


def _group_subagent_logs(session: dict) -> list[dict]:
    """Delegated subagents run concurrently with whatever phase (recon/analyze/...) is active at
    the same time and log their own steps into the SAME session["logs"] stream (phase="subagent"),
    interleaved by step number with the main agent's own entries — correct, but not something a
    human can follow as "what did THIS delegation do" from the flat list alone. Groups those
    entries by which delegated task actually produced them (RunContext's subagent_task_id, set for
    the duration of one delegated task the same way current_finding_title already scopes an
    exploit attempt's own log entries) so session_fragment.html's Subagent log section can render
    one real block per delegation instead of a flat interleaved stream.
    A session persisted before this field existed has phase="subagent" entries with no
    subagent_task_id at all — grouped under "unknown" (entry.get, never a raw [] subscript) so an
    old session's log still renders instead of erroring on a missing key.
    """
    tasks_meta = session.get("subagent_tasks") or {}
    groups: dict[str, list[dict]] = {}
    for entry in session.get("logs") or []:
        if entry.get("phase") != "subagent":
            continue
        groups.setdefault(entry.get("subagent_task_id") or "unknown", []).append(entry)

    result = [
        {
            "task_id": task_id,
            "profile_name": (tasks_meta.get(task_id) or {}).get("profile_name") or entries[0].get("subagent_name") or "Subagent",
            "status": (tasks_meta.get(task_id) or {}).get("status"),
            # "model" for a session predating this field (agent/tools/subagent_tasks.py's
            # register_task default) -- an old task really was always model-initiated, since
            # _auto_delegate_recon_overflow didn't exist yet to have triggered any of them.
            "triggered_by": (tasks_meta.get(task_id) or {}).get("triggered_by", "model"),
            "entries": entries,
        }
        for task_id, entries in groups.items()
    ]
    result.sort(key=lambda g: g["entries"][0]["step"])
    return result


templates.env.filters["subagent_log_groups"] = _group_subagent_logs


def _recon_stats(session: dict) -> dict:
    """Concrete counts for the Recon / Asset Info tab (session_fragment.html) — how many distinct
    hosts/domains/subdomains/IPs/open ports/CVEs recon actually turned up, on top of the raw lists
    that tab already renders below (each stat tile doubles as a click-to-filter button over that
    same list, using the domain_hosts/subdomain_hosts sets returned here). A friendly summary only,
    derived entirely from recon_result + the session's own original target string — never fed back
    into scope/allowlist enforcement, which stays exactly where it already lives
    (agent/tools/allowed_targets.py)."""
    recon_result = session.get("recon_result") or {}
    targets = recon_result.get("targets") or []
    dns_map = recon_result.get("dns_map") or {}
    cves = recon_result.get("cves") or []

    hostnames = {t["host"] for t in targets if t.get("host") and not _is_ip_address(t["host"])}
    hostnames |= set(dns_map.keys())

    # Same loose scheme/wildcard stripping the New Project form's own chip-input preview and
    # validate_scope_entry() apply — good enough to tell "already in the scope the operator typed"
    # from "recon found this on its own", not a security decision (that's the allowlist's job).
    original_entries = {
        re.sub(r"^https?://", "", entry.strip(), flags=re.IGNORECASE).removeprefix("*.").rstrip("/").lower()
        for entry in (session.get("target") or "").split(",")
        if entry.strip()
    }
    subdomains_discovered = {h for h in hostnames if h.lower() not in original_entries}
    domains_in_scope = hostnames - subdomains_discovered

    unique_ips: set[str] = {ip for ips in dns_map.values() for ip in ips if _is_ip_address(ip)}
    unique_ips |= {t["host"] for t in targets if t.get("host") and _is_ip_address(t["host"])}

    return {
        "hosts_scanned": len({t["host"] for t in targets if t.get("host")}),
        "domains": len(domains_in_scope),
        "subdomains_discovered": len(subdomains_discovered),
        "unique_ips": len(unique_ips),
        "open_ports": len(targets),
        "cves_found": len(cves),
        # Membership sets, not just counts -- session_fragment.html's own per-target rows use these
        # to tag themselves with a matching data-filter-category attribute, so the tiles above can
        # act as click-to-filter buttons over the exact same classification the numbers came from
        # (never a second, separately-reasoned "is this a subdomain" check that could disagree).
        "domain_hosts": domains_in_scope,
        "subdomain_hosts": subdomains_discovered,
    }


templates.env.filters["recon_stats"] = _recon_stats


def _group_technology_tokens(tokens: list[str]) -> list[tuple[str, str]]:
    """WhatWeb's own raw output format is a flat list of "Plugin[value1,value2]" (or bare
    "Plugin") chunks, repeated verbatim across every whatweb call made against the same host this
    session — the Recon tab used to just comma-join the whole raw list as-is, an unreadable wall
    of text with the same tokens duplicated many times over (confirmed live: a single host's own
    technologies list routinely had the same "HTTPServer[cloudflare]"-shaped chunk 3+ times).
    Groups by plugin/header name, deduplicating values across repeats, into a clean (name, values)
    list — real "what does this run" signal (WordPress/Drupal/PHP/nginx/Apache-shaped names)
    sorted before generic transport noise (Cookies/Country/IP/UncommonHeaders), not interleaved
    with it in whatever order WhatWeb happened to print them.
    """
    grouped: dict[str, set[str]] = {}
    for token in tokens or []:
        match = re.match(r"^([^\[]+)(?:\[(.*)\])?$", token.strip())
        if not match:
            continue
        name = match.group(1).strip()
        if not name:
            continue
        values = grouped.setdefault(name, set())
        raw_value = match.group(2)
        if raw_value:
            values.update(v.strip() for v in raw_value.split(",") if v.strip())

    noise_names = {"cookies", "country", "ip", "uncommonheaders", "via-proxy", "title", "redirectlocation", "x-ua-compatible"}

    def sort_key(item: tuple[str, set[str]]) -> tuple[bool, str]:
        return (item[0].lower() in noise_names, item[0].lower())

    return [
        (name, ", ".join(sorted(values)) if values else "")
        for name, values in sorted(grouped.items(), key=sort_key)
    ]


templates.env.filters["group_tech_tokens"] = _group_technology_tokens


def _group_recon_targets_by_host(
    targets: list[dict],
    dns_map: dict,
    os_guesses: dict,
    technologies_by_host: dict,
    protections_by_host: dict,
    technology_certainty_by_host: dict | None = None,
    technology_details_by_host: dict | None = None,
) -> list[dict]:
    """Recon / Asset Info tab: `targets` is flat, one entry per open port (agent/core.py's
    record_target is called once per port) -- rendering one full card per entry used to repeat the
    same host's name/known-hostnames/resolved-IPs/OS-guess/Protection/Technologies once for every
    port it has, confirmed real complaint (a host with several open ports read as a wall of near-
    identical cards). Groups into one entry per real physical host, ports collapsed into that
    host's own compact sub-list instead.

    "Real physical host" uses the exact same DNS-identity notion agent/core.py's own
    _dedupe_hosts_by_dns_identity already applies when deciding how many distinct hosts exist for
    auto-delegation (a hostname and its own resolved IP are the SAME host, never two) -- reused
    here so a host scanned once by hostname (whatweb/httpx) and once by its own resolved IP (nmap)
    renders as ONE card with both names, not two separate cards.

    Each port keeps its own original 1-based index from `targets` for its "R#" chat-reference chip
    -- this MUST exactly match agent/chat.py's _session_snapshot, which numbers
    session["recon_result"]["targets"] in that same original flat order; grouping here must never
    renumber it.

    `technology_certainty_by_host` (optional -- absent for a session recorded before this field
    existed) is WhatWeb's own per-plugin certainty (agent/tools/builders/whatweb.py's
    parse_whatweb_output, from its JSON-Verbose log), looked up the same tolerant way as
    os_guesses/technologies/protections and attached as group["technology_certainty"].

    `technology_details_by_host` (optional -- absent for a session recorded before this field
    existed) is agent/core.py's _merge_technology_details own structured map ({tech_name:
    {version, categories, certainty, sources}}), combining WhatWeb and agent/tools/
    js_fingerprint.py's client-side (JS/DOM-executed) detections -- looked up the same tolerant way
    and attached as group["technology_details"], the Recon tab's source for per-tech version/
    category/"confirmed client-side" display.
    """

    def tolerant_lookup(source: dict, candidates: list[str]):
        for candidate in candidates:
            if candidate in source:
                return source[candidate]
        for candidate in candidates:
            for known_host, value in source.items():
                if candidate and known_host and (candidate in known_host or known_host in candidate):
                    return value
        return None

    groups: list[dict] = []
    identity_to_group: dict[str, dict] = {}

    for index, target in enumerate(targets, start=1):
        host = target.get("host")
        if not host:
            continue

        identity_keys = {host}
        identity_keys.update(dns_map.get(host) or [])
        for hostname, ips in dns_map.items():
            if host in ips:
                identity_keys.add(hostname)

        group = next((identity_to_group[key] for key in identity_keys if key in identity_to_group), None)
        if group is None:
            group = {"primary_host": host, "identity_names": set(), "ports": []}
            groups.append(group)

        group["identity_names"].update(identity_keys)
        for key in identity_keys:
            identity_to_group[key] = group
        group["ports"].append({**target, "index": index})

    for group in groups:
        primary = group["primary_host"]
        aliases = sorted(group["identity_names"] - {primary})
        candidates = [primary, *aliases]
        group["is_ip"] = _is_ip_address(primary)
        group["resolved_ips"] = [] if group["is_ip"] else sorted(dns_map.get(primary) or [])
        group["known_hostnames"] = [n for n in aliases if not _is_ip_address(n)] if group["is_ip"] else []
        group["os_guess"] = tolerant_lookup(os_guesses, candidates)
        group["technologies"] = tolerant_lookup(technologies_by_host, candidates)
        group["protections"] = tolerant_lookup(protections_by_host, candidates)
        group["technology_certainty"] = tolerant_lookup(technology_certainty_by_host or {}, candidates) or {}
        group["technology_details"] = tolerant_lookup(technology_details_by_host or {}, candidates) or {}
        del group["identity_names"]

    return groups


templates.env.filters["group_recon_targets_by_host"] = _group_recon_targets_by_host
templates.env.filters["classify_target_type"] = classify_target_type


# Same ordering _SEVERITY_RANK (agent/core.py) already uses -- a small local copy rather than
# importing a private cross-module name for four fixed strings; both modules already separately
# hardcode this same enum ordering (_VALID_SEVERITIES/_VALID_FINDING_SEVERITIES), so this follows
# established precedent rather than introducing a new pattern.
# Manual (operator-authored) map nodes/edges use these fixed vocabularies -- checked server-side on
# every create/edit so a bad value can never reach the frontend's own hardcoded icon/arrow lookup
# (attack_surface_graph.js) silently unrendered. "actor" is deliberately here alongside the
# infra-shaped kinds -- a real engagement often needs to annotate a person/team (a third-party
# vendor, "the client's SOC"), not just hosts.
_MAP_NODE_KINDS = ["host", "service", "domain", "actor"]
_MAP_EDGE_DIRECTIONS = ["forward", "reverse", "bidirectional", "none"]

_MAP_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_MAP_SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# Ports that make a host worth a second look on sight, regardless of what findings already exist
# on it -- remote admin (RDP/VNC/WinRM), lateral-movement-shaped services (SMB/RPC), and databases
# (an exposed one is very often reachable with no auth at all). Feeds _map_surface_score's own
# node-size weighting below -- deliberately a short, well-known list, not an exhaustive port
# database; the goal is "does this host's own open-port list alone raise an eyebrow", not a
# complete service-risk classifier.
_MAP_RISKY_PORTS = frozenset({
    22, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017,
})


def _map_surface_score(worst_severity: str | None, hypothesis_count: int, has_confirmed_access: bool, ports: list[dict]) -> int:
    """Attack-surface weight for one Map node -- drives node SIZE (attack_surface_graph.js), the
    same idea as Cobalt Strike's own beacon graph drawing a "juicier" box bigger: an operator's eye
    should land on the highest-value target first, not equally on a Critical RDP box and a quiet
    Info-only one. Every input here is already computed/available on the node by the time this is
    called (worst_severity/hypothesis_count/ports), so this is pure arithmetic over existing
    signal, never a new thing the model has to separately report.
    """
    risky_port_count = sum(1 for p in ports if p.get("port") in _MAP_RISKY_PORTS)
    return (
        _MAP_SEVERITY_WEIGHT.get(worst_severity or "", 0)
        + (2 if has_confirmed_access else 0)
        + min(hypothesis_count, 3)
        + 2 * min(risky_port_count, 3)
    )


def _worst_severity(severities) -> str | None:
    present = set(severities)
    return next((s for s in _MAP_SEVERITY_ORDER if s in present), None)


# WhatWeb technology tokens (session["recon_result"]["technologies"], WhatWeb's own raw
# "Plugin[value]" shape) that are page/session-specific noise, never a real "these two hosts share
# infrastructure" signal -- two hosts both showing Title[...] or Cookies[PHPSESSID] says nothing
# about their stack, unlike both showing HTTPServer[nginx] or IP[1.2.3.4], which genuinely does.
# Used by _build_attack_surface_graph's own shared_surface edges below.
_MAP_SHARED_SURFACE_NOISE_PREFIXES = frozenset({
    "Cookies", "Title", "UncommonHeaders", "Script", "X-UA-Compatible",
    "Country", "Open-Graph-Protocol", "Strict-Transport-Security", "HTML5",
})

# Past this many hosts sharing one technology/WAF token, a "shared surface" edge stops being a
# useful signal and starts being visual clutter (a common CDN/framework token on a large recon run
# would otherwise draw one edge per pair) -- _build_attack_surface_graph below stars these instead
# of a full pairwise clique (see its own comment), so this really only bounds how many hosts one
# single star fans out to, not the total edge count.
_MAP_SHARED_SURFACE_MAX_FANOUT = 8


def _map_surface_signal(token: str) -> str | None:
    """Normalizes one WhatWeb technology token into a comparable "shared surface" signal for
    _build_attack_surface_graph's shared_surface edges, or None if it's noise (see
    _MAP_SHARED_SURFACE_NOISE_PREFIXES) never worth an edge over. The comparison key is the WHOLE
    token, not just its "Plugin[value]" prefix -- two hosts both showing "HTTPServer[nginx]" share
    a real signal, but "HTTPServer[nginx]" vs "HTTPServer[cloudflare]" must NOT match just because
    the plugin name matches with a different value.
    """
    prefix = token.split("[", 1)[0]
    return None if prefix in _MAP_SHARED_SURFACE_NOISE_PREFIXES else token


def _map_apex_domain(hostname: str) -> str | None:
    """Registrable-domain heuristic for _build_attack_surface_graph's domain_family edges: the
    last two dot-separated labels ("portal.example.com" -> "example.com"). Deliberately simple
    (not a real public-suffix-list lookup, e.g. "foo.co.uk" would wrongly reduce to "co.uk") --
    good enough for "does this subdomain belong to a domain already on THIS map", which is all
    these edges claim; a real PSL dependency would be over-engineering for that. None for an IP,
    or a name with fewer than 3 labels (already an apex, or too short to have a meaningful parent).
    """
    if _is_ip_address(hostname):
        return None
    labels = hostname.split(".")
    if len(labels) < 3:
        return None
    return ".".join(labels[-2:])


def _build_attack_surface_graph(session: dict) -> dict:
    """Map tab's Attack Surface sub-view (partials/session_fragment.html's own <section
    data-tab="map">) -- nodes are real physical hosts, reusing _group_recon_targets_by_host's own
    DNS-identity merge above so a hostname and its own resolved IP never render as two fake
    separate hosts here either. Colored by the worst severity among findings/hypotheses tied to
    this host's identity set (see _resolve_map_item_node below for how a finding/hypothesis
    resolves to a node) -- None (unlocated) for one that genuinely isn't tied to any known host.
    Called on every session-page render (agent-mode/interactive only), same live-on-every-SSE-tick
    treatment as every other tab -- there is deliberately no separate route/cache for this, a
    session's own target/finding lists are already small enough that recomputing it per render is
    cheap, same reasoning _group_recon_targets_by_host itself already accepts.

    Edges, auto-derived from data the agent already records (never guessed) -- three families:
    - Structural fact: DNS resolution (a domain -> each of its own resolved IPs,
      session["recon_result"]["dns_map"]) and domain_family (a subdomain -> its own registrable
      parent domain, when that parent is itself a node -- _map_apex_domain).
    - Inferred kinship ("these two probably share infrastructure, worth a look"): shared_surface
      (matching WhatWeb technology token or WAF/CDN label across two hosts, _map_surface_signal)
      and credential_reuse (session["asset_graph"]["credentials"], agent/core.py's
      _update_asset_graph) -- the exact same credential-reuse data the Chain tab already renders as
      plain text cards, given a real graph position here instead of a second, disagreeing notion of
      "which hosts are related".
    - Proven attack path: attack_path, one edge per real pivot a Chain pass actually reasoned
      through (session["chain_attempts"], agent/core.py's _persist_chain_attempt) -- the closest
      thing this app has to Cobalt Strike's own beacon-to-beacon pivot lines, backed by the exact
      same reasoning/evidence the Chain tab already shows as plain text, not a guessed connection.

    On top of that real recon data, the operator can also hand-author nodes/edges (a suspected
    pivot, a third-party actor, a beacon relationship worth diagramming before it's proven) --
    session["map_manual"] (see the /api/session/{id}/map/* routes below), merged in here rather
    than kept as a second, disconnected graph so the operator never has to mentally overlay two
    diagrams. Every node (auto or manual) also carries whatever position the operator last dragged
    it to (session["map_manual"]["positions"]), which is the ONLY thing that lets the graph survive
    a real page reload (F5) -- the frontend's own in-memory cytoscape instance does not.
    """
    map_manual = session.get("map_manual") or {}
    positions = map_manual.get("positions") or {}
    recon_result = session.get("recon_result") or {}
    targets = recon_result.get("targets") or []
    dns_map = recon_result.get("dns_map") or {}
    groups = _group_recon_targets_by_host(
        targets, dns_map,
        recon_result.get("os_guesses") or {},
        # Real, confirmed bug this fixes: recon_result has never actually had "technologies_by_host"/
        # "protections_by_host" keys (session_fragment.html's own Recon tab reads the real ones,
        # "technologies"/"protections", into local vars it just happens to name with a "_by_host"
        # suffix) -- every call here silently passed {} for both, so no host node ever carried real
        # technology/protection data. Now that shared_surface edges below actually depend on this,
        # a wrong key here would silently mean "no shared_surface edges ever fire", not just a
        # cosmetic gap.
        recon_result.get("technologies") or {},
        recon_result.get("protections") or {},
    )

    findings = session.get("findings") or []
    hypotheses = session.get("hypotheses") or []

    nodes: list[dict] = []
    node_id_by_identity: dict[str, str] = {}
    identities_by_node: dict[str, set[str]] = {}

    for group in groups:
        node_id = group["primary_host"]
        # known_hostnames alone is NOT enough here -- it's populated for a different case (the
        # SAME physical host recorded once by hostname and once by its own IP) and stays empty
        # whenever the primary is a hostname, per _group_recon_targets_by_host's own known_hostnames
        # line above. Two genuinely DIFFERENT hostnames that happen to share one resolved IP (e.g.
        # two subdomains behind one load balancer) still merge into ONE group here (that's the
        # DNS-identity merge doing its job), but the second hostname's own name would otherwise
        # never enter `identities` -- every raw target host that fed into this group (group["ports"],
        # each carrying its own original "host") is the actual complete source of truth. Real,
        # confirmed bug this fixes: without it, a second hostname sharing a group's IP got a
        # spurious SECOND "domain-only" node below (duplicating a host already on the map) and its
        # own findings/hypotheses silently failed to match this group at all.
        identities = {node_id, *group.get("known_hostnames", []), *group.get("resolved_ips", [])}
        identities.update(p.get("host") for p in group.get("ports", []) if p.get("host"))
        identities_by_node[node_id] = identities
        for identity in identities:
            node_id_by_identity[identity] = node_id

        surface_tokens = sorted({
            signal for tok in (group.get("technologies") or []) if (signal := _map_surface_signal(tok))
        })
        # From the RAW group ports (each a full copy of its original target dict, "discovered_at"
        # included) -- the node's own "ports" field below is a stripped {port, service} projection
        # that drops it, so this has to read group["ports"] directly, not node["ports"] later.
        port_discovery_times = [p.get("discovered_at") for p in group.get("ports") or [] if p.get("discovered_at")]

        nodes.append({
            "id": node_id,
            "label": node_id,
            # The full real alias set (every raw target hostname that fed into this merged group),
            # not group["known_hostnames"] alone -- that field is populated for a DIFFERENT case
            # (see the identities comment above) and silently omits a second hostname sharing this
            # group's IP, which otherwise reads as "this real target vanished from the map" the
            # instant it merges into a sibling's node.
            "known_hostnames": sorted(identities - {node_id} - set(group.get("resolved_ips", []))),
            "resolved_ips": group.get("resolved_ips", []),
            "ports": [{"port": p.get("port"), "service": p.get("service")} for p in group.get("ports", [])],
            "technologies": surface_tokens,
            # Filled in below, once every node's own identity set is known -- a finding/hypothesis
            # can reference a host this loop hasn't reached yet.
            "finding_count_by_severity": {},
            "worst_severity": None,
            "has_open_hypothesis": False,
            "hypothesis_count": 0,
            "has_confirmed_access": False,
            "surface_score": 0,
            "first_seen_at": min(port_discovery_times, default=None),
            "manual": False,
            "kind": "host",
            "notes": "",
            "position": positions.get(node_id),
        })

    # Domain-only nodes: a dns_map key not yet covered by any target group (recon found the
    # domain -- crt.sh/subfinder/whois -- but nothing has port-scanned it yet).
    for domain, ips in dns_map.items():
        if domain in node_id_by_identity:
            continue
        node_id_by_identity[domain] = domain
        identities_by_node[domain] = {domain, *ips}
        nodes.append({
            "id": domain, "label": domain, "known_hostnames": [], "resolved_ips": sorted(ips),
            "ports": [], "technologies": [], "finding_count_by_severity": {},
            "worst_severity": None, "has_open_hypothesis": False, "hypothesis_count": 0,
            "has_confirmed_access": False, "surface_score": 0, "first_seen_at": None,
            "manual": False, "kind": "domain", "notes": "", "position": positions.get(domain),
        })

    def _resolve_map_item_node(item: dict, text_fields: tuple[str, ...]) -> str | None:
        """Resolves a finding/hypothesis to the node it's about: its own structured "host" field
        when set and it actually names a known identity, else a tolerant substring match of that
        same identity set against its free-text field(s) -- record_finding/record_hypothesis both
        have an optional "host" that's rarely set in practice (confirmed live: 0 of 4 hypotheses,
        16 of 21 findings in a real operator session had it) even though the model's own title/text
        almost always names the real host in plain language ("RDP on play.example.com:3389 ...").
        Real, confirmed bug this fixes: findings never had this fallback at all (only hypotheses
        did) -- most confirmed findings in a real session never colored ANY node's severity border,
        the single most useful signal this graph has, purely because the structured field they
        happened to be recorded with was left empty.
        """
        host = item.get("host")
        if host:
            return node_id_by_identity.get(host)
        text = " ".join(str(item.get(f) or "") for f in text_fields)
        # Real, confirmed bug this fixes: picking the first identities_by_node match (dict
        # insertion order) let a short, generic identity steal a match meant for one of its own
        # subdomains -- "example.com" is itself a substring of "play.example.com", so a finding
        # titled "...RDP on play.example.com:3389..." matched the PARENT domain's own "example.com"
        # identity before ever reaching play.example.com's own, more specific one. The longest
        # matching identity is always the most specific host actually named, so it wins regardless
        # of iteration order.
        best_node_id, best_len = None, -1
        for nid, identities in identities_by_node.items():
            for identity in identities:
                if identity and len(identity) > best_len and identity in text:
                    best_node_id, best_len = nid, len(identity)
        return best_node_id

    findings_by_node: dict[str, list[dict]] = {}
    finding_node_by_title: dict[str, str] = {}
    for finding in findings:
        node_id = _resolve_map_item_node(finding, ("title", "description"))
        if node_id is None:
            continue
        findings_by_node.setdefault(node_id, []).append(finding)
        if finding.get("title"):
            finding_node_by_title[finding["title"]] = node_id

    hypotheses_by_node: dict[str, list[dict]] = {}
    for hypothesis in hypotheses:
        # record_hypothesis has never had a "severity" field (a hypothesis is an open QUESTION,
        # not a scored vulnerability) -- only "unconfirmed" counts as open signal here: "confirmed"
        # gets a real finding recorded alongside it (that finding's own severity already covers
        # this host, handled above) and "ruled_out" is settled.
        if hypothesis.get("status") != "unconfirmed":
            continue
        node_id = _resolve_map_item_node(hypothesis, ("text",))
        if node_id is not None:
            hypotheses_by_node.setdefault(node_id, []).append(hypothesis)

    for node in nodes:
        node_findings = findings_by_node.get(node["id"], [])
        severity_counts: dict[str, int] = {}
        for finding in node_findings:
            severity = finding.get("severity") or "Low"
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        node["finding_count_by_severity"] = severity_counts
        node["worst_severity"] = _worst_severity(severity_counts)
        open_hypotheses = hypotheses_by_node.get(node["id"], [])
        # An open hypothesis has no severity to borrow -- it gets its own honest signal (a neutral
        # accent-colored dashed border, frontend-side) instead of a fabricated severity color. Only
        # matters when there's no confirmed finding yet; once one exists, the real severity color
        # is the more concrete, actionable thing to show.
        node["has_open_hypothesis"] = len(open_hypotheses) > 0
        node["hypothesis_count"] = len(open_hypotheses)
        # "Confirmed access" -- a REAL foothold (record_finding's own "exploited" flag, set only
        # once exploit confirmation actually reached/demonstrated something on this host), not just
        # "a vulnerability was found here". The single clearest CS-style visual distinction this
        # graph can offer: a filled icon (frontend) means real access was proven, not merely that
        # something looked wrong.
        node["has_confirmed_access"] = any(f.get("exploited") for f in node_findings)
        node["surface_score"] = _map_surface_score(
            node["worst_severity"], node["hypothesis_count"], node["has_confirmed_access"], node.get("ports") or [],
        )
        # Earliest real timestamp this node is known from -- a target's own "discovered_at"
        # (agent/core.py's _run_recon, only ever set going forward, so an older session's targets
        # legitimately have none) or, failing that, its earliest finding's "found_at". Frontend's
        # own timeline scrubber (attack_surface_graph.js) uses this to replay roughly the order
        # things were actually found in -- a node with no timestamp at all from either source
        # simply has no known discovery time and always stays visible, never hidden by the
        # scrubber (an honest "unknown", not treated as "found at the very start").
        # node["first_seen_at"] may already hold a real port-discovery timestamp set above (the
        # groups loop) -- merge in finding timestamps rather than overwrite, so a node's earliest
        # known moment wins regardless of which source actually has the earlier one.
        candidate_timestamps = [f.get("found_at") for f in node_findings]
        if node.get("first_seen_at"):
            candidate_timestamps.append(node["first_seen_at"])
        node["first_seen_at"] = min((t for t in candidate_timestamps if t), default=None)

    # Manual (operator-authored) nodes -- same node shape as an auto one so the frontend never
    # needs a second code path, just a "manual": True flag deciding whether it's editable/
    # deletable. Never collides with an auto node's own id (manual ids are always "manual-<uuid4>",
    # see the create route below), so no identity-merge logic is needed here.
    for manual_node in map_manual.get("nodes") or []:
        node_id_by_identity[manual_node["id"]] = manual_node["id"]
        nodes.append({
            "id": manual_node["id"], "label": manual_node.get("label") or manual_node["id"],
            "known_hostnames": [], "resolved_ips": [], "ports": [], "technologies": [],
            "finding_count_by_severity": {},
            "worst_severity": None, "has_open_hypothesis": False, "hypothesis_count": 0,
            "has_confirmed_access": False, "surface_score": 0,
            # None, deliberately never computed for a manual node -- an operator placed it
            # themselves, so the timeline scrubber (frontend) always shows it regardless of
            # position, the same "unknown discovery time never hides a node" rule real recon-
            # derived nodes with no timestamp source get too.
            "first_seen_at": None,
            "manual": True, "kind": manual_node.get("kind") or "host",
            "notes": manual_node.get("notes") or "",
            "position": positions.get(manual_node["id"]),
        })

    edges: list[dict] = []
    seen_edges: set[tuple] = set()

    def add_edge(source: str, target: str, kind: str, label: str = "", direction: str = "none") -> dict | None:
        if source == target:
            return None
        key = (frozenset((source, target)), kind)
        if key in seen_edges:
            return None
        seen_edges.add(key)
        edge = {
            "id": f"{source}->{target}:{kind}", "source": source, "target": target, "kind": kind,
            "label": label, "direction": direction, "manual": False,
            "data_type": "", "volume": "", "format": "", "interval": "", "notes": "",
            # None by default -- a structural fact (domain_family, dns) or inferred kinship
            # (shared_surface) has no single "moment" it happened, so the timeline scrubber
            # (frontend) always shows it once both endpoints are visible. Only attack_path edges
            # below set this to a real timestamp -- a proven pivot IS a moment in the story.
            "at": None,
        }
        edges.append(edge)
        return edge

    # A "dns" edge only ever appears between two GENUINELY distinct nodes -- most dns_map entries
    # never produce one at all, because _group_recon_targets_by_host above already used this exact
    # same dns_map to merge a hostname with its own resolved IP into ONE node (that's the whole
    # point of the DNS-identity merge, see that function's own docstring) before this loop ever
    # runs. The real case this DOES catch: a domain dns_map knows about that was never itself
    # port-scanned (so it's not in `targets`, and _group_recon_targets_by_host never saw it) but
    # shares a resolved IP with a domain that WAS -- that domain becomes its own separate node
    # (the loop above), and add_edge's own source==target guard is what naturally no-ops every
    # already-merged case instead of needing a second, explicit check here.
    for domain, ips in dns_map.items():
        domain_node = node_id_by_identity.get(domain, domain)
        for ip in ips:
            # "forward" -- a domain resolving to an IP is a genuinely directional fact (unlike
            # credential_reuse below, which is symmetric: neither host "points at" the other).
            add_edge(domain_node, node_id_by_identity.get(ip, ip), "dns", direction="forward")

    credentials = (session.get("asset_graph") or {}).get("credentials") or []
    hosts_by_credential_pair: dict[tuple, set[str]] = {}
    for cred in credentials:
        host = cred.get("found_on_host")
        if not host:
            continue
        pair = (cred.get("username"), cred.get("password"))
        hosts_by_credential_pair.setdefault(pair, set()).add(node_id_by_identity.get(host, host))
    for shared_hosts in hosts_by_credential_pair.values():
        ordered = sorted(shared_hosts)
        for i, source in enumerate(ordered):
            for target in ordered[i + 1:]:
                add_edge(source, target, "credential_reuse", "shared credential")

    # domain_family: a subdomain -> its own registrable parent domain, when that parent is ALSO a
    # node on this map (never invents a phantom node just to draw an edge to it). Real, confirmed
    # gap this fixes: dns edges above almost never fire in practice (see that block's own comment
    # -- a scanned hostname and its resolved IP already merge into one node before edges are even
    # built), so a typical recon-heavy session with a dozen real subdomains and zero shared
    # credentials rendered as a pile of completely disconnected icons with no relationship between
    # any of them -- confirmed live on a real 21-target session. This is a structural fact
    # (dashed borders/severity colors carry the interesting per-host signal, this just supplies the
    # backbone), not a guess, so every non-apex node gets exactly one such edge -- O(n) total, never
    # a clique.
    for node in nodes:
        if node["manual"]:
            continue
        apex = _map_apex_domain(node["id"])
        apex_node_id = node_id_by_identity.get(apex) if apex else None
        if apex_node_id:
            add_edge(apex_node_id, node["id"], "domain_family", "subdomain", direction="forward")

    # shared_surface: two (or more) hosts whose WhatWeb technology fingerprint, WAF/CDN label, or
    # TLS certificate genuinely matches -- inferred kinship ("these probably share infrastructure,
    # worth a look"), not a proven fact, so it's visually distinct (frontend) from domain_family/
    # dns above. Starred from one anchor host per shared signal rather than a full pairwise clique
    # -- a common token (e.g. plain "nginx") shared by many hosts would otherwise draw one edge per
    # PAIR (_MAP_SHARED_SURFACE_MAX_FANOUT skips a signal entirely once it's THAT common, since at
    # that point it stops being a useful "these two are related" signal and starts being noise).
    signal_to_nodes: dict[str, list[str]] = {}
    for group in groups:
        node_id = group["primary_host"]
        for tok in group.get("technologies") or []:
            signal = _map_surface_signal(tok)
            if signal:
                signal_to_nodes.setdefault(signal, []).append(node_id)
        protections = group.get("protections") or []
        if protections:
            # "cloudflare (WAF/CDN, whatweb, via HTTPServer, 100% certainty)" -> "cloudflare" -- the
            # leading name is the actual comparable signal, the parenthesized part is per-detection
            # provenance that would never match across two independent detections of the same WAF.
            waf_name = protections[0].split(" (", 1)[0].strip()
            if waf_name:
                signal_to_nodes.setdefault(f"waf:{waf_name}", []).append(node_id)
    # A shared TLS certificate (recon_result["tls_sans"], agent/core.py's _record_tls_cert_info,
    # ssl_cert_info's own subject_alt_names) is a STRONGER signal than a shared tech token -- a
    # wildcard/multi-domain cert presented by two different hostnames is real, first-party evidence
    # they're the same origin, not a coincidence two unrelated sites both run nginx. Keyed by
    # node_id_by_identity the same way dns edges resolve a raw host string, since ssl_cert_info's
    # own "target" argument can be a hostname the model already scanned under a different alias.
    for host, sans in (recon_result.get("tls_sans") or {}).items():
        node_id = node_id_by_identity.get(host, host)
        for san in sans:
            signal_to_nodes.setdefault(f"cert:{san}", []).append(node_id)
    for signal, signal_nodes in signal_to_nodes.items():
        distinct_nodes = sorted(set(signal_nodes))
        if len(distinct_nodes) < 2 or len(distinct_nodes) > _MAP_SHARED_SURFACE_MAX_FANOUT:
            continue
        if signal.startswith("waf:"):
            label = signal[4:]
        elif signal.startswith("cert:"):
            label = "cert: " + signal[5:]
        else:
            label = signal
        anchor, rest = distinct_nodes[0], distinct_nodes[1:]
        for other in rest:
            add_edge(anchor, other, "shared_surface", label)

    # attack_path, high-fidelity half: one edge per real pivot the agent explicitly proved via
    # record_host_relationship (session["agent_relationships"], agent/core.py's
    # _record_agent_relationship) -- a real mechanism label + evidence attached directly by the
    # model at the moment it proved the pivot, not reconstructed after the fact. Added BEFORE the
    # chain_attempts-derived pass below so add_edge's own dedup (same source/target/kind) prefers
    # this richer version whenever both exist for the same pair -- an explicit assertion beats a
    # guess reconstructed from free-text reasoning.
    for rel in session.get("agent_relationships") or []:
        source_node = node_id_by_identity.get(rel.get("source_host"), rel.get("source_host"))
        target_node = node_id_by_identity.get(rel.get("target_host"), rel.get("target_host"))
        if not source_node or not target_node:
            continue
        edge = add_edge(source_node, target_node, "attack_path", rel.get("mechanism") or "pivot", direction="forward")
        if edge is not None:
            edge["notes"] = rel.get("evidence") or ""
            edge["at"] = rel.get("recorded_at")

    # attack_path, reconstructed half: one edge per real pivot a Chain pass actually reasoned
    # through (session["chain_attempts"], agent/core.py's _persist_chain_attempt) -- the
    # finding_titles a chain attempt names are resolved to their own host the exact same way
    # findings resolve above,
    # then connected as a sequence (hop 1 -> hop 2 -> ...) since that's the real order the model's
    # own reasoning named them in. This is the closest thing this app has to Cobalt Strike's own
    # beacon-to-beacon pivot lines -- backed by the Chain tab's own real evidence/reasoning, never a
    # guessed connection, so it only ever appears once a chain pass genuinely tied two+ findings on
    # different hosts together (most sessions, and every chain pass that found nothing, contribute
    # none of these -- an honest gap, not a bug).
    for attempt in session.get("chain_attempts") or []:
        hop_nodes: list[str] = []
        for title in attempt.get("finding_titles") or []:
            node_id = finding_node_by_title.get(title)
            if node_id and (not hop_nodes or hop_nodes[-1] != node_id):
                hop_nodes.append(node_id)
        if len(set(hop_nodes)) < 2:
            continue
        reasoning = (attempt.get("reasoning") or "").strip()
        label = attempt.get("outcome") or "chain"
        note = reasoning[:200] + ("…" if len(reasoning) > 200 else "")
        for source, target in zip(hop_nodes, hop_nodes[1:]):
            edge = add_edge(source, target, "attack_path", label, direction="forward")
            if edge is not None:
                edge["notes"] = note
                edge["at"] = attempt.get("ran_at")

    # Manual (operator-authored) edges -- unlike auto edges above, these carry real free-text
    # metadata (what's actually flowing between the two nodes, how much, how often) because that's
    # exactly what a hand-drawn connection is FOR here: documenting a suspected pivot/beacon/data
    # flow before -- or instead of -- a tool ever proving it automatically. Validated at write time
    # (create_map_edge route below) that both ids exist and aren't the same node, so nothing here
    # needs to re-check that on every render.
    for manual_edge in map_manual.get("edges") or []:
        edges.append({
            "id": manual_edge["id"], "source": manual_edge["source"], "target": manual_edge["target"],
            "kind": "manual", "label": manual_edge.get("label") or manual_edge.get("data_type") or "",
            "direction": manual_edge.get("direction") or "forward", "manual": True,
            "data_type": manual_edge.get("data_type") or "", "volume": manual_edge.get("volume") or "",
            "format": manual_edge.get("format") or "", "interval": manual_edge.get("interval") or "",
            "notes": manual_edge.get("notes") or "",
        })

    # "Hide" (not delete) is the only removal a real, recon-derived node can ever get -- it's
    # re-derived fresh from recon_result/findings on every render, so there's no underlying record
    # to delete in the first place; hiding it from the map is a pure display preference, stored
    # server-side (not localStorage) so it survives across browsers the same way positions do.
    # Manual nodes/edges use real deletion instead (the create/edit/delete routes above) since they
    # ARE the underlying record.
    hidden_ids = set(map_manual.get("hidden_node_ids") or [])
    visible_nodes = [n for n in nodes if n["id"] not in hidden_ids]
    visible_node_ids = {n["id"] for n in visible_nodes}
    visible_edges = [e for e in edges if e["source"] in visible_node_ids and e["target"] in visible_node_ids]
    actually_hidden = hidden_ids & {n["id"] for n in nodes}
    return {"nodes": visible_nodes, "edges": visible_edges, "hidden_count": len(actually_hidden)}


templates.env.filters["build_attack_surface_graph"] = _build_attack_surface_graph


# Defensive cap on /program's own load_session() × N fan-out, same hardcoded-not-configurable
# precedent as agent/core.py's _STALL_REPEAT_THRESHOLD -- guards against the exact class of
# incident already hit once in this file (_mark_orphaned_sessions_interrupted, a 364MB session.json
# slowing every server-startup full-parse), not a per-engagement tunable an operator would ever
# want to raise.
_PROGRAM_MAX_SESSIONS = 50


def _aggregate_recon_for_sessions(sessions: list[dict]) -> dict:
    """Merges recon_result across every session sharing one target into a single synthetic dict
    shaped exactly like ONE session's own recon_result (same keys session_fragment.html reads at
    :937-950 -- targets/dns_map/os_guesses/technologies/protections/technology_certainty/
    technology_details/cves), so /program's Recon tab can feed it through the exact same
    group_recon_targets_by_host filter call a single session already uses, with no separate
    aggregation-aware rendering logic. Uses the real recon_result key names ("technologies"/
    "protections") -- _build_attack_surface_graph above used to read the wrong "*_by_host" ones
    (fixed there now too), unrelated to this function.

    List-shaped per-host fields (dns_map/technologies/protections) union without duplicates;
    dict-shaped per-host fields (technology_certainty/technology_details) shallow-merge per host,
    later session wins on a shared key -- acceptable for a read-only informational view of what is,
    in practice, the same real host scanned more than once.
    """
    targets: list[dict] = []
    dns_map: dict[str, list[str]] = {}
    os_guesses: dict[str, str] = {}
    technologies: dict[str, list[str]] = {}
    protections: dict[str, list[str]] = {}
    technology_certainty: dict[str, dict] = {}
    technology_details: dict[str, dict] = {}
    cves: set[str] = set()

    def _union_extend(bucket: dict[str, list], host: str, values) -> None:
        existing = bucket.setdefault(host, [])
        for value in values or []:
            if value not in existing:
                existing.append(value)

    for session in sessions:
        recon_result = session.get("recon_result") or {}
        targets.extend(recon_result.get("targets") or [])
        for host, ips in (recon_result.get("dns_map") or {}).items():
            _union_extend(dns_map, host, ips)
        os_guesses.update(recon_result.get("os_guesses") or {})
        for host, tokens in (recon_result.get("technologies") or {}).items():
            _union_extend(technologies, host, tokens)
        for host, labels in (recon_result.get("protections") or {}).items():
            _union_extend(protections, host, labels)
        for host, certainty in (recon_result.get("technology_certainty") or {}).items():
            technology_certainty.setdefault(host, {}).update(certainty or {})
        for host, details in (recon_result.get("technology_details") or {}).items():
            technology_details.setdefault(host, {}).update(details or {})
        cves.update(recon_result.get("cves") or [])

    return {
        "targets": targets, "dns_map": dns_map, "os_guesses": os_guesses,
        "technologies": technologies, "protections": protections,
        "technology_certainty": technology_certainty, "technology_details": technology_details,
        "cves": sorted(cves),
    }


def _aggregate_findings_for_sessions(sessions: list[dict]) -> list[dict]:
    """Concatenates session["findings"] across every session sharing one target, tagging each with
    where it came from (underscore-prefixed so these can never collide with a real field
    record_finding writes) -- /program's Findings tab links each row back to its origin session,
    same "external link to the finding" shape Piligrim's own Findings tab showed."""
    findings: list[dict] = []
    for session in sessions:
        for finding in session.get("findings") or []:
            findings.append({
                **finding,
                "_source_session_id": session.get("session_id"),
                "_source_session_name": session.get("name") or session.get("session_id"),
                "_source_session_created_at": session.get("created_at"),
            })
    return findings


def _build_site_map_tree(entries: list[dict], scope_entries: list[str] | None = None, candidate_urls: list[str] | None = None) -> dict:
    """Map tab's Site Map sub-view -- groups the SAME flat captured-traffic entries the Toolkit's
    own proxy-history table (partials/toolkit_traffic_list.html) already renders as a flat list
    into a real hierarchical tree, host then URL path segment (OWASP ZAP's own "Sites tree" shape)
    -- a different, aggregated view of the identical underlying data, not a second capture
    mechanism. Each leaf keeps its own entry id/method/status/passive-detector flags (the same
    ⚑-badge signal the flat list already shows, agent/tools/passive_detectors.py, computed once at
    capture time) so it can open the exact same #toolkit-traffic-detail dialog a flat-list row
    already does, from either view.

    Returns {"in_scope": [...], "other": [...]} instead of one flat, alphabetically-sorted list of
    every host -- real, confirmed operator complaint ("the tree is ugly/uncomfortable"), traced by
    actually opening a real 4.5-hour session's own Site Tree: the target's own real subdomains
    (dashboard./checkout./..., several of them) were buried alphabetically among dozens of
    incidental third-party hosts a browser tool call or a manual Toolkit visit pulls in along the
    way (fonts.gstatic.com, ad.doubleclick.net, i.clarity.ms, hackerone.com's own asset CDN, ...) --
    the tree wasn't badly STYLED (a previous pass already fixed that, see site_map_tree.html's own
    docstring), it had no signal/noise separation at all. `scope_entries` (the session's own target
    list, same comma-separated/wildcard shape `_matches_scope_entries` already handles for exploit
    authorization) splits hosts the exact same way the Attack Surface graph already implicitly does
    by only ever showing real recon targets -- in-scope hosts stay open and prominent, everything
    else collapses into its own "Other traffic" group instead of interleaving with the real target.
    `scope_entries=None` (or empty) means "no scope known yet" -- everything goes to "in_scope"
    rather than mislabeling real targets as noise before a target's even been set.

    `candidate_urls` -- real, confirmed operator complaint this fixes: passive-discovery tools
    (wayback_urls/common_crawl_urls, agent/tools/native.py) routinely surface hundreds of real
    historical URLs that were never actually requested through the proxy or the agent's own
    browser -- before this, those URLs existed nowhere but a truncated JSON blob inside one
    session["logs"] entry, invisible to this tree entirely, which read as "the map only shows
    what got clicked", not "the map shows what's known about this site". Each url here that isn't
    ALREADY a real captured entry's own url (`seen_urls`) becomes its own leaf via the exact same
    host/path walk as a real entry, just with confirmed=False and no id/method/status/flags -- it
    was found, not fetched. Every leaf (real or candidate) now carries "confirmed" so the template
    can tell the two apart; real leaves are unconditionally True, never omitted, so existing
    callers that only ever passed real entries keep getting confirmed=True on every leaf, unchanged.
    """
    hosts: dict[str, dict] = {}
    seen_urls: set[str] = set()

    def add_leaf(url: str | None, *, confirmed: bool, entry: dict | None = None) -> None:
        parts = urlsplit(url or "")
        host_node = hosts.setdefault(parts.netloc or "(unknown host)", {"name": parts.netloc or "(unknown host)", "children": {}, "leaves": []})
        node = host_node
        for segment in (s for s in parts.path.split("/") if s):
            node = node["children"].setdefault(segment, {"name": segment, "children": {}, "leaves": []})
        # A compact display name (OWASP ZAP's own Sites tree shows "GET:name", never the full URL,
        # for exactly this reason: the surrounding folders already spell out the path, repeating
        # it on every single leaf just adds noise). The final path segment, or "/" for the bare
        # host root; a query string is real, meaningful signal (two hits on the same path with
        # different parameters are two different things worth telling apart at a glance) so it's
        # appended rather than dropped, capped so one long querystring can't blow out the row.
        segments = [s for s in parts.path.split("/") if s]
        leaf_name = segments[-1] if segments else "/"
        if parts.query:
            query_display = parts.query if len(parts.query) <= 60 else parts.query[:57] + "..."
            leaf_name += "?" + query_display
        node["leaves"].append({
            "id": (entry or {}).get("id"),
            "method": (entry or {}).get("method"),
            "status": (entry or {}).get("response_status"),
            "flags": (entry or {}).get("flags") or [],
            "url": url,
            "name": leaf_name,
            "confirmed": confirmed,
        })

    for entry in entries:
        url = entry.get("url")
        if url:
            seen_urls.add(url)
        add_leaf(url, confirmed=True, entry=entry)

    for url in candidate_urls or []:
        if not url or url in seen_urls:
            continue  # already a real, confirmed leaf for this exact URL -- never show the same path twice
        seen_urls.add(url)
        add_leaf(url, confirmed=False)

    def finalize(node: dict) -> dict:
        return {
            "name": node["name"],
            "children": sorted((finalize(c) for c in node["children"].values()), key=lambda c: c["name"]),
            "leaves": node["leaves"],
        }

    finalized = sorted((finalize(h) for h in hosts.values()), key=lambda h: h["name"])
    if not scope_entries:
        return {"in_scope": finalized, "other": []}
    in_scope, other = [], []
    for host_node in finalized:
        (in_scope if _matches_scope_entries(host_node["name"], scope_entries) else other).append(host_node)
    return {"in_scope": in_scope, "other": other}


templates.env.filters["build_site_map_tree"] = _build_site_map_tree


# Curated set of vendored brand-logo SVGs (static/icons/tech/<key>.svg -- Simple Icons, CC0,
# downloaded once, same "no CDN calls at runtime" rule Tailwind/htmx already follow, see base.html)
# matched by keyword against a Recon tab technology/WAF label. Order matters: a more specific
# keyword (e.g. "tomcat") is checked before a broader one that would otherwise also match it
# (e.g. "apache") sits later, so a WhatWeb "Apache-Tomcat" token doesn't get mapped to the plain
# Apache-httpd logo.
_TECH_ICON_LOGO_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("cloudflare", ("cloudflare",)),
    ("akamai", ("akamai",)),
    ("f5", ("f5-big-ip", "big-ip", "bigip", "f5 ", "f5[")),
    ("fastly", ("fastly",)),
    ("tomcat", ("tomcat",)),
    ("nginx", ("nginx",)),
    ("apache", ("apache",)),
    ("wordpress", ("wordpress", "wp-", "wp_")),
    ("php", ("php",)),
    ("mysql", ("mysql",)),
    ("drupal", ("drupal",)),
    ("joomla", ("joomla",)),
    ("jquery", ("jquery",)),
    ("react", ("react",)),
    ("vuejs", ("vue.js", "vuejs", "vue-js")),
    ("angular", ("angular",)),
    ("bootstrap", ("bootstrap",)),
    ("nodejs", ("node.js", "nodejs", "node-js")),
    ("django", ("django",)),
    ("rubyonrails", ("ruby on rails", "rails")),
    ("python", ("python",)),
    ("docker", ("docker",)),
    ("kubernetes", ("kubernetes", "k8s")),
    ("redis", ("redis",)),
    ("mongodb", ("mongodb", "mongo")),
    ("postgresql", ("postgresql", "postgres")),
    ("laravel", ("laravel",)),
    ("symfony", ("symfony",)),
    ("openssl", ("openssl",)),
    ("cpanel", ("cpanel",)),
    ("googleanalytics", ("google analytics", "google-analytics", "ua-", "gtag")),
    ("googletagmanager", ("google tag manager", "gtm-")),
    ("letsencrypt", ("let's encrypt", "lets encrypt", "letsencrypt")),
    ("javascript", ("javascript",)),
]

# WAF/CDN vendors WhatWeb/nuclei can report that have no vendored logo above -- the SAME allowlist
# agent/core.py's _merge_protection_detection already uses to decide what counts as a WAF/CDN in
# the first place, reused here rather than a second, separately-curated guess that could disagree
# with it about what "is" a WAF.
_TECH_ICON_WAF_FALLBACK_NAMES = _WHATWEB_WAF_CDN_PLUGIN_NAMES | {"waf", "unidentified waf"}


def _tech_icon_meta(display_text: str) -> dict:
    """Classifies one Recon tab technology/Protection label into what icon to show: a real vendor
    logo (kind="logo", vendored under static/icons/tech/) for a recognized product, a shield glyph
    (kind="waf") for a known WAF/CDN vendor with no vendored logo, or a generic chip glyph
    (kind="generic") for anything else -- so an unrecognized token still reads as something instead
    of a blank gap, the same "always render SOMETHING" spirit as project_icon()'s own shield
    default (templates/macros/project_icons.html).

    Matched by substring against the WHOLE label, case-insensitive -- a technology can be its own
    WhatWeb plugin name ("WordPress") or buried inside a generic header's value
    ("HTTPServer[nginx/1.18]"), so the caller passes name+values joined, not the bare grouped name
    alone, or the second shape would never match.
    """
    haystack = display_text.lower()
    for key, keywords in _TECH_ICON_LOGO_KEYWORDS:
        if any(kw in haystack for kw in keywords):
            return {"kind": "logo", "key": key}
    if any(name in haystack for name in _TECH_ICON_WAF_FALLBACK_NAMES):
        return {"kind": "waf", "key": "waf-generic"}
    return {"kind": "generic", "key": "tech-generic"}


templates.env.filters["tech_icon_meta"] = _tech_icon_meta

_PINNED_REF_PATTERN = re.compile(r"^([FHR])(\d+)$")


def _resolve_pinned_refs(session: dict) -> list[dict]:
    """Agent-mode's collapsed-chat side panel (partials/session_side_panel.html) -- resolves
    session["pinned_refs"] (a list of the exact same F#/H#/R# ids chat_ref() already renders on
    every finding/hypothesis/recon-target card, agent/chat.py's _session_snapshot numbers them
    identically) back into the real object each one refers to, so the panel can show a short,
    live summary of whatever the operator pinned regardless of which tab is actually open.

    A stale ref (pinned before a rescan shrank the underlying list) is silently skipped, never a
    crash or a placeholder row -- the same "degrade quietly" choice recon_targets/os_guesses
    lookups elsewhere in this file already make for a similarly stale cross-reference.
    """
    refs = session.get("pinned_refs") or []
    findings = session.get("findings") or []
    hypotheses = session.get("hypotheses") or []
    recon_targets = session.get("recon_result", {}).get("targets") or []

    resolved: list[dict] = []
    for ref in refs:
        match = _PINNED_REF_PATTERN.match(ref)
        if not match:
            continue
        kind, index_str = match.groups()
        index = int(index_str) - 1

        if kind == "F" and 0 <= index < len(findings):
            f = findings[index]
            resolved.append({"ref": ref, "kind": "finding", "title": f.get("title") or "Untitled finding", "meta": f.get("severity")})
        elif kind == "H" and 0 <= index < len(hypotheses):
            h = hypotheses[index]
            resolved.append({"ref": ref, "kind": "hypothesis", "title": h.get("text") or "", "meta": h.get("status")})
        elif kind == "R" and 0 <= index < len(recon_targets):
            t = recon_targets[index]
            host_port = f"{t.get('host')}:{t.get('port')}" if t.get("port") is not None else (t.get("host") or "")
            resolved.append({"ref": ref, "kind": "recon", "title": host_port, "meta": t.get("service")})
    return resolved


templates.env.filters["resolve_pinned_refs"] = _resolve_pinned_refs
templates.env.filters["efficiency_score"] = compute_efficiency_score
templates.env.filters["llm_usage_summary"] = compute_llm_usage_summary
# A global, not a filter -- compute_provider_leaderboard takes no session argument (it's a
# cross-session aggregate over every project on disk, sessions.store.list_session_summaries()'s own
# cached index), so every Summary tab render calls it directly (provider_leaderboard()) rather than
# piping a value through it. Recomputed on every render (never cached at this layer) -- cheap
# because list_session_summaries() itself already is (see that function's own docstring); a session
# page re-rendered every few seconds during a live scan pays this same small cost every other
# summary-derived value on that page already pays.
templates.env.globals["provider_leaderboard"] = compute_provider_leaderboard


def _efficiency_needle_point(score: int) -> dict:
    """Pure presentation geometry for the Summary tab's efficiency gauge (a semicircle from -100
    at the left through 0 at the top to +100 at the right) — deliberately kept out of
    compute_efficiency_score (agent/core.py), which owns the SCORE formula, not pixel coordinates.
    Center (100, 100), radius 62 (short of the 80-radius arc track itself, so the needle tip sits
    inside it rather than overlapping). math.pi/cos/sin aren't available as Jinja filters by
    default, so this is computed here in Python and handed to the template as plain numbers.
    """
    t = (max(-100, min(100, score)) + 100) / 200
    theta = math.pi * (1 - t)
    return {"x": 100 + 62 * math.cos(theta), "y": 100 - 62 * math.sin(theta)}


templates.env.filters["efficiency_needle_point"] = _efficiency_needle_point


def _rescanned_as_summaries(session_id: str) -> list[dict]:
    """Forward half of the rescan link -- session_fragment.html's own backward "Rescan of X" line
    already reads session.rescanned_from_name (denormalized on the CHILD at rescan-creation time);
    this answers the other direction, "was a new project ever rescanned FROM this one" (main.py's
    own rescan_session route -- rescan-in-place never creates a new session_id, so it has no
    forward link of its own to show). Cheap: reads list_session_summaries()'s own cached index, not
    a full parse of every session.json on this project's page load.
    """
    return [s for s in list_session_summaries() if s.get("rescanned_from") == session_id]


def _render_fragment(request: Request, session: dict) -> str:
    return templates.env.get_template("partials/session_fragment.html").render(
        {
            "request": request,
            "session": _ensure_resumable_from(session),
            "rescanned_as": _rescanned_as_summaries(session["session_id"]),
        }
    )


def _render_backups_fragment(request: Request, session: dict) -> str:
    """Just the Backups widget (partials/project_backups.html) -- the backup/restore/delete
    routes' own hx-target is the small <details id="project-backups"> element (that partial's own
    root), never the whole session view, so this must stay scoped to it. Real, confirmed bug this
    fixes: those three routes used to hand back _render_fragment's WHOLE session_fragment.html (an
    entire second copy of Target/Status/the tab bar/everything) as if it were that one small
    widget's replacement -- hx-swap="outerHTML" doesn't care that the response is bigger than the
    target, it just drops the whole thing in, nesting a full duplicate #session-content one level
    inside what was supposed to stay a single <details>. Worse, that duplicate copy carries its own
    <details id="project-backups"> (same id, now duplicated in the DOM) -- so the NEXT backup
    action landed on one of the now-multiple matches and nested another full copy inside THAT one,
    compounding by one extra layer per click (visible live as Target/Status repeating once per
    Backup/Restore/Delete ever clicked in that tab)."""
    return templates.env.get_template("partials/project_backups.html").render(
        {"request": request, "session": session}
    )


def _chat_context(session: dict) -> dict:
    """Render context the chat panel's full-page render (session.html, via get_session_page) needs
    beyond the bare session dict — the ACTIVE thread (agent/chat.py's own _get_active_thread,
    migrating an old flat session["chat"] into chat_threads on first read if needed) plus the
    provider/model picker context (_provider_picker_context, the same one subagents.html's picker
    uses) and this session's own pre-fetched model choices. chat_turn's POST response and
    chat_stream's own SSE push don't need this — they only ever render chat_messages.html
    (_render_chat_messages below), which has no picker in it at all.
    """
    thread = _get_active_thread(session)
    provider = thread.get("provider")
    model_choices = _model_choices_with_fallback(provider, thread.get("model")) if provider and is_known_provider_id(provider) else []
    return {
        "session": session,
        "thread": thread,
        # Only actually rendered by chat_panel.html when show_chat_tabs is set (templates/chat.html's
        # own tab strip, partials/chat_thread_tabs.html) -- harmless, cheap extra context on every
        # OTHER page that includes chat_panel.html (a project's own sidebar chat) too, same "compute
        # it once here, let the template decide whether to use it" reasoning chat_model_choices below
        # already follows.
        "threads": list_chat_threads(session["session_id"]),
        "rescanned_as": _rescanned_as_summaries(session["session_id"]),
        **_provider_picker_context(),
        # Pre-fetched so the model <select> renders the right options (and the saved model
        # pre-selected) on first load, before the provider dropdown's own hx-get
        # (/api/subagents/model-options, shared with the subagent picker) ever fires — same
        # reasoning as subagent_model_choices in _subagent_context.
        "chat_model_choices": model_choices,
    }


def _render_chat_messages(request: Request, session: dict, flash: str | None = None) -> str:
    """Just the message log + pending indicator (partials/chat_messages.html) -- the SSE morph
    target inside chat_panel.html's own #chat-stream wrapper, and what chat_turn's own POST
    response returns too (same target/swap as the live push — see that route's own docstring). A
    live push or a message send must never touch the form/provider/model <select>s sitting
    alongside it (an in-progress typed draft or an open dropdown would otherwise get reset on
    every push), same "morph the target's children, never its siblings" discipline
    #session-stream already established for the main log. The chat panel's own full-page render
    (session.html, via get_session_page's _chat_context spread) needs no separate render helper
    here — it's a plain {% include %}, not a route response.

    flash: a one-off, never-persisted note for THIS one response only (e.g. compact_chat_thread_route's
    own "nothing to compact yet" — the manual /compact call that turned out to be a no-op still
    deserves honest feedback, not silence) — never written to session["chat_threads"] itself, so a
    later live SSE push naturally replaces it with the real, durable state.
    """
    thread = _get_active_thread(session)
    return templates.env.get_template("partials/chat_messages.html").render({"request": request, "session": session, "thread": thread, "flash": flash})


def _index_context(*, error: str | None = None, target: str = "", name: str = "") -> dict:
    return {"error": error, "target": target, "name": name}


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    recent_sessions = _load_all_sessions()[:5]
    return templates.TemplateResponse(
        request, "index.html", {**_index_context(), "recent_sessions": recent_sessions}
    )


async def _run_session_task(session_id: str, provider_id: str | None, entry_point: str = "recon") -> None:
    try:
        await run_session(session_id, provider_id=provider_id, entry_point=entry_point)
    except asyncio.CancelledError:
        # A graceful shutdown (Ctrl+C/SIGINT) — run_session() already logged this cleanly and
        # persisted status="interrupted" with a resume point before re-raising; swallow it here for
        # the same reason as the except Exception below, one clean log line instead of a raw,
        # unhandled traceback dumped by Starlette's background-task runner for an outcome that is
        # expected on shutdown, not a crash.
        pass
    except Exception:
        # run_session() already logged the traceback and persisted status="failed" before
        # re-raising (the CLI entrypoint needs that raise to surface a failure); swallow it here so
        # Starlette's background-task runner doesn't also dump a second, redundant "Exception in
        # ASGI application" trace for a failure that's already been handled and recorded.
        pass
    finally:
        session = load_session(session_id)
        logger.debug("api: background scan finished session_id=%s status=%s", session_id, session.get("status") if session else "unknown")


async def _run_re_triage_task(session_id: str, provider_id: str | None, is_resume: bool = False) -> None:
    """Same shape as _run_session_task above, for the Reverse Engineering mode's bounded
    baseline-triage run (agent/core.py's run_re_triage) instead of the recon/analyze/exploit/
    chain/validate loop -- start_session below branches to this one instead when
    session["mode"] == "reverse_engineering". is_resume passed straight through to run_re_triage
    -- see that function's own docstring (the /re-triage/resume and /re-triage/rescan routes below
    are this parameter's only two callers)."""
    try:
        await run_re_triage(session_id, provider_id=provider_id, is_resume=is_resume)
    except asyncio.CancelledError:
        pass
    except Exception:
        pass
    finally:
        session = load_session(session_id)
        logger.debug("api: background re_triage finished session_id=%s status=%s", session_id, session.get("status") if session else "unknown")


async def _run_re_reverify_task(session_id: str, finding_titles: list[str] | None, provider_id: str | None) -> None:
    """Same shape as _run_re_triage_task above, for the Reverse Engineering findings panel's own
    Re-verify (one finding) / Re-verify all (finding_titles=None) buttons -- agent/core.py's
    run_re_reverify."""
    try:
        await run_re_reverify(session_id, finding_titles=finding_titles, provider_id=provider_id)
    except asyncio.CancelledError:
        pass
    except Exception:
        pass
    finally:
        session = load_session(session_id)
        logger.debug("api: background re_reverify finished session_id=%s status=%s", session_id, session.get("status") if session else "unknown")


# A session sitting in one of these statuses right when the server starts can only mean its
# run_session() coroutine died with the previous process — nothing in the new process is running
# it. "interrupted" is distinct from "failed": the run itself never errored, the process holding
# it just stopped existing (e.g. a computer restart).
_ORPHANABLE_STATUSES = ("processing", "awaiting_approval")

# Both mean "run_session() isn't touching this session file right now, and there's real durable
# progress worth continuing from" — "interrupted" (the process itself died, orphaned at startup)
# and "failed" (run_session() caught a real exception, e.g. the LLM API going unreachable
# mid-scan — see agent/core.py's run_session) used to only offer resume for the former, leaving a
# scan that failed on a network blip with no way back except starting over from scratch.
_RESUMABLE_STATUSES = ("interrupted", "failed")


def _ensure_resumable_from(session: dict) -> dict:
    """A session that failed/was interrupted before this resumable_from-on-failure behavior existed
    (agent/core.py's run_session) has no resumable_from stored — computed here at render time
    instead of leaving the Resume UI with nothing to show, same rule, just applied lazily. Returns
    a shallow copy rather than mutating the caller's dict; the real, persisted value is still only
    ever written by run_session/_mark_orphaned_sessions_interrupted, never by a GET request."""
    if session.get("status") in _RESUMABLE_STATUSES and not session.get("resumable_from"):
        return {**session, "resumable_from": compute_resume_entry_point(session)}
    return session


def _mark_orphaned_sessions_interrupted() -> None:
    # Real incident this fixes: this used to json.load() EVERY session file, unconditionally,
    # before even checking status -- on a real Documents/ASRA Projects tree with one session that
    # had grown to 364 MB (a since-fixed logging bug, see agent/core.py's _describe_command), that
    # alone made server startup itself "долговато" (noticeably slow) before the app could serve a
    # single request. list_session_summaries() answers "which sessions are even orphanable" from
    # the cheap summary cache; only the (normally tiny) subset actually in _ORPHANABLE_STATUSES
    # pays for a real load_session() full parse.
    for summary in list_session_summaries():
        if summary["status"] not in _ORPHANABLE_STATUSES:
            continue
        session_id = summary["session_id"]
        data = load_session(session_id)
        if data is None:
            continue
        # A background job (e.g. a Hydra brute-force run) this session started can outlive the
        # process that started it -- its real OS process is not guaranteed to die just because its
        # parent did. Reconciled here, in the same sweep, so an orphaned job never keeps running
        # against a real target completely untracked just because nobody's process died with it.
        reconcile_orphaned_background_jobs(session_id, data)
        # A delegated Subagent's own asyncio.Task cannot survive the process that spawned it
        # (unlike a background job's real OS subprocess, it simply ceases to exist) -- nothing to
        # kill here, just an honest status correction so a stale "running" entry never lingers.
        reconcile_orphaned_subagent_tasks(session_id, data)
        data["status"] = "interrupted"
        data["resumable_from"] = compute_resume_entry_point(data)
        try:
            save_session(session_id, data)
        except OSError as exc:
            # Real incident this fixes: one session's file was persistently locked (something else
            # had it open, outlasting save_session's own bounded retry) and the resulting
            # PermissionError propagated all the way up through this startup handler, crashing the
            # ENTIRE app before it could even serve a single request -- every other session's
            # startup recovery, and the app itself, must never depend on one uncooperative file.
            # Left exactly as it was on disk; this same sweep retries it again next startup.
            logger.debug(
                "api: could not mark orphaned session interrupted session_id=%s (%s) -- left as-is, will retry next startup",
                session_id, exc,
            )
            continue
        logger.debug(
            "api: marked orphaned session interrupted session_id=%s resumable_from=%s",
            session_id, data["resumable_from"],
        )


def _reconcile_orphaned_chat_threads_sweep() -> None:
    """A chat turn's own run_chat_turn_background coroutine cannot survive the process that was
    running it -- same reasoning _mark_orphaned_sessions_interrupted's own background-job/subagent-
    task reconciliation above already applies, just for a third kind of in-memory-only state a
    chat thread's pending=True flag represents (agent/chat.py's reconcile_orphaned_chat_threads).
    Kept as its own sweep rather than folded into that loop: a stuck chat thread can exist on a
    session in ANY status (interactive, completed, interrupted, ...), not just _ORPHANABLE_STATUSES,
    so it needs list_session_summaries()'s own separate has_pending_chat field (sessions/store.py's
    _build_summary) to stay cheap at scale instead of a full load_session() per session.
    """
    for summary in list_session_summaries():
        if not summary.get("has_pending_chat"):
            continue
        session_id = summary["session_id"]
        data = load_session(session_id)
        if data is None:
            continue
        reconcile_orphaned_chat_threads(session_id, data)
        try:
            save_session(session_id, data)
        except OSError as exc:
            # Same "never let one uncooperative file crash startup, just retry next time" reasoning
            # as _mark_orphaned_sessions_interrupted's own identical guard.
            logger.debug(
                "api: could not reconcile orphaned chat thread(s) session_id=%s (%s) -- left as-is, will retry next startup",
                session_id, exc,
            )


def _startup_progress(step: str) -> None:
    """One console progress line at server boot -- cyan [ASRA] tag, flushed immediately so each step
    shows the moment it happens (uvicorn's own INFO lines interleave around these). Complements the
    "Loading modules..." notice run.sh prints before the interpreter even reaches this file."""
    import sys
    sys.stderr.write(f"\033[36m[ASRA]\033[0m {step}\n")
    sys.stderr.flush()


_PROGRAM_URL_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,62}[a-zA-Z0-9])?)+$")


def _clean_program_url(raw: str) -> str:
    """Shared by start_scan and update_program_url below -- program_url (session["program_url"])
    is a plain informational link, not a scope entry, so it doesn't go through
    validate_scope_entry the way Target(s)/out_of_scope do; it only needs to be a plausible
    http(s) URL. An invalid value is dropped (returns "") rather than failing the whole form,
    the same tolerance already given to out_of_scope free text above.

    urlsplit's own .hostname alone isn't a real validity check -- it happily returns a garbage
    string like "not a url at all!!" as the "hostname" for "https://not a url at all!!" (confirmed
    live: urlsplit never raises and never validates characters). _PROGRAM_URL_HOSTNAME_RE requires
    a real dot-separated DNS-label shape (also matches a bare IPv4 host, digits being valid label
    characters too) so free-text pasted into this field by mistake is actually rejected.
    """
    candidate = (raw or "").strip()
    if not candidate:
        return ""
    normalized = _normalize_url(candidate)
    parts = urlsplit(normalized)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname or not _PROGRAM_URL_HOSTNAME_RE.match(parts.hostname):
        logger.debug("start_scan: program_url %r doesn't look like a valid http(s) URL, dropped", raw)
        return ""
    return normalized


def _resolve_time_budget_seconds(time_budget_preset: str, time_budget_custom_minutes: str) -> int | None:
    """Shared by start_scan/rescan_session/rescan_session_in_place -- all three offer the identical
    Time budget field (New Project form / the rescan dialog's own copy of it) and must resolve it
    the exact same way, not three independently-maintained copies of this logic. "" (No limit) ->
    None, a fixed preset -> that many seconds directly, "custom" -> whatever the operator typed in
    minutes. A malformed/empty custom value with preset="custom" selected tolerates down to "no
    budget" rather than failing the whole form submission over one bad sub-field.
    """
    if time_budget_preset == "custom":
        try:
            custom_minutes = float(time_budget_custom_minutes)
            if custom_minutes > 0:
                return int(custom_minutes * 60)
        except ValueError:
            pass
        return None
    if time_budget_preset:
        try:
            return int(time_budget_preset)
        except ValueError:
            pass
    return None


def _resolve_enabled_subagent_ids(submitted_ids: list[str]) -> list[str] | None:
    """Shared by start_scan/start_interactive/start_re -- all three offer the identical New
    Project form Subagents checklist (partials/new_project_form.html) and must resolve it the
    same way. Every checkbox defaults to CHECKED (every currently globally-enabled profile), so
    leaving them all checked resolves to None (no restriction at all — sessions/store.py's
    create_session docstring), keeping the project's own access list "live" against whatever gets
    enabled globally later, rather than a frozen snapshot. Only an actual narrowing (at least one
    currently-enabled profile left unchecked) resolves to a real, explicit list, which can be
    empty (every box unchecked). Filtered against get_enabled_profiles() rather than trusted as-is
    so a stale form render (a profile deleted/disabled between page load and submit) can never
    smuggle a dead id into the stored list.
    """
    all_enabled_ids = {p["id"] for p in get_enabled_profiles()}
    selected_ids = set(submitted_ids) & all_enabled_ids
    return None if selected_ids == all_enabled_ids else sorted(selected_ids)


_IDENTITY_FIELD_NAMES = ("username", "email", "password", "login_url", "cookie", "authorization_header")


def _parse_extra_identities(form) -> dict[str, dict]:
    """Reads the New Project form's dynamically-added "+ Add another account" identity cards
    (templates/partials/new_project_form.html) out of the raw multipart form body -- these have no
    fixed Form(...) params (unlike user_a/user_b) since there's no hardcoded cap on how many an
    operator can add, each named identity_extra_<n>_<field> by the page's own cloning script.
    Returns {"identity_extra_<n>": {field: value, ...}, ...}, one entry per distinct index actually
    present in the submission — a card added then removed client-side before submit simply isn't
    in the form body at all, so nothing here needs to filter those back out.
    """
    indices: set[str] = set()
    prefix = "identity_extra_"
    for key in form.keys():
        if not key.startswith(prefix):
            continue
        rest = key[len(prefix):]
        index, _, field = rest.partition("_")
        if index.isdigit() and field in _IDENTITY_FIELD_NAMES:
            indices.add(index)
    # password is deliberately NOT stripped, matching user_a/user_b's own handling just below --
    # every other field is (a pasted cookie/header/URL/login commonly picks up incidental
    # leading/trailing whitespace that should be dropped, a password's own whitespace is real).
    return {
        f"identity_extra_{index}": {
            field: str(form.get(f"{prefix}{index}_{field}", "")) if field == "password"
            else str(form.get(f"{prefix}{index}_{field}", "")).strip()
            for field in _IDENTITY_FIELD_NAMES
        }
        for index in indices
    }


@app.post("/api/scan")
async def start_scan(
    request: Request,
    name: str = Form(""),
    target: str = Form(""),
    llm_provider: str | None = Form(None),
    authorize_exploit: str | None = Form(None),
    enumerate_subdomains: str | None = Form(None),
    time_budget_preset: str = Form(""),
    time_budget_custom_minutes: str = Form(""),
    goal: str = Form(""),
    qualifying_vulnerabilities: str = Form(""),
    non_qualifying_vulnerabilities: str = Form(""),
    initial_hypotheses: str = Form(""),
    custom_instructions: str = Form(""),
    out_of_scope: str = Form(""),
    program_url: str = Form(""),
    custom_user_agent: str = Form(""),
    custom_headers: str = Form(""),
    user_a_username: str = Form(""),
    user_a_email: str = Form(""),
    user_a_password: str = Form(""),
    user_a_login_url: str = Form(""),
    user_a_cookie: str = Form(""),
    user_a_authorization_header: str = Form(""),
    user_b_username: str = Form(""),
    user_b_email: str = Form(""),
    user_b_password: str = Form(""),
    user_b_login_url: str = Form(""),
    user_b_cookie: str = Form(""),
    user_b_authorization_header: str = Form(""),
    icon: str = Form(""),
    icon_color: str = Form(""),
    enabled_subagent_ids: list[str] = Form([]),
) -> Response:
    def _error(message: str, status_code: int = 400) -> Response:
        # An htmx submission (the New Project dialog, base.html) targets/swaps just the form's own
        # container (partials/new_project_form.html's hx-target/hx-swap) -- rendering the FULL
        # index.html page here would dump the whole page's markup into that one swap target.
        # Real bug this fixes: before the form carried hx-post at all, a validation error here
        # navigated the entire tab to a bare /api/scan page instead of redisplaying in the still-
        # open dialog -- the dialog closing and the SAME form reappearing inline on a fresh
        # index.html looked like a duplicate dialog, not an error message. A plain/no-JS submit
        # (this route's own real <form method="post" action> fallback) still gets the full page,
        # matching what a real page navigation actually requires.
        # Carry the chosen icon + color back so a validation error doesn't wipe the operator's own
        # icon/color pick (new_project_form.html passes them into icon_picker()).
        _icon_ctx = {"icon": icon, "icon_color": icon_color}
        if request.headers.get("hx-request") == "true":
            html = templates.env.get_template("partials/new_project_form.html").render(
                {"request": request, **_index_context(error=message, target=target, name=name), **_icon_ctx}
            )
            # 200, not status_code (400) -- htmx (1.9.x default responseHandling) only swaps
            # 2xx/3xx responses; a real 4xx here would fire htmx:responseError and never actually
            # show this error fragment. The error is communicated through the rendered HTML itself
            # (the same red banner this partial already renders for the no-JS path), not the
            # status code -- a real, non-htmx client (this route's own plain-form fallback, or an
            # API caller) still gets the honest 400 below.
            return HTMLResponse(html, status_code=200)
        return templates.TemplateResponse(
            request, "index.html", {**_index_context(error=message, target=target, name=name), **_icon_ctx}, status_code=status_code
        )

    clean_name = name.strip()
    if not clean_name:
        return _error("Project name is required.")
    if name_exists(clean_name):
        return _error(f"A project named {clean_name!r} already exists — pick a different name.")

    # A scope, not just one host: comma-separated URL/domain/host/IPv4/IPv6/"*.domain" entries,
    # each validated on its own (validate_scope_entry()'s shape check doesn't allow commas/spaces,
    # so it has to run per-entry, not on the raw joined string). "*.example.com" is accepted here
    # specifically — bug-bounty scope tables commonly write scope that way — but the marker never
    # reaches a real tool call as-is; it only steers the recon prompt and allowlist matching.
    #
    # Each raw entry is expanded BEFORE validation, not instead of it: a bug-bounty program that
    # owns one domain under many ccTLDs commonly writes its whole scope as one line, e.g.
    # "https://www.vidaxl.(at|be|bg|com|de|...)" -- expand_target_alternation() turns that into one
    # concrete candidate per alternative, each of which still has to pass validate_scope_entry()
    # like any other entry. A plain entry with no "(a|b)" group expands to itself unchanged.
    raw_targets = [t.strip() for t in target.split(",") if t.strip()]
    if not raw_targets:
        return _error("At least one target is required.")
    try:
        clean_targets = [
            validate_scope_entry(expanded)
            for raw in raw_targets
            for expanded in expand_target_alternation(raw)
        ]
    except ValueError as exc:
        return _error(str(exc))
    clean_target = ", ".join(clean_targets)

    # Same shape as the Target(s) scope above (comma-separated, "*.domain" wildcard allowed) but
    # the exclusion direction — optional, so an empty field is not an error, unlike Target(s).
    # Real scope tables also commonly write a qualifying phrase here instead of (or alongside) a
    # concrete host, e.g. "All domains or subdomains not listed in the above list of Scopes" —
    # that can't be shape-validated as a host/URL, so it's routed to out_of_scope_notes (plain
    # text shown to the model, sessions/store.py's create_session) instead of rejecting the whole
    # form the way a hard validation error would.
    raw_out_of_scope = [t.strip() for t in out_of_scope.split(",") if t.strip()]
    clean_out_of_scope: list[str] = []
    out_of_scope_notes: list[str] = []
    for entry in raw_out_of_scope:
        try:
            expanded_entries = expand_target_alternation(entry)
        except ValueError:
            # Too many combinations to expand safely -- same fallback as an entry that never
            # parsed as a host at all: shown to the model as a plain-language note instead of
            # silently dropped.
            out_of_scope_notes.append(entry)
            continue
        for expanded in expanded_entries:
            try:
                clean_out_of_scope.append(validate_scope_entry(expanded))
            except ValueError:
                out_of_scope_notes.append(expanded)

    # One suspicion per line, not comma-separated like target/out_of_scope above -- a hypothesis is
    # free-form prose ("staging.example.com probably still has debug mode on") that could easily
    # contain a comma of its own. Capped at a sane count (not enforced as a hard validation error --
    # an operator pasting a slightly-too-long list shouldn't lose the whole form submission over it,
    # same "don't fail the whole call over one bad sub-field" tolerance this project applies
    # elsewhere) so a pathological paste can't seed hundreds of hypotheses the end-of-session gate
    # would then have to work through.
    _MAX_INITIAL_HYPOTHESES = 20
    clean_initial_hypotheses = [line.strip() for line in initial_hypotheses.splitlines() if line.strip()][:_MAX_INITIAL_HYPOTHESES]

    resolved_provider = llm_provider if llm_provider in PROVIDER_REGISTRY else None

    resolved_subagent_ids = _resolve_enabled_subagent_ids(enabled_subagent_ids)

    resolved_time_budget_seconds = _resolve_time_budget_seconds(time_budget_preset, time_budget_custom_minutes)
    clean_program_url = _clean_program_url(program_url)
    extra_identities = _parse_extra_identities(await request.form())
    extra_identities_configured = sum(
        1 for creds in extra_identities.values() if creds.get("username") or creds.get("email")
    )

    # Still a deliberate, explicit, off-by-default opt-in (unchecked unless the user ticks it
    # here) — the New Project form just moved where that opt-in lives, it didn't remove it.
    # Recon/scan tools remain unaffected either way; this only ever gates real exploitation
    # (Metasploit/sqlmap), enforced in agent/tools/runner.py regardless of where the target
    # entered the allowlist from. Every target in the scope gets authorized, not just the first.
    if authorize_exploit:
        authorize_exploit_targets(clean_targets, bool(enumerate_subdomains))

    session_id = create_session(
        clean_target,
        name=clean_name,
        enumerate_subdomains=bool(enumerate_subdomains),
        qualifying_vulnerabilities=qualifying_vulnerabilities,
        non_qualifying_vulnerabilities=non_qualifying_vulnerabilities,
        initial_hypotheses=clean_initial_hypotheses,
        custom_instructions=custom_instructions,
        goal=goal,
        custom_user_agent=custom_user_agent,
        custom_headers=custom_headers,
        out_of_scope=clean_out_of_scope,
        out_of_scope_notes=out_of_scope_notes,
        program_url=clean_program_url,
        # Recorded now (previously only the allowlist side effect existed, with no record of
        # intent on the session itself) so main.py's rescan route can later tell "this project was
        # authorized for exploitation" from "it wasn't" and correctly replay (or not replay) the
        # widening above for a new session covering the same target(s).
        authorize_exploit=bool(authorize_exploit),
        llm_provider=resolved_provider,
        # The New Project form's "Create" button only creates the project -- Overview tab's own
        # "Start" button (POST /api/session/{id}/start) is what actually schedules the scan, so a
        # freshly created session must not look "live" (session_fragment.html's own
        # `session.status in (..., "pending")` checks) before that click ever happens.
        initial_status="created",
        identity_a_configured=bool(user_a_username.strip() or user_a_email.strip()),
        identity_b_configured=bool(user_b_username.strip() or user_b_email.strip()),
        extra_identities_configured=extra_identities_configured,
        time_budget_seconds=resolved_time_budget_seconds,
        icon=icon.strip(),
        icon_color=icon_color.strip(),
        enabled_subagent_ids=resolved_subagent_ids,
    )

    # Optional, per-project — the authenticated_request tool's IDOR/access-control testing (see
    # agent/tools/native.py). Stored separately from the session on purpose: never rendered back
    # in this UI, never in Export Proof, never passed as raw text into an LLM prompt. Username and
    # email are separate fields (not one ambiguous "username or email" box) because
    # _get_authenticated_client submits whichever are actually filled in — some login forms key
    # off a username/handle, others specifically require an email address, and a real account can
    # have both without them being the same value.
    save_identity_credentials(
        session_id,
        {
            "user_a": {
                "username": user_a_username.strip(), "email": user_a_email.strip(), "password": user_a_password,
                "login_url": user_a_login_url.strip(), "cookie": user_a_cookie.strip(),
                "authorization_header": user_a_authorization_header.strip(),
            },
            "user_b": {
                "username": user_b_username.strip(), "email": user_b_email.strip(), "password": user_b_password,
                "login_url": user_b_login_url.strip(), "cookie": user_b_cookie.strip(),
                "authorization_header": user_b_authorization_header.strip(),
            },
            # "+ Add another account" cards (new_project_form.html) beyond the fixed user_a/user_b
            # pair -- save_identity_credentials already drops any entry with every field blank, so
            # a card added then left empty is a no-op here exactly like an empty user_a/user_b.
            **extra_identities,
        },
    )

    logger.debug(
        "api: POST /api/scan name=%s target=%s session_id=%s llm_provider=%s authorize_exploit=%s "
        "enumerate_subdomains=%s scope_rules_set=%s custom_instructions_set=%s goal_set=%s custom_user_agent_set=%s "
        "custom_headers_set=%s out_of_scope=%s out_of_scope_notes=%s program_url=%r extra_identities_configured=%s",
        clean_name, clean_target, session_id, resolved_provider, bool(authorize_exploit), bool(enumerate_subdomains),
        bool(qualifying_vulnerabilities.strip() or non_qualifying_vulnerabilities.strip()),
        bool(custom_instructions.strip()), bool(goal.strip()), bool(custom_user_agent.strip()), bool(custom_headers.strip()),
        clean_out_of_scope, out_of_scope_notes, clean_program_url, extra_identities_configured,
    )
    # Deliberately no background_tasks.add_task here anymore -- "Create" only creates the project
    # (status="created" above); the scan itself only starts once the operator clicks "Start" on
    # the new session's own Overview tab (POST /api/session/{id}/start below).
    if request.headers.get("hx-request") == "true":
        # htmx never auto-navigates on a plain 3xx the way a real <form> submit does -- HX-Redirect
        # is the header it specifically watches for to trigger a real client-side navigation
        # (window.location), which is what "just-created project, go look at it" actually needs
        # (a real URL change, not an XHR response swapped into the dialog).
        return Response(status_code=200, headers={"HX-Redirect": f"/session/{session_id}"})
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/scan/interactive")
def start_interactive(
    request: Request, name: str = Form(""), icon: str = Form(""), icon_color: str = Form(""),
    enabled_subagent_ids: list[str] = Form([]),
) -> Response:
    """The New Project form's "Interactive mode" tab (partials/new_project_form.html) -- a
    deliberately minimal counterpart to start_scan above: just a project name, no target/scope/
    options up front. Creates a chat-only console session (session["mode"]="interactive") the
    operator drives entirely from the full-window chat on the session page (session.html's own
    interactive branch); the target and the task are named in the chat, not here, and no autonomous
    scan is ever scheduled. Exploitation is authorized wholesale for the session at run time
    (agent/chat.py's run_chat_turn_background), so nothing about scope/exploit needs collecting on
    this form."""
    def _error(message: str, status_code: int = 400) -> Response:
        # Same htmx-vs-plain split as start_scan's own _error, but re-renders with the Interactive
        # tab kept active so the error shows where the operator actually was (active_tab, read by
        # new_project_form.html's tab radios).
        _icon_ctx = {"icon": icon, "icon_color": icon_color}
        if request.headers.get("hx-request") == "true":
            html = templates.env.get_template("partials/new_project_form.html").render(
                {"request": request, **_index_context(error=message, name=name), "active_tab": "interactive", **_icon_ctx}
            )
            return HTMLResponse(html, status_code=200)
        return templates.TemplateResponse(
            request, "index.html", {**_index_context(error=message, name=name), "active_tab": "interactive", **_icon_ctx}, status_code=status_code
        )

    clean_name = name.strip()
    if not clean_name:
        return _error("Project name is required.")
    if name_exists(clean_name):
        return _error(f"A project named {clean_name!r} already exists — pick a different name.")

    session_id = create_session(
        "",  # No target up front -- the operator names it in the chat (INTERACTIVE_CHAT_PROMPT).
        name=clean_name,
        mode="interactive",
        # Its own status, distinct from the pipeline's created/pending/processing/... -- a chat-only
        # console never runs a scan, so it must never render Start/Resume-scan controls or count as
        # an "active" (scanning) session. status_badge just prints it; nothing offers scan actions
        # for it (session_fragment.html isn't even rendered for this mode, session.html's branch).
        initial_status="interactive",
        # Semantic record that exploitation is authorized for this session (the real enforcement is
        # the run-time context switch in agent/chat.py, not this flag) -- kept true for consistency
        # with what the mode actually allows.
        authorize_exploit=True,
        icon=icon.strip(),
        icon_color=icon_color.strip(),
        enabled_subagent_ids=_resolve_enabled_subagent_ids(enabled_subagent_ids),
    )
    logger.debug("api: POST /api/scan/interactive name=%s session_id=%s", clean_name, session_id)
    if request.headers.get("hx-request") == "true":
        return Response(status_code=200, headers={"HX-Redirect": f"/session/{session_id}"})
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/re-target/check")
async def check_re_target_route(target: str = Form("")) -> JSONResponse:
    """The New Project form's Reverse Engineering panel — live status-dot check for the target
    field, called on every debounced keystroke (agent/tools/builders/re_target.py's own
    check_re_target does the real work: local path existence, or a git ls-remote probe for a
    GitHub/GitLab URL). Read-only, never mutates a session or clones/extracts anything — see
    start_re below for the one-time real staging step at actual submission."""
    result = check_re_target(target)
    return JSONResponse(result)


_RE_EXPERIENCE_LEVELS = ("novice", "hobbyist", "professional")


@app.post("/api/scan/re")
def start_re(
    request: Request,
    name: str = Form(""),
    target: str = Form(""),
    goal: str = Form(""),
    custom_instructions: str = Form(""),
    qualifying_vulnerabilities: str = Form(""),
    non_qualifying_vulnerabilities: str = Form(""),
    re_experience_level: str = Form("hobbyist"),
    icon: str = Form(""),
    icon_color: str = Form(""),
    enabled_subagent_ids: list[str] = Form([]),
) -> Response:
    """The New Project form's "Reverse Engineering" tab -- modeled directly on start_interactive
    above (its own minimal Form field set, no validate_scope_entry/validate_target call: that
    regex is host/URL-shaped and doesn't apply to a local file/folder/archive path or a git repo
    URL, which is what this mode's target actually is). Unlike Interactive mode, the target IS
    collected up front here (see RE_TRIAGE_PROMPT, agent/core.py's run_re_triage) -- the operator
    already has it staged wherever convenient on their own machine, or names a public repo URL to
    be cloned into this project's own folder. qualifying_vulnerabilities/non_qualifying_vulnerabilities
    reuse the exact same session["scope_rules"] storage and agent/core.py's own
    _scope_rules_task_addendum Agent mode already has -- RE-scoped vulnerability classes here
    instead of web CWEs, but the plumbing underneath is identical, no new schema needed."""
    def _error(message: str, status_code: int = 400) -> Response:
        # custom_instructions/qualifying/non_qualifying have no home in _index_context (an
        # Agent-mode-shaped helper, no RE fields at all) -- passed as their own extra context keys
        # instead of widening that shared helper for one mode's own fields. Real incident this
        # fixes: a validation error (e.g. a bad target path) used to silently wipe whatever the
        # operator had already typed into these fields, since the re-rendered form's context never
        # carried them back.
        _re_ctx = {
            "icon": icon, "icon_color": icon_color, "custom_instructions": custom_instructions,
            "qualifying_vulnerabilities": qualifying_vulnerabilities, "non_qualifying_vulnerabilities": non_qualifying_vulnerabilities,
            "goal": goal, "re_experience_level": re_experience_level if re_experience_level in _RE_EXPERIENCE_LEVELS else "hobbyist",
        }
        if request.headers.get("hx-request") == "true":
            html = templates.env.get_template("partials/new_project_form.html").render(
                {"request": request, **_index_context(error=message, name=name, target=target), "active_tab": "reverse_engineering", **_re_ctx}
            )
            return HTMLResponse(html, status_code=200)
        return templates.TemplateResponse(
            request, "index.html", {**_index_context(error=message, name=name, target=target), "active_tab": "reverse_engineering", **_re_ctx}, status_code=status_code
        )

    clean_name = name.strip()
    if not clean_name:
        return _error("Project name is required.")
    if name_exists(clean_name):
        return _error(f"A project named {clean_name!r} already exists — pick a different name.")

    clean_target = target.strip()
    if not clean_target:
        return _error("Target is required — a local file/folder path, or a public GitHub/GitLab repo URL.")
    check_result = check_re_target(clean_target)
    if not check_result["ok"]:
        return _error(check_result["message"])

    session_id = create_session(
        clean_target,  # Replaced below with the real staged/resolved path once the project folder exists.
        name=clean_name,
        mode="reverse_engineering",
        goal=goal.strip(),
        custom_instructions=custom_instructions.strip(),
        qualifying_vulnerabilities=qualifying_vulnerabilities.strip(),
        non_qualifying_vulnerabilities=non_qualifying_vulnerabilities.strip(),
        re_experience_level=re_experience_level if re_experience_level in _RE_EXPERIENCE_LEVELS else "hobbyist",
        initial_status="created",
        authorize_exploit=True,
        icon=icon.strip(),
        icon_color=icon_color.strip(),
        enabled_subagent_ids=_resolve_enabled_subagent_ids(enabled_subagent_ids),
    )

    project_folder = get_session_folder(session_id)
    try:
        resolved_target = clone_or_stage_re_target(clean_target, Path(project_folder))
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        # Passed the live-check above but failed at the real, one-time staging step (e.g. the repo
        # went private/was deleted between the check and this submission, or a corrupt archive) --
        # the session already exists at this point, so surface this as a real error on it rather
        # than silently leaving session["target"] as the unresolved raw string.
        logger.debug("api: POST /api/scan/re session_id=%s staging failed for %r (%s)", session_id, clean_target, exc)
        delete_session(session_id)
        return _error(f"Could not prepare the target: {exc}")

    session = load_session(session_id)
    session["target"] = str(resolved_target)
    save_session(session_id, session)

    logger.debug("api: POST /api/scan/re name=%s target=%s -> %s session_id=%s", clean_name, clean_target, resolved_target, session_id)
    if request.headers.get("hx-request") == "true":
        return Response(status_code=200, headers={"HX-Redirect": f"/session/{session_id}"})
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


# Field set both wizard routes below pre-fill on partials/new_project_form.html -- kept as one
# tuple so the two routes and their shared render helper can't silently drift out of sync with
# each other (e.g. one route learning a new field the other's context dict forgets to default).
_WIZARD_FORM_FIELDS = (
    "name", "target", "out_of_scope", "qualifying_vulnerabilities",
    "non_qualifying_vulnerabilities", "custom_instructions", "goal", "custom_user_agent", "custom_headers",
)


def _wizard_form_response(
    request: Request, url: str, result: dict, active_tab: str = "agent", is_program_page: bool = False,
) -> HTMLResponse:
    """Shared render for both New Project wizard routes below -- turns agent/tools/
    bugbounty_import.py's own {"status": "ok"/"error", ...} result into
    partials/new_project_form.html's own prefill context and re-renders just that partial (not the
    full index.html page) so it can hx-swap the dialog's #new-project-form-container in place.

    Always 200 (FastAPI's default, never overridden here) even on a "soft" failure (bad URL, page
    wouldn't render, no LLM provider) -- these routes are hx-post targets, and htmx only swaps a
    response's content on a 2xx status by default; a 4xx here would leave the operator's own dialog
    frozen on its old (pre-click) content with no visible explanation of what went wrong, instead of
    showing the real error message this function put into the re-rendered form.

    The operator's own typed url is always preserved (wizard_url) so a failed lookup doesn't also
    discard what they just pasted. A failed analyze_bugbounty_program call can still carry partial,
    genuinely-extracted fields alongside its own error (e.g. it found the program's rules but no
    concrete in-scope host) -- shown rather than thrown away, the same "never discard real partial
    work" discipline this app already applies elsewhere (agent/chat.py's own module docstring).
    """
    context = {field: "" for field in _WIZARD_FORM_FIELDS}
    context["wizard_url"] = url
    context["error"] = None
    # Which wizard panel to land back on -- "agent" (the default, both existing Agent-mode wizard
    # routes below) or "reverse_engineering" (analyze_re_program's own route). Every field name in
    # _WIZARD_FORM_FIELDS already happens to be exactly what the RE panel's own qualifying/
    # non-qualifying/target/custom_instructions fields use too, so no separate field tuple was
    # needed for this -- just a different tab to re-render onto.
    context["active_tab"] = active_tab
    # Not one of _WIZARD_FORM_FIELDS above -- ua_snippet has no name= of its own on the real
    # /api/scan form at all (see new_project_form.html's own "Merge into my browser's UA" comment),
    # it only ever prefills that one client-side-only input's value=. Read the same way regardless
    # of status, same "partial extraction survives an error" treatment as _WIZARD_FORM_FIELDS below.
    context["ua_snippet"] = result.get("user_agent_snippet") or ""
    # Not one of _WIZARD_FORM_FIELDS either -- only the "Study program page" button's own URL
    # (wizard_import_program, is_program_page=True) is a real bug-bounty PROGRAM link worth
    # carrying into session["program_url"] later. "Use this link as target" (prepare_target_only)
    # and the RE panel's analyze_re_program point at a pentest target / code resource, never a
    # program page, so program_url stays blank there. Preserved regardless of extraction status
    # (same "operator's own typed url is always kept" treatment wizard_url itself already gets) --
    # a failed scope extraction doesn't mean the URL itself wasn't a real program page.
    context["program_url"] = url if is_program_page else ""
    if result.get("status") == "ok":
        context.update({field: result.get(field, "") for field in _WIZARD_FORM_FIELDS})
    else:
        context["error"] = result.get("error") or "Something went wrong."
        context.update({field: result[field] for field in _WIZARD_FORM_FIELDS if result.get(field)})
    return templates.TemplateResponse(request, "partials/new_project_form.html", context)


@app.post("/api/scan/wizard/import-program", response_class=HTMLResponse)
async def wizard_import_program(request: Request, url: str = Form("")) -> HTMLResponse:
    """New Project dialog's "Study program page & fill fields" button -- reads a bug-bounty
    PROGRAM page (HackerOne/Bugcrowd/YesWeHack/...) via a real rendered browser session and an LLM
    extraction pass (agent/tools/bugbounty_import.py), never the target itself."""
    logger.debug("api: POST /api/scan/wizard/import-program url=%r", url)
    result = await analyze_bugbounty_program(url)
    logger.debug("api: wizard/import-program url=%r status=%s", url, result.get("status"))
    return _wizard_form_response(request, url, result, is_program_page=True)


@app.post("/api/scan/wizard/target-only", response_class=HTMLResponse)
async def wizard_target_only(request: Request, url: str = Form("")) -> HTMLResponse:
    """New Project dialog's "Use this link as the target" button -- the pasted link itself becomes
    the pentest target (agent/tools/bugbounty_import.py's prepare_target_only), no program page
    read at all. Async because prepare_target_only now opens a real (if brief) browser session of
    its own to read the target's own real, JS-rendered page title -- see that function's own
    docstring for why a plain HTTP GET isn't good enough for this."""
    logger.debug("api: POST /api/scan/wizard/target-only url=%r", url)
    result = await prepare_target_only(url)
    logger.debug("api: wizard/target-only url=%r status=%s", url, result.get("status"))
    return _wizard_form_response(request, url, result)


@app.post("/api/scan/wizard/check-disclosed-reports", response_class=HTMLResponse)
async def wizard_check_disclosed_reports(request: Request, url: str = Form("")) -> HTMLResponse:
    """New Project dialog's "Check disclosed reports" button -- reads a HackerOne/Bugcrowd/
    YesWeHack program's own public disclosed-reports feed and returns an LLM-summarized list of
    what's already been disclosed (agent/tools/bugbounty_import.py's check_disclosed_reports) so
    the operator can sanity-check for an already-known duplicate before spending real time on a
    program. Informational only: swaps its own small #disclosed-reports-result container, never
    the form fields above (unlike the other two wizard buttons, which prefill scope/target)."""
    logger.debug("api: POST /api/scan/wizard/check-disclosed-reports url=%r", url)
    result = await check_disclosed_reports(url)
    logger.debug("api: wizard/check-disclosed-reports url=%r status=%s", url, result.get("status"))
    return templates.TemplateResponse(request, "partials/disclosed_reports_result.html", {"result": result})


@app.post("/api/scan/wizard/analyze-re-program", response_class=HTMLResponse)
async def wizard_analyze_re_program(request: Request, url: str = Form("")) -> HTMLResponse:
    """The Reverse Engineering New Project panel's own "Analyze program/resource link" button --
    reads a GitHub/GitLab repo or another code-resource page and pre-fills target/qualifying/
    non-qualifying/custom instructions (agent/tools/bugbounty_import.py's analyze_re_program) --
    the RE-mode sibling of wizard_import_program above, restricted to code resources rather than
    live web-app bug-bounty program pages (that case is already Agent mode's own wizard button)."""
    logger.debug("api: POST /api/scan/wizard/analyze-re-program url=%r", url)
    result = await analyze_re_program(url)
    logger.debug("api: wizard/analyze-re-program url=%r status=%s", url, result.get("status"))
    return _wizard_form_response(request, url, result, active_tab="reverse_engineering")


@app.get("/api/session/{session_id}")
def get_session_json(session_id: str) -> dict:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.get("/api/session/{session_id}/fragment", response_class=HTMLResponse)
def get_session_fragment(request: Request, session_id: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return HTMLResponse(_render_fragment(request, session))


# Max chars of a captured TEXT request/response body rendered in the Site Map's raw detail view --
# same "cap what a human is asked to look at" posture as debug.py's own dump_large_payload/
# truncate_for_log, just a larger budget (a human scrolling a dialog tolerates far more than an
# LLM's own token-priced context -- see WEB_FETCH_MAX_TEXT_CHARS for that much smaller number).
# The STORED entry (agent/tools/toolkit_store.py) always keeps the full body regardless -- only
# this one rendering truncates.
_TOOLKIT_DETAIL_MAX_BODY_CHARS = 50_000
# Max base64 chars of an image/* body rendered inline as an <img> preview (~1.5MB decoded) --
# bigger than the text cap above since an image preview needs to stay intact to render at all (a
# truncated JPEG is just a broken image, unlike truncated text which is still readable up to the
# cut). Past this, still shown as "(binary content...)", same as any other non-image binary body.
_TOOLKIT_DETAIL_MAX_IMAGE_BASE64_CHARS = 2_000_000
# Max matches the Site Map's own filter box (templates/partials/toolkit_traffic_list.html) renders
# for one query -- an operator scrolling a table tolerates more than the agent tool's own
# LIST_TRAFFIC_MAX_LIMIT (200, toolkit_agent_tools.py), but a query still needs SOME cap so one
# broad filter can't force rendering the entire history in one response.
_TOOLKIT_QUERY_MANUAL_MAX_RESULTS = 500


def _content_type_for(headers: dict) -> str:
    for name, value in headers.items():
        if name.lower() == "content-type":
            return value.split(";")[0].strip().lower()
    return ""


def _prepare_detail_body(headers: dict, body: str, encoding: str, content_length: int) -> dict:
    """One of three shapes for the Site Map detail view to render, decided server-side so the
    template never has to guess at content-type sniffing itself:
    - {"kind": "text", "text": ..., "truncated": bool} -- the common case, real readable content.
    - {"kind": "image", "content_type": ..., "data_uri": ...} -- an image/* body captured as
      base64 (agent/tools/toolkit_proxy.py's _encode_body), small enough to preview inline.
    - {"kind": "binary", "content_type": ..., "content_length": int} -- any other binary body, or
      an image too large to preview -- never force-rendered as text (the real incident this whole
      encoding scheme fixes: a JPEG response rendered as mojibake before *_body_encoding existed)."""
    content_type = _content_type_for(headers)
    if encoding == "base64":
        if content_type.startswith("image/") and len(body) <= _TOOLKIT_DETAIL_MAX_IMAGE_BASE64_CHARS:
            return {"kind": "image", "content_type": content_type, "data_uri": f"data:{content_type};base64,{body}"}
        return {"kind": "binary", "content_type": content_type or "application/octet-stream", "content_length": content_length}
    text, truncated = (body, False)
    if len(text) > _TOOLKIT_DETAIL_MAX_BODY_CHARS:
        text, truncated = text[:_TOOLKIT_DETAIL_MAX_BODY_CHARS], True
    return {"kind": "text", "text": text, "truncated": truncated}


def _toolkit_base_url(session_id: str | None) -> str:
    """Every toolkit template builds its own hx-get/hx-post URLs off this one value instead of
    hardcoding the session-scoped path pattern -- the same partial renders unchanged whether it's
    embedded in a real project's session page (session_id given) or the standalone /toolkit page
    reachable straight from the sidebar (session_id=None, decision: Toolkit is genuinely native,
    never a hidden/fake "project" of any kind -- see agent/tools/toolkit_store.py's own docstring)."""
    return f"/api/session/{session_id}/toolkit" if session_id else "/api/toolkit"


def _toolkit_session_guard(session_id: str | None) -> None:
    """Raises 404 for a real session_id that doesn't exist -- skipped entirely for the standalone
    page (session_id=None), which has no session to look up at all."""
    if session_id is not None and load_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")


# session_id -> (traffic_file_mtime_ns, scope_entries, candidate_url_count, tree) --
# _build_site_map_tree re-parses and re-walks EVERY captured traffic entry from scratch (confirmed
# live: an hours-long scan's traffic.jsonl can reach hundreds of MB, see
# load_recent_traffic_entries' own docstring for the ~8.6s incident this same full-file-parse
# pattern already caused elsewhere). Polled every 4s for as long as the Map tab stays open, this
# route was redoing that full rebuild on every single tick even when nothing new had actually been
# captured since the last one -- the dominant cost behind the "UI gets laggier the longer a scan
# runs" report. traffic_file_mtime_ns is a cheap stat() that tells "nothing changed" apart from "go
# rebuild", without needing to load the file to find out. candidate_url_count is the same kind of
# cheap growth-only signal for session["recon_result"]["candidate_urls"] (wayback_urls/
# common_crawl_urls discoveries, agent/core.py's _persist_candidate_urls -- append-only, so a
# length change is a sufficient "something new" signal, exactly like mtime_ns is for the traffic
# file: neither one is a full content hash, both are cheap proxies for "did this grow".
_SITE_MAP_TREE_CACHE: dict[str, tuple[int | None, tuple[str, ...], int, dict]] = {}


@app.get("/api/session/{session_id}/site-map-tree", response_class=HTMLResponse)
def get_site_map_tree(request: Request, session_id: str) -> HTMLResponse:
    """Polled by the Map tab's own Site Tree sub-view (partials/session_fragment.html,
    hx-trigger="load, every 4s") -- own independent poll rather than riding the agent's own SSE
    tick, same reasoning the Toolkit's flat traffic list already has its own poll for: captured
    traffic can come from the operator's own manual Toolkit use too, not just agent tool calls.
    Real session_id only (unlike the Toolkit's own traffic routes) -- this view has no standalone-
    page equivalent, it only ever exists inside a real project's Map tab.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    scope_entries = tuple(t.strip() for t in (session.get("target") or "").split(",") if t.strip())
    candidate_urls = (session.get("recon_result") or {}).get("candidate_urls") or []
    mtime_ns = traffic_file_mtime_ns(session_id)
    cached = _SITE_MAP_TREE_CACHE.get(session_id)
    if cached is not None and cached[0] == mtime_ns and cached[1] == scope_entries and cached[2] == len(candidate_urls):
        tree = cached[3]
    else:
        tree = _build_site_map_tree(load_traffic_entries(session_id), list(scope_entries), candidate_urls)
        _SITE_MAP_TREE_CACHE[session_id] = (mtime_ns, scope_entries, len(candidate_urls), tree)
    return templates.TemplateResponse(request, "partials/site_map_tree.html", {"tree": tree, "session_id": session_id})


@app.get("/api/toolkit/traffic", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/traffic", response_class=HTMLResponse)
def get_toolkit_traffic_list(request: Request, session_id: str | None = None, query: str | None = None) -> HTMLResponse:
    """Polled by the Site Map sub-tab (partials/toolkit_panel.html, hx-trigger="load, every 4s",
    hx-include pointed at the filter box so every poll tick resubmits the operator's current query
    too) -- newest capture first, matching a manual HTTP proxy's usual history default order.

    query: optional HTTPQL-lite filter (agent/tools/toolkit_query.py) typed into the Site Map's own
    filter box -- the SAME parser/predicate engine backing the agent-facing list_captured_traffic
    tool's own `query` parameter, so a filter that works by hand works identically for the model.
    A malformed query renders the list empty with an inline error message instead of a 500 -- the
    operator is actively typing it, mid-edit queries are expected to be transiently invalid."""
    _toolkit_session_guard(session_id)
    query_text = (query or "").strip()
    query_error: str | None = None
    query_truncated = False
    if query_text:
        try:
            predicate = compile_query(query_text)
        except QuerySyntaxError as exc:
            query_error = str(exc)
            entries: list[dict] = []
        else:
            matches, query_truncated = load_matching_traffic_entries(session_id, predicate, _TOOLKIT_QUERY_MANUAL_MAX_RESULTS)
            entries = list(reversed(matches))
    else:
        entries = list(reversed(load_traffic_entries(session_id)))
    return templates.TemplateResponse(
        request, "partials/toolkit_traffic_list.html",
        {
            "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id), "entries": entries,
            "query_error": query_error, "query_truncated": query_truncated, "query_active": bool(query_text),
        },
    )


@app.get("/api/toolkit/traffic/{entry_id}", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/traffic/{entry_id}", response_class=HTMLResponse)
def get_toolkit_traffic_detail(request: Request, entry_id: str, session_id: str | None = None) -> HTMLResponse:
    """Lazy-loaded into the Site Map's shared #toolkit-traffic-detail dialog on row click -- one
    request per view, not pre-rendered per row (a real session can capture hundreds of requests,
    each with a body up to ~1MB -- confirmed live -- so a dialog-per-row like
    session_fragment.html's finding cards would be far too heavy here)."""
    _toolkit_session_guard(session_id)
    entry = get_traffic_entry(session_id, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Traffic entry not found")
    request_detail = _prepare_detail_body(
        entry["request_headers"], entry["request_body"],
        entry.get("request_body_encoding", "text"), entry.get("request_content_length", len(entry["request_body"])),
    )
    response_detail = _prepare_detail_body(
        entry["response_headers"], entry["response_body"],
        entry.get("response_body_encoding", "text"), entry.get("response_content_length", len(entry["response_body"])),
    )
    return templates.TemplateResponse(
        request, "partials/toolkit_traffic_detail.html",
        {"entry": entry, "request_detail": request_detail, "response_detail": response_detail},
    )


def _repeater_history(session_id: str | None) -> list[dict]:
    return [e for e in reversed(load_traffic_entries(session_id)) if e.get("source") == "repeater"]


@app.get("/api/toolkit/repeater", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/repeater", response_class=HTMLResponse)
def get_toolkit_repeater_panel(request: Request, session_id: str | None = None, entry_id: str | None = None) -> HTMLResponse:
    """Renders the Repeater sub-tab's whole self-contained #toolkit-repeater-container -- both the
    Site Map's "Send to Repeater" button and a History row reuse this exact route (entry_id
    optional either way) so pre-filling the editor from an existing capture/attempt is always the
    same code path, never duplicated between "load fresh" and "reload a past one"."""
    _toolkit_session_guard(session_id)

    prefill = get_traffic_entry(session_id, entry_id) if entry_id else None
    context: dict = {
        "session_id": session_id,
        "toolkit_base_url": _toolkit_base_url(session_id),
        "method": prefill["method"] if prefill else "GET",
        "url": prefill["url"] if prefill else "",
        "headers_text": _format_header_lines(prefill["request_headers"]) if prefill else "",
        "body": "",
        "binary_request_body_note": None,
        "result_entry": None,
        "response_detail": None,
        "send_error": None,
        "history": _repeater_history(session_id),
    }
    if prefill:
        if prefill.get("request_body_encoding", "text") == "base64":
            # Editing a binary body (e.g. a file upload) as plain text would silently corrupt it
            # on resend -- left empty rather than showing base64 the operator might not realize
            # isn't safe to touch and send back as literal text.
            context["binary_request_body_note"] = (
                f"Original request had a binary body ({prefill.get('request_content_length', 0)} bytes) "
                "-- not shown here, type a new one if you need to resend one."
            )
        else:
            context["body"] = prefill["request_body"]
        # A history entry (source="repeater") already carries its OWN response -- show it
        # immediately, same as reopening a saved manual-replay tab. A Site Map entry (source="proxy")
        # sent here for the first time has no Repeater response yet -- prefill only.
        if prefill.get("source") == "repeater":
            context["result_entry"] = prefill
            context["response_detail"] = _prepare_detail_body(
                prefill["response_headers"], prefill["response_body"],
                prefill.get("response_body_encoding", "text"),
                prefill.get("response_content_length", len(prefill["response_body"])),
            )
    return templates.TemplateResponse(request, "partials/toolkit_repeater.html", context)


@app.post("/api/toolkit/repeater/send", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/repeater/send", response_class=HTMLResponse)
async def post_toolkit_repeater_send(
    request: Request, session_id: str | None = None,
    method: str = Form(...), url: str = Form(...), headers_text: str = Form(""), body: str = Form(""),
) -> HTMLResponse:
    """{{name}} placeholders (agent/tools/toolkit_variables.py) in url/headers_text/body are
    resolved against this session's saved variables right before sending -- the form itself keeps
    showing the operator's original {{name}} template (never the resolved value) so it stays
    reusable for the next send, only the ACTUAL request that goes out (and the traffic entry it's
    recorded as) reflects the resolved values."""
    _toolkit_session_guard(session_id)

    variables = toolkit_variables.load_variables(session_id)
    headers = _parse_header_lines(toolkit_variables.substitute(headers_text, variables))
    send_result = await send_raw_request(
        session_id=session_id, method=method.strip().upper() or "GET",
        url=toolkit_variables.substitute(url.strip(), variables),
        headers=headers, body=toolkit_variables.substitute(body, variables),
    )
    context: dict = {
        "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id),
        "method": method, "url": url, "headers_text": headers_text, "body": body,
        "binary_request_body_note": None, "result_entry": None, "response_detail": None, "send_error": None,
    }
    if send_result["status"] == "ok":
        entry = send_result["entry"]
        context["result_entry"] = entry
        context["response_detail"] = _prepare_detail_body(
            entry["response_headers"], entry["response_body"],
            entry.get("response_body_encoding", "text"), entry.get("response_content_length", len(entry["response_body"])),
        )
    else:
        context["send_error"] = send_result["error"]
    # Fetched only once, after the send attempt (not before) -- a successful send's own new entry
    # must already be in this list, not appear only after the operator's NEXT send.
    context["history"] = _repeater_history(session_id)
    return templates.TemplateResponse(request, "partials/toolkit_repeater.html", context)


@app.post("/api/toolkit/repeater/history/{entry_id}/delete", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/repeater/history/{entry_id}/delete", response_class=HTMLResponse)
def post_toolkit_repeater_delete_history_entry(request: Request, entry_id: str, session_id: str | None = None) -> HTMLResponse:
    """Lets the operator clear a mistaken/junk entry out of Repeater's own History list -- the
    append-only traffic store otherwise had no delete path at all. Re-renders only the History
    fragment (hx-target scoped to #toolkit-repeater-history in the template), never the whole
    container, so a delete never discards whatever the operator currently has typed into the
    request editor above it."""
    _toolkit_session_guard(session_id)
    delete_traffic_entry(session_id, entry_id)
    context = {
        "session_id": session_id,
        "toolkit_base_url": _toolkit_base_url(session_id),
        "history": _repeater_history(session_id),
    }
    return templates.TemplateResponse(request, "partials/toolkit_repeater_history.html", context)


def _decoder_context(session_id: str | None, scheme: str, mode: str, input_text: str) -> dict:
    return {
        "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id),
        "schemes": DECODER_SCHEMES, "scheme": scheme, "mode": mode,
        "input_text": input_text, "result": None, "error": None,
    }


@app.get("/api/toolkit/decoder", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/decoder", response_class=HTMLResponse)
def get_toolkit_decoder_panel(request: Request, session_id: str | None = None) -> HTMLResponse:
    """Lazy-loaded into the Decoder sub-tab the same "load" trigger convention as the Repeater
    container (partials/toolkit_panel.html) -- always starts blank, no prefill/history concept
    here since a Decoder run isn't tied to any captured traffic entry."""
    _toolkit_session_guard(session_id)
    return templates.TemplateResponse(
        request, "partials/toolkit_decoder.html", _decoder_context(session_id, "base64", "encode", ""),
    )


@app.post("/api/toolkit/decoder/run", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/decoder/run", response_class=HTMLResponse)
def post_toolkit_decoder_run(
    request: Request, session_id: str | None = None,
    scheme: str = Form(...), mode: str = Form(...), input_text: str = Form(""),
) -> HTMLResponse:
    _toolkit_session_guard(session_id)
    context = _decoder_context(session_id, scheme, mode, input_text)
    codec_result = run_codec(scheme=scheme, mode=mode, text=input_text)
    if codec_result["status"] == "ok":
        context["result"] = codec_result["result"]
    else:
        context["error"] = codec_result["error"]
    return templates.TemplateResponse(request, "partials/toolkit_decoder.html", context)


def _comparer_context(session_id: str | None, entries: list[dict], entry_id_a: str | None, entry_id_b: str | None, part: str) -> dict:
    return {
        "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id), "entries": entries,
        "entry_id_a": entry_id_a, "entry_id_b": entry_id_b, "part": part,
        "rows": None, "error": None,
    }


@app.get("/api/toolkit/comparer", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/comparer", response_class=HTMLResponse)
def get_toolkit_comparer_panel(request: Request, session_id: str | None = None) -> HTMLResponse:
    """Lazy-loaded into the Comparer sub-tab, same "load" trigger convention as Repeater/Decoder.
    The two pick-lists reuse the exact same entry list the Site Map already shows (newest first) --
    a Repeater attempt is just a traffic entry with source="repeater", already included, so there's
    no separate "pick a Repeater attempt" list to keep in sync with this one."""
    _toolkit_session_guard(session_id)
    entries = list(reversed(load_traffic_entries(session_id)))
    return templates.TemplateResponse(
        request, "partials/toolkit_comparer.html", _comparer_context(session_id, entries, None, None, "response"),
    )


@app.post("/api/toolkit/comparer/run", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/comparer/run", response_class=HTMLResponse)
def post_toolkit_comparer_run(
    request: Request, session_id: str | None = None,
    entry_id_a: str = Form(...), entry_id_b: str = Form(...), part: str = Form("response"),
) -> HTMLResponse:
    _toolkit_session_guard(session_id)
    entries = list(reversed(load_traffic_entries(session_id)))
    context = _comparer_context(session_id, entries, entry_id_a, entry_id_b, part)
    diff_result = diff_entries(session_id=session_id, entry_id_a=entry_id_a, entry_id_b=entry_id_b, part=part)
    if diff_result["status"] == "ok":
        context["rows"] = diff_result["rows"]
    else:
        context["error"] = diff_result["error"]
    return templates.TemplateResponse(request, "partials/toolkit_comparer.html", context)


def _intruder_context(
    session_id: str | None, *, method: str = "GET", url: str = "", headers_text: str = "", body: str = "",
    mode: str = "sniper", payload_text: str = "", error: str | None = None,
    run_id: str | None = None, expected: int | None = None,
) -> dict:
    return {
        "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id),
        "method": method, "url": url, "headers_text": headers_text,
        "body": body, "mode": mode, "payload_text": payload_text, "error": error,
        "run_id": run_id, "expected": expected,
    }


@app.get("/api/toolkit/intruder", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/intruder", response_class=HTMLResponse)
def get_toolkit_intruder_panel(request: Request, session_id: str | None = None, entry_id: str | None = None) -> HTMLResponse:
    """Lazy-loaded into the Intruder sub-tab, same "load" trigger convention as Repeater/Decoder/
    Comparer. entry_id optionally prefills the template from a captured entry (same "send to X"
    convenience Repeater already has) -- the operator adds their own §...§ markers by hand from
    there, the same manual-marking convention a payload-injection tool typically uses."""
    _toolkit_session_guard(session_id)
    prefill = get_traffic_entry(session_id, entry_id) if entry_id else None
    context = _intruder_context(session_id)
    if prefill:
        context["method"] = prefill["method"]
        context["url"] = prefill["url"]
        context["headers_text"] = _format_header_lines(prefill["request_headers"])
        if prefill.get("request_body_encoding", "text") != "base64":
            context["body"] = prefill["request_body"]
    return templates.TemplateResponse(request, "partials/toolkit_intruder.html", context)


@app.post("/api/toolkit/intruder/run", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/intruder/run", response_class=HTMLResponse)
async def post_toolkit_intruder_run(
    request: Request, session_id: str | None = None,
    method: str = Form("GET"), url: str = Form(""), headers_text: str = Form(""), body: str = Form(""),
    mode: str = Form("sniper"), payload_text: str = Form(""),
) -> HTMLResponse:
    """async def (not the plain sync def every other toolkit route uses) -- deliberately: this is
    the ONE toolkit route that fires a real asyncio.create_task (toolkit_intruder.
    start_attack_in_background), which requires a running event loop in the calling context.
    FastAPI dispatches a sync `def` route through a worker thread with no event loop of its own
    (the same reason agent/tools/runner.py's native_function tools are always plain sync); running
    this one as `async def` keeps it on the real server event loop instead."""
    _toolkit_session_guard(session_id)
    context = _intruder_context(
        session_id, method=method, url=url, headers_text=headers_text, body=body,
        mode=mode, payload_text=payload_text,
    )
    # {{name}} placeholders resolved BEFORE §...§ attack-position substitution -- distinct syntax,
    # so the two never collide; the form itself keeps showing the original {{name}} template (see
    # post_toolkit_repeater_send's own docstring for why).
    variables = toolkit_variables.load_variables(session_id)
    started = toolkit_intruder.start_attack_in_background(
        session_id=session_id, method=method.strip().upper() or "GET",
        url=toolkit_variables.substitute(url.strip(), variables),
        headers_text=toolkit_variables.substitute(headers_text, variables),
        body=toolkit_variables.substitute(body, variables), mode=mode, payload_text=payload_text,
    )
    if started["status"] != "ok":
        context["error"] = started["error"]
    else:
        context["run_id"] = started["run_id"]
        context["expected"] = started["expected"]
    return templates.TemplateResponse(request, "partials/toolkit_intruder.html", context)


_INTRUDER_SORT_KEYS = {
    "time": lambda e: e["timestamp"],
    "status": lambda e: e.get("response_status") or 0,
    "length": lambda e: e.get("response_content_length") or 0,
    "duration": lambda e: e.get("duration_ms") or 0,
}


@app.get("/api/toolkit/intruder/results/{run_id}", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/intruder/results/{run_id}", response_class=HTMLResponse)
def get_toolkit_intruder_results(
    request: Request, run_id: str, session_id: str | None = None, expected: int = 0,
    sort: str = "time", anomalies_only: bool = False,
) -> HTMLResponse:
    """Polled by the results panel itself (partials/toolkit_intruder_results.html, self-swapping
    hx-get -- see that template's own comment for why it needs full outerHTML replacement, not
    Site Map's morph:innerHTML, to let hx-trigger stop repeating once the attack is done). Reads
    directly from toolkit_store -- there is no separate in-memory "results so far" structure, every
    completed attempt is already durable there the instant toolkit_repeater.send_raw_request
    records it (see toolkit_intruder.run_attack's own docstring)."""
    _toolkit_session_guard(session_id)
    entries = [e for e in load_traffic_entries(session_id) if e.get("intruder_run_id") == run_id]

    # Anomaly heuristic: the (status, length) pair shared by the MOST attempts so far is this
    # attack's own "baseline" response -- any attempt landing on a different pair is flagged. A
    # real, simple, payload-injection-style signal (a commercial equivalent's own default
    # response-grouping works the same way in practice), not full statistical outlier detection --
    # matches this whole phase's own "minimally useful, not a full commercial feature set" scope.
    pair_counts: dict[tuple, int] = {}
    for e in entries:
        pair = (e.get("response_status"), e.get("response_content_length"))
        pair_counts[pair] = pair_counts.get(pair, 0) + 1
    baseline_pair = max(pair_counts, key=lambda pair: pair_counts[pair]) if pair_counts else None
    rows = [{**e, "is_anomaly": (e.get("response_status"), e.get("response_content_length")) != baseline_pair} for e in entries]

    sort_key = _INTRUDER_SORT_KEYS.get(sort, _INTRUDER_SORT_KEYS["time"])
    rows.sort(key=sort_key, reverse=True)
    if anomalies_only:
        rows = [r for r in rows if r["is_anomaly"]]

    return templates.TemplateResponse(
        request, "partials/toolkit_intruder_results.html",
        {
            "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id),
            "run_id": run_id, "expected": expected, "rows": rows,
            "received": len(entries), "running": toolkit_intruder.attack_status(run_id) == "running",
            "sort": sort, "anomalies_only": anomalies_only,
        },
    )


def _racer_context(
    session_id: str | None, *, method: str = "GET", url: str = "", headers_text: str = "", body: str = "",
    strategy: str = "last_byte", request_count: int = 10, result: dict | None = None, error: str | None = None,
) -> dict:
    return {
        "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id),
        "method": method, "url": url, "headers_text": headers_text, "body": body,
        "strategy": strategy, "request_count": request_count, "result": result, "error": error,
    }


@app.get("/api/toolkit/racer", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/racer", response_class=HTMLResponse)
def get_toolkit_racer_panel(request: Request, session_id: str | None = None, entry_id: str | None = None) -> HTMLResponse:
    """Lazy-loaded into the Racer sub-tab, same "load" trigger convention as every other Toolkit
    sub-tab. entry_id optionally prefills the template from a captured entry -- same "send to X"
    convenience Repeater/Intruder already have."""
    _toolkit_session_guard(session_id)
    prefill = get_traffic_entry(session_id, entry_id) if entry_id else None
    context = _racer_context(session_id)
    if prefill:
        context["method"] = prefill["method"]
        context["url"] = prefill["url"]
        context["headers_text"] = _format_header_lines(prefill["request_headers"])
        if prefill.get("request_body_encoding", "text") != "base64":
            context["body"] = prefill["request_body"]
    return templates.TemplateResponse(request, "partials/toolkit_racer.html", context)


@app.post("/api/toolkit/racer/run", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/racer/run", response_class=HTMLResponse)
async def post_toolkit_racer_run(
    request: Request, session_id: str | None = None,
    method: str = Form("GET"), url: str = Form(""), headers_text: str = Form(""), body: str = Form(""),
    strategy: str = Form("last_byte"), request_count: int = Form(10),
) -> HTMLResponse:
    """async def, awaited directly (no background task, unlike Intruder's own
    post_toolkit_intruder_run) -- request_count is hard-capped much lower than an Intruder sweep
    (toolkit_racer.py's own _MAX_ALLOWED_REQUESTS), so one race run completes in at most a few
    seconds; the extra background-task/polling-results machinery Intruder needs for a run that can
    take minutes would be pure complexity here for no real benefit, same synchronous-await shape
    post_toolkit_sequencer_analyze already uses for the same reason."""
    _toolkit_session_guard(session_id)
    context = _racer_context(
        session_id, method=method, url=url, headers_text=headers_text, body=body,
        strategy=strategy, request_count=request_count,
    )
    # {{name}} placeholders resolved before racing -- see post_toolkit_repeater_send's own
    # docstring for why the form itself keeps showing the original {{name}} template.
    variables = toolkit_variables.load_variables(session_id)
    result = await toolkit_racer.run_race(
        session_id=session_id, method=method.strip().upper() or "GET",
        url=toolkit_variables.substitute(url.strip(), variables),
        headers_text=toolkit_variables.substitute(headers_text, variables),
        body=toolkit_variables.substitute(body, variables),
        request_count=request_count, strategy=strategy,
    )
    if result["status"] != "ok":
        context["error"] = result["error"]
    else:
        context["result"] = result
    return templates.TemplateResponse(request, "partials/toolkit_racer.html", context)


@app.get("/api/toolkit/variables", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/variables", response_class=HTMLResponse)
def get_toolkit_variables_panel(request: Request, session_id: str | None = None) -> HTMLResponse:
    """{{name}} variables (agent/tools/toolkit_variables.py) for the manual Repeater/Intruder/Racer
    forms -- lazy-loaded into the Variables sub-tab, same "load" trigger convention as every other
    Toolkit sub-tab."""
    _toolkit_session_guard(session_id)
    return templates.TemplateResponse(
        request, "partials/toolkit_variables.html",
        {"session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id), "variables": toolkit_variables.load_variables(session_id)},
    )


@app.post("/api/toolkit/variables/set", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/variables/set", response_class=HTMLResponse)
def post_toolkit_variables_set(request: Request, session_id: str | None = None, name: str = Form(""), value: str = Form("")) -> HTMLResponse:
    _toolkit_session_guard(session_id)
    variables = toolkit_variables.set_variable(session_id, name, value)
    return templates.TemplateResponse(
        request, "partials/toolkit_variables.html",
        {"session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id), "variables": variables},
    )


@app.post("/api/toolkit/variables/{name}/delete", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/variables/{name}/delete", response_class=HTMLResponse)
def post_toolkit_variables_delete(request: Request, name: str, session_id: str | None = None) -> HTMLResponse:
    _toolkit_session_guard(session_id)
    variables = toolkit_variables.delete_variable(session_id, name)
    return templates.TemplateResponse(
        request, "partials/toolkit_variables.html",
        {"session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id), "variables": variables},
    )


def _sequencer_context(
    session_id: str | None, *, collect_mode: str = "stored", header_name: str = "",
    method: str = "GET", url: str = "", headers_text: str = "", body: str = "", count: int = 20,
    result: dict | None = None, error: str | None = None,
) -> dict:
    return {
        "session_id": session_id, "toolkit_base_url": _toolkit_base_url(session_id),
        "collect_mode": collect_mode, "header_name": header_name,
        "method": method, "url": url, "headers_text": headers_text, "body": body, "count": count,
        "result": result, "error": error,
    }


@app.get("/api/toolkit/sequencer", response_class=HTMLResponse)
@app.get("/api/session/{session_id}/toolkit/sequencer", response_class=HTMLResponse)
def get_toolkit_sequencer_panel(request: Request, session_id: str | None = None) -> HTMLResponse:
    _toolkit_session_guard(session_id)
    return templates.TemplateResponse(request, "partials/toolkit_sequencer.html", _sequencer_context(session_id))


@app.post("/api/toolkit/sequencer/analyze", response_class=HTMLResponse)
@app.post("/api/session/{session_id}/toolkit/sequencer/analyze", response_class=HTMLResponse)
async def post_toolkit_sequencer_analyze(
    request: Request, session_id: str | None = None,
    collect_mode: str = Form("stored"), header_name: str = Form(""),
    method: str = Form("GET"), url: str = Form(""), headers_text: str = Form(""), body: str = Form(""),
    count: int = Form(20),
) -> HTMLResponse:
    _toolkit_session_guard(session_id)
    context = _sequencer_context(
        session_id, collect_mode=collect_mode, header_name=header_name, method=method,
        url=url, headers_text=headers_text, body=body, count=count,
    )
    if not header_name.strip():
        context["error"] = "Name the header/cookie to analyze first (e.g. 'X-CSRF-Token' or 'cookie:session')."
        return templates.TemplateResponse(request, "partials/toolkit_sequencer.html", context)

    if collect_mode == "live":
        collected = await toolkit_sequencer.collect_live_samples(
            session_id=session_id, method=method.strip().upper() or "GET", url=url.strip(),
            headers_text=headers_text, body=body, header_name=header_name.strip(), count=count,
        )
        samples = collected["samples"]
    else:
        samples = toolkit_sequencer.collect_stored_samples(session_id, header_name.strip())

    analysis = toolkit_sequencer.analyze_samples(samples)
    if analysis["status"] != "ok":
        context["error"] = analysis["error"]
    else:
        context["result"] = analysis
    return templates.TemplateResponse(request, "partials/toolkit_sequencer.html", context)


@app.get("/api/session/{session_id}/toolkit/screencast-panel", response_class=HTMLResponse)
def get_toolkit_screencast_panel(request: Request, session_id: str, visible: bool = False) -> HTMLResponse:
    """The Live View toggle button -- both directions (Show/Hide) round-trip through here rather
    than a client-side-only show/hide, specifically so the "on" fragment's own sse-connect element
    only ever EXISTS in the DOM while actually visible (off by default -- streaming frames nobody's
    watching isn't free). Toggling back to "off" removes that element from the DOM entirely, which
    is what actually closes the underlying EventSource (htmx's sse extension tears it down on
    element cleanup) and, on the stream route's own side (toolkit_screencast_stream below), stops
    the real CDP screencast."""
    if load_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return templates.TemplateResponse(
        request, "partials/toolkit_live_view.html",
        {"session_id": session_id, "visible": visible},
    )


@app.get("/api/session/{session_id}/toolkit/screencast/stream")
async def toolkit_screencast_stream(request: Request, session_id: str) -> StreamingResponse:
    """Independent SSE connection, deliberately NOT multiplexed onto #session-stream's own (same
    reasoning as chat_stream above -- and more forced here: the Live View panel physically lives
    outside #session-stream's own DOM subtree entirely, partials/toolkit_panel.html, so it
    couldn't share that connection's sse-swap target even if it wanted to). Starts the real CDP
    screencast on connect (retried every tick via start_screencast's own idempotent no-op-once-
    running behavior, so opening Live View before the agent has ever called browser_navigate keeps
    trying instead of failing once), stops it the moment this connection closes -- streaming
    frames only costs anything for as long as someone is actually watching."""
    if _load_session_for_stream(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")

    manager = get_browser_manager()

    async def event_generator():
        last_frame_id: int | None = None
        try:
            while True:
                if await request.is_disconnected():
                    break
                await manager.start_screencast(session_id)
                frame = manager.get_latest_screencast_frame(session_id)
                if frame is not None and frame["id"] != last_frame_id:
                    last_frame_id = frame["id"]
                    # tabindex + data-viewport-* -- static/js/live_view_input.js's own click/scroll/
                    # keyboard forwarding needs both: tabindex so the frame can actually receive
                    # keyboard focus (a plain <img> can't), the real viewport size (BrowserSession
                    # Manager.get_live_view_viewport -- NOT this image's own downscaled pixel
                    # dimensions) to convert a click's on-screen position back into real page-space
                    # coordinates for Input dispatch.
                    viewport = manager.get_live_view_viewport(session_id)
                    html = (
                        f'<img id="toolkit-live-frame" src="data:image/jpeg;base64,{frame["data"]}" tabindex="0" '
                        f'data-viewport-width="{viewport["width"] if viewport else ""}" '
                        f'data-viewport-height="{viewport["height"] if viewport else ""}" '
                        'class="w-full rounded border border-default cursor-pointer" '
                        'alt="Live view of the agent\'s browser — click to interact, scroll to scroll, type to type">'
                    )
                    yield _format_sse_event(html)
                # 300ms -- a live-ish preview, not a video call; CDP itself may produce frames
                # faster (start_screencast's own everyNthFrame=1), but only the latest is ever
                # kept, so pushing out any faster than this would just waste bandwidth on frames
                # nobody could perceive as smoother anyway.
                await asyncio.sleep(0.3)
        except asyncio.CancelledError:
            raise
        finally:
            await manager.stop_screencast(session_id)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/session/{session_id}/toolkit/live-view/input")
async def toolkit_live_view_input(request: Request, session_id: str) -> Response:
    """The Live View panel's own click/scroll/keyboard forwarding (static/js/live_view_input.js) --
    real mouse/keyboard input the operator sends by interacting with the streamed screencast frame
    itself, routed straight into this session's real Playwright page
    (BrowserSessionManager.dispatch_live_view_input) rather than through any agent tool-call
    machinery. A malformed/missing JSON body is best-effort, same as debug_client_event above --
    this is a background fetch() call the operator never sees the response of, not a real API
    contract worth a 4xx for a body-parsing hiccup.
    """
    if load_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")
    try:
        payload = await request.json()
    except Exception:
        return Response(status_code=204)

    manager = get_browser_manager()
    result = await manager.dispatch_live_view_input(
        session_id,
        event_type=payload.get("type", ""),
        x=float(payload.get("x") or 0),
        y=float(payload.get("y") or 0),
        button=payload.get("button", "left"),
        click_count=int(payload.get("click_count") or 1),
        key=payload.get("key", ""),
        dx=float(payload.get("dx") or 0),
        dy=float(payload.get("dy") or 0),
    )
    logger.debug(
        "api: live-view input session_id=%s type=%s status=%s", session_id, payload.get("type"), result.get("status"),
    )
    return Response(status_code=204)


def _format_sse_event(html: str) -> str:
    data_lines = "\n".join(f"data: {line}" for line in html.splitlines())
    return f"{data_lines}\n\n"


def _load_session_for_stream(session_id: str) -> dict | None:
    """load_session() for an SSE poll loop specifically -- real, confirmed incident this fixes:
    sessions/store.py's load_session() retries a torn/corrupt JSON read for up to
    LOAD_SESSION_RETRY_ATTEMPTS * LOAD_SESSION_RETRY_DELAY_SECONDS (~4s default) BLOCKING (a plain
    time.sleep loop, not an await), then RAISES if it never recovers. Called straight from an async
    generator with no try/except (stream_session/chat_stream below), that ~4s blocked the ENTIRE
    process event loop -- every other concurrent request, every other open tab, the agent's own
    tool-call loop, all frozen -- and the raised exception then killed the StreamingResponse, which
    made the browser's own EventSource auto-reconnect INSTANTLY (the spec default on any connection
    close), hitting this same broken read again: a continuous ~4s-freeze-then-crash loop for as
    long as that one project's tab stayed open. Observed live: a real (since self-healed) torn
    write on one project's session.json produced 96 identical "still unreadable" log lines in one
    minute, and that same project's own debug.log shows real "sse: error/reconnecting" client
    events on a LATER day too -- this is not a one-off, it recurs for any future transient/corrupt
    read on any session. Treating it the same as "session not found" (an ended stream, not a crash)
    is the correct degrade -- the next poll cycle (or a fresh page load) tries again on its own."""
    try:
        return load_session(session_id)
    except json.JSONDecodeError as exc:
        logger.debug("stream: session=%s unreadable this cycle, ending this stream cleanly (%s)", session_id, exc)
        return None


@app.get("/api/session/{session_id}/stream")
async def stream_session(request: Request, session_id: str) -> StreamingResponse:
    if _load_session_for_stream(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator():
        # An in-memory write-counter comparison (sessions/store.py's get_session_revision), not a
        # full hashlib.sha256(json.dumps(session, ...)) of the whole session dict every tick --
        # real, confirmed root cause of a live session's own UI getting progressively laggier (and,
        # on an actual 4.5-hour bug-bounty run, the Map tab's graph disappearing outright) the
        # longer a scan ran: the old hash-the-whole-session approach cost more with every log line/
        # finding/hypothesis a long scan accumulated, with no ceiling, and it's a synchronous,
        # CPU-bound block with no `await` in it -- for however long that dump+hash took on a large
        # session, it stalled THIS WHOLE PROCESS's event loop, delaying every other concurrent
        # request (every other open tab, every other route, the agent's own tool-call loop) once
        # per second, every second, for the entire session. See get_session_revision's own
        # docstring for why an O(1) integer compare is a complete, sound replacement -- every
        # mutation path already funnels through save_session(), which is the one place this counter
        # is bumped.
        last_revision: int | None = None
        while True:
            if await request.is_disconnected():
                break

            session = _load_session_for_stream(session_id)
            if session is None:
                break

            current_revision = get_session_revision(session_id)
            if current_revision != last_revision:
                last_revision = current_revision
                yield _format_sse_event(_render_fragment(request, session))

            # Deliberately never breaks just because the session reached a terminal status — a
            # server-initiated close made the browser's EventSource auto-reconnect (that's the
            # spec default on any connection close, not just errors), which hit this same route
            # again, got one event, closed again, reconnected again... an endless flap that showed
            # as a stuck "reconnecting…" indicator, especially reopening an already-completed old
            # session (see also: index() only wires up sse-connect for non-terminal sessions in
            # the first place). Idling here instead costs one open connection per viewed tab,
            # trivial for a single-operator local tool — the loop still ends via is_disconnected()
            # above once the tab closes or navigates away.
            await asyncio.sleep(_SSE_POLL_INTERVAL_SECONDS)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/session/{session_id}/chat/stream")
async def chat_stream(request: Request, session_id: str) -> StreamingResponse:
    """Same shape as stream_session above, deliberately its OWN independent SSE connection rather
    than a second event type multiplexed onto that one — #session-stream's own hx-ext/sse-connect
    wiring already carries hard-won, heavily-commented morph-corruption fixes (see session.html);
    reusing it for a second, unrelated concern risks regressing something already fragile, for the
    sake of avoiding one extra idle connection per open tab — the same "trivial for a
    single-operator local tool" tradeoff stream_session's own docstring already makes.

    Hashes the ACTIVE chat thread's own full content (not the whole session, and not the other,
    inactive threads' own messages) — a scan's own log/finding activity must never cause a chat
    re-render (which would fight an in-progress typed draft) and vice versa; switching threads
    (main.py's switch_chat_thread_route) changes which thread is "active" and therefore what this
    hashes, so a push still fires exactly when the visible content actually changes.

    ALSO hashes a lightweight {id, pending, title, color} summary of every OTHER thread — the tab
    strip's own live-dot/title/color (partials/chat_thread_tabs.html) can change for a thread that
    was never the active one at all (a background run_chat_turn_background finishing, a rename/
    recolor from the picker while a different thread is open), none of which the active thread's
    own content hash could ever catch. Whenever either half changes, push BOTH the active thread's
    messages and an OOB refresh of the tab strip/header (_render_chat_header_oob) — same
    concatenation every other chat-mutating route already returns, just via SSE instead of a
    direct response.
    """
    if _load_session_for_stream(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator():
        last_hash: str | None = None
        while True:
            if await request.is_disconnected():
                break

            session = _load_session_for_stream(session_id)
            if session is None:
                break

            thread = _get_active_thread(session)
            other_threads_summary = [
                {"id": t.get("id"), "pending": t.get("pending"), "title": t.get("title"), "color": t.get("color")}
                for t in (session.get("chat_threads") or [])
            ]
            current_hash = hashlib.sha256(
                json.dumps({"active": thread, "all": other_threads_summary}, sort_keys=True, default=str).encode("utf-8")
            ).hexdigest()
            if current_hash != last_hash:
                last_hash = current_hash
                yield _format_sse_event(_render_chat_messages(request, session) + _render_chat_header_oob(request, session))

            await asyncio.sleep(_SSE_POLL_INTERVAL_SECONDS)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/session/{session_id}", response_class=HTMLResponse)
def get_session_page(request: Request, session_id: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("mode") == "standalone":
        # The one real session backing Quick Chat (get_or_create_quick_chat_session) -- it's never
        # linked to from anywhere as a project page (list_session_summaries keeps it out of the
        # Projects list entirely), but a stale bookmark or a manually-typed URL could still land
        # here; session.html assumes a real project's own full field set (approvals/plan/
        # chain_attempts/...), none of which this session has, so send it to its real home instead
        # of risking a confusing render/crash.
        return RedirectResponse(url="/chat", status_code=302)
    # chat_panel.html is {% include %}'d by session.html, which inherits the parent template's
    # full render context in Jinja by default -- _chat_context's provider-picker/chat_model_choices
    # keys have to be spread in here, not just "session", or the picker <select>s would render
    # with an empty/broken context on the session page's own full load (only chat_turn's own POST
    # response would ever have them, which is exactly the "one render site missed a context helper"
    # class of bug this project's own tojson/Undefined incident already warns about).
    session = _ensure_resumable_from(session)
    # entries: partials/re_triage_tab.html's own timeline section (an {% include %} inside
    # session.html, which inherits this same context) -- session.html's Triage tab needs this on
    # the page's own FIRST load too, not just re_triage_tab's own GET route below, or it renders
    # the "No tool activity yet" empty state even when session["logs"] is genuinely non-empty
    # (confirmed live: the graph half of that same tab already worked here since
    # _re_triage_graph_context was already being spread in, the timeline half wasn't). Only ever
    # rendered for RE mode (session.html's own Triage tab is RE-only) -- gated the same way so an
    # ordinary Agent-mode session page load never pays for flattening every chat thread/log entry
    # for a value it will never use.
    extra_context = {"entries": _interactive_log_entries(session)} if session.get("mode") == "reverse_engineering" else {}
    return templates.TemplateResponse(request, "session.html", {
        **_chat_context(session), **_re_triage_graph_context(session), **extra_context,
    })


def _interactive_log_entries(session: dict) -> list[dict]:
    """Flattens every tool_call segment across ALL of this session's chat threads, PLUS (for modes
    that populate it) session["logs"] itself, into one chronological list. Interactive mode never
    writes session["logs"] (agent/chat.py never touches it) -- the chat threads ARE its whole
    record. Reverse Engineering mode is different: agent/core.py's run_re_triage reuses the same
    _run_llm_tool_loop/_append_log machinery Agent-mode's recon/analyze/exploit phases use, so its
    own baseline-triage trace lands in session["logs"], not any chat thread -- folded in here too
    (unconditionally; harmless no-op for a mode where it's always empty) so this Logs view is
    complete for whichever mode the session is in, not just Interactive's own chat-only case.

    Also folds in reward events (role="reward" messages, agent/chat.py's
    deliver_storage_reward_to_chat) from every chat thread -- these have no "segments" at all (a
    different message shape than a real chat turn), so the tool_call-only loop below never sees
    them on its own; a finding/technique actually landing in storage is real session activity
    worth a durable log line here too, not just an ephemeral "+1" toast the operator might not
    have been looking at when it fired.

    Sorted by each entry's own timestamp so chat threads, reward events, and (for RE mode)
    session["logs"] all read as one ordered activity trail regardless of which source produced
    them. Kept in main.py (not the template) so the template just iterates a ready list instead of
    doing this flattening + sorting in Jinja."""
    entries: list[dict] = []
    for thread in session.get("chat_threads", []):
        for message in thread.get("messages", []):
            at = message.get("at")
            if message.get("role") == "reward":
                reward = message.get("reward") or {}
                entries.append({
                    "at": at,
                    "name": f"+{reward.get('delta', 1)} {reward.get('kind', 'reward')}",
                    "arg_summary": reward.get("label"),
                    "output": reward.get("detail"),
                    "error": False,
                    "done": True,
                })
                continue
            for segment in message.get("segments", []):
                if segment.get("type") != "tool_call":
                    continue
                entries.append({
                    "at": at,
                    "name": segment.get("name", "?"),
                    "arg_summary": segment.get("arg_summary"),
                    "output": segment.get("output"),
                    "error": bool(segment.get("error")),
                    "done": segment.get("done", True),
                })
    for log_entry in session.get("logs", []):
        command = log_entry.get("command") or ""
        entries.append({
            "at": log_entry.get("at"),
            "name": command.split()[0] if command else (log_entry.get("phase") or "?"),
            "arg_summary": command,
            "output": log_entry.get("output") or log_entry.get("thought"),
            "error": log_entry.get("status") not in ("ok", "success"),
            "done": True,
        })
    entries.sort(key=lambda e: e["at"] or "")
    # Stable, position-based id -- entries are append-only (nothing ever reorders or gets removed
    # from the sources this flattens), so the same real entry keeps the same idx across repeated
    # calls as new ones land after it. interactive_log.html turns this into a real DOM id so
    # idiomorph (partials/re_triage_tab.html's morph-swap poll) can match each <details> to its own
    # PREVIOUS render and leave an operator-expanded card's open state alone, instead of the whole
    # list being torn down and rebuilt (and every open card silently re-closing) on every 3s poll.
    for idx, entry in enumerate(entries):
        entry["idx"] = idx
    return entries


@app.get("/api/session/{session_id}/interactive-log", response_class=HTMLResponse)
def interactive_log(request: Request, session_id: str) -> HTMLResponse:
    """The Interactive/Reverse-Engineering-mode "Logs" button (session.html) -- renders every tool
    the chat agent ran this session (plus, for RE mode, its own baseline-triage trace) as a
    chronological activity log, the Interactive/RE analog of Agent mode's Logs tab. Fetched fresh
    on each open into the log modal, not live-streamed."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    entries = _interactive_log_entries(session)
    logger.debug("api: interactive-log session_id=%s entries=%d", session_id, len(entries))
    return templates.TemplateResponse(request, "partials/interactive_log.html", {"entries": entries})


# Mirrors static/js/diagram_builder.js's own extractToolName exactly (kept in sync deliberately,
# same convention that file's own top comment already documents for session.html's "which subtask
# is active" heuristic) -- a native tool call's own _describe_command shape is "name({...})", a
# subprocess tool's is "toolname --flag value ..." OR "/usr/local/bin/toolname --flag value ..."
# (radare2/gdb/etc. run via their resolved absolute path, not a bare command name) -- matching the
# name(...) shape first, then taking just the basename of the first whitespace token, handles all
# three. Real, confirmed data-quality bug this fixes: the RE-triage node graph
# (_re_triage_graph_context below) showed a node labeled "/usr/local" (Jinja's own truncate(10)
# cutting "/usr/local/bin/radare2" at 10 chars) instead of "radare2" -- the full absolute path was
# being used as the "tool name" outright, not just its basename.
_RE_GRAPH_NATIVE_CALL_RE = re.compile(r"^([A-Za-z_]\w*)\(")


def _extract_tool_name_from_command(command: str | None) -> str | None:
    if not command:
        return None
    trimmed = command.strip()
    native_match = _RE_GRAPH_NATIVE_CALL_RE.match(trimmed)
    if native_match:
        return native_match.group(1)
    first_token = trimmed.split(None, 1)[0] if trimmed else None
    return first_token.rsplit("/", 1)[-1] if first_token else None


# TARGET reticle radius -- must match macros/re_triage_graph.html's own re-graph-target-node r=34
# exactly, since _rect_boundary_point below uses it to compute each edge's START point (the
# reticle's own boundary, not its center), the Python half of the "lines stop exactly at element
# edges" fix. Two numbers that have to agree across a .py/.html boundary is a real seam, but the
# graph's own viewBox (400x400, center 200,200) is just as fixed a shared constant already, on the
# same boundary, so this isn't a new kind of coupling -- just one more coordinate both sides read.
_RE_GRAPH_TARGET_RADIUS = 34.0
_RE_GRAPH_PILL_HEIGHT = 26.0
_RE_GRAPH_NAME_TRUNCATE_LEN = 14

# Coarse "which stage of a triage pass is this tool part of" lookup for the sweep-sequence strip
# (re_triage_tab.html) -- deliberately basename-keyed, matching exactly what
# _extract_tool_name_from_command already reduces every logged command to, so a tool newly added
# to setup_tools.sh only needs one line here, not a parallel naming scheme. Ordered because the
# strip reads left-to-right as the RE workflow's own natural progression (learn what the target
# even is -> read it statically -> watch it run -> automate the repetitive part) -- a tool that
# doesn't match any bucket just never lights one up, it isn't forced into a wrong one.
_RE_GRAPH_STAGES: list[tuple[str, str, frozenset[str]]] = [
    ("profile", "Profiling", frozenset({"record_target_profile", "query_playbook", "file", "strings"})),
    ("static", "Static analysis", frozenset({"radare2", "jadx", "ilspycmd", "apktool", "binwalk", "heimdall", "objdump", "readelf", "nm"})),
    ("dynamic", "Dynamic analysis", frozenset({"gdb", "frida", "frida-trace", "wine", "strace", "ltrace"})),
    ("automation", "Custom automation", frozenset({"custom_re_script"})),
]


def _re_graph_tool_label(name: str, count: int) -> str:
    """Same truncation Jinja's `truncate(14, true, "")` performs (killwords, no ellipsis, and --
    Jinja's own `leeway=5` default -- only actually cuts a name longer than 14+5=19 chars), moved
    here so the label text used for the tag itself and the pill-width math below (which needs to
    know the REAL rendered text, not the untruncated tool name) can never drift apart the way a
    macro computing its own width from a differently-truncated string once did."""
    truncated = name if len(name) <= _RE_GRAPH_NAME_TRUNCATE_LEN + 5 else name[:_RE_GRAPH_NAME_TRUNCATE_LEN]
    return f"{truncated} ×{count}"


def _re_graph_pill_width(label_text: str) -> float:
    return max(len(label_text) * 6.4 + 20, 46.0)


def _re_graph_rect_boundary_point(cx: float, cy: float, cos_a: float, sin_a: float, half_w: float, half_h: float) -> tuple[float, float]:
    """Where the radial line from the reticle through this pill's own CENTER actually crosses the
    pill's rectangular boundary -- the real fix for "lines don't stop at the element, they run
    underneath it": the old markup drew every edge straight to (node.x, node.y), i.e. the pill's
    center, banking entirely on later paint order (the pill rect is drawn after the line) to hide
    the overlap rather than the line actually ending where the shape does. Standard ray-from-
    rect-center-to-boundary formula: the boundary is `t` units back from the center along the
    incoming direction, where `t` is however far you can go before hitting either the left/right
    or top/bottom edge first, whichever the ray reaches sooner."""
    denom = max(abs(cos_a) / half_w if half_w else 0.0, abs(sin_a) / half_h if half_h else 0.0)
    t = (1.0 / denom) if denom else 0.0
    return (cx - t * cos_a, cy - t * sin_a)


def _re_triage_graph_context(session: dict) -> dict:
    """Live node-graph data for partials/re_triage_stage.html's own visual (a real, confirmed
    operator ask: "хоть какой-то визуал" instead of a bare spinner while the baseline triage pass
    runs) -- one node per DISTINCT tool session["logs"] shows has actually been called so far,
    radiating around a center node for the target itself, re-computed fresh on every 3s poll
    (partials/re_triage_stage.html's own hx-trigger) alongside the rest of that fragment.

    Honest about what "live" means here: session["logs"] only ever gets an entry once a tool call
    has fully RESOLVED (agent/core.py's _append_log is called with the already-final status, never
    a separate "started" event) -- there is no real "this tool is running right now this instant"
    signal available from the data this reads. "is_latest" (the most recently resolved call, by log
    step) gets a distinct pulsing visual treatment as the closest honest proxy for "something just
    happened here", not a claim that tool is still actively running at the exact moment this
    renders.

    Also returns edge_x1/y1/x2/y2 per node (the reticle's own boundary to the pill's own boundary,
    not center-to-center -- see _re_graph_rect_boundary_point), an "order" (1-based, first-use
    order, doubling as the discovery sequence a plain radial layout otherwise has no way to show),
    "has_error" (any call to that tool that didn't resolve ok/success), and a stage-sequence strip
    (_RE_GRAPH_STAGES) so the graph can honestly show "what's already been touched" plus, only ever
    framed as such, "which stage hasn't been touched yet" -- never a claim about which SPECIFIC
    tool runs next, which nothing in this data can actually support.
    """
    logs = session.get("logs") or []
    tool_order: list[str] = []
    tool_counts: dict[str, int] = {}
    tool_errors: dict[str, int] = {}
    latest_tool: str | None = None
    last_activity_at: str | None = None
    for entry in logs:
        name = _extract_tool_name_from_command(entry.get("command"))
        at = entry.get("at")
        if at and (last_activity_at is None or at > last_activity_at):
            last_activity_at = at
        if not name:
            continue
        if name not in tool_counts:
            tool_order.append(name)
            tool_counts[name] = 0
            tool_errors[name] = 0
        tool_counts[name] += 1
        if entry.get("status") not in ("ok", "success"):
            tool_errors[name] += 1
        latest_tool = name

    center = 200.0
    radius = 145.0
    half_h = _RE_GRAPH_PILL_HEIGHT / 2
    count = len(tool_order)
    nodes = []
    for i, name in enumerate(tool_order):
        # Start at the top (-90deg) and go clockwise, same convention a clock face uses -- purely
        # cosmetic, but a consistent starting point keeps node positions stable across polls
        # instead of jumping around as tools accumulate.
        angle = (-math.pi / 2) + (2 * math.pi * i / count) if count else 0.0
        cos_a, sin_a = math.cos(angle), math.sin(angle)
        node_x, node_y = center + radius * cos_a, center + radius * sin_a
        label_text = _re_graph_tool_label(name, tool_counts[name])
        pill_w = _re_graph_pill_width(label_text)
        edge_x2, edge_y2 = _re_graph_rect_boundary_point(node_x, node_y, cos_a, sin_a, pill_w / 2, half_h)
        nodes.append({
            "name": name,
            "x": round(node_x, 1),
            "y": round(node_y, 1),
            "count": tool_counts[name],
            "is_latest": name == latest_tool,
            "has_error": tool_errors[name] > 0,
            "order": i + 1,
            "label_text": label_text,
            "pill_w": round(pill_w, 1),
            "edge_x1": round(center + _RE_GRAPH_TARGET_RADIUS * cos_a, 1),
            "edge_y1": round(center + _RE_GRAPH_TARGET_RADIUS * sin_a, 1),
            "edge_x2": round(edge_x2, 1),
            "edge_y2": round(edge_y2, 1),
        })

    touched_tools = set(tool_order)
    stages = [
        {"key": key, "label": label, "active": bool(touched_tools & tools), "count": sum(tool_counts[t] for t in touched_tools & tools)}
        for key, label, tools in _RE_GRAPH_STAGES
    ]
    # "Next" is the first untouched stage AFTER the furthest one actually touched -- not just the
    # first untouched stage overall. A pass that jumped straight to static analysis without ever
    # calling record_target_profile has "skipped" Profiling, not "still has it coming next"; the
    # honest reading of that gap is "still hasn't reached Dynamic analysis", not "still hasn't done
    # Profiling" (which would already be behind where the operator actually is).
    active_indices = [i for i, s in enumerate(stages) if s["active"]]
    furthest_active = max(active_indices) if active_indices else -1
    next_marked = False
    for i, stage in enumerate(stages):
        if i > furthest_active and not stage["active"] and not next_marked:
            stage["is_next"] = True
            next_marked = True
        else:
            stage["is_next"] = False

    return {
        "graph_target_label": (session.get("target") or "")[:40],
        "graph_nodes": nodes,
        "graph_center": center,
        "graph_stages": stages,
        "graph_last_activity_at": last_activity_at,
    }


def _re_findings_context(session: dict) -> dict:
    """Shared render context for partials/interactive_findings.html, used by both the GET
    interactive-findings route and the POST re-reverify route below (so a re-verify's own response
    re-renders the exact same panel shape a plain refresh would). "index" pairs each finding with
    its 1-indexed position in the ORIGINAL (unreversed) session["findings"] order -- the exact same
    order agent/chat.py's _session_snapshot numbers F1/F2/... chat-reference tags from -- computed
    BEFORE reversing for newest-first display. Real bug this avoids: naively numbering the
    already-reversed list from the template's own loop.index would show a DIFFERENT F# than what
    typing "[F3]" in chat actually resolves to, silently mismatched."""
    findings = session.get("findings", [])
    indexed = [{"index": i, "finding": f} for i, f in enumerate(findings, start=1)]
    indexed.reverse()
    return {"findings": indexed, "session_id": session["session_id"], "session_status": session.get("status")}


@app.get("/api/session/{session_id}/interactive-findings", response_class=HTMLResponse)
def interactive_findings(request: Request, session_id: str) -> HTMLResponse:
    """The Interactive/Reverse-Engineering-mode Findings panel (session.html, revealed when the
    chat is collapsed) -- situational findings the chat agent recorded (agent/chat.py's
    record_finding), plus (for RE mode) whatever agent/core.py's run_re_triage/run_re_reverify
    recorded via the full native record_finding tool -- session["findings"] holds both shapes at
    once for an RE-mode session, the template's own field-by-field `{% if %}` guards handle a
    finding missing any given field either shape doesn't have. Fetched fresh each time the panel
    is opened. Newest first, so the most recent win is at the top."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    context = _re_findings_context(session)
    logger.debug("api: interactive-findings session_id=%s findings=%d", session_id, len(context["findings"]))
    return templates.TemplateResponse(request, "partials/interactive_findings.html", context)


@app.get("/api/session/{session_id}/re-summary-tab", response_class=HTMLResponse)
def re_summary_tab(request: Request, session_id: str) -> HTMLResponse:
    """The RE-mode Summary tab (session.html's re-info-tabbar) -- polled every 3s by session.html's
    own wrapper around this partial, same idiom as re-triage-tab/interactive-findings just above and
    below. Real, confirmed gap this closes: this tab used to be rendered directly, once, at page load
    (session.html's own `{% include %}`) with no route of its own at all -- correct at that instant,
    but never updated again without a full page reload, even though everything it shows (process
    efficiency, severity/verification breakdown, hypotheses summary, target profile) keeps changing
    for as long as the baseline triage pass or a re-verify keeps running in the background. Read-only
    (a plain load_session), same shape as re_triage_tab/interactive_findings."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: re-summary-tab session_id=%s status=%s", session_id, session.get("status"))
    return templates.TemplateResponse(request, "partials/re_summary_tab.html", {"session": session})


@app.get("/api/session/{session_id}/target-profile", response_class=HTMLResponse)
def target_profile(request: Request, session_id: str) -> HTMLResponse:
    """The RE-mode Target Profile panel (session.html, the "Reserved" pane next to Findings,
    revealed when the chat is collapsed) -- durable facts about the target (language, compiler,
    obfuscator, platform, version, ...) the agent/chat established via record_target_profile
    (agent/core.py). Same "fetched fresh each time the panel is opened" shape as
    interactive-findings just above -- this is a small, rarely-changing list, no live polling
    needed."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    facts = session.get("target_profile", [])
    logger.debug("api: target-profile session_id=%s facts=%d", session_id, len(facts))
    return templates.TemplateResponse(request, "partials/target_profile.html", {"facts": facts})


@app.get("/api/session/{session_id}/side-panel", response_class=HTMLResponse)
def session_side_panel(request: Request, session_id: str) -> HTMLResponse:
    """Agent-mode's collapsed-chat side panel (session.html, the reserved 30rem gutter that used
    to sit empty behind the chat panel once it's slid off-screen) -- Pulse status + the Pinned/
    Activity tab bodies. Polled every 3s by the panel's own wrapper, same idiom as re-summary-tab
    just above (read-only, a plain load_session, no write side effect of its own). Notes is
    deliberately NOT part of this fragment -- see partials/session_collapsed_panel.html's own
    comment for why a live poll must never touch that textarea."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return templates.TemplateResponse(request, "partials/session_side_panel.html", {"session": session})


@app.post("/api/session/{session_id}/notes", response_class=HTMLResponse)
def save_session_notes(request: Request, session_id: str, operator_notes: str = Form("")) -> HTMLResponse:
    """Agent-mode's collapsed-chat side panel Notes textarea -- a purely personal, per-session
    scratchpad (a lead to check later, a payload that didn't work), saved on blur/change
    (hx-swap="none", same "save a setting with no visible response" idiom settings.html's own
    toggles already use throughout). reload_merge_save (not a blind save_session of a stale
    in-memory dict) so this can never clobber a concurrent write from the agent loop itself while
    a scan is still live.

    session["operator_notes"] must NEVER be threaded into agent/chat.py's _session_snapshot or any
    prompt -- it's the one piece of state in this whole app that's deliberately never shown to the
    model. See tests/test_operator_notes_excluded_from_snapshot.py for the regression guard."""
    session = reload_merge_save(session_id, lambda s: s.__setitem__("operator_notes", operator_notes))
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: session-notes session_id=%s chars=%d", session_id, len(operator_notes))
    return HTMLResponse("")


@app.post("/api/session/{session_id}/pin", response_class=HTMLResponse)
def toggle_pinned_ref(request: Request, session_id: str, ref: str = Form(...)) -> HTMLResponse:
    """Toggles one F#/H#/R# id in/out of session["pinned_refs"] (macros/ui.html's chat_ref, opted
    into pinning at every finding/hypothesis/recon-target card in session_fragment.html) --
    reload_merge_save so this can't race a concurrent agent-loop save either. Returns the SAME
    chat_ref span re-rendered with its new state (partials/chat_ref_fragment.html) -- the clicked
    button's own hx-target="closest span"/hx-swap="outerHTML" replaces just itself; the side
    panel's own Pinned rail catches up on its next 3s poll (session_side_panel route above), no
    out-of-band swap needed for that."""
    def _toggle(s: dict) -> None:
        pinned_refs = s.setdefault("pinned_refs", [])
        if ref in pinned_refs:
            pinned_refs.remove(ref)
        else:
            pinned_refs.append(ref)

    session = reload_merge_save(session_id, _toggle)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    pinned = ref in (session.get("pinned_refs") or [])
    logger.debug("api: pin session_id=%s ref=%s pinned=%s", session_id, ref, pinned)
    return templates.TemplateResponse(request, "partials/chat_ref_fragment.html", {"ref": ref, "pinned": pinned, "session_id": session_id})


# Map tab's Attack Surface graph -- operator-authored (manual) nodes/edges and per-node drag
# positions, all merged into _build_attack_surface_graph's own output above. Every route here
# writes through reload_merge_save (same race-safety as save_session_notes/toggle_pinned_ref above)
# and returns an empty 200 body: static/js/attack_surface_graph.js does its own writing via fetch(),
# not htmx, and the next live SSE tick (or the same MutationObserver watching #session-stream for
# any other reason) is what actually refreshes the on-screen graph -- no second response format to
# keep in sync with the JSON blob's own shape.
def _map_manual(session: dict) -> dict:
    manual = session.setdefault("map_manual", {"nodes": [], "edges": [], "positions": {}})
    manual.setdefault("hidden_node_ids", [])
    return manual


def _current_map_node_ids(session: dict) -> set[str]:
    return {node["id"] for node in _build_attack_surface_graph(session)["nodes"]}


@app.post("/api/session/{session_id}/map/node")
def create_map_node(
    request: Request, session_id: str,
    label: str = Form(...), kind: str = Form("host"), notes: str = Form(""),
) -> JSONResponse:
    """Returns the created node's real data (id included) instead of an empty body -- the ONLY way
    attack_surface_graph.js can add it to the live cytoscape instance immediately on success. Real,
    confirmed operator complaint this fixes: adding/deleting a node used to feel laggy, not
    instant, because the only path to seeing it land was the next SSE tick (up to
    _SSE_POLL_INTERVAL_SECONDS=1s) re-rendering the WHOLE session fragment and the map's own
    MutationObserver noticing the data blob changed -- same "must apply live, not on next
    poll/reload" rule this project already applies to every other visual toggle."""
    if kind not in _MAP_NODE_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {_MAP_NODE_KINDS}")
    if not label.strip():
        raise HTTPException(status_code=400, detail="label is required")
    node_id = f"manual-{secrets.token_hex(8)}"

    def _create(s: dict) -> None:
        _map_manual(s)["nodes"].append({"id": node_id, "label": label.strip(), "kind": kind, "notes": notes})

    session = reload_merge_save(session_id, _create)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: map-create-node session_id=%s node_id=%s kind=%s", session_id, node_id, kind)
    return JSONResponse({"id": node_id, "label": label.strip(), "kind": kind, "notes": notes})


@app.post("/api/session/{session_id}/map/node/{node_id}/edit", response_class=HTMLResponse)
def edit_map_node(
    request: Request, session_id: str, node_id: str,
    label: str = Form(...), kind: str = Form("host"), notes: str = Form(""),
) -> HTMLResponse:
    if kind not in _MAP_NODE_KINDS:
        raise HTTPException(status_code=400, detail=f"kind must be one of {_MAP_NODE_KINDS}")
    if not label.strip():
        raise HTTPException(status_code=400, detail="label is required")

    def _edit(s: dict) -> None:
        nodes = _map_manual(s)["nodes"]
        target = next((n for n in nodes if n["id"] == node_id), None)
        if target is None:
            # Deliberately not a hard 404/400 here -- reload_merge_save's mutator has no way to
            # signal "not found" back out except raising, and raising mid-mutation would still
            # leave the reload/save cycle half-run. The route-level check right after this call
            # (session is None / node still missing) is what actually reports the error.
            return
        target["label"] = label.strip()
        target["kind"] = kind
        target["notes"] = notes

    session = reload_merge_save(session_id, _edit)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if not any(n["id"] == node_id for n in _map_manual(session)["nodes"]):
        raise HTTPException(status_code=404, detail="Manual node not found -- only operator-created nodes can be edited")
    logger.debug("api: map-edit-node session_id=%s node_id=%s", session_id, node_id)
    return HTMLResponse("")


@app.post("/api/session/{session_id}/map/node/{node_id}/delete", response_class=HTMLResponse)
def delete_map_node(request: Request, session_id: str, node_id: str) -> HTMLResponse:
    if not node_id.startswith("manual-"):
        raise HTTPException(status_code=400, detail="Only operator-created nodes can be deleted")

    def _delete(s: dict) -> None:
        manual = _map_manual(s)
        manual["nodes"] = [n for n in manual["nodes"] if n["id"] != node_id]
        # Cascade: a manual edge left pointing at a node that no longer exists is a real dangling
        # reference, not a hypothetical one -- every manual edge's source/target can ONLY be a
        # manual node id or a real recon-derived host id, and this node is gone from the former set.
        manual["edges"] = [e for e in manual["edges"] if e["source"] != node_id and e["target"] != node_id]
        manual["positions"].pop(node_id, None)

    session = reload_merge_save(session_id, _delete)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: map-delete-node session_id=%s node_id=%s", session_id, node_id)
    return HTMLResponse("")


@app.post("/api/session/{session_id}/map/edge")
def create_map_edge(
    request: Request, session_id: str,
    source: str = Form(...), target: str = Form(...), direction: str = Form("forward"),
    data_type: str = Form(""), volume: str = Form(""), format: str = Form(""),
    interval: str = Form(""), label: str = Form(""), notes: str = Form(""),
) -> JSONResponse:
    """Returns the created edge's real data (id included) instead of an empty body -- same
    "apply live, don't wait on the next SSE tick" reasoning as create_map_node above."""
    if direction not in _MAP_EDGE_DIRECTIONS:
        raise HTTPException(status_code=400, detail=f"direction must be one of {_MAP_EDGE_DIRECTIONS}")
    if source == target:
        raise HTTPException(status_code=400, detail="A connection needs two different nodes")

    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    valid_ids = _current_map_node_ids(session)
    if source not in valid_ids or target not in valid_ids:
        raise HTTPException(status_code=400, detail="Both nodes must already exist on the map")

    edge_id = f"manual-{secrets.token_hex(8)}"

    def _create(s: dict) -> None:
        _map_manual(s)["edges"].append({
            "id": edge_id, "source": source, "target": target, "direction": direction,
            "data_type": data_type, "volume": volume, "format": format, "interval": interval,
            "label": label, "notes": notes,
        })

    session = reload_merge_save(session_id, _create)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: map-create-edge session_id=%s edge_id=%s %s->%s", session_id, edge_id, source, target)
    return JSONResponse({
        "id": edge_id, "source": source, "target": target, "direction": direction,
        "data_type": data_type, "volume": volume, "format": format, "interval": interval,
        "label": label, "notes": notes,
    })


@app.post("/api/session/{session_id}/map/edge/{edge_id}/edit", response_class=HTMLResponse)
def edit_map_edge(
    request: Request, session_id: str, edge_id: str,
    direction: str = Form("forward"), data_type: str = Form(""), volume: str = Form(""),
    format: str = Form(""), interval: str = Form(""), label: str = Form(""), notes: str = Form(""),
) -> HTMLResponse:
    if direction not in _MAP_EDGE_DIRECTIONS:
        raise HTTPException(status_code=400, detail=f"direction must be one of {_MAP_EDGE_DIRECTIONS}")

    def _edit(s: dict) -> None:
        target_edge = next((e for e in _map_manual(s)["edges"] if e["id"] == edge_id), None)
        if target_edge is None:
            return
        target_edge.update(direction=direction, data_type=data_type, volume=volume, format=format,
                            interval=interval, label=label, notes=notes)

    session = reload_merge_save(session_id, _edit)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if not any(e["id"] == edge_id for e in _map_manual(session)["edges"]):
        raise HTTPException(status_code=404, detail="Manual connection not found -- only operator-created connections can be edited")
    logger.debug("api: map-edit-edge session_id=%s edge_id=%s", session_id, edge_id)
    return HTMLResponse("")


@app.post("/api/session/{session_id}/map/edge/{edge_id}/delete", response_class=HTMLResponse)
def delete_map_edge(request: Request, session_id: str, edge_id: str) -> HTMLResponse:
    def _delete(s: dict) -> None:
        manual = _map_manual(s)
        manual["edges"] = [e for e in manual["edges"] if e["id"] != edge_id]

    session = reload_merge_save(session_id, _delete)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: map-delete-edge session_id=%s edge_id=%s", session_id, edge_id)
    return HTMLResponse("")


@app.post("/api/session/{session_id}/map/position", response_class=HTMLResponse)
def save_map_position(request: Request, session_id: str, node_id: str = Form(...), x: float = Form(...), y: float = Form(...)) -> HTMLResponse:
    """Called on every drag-release (attack_surface_graph.js's own 'dragfree' handler) for BOTH
    auto and manual nodes -- this is the entire mechanism behind "the map survives a page reload":
    without it, cytoscape's own in-memory node positions live only in that one browser tab's JS
    heap and are gone the instant the operator hits F5."""
    def _save(s: dict) -> None:
        _map_manual(s)["positions"][node_id] = {"x": x, "y": y}

    session = reload_merge_save(session_id, _save)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return HTMLResponse("")


@app.post("/api/session/{session_id}/map/node/{node_id}/hide", response_class=HTMLResponse)
def hide_map_node(request: Request, session_id: str, node_id: str, hidden: bool = Form(True)) -> HTMLResponse:
    """Real recon-derived nodes are re-derived fresh from recon_result/findings on every render --
    there's nothing to actually delete, so the right-click "Remove from map" action on one of those
    (attack_surface_graph.js's context menu) hides it instead, a pure display preference. Manual
    nodes use real deletion (delete_map_node above) since they ARE the underlying record."""
    def _set_hidden(s: dict) -> None:
        manual = _map_manual(s)
        ids = set(manual["hidden_node_ids"])
        if hidden:
            ids.add(node_id)
        else:
            ids.discard(node_id)
        manual["hidden_node_ids"] = sorted(ids)

    session = reload_merge_save(session_id, _set_hidden)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: map-hide-node session_id=%s node_id=%s hidden=%s", session_id, node_id, hidden)
    return HTMLResponse("")


@app.post("/api/session/{session_id}/map/unhide-all", response_class=HTMLResponse)
def unhide_all_map_nodes(request: Request, session_id: str) -> HTMLResponse:
    session = reload_merge_save(session_id, lambda s: _map_manual(s).__setitem__("hidden_node_ids", []))
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return HTMLResponse("")


@app.post("/api/session/{session_id}/open-target-folder", response_class=HTMLResponse)
def open_target_folder(request: Request, session_id: str) -> HTMLResponse:
    """RE mode's "Open target folder" button (session.html's Target Profile header) -- one row per
    session["target"] entry (comma-separated for a multi-target project, see
    agent/tools/builders/re_target.py). See projects.paths.resolve_open_target's own docstring for
    why this never spawns Windows Explorer directly under WSL2."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    targets = [t.strip() for t in (session.get("target") or "").split(",") if t.strip()]
    results = [resolve_open_target(Path(t)) for t in targets]
    logger.debug("api: open-target-folder session_id=%s targets=%d kinds=%s", session_id, len(targets), [r["kind"] for r in results])
    return templates.TemplateResponse(request, "partials/open_target_folder_result.html", {"results": results})


@app.get("/api/session/{session_id}/re-triage-stage", response_class=HTMLResponse)
def re_triage_stage(request: Request, session_id: str) -> HTMLResponse:
    """Polled every 3s by partials/re_triage_stage.html's own hx-trigger while a Reverse
    Engineering session's baseline triage pass is still running -- re-renders that exact same
    partial fresh, so the moment session["status"] flips away from pending/processing this
    response naturally contains the real chat panel (partials/chat_panel.html) instead of the
    spinner, with no hx-trigger of its own on the swapped-in content, which is what makes htmx
    stop polling once it's no longer needed. Read-only (a plain load_session), same "purely a
    status read" reasoning as interactive_findings just below -- doesn't touch the chat-vs-triage
    write race this placeholder exists to avoid."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    # Once status flips away from pending/processing, the {% else %} branch renders the real
    # chat_panel.html, which needs the full _chat_context (thread/provider/model picker state) --
    # not just a bare session dict, or that include throws (chat_panel.html reads `thread` at the
    # top of the message list unconditionally, confirmed live via a TestClient smoke test hitting
    # this exact route with a completed-status session).
    context = {"request": request, **_chat_context(session), **_re_triage_graph_context(session)}
    return templates.TemplateResponse(request, "partials/re_triage_stage.html", context)


# session_id -> the status last actually logged for its re-triage-tab poll, so the debug line
# below only fires again when status changes, not on every single 3s poll -- real, confirmed
# incident: this one line was ~87% of a whole session's debug.log (orrery-usr_38e422), the same
# "don't log trivial things" violation already fixed once for await_all_running_subagent_tasks's
# own polling line (agent/tools/subagent_tasks.py).
_LAST_LOGGED_RE_TRIAGE_TAB_STATUS: dict[str, str | None] = {}


@app.get("/api/session/{session_id}/re-triage-tab", response_class=HTMLResponse)
def re_triage_tab(request: Request, session_id: str) -> HTMLResponse:
    """The persistent "Triage" tab (session.html, RE mode only) -- unlike re_triage_stage above,
    this renders the SAME graph (_re_triage_graph_context reads purely from session["logs"], no
    status-gating inside it) plus a timeline (_interactive_log_entries, the same data
    partials/interactive_log.html's modal already shows) regardless of session status, so the
    visual doesn't just vanish the moment triage finishes/gets interrupted -- the real, confirmed
    operator complaint this closes. Only polls live (partials/re_triage_tab.html's own hx-trigger)
    while pending/processing; once triage isn't live there's nothing changing to poll for.

    Renders re_triage_tab_content.html (NOT the re_triage_tab.html shell session.html includes for
    the initial page load) -- that shell's own hx-swap="morph:innerHTML" morphs its children
    against this response body, so the response has to be the bare content, never a second copy of
    the shell's own id/hx-* attributes (see that file's own top comment for what returning the
    shell here used to break)."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    context = {
        "session": session,
        "entries": _interactive_log_entries(session),
        **_re_triage_graph_context(session),
    }
    status = session.get("status")
    if _LAST_LOGGED_RE_TRIAGE_TAB_STATUS.get(session_id) != status:
        _LAST_LOGGED_RE_TRIAGE_TAB_STATUS[session_id] = status
        logger.debug("api: re-triage-tab session_id=%s status=%s", session_id, status)
    return templates.TemplateResponse(request, "partials/re_triage_tab_content.html", context)


@app.post("/api/session/{session_id}/re-reverify", response_class=HTMLResponse)
def re_reverify(request: Request, session_id: str, background_tasks: BackgroundTasks, finding_title: str = Form("")) -> HTMLResponse:
    """The Reverse Engineering findings panel's own "Re-verify" (one finding, finding_title set)
    and "Re-verify all" (finding_title empty) buttons -- schedules agent/core.py's run_re_reverify
    as a background task, same "flip status, schedule, redirect/re-render" shape start_session's
    own Start button uses. Flips session["status"] to "processing" synchronously, before scheduling
    or rendering, so the panel this same response re-renders already shows the Re-verify button(s)
    disabled -- not just after the background task itself eventually gets around to it. Refuses to
    schedule a second concurrent pass if one is already running (triage or an earlier re-verify)
    for the same "never risk two writers on the same session" reasoning session.html's own
    chat-vs-triage gate already documents."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("mode") != "reverse_engineering":
        raise HTTPException(status_code=400, detail="Re-verify is only available for Reverse Engineering mode sessions")

    if session.get("status") not in ("pending", "processing"):
        titles = [finding_title.strip()] if finding_title.strip() else None
        session["status"] = "processing"
        save_session(session_id, session)
        background_tasks.add_task(_run_re_reverify_task, session_id, titles, session.get("llm_provider"))
        logger.debug("api: re-reverify session_id=%s finding_titles=%s", session_id, titles)
        session = load_session(session_id)

    return templates.TemplateResponse(request, "partials/interactive_findings.html", _re_findings_context(session))


@app.post("/api/session/{session_id}/approve-exploit", response_class=HTMLResponse)
def approve_exploit(request: Request, session_id: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    get_approval_event(session_id).set()
    logger.debug("api: approve-exploit session_id=%s", session_id)
    return HTMLResponse(_render_fragment(request, session))


@app.post("/api/session/{session_id}/deny-exploit", response_class=HTMLResponse)
def deny_exploit(request: Request, session_id: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    # Same wait_for the approve route wakes up (get_approval_event) — the exploit_denied flag,
    # checked in agent/core.py's _await_exploit_approval right after that wait returns, is what
    # actually decides the outcome was a denial and not an approval.
    session["exploit_denied"] = True
    save_session(session_id, session)
    get_approval_event(session_id).set()
    logger.debug("api: deny-exploit session_id=%s", session_id)
    return HTMLResponse(_render_fragment(request, load_session(session_id) or session))


@app.post("/api/session/{session_id}/deep-dive", response_class=HTMLResponse)
def deep_dive(request: Request, session_id: str, background_tasks: BackgroundTasks, finding_title: str = Form("")) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    findings = session.get("findings", [])
    index = next((i for i, f in enumerate(findings) if f.get("title") == finding_title), None)
    if index is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    if session.get("status") in _ORPHANABLE_STATUSES or session.get("status") == "pending":
        # Something is already running this session's run_session() loop — queuing is the only
        # safe option, a second concurrent writer to the same session file is a real race.
        get_instruction_queue(session_id).put_nowait({"type": "deep_dive", "finding_title": finding_title})
        message = "Queued — the agent will prioritize this finding next, then resume the rest."
        logger.debug("api: deep-dive session_id=%s finding=%r queued (session is live)", session_id, finding_title)
    else:
        # Nothing else is touching this session file right now — safe to run as its own
        # BackgroundTask instead of just queuing into a loop that isn't there to consume it.
        background_tasks.add_task(run_focused_exploit, session_id, finding_title)
        message = "Started — check the finding's activity log below shortly."
        logger.debug("api: deep-dive session_id=%s finding=%r started (session was idle)", session_id, finding_title)

    return templates.TemplateResponse(request, "partials/deep_dive_response.html", {"message": message, "finding_index": index})


@app.post("/api/session/{session_id}/hypotheses", response_class=HTMLResponse)
def submit_hypothesis(
    request: Request, session_id: str, background_tasks: BackgroundTasks,
    raw_text: str = Form(""), hypothesis_id: str = Form(""),
) -> HTMLResponse:
    """The Hypotheses tab's own submit form — same live-vs-idle branch as deep_dive above, for the
    identical reason (a second concurrent writer to the same session file is a real race while
    run_session()'s own loop is active). Deliberately NOT routed through the chat panel's LLM-based
    intent classification (agent/chat.py's _handle_tool_calls) to decide WHAT the operator wants —
    a single free-text box, but the routing decision itself (queue vs. background task) is still
    plain code, not a second LLM call; only splitting the raw text into a clean {text, evidence}
    pair (agent/core.py's _structure_hypothesis_text) is LLM-backed, and that happens downstream
    (inside _drain_pending_hypotheses when live, inside run_hypothesis_verification when idle) —
    never blocking this route itself.

    Two mutually-independent inputs, either can be set alone: raw_text (a brand-new suspicion —
    can be a one-liner or a whole paste copied from a different scan's finding) and hypothesis_id
    ("Investigate now" on an existing open one). Unlike the earlier version of this route,
    hypothesis_id works in BOTH branches now, not idle-only — a live session queues a same-turn
    priority nudge instead of rejecting the click, so the button behaves identically regardless of
    session state (no more "sometimes there, sometimes not" for the operator to puzzle over).
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    clean_raw_text = raw_text.strip()
    clean_hypothesis_id = hypothesis_id.strip()
    if not clean_raw_text and not clean_hypothesis_id:
        raise HTTPException(status_code=400, detail="raw_text is required")

    # "Prioritize now"/"Investigate now" on an existing open hypothesis: mark it priority_requested
    # so the card renders a disabled, greyed-out "Queued" button instead of the live one until the
    # agent actually picks it up (cleared in agent/core.py's _drain_pending_hypotheses when live,
    # run_hypothesis_verification when idle). Real operator complaint this fixes: the button gave no
    # visible sign a click registered, so it was unclear whether anything happened — and nothing
    # stopped re-clicking it, queueing a fresh nudge every time.
    if clean_hypothesis_id:
        target_hypothesis = next(
            (h for h in session.get("hypotheses", []) if h.get("id") == clean_hypothesis_id), None,
        )
        if target_hypothesis is not None:
            target_hypothesis["priority_requested"] = True
            save_session(session_id, session)

    is_live = session.get("status") in _ORPHANABLE_STATUSES or session.get("status") == "pending"
    if is_live:
        if clean_hypothesis_id:
            get_instruction_queue(session_id).put_nowait({"type": "prioritize_hypothesis", "hypothesis_id": clean_hypothesis_id})
            logger.debug("api: hypotheses session_id=%s hypothesis_id=%r prioritized (session is live)", session_id, clean_hypothesis_id)
        else:
            get_instruction_queue(session_id).put_nowait({"type": "add_hypothesis", "raw_text": clean_raw_text})
            logger.debug("api: hypotheses session_id=%s raw_text=%r queued (session is live)", session_id, clean_raw_text)
    else:
        background_tasks.add_task(
            run_hypothesis_verification, session_id, clean_raw_text, clean_hypothesis_id or None,
        )
        logger.debug(
            "api: hypotheses session_id=%s hypothesis_id=%r raw_text=%r verification started (session was idle)",
            session_id, clean_hypothesis_id or None, clean_raw_text,
        )

    return HTMLResponse(_render_fragment(request, load_session(session_id) or session))


@app.post("/api/session/{session_id}/recon/add", response_class=HTMLResponse)
def submit_recon_item(
    request: Request, session_id: str, background_tasks: BackgroundTasks,
    raw_text: str = Form(""),
) -> HTMLResponse:
    """The Recon tab's own "Add target or note" form — same live-vs-idle branch as submit_hypothesis
    above, for the identical reason (a second concurrent writer to the same session file is a real
    race while run_session()'s own loop is active). A single free-text box that accepts EITHER a new
    scope target (any format the New Project form's own Target(s) field accepts — validated the same
    way, agent/core.py's _classify_and_record_recon_item) OR a plain-language idea/lead (structured
    into a hypothesis the same way the Hypotheses tab's own box already does) — the classification
    itself happens downstream (inside _drain_pending_recon_notes when live, inside
    run_recon_note_investigation when idle), never blocking this route.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    clean_raw_text = raw_text.strip()
    if not clean_raw_text:
        raise HTTPException(status_code=400, detail="raw_text is required")

    is_live = session.get("status") in _ORPHANABLE_STATUSES or session.get("status") == "pending"
    if is_live:
        get_instruction_queue(session_id).put_nowait({"type": "add_recon_item", "raw_text": clean_raw_text})
        logger.debug("api: recon/add session_id=%s raw_text=%r queued (session is live)", session_id, clean_raw_text)
    else:
        background_tasks.add_task(run_recon_note_investigation, session_id, clean_raw_text)
        logger.debug("api: recon/add session_id=%s raw_text=%r investigation started (session was idle)", session_id, clean_raw_text)

    return HTMLResponse(_render_fragment(request, load_session(session_id) or session))


@app.post("/api/session/{session_id}/credentials/add", response_class=HTMLResponse)
def add_manual_credential(
    request: Request, session_id: str,
    username: str = Form(...), password: str = Form(""), found_on_host: str = Form(""),
    email: str = Form(""), login_url: str = Form(""), cookie: str = Form(""), authorization_header: str = Form(""),
) -> HTMLResponse:
    """The Recon tab's Credentials card own "Add credential" form -- for a login the operator
    already has (typed in at any point mid-engagement, not just at project creation) or one
    obtained outside this app's own tool loop entirely. Recorded straight into
    session["asset_graph"]["credentials"] with source_tool="manual" -- the SAME structure
    agent/core.py's _update_asset_graph builds for a tool-discovered credential, so the Credentials
    card's two tables (provided by the operator vs. obtained by the agent) render off one shared
    list/shape, just filtered by source_tool, never a second parallel structure to keep in sync.
    Also registered into this project's own credential store (register_discovered_credential) so
    it's immediately usable via authenticated_request/idor_probe's own identity= lookup, exactly
    like a freshly cracked or self-registered one -- the operator shouldn't have to re-type
    something they just typed here a second time into a New Project field that no longer exists
    for an already-running project.

    A direct reload_merge_save, not routed through the live-vs-idle instruction-queue dance
    submit_recon_item/submit_hypothesis above use -- this never needs the agent to classify or act
    on anything, it's a plain, immediate, human-authored fact about this project.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    clean_username = username.strip()
    if not clean_username:
        raise HTTPException(status_code=400, detail="username is required")

    graph = session.get("asset_graph", {}).get("credentials", [])
    identity_name = f"manual_{sum(1 for c in graph if c.get('source_tool') == 'manual') + 1}"
    clean_login_url = login_url.strip() or None
    clean_email = email.strip() or None
    clean_cookie = cookie.strip() or None
    clean_authorization_header = authorization_header.strip() or None

    register_discovered_credential(
        session_id, identity_name, clean_username, password, clean_login_url,
        email=clean_email, cookie=clean_cookie, authorization_header=clean_authorization_header,
    )

    entry = {
        "id": secrets.token_hex(6),
        "username": clean_username, "password": password,
        "found_on_host": found_on_host.strip() or "(not specified)",
        "source_tool": "manual",
        "identity_name": identity_name,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "suggested_hosts": [],
    }

    def _add(s: dict) -> None:
        s.setdefault("asset_graph", {}).setdefault("credentials", []).append(entry)

    updated = reload_merge_save(session_id, _add)
    if updated is None:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: credentials-add session_id=%s identity=%s found_on_host=%r", session_id, identity_name, entry["found_on_host"])
    return HTMLResponse(_render_fragment(request, updated))


@app.post("/api/session/{session_id}/identity/{identity_name}/reveal/{field}", response_class=HTMLResponse)
def reveal_identity_field_route(request: Request, session_id: str, identity_name: str, field: str) -> HTMLResponse:
    """One explicit-click reveal of a single configured-identity field (Recon tab's Credentials
    card, macros/ui.html's masked_identity_field()) -- the only place a real value from
    data/credentials/<session_id>.json ever reaches a rendered page. Every subsequent show/hide
    toggle for this SAME field is pure client-side after this (static/js/identity_reveal.js), so
    this fires at most once per field per page load, not once per toggle.
    """
    if load_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")
    value = reveal_identity_field(session_id, identity_name, field)
    if value is None:
        raise HTTPException(status_code=404, detail="No such identity/field, or it's empty")
    logger.debug("api: identity-reveal session_id=%s identity=%s field=%s", session_id, identity_name, field)
    return templates.TemplateResponse(request, "partials/identity_field_reveal.html", {"value": value})


@app.post("/api/session/{session_id}/program-url", response_class=HTMLResponse)
def update_program_url(
    request: Request, session_id: str, background_tasks: BackgroundTasks, program_url: str = Form(""),
) -> HTMLResponse:
    """Overview tab's own editable "Program URL" field, including its "Recheck now" button (which
    just re-posts the current value unchanged) -- lets the operator attach/change/clear the
    bug-bounty program this project belongs to at any time, not just via the New Project wizard.
    Uses reload_merge_save (sessions/store.py), not a blind load-mutate-save, since this can be
    clicked while a scan is live and racing agent/core.py's own program_url-driven phase hook.

    Changing the URL resets program_check to its blank shape so the Overview tab's own "Last
    checked" never shows a stale timestamp against a program it no longer points at; an unchanged
    URL (the plain "Recheck now" case) leaves the cached snapshot in place until the background
    refresh below actually replaces it. Never blocks: the refresh itself always runs as a
    background task, exactly like verify_all_hypotheses above -- this route only re-renders the
    session as it is right now, the fresher "last checked" appears once that task finishes.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    clean_url = _clean_program_url(program_url)
    if program_url.strip() and not clean_url:
        raise HTTPException(status_code=400, detail=f"{program_url!r} doesn't look like a valid http(s) URL.")
    url_changed = clean_url != (session.get("program_url") or "")

    def _apply(fresh: dict) -> None:
        fresh["program_url"] = clean_url
        if url_changed:
            fresh["program_check"] = {"last_checked": None, "last_error": None, "disclosed_reports_text": "", "disclosed_reports_checked_at": None}

    updated = reload_merge_save(session_id, _apply)
    logger.debug("api: program-url session_id=%s program_url=%r url_changed=%s", session_id, clean_url, url_changed)
    if clean_url:
        background_tasks.add_task(refresh_program_check, session_id, clean_url, force=True)

    return HTMLResponse(_render_fragment(request, updated or session))


@app.post("/api/session/{session_id}/hypotheses/verify-all", response_class=HTMLResponse)
def verify_all_hypotheses(request: Request, session_id: str, background_tasks: BackgroundTasks) -> HTMLResponse:
    """The Hypotheses tab's "Verify/recheck all" button — every hypothesis on the session, first to
    last (agent/core.py's run_all_hypotheses_verification), not just the "Investigate now" button's
    one-at-a-time single-item pass. Idle-only, unlike submit_hypothesis's own live-vs-idle branch
    above: queuing N separate instructions for a running session's own loop to drain one at a time
    has no equivalent to run_all_hypotheses_verification's own sequential, stop-aware loop, and
    reusing the queue here would mean reimplementing that loop a second time inside
    _drain_pending_hypotheses for no real benefit — an operator can already just wait for the live
    run to finish, then click this once it's idle.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") in _ORPHANABLE_STATUSES or session.get("status") == "pending":
        raise HTTPException(status_code=409, detail="Session is still running — wait for it to finish before verifying all hypotheses.")

    background_tasks.add_task(run_all_hypotheses_verification, session_id)
    logger.debug("api: verify-all-hypotheses session_id=%s started (%d hypotheses)", session_id, len(session.get("hypotheses", [])))
    return HTMLResponse(_render_fragment(request, session))


@app.post("/api/session/{session_id}/findings/verify-all", response_class=HTMLResponse)
def verify_all_findings(request: Request, session_id: str, background_tasks: BackgroundTasks) -> HTMLResponse:
    """The Findings tab's "Verify/recheck all" button — same shape as verify_all_hypotheses above,
    built on run_all_findings_verification (agent/core.py), which loops the existing Deep dive
    mechanism (run_focused_exploit) across every finding instead of one at a time by hand."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") in _ORPHANABLE_STATUSES or session.get("status") == "pending":
        raise HTTPException(status_code=409, detail="Session is still running — wait for it to finish before verifying all findings.")

    background_tasks.add_task(run_all_findings_verification, session_id)
    logger.debug("api: verify-all-findings session_id=%s started (%d findings)", session_id, len(session.get("findings", [])))
    return HTMLResponse(_render_fragment(request, session))


@app.post("/api/session/{session_id}/start")
def start_session(session_id: str, background_tasks: BackgroundTasks) -> Response:
    """The Overview tab's own "Start" button -- the second, deliberate step start_scan's "Create"
    no longer takes on its own (see that route's own comment): a project sitting in status=
    "created" has been reviewed but never run. Same "flip status, schedule in the background,
    then redirect" shape as resume_session, using this exact session's own persisted llm_provider
    (start_scan's resolved_provider, saved at creation time specifically so this route doesn't
    need to ask again)."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") != "created":
        raise HTTPException(status_code=400, detail="Session has already been started")

    session["status"] = "pending"
    save_session(session_id, session)
    logger.debug("api: start session_id=%s llm_provider=%s", session_id, session.get("llm_provider"))
    # Reverse Engineering mode runs a single bounded triage pass (run_re_triage), never the
    # recon/analyze/exploit/chain/validate loop run_session drives -- see agent/core.py's
    # run_re_triage docstring for why that pipeline shape doesn't fit this mode.
    if session.get("mode") == "reverse_engineering":
        background_tasks.add_task(_run_re_triage_task, session_id, session.get("llm_provider"))
    else:
        background_tasks.add_task(_run_session_task, session_id, session.get("llm_provider"))
    # Same shape as a fresh scan used to be end-to-end (start_scan) and as resume_session still is
    # -- "go do more work, then go watch it", not an in-place fragment swap.
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/enqueue")
def enqueue_session_route(session_id: str) -> Response:
    """Fleet mode's own alternative to Start above -- queues this "created" project instead of
    starting it immediately; _fleet_worker_loop starts it later, once real capacity is free
    (FLEET_MAX_CONCURRENT_SESSIONS). Same "created" precondition as start_session — a project
    that's already running (or already queued, or already finished) has nothing left to queue."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") != "created":
        raise HTTPException(status_code=400, detail="Session has already been started")
    fleet_store.enqueue_session(session_id)
    logger.debug("api: session_id=%s queued for fleet mode", session_id)
    return RedirectResponse(url="/fleet", status_code=303)


@app.post("/api/fleet/{session_id}/dequeue")
def dequeue_session_route(session_id: str) -> Response:
    """The /fleet page's own "Cancel" button for a still-waiting queue entry -- the project itself
    is untouched (still sits in status="created", startable normally via Start or re-queued
    later), only its place in the fleet queue is removed."""
    if not fleet_store.dequeue_session(session_id):
        raise HTTPException(status_code=404, detail="Session is not in the fleet queue")
    logger.debug("api: session_id=%s removed from the fleet queue", session_id)
    return RedirectResponse(url="/fleet", status_code=303)


@app.get("/fleet", response_class=HTMLResponse)
def get_fleet(request: Request) -> HTMLResponse:
    """Fleet mode's own status page -- the queue (in start order) plus every currently
    fleet-relevant active session, so the operator can see the whole portfolio's throughput at a
    glance instead of checking each project individually. Pure read of existing state (the fleet
    queue file + list_session_summaries()'s already-cheap index) -- starting/stopping anything
    happens through the dedicated routes above, never from this page's own GET."""
    summaries_by_id = {s["session_id"]: s for s in list_session_summaries()}
    queue = [
        {"session_id": sid, "summary": summaries_by_id.get(sid)}
        for sid in fleet_store.load_fleet_queue()
    ]
    running = [
        s for s in summaries_by_id.values()
        if s["status"] in _ORPHANABLE_STATUSES or s["status"] == "pending"
    ]
    logger.debug("api: GET /fleet queue_depth=%d running=%d", len(queue), len(running))
    return templates.TemplateResponse(request, "fleet.html", {
        "queue": queue,
        "running": running,
        "max_concurrent": fleet_store.max_concurrent_sessions(),
    })


@app.post("/api/session/{session_id}/interrupt", response_class=HTMLResponse)
def interrupt_session(request: Request, session_id: str) -> HTMLResponse:
    """The session page's Stop button, gated behind its own confirm() dialog (session_fragment.html's
    hx-confirm) since this is a deliberate, hard-to-undo-in-the-moment operator decision, not a
    passive UI toggle. Only flips an in-memory signal (request_session_stop) -- the actual
    run_session()/run_focused_exploit() loop notices it at its own next safe checkpoint (agent/
    core.py's _llm_complete choke point, or an in-progress exploit-approval wait) and persists
    status="interrupted" itself; this route never writes the session file directly, which would
    race that loop's own read-modify-write cycle over the exact same file.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") not in _ORPHANABLE_STATUSES and session.get("status") != "pending":
        raise HTTPException(status_code=400, detail="Session is not currently running")
    request_session_stop(session_id)
    # current_session_id set around this one line so it lands in the session's own project-folder
    # debug.log, not just the global app log — real, confirmed incident this fixes: every one of
    # this file's own Stop/Pause/Resume/Rescan control-bar routes logged unqualified, so a
    # log-review pass of one specific session's own debug.log could never confirm whether the
    # operator's own click actually reached the server (123321123321222222-usr_3cb010).
    token = current_session_id.set(session_id)
    try:
        logger.debug("api: interrupt requested session_id=%s", session_id)
    finally:
        current_session_id.reset(token)
    return HTMLResponse(_render_fragment(request, session))


# Statuses run_re_triage can leave a session in that still have real, durable progress worth
# continuing from -- "paused"/"interrupted" (a deliberate Pause/Stop, or a real process crash the
# startup orphan-sweep caught) and "failed" (a real exception inside the tool loop), same
# reasoning as _RESUMABLE_STATUSES above but kept separate: that tuple is Agent-mode's own
# phase-based resume machinery (compute_resume_entry_point has no notion of RE triage's single
# bounded pass), and RE mode never produces a status Agent-mode's tuple would need to know about
# either -- reusing it would only couple two genuinely different resume mechanisms together.
_RE_RESUMABLE_STATUSES = ("paused", "interrupted", "failed")


@app.get("/api/session/{session_id}/re-triage/controls", response_class=HTMLResponse)
def re_triage_controls(request: Request, session_id: str) -> HTMLResponse:
    """Polled every 3s by partials/re_control_bar.html's own hx-trigger while a Reverse Engineering
    baseline triage pass is still pending/processing -- re-renders that exact control bar fresh so a
    background self-completion (the pass finishing on its own) immediately swaps the live Pause/Stop
    buttons for the terminal Resume/Re-scan set, instead of leaving a stale Stop hanging until a
    manual reload. The moment status flips to a terminal state the re-rendered partial no longer
    carries hx-trigger, so htmx stops polling -- same self-terminating mechanism re_triage_stage
    uses. Read-only (a plain load_session), doesn't touch the chat-vs-triage write race."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return templates.TemplateResponse(request, "partials/re_control_bar.html", {"session": session})


@app.post("/api/session/{session_id}/re-triage/stop")
def re_triage_stop(session_id: str) -> RedirectResponse:
    """RE mode's own Stop button -- same underlying request_session_stop signal /interrupt above
    uses, but this route (and pause/resume/rescan below) redirect back to the session page instead
    of returning an htmx fragment, matching the plain (non-htmx) form-submit convention
    session.html's own RE-mode block already established for its Start button (see that block's
    own comment for why -- a plain redirect already lands back on the exact page that needs to
    reflect the new status, no fragment swap needed)."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    # Idempotent on purpose: if the pass already stopped on its own (completed/interrupted/failed)
    # the operator's desired end state -- "not running" -- is already true, so a stale Stop click
    # is a no-op, not an error. Answering it with a raw HTTPException(400) here used to hand the
    # plain (non-htmx) form submit a bare {"detail": ...} JSON body, which the desktop webview then
    # rendered as a whole-page dead-end. Redirect back to the page instead -- it re-renders with the
    # real final status and the correct buttons. re_control_bar.html's own live poll is the other
    # half of this fix (it stops offering Stop once the pass ends, so this path gets hit far less).
    if session.get("status") not in _ORPHANABLE_STATUSES and session.get("status") != "pending":
        token = current_session_id.set(session_id)
        try:
            logger.debug("api: re-triage stop no-op session_id=%s status=%s", session_id, session.get("status"))
        finally:
            current_session_id.reset(token)
        return RedirectResponse(url=f"/session/{session_id}", status_code=303)
    set_re_stop_intent(session_id, "stop")
    request_session_stop(session_id)
    # current_session_id set around this line -- see interrupt_session's own comment above for why.
    token = current_session_id.set(session_id)
    try:
        logger.debug("api: re-triage stop requested session_id=%s", session_id)
    finally:
        current_session_id.reset(token)
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/re-triage/pause")
def re_triage_pause(session_id: str) -> RedirectResponse:
    """RE mode's own Pause button -- mechanically identical to Stop above (same
    request_session_stop signal), the only difference is the intent recorded for run_re_triage's
    own except branch to read (agent/core.py's set_re_stop_intent/pop_re_stop_intent), which
    decides whether the halted session lands on "paused" (resumable, operator meant to continue)
    vs "interrupted" (also resumable, but reads as a harder stop)."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    # Same idempotent reasoning as re_triage_stop above -- a stale Pause on an already-halted pass
    # redirects back to the page instead of dead-ending the webview on a raw 400 JSON body.
    if session.get("status") not in _ORPHANABLE_STATUSES and session.get("status") != "pending":
        token = current_session_id.set(session_id)
        try:
            logger.debug("api: re-triage pause no-op session_id=%s status=%s", session_id, session.get("status"))
        finally:
            current_session_id.reset(token)
        return RedirectResponse(url=f"/session/{session_id}", status_code=303)
    set_re_stop_intent(session_id, "pause")
    request_session_stop(session_id)
    # current_session_id set around this line -- see interrupt_session's own comment above for why.
    token = current_session_id.set(session_id)
    try:
        logger.debug("api: re-triage pause requested session_id=%s", session_id)
    finally:
        current_session_id.reset(token)
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/re-triage/resume")
def re_triage_resume(background_tasks: BackgroundTasks, session_id: str) -> RedirectResponse:
    """Continues a paused/interrupted/failed baseline triage pass -- see run_re_triage's own
    is_resume docstring for what "continues" actually means here (a fresh LLM conversation told
    what's already been established, not a literal replay of the prior one)."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    # Idempotent like stop/pause above: a stale Resume (the pass is already running again, or a
    # double-submit) redirects back to the page rather than dead-ending the webview on a raw 400.
    if session.get("status") not in _RE_RESUMABLE_STATUSES:
        token = current_session_id.set(session_id)
        try:
            logger.debug("api: re-triage resume no-op session_id=%s status=%s", session_id, session.get("status"))
        finally:
            current_session_id.reset(token)
        return RedirectResponse(url=f"/session/{session_id}", status_code=303)
    session["status"] = "pending"
    save_session(session_id, session)
    background_tasks.add_task(_run_re_triage_task, session_id, session.get("llm_provider"), True)
    # current_session_id set around this line -- see interrupt_session's own comment above for why.
    token = current_session_id.set(session_id)
    try:
        logger.debug("api: re-triage resume session_id=%s", session_id)
    finally:
        current_session_id.reset(token)
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/re-triage/rescan")
def re_triage_rescan(background_tasks: BackgroundTasks, session_id: str) -> RedirectResponse:
    """A deliberate extra baseline-triage pass after a clean completion -- same is_resume=True
    "informed restart" as re_triage_resume above (never blindly redoes analysis record_finding/
    record_target_profile already captured), offered separately from Resume since a completed
    session isn't "unfinished," the operator is choosing to run it again on purpose."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    # Idempotent like stop/pause/resume above: a stale Re-scan (pass already running again, or a
    # double-submit) redirects back to the page rather than dead-ending the webview on a raw 400.
    if session.get("status") != "completed":
        token = current_session_id.set(session_id)
        try:
            logger.debug("api: re-triage rescan no-op session_id=%s status=%s", session_id, session.get("status"))
        finally:
            current_session_id.reset(token)
        return RedirectResponse(url=f"/session/{session_id}", status_code=303)
    session["status"] = "pending"
    save_session(session_id, session)
    background_tasks.add_task(_run_re_triage_task, session_id, session.get("llm_provider"), True)
    # current_session_id set around this line -- see interrupt_session's own comment above for why.
    token = current_session_id.set(session_id)
    try:
        logger.debug("api: re-triage rescan session_id=%s", session_id)
    finally:
        current_session_id.reset(token)
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/stop-time-budget", response_class=HTMLResponse)
def stop_time_budget(request: Request, session_id: str) -> HTMLResponse:
    """Overview tab's "Stop timer" control — lets the operator remove a running session's own
    configured time budget WITHOUT stopping the whole scan (sibling to the Stop session button,
    which stops everything). Only meaningful while the session is actually live; queues the same
    way skip_finding/deep_dive already do (main.py's deep_dive route) rather than writing
    session.json directly, since a second concurrent writer to the same file while run_session()'s
    own loop is active is a real race — agent/core.py's _llm_complete consumes it every turn, so it
    takes effect essentially immediately rather than waiting for a full-pass boundary.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") not in _ORPHANABLE_STATUSES and session.get("status") != "pending":
        raise HTTPException(status_code=400, detail="Session is not currently running")
    if not session.get("time_budget_seconds"):
        raise HTTPException(status_code=400, detail="This session has no time budget set")
    get_instruction_queue(session_id).put_nowait({"type": "clear_time_budget"})
    logger.debug("api: stop-time-budget queued session_id=%s (session is live)", session_id)
    return HTMLResponse(_render_fragment(request, session))


@app.post("/api/session/{session_id}/resume")
def resume_session(session_id: str, background_tasks: BackgroundTasks, entry_point: str = Form("")) -> Response:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") not in _RESUMABLE_STATUSES:
        raise HTTPException(status_code=400, detail="Session is not in a resumable state")

    # The session page's resume form (session_fragment.html) lets the operator pick a specific
    # phase to re-run instead of always accepting the auto-detected one — e.g. re-doing Recon from
    # scratch instead of jumping straight to Analyze on whatever partial recon_result exists. An
    # invalid/missing choice (the Projects list's own resume button doesn't send one at all) falls
    # back to the same auto-detected phase orphaned-session recovery already uses.
    resolved_entry_point = entry_point if entry_point in VALID_ENTRY_POINTS else (session.get("resumable_from") or compute_resume_entry_point(session))
    session["status"] = "processing"
    save_session(session_id, session)
    logger.debug("api: resume session_id=%s entry_point=%s", session_id, resolved_entry_point)
    background_tasks.add_task(_run_session_task, session_id, None, resolved_entry_point)
    # Same shape as a fresh scan (start_scan) — resuming is "go do more work, then go watch it",
    # not an in-place fragment swap, so a plain redirect (not an HTMX partial) works from both
    # the sessions list and the session page itself without a fragment-shape mismatch.
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


# Matches a trailing "- Rescan N" this project's own rescan-name numbering appends -- used both to
# strip it back to the true root name (so rescanning a rescan numbers off the ORIGINAL name, never
# compounding into "X - Rescan 1 - Rescan 2") and to find the highest N already used for that root.
_RESCAN_NAME_SUFFIX_PATTERN = re.compile(r"\s*-\s*Rescan\s+(\d+)\s*$", re.IGNORECASE)


def _next_rescan_name(base_name: str) -> str:
    """Numbers a new-project rescan's own name off however many rescans of the SAME root project
    already exist -- "<name> - Rescan 1", then "<name> - Rescan 2", and so on. Real gap this closes:
    the old fixed "(rescan)" suffix gave every rescan of the same project the identical display
    name, impossible to tell apart in the Projects list once there was more than one. Only scans
    list_session_summaries() (the cheap cached index, not a full parse of every session.json) --
    same cost discipline every other Projects-list-adjacent read in this file already follows.
    """
    root = _RESCAN_NAME_SUFFIX_PATTERN.sub("", base_name).strip()
    existing_numbers = []
    for summary in list_session_summaries():
        name = summary.get("name") or ""
        match = _RESCAN_NAME_SUFFIX_PATTERN.search(name)
        if match and _RESCAN_NAME_SUFFIX_PATTERN.sub("", name).strip() == root:
            existing_numbers.append(int(match.group(1)))
    return f"{root} - Rescan {max(existing_numbers, default=0) + 1}"


@app.post("/api/session/{session_id}/rescan")
def rescan_session(
    session_id: str, goal: str = Form(""),
    time_budget_preset: str = Form(""), time_budget_custom_minutes: str = Form(""),
) -> Response:
    """Re-audits a project from scratch as a brand-new session, but treats its prior findings as
    claims to actively re-verify (agent/core.py's _run_reverify) rather than trust forward blindly
    — the old session is never mutated, staying a clean, independent audit record even if the new
    one goes wrong. Available regardless of the old session's status, not just "completed" — an
    interrupted/failed session's real, already-durable findings (recorded the instant they're
    found, never batched at phase end — see agent/core.py's module docstring) are exactly as valid
    a "known findings" baseline for _run_reverify to re-check as a cleanly completed scan's; a run
    that never finished isn't a reason to withhold a fresh, independent re-audit the operator
    explicitly asked for. Resume (continues the SAME session from where it stopped) stays the
    right choice when the goal is just finishing that one run, not starting an independent one.

    Only CREATES the new session, same create->review->start split start_scan already gives a
    brand-new project (initial_status="created", nothing scheduled here) -- the operator gets a
    chance to look at the fresh project before it actually starts running, via the same
    /api/session/{id}/start route (session_fragment.html's own "created" Start button). Previously
    this scheduled the scan in the same request that created it, with no review step at all.
    """
    old_session = load_session(session_id)
    if old_session is None:
        raise HTTPException(status_code=404, detail="Session not found")

    raw_targets = [t.strip() for t in old_session["target"].split(",") if t.strip()]
    new_session_id = create_session(
        old_session["target"],
        name=_next_rescan_name(old_session["name"]),
        enumerate_subdomains=bool(old_session.get("enumerate_subdomains")),
        qualifying_vulnerabilities=old_session.get("scope_rules", {}).get("qualifying", ""),
        non_qualifying_vulnerabilities=old_session.get("scope_rules", {}).get("non_qualifying", ""),
        custom_instructions=old_session.get("custom_instructions", ""),
        # From the rescan dialog's own Goal input (base.html), not old_session -- prefilled with
        # the old session's current goal via asraOpenRescanDialog's JS, but genuinely editable
        # right there, which is the only way to SET one for a project that predates this field, or
        # to change a stale one, since the New Project form's own fields are otherwise read-only
        # after creation.
        goal=goal,
        custom_user_agent=old_session.get("custom_user_agent", ""),
        custom_headers=old_session.get("custom_headers", ""),
        out_of_scope=old_session.get("out_of_scope") or [],
        out_of_scope_notes=old_session.get("out_of_scope_notes") or [],
        authorize_exploit=bool(old_session.get("authorize_exploit")),
        # Same "from the rescan dialog, not old_session" reasoning as goal above -- a brand-new
        # session's own started_at isn't set until run_session actually begins, so no special
        # elapsed-time correction is needed here the way rescan_session_in_place needs one below.
        time_budget_seconds=_resolve_time_budget_seconds(time_budget_preset, time_budget_custom_minutes),
        # Carried over from the old session -- start_scan's own resolved_provider would otherwise
        # be silently lost on rescan, forcing the new session back onto whatever create_session's
        # own default provider is instead of the operator's actual persisted choice.
        llm_provider=old_session.get("llm_provider"),
        # Carried over verbatim, same reasoning as llm_provider above -- a project's own per-project
        # Subagent narrowing (New Project form) shouldn't silently reset back to "every profile" on
        # its very first rescan just because create_session's own default is None.
        enabled_subagent_ids=old_session.get("enabled_subagent_ids"),
        # Create-only, same as start_scan's own new-project flow -- /api/session/{id}/start is the
        # deliberate second step that actually schedules the scan (see this route's own docstring).
        initial_status="created",
    )

    # Replays the exact same widening start_scan does, using the OLD session's real recorded
    # intent — safe and idempotent (add_allowed_target dedups). Old sessions that predate the
    # authorize_exploit field (.get returns None/falsy) simply don't get auto-widened: an honest,
    # conservative limitation, not a guess that could over-authorize a target the user never
    # actually intended to authorize for exploitation.
    if old_session.get("authorize_exploit"):
        authorize_exploit_targets(raw_targets, bool(old_session.get("enumerate_subdomains")))

    # Otherwise authenticated_request/authenticated_crawl/idor_probe silently lose their
    # configured identities on rescan — data/credentials/<id>.json is keyed by session_id, and the
    # new session has a brand new one. Purely additive: harmless if the old session never had one.
    old_credentials_path = _CREDENTIALS_DIR / f"{session_id}.json"
    if old_credentials_path.exists():
        _CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy(old_credentials_path, _CREDENTIALS_DIR / f"{new_session_id}.json")

    new_session = load_session(new_session_id)
    new_session["rescanned_from"] = session_id
    # Denormalized rather than looked up live at render time — the old session can be deleted
    # later (delete_session_route has no guard preventing that) and this project's own provenance
    # display must keep working regardless of what happens to the old one afterward.
    new_session["rescanned_from_name"] = old_session.get("name")
    new_session["rescanned_from_target"] = old_session.get("target")
    new_session["rescanned_from_created_at"] = old_session.get("created_at")
    # Frozen snapshot at rescan time — agent/core.py's _run_reverify works through this list once
    # and never again; the old session's own findings are never touched by anything that happens
    # to this new one.
    new_session["carried_over_findings"] = copy.deepcopy(old_session.get("findings") or [])
    new_session["reverification_history"] = []
    # Unlike reverification_history just above (reset every rescan purely for THIS pass's own
    # idempotency on resume), this ledger is never reset -- it's this lineage's actual cross-rescan
    # memory of what _run_reverify already found each time, carried forward so a finding re-checked
    # for the 3rd rescan running doesn't look like a totally fresh unknown (agent/core.py's own
    # prior_history_note/_previously_ruled_out_task_addendum are what read it back).
    new_session["past_reverification_outcomes"] = copy.deepcopy(old_session.get("past_reverification_outcomes") or [])
    # Carry the old session's recon straight over instead of re-discovering it from scratch — a
    # rescan of the same target has no reason to re-run nmap/dns_lookup/subfinder for hosts/ports it
    # already found. agent/core.py's _run_recon already has the "resumed recon phase" machinery
    # (existing_targets present -> the model is told exactly what's recorded and to not redo those
    # tool calls), which only ever kicked in for a same-session resume/in-place pass before; seeding
    # recon_result here is what makes a brand-new rescan session get the same treatment. deepcopy so
    # editing the new session never mutates the old audit record. asset_graph (discovered
    # credentials) rides along for the same reason — real, found data worth keeping, not re-earning.
    new_session["recon_result"] = reset_host_health_streaks_for_new_pass(
        copy.deepcopy(old_session.get("recon_result") or {})
    )
    new_session["asset_graph"] = copy.deepcopy(old_session.get("asset_graph") or {"credentials": []})
    # Hypotheses were silently dropped here before -- every open/confirmed/ruled_out lead from the
    # prior scan vanished the instant a brand-new rescan session was created, unlike findings/recon,
    # which already carried forward. past_hypothesis_outcomes is this lineage's own cross-rescan
    # memory of what got resolved and how (agent/core.py's _resolve_hypothesis writes to it,
    # _previously_resolved_hypotheses_task_addendum reads it back) -- never reset, same treatment as
    # past_reverification_outcomes above.
    new_session["hypotheses"] = copy.deepcopy(old_session.get("hypotheses") or [])
    new_session["past_hypothesis_outcomes"] = copy.deepcopy(old_session.get("past_hypothesis_outcomes") or [])
    # chain_attempts (the Chain phase's own hop-by-hop escalation trace) and map_manual (the only
    # actually-persisted part of the Map tab's attack-surface graph -- everything else there
    # recomputes fresh from recon_result/findings/hypotheses/asset_graph/chain_attempts on every
    # render) were both simply missing from this carry-forward block before -- a brand-new rescan
    # silently lost the operator's own manual map edits and the whole reasoning trail behind any
    # multi-step chain a prior pass found, keeping only the findings a chain happened to produce.
    new_session["chain_attempts"] = copy.deepcopy(old_session.get("chain_attempts") or [])
    new_session["map_manual"] = copy.deepcopy(old_session.get("map_manual") or {"nodes": [], "edges": [], "positions": {}})
    # The prior pass's plan, kept as the working roadmap but reset to "pending" so it reads as an
    # actionable to-do list for this pass rather than a wall of already-"done" entries (see
    # reset_plan_for_new_pass) — the agent refines/supplements it as each phase re-runs.
    new_session["plan"] = reset_plan_for_new_pass(old_session.get("plan"))
    save_session(new_session_id, new_session)

    logger.debug(
        "api: rescan old_session_id=%s new_session_id=%s target=%s carried_over_findings=%d "
        "carried_recon_targets=%d carried_plan_phases=%d carried_reverification_history=%d "
        "authorize_exploit=%s goal_set=%s time_budget_seconds=%s",
        session_id, new_session_id, old_session["target"], len(new_session["carried_over_findings"]),
        len(new_session["recon_result"].get("targets", [])), len(new_session["plan"].get("phases", [])),
        len(new_session["past_reverification_outcomes"]),
        bool(old_session.get("authorize_exploit")), bool(goal.strip()), new_session.get("time_budget_seconds"),
    )
    return RedirectResponse(url=f"/session/{new_session_id}", status_code=303)


# The Overview tab's own "Continue — dig deeper" button (continue_deeper_session below) defaults
# to this when the session has no goal of its own set yet -- _goal_task_addendum (agent/core.py)
# threads whatever goal is set into every phase's own task prompt (Recon/Analyze/Exploit alike),
# so a real default here is genuinely enough to make a fresh in-place pass behave like "look at
# everything found so far and actively try to get further," not just a passive re-verify.
_DEFAULT_CONTINUE_DEEPER_GOAL = (
    "Continue this engagement using everything already found (findings, hypotheses, recon data) "
    "as one holistic picture. Actively try to escalate and chain findings together toward real, "
    "demonstrable access/impact on the highest-value targets -- don't just re-verify what's "
    "already proven, keep investigating for whatever hasn't been tried yet too."
)


def _prepare_in_place_pass(session: dict) -> None:
    """The shared "one more in-place pass" prep both rescan_session_in_place and
    continue_deeper_session use — every finding/hypothesis/target already recorded stays right
    here (session["hypotheses"]/["recon_result"]["targets"] untouched), existing findings become
    THIS pass's own carried_over_findings for real re-verification (agent/core.py's _run_reverify),
    and session["findings"] is seeded back with a copy of the same findings (not left empty) tagged
    _carried_over_pending_reverify — real operator complaint this fixes: the Findings tab's own
    count badge used to crater to 0 the instant a pass started and only climb back up one at a time
    as _run_reverify worked through carried_over_findings, which can take 50+ minutes for ~10
    findings — during that whole window the operator was looking at an apparently-empty Findings
    tab with nothing explaining why. Lands on status="created", same create->review->start split
    every other session-producing route in this file uses (main.py's start_scan/rescan_session) —
    callers decide goal/time_budget_seconds themselves afterward, this only prepares the rest.
    """
    session["carried_over_findings"] = copy.deepcopy(session.get("findings") or [])
    session["findings"] = [
        {**copy.deepcopy(f), "_carried_over_pending_reverify": True}
        for f in session["carried_over_findings"]
    ]
    session["reverification_history"] = []
    # session["past_reverification_outcomes"] deliberately NOT reset here (unlike
    # reverification_history just above) -- it's this lineage's cross-rescan memory (see
    # rescan_session's own identical carry-forward, and agent/core.py's _run_reverify/_run_analyze
    # addenda that read it back), and this is the SAME session object, so leaving it untouched IS
    # carrying it forward.
    # recon_result/hypotheses stay exactly as they are (this is the same session) so a fresh pass
    # never re-discovers what's already known -- but the plan, if left untouched, would sit here with
    # every subtask still marked "done" from the pass that just finished, reading as complete/inert
    # for the whole new pass. Reset it (structure kept, statuses back to "pending") so it's an
    # actionable roadmap again the agent refines as each phase re-runs. Real symptom this fixes: an
    # in-place rescan's plan tab showing a fully-"done" plan that never came back to life.
    session["plan"] = reset_plan_for_new_pass(session.get("plan"))
    # Same reasoning as rescan_session's own new-project carry-forward: a host blocked "dead" by the
    # pass that just finished must not start THIS new pass already blocked with zero real attempt
    # made in it -- only the carried-forward streak is cleared, a genuinely-still-dead host re-blocks
    # on its own within this pass.
    session["recon_result"] = reset_host_health_streaks_for_new_pass(session.get("recon_result"))
    session["in_place_rescan_count"] = int(session.get("in_place_rescan_count") or 0) + 1
    session["last_rescanned_at"] = datetime.now(timezone.utc).isoformat()
    session["status"] = "created"


@app.post("/api/session/{session_id}/continue-deeper")
def continue_deeper_session(session_id: str) -> Response:
    """The Overview tab's own one-click "Continue — dig deeper" button: the same in-place "re-
    verify everything found, then keep digging" pass as /rescan-in-place (_prepare_in_place_pass),
    but with no dialog to fill in first. A session that already has a goal set keeps it untouched
    (still the operator's own real intent); one that doesn't gets _DEFAULT_CONTINUE_DEEPER_GOAL
    instead of staying silently generic — see that constant's own comment for why a goal alone is
    genuinely enough here, no new pipeline/entry_point required. time_budget_seconds is left
    exactly as it already was (no dialog to change it from), unlike /rescan-in-place's own explicit
    preset/custom fields.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") in _ORPHANABLE_STATUSES:
        raise HTTPException(status_code=400, detail="Session is currently running — stop or wait for it to finish first")
    # started_at is only ever set once run_session actually begins (never at plain creation) --
    # server-side twin of session_fragment.html's own `{% if session.started_at %}` gate on this
    # button, so a direct POST replay can't bypass it: nothing has been found yet for a project
    # that's never been started, so there's nothing real for an in-place pass to "dig deeper" into.
    if not session.get("started_at"):
        raise HTTPException(status_code=400, detail="This project hasn't been started yet — click Start first")

    _prepare_in_place_pass(session)
    if not (session.get("goal") or "").strip():
        session["goal"] = _DEFAULT_CONTINUE_DEEPER_GOAL
    save_session(session_id, session)

    logger.debug(
        "api: continue-deeper session_id=%s target=%s carried_over_findings=%d goal_defaulted=%s",
        session_id, session["target"], len(session["carried_over_findings"]),
        session["goal"] == _DEFAULT_CONTINUE_DEEPER_GOAL,
    )
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/rescan-in-place")
def rescan_session_in_place(
    session_id: str, goal: str = Form(""),
    time_budget_preset: str = Form(""), time_budget_custom_minutes: str = Form(""),
) -> Response:
    """The second rescan option (session_fragment.html's rescan dialog): re-audits this SAME
    project instead of spinning up an independent new one — every finding/hypothesis/target already
    recorded stays right here, visible to the fresh pass, instead of living in a second, separate
    project the operator now has to cross-reference by hand. Existing findings become THIS pass's
    own carried_over_findings and go through the exact same real re-verification agent/core.py's
    _run_reverify already gives a brand-new rescan project — same mechanism, just applied in place
    instead of to a duplicated session. session["hypotheses"]/["recon_result"]["targets"] are left
    completely untouched (never cleared), so the fresh Recon/Analyze pass sees them exactly as they
    already are, the same way a resumed session already would.

    Guarded against a session that's currently actually running (unlike /rescan, which always
    creates an independent session with nothing to race) — this mutates the SAME session file a
    live run_session() loop could be mid-write on, so it must never fire while one is in flight.
    Available for every OTHER status (completed/failed/interrupted/pending) — an in-place rescan is
    exactly as valid a next step for an interrupted run's own already-durable findings as a
    cleanly-completed one's.

    Only prepares this pass, same create->review->start split /rescan gives a brand-new project --
    lands on status="created" with nothing scheduled here, so the operator gets a chance to look at
    the fresh goal/time budget before it actually starts running, via the same
    /api/session/{id}/start route (session_fragment.html's own "created" Start button, whose copy
    branches on in_place_rescan_count to describe THIS case correctly). Previously this scheduled
    the pass in the same request that prepared it, with no review step at all.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") in _ORPHANABLE_STATUSES:
        raise HTTPException(status_code=400, detail="Session is currently running — stop or wait for it to finish first")

    # Same "frozen snapshot, _run_reverify works through it once and never again" contract as the
    # new-project /rescan route above — findings themselves move OUT of session["findings"] and
    # into carried_over_findings for real re-verification; Analyze/Exploit/Validate's own existing
    # dedup and skip-already-resolved logic is what naturally turns "re-verify everything, then
    # keep looking" into real behavior here, no new pipeline logic needed. Shared with
    # continue_deeper_session above (_prepare_in_place_pass) — everything except goal/
    # time_budget_seconds below is identical either way.
    _prepare_in_place_pass(session)
    # From the rescan dialog's own Goal input (base.html) -- overwrites this same session's goal
    # in place, prefilled with whatever it already was via asraOpenRescanDialog's JS, so this is
    # the only way to SET one for a project that predates this field, or update a stale one,
    # without retyping something that was never cleared.
    session["goal"] = goal.strip()
    # Same dialog, same "whatever's chosen wins, including explicitly clearing it" contract as
    # goal above -- but a straight overwrite of time_budget_seconds would be silently wrong here:
    # agent/core.py's _time_budget_deadline_timestamp computes started_at + time_budget_seconds,
    # and THIS session's own started_at can be arbitrarily old (this project may have finished
    # weeks ago) -- setting e.g. "2 more hours" verbatim would compute a deadline already long in
    # the past, and _time_budget_remaining would silently return False from the very first check,
    # making the "keep working the full budget" feature the operator just explicitly asked for do
    # nothing at all, with no error or indication anything was wrong. Grounding it in elapsed time
    # since started_at keeps _time_budget_deadline_timestamp's own formula untouched while making
    # the resolved duration actually mean "N more time from right now" regardless of how old this
    # project already is.
    resolved_time_budget_seconds = _resolve_time_budget_seconds(time_budget_preset, time_budget_custom_minutes)
    if resolved_time_budget_seconds is not None:
        elapsed_seconds = 0
        started_at_raw = session.get("started_at")
        if started_at_raw:
            try:
                elapsed_seconds = max(0, int(time.time() - datetime.fromisoformat(started_at_raw).timestamp()))
            except ValueError:
                elapsed_seconds = 0
        session["time_budget_seconds"] = elapsed_seconds + resolved_time_budget_seconds
    else:
        session["time_budget_seconds"] = None
    save_session(session_id, session)

    logger.debug(
        "api: rescan-in-place session_id=%s target=%s carried_over_findings=%d pass=%d goal_set=%s time_budget_seconds=%s",
        session_id, session["target"], len(session["carried_over_findings"]), session["in_place_rescan_count"],
        bool(session["goal"]), session["time_budget_seconds"],
    )
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/extend-time-budget")
def extend_time_budget(
    session_id: str, background_tasks: BackgroundTasks,
    time_budget_preset: str = Form(""), time_budget_custom_minutes: str = Form(""),
) -> Response:
    """Adds more time to a session's own time budget (New Project form's Time budget field) and
    resumes it for another real pass — session_fragment.html's own "Add more time" control, offered
    once a time-budgeted session has actually stopped because its budget ran out (agent/core.py's
    run_session own while-loop breaks out of its "keep digging" cycle the moment
    _time_budget_remaining(session) goes False). Additive, not a replacement — "add 1 more hour"
    means 1 hour beyond whatever budget was already there, never a reset to exactly 1 hour total.
    Same fixed-preset/custom-minutes shape (and the same server-side resolution, not a client-JS
    computation) as start_scan's own Time budget field, for the identical reason: the plain no-JS
    form fallback must still work.

    Guarded the same way rescan_session_in_place is (must not currently be actually running) for
    the identical reason: this mutates the SAME session file a live run_session() loop could be
    mid-write on. A session with no time budget at all yet (time_budget_seconds was never set) can
    still use this — it simply starts one now, the same as if it had been set at creation time.
    """
    additional_seconds = _resolve_time_budget_seconds(time_budget_preset, time_budget_custom_minutes)
    if not additional_seconds or additional_seconds < 60:
        raise HTTPException(status_code=400, detail="A real amount of additional time (at least 60 seconds) is required")

    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") in _ORPHANABLE_STATUSES:
        raise HTTPException(status_code=400, detail="Session is currently running — stop or wait for it to finish first")
    if not session.get("started_at"):
        raise HTTPException(status_code=400, detail="Session has never actually started yet")

    session["time_budget_seconds"] = int(session.get("time_budget_seconds") or 0) + additional_seconds
    # Same in-place data prep as rescan_session_in_place's own "start a fresh full pass, prior
    # findings actively re-verified" contract — a session sitting "completed" with everything
    # already resolved would otherwise re-enter at entry_point="exploit" and find nothing new to
    # do (Exploit's own skip-already-resolved logic correctly leaves settled findings alone), which
    # would just immediately re-exhaust the newly-added time doing nothing. Seeds findings with
    # _carried_over_pending_reverify placeholders (same as rescan_session_in_place below) rather
    # than wiping to [] — a session that gets interrupted again before Reverify catches up must keep
    # showing its last real result, not an apparently-empty Findings tab.
    session["carried_over_findings"] = copy.deepcopy(session.get("findings") or [])
    session["findings"] = [
        {**copy.deepcopy(f), "_carried_over_pending_reverify": True}
        for f in session["carried_over_findings"]
    ]
    session["reverification_history"] = []
    # Same fresh-pass plan reset as rescan_session_in_place (_prepare_in_place_pass) — a completed
    # session's plan is all "done", which would sit inert through this newly-funded pass otherwise.
    session["plan"] = reset_plan_for_new_pass(session.get("plan"))
    # Same host_health streak reset as rescan_session/_prepare_in_place_pass — this newly-funded
    # pass must get at least one real attempt against every host, not inherit a block from whatever
    # pass just ran out of time.
    session["recon_result"] = reset_host_health_streaks_for_new_pass(session.get("recon_result"))
    session["status"] = "processing"
    save_session(session_id, session)

    logger.debug(
        "api: extend-time-budget session_id=%s additional_seconds=%d new_total_seconds=%d",
        session_id, additional_seconds, session["time_budget_seconds"],
    )
    background_tasks.add_task(_run_session_task, session_id, None, "recon")
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/continue-without-time-budget")
def continue_without_time_budget(session_id: str, background_tasks: BackgroundTasks) -> Response:
    """Sibling to extend_time_budget just above, for the other option offered once a time-budgeted
    session stops on session["stopped_reason"] == "time_budget_expired" (agent/core.py's
    _time_budget_expired, checked at _llm_complete's own choke point) — clears the budget entirely
    and resumes for a real, unbounded pass instead of adding more time to the same ticking clock.
    Same in-place data prep and guard against a currently-running session as extend_time_budget.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") in _ORPHANABLE_STATUSES:
        raise HTTPException(status_code=400, detail="Session is currently running — stop or wait for it to finish first")
    if not session.get("started_at"):
        raise HTTPException(status_code=400, detail="Session has never actually started yet")

    session["time_budget_seconds"] = None
    # Same _carried_over_pending_reverify seeding as extend_time_budget/rescan_session_in_place —
    # never wipe findings to [] outright, see those two routes' own comments for the incident this
    # avoids.
    session["carried_over_findings"] = copy.deepcopy(session.get("findings") or [])
    session["findings"] = [
        {**copy.deepcopy(f), "_carried_over_pending_reverify": True}
        for f in session["carried_over_findings"]
    ]
    session["reverification_history"] = []
    # Same fresh-pass plan reset as extend_time_budget/rescan_session_in_place above.
    session["plan"] = reset_plan_for_new_pass(session.get("plan"))
    # Same host_health streak reset as extend_time_budget/rescan_session_in_place above.
    session["recon_result"] = reset_host_health_streaks_for_new_pass(session.get("recon_result"))
    session["status"] = "processing"
    save_session(session_id, session)

    logger.debug("api: continue-without-time-budget session_id=%s", session_id)
    background_tasks.add_task(_run_session_task, session_id, None, "recon")
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/delete")
def delete_session_route(session_id: str) -> Response:
    if not delete_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: delete session_id=%s", session_id)
    return RedirectResponse(url="/sessions", status_code=303)


@app.post("/api/sessions/delete-all")
def delete_all_sessions_route() -> Response:
    deleted = delete_all_sessions()
    logger.debug("api: delete-all sessions deleted=%d", deleted)
    return RedirectResponse(url="/sessions", status_code=303)


@app.post("/api/session/{session_id}/chat", response_class=HTMLResponse)
def chat_turn(
    request: Request, session_id: str, background_tasks: BackgroundTasks,
    message: str = Form(""), provider: str | None = Form(None), model: str | None = Form(None),
) -> HTMLResponse:
    """Fast half of a chat turn (agent/chat.py's append_pending_chat_message) — persists the
    operator's own message and pending=True, then hands the actual LLM call off to a
    BackgroundTask, so this response comes back immediately instead of only after the whole reply
    is ready (the panel's own #chat-stream SSE connection, chat_stream below, picks up the real
    reply once run_chat_turn_background finishes). provider/model are the chat picker's own
    <select> values — "" is treated the same as never-given (None) by append_pending_chat_message,
    both meaning "leave whatever was already chosen, or default to the main agent's own provider".

    Returns just the messages fragment (_render_chat_messages), not the whole panel — the chat
    form's own hx-target is "#chat-stream" with hx-swap="morph:innerHTML", the exact same
    target/swap chat_stream's own SSE pushes use, so a message send never tears down and reopens
    that SSE connection (a plain outerHTML swap of the whole panel would destroy #chat-stream's own
    hx-ext/sse-connect attributes along with it) and never resets the sibling form's own
    provider/model <select>s or in-progress typed draft.

    A send while the active thread's own previous turn is still pending is no longer dropped or
    rejected -- agent/chat.py's append_pending_chat_message queues it (started=False) instead, and
    the already-running run_chat_turn_background BackgroundTask drains that queue itself once the
    current turn finishes, so a second background task is only scheduled when THIS call actually
    started a fresh turn (started=True).
    """
    message = message.strip()
    if load_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if not message:
        raise HTTPException(status_code=400, detail="Message must not be empty")

    logger.debug("api: chat session_id=%s message_len=%d provider=%r model=%r", session_id, len(message), provider, model)
    session, started = append_pending_chat_message(session_id, message, provider or None, model or None)
    if started:
        background_tasks.add_task(run_chat_turn_background, session_id)
    else:
        logger.debug("api: chat session_id=%s message queued — a turn is already pending", session_id)
    # A thread's OWN title is set here, from its first real message (agent/chat.py's
    # append_pending_chat_message) -- without this, the Quick Chat tab strip's own label for the
    # thread just sent in kept reading the stale default ("New chat") until some LATER, unrelated
    # new-thread/switch-thread/delete-thread call happened to refresh it.
    return HTMLResponse(_render_chat_messages(request, session) + _render_chat_header_oob(request, session))


@app.post("/api/session/{session_id}/chat/stop", response_class=HTMLResponse)
def stop_chat_turn_route(request: Request, session_id: str, thread_id: str = Form(...)) -> HTMLResponse:
    """The "thinking…" indicator's own Stop button (chat_messages.html) -- mirrors /interrupt above
    for the autonomous scan, but scoped to one chat thread's own in-flight turn (agent/chat.py's
    request_chat_stop) instead of the whole session: a chat conversation is a genuinely separate
    thing from the scan loop (see agent/chat.py's own module docstring), so stopping one must never
    touch the other. Only flips an in-memory signal -- _run_chat_tool_loop's own checkpoints notice
    it and _run_one_chat_turn persists the outcome (a "Stopped by the operator." notice, pending
    cleared, any queued follow-ups dropped too), same non-writing-the-session-file-directly
    reasoning as /interrupt.
    """
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    thread = _find_thread(session, thread_id)
    if thread is None:
        raise HTTPException(status_code=404, detail="Unknown chat thread")
    if not thread.get("pending"):
        raise HTTPException(status_code=400, detail="This chat turn is not currently running")
    request_chat_stop(session_id, thread_id)
    logger.debug("api: chat session_id=%s thread=%s stop requested", session_id, thread_id)
    return HTMLResponse(_render_chat_messages(request, session))


@app.post("/api/session/{session_id}/chat/queued/cancel", response_class=HTMLResponse)
def cancel_queued_chat_message_route(
    request: Request, session_id: str, thread_id: str = Form(...), message_id: str = Form(...),
) -> HTMLResponse:
    """A queued bubble's own "x" (chat_messages.html) -- the operator changed their mind about a
    not-yet-dispatched follow-up before it was actually sent (agent/chat.py's
    cancel_queued_chat_message)."""
    try:
        session = cancel_queued_chat_message(session_id, thread_id, message_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown chat thread")
    logger.debug("api: chat session_id=%s thread=%s cancelled queued message=%s", session_id, thread_id, message_id)
    return HTMLResponse(_render_chat_messages(request, session))


def _render_chat_header_oob(request: Request, session: dict) -> str:
    """Out-of-band refresh for the two chat-panel header pieces that can go stale once more than one
    request can change which thread is active: the panel's own title (id="chat-panel-title",
    chat_panel.html) and, on the standalone Quick Chat page only, its tab strip
    (partials/chat_thread_tabs.html). Appended to new-thread/switch-thread/delete-thread AND a plain
    message send (which sets a thread's real title from its first message) -- every one of them can
    change either which thread is active or that active thread's own title.

    Real, confirmed bug this fixes: the header title used to only ever come from the full page's
    initial render (thread.title at load time) -- switching threads (via the tab strip above, or the
    /resume picker) left it showing whichever thread was active when the page first loaded, visibly
    wrong the instant a second thread existed to switch to.

    Both fragments are unconditional, not gated on the page actually having tabs -- htmx's
    hx-swap-oob is a no-op wherever its target id isn't in the current DOM, so the tabs fragment
    never does anything on a project's own compact sidebar chat, which has no #chat-thread-tabs at
    all (its own header title, id="chat-panel-title", still gets the same live fix either way).
    """
    threads = list_chat_threads(session["session_id"])
    active_id = session.get("active_chat_thread_id")
    active_title = next((t["title"] for t in threads if t["id"] == active_id), "")
    title_oob = f'<p id="chat-panel-title" hx-swap-oob="innerHTML">{markupsafe.escape(active_title)}</p>'
    tabs_oob = templates.env.get_template("partials/chat_thread_tabs.html").render(
        {"request": request, "threads": threads, "session": session, "oob": True}
    )
    return title_oob + tabs_oob


@app.post("/api/session/{session_id}/chat/new-thread", response_class=HTMLResponse)
def new_chat_thread_route(request: Request, session_id: str) -> HTMLResponse:
    """/new (button or slash command, chat_panel.html) — old threads are never destroyed, just no
    longer active (agent/chat.py's start_new_chat_thread)."""
    try:
        session = start_new_chat_thread(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: chat session_id=%s started a new thread", session_id)
    return HTMLResponse(_render_chat_messages(request, session) + _render_chat_header_oob(request, session))


@app.get("/api/session/{session_id}/chat/threads", response_class=HTMLResponse)
def get_chat_threads_route(request: Request, session_id: str) -> HTMLResponse:
    """/resume's own picker (button or slash command) — a <dialog>'s worth of content
    (partials/chat_thread_picker.html), the same asraOpenDialog mechanism New Project/finding-detail
    already use, not a separate page."""
    try:
        threads = list_chat_threads(session_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    session = load_session(session_id)
    active_id = (session or {}).get("active_chat_thread_id")
    return templates.TemplateResponse(
        request, "partials/chat_thread_picker.html",
        {"threads": threads, "session_id": session_id, "active_thread_id": active_id},
    )


@app.get("/api/session/{session_id}/subagents-panel", response_class=HTMLResponse)
def get_session_subagents_panel(request: Request, session_id: str) -> HTMLResponse:
    """chat_panel.html's own #chat-subagents-btn (Quick Chat only -- see that button's own
    docstring for why a real project never renders it) -- a <dialog>'s worth of content
    (partials/chat_subagents_panel.html), same shape as get_chat_threads_route just above. This
    endpoint itself is a plain, session-id-generic read of session["enabled_subagent_ids"]; only
    the ONE button that links to it is restricted to mode == "standalone"."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return templates.TemplateResponse(
        request, "partials/chat_subagents_panel.html",
        {"session": session, "enabled_subagents": get_enabled_profiles()},
    )


@app.post("/api/session/{session_id}/enabled-subagents")
def save_session_enabled_subagents(session_id: str, enabled_subagent_ids: list[str] = Form([])) -> Response:
    """Quick Chat's own Subagents dialog (partials/chat_subagents_panel.html) saves straight into
    its session here, one field at a time, same "each toggle its own independent request" posture
    as save_chat_setting_route -- every checkbox submits the checklist's CURRENT full state
    (hx-include="closest [data-chat-subagents-checklist]"), so this always resolves the complete
    picture, never a single field in isolation. This endpoint itself is a plain, session-id-generic
    write to session["enabled_subagent_ids"] -- nothing here is Quick-Chat-specific, only the ONE
    button that links to it is."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    resolved = _resolve_enabled_subagent_ids(enabled_subagent_ids)
    session["enabled_subagent_ids"] = resolved
    save_session(session_id, session)
    logger.debug("api: session=%s enabled_subagent_ids=%s (set from the chat panel)", session_id, resolved)
    return Response(status_code=204)


@app.post("/api/session/{session_id}/chat/switch-thread", response_class=HTMLResponse)
def switch_chat_thread_route(request: Request, session_id: str, thread_id: str = Form(...)) -> HTMLResponse:
    try:
        session = switch_chat_thread(session_id, thread_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown chat thread")
    logger.debug("api: chat session_id=%s switched to thread=%s", session_id, thread_id)
    return HTMLResponse(_render_chat_messages(request, session) + _render_chat_header_oob(request, session))


@app.post("/api/session/{session_id}/chat/delete-thread", response_class=HTMLResponse)
def delete_chat_thread_route(request: Request, session_id: str, thread_id: str = Form(...)) -> HTMLResponse:
    """The /resume picker's own delete control -- hx-confirm on the button (confirm_dialog.js's
    global htmx:confirm hook) gates this the same way every other destructive action in this app
    is gated, before the request is even issued. Re-renders the picker's own thread list (this
    request's primary hx-target) plus an out-of-band #chat-stream update (agent/chat.py's
    delete_chat_thread may have switched the active thread if the deleted one was it) -- htmx's
    hx-swap-oob applies that second fragment to #chat-stream regardless of what this request's own
    primary target was, without a second round-trip.
    """
    try:
        session = delete_chat_thread(session_id, thread_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown chat thread")
    logger.debug("api: chat session_id=%s deleted thread=%s", session_id, thread_id)
    threads = list_chat_threads(session_id)
    active_id = session.get("active_chat_thread_id")
    picker_html = templates.env.get_template("partials/chat_thread_picker.html").render(
        {"request": request, "threads": threads, "session_id": session_id, "active_thread_id": active_id}
    )
    oob_stream = f'<div id="chat-stream" hx-swap-oob="morph:innerHTML">{_render_chat_messages(request, session)}</div>'
    return HTMLResponse(picker_html + oob_stream + _render_chat_header_oob(request, session))


@app.post("/api/session/{session_id}/chat/rename-thread", response_class=HTMLResponse)
def rename_chat_thread_route(request: Request, session_id: str, thread_id: str = Form(...), title: str = Form(...)) -> HTMLResponse:
    """Chat tab strip's inline rename (real, explicit operator ask: parity with the Terminal tab
    strip's own dblclick-to-rename) -- static/js/terminal.js's own equivalent applies the new label
    to its tab instantly client-side and persists in the background, so this route's own response
    body is never actually read by the caller; it exists purely so OTHER open tabs/surfaces (this
    session's chat_stream SSE, widened below to also watch every thread's title/color/pending) pick
    the rename up too, same as every other chat mutation already does.
    """
    session = rename_chat_thread(session_id, thread_id, title)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or unknown thread")
    logger.debug("api: chat rename-thread session_id=%s thread_id=%s", session_id, thread_id)
    return HTMLResponse(_render_chat_header_oob(request, session))


@app.post("/api/session/{session_id}/chat/thread-color", response_class=HTMLResponse)
def set_chat_thread_color_route(request: Request, session_id: str, thread_id: str = Form(...), color: str = Form("")) -> HTMLResponse:
    """Chat tab strip's per-tab color picker -- same "client already applied it instantly,
    this just persists it for other surfaces" shape as rename_chat_thread_route just above."""
    session = set_chat_thread_color(session_id, thread_id, color or None)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found or unknown thread")
    logger.debug("api: chat thread-color session_id=%s thread_id=%s color=%s", session_id, thread_id, color)
    return HTMLResponse(_render_chat_header_oob(request, session))


@app.post("/api/session/{session_id}/chat/compact", response_class=HTMLResponse)
async def compact_chat_thread_route(request: Request, session_id: str, instructions: str = Form("")) -> HTMLResponse:
    """/compact [instructions] (button or slash command) — a single, quick, tool-less LLM call
    (agent/chat.py's compact_chat_thread), so this runs synchronously to completion within this one
    request rather than needing append_pending_chat_message's own pending/BackgroundTask handoff —
    same reasoning the hypothesis-text-structuring pass (agent/core.py) already applies to its own
    single quick LLM call.
    """
    try:
        did_compact = await compact_chat_thread(session_id, instructions.strip())
    except ValueError:
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: chat session_id=%s manual compact did_compact=%s", session_id, did_compact)
    session = load_session(session_id)
    flash = None if did_compact else "Nothing to compact yet — not enough history."
    return HTMLResponse(_render_chat_messages(request, session, flash=flash))


_EXPORT_CONTENT_TYPES = {
    "html": "text/html; charset=utf-8",
    "txt": "text/plain; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    # RTF content served under the classic .doc extension (see render_doc's own docstring for why)
    # -- application/msword, not text/rtf, so the browser's own save dialog offers the .doc
    # extension/icon a "Word 97-2003" choice is expected to produce.
    "doc": "application/msword",
    "zip": "application/zip",
}


@app.get("/api/session/{session_id}/export")
def export_proof(request: Request, session_id: str, format: str = "html") -> Response:
    # "format" is the query param name users/links actually see (?format=pdf) -- aliased to avoid
    # shadowing the builtin of the same name for the rest of this function.
    export_format = format
    session = load_session(session_id)
    if session is None or session.get("status") != "completed" or not session.get("findings"):
        raise HTTPException(status_code=404, detail="No proof available for this session")
    if export_format not in EXPORT_FORMATS:
        raise HTTPException(status_code=400, detail=f"Unknown export format: {export_format!r}")

    generated_at = datetime.now(timezone.utc).isoformat()
    logger.debug("export_proof session=%s format=%s", session_id, export_format)

    # proof_report.html (Jinja) stays the single source of truth for the HTML format itself, and
    # for the copy bundled inside the "all formats" zip below -- every other format is built from
    # build_report_data's own extraction pass instead (agent/utils/report_export.py).
    html_content = templates.env.get_template("proof_report.html").render(
        {"request": request, "session": session, "generated_at": generated_at}
    )
    if export_format == "html":
        content: str | bytes = html_content
    else:
        data = build_report_data(session, generated_at)
        if export_format == "txt":
            content = render_txt(data)
        elif export_format == "md":
            content = render_md(data)
        elif export_format == "pdf":
            content = render_pdf(data)
        elif export_format == "docx":
            content = render_docx(data)
        elif export_format == "doc":
            content = render_doc(data)
        else:  # zip
            content = render_zip(data, html_content)

    filename = f"asra-proof-{session_id}-all-formats.zip" if export_format == "zip" else f"asra-proof-{session_id}.{export_format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=content, media_type=_EXPORT_CONTENT_TYPES[export_format], headers=headers)


def _load_all_sessions() -> list[dict]:
    """Thin wrapper over sessions.store's cached summaries -- this is polled every 5s from THREE
    separate places (base.html's sidebar, on every single page; index.html's recent-projects
    fragment; sessions_list.html's Projects list) plus synchronously on every fresh Projects page
    load. Used to json.load() every session file on every one of those calls; see
    sessions/store.py's _build_summary docstring for the real incident this fixes (a 364 MB session
    file made the whole app, not just that one project's page, "жутко долго" on every tab switch)."""
    summaries = list_session_summaries()
    summaries.sort(key=lambda s: s["created_at"], reverse=True)
    return summaries


@app.get("/api/active-session", response_class=HTMLResponse)
def get_active_session(request: Request) -> HTMLResponse:
    """Sidebar quick-return widget (polled) — surfaces whichever session is currently running in
    the background, so switching pages/opening the New Project dialog never loses track of it."""
    active = [s for s in _load_all_sessions() if s["status"] in _ORPHANABLE_STATUSES]
    return templates.TemplateResponse(request, "partials/active_session_badge.html", {"active_sessions": active})


def _check_system_health() -> tuple[bool, str]:
    """Sidebar status dot (base.html, polled via /api/system-health) — real signal, not a
    hardcoded "always online" dot. Two cheap, already-available checks rather than a network
    round-trip to an LLM provider on every poll: the sessions store must actually be readable
    (the same call every list/summary view already depends on), and at least one configured LLM
    provider must be usable (no key required, or a key is actually set) -- the same check
    _subagent_context() already does for its own provider picker."""
    try:
        list_session_summaries()
    except Exception as exc:
        return False, f"Session storage is unreadable: {exc}"

    has_usable_provider = (
        any(not cfg.api_key_required or bool(get_provider_api_key(cfg)) for cfg in PROVIDER_REGISTRY.values())
        or any(p.get("enabled", True) for p in load_custom_providers())
        or load_codex_tokens() is not None
        or load_copilot_tokens() is not None
    )
    if not has_usable_provider:
        return False, "No LLM provider is configured — add an API key in Settings."

    return True, "Local-only — scan data never leaves this machine."


_last_logged_system_health: tuple[bool, str] | None = None


@app.get("/api/system-health", response_class=HTMLResponse)
def get_system_health(request: Request) -> HTMLResponse:
    """Polled by the sidebar (base.html, every 20s -- from every open tab independently) — see
    _check_system_health() above. Logged only on an actual state change, not every poll: real
    operator complaint this fixes -- with even a couple of tabs open this line alone was over 60% of
    the entire global debug.log's volume, visually burying the far rarer AGENT/LLM/TOOLS/CHAT lines
    an operator actually watching the debug console cares about, while the health result itself
    almost never changes poll to poll."""
    global _last_logged_system_health
    healthy, reason = _check_system_health()
    if (healthy, reason) != _last_logged_system_health:
        logger.debug("api: system-health healthy=%s reason=%s", healthy, reason)
        _last_logged_system_health = (healthy, reason)
    response = templates.TemplateResponse(request, "partials/system_status.html", {"healthy": healthy, "reason": reason})
    # _SOURCE_MTIME_AT_STARTUP's own comment above -- lets a fresh process about to (maybe) reuse
    # this one tell "my code is newer than this running instance's" apart from "it's current".
    response.headers["X-ASRA-Source-Mtime"] = str(_SOURCE_MTIME_AT_STARTUP)
    return response


@app.get("/api/updates/status", response_class=HTMLResponse)
def api_updates_status(request: Request) -> HTMLResponse:
    """Settings -> Updates panel initial render, from the startup cache (no network)."""
    return templates.TemplateResponse(request, "partials/update_status.html", {"u": updater.cached_status(), "result": None})


@app.get("/api/updates/check", response_class=HTMLResponse)
def api_updates_check(request: Request) -> HTMLResponse:
    """Force a fresh check (git fetch) and re-render the panel. Also refreshes the cache."""
    status = updater.refresh_cache(fetch=True)
    logger.debug("api: updates check available=%s behind=%d error=%s", status.available, status.behind, status.error)
    return templates.TemplateResponse(request, "partials/update_status.html", {"u": status, "result": None})


@app.post("/api/updates/apply", response_class=HTMLResponse)
def api_updates_apply(request: Request) -> HTMLResponse:
    """Fast-forward pull if safe, then re-render the panel with the result."""
    result = updater.apply_update()
    status = updater.refresh_cache(fetch=False)
    logger.debug("api: updates apply ok=%s no_op=%s", result.get("ok"), result.get("no_op"))
    return templates.TemplateResponse(request, "partials/update_status.html", {"u": status, "result": result})


@app.get("/api/updates/indicator", response_class=HTMLResponse)
def api_updates_indicator(request: Request) -> HTMLResponse:
    """Tiny sidebar badge (base.html, polled) — shows a dot only when an update is available."""
    status = updater.cached_status()
    return templates.TemplateResponse(
        request,
        "partials/update_indicator.html",
        {"available": bool(status and status.available), "behind": status.behind if status else 0},
    )


@app.get("/sessions", response_class=HTMLResponse)
def list_sessions(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "sessions_list.html", {"sessions": _load_all_sessions()})


@app.get("/api/sessions/fragment", response_class=HTMLResponse)
def get_sessions_list_fragment(request: Request) -> HTMLResponse:
    """Polled by the Projects page (sessions_list.html, every 5s) so a status/finding-count change
    shows up on its own — this page used to render exactly once at page load, same class of bug
    the session detail page already solved for itself with SSE (stream_session above)."""
    return templates.TemplateResponse(request, "partials/sessions_list_fragment.html", {"sessions": _load_all_sessions()})


@app.get("/api/recent-projects/fragment", response_class=HTMLResponse)
def get_recent_projects_fragment(request: Request) -> HTMLResponse:
    """Polled by the home page's "Recent projects" list (index.html, every 5s) — same fix as
    get_sessions_list_fragment above, for the other page that shows session summaries."""
    return templates.TemplateResponse(request, "partials/recent_projects_fragment.html", {"recent_sessions": _load_all_sessions()[:5]})


def _llm_settings_context() -> dict:
    saved = load_llm_settings()
    current_provider = saved.get("provider") or os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER)
    # is_known_provider_id, not a bare PROVIDER_REGISTRY membership check -- real bug this fixes: a
    # saved custom-provider choice used to be silently reset back to DEFAULT_PROVIDER on every
    # single render, since a custom id (e.g. "custom-abc123") is never a PROVIDER_REGISTRY key.
    if not is_known_provider_id(current_provider):
        current_provider = DEFAULT_PROVIDER

    if is_custom_provider_id(current_provider):
        custom = get_custom_provider(current_provider) or {}
        current_model = (
            saved.get("model") if saved.get("provider") == current_provider else None
        ) or custom.get("model") or ""
    elif current_provider == CODEX_PROVIDER_ID:
        current_model = (
            saved.get("model") if saved.get("provider") == current_provider else None
        ) or CODEX_DEFAULT_MODEL
    elif current_provider == COPILOT_PROVIDER_ID:
        from agent.copilot_provider import COPILOT_DEFAULT_MODEL
        current_model = (
            saved.get("model") if saved.get("provider") == current_provider else None
        ) or COPILOT_DEFAULT_MODEL
    else:
        config = PROVIDER_REGISTRY[current_provider]
        current_model = (
            saved.get("model") if saved.get("provider") == current_provider else None
        ) or os.getenv(config.model_env) or config.model_default

    provider_key_status = {pid: bool(get_provider_api_key(cfg)) for pid, cfg in PROVIDER_REGISTRY.items()}
    provider_base_url_value = {pid: os.getenv(cfg.base_url_env) or "" for pid, cfg in PROVIDER_REGISTRY.items()}
    added = get_added_providers()
    # A built-in only ever renders as a row in the Providers list once it's genuinely "there" --
    # explicitly added (added_providers), OR self-evidently already in real use (a saved key, the
    # provider actively selected above, or a real endpoint override) so upgrading an install that
    # configured providers before this flag existed never silently hides them. Real incident this
    # fixes: every built-in used to render unconditionally from install, including ones nobody had
    # ever touched (no key, no override, not selected) -- reading as "already added" when nothing
    # had happened yet, and their Delete button had nothing real to remove either.
    provider_added = {
        pid: (
            pid in added
            or provider_key_status[pid]
            or pid == current_provider
            or bool(provider_base_url_value[pid]) and provider_base_url_value[pid] != PROVIDER_REGISTRY[pid].base_url_default
        )
        for pid in PROVIDER_REGISTRY
    }

    return {
        "current_provider": current_provider,
        "current_model": current_model,
        "provider_models": get_model_choices(current_provider) or ([current_model] if current_model else []),
        # Per-request, not a startup global like provider_is_local/provider_key_required — an
        # operator can Save/Clear a key or endpoint from this same screen, and .env can change
        # underneath a long-running process, so these have to be read fresh on every render.
        "provider_key_status": provider_key_status,
        "provider_base_url_value": provider_base_url_value,
        "provider_added": provider_added,
        # The AI Provider & Model picker's own Cloud/Local option lists -- ONLY built-ins the
        # operator has actually added (provider_added above) AND not disabled via the Providers
        # list's own toggle button (is_provider_enabled), the same subset the "// Providers" list
        # below renders, so the two never disagree. Real incident this fixes: the picker used to
        # iterate the cloud_provider_ids/local_provider_ids template globals (the whole
        # PROVIDER_REGISTRY) unconditionally, so every built-in showed up as pickable even when the
        # operator had added only a handful -- reading as "everything's already configured" while
        # the Providers list right beside it showed just the four real ones. A second, separate
        # incident this also fixes: this picker used to ignore is_provider_enabled entirely, so a
        # provider the operator explicitly disabled from the Providers list (still "added"/
        # configured, just toggled off) kept showing up here as if it were still pickable -- the
        # toggle's whole documented purpose (see provider_row's own comment above) is to pull a
        # provider out of every picker without touching its saved key, and this one was the
        # exception. current_provider is exempted from the enabled check the same way it's exempted
        # from provider_added, so the active choice can never filter itself out of its own dropdown
        # even if it happens to be the disabled one.
        "added_cloud_provider_ids": [
            pid for pid in PROVIDER_REGISTRY
            if not PROVIDER_REGISTRY[pid].is_local and provider_added[pid] and (is_provider_enabled(pid) or pid == current_provider)
        ],
        "added_local_provider_ids": [
            pid for pid in PROVIDER_REGISTRY
            if PROVIDER_REGISTRY[pid].is_local and provider_added[pid] and (is_provider_enabled(pid) or pid == current_provider)
        ],
        # Settings -> Providers row toggle (agent/settings.py's set_provider_enabled) -- read fresh
        # per-request like provider_key_status above, not a startup global, since the operator can
        # flip it from this same screen.
        "provider_enabled": {pid: is_provider_enabled(pid) for pid in PROVIDER_REGISTRY},
        # Every selectable provider (6 built-ins + every enabled custom instance), for the AI
        # Provider & Model picker's own "Custom" optgroup (settings.html) -- the single source of
        # truth agent/llm_client.py's all_provider_choices() already is for every other
        # provider-picking dropdown in this app (Reserve providers rows, a subagent's own picker).
        "all_provider_choices": all_provider_choices(),
    }


def _secondary_verification_context() -> dict:
    """Settings -> Secondary verification provider (agent/core.py's ensemble second-opinion check
    for Skeptical Verification, agent/settings.py's get_secondary_verification_provider) -- a
    single, static provider+model pair, deliberately NOT the Reserve providers chain's own
    dynamic multi-row UI (that complexity buys "try these in order until one works"; this is a
    single fixed choice, always used or not used at all). Blank/unset (the default) means the
    feature is off. Reuses the exact same /api/settings/model-options endpoint the main AI
    Provider & Model picker's own model dropdown already hits on a provider change -- one fewer
    endpoint to build and keep in sync.
    """
    current = get_secondary_verification_provider()
    current_provider = (current or {}).get("provider") or ""
    current_model = (current or {}).get("model") or ""
    # Only providers actually CONFIGURED right now (a real key set, or none needed) -- same
    # reasoning/function as _fallback_chain_context's own dropdown_provider_ids just above: an
    # unconfigured entry here would look pickable but just crash the ensemble check (get_provider
    # raising ValueError) the first time it actually tried to use it. The currently-saved choice
    # stays visible even if it's since become unconfigured, same "never silently hide an
    # already-made selection" reasoning -- picking a DIFFERENT one is what's narrowed, not this.
    choices = configured_provider_choices()
    # Local providers (LM Studio/Ollama) additionally need a real, live reachability check -- see
    # _reachable_local_provider_ids's own docstring for the real incident ("no API key required"
    # alone offered a local server nobody had ever started) this closes for this picker too.
    local_ids = {pid for pid, cfg in PROVIDER_REGISTRY.items() if cfg.is_local}
    if any(pid in local_ids for pid, _ in choices):
        reachable = _reachable_local_provider_ids()
        choices = [(pid, name) for pid, name in choices if pid not in local_ids or pid in reachable]
    if current_provider and current_provider not in {pid for pid, _ in choices}:
        all_names = dict(all_provider_choices())
        choices = [*choices, (current_provider, all_names.get(current_provider, current_provider))]
    return {
        "secondary_verification_provider": current_provider,
        "secondary_verification_model": current_model,
        "secondary_verification_provider_choices": choices,
        "secondary_verification_model_choices": (
            get_model_choices(current_provider) or ([current_model] if current_model else [])
        ) if current_provider else [],
    }


def _wordlist_settings_context() -> dict:
    return {
        "wordlists": list_all_wordlists(),
        "assignable_roles": ASSIGNABLE_ROLES,
        "wordlist_assignments": {role: get_assigned_wordlist(role) for role in ASSIGNABLE_ROLES},
    }


def _custom_providers_context() -> dict:
    return {
        "custom_providers": load_custom_providers(),
        "custom_provider_type_presets": CUSTOM_PROVIDER_TYPE_PRESETS,
    }


def _toolkit_agent_settings_context() -> dict:
    """Settings -> "Native toolkit access" section -- the independent toggles deciding whether the
    autonomous agent/chat/subagents can use send_raw_request/list_captured_traffic/decode_value/
    diff_requests/intruder_run/sequencer_analyze. The manual UI (the Toolkit tab on a session page)
    never reads this -- it always works."""
    return {"toolkit_agent_settings": load_toolkit_agent_settings()}


def _tool_api_keys_context() -> dict:
    """Settings -> Tool API Keys -- one row per agent/tools/tool_api_keys.py's TOOL_API_KEY_SPECS
    entry (currently just WPScan's --api-token). Same "never re-render the real secret" discipline
    _llm_settings_context() already follows for LLM provider keys (its own provider_key_status) --
    only a bool "is one saved" ever reaches the template, read fresh per-request since Save/Clear
    on this same screen can change it underneath a long-running process."""
    return {
        "tool_api_key_specs": TOOL_API_KEY_SPECS,
        "tool_api_key_status": {name: bool(get_tool_api_key(name)) for name in TOOL_API_KEY_SPECS},
    }


def _timezone_settings_context() -> dict:
    """Settings -> Timezone -- the display zone main.py's own human_dt filter (and the header
    clock, templates/base.html) render every stored UTC timestamp into. Read fresh per-request,
    same as every other Settings context helper here, since Save on this same screen can change it
    underneath a long-running process."""
    return {
        "current_display_timezone": load_display_timezone(),
        "available_timezones": display_timezone_choices(),
        "clock_show_time": load_clock_show_time(),
        "clock_show_zone_label": load_clock_show_zone_label(),
        "clock_show_date": load_clock_show_date(),
        "clock_style": load_clock_style(),
        "clock_styles": CLOCK_STYLES,
    }


def _sound_settings_context() -> dict:
    """Settings -> Customization -> Sounds -- agent/sound_settings.py's own on-disk store. Read fresh per-request,
    same as every other Settings context helper here."""
    return {
        "sound_settings": load_sound_settings(),
        "sound_events": SOUND_EVENTS,
        "sound_profiles": SOUND_PROFILES,
    }


def _intro_settings_context() -> dict:
    """Settings -> Customization -> Visual -- whether the desktop shell's own pre-launch intro
    animation plays, and whether its synthesized sound (ambient drone + the three glass-impact
    hits) plays alongside it (agent/intro_settings.py, both written straight to .env since the
    Rust desktop shell reads them before this backend exists). Read fresh per-request, same as
    every other Settings context helper here."""
    return {"intro_enabled": load_intro_enabled(), "intro_sound_enabled": load_intro_sound_enabled()}


def _chat_settings_context() -> dict:
    """Settings -> Chat -- the chat panel's own capability toggles (web_fetch/browser/dork_engine/
    subagents), shared by a project's own chat sidebar and the standalone Quick Chat alike. Every
    settings.html render site needs this spread in, not just GET /settings itself -- the Chat tab's
    own <section> is always present in the rendered DOM (CSS display:none just hides whichever tab
    isn't active, see that section's own comment), so any render that omits this key fails with a
    strict-Undefined error the instant that section's toggle_switch calls dereference it, even on a
    completely unrelated tab's own error re-render."""
    return {"chat_settings": load_chat_settings()}


def _capability_settings_context(*, install_error: dict | None = None) -> dict:
    """Settings -> Optional interpreters/compilers accordion -- one row per
    agent/tools/capability_registry.py entry, merged with its live install status and any saved
    path override. install_error (set only by the Install route on failure, agent/tools/
    capability_install.py's own error dict) carries the exact fallback command + Copy button for
    whichever single row just failed -- never set on a plain page load."""
    saved_paths = load_tool_paths()
    capabilities = [
        {**capability, **get_capability_status(capability["id"]), "saved_path": saved_paths.get(capability["id"], "")}
        for capability in OPTIONAL_CAPABILITIES
    ]
    return {
        "optional_capabilities": capabilities, "capability_install_error": install_error,
        "sudo_password_set": has_sudo_password(),
    }


def _codex_oauth_context() -> dict:
    """"Sign in with ChatGPT" status for its own Settings card -- separate from the generic
    per-provider API-key card every PROVIDER_REGISTRY built-in gets, since there's no key to type
    here, just a signed-in/signed-out state. Must be spread into every settings.html render site
    (same discipline _custom_providers_context() already needs -- see this project's own
    tojson/Undefined incident for what happens when a context helper is missed at one call site).
    """
    tokens = load_codex_tokens()
    return {
        "codex_provider_id": CODEX_PROVIDER_ID,
        "codex_display_name": CODEX_DISPLAY_NAME,
        "codex_signed_in": tokens is not None,
        "codex_account_id": tokens.get("account_id") if tokens else None,
        "codex_models": list(CODEX_MODELS.keys()),
    }


def _copilot_oauth_context() -> dict:
    """"Sign in with GitHub Copilot" status for its own Settings card -- the GitHub-Copilot
    counterpart of _codex_oauth_context() above, same reasoning (no key to type, just a signed-in/
    signed-out state) and same "must be spread into every settings.html render site" discipline.
    No live model-list fetch here (unlike agent/llm_client.py's own get_model_choices for this
    provider) -- nothing in settings.html/subagents.html reads a "copilot_models" field the way
    codex_models above is actually unused too, so this stays a plain, network-free status check.
    """
    tokens = load_copilot_tokens()
    return {
        "copilot_provider_id": COPILOT_PROVIDER_ID,
        "copilot_display_name": COPILOT_DISPLAY_NAME,
        "copilot_signed_in": tokens is not None,
    }


def _reachable_local_provider_ids() -> set[str]:
    """Which of PROVIDER_REGISTRY's is_local entries (LM Studio/Ollama) are ACTUALLY reachable
    right now -- a real, live check (get_model_choices() hits the local server's own /v1/models,
    bounded by LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS, empty/never raises if nothing answers), not
    just "needs no API key". Deliberately separate from llm_client.configured_provider_choices()
    itself: that function stays a fast, non-network-calling "has real credentials, or none
    required" check reusable from anywhere, while "is a local server actually running" can only
    ever be answered by a real probe. Real, confirmed incident this exists because of: an operator
    who has never touched LM Studio/Ollama at all still saw both listed as pickable in Reserve
    providers/Secondary verification, indistinguishable on sight from opencode-zen (which never
    needs a running server at all) -- picking one would have looked like a real reserve step and
    then simply never fired. Run concurrently (at most 2 local providers exist today) so a
    not-running server's own timeout is paid once, not serially stacked with the other one."""
    local_ids = [pid for pid, cfg in PROVIDER_REGISTRY.items() if cfg.is_local]
    if not local_ids:
        return set()
    with ThreadPoolExecutor(max_workers=len(local_ids)) as executor:
        reachable = dict(zip(local_ids, executor.map(get_model_choices, local_ids)))
    return {pid for pid, models in reachable.items() if models}


def _fallback_chain_context(*, error: str | None = None) -> dict:
    """Settings -> Reserve providers: every row is a real (provider, model) dropdown pair, sourced
    from every provider actually CONFIGURED right now (llm_client.configured_provider_choices) --
    a real key set, or none needed at all -- plus each one's own actual configured models (the
    same get_model_choices() the main AI Provider & Model picker already uses) — never free text,
    so there's nothing here for an operator to mistype OR pick that's guaranteed to be skipped at
    scan time for having no key. A provider a saved row already references stays visible even if
    it's since become unconfigured — see dropdown_provider_ids below for why."""
    saved = load_llm_settings()
    raw_chain = saved.get("fallback_chain") or []
    provider_ids = [pid for pid, _ in all_provider_choices()]
    referenced_ids = {saved.get("provider")} | {entry.get("provider") for entry in raw_chain}
    # Dropdown OPTIONS offered when picking a provider for a row -- only ones actually configured
    # right now (a real key, or none needed), so the operator can never pick one guaranteed to
    # just be skipped at scan time. A provider a SAVED row already references stays offered even
    # if it's since become unconfigured (key removed) -- this only narrows FUTURE picks, dropping
    # it here would silently make an already-made selection impossible to even see was ever there.
    # Local providers (LM Studio/Ollama) additionally need a real, live reachability check --
    # "no API key required" alone would otherwise offer a local server that's simply never been
    # started, see _reachable_local_provider_ids's own docstring for the real incident this fixes.
    configured_ids = {pid for pid, _ in configured_provider_choices()}
    local_ids = {pid for pid, cfg in PROVIDER_REGISTRY.items() if cfg.is_local}
    if configured_ids & local_ids:
        configured_ids = (configured_ids - local_ids) | (configured_ids & _reachable_local_provider_ids())
    dropdown_provider_ids = [pid for pid in provider_ids if pid in configured_ids or pid in referenced_ids]

    # Precomputed once for every EAGER provider (not just each row's own), so a JS-added row (no
    # server-rendered <option>s of its own yet) can populate its model dropdown immediately from
    # this same map instead of needing its own round-trip the moment it appears. Concurrent, not a
    # plain sequential dict comprehension -- real, confirmed incident: each get_model_choices() call
    # for a local provider (LM Studio/Ollama), a custom endpoint, or Copilot is a genuine network
    # round trip, and running them serially made a plain /settings load measure ~7.2s wall clock
    # with both local providers stopped. Concurrency alone dropped that to ~roughly the single
    # slowest provider (still ~2s, LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS) -- but that still landed
    # on EVERY /settings load's own critical path even for an operator who has never touched the
    # (off-by-default) fallback chain feature and runs no local LLM server at all. Real, confirmed
    # incident this fixes: /settings measured ~2s server-side on a cold cache purely from probing
    # LM Studio/Ollama nobody had running. Below, only providers actually already in use (a saved
    # chain row, or the current primary provider/model) get probed eagerly; every other
    # network-probe-requiring provider is resolved on demand instead, by the row's own
    # provider-select change handler (settings.html) hitting the same
    # /api/settings/model-options endpoint the main AI Provider & Model picker already uses for
    # exactly this reason -- a live check is the semantically correct thing for a local server's
    # "what's loaded right now" question anyway, not merely a fallback.

    def _requires_live_probe(pid: str) -> bool:
        if is_custom_provider_id(pid) or pid == COPILOT_PROVIDER_ID:
            return True
        config = PROVIDER_REGISTRY.get(pid)
        return bool(config and config.is_local)

    deferred_ids = {pid for pid in provider_ids if pid not in referenced_ids and _requires_live_probe(pid)}
    eager_ids = [pid for pid in provider_ids if pid not in deferred_ids]
    with ThreadPoolExecutor(max_workers=max(len(eager_ids), 1)) as executor:
        eager_choices = dict(zip(eager_ids, executor.map(get_model_choices, eager_ids)))
    provider_model_choices = {pid: (eager_choices.get(pid) or []) for pid in provider_ids}
    rows = []
    for entry in raw_chain:
        provider_id, model = entry.get("provider"), entry.get("model")
        if provider_id not in provider_ids:
            continue  # a provider removed/disabled since this was saved -- drop it silently, same tolerance stale-field handling already gets elsewhere in this app
        choices = provider_model_choices[provider_id]
        if model and model not in choices:
            # A model the live catalog no longer lists (renamed/retired upstream) must still show
            # up as this row's own selected option -- otherwise the saved choice would silently
            # vanish from the dropdown the moment its turn came up here, with nothing to explain why.
            choices = [model, *choices]
        rows.append({"provider": provider_id, "model": model, "model_choices": choices})
    return {
        "fallback_chain_enabled": bool(saved.get("fallback_chain_enabled")),
        "fallback_chain_rows": rows,
        "fallback_chain_error": error,
        "fallback_chain_provider_ids": dropdown_provider_ids,
        "fallback_chain_provider_model_choices": provider_model_choices,
        "fallback_chain_provider_names": dict(all_provider_choices()),
        "fallback_chain_deferred_provider_ids": sorted(deferred_ids),
    }


@app.get("/settings", response_class=HTMLResponse)
def get_settings(request: Request) -> HTMLResponse:
    # Tools tab context (_grouped_tools_context/list_nuclei_packs) -- same two calls the old
    # standalone /tools page used, now feeding Settings' own "tools" tab instead (real, explicit
    # operator ask to fold Tools into Settings rather than its own sidebar entry).
    tools_context = _grouped_tools_context(list_tool_availability())
    tools_context["nuclei_packs"] = list_nuclei_packs()
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "error": None, "wordlist_error": None,
            **_llm_settings_context(), **_wordlist_settings_context(), **_fallback_chain_context(), **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(), **_capability_settings_context(), **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            **tools_context,
        },
    )


def _render_model_options(request: Request, provider: str, preferred_model: str | None = None) -> HTMLResponse:
    """preferred_model overrides whatever this provider's own generic "what was last used" default
    logic would otherwise pick -- for a caller (the Library panel) that has its own separately-
    persisted last-used model, unrelated to Settings' own main-agent model. Real, confirmed operator
    complaint this fixes: switching provider in the Library panel's picker always reset the model to
    that provider's generic hardcoded default (or Settings' own unrelated main-agent model, if that
    happened to match), silently discarding whatever model the operator had actually used with this
    provider in the Library before -- confirmed live: library_store's own saved
    last_provider="openrouter"/last_model="nvidia/nemotron-3-ultra-550b-a55b:free" existed on disk,
    but this endpoint kept marking "openrouter/auto" (the provider's own hardcoded default) selected
    instead, every single time."""
    if is_custom_provider_id(provider):
        custom = get_custom_provider(provider)
        if custom is None:
            return HTMLResponse("")
        current_model = preferred_model or custom.get("model") or ""
        models = get_model_choices(provider) or ([current_model] if current_model else [])
        return templates.TemplateResponse(
            request, "partials/model_options.html", {"provider_models": models, "current_model": current_model}
        )

    if provider == CODEX_PROVIDER_ID:
        saved = load_llm_settings()
        current_model = preferred_model or (saved.get("model") if saved.get("provider") == provider else None) or CODEX_DEFAULT_MODEL
        return templates.TemplateResponse(
            request, "partials/model_options.html", {"provider_models": list(CODEX_MODELS.keys()), "current_model": current_model}
        )

    if provider == COPILOT_PROVIDER_ID:
        from agent.copilot_provider import COPILOT_DEFAULT_MODEL
        saved = load_llm_settings()
        current_model = preferred_model or (saved.get("model") if saved.get("provider") == provider else None) or COPILOT_DEFAULT_MODEL
        models = get_model_choices(provider) or list(COPILOT_MODELS.keys())
        return templates.TemplateResponse(
            request, "partials/model_options.html", {"provider_models": models, "current_model": current_model}
        )

    config = PROVIDER_REGISTRY.get(provider)
    if config is None:
        return HTMLResponse("")
    saved = load_llm_settings()
    current_model = preferred_model or (
        saved.get("model") if saved.get("provider") == provider else None
    ) or os.getenv(config.model_env) or config.model_default
    models = get_model_choices(provider) or [current_model]
    return templates.TemplateResponse(
        request, "partials/model_options.html", {"provider_models": models, "current_model": current_model}
    )


@app.get("/api/settings/model-options", response_class=HTMLResponse)
def get_model_options(request: Request, provider: str = "") -> HTMLResponse:
    """HTMX-swapped <option> list for the model dropdown — refetched whenever the provider
    dropdown changes, since which models exist depends on which provider is selected."""
    return _render_model_options(request, provider)


@app.get("/api/subagents/model-options", response_class=HTMLResponse)
def get_subagent_model_options(request: Request, provider: str = "") -> HTMLResponse:
    """Same swap as Settings' own model dropdown (_render_model_options), plus the one case
    Settings never needs: a subagent's provider select has a blank "(same as main agent)" option
    Settings' own provider select doesn't, and that has to render a matching model placeholder
    instead of an empty <select> with zero <option> elements."""
    if not provider:
        return HTMLResponse('<option value="">(same as main agent)</option>')
    return _render_model_options(request, provider)


@app.get("/api/library/model-options", response_class=HTMLResponse)
def get_library_model_options(request: Request, provider: str = "") -> HTMLResponse:
    """Same swap as get_subagent_model_options, but pre-selects the Library panel's OWN last-used
    model for this provider (library_store.load_library_settings()) instead of Settings' unrelated
    main-agent model or a generic provider default -- see _render_model_options's own docstring for
    the real, confirmed bug this closes."""
    if not provider:
        return HTMLResponse('<option value="">(same as main agent)</option>')
    library_settings = library_store.load_library_settings()
    preferred = library_settings["last_model"] if library_settings["last_provider"] == provider else None
    return _render_model_options(request, provider, preferred_model=preferred)


@app.post("/api/settings/llm")
def save_llm(request: Request, provider: str = Form(""), model: str = Form("")) -> Response:
    if not is_known_provider_id(provider) or not model:
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "error": "Pick a valid provider and model.",
                "wordlist_error": None,
                **_llm_settings_context(),
                **_wordlist_settings_context(),
                **_fallback_chain_context(),
                **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(), **_capability_settings_context(), **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            },
            status_code=400,
        )

    save_llm_settings(provider, model)
    logger.debug("api: llm settings saved provider=%s model=%s", provider, model)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/secondary-verification")
def save_secondary_verification(provider: str = Form(""), model: str = Form("")) -> Response:
    """Settings -> Secondary verification provider -- a single static provider+model pair (never
    the multi-row Reserve providers UI), agent/settings.py's save_secondary_verification_provider.
    Both fields blank clears it (feature off) -- no validation error path needed the way the main
    AI Provider & Model picker has one, since an unset value is a perfectly normal, supported
    state here, not a mistake to reject."""
    clean_provider, clean_model = provider.strip(), model.strip()
    save_secondary_verification_provider(clean_provider or None, clean_model or None)
    logger.debug("api: secondary verification provider saved provider=%r model=%r", clean_provider, clean_model)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/fallback-chain")
def save_fallback_chain(
    request: Request,
    enabled: str = Form(""),
    chain_provider: list[str] = Form([]),
    chain_model: list[str] = Form([]),
) -> Response:
    """Settings -> Reserve providers -- an opt-in, off-by-default ordered LLM fallback chain built
    from real (provider, model) dropdown rows, not free text (agent/llm_client.py's
    get_next_chain_step docstring has the full incident writeup for why this replaced the old
    always-on automatic cross-provider fallback). chain_provider/chain_model arrive as same-length,
    position-paired lists -- one pair per row, in the DOM order the operator arranged them in
    (browsers serialize a form's repeated-name fields in document order), exactly the order the
    chain is walked in later.
    """
    chain: list[dict] = []
    unknown_providers: set[str] = set()
    for provider_id, model in zip(chain_provider, chain_model):
        provider_id, model = provider_id.strip(), model.strip()
        if not provider_id or not model:
            continue
        if not is_known_provider_id(provider_id):
            unknown_providers.add(provider_id)
            continue
        chain.append({"provider": provider_id, "model": model})

    if unknown_providers:
        # Only reachable via a hand-crafted request -- the real <select> only ever offers a known
        # provider id -- but never trust client-submitted data blindly regardless of what the UI
        # normally sends.
        error = f"Unknown provider id(s): {', '.join(sorted(unknown_providers))}."
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "error": None,
                "wordlist_error": None,
                **_llm_settings_context(),
                **_wordlist_settings_context(),
                **_fallback_chain_context(error=error),
                **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(), **_capability_settings_context(), **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            },
            status_code=400,
        )

    save_fallback_chain_settings(enabled == "on", chain)
    logger.debug("api: fallback chain saved enabled=%s chain=%s", enabled == "on", chain)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/test-llm/start", response_class=HTMLResponse)
def test_llm_start(request: Request, provider: str = Form(""), model: str = Form(""), target_id: str = Form("llm-test-status")) -> HTMLResponse:
    """A real, minimal completion call against whatever's currently picked in the form — not
    necessarily saved yet, same "try before you commit" flow as Project Assistant's own model
    Test button (src/providers/registry.ts testModelAvailability), which this mirrors.

    Runs as a tracked background thread (agent/tools/llm_test_job.py), not a blocking call — see
    that module's own docstring for why: up to ~60s of silent retry backoff used to leave this
    button showing "Testing..." with zero visibility and no way to cancel. This route only starts
    the thread and renders the first status fragment, which then polls test_llm_status itself.

    target_id doubles as the test job's own key (agent/tools/llm_test_job.py) -- Secondary
    verification, each Reserve providers chain row, a subagent profile's own picker, and this same
    main picker each get their own independent background job now, so clicking Test on several of
    them at once runs genuinely concurrent tests rather than fighting over one shared slot (real,
    confirmed regression from an earlier single-slot design, once more than one Test button existed
    on the same page — see that module's own docstring).
    """
    if not is_known_provider_id(provider) or not model:
        return templates.TemplateResponse(request, "partials/llm_test_status.html", {
            "status": {"running": False, "state": "error", "message": "Pick a provider and model first."},
            "target_id": target_id,
        })
    start_test(target_id, provider, model)
    return templates.TemplateResponse(request, "partials/llm_test_status.html", {
        "status": test_status(target_id), "target_id": target_id,
    })


@app.get("/api/settings/test-llm/status", response_class=HTMLResponse)
def test_llm_status(request: Request, target_id: str = "llm-test-status") -> HTMLResponse:
    return templates.TemplateResponse(request, "partials/llm_test_status.html", {
        "status": test_status(target_id), "target_id": target_id,
    })


@app.post("/api/settings/test-llm/cancel", response_class=HTMLResponse)
def test_llm_cancel(request: Request, target_id: str = "llm-test-status") -> HTMLResponse:
    return templates.TemplateResponse(request, "partials/llm_test_status.html", {
        "status": cancel_test(target_id), "target_id": target_id,
    })


@app.post("/api/settings/providers/custom", response_class=HTMLResponse)
def add_custom_provider_route(
    request: Request,
    name: str = Form(""),
    type: str = Form("universal"),
    base_url: str = Form(""),
    api_key: str = Form(""),
    model: str = Form(""),
) -> Response:
    """Settings -> LLM Providers -> Add Provider -- one dialog, two real outcomes depending on the
    picked Type. Picking one of the 8 built-ins (PROVIDER_REGISTRY) ACTIVATES that real row (saves
    into its own .env slot via save_provider_api_key/save_provider_base_url, marks it added via
    agent/settings.py's add_provider_to_list) -- it does NOT create a separate custom-provider
    entry. Real incident this branch fixes: before it existed, picking a built-in's name here
    (there used to be a same-named preset per built-in) created a confusing SECOND, differently-
    scoped "Custom" card duplicating that built-in's own name, with none of its actual behavior.
    Only "universal" (an arbitrary, not-already-built-in endpoint) falls through to the real
    custom-provider path below (agent/custom_providers.py has that path's own full rationale).
    """
    if type in PROVIDER_REGISTRY:
        if api_key.strip():
            save_provider_api_key(type, api_key.strip())
        if base_url.strip():
            save_provider_base_url(type, base_url.strip())
        add_provider_to_list(type)
        logger.debug("api: built-in provider activated id=%s", type)
        return RedirectResponse(url="/settings", status_code=303)

    clean_name = name.strip()
    resolved_type = type if type in CUSTOM_PROVIDER_TYPE_PRESETS else "universal"
    resolved_base_url = base_url.strip() or CUSTOM_PROVIDER_TYPE_PRESETS[resolved_type]["default_base_url"]

    error = None
    if not clean_name:
        error = "Provider name is required."
    elif not resolved_base_url:
        error = "Base URL is required for this provider type."

    if error:
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "error": error,
                "wordlist_error": None,
                **_llm_settings_context(),
                **_wordlist_settings_context(),
                **_fallback_chain_context(),
                **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(), **_capability_settings_context(), **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            },
            status_code=400,
        )

    entry = create_custom_provider(clean_name, resolved_base_url, api_key.strip(), model.strip(), type=resolved_type)
    invalidate_model_choices_cache()
    logger.debug("api: custom provider created id=%s name=%s type=%s base_url=%s", entry["id"], clean_name, resolved_type, resolved_base_url)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/providers/custom/{provider_id}/edit", response_class=HTMLResponse)
def edit_custom_provider_route(
    request: Request,
    provider_id: str,
    name: str = Form(""),
    base_url: str = Form(""),
    api_key: str = Form(""),
    model: str = Form(""),
) -> Response:
    """Settings -> Providers -> a custom row's own gear button (templates/settings.html's
    custom_provider_edit_dialog) -- fixes a typo'd base_url, rotates a key, or renames an already-
    created custom instance in place (agent/custom_providers.py's update_custom_provider). Real gap
    this fixes: Delete + re-Add used to be the only way to touch anything about a custom provider
    once created, which meant a NEW id (breaking any Reserve-chain row or subagent picker pointing
    at the old one) just to fix a typo. Same "blank api_key means keep the existing one" convention
    save_api_key already uses for built-ins (see its own docstring) -- name/base_url/model ARE
    pre-filled with their real current values in the dialog, so a deliberately emptied one here
    does overwrite, same as add_custom_provider_route's own validation on those two fields.
    """
    entry = get_custom_provider(provider_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Custom provider not found")

    clean_name = name.strip()
    clean_base_url = base_url.strip()
    error = None
    if not clean_name:
        error = "Provider name is required."
    elif not clean_base_url:
        error = "Base URL is required."

    if error:
        return templates.TemplateResponse(
            request,
            "settings.html",
            {
                "error": error,
                "wordlist_error": None,
                **_llm_settings_context(),
                **_wordlist_settings_context(),
                **_fallback_chain_context(),
                **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(), **_capability_settings_context(), **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            },
            status_code=400,
        )

    fields = {"name": clean_name, "base_url": clean_base_url, "model": model.strip()}
    if api_key.strip():
        fields["api_key"] = api_key.strip()
    update_custom_provider(provider_id, **fields)
    invalidate_model_choices_cache(provider_id)
    logger.debug("api: custom provider edited id=%s", provider_id)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/providers/custom/{provider_id}/toggle")
def toggle_custom_provider_route(provider_id: str) -> Response:
    entry = get_custom_provider(provider_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Custom provider not found")
    new_state = not entry.get("enabled", True)
    update_custom_provider(provider_id, enabled=new_state)
    invalidate_model_choices_cache(provider_id)
    logger.debug("api: custom provider id=%s enabled=%s", provider_id, new_state)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/providers/custom/{provider_id}/delete")
def delete_custom_provider_route(provider_id: str) -> Response:
    if not delete_custom_provider(provider_id):
        raise HTTPException(status_code=404, detail="Custom provider not found")
    invalidate_model_choices_cache(provider_id)
    logger.debug("api: custom provider deleted id=%s", provider_id)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/providers/custom/test", response_class=HTMLResponse)
def test_custom_provider_route(request: Request, base_url: str = Form(""), api_key: str = Form("")) -> HTMLResponse:
    """Stateless connection check for a custom endpoint -- works both for the Add Provider modal
    (testing form values before anything is saved) and for an already-saved row's own Test button
    (that row's own base_url/api_key included from its small standalone form), same "try before
    you commit" Test button every other provider row in this app already has."""
    if not base_url.strip():
        return templates.TemplateResponse(request, "partials/api_key_test_result.html", {"ok": False, "message": "Enter a Base URL first."})
    result = test_custom_provider_connection(base_url.strip(), api_key.strip())
    logger.debug("api: test custom provider base_url=%s ok=%s", base_url, result["ok"])
    return templates.TemplateResponse(request, "partials/api_key_test_result.html", result)


@app.post("/api/settings/providers/openai-chatgpt/login/start")
def start_codex_login() -> dict:
    """Settings -> "Sign in with ChatGPT" button. Starts the PKCE flow (agent/codex_oauth.py) and
    returns the URL the frontend opens in a new tab -- a JSON endpoint, not an HTML fragment,
    since the button's own JS needs the raw auth_url to call window.open() and then poll
    login/status below, not a swapped-in DOM fragment.
    """
    attempt = start_codex_login_flow()
    logger.debug("api: codex oauth login started state=%s", attempt["state"])
    return attempt


@app.get("/api/settings/providers/openai-chatgpt/login/status")
def codex_login_status(state: str = "") -> dict:
    """Polled by the Settings page while a "Sign in with ChatGPT" tab is open, to detect the local
    callback listener (127.0.0.1:1455) actually completing the flow -- see
    agent/codex_oauth.py's start_login_flow/get_login_status docstrings."""
    if not state:
        return {"status": "error", "message": "Missing state."}
    return get_codex_login_status(state)


@app.post("/api/settings/providers/openai-chatgpt/logout")
def codex_logout() -> Response:
    clear_codex_tokens()
    logger.debug("api: codex oauth signed out")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/providers/openai-chatgpt/test", response_class=HTMLResponse)
def test_codex_session(request: Request) -> HTMLResponse:
    """Settings -> "Sign in with ChatGPT" -> Test. Quota-free on purpose, unlike test-llm/start's
    real minimal completion call for an API-key provider: this only refreshes/validates the stored
    OAuth token the same way get_valid_access_token always does right before a real Codex call
    (agent/codex_oauth.py) -- a plain OAuth token-refresh request to auth.openai.com, never a call
    to the actual Codex/chat backend, so it never spends any of the operator's ChatGPT usage.
    force_refresh=True so this always genuinely re-validates the session with OpenAI rather than
    trusting a locally-cached token that looks unexpired but was already revoked server-side.
    """
    try:
        token_info = get_valid_codex_access_token(force_refresh=True)
        ok, message = True, f"Session valid (account {token_info['account_id'][:8]}...)."
    except RuntimeError as exc:
        ok, message = False, str(exc)
    logger.debug("api: codex session test ok=%s", ok)
    return templates.TemplateResponse(request, "partials/api_key_test_result.html", {"ok": ok, "message": message})


@app.post("/api/settings/providers/github-copilot/login/start")
def start_copilot_login() -> dict:
    """Settings -> "Sign in with GitHub Copilot" button. Unlike start_codex_login above, this is a
    real network call to GitHub's own device-code endpoint (agent/copilot_oauth.py's
    _request_device_code) and can genuinely fail (GitHub outage, no network) -- caught here and
    turned into the same {"error": ...} shape the frontend's own asraStartCopilotLogin already
    checks for, rather than a bare 500.
    """
    try:
        attempt = start_copilot_login_flow()
    except RuntimeError as exc:
        logger.debug("api: copilot oauth login start failed: %s", exc)
        return {"error": str(exc)}
    logger.debug("api: copilot oauth login started user_code=%s", attempt["user_code"])
    return attempt


@app.get("/api/settings/providers/github-copilot/login/status")
def copilot_login_status(device_code: str = "") -> dict:
    """Polled by the Settings page while a "Sign in with GitHub Copilot" device-flow attempt is in
    progress -- see agent/copilot_oauth.py's start_login_flow/get_login_status docstrings."""
    if not device_code:
        return {"status": "error", "message": "Missing device_code."}
    return get_copilot_login_status(device_code)


@app.post("/api/settings/providers/github-copilot/logout")
def copilot_logout() -> Response:
    clear_copilot_tokens()
    logger.debug("api: copilot oauth signed out")
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/providers/github-copilot/test", response_class=HTMLResponse)
def test_copilot_session(request: Request) -> HTMLResponse:
    """Copilot counterpart to test_codex_session above -- see its own docstring for why this is
    deliberately quota-free. Exchanges the stored GitHub OAuth token for a fresh Copilot API token
    (agent/copilot_oauth.py's get_valid_copilot_token, GET api.github.com/copilot_internal/v2/token)
    but never calls api.githubcopilot.com's own chat/completions endpoint, so it never spends any
    of the operator's Copilot usage either.
    """
    try:
        get_valid_copilot_token(force_refresh=True)
        ok, message = True, "Session valid."
    except RuntimeError as exc:
        ok, message = False, str(exc)
    logger.debug("api: copilot session test ok=%s", ok)
    return templates.TemplateResponse(request, "partials/api_key_test_result.html", {"ok": ok, "message": message})


@app.post("/api/settings/api-key")
def save_api_key(provider: str = Form(""), api_key: str = Form(""), base_url: str = Form("")) -> Response:
    """Saves this provider's key and/or endpoint override in one submit (Settings' per-provider
    modal). Blank api_key is a no-op (preserves whatever's already saved) -- the field is never
    pre-filled with a real secret, so an empty submit could just mean "didn't retype it", never
    "clear it" (that's the separate, explicitly-confirmed Clear button). Blank base_url, in
    contrast, actively reverts to the registry default: that field IS pre-filled with its real
    current value, so a deliberately emptied field is unambiguous -- see save_provider_base_url.
    """
    if provider not in PROVIDER_REGISTRY:
        raise HTTPException(status_code=400, detail="Unknown provider")
    if api_key.strip():
        save_provider_api_key(provider, api_key.strip())
        logger.debug("api: api-key saved provider=%s", provider)
    save_provider_base_url(provider, base_url.strip())
    logger.debug("api: base-url set provider=%s override=%s", provider, bool(base_url.strip()))
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/clear-api-key")
def clear_api_key(provider: str = Form("")) -> Response:
    if provider not in PROVIDER_REGISTRY:
        raise HTTPException(status_code=400, detail="Unknown provider")
    clear_provider_api_key(provider)
    logger.debug("api: api-key cleared provider=%s", provider)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/tool-api-key")
def save_tool_api_key_route(tool: str = Form(""), api_key: str = Form("")) -> Response:
    """Settings -> Tool API Keys -> Save (agent/tools/tool_api_keys.py). Same "blank is a no-op"
    rule save_api_key above already follows for LLM provider keys -- this field is never pre-filled
    with the real saved secret, so an empty submit means "didn't retype it", never "clear it" (the
    separate, explicitly-confirmed Clear route below)."""
    if tool not in TOOL_API_KEY_SPECS:
        raise HTTPException(status_code=400, detail="Unknown tool")
    if api_key.strip():
        save_tool_api_key(tool, api_key.strip())
        logger.debug("api: tool api-key saved tool=%s", tool)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/clear-tool-api-key")
def clear_tool_api_key_route(tool: str = Form("")) -> Response:
    if tool not in TOOL_API_KEY_SPECS:
        raise HTTPException(status_code=400, detail="Unknown tool")
    clear_tool_api_key(tool)
    logger.debug("api: tool api-key cleared tool=%s", tool)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/timezone")
def save_timezone_route(tz: str = Form("")) -> Response:
    if tz not in display_timezone_choices():
        raise HTTPException(status_code=400, detail="Unknown timezone")
    save_display_timezone(tz)
    logger.debug("api: display timezone saved tz=%s", tz)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/clock-display/{field}")
def save_clock_display_route(field: str, enabled: str | None = Form(None)) -> Response:
    """One toggle, one independent request touching only its own field -- same pattern as
    save_toolkit_agent_setting_route below (a stale-tab-reverts-a-sibling-field bug class already
    fixed once for that one)."""
    if field == "show_clock":
        save_clock_show_time(bool(enabled))
    elif field == "show_zone_label":
        save_clock_show_zone_label(bool(enabled))
    elif field == "show_date":
        save_clock_show_date(bool(enabled))
    else:
        raise HTTPException(status_code=404, detail=f"unknown clock display setting {field!r}")
    logger.debug("api: clock-display saved %s=%s", field, bool(enabled))
    return Response(status_code=204)


@app.post("/api/settings/clock-style")
def save_clock_style_route(style: str = Form("")) -> Response:
    if style not in CLOCK_STYLES:
        raise HTTPException(status_code=400, detail="Unknown clock style")
    save_clock_style(style)
    logger.debug("api: clock style saved style=%s", style)
    return Response(status_code=204)


@app.post("/api/settings/intro")
def save_intro_enabled_route(enabled: str | None = Form(None)) -> Response:
    """Settings -> Customization -> Visual's "Play launch intro" switch -- persisted straight to
    .env (agent/intro_settings.py) rather than this app's usual on-disk JSON stores, since the
    Rust desktop shell's own get_start_config() reads it directly from .env on the NEXT launch,
    before this backend even exists. This already-running process has no live use for the new
    value itself."""
    save_intro_enabled(bool(enabled))
    logger.debug("api: intro enabled saved enabled=%s", bool(enabled))
    return Response(status_code=204)


@app.post("/api/settings/intro-sound")
def save_intro_sound_enabled_route(enabled: str | None = Form(None)) -> Response:
    """Settings -> Customization -> Visual's "Play intro sound" switch -- same .env-backed
    convention as save_intro_enabled_route above (agent/intro_settings.py), since the Rust desktop
    shell reads it directly on the NEXT launch, before this backend exists."""
    save_intro_sound_enabled(bool(enabled))
    logger.debug("api: intro sound enabled saved enabled=%s", bool(enabled))
    return Response(status_code=204)


@app.post("/api/settings/sounds/master")
def save_sound_master_route(enabled: str | None = Form(None)) -> Response:
    """Settings -> Customization -> Sounds top-level switch -- everything under it stays off regardless of each
    event's own toggle unless this is also on (belt-and-suspenders with each event defaulting to
    off itself, and a fast one-flip mute-all)."""
    save_master_sound_enabled(bool(enabled))
    logger.debug("api: sound master saved enabled=%s", bool(enabled))
    return Response(status_code=204)


@app.post("/api/settings/sounds/{event_id}")
def save_sound_event_route(event_id: str, enabled: str | None = Form(None), sound: str = Form("")) -> Response:
    """One event row, one independent request touching only its own field -- same pattern as
    save_clock_display_route above (a stale-tab-reverts-a-sibling-field bug class already fixed
    once for that one)."""
    try:
        save_sound_event(event_id, bool(enabled), sound)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    logger.debug("api: sound event saved event=%s enabled=%s sound=%s", event_id, bool(enabled), sound)
    return Response(status_code=204)


@app.post("/api/settings/providers/{provider_id}/toggle")
def toggle_builtin_provider_route(provider_id: str) -> Response:
    """Settings -> Providers row toggle for a built-in (PROVIDER_REGISTRY) provider -- same idea as
    toggle_custom_provider_route above, for the 8 fixed providers instead of an operator-added
    instance. Does not touch the saved key/endpoint, only whether this provider is offered in the
    Reserve providers chain and subagent pickers (agent.llm_client.all_provider_choices)."""
    if provider_id not in PROVIDER_REGISTRY:
        raise HTTPException(status_code=400, detail="Unknown provider")
    new_state = not is_provider_enabled(provider_id)
    set_provider_enabled(provider_id, new_state)
    logger.debug("api: provider id=%s enabled=%s", provider_id, new_state)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/providers/{provider_id}/remove")
def remove_builtin_provider_route(provider_id: str) -> Response:
    """Settings -> Providers row Delete for a built-in -- the row-level counterpart of
    delete_custom_provider_route, for one of the 8 fixed providers instead of an operator-added
    instance. Deliberately a DIFFERENT, broader action than clear_api_key above (that one is the
    Configure dialog's own narrower "Remove saved key" link, which never touches the endpoint
    override or this provider's visibility): this clears the saved key AND any endpoint override
    AND un-adds the provider (agent/settings.py's remove_provider_from_list), so the row disappears
    from the Providers list again until explicitly added a second time -- a full, honest reset, not
    a half-clear that would leave a still-visible row with nothing real behind it.
    """
    if provider_id not in PROVIDER_REGISTRY:
        raise HTTPException(status_code=400, detail="Unknown provider")
    clear_provider_api_key(provider_id)
    clear_provider_base_url(provider_id)
    remove_provider_from_list(provider_id)
    logger.debug("api: built-in provider removed id=%s", provider_id)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/test-api-key", response_class=HTMLResponse)
def test_api_key(request: Request, provider: str = Form(""), api_key: str = Form(""), base_url: str = Form("")) -> HTMLResponse:
    """Token-free key check -- see check_api_key's own docstring (agent/llm_client.py) for why
    this deliberately does not call llm.complete() the way test_llm above does. base_url, when
    typed but not yet saved, is honored too -- lets an operator confirm a custom endpoint works
    before committing it, not just whatever's already in .env."""
    config = PROVIDER_REGISTRY.get(provider)
    if config is None:
        return templates.TemplateResponse(request, "partials/api_key_test_result.html", {"ok": False, "message": "Unknown provider."})
    key_to_test = api_key.strip() or get_provider_api_key(config)
    if not key_to_test and config.api_key_required:
        return templates.TemplateResponse(request, "partials/api_key_test_result.html", {"ok": False, "message": "No key to test — type one first."})
    result = check_api_key(provider, key_to_test, base_url.strip() or None)
    logger.debug("api: test-api-key provider=%s ok=%s", provider, result["ok"])
    return templates.TemplateResponse(request, "partials/api_key_test_result.html", result)


@app.post("/api/settings/wordlists/download", response_class=HTMLResponse)
def download_wordlist_route(request: Request, source_url: str = Form(""), name: str = Form(""), kind: str = Form("general")) -> HTMLResponse:
    """Human-triggered only -- the operator pastes a URL they already trust into their own app's
    Settings page and clicks Download. There is no equivalent tool registration, so the LLM agent
    can never reach this itself; it exists purely for provisioning the machine, same category as
    setup_tools.sh's own opt-in installers."""
    if not source_url.strip():
        return templates.TemplateResponse(
            request, "settings.html",
            {
                "error": None, "wordlist_error": "Enter a URL to download from.",
                **_llm_settings_context(), **_wordlist_settings_context(), **_fallback_chain_context(), **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(), **_capability_settings_context(), **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            },
            status_code=400,
        )
    try:
        download_wordlist(source_url.strip(), name.strip(), kind.strip() or "general")
    except ValueError as exc:
        logger.debug("api: wordlist download failed url=%s: %s", source_url, exc)
        return templates.TemplateResponse(
            request, "settings.html",
            {
                "error": None, "wordlist_error": str(exc),
                **_llm_settings_context(), **_wordlist_settings_context(), **_fallback_chain_context(), **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(), **_capability_settings_context(), **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            },
            status_code=400,
        )
    logger.debug("api: wordlist downloaded url=%s kind=%s", source_url, kind)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/wordlists/assign")
def assign_wordlist_route(role: str = Form(""), path: str = Form("")) -> Response:
    if role not in ASSIGNABLE_ROLES:
        raise HTTPException(status_code=400, detail="Unknown wordlist role")
    set_assignment(role, path.strip() or None)
    logger.debug("api: wordlist assignment role=%s path=%r", role, path)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/capabilities/{capability_id}/install", response_class=HTMLResponse)
def install_capability_route(request: Request, capability_id: str) -> Response:
    """Settings -> Optional interpreters/compilers -> Install. Same "plain form POST, redirect on
    success, re-render settings.html inline on failure" shape as the wordlist download route above
    -- on failure the re-render carries capability_install_error (agent/tools/capability_install.py's
    own error dict: the exact command + stdout/stderr) so that one row can show the manual-install
    fallback + Copy button, everything else on the page unchanged."""
    if get_capability(capability_id) is None:
        raise HTTPException(status_code=404, detail="Unknown capability")

    result = install_capability(capability_id)
    logger.debug("api: capability install id=%s status=%s", capability_id, result["status"])
    if result["status"] != "ok":
        return templates.TemplateResponse(
            request, "settings.html",
            {
                "error": None, "wordlist_error": None,
                **_llm_settings_context(), **_wordlist_settings_context(), **_fallback_chain_context(),
                **_custom_providers_context(), **_codex_oauth_context(), **_copilot_oauth_context(),
                **_capability_settings_context(install_error={"capability_id": capability_id, **result}),
                **_toolkit_agent_settings_context(), **_tool_api_keys_context(), **_timezone_settings_context(), **_sound_settings_context(), **_intro_settings_context(), **_secondary_verification_context(), **_chat_settings_context(),
            },
            status_code=400,
        )
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/capabilities/{capability_id}/path")
def save_capability_path_route(capability_id: str, path: str = Form("")) -> Response:
    if get_capability(capability_id) is None:
        raise HTTPException(status_code=404, detail="Unknown capability")
    save_tool_path(capability_id, path)
    logger.debug("api: capability path id=%s path=%r", capability_id, path)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/sudo-password")
def save_sudo_password_route(password: str = Form("")) -> Response:
    """Settings -> Optional interpreters/compilers -> Sudo password (optional, empty by default).
    Never logs or echoes the value back -- same discipline agent/llm_client.py's own provider-key
    save route already follows."""
    save_sudo_password(password)
    logger.debug("api: sudo password %s", "saved" if password.strip() else "cleared")
    return RedirectResponse(url="/settings", status_code=303)


def _provider_picker_context() -> dict:
    """The provider-list portion any "pick an LLM provider actually configured in Settings" UI
    needs — shared by a subagent profile's own picker (subagents.html) and the chat panel's own
    picker (chat_panel.html); factored out of _subagent_context (below) once chat needed the exact
    same thing, rather than a second near-duplicate copy.

    Same "Configured"/"Not set" status-dot convention as Settings' own provider rows — read fresh
    on every render, since a key can be added/removed from .env between requests. Only providers
    actually usable right now (no key required, or a key already saved in Settings) are offered —
    picking an unconfigured one here would just fail at run time with no way to fix the key from
    this page. A previously-saved provider that later loses its key is still shown as a fallback
    option by the provider_options macro (macros/ui.html), so a picker never silently discards an
    already-stored choice.
    """
    provider_key_status = {pid: bool(get_provider_api_key(cfg)) for pid, cfg in PROVIDER_REGISTRY.items()}
    # Real, confirmed bug this fixes: a local provider (LM Studio/Ollama, api_key_required=False)
    # used to pass the "usable" check unconditionally -- `not cfg.api_key_required` is trivially
    # True for BOTH of them regardless of whether the operator ever touched Settings, because
    # LMSTUDIO_BASE_URL/OLLAMA_BASE_URL are already pre-filled in .env.example with the exact same
    # localhost URL PROVIDER_REGISTRY's own base_url_default already hardcodes -- the same
    # "un-edited placeholder reads as configured" trap _looks_like_env_example_placeholder already
    # exists to catch for API keys, just with no equivalent guard for a local provider's base_url.
    # _reachable_local_provider_ids() (not a per-provider get_model_choices() call here) is a REAL
    # live probe of each local provider's own /models endpoint (_fetch_local_model_ids, already
    # cached 30s) -- empty means nothing is actually listening there, which is the one honest
    # signal that distinguishes "the operator is genuinely running LM Studio/Ollama" from "the
    # .env default is just sitting there unused," the same way an operator explicitly setting a
    # real API key does for a cloud one. Run CONCURRENTLY, not one get_model_choices(pid) call per
    # local provider in the comprehension below -- real, confirmed incident this fixes: every
    # session page load (this function is part of get_session_page's own _chat_context) paid LM
    # Studio's own LOCAL_MODEL_DISCOVERY_TIMEOUT_SECONDS timeout, then Ollama's, back to back,
    # whenever the operator runs neither and the 30s cache was stale -- "opening any project" cost
    # up to ~4s of pure network-timeout wait on this app's own critical path, the identical shape
    # _reachable_local_provider_ids's own docstring already documents fixing for /settings.
    reachable_local_ids = _reachable_local_provider_ids()
    configured_provider_ids = [
        pid for pid, cfg in PROVIDER_REGISTRY.items()
        if is_provider_enabled(pid) and (
            pid in reachable_local_ids if cfg.is_local
            else (not cfg.api_key_required or provider_key_status[pid])
        )
    ]
    # Enabled custom instances (agent/custom_providers.py) are always considered "usable" here --
    # unlike a PROVIDER_REGISTRY built-in, a custom entry has no separate "key required" concept to
    # check: the operator already supplied whatever key/base_url it needs at creation time.
    custom_providers = [p for p in load_custom_providers() if p.get("enabled", True)]
    return {
        "configured_cloud_provider_ids": [pid for pid in configured_provider_ids if not PROVIDER_REGISTRY[pid].is_local],
        "configured_local_provider_ids": [pid for pid in configured_provider_ids if PROVIDER_REGISTRY[pid].is_local],
        "custom_providers": custom_providers,
        # Same "only offer what's actually usable right now" rule as configured_provider_ids above
        # -- unlike the main Settings picker (which lists it unconditionally, same as an API-key
        # built-in is listed before its key is set), a picker here choosing an unsigned-in Codex
        # session would just fail at run time with no way to fix it from this page.
        **_codex_oauth_context(), **_copilot_oauth_context(),
        # provider_display_names (the module-load-time Jinja global, built-ins only) plus every
        # custom instance's own name -- a plain-text provider display (not through provider_options'
        # own <option> labels) needs this to resolve a custom provider id to something readable
        # instead of the bare id string.
        "all_provider_display_names": dict(all_provider_choices()),
    }


def _tool_domain(entry: dict) -> str:
    """Buckets one list_tool_availability() entry into the 4 domains an operator actually thinks in
    terms of -- "browser"/"re"/"toolkit"/"web" -- shared by both the /tools page's own grouped
    sections and the Subagents tool checklist's per-row indicator dot, so the two views can never
    silently disagree about which bucket a given tool belongs to.

    Real, confirmed gap this closes: both views used to show every tool as one flat, alphabetically
    sorted list with no domain signal at all -- indistinguishable at a glance whether a given name
    was a reverse-engineering tool, an ordinary web-pentest one, or a manual HTTP-toolkit
    primitive, on either page.

    registry.py's own Category type has exactly 6 values (recon/scan/exploit/post_exploit/toolkit/
    re) and its own docstrings confirm "re" and "toolkit" are never mixed with each other or with a
    web category in the same ToolSpec (grepped live across every register_tool call site to
    confirm this before relying on it) -- so classifying on "re" first, then "toolkit", with
    everything else falling through to "web" is an exhaustive, non-overlapping partition, not a
    guess. "browser" is checked first and takes priority over all three: every browser_* tool is
    itself category=("recon","scan","exploit") (agent/core.py's _BROWSER_TOOL_NAMES, so it's
    offered in every ordinary web phase too) and would otherwise land in "web" -- but an operator
    thinking "which tools drive an actual browser page" wants that as its own clearly separate
    group, not buried alphabetically inside three dozen other web-pentest tools. Name-prefix check
    (not importing agent.core's own private _BROWSER_TOOL_NAMES across a module boundary) --
    every one of them is literally named browser_*, confirmed live, a simpler and equally correct
    signal than reaching into another module's underscore-prefixed constant.
    """
    if entry["name"].startswith("browser_"):
        return "browser"
    categories = entry["categories"]
    if "re" in categories:
        return "re"
    if "toolkit" in categories:
        return "toolkit"
    return "web"


def _subagent_context() -> dict:
    profiles = load_subagent_profiles()["profiles"]
    installed_tools = [entry for entry in list_tool_availability() if entry["installed"]]
    # delegate_to_subagent/check_subagent_task/record_finding/record_target and the six phase-
    # terminal "recording" tools are never offered as a checkable option for a subagent profile's
    # own tool list -- agent/core.py's _delegate_to_subagent_impl (_subagent_disallowed_tools)
    # strips them from tool_specs unconditionally regardless of what's stored here (see that
    # filter's own docstring for the real recursive-delegation incident the first two close, and
    # the real finding-loss incident record_finding/record_target and their six siblings close), so
    # showing them as checkable would just be a checkbox that silently does nothing useful once
    # saved -- worse than an ordinary unavailable tool, since the tool call itself still returns
    # "status": "ok", making it look like it worked right up until the operator notices the
    # finding/decision never actually made it into the report.
    _subagent_unofferable_tools = {
        "delegate_to_subagent", "check_subagent_task", "record_finding", "record_target",
        "record_hypothesis", "resolve_hypothesis", "record_exploit_decision",
        "record_chain_result", "record_reverification_result", "record_skeptical_verification_result",
    }
    installed_tools = [entry for entry in installed_tools if entry["name"] not in _subagent_unofferable_tools]
    return {
        "subagent_profiles": profiles,
        # Only real, currently-installed tools are ever offered for a profile's own checklist —
        # never a hardcoded list a machine might not actually have (agent/tools/tool_inventory.py).
        "available_tools": [entry["name"] for entry in installed_tools],
        # Surfaced as a hover tooltip on each tool checkbox (subagents.html's tool_checklist macro)
        # so picking a tool doesn't require already knowing what it does.
        "tool_descriptions": {entry["name"]: entry["description"] for entry in installed_tools},
        # Drives the small colored domain dot subagents.html renders next to each checkbox --
        # see _tool_domain's own docstring for the browser/re/toolkit/web bucketing itself.
        "tool_domains": {entry["name"]: _tool_domain(entry) for entry in installed_tools},
        **_provider_picker_context(),
        # Pre-fetched per-profile so each edit dialog's model <select> renders the right options
        # (and the saved model pre-selected) on first page load, before the provider dropdown's
        # own hx-get ever fires — same source (get_model_choices) the provider-change swap uses,
        # so the list never disagrees with what picking that provider live would show.
        "subagent_model_choices": {
            profile["id"]: _model_choices_with_fallback(profile["provider"], profile.get("model"))
            for profile in profiles
            if profile.get("provider") and is_known_provider_id(profile["provider"])
        },
    }


def _model_choices_with_fallback(provider_id: str, current_model: str | None) -> list[str]:
    choices = get_model_choices(provider_id)
    if current_model and current_model not in choices:
        choices = [*choices, current_model]
    return choices


@app.get("/toolkit", response_class=HTMLResponse)
def get_toolkit_standalone(request: Request) -> HTMLResponse:
    """The standalone Toolkit page (sidebar nav) -- genuinely no project/session involved, see
    templates/toolkit_standalone.html's own docstring. This route itself needs no context at all;
    partials/toolkit_panel.html's own sub-panels each fetch their own data via the /api/toolkit/...
    routes (the un-prefixed twin of every /api/session/{session_id}/toolkit/... route)."""
    return templates.TemplateResponse(request, "toolkit_standalone.html", {})


_DORK_KIND_LABELS = {
    "search_lead": "Search-engine dorks",
    "native_tool": "Live OSINT lookups (ASRA's own tools)",
    "external_link": "Third-party OSINT services",
    "direct_url": "Direct target paths",
}


def _dorks_panel_context(
    target: str = "", engine: str = DORK_DEFAULT_ENGINE, custom_dork: str = "", result: dict | None = None,
) -> dict:
    categories_by_kind: dict[str, list] = {}
    for category in list_dork_categories():
        categories_by_kind.setdefault(category.kind, []).append(category)
    return {
        "target": target,
        "engine": engine,
        "custom_dork": custom_dork,
        "result": result,
        "engines": sorted(DORK_SEARCH_ENGINES),
        # dict insertion order == _DORK_KIND_LABELS' own order, which controls the section order
        # the manual tab renders in -- search dorks first (the genuinely new capability this
        # feature adds), live lookups second, then the two smaller third-party/direct buckets.
        "categories_by_kind": {kind: categories_by_kind[kind] for kind in _DORK_KIND_LABELS if kind in categories_by_kind},
        "kind_labels": _DORK_KIND_LABELS,
    }


@app.get("/dorks", response_class=HTMLResponse)
def get_dorks_standalone(request: Request) -> HTMLResponse:
    """Dork Engine's standalone page (sidebar nav) -- same "no project/session needed" shape as
    /toolkit (templates/toolkit_standalone.html), for the same reason: dorking a target is ad-hoc
    manual work, never tied to one specific engagement's own project folder. The exact same catalog
    (agent/tools/dork_engine.py) backs the dork_search tool the autonomous agent/subagents/chat all
    call natively -- this page is the manual, point-and-click front end onto the same code, not a
    second implementation."""
    return templates.TemplateResponse(request, "dorks_standalone.html", _dorks_panel_context())


@app.post("/api/dorks/build", response_class=HTMLResponse)
def post_dorks_build(
    request: Request,
    target: str = Form(""),
    category: str = Form(""),
    custom_dork: str = Form(""),
    engine: str = Form(DORK_DEFAULT_ENGINE),
) -> HTMLResponse:
    result = build_dork_result(
        target=target.strip() or None,
        category_id=category.strip() or None,
        custom_dork=custom_dork.strip() or None,
        engine=engine,
    )
    logger.debug(
        "api: dorks build target=%r category=%r engine=%s -> status=%s",
        target, category or None, engine, result.get("status"),
    )
    context = _dorks_panel_context(target=target, engine=engine, custom_dork=custom_dork, result=result)
    return templates.TemplateResponse(request, "partials/dorks_panel.html", context)


@app.get("/terminal", response_class=HTMLResponse)
def get_terminal_page(request: Request, cwd: str = "") -> HTMLResponse:
    """Standalone Terminal tab (sidebar nav) -- a real system shell, no project/session required.
    An optional ?cwd= (the per-project "Open terminal here" button, session.html) tells the
    frontend (static/js/terminal.js) to auto-open a first tab rooted there instead of the
    operator's own home directory."""
    return templates.TemplateResponse(request, "terminal.html", {
        "initial_cwd": cwd,
        "initial_skip_close_confirm": terminal_settings.load_terminal_settings()["skip_close_confirm"],
    })


@app.get("/api/terminal/shells")
def list_terminal_shells() -> JSONResponse:
    """Real, verified-present shells on this machine (agent/tools/terminal_manager.py's own
    detect_available_shells) -- backs the tab-strip's terminal-type picker (like VS Code's own "+"
    dropdown)."""
    return JSONResponse({
        "shells": terminal_manager.detect_available_shells(),
        "default": terminal_manager.default_shell_path(),
    })


@app.post("/api/terminal/settings")
async def save_terminal_settings_route(request: Request) -> Response:
    """The tab strip's "don't ask again" checkbox (middle-click close confirmation) -- persisted
    server-side (agent/tools/terminal_settings.py) so it survives a full ASRA process restart and
    is shared between the desktop shell's own webview and a plain browser tab, neither of which a
    localStorage-only flag could give. Best-effort body parsing, same convention as
    toolkit_live_view_input above -- this is a background fetch() the operator never sees the
    response of."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    terminal_settings.save_skip_close_confirm(bool(payload.get("skip_close_confirm")))
    return Response(status_code=204)


@app.post("/api/terminal/new")
async def create_terminal_session(request: Request) -> JSONResponse:
    """Spawns a brand-new real PTY shell (agent/tools/terminal_manager.py) and returns its id --
    the WS connection itself carries all actual terminal I/O, this just creates the process. A
    malformed/missing JSON body just means "no cwd/shell override", same best-effort body parsing
    as toolkit_live_view_input above."""
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    cwd = (payload.get("cwd") or "").strip() or None
    shell = (payload.get("shell") or "").strip() or None
    session = await terminal_manager.create_terminal(cwd, shell)
    return JSONResponse({"terminal_id": session.id, "cwd": session.cwd, "shell": session.shell, "kind": session.kind})


@app.get("/api/terminal/list")
def list_terminal_sessions() -> JSONResponse:
    """Every live/exited-but-not-closed terminal session (agent/tools/terminal_manager.py) -- called
    by static/js/terminal.js on every Terminal-page load so it can reattach to whatever's still
    actually running server-side instead of blindly spawning a fresh shell and orphaning the old
    one. Real, confirmed bug this fixes: a full page reload/navigation used to always call
    /api/terminal/new, silently leaking every previously-open tab's real PTY process forever while
    the operator watched their terminal get wiped clean on every refresh/tab-switch."""
    return JSONResponse({"terminals": terminal_manager.list_terminals()})


@app.post("/api/terminal/{terminal_id}/close")
def close_terminal_session(terminal_id: str) -> Response:
    terminal_manager.close_terminal(terminal_id)
    return Response(status_code=204)


@app.websocket("/ws/terminal/{terminal_id}")
async def ws_terminal(websocket: WebSocket, terminal_id: str) -> None:
    """The Terminal tab's real byte-stream channel. Binary frames only.
    Client -> server: first byte is a tiny command tag -- 0x00 = raw stdin bytes follow, 0x01 =
    resize (4 bytes follow: cols then rows, each big-endian u16). Server -> client: raw PTY output
    as-is (no framing needed -- only one kind of data ever flows this direction), plus the odd
    text/JSON frame for a lifecycle event ("exited" with the child's exit code). A fresh
    (re)attach gets the session's in-memory scrollback replayed immediately, so reconnecting after
    a page reload doesn't lose what was already on screen.
    """
    if not _desktop_ui_token_ok(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()

    session = await terminal_manager.attach(terminal_id, websocket)
    if session is None:
        await websocket.send_json({"type": "error", "message": "terminal not found"})
        await websocket.close(code=1000)
        return

    scrollback = session.get_scrollback()
    if scrollback:
        await websocket.send_bytes(scrollback)
    if session.exited:
        await websocket.send_json({"type": "exited", "code": session.exit_code})

    try:
        while True:
            try:
                message = await websocket.receive_bytes()
            except WebSocketDisconnect:
                break
            if not message:
                continue
            tag = message[0]
            if tag == 0x00:
                session.write_input(message[1:])
            elif tag == 0x01 and len(message) >= 5:
                cols = int.from_bytes(message[1:3], "big")
                rows = int.from_bytes(message[3:5], "big")
                session.resize(cols, rows)
    finally:
        terminal_manager.detach(terminal_id, websocket)


def _filter_techniques(techniques: list[dict], query: str, outcome: str = "", rank: str = "", confidence: str = "", source_id: str = "") -> list[dict]:
    """Narrows the list by the operator's own filters, most-selective/cheapest first: outcome
    ('worked'/'failed', from the Outcome dropdown), rank tier ('bronze'..'legendary', see
    playbook_store.RANK_ORDER, from the Rank dropdown), confidence ('unreviewed', from the Review
    dropdown -- library-extracted entries not yet confirmed, see agent/tools/library_store.py),
    source_id (one specific Library source's own extractions only -- the Library panel's "Review in
    Playbook" link now scopes to this instead of dumping every unreviewed technique from every
    source into one undifferentiated list, a real, confirmed operator complaint: "не все вместе в
    кашу"), then the free-text substring search over technique text/tech keywords/WAF vendors/vuln
    class. Every filter left at its default ("") is a no-op, so an empty toolbar still returns
    everything."""
    out = techniques
    if outcome in ("worked", "failed"):
        out = [t for t in out if t.get("outcome") == outcome]
    if rank in playbook_store.RANK_ORDER:
        out = [t for t in out if t.get("rank") == rank]
    if confidence == "unreviewed":
        out = [t for t in out if t.get("confidence") == "unreviewed"]
    if source_id:
        out = [t for t in out if t.get("source_id") == source_id]
    q = (query or "").strip().lower()
    if q:
        def _hay(t: dict) -> str:
            return " ".join([
                str(t.get("technique", "")), str(t.get("vuln_class") or ""),
                " ".join(t.get("tech_keywords") or []), " ".join(t.get("waf_vendors") or []),
                str(t.get("outcome") or ""),
            ]).lower()
        out = [t for t in out if q in _hay(t)]
    return out


def _sort_techniques(techniques: list[dict], sort: str) -> list[dict]:
    """Re-orders an already-filtered list per the Sort dropdown. 'recent' (default, "") is a no-op --
    list_all_techniques already returns newest-last_seen-first; everything else makes an explicit,
    operator-chosen use of data the cards already show (rank score, times confirmed, success rate,
    staleness) that the single free-text search box can't reach on its own."""
    if sort == "rank":
        return sorted(techniques, key=lambda t: t.get("rank_score") or 0.0, reverse=True)
    if sort == "confirmed":
        return sorted(techniques, key=lambda t: int(t.get("times_confirmed", 1) or 1), reverse=True)
    if sort == "success":
        return sorted(techniques, key=lambda t: t["success_rate"] if t.get("success_rate") is not None else -1.0, reverse=True)
    if sort == "stale":
        return sorted(techniques, key=lambda t: (0 if t.get("stale") else 1, -(t.get("rank_score") or 0.0)))
    return techniques


def _render_playbook_list(request: Request, query: str = "", outcome: str = "", rank: str = "", sort: str = "", message: str = "", confidence: str = "", source_id: str = "") -> str:
    all_techniques = playbook_store.list_all_techniques()
    techniques = _sort_techniques(_filter_techniques(all_techniques, query, outcome, rank, confidence, source_id), sort)
    # A human title for the "Reviewing from: X" banner even when the scoped list comes up empty
    # (e.g. every technique from that source is already reviewed, and some OTHER active filter --
    # confidence=unreviewed, an outcome/rank/text filter -- excludes all of them from `techniques`
    # itself) -- looked up against `all_techniques` (source_id only, ignoring every other filter),
    # never `techniques`, so the banner's own title survives regardless of what else is filtered.
    # Reads the title off any technique that still carries this source_id (every extracted entry
    # already denormalizes its own source_title, agent/tools/library_store.py's _ingest_candidate)
    # rather than a second library_store lookup that would return nothing once the source itself
    # gets deleted.
    source_title = next((t.get("source_title") for t in all_techniques if t.get("source_id") == source_id), None) if source_id else None
    # Which extracted entries' own Library source still exists, for the provenance block's "open
    # in Library" link (templates/partials/playbook_list.html) -- a source can be deleted from the
    # Library independently of the playbook entries it already produced (those survive on purpose,
    # same as everything else in this store), so the link must not be offered for a dead source_id.
    library_source_ids = {s["id"] for s in library_store.list_sources()}
    # How many of THIS source's own extractions are still unreviewed -- gates whether the banner's
    # own "Confirm all"/"Reject all" buttons show at all (nothing to bulk-act on once they're all
    # reviewed) and what count to put on them. Computed the same source_id-only way as
    # source_title above, for the same reason: must stay correct regardless of whatever OTHER
    # filter (confidence, outcome, a text search) is also currently narrowing `techniques`.
    source_unreviewed_count = sum(
        1 for t in all_techniques if t.get("source_id") == source_id and t.get("confidence") == "unreviewed"
    ) if source_id else 0
    return templates.env.get_template("partials/playbook_list.html").render({
        "request": request, "techniques": techniques, "query": query,
        "outcome": outcome, "rank": rank, "sort": sort, "message": message, "confidence": confidence,
        "source_id": source_id, "source_title": source_title, "library_source_ids": library_source_ids,
        "source_unreviewed_count": source_unreviewed_count,
        "total": playbook_store.count_techniques(), "rank_order": playbook_store.RANK_ORDER,
    })


@app.get("/dashboard", response_class=HTMLResponse)
def get_dashboard(request: Request) -> HTMLResponse:
    """Cross-session cost/efficiency dashboard -- aggregates compute_portfolio_summary (by
    target/program) and compute_provider_leaderboard (by LLM provider) across every project on
    disk, so the operator can tell which programs/providers are actually worth continued LLM
    spend without opening each project individually. Pure aggregation of data every session
    already records (llm_usage/phase_efficiency/stall_events, see sessions/store.py's
    _build_summary) -- no new data collection, no fresh load_session() per project."""
    portfolio = compute_portfolio_summary()
    leaderboard = compute_provider_leaderboard()
    logger.debug(
        "api: GET /dashboard sessions=%d findings=%d programs=%d providers=%d",
        portfolio["total_sessions"], portfolio["total_findings"], len(portfolio["programs"]), len(leaderboard),
    )
    return templates.TemplateResponse(request, "dashboard.html", {
        "portfolio": portfolio,
        "leaderboard": leaderboard,
    })


@app.get("/program", response_class=HTMLResponse)
def get_program(request: Request, target: str) -> HTMLResponse:
    """Drill-down from /dashboard's "By program" table -- a "project" here is defined as every
    session whose own target string matches this one exactly, the same grouping
    compute_portfolio_summary() already uses for that table (agent/core.py). No separate project
    entity/migration: this is a pure on-the-fly read of the current session index, same as
    /dashboard itself."""
    matching = [s for s in list_session_summaries() if (s.get("target") or "(unknown target)") == target]
    if not matching:
        raise HTTPException(status_code=404, detail="No sessions found for this target.")
    matching.sort(key=lambda s: s.get("created_at") or "", reverse=True)
    truncated = len(matching) > _PROGRAM_MAX_SESSIONS
    matching = matching[:_PROGRAM_MAX_SESSIONS]
    sessions = [data for s in matching if (data := load_session(s["session_id"])) is not None]
    recon_result = _aggregate_recon_for_sessions(sessions)
    findings = _aggregate_findings_for_sessions(sessions)
    logger.debug(
        "api: GET /program target=%r sessions=%d findings=%d truncated=%s",
        target, len(sessions), len(findings), truncated,
    )
    return templates.TemplateResponse(request, "program.html", {
        "target": target,
        "sessions": sessions,
        "session_summaries": matching,
        "truncated": truncated,
        "recon_result": recon_result,
        "findings": findings,
    })


@app.get("/playbook", response_class=HTMLResponse)
def get_playbook(request: Request) -> HTMLResponse:
    """The Playbook manager page -- view/search/edit/delete the cross-session technique store plus
    import/export/seed. The store is global operator knowledge (agent/tools/playbook_store.py), not
    tied to any one session."""
    total = playbook_store.count_techniques()
    embedded = playbook_store.embeddings_count()
    logger.debug("api: GET /playbook (total=%d embedded=%d)", total, embedded)
    # Real, confirmed operator complaint this fixes: the shared "Analyze with" picker always
    # reset to blank ("same as main agent") on every page load, so a favorite provider/model had
    # to be re-picked every single time instead of being remembered (library_store.py's own
    # save_last_analysis_llm/load_library_settings -- same shape as chat_settings_store.py's
    # identical last_provider/last_model pair for the Chat panel).
    library_settings = library_store.load_library_settings()
    library_last_provider = library_settings["last_provider"] or ""
    library_last_model = library_settings["last_model"] or ""
    library_last_model_choices = get_model_choices(library_last_provider) if library_last_provider else []
    return templates.TemplateResponse(request, "playbook.html", {
        "list_html": _render_playbook_list(request),
        "total": total,
        "embedded": embedded,
        "seeded": playbook_store.seed_pack_imported(),
        "rank_order": playbook_store.RANK_ORDER,
        "library_sources_html": _render_library_sources(request),
        "library_last_provider": library_last_provider,
        "library_last_model": library_last_model,
        "library_last_model_choices": library_last_model_choices,
        # provider/model picker context (configured_cloud_provider_ids/configured_local_provider_ids/
        # custom_providers/...) for the library panel's own analyze form -- same helper the chat panel
        # and subagent profile picker already share, see its own docstring.
        **_provider_picker_context(),
    })


@app.get("/api/playbook", response_class=HTMLResponse)
def playbook_list(request: Request, q: str = "", outcome: str = "", rank: str = "", sort: str = "", confidence: str = "", source_id: str = "") -> HTMLResponse:
    logger.debug("api: GET /api/playbook q=%r outcome=%r rank=%r sort=%r confidence=%r source_id=%r", q, outcome, rank, sort, confidence, source_id)
    return HTMLResponse(_render_playbook_list(request, q, outcome, rank, sort, confidence=confidence, source_id=source_id))


def _parse_keyword_list(raw: str) -> list[str]:
    """Comma-separated operator input -> a clean, lowercased, deduped keyword list. Preserves the
    operator's own tokens verbatim (no known-tech-vocabulary filtering) -- a manual edit is explicit
    intent, and the match is a plain keyword overlap either way."""
    seen: list[str] = []
    for token in (raw or "").split(","):
        t = token.strip().lower()
        if t and t not in seen:
            seen.append(t)
    return seen


@app.post("/api/playbook/{technique_id}/update", response_class=HTMLResponse)
def playbook_update(request: Request, technique_id: str, technique: str = Form(""), payload_or_command: str = Form(""),
                    vuln_class: str = Form(""), outcome: str = Form("worked"), tech_keywords: str = Form(""),
                    waf_vendors: str = Form(""), cves: str = Form(""), q: str = Form(""),
                    filter_outcome: str = Form(""), filter_rank: str = Form(""), sort: str = Form(""),
                    filter_confidence: str = Form(""), filter_source_id: str = Form("")) -> HTMLResponse:
    updates = {
        "technique": technique.strip(),
        "payload_or_command": payload_or_command.strip() or None,
        "vuln_class": vuln_class.strip() or None,
        "outcome": "failed" if outcome == "failed" else "worked",
    }
    # tech_keywords/waf_vendors are always submitted (prefilled) -- update_technique only actually
    # re-keys when the resulting fingerprint key genuinely differs, so an unchanged edit is a no-op.
    ok = playbook_store.update_technique(
        technique_id, updates,
        tech_keywords=_parse_keyword_list(tech_keywords), waf_vendors=_parse_keyword_list(waf_vendors),
        cves=[cves],
    )
    logger.debug("api: playbook update id=%s ok=%s", technique_id, ok)
    return HTMLResponse(_render_playbook_list(request, q, filter_outcome, filter_rank, sort, confidence=filter_confidence, source_id=filter_source_id))


@app.post("/api/playbook/{technique_id}/delete", response_class=HTMLResponse)
def playbook_delete(request: Request, technique_id: str, q: str = Form(""), filter_outcome: str = Form(""),
                    filter_rank: str = Form(""), sort: str = Form(""), filter_confidence: str = Form(""),
                    filter_source_id: str = Form("")) -> HTMLResponse:
    ok = playbook_store.delete_technique(technique_id)
    logger.debug("api: playbook delete id=%s ok=%s", technique_id, ok)
    return HTMLResponse(_render_playbook_list(request, q, filter_outcome, filter_rank, sort, confidence=filter_confidence, source_id=filter_source_id))


@app.post("/api/playbook/{technique_id}/review", response_class=HTMLResponse)
def playbook_review(request: Request, technique_id: str, confirmed: str = Form("true"), q: str = Form(""),
                    filter_outcome: str = Form(""), filter_rank: str = Form(""), sort: str = Form(""),
                    filter_confidence: str = Form(""), filter_source_id: str = Form("")) -> HTMLResponse:
    """The Playbook UI's own "Confirm"/"Reject" buttons on an unreviewed (library-extracted, see
    agent/tools/library_store.py) card -- the manual half of reviewing an entry (the automatic
    half is playbook_store.record_technique's own dedup-against-a-live-capture branch)."""
    ok = playbook_store.mark_reviewed(technique_id, confirmed == "true")
    logger.debug("api: playbook review id=%s confirmed=%s ok=%s", technique_id, confirmed, ok)
    return HTMLResponse(_render_playbook_list(request, q, filter_outcome, filter_rank, sort, confidence=filter_confidence, source_id=filter_source_id))


@app.post("/api/playbook/bulk-review", response_class=HTMLResponse)
def playbook_bulk_review(request: Request, source_id: str = Form(...), confirmed: str = Form("true"),
                    q: str = Form(""), filter_outcome: str = Form(""), filter_rank: str = Form(""),
                    sort: str = Form(""), filter_confidence: str = Form("")) -> HTMLResponse:
    """Bulk counterpart to playbook_review -- the "Reviewing techniques extracted from X" banner's
    own "Confirm all"/"Reject all" buttons (templates/partials/playbook_list.html), scoped to
    exactly one Library source's own still-unreviewed entries. Real, direct operator ask: reviewing
    a whole book's worth of extracted techniques one Confirm click at a time doesn't scale.
    source_id is required (Form(...), no default) -- this route only ever exists to be called from
    inside that one scoped banner, never as a bare "confirm everything in the whole playbook"
    action."""
    affected = playbook_store.bulk_mark_reviewed(source_id, confirmed == "true")
    logger.debug("api: playbook bulk-review source_id=%s confirmed=%s affected=%d", source_id, confirmed, affected)
    verb = "Confirmed" if confirmed == "true" else "Rejected"
    message = f"{verb} {affected} technique{'s' if affected != 1 else ''}." if affected else "Nothing left to review for this source."
    return HTMLResponse(_render_playbook_list(request, q, filter_outcome, filter_rank, sort, message=message, confidence=filter_confidence, source_id=source_id))


def _render_library_sources(request: Request, message: str = "") -> str:
    return templates.env.get_template("partials/library_sources.html").render({
        "request": request, "sources": library_store.list_sources(), "message": message,
        "running_analyses": library_store.count_running_analyses(),
        "max_concurrent_label": library_store._limit_label(library_store._MAX_CONCURRENT_ANALYSES),
        **_provider_picker_context(),
    })


def _render_library_card(request: Request, source_id: str) -> str | None:
    source = library_store.get_source(source_id)
    if source is None:
        return None
    return templates.env.get_template("partials/library_card.html").render({"request": request, "s": source})


@app.post("/api/library/upload", response_class=HTMLResponse)
async def library_upload(request: Request, file: UploadFile = File(...), title: str = Form(""), author: str = Form("")) -> HTMLResponse:
    """The library panel's own dropzone -- first real file-upload endpoint in this app
    (python-multipart was already a dependency, just never used for one before). Normalization
    (agent/tools/library_store.py's add_source) runs synchronously here -- page/chapter text
    extraction is seconds of work even for a real book, nowhere near heavy enough to need its own
    background job the way the LLM analysis pass does."""
    data = await file.read()
    source_id = library_store.add_source(data, file.filename or "upload", title=title, author=author)
    message = "" if source_id else "Unsupported file type -- expected .pdf, .epub, .md, or .txt."
    logger.debug("api: library upload filename=%r source_id=%s", file.filename, source_id)
    return HTMLResponse(_render_library_sources(request, message))


@app.post("/api/library/upload-url", response_class=HTMLResponse)
async def library_upload_url(request: Request, url: str = Form(""), title: str = Form(""), author: str = Form("")) -> HTMLResponse:
    """Companion to library_upload -- lets the operator paste a URL (an article/writeup, or a
    direct PDF/epub link) instead of uploading a file. The actual fetch (agent/tools/
    library_store.py's add_source_from_url) is a blocking httpx call -- run via asyncio.to_thread
    so a slow/unresponsive URL never stalls this server's whole event loop (every other in-flight
    request, every open terminal WS) for the length of its own timeout."""
    source_id = await asyncio.to_thread(library_store.add_source_from_url, url, title, author)
    message = "" if source_id else "Couldn't fetch that URL -- check it's a real http(s) link."
    logger.debug("api: library upload-url url=%r source_id=%s", url, source_id)
    return HTMLResponse(_render_library_sources(request, message))


@app.get("/api/library/sources", response_class=HTMLResponse)
def library_sources(request: Request) -> HTMLResponse:
    """The whole source list, on demand -- not a self-poll target (each card polls only ITSELF,
    via /api/library/{id}/card, while its own status=="analyzing"; see that route's own
    docstring)."""
    return HTMLResponse(_render_library_sources(request))


@app.get("/api/library/{source_id}/card", response_class=HTMLResponse)
def library_card(request: Request, source_id: str) -> HTMLResponse:
    """The per-card self-poll target (partials/library_card.html's own hx-trigger="every 2s"
    while THAT card's own status=="analyzing") -- see that template's own docstring for the real
    flicker bug this replaces (polling the whole list used to re-swap every card, not just the
    one actually changing)."""
    html = _render_library_card(request, source_id)
    if html is None:
        return HTMLResponse("", status_code=404)
    return HTMLResponse(html)


@app.get("/api/library/{source_id}/estimate", response_class=HTMLResponse)
def library_estimate(source_id: str, provider: str = "", model: str = "") -> HTMLResponse:
    """A live "~N / MAX chunks" estimate shown before the operator commits to Analyze --
    refetched whenever the provider/model picker changes, since chunk size depends on the chosen
    model's own real context_limit (library_store.estimate_chunk_count). MAX is library_store's
    own _MAX_CHUNKS safety cap (shown as the infinity symbol when configured as unlimited) --
    always shown, not just when exceeded, so the operator can see how close to it they are before
    clicking Analyze, not only as an error after."""
    count = library_store.estimate_chunk_count(source_id, provider, model)
    max_label = library_store._limit_label(library_store._MAX_CHUNKS)
    if not count:
        return HTMLResponse(f"n/a / {max_label} chunks")
    label = f"~{count} / {max_label} chunk{'s' if count != 1 else ''} (LLM call{'s' if count != 1 else ''})"
    if library_store._MAX_CHUNKS > 0 and count > library_store._MAX_CHUNKS:
        return HTMLResponse(f'<span class="text-severity-high">{label} — over the limit, pick a bigger-context model</span>')
    return HTMLResponse(label)


@app.post("/api/library/{source_id}/analyze", response_class=HTMLResponse)
async def library_analyze(request: Request, source_id: str, provider: str = Form(""), model: str = Form("")) -> HTMLResponse:
    """async def (not sync) is load-bearing here, not stylistic -- library_store.start_analysis
    calls asyncio.create_task, which needs a running event loop. A sync route handler runs in
    Starlette's own worker thread pool with no loop of its own to attach to; an async handler runs
    directly on the main event loop instead, exactly where the fire-and-forget analysis task needs
    to be created so it keeps running after this request already returned its response."""
    refusal = library_store.start_analysis(source_id, provider, model)
    logger.debug("api: library analyze source=%s provider=%s model=%s refusal=%r", source_id, provider, model, refusal)
    message = f"Couldn't start analysis: {refusal}." if refusal else ""
    return HTMLResponse(_render_library_sources(request, message))


@app.post("/api/library/{source_id}/stop-analysis", response_class=HTMLResponse)
def library_stop_analysis(request: Request, source_id: str) -> HTMLResponse:
    stopped = library_store.stop_analysis(source_id)
    logger.debug("api: library stop-analysis source=%s stopped=%s", source_id, stopped)
    message = "" if stopped else "Nothing is currently running for this source."
    return HTMLResponse(_render_library_sources(request, message))


@app.post("/api/library/{source_id}/delete", response_class=HTMLResponse)
def library_delete(request: Request, source_id: str) -> HTMLResponse:
    ok = library_store.delete_source(source_id)
    logger.debug("api: library delete source=%s ok=%s", source_id, ok)
    return HTMLResponse(_render_library_sources(request))


@app.post("/api/library/{source_id}/confirm-duplicate", response_class=HTMLResponse)
def library_confirm_duplicate(request: Request, source_id: str) -> HTMLResponse:
    """The "Add anyway" button on a status="duplicate_pending" card -- real, direct operator ask:
    the same material re-uploaded should be flagged and confirmed, not silently duplicated OR
    silently blocked. Proceeds with the bytes already stored on disk (library_store.
    confirm_duplicate_upload); to discard instead, the existing Delete button already works on
    this status same as any other."""
    ok = library_store.confirm_duplicate_upload(source_id)
    logger.debug("api: library confirm-duplicate source=%s ok=%s", source_id, ok)
    return HTMLResponse(_render_library_sources(request))


@app.get("/api/playbook/export")
def playbook_export() -> Response:
    """Download the whole playbook as JSON (the operator's own local knowledge base) for backup or
    moving between machines. Import merges it back (playbook_import)."""
    payload = json.dumps(playbook_store.load_playbook_store(), indent=2, ensure_ascii=False)
    logger.debug("api: playbook export (%d bytes)", len(payload))
    return Response(payload, media_type="application/json", headers={"Content-Disposition": 'attachment; filename="asra_playbook.json"'})


def _count_valid_entries(incoming: dict) -> int:
    """How many entries in a {fingerprint_key: [entry, ...]} shape would actually be considered for
    import by playbook_store.import_entries (well-formed dict, non-empty technique text) -- used only
    to tell the operator how many of what they pasted were duplicates vs genuinely new, never to
    decide what gets imported (import_entries remains the single source of truth for that)."""
    if not isinstance(incoming, dict):
        return 0
    return sum(
        1 for entries in incoming.values() if isinstance(entries, list)
        for e in entries if isinstance(e, dict) and str(e.get("technique", "")).strip()
    )


@app.post("/api/playbook/import", response_class=HTMLResponse)
def playbook_import(request: Request, data: str = Form("")) -> HTMLResponse:
    """Merge a pasted/exported playbook JSON (e.g. a colleague's own playbook export) into the store --
    dedup by id, then by identical technique text under the same fingerprint key (playbook_store's
    record_technique), so re-importing the same file or merging someone else's overlapping techniques
    only ever inserts what's genuinely new. Malformed JSON is reported inline, never fatal."""
    try:
        incoming = json.loads(data) if data.strip() else {}
    except json.JSONDecodeError:
        return HTMLResponse(_render_playbook_list(request, message="That's not valid JSON — nothing imported."), status_code=200)
    total = _count_valid_entries(incoming)
    added = playbook_store.import_entries(incoming, source_label="import")
    skipped = max(0, total - added)
    logger.debug("api: playbook import total=%d added=%d skipped=%d", total, added, skipped)
    if not total:
        message = "No techniques found in that JSON — nothing imported."
    elif skipped:
        message = f"Added {added} new technique{'s' if added != 1 else ''}, skipped {skipped} already in your playbook."
    else:
        message = f"Added {added} new technique{'s' if added != 1 else ''}."
    return HTMLResponse(_render_playbook_list(request, message=message))


@app.post("/api/playbook/seed", response_class=HTMLResponse)
def playbook_seed(request: Request) -> HTMLResponse:
    added = playbook_store.import_seed_pack()
    logger.debug("api: playbook seed added=%d", added)
    message = f"Added {added} seed technique{'s' if added != 1 else ''}." if added else "Seed pack already in your playbook — nothing new to add."
    return HTMLResponse(_render_playbook_list(request, message=message))


@app.post("/api/playbook/dedupe", response_class=HTMLResponse)
def playbook_dedupe(request: Request) -> HTMLResponse:
    """Manual cleanup for a bulk import that left duplicate techniques behind -- the same confirmed
    finding, scanned by two operators, whose sessions each extracted a slightly different
    tech-keyword fingerprint for the same target. import_entries/record_technique already dedup an
    exact-text match WITHIN one fingerprint key on every import; this widens that same rule to the
    whole store (playbook_store.dedupe_all_techniques)."""
    removed = playbook_store.dedupe_all_techniques()
    logger.debug("api: playbook dedupe removed=%d", removed)
    message = f"Removed {removed} duplicate technique{'s' if removed != 1 else ''} — kept the most recently confirmed copy of each." if removed else "No duplicates found."
    return HTMLResponse(_render_playbook_list(request, message=message))


@app.get("/api/playbook/duplicates", response_class=HTMLResponse)
def playbook_duplicates(request: Request) -> HTMLResponse:
    """Read-only preview behind the Playbook toolbar's "Check duplicates" button -- real, direct
    operator ask, replacing the old "Remove duplicates" button's blind auto-merge-on-click with an
    actual look at what would be merged first (playbook_store.find_duplicate_groups)."""
    groups = playbook_store.find_duplicate_groups()
    logger.debug("api: GET /api/playbook/duplicates found %d group(s)", len(groups))
    return templates.TemplateResponse(request, "partials/playbook_duplicates.html", {"groups": groups})


@app.post("/api/playbook/duplicates/merge", response_class=HTMLResponse)
def playbook_duplicates_merge(request: Request, keep_id: str = Form(...), other_ids: str = Form("")) -> HTMLResponse:
    """One "Keep this one" click inside the duplicates dialog -- merges one operator-chosen group,
    then re-renders the same dialog content with that group gone so the operator can keep working
    through whatever's left without the dialog closing."""
    other_id_list = [i for i in other_ids.split(",") if i]
    removed = playbook_store.merge_duplicate_group(keep_id, other_id_list)
    logger.debug("api: playbook duplicates merge keep_id=%s other_count=%d removed=%d", keep_id, len(other_id_list), removed)
    groups = playbook_store.find_duplicate_groups()
    return templates.TemplateResponse(request, "partials/playbook_duplicates.html", {"groups": groups})


@app.post("/api/playbook/refresh-intel", response_class=HTMLResponse)
def playbook_refresh_intel(request: Request) -> HTMLResponse:
    """Pull live KEV/EPSS threat-intel for every technique that names CVEs and stamp it onto them, so
    the agent prioritizes what's actually being exploited in the wild. Best-effort (offline-tolerant,
    TTL-cached in agent/tools/threat_intel.py)."""
    updated = playbook_store.refresh_threat_intel()
    logger.debug("api: playbook refresh-intel updated=%d", updated)
    return HTMLResponse(_render_playbook_list(request))


@app.post("/api/playbook/add", response_class=HTMLResponse)
def playbook_add(request: Request, technique: str = Form(""), payload_or_command: str = Form(""),
                 tech_keywords: str = Form(""), waf_vendors: str = Form(""), vuln_class: str = Form(""),
                 outcome: str = Form("worked"), cves: str = Form("")) -> HTMLResponse:
    """The Playbook manager's own "+ Add technique" form -- lets the operator hand-add a single
    technique they already know. Empty technique text is a no-op (the list just re-renders)."""
    new_id = playbook_store.add_manual_technique(
        technique, payload_or_command=payload_or_command,
        tech_keywords=_parse_keyword_list(tech_keywords), waf_vendors=_parse_keyword_list(waf_vendors),
        vuln_class=vuln_class, worked=(outcome != "failed"), cves=cves,
    )
    # Embed the new one for semantic search via the default provider (best-effort, no-op without one).
    if new_id:
        fresh = [e for e in playbook_store.list_all_techniques() if e.get("id") == new_id]
        if fresh:
            _embed_playbook_entries(get_provider(None), fresh)
    logger.debug("api: playbook add technique -> id=%s", new_id)
    return HTMLResponse(_render_playbook_list(request))


@app.post("/api/playbook/reembed", response_class=HTMLResponse)
def playbook_reembed(request: Request) -> HTMLResponse:
    """Backfill embeddings for every technique that doesn't have one yet (legacy/imported entries),
    so semantic search covers the whole playbook. Uses the default LLM provider; a no-op if that
    provider has no embeddings endpoint."""
    missing = set(playbook_store.technique_ids_missing_embeddings())
    entries = [e for e in playbook_store.list_all_techniques() if e.get("id") in missing]
    embedded = _embed_playbook_entries(get_provider(None), entries) if entries else 0
    logger.debug("api: playbook reembed missing=%d embedded=%d", len(entries), embedded)
    return HTMLResponse(_render_playbook_list(request))


@app.get("/special-agents", response_class=HTMLResponse)
def get_special_agents(request: Request) -> HTMLResponse:
    """Placeholder page for a not-yet-built feature (real operator request: a visible "coming
    soon" marker in the sidebar). No context needed -- the template is entirely static copy."""
    return templates.TemplateResponse(request, "special_agents.html", {})


@app.get("/subagents", response_class=HTMLResponse)
def get_subagents(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "subagents.html", {"error": None, "message": None, **_subagent_context()})


@app.get("/chat-settings")
def get_chat_settings_redirect() -> RedirectResponse:
    """The Chat capabilities toggles moved into Settings' own "Chat" tab, then folded into General
    (real operator ask -- it's one more "general app behavior" card, not its own nav-worthy tab).
    This route now only exists so an old bookmark/muscle-memory visit to /chat-settings still lands
    somewhere useful instead of a 404. #general/settings-chat-section is the same compound
    "#tab/elementId" hash settings.html's own script (and base.html's sidebar clock link) use to
    land on a specific card, not just the tab. The nav's own "Chat" entry (base.html) points at
    /chat (Quick Chat) now."""
    return RedirectResponse(url="/settings#general/settings-chat-section", status_code=301)


def get_or_create_quick_chat_session() -> dict:
    """Lazily creates the one real session backing the top-level, project-less Quick Chat (GET
    /chat) the first time it's ever opened, and reuses that exact same session on every later
    visit -- built via the normal create_session() (mode="standalone"), so it gets a real project
    folder and the exact same field defaults every other session gets, just never shown anywhere
    (sessions.store.list_session_summaries filters mode="standalone" out at the source). The
    resulting session_id is remembered in chat_settings.json (a fixed id would work too, but this
    way it never has to special-case its own storage path the way every other session doesn't).
    """
    settings = load_chat_settings()
    session_id = settings.get("quick_chat_session_id")
    if session_id:
        existing = load_session(session_id)
        if existing is not None:
            return existing
        logger.debug("get_or_create_quick_chat_session: stored id=%s no longer resolves, creating a fresh one", session_id)

    session_id = create_session(target="", name="Quick Chat", mode="standalone", initial_status="completed")
    save_quick_chat_session_id(session_id)
    logger.debug("get_or_create_quick_chat_session: created new Quick Chat session id=%s", session_id)
    return load_session(session_id)


@app.get("/chat", response_class=HTMLResponse)
def get_quick_chat(request: Request) -> HTMLResponse:
    """The top-level "Chat" nav entry -- a single, standalone chat not tied to any project, for a
    fast security question or to learn something, visually/logically the same thread/provider/
    model picker a project's own mini-chat has (templates/partials/chat_panel.html, reused as-is),
    just filling the whole page instead of sitting in a project's own sidebar column."""
    session = get_or_create_quick_chat_session()
    return templates.TemplateResponse(request, "chat.html", _chat_context(session))


_CHAT_SETTINGS_FIELDS = {"web_fetch_enabled", "browser_enabled", "subagents_enabled", "dork_engine_enabled"}


@app.post("/api/chat-settings/{field}")
def save_chat_setting_route(field: str, enabled: str | None = Form(None)) -> Response:
    """One toggle, one independent request touching only its own field -- the other two are always
    read fresh from disk here, never trusted from the client. Real, confirmed operator complaint
    this fixes: the old version was a single shared <form> resubmitting all three checkboxes'
    CLIENT-SIDE state together on every toggle click. A /chat-settings tab left open (not reloaded)
    since before some OTHER change landed still showed that other field's stale value; clicking any
    toggle on it silently reverted that field back to whatever the stale page happened to show, even
    though the operator only meant to change a completely different one. A checkbox that's
    unchecked is simply absent from ITS OWN submitted form (standard HTML behavior) -- Form(None) +
    bool(...) turns "present" into True, "absent" into False.
    """
    if field not in _CHAT_SETTINGS_FIELDS:
        raise HTTPException(status_code=404, detail=f"unknown chat setting {field!r}")
    current = load_chat_settings()
    current[field] = bool(enabled)
    saved = save_chat_settings(
        current["web_fetch_enabled"], current["browser_enabled"], current["subagents_enabled"], current["dork_engine_enabled"],
    )
    logger.debug(
        "api: chat-settings saved web_fetch_enabled=%s browser_enabled=%s subagents_enabled=%s dork_engine_enabled=%s",
        saved["web_fetch_enabled"], saved["browser_enabled"], saved["subagents_enabled"], saved["dork_engine_enabled"],
    )
    return Response(status_code=204)


@app.post("/api/toolkit-agent-settings/{field}")
def save_toolkit_agent_setting_route(field: str, enabled: str | None = Form(None)) -> Response:
    """One toggle, one independent request touching only its own field -- same "never trust the
    client's other checkboxes" reasoning as save_chat_setting_route above (a stale-tab-reverts-a-
    sibling-field bug class already fixed once for chat's own toggles)."""
    if field not in TOOLKIT_AGENT_SETTINGS_FIELDS:
        raise HTTPException(status_code=404, detail=f"unknown toolkit agent setting {field!r}")
    current = load_toolkit_agent_settings()
    current[field] = bool(enabled)
    saved = save_toolkit_agent_settings(current)
    logger.debug("api: toolkit-agent-settings saved %s", saved)
    return Response(status_code=204)


@app.post("/api/subagents")
def create_subagent_route(
    request: Request,
    name: str = Form(""),
    allowed_tools: list[str] = Form([]),
    instructions: str = Form(""),
    provider: str = Form(""),
    model: str = Form(""),
    icon: str = Form(""),
    icon_color: str = Form(""),
) -> Response:
    if not name.strip():
        return templates.TemplateResponse(
            request, "subagents.html", {"error": "Name this subagent before saving it.", **_subagent_context()}, status_code=400,
        )
    # Same "unchosen falls back to a real random pick, never an empty/invalid value silently
    # stored" validation sessions/store.py's create_session already applies to a project's own
    # icon/icon_color -- subagent_icons is a deliberately separate pool (that module's own
    # docstring), not a re-import of projects/icons.py, even though the validation shape matches.
    resolved_icon = icon if subagent_icons.is_valid_icon(icon) else subagent_icons.random_icon()
    _color_chosen = subagent_icons.is_valid_color(icon_color) and icon_color.strip().lower() != "#000000"
    resolved_icon_color = icon_color if _color_chosen else subagent_icons.random_color()
    add_profile(
        name.strip(), allowed_tools, instructions.strip(), provider.strip() or None, model.strip() or None,
        icon=resolved_icon, icon_color=resolved_icon_color,
    )
    logger.debug("api: subagent profile created name=%r tools=%d icon=%s", name, len(allowed_tools), resolved_icon)
    return RedirectResponse(url="/subagents", status_code=303)


@app.get("/api/subagents/export")
def subagent_export() -> Response:
    """Download every subagent profile as JSON for backup or moving between machines. Import merges
    it back (subagent_import) -- same export/import pairing as the Playbook manager's own
    playbook_export/playbook_import."""
    payload = json.dumps(load_subagent_profiles(), indent=2, ensure_ascii=False)
    logger.debug("api: subagent export (%d bytes)", len(payload))
    return Response(payload, media_type="application/json", headers={"Content-Disposition": 'attachment; filename="asra_subagents.json"'})


def _count_valid_profiles(incoming: dict) -> int:
    """How many profiles in a {"profiles": [profile, ...]} shape would actually be considered for
    import by subagent_store.import_profiles (well-formed dict, non-empty name) -- used only to tell
    the operator how many of what they pasted were duplicates vs genuinely new, never to decide what
    gets imported (import_profiles remains the single source of truth for that)."""
    if not isinstance(incoming, dict):
        return 0
    profiles = incoming.get("profiles")
    if not isinstance(profiles, list):
        return 0
    return sum(1 for p in profiles if isinstance(p, dict) and str(p.get("name", "")).strip())


@app.post("/api/subagents/import", response_class=HTMLResponse)
def subagent_import(request: Request, data: str = Form("")) -> HTMLResponse:
    """Merge a pasted/exported subagent-profile JSON (e.g. a colleague's own export) into the store --
    dedup by id (subagent_store.import_profiles), so re-importing the same file or merging someone
    else's overlapping profiles only ever adds what's genuinely new. Imported profiles always land
    disabled, so the operator reviews tools/provider before the main agent can delegate to them.
    Malformed JSON is reported inline, never fatal. Registered ABOVE update_subagent_route
    ("/api/subagents/{profile_id}") deliberately -- FastAPI/Starlette match routes in registration
    order, and a static "/import" segment registered after the dynamic "{profile_id}" route would
    get swallowed by it (profile_id="import") instead of ever reaching this handler."""
    try:
        incoming = json.loads(data) if data.strip() else {}
    except json.JSONDecodeError:
        return templates.TemplateResponse(request, "subagents.html", {
            "error": None, "message": "That's not valid JSON — nothing imported.", **_subagent_context(),
        })
    total = _count_valid_profiles(incoming)
    added = import_profiles(incoming, source_label="import")
    skipped = max(0, total - added)
    logger.debug("api: subagent import total=%d added=%d skipped=%d", total, added, skipped)
    if not total:
        message = "No subagent profiles found in that JSON — nothing imported."
    elif skipped:
        message = f"Added {added} new profile{'s' if added != 1 else ''}, skipped {skipped} already configured."
    else:
        message = f"Added {added} new profile{'s' if added != 1 else ''}."
    return templates.TemplateResponse(request, "subagents.html", {"error": None, "message": message, **_subagent_context()})


@app.post("/api/subagents/{profile_id}")
def update_subagent_route(
    request: Request,
    profile_id: str,
    name: str = Form(""),
    allowed_tools: list[str] = Form([]),
    instructions: str = Form(""),
    provider: str = Form(""),
    model: str = Form(""),
    icon: str = Form(""),
    icon_color: str = Form(""),
) -> Response:
    if not name.strip():
        return templates.TemplateResponse(
            request, "subagents.html", {"error": "Name this subagent before saving it.", **_subagent_context()}, status_code=400,
        )
    resolved_icon = icon if subagent_icons.is_valid_icon(icon) else subagent_icons.random_icon()
    _color_chosen = subagent_icons.is_valid_color(icon_color) and icon_color.strip().lower() != "#000000"
    resolved_icon_color = icon_color if _color_chosen else subagent_icons.random_color()
    try:
        update_profile(
            profile_id, name=name.strip(), allowed_tools=allowed_tools, instructions=instructions.strip(),
            provider=provider.strip() or None, model=model.strip() or None,
            icon=resolved_icon, icon_color=resolved_icon_color,
        )
    except ValueError:
        raise HTTPException(status_code=404, detail="Unknown subagent profile")
    logger.debug("api: subagent profile updated id=%s", profile_id)
    return RedirectResponse(url="/subagents", status_code=303)


@app.post("/api/subagents/{profile_id}/toggle")
def toggle_subagent_route(profile_id: str) -> Response:
    profile = next((p for p in load_subagent_profiles()["profiles"] if p["id"] == profile_id), None)
    if profile is None:
        raise HTTPException(status_code=404, detail="Unknown subagent profile")
    update_profile(profile_id, enabled=not profile.get("enabled"))
    logger.debug("api: subagent profile id=%s enabled=%s", profile_id, not profile.get("enabled"))
    return RedirectResponse(url="/subagents", status_code=303)


@app.post("/api/subagents/{profile_id}/delete")
def delete_subagent_route(profile_id: str) -> Response:
    delete_profile(profile_id)
    logger.debug("api: subagent profile deleted id=%s", profile_id)
    return RedirectResponse(url="/subagents", status_code=303)


_TOOL_DOMAIN_SECTIONS = (
    ("web", "Web / API Pentest", "Recon, scan, exploit, and post-exploit tools for a live web/API target."),
    ("re", "Reverse Engineering", "Static/dynamic analysis for a local binary, mobile app, smart contract, or source tree."),
    ("browser", "Browser Automation", "Drives a real Playwright-controlled page -- clicking, filling forms, reading the DOM."),
    ("toolkit", "Toolkit", "Manual HTTP-testing primitives (proxy/repeater/decoder/comparer/intruder/sequencer) -- protocol-level, so they apply to any HTTP target, including a mobile app's own backend API, not just a browser-rendered site."),
)


def _grouped_tools_context(tools: list[dict]) -> dict:
    """Buckets the flat tool list into the 4 domains _tool_domain recognizes, each split further
    into "native" (tier=1, ships with ASRA itself, no separate install step -- installed the moment
    the Python code that defines it exists) vs "external" (tier=2, a real binary setup_tools.sh has
    to actually provision, genuinely either present or missing on this specific machine). Real,
    confirmed gap this closes: the old /tools page was one flat, alphabetically sorted table with no
    domain signal at all -- indistinguishable at a glance which of the 6 registry categories a given
    tool served, or whether a red "Not found" status meant "re-run setup_tools.sh" (external) vs
    "something is actually broken in this install" (native, should never be missing).
    """
    sections = []
    for key, label, description in _TOOL_DOMAIN_SECTIONS:
        matching = [t for t in tools if _tool_domain(t) == key]
        sections.append({
            "key": key, "label": label, "description": description,
            "native": [t for t in matching if t["tier"] == 1],
            "external": [t for t in matching if t["tier"] == 2],
        })
    return {"sections": sections}


@app.get("/tools")
def get_tools_page() -> RedirectResponse:
    """Tools moved into Settings as its own tab (real, explicit operator ask) -- this old standalone
    route now just redirects any existing bookmark/link straight to that tab instead of 404ing."""
    return RedirectResponse(url="/settings#tools", status_code=307)


@app.get("/api/tools/arsenal/check", response_class=HTMLResponse)
def get_arsenal_check(request: Request) -> HTMLResponse:
    """Live read-only readiness summary for the Tools page's "Check arsenal" button -- starts
    nothing, just the same tool_is_installed check the agent itself makes (agent/tools/arsenal.py)."""
    summary = summarize_arsenal()
    logger.debug("arsenal check: verdict=%s external=%s/%s", summary["verdict"],
                 summary["external_installed"], summary["external_total"])
    return templates.TemplateResponse(request, "partials/arsenal_check.html", {"summary": summary})


@app.get("/api/tools/arsenal/install/confirm", response_class=HTMLResponse)
def get_arsenal_install_confirm(request: Request) -> HTMLResponse:
    """Warning/confirm step for the "Install" button -- shows what runs, the approx size, and
    whether an automatic run is even possible here, WITHOUT installing anything yet."""
    return templates.TemplateResponse(
        request, "partials/arsenal_confirm.html",
        {"preflight": can_autostart(),
         "measured_gb": measure_arsenal_size_gb(),
         "approx_gb": approx_download_size_gb()},
    )


@app.post("/api/tools/arsenal/install/start", response_class=HTMLResponse)
def post_arsenal_install_start(request: Request, include_wordlists: bool = Form(False)) -> HTMLResponse:
    """Actually kicks off setup_tools.sh in the background, then hands back the live-polling log
    view. A non-startable result (manual/unsupported) renders as a blocked message instead."""
    result = start_arsenal_install(include_wordlists=include_wordlists)
    if result["status"] in ("started", "running"):
        return templates.TemplateResponse(
            request, "partials/arsenal_install.html", {"status": arsenal_install_status(), "blocked": False})
    return templates.TemplateResponse(
        request, "partials/arsenal_install.html",
        {"blocked": True, "blocked_message": result.get("message", "Install unavailable."),
         "blocked_command": result.get("command")},
    )


@app.get("/api/tools/arsenal/install/status", response_class=HTMLResponse)
def get_arsenal_install_status(request: Request) -> HTMLResponse:
    """Polled every 2s by the install view while a run is in flight -- tails the install log and
    stops polling on its own once the process exits (agent/tools/arsenal_install.py)."""
    return templates.TemplateResponse(
        request, "partials/arsenal_install.html", {"status": arsenal_install_status(), "blocked": False})


@app.get("/api/tools/nuclei-packs", response_class=HTMLResponse)
def get_nuclei_packs_list(request: Request) -> HTMLResponse:
    """Re-render of the whole pack list -- used by each pack's post-install 'Refresh' button so a
    just-finished install flips that row from Install to Uninstall without a full page reload."""
    return templates.TemplateResponse(request, "partials/nuclei_packs_list.html", {"nuclei_packs": list_nuclei_packs()})


@app.post("/api/session/{session_id}/backup", response_class=HTMLResponse)
def post_session_backup(request: Request, session_id: str) -> HTMLResponse:
    """Manual project backup button (agent/tools/project_backup.py) -- a real tar.gz snapshot of
    this project's own folder, taken on demand regardless of session status (a snapshot of a still-
    running session's current state is still useful, unlike a restore over it -- see the restore
    route below for why THAT one is status-gated and this one isn't)."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    result = create_project_backup(session_id)
    logger.debug("api: backup requested session_id=%s result=%s", session_id, result.get("status"))
    return HTMLResponse(_render_backups_fragment(request, session))


@app.post("/api/session/{session_id}/backup/{backup_name}/restore", response_class=HTMLResponse)
def post_session_backup_restore(request: Request, session_id: str, backup_name: str) -> HTMLResponse:
    """Extracts a backup back over the live project folder -- gated behind session_fragment.html's
    own hx-confirm (same "real, styled confirm before a hard-to-undo action" discipline as Pause/
    Stop above). Refused while the session is actually running: run_session()/run_focused_exploit()
    read-modify-write session.json on their own schedule, and a restore racing that would either get
    silently clobbered by the next autosave or leave the file in a state neither the backup nor the
    live run actually intended."""
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") in _ORPHANABLE_STATUSES or session.get("status") == "pending":
        raise HTTPException(status_code=400, detail="Can't restore into a running session -- pause or stop it first.")
    result = restore_project_backup(session_id, backup_name)
    logger.debug("api: restore requested session_id=%s backup=%s result=%s",
                 session_id, backup_name, result.get("status"))
    refreshed = load_session(session_id) or session
    return HTMLResponse(_render_backups_fragment(request, refreshed))


@app.post("/api/session/{session_id}/backup/{backup_name}/delete", response_class=HTMLResponse)
def post_session_backup_delete(request: Request, session_id: str, backup_name: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    delete_project_backup(session_id, backup_name)
    logger.debug("api: backup delete session_id=%s backup=%s", session_id, backup_name)
    return HTMLResponse(_render_backups_fragment(request, session))


@app.post("/api/tools/nuclei-packs/{key}/install", response_class=HTMLResponse)
def post_nuclei_pack_install(request: Request, key: str) -> HTMLResponse:
    """Starts `GITHUB_TEMPLATE_REPO=<repo> nuclei -update-templates` in the background for one
    template pack (agent/tools/nuclei_template_packs.py) and hands back the live-polling log view.
    A pack that can't start (nuclei missing, unknown key) renders as a blocked message instead."""
    result = install_nuclei_pack(key)
    if result["status"] in ("started", "running"):
        logger.debug("nuclei pack install: key=%s started", key)
        return templates.TemplateResponse(
            request, "partials/nuclei_pack_install.html", {"status": result, "key": key, "blocked": False})
    logger.debug("nuclei pack install: key=%s blocked (%s)", key, result.get("message"))
    return templates.TemplateResponse(
        request, "partials/nuclei_pack_install.html",
        {"key": key, "blocked": True, "blocked_message": result.get("message", "Install unavailable.")},
    )


@app.get("/api/tools/nuclei-packs/{key}/status", response_class=HTMLResponse)
def get_nuclei_pack_status(request: Request, key: str) -> HTMLResponse:
    """Polled every 2s by the install view while a pack sync is in flight -- stops polling on its
    own once the process exits (same pattern as /api/tools/arsenal/install/status)."""
    return templates.TemplateResponse(
        request, "partials/nuclei_pack_install.html", {"status": nuclei_pack_status(key), "key": key, "blocked": False})


@app.post("/api/tools/nuclei-packs/{key}/uninstall", response_class=HTMLResponse)
def post_nuclei_pack_uninstall(request: Request, key: str) -> HTMLResponse:
    """Removes the pack's synced template directory -- the real 'disable' mechanism, since
    list_packs()/installed_template_args() both key off that directory's presence, not a flag."""
    uninstall_nuclei_pack(key)
    logger.debug("nuclei pack uninstall: key=%s", key)
    return templates.TemplateResponse(request, "partials/nuclei_packs_list.html", {"nuclei_packs": list_nuclei_packs()})


@app.post("/api/debug/client-event")
async def debug_client_event(request: Request) -> Response:
    """The browser-side half of the debug module (static/js/debug_events.js) — every click, form
    field change, and htmx/SSE lifecycle event lands here and gets logged under the UI category.
    A malformed/missing body is never an error worth surfacing — this is best-effort telemetry,
    not a real API contract. When a session_id is given, the log line also lands in that
    session's own project folder (agent/utils/debug.py's current_session_id), not just the
    global app log.
    """
    try:
        payload = await request.json()
    except Exception:
        return Response(status_code=204)

    session_id = payload.get("session_id")
    ui_logger = get_logger("UI")
    if session_id:
        token = current_session_id.set(session_id)
        try:
            ui_logger.debug("%s: %s", payload.get("action", "event"), payload.get("detail", ""))
        finally:
            current_session_id.reset(token)
    else:
        ui_logger.debug("%s: %s", payload.get("action", "event"), payload.get("detail", ""))

    return Response(status_code=204)


def _port_has_live_listener(host: str, port: int) -> bool:
    """True only if something is actually ACCEPTING connections on host:port right now -- not just
    "the strict probe-bind below couldn't claim it". A listening socket that's genuinely closed
    frees its port immediately, but a very recently closed CONNECTION on that same port (an SSE/
    live-view stream, an htmx poll ASRA's own previous instance still had open when it was
    stopped) lingers in TIME_WAIT for up to a couple of minutes -- and the probe-bind's own
    SO_REUSEADDR=0 (deliberate, so it notices a genuine second listener) trips on that completely
    harmless leftover state exactly the same way it trips on a real conflicting listener, since
    both make bind() fail with the same OSError. The only way to tell them apart is an actual
    connect attempt: a real listener accepts it, a TIME_WAIT-only port refuses it outright (nothing
    is listening to accept anything).
    """
    import socket

    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def _terminate_stale_asra(host: str, port: int) -> bool:
    """Actually ends a confirmed-stale ASRA instance holding `port`, instead of just refusing to
    reuse it -- returns True once the port is genuinely free again, False if that couldn't be
    confirmed (caller falls back to the old refuse-and-explain behavior rather than ever binding
    on top of something that might still be alive).

    Real, confirmed incident this fixes: an operator restarted ASRA FOUR separate times (via the
    desktop launcher) and hit the exact same "stale" refusal every single time -- because nothing,
    anywhere in this project, ever actually killed the stale process; every relaunch just
    rediscovered it, printed the same explanation, and gave up again. Tracing the full launch
    stack (run.bat/run.sh have no process-management code at all; the desktop shell's own
    launch_backend() does a bare TCP "is anything answering" check and, if so, ADOPTS whatever is
    there without ever verifying it's running current code) confirmed this refusal was a dead end
    with no path back to a working state short of the operator finding and killing the process by
    hand -- which they were never told how to do either.

    Uses psutil (already a real project dependency, agent/tools/fleet_store.py) to find the PID
    actually bound to `port` and send it a graceful SIGTERM, escalating to SIGKILL only if it
    doesn't exit in time -- the same "graceful first, force as a last resort" shape stop_backend()
    already uses on the desktop side, just reachable from a plain `python main.py`/run.bat launch
    too, so this self-heals regardless of which launch path the operator actually used.
    """
    import time

    import psutil

    target_pid: int | None = None
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr and conn.laddr.port == port and conn.status == psutil.CONN_LISTEN:
                target_pid = conn.pid
                break
    except (psutil.AccessDenied, OSError):
        return False
    if target_pid is None:
        return False

    try:
        proc = psutil.Process(target_pid)
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except psutil.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    except psutil.NoSuchProcess:
        pass  # already gone -- exactly what we wanted
    except (psutil.AccessDenied, psutil.TimeoutExpired, OSError):
        return False

    # SIGTERM/SIGKILL asks the OS to end the process; it doesn't guarantee the port is
    # immediately re-bindable (a brief TIME_WAIT-style gap is possible) -- poll rather than
    # trust a single check, same reasoning _port_has_live_listener's own docstring explains.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _port_has_live_listener(host, port):
            return True
        time.sleep(0.2)
    return not _port_has_live_listener(host, port)


def _existing_asra_status(host: str, port: int) -> str:
    """The port is taken -- what's actually there? Three possibilities:

    - "foreign": an unrelated program squatting on the port -- a real problem only the operator
      can fix. A quick GET to ASRA's own health endpoint tells this apart from our own instance
      without false-positiving on some random other HTTP server that happens to hold this port.
    - "stale": it IS our own ASRA, healthy, but its Python code (main.py + whatever it imports --
      unlike templates, never hot-reloaded once running, see _SOURCE_MTIME_AT_STARTUP's own
      comment above) predates a LATER edit to main.py that's already on disk. Silently reusing it
      is exactly the real, confirmed incident that comment documents: a hot-reloaded template
      calling a route/filter this older process never registered, an opaque, traceback-free
      "Internal Server Error" on the very next render, with no restart of its own to ever fix it.
    - "fresh": our own ASRA, healthy, running code at least as new as this (new) process's own
      copy of main.py -- safe to reuse.
    """
    import http.client

    conn = http.client.HTTPConnection(host, port, timeout=2)
    try:
        conn.request("GET", "/api/system-health")
        response = conn.getresponse()
        if response.status != 200:
            return "foreign"
        source_mtime_header = response.getheader("X-ASRA-Source-Mtime")
        response.read()
    except OSError:
        return "foreign"
    finally:
        conn.close()

    # Missing header: an older ASRA build from before this staleness check existed at all -- there
    # is no earlier snapshot to compare against, so this can't be judged either way. Default to
    # "fresh" (the prior, unconditional-reuse behavior) rather than blocking startup on ambiguous
    # data; once every running instance is past this point, every one of them sends the header.
    try:
        running_mtime = float(source_mtime_header) if source_mtime_header else None
    except ValueError:
        running_mtime = None
    if running_mtime is not None and running_mtime < os.path.getmtime(__file__):
        return "stale"
    return "fresh"


if __name__ == "__main__":
    # run.sh/run.bat invoke this file directly (python main.py) instead of the bare "uvicorn
    # main:app" CLI specifically so this try/except is actually in the call chain: uvicorn's own
    # CLI has no equivalent wrapping, so a second Ctrl+C during graceful shutdown (the first
    # triggers "Shutting down", the second force-quits before it finishes) re-raises
    # KeyboardInterrupt out of uvicorn/uvloop's own internals and Python's default top-level handler
    # prints the full traceback -- confirmed live, this is exactly what showed up as ~30 lines of
    # asyncio/uvloop/starlette internals after a real shutdown that had already completed cleanly.
    # Catching it here doesn't change shutdown behavior at all (uvicorn already closed everything
    # before re-raising) -- it only replaces Python's own noisy default reporting with one clear
    # line. HOST/PORT match run.sh's own previous CLI flags exactly (127.0.0.1 fixed, PORT from
    # env with the same "8000" default run.sh already used) -- no behavior change, only how the
    # process is launched and how it responds to a second Ctrl+C.
    import socket

    import uvicorn

    host = "127.0.0.1"
    port = int(os.getenv("PORT", "8000"))

    # Real, confirmed incident this fixes: launching a SECOND instance while a first one is still
    # alive on the same port doesn't fail fast the way it looks like it should. uvicorn's own
    # ASGI lifespan startup (our _lifespan handler, which runs _mark_orphaned_sessions_interrupted
    # -- a real, session-file-MUTATING sweep) completes in full BEFORE uvicorn's own socket bind
    # failure ever surfaces (confirmed live in a real console capture: "Application startup
    # complete" printed, THEN "[Errno 98] address already in use"). A doomed-to-fail duplicate
    # launch was therefore still marking a perfectly healthy, actively-running session "interrupted"
    # out from under the FIRST (real, still-serving) process, moments before the duplicate itself
    # exited -- exactly what looked like a mystery crash in a real operator session. A cheap
    # probe-bind here, before uvicorn (and therefore before the lifespan startup) ever runs, catches
    # it up front.
    #
    # An occupied port has FOUR very different causes that used to be collapsed into two (and,
    # before that, one scary error -- run.bat then compounded it by pausing with a misleading
    # "check your WSL tools" message, making a routine double-launch read as a fatal crash):
    #   - It's OUR own ASRA, already up, serving, and running code at least as new as this launch's
    #     own copy of main.py ("fresh") -- the operator just launched it twice. That's harmless, so
    #     surface it as such, open it in the browser, and exit 0 so run.bat treats the launch as a
    #     success (no error block, no pause).
    #   - It's OUR own ASRA, but its code predates a later edit to main.py that's already on disk
    #     ("stale", _existing_asra_status's own docstring) -- reusing it as-is risks the exact
    #     "hot-reloaded template calls a route/filter this older process never registered" 500 that
    #     silently confused an operator once already. Refuse to reuse it; say exactly why.
    #   - It's some unrelated program holding the port ("foreign") -- a real problem only the
    #     operator can fix, so say exactly that and exit non-zero.
    #   - Nothing is actually listening at all -- the strict (SO_REUSEADDR=0, deliberate) probe
    #     below just tripped on a TIME_WAIT-only leftover connection, almost always from ASRA's OWN
    #     previous instance shutting down (an SSE/live-view/htmx-poll connection still winding
    #     down). Real, confirmed incident: an operator closed ASRA and relaunched it seconds later,
    #     got "Port 8000 is already in use by another program (not ASRA)" even though nothing else
    #     was running at all -- the port was genuinely free moments later, once TIME_WAIT expired on
    #     its own. _port_has_live_listener's real connect attempt (not just "can I bind") is what
    #     actually tells this apart from a genuine second listener; uvicorn's own socket setup
    #     (asyncio's reuse_address=True default on POSIX) binds straight through a TIME_WAIT-only
    #     leftover on its own, so there's nothing else to work around here once this is detected.
    # A "stale" instance gets exactly one self-heal attempt (_terminate_stale_asra) before this
    # loop falls through to the original refuse-and-explain behavior -- looping at most twice
    # (the initial probe, then one retry after a successful kill) rather than open-endedly, so a
    # process that genuinely won't die (killed but something else re-grabs the port, or the kill
    # itself failed) still ends in the same clear, safe refusal as before instead of spinning.
    for attempt in range(2):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            probe.bind((host, port))
            break
        except OSError:
            url = f"http://{host}:{port}"
            if not _port_has_live_listener(host, port):
                logger.debug("api: port %s probe-bind failed but nothing is actually listening -- TIME_WAIT leftover, proceeding", port)
                break
            status = _existing_asra_status(host, port)
            if status == "fresh":
                logger.debug("api: port %s already held by a running ASRA -- reusing it, not launching a duplicate", port)
                print(f"ASRA is already running — open {url} in your browser.")
                raise SystemExit(0) from None
            elif status == "stale":
                if attempt == 0:
                    logger.debug("api: port %s held by a running ASRA whose code predates a later edit on disk -- terminating it and retrying", port)
                    print(f"ASRA is already running on port {port}, but it's running OLDER code than what's on disk now (main.py was edited after it started).")
                    print("Stopping that instance and starting fresh with the current code...")
                    if _terminate_stale_asra(host, port):
                        continue  # port should be free now -- loop back and probe again
                    logger.debug("api: port %s stale instance could not be terminated -- falling back to refusing to reuse it", port)
                print("Could not automatically stop the older instance. Close it (or its terminal/process) yourself, then start ASRA again.")
                raise SystemExit(1) from None
            else:
                logger.debug("api: port %s is occupied by a non-ASRA process -- refusing to start", port)
                print(f"Port {port} is already in use by another program (not ASRA).")
                print("Close whatever is using it, or set PORT in .env to a free port, then start ASRA again.")
                raise SystemExit(1) from None
        finally:
            probe.close()

    try:
        uvicorn.run(app, host=host, port=port)
    except KeyboardInterrupt:
        logger.debug("api: second Ctrl+C during shutdown -- forced quit, suppressing the noisy default traceback")
        print("\nASRA stopped.")
