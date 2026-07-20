"""FastAPI app entrypoint: wraps the already-working agent (agent/core.py) in a web UI.

Every route is a thin layer over sessions/store.py (file-based session state) and agent.core
(the ReAct loop that mutates that state). No business logic lives here beyond request
validation and template rendering.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agent.chat import run_chat_turn
from agent.core import get_approval_event, get_instruction_queue, run_focused_exploit, run_session
from agent.llm_client import DEFAULT_PROVIDER, PROVIDER_REGISTRY, get_provider
from agent.providers.models_dev import list_models
from agent.settings import load_llm_settings, save_llm_settings
from agent.tools.allowed_targets import add_allowed_target
from agent.tools.builders.validators import validate_target
from agent.utils.logger import get_logger
from sessions.store import create_session, delete_session, get_session_folder, iter_all_session_paths, load_session, name_exists, save_session

logger = get_logger("API")

app = FastAPI(title="ASRA")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# How often the SSE stream re-reads the session file and checks whether it changed.
_SSE_POLL_INTERVAL_SECONDS = 1.0

# The New Project dialog (base.html, on every page) needs these — Jinja globals, not per-route
# context, since they're static config (provider registry/.env defaults), not per-request state.
templates.env.globals["provider_ids"] = list(PROVIDER_REGISTRY)
templates.env.globals["llm_provider_default"] = os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER)


def _render_fragment(request: Request, session: dict) -> str:
    return templates.env.get_template("partials/session_fragment.html").render({"request": request, "session": session})


def _render_chat_panel(request: Request, session: dict) -> str:
    return templates.env.get_template("partials/chat_panel.html").render({"request": request, "session": session})


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
    finally:
        session = load_session(session_id)
        logger.debug("api: background scan finished session_id=%s status=%s", session_id, session.get("status") if session else "unknown")


# A session sitting in one of these statuses right when the server starts can only mean its
# run_session() coroutine died with the previous process — nothing in the new process is running
# it. "interrupted" is distinct from "failed": the run itself never errored, the process holding
# it just stopped existing (e.g. a computer restart).
_ORPHANABLE_STATUSES = ("processing", "awaiting_approval")


def _compute_resume_entry_point(session: dict) -> str:
    if session.get("findings"):
        return "exploit"
    if (session.get("recon_result") or {}).get("targets"):
        return "analyze"
    return "recon"


def _mark_orphaned_sessions_interrupted() -> None:
    for path in iter_all_session_paths():
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if data.get("status") not in _ORPHANABLE_STATUSES:
            continue
        data["status"] = "interrupted"
        data["resumable_from"] = _compute_resume_entry_point(data)
        save_session(data.get("session_id", path.stem), data)
        logger.debug(
            "api: marked orphaned session interrupted session_id=%s resumable_from=%s",
            data.get("session_id", path.stem), data["resumable_from"],
        )


@app.on_event("startup")
def _on_startup() -> None:
    _mark_orphaned_sessions_interrupted()


@app.post("/api/scan")
def start_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    name: str = Form(""),
    target: str = Form(""),
    llm_provider: str | None = Form(None),
    authorize_exploit: str | None = Form(None),
) -> Response:
    def _error(message: str, status_code: int = 400) -> Response:
        return templates.TemplateResponse(
            request, "index.html", _index_context(error=message, target=target, name=name), status_code=status_code
        )

    clean_name = name.strip()
    if not clean_name:
        return _error("Project name is required.")
    if name_exists(clean_name):
        return _error(f"A project named {clean_name!r} already exists — pick a different name.")

    # A scope, not just one host: comma-separated URL/domain/host/IPv4/IPv6 entries, each
    # validated on its own (validate_target()'s shape check doesn't allow commas/spaces, so it
    # has to run per-entry, not on the raw joined string).
    raw_targets = [t.strip() for t in target.split(",") if t.strip()]
    if not raw_targets:
        return _error("At least one target is required.")
    try:
        clean_targets = [validate_target(t) for t in raw_targets]
    except ValueError as exc:
        return _error(str(exc))
    clean_target = ", ".join(clean_targets)

    resolved_provider = llm_provider if llm_provider in PROVIDER_REGISTRY else None

    # Still a deliberate, explicit, off-by-default opt-in (unchecked unless the user ticks it
    # here) — the New Project form just moved where that opt-in lives, it didn't remove it.
    # Recon/scan tools remain unaffected either way; this only ever gates real exploitation
    # (Metasploit/sqlmap), enforced in agent/tools/runner.py regardless of where the target
    # entered the allowlist from. Every target in the scope gets authorized, not just the first.
    if authorize_exploit:
        for one_target in clean_targets:
            add_allowed_target(one_target)

    session_id = create_session(clean_target, name=clean_name)
    logger.debug(
        "api: POST /api/scan name=%s target=%s session_id=%s llm_provider=%s authorize_exploit=%s",
        clean_name, clean_target, session_id, resolved_provider, bool(authorize_exploit),
    )
    background_tasks.add_task(_run_session_task, session_id, resolved_provider)
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


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


def _format_sse_event(html: str) -> str:
    data_lines = "\n".join(f"data: {line}" for line in html.splitlines())
    return f"{data_lines}\n\n"


@app.get("/api/session/{session_id}/stream")
async def stream_session(request: Request, session_id: str) -> StreamingResponse:
    if load_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")

    async def event_generator():
        last_hash: str | None = None
        while True:
            if await request.is_disconnected():
                break

            session = load_session(session_id)
            if session is None:
                break

            current_hash = hashlib.sha256(json.dumps(session, sort_keys=True, default=str).encode("utf-8")).hexdigest()
            if current_hash != last_hash:
                last_hash = current_hash
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


@app.get("/session/{session_id}", response_class=HTMLResponse)
def get_session_page(request: Request, session_id: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return templates.TemplateResponse(request, "session.html", {"session": session})


@app.post("/api/session/{session_id}/approve-exploit", response_class=HTMLResponse)
def approve_exploit(request: Request, session_id: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    get_approval_event(session_id).set()
    logger.debug("api: approve-exploit session_id=%s", session_id)
    return HTMLResponse(_render_fragment(request, session))


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


@app.post("/api/session/{session_id}/resume")
def resume_session(session_id: str, background_tasks: BackgroundTasks) -> Response:
    session = load_session(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if session.get("status") != "interrupted":
        raise HTTPException(status_code=400, detail="Session is not in an interrupted state")

    entry_point = session.get("resumable_from") or "recon"
    session["status"] = "processing"
    save_session(session_id, session)
    logger.debug("api: resume session_id=%s entry_point=%s", session_id, entry_point)
    background_tasks.add_task(_run_session_task, session_id, None, entry_point)
    # Same shape as a fresh scan (start_scan) — resuming is "go do more work, then go watch it",
    # not an in-place fragment swap, so a plain redirect (not an HTMX partial) works from both
    # the sessions list and the session page itself without a fragment-shape mismatch.
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


@app.post("/api/session/{session_id}/delete")
def delete_session_route(session_id: str) -> Response:
    if not delete_session(session_id):
        raise HTTPException(status_code=404, detail="Session not found")
    logger.debug("api: delete session_id=%s", session_id)
    return RedirectResponse(url="/sessions", status_code=303)


@app.post("/api/session/{session_id}/chat", response_class=HTMLResponse)
async def chat_turn(request: Request, session_id: str, message: str = Form("")) -> HTMLResponse:
    message = message.strip()
    if load_session(session_id) is None:
        raise HTTPException(status_code=404, detail="Session not found")
    if not message:
        raise HTTPException(status_code=400, detail="Message must not be empty")

    logger.debug("api: chat session_id=%s message_len=%d", session_id, len(message))
    await run_chat_turn(session_id, message)
    # Available during processing and after completed, by design — chat.py always
    # re-reads the session itself, so the panel below reflects whatever state it's actually in.
    session = load_session(session_id)
    return HTMLResponse(_render_chat_panel(request, session))


@app.get("/api/session/{session_id}/export")
def export_proof(request: Request, session_id: str) -> HTMLResponse:
    session = load_session(session_id)
    if session is None or session.get("status") != "completed" or not session.get("findings"):
        raise HTTPException(status_code=404, detail="No proof available for this session")

    html = templates.env.get_template("proof_report.html").render(
        {"request": request, "session": session, "generated_at": datetime.now(timezone.utc).isoformat()}
    )
    headers = {"Content-Disposition": f'attachment; filename="asra-proof-{session_id}.html"'}
    return HTMLResponse(html, headers=headers)


def _load_all_sessions() -> list[dict]:
    summaries = []
    for path in iter_all_session_paths():
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        session_id = data.get("session_id", path.stem)
        logs = data.get("logs", [])
        summaries.append(
            {
                "session_id": session_id,
                "name": data.get("name") or session_id,
                "target": data.get("target", ""),
                "status": data.get("status", "unknown"),
                "findings_count": len(data.get("findings", [])),
                "created_at": data.get("created_at", ""),
                "resumable_from": data.get("resumable_from"),
                "folder": get_session_folder(session_id),
                "phase": logs[-1].get("phase") if logs else None,
            }
        )
    summaries.sort(key=lambda s: s["created_at"], reverse=True)
    return summaries


@app.get("/api/active-session", response_class=HTMLResponse)
def get_active_session(request: Request) -> HTMLResponse:
    """Sidebar quick-return widget (polled) — surfaces whichever session is currently running in
    the background, so switching pages/opening the New Project dialog never loses track of it."""
    active = [s for s in _load_all_sessions() if s["status"] in _ORPHANABLE_STATUSES]
    return templates.TemplateResponse(request, "partials/active_session_badge.html", {"active_sessions": active})


@app.get("/sessions", response_class=HTMLResponse)
def list_sessions(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "sessions_list.html", {"sessions": _load_all_sessions()})


def _llm_settings_context() -> dict:
    saved = load_llm_settings()
    current_provider = saved.get("provider") or os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER)
    if current_provider not in PROVIDER_REGISTRY:
        current_provider = DEFAULT_PROVIDER
    config = PROVIDER_REGISTRY[current_provider]
    current_model = (
        saved.get("model") if saved.get("provider") == current_provider else None
    ) or os.getenv(config.model_env) or config.model_default
    return {
        "current_provider": current_provider,
        "current_model": current_model,
        "provider_models": list_models(config.models_dev_id) or [current_model],
    }


@app.get("/settings", response_class=HTMLResponse)
def get_settings(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "settings.html", {"error": None, **_llm_settings_context()}
    )


@app.get("/api/settings/model-options", response_class=HTMLResponse)
def get_model_options(request: Request, provider: str = "") -> HTMLResponse:
    """HTMX-swapped <option> list for the model dropdown — refetched whenever the provider
    dropdown changes, since which models exist depends on which provider is selected."""
    config = PROVIDER_REGISTRY.get(provider)
    if config is None:
        return HTMLResponse("")
    saved = load_llm_settings()
    current_model = (
        saved.get("model") if saved.get("provider") == provider else None
    ) or os.getenv(config.model_env) or config.model_default
    models = list_models(config.models_dev_id) or [current_model]
    return templates.TemplateResponse(
        request, "partials/model_options.html", {"provider_models": models, "current_model": current_model}
    )


@app.post("/api/settings/llm")
def save_llm(request: Request, provider: str = Form(""), model: str = Form("")) -> Response:
    if provider not in PROVIDER_REGISTRY or not model:
        return templates.TemplateResponse(
            request, "settings.html", {"error": "Pick a valid provider and model.", **_llm_settings_context()}, status_code=400,
        )

    save_llm_settings(provider, model)
    logger.debug("api: llm settings saved provider=%s model=%s", provider, model)
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/api/settings/test-llm", response_class=HTMLResponse)
def test_llm(request: Request, provider: str = Form(""), model: str = Form("")) -> HTMLResponse:
    """A real, minimal completion call against whatever's currently picked in the form — not
    necessarily saved yet, same "try before you commit" flow as Project Assistant's own model
    Test button (src/providers/registry.ts testModelAvailability), which this mirrors.
    """
    if provider not in PROVIDER_REGISTRY or not model:
        return templates.TemplateResponse(request, "partials/llm_test_result.html", {"ok": False, "message": "Pick a provider and model first."})

    started_at = time.monotonic()
    try:
        llm = get_provider(provider, model)
        response = llm.complete([{"role": "user", "content": "ping"}])
        elapsed_ms = int((time.monotonic() - started_at) * 1000)
        if not response.content and response.finish_reason not in ("length", "max_tokens"):
            logger.debug("api: test-llm provider=%s model=%s empty response, finish_reason=%s", provider, model, response.finish_reason)
            message = f"Model returned an empty response (finish_reason: {response.finish_reason or 'none'})."
            return templates.TemplateResponse(request, "partials/llm_test_result.html", {"ok": False, "message": message})
        logger.debug("api: test-llm provider=%s model=%s ok elapsed_ms=%d", provider, model, elapsed_ms)
        return templates.TemplateResponse(request, "partials/llm_test_result.html", {"ok": True, "message": f"Model is available ({elapsed_ms}ms)."})
    except Exception as exc:
        logger.debug("api: test-llm provider=%s model=%s failed: %s", provider, model, exc)
        return templates.TemplateResponse(request, "partials/llm_test_result.html", {"ok": False, "message": str(exc)})
