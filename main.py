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
from datetime import datetime, timezone

from fastapi import BackgroundTasks, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from agent.core import get_approval_event, run_session
from agent.llm_client import DEFAULT_PROVIDER, PROVIDER_REGISTRY
from agent.tools.allowed_targets import add_allowed_target, load_allowed_targets, remove_allowed_target
from agent.tools.builders.validators import validate_target
from agent.utils.logger import get_logger
from sessions.store import SESSIONS_DIR, create_session, load_session, save_session

logger = get_logger("API")

app = FastAPI(title="ASRA")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Sanity bounds on the max_iterations form override (4.1.6) — out-of-range or unparsable input is
# silently ignored in favor of the .env-configured default, not rejected as a validation error.
_MIN_MAX_ITERATIONS = 5
_MAX_MAX_ITERATIONS = 40

# How often the SSE stream re-reads the session file and checks whether it changed.
_SSE_POLL_INTERVAL_SECONDS = 1.0


def _render_fragment(request: Request, session: dict) -> str:
    return templates.env.get_template("partials/session_fragment.html").render({"request": request, "session": session})


def _index_context(*, error: str | None = None, target: str = "") -> dict:
    return {
        "error": error,
        "target": target,
        "provider_ids": list(PROVIDER_REGISTRY),
        "llm_provider_default": os.getenv("LLM_PROVIDER", DEFAULT_PROVIDER),
        "max_iterations_default": int(os.getenv("MAX_ITERATIONS", "20")),
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html", _index_context())


def _resolve_max_iterations(raw: str | None) -> int | None:
    if not raw:
        return None
    try:
        parsed = int(raw)
    except ValueError:
        return None
    if _MIN_MAX_ITERATIONS <= parsed <= _MAX_MAX_ITERATIONS:
        return parsed
    return None


async def _run_session_task(
    session_id: str, provider_id: str | None, max_iterations: int | None, entry_point: str = "recon"
) -> None:
    try:
        await run_session(session_id, provider_id=provider_id, max_iterations=max_iterations, entry_point=entry_point)
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
    for path in SESSIONS_DIR.glob("*.json"):
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
    target: str = Form(""),
    max_iterations: str | None = Form(None),
    llm_provider: str | None = Form(None),
) -> Response:
    try:
        clean_target = validate_target(target)
    except ValueError as exc:
        return templates.TemplateResponse(
            request, "index.html", _index_context(error=str(exc), target=target), status_code=400
        )

    resolved_max_iterations = _resolve_max_iterations(max_iterations)
    resolved_provider = llm_provider if llm_provider in PROVIDER_REGISTRY else None

    session_id = create_session(clean_target)
    logger.debug(
        "api: POST /api/scan target=%s session_id=%s max_iterations=%s llm_provider=%s",
        clean_target, session_id, resolved_max_iterations, resolved_provider,
    )
    background_tasks.add_task(_run_session_task, session_id, resolved_provider, resolved_max_iterations)
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

            if session.get("status") in ("completed", "failed"):
                break
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
    background_tasks.add_task(_run_session_task, session_id, None, None, entry_point)
    # Same shape as a fresh scan (start_scan) — resuming is "go do more work, then go watch it",
    # not an in-place fragment swap, so a plain redirect (not an HTMX partial) works from both
    # the sessions list and the session page itself without a fragment-shape mismatch.
    return RedirectResponse(url=f"/session/{session_id}", status_code=303)


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
    for path in SESSIONS_DIR.glob("*.json"):
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        summaries.append(
            {
                "session_id": data.get("session_id", path.stem),
                "target": data.get("target", ""),
                "status": data.get("status", "unknown"),
                "findings_count": len(data.get("findings", [])),
                "created_at": data.get("created_at", ""),
                "resumable_from": data.get("resumable_from"),
            }
        )
    summaries.sort(key=lambda s: s["created_at"], reverse=True)
    return summaries


@app.get("/sessions", response_class=HTMLResponse)
def list_sessions(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "sessions_list.html", {"sessions": _load_all_sessions()})


@app.get("/settings", response_class=HTMLResponse)
def get_settings(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "settings.html", {"allowed_targets": load_allowed_targets(), "error": None}
    )


@app.post("/api/settings/allowed-targets")
def add_target(request: Request, target: str = Form("")) -> Response:
    try:
        clean_target = validate_target(target)
    except ValueError as exc:
        return templates.TemplateResponse(
            request,
            "settings.html",
            {"allowed_targets": load_allowed_targets(), "error": str(exc)},
            status_code=400,
        )

    add_allowed_target(clean_target)
    logger.debug("api: allowed_targets add target=%s", clean_target)
    return RedirectResponse(url="/settings", status_code=303)


@app.delete("/api/settings/allowed-targets/{target}")
def delete_target(target: str) -> Response:
    remove_allowed_target(target)
    logger.debug("api: allowed_targets remove target=%s", target)
    return Response(status_code=200, content="")
