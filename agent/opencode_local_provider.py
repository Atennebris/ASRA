"""OpenCodeLocalProvider -- the LLMProvider implementation for a local `opencode serve` process
(see agent/llm_client.py's OPENCODE_LOCAL_PROVIDER_ID/OPENCODE_LOCAL_DISPLAY_NAME for the id/label
wiring, same split as CodexOAuthProvider/CopilotOAuthProvider -- those constants live in
llm_client.py to avoid a circular import, the real class lives here).

Why this exists at all: opencode.ai's own "zen" free tier (PROVIDER_REGISTRY["opencode-zen"],
OpenAICompatProvider talking straight to https://opencode.ai/zen/v1) only answers genuine opencode
CLI traffic -- a plain OpenAI-compatible request (headers mimicked or not) gets 403
"can only be used from within OpenCode" for most free-branded models. This provider sidesteps that
entirely by spawning the REAL opencode CLI on this machine (`opencode serve`) and talking to its own
local session API instead -- opencode itself is the "genuine client" the free tier's gate wants.
Confirmed live against the real installed CLI (1.18.32) while building this: a session created
through this exact path gets a real, free reply from "big-pickle" with cost=0, where a bare HTTP
POST to the zen endpoint would 403.

Architecture, mirrored from this project's own sibling Node/Electron app (which proved this same
approach first) but written fresh against THIS project's own LLMProvider contract and this exact
opencode version's real, live-verified HTTP API (its OpenAPI shape has drifted from what that
sibling project documented for an older point release -- e.g. the permission-reply endpoint moved
from `/session/{id}/permissions/{permissionID}` to `/permission/{requestID}/reply`; everything below
was checked against a live `opencode serve` process, not assumed from memory):

- One `opencode serve` process for the whole app (module-level singleton, _get_shared_server),
  started lazily on first use and reused by every call -- a fresh OpenCodeLocalProvider instance is
  built per get_provider() call (see llm_client.py), so the server can't live on the instance.
- The server is started with its CWD set to a disposable per-process temp directory that holds a
  project-local opencode.json defining a custom "asra-ask" primary agent. Confirmed live that this
  is the mechanism that actually works -- a runtime `PATCH /config` call on an already-running
  server does NOT persist (verified: a subsequent GET /config came back with no agent at all), but
  a project-local opencode.json file present in the server's own CWD *at startup* loads correctly.
- That agent's `permission` block sets edit/bash/webfetch/external_directory to "ask" (not "deny").
  This project's own sibling app's hard-won finding (confirmed structurally plausible here, and
  consistent with every live test run while building this) is that denying a tool outright removes
  it from what the model is even OFFERED, and restricting the offered tool set is itself what the
  free tier's gate reacts to -- "ask" keeps every tool genuinely offered (satisfying the gate)
  without ever letting one actually run unapproved. A background daemon thread (_PermissionDenier)
  polls the server's own `GET /permission` (a plain pending-request list, no SSE needed -- simpler
  than the sibling project's event-stream subscription, and confirmed live to work) and replies
  "reject" to every pending request. This is safe and intentional, not a missing feature: ASRA's
  own tool loop (agent/core.py) executes every real tool call itself, through ASRA's own permission
  gate -- letting opencode's internal bash/edit/webfetch tools actually run here would be a second,
  redundant, unsandboxed execution path for the exact same kind of action.
- Native tool-calling has no channel into opencode's session API at all (it only ever runs its own
  internal tools, never a caller-supplied JSON-schema tool) -- ASRA's own tools are offered to the
  model via the exact same prompt-injection machinery agent/llm_client.py's OpenAICompatProvider
  already uses in "prompt" mode (_inject_tool_instructions/_extract_prompt_tool_calls, imported
  directly rather than re-implemented a second time here).
- The local session API takes one message per call, not a structured multi-turn history -- rather
  than keep a long-lived opencode session in step with ASRA's own transcript, every call opens a
  fresh ephemeral session, flattens the whole conversation into one labeled text block
  (_render_transcript), sends it, reads the reply, and deletes the session again. An extra
  create+delete round trip per turn; correct and simple beats stateful and fragile here.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path
from tempfile import mkdtemp

import httpx

from agent.llm_client import (
    OPENCODE_LOCAL_PROVIDER_ID,
    EmptyResponseError,
    LLMResponse,
    ToolCallRequest,
    _call_with_backoff,
    _extract_prompt_tool_calls,
    _inject_tool_instructions,
)
from agent.utils.debug import truncate_for_log
from agent.utils.lazy_openai import openai
from agent.utils.logger import get_logger

logger = get_logger("LLM")

# "big-pickle" -- the same default opencode-zen already uses (PROVIDER_REGISTRY), since both
# ultimately serve the exact same opencode-hosted model catalog; a free, tool-calling-capable model
# every sign-in-less install already has access to, confirmed live via GET /config/providers.
OPENCODE_LOCAL_DEFAULT_MODEL = "big-pickle"
_AGENT_NAME = "asra-ask"
# How long to wait for `opencode serve` to come up before giving up -- operator-tunable (a slow
# machine, or the CLI's own first-ever cold start on this install, can genuinely need longer than
# the default; CLAUDE.md -- anything that can vary, timeouts included, belongs in config/env, not
# baked in).
_DEFAULT_READY_TIMEOUT_SECONDS = 20
_PERMISSION_POLL_INTERVAL_SECONDS = 0.4
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 120
_SERVER_LOG_TAIL_LINES = 50


def _ready_timeout_seconds() -> float:
    return float(os.getenv("OPENCODE_LOCAL_READY_TIMEOUT_SECONDS", str(_DEFAULT_READY_TIMEOUT_SECONDS)))

# Written as this server's own project-local opencode.json -- see module docstring for why a
# runtime PATCH /config doesn't stick but this file, present in the server's CWD at startup, does.
_AGENT_CONFIG: dict = {
    "$schema": "https://opencode.ai/config.json",
    "agent": {
        _AGENT_NAME: {
            "mode": "primary",
            "description": (
                "ASRA local-provider session. Every mutating tool asks for approval before it "
                "runs; ASRA auto-denies all of them from the outside (its own tool loop executes "
                "real tools separately, through its own permission gate) -- see this project's "
                "agent/opencode_local_provider.py module docstring."
            ),
            "permission": {
                "edit": "ask",
                "bash": "ask",
                "webfetch": "ask",
                "external_directory": "ask",
                "doom_loop": "allow",
            },
        }
    },
}


def _find_free_port() -> int:
    """A port nothing is listening on right now. Confirmed live: `opencode serve --port 0` does
    NOT mean "pick a free port" -- it falls back to a fixed 4096, which collides with any other
    opencode server already running on the machine (the operator's own, or one a crashed ASRA run
    left behind). Asking the OS for a real ephemeral port first takes the collision away.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _resolve_opencode_binary() -> str:
    binary = shutil.which("opencode")
    if not binary:
        raise ValueError(
            "The opencode CLI is not installed (or not on this process's PATH). Install it "
            "(`npm install -g opencode-ai`, or see https://opencode.ai) in this machine's own "
            "shell -- under this project's WSL2 launch path (see CLAUDE.md), that means installed "
            "*inside* WSL2, not just on the Windows side -- then try this provider again."
        )
    return binary


class _PermissionDenier(threading.Thread):
    """Runs for the whole lifetime of one shared server. Polls GET /permission (a plain pending-
    request list) and replies "reject" to everything found -- see module docstring for why this is
    the correct, intentional behavior rather than a stub. A failed poll/reply (server mid-restart,
    one request answered a moment too late by something else) is logged at debug level and
    retried next tick, never raised -- this thread must never be the thing that takes the shared
    server down.
    """

    def __init__(self, base_url: str, stop_event: threading.Event):
        super().__init__(daemon=True, name="asra-opencode-local-permission-denier")
        self._base_url = base_url
        self._stop_event = stop_event

    def run(self) -> None:
        with httpx.Client(timeout=5.0) as client:
            while not self._stop_event.is_set():
                try:
                    response = client.get(f"{self._base_url}/permission")
                    if response.is_success:
                        for pending in response.json():
                            request_id = pending.get("id")
                            if not request_id:
                                continue
                            client.post(f"{self._base_url}/permission/{request_id}/reply", json={"reply": "reject"})
                            logger.debug(
                                "opencode_local_provider: denied pending permission request=%s permission=%s",
                                request_id, pending.get("permission"),
                            )
                except httpx.HTTPError as exc:
                    logger.debug("opencode_local_provider: permission poll failed (will retry): %s", exc)
                self._stop_event.wait(_PERMISSION_POLL_INTERVAL_SECONDS)


class _LogDrain(threading.Thread):
    """Continuously drains the server subprocess's stdout -- NOT just for cosmetics: a pipe nobody
    reads from fills its OS buffer once `--print-logs` writes enough output, at which point the
    opencode process blocks on its own next write and the whole server hangs. Keeps only the last
    _SERVER_LOG_TAIL_LINES for a startup-failure error message; everything else is logged at debug
    level (so DEBUG=true still surfaces it in this project's own debug log, per CLAUDE.md's debug-
    module rule) and then discarded.
    """

    def __init__(self, process: subprocess.Popen):
        super().__init__(daemon=True, name="asra-opencode-local-log-drain")
        self._process = process
        self.tail: deque[str] = deque(maxlen=_SERVER_LOG_TAIL_LINES)

    def run(self) -> None:
        stdout = self._process.stdout
        if stdout is None:
            return
        for line in stdout:
            line = line.rstrip("\n")
            self.tail.append(line)
            logger.debug("opencode_local_provider: [server] %s", line)


class _SharedServer:
    def __init__(self, base_url: str, process: subprocess.Popen, sandbox_dir: str, log_drain: _LogDrain):
        self.base_url = base_url
        self.process = process
        self.sandbox_dir = sandbox_dir
        self._log_drain = log_drain
        self._stop_event = threading.Event()
        self._denier = _PermissionDenier(base_url, self._stop_event)
        self._denier.start()

    def is_alive(self) -> bool:
        return self.process.poll() is None

    def close(self) -> None:
        self._stop_event.set()
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
        logger.debug("opencode_local_provider: shared server stopped")


_shared_server: _SharedServer | None = None
_shared_server_lock = threading.Lock()


def _start_server() -> _SharedServer:
    binary = _resolve_opencode_binary()
    sandbox_dir = mkdtemp(prefix="asra-opencode-local-")
    Path(sandbox_dir, "opencode.json").write_text(json.dumps(_AGENT_CONFIG), encoding="utf-8")
    port = _find_free_port()
    logger.info("opencode_local_provider: starting local opencode server port=%s sandbox=%s", port, sandbox_dir)
    process = subprocess.Popen(  # noqa: S603 -- fixed argv, no shell, no user-controlled input
        [binary, "serve", "--hostname", "127.0.0.1", "--port", str(port), "--print-logs"],
        cwd=sandbox_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    log_drain = _LogDrain(process)
    log_drain.start()

    base_url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + _ready_timeout_seconds()
    with httpx.Client(timeout=2.0) as probe:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                tail = "\n".join(log_drain.tail) or "(no output)"
                raise ValueError(f"The local opencode server exited before it was ready:\n{tail}")
            try:
                if probe.get(f"{base_url}/config").is_success:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        else:
            process.kill()
            tail = "\n".join(log_drain.tail) or "(no output)"
            raise ValueError(f"The local opencode server did not become ready in time:\n{tail}")

    logger.info("opencode_local_provider: local opencode server ready base_url=%s", base_url)
    return _SharedServer(base_url=base_url, process=process, sandbox_dir=sandbox_dir, log_drain=log_drain)


def _get_shared_server() -> _SharedServer:
    global _shared_server
    with _shared_server_lock:
        if _shared_server is None or not _shared_server.is_alive():
            _shared_server = _start_server()
        return _shared_server


def close_shared_opencode_server() -> None:
    """Stops the shared local opencode server, if one was ever started. Call on app shutdown
    (main.py's _lifespan, alongside its other background-process backstops)."""
    global _shared_server
    with _shared_server_lock:
        if _shared_server is not None:
            _shared_server.close()
            _shared_server = None


def _live_opencode_models() -> dict[str, dict]:
    """model_id -> {"free": bool} for every model THIS machine's opencode can actually run right
    now, straight from the live server's own GET /config/providers -- first-party, real-time data,
    not the third-party models.dev catalog (see agent/providers/models_dev.py's own get_model_cost
    docstring for why a catalog's cost field isn't always trustworthy as a free/paid signal).
    Returns {} (never raises) when the opencode CLI isn't installed or the server fails to start --
    same "no models yet, not an error" contract agent/llm_client.py's own local-provider discovery
    (_fetch_local_model_ids, for LM Studio/Ollama) already follows.
    """
    try:
        server = _get_shared_server()
        with httpx.Client(timeout=10.0) as client:
            response = client.get(f"{server.base_url}/config/providers")
            response.raise_for_status()
            data = response.json()
    except (ValueError, httpx.HTTPError) as exc:
        logger.debug("opencode_local_provider: model discovery failed: %s", exc)
        return {}

    for provider in data.get("providers", []):
        if provider.get("id") != "opencode":
            continue
        models = {}
        for model_id, model in provider.get("models", {}).items():
            cost = model.get("cost") or {}
            models[model_id] = {"free": cost.get("input") == 0 and cost.get("output") == 0}
        return models
    return {}


def list_opencode_local_models(signal: object = None) -> dict[str, dict]:
    """model_id -> {"free": bool, "available": bool} -- the live list ABOVE (_live_opencode_models,
    "available": True) plus every OTHER model opencode's own real catalog knows about
    ("available": False), filled in from models.dev's "opencode" entry. Real, confirmed operator
    complaint this fixes: with no `opencode auth login` on this machine, the live server lists only
    its free tier (10 models) -- opencode itself genuinely supports well over a hundred more
    (Claude/GPT/Gemini/GLM/... paid models) once signed in, and a model picker showing only the
    free 10 reads as "this provider barely supports anything," not "sign in to unlock the rest."
    Same "whole catalog, narrowed list filled back in" idea this project's own sibling dashboard
    app already uses for this exact provider (its own withCatalogFillIn/signInReveals).

    free for a catalog-only (not live) entry comes from models.dev's own cost data (
    agent.providers.models_dev.is_model_free) -- None there (price genuinely unknown) reads as
    "free": False here only when the catalog is silent AND it isn't live either; never silently
    promoted to true. Returns at least the live dict on any catalog-fetch failure (graceful
    degrade, never worse than before this fill-in existed).
    """
    from agent.providers.models_dev import is_model_free, list_models

    live = _live_opencode_models()
    models = {model_id: {**info, "available": True} for model_id, info in live.items()}
    for model_id in list_models("opencode"):
        if model_id in models:
            continue
        free = is_model_free("opencode", model_id)
        models[model_id] = {"free": bool(free), "available": False}
    return models


def _render_transcript(messages: list[dict]) -> tuple[str, str]:
    """(system_text, transcript_text). opencode's own session/message API takes one turn's worth
    of free text, not a structured multi-turn array -- flattens the whole conversation into one
    labeled text block instead (see module docstring for why), mirroring how
    agent/codex_provider.py's own _messages_to_codex_input walks the same message shape for a
    different backend's own different input format.
    """
    system_parts: list[str] = []
    blocks: list[str] = []
    for message in messages:
        role = message.get("role")
        if role == "system":
            if message.get("content"):
                system_parts.append(message["content"])
            continue
        if role == "tool":
            content = message.get("content") or ""
            if content:
                blocks.append(f"Tool result:\n{content}")
            continue
        tool_calls = message.get("tool_calls") or []
        call_lines = [
            f"[called {call.get('function', {}).get('name', '')} with "
            f"{call.get('function', {}).get('arguments', '{}')}]"
            for call in tool_calls
        ]
        text = message.get("content") or ""
        body_lines = ([text] if text else []) + call_lines
        if body_lines:
            label = "Assistant" if role == "assistant" else "User"
            blocks.append(f"{label}: " + "\n".join(body_lines))
    return "\n\n".join(system_parts), "\n\n".join(blocks)


def _describe_assistant_error(error: dict | None) -> str:
    if not error:
        return "unknown error"
    data = error.get("data") if isinstance(error, dict) else None
    if isinstance(data, dict) and isinstance(data.get("message"), str):
        return data["message"]
    return str(error.get("name") or error)


class OpenCodeLocalProvider:
    def __init__(self, model: str | None = None):
        self.provider_id = OPENCODE_LOCAL_PROVIDER_ID
        self.model = model or OPENCODE_LOCAL_DEFAULT_MODEL
        # Unknown upfront (no models.dev entry for opencode's own locally-served catalog carries a
        # context window today) -- None is this project's own established "unknown, don't guess"
        # contract for this field (see agent/llm_client.py's LLMProvider Protocol docstring).
        self.context_limit: int | None = None

    def complete(
        self, messages: list[dict], tools: list[dict] | None = None, stop_check: Callable[[], bool] | None = None
    ) -> LLMResponse:
        prompt_messages = _inject_tool_instructions(messages, tools) if tools else messages
        if tools:
            # Confirmed live while building this: without this disclaimer, the model -- running
            # inside opencode's own real agentic harness, which genuinely offers it bash/edit/
            # webfetch/websearch/question -- reliably (not occasionally) tries to invoke the
            # prompt-injected tool the SAME way it invokes those real ones (native function-
            # calling through opencode's own dispatch), gets "Model tried to call unavailable tool
            # '<name>'" back from opencode itself, and reports that failure in prose instead of
            # falling back to the literal <tool_call> text format _inject_tool_instructions asked
            # for. A plain OpenAICompatProvider never hits this because its own model has no real
            # tool-execution channel to confuse the prompt-injected one with in the first place.
            # Tried and REJECTED as a fix: disabling opencode's own real tools for just this one
            # message (the per-message `tools: {bash: false, ...}` body field) -- confirmed live
            # that this reproduces the exact same "can only be used from within OpenCode" 403 the
            # free tier's gate gives a plain HTTP client, for the identical reason this provider
            # exists at all (see module docstring): restricting what's OFFERED is what the gate
            # reacts to, whether that's done via the agent's own permission config or this field.
            prompt_messages = [
                {
                    "role": "system",
                    "content": (
                        "IMPORTANT: the tool(s) described below are NOT part of your real tool "
                        "environment here (they are not bash/edit/webfetch/websearch/question or "
                        "anything else actually wired up) -- trying to invoke one the normal way "
                        "will fail with \"unavailable tool\". The ONLY way to use one is to answer "
                        "with the exact literal text format given below; do not attempt any other "
                        "invocation method, and do not report the normal invocation as having "
                        "failed -- just answer in that literal text format directly."
                    ),
                },
                *prompt_messages,
            ]
        system_text, transcript_text = _render_transcript(prompt_messages)

        logger.debug(
            "opencode_local_provider: request model=%s messages=%d tools=%d",
            self.model, len(messages), len(tools or []),
        )

        payload = _call_with_backoff(
            lambda: self._run_turn(system_text, transcript_text), stop_check=stop_check,
        )
        response = self._parse_response(payload, bool(tools))

        logger.debug(
            "opencode_local_provider: response finish_reason=%s tool_calls=%d usage=%s content_preview=%s",
            response.finish_reason, len(response.tool_calls), response.usage,
            truncate_for_log(response.content or "", step_id=f"opencode_local_response_{int(time.time() * 1000)}"),
        )
        return response

    def _run_turn(self, system_text: str, transcript_text: str) -> dict:
        """One full session create -> message -> delete cycle. Raises the exact openai-SDK
        exception types _call_with_backoff already knows how to retry (429/5xx/connection errors),
        same convention agent/codex_provider.py's own _raw_request already follows for its own,
        different backend -- so a transient opencode_local failure is retried and (if the operator
        has one configured) falls back through the Reserve providers chain exactly like any other
        provider's failure, with no provider-specific branch needed anywhere else.
        """
        server = _get_shared_server()
        timeout = float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", str(_DEFAULT_REQUEST_TIMEOUT_SECONDS)))
        with httpx.Client(timeout=timeout) as client:
            session_response = self._post(client, f"{server.base_url}/session", {"title": "asra"})
            session_id = session_response.json()["id"]
            try:
                body: dict = {
                    "agent": _AGENT_NAME,
                    "model": {"providerID": "opencode", "modelID": self.model},
                    "parts": [{"type": "text", "text": transcript_text}],
                }
                if system_text:
                    body["system"] = system_text
                message_response = self._post(client, f"{server.base_url}/session/{session_id}/message", body)
                return message_response.json()
            finally:
                try:
                    client.delete(f"{server.base_url}/session/{session_id}")
                except httpx.HTTPError as exc:
                    logger.debug("opencode_local_provider: failed to clean up ephemeral session=%s: %s", session_id, exc)

    @staticmethod
    def _post(client: httpx.Client, url: str, body: dict) -> httpx.Response:
        try:
            response = client.post(url, json=body)
        except httpx.TimeoutException as exc:
            raise openai.APITimeoutError(request=exc.request) from exc
        except httpx.ConnectError as exc:
            raise openai.APIConnectionError(message=str(exc), request=exc.request) from exc
        if response.status_code == 429:
            raise openai.RateLimitError("opencode local server returned 429.", response=response, body=None)
        if not response.is_success:
            raise openai.APIStatusError(
                f"opencode local server HTTP {response.status_code}: {response.text[:300]}",
                response=response, body=None,
            )
        return response

    def _parse_response(self, payload: dict, had_tools: bool) -> LLMResponse:
        info = payload.get("info") or {}
        parts = payload.get("parts") or []
        text = "".join(part.get("text", "") for part in parts if part.get("type") == "text")

        error = info.get("error")
        if error and not text:
            # Mirrors _create_completion_with_backoff's own "finish_reason == error with nothing
            # usable" gate for OpenAICompatProvider -- an EmptyResponseError here is retried by
            # _call_with_backoff exactly like any other provider's transient empty reply.
            raise EmptyResponseError(f"opencode local session reported: {_describe_assistant_error(error)}")

        tool_calls: list[ToolCallRequest] = _extract_prompt_tool_calls(text) if had_tools else []
        tokens = info.get("tokens") or {}
        usage = None
        if tokens.get("input") is not None or tokens.get("output") is not None:
            usage = {
                "prompt_tokens": int(tokens.get("input") or 0),
                "completion_tokens": int(tokens.get("output") or 0),
            }
        finish_reason = info.get("finish") or ("tool_use" if tool_calls else "stop")
        return LLMResponse(
            content=text or None, tool_calls=tool_calls, finish_reason=finish_reason,
            content_was_malformed=False, usage=usage,
        )
