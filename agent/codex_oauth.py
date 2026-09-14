""""Sign in with ChatGPT" — OAuth2/PKCE login for the OpenAI provider, giving ASRA access to a
ChatGPT Plus/Pro/Team subscription's own Codex backend instead of a separate pay-per-token API key.
Ported from a real, working reference implementation (Umbra-Agent's openai-codex OAuth flow) —
same client_id, same endpoints, same PKCE mechanics; this file only adapts it to ASRA's own
sync/httpx stack and JSON-file storage conventions (agent/custom_providers.py's own style).

This is deliberately a SEPARATE, explicitly-chosen provider identity (see CODEX_PROVIDER_ID in
agent/llm_client.py) rather than a hidden alternate mode of the existing "openai" API-key provider —
this project's whole fallback-chain feature exists specifically to avoid silent, implicit provider
switching, and a ChatGPT-subscription login swapping in behind the same "openai" id the moment
tokens happen to exist would be exactly that.

Token storage: data/codex_oauth_tokens.json (gitignored — holds a real, working OAuth refresh
token). The redirect_uri (http://localhost:1455/auth/callback) is fixed by this client_id's own
OAuth app registration and cannot be changed — the local callback listener below must bind exactly
that host/port.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("LLM")

# Global app data (Documents/ASRA/data on Windows/macOS, see projects/paths.py's
# resolve_global_app_dir), never a repo-relative data/ folder -- a real, working OAuth refresh
# token has no business sitting inside the same directory as the git checkout.
CODEX_TOKENS_PATH = resolve_global_app_dir() / "data" / "codex_oauth_tokens.json"

# Public OAuth client id shared by every "Sign in with ChatGPT" integration using this exact flow
# (Codex CLI and the community tools that interoperate with it) — not a secret, it identifies the
# OAuth application, not a credential.
_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
_TOKEN_URL = "https://auth.openai.com/oauth/token"
_CALLBACK_HOST = "127.0.0.1"
_CALLBACK_PORT = 1455
_REDIRECT_URI = f"http://localhost:{_CALLBACK_PORT}/auth/callback"
_SCOPE = "openid profile email offline_access"
_JWT_CLAIM_PATH = "https://api.openai.com/auth"

# How long a not-yet-completed login attempt (state + PKCE verifier) is held in memory before it's
# treated as abandoned — bounds both _PENDING_LOGINS and the callback listener thread's own
# lifetime, so an operator who starts a login and never finishes it doesn't leave either running
# forever unattended, same "own every background task until it's stopped" discipline this
# project applies to any long-lived process it starts.
_LOGIN_ATTEMPT_TIMEOUT_SECONDS = 300

_pending_lock = threading.Lock()
# state -> {"verifier": str, "created_at": float, "status": "pending"|"success"|"error", "message": str}
_pending_logins: dict[str, dict] = {}
_active_server: HTTPServer | None = None
_active_server_thread: threading.Thread | None = None


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _decode_jwt_payload(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except (ValueError, json.JSONDecodeError):
        return None


def extract_account_id(access_token: str) -> str | None:
    payload = _decode_jwt_payload(access_token)
    if not payload:
        return None
    auth_claim = payload.get(_JWT_CLAIM_PATH)
    if not isinstance(auth_claim, dict):
        return None
    account_id = auth_claim.get("chatgpt_account_id")
    return account_id if isinstance(account_id, str) and account_id else None


def build_authorize_url(state: str, challenge: str) -> str:
    params = {
        "response_type": "code",
        "client_id": _CLIENT_ID,
        "redirect_uri": _REDIRECT_URI,
        "scope": _SCOPE,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "id_token_add_organizations": "true",
        "originator": "asra",
    }
    return f"{_AUTHORIZE_URL}?{urlencode(params)}"


def _token_request(data: dict) -> dict:
    """POSTs to OpenAI's token endpoint (authorization_code or refresh_token grant) and returns
    {"access", "refresh", "expires" (epoch seconds), "account_id"}. Raises RuntimeError with a
    human-readable message on any failure — the caller (login flow / get_valid_access_token) is
    responsible for deciding whether that's worth surfacing to the operator or retrying.
    """
    request_timeout = float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", "120"))
    response = httpx.post(
        _TOKEN_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=request_timeout,
    )
    if response.status_code != 200:
        raise RuntimeError(f"OpenAI token endpoint returned {response.status_code}: {response.text[:300]}")
    payload = response.json()
    access = payload.get("access_token")
    refresh = payload.get("refresh_token")
    expires_in = payload.get("expires_in")
    if not access or not refresh or not isinstance(expires_in, (int, float)):
        raise RuntimeError(f"OpenAI token endpoint response is missing expected fields: {list(payload.keys())}")
    account_id = extract_account_id(access)
    if not account_id:
        raise RuntimeError("Could not extract a ChatGPT account id from the issued access token.")
    return {"access": access, "refresh": refresh, "expires": time.time() + float(expires_in), "account_id": account_id}


def exchange_code(code: str, verifier: str) -> dict:
    return _token_request({
        "grant_type": "authorization_code",
        "client_id": _CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": _REDIRECT_URI,
    })


def refresh_access_token(refresh_token: str) -> dict:
    return _token_request({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": _CLIENT_ID,
    })


def load_tokens() -> dict | None:
    if not CODEX_TOKENS_PATH.exists():
        return None
    try:
        with CODEX_TOKENS_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("codex_oauth: token file unreadable (%s) -- treating as signed out", exc)
        return None
    return data if isinstance(data, dict) and data.get("access") else None


def save_tokens(tokens: dict) -> None:
    CODEX_TOKENS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = CODEX_TOKENS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    os.replace(tmp_path, CODEX_TOKENS_PATH)
    logger.debug("codex_oauth: tokens saved for account=%s", tokens.get("account_id"))


def clear_tokens() -> None:
    if CODEX_TOKENS_PATH.exists():
        CODEX_TOKENS_PATH.unlink()
    logger.debug("codex_oauth: tokens cleared (signed out)")


def is_signed_in() -> bool:
    return load_tokens() is not None


def get_valid_access_token(force_refresh: bool = False) -> dict:
    """Returns {"access", "account_id"}, transparently refreshing the stored token first if it's
    within 60s of expiring (same margin Umbra-Agent's own reference implementation uses), or
    always when force_refresh=True -- used by codex_provider.py's own single 401-triggers-refresh-
    and-retry handling for the case where the token looks unexpired by our own clock but the
    backend has already invalidated it server-side. Raises RuntimeError with a message safe to show
    the operator (never a raw provider error body) when there's no session at all or the refresh
    itself fails -- both mean "sign in again", not "retry this request".
    """
    stored = load_tokens()
    if stored is None:
        raise RuntimeError('Not signed in to ChatGPT. Go to Settings and click "Sign in with ChatGPT".')
    if not force_refresh and time.time() < stored["expires"] - 60:
        return {"access": stored["access"], "account_id": stored["account_id"]}
    try:
        refreshed = refresh_access_token(stored["refresh"])
    except RuntimeError as exc:
        # A force_refresh means the caller already knows the current token was just rejected (a
        # 401) -- falling back to that same token would just reproduce the failure, so only the
        # proactive/lazy (about-to-expire) path gets to keep coasting on a still-technically-valid
        # token when refresh itself fails.
        if not force_refresh and time.time() < stored["expires"]:
            logger.debug("codex_oauth: refresh failed but stored token is still valid, using it: %s", exc)
            return {"access": stored["access"], "account_id": stored["account_id"]}
        raise RuntimeError("ChatGPT session expired and refresh failed -- please sign in again.") from exc
    save_tokens(refreshed)
    return {"access": refreshed["access"], "account_id": refreshed["account_id"]}


_SUCCESS_HTML = (
    '<!doctype html><html><head><meta charset="utf-8"><title>Signed in</title>'
    "<style>body{font-family:system-ui,sans-serif;background:#09090b;color:#fafafa;min-height:100vh;"
    "display:flex;align-items:center;justify-content:center;text-align:center;margin:0}"
    "h1{font-size:1.5rem;color:#22c55e}p{color:#a1a1aa}</style></head>"
    "<body><main><h1>Signed in to ChatGPT</h1><p>You can close this tab and go back to ASRA.</p></main></body></html>"
)
_FAILURE_HTML_TEMPLATE = (
    '<!doctype html><html><head><meta charset="utf-8"><title>Sign-in failed</title>'
    "<style>body{{font-family:system-ui,sans-serif;background:#09090b;color:#fafafa;min-height:100vh;"
    "display:flex;align-items:center;justify-content:center;text-align:center;margin:0}}"
    "h1{{font-size:1.5rem;color:#ef4444}}p{{color:#a1a1aa}}</style></head>"
    "<body><main><h1>Sign-in failed</h1><p>{message}</p></main></body></html>"
)


class _CallbackHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - stdlib signature
        logger.debug("codex_oauth: callback listener: " + format, *args)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/auth/callback":
            self.send_response(404)
            self.end_headers()
            return
        query = parse_qs(parsed.query)
        state = (query.get("state") or [None])[0]
        code = (query.get("code") or [None])[0]
        error = (query.get("error") or [None])[0]

        with _pending_lock:
            attempt = _pending_logins.get(state) if state else None

        if attempt is None:
            self._respond(400, "Unknown or expired sign-in attempt. Start again from Settings.")
        elif error:
            self._finish(state, "error", f"OpenAI returned an error: {error}")
        elif not code:
            self._finish(state, "error", "Missing authorization code in the callback.")
        else:
            self._complete_exchange(state, code, attempt["verifier"])

    def _complete_exchange(self, state: str, code: str, verifier: str) -> None:
        try:
            tokens = exchange_code(code, verifier)
        except RuntimeError as exc:
            self._finish(state, "error", str(exc))
            return
        save_tokens(tokens)
        self._finish(state, "success", f"Signed in as account {tokens['account_id'][:8]}...")

    def _finish(self, state: str, status: str, message: str) -> None:
        with _pending_lock:
            if state in _pending_logins:
                _pending_logins[state]["status"] = status
                _pending_logins[state]["message"] = message
        if status == "success":
            self._respond(200, None)
        else:
            self._respond(400, message)

    def _respond(self, code: int, error_message: str | None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = _SUCCESS_HTML if error_message is None else _FAILURE_HTML_TEMPLATE.format(message=error_message)
        self.wfile.write(body.encode("utf-8"))


def _prune_expired_attempts() -> None:
    cutoff = time.time() - _LOGIN_ATTEMPT_TIMEOUT_SECONDS
    expired = [state for state, attempt in _pending_logins.items() if attempt["created_at"] < cutoff and attempt["status"] == "pending"]
    for state in expired:
        _pending_logins[state]["status"] = "error"
        _pending_logins[state]["message"] = "Sign-in attempt timed out."


def start_login_flow() -> dict:
    """Begins a "Sign in with ChatGPT" attempt: generates a fresh PKCE verifier/challenge + state,
    starts the local callback listener (127.0.0.1:1455) if one isn't already running, and returns
    the URL the frontend should open in a new tab. The listener auto-stops the moment it handles a
    real callback, or after _LOGIN_ATTEMPT_TIMEOUT_SECONDS if the operator never completes the flow
    in their browser -- it never lingers unattended past either of those.
    """
    global _active_server, _active_server_thread
    verifier, challenge = generate_pkce()
    state = secrets.token_hex(16)

    with _pending_lock:
        _prune_expired_attempts()
        _pending_logins[state] = {"verifier": verifier, "created_at": time.time(), "status": "pending", "message": ""}
        server_already_running = _active_server is not None

    if not server_already_running:
        server = HTTPServer((_CALLBACK_HOST, _CALLBACK_PORT), _CallbackHandler)
        thread = threading.Thread(target=_run_server_with_watchdog, args=(server,), daemon=True)
        with _pending_lock:
            _active_server = server
            _active_server_thread = thread
        thread.start()
        logger.debug("codex_oauth: callback listener started on %s:%d", _CALLBACK_HOST, _CALLBACK_PORT)

    return {"state": state, "auth_url": build_authorize_url(state, challenge)}


def _run_server_with_watchdog(server: HTTPServer) -> None:
    """Serves callback requests (server.handle_request(), one per loop iteration, each bounded by
    server.timeout so a quiet socket never blocks longer than that) until every pending login
    attempt has resolved or the overall deadline passes -- whichever comes first. Always cleans up
    the socket and the module-level "a listener is running" state in `finally`, so a login the
    operator never completes in their browser can't leave this thread (or the bound port) alive
    past _LOGIN_ATTEMPT_TIMEOUT_SECONDS.
    """
    server.timeout = 5.0
    deadline = time.time() + _LOGIN_ATTEMPT_TIMEOUT_SECONDS
    try:
        while time.time() < deadline:
            with _pending_lock:
                still_pending = any(a["status"] == "pending" for a in _pending_logins.values())
            if not still_pending:
                break
            server.handle_request()
    finally:
        try:
            server.server_close()
        except OSError:
            pass
        with _pending_lock:
            global _active_server, _active_server_thread
            if _active_server is server:
                _active_server = None
                _active_server_thread = None
        logger.debug("codex_oauth: callback listener watchdog exited")


def get_login_status(state: str) -> dict:
    with _pending_lock:
        attempt = _pending_logins.get(state)
        if attempt is None:
            return {"status": "error", "message": "Unknown or expired sign-in attempt."}
        return {"status": attempt["status"], "message": attempt["message"]}
