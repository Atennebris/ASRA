""""Sign in with GitHub Copilot" -- OAuth device-flow login giving ASRA access to an existing
GitHub Copilot subscription (Individual/Business/Enterprise) instead of a separate per-token API
key. The GitHub-Copilot counterpart of agent/codex_oauth.py's "Sign in with ChatGPT" -- same
motivation, same overall shape (a signed-in/signed-out session stored as a JSON file, resolved lazily
into a real LLMProvider by agent/llm_client.py), different underlying OAuth mechanics because GitHub
Copilot doesn't expose a browser-redirect PKCE flow for third-party tools the way ChatGPT does.

Two token layers, not one:
1. A GitHub OAuth device-flow access token, obtained once via https://github.com/login/device/code +
   https://github.com/login/oauth/access_token -- the operator visits a verification URL, types in a
   short code, and this process polls GitHub until it's approved. This token doesn't expire on its
   own (only revoking it at github.com/settings/applications invalidates it) -- there is no refresh
   grant for it, unlike Codex's own refresh_token.
2. A short-lived (~25-30 minute) Copilot API token, exchanged from #1 via GET
   https://api.github.com/copilot_internal/v2/token -- THIS is the token actually sent to
   api.githubcopilot.com's own chat/completions endpoint (see agent/copilot_provider.py), and must be
   refreshed periodically (get_valid_copilot_token below), independently of #1.

The client id, both endpoints, and the required request headers below are the same public,
widely-documented values every third-party GitHub Copilot client uses for this exact flow
(github/copilot.vim, the Copilot Language Server, and the various community tools built against
them) -- not a secret, same "identifies the OAuth application, not a credential" status
agent/codex_oauth.py's own _CLIENT_ID already has. This is unofficial, reverse-engineered use of a
real GitHub Copilot subscription from outside an official IDE integration -- the same category of
thing agent/codex_oauth.py's "Sign in with ChatGPT" already does for a ChatGPT subscription, not a
new kind of risk for this codebase to take on.

No local callback listener is needed here, unlike agent/codex_oauth.py's 127.0.0.1:1455 HTTP server
-- GitHub's device flow has nothing to redirect back to at all, the operator just types a code into
github.com/login/device in their own time, and this module polls GitHub's own token endpoint from
the backend (rate-limited to the interval GitHub itself specifies) until that happens.

Token storage: data/copilot_oauth_tokens.json (gitignored -- holds a real, working GitHub OAuth
token for the signed-in account).
"""
from __future__ import annotations

import json
import os
import threading
import time

import httpx

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("LLM")

# Global app data (Documents/ASRA/data, see projects/paths.py), never a repo-relative data/ folder
# -- a real, working GitHub OAuth token has no business sitting inside the same directory as the
# git checkout.
COPILOT_TOKENS_PATH = resolve_global_app_dir() / "data" / "copilot_oauth_tokens.json"

# Public device-flow OAuth app id shared by every third-party GitHub Copilot client using this exact
# flow (github/copilot.vim and the community tools that interoperate with it) -- not a secret, it
# identifies the OAuth application, not a credential.
_CLIENT_ID = "01ab8ac9400c4e429b23"
_DEVICE_CODE_URL = "https://github.com/login/device/code"
_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
_COPILOT_TOKEN_URL = "https://api.github.com/copilot_internal/v2/token"
_SCOPE = "read:user"
# GitHub's own device/access-token endpoints require a real User-Agent (a UA-less request is
# rejected outright) -- this mirrors the same widely-used third-party Copilot client identity every
# other reverse-engineered header below (agent/copilot_provider.py's _REQUIRED_HEADERS) already uses.
_USER_AGENT = "GithubCopilot/1.155.0"
_GITHUB_HEADERS = {"Accept": "application/json", "User-Agent": _USER_AGENT}

# Additional wait GitHub asks for on a "slow_down" response, per its own device-flow docs -- added
# to that attempt's own interval, not a fixed re-guess.
_SLOW_DOWN_INCREMENT_SECONDS = 5.0

_pending_lock = threading.Lock()
# device_code -> {"interval": float, "expires_at": float, "last_poll_at": float,
#                 "status": "pending"|"success"|"error", "message": str}
_pending_logins: dict[str, dict] = {}


def _request_timeout() -> float:
    return float(os.getenv("LLM_REQUEST_TIMEOUT_SECONDS", "120"))


def _request_device_code() -> dict:
    response = httpx.post(
        _DEVICE_CODE_URL, data={"client_id": _CLIENT_ID, "scope": _SCOPE},
        headers=_GITHUB_HEADERS, timeout=_request_timeout(),
    )
    if response.status_code != 200:
        raise RuntimeError(f"GitHub device-code endpoint returned {response.status_code}: {response.text[:300]}")
    payload = response.json()
    required = ("device_code", "user_code", "verification_uri", "expires_in", "interval")
    if not all(payload.get(field) for field in required):
        raise RuntimeError(f"GitHub device-code response is missing expected fields: {list(payload.keys())}")
    return payload


def _poll_access_token(device_code: str) -> dict:
    response = httpx.post(
        _ACCESS_TOKEN_URL,
        data={"client_id": _CLIENT_ID, "device_code": device_code, "grant_type": "urn:ietf:params:oauth:grant-type:device_code"},
        headers=_GITHUB_HEADERS, timeout=_request_timeout(),
    )
    if response.status_code != 200:
        raise RuntimeError(f"GitHub access-token endpoint returned {response.status_code}: {response.text[:300]}")
    return response.json()


def _fetch_copilot_token(github_token: str) -> dict:
    """Exchanges the long-lived GitHub token for a short-lived Copilot API token. Raises
    RuntimeError with a message safe to show the operator on any failure -- the caller
    (get_valid_copilot_token) decides whether that means "sign in again" or "coast on the still-
    cached token a little longer"."""
    response = httpx.get(
        _COPILOT_TOKEN_URL, headers={**_GITHUB_HEADERS, "Authorization": f"token {github_token}"}, timeout=_request_timeout(),
    )
    if response.status_code != 200:
        raise RuntimeError(f"GitHub Copilot token endpoint returned {response.status_code}: {response.text[:300]}")
    payload = response.json()
    token = payload.get("token")
    expires_at = payload.get("expires_at")
    if not token or not isinstance(expires_at, (int, float)):
        raise RuntimeError(f"GitHub Copilot token endpoint response is missing expected fields: {list(payload.keys())}")
    return {"token": token, "expires": float(expires_at)}


def load_tokens() -> dict | None:
    if not COPILOT_TOKENS_PATH.exists():
        return None
    try:
        with COPILOT_TOKENS_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("copilot_oauth: token file unreadable (%s) -- treating as signed out", exc)
        return None
    return data if isinstance(data, dict) and data.get("github_token") else None


def save_tokens(tokens: dict) -> None:
    COPILOT_TOKENS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = COPILOT_TOKENS_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)
    os.replace(tmp_path, COPILOT_TOKENS_PATH)
    logger.debug("copilot_oauth: tokens saved")


def clear_tokens() -> None:
    if COPILOT_TOKENS_PATH.exists():
        COPILOT_TOKENS_PATH.unlink()
    logger.debug("copilot_oauth: tokens cleared (signed out)")


def is_signed_in() -> bool:
    return load_tokens() is not None


def get_valid_copilot_token(force_refresh: bool = False) -> str:
    """Returns a Copilot API token, transparently exchanging/refreshing it from the stored GitHub
    token first if it's within 60s of expiring (same margin agent/codex_oauth.py's own
    get_valid_access_token uses), or always when force_refresh=True -- used by
    agent/copilot_provider.py's own single 401-triggers-refresh-and-retry handling. Raises
    RuntimeError with a message safe to show the operator when there's no session at all, or the
    exchange itself fails with no still-valid cached token to fall back on.
    """
    stored = load_tokens()
    if stored is None:
        raise RuntimeError('Not signed in to GitHub Copilot. Go to Settings and click "Sign in with GitHub Copilot".')

    cached_token = stored.get("copilot_token")
    cached_expires = stored.get("copilot_expires")
    if not force_refresh and cached_token and isinstance(cached_expires, (int, float)) and time.time() < cached_expires - 60:
        return cached_token

    try:
        fetched = _fetch_copilot_token(stored["github_token"])
    except RuntimeError as exc:
        if not force_refresh and cached_token and isinstance(cached_expires, (int, float)) and time.time() < cached_expires:
            logger.debug("copilot_oauth: copilot token exchange failed but cached token is still valid, using it: %s", exc)
            return cached_token
        raise RuntimeError("GitHub Copilot session expired or unavailable -- please sign in again.") from exc

    stored["copilot_token"] = fetched["token"]
    stored["copilot_expires"] = fetched["expires"]
    save_tokens(stored)
    return fetched["token"]


def _prune_expired_attempts() -> None:
    now = time.time()
    with _pending_lock:
        expired = [dc for dc, attempt in _pending_logins.items() if attempt["status"] == "pending" and now > attempt["expires_at"]]
        for dc in expired:
            _pending_logins[dc]["status"] = "error"
            _pending_logins[dc]["message"] = "Sign-in attempt timed out."


def start_login_flow() -> dict:
    """Begins a "Sign in with GitHub Copilot" attempt: requests a fresh device code from GitHub and
    returns everything the frontend needs to show the operator (user_code + verification_uri) and
    start polling get_login_status(device_code). Raises RuntimeError (safe to show the operator) if
    GitHub's device-code endpoint itself is unreachable or rejects the request.
    """
    _prune_expired_attempts()
    payload = _request_device_code()
    device_code = payload["device_code"]
    with _pending_lock:
        _pending_logins[device_code] = {
            "interval": float(payload["interval"]),
            "expires_at": time.time() + float(payload["expires_in"]),
            # GitHub's own device-flow docs say to wait a full interval before the FIRST poll too,
            # not just between polls -- seeding this with "now" (not 0.0) means the very first
            # get_login_status() call right after start_login_flow() correctly reports "pending"
            # without contacting GitHub at all yet, instead of immediately polling.
            "last_poll_at": time.time(),
            "status": "pending",
            "message": "",
        }
    logger.debug("copilot_oauth: device login started user_code=%s", payload["user_code"])
    return {
        "device_code": device_code,
        "user_code": payload["user_code"],
        "verification_uri": payload["verification_uri"],
        "interval": payload["interval"],
        "expires_in": payload["expires_in"],
    }


def get_login_status(device_code: str) -> dict:
    """Polled by the Settings page while a device-flow sign-in is in progress. Actually contacts
    GitHub's own token endpoint at most once per that attempt's own interval (bumped by
    _SLOW_DOWN_INCREMENT_SECONDS on a "slow_down" response) -- the frontend is free to poll THIS
    function faster than that (same 2s cadence as agent/codex_oauth.py's own polling UX) without
    that translating into hammering GitHub's real endpoint.
    """
    with _pending_lock:
        attempt = _pending_logins.get(device_code)
    if attempt is None:
        return {"status": "error", "message": "Unknown or expired sign-in attempt."}
    if attempt["status"] != "pending":
        return {"status": attempt["status"], "message": attempt["message"]}
    if time.time() > attempt["expires_at"]:
        with _pending_lock:
            attempt["status"] = "error"
            attempt["message"] = "Sign-in attempt timed out."
        return {"status": "error", "message": attempt["message"]}
    if time.time() - attempt["last_poll_at"] < attempt["interval"]:
        return {"status": "pending", "message": ""}

    with _pending_lock:
        attempt["last_poll_at"] = time.time()
    try:
        payload = _poll_access_token(device_code)
    except RuntimeError as exc:
        with _pending_lock:
            attempt["status"] = "error"
            attempt["message"] = str(exc)
        return {"status": "error", "message": attempt["message"]}

    error = payload.get("error")
    if error == "authorization_pending":
        return {"status": "pending", "message": ""}
    if error == "slow_down":
        with _pending_lock:
            attempt["interval"] += _SLOW_DOWN_INCREMENT_SECONDS
        return {"status": "pending", "message": ""}
    if error in ("expired_token", "access_denied"):
        message = "Sign-in was denied." if error == "access_denied" else "Sign-in code expired -- try again."
        with _pending_lock:
            attempt["status"] = "error"
            attempt["message"] = message
        return {"status": "error", "message": message}
    if error:
        message = f"GitHub returned an error: {error}"
        with _pending_lock:
            attempt["status"] = "error"
            attempt["message"] = message
        return {"status": "error", "message": message}

    access_token = payload.get("access_token")
    if not access_token:
        message = "GitHub did not return an access token."
        with _pending_lock:
            attempt["status"] = "error"
            attempt["message"] = message
        return {"status": "error", "message": message}

    save_tokens({"github_token": access_token})
    message = "Signed in to GitHub Copilot."
    with _pending_lock:
        attempt["status"] = "success"
        attempt["message"] = message
    logger.debug("copilot_oauth: device login succeeded")
    return {"status": "success", "message": message}
