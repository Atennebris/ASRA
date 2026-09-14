"""agent/codex_oauth.py -- PKCE mechanics, JWT account-id extraction, token file storage, the
lazy-refresh policy in get_valid_access_token, and a real end-to-end run of the local callback
listener (the exact class of bug this project's own Known bug patterns warn about: a server that
looks correct until actually driven through a real socket -- see the .shutdown()-hangs-forever bug
caught and fixed while building this).
"""
import base64
import json
import time

import httpx
import pytest

import agent.codex_oauth as codex_oauth


def _fake_jwt(account_id: str | None) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    payload_obj = {"https://api.openai.com/auth": {"chatgpt_account_id": account_id}} if account_id else {}
    payload = base64.urlsafe_b64encode(json.dumps(payload_obj).encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.signature"


def test_generate_pkce_produces_a_verifier_and_a_derived_challenge():
    verifier, challenge = codex_oauth.generate_pkce()
    assert verifier and challenge
    assert verifier != challenge
    # Both must be pure base64url (no padding, no +/ characters) -- OpenAI's own authorize
    # endpoint rejects a challenge containing standard-base64 characters.
    for value in (verifier, challenge):
        assert "+" not in value and "/" not in value and "=" not in value


def test_extract_account_id_reads_the_real_claim_path():
    token = _fake_jwt("acct_12345")
    assert codex_oauth.extract_account_id(token) == "acct_12345"


def test_extract_account_id_returns_none_for_a_token_with_no_claim():
    assert codex_oauth.extract_account_id(_fake_jwt(None)) is None
    assert codex_oauth.extract_account_id("not-a-jwt") is None


def test_build_authorize_url_embeds_state_and_challenge():
    url = codex_oauth.build_authorize_url("state123", "challenge456")
    assert "state=state123" in url
    assert "challenge456" in url
    assert url.startswith("https://auth.openai.com/oauth/authorize?")


def test_token_roundtrip_save_load_clear():
    assert codex_oauth.load_tokens() is None
    assert not codex_oauth.is_signed_in()

    tokens = {"access": "a", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"}
    codex_oauth.save_tokens(tokens)
    assert codex_oauth.is_signed_in()
    assert codex_oauth.load_tokens() == tokens

    codex_oauth.clear_tokens()
    assert codex_oauth.load_tokens() is None


def test_get_valid_access_token_raises_when_signed_out():
    with pytest.raises(RuntimeError, match="Not signed in"):
        codex_oauth.get_valid_access_token()


def test_get_valid_access_token_returns_cached_token_when_not_near_expiry(monkeypatch):
    codex_oauth.save_tokens({"access": "a", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"})

    def _boom(refresh_token):
        raise AssertionError("should not refresh a token that isn't near expiry")
    monkeypatch.setattr(codex_oauth, "refresh_access_token", _boom)

    result = codex_oauth.get_valid_access_token()
    assert result == {"access": "a", "account_id": "acct_1"}


def test_get_valid_access_token_refreshes_when_within_60s_of_expiry(monkeypatch):
    codex_oauth.save_tokens({"access": "old", "refresh": "r", "expires": time.time() + 10, "account_id": "acct_1"})
    refreshed = {"access": "new", "refresh": "r2", "expires": time.time() + 3600, "account_id": "acct_1"}
    monkeypatch.setattr(codex_oauth, "refresh_access_token", lambda refresh_token: refreshed)

    result = codex_oauth.get_valid_access_token()
    assert result == {"access": "new", "account_id": "acct_1"}
    assert codex_oauth.load_tokens()["access"] == "new"  # refreshed token actually persisted


def test_get_valid_access_token_force_refresh_ignores_a_still_valid_stored_token(monkeypatch):
    codex_oauth.save_tokens({"access": "old", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"})
    calls = []
    def _refresh(refresh_token):
        calls.append(refresh_token)
        return {"access": "forced-new", "refresh": "r2", "expires": time.time() + 3600, "account_id": "acct_1"}
    monkeypatch.setattr(codex_oauth, "refresh_access_token", _refresh)

    result = codex_oauth.get_valid_access_token(force_refresh=True)
    assert calls == ["r"]
    assert result["access"] == "forced-new"


def test_get_valid_access_token_force_refresh_does_not_fall_back_to_the_rejected_token(monkeypatch):
    """The one real bug this test guards: a force_refresh means the caller already knows the
    current token was just rejected by the server (a 401) -- silently returning that same token
    again on a failed refresh would just reproduce the same failure with no visible progress."""
    codex_oauth.save_tokens({"access": "old", "refresh": "r", "expires": time.time() + 3600, "account_id": "acct_1"})
    monkeypatch.setattr(codex_oauth, "refresh_access_token", lambda refresh_token: (_ for _ in ()).throw(RuntimeError("refresh failed")))

    with pytest.raises(RuntimeError, match="please sign in again"):
        codex_oauth.get_valid_access_token(force_refresh=True)


def test_get_valid_access_token_lazy_path_falls_back_to_stored_token_if_refresh_fails_but_not_yet_expired(monkeypatch):
    codex_oauth.save_tokens({"access": "old", "refresh": "r", "expires": time.time() + 10, "account_id": "acct_1"})
    monkeypatch.setattr(codex_oauth, "refresh_access_token", lambda refresh_token: (_ for _ in ()).throw(RuntimeError("network blip")))

    result = codex_oauth.get_valid_access_token()
    assert result == {"access": "old", "account_id": "acct_1"}


def test_get_login_status_for_unknown_state_is_an_error():
    assert codex_oauth.get_login_status("never-started") == {"status": "error", "message": "Unknown or expired sign-in attempt."}


def test_start_login_flow_and_real_callback_round_trip(monkeypatch):
    """Drives the ACTUAL local HTTP listener (127.0.0.1:1455) through a real socket -- this is the
    exact class of bug (server code that looks right until actually executed) that caught a real
    server.shutdown()-hangs-forever mistake while building this feature. Monkeypatches
    exchange_code so no real network call to OpenAI happens; everything else (PKCE storage, the
    listener thread, request routing, state matching, response body) is real.

    The watchdog loop re-checks "any attempt still pending" after every handled request and exits
    immediately once none remain (see _run_server_with_watchdog's own docstring) -- so this test's
    one real callback request should make the whole listener thread wind itself down well within
    a couple seconds, not sit bound to the port for its full timeout.
    """
    monkeypatch.setattr(codex_oauth, "exchange_code", lambda code, verifier: {
        "access": "tok", "refresh": "ref", "expires": time.time() + 3600, "account_id": "acct_real",
    })

    attempt = codex_oauth.start_login_flow()
    state = attempt["state"]
    assert attempt["auth_url"].startswith("https://auth.openai.com/oauth/authorize?")
    assert codex_oauth.get_login_status(state) == {"status": "pending", "message": ""}

    response = httpx.get(f"http://127.0.0.1:{codex_oauth._CALLBACK_PORT}/auth/callback", params={"code": "abc123", "state": state}, timeout=5.0)
    assert response.status_code == 200
    assert "Signed in" in response.text

    status = codex_oauth.get_login_status(state)
    assert status["status"] == "success"
    assert codex_oauth.load_tokens()["account_id"] == "acct_real"

    deadline = time.time() + 5
    while codex_oauth._active_server is not None and time.time() < deadline:
        time.sleep(0.1)
    assert codex_oauth._active_server is None, "listener thread should self-clean once every pending attempt resolved"


def test_callback_with_wrong_state_is_rejected_without_signing_in(monkeypatch):
    exchange_calls = []
    def _exchange(code, verifier):
        exchange_calls.append((code, verifier))
        return {"access": "tok2", "refresh": "ref2", "expires": time.time() + 3600, "account_id": "acct_2"}
    monkeypatch.setattr(codex_oauth, "exchange_code", _exchange)

    attempt = codex_oauth.start_login_flow()
    real_state = attempt["state"]

    response = httpx.get(f"http://127.0.0.1:{codex_oauth._CALLBACK_PORT}/auth/callback", params={"code": "abc123", "state": "not-the-real-state"}, timeout=5.0)
    assert response.status_code == 400
    assert exchange_calls == []  # the unmatched state must never even attempt a real code exchange
    assert codex_oauth.load_tokens() is None

    # Clean up the still-pending real attempt so the listener thread doesn't linger for this
    # test's own duration -- complete it (with the correct state this time) rather than leaving a
    # background thread bound to the port for the rest of the test run. Waited out (not just
    # fired) so the NEXT test's own start_login_flow() doesn't race this thread's own socket
    # teardown and hit "Address already in use".
    httpx.get(f"http://127.0.0.1:{codex_oauth._CALLBACK_PORT}/auth/callback", params={"code": "abc123", "state": real_state}, timeout=5.0)
    deadline = time.time() + 5
    while codex_oauth._active_server is not None and time.time() < deadline:
        time.sleep(0.1)
    assert codex_oauth._active_server is None
