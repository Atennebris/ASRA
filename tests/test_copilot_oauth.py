"""agent/copilot_oauth.py -- token file storage, the lazy-refresh policy in
get_valid_copilot_token (same shape as agent/codex_oauth.py's own get_valid_access_token, see that
module's own test file for the twin cases), and the device-flow polling state machine in
start_login_flow/get_login_status (authorization_pending/slow_down/expired_token/access_denied/
success), with every real network call mocked (no real socket, unlike codex_oauth's own callback-
listener tests -- GitHub's device flow has nothing to listen for, this module only ever polls out).
"""
import time

import pytest

import agent.copilot_oauth as copilot_oauth


def test_token_roundtrip_save_load_clear():
    assert copilot_oauth.load_tokens() is None
    assert not copilot_oauth.is_signed_in()

    tokens = {"github_token": "gho_abc"}
    copilot_oauth.save_tokens(tokens)
    assert copilot_oauth.is_signed_in()
    assert copilot_oauth.load_tokens() == tokens

    copilot_oauth.clear_tokens()
    assert copilot_oauth.load_tokens() is None


def test_get_valid_copilot_token_raises_when_signed_out():
    with pytest.raises(RuntimeError, match="Not signed in"):
        copilot_oauth.get_valid_copilot_token()


def test_get_valid_copilot_token_returns_cached_token_when_not_near_expiry(monkeypatch):
    copilot_oauth.save_tokens({"github_token": "gho_1", "copilot_token": "tid=old", "copilot_expires": time.time() + 3600})

    def _boom(github_token):
        raise AssertionError("should not re-exchange a token that isn't near expiry")
    monkeypatch.setattr(copilot_oauth, "_fetch_copilot_token", _boom)

    assert copilot_oauth.get_valid_copilot_token() == "tid=old"


def test_get_valid_copilot_token_refreshes_when_within_60s_of_expiry(monkeypatch):
    copilot_oauth.save_tokens({"github_token": "gho_1", "copilot_token": "tid=old", "copilot_expires": time.time() + 10})
    monkeypatch.setattr(copilot_oauth, "_fetch_copilot_token", lambda github_token: {"token": "tid=new", "expires": time.time() + 1800})

    result = copilot_oauth.get_valid_copilot_token()
    assert result == "tid=new"
    assert copilot_oauth.load_tokens()["copilot_token"] == "tid=new"  # refreshed token actually persisted


def test_get_valid_copilot_token_exchanges_when_never_fetched_before(monkeypatch):
    copilot_oauth.save_tokens({"github_token": "gho_1"})
    monkeypatch.setattr(copilot_oauth, "_fetch_copilot_token", lambda github_token: {"token": "tid=first", "expires": time.time() + 1800})

    assert copilot_oauth.get_valid_copilot_token() == "tid=first"


def test_get_valid_copilot_token_force_refresh_ignores_a_still_valid_cached_token(monkeypatch):
    copilot_oauth.save_tokens({"github_token": "gho_1", "copilot_token": "tid=old", "copilot_expires": time.time() + 3600})
    calls = []
    def _fetch(github_token):
        calls.append(github_token)
        return {"token": "tid=forced-new", "expires": time.time() + 1800}
    monkeypatch.setattr(copilot_oauth, "_fetch_copilot_token", _fetch)

    result = copilot_oauth.get_valid_copilot_token(force_refresh=True)
    assert calls == ["gho_1"]
    assert result == "tid=forced-new"


def test_get_valid_copilot_token_force_refresh_does_not_fall_back_to_the_rejected_token(monkeypatch):
    """Mirrors agent/codex_oauth.py's own identical guard: a force_refresh means the caller already
    knows the current token was just rejected (a 401) -- silently returning that same token again
    on a failed re-exchange would just reproduce the same failure with no visible progress."""
    copilot_oauth.save_tokens({"github_token": "gho_1", "copilot_token": "tid=old", "copilot_expires": time.time() + 3600})
    monkeypatch.setattr(copilot_oauth, "_fetch_copilot_token", lambda github_token: (_ for _ in ()).throw(RuntimeError("exchange failed")))

    with pytest.raises(RuntimeError, match="please sign in again"):
        copilot_oauth.get_valid_copilot_token(force_refresh=True)


def test_get_valid_copilot_token_lazy_path_falls_back_to_cached_token_if_exchange_fails_but_not_yet_expired(monkeypatch):
    copilot_oauth.save_tokens({"github_token": "gho_1", "copilot_token": "tid=old", "copilot_expires": time.time() + 10})
    monkeypatch.setattr(copilot_oauth, "_fetch_copilot_token", lambda github_token: (_ for _ in ()).throw(RuntimeError("network blip")))

    assert copilot_oauth.get_valid_copilot_token() == "tid=old"


def test_get_login_status_for_unknown_device_code_is_an_error():
    assert copilot_oauth.get_login_status("never-started") == {"status": "error", "message": "Unknown or expired sign-in attempt."}


def _fake_device_code_payload(**overrides):
    payload = {"device_code": "dc_1", "user_code": "ABCD-1234", "verification_uri": "https://github.com/login/device", "expires_in": 900, "interval": 5}
    payload.update(overrides)
    return payload


def test_start_login_flow_returns_what_the_frontend_needs(monkeypatch):
    monkeypatch.setattr(copilot_oauth, "_request_device_code", lambda: _fake_device_code_payload())

    attempt = copilot_oauth.start_login_flow()
    assert attempt == {
        "device_code": "dc_1", "user_code": "ABCD-1234",
        "verification_uri": "https://github.com/login/device", "interval": 5, "expires_in": 900,
    }
    assert copilot_oauth.get_login_status("dc_1") == {"status": "pending", "message": ""}


def test_start_login_flow_propagates_a_device_code_request_failure(monkeypatch):
    monkeypatch.setattr(copilot_oauth, "_request_device_code", lambda: (_ for _ in ()).throw(RuntimeError("GitHub is down")))
    with pytest.raises(RuntimeError, match="GitHub is down"):
        copilot_oauth.start_login_flow()


def test_get_login_status_does_not_repoll_github_before_the_interval_elapses(monkeypatch):
    monkeypatch.setattr(copilot_oauth, "_request_device_code", lambda: _fake_device_code_payload(interval=5))
    copilot_oauth.start_login_flow()

    calls = []
    def _poll(device_code):
        calls.append(device_code)
        return {"error": "authorization_pending"}
    monkeypatch.setattr(copilot_oauth, "_poll_access_token", _poll)

    # A call made immediately after start_login_flow must NOT poll GitHub yet -- start_login_flow
    # seeds last_poll_at at "now", so the operator's own device code's interval hasn't elapsed.
    assert copilot_oauth.get_login_status("dc_1") == {"status": "pending", "message": ""}
    assert len(calls) == 0

    # Once the interval has genuinely elapsed since the last real poll, the next call does poll...
    with copilot_oauth._pending_lock:
        copilot_oauth._pending_logins["dc_1"]["last_poll_at"] -= 10
    assert copilot_oauth.get_login_status("dc_1") == {"status": "pending", "message": ""}
    assert len(calls) == 1
    # ...but calling again immediately after that (well within the 5s interval) must not re-poll.
    assert copilot_oauth.get_login_status("dc_1") == {"status": "pending", "message": ""}
    assert len(calls) == 1


def test_get_login_status_slow_down_increases_the_interval_without_erroring(monkeypatch):
    monkeypatch.setattr(copilot_oauth, "_request_device_code", lambda: _fake_device_code_payload(interval=5))
    copilot_oauth.start_login_flow()
    monkeypatch.setattr(copilot_oauth, "_poll_access_token", lambda device_code: {"error": "slow_down"})
    with copilot_oauth._pending_lock:
        copilot_oauth._pending_logins["dc_1"]["last_poll_at"] -= 10  # force the poll to actually be due

    status = copilot_oauth.get_login_status("dc_1")
    assert status == {"status": "pending", "message": ""}
    with copilot_oauth._pending_lock:
        assert copilot_oauth._pending_logins["dc_1"]["interval"] == 10.0  # 5 + _SLOW_DOWN_INCREMENT_SECONDS


@pytest.mark.parametrize("error,expected_message", [
    ("expired_token", "Sign-in code expired -- try again."),
    ("access_denied", "Sign-in was denied."),
])
def test_get_login_status_terminal_errors(monkeypatch, error, expected_message):
    monkeypatch.setattr(copilot_oauth, "_request_device_code", lambda: _fake_device_code_payload(interval=0))
    copilot_oauth.start_login_flow()
    monkeypatch.setattr(copilot_oauth, "_poll_access_token", lambda device_code: {"error": error})

    assert copilot_oauth.get_login_status("dc_1") == {"status": "error", "message": expected_message}
    # A terminal status must stick -- a further poll must not re-contact GitHub at all.
    assert copilot_oauth.get_login_status("dc_1") == {"status": "error", "message": expected_message}


def test_get_login_status_success_saves_the_github_token(monkeypatch):
    monkeypatch.setattr(copilot_oauth, "_request_device_code", lambda: _fake_device_code_payload(interval=0))
    copilot_oauth.start_login_flow()
    monkeypatch.setattr(copilot_oauth, "_poll_access_token", lambda device_code: {"access_token": "gho_real", "token_type": "bearer", "scope": "read:user"})

    status = copilot_oauth.get_login_status("dc_1")
    assert status["status"] == "success"
    assert copilot_oauth.load_tokens() == {"github_token": "gho_real"}


def test_get_login_status_expires_a_stale_pending_attempt_without_polling_github(monkeypatch):
    monkeypatch.setattr(copilot_oauth, "_request_device_code", lambda: _fake_device_code_payload(expires_in=-1, interval=0))
    copilot_oauth.start_login_flow()

    def _boom(device_code):
        raise AssertionError("an already-expired attempt must never be polled")
    monkeypatch.setattr(copilot_oauth, "_poll_access_token", _boom)

    assert copilot_oauth.get_login_status("dc_1") == {"status": "error", "message": "Sign-in attempt timed out."}
