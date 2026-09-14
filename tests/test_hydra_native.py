"""hydra_start / web_login_bruteforce_start / background_job_check / the real empirical preflight
check (agent/tools/native.py). agent.tools.native.start_background_job is mocked throughout (no
real subprocess/network needed to test the gluing logic) except where noted; the preflight and the
underlying builders/background_jobs mechanics are each covered by their own real, live-verified
test files (test_hydra_builder.py, test_web_login_bruteforce_builder.py, test_background_jobs.py).
"""
import httpx

from agent.tools import native


def _session_ctx(session_id="usr_hydra_native_test"):
    return {"_session_id": session_id, "_session": {"session_id": session_id, "background_jobs": {}}}


# --- session-context requirement, shared by all three tool functions ---


def test_hydra_start_requires_session_context():
    result = native.hydra_start({"target": "10.0.0.1", "protocol": "ssh"})
    assert result["status"] == "error"


def test_web_login_bruteforce_start_requires_session_context():
    result = native.web_login_bruteforce_start({"target": "http://example.com", "login_path": "/login", "failure_string": "bad"})
    assert result["status"] == "error"


def test_background_job_check_requires_session_context():
    result = native.background_job_check({"job_id": "abc"})
    assert result["status"] == "error"


def test_background_job_check_requires_job_id():
    result = native.background_job_check(_session_ctx())
    assert result["status"] == "error"
    assert "job_id" in result["error"]


# --- hydra_start: delegates to background_jobs.start_background_job, with a real preflight gate
# for web-form protocols only ---


def test_hydra_start_delegates_to_start_background_job_for_a_network_protocol(monkeypatch):
    captured = {}

    def fake_start(session_id, session, tool, setup, max_concurrent, timeout_seconds, extra_metadata=None):
        captured["tool"] = tool
        captured["max_concurrent"] = max_concurrent
        captured["timeout_seconds"] = timeout_seconds
        captured["extra_metadata"] = extra_metadata
        return {"status": "ok", "job_id": "fakejob1"}

    monkeypatch.setattr(native, "start_background_job", fake_start)
    monkeypatch.setenv("HYDRA_MAX_CONCURRENT_JOBS", "3")
    monkeypatch.setenv("HYDRA_TIMEOUT_SECONDS", "123")

    params = {**_session_ctx(), "target": "10.0.0.1", "protocol": "ssh"}
    result = native.hydra_start(params)

    assert result == {"status": "ok", "job_id": "fakejob1"}
    assert captured["tool"] == "hydra"
    assert captured["max_concurrent"] == 3
    assert captured["timeout_seconds"] == 123
    # protocol is stashed alongside target -- agent/core.py's _auto_record_cracked_credentials_finding
    # needs it to tell Hydra's unreliable rdp module apart from its other, reliable protocol modules.
    assert captured["extra_metadata"] == {"target": "10.0.0.1", "protocol": "ssh"}


def test_hydra_start_never_reaches_background_jobs_when_preflight_detects_a_lockout(monkeypatch):
    calls = []
    monkeypatch.setattr(native, "start_background_job", lambda *a, **k: calls.append(1))
    monkeypatch.setattr(native, "_hydra_http_form_preflight", lambda params: "simulated lockout detected")

    params = {**_session_ctx(), "target": "http://example.com", "protocol": "http-post-form", "login_path": "/login", "failure_string": "bad"}
    result = native.hydra_start(params)

    assert result == {"status": "skipped", "reason": "simulated lockout detected"}
    assert calls == []  # start_background_job never called


def test_hydra_start_skips_the_preflight_entirely_for_network_protocols(monkeypatch):
    preflight_calls = []
    monkeypatch.setattr(native, "_hydra_http_form_preflight", lambda params: preflight_calls.append(1))
    monkeypatch.setattr(native, "start_background_job", lambda *a, **k: {"status": "ok", "job_id": "j1"})

    native.hydra_start({**_session_ctx(), "target": "10.0.0.1", "protocol": "ssh"})

    assert preflight_calls == []  # preflight is only for http-post-form/http-get-form


def test_hydra_start_reports_a_build_command_error_cleanly(monkeypatch, tmp_path):
    """build_hydra_command validation errors (e.g. an unknown protocol) must come back as a
    normal {"status": "error"} result, not propagate as an uncaught exception."""
    def fake_start(session_id, session, tool, setup, max_concurrent, timeout_seconds, extra_metadata=None):
        return setup("jobid", tmp_path)  # forces the real setup closure to run and raise

    monkeypatch.setattr(native, "start_background_job", fake_start)

    params = {**_session_ctx(), "target": "10.0.0.1", "protocol": "made-up-protocol"}
    result = native.hydra_start(params)
    assert result["status"] == "error"


# --- web_login_bruteforce_start: ALWAYS runs the preflight (no protocol branch to skip it) ---


def test_web_login_bruteforce_start_always_runs_the_preflight(monkeypatch):
    monkeypatch.setattr(native, "_hydra_http_form_preflight", lambda params: "simulated lockout")
    calls = []
    monkeypatch.setattr(native, "start_background_job", lambda *a, **k: calls.append(1))

    result = native.web_login_bruteforce_start({**_session_ctx(), "target": "http://example.com", "login_path": "/login", "failure_string": "bad"})

    assert result == {"status": "skipped", "reason": "simulated lockout"}
    assert calls == []


def test_web_login_bruteforce_start_delegates_when_preflight_is_clean(monkeypatch):
    monkeypatch.setattr(native, "_hydra_http_form_preflight", lambda params: None)
    captured = {}

    def fake_start(session_id, session, tool, setup, max_concurrent, timeout_seconds, extra_metadata=None):
        captured["tool"] = tool
        captured["extra_metadata"] = extra_metadata
        return {"status": "ok", "job_id": "fakejob2"}

    monkeypatch.setattr(native, "start_background_job", fake_start)

    result = native.web_login_bruteforce_start({**_session_ctx(), "target": "http://example.com", "login_path": "/login", "failure_string": "bad"})

    assert result == {"status": "ok", "job_id": "fakejob2"}
    assert captured["tool"] == "web_login_bruteforce"
    assert captured["extra_metadata"] == {"target": "http://example.com"}


# --- background_job_check: thin delegation to background_jobs.check_background_job ---


def test_background_job_check_delegates_correctly(monkeypatch):
    captured = {}

    def fake_check(session_id, session, job_id):
        captured.update(session_id=session_id, job_id=job_id)
        return {"status": "ok", "result": {"credentials": []}}

    monkeypatch.setattr(native, "check_background_job", fake_check)

    ctx = _session_ctx("usr_check_deleg_test")
    result = native.background_job_check({**ctx, "job_id": "job123"})

    assert result == {"status": "ok", "result": {"credentials": []}}
    assert captured == {"session_id": "usr_check_deleg_test", "job_id": "job123"}


# --- _hydra_http_form_preflight: the real empirical lockout/CAPTCHA/rate-limit check ---


class _FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _FakeClient:
    def __init__(self, responses):
        self._responses = list(responses)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, data=None):
        return self._responses.pop(0)


def test_preflight_returns_none_when_login_path_missing():
    assert native._hydra_http_form_preflight({"target": "http://example.com"}) is None


def test_preflight_detects_a_real_lockout_keyword(monkeypatch):
    responses = [_FakeResponse(200, "Invalid credentials"), _FakeResponse(200, "Invalid credentials"), _FakeResponse(200, "Too many attempts, account locked")]
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _FakeClient(responses))

    reason = native._hydra_http_form_preflight({"target": "http://example.com", "login_path": "/login"})
    assert reason is not None
    assert "lockout" in reason or "CAPTCHA" in reason or "rate-limit" in reason


def test_preflight_detects_escalating_status_codes(monkeypatch):
    responses = [_FakeResponse(200, "nope"), _FakeResponse(200, "nope"), _FakeResponse(429, "slow down")]
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _FakeClient(responses))

    reason = native._hydra_http_form_preflight({"target": "http://example.com", "login_path": "/login"})
    assert reason is not None
    assert "429" in reason


def test_preflight_returns_none_for_a_clean_undefended_form(monkeypatch):
    responses = [_FakeResponse(200, "Invalid credentials") for _ in range(3)]
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _FakeClient(responses))

    reason = native._hydra_http_form_preflight({"target": "http://example.com", "login_path": "/login"})
    assert reason is None


def test_preflight_returns_none_when_the_target_is_unreachable(monkeypatch):
    class _RaisingClient:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, data=None):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: _RaisingClient())

    # Can't reach it at all -- not a defense signal, the real run's own error handling reports this.
    reason = native._hydra_http_form_preflight({"target": "http://example.com", "login_path": "/login"})
    assert reason is None
