"""Settings "Test" button (settings.html, next to the Provider/Model dropdowns) -- a real, minimal
completion call against whatever's picked in the form, run as a tracked background thread
(agent/tools/llm_test_job.py) rather than a blocking request: POST /api/settings/test-llm/start
kicks it off, GET /api/settings/test-llm/status polls progress, POST /api/settings/test-llm/cancel
aborts it mid-retry. Covers the real, confirmed incident this route's own error path used to have: a
genuine provider failure (opencode-zen's free-tier 429, "FreeUsageLimitError") rendered as a raw
`str(exc)` dict repr ("Error code: 429 - {'type': 'error', ...}") with nothing telling the operator
this is an external, provider-side condition, not an ASRA bug -- fixed by reusing agent/chat.py's own
_format_llm_error. Also covers the real, confirmed complaint that motivated the async rewrite itself:
the retry-with-backoff schedule can legitimately take up to ~60s of silent waiting, during which the
old blocking version just said "Testing..." with no attempt count and no way to cancel.
"""
import time
from types import SimpleNamespace

import openai
from fastapi.testclient import TestClient

import main
from agent.llm_client import LLMResponse
from agent.tools import llm_test_job

_FORM_HEADERS = {"Content-Type": "application/x-www-form-urlencoded"}


class _FakeLLM:
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, response=None, exc=None, on_complete=None):
        self._response = response
        self._exc = exc
        self._on_complete = on_complete

    def complete(self, messages, tools=None, stop_check=None):
        if self._on_complete is not None:
            return self._on_complete(stop_check)
        if self._exc is not None:
            raise self._exc
        return self._response


def _api_status_error(status_code: int, message: str = "error") -> openai.APIStatusError:
    request = SimpleNamespace(method="POST", url="https://example.test/v1/chat/completions")
    response = SimpleNamespace(status_code=status_code, headers={}, request=request)
    return openai.APIStatusError(message, response=response, body=None)


_DEFAULT_KEY = "llm-test-status"  # main.py's test-llm routes default target_id to this


def _wait_until_done(timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not llm_test_job.test_status(_DEFAULT_KEY)["running"]:
            return
        time.sleep(0.01)
    raise AssertionError(f"test-llm job still running after {timeout}s: {llm_test_job.test_status(_DEFAULT_KEY)}")


def test_test_llm_start_rejects_an_unknown_provider():
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-llm/start", data={"provider": "not-a-real-provider", "model": "x"}, headers=_FORM_HEADERS)
    assert resp.status_code == 200
    assert "Pick a provider and model first" in resp.text


def test_test_llm_start_rejects_a_missing_model():
    client = TestClient(main.app)
    resp = client.post("/api/settings/test-llm/start", data={"provider": "opencode-zen", "model": ""}, headers=_FORM_HEADERS)
    assert "Pick a provider and model first" in resp.text


def test_test_llm_reports_success_with_elapsed_time(monkeypatch):
    monkeypatch.setattr(llm_test_job, "get_provider", lambda provider, model: _FakeLLM(response=LLMResponse(content="pong", tool_calls=[])))
    client = TestClient(main.app)
    client.post("/api/settings/test-llm/start", data={"provider": "opencode-zen", "model": "deepseek-v4-flash-free"}, headers=_FORM_HEADERS)
    _wait_until_done()
    resp = client.get("/api/settings/test-llm/status")
    assert "Model is available" in resp.text
    assert "ms)" in resp.text


def test_test_llm_reports_an_empty_response_distinctly(monkeypatch):
    empty_response = LLMResponse(content=None, tool_calls=[], finish_reason="content_filter")
    monkeypatch.setattr(llm_test_job, "get_provider", lambda provider, model: _FakeLLM(response=empty_response))
    client = TestClient(main.app)
    client.post("/api/settings/test-llm/start", data={"provider": "opencode-zen", "model": "deepseek-v4-flash-free"}, headers=_FORM_HEADERS)
    _wait_until_done()
    resp = client.get("/api/settings/test-llm/status")
    assert "empty response" in resp.text
    assert "content_filter" in resp.text


def test_test_llm_formats_a_real_rate_limit_error_instead_of_a_raw_dict_repr(monkeypatch):
    """The exact real incident this fixes: a genuine opencode-zen free-tier 429
    (openai.APIStatusError, FreeUsageLimitError body) used to render as
    "Error code: 429 - {'type': 'error', 'error': {'type': 'FreeUsageLimitError', ...}}" -- an
    unreadable raw dict repr the operator can't act on. Must now go through _format_llm_error and
    say this is a rate limit, name the provider, and say it's not an ASRA bug."""
    exc = _api_status_error(429, "Error from provider (Console): Rate limit exceeded. Please try again later.")
    monkeypatch.setattr(llm_test_job, "get_provider", lambda provider, model: _FakeLLM(exc=exc))
    client = TestClient(main.app)

    client.post("/api/settings/test-llm/start", data={"provider": "opencode-zen", "model": "deepseek-v4-flash-free"}, headers=_FORM_HEADERS)
    _wait_until_done()
    resp = client.get("/api/settings/test-llm/status")

    assert "opencode-zen/deepseek-v4-flash-free" in resp.text
    assert "rate limit" in resp.text.lower()
    assert "not an ASRA bug" in resp.text
    assert "{'type': 'error'" not in resp.text  # the raw dict repr must never reach the operator


def test_test_llm_formats_an_auth_failure(monkeypatch):
    monkeypatch.setattr(llm_test_job, "get_provider", lambda provider, model: _FakeLLM(exc=_api_status_error(401)))
    client = TestClient(main.app)
    client.post("/api/settings/test-llm/start", data={"provider": "openai", "model": "gpt-4o"}, headers=_FORM_HEADERS)
    _wait_until_done()
    resp = client.get("/api/settings/test-llm/status")
    assert "authentication failed" in resp.text.lower()


def test_test_llm_formats_a_connection_failure(monkeypatch):
    exc = openai.APIConnectionError(request=SimpleNamespace(method="POST", url="https://example.test/v1/chat/completions"))
    monkeypatch.setattr(llm_test_job, "get_provider", lambda provider, model: _FakeLLM(exc=exc))
    client = TestClient(main.app)
    client.post("/api/settings/test-llm/start", data={"provider": "openai", "model": "gpt-4o"}, headers=_FORM_HEADERS)
    _wait_until_done()
    resp = client.get("/api/settings/test-llm/status")
    assert "not an ASRA bug" in resp.text


def test_test_llm_cancel_stops_a_running_test(monkeypatch):
    """Real, confirmed gap this fixes: no way to abort a hung Test click short of reloading the
    page. Reuses the same stop_check/LLMCallAborted mechanism a session's own Stop button already
    relies on (agent/llm_client.py) -- proven here by a fake complete() that blocks until its own
    stop_check flips true, exactly like a real backoff wait would."""
    def blocking_complete(stop_check):
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if stop_check is not None and stop_check():
                from agent.llm_client import LLMCallAborted
                raise LLMCallAborted("stop requested during backoff wait")
            time.sleep(0.01)
        raise AssertionError("cancel was never observed by the fake completion")

    monkeypatch.setattr(llm_test_job, "get_provider", lambda provider, model: _FakeLLM(on_complete=blocking_complete))
    client = TestClient(main.app)
    client.post("/api/settings/test-llm/start", data={"provider": "opencode-zen", "model": "deepseek-v4-flash-free"}, headers=_FORM_HEADERS)

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and not llm_test_job.test_status(_DEFAULT_KEY)["running"]:
        time.sleep(0.005)  # let the background thread actually start before cancelling it
    assert llm_test_job.test_status(_DEFAULT_KEY)["running"]

    client.post("/api/settings/test-llm/cancel")
    _wait_until_done()
    resp = client.get("/api/settings/test-llm/status")
    assert "Cancelled" in resp.text
    assert llm_test_job.test_status(_DEFAULT_KEY)["state"] == "cancelled"


def test_two_target_ids_run_fully_concurrently_not_one_at_a_time(monkeypatch):
    """Real, confirmed regression this fixes: once more than one Test button existed on a page
    (Reserve providers chain rows, Secondary verification, a subagent's own picker), the old
    single-slot design meant starting a SECOND test while a first was still running didn't start
    anything new -- it just returned/rendered the first one's own still-in-flight status under the
    second button's label. agent/tools/llm_test_job.py is now keyed by target_id specifically so
    two different widgets' tests run as two real, independent background threads at once."""
    release_first = __import__("threading").Event()

    def blocking_complete(stop_check):
        release_first.wait(timeout=5.0)
        return LLMResponse(content="pong", tool_calls=[])

    monkeypatch.setattr(llm_test_job, "get_provider", lambda provider, model: _FakeLLM(on_complete=blocking_complete))
    client = TestClient(main.app)

    client.post("/api/settings/test-llm/start", data={"provider": "opencode-zen", "model": "deepseek-v4-flash-free", "target_id": "row-a"}, headers=_FORM_HEADERS)
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and not llm_test_job.test_status("row-a")["running"]:
        time.sleep(0.005)
    assert llm_test_job.test_status("row-a")["running"], "first job (row-a) never started"

    # A second target_id's own start must launch its OWN job right away, not report row-a's own
    # still-running state under a different key -- the old single-slot design would have returned
    # status="already_running" here and left row-b's own status forever describing row-a's job.
    resp = client.post("/api/settings/test-llm/start", data={"provider": "opencode-zen", "model": "deepseek-v4-flash-free", "target_id": "row-b"}, headers=_FORM_HEADERS)
    assert 'id="row-b"' in resp.text
    assert "Testing" in resp.text

    assert llm_test_job.test_status("row-a")["running"]
    assert llm_test_job.test_status("row-b")["running"]

    release_first.set()
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and (llm_test_job.test_status("row-a")["running"] or llm_test_job.test_status("row-b")["running"]):
        time.sleep(0.01)
    assert llm_test_job.test_status("row-a")["state"] == "ok"
    assert llm_test_job.test_status("row-b")["state"] == "ok"
