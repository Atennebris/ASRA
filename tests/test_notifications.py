"""agent/tools/notifications.py -- vendor-agnostic operator webhook. No-op when unset (the normal
case for every project that never opts in), a best-effort JSON POST that never raises when set.
"""
import asyncio

import httpx

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import request_session_stop, run_session
from agent.tools import notifications
from sessions import store


def test_notify_is_a_noop_when_no_webhook_url_configured(monkeypatch):
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append((a, k)))

    notifications.notify("hello")

    assert calls == []


def test_notify_posts_a_dual_key_json_payload_when_configured(monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://example.test/webhook")
    calls = []
    monkeypatch.setattr(httpx, "post", lambda url, json=None, timeout=None: calls.append((url, json, timeout)))

    notifications.notify("hello world")

    assert len(calls) == 1
    url, payload, timeout = calls[0]
    assert url == "https://example.test/webhook"
    assert payload == {"content": "hello world", "text": "hello world"}
    assert timeout == notifications._WEBHOOK_TIMEOUT_SECONDS


def test_notify_swallows_a_failed_post_instead_of_raising(monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://example.test/webhook")

    def _raise(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", _raise)

    notifications.notify("hello")  # must not raise


def test_notify_treats_a_blank_url_as_unset(monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "   ")
    calls = []
    monkeypatch.setattr(httpx, "post", lambda *a, **k: calls.append(1))

    notifications.notify("hello")

    assert calls == []


def test_notify_session_ended_uses_a_different_emoji_for_failed(monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://example.test/webhook")
    sent = []
    monkeypatch.setattr(notifications, "notify", lambda message: sent.append(message))

    notifications.notify_session_ended("My Project", "example.com", "completed", 3)
    notifications.notify_session_ended("My Project", "example.com", "failed", 0)

    assert "✅" in sent[0] and "completed" in sent[0] and "3 finding" in sent[0]
    assert "⚠️" in sent[1] and "failed" in sent[1]


# --- run_session wiring: notify only on the two genuinely terminal outcomes ---------------------


def _base_session(session_id, **overrides):
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


class _NeverCalledLLM:
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        raise AssertionError("LLM should never be called once a stop was already requested")


class _AlwaysCrashingLLM:
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        raise RuntimeError("simulated crash")


def _run(coro):
    return asyncio.run(coro)


def test_run_session_does_not_notify_on_a_plain_interrupt(tmp_path, monkeypatch):
    """"interrupted" is very often the operator's own Stop click -- they already know, and a
    resumed run will end here again for real later. Must not fire a notification."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _NeverCalledLLM())
    notified = []
    monkeypatch.setattr(core, "notify_session_ended", lambda *a, **k: notified.append(a))

    session_id = "usr_notify_interrupt_test"
    store.save_session(session_id, _base_session(session_id, status="failed"))
    request_session_stop(session_id)

    _run(run_session(session_id))  # stops immediately at the first LLM checkpoint

    assert store.load_session(session_id)["status"] == "interrupted"
    assert notified == []


def test_run_session_notifies_on_a_real_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _AlwaysCrashingLLM())
    notified = []
    monkeypatch.setattr(core, "notify_session_ended", lambda *a, **k: notified.append(a))

    session_id = "usr_notify_failure_test"
    store.save_session(session_id, _base_session(session_id))

    try:
        _run(run_session(session_id))
    except RuntimeError:
        pass

    assert store.load_session(session_id)["status"] == "failed"
    assert len(notified) == 1
    assert notified[0][2] == "failed"  # (name, target, status, findings_count)


def test_run_session_computes_efficiency_notes_on_a_real_terminal_outcome(tmp_path, monkeypatch):
    """compute_efficiency_notes (agent/core.py) -- the standing self-audit -- must actually be
    computed and persisted once a session reaches a genuinely terminal status, not just available
    as a function nobody calls."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _AlwaysCrashingLLM())

    session_id = "usr_efficiency_notes_wiring_test"
    store.save_session(session_id, _base_session(session_id))

    try:
        _run(run_session(session_id))
    except RuntimeError:
        pass

    saved = store.load_session(session_id)
    assert "efficiency_notes" in saved
    assert isinstance(saved["efficiency_notes"], list)
