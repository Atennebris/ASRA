"""Graceful shutdown / Ctrl+C mid-session: asyncio.CancelledError is a BaseException, not an
Exception, so it needs its own handling wherever a background scan's exceptions are caught --
agent/core.py's run_session() and main.py's _run_session_task() both used to only catch
Exception, letting a CancelledError escape uncaught into Starlette's background-task runner as a
raw, unhandled traceback with no useful session state behind it (real incident: exactly this
happened on a Ctrl+C mid-exploit-phase). Both now persist status="interrupted" (with a computed
resume point) before letting the cancellation continue to propagate.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
import pytest
from agent.core import run_session
from sessions import store


class _CancellingLLM:
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        raise asyncio.CancelledError()


def _base_session(session_id, **overrides):
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


def test_run_session_persists_interrupted_status_on_cancellation(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _CancellingLLM())

    session_id = "usr_cancel_test"
    store.save_session(session_id, _base_session(session_id))

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(run_session(session_id))

    saved = store.load_session(session_id)
    assert saved["status"] == "interrupted"
    assert saved["resumable_from"] == "recon"


def test_run_session_task_swallows_cancellation_without_raising(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _CancellingLLM())

    session_id = "usr_cancel_task_test"
    store.save_session(session_id, _base_session(session_id))

    # main._run_session_task must not let the CancelledError reach its caller (Starlette's
    # background-task runner) -- run_session() already persisted and logged everything useful.
    asyncio.run(main._run_session_task(session_id, provider_id=None))

    saved = store.load_session(session_id)
    assert saved["status"] == "interrupted"
