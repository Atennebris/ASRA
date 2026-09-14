"""The session page's Stop button (session_fragment.html) + main.py's /interrupt route: a
deliberate, operator-confirmed way to end a live session early, distinct from an accidental
Ctrl+C/crash (tests/test_session_cancellation.py). The mechanism (agent/core.py's
request_session_stop/get_stop_event) mirrors the existing exploit-approval signal
(get_approval_event) rather than writing into the session file directly from the HTTP route --
that file's read-modify-write cycle is already owned by the live run_session()/run_focused_exploit()
loop, and a second writer racing it is exactly the bug class _instruction_queues/_approval_events
already exist to avoid.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
import pytest
from agent.core import RunContext, SessionStopRequested, run_focused_exploit, run_session
from agent.llm_client import LLMCallAborted
from fastapi.testclient import TestClient
from projects import paths as project_paths
from sessions import store


class _NeverCalledLLM:
    """Proves the stop was caught at _llm_complete's own checkpoint, before any real request —
    calling .complete() at all is a test failure, not just an unexpected result."""

    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        raise AssertionError("LLM should never be called once a stop was already requested")


def _base_session(session_id, **overrides):
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    session.update(overrides)
    return session


def test_llm_complete_raises_but_does_not_consume_the_stop_flag(monkeypatch):
    """Real, confirmed incident: get_stop_event(session_id) is keyed only by session_id, and a
    delegated Subagent task's own conversation runs as a genuinely concurrent asyncio.Task sharing
    that SAME session_id and hitting this SAME _llm_complete checkpoint. When _llm_complete used to
    clear() the flag the instant IT saw it, whichever of the two (main loop or a concurrent
    subagent) happened to check first silently stole the signal from the other -- confirmed live,
    a Stop click was swallowed by a subagent task's own check, and the main session's very next
    _llm_complete call found the flag already clear and sailed straight into the next phase,
    completely oblivious a Stop had been requested. _llm_complete must now raise WITHOUT clearing,
    so every concurrent consumer independently sees and reacts to the same still-set flag -- see
    test_run_session_actually_clears_the_stop_flag_once_the_whole_run_has_ended below for proof the
    flag still gets cleared exactly once, by the one place that actually owns doing so."""
    session_id = "usr_llm_stop_test"
    ctx = RunContext(llm=None, session=_base_session(session_id), session_id=session_id)
    core.request_session_stop(session_id)

    with pytest.raises(SessionStopRequested):
        asyncio.run(core._llm_complete(ctx, [], []))

    assert core.get_stop_event(session_id).is_set() is True

    # A second, concurrent checkpoint (e.g. a subagent task sharing the same session_id) must
    # independently see and react to the exact same still-set flag, not find it already stolen.
    with pytest.raises(SessionStopRequested):
        asyncio.run(core._llm_complete(ctx, [], []))


class _AbortsMidBackoffLLM:
    """Simulates ctx.llm.complete() itself hitting a Stop mid-retry-wait (agent/llm_client.py's
    _call_with_backoff raises LLMCallAborted from inside its backoff sleep) -- proves _llm_complete
    converts that into the same SessionStopRequested a pre-call check produces, rather than letting
    it escape as a raw LLMCallAborted the rest of run_session doesn't know how to handle."""

    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        raise LLMCallAborted("stop requested during backoff wait")


def test_llm_complete_converts_aborted_backoff_wait_into_session_stop(monkeypatch):
    session_id = "usr_llm_stop_mid_backoff_test"
    ctx = RunContext(llm=_AbortsMidBackoffLLM(), session=_base_session(session_id), session_id=session_id)
    # Deliberately NOT set via request_session_stop() -- the pre-call checkpoint at the top of
    # _llm_complete would otherwise short-circuit before ctx.llm.complete is ever reached, and this
    # test is specifically about the *other* checkpoint: LLMCallAborted raised from mid-wait,
    # after the pre-call check already passed.

    with pytest.raises(SessionStopRequested):
        asyncio.run(core._llm_complete(ctx, [], []))

    # Never set to begin with in this test (see comment above) -- stays that way, since this
    # checkpoint no longer clears the flag either (see the pre-call checkpoint test above).
    assert core.get_stop_event(session_id).is_set() is False


def test_run_session_persists_interrupted_status_on_stop_request(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _NeverCalledLLM())

    session_id = "usr_stop_run_session_test"
    store.save_session(session_id, _base_session(session_id))
    core.request_session_stop(session_id)

    asyncio.run(run_session(session_id))  # must not raise -- SessionStopRequested is fully handled

    saved = store.load_session(session_id)
    assert saved["status"] == "interrupted"
    assert saved["resumable_from"] == "recon"
    # run_session's own finally block (not _llm_complete's per-call checkpoint, see that function's
    # docstring) is the one true owner of clearing the stop flag once the whole run has genuinely
    # ended -- a later resumed run of this same session_id must not immediately re-trigger stop on
    # its very first LLM call just because a stale flag was left set.
    assert core.get_stop_event(session_id).is_set() is False


def test_run_session_stop_actually_kills_a_real_running_background_job(tmp_path, monkeypatch):
    """A Stop must actually kill any background job (e.g. Hydra) the session started -- the
    operator asked everything to stop, not just the LLM loop, leaving a real brute-force run
    quietly continuing in the background untouched."""
    import os
    import sys
    import time

    from agent.tools import background_jobs

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _NeverCalledLLM())

    session_id = "usr_stop_kills_background_job_test"
    session = _base_session(session_id)
    start = background_jobs.start_background_job(
        session_id, session, "test-tool",
        lambda job_id, job_dir: ([sys.executable, "-c", "import time; time.sleep(30)"], lambda log_path: {}),
        max_concurrent=2, timeout_seconds=60,
    )
    pid = session["background_jobs"][start["job_id"]]["pid"]
    store.save_session(session_id, session)
    core.request_session_stop(session_id)

    try:
        asyncio.run(run_session(session_id))  # must not raise

        saved = store.load_session(session_id)
        assert saved["background_jobs"][start["job_id"]]["status"] == "killed"
        time.sleep(0.3)
        with pytest.raises(OSError):
            os.kill(pid, 0)  # the real process is actually gone, not just relabeled
    finally:
        background_jobs._RUNNING_PROCESSES.clear()
        background_jobs._PARSERS.clear()


def test_run_focused_exploit_persists_interrupted_status_on_stop_request(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _NeverCalledLLM())

    session_id = "usr_stop_deep_dive_test"
    finding = {"title": "Some finding", "severity": "High", "verification": "verified"}
    store.save_session(session_id, _base_session(session_id, status="completed", findings=[finding]))
    core.request_session_stop(session_id)

    asyncio.run(run_focused_exploit(session_id, "Some finding"))  # must not raise

    saved = store.load_session(session_id)
    assert saved["status"] == "interrupted"
    # Same single-owner clearing guarantee as run_session's own finally block -- see that test's
    # equivalent assertion.
    assert core.get_stop_event(session_id).is_set() is False
    assert saved["resumable_from"] == "exploit"


def test_await_exploit_approval_raises_stop_instead_of_treating_the_wakeup_as_approval(tmp_path, monkeypatch):
    """request_session_stop() wakes the same event the approve/deny routes use to unblock a
    paused approval wait -- this proves a stop racing that wait is never misread as a real
    approve/deny decision (agent/core.py's _await_exploit_approval checks stop first)."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("EXPLOIT_REQUIRE_APPROVAL", "true")

    session_id = "usr_stop_approval_test"
    session = _base_session(session_id)
    ctx = RunContext(llm=None, session=session, session_id=session_id)

    async def _run():
        async def _stop_soon():
            await asyncio.sleep(0.05)
            core.request_session_stop(session_id)

        waiter = asyncio.ensure_future(core._await_exploit_approval(ctx, {"title": "Some finding"}))
        asyncio.ensure_future(_stop_soon())
        return await waiter

    with pytest.raises(SessionStopRequested):
        asyncio.run(_run())

    # exploit_approved must never have been set -- a later finding in the same (resumed) run must
    # still ask for a fresh approval, not silently inherit a stop-triggered wakeup as a green light.
    assert session.get("exploit_approved") is not True


def _post(client, path, **kwargs):
    return client.post(path, **kwargs)


def test_interrupt_route_requires_a_running_session(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()

    client = TestClient(main.app)
    try:
        assert _post(client, "/api/session/usr_does_not_exist/interrupt").status_code == 404

        session_id = "usr_interrupt_route_test"
        store.save_session(session_id, _base_session(session_id, status="completed"))
        assert _post(client, f"/api/session/{session_id}/interrupt").status_code == 400

        store.save_session(session_id, _base_session(session_id, status="processing"))
        resp = _post(client, f"/api/session/{session_id}/interrupt")
        assert resp.status_code == 200
        assert core.get_stop_event(session_id).is_set() is True
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
