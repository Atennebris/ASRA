"""agent/tools/subagent_tasks.py: fire-and-check async task tracking for Subagent delegation --
the LLM-conversation equivalent of agent/tools/background_jobs.py's subprocess tracking. Uses real
asyncio.Task objects (real coroutines/asyncio.sleep/asyncio.wait_for), not mocks, same "exercise
the real mechanism" discipline as test_background_jobs.py.
"""
import asyncio
import time

import pytest

from agent.tools import subagent_tasks as st
from sessions import store


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    from projects import paths as project_paths
    project_paths.resolve_projects_base_dir.cache_clear()
    yield
    project_paths.resolve_projects_base_dir.cache_clear()
    st._RUNNING_SUBAGENT_TASKS.clear()
    st._LIVE_TRACES.clear()


def _run(coro):
    return asyncio.run(coro)


def _base_session(session_id):
    return {"session_id": session_id, "subagent_tasks": {}}


async def _quick_ok():
    return {"summary": "done"}, [{"tool": "dns_lookup"}]


async def _quick_fail():
    raise RuntimeError("something real broke")


async def _sleep(seconds):
    await asyncio.sleep(seconds)
    return {"summary": "slow but done"}, []


def test_register_task_stores_session_metadata_and_the_real_handle():
    session_id = "usr_subagent_register_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(_quick_ok())
        st.register_task(session_id, session, "task1", "Recon Bot", task, deadline=1e18, trace=[])
        await task

    _run(_go())
    assert session["subagent_tasks"]["task1"]["status"] == "running"  # not reaped until checked
    assert session["subagent_tasks"]["task1"]["profile_name"] == "Recon Bot"
    assert "task1" in st._RUNNING_SUBAGENT_TASKS


def test_register_task_triggered_by_defaults_to_model_and_can_be_overridden():
    session_id = "usr_subagent_triggered_by_test"
    session = _base_session(session_id)

    async def _go():
        task_a = asyncio.create_task(_quick_ok())
        st.register_task(session_id, session, "task-model", "Recon Bot", task_a, deadline=1e18, trace=[])
        task_b = asyncio.create_task(_quick_ok())
        st.register_task(session_id, session, "task-auto", "Recon Bot", task_b, deadline=1e18, trace=[], triggered_by="auto_overflow")
        await task_a
        await task_b

    _run(_go())
    assert session["subagent_tasks"]["task-model"]["triggered_by"] == "model"
    assert session["subagent_tasks"]["task-auto"]["triggered_by"] == "auto_overflow"


def test_register_task_chat_thread_id_defaults_to_none_and_can_be_set():
    """chat_thread_id (set only by agent/chat.py's own delegate_to_subagent call) is what lets
    agent/core.py's _on_subagent_task_done tell a chat-triggered delegation apart from an ordinary
    model/auto_overflow one and route its result to the right place."""
    session_id = "usr_subagent_chat_thread_id_test"
    session = _base_session(session_id)

    async def _go():
        task_a = asyncio.create_task(_quick_ok())
        st.register_task(session_id, session, "task-scan", "Recon Bot", task_a, deadline=1e18, trace=[])
        task_b = asyncio.create_task(_quick_ok())
        st.register_task(session_id, session, "task-chat", "Recon Bot", task_b, deadline=1e18, trace=[], chat_thread_id="thread1")
        await task_a
        await task_b

    _run(_go())
    assert session["subagent_tasks"]["task-scan"]["chat_thread_id"] is None
    assert session["subagent_tasks"]["task-chat"]["chat_thread_id"] == "thread1"


def test_check_subagent_task_returns_running_while_still_in_progress():
    session_id = "usr_subagent_running_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(2), timeout=5))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=[])
        await asyncio.sleep(0)  # let the event loop actually start the wrapped inner task once
        result = st.check_subagent_task(session_id, session, "task1")
        task.cancel()  # don't actually let the sleep run out the test
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        return result

    result = _run(_go())
    assert result["status"] == "running"


def test_check_subagent_task_reports_a_real_completed_result():
    session_id = "usr_subagent_done_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_quick_ok(), timeout=5))
        st.register_task(session_id, session, "task1", "Recon Bot", task, deadline=1e18, trace=[])
        await asyncio.sleep(0.05)  # let the task actually finish
        return st.check_subagent_task(session_id, session, "task1")

    result = _run(_go())
    assert result["status"] == "done"
    assert result["result"] == {"summary": "done"}
    assert "task1" not in st._RUNNING_SUBAGENT_TASKS  # popped once reaped


def test_check_subagent_task_reports_a_real_error():
    session_id = "usr_subagent_error_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_quick_fail(), timeout=5))
        st.register_task(session_id, session, "task1", "Recon Bot", task, deadline=1e18, trace=[])
        await asyncio.sleep(0.05)
        return st.check_subagent_task(session_id, session, "task1")

    result = _run(_go())
    assert result["status"] == "error"
    assert "something real broke" in result["result"]["error"]


def test_check_subagent_task_reports_a_real_timeout():
    session_id = "usr_subagent_timeout_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(5), timeout=0.05))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=[])
        await asyncio.sleep(0.2)  # let the real timeout actually fire
        return st.check_subagent_task(session_id, session, "task1")

    result = _run(_go())
    assert result["status"] == "timeout"
    assert result["result"] is None


def test_check_subagent_task_reports_partial_progress_on_a_real_timeout():
    """Real incident this covers: an auto-delegated task hit its own asyncio.wait_for() deadline
    after making 29 genuinely successful tool calls, and the old behavior (result=None on any
    timeout) discarded all of it -- the same list object the subagent's own _run_llm_tool_loop
    would have mutated in place (external_trace, agent/core.py) must survive the cancellation
    since it's registered here BEFORE the timeout ever fires, not read off the cancelled task
    afterward."""
    session_id = "usr_subagent_timeout_partial_test"
    session = _base_session(session_id)
    live_trace = [{"tool": "whatweb", "arguments": {"target": "portal.example.com"}, "result": {"status": "ok"}}]

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(5), timeout=0.05))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=live_trace)
        live_trace.append({"tool": "ffuf", "arguments": {"target": "portal.example.com"}, "result": {"status": "ok"}})
        await asyncio.sleep(0.2)  # let the real timeout actually fire
        return st.check_subagent_task(session_id, session, "task1")

    result = _run(_go())
    assert result["status"] == "timeout"
    assert result["result"] is not None
    assert result["result"]["tool_calls"] == 2
    assert result["result"]["partial_trace"] == live_trace
    assert "task1" not in st._LIVE_TRACES  # popped once reaped, no leak across the session


def test_check_subagent_task_caps_a_huge_trace_entry_result():
    """Real incident this covers: a real bug-bounty session's auto-delegated overflow subagent
    timed out mid-sweep with two `nuclei` calls still in its trace whose raw stdout was
    2.27MB/1.73MB each -- embedded verbatim into partial_trace (the old behavior), that alone blew
    session.json to 4.7MB and, once _drain_subagent_results (agent/core.py) delivered this same
    dict into the main phase's own conversation, pushed the next several LLM requests in that
    phase past 2 million tokens -- exhausting every configured fallback provider and failing the
    whole session. A small entry must come through completely untouched (not even copied) so a
    subagent's ordinary, already-small trace entries are unaffected."""
    session_id = "usr_subagent_huge_trace_test"
    session = _base_session(session_id)
    huge_stdout = "A" * 50_000
    small_entry = {"tool": "http_request", "arguments": {"target": "https://example.com"}, "result": {"status": "ok", "body": "small"}}
    huge_entry = {"tool": "nuclei", "arguments": {"target": "https://example.com"}, "result": {"status": "ok", "stdout": huge_stdout}}
    live_trace = [small_entry, huge_entry]

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(5), timeout=0.05))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=live_trace)
        await asyncio.sleep(0.2)  # let the real timeout actually fire
        return st.check_subagent_task(session_id, session, "task1")

    result = _run(_go())
    trace = result["result"]["partial_trace"]
    assert trace[0] == small_entry  # left completely unmodified, well under the cap
    assert trace[1]["tool"] == "nuclei"
    assert trace[1]["arguments"] == huge_entry["arguments"]
    assert isinstance(trace[1]["result"], str)  # capped down from the original dict to a preview string
    assert len(trace[1]["result"]) <= st._TRACE_RESULT_CHAR_LIMIT + 50
    assert "truncated" in trace[1]["result"]


def test_check_subagent_task_returns_error_for_an_unknown_id():
    session = _base_session("usr_x")
    result = st.check_subagent_task("usr_x", session, "does-not-exist")
    assert result["status"] == "error"


def test_await_all_running_subagent_tasks_blocks_until_a_real_task_finishes():
    session_id = "usr_subagent_await_all_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(0.3), timeout=5))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=[])
        await st.await_all_running_subagent_tasks(session_id, session)
        return session["subagent_tasks"]["task1"]["status"]

    status = _run(_go())
    assert status == "done"


def test_reap_reports_stopped_not_timeout_when_cancelled_well_before_its_own_deadline():
    """Real incident this covers: a server shutdown (Ctrl+C) cancels every outstanding
    asyncio.Task the way asyncio always does on exit -- including a chat-triggered subagent task
    that was only ~4 minutes into its real 900s budget. Before this fix, _reap() couldn't tell
    that apart from a real asyncio.wait_for() deadline actually firing (both leave
    task.cancelled() == True) and mislabeled it status="timeout" ("hit its time budget") even
    though the real cause was the process going down, not the subagent running out of time.
    Unlike test_check_subagent_task_reports_a_real_timeout (wait_for's OWN internal timeout,
    which raises TimeoutError as the task's result rather than cancelling the outer task), this
    cancels the outer task handle directly -- the same thing uvicorn/asyncio shutdown does -- with
    a real deadline still far in the future, same as kill_all_running_subagent_tasks would see."""
    session_id = "usr_subagent_shutdown_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(5), timeout=900))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=time.time() + 900, trace=[])
        await asyncio.sleep(0)  # let the event loop actually start the wrapped inner task once
        task.cancel()  # simulate uvicorn/asyncio cancelling every outstanding task on shutdown
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        return st.check_subagent_task(session_id, session, "task1")

    result = _run(_go())
    assert result["status"] == "stopped"
    assert "shut down" in result["result"]["summary"]


def test_kill_all_running_subagent_tasks_actually_cancels_the_real_task():
    session_id = "usr_subagent_kill_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(5), timeout=10))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=[])
        await asyncio.sleep(0)  # let the event loop actually start the wrapped inner task once
        await st.kill_all_running_subagent_tasks(session)
        return task

    task = _run(_go())
    assert task.cancelled() or task.done()
    assert "task1" not in st._RUNNING_SUBAGENT_TASKS


def test_kill_all_running_subagent_tasks_preserves_the_real_partial_trace():
    """Real, confirmed incident this fixes (again-tests-usr_73fe2f): two subagent tasks did ~19
    minutes of real work (22 and 29 real tool calls each) before the operator's Stop killed them
    -- kill_all_running_subagent_tasks used to discard the live trace outright
    (_LIVE_TRACES.pop(task_id, None), no result ever built), so entry["result"] stayed None
    forever and a resumed session had no way to know that work had already happened. Sibling of
    the already-working timeout path (_synthesize_partial_result), just never applied here."""
    session_id = "usr_subagent_kill_preserves_trace_test"
    session = _base_session(session_id)
    trace = [{"tool": "whatweb", "result": {"ok": True}}, {"tool": "ssl_cert_info", "result": {"ok": True}}]

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(5), timeout=10))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=trace)
        await asyncio.sleep(0)
        await st.kill_all_running_subagent_tasks(session)

    _run(_go())
    entry = session["subagent_tasks"]["task1"]
    assert entry["status"] == "killed"
    assert entry["result"] is not None
    assert entry["result"]["tool_calls"] == 2
    assert len(entry["result"]["partial_trace"]) == 2


def test_kill_all_running_subagent_tasks_result_is_none_with_no_real_work_done():
    """Sibling regression guard: a task killed before making any real tool call still gets
    result=None (matching the pre-existing behavior for a genuinely empty trace), not a
    misleadingly "real progress" summary built from nothing."""
    session_id = "usr_subagent_kill_empty_trace_test"
    session = _base_session(session_id)

    async def _go():
        task = asyncio.create_task(asyncio.wait_for(_sleep(5), timeout=10))
        st.register_task(session_id, session, "task1", "Slow Bot", task, deadline=1e18, trace=[])
        await asyncio.sleep(0)
        await st.kill_all_running_subagent_tasks(session)

    _run(_go())
    assert session["subagent_tasks"]["task1"]["result"] is None


def test_reconcile_orphaned_subagent_tasks_marks_running_entries_orphaned_with_no_kill_step():
    data = {"subagent_tasks": {
        "task1": {"status": "running", "profile_name": "Recon Bot", "result": None},
        "task2": {"status": "done", "profile_name": "Other Bot", "result": {"summary": "ok"}},
    }}

    st.reconcile_orphaned_subagent_tasks("usr_orphan_test", data)

    assert data["subagent_tasks"]["task1"]["status"] == "orphaned"
    assert data["subagent_tasks"]["task1"]["result"] is None
    assert data["subagent_tasks"]["task2"]["status"] == "done"  # untouched, already resolved
