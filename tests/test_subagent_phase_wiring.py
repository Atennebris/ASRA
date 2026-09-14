"""Wiring of Subagent delegation into the real phase loop: _run_llm_tool_loop waits for a still-
running delegated task before returning its own phase verdict (per the operator's explicit rule —
never block on a subagent except right before concluding a phase), a Stop actually cancels a real
running subagent task (not just marks it), and main.py's startup orphan sweep reconciles a real
stale "running" subagent-task entry the same way it already does for background jobs.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.core import RunContext, SessionStopRequested, request_session_stop
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import subagent_store, subagent_tasks
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(subagent_tasks, "_RUNNING_SUBAGENT_TASKS", {})


def _run(coro):
    return asyncio.run(coro)


def _enable_a_profile(name="Recon Bot"):
    profile_store = subagent_store.add_profile(name, [], "Focus on passive recon only.", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)


class _ImmediatelyReportsLLM:
    """The delegated subagent's own LLM stand-in -- reports back on its very first turn."""
    provider_id = "test-subagent-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(
            content=None,
            tool_calls=[ToolCallRequest(id="sub_call_1", name="report_subagent_result", arguments={"summary": "done with subtask"})],
        )


class _DelegatesThenFinishesLLM:
    """The MAIN agent's own LLM stand-in — first turn delegates, second turn says it's done."""
    provider_id = "test-main-provider"
    model = "test-model"
    context_limit = None

    def __init__(self):
        self._turn = 0

    def complete(self, messages, tools=None, stop_check=None):
        self._turn += 1
        if self._turn == 1:
            return LLMResponse(
                content=None,
                tool_calls=[ToolCallRequest(
                    id="call_1", name="delegate_to_subagent",
                    arguments={"subagent_name": "Recon Bot", "task_description": "check subdomains"},
                )],
            )
        return LLMResponse(content="wrapping up my own work now", tool_calls=[])


def test_run_llm_tool_loop_waits_for_a_real_delegated_task_before_concluding_the_phase(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())

    session_id = "usr_phase_wait_test"
    session = {"session_id": session_id, "logs": [], "findings": [], "subagent_tasks": {}}
    ctx = RunContext(llm=_DelegatesThenFinishesLLM(), session=session, session_id=session_id)
    tool_specs = [core.get_tool("delegate_to_subagent"), core.get_tool("check_subagent_task")]

    _run(core._run_llm_tool_loop(ctx, "system", "task", tool_specs, "analyze", expect_json_final=False))

    # The phase's own _run_llm_tool_loop already returned -- by the time it did, the delegated
    # task must have actually been waited on to completion, not left "running".
    task_ids = list(session["subagent_tasks"])
    assert len(task_ids) == 1
    assert session["subagent_tasks"][task_ids[0]]["status"] == "done"


class _NeverFinishesSubagentLLM:
    """.complete() is dispatched via asyncio.to_thread (agent/core.py's _llm_complete) -- a real
    (short) blocking sleep here keeps the subagent's own task genuinely still-running long enough
    for this test to call kill_all_running_subagent_tasks before it would naturally resolve."""
    provider_id = "test-subagent-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        import time
        time.sleep(2)
        return LLMResponse(content="still thinking, no final answer yet", tool_calls=[])


def test_run_session_stop_actually_cancels_a_real_running_subagent_task(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(core, "get_provider", lambda *a, **k: _NeverFinishesSubagentLLM())

    session_id = "usr_subagent_stop_test"
    session = {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "subagent_tasks": {},
    }
    store.save_session(session_id, session)

    async def _spawn_then_stop():
        result = await core._delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check things",
            "_session_id": session_id, "_session": session,
        })
        assert result["status"] == "ok"
        task_id = result["task_id"]
        real_task = subagent_tasks._RUNNING_SUBAGENT_TASKS[task_id]
        await asyncio.sleep(0.1)  # let the task actually start and reach its own (slow) LLM call

        # Simulate what run_session's own SessionStopRequested handler does.
        request_session_stop(session_id)
        try:
            raise SessionStopRequested()
        except SessionStopRequested:
            await subagent_tasks.kill_all_running_subagent_tasks(session)
        return task_id, real_task

    task_id, real_task = _run(_spawn_then_stop())

    assert session["subagent_tasks"][task_id]["status"] == "killed"
    assert real_task.cancelled() or real_task.done()
    assert task_id not in subagent_tasks._RUNNING_SUBAGENT_TASKS


def test_orphaned_session_recovery_marks_a_real_stale_subagent_task_orphaned(tmp_path, monkeypatch):
    from projects import paths as project_paths

    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    try:
        session_id = store.create_session("example.com", name="Orphaned subagent project")
        session = store.load_session(session_id)
        session["status"] = "processing"
        session["subagent_tasks"] = {"task1": {"status": "running", "profile_name": "Recon Bot", "result": None}}
        store.save_session(session_id, session)

        main._mark_orphaned_sessions_interrupted()

        reloaded = store.load_session(session_id)
        assert reloaded["status"] == "interrupted"
        assert reloaded["subagent_tasks"]["task1"]["status"] == "orphaned"
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()
