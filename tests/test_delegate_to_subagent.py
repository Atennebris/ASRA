"""End-to-end: agent/core.py's _delegate_to_subagent_impl (the real implementation behind the
delegate_to_subagent tool) actually spawns a genuinely concurrent asyncio.Task running a scoped-
down _run_llm_tool_loop conversation, returns immediately without blocking, and the finished
subagent's result auto-delivers back to the main agent via the push queue -- exactly the
architecture approved for this feature. Uses a real asyncio.Task (not mocked) and a real, scripted
LLMProvider stand-in, same "exercise the real mechanism" discipline as test_background_jobs.py.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import _delegate_to_subagent_impl, _drain_subagent_results
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import subagent_store, subagent_tasks
from agent.tools.native import check_subagent_task
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(subagent_tasks, "_RUNNING_SUBAGENT_TASKS", {})


def _run(coro):
    return asyncio.run(coro)


def _base_session(session_id):
    return {"session_id": session_id, "logs": [], "subagent_tasks": {}}


def _enable_a_profile(name="Recon Bot", allowed_tools=None):
    profile_store = subagent_store.add_profile(name, allowed_tools or [], "Focus on passive recon only.", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)


class _ImmediatelyReportsLLM:
    """A real LLMProvider-shaped stand-in whose very first turn calls report_subagent_result --
    exercises the terminal_tool contract for real, not mocked away."""
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(
            content=None,
            tool_calls=[ToolCallRequest(id="call_1", name="report_subagent_result", arguments={"summary": "Found 3 subdomains: a, b, c"})],
        )


def test_delegate_to_subagent_returns_immediately_with_a_task_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())

    session_id = "usr_delegate_test"
    session = _base_session(session_id)

    async def _go():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check subdomains a,b,c",
            "_session_id": session_id, "_session": session,
        })
        assert result["status"] == "ok"
        assert result["task_id"]
        # Not blocking -- returned before the (fast but real) subagent task necessarily finished.
        assert session["subagent_tasks"][result["task_id"]]["status"] in ("running", "done")
        return result["task_id"]

    task_id = _run(_go())
    assert task_id in session["subagent_tasks"]


def test_delegate_to_subagent_real_result_auto_delivers_to_the_main_agent(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())

    session_id = "usr_delegate_delivery_test"
    session = _base_session(session_id)

    async def _go():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check subdomains a,b,c",
            "_session_id": session_id, "_session": session,
        })
        await asyncio.sleep(0.2)  # let the real (fast) task actually finish and its done-callback fire
        return result["task_id"]

    task_id = _run(_go())
    assert session["subagent_tasks"][task_id]["status"] == "done"

    pushed = _drain_subagent_results(session_id)
    assert len(pushed) == 1
    assert pushed[0]["profile_name"] == "Recon Bot"
    assert "Found 3 subdomains" in pushed[0]["result"]["result"]["summary"]


def test_delegate_to_subagent_with_chat_thread_id_delivers_directly_to_that_chat_thread_not_the_shared_queue(tmp_path, monkeypatch):
    """agent/chat.py's own delegate_to_subagent call tags itself with _chat_thread_id --
    _on_subagent_task_done must route a chat-triggered task's result straight into that chat
    thread (agent/chat.py's deliver_subagent_result_to_chat), and skip the shared instruction
    queue entirely (only a live scan's own phase loop ever drains that queue; chat never does --
    exactly the real bug this fixes: a chat-delegated subagent used to finish for real, visible in
    debug.log, with its result then sitting in a queue nobody ever read)."""
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())

    session_id = "usr_delegate_chat_delivery_test"
    session = _base_session(session_id)
    session["chat_threads"] = [{"id": "thread1", "messages": []}]
    session["active_chat_thread_id"] = "thread1"
    store.save_session(session_id, session)

    async def _go():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check subdomains a,b,c",
            "_session_id": session_id, "_session": session, "_chat_thread_id": "thread1",
        })
        await asyncio.sleep(0.2)  # let the real (fast) task actually finish and its done-callback fire
        return result["task_id"]

    _run(_go())

    # Never leaked into the shared instruction queue -- a live scan sharing this session_id must
    # never see an operator's own ad-hoc chat delegation mixed into its own reasoning.
    assert _drain_subagent_results(session_id) == []

    reloaded = store.load_session(session_id)
    thread = next(t for t in reloaded["chat_threads"] if t["id"] == "thread1")
    assert len(thread["messages"]) == 1
    delivered = thread["messages"][0]
    assert delivered["role"] == "assistant"
    text = delivered["segments"][0]["content"]
    assert "Recon Bot" in text
    assert "Found 3 subdomains" in text


def test_delegate_to_subagent_falls_back_to_check_subagent_task_when_polled_explicitly(tmp_path, monkeypatch):
    """The explicit fallback path (native.py's check_subagent_task) must also work, even though
    the auto-push is the primary delivery mechanism."""
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())

    session_id = "usr_delegate_poll_test"
    session = _base_session(session_id)

    async def _go():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check subdomains",
            "_session_id": session_id, "_session": session,
        })
        await asyncio.sleep(0.2)
        return result["task_id"]

    task_id = _run(_go())
    polled = check_subagent_task({"task_id": task_id, "_session_id": session_id, "_session": session})
    assert polled["status"] == "done"
    assert "Found 3 subdomains" in polled["result"]["summary"]


def test_delegate_to_subagent_tags_its_own_log_entries_with_task_id_and_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())

    session_id = "usr_delegate_log_tagging_test"
    session = _base_session(session_id)

    async def _go():
        result = await _delegate_to_subagent_impl({
            "subagent_name": "Recon Bot", "task_description": "check subdomains a,b,c",
            "_session_id": session_id, "_session": session,
        })
        await asyncio.sleep(0.2)  # let the real (fast) task actually finish and log its own steps
        return result["task_id"]

    task_id = _run(_go())

    subagent_entries = [entry for entry in session["logs"] if entry["phase"] == "subagent"]
    assert subagent_entries
    assert all(entry["subagent_task_id"] == task_id for entry in subagent_entries)
    assert all(entry["subagent_name"] == "Recon Bot" for entry in subagent_entries)


def test_delegate_to_subagent_rejects_a_profile_not_in_this_projects_own_allowlist(tmp_path, monkeypatch):
    """session["enabled_subagent_ids"] (New Project form's per-project Subagent picker) narrows
    delegation even for a profile that's genuinely enabled globally -- a project that unchecked a
    subagent must never be able to reach it anyway just by naming it directly."""
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())

    session_id = "usr_delegate_project_scoped_test"
    session = _base_session(session_id)
    # This project's own allowlist names some OTHER (nonexistent) profile id -- Recon Bot, though
    # enabled globally, was never granted to this specific project.
    session["enabled_subagent_ids"] = ["some-other-profile-id"]

    result = _run(_delegate_to_subagent_impl({
        "subagent_name": "Recon Bot", "task_description": "check subdomains a,b,c",
        "_session_id": session_id, "_session": session,
    }))

    assert result["status"] == "error"
    assert "Recon Bot" in result["error"]


def test_delegate_to_subagent_allows_a_profile_actually_in_this_projects_own_allowlist(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setattr(core, "get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    profile_id = subagent_store.get_enabled_profiles()[0]["id"]

    session_id = "usr_delegate_project_scoped_allowed_test"
    session = _base_session(session_id)
    session["enabled_subagent_ids"] = [profile_id]

    result = _run(_delegate_to_subagent_impl({
        "subagent_name": "Recon Bot", "task_description": "check subdomains a,b,c",
        "_session_id": session_id, "_session": session,
    }))

    assert result["status"] == "ok"


def test_delegate_to_subagent_rejects_an_unknown_or_disabled_subagent_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_delegate_unknown_test"
    session = _base_session(session_id)

    result = _run(_delegate_to_subagent_impl({
        "subagent_name": "Nonexistent Bot", "task_description": "do something",
        "_session_id": session_id, "_session": session,
    }))

    assert result["status"] == "error"
    assert "Nonexistent Bot" in result["error"]


def test_delegate_to_subagent_requires_both_arguments(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_delegate_missing_args_test"
    session = _base_session(session_id)

    result = _run(_delegate_to_subagent_impl({"_session_id": session_id, "_session": session}))
    assert result["status"] == "error"


def test_delegate_to_subagent_respects_the_concurrency_cap(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_a_profile()
    monkeypatch.setenv("SUBAGENT_MAX_CONCURRENT_TASKS", "1")

    def _fail_if_called(provider, model):
        raise AssertionError("get_provider should never be reached for a delegation that's about to be capped")

    monkeypatch.setattr(core, "get_provider", _fail_if_called)

    session_id = "usr_delegate_cap_test"
    session = _base_session(session_id)
    # Simulate one already-running task without needing a real slow LLM.
    session["subagent_tasks"]["existing"] = {"status": "running", "profile_name": "Recon Bot", "result": None}

    result = _run(_delegate_to_subagent_impl({
        "subagent_name": "Recon Bot", "task_description": "another task",
        "_session_id": session_id, "_session": session,
    }))

    assert result["status"] == "skipped"
