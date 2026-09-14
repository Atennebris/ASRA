"""agent/core.py's subagent-result auto-delivery: _push_subagent_result/_drain_subagent_results
clone the exact same per-session instruction-queue mechanism already proven for operator guidance
(_drain_pending_guidance) -- a finished subagent's result gets injected into the MAIN loop's own
conversation on its very next iteration, no explicit polling required. The is_subagent flag on
_run_llm_tool_loop must gate this: a subagent's own loop must never drain a result meant for the
main agent (or a sibling subagent).

Also covers _requeue_undelivered_subagent_results: a subagent task that finishes AFTER the main
session has already crashed/exited pushes into a queue nothing is left listening to -- the result
stays durable in session["subagent_tasks"][task_id]["result"] (subagent_tasks.py's own
register_task/_reap both save_session), but without this, nothing ever automatically revisits it.
run_session calls this once, near the top, before its own phase dispatch begins.
"""
import asyncio

import agent.core as core
from agent.core import (
    RunContext,
    _drain_pending_guidance,
    _drain_subagent_results,
    _push_subagent_result,
    _requeue_undelivered_subagent_results,
    _run_llm_tool_loop,
    get_instruction_queue,
)
from agent.llm_client import LLMResponse
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def test_push_and_drain_round_trip():
    session_id = "usr_subagent_delivery_test"
    _push_subagent_result(session_id, "Recon Bot", {"summary": "found 3 subdomains"}, "task_1")

    results = _drain_subagent_results(session_id)

    assert len(results) == 1
    assert results[0]["profile_name"] == "Recon Bot"
    assert results[0]["result"] == {"summary": "found 3 subdomains"}
    # Consumed, not left in the queue for a second drain to see again.
    assert _drain_subagent_results(session_id) == []


def test_drain_subagent_results_leaves_unrelated_guidance_instructions_alone():
    session_id = "usr_subagent_delivery_queue_test"
    get_instruction_queue(session_id).put_nowait({"type": "add_guidance", "text": "focus on the API"})
    _push_subagent_result(session_id, "Recon Bot", {"summary": "done"}, "task_1")

    subagent_results = _drain_subagent_results(session_id)
    assert len(subagent_results) == 1

    # The guidance instruction survived the subagent-result drain, untouched, in original order.
    guidance = _drain_pending_guidance(session_id)
    assert guidance == ["focus on the API"]


def test_drain_pending_guidance_leaves_subagent_results_alone():
    session_id = "usr_subagent_delivery_queue_test2"
    _push_subagent_result(session_id, "Recon Bot", {"summary": "done"}, "task_1")
    get_instruction_queue(session_id).put_nowait({"type": "add_guidance", "text": "focus on the API"})

    guidance = _drain_pending_guidance(session_id)
    assert guidance == ["focus on the API"]

    subagent_results = _drain_subagent_results(session_id)
    assert len(subagent_results) == 1
    assert subagent_results[0]["profile_name"] == "Recon Bot"


class _RecordingLLM:
    provider_id = "test-provider"
    model = "test-model"
    context_limit = None

    def __init__(self, replies):
        self._replies = list(replies)
        self.seen_messages: list[list[dict]] = []

    def complete(self, messages, tools=None, stop_check=None):
        self.seen_messages.append([dict(m) for m in messages])
        if self._replies:
            return self._replies.pop(0)
        return LLMResponse(content="done", tool_calls=[])


def test_run_llm_tool_loop_auto_injects_a_pushed_subagent_result_on_its_first_iteration(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_subagent_delivery_e2e_test"
    _push_subagent_result(session_id, "Recon Bot", {"summary": "found 3 subdomains"}, "task_1")

    llm = _RecordingLLM([LLMResponse(content="wrapping up", tool_calls=[])])
    ctx = RunContext(llm=llm, session={"session_id": session_id, "logs": []}, session_id=session_id)

    _run(_run_llm_tool_loop(ctx, "system", "task", [], "analyze", expect_json_final=False))

    first_call_messages = llm.seen_messages[0]
    injected = [m for m in first_call_messages if m["role"] == "user" and "Recon Bot" in m["content"]]
    assert len(injected) == 1
    assert "found 3 subdomains" in injected[0]["content"]


def test_run_llm_tool_loop_never_drains_subagent_results_when_is_subagent(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_subagent_delivery_no_self_drain_test"
    _push_subagent_result(session_id, "Recon Bot", {"summary": "found 3 subdomains"}, "task_1")

    llm = _RecordingLLM([LLMResponse(content="wrapping up", tool_calls=[])])
    ctx = RunContext(llm=llm, session={"session_id": session_id, "logs": []}, session_id=session_id)

    _run(_run_llm_tool_loop(ctx, "system", "task", [], "subagent", expect_json_final=False, is_subagent=True))

    first_call_messages = llm.seen_messages[0]
    assert not any("Recon Bot" in m.get("content", "") for m in first_call_messages if m["role"] == "user")
    # Untouched -- still there for the main agent's own loop to drain later.
    assert len(core._drain_subagent_results(session_id)) == 1


def test_drained_result_marks_its_own_subagent_tasks_entry_delivered(tmp_path, monkeypatch):
    """The other half of the delivered flag: a result that DOES get drained by a live turn must be
    marked so on the session's own subagent_tasks entry, or _requeue_undelivered_subagent_results
    would re-inject the exact same result into every later phase forever."""
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_subagent_delivery_marks_delivered_test"
    session = {
        "session_id": session_id, "logs": [],
        "subagent_tasks": {"task_1": {"profile_name": "Recon Bot", "status": "done", "result": {"summary": "x"}, "delivered": False}},
    }
    _push_subagent_result(session_id, "Recon Bot", {"summary": "found 3 subdomains"}, "task_1")
    llm = _RecordingLLM([LLMResponse(content="wrapping up", tool_calls=[])])
    ctx = RunContext(llm=llm, session=session, session_id=session_id)

    _run(_run_llm_tool_loop(ctx, "system", "task", [], "analyze", expect_json_final=False))

    assert session["subagent_tasks"]["task_1"]["delivered"] is True


def test_requeue_undelivered_subagent_results_re_pushes_a_stranded_result(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (a real YesWeHack session, usr_57af40): the main session
    crashed while a subagent was still running; it finished 6-9 minutes later and pushed a real,
    confirmed CORS finding into a queue nothing was left listening to. The result stayed durable on
    session["subagent_tasks"], but nothing ever re-delivered it. run_session now calls this once,
    near the top, before dispatching into whatever phase runs next."""
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_requeue_test"
    session = {
        "subagent_tasks": {
            "task_stranded": {
                "profile_name": "Recon Bot", "status": "done",
                "result": {"summary": "CORS: reflects any origin + credentials=true"},
                "delivered": False, "chat_thread_id": None,
            },
        },
    }

    _requeue_undelivered_subagent_results(session_id, session)

    results = _drain_subagent_results(session_id)
    assert len(results) == 1
    assert results[0]["task_id"] == "task_stranded"
    assert results[0]["result"]["result"]["summary"] == "CORS: reflects any origin + credentials=true"


def test_requeue_undelivered_subagent_results_skips_already_delivered_and_running_and_chat_routed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_requeue_skip_test"
    session = {
        "subagent_tasks": {
            "task_already_delivered": {"profile_name": "A", "status": "done", "result": {}, "delivered": True},
            "task_still_running": {"profile_name": "B", "status": "running", "result": None, "delivered": False},
            "task_chat_routed": {"profile_name": "C", "status": "done", "result": {}, "delivered": False, "chat_thread_id": "thread_1"},
        },
    }

    _requeue_undelivered_subagent_results(session_id, session)

    assert _drain_subagent_results(session_id) == []


def test_requeue_undelivered_subagent_results_is_idempotent_once_actually_drained(tmp_path, monkeypatch):
    """Called on every run_session entry (fresh or resumed) -- once a re-queued result has actually
    been drained into a live conversation (marking its subagent_tasks entry delivered=True, same as
    the ordinary live-push path), a LATER run_session call must never re-inject the same result
    again. Goes through the real _run_llm_tool_loop, not a bare _drain_subagent_results call, since
    the delivered=True marking only happens at that real consumption point."""
    _isolate(tmp_path, monkeypatch)
    session_id = "usr_requeue_idempotent_test"
    session = {
        "session_id": session_id, "logs": [],
        "subagent_tasks": {"task_1": {"profile_name": "A", "status": "done", "result": {"x": 1}, "delivered": False}},
    }

    _requeue_undelivered_subagent_results(session_id, session)
    llm = _RecordingLLM([LLMResponse(content="wrapping up", tool_calls=[])])
    ctx = RunContext(llm=llm, session=session, session_id=session_id)
    _run(_run_llm_tool_loop(ctx, "system", "task", [], "analyze", expect_json_final=False))
    assert session["subagent_tasks"]["task_1"]["delivered"] is True

    # A second run_session entry (e.g. an operator resuming again) must find nothing left to requeue.
    _requeue_undelivered_subagent_results(session_id, session)
    assert _drain_subagent_results(session_id) == []
