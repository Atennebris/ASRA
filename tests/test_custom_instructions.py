"""Custom instructions for a specific bug-bounty program: the New Project form's free-text field
(sessions/store.py's create_session), and agent/core.py's _custom_instructions_task_addendum that
actually threads it into every phase's task message (recon, analyze, exploit) — not just Analyze
like the Qualifying/Non-qualifying scope rules, since program rules commonly constrain HOW to scan
(testing windows, required test accounts, out-of-scope paths), not just which vuln classes pay out.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _custom_instructions_task_addendum, _run_analyze, _run_recon
from agent.llm_client import LLMResponse, ToolCallRequest
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


def _run(coro):
    return asyncio.run(coro)


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, tool_calls_per_turn=()):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0
        self.last_messages = None

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        self.last_messages = messages
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def test_create_session_defaults_custom_instructions_to_blank(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    try:
        session_id = create_session("example.com")
        assert load_session(session_id)["custom_instructions"] == ""
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_create_session_stores_and_strips_custom_instructions(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    try:
        session_id = create_session("example.com", custom_instructions="  Only test the mobile API.  ")
        assert load_session(session_id)["custom_instructions"] == "Only test the mobile API."
    finally:
        project_paths.resolve_projects_base_dir.cache_clear()


def test_custom_instructions_task_addendum_is_empty_when_blank():
    assert _custom_instructions_task_addendum({"custom_instructions": ""}) == ""
    assert _custom_instructions_task_addendum({}) == ""


def test_custom_instructions_task_addendum_carries_the_operator_text():
    addendum = _custom_instructions_task_addendum({"custom_instructions": "Use only the provided test account."})
    assert "Use only the provided test account." in addendum


def test_recon_task_message_includes_custom_instructions(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {
        "session_id": "usr_recon_custom", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "custom_instructions": "No automated scanners against /checkout.",
    }
    llm = _ScriptedLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    task_text = llm.last_messages[1]["content"]
    assert "No automated scanners against /checkout." in task_text


def test_analyze_task_message_includes_custom_instructions(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {
        "session_id": "usr_analyze_custom", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "custom_instructions": "Focus on the mobile API.",
    }
    llm = _ScriptedLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", {"targets": []}))

    task_text = llm.last_messages[1]["content"]
    assert "Focus on the mobile API." in task_text
