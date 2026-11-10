"""Operator-registered "(custom)" tools (agent/tools/custom_tool_runtime.py) becoming real,
model-visible tools for both the main agent and its subagents -- the one guarantee RE_
CAPABILITIES-style roadmap planning explicitly warned not to assume works without checking (custom
ToolSpecs are minted fresh, never part of the static TOOL_REGISTRY, so nothing finds one without
an explicit append at every call site). Same real-phase-function, _CapturingLLM harness as
tests/test_toolkit_agent_access.py -- verifies the SCHEMA the model actually receives, not just
that the underlying _custom_tool_extras() helper returns the right names in isolation.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _delegate_to_subagent_impl,
    _run_analyze,
    _run_exploit_for_finding,
    _run_recon,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import custom_tools_store as cts
from agent.tools import subagent_store
from agent.tools.registry import get_tools_by_category
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(cts, "CUSTOM_TOOLS_STORE_PATH", tmp_path / "custom_tools.json")
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _register(category: str, *, enabled: bool = True) -> dict:
    record = cts.add_custom_tool(name="mycustomtool", path="/opt/tools/mycustomtool", description="d", requires_target=False, category=category)
    if not enabled:
        cts.set_custom_tool_enabled(record["id"], False)
    return record


class _CapturingLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, final_response: LLMResponse):
        self._final_response = final_response
        self.captured_tool_names: list[set] = []

    def complete(self, messages, tools=None, stop_check=None):
        self.captured_tool_names.append({t["function"]["name"] for t in (tools or [])})
        return self._final_response


def test_recon_phase_offers_an_enabled_recon_category_custom_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _register("recon")
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_recon_custom_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    assert "mycustomtool" in llm.captured_tool_names[0]


def test_recon_phase_never_offers_a_disabled_custom_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _register("recon", enabled=False)
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_recon_custom_disabled_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    assert "mycustomtool" not in llm.captured_tool_names[0]


def test_recon_phase_never_offers_an_re_only_custom_tool(tmp_path, monkeypatch):
    """A custom tool scoped to "re" must not leak into an ordinary web-pentest phase -- same
    scoping get_tools_by_category itself already gives every other "re" tool."""
    _isolate(tmp_path, monkeypatch)
    _register("re")
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_recon_custom_re_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    assert "mycustomtool" not in llm.captured_tool_names[0]


def test_analyze_phase_offers_an_enabled_scan_category_custom_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _register("scan")
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_analyze_custom_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", {"targets": [], "cves": []}))

    assert "mycustomtool" in llm.captured_tool_names[0]


def test_exploit_for_finding_offers_an_enabled_exploit_category_custom_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _register("exploit")
    llm = _CapturingLLM(LLMResponse(
        content=None,
        tool_calls=[ToolCallRequest(id="c1", name="record_exploit_decision", arguments={"action": "skipped_no_suitable_tool"})],
    ))
    session = {"session_id": "usr_exploit_custom_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    finding = {"title": "Test Finding", "verification": "verified"}
    exploit_tools = get_tools_by_category("exploit")

    _run(_run_exploit_for_finding(ctx, "example.com", finding, exploit_tools))

    assert "mycustomtool" in llm.captured_tool_names[0]


def test_a_custom_category_tool_is_offered_in_every_ordinary_phase(tmp_path, monkeypatch):
    """The operator-facing "not sure which bucket fits" choice -- must reach recon, scan, AND
    exploit all at once (custom_tool_runtime.py's own _category_for expansion)."""
    _isolate(tmp_path, monkeypatch)
    _register("custom")
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))

    recon_session = {"session_id": "usr_recon_custom_cat_test", "logs": [], "findings": []}
    _run(_run_recon(RunContext(llm=llm, session=recon_session, session_id=recon_session["session_id"]), "example.com"))
    assert "mycustomtool" in llm.captured_tool_names[-1]

    analyze_session = {"session_id": "usr_analyze_custom_cat_test", "logs": [], "findings": []}
    _run(_run_analyze(RunContext(llm=llm, session=analyze_session, session_id=analyze_session["session_id"]), "example.com", {"targets": [], "cves": []}))
    assert "mycustomtool" in llm.captured_tool_names[-1]


# --- subagent delegation: unconditional, not category-filtered ----------------------------------


def _profile_with_tools(name: str, allowed_tools: list[str]) -> dict:
    profile_store = subagent_store.add_profile(name, allowed_tools, "", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    return subagent_store.update_profile(profile_id, enabled=True)


async def _delegate_and_await_completion(session: dict, subagent_name: str) -> None:
    from agent.tools import subagent_tasks
    result = await _delegate_to_subagent_impl({
        "_session_id": session["session_id"], "_session": session,
        "subagent_name": subagent_name, "task_description": "do something",
    })
    assert result["status"] == "ok", result
    task = subagent_tasks._RUNNING_SUBAGENT_TASKS[result["task_id"]]
    await task


def test_subagent_gets_an_enabled_custom_tool_even_though_its_profile_never_named_it(tmp_path, monkeypatch):
    """Real, confirmed gap this guards against: a subagent profile's own allowed_tools checklist
    (Settings -> Subagents) has no UI path to ever name a dynamically-minted custom tool at all --
    _custom_tool_extras() is appended to every subagent's own toolset unconditionally, same
    "operator turned it on, it should just work everywhere" principle as the main agent's own
    category-scoped access, not something a profile has to opt into per tool."""
    _isolate(tmp_path, monkeypatch)
    _register("recon")
    _profile_with_tools("Recon Bot", [])  # deliberately empty -- never names the custom tool

    llm = _CapturingLLM(LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="report_subagent_result", arguments={"summary": "done"})]))
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: llm)
    session = {"session_id": "usr_subagent_custom_test", "logs": [], "subagent_tasks": {}}

    _run(_delegate_and_await_completion(session, "Recon Bot"))

    assert llm.captured_tool_names
    assert "mycustomtool" in llm.captured_tool_names[0]


def test_subagent_never_gets_a_disabled_custom_tool(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _register("recon", enabled=False)
    _profile_with_tools("Recon Bot", [])

    llm = _CapturingLLM(LLMResponse(content=None, tool_calls=[ToolCallRequest(id="c1", name="report_subagent_result", arguments={"summary": "done"})]))
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: llm)
    session = {"session_id": "usr_subagent_custom_disabled_test", "logs": [], "subagent_tasks": {}}

    _run(_delegate_and_await_completion(session, "Recon Bot"))

    assert llm.captured_tool_names
    assert "mycustomtool" not in llm.captured_tool_names[0]
