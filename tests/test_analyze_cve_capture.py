"""cve_lookup results get captured into session.recon_result.cves during Analyze — regression
test for a real bug: the tool is registered category="scan" (only Analyze's tool set includes
it, matching ANALYZE_PROMPT's own instruction to use it there), but the capture hook used to sit
in _run_recon's execute() instead, where the model never had cve_lookup in its schema at all and
so could never trigger it. Moved to _run_analyze; this pins the fix down directly.
"""
import asyncio
import dataclasses

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_analyze
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import TOOL_REGISTRY
from sessions import store


def _run(coro):
    return asyncio.run(coro)


class _ScriptedLLM:
    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def test_cve_lookup_is_available_during_analyze_not_recon():
    """The actual bug: which phase's tool set includes cve_lookup at all."""
    from agent.tools.registry import get_tools_by_category

    recon_names = {spec.name for spec in get_tools_by_category("recon")}
    scan_names = {spec.name for spec in get_tools_by_category("scan")}
    assert "cve_lookup" in scan_names
    assert "cve_lookup" not in recon_names


def test_cve_lookup_result_lands_in_recon_result_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    # ToolSpec is a frozen dataclass — can't monkeypatch an attribute on the instance itself,
    # swap the whole registry entry for one with a fake native_function instead (TOOL_REGISTRY
    # is a plain list, not a Mapping, so this is a manual save/restore, not monkeypatch.setitem).
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == "cve_lookup")
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(
        original_spec,
        native_function=lambda params: {"status": "ok", "cve_ids": ["CVE-2019-10758", "CVE-2018-16487"]},
    )
    try:
        session = {
            "session_id": "usr_cve_test", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        llm = _ScriptedLLM([("cve_lookup", {"product": "mongoose-os"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "example.com", {"targets": []}))

        assert session["recon_result"]["cves"] == ["CVE-2018-16487", "CVE-2019-10758"]
    finally:
        TOOL_REGISTRY[index] = original_spec
