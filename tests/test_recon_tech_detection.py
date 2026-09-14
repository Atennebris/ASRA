"""OS fingerprinting (nmap -O) and CMS/tech fingerprinting (whatweb) must land in
session["recon_result"] deterministically -- the instant the tool returns them -- rather than only
existing if the model also remembers to transcribe them into a separate record_target call. This
also covers the one thing that data actually gates: a tech-gated tool like wpscan must not run
against a host with no real, tool-confirmed technology signal yet (agent/core.py's
_TECH_GATED_TOOLS/_tech_gate_blocked), checked before the real subprocess ever runs, not just
discouraged in a prompt.
"""
import asyncio
import dataclasses
import json

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _run_analyze, _run_recon, _run_tool_with_retry, _tech_gate_blocked
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.registry import TOOL_REGISTRY
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _swap_tool(name, fake_result):
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == name)
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, tool_tier=1, native_function=lambda params: dict(fake_result))
    return index, original_spec


class _ScriptedLLM:
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


_NMAP_STDOUT_WITH_OS = """PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0
OS details: Linux 5.0 - 5.4
"""

_WHATWEB_STDOUT_WORDPRESS = json.dumps([
    "http://example.com", 200,
    [
        ["HTTPServer", [{"string": "Apache/2.4.41", "certainty": 100}]],
        ["WordPress", [{"string": "5.8.1", "certainty": 90}]],
    ],
])


# --- nmap OS guess auto-merge (Recon phase) ---


def test_recon_auto_merges_nmap_os_guess_into_recon_result(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec = _swap_tool("nmap", {"status": "ok", "stdout": _NMAP_STDOUT_WITH_OS})
    try:
        session = {
            "session_id": "usr_os_guess", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        }
        llm = _ScriptedLLM([("nmap", {"target": "example.com"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_recon(ctx, "example.com"))

        assert session["recon_result"]["os_guesses"]["example.com"] == "Linux 5.0 - 5.4"
    finally:
        TOOL_REGISTRY[index] = original_spec


# --- whatweb technologies auto-merge (Analyze phase) ---


def test_analyze_auto_merges_whatweb_technologies_into_recon_result(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec = _swap_tool("whatweb", {"status": "ok", "stdout": _WHATWEB_STDOUT_WORDPRESS})
    try:
        session = {
            "session_id": "usr_tech_merge", "target": "http://example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": {"targets": [], "cves": []},
        }
        llm = _ScriptedLLM([("whatweb", {"target": "http://example.com"})])
        ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

        _run(_run_analyze(ctx, "http://example.com", session["recon_result"]))

        technologies = session["recon_result"]["technologies"]["http://example.com"]
        assert any("WordPress" in tech for tech in technologies)
        assert session["recon_result"]["technology_certainty"]["http://example.com"]["WordPress"] == 90
    finally:
        TOOL_REGISTRY[index] = original_spec


# --- _tech_gate_blocked: pure unit tests (wpscan is the one real entry in _TECH_GATED_TOOLS) ---


def test_wpscan_cms_gate_blocks_when_no_recon_result_at_all():
    assert _tech_gate_blocked({}, "wpscan", {"target": "http://example.com"}) is True


def test_wpscan_cms_gate_blocks_when_technologies_exist_but_no_wordpress():
    session = {"recon_result": {"technologies": {"http://example.com": ["HTTPServer[nginx/1.18.0]"]}}}
    assert _tech_gate_blocked(session, "wpscan", {"target": "http://example.com"}) is True


def test_wpscan_cms_gate_allows_when_wordpress_confirmed_for_that_host():
    session = {"recon_result": {"technologies": {"http://example.com": ["WordPress[5.8.1]"]}}}
    assert _tech_gate_blocked(session, "wpscan", {"target": "http://example.com"}) is False


def test_wpscan_cms_gate_does_not_leak_across_unrelated_hosts():
    session = {"recon_result": {"technologies": {"http://other.com": ["WordPress[5.8.1]"]}}}
    assert _tech_gate_blocked(session, "wpscan", {"target": "http://example.com"}) is True


def test_tech_gate_is_a_no_op_for_a_tool_not_in_the_table():
    session = {"recon_result": {"technologies": {}}}
    assert _tech_gate_blocked(session, "nuclei", {"target": "http://example.com"}) is False


# --- integration: _run_tool_with_retry actually blocks the real wpscan call pre-execution ---


class _FailIfCalledLLM:
    provider_id = "test-provider"
    model = "test-model"
    def complete(self, messages, tools=None, stop_check=None):
        raise AssertionError("no LLM call should be needed for a deterministic pre-execution skip")


def test_run_tool_with_retry_skips_wpscan_without_confirmed_wordpress(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {
        "session_id": "usr_wpscan_blocked", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": [], "cves": [], "technologies": {}},
    }
    ctx = RunContext(llm=_FailIfCalledLLM(), session=session, session_id=session["session_id"])
    spec = next(s for s in TOOL_REGISTRY if s.name == "wpscan")

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "http://example.com"}))

    assert result["status"] == "skipped"
    assert "whatweb" in result["reason"].lower()


def test_run_tool_with_retry_allows_wpscan_once_wordpress_is_confirmed(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec = _swap_tool("wpscan", {"status": "ok", "stdout": "[+] WordPress version 5.8.1 identified.\n"})
    try:
        session = {
            "session_id": "usr_wpscan_allowed", "target": "example.com", "status": "processing",
            "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
            "recon_result": {"targets": [], "cves": [], "technologies": {"http://example.com": ["WordPress[5.8.1]"]}},
        }
        ctx = RunContext(llm=_FailIfCalledLLM(), session=session, session_id=session["session_id"])
        spec = next(s for s in TOOL_REGISTRY if s.name == "wpscan")

        result = _run(_run_tool_with_retry(ctx, spec, {"target": "http://example.com"}))

        assert result["status"] == "ok"
    finally:
        TOOL_REGISTRY[index] = original_spec
