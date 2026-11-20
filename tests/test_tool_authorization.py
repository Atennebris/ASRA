"""Default-deny tool authorization (agent/tools/tool_authorization.py, enforced at the top of
agent/core.py's _run_tool_with_retry -- the one funnel every agent tool execution passes through).

A tool runs only if it is the exact ToolSpec registered under its name, or an enabled operator
custom tool; an external-provider (mcp_ namespace) tool never auto-runs even when registered, until
the operator lists it in ASRA_ALLOWED_EXTERNAL_TOOLS. A refused tool must never execute and must
come back with an explicit reason, not a bare error.
"""
import asyncio
import json
from dataclasses import replace

import pytest

import agent.tools.custom_tools_store as custom_tools_store
from agent.core import RunContext, _run_tool_with_retry
from agent.tools.custom_tool_runtime import build_dynamic_toolspecs
from agent.tools.registry import ToolSpec, get_tool
from agent.tools.tool_authorization import authorization_block_result, unrecognized_tool_reason


def _run(coro):
    return asyncio.run(coro)


def _ctx(session_id: str = "usr_tool_auth_test") -> RunContext:
    session = {"session_id": session_id, "logs": []}
    return RunContext(llm=None, session=session, session_id=session_id)


def _spy_spec(name: str, calls: list) -> ToolSpec:
    def native(params):
        calls.append(params)
        return {"status": "ok", "ran": True}

    return ToolSpec(
        name=name, category="recon", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True, native_function=native,
    )


@pytest.fixture
def custom_store(tmp_path, monkeypatch):
    path = tmp_path / "custom_tools.json"
    monkeypatch.setattr(custom_tools_store, "CUSTOM_TOOLS_STORE_PATH", path)
    return path


def _write_custom_record(path, *, enabled: bool, name: str = "my_scanner", tool_path: str = "/opt/tools/my_scanner"):
    record = {
        "id": "ct_1", "name": name, "path": tool_path, "description": "operator tool",
        "requires_target": False, "category": "recon", "enabled": enabled,
    }
    path.write_text(json.dumps([record]), encoding="utf-8")
    return record


def test_a_registered_builtin_tool_is_authorized():
    assert unrecognized_tool_reason(get_tool("decode_value")) is None


def test_a_registered_builtin_tool_still_runs_through_the_dispatch_funnel():
    result = _run(_run_tool_with_retry(_ctx(), get_tool("decode_value"), {"scheme": "base64", "mode": "encode", "text": "hi"}))

    assert result["status"] == "ok"
    assert result["result"] == "aGk="


def test_an_unregistered_tool_is_refused_and_never_executes():
    calls: list = []
    spec = _spy_spec("totally_fabricated_tool", calls)

    result = _run(_run_tool_with_retry(_ctx(), spec, {"target": "example.com"}))

    assert calls == []
    assert result["status"] == "blocked"
    assert result["tool"] == "totally_fabricated_tool"
    assert "not a recognized ASRA tool" in result["reason"]
    assert "platform policy" in result["reason"]


def test_a_spec_reusing_a_registered_name_does_not_inherit_its_trust():
    calls: list = []
    impostor = replace(get_tool("decode_value"), native_function=lambda params: calls.append(params) or {"status": "ok"})

    result = _run(_run_tool_with_retry(_ctx(), impostor, {"scheme": "base64", "mode": "encode", "text": "hi"}))

    assert calls == []
    assert result["status"] == "blocked"
    assert "reusing a registered name" in result["reason"]


def test_an_external_provider_tool_is_blocked_even_when_registered(register_test_tool, monkeypatch):
    monkeypatch.delenv("ASRA_ALLOWED_EXTERNAL_TOOLS", raising=False)
    calls: list = []
    spec = register_test_tool(_spy_spec("mcp_someserver_list_files", calls))

    result = _run(_run_tool_with_retry(_ctx(), spec, {}))

    assert calls == []
    assert result["status"] == "blocked"
    assert "external tool provider" in result["reason"]


def test_an_external_provider_tool_runs_once_the_operator_allows_it(register_test_tool, monkeypatch):
    calls: list = []
    spec = register_test_tool(_spy_spec("mcp_someserver_list_files", calls))
    monkeypatch.setenv("ASRA_ALLOWED_EXTERNAL_TOOLS", "mcp_other_tool, mcp_someserver_list_files")

    result = _run(_run_tool_with_retry(_ctx(), spec, {}))

    assert result["status"] == "ok"
    assert len(calls) == 1


def test_an_allowlisted_external_name_still_needs_to_be_the_registered_tool(monkeypatch):
    monkeypatch.setenv("ASRA_ALLOWED_EXTERNAL_TOOLS", "mcp_someserver_list_files")
    calls: list = []

    result = authorization_block_result(_spy_spec("mcp_someserver_list_files", calls))

    assert result is not None and result["status"] == "blocked"


def test_an_enabled_custom_tool_is_authorized(custom_store):
    _write_custom_record(custom_store, enabled=True)
    (spec,) = build_dynamic_toolspecs()

    assert unrecognized_tool_reason(spec) is None


def test_a_custom_tool_disabled_after_its_spec_was_minted_is_refused(custom_store):
    record = _write_custom_record(custom_store, enabled=True)
    (spec,) = build_dynamic_toolspecs()
    custom_store.write_text(json.dumps([{**record, "enabled": False}]), encoding="utf-8")

    assert unrecognized_tool_reason(spec) is not None


def test_a_custom_tool_whose_path_changed_is_refused(custom_store):
    record = _write_custom_record(custom_store, enabled=True)
    (spec,) = build_dynamic_toolspecs()
    custom_store.write_text(json.dumps([{**record, "path": "/opt/tools/something_else"}]), encoding="utf-8")

    assert unrecognized_tool_reason(spec) is not None
