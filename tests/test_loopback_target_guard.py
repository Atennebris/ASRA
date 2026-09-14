"""Loopback/link-local target guard (agent/core.py's _loopback_or_link_local_target, wired into
_run_tool_with_retry) -- a real, code-level skip, not just a prompt suggestion the model could
ignore. Real incident this fixes: a model chasing a cPanel-origin lead called tcp_port_check with
target="127.0.0.1" instead of the real host -- it silently "succeeded", probing the agent's own
machine and telling the model nothing about the actual scan target. See also
tests/test_out_of_scope.py, whose _run_tool_with_retry-level test this mirrors.
"""
import asyncio

from agent.core import RunContext, _loopback_or_link_local_target, _run_tool_with_retry
from agent.tools.registry import ToolSpec
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def test_loopback_or_link_local_target_matches_ipv4_loopback():
    assert _loopback_or_link_local_target({"target": "127.0.0.1"}) == "127.0.0.1"


def test_loopback_or_link_local_target_matches_ipv6_loopback():
    assert _loopback_or_link_local_target({"target": "::1"}) == "::1"


def test_loopback_or_link_local_target_matches_link_local_and_cloud_metadata():
    assert _loopback_or_link_local_target({"host": "169.254.169.254"}) == "169.254.169.254"


def test_loopback_or_link_local_target_ignores_a_real_hostname():
    assert _loopback_or_link_local_target({"target": "https://insanitycheats.com/"}) is None


def test_loopback_or_link_local_target_does_not_block_private_rfc1918_ranges():
    # A private IP can be a real, in-scope target for an internal-network engagement, unlike a
    # loopback or link-local address, which never legitimately is.
    assert _loopback_or_link_local_target({"target": "192.168.1.5"}) is None
    assert _loopback_or_link_local_target({"target": "10.0.0.5"}) is None


def test_loopback_or_link_local_target_returns_none_when_no_target_shaped_key_present():
    assert _loopback_or_link_local_target({"domain": "example.com"}) is None


def _make_tool(name: str = "tcp_port_check") -> ToolSpec:
    return ToolSpec(
        name=name, category="scan", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True,
        native_function=lambda args: {"status": "ok", "tool": name, "called_with": args},
    )


def test_run_tool_with_retry_skips_a_call_against_a_loopback_target(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {"session_id": "usr_loopback_test", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = _make_tool()

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "127.0.0.1", "port": 2077}))

    assert result["status"] == "skipped"
    assert "loopback" in result["reason"]


def test_run_tool_with_retry_runs_normally_for_a_real_target(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = {"session_id": "usr_loopback_clear", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    spec = _make_tool()

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "insanitycheats.com", "port": 443}))

    assert result["status"] == "ok"
