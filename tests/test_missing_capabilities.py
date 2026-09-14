"""_record_missing_capability (agent/core.py): durable "the agent needed X, wasn't installed"
records, generic over whatever X is (not python2-specific) -- a tool opts in simply by putting a
"capability" key on its own tool_unavailable result. Linked to whichever finding/hypothesis was
active (ctx.current_finding_title/current_hypothesis_id) so the Summary tab card can point at the
exact existing Deep-dive/"Investigate now" button for it.
"""
import asyncio
import dataclasses

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _record_missing_capability, _run_tool_with_retry, run_hypothesis_verification
from agent.tools import allowed_targets
from agent.tools.allowed_targets import add_allowed_target
from agent.tools.registry import TOOL_REGISTRY, get_tool
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _make_session():
    return {
        "session_id": "usr_missing_cap_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "hypotheses": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "missing_capabilities": [],
    }


def _ctx(session):
    return RunContext(llm=object(), session=session, session_id=session["session_id"])


def _spec(name):
    return get_tool(name)


def test_records_a_capability_shaped_tool_unavailable_result(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)
    result = {"status": "tool_unavailable", "tool": "exploit_db_run", "capability": "python2", "error": "'python2' is not installed"}

    _record_missing_capability(ctx, _spec("exploit_db_run"), result)

    entries = ctx.session["missing_capabilities"]
    assert len(entries) == 1
    assert entries[0]["capability"] == "python2"
    assert entries[0]["tool_name"] == "exploit_db_run"
    assert entries[0]["needed_for"] == "'python2' is not installed"
    assert entries[0]["finding_title"] is None
    assert entries[0]["hypothesis_id"] is None
    assert entries[0]["created_at"]


def test_ignores_tool_unavailable_without_a_capability_key(tmp_path, monkeypatch):
    """arjun/oob_generate's own unrelated tool_unavailable results must stay untouched -- only a
    tool that explicitly opts in via "capability" gets recorded here."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)

    _record_missing_capability(ctx, _spec("arjun"), {"status": "tool_unavailable", "tool": "arjun"})

    assert ctx.session["missing_capabilities"] == []


def test_ignores_a_capability_key_on_a_non_tool_unavailable_result(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)

    _record_missing_capability(ctx, _spec("exploit_db_run"), {"status": "ok", "capability": "python2"})

    assert ctx.session["missing_capabilities"] == []


def test_links_the_finding_being_worked_when_it_happened(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)
    ctx.current_finding_title = "Legacy PoC RCE"

    _record_missing_capability(ctx, _spec("exploit_db_run"), {"status": "tool_unavailable", "capability": "python2"})

    assert ctx.session["missing_capabilities"][0]["finding_title"] == "Legacy PoC RCE"
    assert ctx.session["missing_capabilities"][0]["hypothesis_id"] is None


def test_links_the_hypothesis_being_worked_when_it_happened(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)
    ctx.current_hypothesis_id = "hyp_abc123"

    _record_missing_capability(ctx, _spec("exploit_db_run"), {"status": "tool_unavailable", "capability": "python2"})

    assert ctx.session["missing_capabilities"][0]["hypothesis_id"] == "hyp_abc123"
    assert ctx.session["missing_capabilities"][0]["finding_title"] is None


def test_persists_to_disk(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    store.save_session(session["session_id"], session)
    ctx = _ctx(session)

    _record_missing_capability(ctx, _spec("exploit_db_run"), {"status": "tool_unavailable", "capability": "python2"})

    reloaded = store.load_session(session["session_id"])
    assert len(reloaded["missing_capabilities"]) == 1
    assert reloaded["missing_capabilities"][0]["capability"] == "python2"


def _swap_tool(name, fake_result):
    """Same fake-native-function-swap pattern as tests/test_asset_graph.py -- exercises the real
    _run_tool_with_retry call path, not just the unit-level _record_missing_capability calls above."""
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == name)
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, tool_tier=1, native_function=lambda params: dict(fake_result))
    return index, original_spec


def test_real_tool_unavailable_call_reaches_the_session_via_run_tool_with_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    add_allowed_target("example.com")
    index, original_spec = _swap_tool("exploit_db_run", {"status": "tool_unavailable", "tool": "exploit_db_run", "capability": "python2", "error": "'python2' is not installed"})
    try:
        session = _make_session()
        ctx = _ctx(session)
        result = _run(_run_tool_with_retry(ctx, TOOL_REGISTRY[index], {"edb_id": "1", "target": "example.com", "args": []}))
    finally:
        TOOL_REGISTRY[index] = original_spec

    assert result["status"] == "tool_unavailable"
    assert ctx.session["missing_capabilities"][0]["capability"] == "python2"


def test_run_hypothesis_verification_sets_and_clears_current_hypothesis_id(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session_id = store.create_session("example.com", name="hyp-ctx-test")
    session = store.load_session(session_id)
    session["hypotheses"].append({
        "id": "hyp_xyz", "text": "test hypothesis", "evidence": "", "source_phase": "pre_scan",
        "source": "user", "status": "unconfirmed", "resolution_note": None,
        "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
    })
    store.save_session(session_id, session)

    captured = {}

    async def _fake_run_llm_tool_loop(ctx, *args, **kwargs):
        captured["hypothesis_id_during_run"] = ctx.current_hypothesis_id

    monkeypatch.setattr("agent.core._run_llm_tool_loop", _fake_run_llm_tool_loop)

    _run(run_hypothesis_verification(session_id, hypothesis_id="hyp_xyz"))

    assert captured["hypothesis_id_during_run"] == "hyp_xyz"
