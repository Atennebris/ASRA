"""record_host_relationship (agent/tools/native.py) + its persistence hook,
_record_agent_relationship (agent/core.py) -- the high-fidelity, agent-authored sibling of the Map
tab's chain_attempts-derived attack_path edges: an explicit "I proved a real pivot from A to B"
assertion with a real mechanism label and evidence, recorded the moment it's proven rather than
reconstructed after an entire Chain pass concludes. Also covers _record_tls_cert_info, the same
kind of deterministic bookkeeping for ssl_cert_info's own real TLS handshake (feeds the Map tab's
shared_surface edges, see tests/test_attack_surface_graph.py for the graph-building side of both).
"""
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _record_agent_relationship, _record_tls_cert_info
from agent.tools.native import record_host_relationship
from agent.tools.registry import get_tool
from sessions import store


def _make_session():
    return {
        "session_id": "usr_relationship_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "hypotheses": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": []},
    }


def _ctx(session):
    return RunContext(llm=object(), session=session, session_id=session["session_id"])


# ---- record_host_relationship (native function validation) ------------------------------------

def test_record_host_relationship_requires_source_host():
    result = record_host_relationship({"target_host": "b.example.com", "mechanism": "SSRF", "evidence": "proof"})
    assert result["status"] == "error"
    assert "source_host" in result["error"]


def test_record_host_relationship_requires_target_host():
    result = record_host_relationship({"source_host": "a.example.com", "mechanism": "SSRF", "evidence": "proof"})
    assert result["status"] == "error"
    assert "target_host" in result["error"]


def test_record_host_relationship_rejects_the_same_host_on_both_sides():
    result = record_host_relationship({
        "source_host": "a.example.com", "target_host": "a.example.com", "mechanism": "SSRF", "evidence": "proof",
    })
    assert result["status"] == "error"


def test_record_host_relationship_requires_mechanism():
    result = record_host_relationship({"source_host": "a.example.com", "target_host": "b.example.com", "evidence": "proof"})
    assert result["status"] == "error"
    assert "mechanism" in result["error"]


def test_record_host_relationship_requires_evidence():
    result = record_host_relationship({"source_host": "a.example.com", "target_host": "b.example.com", "mechanism": "SSRF"})
    assert result["status"] == "error"
    assert "evidence" in result["error"]


def test_record_host_relationship_accepts_a_well_formed_call():
    result = record_host_relationship({
        "source_host": "a.example.com", "target_host": "b.example.com",
        "mechanism": "leaked credentials", "evidence": "authenticated_request with the leaked pair succeeded",
    })
    assert result == {
        "status": "ok",
        "source_host": "a.example.com", "target_host": "b.example.com",
        "mechanism": "leaked credentials", "evidence": "authenticated_request with the leaked pair succeeded",
    }


def test_record_host_relationship_is_registered_under_the_exploit_category():
    # category="exploit" (not "post_exploit" like record_chain_result) is deliberate -- it must
    # reach get_tools_by_category("exploit")'s every real consumer (Exploit's own tool list,
    # Chain's -- built FROM the exploit category, interactive/chat mode), not just Chain.
    spec = get_tool("record_host_relationship")
    assert spec is not None
    assert spec.category == "exploit"


# ---- _record_agent_relationship (persistence hook) ---------------------------------------------

def test_record_agent_relationship_appends_to_session(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)
    result = {
        "status": "ok", "source_host": "a.example.com", "target_host": "b.example.com",
        "mechanism": "SSRF", "evidence": "real proof",
    }

    _record_agent_relationship(ctx, get_tool("record_host_relationship"), result)

    relationships = ctx.session["agent_relationships"]
    assert len(relationships) == 1
    entry = relationships[0]
    assert entry["source_host"] == "a.example.com"
    assert entry["target_host"] == "b.example.com"
    assert entry["mechanism"] == "SSRF"
    assert entry["evidence"] == "real proof"
    assert entry["recorded_at"]  # a real timestamp was stamped, not left blank


def test_record_agent_relationship_ignores_an_unrelated_tool(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)

    _record_agent_relationship(ctx, get_tool("record_finding"), {"status": "ok"})

    assert "agent_relationships" not in ctx.session


def test_record_agent_relationship_ignores_an_error_result(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)

    _record_agent_relationship(ctx, get_tool("record_host_relationship"), {"status": "error", "error": "x"})

    assert "agent_relationships" not in ctx.session


def test_record_agent_relationship_keeps_two_distinct_pivots_between_the_same_pair(tmp_path, monkeypatch):
    # Deliberately not deduplicated like _update_asset_graph's own credential list -- a real pivot
    # proven twice, via two different mechanisms, is two genuinely different facts worth keeping.
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)
    spec = get_tool("record_host_relationship")

    _record_agent_relationship(ctx, spec, {
        "status": "ok", "source_host": "a.example.com", "target_host": "b.example.com",
        "mechanism": "SSRF", "evidence": "first proof",
    })
    _record_agent_relationship(ctx, spec, {
        "status": "ok", "source_host": "a.example.com", "target_host": "b.example.com",
        "mechanism": "leaked credentials", "evidence": "second proof",
    })

    assert len(ctx.session["agent_relationships"]) == 2


# ---- _record_tls_cert_info (persistence hook) --------------------------------------------------

def test_record_tls_cert_info_captures_subject_alt_names(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)
    result = {"status": "ok", "subject_alt_names": ["*.example.com", "example.com"]}

    _record_tls_cert_info(ctx, get_tool("ssl_cert_info"), {"target": "a.example.com"}, result)

    assert ctx.session["recon_result"]["tls_sans"]["a.example.com"] == ["*.example.com", "example.com"]


def test_record_tls_cert_info_ignores_a_failed_handshake(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _make_session()
    ctx = _ctx(session)

    _record_tls_cert_info(ctx, get_tool("ssl_cert_info"), {"target": "a.example.com"}, {"status": "error", "error": "x"})

    assert "tls_sans" not in ctx.session["recon_result"]
