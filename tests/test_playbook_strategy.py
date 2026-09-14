"""Payload templates + LLM strategy synthesis (Unit 4): render_payload_template's {{slot}} filling,
the distillation pass generalizing a concrete payload into a reusable template, and the
playbook_strategy chat tool composing retrieved techniques into one ordered plan (LLM mocked, no
network)."""
import asyncio
import json

import agent.chat as chat
import agent.core as core
from agent.core import RunContext, _run_playbook_distillation_pass
from agent.llm_client import LLMResponse
from agent.tools import playbook_store


def _key(tech, waf=None):
    return json.dumps({"tech": sorted(tech), "waf": sorted(waf or [])}, sort_keys=True)


class _FakeLLM:
    """Provider stub with both embed() (fixed vector) and complete() (fixed content)."""
    provider_id = "test-provider"
    model = "test-model"
    def __init__(self, content="", embed_ok=True):
        self._content = content
        self._embed_ok = embed_ok

    def embed(self, texts, model=None):
        return None if not self._embed_ok else [[0.0, 0.0, 1.0] for _ in texts]

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content=self._content)


# --- render_payload_template ---


def test_render_fills_known_slots():
    tpl = "curl 'https://{{target}}/?{{param}}=payload'"
    out = playbook_store.render_payload_template(tpl, {"target": "site.com", "param": "id"})
    assert out == "curl 'https://site.com/?id=payload'"


def test_render_leaves_unknown_slots_intact():
    tpl = "curl 'https://{{target}}/?{{param}}=x'"
    out = playbook_store.render_payload_template(tpl, {"target": "site.com"})
    assert out == "curl 'https://site.com/?{{param}}=x'"


def test_render_tolerates_whitespace_in_slots():
    assert playbook_store.render_payload_template("{{ target }}", {"target": "x"}) == "x"


def test_render_empty_template_is_empty():
    assert playbook_store.render_payload_template("", {"target": "x"}) == ""


# --- distillation generalizes a payload into a template ---


def test_distillation_stamps_payload_template(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "techniques.json")
    key = _key(["wordpress"])
    playbook_store.record_technique(key, {
        "id": "a1", "technique": "SQLi via double encoding", "times_confirmed": 1,
        "payload_or_command": "curl 'https://victim.com/?s=%2527'", "source_session_ids": ["s1"],
    })
    response = json.dumps({
        "merges": [],
        "templates": [{"id": "a1", "payload_template": "curl 'https://{{target}}/?{{param}}=%2527'"}],
        "local_notes": None,
    })
    session = {"session_id": "usr_tpl", "target": "x", "status": "processing", "logs": [],
               "findings": [], "hypotheses": [], "recon_result": {}, "playbook_touched_keys": [key]}
    ctx = RunContext(llm=_FakeLLM(response), session=session, session_id=session["session_id"])
    monkeypatch.setattr(core, "get_session_folder", lambda session_id: None)

    asyncio.run(_run_playbook_distillation_pass(ctx))

    entry = playbook_store.load_playbook_store()[key][0]
    assert entry["payload_template"] == "curl 'https://{{target}}/?{{param}}=%2527'"


def test_distillation_ignores_template_for_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "techniques.json")
    key = _key(["nginx"])
    playbook_store.record_technique(key, {"id": "real", "technique": "t", "times_confirmed": 1, "source_session_ids": ["s1"]})
    response = json.dumps({"merges": [], "templates": [{"id": "ghost", "payload_template": "x"}], "local_notes": None})
    session = {"session_id": "usr_tpl2", "target": "x", "status": "processing", "logs": [],
               "findings": [], "hypotheses": [], "recon_result": {}, "playbook_touched_keys": [key]}
    ctx = RunContext(llm=_FakeLLM(response), session=session, session_id=session["session_id"])
    monkeypatch.setattr(core, "get_session_folder", lambda session_id: None)

    asyncio.run(_run_playbook_distillation_pass(ctx))

    assert "payload_template" not in playbook_store.load_playbook_store()[key][0]


# --- playbook_strategy chat tool ---


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    monkeypatch.setattr(playbook_store, "PLAYBOOK_EMBEDDINGS_PATH", tmp_path / "playbook" / "embeddings.json")


def test_strategy_composes_from_matches(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    playbook_store.record_technique(_key(["wordpress"]), {"id": "t1", "technique": "double-encode past WAF", "source_session_ids": ["s"]})
    llm = _FakeLLM(content="Step 1: recon. Step 2: double-encode the search param.")
    out = asyncio.run(chat._apply_chat_playbook_strategy({"query": "wordpress rce", "tech_keywords": ["wordpress"]}, llm))
    assert "Attack strategy composed from 1 playbook technique" in out
    assert "double-encode the search param" in out


def test_strategy_reports_when_nothing_stored(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    llm = _FakeLLM(content="unused")
    out = asyncio.run(chat._apply_chat_playbook_strategy({"query": "nothing here", "tech_keywords": ["obscure"]}, llm))
    assert "nothing to build a strategy from" in out


def test_strategy_falls_back_to_raw_matches_on_empty_synthesis(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    playbook_store.record_technique(_key(["nginx"]), {"id": "t1", "technique": "smuggle via TE.CL", "source_session_ids": ["s"]})
    llm = _FakeLLM(content="")  # synthesis returns nothing -> graceful raw list
    out = asyncio.run(chat._apply_chat_playbook_strategy({"query": "nginx smuggling", "tech_keywords": ["nginx"]}, llm))
    assert "couldn't compose a plan" in out
    assert "smuggle via TE.CL" in out


def test_strategy_needs_a_query(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    out = asyncio.run(chat._apply_chat_playbook_strategy({"query": "   "}, _FakeLLM()))
    assert "Describe the target" in out
