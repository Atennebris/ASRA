"""Playbook semantic (RAG) search: cosine, the embeddings store, hybrid retrieval, embed-on-write,
the query_playbook chat tool, and the re-embed route. Embeddings are mocked (a fake provider),
so nothing here makes a real network call -- and the graceful keyword fallback is pinned too."""
import json

import pytest
from fastapi.testclient import TestClient

import agent.chat as chat
import agent.core as core
import main
from agent.tools import playbook_store


class _FakeEmbedLLM:
    """A provider whose embed() returns a fixed vector per input text (via a lookup), or None to
    simulate a provider with no embeddings endpoint."""
    def __init__(self, table=None, unavailable=False):
        self.table = table or {}
        self.unavailable = unavailable

    def embed(self, texts, model=None):
        if self.unavailable:
            return None
        return [self.table.get(t, [0.0, 0.0, 1.0]) for t in texts]


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(playbook_store, "PLAYBOOK_STORE_PATH", tmp_path / "playbook" / "techniques.json")
    monkeypatch.setattr(playbook_store, "PLAYBOOK_EMBEDDINGS_PATH", tmp_path / "playbook" / "embeddings.json")


def _key(tech, waf=None):
    return json.dumps({"tech": sorted(tech), "waf": sorted(waf or [])}, sort_keys=True)


# --- cosine + embeddings store ---


def test_cosine_basics():
    assert playbook_store._cosine([1, 0], [1, 0]) == pytest.approx(1.0)
    assert playbook_store._cosine([1, 0], [0, 1]) == pytest.approx(0.0)
    assert playbook_store._cosine([], [1]) == 0.0


def test_store_and_count_embeddings_and_model_change_invalidates():
    playbook_store.store_embeddings({"a": [1, 0, 0], "b": [0, 1, 0]}, "m1")
    assert playbook_store.embeddings_count() == 2
    # same model merges
    playbook_store.store_embeddings({"c": [0, 0, 1]}, "m1")
    assert playbook_store.embeddings_count() == 3
    # a different model drops the old vectors first
    playbook_store.store_embeddings({"d": [1, 1, 0]}, "m2")
    assert playbook_store.embeddings_count() == 1
    assert playbook_store.load_embeddings()["_model"] == "m2"


def test_missing_embeddings_lists_unembedded_ids():
    playbook_store.record_technique(_key(["nginx"]), {"id": "t1", "technique": "a", "source_session_ids": ["s"]})
    playbook_store.record_technique(_key(["nginx"]), {"id": "t2", "technique": "b", "source_session_ids": ["s"]})
    playbook_store.store_embeddings({"t1": [1, 0, 0]}, "m1")
    assert playbook_store.technique_ids_missing_embeddings() == ["t2"]


# --- hybrid retrieval ---


def test_semantic_surfaces_a_technique_with_no_keyword_overlap():
    # technique keyed to nginx, queried with php (no keyword overlap) -- only its embedding matches
    playbook_store.record_technique(_key(["nginx"]), {"id": "t1", "technique": "origin exposure", "source_session_ids": ["s"]})
    playbook_store.store_embeddings({"t1": [1.0, 0.0, 0.0]}, "m1")

    keyword_only = playbook_store.find_similar_techniques({"php"}, set(), 5)
    assert keyword_only == []  # no keyword overlap -> nothing without semantics

    hybrid = playbook_store.find_similar_techniques({"php"}, set(), 5, query_embedding=[1.0, 0.0, 0.0])
    assert [m["id"] for m in hybrid] == ["t1"]  # meaning match pulls it in


def test_semantic_ranks_the_closer_meaning_higher():
    playbook_store.record_technique(_key(["nginx"]), {"id": "close", "technique": "x", "source_session_ids": ["s"]})
    playbook_store.record_technique(_key(["nginx"]), {"id": "far", "technique": "y", "source_session_ids": ["s"]})
    playbook_store.store_embeddings({"close": [1.0, 0.0, 0.0], "far": [0.0, 1.0, 0.0]}, "m1")

    matches = playbook_store.find_similar_techniques({"nginx"}, set(), 5, query_embedding=[0.95, 0.05, 0.0])
    assert matches[0]["id"] == "close"


# --- embed-on-write + fallback ---


def test_embed_playbook_entries_stores_vectors():
    playbook_store.record_technique(_key(["nginx"]), {"id": "t1", "technique": "double encode", "source_session_ids": ["s"]})
    entries = playbook_store.list_all_techniques()
    n = core._embed_playbook_entries(_FakeEmbedLLM(), entries)
    assert n == 1
    assert playbook_store.embeddings_count() == 1


def test_embed_playbook_entries_noop_when_provider_has_no_embeddings():
    playbook_store.record_technique(_key(["nginx"]), {"id": "t1", "technique": "x", "source_session_ids": ["s"]})
    n = core._embed_playbook_entries(_FakeEmbedLLM(unavailable=True), playbook_store.list_all_techniques())
    assert n == 0
    assert playbook_store.embeddings_count() == 0


def test_embed_query_returns_none_without_embeddings():
    assert core._embed_playbook_query(_FakeEmbedLLM(unavailable=True), "some query") is None
    assert core._embed_playbook_query(_FakeEmbedLLM(), "some query") == [0.0, 0.0, 1.0]


# --- query_playbook tool ---


def test_query_playbook_tool_semantic_hit():
    playbook_store.record_technique(_key(["nginx"]), {"id": "t1", "technique": "recover origin behind CDN", "source_session_ids": ["s"]})
    playbook_store.store_embeddings({"t1": [1.0, 0.0, 0.0]}, "m1")
    llm = _FakeEmbedLLM(table={"how to get the real IP": [1.0, 0.0, 0.0]})
    out = chat._apply_chat_query_playbook({"query": "how to get the real IP"}, llm)
    assert "semantic search" in out
    assert "recover origin behind CDN" in out


def test_query_playbook_tool_keyword_fallback_without_embeddings():
    playbook_store.record_technique(_key(["wordpress"]), {"id": "t1", "technique": "wp bug", "source_session_ids": ["s"]})
    out = chat._apply_chat_query_playbook({"query": "wordpress issue"}, _FakeEmbedLLM(unavailable=True))
    assert "keyword search" in out
    assert "wp bug" in out


# --- reembed route ---


def test_reembed_route_backfills_missing(monkeypatch):
    playbook_store.record_technique(_key(["nginx"]), {"id": "t1", "technique": "a", "source_session_ids": ["s"]})
    monkeypatch.setattr(main, "get_provider", lambda *a, **k: _FakeEmbedLLM())
    client = TestClient(main.app)
    resp = client.post("/api/playbook/reembed")
    assert resp.status_code == 200
    assert playbook_store.embeddings_count() == 1
