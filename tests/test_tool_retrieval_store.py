"""Tool-retrieval / routing layer (agent/tools/tool_retrieval_store.py, item 3 of the
tool-selection roadmap): the top-K candidate shortlist that blends into agent/core.py's
_apply_plan_recommendations as its own (c) signal alongside (a) model-recommended and (b) learned
tool-affinity. Embeddings are mocked (a fake provider, same shape as test_playbook_semantic.py's
own _FakeEmbedLLM) -- nothing here makes a real network call, and the keyword-only fallback when
there's no provider at all is pinned too.
"""
import pytest

from agent.tools import tool_retrieval_store
from agent.tools.registry import ToolSpec


class _CountingFakeEmbedLLM:
    """A provider whose embed() buckets each input text's vector by a keyword it contains, so
    semantic similarity is fully deterministic and controllable per test -- and counts how many
    times it was actually called, to prove ensure_index() skips tools already indexed."""
    def __init__(self):
        self.calls = 0

    def embed(self, texts, model=None):
        self.calls += 1
        vectors = []
        for t in texts:
            low = t.lower()
            if "network" in low or "port" in low:
                vectors.append([1.0, 0.0, 0.0])
            elif "sql" in low or "inject" in low:
                vectors.append([0.0, 1.0, 0.0])
            elif "whois" in low or "domain" in low:
                vectors.append([0.0, 0.0, 1.0])
            else:
                vectors.append([0.33, 0.33, 0.34])
        return vectors


class _UnavailableEmbedLLM:
    def embed(self, texts, model=None):
        return None


def _tool(name, description, category="recon"):
    return ToolSpec(
        name=name, category=category, tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"}, description=description,
    )


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_retrieval_store, "TOOL_RETRIEVAL_STORE_PATH", tmp_path / "tool_retrieval" / "embeddings.json")
    tool_retrieval_store._QUERY_EMBED_CACHE.clear()
    tool_retrieval_store._LAST_LOGGED_SHORTLIST.clear()
    tool_retrieval_store._LAST_LOGGED_MULTISTEP_SHORTLIST.clear()
    monkeypatch.delenv("TOOL_RETRIEVAL_ENABLED", raising=False)
    monkeypatch.delenv("TOOL_RETRIEVAL_TOP_K", raising=False)
    monkeypatch.delenv("TOOL_RETRIEVAL_LOOKAHEAD_STEPS", raising=False)


# --- env knobs ---


def test_is_enabled_defaults_true_and_respects_the_env_flag(monkeypatch):
    assert tool_retrieval_store.is_enabled() is True
    monkeypatch.setenv("TOOL_RETRIEVAL_ENABLED", "false")
    assert tool_retrieval_store.is_enabled() is False


def test_top_k_defaults_and_is_env_overridable(monkeypatch):
    assert tool_retrieval_store._top_k() == 8
    monkeypatch.setenv("TOOL_RETRIEVAL_TOP_K", "3")
    assert tool_retrieval_store._top_k() == 3
    monkeypatch.setenv("TOOL_RETRIEVAL_TOP_K", "not-a-number")
    assert tool_retrieval_store._top_k() == 8  # bad value falls back to the default


def test_build_tool_embedding_text_carries_name_and_description():
    spec = _tool("port_scanner", "Scans network ports and services on a host")
    text = tool_retrieval_store.build_tool_embedding_text(spec)
    assert "port_scanner" in text
    assert "network ports" in text


# --- ensure_index: embeds once, refreshes on a model change, degrades gracefully ---


def test_ensure_index_embeds_missing_tools_and_persists():
    llm = _CountingFakeEmbedLLM()
    specs = [_tool("port_scanner", "Scans network ports and services")]
    embedded = tool_retrieval_store.ensure_index(llm, specs)
    assert embedded == 1
    assert llm.calls == 1
    stored = tool_retrieval_store.load_tool_vectors()
    assert "port_scanner" in stored


def test_ensure_index_skips_tools_already_embedded():
    llm = _CountingFakeEmbedLLM()
    specs = [_tool("port_scanner", "Scans network ports and services")]
    tool_retrieval_store.ensure_index(llm, specs)
    assert llm.calls == 1
    embedded_again = tool_retrieval_store.ensure_index(llm, specs)
    assert embedded_again == 0
    assert llm.calls == 1  # no new embed() call for an already-indexed tool


def test_ensure_index_drops_stale_vectors_on_a_model_change(monkeypatch):
    llm = _CountingFakeEmbedLLM()
    specs = [_tool("port_scanner", "Scans network ports and services")]
    tool_retrieval_store.ensure_index(llm, specs)
    monkeypatch.setattr(tool_retrieval_store.playbook_store, "embedding_model", lambda: "a-different-model")
    tool_retrieval_store.ensure_index(llm, specs)
    assert llm.calls == 2  # re-embedded under the new model
    assert tool_retrieval_store.load_tool_vectors()["_model"] == "a-different-model"


def test_ensure_index_noop_when_provider_has_no_embeddings():
    specs = [_tool("port_scanner", "Scans network ports and services")]
    embedded = tool_retrieval_store.ensure_index(_UnavailableEmbedLLM(), specs)
    assert embedded == 0
    assert tool_retrieval_store.load_tool_vectors() == {}


def test_ensure_index_noop_with_no_llm_or_no_specs():
    assert tool_retrieval_store.ensure_index(None, [_tool("x", "y")]) == 0
    assert tool_retrieval_store.ensure_index(_CountingFakeEmbedLLM(), []) == 0


# --- shortlist_for: hybrid keyword + semantic, never a gate, graceful degradation ---


def test_shortlist_for_disabled_returns_nothing(monkeypatch):
    monkeypatch.setenv("TOOL_RETRIEVAL_ENABLED", "false")
    specs = [_tool("port_scanner", "Scans network ports and services")]
    names, reasons = tool_retrieval_store.shortlist_for(_CountingFakeEmbedLLM(), "scan the network", "recon", "web", specs)
    assert names == []
    assert reasons == {}


def test_shortlist_for_returns_nothing_with_no_query_text_or_no_candidates():
    specs = [_tool("port_scanner", "Scans network ports and services")]
    assert tool_retrieval_store.shortlist_for(_CountingFakeEmbedLLM(), "", "recon", "web", specs) == ([], {})
    assert tool_retrieval_store.shortlist_for(_CountingFakeEmbedLLM(), "scan it", "recon", "web", []) == ([], {})


def test_shortlist_for_keyword_only_without_a_provider():
    # No llm at all -- semantic is always 0, so this proves the keyword half alone can surface a
    # candidate (a literal name mention, plus real token overlap with its own description).
    alpha = _tool("port_scanner", "Scans network ports and services on a host")
    beta = _tool("whois_lookup", "Queries public WHOIS registration data for a domain")
    names, reasons = tool_retrieval_store.shortlist_for(None, "scan the open network ports on this host", "recon", "web", [alpha, beta])
    assert names == ["port_scanner"]
    assert "port_scanner" in reasons


def test_keyword_half_surfaces_a_literal_name_match_that_semantic_alone_would_miss():
    # whois_lookup's own tool vector buckets to "network" (see _CountingFakeEmbedLLM) while the
    # query text buckets to "sql" -- cosine between them is 0, so semantic alone would never
    # surface it. The query text also literally names the tool, so the keyword half's name-match
    # bonus must still pull it in -- this is exactly the "pure dense retrieval underperforms for
    # tool retrieval" gap the roadmap's hybrid design exists to close.
    mismatched = ToolSpec(
        name="whois_lookup", category="recon", tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"},
        description="Scans network ports and services",  # deliberately semantic-mismatched text
    )
    llm = _CountingFakeEmbedLLM()
    names, reasons = tool_retrieval_store.shortlist_for(llm, "run whois_lookup for sql injection recon", "recon", "web", [mismatched])
    assert names == ["whois_lookup"]
    assert "whois_lookup" in reasons["whois_lookup"]


def test_semantic_half_surfaces_a_tool_with_zero_keyword_overlap():
    # The tool's own description shares not one meaningful token with the query, but its
    # embedding vector (bucketed on "sql"/"inject") is identical to the query's -- only the
    # semantic half can surface this, proving hybrid adds real value beyond keyword alone.
    sql_tool = _tool("payload_runner", "Executes a crafted SQL injection payload against a parameter")
    llm = _CountingFakeEmbedLLM()
    names_no_llm, _ = tool_retrieval_store.shortlist_for(None, "need something for a blind boolean database attack", "exploit", "web", [sql_tool])
    assert names_no_llm == []  # keyword-only: no overlap at all, nothing surfaces

    names_hybrid, reasons = tool_retrieval_store.shortlist_for(llm, "need something for a blind boolean database injection attack", "exploit", "web", [sql_tool])
    assert names_hybrid == ["payload_runner"]
    assert "semantic=" in reasons["payload_runner"]


def test_shortlist_for_respects_top_k(monkeypatch):
    monkeypatch.setenv("TOOL_RETRIEVAL_TOP_K", "1")
    specs = [
        _tool("alpha_scanner", "Scans network ports for alpha targets"),
        _tool("beta_scanner", "Scans network ports for beta targets"),
    ]
    names, _ = tool_retrieval_store.shortlist_for(_CountingFakeEmbedLLM(), "scan network ports now", "recon", "web", specs)
    assert len(names) == 1


def test_shortlist_for_never_returns_a_name_outside_the_candidate_set():
    in_scope = _tool("port_scanner", "Scans network ports and services")
    names, _ = tool_retrieval_store.shortlist_for(_CountingFakeEmbedLLM(), "scan network ports", "recon", "web", [in_scope])
    assert set(names) <= {"port_scanner"}


def test_shortlist_for_degrades_gracefully_when_embed_raises():
    class _ExplodingLLM:
        def embed(self, texts, model=None):
            raise RuntimeError("provider is down")

    specs = [_tool("port_scanner", "Scans network ports and services")]
    # Must not raise -- falls back to keyword-only scoring for this call.
    names, _ = tool_retrieval_store.shortlist_for(_ExplodingLLM(), "scan network ports", "recon", "web", specs)
    assert names == ["port_scanner"]


# --- query-embedding cache: a repeated identical query text never re-embeds ---


def test_query_embedding_is_cached_across_repeated_calls():
    llm = _CountingFakeEmbedLLM()
    specs = [_tool("port_scanner", "Scans network ports and services")]
    tool_retrieval_store.shortlist_for(llm, "scan the network", "recon", "web", specs)
    calls_after_first = llm.calls
    tool_retrieval_store.shortlist_for(llm, "scan the network", "recon", "web", specs)
    assert llm.calls == calls_after_first  # identical query text -> cached, no second embed() call for it


# --- lookahead_steps: the item-4 env knob for how many upcoming plan steps get queried ---


def test_lookahead_steps_defaults_and_is_env_overridable(monkeypatch):
    assert tool_retrieval_store.lookahead_steps() == 3
    monkeypatch.setenv("TOOL_RETRIEVAL_LOOKAHEAD_STEPS", "5")
    assert tool_retrieval_store.lookahead_steps() == 5
    monkeypatch.setenv("TOOL_RETRIEVAL_LOOKAHEAD_STEPS", "not-a-number")
    assert tool_retrieval_store.lookahead_steps() == 3  # bad value falls back to the default
    monkeypatch.setenv("TOOL_RETRIEVAL_LOOKAHEAD_STEPS", "0")
    assert tool_retrieval_store.lookahead_steps() == 1  # floored at 1, never disables via this knob


# --- shortlist_for_steps: item 4, TOOLQP multi-step retrieval over the plan/kill-chain ---


def test_shortlist_for_steps_disabled_returns_nothing(monkeypatch):
    monkeypatch.setenv("TOOL_RETRIEVAL_ENABLED", "false")
    specs = [_tool("port_scanner", "Scans network ports and services")]
    names, reasons = tool_retrieval_store.shortlist_for_steps(None, ["scan the network"], "recon", "web", specs)
    assert names == []
    assert reasons == {}


def test_shortlist_for_steps_returns_nothing_with_no_queries_or_no_candidates():
    specs = [_tool("port_scanner", "Scans network ports and services")]
    assert tool_retrieval_store.shortlist_for_steps(None, [], "recon", "web", specs) == ([], {})
    assert tool_retrieval_store.shortlist_for_steps(None, ["scan it"], "recon", "web", []) == ([], {})


def test_shortlist_for_steps_with_one_query_matches_shortlist_for_exactly():
    # The common case (a phase with exactly one open step) must degrade to byte-identical
    # behavior to calling shortlist_for directly -- no parallel mechanism, no behavior change.
    specs = [_tool("port_scanner", "Scans network ports and services on a host")]
    query = "scan the open network ports on this host"
    direct = tool_retrieval_store.shortlist_for(None, query, "recon", "web", specs)
    stepped = tool_retrieval_store.shortlist_for_steps(None, [query], "recon", "web", specs)
    assert stepped == direct


def test_shortlist_for_steps_surfaces_a_tool_only_a_later_step_needs():
    # The classic TOOLQP miss this item exists to close: port_scanner is only relevant to step 1's
    # own text, whois_lookup only to step 2's -- a single-query retriever on step 1 alone would
    # never surface whois_lookup at all. Querying both steps and merging must surface both.
    port_scanner = _tool("port_scanner", "Scans network ports and services on a host")
    whois_lookup = _tool("whois_lookup", "Queries public WHOIS registration data for a domain")
    step1 = "scan the open network ports on this host"
    step2 = "look up public whois registration data for this domain"
    names, reasons = tool_retrieval_store.shortlist_for_steps(None, [step1, step2], "recon", "web", [port_scanner, whois_lookup])
    assert names == ["port_scanner", "whois_lookup"]  # step 1's own pick first, step 2's new pick after
    assert not reasons["port_scanner"].startswith("step")  # the CURRENT step's own reason, unprefixed
    assert reasons["whois_lookup"].startswith("step 2/2 lookahead:")  # honestly labeled as "needed soon"


def test_shortlist_for_steps_dedupes_a_name_the_current_step_already_claimed():
    # whois_lookup matches BOTH steps' text -- the more urgent (current, step 1) step's claim on
    # it must win; step 2 must never re-add it or overwrite its reason with a "lookahead" label.
    port_scanner = _tool("port_scanner", "Scans network ports and services on a host")
    whois_lookup = _tool("whois_lookup", "Queries public WHOIS registration data for a domain")
    step1 = "scan the open network ports and look up whois domain registration data"
    step2 = "look up public whois registration data for this domain"
    names, reasons = tool_retrieval_store.shortlist_for_steps(None, [step1, step2], "recon", "web", [port_scanner, whois_lookup])
    assert names.count("whois_lookup") == 1
    assert not reasons["whois_lookup"].startswith("step")  # claimed by step 1, not relabeled by step 2


def test_shortlist_for_steps_respects_top_k_across_merged_steps(monkeypatch):
    monkeypatch.setenv("TOOL_RETRIEVAL_TOP_K", "1")
    port_scanner = _tool("port_scanner", "Scans network ports and services on a host")
    whois_lookup = _tool("whois_lookup", "Queries public WHOIS registration data for a domain")
    step1 = "scan the open network ports on this host"
    step2 = "look up public whois registration data for this domain"
    names, _ = tool_retrieval_store.shortlist_for_steps(None, [step1, step2], "recon", "web", [port_scanner, whois_lookup])
    assert names == ["port_scanner"]  # the cap is combined across steps, not per-step


# --- item 5: target_shape as a first-class scoring facet, not just a logging/cache-key pass-through ---


def test_tool_shape_bucket_classifies_re_web_neutral_and_toolkit():
    re_only = _tool("radare2", "disassembles a binary", category="re")
    web_only = _tool("nuclei", "scans for web vulnerabilities", category="recon")
    cross_cutting = ToolSpec(
        name="grep", category=("re", "recon"), tool_tier=1, executable="", build_command=None,
        requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"}, description="searches files",
    )
    toolkit_only = _tool("proxy_intercept", "intercepts http traffic", category="toolkit")
    assert tool_retrieval_store._tool_shape_bucket(re_only) == "binary"
    assert tool_retrieval_store._tool_shape_bucket(web_only) == "web"
    assert tool_retrieval_store._tool_shape_bucket(cross_cutting) == ""  # neutral -- spans both worlds
    assert tool_retrieval_store._tool_shape_bucket(toolkit_only) == ""  # neutral -- not bucketable yet


def test_shortlist_for_shape_match_promotes_the_same_bucket_tool_over_an_equally_worded_rival():
    # Identical description text on both tools (so keyword score is byte-identical, semantic is 0
    # with no llm) isolates the shape facet as the ONLY thing that can break the tie. re_tool's
    # own category is "re" (binary bucket); web_tool's is "recon" (web bucket); the query's own
    # shape is a real RE-mode target_shape -- only re_tool should survive a top_k=1 cutoff.
    description = "inspects the binary structure and extracts embedded strings for analysis"
    re_tool = _tool("re_tool", description, category="re")
    web_tool = _tool("web_tool", description, category="recon")
    names, reasons = tool_retrieval_store.shortlist_for(
        None, "inspects the binary structure and extracts embedded strings", "analyze", "pe_x86_64", [re_tool, web_tool],
    )
    assert names[0] == "re_tool"
    assert reasons["re_tool"].endswith("; shape-matched")
    assert not reasons.get("web_tool", "").endswith("; shape-matched")


def test_shortlist_for_shape_mismatch_never_excludes_a_strong_keyword_match_outright():
    # Dampened, not removed -- a cross-bucket tool with a decisive enough keyword signal (its own
    # name literally named in the query) must still surface.
    web_tool = _tool("sqlmap", "tests for sql injection", category="exploit")
    names, _ = tool_retrieval_store.shortlist_for(None, "run sqlmap against this binary target", "exploit", "pe_x86_64", [web_tool])
    assert names == ["sqlmap"]


def test_shortlist_for_applies_no_shape_adjustment_when_the_query_shape_is_unknown():
    # No real shape signal yet (a brand-new session) -- must never guess a shape match either way,
    # same "don't act on no signal" posture tool_affinity_store.shape_bucket's own "unknown" uses.
    description = "enumerates open services on the target"
    re_tool = _tool("re_tool", description, category="re")
    web_tool = _tool("web_tool", description, category="recon")
    names, _ = tool_retrieval_store.shortlist_for(None, "enumerates open services on the target", "recon", "unknown", [re_tool, web_tool])
    assert set(names) == {"re_tool", "web_tool"}  # tied -- neither got a shape-driven edge


def test_shortlist_for_applies_no_shape_adjustment_for_a_neutral_cross_cutting_tool():
    # A tool spanning both worlds (e.g. item 0's widened read-only primitives) must never be
    # boosted OR dampened by the shape facet -- confirmed here by comparing it against an
    # exact-bucket-matching rival that DOES earn the bonus.
    description = "reads and lists files for the current task"
    neutral_tool = ToolSpec(
        name="list_dir", category=("re", "recon", "scan", "exploit", "post_exploit"), tool_tier=1,
        executable="", build_command=None, requires_allowed_target=False, installed_by_default=True,
        native_function=lambda params: {"status": "ok"}, description=description,
    )
    binary_tool = _tool("binary_tool", description, category="re")
    names, reasons = tool_retrieval_store.shortlist_for(None, description, "recon", "pe_x86_64", [neutral_tool, binary_tool])
    assert names[0] == "binary_tool"  # earned the bonus; the neutral tool did not
    assert not reasons["list_dir"].endswith("; shape-matched")
