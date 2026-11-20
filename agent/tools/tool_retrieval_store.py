"""Tool-retrieval / routing layer (tool-selection roadmap item 3): returns a compact top-K
candidate shortlist of tools for the current task instead of letting the model pick cold from the
whole ~40+-tool registry every turn -- the "tool explosion" fix (flat dump-the-whole-registry
selection degrades as the candidate count grows).

Also carries item 4, multi-step retrieval over the plan/kill-chain (TOOLQP) -- shortlist_for_steps
near the bottom of this module -- built directly on top of shortlist_for rather than as a second,
parallel mechanism: it calls shortlist_for once per one of the phase's own still-open upcoming plan
steps and merges the results, so a tool a LATER step will need is already shortlisted before that
step's own turn arrives, the classic miss a single-query retriever has.

Reuses ASRA's EXISTING embedding infrastructure end to end -- the same provider.embed() method
agent/core.py's _embed_playbook_query/_embed_playbook_entries call, and
agent/tools/playbook_store.py's own embedding_model()/cosine-similarity shape -- rather than
standing up a second pipeline. This module only adds its OWN vector store (tool texts, not
playbook techniques) and its OWN cheap query-embedding cache, since those are a genuinely
different corpus/call pattern, not shared state.

HYBRID by design, not pure dense retrieval: the research backing this roadmap found pure semantic
retrieval underperforms specifically for tool retrieval, so every candidate is scored by semantic
cosine PLUS a keyword overlap, summed -- a literal name/argument match (the operator typing "nmap")
and a meaning-only match (a task described in words that never mention a tool by name) both surface
candidates the other half alone would miss. The keyword half is IDF-weighted, not a plain overlap
count -- confirmed live against the real registry: a plain count let generic words nearly every
ASRA tool's own description happens to share ("target", "host", "port" -- every tool here is a
pentest tool) outweigh genuinely distinctive ones, pulling in irrelevant candidates. Document
frequency is computed fresh from each call's own candidate set, never a hardcoded stoplist.

Always a STEER, never a gate (same invariant as tool_affinity_store.py): this module never removes
a tool from a candidate set, it only names which ones to promote. agent/core.py's
_apply_plan_recommendations is the sole consumer -- it blends this shortlist in alongside (a) the
model's own recommended_tools and (b) the learned tool-affinity ranking, never replacing either.

Item 5 (typed/grouped recall) correction: `target_shape` was already a parameter on shortlist_for/
shortlist_for_steps, but until now it was ONLY ever used for the log/cache dedup key below -- it
never actually touched scoring, so a narrow binary-shape query could still be outscored by an
unrelated web tool purely on generic keyword/semantic noise, the exact dilution item 5 exists to
fix. _tool_shape_bucket() (below) re-indexes each candidate's own already-registered category
metadata (agent/tools/registry.py's Category enum -- no new capture path, confirming the roadmap's
"largely a re-indexing" claim once pointed at THIS store's real data instead of playbook's) into
the same web/binary bucket tool_affinity_store.shape_bucket() already uses for the query side, and
shortlist_for below now nudges the hybrid score with it: a same-bucket match gets a flat bonus, a
genuinely cross-bucket mismatch gets dampened -- still only ever a soft steer (a mismatched tool
can still surface on a strong enough semantic/keyword match alone, it's dampened, never excluded).

Presentation follows Umbra-Agent's formatSkillsForPrompt progressive-disclosure shape (adaptation
reference approved for this roadmap item): the shortlist surfaces as a compact name + one-line
reason, never a second copy of the tool's full description/schema -- the full ToolSpec a shortlisted
tool is matched against is already sitting in tool_specs untouched; this module only decides which
names earn the promotion tag.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
from collections import OrderedDict

from agent.tools import playbook_store, tool_affinity_store
from agent.tools.registry import ToolSpec, categories_of
from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

# Own file, separate from playbook's embeddings.json -- a different corpus (tool catalog text, not
# captured techniques) that happens to reuse the same embedder/model, not the same data.
TOOL_RETRIEVAL_STORE_PATH = resolve_global_app_dir() / "data" / "tool_retrieval" / "embeddings.json"

# How much a perfect semantic match (cosine 1.0) is worth relative to the keyword score -- same
# weighting role as playbook_store._SEMANTIC_WEIGHT, kept as its own constant (not env-configurable,
# same reasoning as that module's own comment: this is an internal scoring-shape knob, not something
# an operator is expected to need to tune) since the two corpora's score distributions aren't
# necessarily identical.
_SEMANTIC_WEIGHT = 4.0

# One point per overlapping meaningful token between the query text and a tool's own
# name/description/category text, plus this flat bonus when the tool's name itself appears
# verbatim in the query (the strongest possible keyword signal -- the operator/model's task text
# just named the tool).
_NAME_MATCH_BONUS = 3.0

# Item 5's shape facet: smaller than _NAME_MATCH_BONUS/_SEMANTIC_WEIGHT on purpose -- a coarse
# web/binary category-bucket match is a much weaker signal than a literal name match or a strong
# semantic hit, this is a nudge toward the right neighborhood, not a decisive vote. Kept as an
# internal scoring-shape constant, not an env var, same precedent as _SEMANTIC_WEIGHT/
# _NAME_MATCH_BONUS right above it in this same module.
_SHAPE_MATCH_BONUS = 1.5
# A cross-bucket tool (binary-only tool scored against a web query, or vice versa) is dampened,
# never excluded -- still a soft steer: a genuinely strong keyword/semantic match can clear this.
_SHAPE_MISMATCH_DAMPENING = 0.5

# Tokens too short or too generic to carry any real signal -- excluded from the keyword overlap so
# "the" or "to" never counts as a match. Deliberately small/generic, not a hand-tuned stoplist.
_STOPWORDS = frozenset({
    "the", "a", "an", "to", "of", "and", "or", "in", "on", "for", "with", "this", "that", "is",
    "are", "it", "its", "be", "as", "at", "by", "from", "if", "not", "no", "yet", "has", "have",
})
_TOKEN_RE = re.compile(r"[a-z0-9_]+")

# Bounded in-memory cache of query text -> embedding vector, so a repeated call with the SAME task
# text (the common case -- this is consulted every turn, but the plan's own task text only changes
# when update_plan actually runs) never pays a second real embedding API call. Capped so a
# long-running server process across many sessions/phases can't grow this unboundedly; oldest
# entries evicted first once full.
_QUERY_EMBED_CACHE: "OrderedDict[str, list[float] | None]" = OrderedDict()
_QUERY_EMBED_CACHE_MAX = 256

# (target_shape, phase) -> the shortlisted-name set last actually logged for it, same dedup shape as
# agent/core.py's own _LAST_LOGGED_PLAN_RECOMMENDATIONS -- avoids re-logging an unchanged shortlist
# on every single turn a phase runs.
_LAST_LOGGED_SHORTLIST: dict[tuple[str, str], frozenset[str]] = {}

# Same dedup shape as _LAST_LOGGED_SHORTLIST above, kept as its own cache rather than reused --
# shortlist_for_steps' own merged, multi-step result is a genuinely different event (how many steps
# were looked ahead, what the MERGED set ended up being) than any single step's own shortlist_for
# call, so collapsing them into one cache key would make one call's log suppress the other's.
_LAST_LOGGED_MULTISTEP_SHORTLIST: dict[tuple[str, str], frozenset[str]] = {}


def is_enabled() -> bool:
    return os.getenv("TOOL_RETRIEVAL_ENABLED", "true").strip().lower() not in ("false", "0", "no")


def _top_k() -> int:
    try:
        return max(1, int(os.getenv("TOOL_RETRIEVAL_TOP_K", "8")))
    except ValueError:
        return 8


def lookahead_steps() -> int:
    """How many of the plan's own next still-open steps shortlist_for_steps queries separately
    (tool-selection roadmap item 4, TOOLQP-style multi-step retrieval) -- public, unlike _top_k,
    since agent/core.py's _plan_lookahead_query_texts needs it to cap how many per-step query
    strings it even builds in the first place, not just how the resulting shortlist is sized.
    Bounded at 1 so a misconfigured 0/negative value never silently disables lookahead outright --
    that's TOOL_RETRIEVAL_ENABLED's job, not this knob's."""
    try:
        return max(1, int(os.getenv("TOOL_RETRIEVAL_LOOKAHEAD_STEPS", "3")))
    except ValueError:
        return 3


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def load_tool_vectors() -> dict:
    if not TOOL_RETRIEVAL_STORE_PATH.exists():
        return {}
    try:
        with TOOL_RETRIEVAL_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("tool_retrieval: embeddings.json unreadable (%s) -- treating as none stored", exc)
        return {}


def _write_tool_vectors(data: dict) -> None:
    TOOL_RETRIEVAL_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = TOOL_RETRIEVAL_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp_path, TOOL_RETRIEVAL_STORE_PATH)


def _tokenize(text: str) -> set[str]:
    return {t for t in _TOKEN_RE.findall((text or "").lower()) if len(t) > 2 and t not in _STOPWORDS}


def build_tool_embedding_text(spec: ToolSpec) -> str:
    """The text a tool is embedded/keyword-matched from -- name, its own description (the exact
    text the model already sees in its schema) and categories, plus a handful of templated
    example-intent phrasings generated FROM that same description. These phrasings are produced
    programmatically from existing ToolSpec metadata, not hand-authored per tool (no hardcoded
    per-tool catalog to maintain across ~40+ registered tools, consistent with this project's own
    "no hardcoding" rule) -- the same "concatenate the entry's own fields into one embeddable
    string" shape as playbook_store.build_embedding_text, applied to a ToolSpec instead of a
    captured technique."""
    description = spec.description or spec.full_description or ""
    categories = " ".join(categories_of(spec))
    phrasings = [
        f"use {spec.name} for {description}" if description else spec.name,
        f"when the task is: {description}" if description else "",
        f"to {description}" if description else "",
    ]
    parts = [spec.name, description, categories, *phrasings]
    return " ".join(p for p in parts if p).strip()


def _registry_signature(specs: list[ToolSpec]) -> frozenset[str]:
    """Cheap stand-in for "has the registry changed" -- the set of tool names currently offered.
    ensure_index() re-checks this (and the stored embedding model) on every call, so a newly
    registered/removed tool (a custom tool add/remove, picked up the next time the registry is
    (re)built) gets its vector embedded/left stale automatically, without needing a separate
    explicit "registry changed" event the current registry (agent/tools/registry.py) has no hook
    for in the first place -- see this module's own docstring on why that's the right level of
    "refresh on change" for how TOOL_REGISTRY is actually populated today."""
    return frozenset(spec.name for spec in specs)


def ensure_index(llm, specs: list[ToolSpec]) -> int:
    """Best-effort: embeds any of `specs` missing a vector under the active embedding model, and
    persists the result -- the one-time "index, refresh when the registry changes" step the roadmap
    calls for. Returns how many tools were (re)embedded this call (0 is the common case once the
    index is warm -- nothing to do). Never raises; a provider with no embeddings endpoint (llm is
    None, or embed() itself returns None) just means every subsequent call degrades to keyword-only
    scoring, same graceful-degradation shape as playbook_store's own semantic search.
    """
    if llm is None or not specs:
        return 0
    embed = getattr(llm, "embed", None)
    if embed is None:
        return 0
    model = playbook_store.embedding_model()
    data = load_tool_vectors()
    if data.get("_model") not in (None, model):
        logger.debug("tool_retrieval: embedding model changed %r -> %r, dropping stale tool vectors", data.get("_model"), model)
        data = {}
    # Deduped by name, not just filtered -- `specs` can legitimately contain the same ToolSpec
    # twice (a tool registered under more than one category, e.g. list_dir/read_file/grep are both
    # "re" and "recon") when a caller assembles candidates from more than one category. Without
    # this, the same tool's text would be sent to embed() twice in one call, and the "embedded N"
    # count/log line below would overcount -- confirmed live against the real registry.
    missing_by_name: dict[str, ToolSpec] = {}
    for spec in specs:
        if spec.name not in data and spec.name not in missing_by_name:
            missing_by_name[spec.name] = spec
    missing = list(missing_by_name.values())
    if not missing:
        return 0
    texts = [build_tool_embedding_text(spec) for spec in missing]
    try:
        vectors = embed(texts, model=model)
    except Exception as exc:
        logger.debug("tool_retrieval: embed failed for %d tool(s) (%s) -- keyword-only scoring stands in", len(missing), exc)
        return 0
    if not vectors:
        return 0
    data["_model"] = model
    for spec, vec in zip(missing, vectors):
        if isinstance(vec, list):
            data[spec.name] = vec
    _write_tool_vectors(data)
    embedded = sum(1 for spec in missing if spec.name in data)
    logger.debug("tool_retrieval: index built/refreshed -- embedded %d new tool(s), %d total in index", embedded, sum(1 for k in data if k != "_model"))
    return embedded


def _embed_query_cached(llm, text: str) -> list[float] | None:
    model = playbook_store.embedding_model()
    cache_key = hashlib.sha1(f"{model}::{text}".encode("utf-8")).hexdigest()
    if cache_key in _QUERY_EMBED_CACHE:
        _QUERY_EMBED_CACHE.move_to_end(cache_key)
        return _QUERY_EMBED_CACHE[cache_key]
    embed = getattr(llm, "embed", None)
    vec: list[float] | None = None
    if embed is not None:
        try:
            vectors = embed([text], model=model)
            vec = vectors[0] if vectors else None
        except Exception as exc:
            logger.debug("tool_retrieval: query embed failed (%s) -- keyword-only scoring for this query", exc)
            vec = None
    _QUERY_EMBED_CACHE[cache_key] = vec
    if len(_QUERY_EMBED_CACHE) > _QUERY_EMBED_CACHE_MAX:
        _QUERY_EMBED_CACHE.popitem(last=False)
    return vec


def _token_document_frequencies(tool_token_sets: list[set[str]]) -> dict[str, int]:
    """How many of THIS call's own candidate tools' embedding texts contain each token -- the
    corpus a token's weight is judged against, recomputed fresh every call rather than over the
    whole registry, so a token that's generic within a mixed recon+exploit candidate set but
    distinctive within a narrower one is scored correctly for whichever set is actually in play."""
    df: dict[str, int] = {}
    for tokens in tool_token_sets:
        for tok in tokens:
            df[tok] = df.get(tok, 0) + 1
    return df


def _idf(token: str, df: dict[str, int], n_docs: int) -> float:
    """Smoothed inverse-document-frequency weight. Real, confirmed gap this closes (found live
    against the actual tool registry, not a hypothetical): a plain unweighted token-overlap count
    let a web-recon query pull in genuinely RE-only tools (tshark_capture, custom_re_script) purely
    because words like "target"/"host"/"port" happen to appear in nearly every ASRA tool's own
    description -- every tool is a pentest tool, so those words carry almost no discriminative
    signal. A token shared by nearly every candidate here gets a weight near the floor of ~1.0; one
    only a handful of candidates share gets several times that. Computed fresh from the ACTUAL
    candidate set every call -- never a hardcoded stoplist of "common pentest words" to maintain --
    so it adapts automatically as tools are added, removed, or reworded."""
    return math.log((n_docs + 1) / (df.get(token, 0) + 1)) + 1.0


def _keyword_score(query_tokens: set[str], query_text: str, spec: ToolSpec, tool_tokens: set[str], df: dict[str, int], n_docs: int) -> float:
    if not query_tokens:
        return 0.0
    score = sum(_idf(tok, df, n_docs) for tok in (query_tokens & tool_tokens))
    if spec.name.lower() in query_text.lower():
        score += _NAME_MATCH_BONUS
    return score


def _tool_shape_bucket(spec: ToolSpec) -> str:
    """Re-indexes `spec`'s own already-registered categories (agent/tools/registry.py's Category
    enum) into the same web/binary bucket tool_affinity_store.shape_bucket() uses for the query
    side -- item 5's typed facet, built from data this registry already stores, no new capture
    path. "" (neutral) for a tool genuinely useful across both worlds (e.g. the read-only
    list_dir/read_file/grep primitives item 0 widened to every category) or one this coarse
    two-bucket split can't place (toolkit-only) -- a neutral tool is never boosted OR dampened,
    same "don't guess without real signal" posture shape_bucket()'s own "unknown" already uses."""
    cats = set(categories_of(spec))
    if not cats:
        return ""
    if cats <= {"re"}:
        return "binary"
    if cats <= {"recon", "scan", "exploit", "post_exploit"}:
        return "web"
    return ""


def shortlist_for(
    llm,
    query_text: str,
    phase: str,
    target_shape: str,
    candidate_specs: list[ToolSpec],
) -> tuple[list[str], dict[str, str]]:
    """The item-3 retrieval shortlist for agent/core.py's _apply_plan_recommendations (its own
    documented (c) extension point) -- ranks `candidate_specs` (this phase's own tool_specs) by a
    hybrid semantic+keyword score against `query_text` (the phase's current open-task text), and
    returns the top TOOL_RETRIEVAL_TOP_K names plus a one-line, auditable reason per name (the
    Umbra-Agent formatSkillsForPrompt-style compact presentation this roadmap item calls for).

    `target_shape` also now feeds scoring directly (item 5): each candidate's own registered
    category is bucketed into "web"/"binary"/"" via _tool_shape_bucket and compared against
    `target_shape`'s own bucket (tool_affinity_store.shape_bucket) -- a same-bucket match earns
    _SHAPE_MATCH_BONUS, a genuine cross-bucket mismatch is dampened by _SHAPE_MISMATCH_DAMPENING,
    so a narrow-shape query (e.g. an RE pe_x86_64 task) is no longer diluted by an unrelated web
    tool purely on generic keyword/semantic overlap, without ever excluding it outright.

    Soft steer only, same safeguard as tool_affinity_store.recommended_tools_for: never removes a
    tool from the candidate set, only names which ones to promote. Never raises; disabled, no query
    text, or no candidates returns ([], {}) -- the caller's existing (a)/(b) signals stand on their
    own.
    """
    if not is_enabled() or not (query_text or "").strip() or not candidate_specs:
        return [], {}
    try:
        ensure_index(llm, candidate_specs)
        vectors = load_tool_vectors() if llm is not None else {}
        query_vec = _embed_query_cached(llm, query_text) if llm is not None else None
        query_tokens = _tokenize(query_text)

        # Tokenized once per candidate per call, and the document frequencies derived from that
        # SAME set -- the IDF weighting below judges a token's distinctiveness against whichever
        # candidates are actually in play this call, not the whole registry.
        tool_tokens_by_name = {spec.name: _tokenize(build_tool_embedding_text(spec)) for spec in candidate_specs}
        df = _token_document_frequencies(list(tool_tokens_by_name.values()))
        n_docs = len(candidate_specs)

        # Item 5's shape facet: "unknown" (no signal yet on the query side -- see
        # tool_affinity_store.shape_bucket's own docstring) means neither a bonus nor a dampening
        # is earned, exactly like a neutral ("") tool bucket below -- never guess a shape match
        # from no real signal.
        query_bucket = tool_affinity_store.shape_bucket(target_shape)

        scored: list[tuple[float, str, float, float, bool]] = []
        for spec in candidate_specs:
            semantic = 0.0
            if query_vec is not None:
                vec = vectors.get(spec.name)
                if isinstance(vec, list):
                    semantic = _cosine(query_vec, vec) * _SEMANTIC_WEIGHT
            keyword = _keyword_score(query_tokens, query_text, spec, tool_tokens_by_name[spec.name], df, n_docs)
            total = semantic + keyword
            if total <= 0.0:
                continue
            tool_bucket = _tool_shape_bucket(spec)
            shape_matched = False
            if query_bucket != "unknown" and tool_bucket:
                if tool_bucket == query_bucket:
                    total += _SHAPE_MATCH_BONUS
                    shape_matched = True
                else:
                    total *= _SHAPE_MISMATCH_DAMPENING
            scored.append((total, spec.name, semantic, keyword, shape_matched))

        scored.sort(key=lambda row: row[0], reverse=True)
        top = scored[:_top_k()]
        names = [name for _, name, _, _, _ in top]
        query_preview = query_text if len(query_text) <= 80 else query_text[:77] + "..."
        reasons = {
            name: (
                f"retrieval shortlist match for '{query_preview}' (semantic={semantic:.2f}, keyword={keyword:.0f})"
                + ("; shape-matched" if shape_matched else "")
            )
            for _, name, semantic, keyword, shape_matched in top
        }

        shortlist_key = (target_shape or "unknown", phase or "unscoped")
        shortlisted_names = frozenset(names)
        if names and _LAST_LOGGED_SHORTLIST.get(shortlist_key) != shortlisted_names:
            _LAST_LOGGED_SHORTLIST[shortlist_key] = shortlisted_names
            logger.debug(
                "tool_retrieval: shape=%r phase=%r query=%r shortlisted %d tool(s): %s",
                target_shape, phase, query_preview, len(names),
                [(name, round(semantic, 2), keyword, shape_matched) for _, name, semantic, keyword, shape_matched in top],
            )
        return names, reasons
    except Exception:
        logger.debug("tool_retrieval: shortlist_for failed for shape=%r phase=%r, returning no shortlist", target_shape, phase, exc_info=True)
        return [], {}


def shortlist_for_steps(
    llm,
    query_texts: list[str],
    phase: str,
    target_shape: str,
    candidate_specs: list[ToolSpec],
) -> tuple[list[str], dict[str, str]]:
    """Multi-step retrieval over the plan / kill-chain (tool-selection roadmap item 4, TOOLQP) --
    the classic single-query miss this closes: step 2 of a plan needs tool B, but a retriever that
    only ever queries the CURRENT step's text never surfaces B until step 2 actually arrives, by
    which point it's too late to have been proactively shortlisted. Fix: call shortlist_for (item
    3) once per entry in `query_texts` -- one of the phase's own still-open plan steps each,
    already capped by the caller (agent/core.py's _plan_lookahead_query_texts, via lookahead_steps()
    above) -- instead of once for a single blended query, then merge the per-step results into one
    ranked shortlist. Built directly ON TOP OF shortlist_for: no second scoring/embedding path,
    every step still pays exactly that function's own (cached) hybrid semantic+keyword pass.

    Merge rule: a step closer to right now outranks one further ahead. The first (current) step's
    own ranked picks are kept in full; each later step's NEW names (ones no earlier, more urgent
    step already shortlisted) are appended in that later step's own rank order, until the combined
    list reaches shortlist_for's own TOOL_RETRIEVAL_TOP_K cap -- so looking further ahead widens how
    FAR this reaches, never how BIG the final promoted menu gets (the same token/cost discipline
    TOOL_RETRIEVAL_TOP_K already enforces for a single query). A name promoted only because of a
    step beyond the current one carries that in its own reason string ("step 2/3 lookahead: ..."),
    so the promotion reads honestly in the UI as "needed soon", not "needed right now".

    With exactly one open step (the common case -- most phases have one active task at a time) this
    degrades to byte-identical behavior to calling shortlist_for directly: one call, its own names
    and reasons returned unchanged. Same safeguards as shortlist_for itself: never raises, empty
    input returns ([], {}), and this never removes a tool from the candidate set -- only names which
    ones to promote.
    """
    if not is_enabled() or not query_texts or not candidate_specs:
        return [], {}
    total_steps = len(query_texts)
    top_k = _top_k()
    merged_names: list[str] = []
    merged_reasons: dict[str, str] = {}
    seen: set[str] = set()
    for step_index, query_text in enumerate(query_texts):
        if len(merged_names) >= top_k:
            break
        names, reasons = shortlist_for(llm, query_text, phase, target_shape, candidate_specs)
        for name in names:
            if name in seen:
                continue
            if len(merged_names) >= top_k:
                break
            seen.add(name)
            merged_names.append(name)
            reason = reasons.get(name, "retrieval shortlist match")
            merged_reasons[name] = (
                reason if step_index == 0 else f"step {step_index + 1}/{total_steps} lookahead: {reason}"
            )

    if merged_names:
        shortlist_key = (target_shape or "unknown", phase or "unscoped")
        shortlisted_names = frozenset(merged_names)
        if _LAST_LOGGED_MULTISTEP_SHORTLIST.get(shortlist_key) != shortlisted_names:
            _LAST_LOGGED_MULTISTEP_SHORTLIST[shortlist_key] = shortlisted_names
            logger.debug(
                "tool_retrieval: multi-step lookahead shape=%r phase=%r looked ahead %d step(s), merged shortlist (%d tool(s)): %s",
                target_shape, phase, total_steps, len(merged_names), merged_names,
            )
    return merged_names, merged_reasons
