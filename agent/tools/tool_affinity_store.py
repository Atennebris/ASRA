"""Learned tool-affinity index: a cross-session record of how well a SCAN/EXPLOIT tool has
performed for a given (tool_name, target_shape, phase) context -- the "which tool should I reach
for" signal, scored from the agent's own real history instead of a per-moment model guess.

Distinct from two existing, adjacent stores:
- agent/tools/tool_memory_store.py -- exact tech/WAF fingerprint, no phase, one dedup'd entry per
  (fingerprint, tool) that only ever upgrades toward "productive". This module is phase-aware
  (recon/analyze/exploit all score separately) and keeps real per-outcome COUNTERS rather than one
  mutable verdict, which is what lets it compute a confidence-aware rate instead of a single flag.
- agent/tools/playbook_store.py -- proven exploitation TECHNIQUES/payloads, not tool choice.

Negative knowledge is deliberately narrow, by design, not by oversight: ONLY a mechanical
execution failure (non-zero exit, a raised exception, a timeout, an empty-with-error result, a
validator rejection, a detected shape mismatch) ever lowers a tool's standing. A tool that ran
cleanly and reported "not present / not vulnerable" did its job -- that is recorded as a neutral
null_result, never a failure. "The tool found nothing" is not negative knowledge; "the tool failed
to run usefully" is. Three outcome classes per attempt, mutually exclusive:
  1. success     -- ran AND the engagement's own recorded outcome credits it (a finding's
                     tool_timeline, or a confirmed hypothesis's resolving_tool).
  2. null_result -- ran cleanly, no mechanical failure, not (yet, or ever) credited as a success.
                     Covers both "legitimately ruled this out" and "ran fine, verdict pending" --
                     either way it KEEPS the tool's standing, it never counts against it.
  3. failure     -- a real execution failure, classified mechanically from the tool-runner result,
                     never an LLM judgment call.

Five safeguards (so a misjudgment here can never do real damage):
- Statistical/thresholded: below TOOL_AFFINITY_MIN_ATTEMPTS, score_record returns None -- no
  promotion or demotion from a thin sample.
- Soft steer, never a gate: this module only ever feeds a reordering/labeling hook
  (agent/core.py's _apply_plan_recommendations) -- a tool stays fully callable regardless of score.
- Context-scoped: every record is keyed by the full (tool, target_shape, phase) triple, never a
  bare per-tool verdict -- a tool useless on one shape can be essential on another.
- Decays: _staleness_decay fades an old record's weight over TOOL_AFFINITY_DECAY_DAYS.
- Operator overrides win: set_operator_feedback's "trusted"/"irrelevant" mark short-circuits the
  learned score entirely, in either direction.

Item 5 (typed/grouped recall) re-verified against this module's actual, already-landed key
structure rather than the roadmap's original guess: every lookup here (record_outcome,
score_record via recommended_tools_for) already goes through _record_key(tool, target_shape,
phase) -- an exact dict key, never a flat scan merging every shape into one similarity pool. A
pe_x86_64 record and a web record already can't dilute each other; there was nothing to re-index
here. shape_bucket() (below, promoted from a private helper so tool_retrieval_store.py can reuse
the exact same web/binary coarsening instead of a second, drifting copy) was already this
module's own typed facet for the one place that DOES need a coarser grouping -- the cold-start
prior table, keyed by (shape bucket, phase), not by every exact architecture string. "mode" (the
roadmap's other named facet) does NOT apply as a separate axis here the way it does for
playbook_store's technique entries: this store's target_shape already carries that distinction on
its own (RE-mode sessions get a real detect_target_shape() value; every other mode -- "agent"
pipeline or "interactive" console -- gets the coarse "web"/"unknown" fallback from
_current_target_affinity_shape), so adding session["mode"] as a second key dimension would only
fragment the same data for no behavioral gain.

Item 6 (distillation + decay) adds run_maintenance_pass() below -- a periodic PASS that mutates
the store (prune/consolidate), distinct from _staleness_decay's existing per-READ fade. Reuses this
project's established "same call site as the skill library's own periodic pass" pattern
(agent/core.py's _run_playbook_distillation_pass) rather than a second, separately-scheduled
mechanism.

Same on-disk convention as allowed_targets.py/tool_memory_store.py (atomic tmp-file + os.replace,
corrupt/missing file treated as "nothing stored yet", resolve_global_app_dir() location).
"""
from __future__ import annotations

import json
import math
import os
import uuid
from datetime import datetime, timezone

from agent.utils.logger import get_logger
from projects.paths import resolve_global_app_dir

logger = get_logger("TOOLS")

TOOL_AFFINITY_STORE_PATH = resolve_global_app_dir() / "data" / "tool_affinity.json"

_VALID_OUTCOME_CLASSES = ("success", "null_result", "failure")
_COUNTER_FIELD = {"success": "successes", "null_result": "null_results", "failure": "failures"}
_VALID_FEEDBACK = ("trusted", "irrelevant")

# Sentinels score_record returns for an operator override -- outside the real [0, 1] Wilson range
# on either side, so a trusted/irrelevant mark always sorts first/last regardless of the learned
# stat underneath it (safeguard #5 / item 7's "operator feedback as top-weight signal").
_OPERATOR_TRUSTED_SCORE = 2.0
_OPERATOR_IRRELEVANT_SCORE = -1.0

# A standard statistics constant (95% confidence), not a project-specific tunable -- not read from
# env for that reason, same as PLAYBOOK's own Wilson-style smoothing has no env knob either.
_WILSON_Z = 1.96

# How many promoted tool names _apply_plan_recommendations' own reordering/labeling is allowed to
# carry per phase -- keeps the prompt's "[[Plan-recommended] ...]" labeling readable instead of
# promoting the entire candidate list once several tools clear a positive score.
_MAX_PROMOTED = 5

# Exploration allowance (item 7): how many under-tried candidates always get a reserved look-in per
# call, so a genuinely-better-but-unused tool is never permanently locked out by a loop that only
# ever recommends what already worked. Deliberately small and not env-configurable -- this is a
# floor against lock-in, not a dial an operator is expected to need to tune.
_EXPLORATION_SLOTS = 1

# Curated, deliberately small fallback for a (shape-bucket, phase) with no learned history yet
# (item 7's Cold-start priors) -- overridden the moment real attempts accumulate (recommended_
# tools_for only ever reaches for this when nothing in the store clears TOOL_AFFINITY_MIN_ATTEMPTS
# for any of the current candidates). Tool names are real, registered ASRA tools (agent/tools/
# __init__.py) -- not placeholders.
_COLD_START_PRIORS: dict[tuple[str, str], tuple[str, ...]] = {
    ("web", "recon"): ("whatweb", "subfinder", "amass_enum", "nmap"),
    ("web", "analyze"): ("nuclei", "nikto"),
    ("web", "exploit"): ("sqlmap", "dalfox", "wpscan", "ffuf"),
    ("binary", "recon"): ("radare2", "binwalk"),
    ("binary", "analyze"): ("radare2", "upx", "jadx"),
    ("binary", "exploit"): ("gdb", "radare2"),
}
# Substrings of a real RE-mode target_shape (detect_target_shape(), agent/tools/builders/
# re_target.py -- e.g. "pe_x86_64"/"elf"/"jvm_bytecode"/"apk"/"ipa"/"wasm"/"unknown_binary_blob")
# that bucket it under "binary" for the cold-start map above, so that map needs one entry per
# phase, not one per exact architecture/format.
_BINARY_SHAPE_MARKERS = ("pe_", "elf", "jvm", "apk", "ipa", "wasm", "mach", "dotnet", "dex", "evm", "binary")


def is_enabled() -> bool:
    return os.getenv("TOOL_AFFINITY_ENABLED", "true").strip().lower() not in ("false", "0", "no")


def _min_attempts() -> int:
    try:
        return max(0, int(os.getenv("TOOL_AFFINITY_MIN_ATTEMPTS", "4")))
    except ValueError:
        return 4


def _decay_halflife_days() -> float:
    try:
        return float(os.getenv("TOOL_AFFINITY_DECAY_DAYS", "180"))
    except ValueError:
        return 180.0


def _negative_weight() -> float:
    try:
        return max(0.0, float(os.getenv("TOOL_AFFINITY_NEGATIVE_WEIGHT", "1.5")))
    except ValueError:
        return 1.5


def _prune_score_threshold() -> float:
    try:
        return max(0.0, float(os.getenv("TOOL_AFFINITY_PRUNE_SCORE_THRESHOLD", "0.05")))
    except ValueError:
        return 0.05


def _prune_stale_days() -> float:
    try:
        return max(0.0, float(os.getenv("TOOL_AFFINITY_PRUNE_STALE_DAYS", "365")))
    except ValueError:
        return 365.0


def _consolidate_score_threshold() -> float:
    try:
        return max(0.0, float(os.getenv("TOOL_AFFINITY_CONSOLIDATE_SCORE_THRESHOLD", "0.75")))
    except ValueError:
        return 0.75


def _record_key(tool: str, target_shape: str, phase: str) -> str:
    return f"{tool}::{target_shape or 'unknown'}::{phase or 'unscoped'}"


def load_tool_affinity_store() -> dict:
    if not TOOL_AFFINITY_STORE_PATH.exists():
        return {}
    try:
        with TOOL_AFFINITY_STORE_PATH.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        logger.debug("tool_affinity.json unreadable (%s) — treating as empty store", exc)
        return {}
    if not isinstance(data, dict):
        logger.debug("tool_affinity.json does not contain an object — treating as empty store")
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, dict)}


def _write_tool_affinity_store(store: dict) -> None:
    TOOL_AFFINITY_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = TOOL_AFFINITY_STORE_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)
    os.replace(tmp_path, TOOL_AFFINITY_STORE_PATH)


def _get_or_create_record(store: dict, key: str, tool: str, target_shape: str, phase: str) -> dict:
    record = store.get(key)
    if record is None:
        record = {
            "id": uuid.uuid4().hex[:12],
            "tool": tool,
            "target_shape": target_shape or "unknown",
            "phase": phase or "unscoped",
            "attempts": 0,
            "successes": 0,
            "null_results": 0,
            "failures": 0,
            "last_updated": None,
            "source_session_ids": [],
            "operator_feedback": None,
            "operator_feedback_at": None,
        }
        store[key] = record
    return record


def record_outcome(tool: str, target_shape: str, phase: str, outcome_class: str, session_id: str | None = None) -> None:
    """Bumps attempts + the matching counter for (tool, target_shape, phase). outcome_class is
    classified by the CALLER (agent/core.py's _track_tool_affinity) -- mechanically for a real
    execution failure, read straight off the tool-runner result, no judgment call needed here.
    Never raises -- a transient disk hiccup must never take down an otherwise-healthy scan over a
    telemetry side-channel (the caller also wraps its own call in a try/except, same belt-and-
    braces posture tool_memory_store's hooks already use).
    """
    if not is_enabled():
        return
    if outcome_class not in _VALID_OUTCOME_CLASSES or not tool:
        logger.debug("tool_affinity: ignoring invalid outcome_class=%r for tool=%r", outcome_class, tool)
        return
    try:
        store = load_tool_affinity_store()
        key = _record_key(tool, target_shape, phase)
        record = _get_or_create_record(store, key, tool, target_shape, phase)
        record["attempts"] = int(record.get("attempts", 0)) + 1
        record[_COUNTER_FIELD[outcome_class]] = int(record.get(_COUNTER_FIELD[outcome_class], 0)) + 1
        record["last_updated"] = datetime.now(timezone.utc).isoformat()
        sources = record.setdefault("source_session_ids", [])
        if session_id and session_id not in sources:
            sources.append(session_id)
        _write_tool_affinity_store(store)
        logger.debug(
            "tool_affinity: tool=%r shape=%r phase=%r outcome=%s attempts=%d (success=%d null=%d fail=%d)",
            tool, target_shape, phase, outcome_class, record["attempts"], record["successes"], record["null_results"], record["failures"],
        )
    except Exception:
        logger.debug("tool_affinity: record_outcome failed for tool=%r, skipping this update", tool, exc_info=True)


def upgrade_to_success(tool: str, target_shape: str, phase: str, session_id: str | None = None) -> None:
    """Deferred class-1 credit once a finding/confirmed hypothesis genuinely lands backed by this
    tool's own output -- same two-phase deferred-credit shape tool_memory_store.credit_tool_run and
    playbook_store's injected_count->led_to_finding_count already use: a dispatch alone is only
    ever recorded provisionally as null_result (class 2 -- ran fine, no verdict yet); real credit
    only ever comes from here. Moves one unit from null_results to successes (floored at 0) rather
    than just incrementing successes alone, so successes+null_results+failures keeps tracking real
    attempts -- the invariant score_record's Wilson bound relies on to read "how often did this
    tool actually run usefully" cleanly.
    """
    if not is_enabled():
        return
    try:
        store = load_tool_affinity_store()
        key = _record_key(tool, target_shape, phase)
        record = store.get(key)
        if record is None:
            # A finding credited a tool under a (shape, phase) key that was never dispatched under
            # THIS exact key (e.g. the session's fingerprint drifted between dispatch and credit
            # time) -- still worth recording as one real successful attempt, not silently dropped.
            record = _get_or_create_record(store, key, tool, target_shape, phase)
            record["attempts"] = int(record.get("attempts", 0)) + 1
        elif int(record.get("null_results", 0)) > 0:
            record["null_results"] = int(record["null_results"]) - 1
        record["successes"] = int(record.get("successes", 0)) + 1
        record["last_updated"] = datetime.now(timezone.utc).isoformat()
        sources = record.setdefault("source_session_ids", [])
        if session_id and session_id not in sources:
            sources.append(session_id)
        _write_tool_affinity_store(store)
        logger.debug(
            "tool_affinity: upgraded tool=%r shape=%r phase=%r to success (attempts=%d successes=%d)",
            tool, target_shape, phase, record["attempts"], record["successes"],
        )
    except Exception:
        logger.debug("tool_affinity: upgrade_to_success failed for tool=%r, skipping this update", tool, exc_info=True)


def _age_days(iso_ts: str | None) -> float | None:
    if not iso_ts:
        return None
    try:
        dt = datetime.fromisoformat(str(iso_ts))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - dt).total_seconds() / 86400.0)


def _staleness_decay(record: dict) -> float:
    """Same shape as playbook_store._staleness_decay (0.2..1.0, halving every decay-halflife days)
    but driven by this module's OWN TOOL_AFFINITY_DECAY_DAYS, not playbook's PLAYBOOK_DECAY_HALFLIFE_
    DAYS -- a tool's usefulness and a specific payload's usefulness don't necessarily rot at the
    same rate, so they get independent knobs even though the formula is identical."""
    hl = _decay_halflife_days()
    if hl <= 0:
        return 1.0
    age = _age_days(record.get("last_updated"))
    if age is None:
        return 1.0
    return max(0.2, 0.5 ** (age / hl))


def _wilson_lower_bound(successes: float, n: float) -> float:
    """95%-confidence Wilson score lower bound -- the standard "a 1/1 shouldn't outrank a 40/50"
    smoothing (item 1's own wording). Pure function of (successes, n); callers decide what counts
    as a "success" for their own ratio."""
    if n <= 0:
        return 0.0
    phat = successes / n
    z2 = _WILSON_Z * _WILSON_Z
    denom = 1.0 + z2 / n
    center = phat + z2 / (2 * n)
    margin = _WILSON_Z * math.sqrt(max(0.0, phat * (1 - phat) / n + z2 / (4 * n * n)))
    return (center - margin) / denom


def score_record(record: dict | None) -> float | None:
    """Confidence-aware "does this tool run usefully here" score. None means "no verdict" -- below
    TOOL_AFFINITY_MIN_ATTEMPTS (safeguard #1: never downweight/promote from too little data) or no
    record at all.

    An operator override (set_operator_feedback) short-circuits everything else, in either
    direction (safeguard #5 / item 7's "operator feedback as top-weight signal").

    Otherwise: "ran usefully" = a real success OR a legitimate clean rule-out (null_result) --
    both KEEP the tool's standing, this is item 2's central nuance. Only a mechanical execution
    failure counts against it, and TOOL_AFFINITY_NEGATIVE_WEIGHT tunes exactly how hard: inflating
    the effective sample size by (failures * weight) dilutes the Wilson ratio's denominator without
    ever touching its numerator, so more (or more heavily weighted) failures pull the score down
    while null_results/successes never do.
    """
    if not record:
        return None
    feedback = record.get("operator_feedback")
    if feedback == "trusted":
        return _OPERATOR_TRUSTED_SCORE
    if feedback == "irrelevant":
        return _OPERATOR_IRRELEVANT_SCORE
    attempts = int(record.get("attempts", 0) or 0)
    if attempts < _min_attempts():
        return None
    successes = int(record.get("successes", 0) or 0)
    null_results = int(record.get("null_results", 0) or 0)
    failures = int(record.get("failures", 0) or 0)
    worked = successes + null_results
    effective_total = worked + failures * _negative_weight()
    if effective_total <= 0:
        return None
    return _wilson_lower_bound(worked, effective_total) * _staleness_decay(record)


def explain_record(record: dict) -> str:
    """One-line, auditable citation behind a promotion/demotion -- traces to the record's own real
    counters, never invented (item 7's Explainability strengthening). e.g. "6/8 past exploit
    attempts with sqlmap against web targets ran usefully (5 success, 1 clean rule-out, 2
    execution failure)"."""
    worked = int(record.get("successes", 0) or 0) + int(record.get("null_results", 0) or 0)
    attempts = int(record.get("attempts", 0) or 0)
    base = (
        f"{worked}/{attempts} past {record.get('phase')} attempts with {record.get('tool')} "
        f"against {record.get('target_shape')} targets ran usefully "
        f"({record.get('successes', 0)} success, {record.get('null_results', 0)} clean rule-out, "
        f"{record.get('failures', 0)} execution failure)"
    )
    feedback = record.get("operator_feedback")
    if feedback == "trusted":
        return f"operator marked trusted — {base}"
    if feedback == "irrelevant":
        return f"operator marked irrelevant — {base}"
    if record.get("consolidated"):
        return f"confirmed stable — {base}"
    return base


def shape_bucket(target_shape: str) -> str:
    """Coarsens a real target_shape value down to the handful of buckets the cold-start map is
    keyed by -- "binary" covers every RE-mode shape detect_target_shape() can return, "web" covers
    the (far more common) web-pentest case, which carries no target_shape field of its own at all
    (see agent/core.py's _current_target_affinity_shape). "unknown" (no signal at all yet -- a
    brand-new session before its first real recon call) deliberately does NOT fall back to "web":
    _COLD_START_PRIORS has no "unknown" entries, so a genuinely signal-less session gets no cold-
    start promotion at all rather than an unearned guess that it must be a web target.

    Public (not a private helper) since item 5 of the tool-selection roadmap has
    tool_retrieval_store.py reuse this EXACT coarsening for its own shape-match scoring facet --
    one shared web/binary bucket definition, not two copies that could silently drift apart."""
    shape = (target_shape or "").strip().lower()
    if not shape or shape == "unknown":
        return "unknown"
    if any(marker in shape for marker in _BINARY_SHAPE_MARKERS):
        return "binary"
    return "web"


def cold_start_tools(target_shape: str, phase: str) -> tuple[str, ...]:
    """Curated static fallback for when there's no learned history yet for this (shape, phase) --
    day-one recommendations aren't empty (item 7's Cold-start priors). Learned affinity overrides
    this the moment real attempts accumulate -- recommended_tools_for only ever reaches for this
    when nothing in the store clears TOOL_AFFINITY_MIN_ATTEMPTS for any current candidate."""
    return _COLD_START_PRIORS.get((shape_bucket(target_shape), phase), ())


def recommended_tools_for(target_shape: str, phase: str, candidate_tool_names: set[str]) -> tuple[list[str], dict[str, str]]:
    """The item-1 consuming-hook data source for agent/core.py's _apply_plan_recommendations --
    ranks `candidate_tool_names` (this phase's own tool_specs) by learned affinity for this
    (target_shape, phase), falling back to a cold-start prior when nothing has enough history yet
    and always reserving one exploration slot for an under-tried candidate. Returns (tool names to
    promote, {tool_name: one-line explanation}).

    Soft steer only (safeguard #2): never removes a tool from `candidate_tool_names`, only names
    which ones to promote -- the caller is responsible for reordering/labeling, this function never
    touches a ToolSpec. Never raises; disabled or no candidates returns ([], {}).
    """
    if not is_enabled() or not candidate_tool_names:
        return [], {}
    try:
        store = load_tool_affinity_store()
        scored: list[tuple[float, str]] = []
        unscored: list[str] = []
        reasons: dict[str, str] = {}
        for tool in candidate_tool_names:
            record = store.get(_record_key(tool, target_shape, phase))
            score = score_record(record)
            if score is None:
                unscored.append(tool)
            else:
                scored.append((score, tool))
                reasons[tool] = explain_record(record)
        scored.sort(key=lambda pair: pair[0], reverse=True)
        promoted = [tool for score, tool in scored if score > 0][:_MAX_PROMOTED]
        # A tool the operator explicitly marked "irrelevant" (score == _OPERATOR_IRRELEVANT_SCORE,
        # the only way a scored tool ends up with score <= 0 that must stay excluded even from the
        # fallbacks below) -- real, confirmed gap this closes: without this set, an operator
        # override that correctly kept a tool OUT of the learned promotion above could still get
        # silently reintroduced a few lines down by the cold-start prior or the exploration slot,
        # neither of which otherwise has any notion of "the operator already said no to this one".
        operator_excluded = {tool for score, tool in scored if score == _OPERATOR_IRRELEVANT_SCORE}

        if not promoted:
            # Cold start (item 7) -- nothing in the store clears the attempt threshold for ANY
            # candidate here yet.
            prior = [t for t in cold_start_tools(target_shape, phase) if t in candidate_tool_names and t not in operator_excluded]
            for tool in prior:
                reasons.setdefault(tool, f"cold-start prior for {target_shape or 'unknown'}/{phase} (no learned history yet)")
            promoted = prior

        # Exploration allowance (item 7): reserve room for one under-tried candidate, so a
        # genuinely-better-but-unused tool is never permanently locked out by a loop that only ever
        # recommends what already worked. Deterministic (not random) for reproducibility -- the
        # first under-tried candidate not already promoted, in stable sorted order. Only kicks in
        # once `scored` is non-empty -- i.e. at least one candidate in this EXACT (shape, phase)
        # already has enough history to be ranked at all. With zero learned history anywhere, there
        # is nothing yet to be locked out FROM, so reserving a slot would just be noise (and would
        # make a plain cold-start call non-deterministic-looking by always tacking on one arbitrary
        # extra tool even when nothing has ever actually run).
        slots_left = _EXPLORATION_SLOTS if scored else 0
        for tool in sorted(unscored):
            if slots_left <= 0:
                break
            if tool in promoted or tool in operator_excluded:
                continue
            reasons.setdefault(tool, "exploration slot — under-tried here, reserved a look-in so it isn't permanently passed over")
            promoted.append(tool)
            slots_left -= 1

        return promoted, reasons
    except Exception:
        logger.debug("tool_affinity: recommended_tools_for failed for shape=%r phase=%r, returning no recommendation", target_shape, phase, exc_info=True)
        return [], {}


def _find_key_and_record_by_id(store: dict, record_id: str) -> tuple[str, dict] | tuple[None, None]:
    for key, record in store.items():
        if record.get("id") == record_id:
            return key, record
    return None, None


def set_operator_feedback(record_id: str, feedback: str | None) -> bool:
    """Operator's manual override (safeguard #5 / item 7's top-weight signal) -- same
    operator_trusted-pattern as playbook_store.set_skill_trust: advisory metadata that outranks the
    learned stat in score_record, never a gate (the tool stays fully callable regardless of this
    mark). feedback=None clears any existing mark. Returns False if record_id doesn't resolve to a
    stored record (nothing to mark feedback on yet)."""
    if feedback is not None and feedback not in _VALID_FEEDBACK:
        logger.debug("tool_affinity: ignoring invalid feedback=%r", feedback)
        return False
    store = load_tool_affinity_store()
    _key, record = _find_key_and_record_by_id(store, record_id)
    if record is None:
        return False
    record["operator_feedback"] = feedback
    record["operator_feedback_at"] = datetime.now(timezone.utc).isoformat() if feedback else None
    _write_tool_affinity_store(store)
    logger.debug("tool_affinity: operator feedback id=%s tool=%r -> %r", record_id, record.get("tool"), feedback)
    return True


def list_records() -> list[dict]:
    """Every stored record, newest-updated first -- the UI's read side (Playbook page's own Tool
    Recommendations panel)."""
    return sorted(load_tool_affinity_store().values(), key=lambda r: r.get("last_updated") or "", reverse=True)


def run_maintenance_pass() -> dict:
    """Item 6 of the tool-selection roadmap: a periodic PASS that mutates the store itself, on top
    of the decay-on-READ _staleness_decay already applies inside score_record every time a record
    is scored. Those are two different things -- decay only ever fades a record's effective weight
    for whoever is reading it right now; nothing ever actually prunes or consolidates the stored
    data on its own. This is the "maintains itself without manual curation" half the roadmap asked
    for, triggered from the exact same call site agent/core.py's own
    _run_playbook_distillation_pass already runs from (same amortized, once-per-pipeline-pass
    cadence) rather than a second, separately-scheduled background job.

    Two actions, both read straight off score_record's own already-correct math (no second scoring
    path invented here):
    - Prune: a record whose learned score is at/below TOOL_AFFINITY_PRUNE_SCORE_THRESHOLD (a real,
      consistent execution-failure pattern -- safeguard #3 already means a low score here can only
      mean that) AND whose last_updated is at/beyond TOOL_AFFINITY_PRUNE_STALE_DAYS (long past any
      plausible comeback, not merely decayed) is removed outright -- proven noise, the same role
      playbook_store.prune_low_value plays for technique entries.
    - Consolidate ("firm up"): a record with enough history to clear TOOL_AFFINITY_MIN_ATTEMPTS and
      a score at/above TOOL_AFFINITY_CONSOLIDATE_SCORE_THRESHOLD gets a durable `consolidated=True`
      stamp (idempotent) -- explain_record surfaces this as "confirmed stable", a record-keeping
      signal for the operator, not a second ranking mechanism (score_record's own Wilson bound +
      decay already rank it correctly on their own).

    Any record carrying an operator_feedback mark (either direction) is skipped entirely by BOTH
    actions -- real, confirmed bug this closes before it could ship: pruning an "irrelevant"-marked
    record would delete the very row recommended_tools_for's operator_excluded set depends on
    existing, silently undoing item 2's own fix for a tool being unretired by the cold-start/
    exploration fallbacks. The operator's own mark already outranks everything learned here
    (safeguard #5); maintenance must never touch it either way.

    Never raises -- same belt-and-braces posture as every other public function in this module, a
    transient disk hiccup must never take down an otherwise-healthy pipeline pass over a self-
    maintenance side-channel. Returns {"pruned": int, "consolidated": int} (0s if disabled, empty,
    or on any internal error).
    """
    if not is_enabled():
        return {"pruned": 0, "consolidated": 0}
    try:
        store = load_tool_affinity_store()
        if not store:
            return {"pruned": 0, "consolidated": 0}
        prune_score = _prune_score_threshold()
        prune_days = _prune_stale_days()
        consolidate_score = _consolidate_score_threshold()

        pruned_keys: list[str] = []
        consolidated_keys: list[str] = []
        for key, record in store.items():
            if record.get("operator_feedback"):
                continue  # operator's own mark always wins -- never auto-pruned or re-labeled
            score = score_record(record)
            if score is None:
                continue  # below TOOL_AFFINITY_MIN_ATTEMPTS -- too thin a sample for either action
            if score <= prune_score:
                age = _age_days(record.get("last_updated"))
                if age is not None and age >= prune_days:
                    pruned_keys.append(key)
                    continue
            if score >= consolidate_score and not record.get("consolidated"):
                record["consolidated"] = True
                record["consolidated_at"] = datetime.now(timezone.utc).isoformat()
                consolidated_keys.append(key)

        for key in pruned_keys:
            store.pop(key, None)
        if pruned_keys or consolidated_keys:
            _write_tool_affinity_store(store)
        if pruned_keys:
            logger.debug("tool_affinity: maintenance pass pruned %d degrading, stale record(s): %s", len(pruned_keys), pruned_keys)
        if consolidated_keys:
            logger.debug("tool_affinity: maintenance pass consolidated %d consistently-strong record(s): %s", len(consolidated_keys), consolidated_keys)
        return {"pruned": len(pruned_keys), "consolidated": len(consolidated_keys)}
    except Exception:
        logger.debug("tool_affinity: run_maintenance_pass failed, leaving store as-is", exc_info=True)
        return {"pruned": 0, "consolidated": 0}
