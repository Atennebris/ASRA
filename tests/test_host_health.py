"""Deterministic per-host success/failure tracking (agent/core.py's _track_host_health,
_dead_host_blocked, _extract_target_host) -- session["recon_result"]["host_health"]. Real incident
this exists because of: a real session hit the SAME dead hosts (portal.example.com,
forum.example.com, ...) with http_request/whatweb/tcp_port_check dozens of times across Analyze
AND Exploit, every single attempt failing, with nothing ever recognizing "this host is dead, stop
spending real attempts on it" or reporting it anywhere the operator could see at a glance.

Scoped to any call naming a "target" argument -- deliberately NOT ToolSpec.requires_allowed_target
(that flag means something unrelated: exploit-tier operator-approval gating, per registry.py's own
docstring) -- confirmed live that http_request/whatweb/tcp_port_check/nmap, the exact tools that
caused the real incident, all have requires_allowed_target=False.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _dead_host_blocked, _extract_target_host, _run_tool_with_retry, _track_host_health
from agent.tools.registry import TOOL_REGISTRY, get_tool
from sessions import store
import dataclasses


def _run(coro):
    return asyncio.run(coro)


def _swap_tool(name, fake_result):
    index = next(i for i, s in enumerate(TOOL_REGISTRY) if s.name == name)
    original_spec = TOOL_REGISTRY[index]
    TOOL_REGISTRY[index] = dataclasses.replace(original_spec, tool_tier=1, native_function=lambda params: dict(fake_result))
    return index, original_spec


class _FailIfCalledLLM:
    provider_id = "test-provider"
    model = "test-model"
    def complete(self, messages, tools=None, stop_check=None):
        raise AssertionError("no LLM call should be needed for a deterministic pre-execution skip")


def _base_session(session_id):
    return {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }


# --- _extract_target_host: pure unit tests ---


def test_extract_target_host_from_a_bare_host():
    assert _extract_target_host({"target": "example.com"}) == "example.com"


def test_extract_target_host_from_a_full_url():
    assert _extract_target_host({"target": "https://portal.example.com/login"}) == "portal.example.com"


def test_extract_target_host_from_a_list_shaped_target():
    assert _extract_target_host({"target": ["example.com", "other.com"]}) == "example.com"


def test_extract_target_host_is_none_for_a_missing_target():
    assert _extract_target_host({"domain": "example.com"}) is None  # e.g. crt_sh_lookup's own param name


def test_extract_target_host_is_none_for_an_empty_target():
    assert _extract_target_host({"target": ""}) is None


# --- _track_host_health: pure unit tests ---


def test_track_host_health_counts_a_success():
    session = {}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"target": "https://example.com"}, {"status": "ok"})
    entry = dict(session["recon_result"]["host_health"]["example.com"])
    last_updated_at = entry.pop("last_updated_at")
    assert entry == {
        "failures": 0, "successes": 1, "consecutive_failures": 0, "last_error": None,
        "consecutive_failure_tools": [],
    }
    assert last_updated_at  # a real ISO timestamp -- telemetry only, not a staleness gate


def test_track_host_health_counts_a_failure_and_records_the_error():
    session = {}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"target": "https://example.com"}, {"status": "error", "error": "Connection refused"})
    entry = session["recon_result"]["host_health"]["example.com"]
    assert entry["failures"] == 1
    assert entry["successes"] == 0
    assert entry["consecutive_failures"] == 1
    assert entry["last_error"] == "Connection refused"


def test_track_host_health_accumulates_across_calls():
    session = {}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"target": "example.com"}, {"status": "error", "error": "e1"})
    _track_host_health(ctx, {"target": "example.com"}, {"status": "error", "error": "e2"})
    _track_host_health(ctx, {"target": "example.com"}, {"status": "ok"})
    entry = session["recon_result"]["host_health"]["example.com"]
    assert entry["failures"] == 2
    assert entry["successes"] == 1
    assert entry["last_error"] == "e2"
    assert entry["consecutive_failures"] == 0  # the trailing success resets the streak


def test_track_host_health_resumes_the_streak_from_an_older_session_shape_missing_the_field():
    """A host_health entry persisted before consecutive_failures existed lacks the key entirely --
    the very next real dispatch must self-heal instead of raising a KeyError."""
    session = {"recon_result": {"host_health": {"example.com": {"failures": 2, "successes": 0, "last_error": "e"}}}}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"target": "example.com"}, {"status": "error", "error": "e3"})
    entry = session["recon_result"]["host_health"]["example.com"]
    assert entry["failures"] == 3
    assert entry["consecutive_failures"] == 1


def test_track_host_health_ignores_a_skipped_status():
    """A guardrail decision (out-of-scope, tech-gated, already-dead) is not a real connectivity
    outcome -- must never count as either a success or a failure."""
    session = {}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"target": "example.com"}, {"status": "skipped", "reason": "out of scope"})
    assert session.get("recon_result", {}).get("host_health", {}) == {}


def test_track_host_health_ignores_a_call_with_no_target_argument():
    session = {}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"domain": "example.com"}, {"status": "error", "error": "e"})
    assert session.get("recon_result", {}).get("host_health", {}) == {}


def test_track_host_health_ignores_a_never_dispatched_build_command_failure():
    """Real, confirmed incident: agent/tools/runner.py's own build_command/native_function
    exception handlers set never_dispatched=True on a result that never even attempted to reach
    the host at all (a malformed call -- e.g. a missing/misplaced argument) -- this must NEVER
    count toward the host's own consecutive-failure streak. Without this, 3 repeats of the SAME
    argument mistake (an easy thing for a model to repeat, since the tool never even ran to teach
    it otherwise) permanently blacklisted a real session's own PRIMARY target host from every
    other tool for the rest of the phase, confirmed live against a real scan."""
    session = {}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"target": "example.com"}, {"status": "error", "error": "e", "never_dispatched": True})
    assert session.get("recon_result", {}).get("host_health", {}) == {}


def test_track_host_health_still_counts_a_real_dispatch_failure_without_the_marker():
    """Regression guard for the fix above -- a genuine dispatch-level failure (no never_dispatched
    marker) must still be tracked exactly as before; the fix only excludes the specific
    never-even-tried case, not error results in general."""
    session = {}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    _track_host_health(ctx, {"target": "example.com"}, {"status": "error", "error": "Connection refused"})
    entry = session["recon_result"]["host_health"]["example.com"]
    assert entry["consecutive_failures"] == 1


# --- reset_host_health_streaks_for_new_pass: pure unit tests ---


def test_reset_host_health_streaks_clears_consecutive_fields_but_keeps_lifetime_counts():
    recon_result = {
        "targets": [{"host": "example.com"}],
        "host_health": {
            "example.com": {
                "failures": 5, "successes": 1, "consecutive_failures": 3,
                "last_error": "timeout", "consecutive_failure_tools": ["nmap", "whatweb"],
                "last_updated_at": "2026-01-01T00:00:00+00:00",
            },
        },
    }
    fresh = store.reset_host_health_streaks_for_new_pass(recon_result)
    entry = fresh["host_health"]["example.com"]
    assert entry["consecutive_failures"] == 0
    assert entry["consecutive_failure_tools"] == []
    assert entry["failures"] == 5
    assert entry["successes"] == 1
    assert entry["last_error"] == "timeout"
    assert entry["last_updated_at"] == "2026-01-01T00:00:00+00:00"
    # deepcopy independence -- the original recon_result must be untouched
    assert recon_result["host_health"]["example.com"]["consecutive_failures"] == 3
    assert fresh["targets"] == recon_result["targets"]


def test_reset_host_health_streaks_is_a_noop_for_a_healthy_host():
    recon_result = {"host_health": {"example.com": {
        "failures": 0, "successes": 2, "consecutive_failures": 0,
        "last_error": None, "consecutive_failure_tools": [],
    }}}
    fresh = store.reset_host_health_streaks_for_new_pass(recon_result)
    assert fresh["host_health"] == recon_result["host_health"]


def test_reset_host_health_streaks_handles_missing_or_empty_recon_result():
    assert store.reset_host_health_streaks_for_new_pass(None) == {}
    assert store.reset_host_health_streaks_for_new_pass({}) == {}
    assert store.reset_host_health_streaks_for_new_pass({"targets": []}) == {"targets": []}


# --- _dead_host_blocked: pure unit tests ---


def test_dead_host_blocked_is_none_with_no_history():
    assert _dead_host_blocked({}, {"target": "example.com"}) is None


def test_dead_host_blocked_is_none_below_the_failure_threshold():
    session = {"recon_result": {"host_health": {"example.com": {"failures": 2, "successes": 0, "consecutive_failures": 2, "last_error": "e"}}}}
    assert _dead_host_blocked(session, {"target": "example.com"}) is None


def test_dead_host_blocked_is_none_right_after_a_success_even_with_many_lifetime_failures():
    """A flaky-but-still-sometimes-live host (successes interspersed with failures) must never be
    blocked -- consecutive_failures is reset to 0 by _track_host_health's own success branch, so a
    host currently on a winning streak stays unblocked regardless of how many times it failed
    earlier in the session."""
    session = {"recon_result": {"host_health": {"example.com": {"failures": 10, "successes": 1, "consecutive_failures": 0, "last_error": "e"}}}}
    assert _dead_host_blocked(session, {"target": "example.com"}) is None


def test_dead_host_blocked_fires_once_the_current_streak_hits_the_threshold_even_with_a_stale_success():
    """Real incident this covers: forum.example.com had 1 success early in the session but then
    failed every subsequent attempt (4 in a row, across 2+ distinct tools) -- the OLD "any success
    ever" rule kept it exempt forever, wasting calls all the way through the session's last phase.
    A stale lifetime success must no longer matter once the CURRENT streak crosses the threshold."""
    session = {"recon_result": {"host_health": {"example.com": {
        "failures": 4, "successes": 1, "consecutive_failures": 4, "last_error": "Connection refused",
        "consecutive_failure_tools": ["http_request", "whatweb"],
    }}}}
    reason = _dead_host_blocked(session, {"target": "example.com"})
    assert reason is not None
    assert "example.com" in reason
    assert "Connection refused" in reason


def test_dead_host_blocked_fires_at_the_threshold_with_zero_successes():
    session = {"recon_result": {"host_health": {"example.com": {
        "failures": 3, "successes": 0, "consecutive_failures": 3, "last_error": "Connection refused",
        "consecutive_failure_tools": ["http_request", "whatweb"],
    }}}}
    reason = _dead_host_blocked(session, {"target": "example.com"})
    assert reason is not None
    assert "example.com" in reason
    assert "Connection refused" in reason


def test_dead_host_blocked_is_none_when_the_streak_is_all_the_same_single_tool():
    """Real, confirmed incident this guards against: httpx alone repeatedly guessing the same
    nonexistent CLI flag racked up 3+ consecutive real failures against ginandjuice.shop, and the
    OLD single-tool-sufficient rule blocked whatweb/http_request/view_source/api_schema_discovery
    from ever even attempting that host for the rest of the session -- despite none of THEM having
    failed even once. One tool's own repeated argument mistake must never blacklist a host for
    every OTHER, unrelated tool; a host is only genuinely presumed dead once 2+ DIFFERENT tools
    have failed against it back-to-back, since a real network/reachability problem affects every
    tool that tries it, not just one."""
    session = {"recon_result": {"host_health": {"ginandjuice.shop": {
        "failures": 5, "successes": 3, "consecutive_failures": 5, "last_error": "flag provided but not defined: -response-in-json",
        "consecutive_failure_tools": ["httpx"],
    }}}}
    assert _dead_host_blocked(session, {"target": "ginandjuice.shop"}) is None


def test_dead_host_blocked_fires_for_a_long_single_tool_streak_past_the_higher_bar():
    """Real, confirmed incident this fixes (rev-retest-rescan-usr_8ba29f): send_raw_request tried
    33 cosmetically different wrappers (http://, ssh://, telnet://, bare host:port) against the same
    dead SSH port over ~29 minutes -- every one a genuine connection/protocol failure, never a
    CLI-flag-guessing mistake, yet the plain 2-distinct-tools rule (see the sibling test right above)
    never let this fire no matter how many times it failed. A single-tool streak THIS much longer
    than the httpx incident's own 5 failures is no longer plausibly "still guessing arguments" and
    is real host-level evidence on its own -- the higher single-tool bar (8) must still catch it."""
    session = {"recon_result": {"host_health": {"portal.example.com": {
        "failures": 33, "successes": 0, "consecutive_failures": 8, "last_error": "Connection refused",
        "consecutive_failure_tools": ["send_raw_request"],
    }}}}
    reason = _dead_host_blocked(session, {"target": "portal.example.com"})
    assert reason is not None
    assert "portal.example.com" in reason


def test_dead_host_blocked_is_none_for_a_single_tool_streak_still_below_the_higher_bar():
    session = {"recon_result": {"host_health": {"portal.example.com": {
        "failures": 7, "successes": 0, "consecutive_failures": 7, "last_error": "Connection refused",
        "consecutive_failure_tools": ["send_raw_request"],
    }}}}
    assert _dead_host_blocked(session, {"target": "portal.example.com"}) is None


def test_dead_host_blocked_is_none_for_an_older_session_shape_missing_the_field():
    """A host_health entry persisted before consecutive_failures existed lacks the key entirely --
    treated as "no recency signal yet" (0), not blocked, and left to self-heal from the next real
    dispatch (see _track_host_health's own equivalent test) rather than raising a KeyError."""
    session = {"recon_result": {"host_health": {"example.com": {"failures": 10, "successes": 0, "last_error": "e"}}}}
    assert _dead_host_blocked(session, {"target": "example.com"}) is None


def test_dead_host_blocked_is_none_for_a_call_with_no_target_argument():
    session = {"recon_result": {"host_health": {"example.com": {"failures": 10, "successes": 0, "last_error": "e"}}}}
    assert _dead_host_blocked(session, {"domain": "example.com"}) is None


# --- integration: _run_tool_with_retry actually blocks a confirmed-dead host pre-execution ---


def test_run_tool_with_retry_skips_a_confirmed_dead_host_without_dispatching(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    session = _base_session("usr_dead_host_blocked")
    session["recon_result"] = {"host_health": {"portal.example.com": {
        "failures": 3, "successes": 0, "consecutive_failures": 3, "last_error": "Connection refused",
        "consecutive_failure_tools": ["http_request", "whatweb"],
    }}}
    ctx = RunContext(llm=_FailIfCalledLLM(), session=session, session_id=session["session_id"])
    spec = get_tool("http_request")

    result = _run(_run_tool_with_retry(ctx, spec, {"target": "https://portal.example.com/login"}))

    assert result["status"] == "skipped"
    assert "portal.example.com" in result["reason"]


def test_run_tool_with_retry_tracks_real_failures_toward_the_dead_host_threshold(tmp_path, monkeypatch):
    """A real, live-through-the-actual-dispatch-path proof: three genuinely failing calls against
    the same host spanning 2 DISTINCT tools, and the FOURTH (from either tool) is blocked
    pre-execution -- not a hand-inspection of the helpers in isolation. Deliberately spans two
    tools, not one: see test_dead_host_blocked_is_none_when_the_streak_is_all_the_same_single_tool
    for the real incident (httpx alone) this distinction exists to guard against."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    # "failed" (not "error") -- deliberately NOT in _RETRYABLE_STATUSES, so this returns straight
    # through the first-attempt path with no 1-Step-Retry LLM call needed (_FailIfCalledLLM would
    # raise if one happened), same as an already-exhausted retry's own terminal status shape.
    index_a, original_spec_a = _swap_tool("tcp_port_check", {"status": "failed", "error": "Connection refused"})
    index_b, original_spec_b = _swap_tool("http_request", {"status": "failed", "error": "Connection refused"})
    try:
        session = _base_session("usr_dead_host_live")
        ctx = RunContext(llm=_FailIfCalledLLM(), session=session, session_id=session["session_id"])
        spec_a = next(s for s in TOOL_REGISTRY if s.name == "tcp_port_check")
        spec_b = next(s for s in TOOL_REGISTRY if s.name == "http_request")

        for spec, params in (
            (spec_a, {"target": "dead.example.com", "port": 80}),
            (spec_a, {"target": "dead.example.com", "port": 81}),
            (spec_b, {"target": "dead.example.com"}),
        ):
            result = _run(_run_tool_with_retry(ctx, spec, params))
            assert result["status"] == "failed"  # a real dispatch failure marked terminal by the runner

        blocked = _run(_run_tool_with_retry(ctx, spec_a, {"target": "dead.example.com", "port": 443}))
        assert blocked["status"] == "skipped"
        assert "dead.example.com" in blocked["reason"]
    finally:
        TOOL_REGISTRY[index_a] = original_spec_a
        TOOL_REGISTRY[index_b] = original_spec_b


def test_run_tool_with_retry_blocks_a_long_single_tool_failure_streak(tmp_path, monkeypatch):
    """Real, live-through-the-actual-dispatch-path proof of the single-tool higher-bar fix: the SAME
    tool failing 8 times in a row against the same host (cosmetically different URL scheme dressing
    each time, matching the real incident's own send_raw_request variations) is blocked on the 9th
    attempt, with no second tool involved at all."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    index, original_spec = _swap_tool("http_request", {"status": "failed", "error": "Connection refused"})
    try:
        session = _base_session("usr_dead_host_single_tool_live")
        ctx = RunContext(llm=_FailIfCalledLLM(), session=session, session_id=session["session_id"])
        spec = next(s for s in TOOL_REGISTRY if s.name == "http_request")

        for scheme in ("http", "https", "http", "https", "http", "https", "http", "https"):
            result = _run(_run_tool_with_retry(ctx, spec, {"target": f"{scheme}://portal.example.com:22"}))
            assert result["status"] == "failed"

        blocked = _run(_run_tool_with_retry(ctx, spec, {"target": "http://portal.example.com:22"}))
        assert blocked["status"] == "skipped"
        assert "portal.example.com" in blocked["reason"]
    finally:
        TOOL_REGISTRY[index] = original_spec
