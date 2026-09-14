"""agent/core.py's _llm_complete: once ctx.llm's own retry budget (llm_client._call_with_backoff)
is exhausted, the safe DEFAULT is to raise immediately -- no automatic cross-provider/model
switching at all, unless the operator has explicitly enabled and configured their own ordered
Reserve providers chain in Settings (agent/llm_client.py's get_fallback_chain_enabled/
get_next_chain_step docstrings have the full incident writeup for why this replaced the old
always-on get_fallback_provider).
"""
import asyncio

import pytest

import agent.core as core
from agent.core import RunContext, _llm_complete
from agent.llm_client import EmptyResponseError, LLMResponse
import httpx
import openai


@pytest.fixture(autouse=True)
def _isolated_exhausted_chain_steps(monkeypatch):
    # get_exhausted_chain_steps/get_claimed_chain_steps (agent/core.py) are module-level dicts
    # keyed by session_id, mutated as a normal side effect of _llm_complete's own fallback loop --
    # every test below reuses the same "usr_fallback_test" session_id, so without resetting these
    # between tests, an earlier test's own bookkeeping would silently leak into a later one.
    monkeypatch.setattr(core, "_exhausted_chain_steps", {})
    monkeypatch.setattr(core, "_claimed_chain_steps", {})


def _run(coro):
    return asyncio.run(coro)


def _base_ctx(llm):
    session = {"session_id": "usr_fallback_test", "logs": [], "findings": []}
    return RunContext(llm=llm, session=session, session_id=session["session_id"])


class _AlwaysFailingLLM:
    provider_id = "primary"
    model = "primary-model"

    def __init__(self, exc):
        self._exc = exc

    def complete(self, messages, tools=None, stop_check=None):
        raise self._exc


class _FallbackLLM:
    provider_id = "fallback"
    model = "fallback-model"

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content="from fallback", tool_calls=[])


def _connection_error():
    return openai.APIConnectionError(request=httpx.Request("POST", "https://example.test/v1/chat/completions"))


def test_llm_complete_reraises_immediately_when_fallback_chain_is_disabled(monkeypatch):
    """The safe default: disabled (as it is unless the operator opted in) means a failed primary
    call fails the turn outright -- no lookup, no chain walk, nothing. Real incident this default
    exists because of: the old always-on fallback silently spent a paid provider's tokens/money the
    operator never explicitly authorized as a reserve for a different one."""
    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: False)
    calls = {"chain_lookups": 0}
    monkeypatch.setattr(core, "get_fallback_chain", lambda: calls.__setitem__("chain_lookups", calls["chain_lookups"] + 1) or [])
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    try:
        _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))
        assert False, "expected EmptyResponseError to propagate"
    except EmptyResponseError:
        pass

    assert ctx.llm.provider_id == "primary"  # never swapped
    assert calls["chain_lookups"] == 0  # the chain isn't even consulted when disabled


def test_llm_complete_swaps_to_the_configured_chain_step_when_enabled(monkeypatch):
    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [{"provider": "fallback", "model": "fallback-model"}])
    monkeypatch.setattr(core, "get_next_chain_step", lambda chain, tried, health_ranking=None: _FallbackLLM() if ("fallback", "fallback-model") not in tried else None)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    result = _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))

    assert result.content == "from fallback"
    assert ctx.llm.provider_id == "fallback"


def test_llm_complete_swaps_on_connection_error_too(monkeypatch):
    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [{"provider": "fallback", "model": "fallback-model"}])
    monkeypatch.setattr(core, "get_next_chain_step", lambda chain, tried, health_ranking=None: _FallbackLLM() if ("fallback", "fallback-model") not in tried else None)
    ctx = _base_ctx(_AlwaysFailingLLM(_connection_error()))

    result = _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))

    assert result.content == "from fallback"
    assert ctx.llm.provider_id == "fallback"


def test_llm_complete_reraises_when_chain_enabled_but_empty(monkeypatch):
    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", lambda chain, tried, health_ranking=None: None)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    try:
        _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))
        assert False, "expected EmptyResponseError to propagate"
    except EmptyResponseError:
        pass


def test_llm_complete_tries_a_second_chain_step_when_the_first_also_fails(monkeypatch):
    """Real incident this loop preserves from the old fallback mechanism: several reserve steps
    configured, the first one also failing (its own quota separately exhausted) must not give up
    before a later, actually-usable step in the SAME chain is ever tried."""
    class _AlsoFailingFallback:
        provider_id = "fallback-1"
        model = "model-1"

        def complete(self, messages, tools=None, stop_check=None):
            raise EmptyResponseError("also no choices")

    seen_tried_steps = []

    def fake_get_next_chain_step(chain, tried_steps, health_ranking=None):
        seen_tried_steps.append(set(tried_steps))
        if ("fallback-1", "model-1") not in tried_steps:
            return _AlsoFailingFallback()
        return _FallbackLLM()  # a later, actually-usable step

    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", fake_get_next_chain_step)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    result = _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))

    assert result.content == "from fallback"
    assert ctx.llm.provider_id == "fallback"
    assert seen_tried_steps == [{("primary", "primary-model")}, {("primary", "primary-model"), ("fallback-1", "model-1")}]


def test_llm_complete_reraises_the_last_failure_once_the_whole_chain_is_exhausted(monkeypatch):
    class _AlsoFailingFallback:
        provider_id = "fallback-1"
        model = "model-1"

        def complete(self, messages, tools=None, stop_check=None):
            raise EmptyResponseError("fallback-1 also empty")

    def fake_get_next_chain_step(chain, tried_steps, health_ranking=None):
        if ("fallback-1", "model-1") not in tried_steps:
            return _AlsoFailingFallback()
        return None  # nothing else configured

    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", fake_get_next_chain_step)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("primary empty")))

    try:
        _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))
        assert False, "expected EmptyResponseError to propagate"
    except EmptyResponseError as exc:
        # The LAST step's own failure, not the original primary error -- the most recent, most
        # relevant piece of information for whoever reads the resulting failed-session log.
        assert "fallback-1" in str(exc)


def test_a_step_exhausted_on_an_earlier_call_is_not_retried_on_a_later_call(monkeypatch):
    """Real, confirmed incident this fixes: tried_steps used to be a fresh LOCAL set on every
    _llm_complete call -- once ctx.llm fell back to a step that later ALSO failed (on some future
    turn), the chain walk restarted from the top and re-attempted an earlier step already proven
    dead this run, paying its full backoff cost again for a guaranteed-to-fail retry. Confirmed
    live across two real, concurrent sessions hitting the same free-tier account: a step exhausted
    early in the run got silently re-offered and re-attempted three more times over the run's
    final minutes before the session finally gave up.
    """
    class _DeadStep:
        provider_id = "dead-step"
        model = "dead-model"

        def complete(self, messages, tools=None, stop_check=None):
            raise EmptyResponseError("dead step always fails")

    class _WorksThenDies:
        provider_id = "works-then-dies"
        model = "model"

        def __init__(self):
            self.calls = 0

        def complete(self, messages, tools=None, stop_check=None):
            self.calls += 1
            if self.calls == 1:
                return LLMResponse(content="first call succeeds", tool_calls=[])
            raise EmptyResponseError("now it dies too")

    works_then_dies = _WorksThenDies()
    lookup_calls = []

    def fake_get_next_chain_step(chain, tried_steps, health_ranking=None):
        lookup_calls.append(set(tried_steps))
        if ("dead-step", "dead-model") not in tried_steps:
            return _DeadStep()
        if ("works-then-dies", "model") not in tried_steps:
            return works_then_dies
        return None

    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", fake_get_next_chain_step)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("primary empty")))

    # First call: primary fails -> dead-step tried and fails -> works-then-dies tried, succeeds.
    first = _run(_llm_complete(ctx, [{"role": "user", "content": "first"}], None))
    assert first.content == "first call succeeds"
    assert ctx.llm.provider_id == "works-then-dies"

    # Second call: ctx.llm (works-then-dies) fails this time too. The one lookup this triggers
    # must already know about every step exhausted so far (primary, dead-step, works-then-dies),
    # not just the current ctx.llm -- proving the seed came from the persisted exhausted set
    # (get_exhausted_chain_steps), not a fresh local one that forgot dead-step.
    lookups_before = len(lookup_calls)
    try:
        _run(_llm_complete(ctx, [{"role": "user", "content": "second"}], None))
        assert False, "expected EmptyResponseError once every step is exhausted"
    except EmptyResponseError:
        pass

    new_lookups = lookup_calls[lookups_before:]
    assert len(new_lookups) == 1  # dead-step must never be re-offered/re-attempted a second time
    assert new_lookups[0] == {
        ("primary", "primary-model"), ("dead-step", "dead-model"), ("works-then-dies", "model"),
    }


def test_exhausted_chain_steps_are_cleared_between_sessions(monkeypatch):
    """get_exhausted_chain_steps is keyed by session_id, so a DIFFERENT session's own exhausted
    steps must never leak into this one -- the isolation fixture above resets the whole dict
    between tests, but this checks the getter's own per-session-id scoping directly."""
    core.get_exhausted_chain_steps("usr_other_session").add(("some", "provider"))
    assert core.get_exhausted_chain_steps("usr_fallback_test") == set()


def test_a_step_already_claimed_by_a_concurrent_caller_is_excluded_from_the_pick(monkeypatch):
    """Real concurrency gap this closes: two callers sharing one session_id (the main loop and an
    active subagent, or two subagents) can both hit exhaustion on their own current step at nearly
    the same instant. Before this fix, only PROVEN-exhausted steps were excluded from a pick, so
    both could independently pick the SAME fresh step while the other's own attempt at it was
    still in flight -- doubling the burst rate right when switching to a fresh reserve. Simulated
    here by pre-claiming a step directly (standing in for "a concurrent caller already picked this
    one and hasn't resolved yet") and checking the exclusion set _llm_complete hands to
    get_next_chain_step includes it, even though it was never marked exhausted."""
    core.get_claimed_chain_steps("usr_fallback_test").add(("fallback", "fallback-model"))
    seen_tried_steps = []

    def fake_get_next_chain_step(chain, tried_steps, health_ranking=None):
        seen_tried_steps.append(set(tried_steps))
        if ("fallback", "fallback-model") not in tried_steps:
            return _FallbackLLM()
        return None  # the caller must never be offered the already-claimed step

    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", fake_get_next_chain_step)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    try:
        _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))
        assert False, "expected EmptyResponseError once the only configured step is already claimed"
    except EmptyResponseError:
        pass

    assert ("fallback", "fallback-model") in seen_tried_steps[0]


def test_claim_is_released_once_a_fallback_step_succeeds(monkeypatch):
    """A step that just succeeded must not stay marked "claimed" forever -- that would wrongly
    block a LATER, unrelated caller from ever using a perfectly good step just because an earlier
    caller once used it."""
    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", lambda chain, tried, health_ranking=None: _FallbackLLM() if ("fallback", "fallback-model") not in tried else None)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))

    assert core.get_claimed_chain_steps("usr_fallback_test") == set()


def test_claim_is_released_and_step_marked_exhausted_once_a_fallback_step_fails(monkeypatch):
    """Same release guarantee on the failure path -- the claim must not survive past resolution
    either way, only exhausted (a real, permanent verdict) should."""
    class _AlsoFailingFallback:
        provider_id = "fallback-1"
        model = "model-1"

        def complete(self, messages, tools=None, stop_check=None):
            raise EmptyResponseError("also no choices")

    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", lambda chain, tried, health_ranking=None: _AlsoFailingFallback() if ("fallback-1", "model-1") not in tried else None)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    try:
        _run(_llm_complete(ctx, [{"role": "user", "content": "hi"}], None))
    except EmptyResponseError:
        pass

    assert core.get_claimed_chain_steps("usr_fallback_test") == set()
    assert ("fallback-1", "model-1") in core.get_exhausted_chain_steps("usr_fallback_test")


def test_llm_complete_only_swaps_step_once_stays_on_it_for_later_calls(monkeypatch):
    """ctx.llm is swapped for the rest of the run -- a later call must use the reserve step
    directly, not re-attempt (and re-pay the retry budget of) the now-proven-dead primary."""
    calls = {"chain_lookups": 0}

    def fake_get_next_chain_step(chain, tried_steps, health_ranking=None):
        calls["chain_lookups"] += 1
        return _FallbackLLM()

    monkeypatch.setattr(core, "get_fallback_chain_enabled", lambda: True)
    monkeypatch.setattr(core, "get_fallback_chain", lambda: [])
    monkeypatch.setattr(core, "get_next_chain_step", fake_get_next_chain_step)
    ctx = _base_ctx(_AlwaysFailingLLM(EmptyResponseError("no choices")))

    _run(_llm_complete(ctx, [{"role": "user", "content": "first"}], None))
    result = _run(_llm_complete(ctx, [{"role": "user", "content": "second"}], None))

    assert result.content == "from fallback"
    assert calls["chain_lookups"] == 1  # only looked up once, not on every subsequent call
