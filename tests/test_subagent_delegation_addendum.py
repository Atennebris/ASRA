"""_subagent_delegation_extras -- delegate_to_subagent/check_subagent_task were already available
in the tool schema whenever a Subagent profile is enabled, but nothing in any phase prompt
(RECON_PROMPT/ANALYZE_PROMPT/EXPLOIT_PROMPT/...) ever told the model delegation was a strategy
worth considering -- confirmed live across multiple real scans (an enabled profile, the tool
present in the schema on every single phase) with zero delegate_to_subagent calls across entire
sessions. Closes that gap with a short, conditional nudge appended to the task text, conditional
on the exact same "at least one profile enabled" check the tool availability itself uses.

Tools and addendum come from ONE function (not two independent get_enabled_profiles() reads) so a
profile toggle landing between the two reads can never make the tool list and the text describing
it disagree -- see _subagent_delegation_extras's own docstring for the real (if narrow) race this
closes. Every one of the 5 real call sites (recon/analyze/reverify/exploit/chain) is verified here
directly against the real phase function, not inferred from reading the source.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _run_analyze,
    _run_chain,
    _run_exploit_for_finding,
    _run_recon,
    _run_reverify,
    _subagent_delegation_extras,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import subagent_store
from agent.tools.registry import get_tools_by_category
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _enable_profile(name: str) -> None:
    profile_store = subagent_store.add_profile(name, [], "", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)


# --- _subagent_delegation_extras: pure unit tests ---


def test_extras_are_empty_when_no_subagent_profile_is_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    tools, addendum = _subagent_delegation_extras({})
    assert tools == []
    assert addendum == ""


def test_extras_stay_empty_when_the_only_profile_is_disabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    subagent_store.add_profile("Recon Bot", [], "", None, None)  # enabled=False by default

    tools, addendum = _subagent_delegation_extras({})

    assert tools == []
    assert addendum == ""


def test_extras_return_both_tools_and_a_matching_addendum_when_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")

    tools, addendum = _subagent_delegation_extras({})

    assert {spec.name for spec in tools} == {"delegate_to_subagent", "check_subagent_task"}
    assert "delegate_to_subagent" in addendum
    assert "'OSINT Bot'" in addendum


def test_extras_name_every_enabled_profile_and_exclude_disabled_ones(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")
    _enable_profile("Bruteforce Bot")
    subagent_store.add_profile("Disabled Bot", [], "", None, None)  # left disabled

    tools, addendum = _subagent_delegation_extras({})

    assert "'OSINT Bot'" in addendum
    assert "'Bruteforce Bot'" in addendum
    assert "Disabled Bot" not in addendum
    assert len(tools) == 2  # still exactly the pair, regardless of how many profiles are named


def test_addendum_mentions_the_real_concurrency_cap(tmp_path, monkeypatch):
    """Real gap this closes: the model was never told more than one subagent slot exists at all,
    or that it applies in every phase -- confirmed live, a real session only ever used exactly one
    subagent task despite 73 minutes of Analyze with nothing else competing for its attention."""
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("SUBAGENT_MAX_CONCURRENT_TASKS", "3")
    _enable_profile("OSINT Bot")

    _, addendum = _subagent_delegation_extras({})

    assert "3 subagent task" in addendum
    assert "every phase you're in" in addendum


def test_addendum_makes_clear_each_delegation_has_a_fresh_context(tmp_path, monkeypatch):
    """Real operator correction this responds to: an earlier subagent task's own low-value outcome
    (e.g. what it found was out of scope) has zero bearing on whether a NEW, independent task is
    worth delegating -- each subagent starts with a clean context, unrelated to any prior one."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")

    _, addendum = _subagent_delegation_extras({})

    assert "fresh subagent" in addendum
    assert "clean context" in addendum


def test_extras_respect_a_projects_own_enabled_subagent_ids(tmp_path, monkeypatch):
    """session["enabled_subagent_ids"] (New Project form's per-project Subagent picker) narrows
    which globally-enabled profiles a SPECIFIC project's phases actually get to see/name, on top
    of the plain global enabled/disabled state get_enabled_profiles() already checks."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")
    _enable_profile("Bruteforce Bot")
    allowed_id = subagent_store.get_enabled_profiles()[0]["id"]  # "OSINT Bot"

    tools, addendum = _subagent_delegation_extras({"enabled_subagent_ids": [allowed_id]})

    assert {spec.name for spec in tools} == {"delegate_to_subagent", "check_subagent_task"}
    assert "'OSINT Bot'" in addendum
    assert "Bruteforce Bot" not in addendum


def test_extras_are_empty_when_a_project_narrows_to_zero_subagents(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")

    tools, addendum = _subagent_delegation_extras({"enabled_subagent_ids": []})

    assert tools == []
    assert addendum == ""


def test_extras_are_unrestricted_when_the_session_has_no_enabled_subagent_ids_key(tmp_path, monkeypatch):
    """Every session created before this per-project picker existed has no such key at all --
    session.get(...) must resolve to None, not KeyError, and None means no restriction."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")

    tools, addendum = _subagent_delegation_extras({})  # no "enabled_subagent_ids" key at all

    assert {spec.name for spec in tools} == {"delegate_to_subagent", "check_subagent_task"}
    assert "'OSINT Bot'" in addendum


def test_extras_tools_and_addendum_can_never_disagree_on_availability(tmp_path, monkeypatch):
    """The exact race this single-function design closes: tools non-empty iff addendum non-empty,
    always, because both come from the same get_enabled_profiles() snapshot."""
    _isolate(tmp_path, monkeypatch)

    tools, addendum = _subagent_delegation_extras({})
    assert (len(tools) > 0) == (addendum != "")

    _enable_profile("Recon Bot")
    tools, addendum = _subagent_delegation_extras({})
    assert (len(tools) > 0) == (addendum != "")


# --- integration: every real phase call site actually wires both halves through ---


class _CapturingLLM:
    """Snapshots messages on every .complete() call (list(messages), not the live reference --
    the caller keeps mutating the same list object after this returns), then answers with
    whatever this phase's own terminal contract needs to end cleanly on the first turn."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, final_response: LLMResponse):
        self._final_response = final_response
        self.captured_messages: list[list[dict]] = []

    def complete(self, messages, tools=None, stop_check=None):
        self.captured_messages.append(list(messages))
        return self._final_response


def _assert_addendum_reached(llm: _CapturingLLM, expected_name: str) -> None:
    assert llm.captured_messages, "the phase never called the LLM at all -- nothing to check"
    task_text = llm.captured_messages[0][-1]["content"]
    assert "delegate_to_subagent" in task_text
    assert f"'{expected_name}'" in task_text


def test_recon_phase_wires_the_addendum_through(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_recon_addendum_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    _assert_addendum_reached(llm, "OSINT Bot")


def test_analyze_phase_wires_the_addendum_through(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")
    llm = _CapturingLLM(LLMResponse(content="done", tool_calls=[]))
    session = {"session_id": "usr_analyze_addendum_test", "logs": [], "findings": []}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", {"targets": [], "cves": []}))

    _assert_addendum_reached(llm, "OSINT Bot")


def test_reverify_phase_wires_the_addendum_through(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")
    llm = _CapturingLLM(LLMResponse(
        content=None,
        tool_calls=[ToolCallRequest(id="call_1", name="record_reverification_result", arguments={"verification_outcome": "confirmed_fixed", "reasoning": "gone"})],
    ))
    session = {
        "session_id": "usr_reverify_addendum_test", "logs": [], "findings": [],
        "carried_over_findings": [{"title": "Old Finding"}],
    }
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_reverify(ctx))

    _assert_addendum_reached(llm, "OSINT Bot")


def test_exploit_phase_wires_the_addendum_through(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")
    llm = _CapturingLLM(LLMResponse(
        content=None,
        tool_calls=[ToolCallRequest(id="call_1", name="record_exploit_decision", arguments={"action": "skipped_no_suitable_tool", "exploitation_scenario": "unchanged", "reasoning": "x"})],
    ))
    session = {"session_id": "usr_exploit_addendum_test", "findings": [], "logs": [], "approvals": [], "chat": {"summary": "", "messages": []}}
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])
    finding = {"title": "X", "severity": "Low", "verification": "verified"}
    exploit_tools = get_tools_by_category("exploit")

    _run(_run_exploit_for_finding(ctx, "example.com", finding, exploit_tools))

    _assert_addendum_reached(llm, "OSINT Bot")


def test_chain_phase_wires_the_addendum_through(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile("OSINT Bot")
    llm = _CapturingLLM(LLMResponse(
        content=None,
        tool_calls=[ToolCallRequest(id="call_1", name="record_chain_result", arguments={"action": "no_chain_found", "reasoning": "unrelated findings"})],
    ))
    session = {
        "session_id": "usr_chain_addendum_test", "logs": [],
        "findings": [{"title": "Finding A"}, {"title": "Finding B"}],
    }
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_chain(ctx))

    _assert_addendum_reached(llm, "OSINT Bot")
