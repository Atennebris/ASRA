"""_pick_overflow_subagent_profile's relevant_tools matching, and _auto_delegate_hypothesis_overflow
built on top of it -- the direct follow-up to the other three _auto_delegate_*_overflow functions'
own fix (profiles[0] -> widest allowed_tools). That fix only closed storage-order fragility: on a
roster where the generalist already happens to have the widest toolset, it kept landing on exactly
the same profile the original bug already happened to pick, so WHICH profile did the work never
actually changed. relevant_tools-based matching (_relevant_tools_for_text) is the real fix -- a
hypothesis that names a known domain (SQLi, leaked secrets, ...) routes to a genuinely matching,
enabled specialist instead of whichever profile is merely biggest.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import (
    RunContext,
    _auto_delegate_hypothesis_overflow,
    _best_matching_profile_overlap,
    _pick_overflow_subagent_profile,
    _relevant_tools_for_text,
)
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import subagent_store, subagent_tasks
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(subagent_tasks, "_RUNNING_SUBAGENT_TASKS", {})


def _run(coro):
    return asyncio.run(coro)


def _add_profile(name, allowed_tools):
    profile_store = subagent_store.add_profile(name, allowed_tools, "test specialist", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)
    return name


def _base_session(session_id, hypotheses=None):
    return {
        "session_id": session_id, "logs": [], "findings": [], "subagent_tasks": {},
        "hypotheses": hypotheses or [],
    }


def _hypothesis(hid, text, evidence="", status="unconfirmed"):
    return {"id": hid, "text": text, "evidence": evidence, "status": status}


class _ImmediatelyReportsLLM:
    provider_id = "test-subagent-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(
            content=None,
            tool_calls=[ToolCallRequest(id="c1", name="report_subagent_result", arguments={"summary": "done"})],
        )


# --- _relevant_tools_for_text / _pick_overflow_subagent_profile matching ---


def test_relevant_tools_matches_sqli_keyword_to_sqli_toolset():
    relevant = _relevant_tools_for_text("Blind SQL injection in the search parameter")
    assert "sqlmap" in relevant
    assert "dalfox" not in relevant


def test_relevant_tools_empty_for_unmatched_text():
    assert _relevant_tools_for_text("a totally generic finding about rate limiting") == set()


def test_pick_overflow_profile_prefers_genuine_match_over_mere_breadth():
    """The real bug the operator flagged: a widest-toolset generalist always won even when a
    narrower, genuinely matching specialist was enabled too. relevant_tools must let the narrower,
    better-fitting profile win instead."""
    generalist = {"name": "Default Subagent", "allowed_tools": ["whatweb", "nmap", "nuclei", "subfinder", "ffuf", "arjun"]}
    sqli_specialist = {"name": "SQLi-Verifier", "allowed_tools": ["sqlmap", "send_raw_request", "diff_requests"]}
    profiles = [generalist, sqli_specialist]

    relevant = _relevant_tools_for_text("Confirmed SQL injection in ?id= parameter")
    picked = _pick_overflow_subagent_profile(profiles, relevant)

    assert picked == "SQLi-Verifier"  # not the generalist, despite it having more tools overall


def test_pick_overflow_profile_prefers_precise_specialist_over_superset_generalist():
    """Real, confirmed incident (Telenor-Sweden-YesWeHack rescan session): a "do everything"
    default profile's allowed_tools is a near-total SUPERSET of every real specialist's own list --
    it contains ffuf/whatweb/wayback_urls/ssl_cert_info too, just buried among ~150 other tools.
    Raw overlap COUNT alone (the round-2 fix) let it win every single auto-overflow delegation that
    session regardless of which specialist was actually enabled, because a superset can never score
    below a specialist on intersection size. Precision (overlap / profile's own toolset size) is
    what actually lets the narrower, genuinely-built-for-this specialist win."""
    generalist = {
        "name": "Default_Subagent_helper",
        "allowed_tools": ["whatweb", "ffuf", "wayback_urls", "ssl_cert_info"] + [f"tool_{i}" for i in range(146)],
    }
    recon_specialist = {
        "name": "Recon-Scout",
        "allowed_tools": ["subfinder", "amass_enum", "whatweb", "nmap", "nuclei", "dns_lookup", "crt_sh_lookup", "wayback_urls", "security_headers_audit", "rank_attack_surface"],
    }
    profiles = [generalist, recon_specialist]

    relevant = {"whatweb", "ffuf", "wayback_urls", "ssl_cert_info"}
    picked = _pick_overflow_subagent_profile(profiles, relevant)

    assert picked == "Recon-Scout"  # not the generalist, despite it matching MORE tools in raw count


def test_pick_overflow_profile_falls_back_to_breadth_when_nothing_matches():
    generalist = {"name": "Default Subagent", "allowed_tools": ["whatweb", "nmap", "nuclei"]}
    narrow = {"name": "Reporter", "allowed_tools": []}
    picked = _pick_overflow_subagent_profile([generalist, narrow], set())
    assert picked == "Default Subagent"


def test_best_matching_profile_overlap_is_zero_when_no_enabled_profile_fits():
    profiles = [{"name": "Reporter", "allowed_tools": []}, {"name": "RE-Binary", "allowed_tools": ["radare2", "gdb"]}]
    relevant = _relevant_tools_for_text("SQL injection confirmed via union select")
    assert _best_matching_profile_overlap(profiles, relevant) == 0


# --- _auto_delegate_hypothesis_overflow ---


def test_noop_when_no_subagent_profile_is_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session = _base_session("usr_hyp_noop_no_profile", [_hypothesis("h1", "possible SQL injection in login form")])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_hypothesis_overflow(ctx, "example.com"))

    assert session["subagent_tasks"] == {}


def test_noop_when_no_enabled_profile_genuinely_matches(tmp_path, monkeypatch):
    """Only a RE-Binary specialist is enabled, but the hypothesis is about SQL injection -- nothing
    enabled genuinely fits, so this must NOT force it onto the unrelated profile."""
    _isolate(tmp_path, monkeypatch)
    _add_profile("RE-Binary", ["radare2", "gdb", "ghidra"])
    session = _base_session("usr_hyp_noop_no_match", [_hypothesis("h1", "possible SQL injection in login form")])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_hypothesis_overflow(ctx, "example.com"))

    assert session["subagent_tasks"] == {}


def test_delegates_a_matching_hypothesis_to_the_right_specialist(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _add_profile("Default Subagent", ["whatweb", "nmap", "nuclei", "subfinder", "ffuf", "arjun"])
    sqli_profile = _add_profile("SQLi-Verifier", ["sqlmap", "send_raw_request", "diff_requests"])
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session(
        "usr_hyp_delegates_right_specialist",
        [_hypothesis("h1", "Possible SQL injection in the ?id= parameter", evidence="error-based response differs")],
    )
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_hypothesis_overflow(ctx, "example.com"))

    assert len(session["subagent_tasks"]) == 1
    task = next(iter(session["subagent_tasks"].values()))
    assert task["profile_name"] == sqli_profile  # the genuine match, not the bigger generalist
    assert session["auto_delegated_hypothesis_ids"] == ["h1"]


def test_never_redelegates_the_same_hypothesis_twice(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _add_profile("SQLi-Verifier", ["sqlmap", "send_raw_request"])
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_hyp_no_redelegate", [_hypothesis("h1", "SQL injection suspected in search")])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_hypothesis_overflow(ctx, "example.com"))
    assert len(session["subagent_tasks"]) == 1

    _run(_auto_delegate_hypothesis_overflow(ctx, "example.com"))
    assert len(session["subagent_tasks"]) == 1  # still exactly one


def test_skips_a_hypothesis_that_is_already_resolved(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _add_profile("SQLi-Verifier", ["sqlmap", "send_raw_request"])
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session(
        "usr_hyp_skip_resolved",
        [_hypothesis("h1", "SQL injection suspected in search", status="confirmed")],
    )
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_hypothesis_overflow(ctx, "example.com"))

    assert session["subagent_tasks"] == {}


# --- mid-phase: a hypothesis recorded DURING Recon/Analyze gets checked immediately, not only ----
# --- once that whole phase finishes (the "always and everywhere" extension of the same fix the ---
# --- recon-overflow-host mid-phase delegation above got) -----------------------------------------


def test_hypothesis_recorded_mid_recon_gets_delegated_before_recon_itself_finishes(tmp_path, monkeypatch):
    """Real, confirmed gap this closes: _auto_delegate_hypothesis_overflow used to only ever be
    CALLED from Analyze's and Exploit's own phase-start code -- a hypothesis recorded during Recon
    (record_hypothesis IS available there) got zero chance at subagent help until Analyze began,
    or never at all if Recon was interrupted first (the exact "subagents don't help during a long
    recon" complaint this session's other fixes already addressed for overflow HOSTS). _run_recon's
    own record_hypothesis handling now re-checks immediately. Proven here by driving the REAL
    _run_recon loop and checking state mid-phase, the same way the host-overflow mid-phase test
    above it in test_auto_delegate_recon_overflow.py does."""
    import dataclasses

    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.core import _run_recon
    from agent.tools.allowed_targets import add_allowed_target
    from agent.tools.registry import TOOL_REGISTRY

    _isolate(tmp_path, monkeypatch)
    _add_profile("SQLi-Verifier", ["sqlmap", "send_raw_request", "diff_requests"])
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    add_allowed_target("example.com")
    session = _base_session("usr_hyp_mid_recon")
    session.update({"target": "example.com", "status": "processing", "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []}})
    observed = {}

    class _RecordingLLM:
        provider_id = "test-provider"
        model = "test-model"
        context_limit = None

        def __init__(self):
            self._script = [("record_hypothesis", {"text": "Possible SQL injection in the ?id= parameter", "evidence": "error-based response differs"})]
            self.calls_made = 0

        def complete(self, messages, tools=None, stop_check=None):
            self.calls_made += 1
            if self.calls_made == 2 and "subagent_tasks_mid_phase" not in observed:
                observed["subagent_tasks_mid_phase"] = len(session.get("subagent_tasks") or {})
            if self._script:
                name, args = self._script.pop(0)
                return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{self.calls_made}", name=name, arguments=args)])
            return LLMResponse(content="done", tool_calls=[])

    ctx = RunContext(llm=_RecordingLLM(), session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    assert observed["subagent_tasks_mid_phase"] == 1
    assert session["auto_delegated_hypothesis_ids"] == [session["hypotheses"][0]["id"]]


def test_hypothesis_recorded_mid_analyze_gets_delegated_before_analyze_itself_finishes(tmp_path, monkeypatch):
    """Same reasoning as the Recon version above -- Analyze is ONE long continuous conversation, and
    the phase-start call to this function only ever sees hypotheses carried over from Recon. One
    recorded partway through Analyze's own conversation used to wait for Exploit's own phase-start
    check -- minutes later, or never if this pass was interrupted first."""
    import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
    from agent.core import _run_analyze

    _isolate(tmp_path, monkeypatch)
    _add_profile("SQLi-Verifier", ["sqlmap", "send_raw_request", "diff_requests"])
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_hyp_mid_analyze")
    session.update({
        "target": "http://example.com", "status": "processing", "logs": [], "findings": [],
        "approvals": [], "chat": {"summary": "", "messages": []},
        "recon_result": {"targets": [], "cves": []},
    })
    observed = {}

    class _RecordingLLM:
        provider_id = "test-provider"
        model = "test-model"
        context_limit = None

        def __init__(self):
            self._script = [("record_hypothesis", {"text": "Possible SQL injection in the ?id= parameter", "evidence": "error-based response differs"})]
            self.calls_made = 0

        def complete(self, messages, tools=None, stop_check=None):
            self.calls_made += 1
            if self.calls_made == 2 and "subagent_tasks_mid_phase" not in observed:
                observed["subagent_tasks_mid_phase"] = len(session.get("subagent_tasks") or {})
            if self._script:
                name, args = self._script.pop(0)
                return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{self.calls_made}", name=name, arguments=args)])
            return LLMResponse(content="done", tool_calls=[])

    ctx = RunContext(llm=_RecordingLLM(), session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "http://example.com", session["recon_result"]))

    assert observed["subagent_tasks_mid_phase"] == 1
    assert session["auto_delegated_hypothesis_ids"] == [session["hypotheses"][0]["id"]]
