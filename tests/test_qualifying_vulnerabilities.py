"""Qualifying/Non-qualifying vulnerabilities scope rules: the New Project form's two optional
fields (sessions/store.py's create_session), record_finding's qualifies_for_bounty validation
(agent/tools/native.py), the Analyze-phase prompt injection and Exploit-phase prioritization that
actually make them steer the agent instead of being decorative text (agent/core.py).
"""
import asyncio

import pytest

from agent.core import (
    RunContext,
    _exploit_priority_key,
    _persist_new_finding,
    _scope_rules_task_addendum,
    _severity_key,
    _warn_if_scope_rules_went_unused,
)
from agent.tools.native import record_finding
from projects import paths as project_paths
from sessions import store
from sessions.store import create_session, load_session


@pytest.fixture(autouse=True)
def _isolated_storage(tmp_path, monkeypatch):
    """Same isolation as test_sessions_store.py — never touches real data/ or Documents storage."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()
    yield
    project_paths.resolve_projects_base_dir.cache_clear()


def test_record_finding_accepts_a_valid_qualifies_for_bounty():
    result = record_finding(
        {"title": "X", "severity": "Low", "description": "d", "exploitation_scenario": "remote_direct", "qualifies_for_bounty": "qualifying"}
    )
    assert result["status"] == "ok"
    assert result["recorded"]["qualifies_for_bounty"] == "qualifying"


def test_record_finding_rejects_an_invalid_qualifies_for_bounty():
    result = record_finding(
        {"title": "X", "severity": "Low", "description": "d", "exploitation_scenario": "remote_direct", "qualifies_for_bounty": "definitely-not-a-real-value"}
    )
    assert result["status"] == "error"
    assert "qualifies_for_bounty" in result["error"]


def test_record_finding_omits_qualifies_for_bounty_by_default():
    result = record_finding({"title": "X", "severity": "Low", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert result["recorded"]["qualifies_for_bounty"] is None


# --- _persist_new_finding: ANALYZE_PROMPT's own instruction ("only set qualifies_for_bounty when
# the task actually gave you scope rules ... if not, omit this field entirely") is a prompt
# instruction, not an enforced contract -- a real session confirmed the model sets "qualifying"
# anyway even with both scope-rule fields left blank. Enforced deterministically here instead,
# the same way _cors_qualifying_conflict already refuses to trust an unsupported "qualifying"
# claim on faith. ---


def test_persist_new_finding_strips_qualifies_for_bounty_when_no_scope_rules_configured():
    session = {"session_id": "usr_x", "findings": [], "scope_rules": {"qualifying": "", "non_qualifying": ""}}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    recorded = {"title": "X", "severity": "Low", "qualifies_for_bounty": "qualifying", "exploitation_scenario": "remote_direct"}

    result = asyncio.run(_persist_new_finding(ctx, recorded))

    assert result is None
    assert session["findings"][0]["qualifies_for_bounty"] is None


def test_persist_new_finding_keeps_qualifies_for_bounty_when_scope_rules_are_set():
    session = {"session_id": "usr_x", "findings": [], "scope_rules": {"qualifying": "RCE, SQLi", "non_qualifying": ""}}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    recorded = {"title": "X", "severity": "Low", "qualifies_for_bounty": "qualifying", "exploitation_scenario": "remote_direct"}

    asyncio.run(_persist_new_finding(ctx, recorded))

    assert session["findings"][0]["qualifies_for_bounty"] == "qualifying"


def test_persist_new_finding_strips_qualifies_for_bounty_when_scope_rules_key_is_missing_entirely():
    """A session dict with no "scope_rules" key at all (shouldn't happen via create_session, but
    defensive against any code path that builds a session dict by hand) must not be treated as
    "rules exist" just because .get() would otherwise raise."""
    session = {"session_id": "usr_x", "findings": []}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    recorded = {"title": "X", "severity": "Low", "qualifies_for_bounty": "non_qualifying", "exploitation_scenario": "remote_direct"}

    asyncio.run(_persist_new_finding(ctx, recorded))

    assert session["findings"][0]["qualifies_for_bounty"] is None


def test_persist_new_finding_records_discovery_tool_as_a_timeline_entry_and_drops_the_raw_field():
    session = {"session_id": "usr_x", "findings": [], "scope_rules": {"qualifying": "RCE", "non_qualifying": ""}}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    recorded = {"title": "X", "severity": "Low", "exploitation_scenario": "remote_direct", "discovery_tool": "nuclei_scan"}

    asyncio.run(_persist_new_finding(ctx, recorded))

    stored = session["findings"][0]
    assert stored["tool_timeline"] == [{"tool": "nuclei_scan", "stage": "discovery"}]
    assert "discovery_tool" not in stored  # transient input, not a field the finding schema itself keeps


def test_persist_new_finding_has_no_timeline_entry_when_no_discovery_tool_given():
    session = {"session_id": "usr_x", "findings": [], "scope_rules": {"qualifying": "RCE", "non_qualifying": ""}}
    ctx = RunContext(llm=None, session=session, session_id="usr_x")
    recorded = {"title": "X", "severity": "Low", "exploitation_scenario": "remote_direct"}

    asyncio.run(_persist_new_finding(ctx, recorded))

    assert "tool_timeline" not in session["findings"][0]


def test_record_finding_accepts_a_false_positive_reason():
    result = record_finding({
        "title": "X", "severity": "Low", "description": "d", "exploitation_scenario": "remote_direct",
        "false_positive_reason": "Confirmed installed version is outside the affected range.",
    })
    assert result["status"] == "ok"
    assert result["recorded"]["false_positive_reason"] == "Confirmed installed version is outside the affected range."


def test_record_finding_omits_false_positive_reason_by_default():
    result = record_finding({"title": "X", "severity": "Low", "description": "d", "exploitation_scenario": "remote_direct"})
    assert result["status"] == "ok"
    assert result["recorded"]["false_positive_reason"] is None


def test_create_session_defaults_scope_rules_to_blank():
    session_id = create_session("example.com")
    session = load_session(session_id)
    assert session["scope_rules"] == {"qualifying": "", "non_qualifying": ""}


def test_create_session_stores_scope_rules_when_given():
    session_id = create_session(
        "example.com",
        qualifying_vulnerabilities=" RCE, SQLi ",
        non_qualifying_vulnerabilities=" missing headers ",
    )
    session = load_session(session_id)
    assert session["scope_rules"] == {"qualifying": "RCE, SQLi", "non_qualifying": "missing headers"}


def test_scope_rules_task_addendum_is_empty_when_both_blank():
    assert _scope_rules_task_addendum({"scope_rules": {"qualifying": "", "non_qualifying": ""}}) == ""
    assert _scope_rules_task_addendum({}) == ""


def test_scope_rules_task_addendum_mentions_both_lists_when_set():
    addendum = _scope_rules_task_addendum(
        {"scope_rules": {"qualifying": "RCE, IDOR", "non_qualifying": "missing headers"}}
    )
    assert "RCE, IDOR" in addendum
    assert "missing headers" in addendum
    assert "qualifies_for_bounty" in addendum


def test_exploit_priority_key_puts_qualifying_finding_before_higher_severity_one():
    qualifying_low = {"severity": "Low", "qualifies_for_bounty": "qualifying"}
    plain_critical = {"severity": "Critical"}
    assert _exploit_priority_key(qualifying_low) < _exploit_priority_key(plain_critical)


def test_exploit_priority_key_falls_back_to_severity_among_non_qualifying():
    high = {"severity": "High"}
    low = {"severity": "Low"}
    assert _exploit_priority_key(high) < _exploit_priority_key(low)
    assert _exploit_priority_key(high)[0] == _exploit_priority_key(low)[0]


def test_severity_key_still_used_directly_elsewhere():
    assert _severity_key({"severity": "Critical"}) < _severity_key({"severity": "Low"})


# --- _warn_if_scope_rules_went_unused: real, confirmed incident (a real session, usr_194956) --
# the New Project form's Qualifying field held a pointer to where the real rules live
# ("The page https://hackerone.com/... shows that it is qualified"), not the rules themselves.
# Analyze correctly declined to guess rather than fabricate a judgment, but nothing told the
# operator their own scope text couldn't be used the way they probably intended. ---


def test_warns_when_qualifying_text_given_but_no_finding_ever_got_tagged():
    session = {
        "scope_rules": {"qualifying": "a link to where the rules live, not the rules"},
        "findings": [{"title": "X", "qualifies_for_bounty": None}, {"title": "Y", "qualifies_for_bounty": None}],
    }
    _warn_if_scope_rules_went_unused(session)
    assert "scope_rules_warning" in session
    assert "qualifying" in session["scope_rules_warning"]


def test_no_warning_when_qualifying_text_was_left_blank():
    session = {"scope_rules": {"qualifying": ""}, "findings": [{"title": "X", "qualifies_for_bounty": None}]}
    _warn_if_scope_rules_went_unused(session)
    assert "scope_rules_warning" not in session


def test_no_warning_when_no_scope_rules_key_at_all():
    session = {"findings": [{"title": "X", "qualifies_for_bounty": None}]}
    _warn_if_scope_rules_went_unused(session)
    assert "scope_rules_warning" not in session


def test_no_warning_when_at_least_one_finding_got_tagged():
    session = {
        "scope_rules": {"qualifying": "RCE, SQLi"},
        "findings": [{"title": "X", "qualifies_for_bounty": "qualifying"}, {"title": "Y", "qualifies_for_bounty": None}],
    }
    _warn_if_scope_rules_went_unused(session)
    assert "scope_rules_warning" not in session


def test_no_warning_when_there_are_no_findings_at_all():
    """A clean scan with genuinely nothing found is a different, unrelated outcome -- must never be
    misreported as "your scope rules text couldn't be used"."""
    session = {"scope_rules": {"qualifying": "RCE, SQLi"}, "findings": []}
    _warn_if_scope_rules_went_unused(session)
    assert "scope_rules_warning" not in session
