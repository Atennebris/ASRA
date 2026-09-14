"""_auto_delegate_analyze_overflow -- the Analyze-phase equivalent of
_auto_delegate_recon_overflow/_auto_delegate_exploit_overflow, closing the gap the operator
explicitly demanded: subagent delegation must be available on EVERY phase where genuinely
independent work exists and current concurrency allows it, not just one. Delegates deeper
vulnerability probing of secondary confirmed hosts (everything but the first, which the main agent
naturally starts on itself) to a subagent while the main agent keeps working. Unlike Exploit,
Analyze runs as one continuous conversation, so the subagent's own summary reaches the main agent
through the normal auto-push queue straight into that ongoing conversation -- no special
"don't decide the verdict" carve-out is needed the way Exploit's own version required.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _analyze_delegated_hosts_task_addendum, _auto_delegate_analyze_overflow, _run_analyze
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


def _enable_profile(name="Default Subagent helper"):
    profile_store = subagent_store.add_profile(name, [], "analyze helper", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)
    return name


def _base_session(session_id):
    return {"session_id": session_id, "logs": [], "findings": [], "subagent_tasks": {}}


def _recon_result(*hosts):
    return {"targets": [{"host": h, "port": 443, "service": "https", "version": None} for h in hosts]}


class _ImmediatelyReportsLLM:
    provider_id = "test-subagent-provider"
    model = "test-model"
    context_limit = None

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(
            content=None,
            tool_calls=[ToolCallRequest(id="c1", name="report_subagent_result", arguments={"summary": "done"})],
        )


# --- no-op cases ---


def test_noop_when_no_subagent_profile_is_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session = _base_session("usr_analyze_noop_no_profile")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", _recon_result("a.example.com", "b.example.com")))

    assert session["subagent_tasks"] == {}


def test_noop_with_only_one_confirmed_host(tmp_path, monkeypatch):
    """With just one host, the main agent covers it alone -- nothing genuinely independent to
    split off yet."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    session = _base_session("usr_analyze_noop_one_host")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", _recon_result("a.example.com")))

    assert session["subagent_tasks"] == {}


def test_noop_with_zero_confirmed_hosts(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    session = _base_session("usr_analyze_noop_zero_hosts")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", _recon_result()))

    assert session["subagent_tasks"] == {}


def test_a_hostname_and_its_own_resolved_ip_only_count_as_one_confirmed_host(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (usr_da8970): recon_result recorded a
    hostname and its own resolved IP as two separate targets entries -- a plain string dedup
    treated them as 2 distinct confirmed hosts (meeting the threshold of 2), delegating a subagent
    whose first action was to re-run the identical nmap scan Recon had already just run against the
    same physical target. dns_map proves they're the same host, so the real distinct count is 1 --
    below threshold, must stay a no-op."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    session = _base_session("usr_analyze_dns_identity_collapse")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_result = _recon_result("example.com", "203.0.113.42")
    recon_result["dns_map"] = {"example.com": ["203.0.113.42"]}

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", recon_result))

    assert session["subagent_tasks"] == {}


# --- real delegation ---


def test_delegates_when_two_or_more_hosts_are_confirmed(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    profile_name = _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_analyze_delegates")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", _recon_result("a.example.com", "b.example.com")))

    assert len(session["subagent_tasks"]) == 1
    task = next(iter(session["subagent_tasks"].values()))
    assert task["profile_name"] == profile_name


def test_never_delegates_the_first_host_the_main_agent_starts_on_itself(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    captured_tasks = []

    class _CapturingLLM(_ImmediatelyReportsLLM):
        provider_id = "test-provider"
        model = "test-model"
        def complete(self, messages, tools=None, stop_check=None):
            captured_tasks.append(messages[-1]["content"])
            return super().complete(messages, tools, stop_check)

    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _CapturingLLM())
    session = _base_session("usr_analyze_delegates_secondary_only")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", _recon_result("primary.example.com", "b.example.com", "c.example.com")))

    task_text = captured_tasks[0]
    assert "primary.example.com" not in task_text.split("actively probe")[1]  # not in the delegated batch
    assert "b.example.com" in task_text
    assert "c.example.com" in task_text


def test_never_re_delegates_the_same_hosts_on_a_later_call(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_analyze_no_redelegate")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_result = _recon_result("a.example.com", "b.example.com")

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", recon_result))
    assert len(session["subagent_tasks"]) == 1

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", recon_result))  # same hosts again
    assert len(session["subagent_tasks"]) == 1  # no second delegation of the same host


def test_batch_is_capped_at_the_max_even_with_many_more_hosts(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_analyze_batch_capped")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    hosts = [f"h{i}.example.com" for i in range(10)]

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", _recon_result(*hosts)))

    assert len(session["auto_delegated_analyze_hosts"]) == 5  # capped, not all 9 secondary hosts


def test_multiple_ports_on_the_same_host_count_as_one_candidate(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_analyze_dedup_ports")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_result = {"targets": [
        {"host": "a.example.com", "port": 80, "service": "http"},
        {"host": "a.example.com", "port": 443, "service": "https"},
        {"host": "b.example.com", "port": 443, "service": "https"},
    ]}

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", recon_result))

    assert len(session["subagent_tasks"]) == 1
    assert session["auto_delegated_analyze_hosts"] == ["b.example.com"]  # a.example.com is "first", never delegated


# --- hosts confirmed on a non-HTTP service only must never get the HTTP-shaped toolset ---


def test_excludes_a_host_confirmed_only_on_a_non_http_port(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (again-tests-usr_73fe2f): a host recon had only ever
    confirmed on port 25 (SMTP) still got the full HTTP toolset (security_headers_audit/
    http_request/whatweb/nuclei/ssl_cert_info) -- 3 of 5 hosts in that real batch turned out to
    have zero HTTP successes / 3 consecutive failures each, a real subagent budget spent on a
    service class none of its tools can meaningfully probe."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_analyze_excludes_smtp_only_host")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_result = {"targets": [
        {"host": "a.example.com", "port": 443, "service": "https"},
        {"host": "mail.example.com", "port": 25, "service": "smtp"},
        {"host": "b.example.com", "port": 443, "service": "https"},
    ]}

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", recon_result))

    assert session["auto_delegated_analyze_hosts"] == ["b.example.com"]
    assert "mail.example.com" not in session["auto_delegated_analyze_hosts"]


def test_does_not_exclude_a_host_whose_only_entry_carries_no_real_port_or_service_info(tmp_path, monkeypatch):
    """Benefit of the doubt: record_target only requires "host" -- an entry with port=None and
    service=None (e.g. a host merely noted from passive discovery, never actually port-scanned)
    carries no real evidence either way and must NOT be treated as proof of "confirmed non-HTTP",
    or a host recon simply hasn't gotten around to probing yet would be silently excluded from
    delegation forever."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = _base_session("usr_analyze_includes_unconfirmed_host")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_result = {"targets": [
        {"host": "a.example.com", "port": 443, "service": "https"},
        {"host": "b.example.com", "port": None, "service": None},
    ]}

    _run(_auto_delegate_analyze_overflow(ctx, "example.com", recon_result))

    assert session["auto_delegated_analyze_hosts"] == ["b.example.com"]


# --- integration: a real _run_analyze phase actually triggers the auto-delegation ---


class _SkipLLM:
    """Main-agent's own conversation -- finishes immediately with no tool calls, so this test only
    checks that auto-delegation fired at the top of the phase, not the unrelated analyze internals
    already covered elsewhere."""
    provider_id = "test-provider"
    model = "test-model"

    def complete(self, messages, tools=None, stop_check=None):
        return LLMResponse(content="done", tool_calls=[])


def test_run_analyze_actually_auto_delegates_the_secondary_hosts(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = {
        "session_id": "usr_analyze_real_phase_auto_delegates", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    ctx = RunContext(llm=_SkipLLM(), session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", _recon_result("a.example.com", "b.example.com", "c.example.com")))

    assert len(session["subagent_tasks"]) == 1
    assert len(session.get("auto_delegated_analyze_hosts") or []) == 2


# --- _analyze_delegated_hosts_task_addendum -- tells the MAIN agent to skip already-delegated hosts,
# closing the gap where nothing ever told it: real incident, confirmed live, api.github.com and
# classroom.github.com each got the identical deep-scan tool set run independently by both the main
# agent and the subagent -- pure duplicate work, zero new information gained the second time.


def test_delegated_hosts_addendum_is_empty_with_nothing_delegated():
    assert _analyze_delegated_hosts_task_addendum({}, {}) == ""
    assert _analyze_delegated_hosts_task_addendum({"auto_delegated_analyze_hosts": []}, {}) == ""


def test_delegated_hosts_addendum_names_the_delegated_hosts_and_tells_main_agent_not_to_duplicate():
    session = {"auto_delegated_analyze_hosts": ["b.example.com", "c.example.com"]}
    recon_result = _recon_result("a.example.com", "b.example.com", "c.example.com")
    addendum = _analyze_delegated_hosts_task_addendum(session, recon_result)
    assert "b.example.com" in addendum
    assert "c.example.com" in addendum
    assert "do not duplicate that work yourself" in addendum


def test_delegated_hosts_addendum_tells_main_agent_to_focus_on_the_REMAINING_hosts_not_the_delegated_ones():
    # Real, confirmed incident: this addendum used to name the delegated hosts THEMSELVES as
    # "the remaining hosts... focus your own effort on", directly contradicting its own "do not
    # duplicate that work yourself" sentence one line above -- the main agent and a subagent then
    # scanned the exact same hosts concurrently. The "focus on" list must be whatever's left in
    # recon_result once the delegated hosts are excluded, never the delegated hosts themselves.
    session = {"auto_delegated_analyze_hosts": ["b.example.com", "c.example.com"]}
    recon_result = _recon_result("a.example.com", "b.example.com", "c.example.com", "d.example.com")
    addendum = _analyze_delegated_hosts_task_addendum(session, recon_result)
    focus_sentence = addendum.split("Focus your own effort on the remaining host(s) instead: ", 1)[1]
    assert "a.example.com" in focus_sentence
    assert "d.example.com" in focus_sentence
    assert "b.example.com" not in focus_sentence
    assert "c.example.com" not in focus_sentence


def test_delegated_hosts_addendum_when_every_confirmed_host_was_delegated():
    session = {"auto_delegated_analyze_hosts": ["b.example.com", "c.example.com"]}
    recon_result = _recon_result("b.example.com", "c.example.com")
    addendum = _analyze_delegated_hosts_task_addendum(session, recon_result)
    assert "nothing else of yours to start independently" in addendum
    assert "Focus your own effort on the remaining" not in addendum


class _CapturingSkipLLM:
    """Like _SkipLLM above, but records the initial task message so the test can inspect the real
    text the main agent actually sees, not just that auto-delegation fired."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self):
        self.captured_messages: list[str] = []

    def complete(self, messages, tools=None, stop_check=None):
        self.captured_messages.append(messages[-1]["content"])
        return LLMResponse(content="done", tool_calls=[])


def test_run_analyze_tells_the_main_agent_which_hosts_the_subagent_already_owns(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    session = {
        "session_id": "usr_analyze_task_mentions_delegation", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    llm = _CapturingSkipLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", _recon_result("primary.example.com", "b.example.com", "c.example.com")))

    task_text = llm.captured_messages[0]
    assert "b.example.com" in task_text
    assert "c.example.com" in task_text
    assert "already running a full deep vulnerability scan" in task_text


def test_run_analyze_task_message_has_no_delegation_addendum_when_nothing_delegated(tmp_path, monkeypatch):
    """No enabled Subagent profile -> _auto_delegate_analyze_overflow is a no-op -> the task message
    must read exactly as it always did, no new text for a session that never uses this feature."""
    _isolate(tmp_path, monkeypatch)
    session = {
        "session_id": "usr_analyze_task_no_delegation", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    }
    llm = _CapturingSkipLLM()
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_analyze(ctx, "example.com", _recon_result("primary.example.com", "b.example.com")))

    task_text = llm.captured_messages[0]
    assert "already running a full deep vulnerability scan" not in task_text
