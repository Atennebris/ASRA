"""_auto_delegate_recon_overflow -- deterministic auto-delegation, not a suggestion the model has
to notice and choose to act on. Real incident this replaces: a soft prompt-level nudge
(_subagent_delegation_extras) confirmed present in the task text and confirmed available in the
tool schema, across two real production sessions with an enabled Subagent profile -- zero
delegate_to_subagent calls either time. This closes that gap by having the code itself delegate a
well-bounded, genuinely independent chunk of work (secondary hosts Recon discovered beyond the
operator's own typed scope) once a real threshold is met, without waiting on the model's judgment.
"""
import asyncio

import agent.core as core
import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _auto_delegate_recon_overflow, run_session
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools import allowed_targets, subagent_store, subagent_tasks
from agent.tools.allowed_targets import add_allowed_target
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(allowed_targets, "ALLOWED_TARGETS_PATH", tmp_path / "allowed.json")
    monkeypatch.setattr(subagent_store, "SUBAGENT_STORE_PATH", tmp_path / "subagent_profiles.json")
    monkeypatch.setattr(subagent_tasks, "_RUNNING_SUBAGENT_TASKS", {})


def _run(coro):
    return asyncio.run(coro)


def _enable_profile(name="Default Subagent helper"):
    profile_store = subagent_store.add_profile(name, [], "osint helper", None, None)
    profile_id = profile_store["profiles"][-1]["id"]
    subagent_store.update_profile(profile_id, enabled=True)
    return name


def _base_session(session_id):
    return {"session_id": session_id, "logs": [], "findings": [], "subagent_tasks": {}}


def _targets(*hosts):
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


def _allow_all(hosts):
    for h in hosts:
        add_allowed_target(h)


# --- no-op cases: must never delegate anything ---


def test_noop_when_no_subagent_profile_is_enabled(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    hosts = [f"h{i}.example.com" for i in range(6)]
    _allow_all(hosts)
    session = _base_session("usr_noop_no_profile")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*hosts)))

    assert session["subagent_tasks"] == {}
    assert "auto_delegated_hosts" not in session


def test_noop_when_fewer_overflow_hosts_than_threshold(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    hosts = ["a.example.com", "b.example.com"]  # below _AUTO_DELEGATE_HOST_THRESHOLD (4)
    _allow_all(hosts)
    session = _base_session("usr_noop_below_threshold")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*hosts)))

    assert session["subagent_tasks"] == {}


def test_a_hostname_and_its_own_resolved_ip_only_count_as_one_overflow_host(tmp_path, monkeypatch):
    """Real, confirmed incident this fixes (usr_da8970): recon_result recorded a
    hostname (an httpx probe) and its own resolved IP (nmap's own IP-based output) as two separate
    entries -- a plain string dedup counted them as 2 distinct "secondary hosts", crossing the
    threshold and delegating a subagent whose first action was to re-run the identical nmap scan
    Recon had already just run against the same physical target. 4 raw host strings here, but two
    of them (host2 + its own IP) are the SAME real host per dns_map -- real distinct count is 3,
    below the threshold of 4, so this must stay a no-op."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    hosts = ["host1.example.com", "host2.example.com", "10.20.30.40", "host3.example.com"]
    _allow_all(hosts)
    session = _base_session("usr_dns_identity_collapse")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_result = _targets(*hosts)
    recon_result["dns_map"] = {"host2.example.com": ["10.20.30.40"]}

    _run(_auto_delegate_recon_overflow(ctx, "example.com", recon_result))

    assert session["subagent_tasks"] == {}


def test_literal_scope_hosts_never_count_as_overflow(tmp_path, monkeypatch):
    """The primary, operator-typed target(s) are the main agent's own job -- they must never be
    counted toward the overflow threshold or delegated away."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    extra = [f"h{i}.example.com" for i in range(3)]  # 3 real overflow, still below threshold
    _allow_all(["example.com", *extra])
    session = _base_session("usr_literal_scope_excluded")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets("example.com", *extra)))

    assert session["subagent_tasks"] == {}  # only 3 real overflow hosts, "example.com" doesn't count


def test_hosts_outside_the_allowlist_are_never_delegated(tmp_path, monkeypatch):
    """A hard backstop, not just trusting recon_result -- reuses is_target_allowed, the exact same
    check every real tool dispatch is gated on, rather than re-deriving its own notion of scope."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    allowed = [f"ok{i}.example.com" for i in range(2)]
    not_allowed = [f"bad{i}.example.com" for i in range(3)]
    _allow_all(allowed)  # not_allowed hosts deliberately never added to the allowlist
    session = _base_session("usr_allowlist_backstop")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*allowed, *not_allowed)))

    # Only 2 real candidates (allowed) -- below threshold, so nothing gets delegated at all; if
    # not_allowed hosts had wrongly counted, this would have reached the threshold (5) instead.
    assert session["subagent_tasks"] == {}


# --- real delegation happens when the threshold is genuinely met ---


def test_delegates_when_the_threshold_is_met(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    profile_name = _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    hosts = [f"h{i}.example.com" for i in range(4)]  # exactly the threshold
    _allow_all(hosts)
    session = _base_session("usr_delegates_at_threshold")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*hosts)))

    assert len(session["subagent_tasks"]) == 1
    task = next(iter(session["subagent_tasks"].values()))
    assert task["profile_name"] == profile_name
    assert session["auto_delegated_hosts"] == hosts


def test_deadline_scales_with_batch_size_instead_of_the_flat_default(tmp_path, monkeypatch):
    """Real incident this fixes: a 6-host auto-delegated batch got the same flat
    SUBAGENT_TASK_TIMEOUT_SECONDS (900s default) a single-host, model-triggered delegation gets,
    and hit that deadline after 29 genuinely successful tool calls with no final report ever
    produced -- 900s split six ways is not a realistic per-host budget. The auto-overflow path must
    scale its own budget by len(batch), not reuse the single-task flat default."""
    _isolate(tmp_path, monkeypatch)
    # _AUTO_DELEGATE_TIMEOUT_PER_HOST_SECONDS is computed once from the env var at import time --
    # patching the already-resolved constant directly is what actually takes effect, not re-setting
    # the env var itself.
    monkeypatch.setattr(core, "_AUTO_DELEGATE_TIMEOUT_PER_HOST_SECONDS", 300)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    hosts = [f"h{i}.example.com" for i in range(6)]
    _allow_all(hosts)
    session = _base_session("usr_deadline_scales")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*hosts)))

    task = next(iter(session["subagent_tasks"].values()))
    budget = task["deadline"] - task["started_at"]
    assert abs(budget - 6 * 300) < 2  # small slack for real wall-clock time elapsed mid-test
    assert budget > 900  # strictly more than the flat single-task default this used to get


def test_batch_is_capped_at_the_max_even_with_many_more_candidates(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    hosts = [f"h{i}.example.com" for i in range(25)]
    _allow_all(hosts)
    session = _base_session("usr_batch_capped")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*hosts)))

    assert len(session["auto_delegated_hosts"]) == 10  # _AUTO_DELEGATE_MAX_HOSTS, not all 25


def test_never_re_delegates_the_same_hosts_on_a_later_resume(tmp_path, monkeypatch):
    """A resumed recon phase re-running _auto_delegate_recon_overflow with the SAME recon_result
    must not delegate the same hosts a second time -- session["auto_delegated_hosts"] is the
    guard."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    hosts = [f"h{i}.example.com" for i in range(4)]
    _allow_all(hosts)
    session = _base_session("usr_no_re_delegate")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*hosts)))
    assert len(session["subagent_tasks"]) == 1

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*hosts)))

    assert len(session["subagent_tasks"]) == 1  # still exactly one -- the second call delegated nothing new


def test_only_genuinely_new_overflow_hosts_trigger_a_second_delegation(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    monkeypatch.setattr("agent.core.get_provider", lambda provider, model: _ImmediatelyReportsLLM())
    first_batch = [f"h{i}.example.com" for i in range(4)]
    second_batch = [f"new{i}.example.com" for i in range(4)]
    _allow_all(first_batch + second_batch)
    session = _base_session("usr_second_wave")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*first_batch)))
    _run(_auto_delegate_recon_overflow(ctx, "example.com", _targets(*first_batch, *second_batch)))

    assert len(session["subagent_tasks"]) == 2
    assert set(session["auto_delegated_hosts"]) == set(first_batch) | set(second_batch)


def test_multiple_ports_on_the_same_host_count_as_one_candidate(tmp_path, monkeypatch):
    """recon_result["targets"] can have multiple port entries for the same host -- the candidate
    count must be by unique HOST, not by raw target entry count."""
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    hosts = [f"h{i}.example.com" for i in range(3)]  # 3 unique hosts, below threshold
    _allow_all(hosts)
    session = _base_session("usr_dup_ports")
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_result = {
        "targets": [
            {"host": hosts[0], "port": 80, "service": "http"},
            {"host": hosts[0], "port": 443, "service": "https"},  # same host, second port
            {"host": hosts[1], "port": 443, "service": "https"},
            {"host": hosts[2], "port": 443, "service": "https"},
        ],
    }

    _run(_auto_delegate_recon_overflow(ctx, "example.com", recon_result))

    assert session["subagent_tasks"] == {}  # still only 3 unique hosts, below the threshold of 4


# --- wiring: run_session itself actually calls this after a real recon phase, not just in isolation ---


def test_run_session_actually_auto_delegates_after_a_real_recon_phase(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    _enable_profile()
    hosts = [f"h{i}.example.com" for i in range(4)]
    _allow_all(["example.com", *hosts])

    class _MainAgentLLM:
        provider_id = "test-main-provider"
        model = "test-model"
        context_limit = None

        def __init__(self):
            self._recon_script = [("record_target", {"host": h, "port": 443, "service": "https"}) for h in hosts]
            self._calls = 0

        def complete(self, messages, tools=None, stop_check=None):
            self._calls += 1
            if self._recon_script:
                name, args = self._recon_script.pop(0)
                return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"c{self._calls}", name=name, arguments=args)])
            # Every later turn (recon's own wrap-up, then analyze/exploit/chain/validate, all with
            # nothing to work with since no findings were ever recorded) just finishes cleanly.
            return LLMResponse(content="done", tool_calls=[])

    main_llm = _MainAgentLLM()
    session_id = "usr_run_session_wiring_test"
    store.save_session(session_id, {
        "session_id": session_id, "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
    })

    # run_session builds its own RunContext internally from get_provider() -- patch that to return
    # the scripted main-agent LLM specifically (not the subagent stand-in _get_provider gives
    # everyone) by wrapping get_provider so the FIRST call (run_session's own ctx.llm) gets
    # main_llm, and every later call (each subagent delegation) gets a fresh reporter.
    call_count = {"n": 0}

    def _get_provider_dispatch(provider_id=None, model=None):
        call_count["n"] += 1
        return main_llm if call_count["n"] == 1 else _ImmediatelyReportsLLM()

    monkeypatch.setattr(core, "get_provider", _get_provider_dispatch)

    _run(run_session(session_id))

    saved = store.load_session(session_id)
    assert len(saved.get("auto_delegated_hosts") or []) == 4
    # 2 delegations, not 1 -- Recon's own overflow-host delegation (asserted above) AND Analyze's
    # own secondary-host delegation (_auto_delegate_analyze_overflow) both fire in a single real
    # run_session pass once there are enough confirmed hosts for each to find something worth
    # splitting off -- proof the operator's own "subagent delegation must work on every phase, not
    # just one" requirement holds end-to-end, not just in each phase's own isolated unit tests.
    assert len(saved.get("subagent_tasks") or {}) == 2
