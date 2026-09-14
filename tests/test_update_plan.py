"""update_plan (agent/tools/native.py): the agent's own adaptive task list, created at session
start and refined as real facts (a confirmed technology, CVE, plugin, version) land. Three levels
-- phase -> task -> subtask -- with task/phase "status" always derived from their own children
(native.py's _derive_plan_status), never independently settable. Same "validate in the native
tool, persist in agent/core.py's own execute() closure" split as record_target/record_finding --
this file covers both halves plus _plan_task_addendum, the addendum that shows the model its own
current plan back before it acts.
"""
import asyncio

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
from agent.core import RunContext, _apply_plan_recommendations, _apply_updated_plan, _plan_task_addendum, _run_recon
from agent.llm_client import LLMResponse, ToolCallRequest
from agent.tools.native import _derive_plan_status, update_plan
from agent.tools.registry import get_tool
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _plan_with_one_subtask(status="pending", recommended_tools=None):
    return {"phases": [{"phase": "recon", "tasks": [{"text": "Enumerate the attack surface", "subtasks": [
        {"text": "WHOIS lookup", "status": status, "recommended_tools": recommended_tools or []},
    ]}]}]}


# --- _derive_plan_status: pure unit tests ---


def test_derive_plan_status_is_pending_when_nothing_started():
    assert _derive_plan_status(["pending", "pending"]) == "pending"


def test_derive_plan_status_is_pending_for_empty_children():
    assert _derive_plan_status([]) == "pending"


def test_derive_plan_status_is_active_when_anything_in_progress():
    assert _derive_plan_status(["pending", "active"]) == "active"


def test_derive_plan_status_is_active_when_some_but_not_all_done():
    assert _derive_plan_status(["done", "pending"]) == "active"


def test_derive_plan_status_is_done_only_when_everything_is_done():
    assert _derive_plan_status(["done", "done"]) == "done"


# --- "blocked": real incident this covers -- a model correctly reported several subtasks as
# genuinely blocked ("the target's Heroku dyno is crash-looping, every request 503s"), but the
# schema at the time only recognized pending/active/done, silently downgrading "blocked" to
# "pending" -- indistinguishable from "never even attempted", and the phase then rendered as
# perpetually "active"/spinning long after the session had genuinely concluded.


def test_derive_plan_status_is_blocked_when_everything_is_done_or_blocked_and_something_is_blocked():
    assert _derive_plan_status(["done", "blocked"]) == "blocked"
    assert _derive_plan_status(["blocked", "blocked"]) == "blocked"


def test_derive_plan_status_is_active_when_blocked_mixes_with_still_open_work():
    """A genuine mix of blocked and still-pending/active children is NOT fully resolved yet --
    must still show "active", not jump straight to "blocked" while real work remains."""
    assert _derive_plan_status(["blocked", "pending"]) == "active"
    assert _derive_plan_status(["blocked", "active"]) == "active"


def test_update_plan_accepts_blocked_as_a_valid_subtask_status():
    recorded = update_plan({"phases": [{"phase": "analyze", "tasks": [
        {"text": "T", "subtasks": [{"text": "S", "status": "blocked"}]},
    ]}]})["recorded"]
    subtask = recorded["phases"][0]["tasks"][0]["subtasks"][0]
    assert subtask["status"] == "blocked"
    assert recorded["phases"][0]["tasks"][0]["status"] == "blocked"
    assert recorded["phases"][0]["status"] == "blocked"


# --- update_plan: pure unit tests (validation only, no session mutation) ---


def test_update_plan_requires_phases():
    result = update_plan({})
    assert result["status"] == "error"
    assert "phases" in result["error"]


def test_update_plan_recovers_phases_sent_as_a_json_encoded_string():
    """Real incident this covers: one real provider+model pair double-encoded this nested array
    parameter as its own JSON string on every single update_plan call across a whole session,
    failing the first attempt 100% of the time and only succeeding via the 1-Step Retry that
    resent the identical data as a real list -- an entirely avoidable extra LLM round-trip, every
    single time this tool was used."""
    import json

    phases = [{"phase": "recon", "tasks": [{"text": "x", "subtasks": [{"text": "y"}]}]}]
    result = update_plan({"phases": json.dumps(phases)})
    assert result["status"] == "ok"
    assert result["recorded"]["phases"][0]["phase"] == "recon"


def test_update_plan_repairs_a_json_string_truncated_by_exactly_one_closing_bracket():
    """Real, confirmed incident this covers (a real HackerOne rescan session): 8 of 9
    update_plan "phases was sent as a string but is not valid JSON" errors in one real session had
    the JSONDecodeError's own position land exactly at len(the original string) -- the provider's
    own function-call argument encoding reliably dropped exactly the last character (always one
    closing ']'), not a random mid-string truncation. This should now be silently repaired instead
    of costing a whole extra 1-Step Retry round-trip."""
    import json

    phases = [{"phase": "recon", "tasks": [{"text": "x", "subtasks": [{"text": "y"}]}]}]
    truncated = json.dumps(phases)[:-1]  # drop exactly the final ']'
    result = update_plan({"phases": truncated})
    assert result["status"] == "ok"
    assert result["recorded"]["phases"][0]["phase"] == "recon"


def test_update_plan_does_not_repair_a_string_truncated_mid_string_literal():
    """The repair is narrowly scoped to "missing only trailing closing brackets" -- a string cut
    off INSIDE an open string literal (no closing quote at all) is a genuinely different,
    non-recoverable malformation and must still fall through to the normal error path, not have
    brackets blindly appended after an unterminated quote."""
    import json

    phases = [{"phase": "recon", "tasks": [{"text": "x", "subtasks": [{"text": "y"}]}]}]
    truncated = json.dumps(phases)[:-7]  # ends right after the "y in "y" -- no closing quote
    result = update_plan({"phases": truncated})
    assert result["status"] == "error"


def test_update_plan_carries_a_reminder_when_phases_was_recovered_from_a_string():
    """Real, confirmed incident this fixes (rev-retest-rescan-usr_8ba29f): the SAME provider+model
    pair sent phases as a JSON string 8 separate times across one recon phase -- the old recovery
    silently self-healed every single time with zero lasting effect, since the 1-Step Retry's own
    correction exchange is a fully isolated side-conversation the model never sees again. The
    reminder must live in THIS call's own "recorded" result instead, so every future turn's own
    conversation history in this same phase can still see it."""
    import json

    phases = [{"phase": "recon", "tasks": [{"text": "x", "subtasks": [{"text": "y"}]}]}]
    result = update_plan({"phases": json.dumps(phases)})
    assert "reminder" in result["recorded"]
    assert "string" in result["recorded"]["reminder"]


def test_update_plan_carries_no_reminder_for_a_normal_native_array_call():
    phases = [{"phase": "recon", "tasks": [{"text": "x", "subtasks": [{"text": "y"}]}]}]
    result = update_plan({"phases": phases})
    assert "reminder" not in result["recorded"]


def test_update_plan_still_rejects_a_string_that_isnt_valid_json():
    result = update_plan({"phases": "not json at all"})
    assert result["status"] == "error"
    assert "phases" in result["error"]


def test_update_plan_rejects_an_unknown_phase_name():
    result = update_plan({"phases": [{"phase": "bogus", "tasks": [{"text": "x", "subtasks": [{"text": "y"}]}]}]})
    assert result["status"] == "error"


def test_update_plan_rejects_a_task_with_no_text():
    result = update_plan({"phases": [{"phase": "recon", "tasks": [{"subtasks": [{"text": "y"}]}]}]})
    assert result["status"] == "error"


def test_update_plan_accepts_an_empty_tasks_list_as_a_draft_only_forward_seed():
    """Real incident this covers: RECON_PROMPT explicitly asks the model to forward-seed a
    rationale-only draft for analyze/exploit in the SAME call as recon's own real plan, even though
    nothing is confirmed yet to build real tasks from -- the old strict "non-empty tasks" check
    rejected the WHOLE call over this, discarding recon's own real plan in the same breath."""
    result = update_plan({"phases": [{"phase": "analyze", "rationale": "Draft only — nothing confirmed yet", "tasks": []}]})
    assert result["status"] == "ok"
    assert result["recorded"]["phases"][0]["tasks"] == []
    assert result["recorded"]["phases"][0]["status"] == "pending"


def test_update_plan_still_rejects_tasks_that_isnt_a_list_at_all():
    result = update_plan({"phases": [{"phase": "analyze", "tasks": "not a list"}]})
    assert result["status"] == "error"
    assert "tasks" in result["error"]


def test_update_plan_rejects_a_task_with_no_subtasks():
    """The whole point of the 3-level structure: a task must be broken into at least one real
    concrete subtask, never left as a bare label with nothing underneath it."""
    result = update_plan({"phases": [{"phase": "recon", "tasks": [{"text": "Enumerate the attack surface"}]}]})
    assert result["status"] == "error"
    assert "subtasks" in result["error"]


def test_update_plan_rejects_an_empty_subtasks_list():
    result = update_plan({"phases": [{"phase": "recon", "tasks": [{"text": "x", "subtasks": []}]}]})
    assert result["status"] == "error"


def test_update_plan_rejects_a_subtask_with_no_text():
    result = update_plan({"phases": [{"phase": "recon", "tasks": [{"text": "x", "subtasks": [{"status": "pending"}]}]}]})
    assert result["status"] == "error"


def test_update_plan_accepts_a_valid_minimal_plan():
    result = update_plan(_plan_with_one_subtask())
    assert result["status"] == "ok"
    task = result["recorded"]["phases"][0]["tasks"][0]
    assert task["text"] == "Enumerate the attack surface"
    subtask = task["subtasks"][0]
    assert subtask["text"] == "WHOIS lookup"
    assert subtask["status"] == "pending"  # default when omitted
    assert subtask["recommended_tools"] == []


def test_update_plan_derives_task_and_phase_status_from_subtasks_not_from_a_settable_field():
    """A task/phase never carries its own independent "status" input -- update_plan's own schema
    doesn't even accept one at that level -- it's always computed from the real leaf-level work."""
    result = update_plan(_plan_with_one_subtask(status="done"))
    task = result["recorded"]["phases"][0]["tasks"][0]
    assert task["status"] == "done"
    assert result["recorded"]["phases"][0]["status"] == "done"


def test_update_plan_task_status_is_active_when_some_subtasks_are_done_and_some_are_not():
    result = update_plan({"phases": [{"phase": "recon", "tasks": [{"text": "x", "subtasks": [
        {"text": "a", "status": "done"},
        {"text": "b", "status": "pending"},
    ]}]}]})
    assert result["recorded"]["phases"][0]["tasks"][0]["status"] == "active"


def test_update_plan_phase_status_is_active_when_one_task_is_done_and_another_is_not():
    result = update_plan({"phases": [{"phase": "recon", "tasks": [
        {"text": "first", "subtasks": [{"text": "a", "status": "done"}]},
        {"text": "second", "subtasks": [{"text": "b", "status": "pending"}]},
    ]}]})
    assert result["recorded"]["phases"][0]["status"] == "active"


def test_update_plan_normalizes_an_invalid_subtask_status_to_pending_instead_of_erroring():
    result = update_plan(_plan_with_one_subtask(status="bogus"))
    assert result["status"] == "ok"
    assert result["recorded"]["phases"][0]["tasks"][0]["subtasks"][0]["status"] == "pending"


def test_update_plan_keeps_a_real_recommended_tool_name_on_the_subtask():
    result = update_plan(_plan_with_one_subtask(recommended_tools=["nmap"]))
    assert result["status"] == "ok"
    assert result["recorded"]["phases"][0]["tasks"][0]["subtasks"][0]["recommended_tools"] == ["nmap"]


def test_update_plan_silently_drops_an_unknown_recommended_tool_name_without_failing_the_call():
    """Real registry names only -- a hallucinated tool name must not fail the whole plan update
    (the plan is still useful for its other, real subtasks), but also must not be treated as if it
    were real -- agent/core.py's _apply_plan_recommendations only ever reorders tools actually
    offered this phase, so a fake name silently doing nothing is the correct, safe outcome."""
    result = update_plan(_plan_with_one_subtask(recommended_tools=["not_a_real_tool"]))
    assert result["status"] == "ok"
    assert result["recorded"]["phases"][0]["tasks"][0]["subtasks"][0]["recommended_tools"] == []
    assert result["recorded"]["_dropped_tool_names"] == ["not_a_real_tool"]


# --- _apply_updated_plan: persists a validated recorded dict into session["plan"] ---


def test_apply_updated_plan_persists_phases_and_bumps_version(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    session = {
        "session_id": "usr_plan_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": [], "version": 0, "updated_at": None},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recorded = update_plan({"phases": [{"phase": "recon", "rationale": "start broad", "tasks": [
        {"text": "port scan", "subtasks": [{"text": "nmap the primary host", "status": "pending", "recommended_tools": ["nmap"]}]},
    ]}]})["recorded"]

    _apply_updated_plan(ctx, recorded, "recon")

    assert session["plan"]["phases"] == recorded["phases"]
    assert session["plan"]["version"] == 1
    assert session["plan"]["updated_at"] is not None


def test_apply_updated_plan_merges_by_phase_key_not_a_blind_replace(tmp_path, monkeypatch):
    """Real regression test for a real, confirmed incident: an Analyze-phase update_plan call
    mislabeled its own new tasks as phase="recon", and because the OLD implementation did a blind
    full replace, it silently destroyed the real, already-accurate recon plan from three earlier
    calls -- the exploit phase never got a plan entry at all either, since nothing ever called
    update_plan with phase="exploit" for real, and the destroyed recon entry was gone forever. The
    fix: plan_phase (the REAL calling context, known deterministically by core.py, not the model's
    own free-text "phase" field inside its submission) is what decides which single entry gets
    replaced -- every other existing phase entry must survive completely untouched."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    real_recon_plan = update_plan({"phases": [{"phase": "recon", "rationale": "real recon work", "tasks": [
        {"text": "Map base domain", "subtasks": [{"text": "WHOIS lookup", "status": "done", "recommended_tools": ["whois_lookup"]}]},
    ]}]})["recorded"]
    session = {
        "session_id": "usr_plan_regression_test", "target": "example.com", "status": "processing",
        # Recon has genuinely already run its own real work by the time Analyze starts (phases run
        # sequentially in this pipeline) -- a real log entry tagged phase="recon" is what
        # _phase_has_started checks, not just the plan already having a "recon" entry.
        "logs": [{"phase": "recon", "command": "whois_lookup(...)"}],
        "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": real_recon_plan["phases"], "version": 3, "updated_at": "2026-01-01T00:00:00+00:00"},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    # The exact real-incident shape: this call is genuinely running in the Analyze tool-phase, but
    # the model mislabeled its own new tasks as phase="recon" instead of phase="analyze".
    mislabeled_recorded = update_plan({"phases": [{"phase": "recon", "rationale": "actually analyze work", "tasks": [
        {"text": "Run whatweb", "subtasks": [{"text": "whatweb on the main host", "status": "active", "recommended_tools": ["whatweb"]}]},
    ]}]})["recorded"]

    _apply_updated_plan(ctx, mislabeled_recorded, "analyze")

    phases_by_key = {entry["phase"]: entry for entry in session["plan"]["phases"]}
    # The real recon plan must survive completely untouched -- this call had no business touching it.
    assert phases_by_key["recon"] == real_recon_plan["phases"][0]
    assert phases_by_key["recon"]["tasks"][0]["text"] == "Map base domain"
    # The mislabeled submission is silently dropped, not applied under the wrong key.
    assert "analyze" not in phases_by_key or phases_by_key.get("analyze", {}).get("tasks", [{}])[0].get("text") != "Run whatweb"


def test_apply_updated_plan_replaces_only_the_matching_phase_key(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    old_plan = update_plan(_plan_with_one_subtask(status="done"))["recorded"]
    session = {
        "session_id": "usr_plan_replace_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": old_plan["phases"], "version": 1, "updated_at": "2026-01-01T00:00:00+00:00"},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    new_recorded = update_plan({"phases": [{"phase": "analyze", "tasks": [
        {"text": "new task", "subtasks": [{"text": "new subtask"}]},
    ]}]})["recorded"]

    _apply_updated_plan(ctx, new_recorded, "analyze")

    # Correctly labeled this time -- both the untouched recon entry and the new analyze entry survive.
    phases_by_key = {entry["phase"]: entry for entry in session["plan"]["phases"]}
    assert set(phases_by_key) == {"recon", "analyze"}
    assert phases_by_key["recon"] == old_plan["phases"][0]  # untouched
    assert phases_by_key["analyze"]["tasks"][0]["text"] == "new task"
    assert session["plan"]["version"] == 2


# --- forward-seeding: Recon may sketch Analyze/Exploit's expected tasks upfront -----------------
# RECON_PROMPT now asks the model to plan all three phases in its very first update_plan call --
# these prove the persistence layer actually allows that (a genuinely new capability) while still
# fully preserving the original incident's protection: once a phase has its own real entry, only a
# call running in THAT phase's own context may ever touch it again.


def test_recon_can_forward_seed_analyze_and_exploit_on_the_very_first_call(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    session = {
        "session_id": "usr_forward_seed_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": [], "version": 0, "updated_at": None},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recorded = update_plan({"phases": [
        {"phase": "recon", "tasks": [{"text": "Map the attack surface", "subtasks": [{"text": "WHOIS lookup"}]}]},
        {"phase": "analyze", "tasks": [{"text": "Expected: fingerprint the web stack", "subtasks": [{"text": "whatweb once a host resolves"}]}]},
        {"phase": "exploit", "tasks": [{"text": "Expected: attempt each confirmed finding", "subtasks": [{"text": "per-finding exploitation pass"}]}]},
    ]})["recorded"]

    _apply_updated_plan(ctx, recorded, "recon")

    phases_by_key = {entry["phase"]: entry for entry in session["plan"]["phases"]}
    assert set(phases_by_key) == {"recon", "analyze", "exploit"}
    assert phases_by_key["analyze"]["tasks"][0]["text"] == "Expected: fingerprint the web stack"
    assert phases_by_key["exploit"]["tasks"][0]["text"] == "Expected: attempt each confirmed finding"
    # Real regression this covers: forward-seeding used to leave the persisted list in
    # ["analyze", "exploit", "recon"] order (whatever order the loop happened to process phases
    # in), because Recon's own entry was only added via own_entry AFTER the forward-seed loop had
    # already added analyze/exploit -- confirmed live in a real session's Plan tab showing
    # ANALYZE/EXPLOIT above RECON. The Plan tab must always show the real pipeline order.
    assert [entry["phase"] for entry in session["plan"]["phases"]] == ["recon", "analyze", "exploit"]


def test_recon_can_forward_seed_a_genuinely_empty_draft_for_analyze_without_losing_its_own_real_plan(tmp_path, monkeypatch):
    """Real, confirmed live incident: a session's very first update_plan call submitted a fully
    broken-down recon plan alongside a rationale-only, tasks-less draft for analyze ("Draft only —
    no services confirmed yet") -- exactly what RECON_PROMPT itself asks for -- and the old
    validation rejected the ENTIRE call, discarding recon's own real plan along with it."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    session = {
        "session_id": "usr_empty_draft_forward_seed_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": [], "version": 0, "updated_at": None},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    result = update_plan({"phases": [
        {"phase": "recon", "rationale": "real recon plan", "tasks": [
            {"text": "Map the attack surface", "subtasks": [{"text": "WHOIS lookup"}]},
        ]},
        {"phase": "analyze", "rationale": "Draft only — no services confirmed yet", "tasks": []},
    ]})
    assert result["status"] == "ok"  # the whole call succeeds, not rejected over analyze's empty draft

    _apply_updated_plan(ctx, result["recorded"], "recon")

    phases_by_key = {entry["phase"]: entry for entry in session["plan"]["phases"]}
    assert phases_by_key["recon"]["tasks"][0]["text"] == "Map the attack surface"
    assert phases_by_key["analyze"]["tasks"] == []
    assert phases_by_key["analyze"]["rationale"] == "Draft only — no services confirmed yet"


def test_a_forward_seeded_phase_can_still_be_freely_overwritten_by_its_own_real_first_call(tmp_path, monkeypatch):
    """Analyze's own first real update_plan call, once Analyze actually starts, must be able to
    fully replace whatever Recon merely sketched ahead of time -- a forward-seed is a first guess,
    never a lock-in."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    session = {
        "session_id": "usr_forward_seed_overwrite_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": [], "version": 0, "updated_at": None},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    recon_seed = update_plan({"phases": [
        {"phase": "recon", "tasks": [{"text": "Map the attack surface", "subtasks": [{"text": "WHOIS lookup"}]}]},
        {"phase": "analyze", "tasks": [{"text": "Expected: guessed analyze work", "subtasks": [{"text": "a guess"}]}]},
    ]})["recorded"]
    _apply_updated_plan(ctx, recon_seed, "recon")

    real_analyze = update_plan({"phases": [
        {"phase": "analyze", "tasks": [{"text": "WordPress confirmed, scan the CMS", "subtasks": [{"text": "run wpscan", "recommended_tools": ["wpscan"]}]}]},
    ]})["recorded"]
    _apply_updated_plan(ctx, real_analyze, "analyze")

    phases_by_key = {entry["phase"]: entry for entry in session["plan"]["phases"]}
    assert phases_by_key["analyze"]["tasks"][0]["text"] == "WordPress confirmed, scan the CMS"  # replaced, not merged with the guess


def test_a_different_phase_can_keep_re_seeding_a_not_yet_started_phase(tmp_path, monkeypatch):
    """Real incident this fixes: RECON_PROMPT explicitly asks the model to keep revising Analyze/
    Exploit's own forward-looking sketch every time a new fact lands, not just once at the very
    start -- confirmed live, a real session submitted a full [recon, analyze, exploit] update 6
    times across one run, and every single non-first attempt to touch analyze/exploit from recon
    was silently dropped even though analyze had never actually started. A forward-seed's own mere
    existence was never the danger the original mislabeling incident needed protecting against --
    a phase that hasn't started yet may be freely re-seeded as many times as an earlier phase
    learns something new about it."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    session = {
        "session_id": "usr_reseed_before_start_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": [], "version": 0, "updated_at": None},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    first_seed = update_plan({"phases": [
        {"phase": "recon", "tasks": [{"text": "Map the attack surface", "subtasks": [{"text": "WHOIS lookup"}]}]},
        {"phase": "analyze", "tasks": [{"text": "First guess", "subtasks": [{"text": "a guess"}]}]},
    ]})["recorded"]
    _apply_updated_plan(ctx, first_seed, "recon")

    second_recon_call = update_plan({"phases": [
        {"phase": "recon", "tasks": [{"text": "Map the attack surface", "status": "done", "subtasks": [{"text": "WHOIS lookup", "status": "done"}]}]},
        {"phase": "analyze", "tasks": [{"text": "Recon learned something new, revised the guess", "subtasks": [{"text": "a better guess"}]}]},
    ]})["recorded"]
    _apply_updated_plan(ctx, second_recon_call, "recon")

    phases_by_key = {entry["phase"]: entry for entry in session["plan"]["phases"]}
    # analyze hasn't actually started (no log entries with phase="analyze" yet) -- the re-seed applies.
    assert phases_by_key["analyze"]["tasks"][0]["text"] == "Recon learned something new, revised the guess"
    assert phases_by_key["recon"]["tasks"][0]["status"] == "done"  # recon's own entry still updates freely


def test_a_different_phase_cannot_re_seed_a_phase_that_has_actually_started(tmp_path, monkeypatch):
    """The protection the original mislabeling incident needed still applies once a phase's own
    real work has begun (session["logs"] has a real entry tagged with that phase) -- only a call
    running in that phase's own context may touch it from that point on."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    session = {
        "session_id": "usr_no_reseed_after_start_test", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": [], "version": 0, "updated_at": None},
    }
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    # Recon forward-seeds analyze's guess -- analyze hasn't started yet, so this applies freely.
    first_seed = update_plan({"phases": [
        {"phase": "recon", "tasks": [{"text": "Map the attack surface", "subtasks": [{"text": "WHOIS lookup"}]}]},
        {"phase": "analyze", "tasks": [{"text": "Analyze's forward-seeded guess", "subtasks": [{"text": "a guess"}]}]},
    ]})["recorded"]
    _apply_updated_plan(ctx, first_seed, "recon")

    # Analyze now genuinely starts -- a real log entry lands, and analyze submits its own real plan.
    session["logs"].append({"phase": "analyze", "command": "whatweb(...)"})
    real_analyze = update_plan({"phases": [
        {"phase": "analyze", "tasks": [{"text": "Analyze's own real plan", "subtasks": [{"text": "a real task"}]}]},
    ]})["recorded"]
    _apply_updated_plan(ctx, real_analyze, "analyze")

    # A later call still running in recon's own context (e.g. a resumed/re-entrant recon pass)
    # tries to touch analyze again -- must be ignored now that analyze has genuinely started.
    second_recon_call = update_plan({"phases": [
        {"phase": "recon", "tasks": [{"text": "Map the attack surface", "status": "done", "subtasks": [{"text": "WHOIS lookup", "status": "done"}]}]},
        {"phase": "analyze", "tasks": [{"text": "Recon tries to overwrite analyze after it started", "subtasks": [{"text": "should be ignored"}]}]},
    ]})["recorded"]
    _apply_updated_plan(ctx, second_recon_call, "recon")

    phases_by_key = {entry["phase"]: entry for entry in session["plan"]["phases"]}
    assert phases_by_key["analyze"]["tasks"][0]["text"] == "Analyze's own real plan"  # untouched
    assert phases_by_key["recon"]["tasks"][0]["status"] == "done"  # recon's own entry still updates freely


# --- _plan_task_addendum: shows the model its own current plan for THIS phase only ---


def test_plan_task_addendum_is_empty_with_no_plan_yet():
    session = {"plan": {"phases": [], "version": 0, "updated_at": None}}
    assert _plan_task_addendum(session, "recon") == ""


def test_plan_task_addendum_is_empty_when_no_phase_entry_matches():
    session = {"plan": {"phases": update_plan(_plan_with_one_subtask())["recorded"]["phases"], "version": 1, "updated_at": "now"}}
    assert _plan_task_addendum(session, "analyze") == ""


def test_plan_task_addendum_renders_matching_phase_task_and_subtask_tree():
    recorded = update_plan({"phases": [{
        "phase": "analyze", "rationale": "WordPress confirmed",
        "tasks": [{"text": "Scan the CMS", "subtasks": [
            {"text": "run wpscan", "status": "active", "recommended_tools": ["wpscan", "nuclei"]},
        ]}],
    }]})["recorded"]
    session = {"plan": {"phases": recorded["phases"], "version": 1, "updated_at": "now"}}

    addendum = _plan_task_addendum(session, "analyze")

    assert "Scan the CMS" in addendum
    assert "run wpscan" in addendum
    assert "wpscan, nuclei" in addendum
    assert "WordPress confirmed" in addendum
    assert "[active]" in addendum  # both the task line (derived active) and the subtask line


# --- _apply_plan_recommendations: reorders (never removes) tool_specs per the current plan ---


def _recon_tools():
    # Real registered ToolSpecs, not fakes -- nmap/dns_lookup are both real recon-category tools,
    # so this exercises the real dataclasses.replace(spec, description=...) path against a real
    # frozen ToolSpec instance, not a hand-built stand-in that might not share its constraints.
    return [get_tool("nmap"), get_tool("dns_lookup"), get_tool("whois_lookup")]


def _plan_session(phase, subtask_status="active", recommended_tools=None):
    recorded = update_plan({"phases": [{"phase": phase, "tasks": [
        {"text": "resolve hostnames", "subtasks": [{"text": "dns", "status": subtask_status, "recommended_tools": recommended_tools or []}]},
    ]}]})["recorded"]
    return {"plan": {"phases": recorded["phases"], "version": 1, "updated_at": "now"}}


def test_apply_plan_recommendations_is_a_no_op_identity_with_no_plan():
    tools = _recon_tools()
    session = {"plan": {"phases": [], "version": 0, "updated_at": None}}
    result = _apply_plan_recommendations(tools, session, "recon")
    assert result == tools


def test_apply_plan_recommendations_promotes_and_labels_a_matching_tool():
    tools = _recon_tools()
    session = _plan_session("recon", recommended_tools=["dns_lookup"])

    result = _apply_plan_recommendations(tools, session, "recon")

    assert result[0].name == "dns_lookup"  # moved to the front
    assert result[0].description.startswith("[Plan-recommended]")
    # Every original tool is still present -- reordering, never removal.
    assert {spec.name for spec in result} == {spec.name for spec in tools}
    # The original registry ToolSpec is untouched -- dataclasses.replace returns a new object.
    assert not get_tool("dns_lookup").description.startswith("[Plan-recommended]")


def test_apply_plan_recommendations_ignores_a_done_subtasks_own_recommendation():
    tools = _recon_tools()
    session = _plan_session("recon", subtask_status="done", recommended_tools=["dns_lookup"])
    result = _apply_plan_recommendations(tools, session, "recon")
    assert result == tools  # a done subtask's recommendation no longer needs to be pushed forward


def test_apply_plan_recommendations_safely_ignores_an_out_of_category_or_unknown_name():
    tools = _recon_tools()
    session = _plan_session("recon", recommended_tools=["sqlmap", "not_a_real_tool"])
    result = _apply_plan_recommendations(tools, session, "recon")
    assert result == tools  # neither name is present in this phase's own tool_specs -- no-op, no crash


def test_apply_plan_recommendations_only_reads_the_matching_phase():
    tools = _recon_tools()
    session = _plan_session("analyze", recommended_tools=["dns_lookup"])
    result = _apply_plan_recommendations(tools, session, "recon")
    assert result == tools  # the recommendation belongs to "analyze", not "recon"


# --- end-to-end: a real _run_recon phase, proving the full wiring, not just the isolated helpers ---


class _PlanScriptedLLM:
    """Like test_recon_tech_detection.py's _ScriptedLLM, but also records the real tools schema
    handed to each turn -- what this test actually needs to prove Stage 5 wired update_plan's own
    effect all the way through a real phase loop, not just that the isolated helper functions work
    in isolation."""
    provider_id = "test-provider"
    model = "test-model"

    def __init__(self, tool_calls_per_turn):
        self._script = list(tool_calls_per_turn)
        self.calls_made = 0
        self.tools_per_call: list[list[dict]] = []

    def complete(self, messages, tools=None, stop_check=None):
        self.calls_made += 1
        self.tools_per_call.append(tools or [])
        if self._script:
            name, arguments = self._script.pop(0)
            return LLMResponse(content=None, tool_calls=[ToolCallRequest(id=f"call_{self.calls_made}", name=name, arguments=arguments)])
        return LLMResponse(content="done", tool_calls=[])


def test_update_plan_call_reorders_tools_for_the_very_next_turn_in_a_real_recon_phase(tmp_path, monkeypatch):
    """Real, live proof of Stage 5's whole point: the model calls update_plan recommending
    dns_lookup on a subtask, and the VERY NEXT turn's real tools schema (what actually reaches the
    LLM) shows dns_lookup promoted to the front with its description marked -- not a
    hand-inspection of _apply_plan_recommendations in isolation, the actual _run_recon loop wiring."""
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")

    session = {
        "session_id": "usr_plan_e2e", "target": "example.com", "status": "processing",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": [], "version": 0, "updated_at": None},
    }
    llm = _PlanScriptedLLM([
        ("update_plan", {"phases": [{"phase": "recon", "tasks": [
            {"text": "resolve hostnames first", "subtasks": [{"text": "dns lookup the primary host", "recommended_tools": ["dns_lookup"]}]},
        ]}]}),
    ])
    ctx = RunContext(llm=llm, session=session, session_id=session["session_id"])

    _run(_run_recon(ctx, "example.com"))

    assert llm.calls_made >= 2, "expected at least the update_plan turn plus one follow-up turn"
    first_turn_tools = [t["function"]["name"] for t in llm.tools_per_call[0]]
    second_turn_tools = [t["function"]["name"] for t in llm.tools_per_call[1]]
    assert first_turn_tools[0] != "dns_lookup"  # not yet recommended on the first turn
    assert second_turn_tools[0] == "dns_lookup"  # promoted to the front once the plan named it

    second_turn_dns_lookup = next(t for t in llm.tools_per_call[1] if t["function"]["name"] == "dns_lookup")
    assert second_turn_dns_lookup["function"]["description"].startswith("[Plan-recommended]")

    assert session["plan"]["phases"][0]["tasks"][0]["subtasks"][0]["recommended_tools"] == ["dns_lookup"]
