"""_finalize_phase_plan_on_normal_completion (agent/core.py): Recon/Analyze's own safety net for
the Plan tab, mirroring _sync_exploit_plan_from_findings' philosophy one level down. Real, confirmed
incident this fixes (Telenor-Sweden-YesWeHack rescan session): a recon phase ran 69 real,
successful tool calls across 30 minutes, and the analyze phase after it also completed normally --
but the ONE update_plan call that would have marked real progress failed (a JSON double-encoding
parse bug) and the model never retried for the rest of either phase. The session completed with
real findings; the Plan tab instead rendered both phases as an almost unbroken wall of red
"blocked" X icons (session_fragment.html's phase_concluded fallback), falsely implying the scan had
failed. This function flips any task/subtask the model never resolved to "done" at the phase's own
normal end-of-loop return, so a phase that genuinely ran its course isn't shown as if it crashed.
"""
from agent.core import RunContext, _finalize_phase_plan_on_normal_completion
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _make_session_with_plan(phases):
    return {
        "session_id": "usr_finalize_plan_test", "target": "example.com", "status": "completed",
        "logs": [], "findings": [], "approvals": [], "chat": {"summary": "", "messages": []},
        "plan": {"phases": phases, "version": 3, "updated_at": "now"},
    }


def test_marks_pending_subtasks_and_tasks_done_when_phase_concluded_normally(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session = _make_session_with_plan([
        {
            "phase": "recon",
            "rationale": "r",
            "status": "pending",
            "tasks": [
                {
                    "text": "Resolve DNS",
                    "status": "pending",
                    "subtasks": [
                        {"text": "DNS lookup", "status": "pending", "recommended_tools": ["dns_lookup"]},
                        {"text": "Subdomain enum", "status": "pending", "recommended_tools": ["subfinder"]},
                    ],
                },
            ],
        },
    ])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _finalize_phase_plan_on_normal_completion(ctx, "recon")

    recon = next(p for p in ctx.session["plan"]["phases"] if p["phase"] == "recon")
    assert recon["status"] == "done"
    assert recon["tasks"][0]["status"] == "done"
    assert all(st["status"] == "done" for st in recon["tasks"][0]["subtasks"])


def test_never_touches_an_already_resolved_subtask(tmp_path, monkeypatch):
    """Only an unresolved ("pending"/"active") subtask gets flipped -- one the model already
    correctly reported (done, or a genuine blocked) is left exactly as reported, never overwritten."""
    _isolate(tmp_path, monkeypatch)
    session = _make_session_with_plan([
        {
            "phase": "analyze",
            "rationale": "a",
            "status": "pending",
            "tasks": [
                {
                    "text": "CVE matching",
                    "status": "pending",
                    "subtasks": [
                        {"text": "Match CVEs", "status": "done", "recommended_tools": []},
                        {"text": "A genuinely unreachable step", "status": "blocked", "recommended_tools": []},
                        {"text": "Rank attack surface", "status": "pending", "recommended_tools": ["rank_attack_surface"]},
                    ],
                },
            ],
        },
    ])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _finalize_phase_plan_on_normal_completion(ctx, "analyze")

    subtasks = ctx.session["plan"]["phases"][0]["tasks"][0]["subtasks"]
    assert subtasks[0]["status"] == "done"      # untouched
    assert subtasks[1]["status"] == "blocked"   # untouched -- a genuine block, not silently erased
    assert subtasks[2]["status"] == "done"      # the only one actually flipped


def test_is_a_no_op_when_the_phase_already_fully_resolved(tmp_path, monkeypatch):
    """No pending work left -- nothing to flip, no spurious plan version bump/save."""
    _isolate(tmp_path, monkeypatch)
    session = _make_session_with_plan([
        {
            "phase": "recon",
            "rationale": "r",
            "status": "done",
            "tasks": [{"text": "t", "status": "done", "subtasks": [{"text": "s", "status": "done", "recommended_tools": []}]}],
        },
    ])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])
    original_version = ctx.session["plan"]["version"]

    _finalize_phase_plan_on_normal_completion(ctx, "recon")

    assert ctx.session["plan"]["version"] == original_version


def test_is_a_no_op_when_the_phase_has_no_plan_entry_at_all(tmp_path, monkeypatch):
    """A phase the model never submitted any plan for (no forward-seed, nothing) -- nothing to
    finalize, must not crash or fabricate a phase entry out of thin air."""
    _isolate(tmp_path, monkeypatch)
    session = _make_session_with_plan([])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _finalize_phase_plan_on_normal_completion(ctx, "recon")

    assert ctx.session["plan"]["phases"] == []


def test_does_not_touch_a_different_phases_entry(tmp_path, monkeypatch):
    """Same "only ever replace the ONE phase entry matching plan_phase" discipline
    _apply_updated_plan/_sync_exploit_plan_from_findings already establish -- finalizing "recon"
    must never reach into "analyze"'s own still-genuinely-in-progress entry."""
    _isolate(tmp_path, monkeypatch)
    session = _make_session_with_plan([
        {"phase": "recon", "rationale": "r", "status": "pending",
         "tasks": [{"text": "t", "status": "pending", "subtasks": [{"text": "s", "status": "pending", "recommended_tools": []}]}]},
        {"phase": "analyze", "rationale": "a", "status": "pending",
         "tasks": [{"text": "t2", "status": "pending", "subtasks": [{"text": "s2", "status": "pending", "recommended_tools": []}]}]},
    ])
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _finalize_phase_plan_on_normal_completion(ctx, "recon")

    analyze = next(p for p in ctx.session["plan"]["phases"] if p["phase"] == "analyze")
    assert analyze["status"] == "pending"
    assert analyze["tasks"][0]["subtasks"][0]["status"] == "pending"
