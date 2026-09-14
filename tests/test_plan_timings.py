"""Plan tab timing: phase-level (session["phase_timings"], agent/core.py's _mark_phase_started/
_mark_phase_finished -- code-driven, exact, independent of whether the model ever calls
update_plan) and task/subtask-level (_stamp_task_timings -- best-effort, matched by text across
successive update_plan submissions, since the model doesn't reliably mark a subtask "active" the
moment it actually starts). Real incident this responds to: the operator asked for a duration next
to each finished task/subtask/phase, on top of the earlier live-phase-indicator work.
"""
import agent.core as core
from agent.core import (
    _mark_phase_finished,
    _mark_phase_started,
    _stamp_task_timings,
    format_accumulated_duration,
    format_duration_between,
    format_phase_duration,
)


# --- _mark_phase_started / _mark_phase_finished / format_phase_duration ---


def test_mark_phase_started_sets_started_at():
    session = {}
    _mark_phase_started(session, "recon")
    assert session["phase_timings"]["recon"]["started_at"] is not None


def test_mark_phase_started_does_not_reset_an_already_set_start_time():
    """Same 'don't reset on resume' convention run_session's own session["started_at"] already
    established for the whole session -- a resumed phase keeps its ORIGINAL start time."""
    session = {}
    _mark_phase_started(session, "recon")
    first_start = session["phase_timings"]["recon"]["started_at"]
    _mark_phase_started(session, "recon")
    assert session["phase_timings"]["recon"]["started_at"] == first_start


def test_mark_phase_finished_sets_finished_at():
    session = {}
    _mark_phase_started(session, "recon")
    _mark_phase_finished(session, "recon")
    assert session["phase_timings"]["recon"]["finished_at"] is not None


def test_mark_phase_finished_logs_when_the_clock_appears_to_step_backward(monkeypatch):
    """Real, confirmed incident this makes observable: a real session's machine clock stepped
    backward by ~1.02s mid-session, making phase_timings.exploit.finished_at come out earlier than
    its own started_at -- format_duration_between's max(0, ...) clamp silently showed "0s" with
    nothing anywhere flagging the underlying timestamps were actually inconsistent. Simulated here
    by setting started_at far in the future -- datetime.now() at _mark_phase_finished's own call
    time is naturally "earlier", the same shape a real backward clock step produces."""
    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))
    session = {"session_id": "usr_clock_test", "phase_timings": {"exploit": {"started_at": "2099-01-01T00:00:00+00:00"}}}

    _mark_phase_finished(session, "exploit")

    warning_calls = [a for a in logged if "clock appears to have stepped backward" in a[0]]
    assert len(warning_calls) == 1
    # The phase's own finished_at is still recorded (best-effort, not blocked by the anomaly).
    assert session["phase_timings"]["exploit"]["finished_at"] is not None


def test_mark_phase_finished_does_not_log_for_a_normal_forward_moving_clock(monkeypatch):
    logged = []
    monkeypatch.setattr(core.logger, "debug", lambda *args, **kwargs: logged.append(args))
    session = {"session_id": "usr_normal_clock_test"}

    _mark_phase_started(session, "recon")
    _mark_phase_finished(session, "recon")

    assert not any("clock appears to have stepped backward" in a[0] for a in logged)


def test_format_phase_duration_is_empty_when_phase_never_started():
    session = {"phase_timings": {}}
    assert format_phase_duration(session, "recon") == ""


def test_format_phase_duration_counts_up_while_still_running():
    session = {"phase_timings": {"recon": {"started_at": "2026-01-01T00:00:00+00:00"}}}
    result = format_phase_duration(session, "recon")
    assert result != ""  # counts to "now", not frozen at 0


def test_format_phase_duration_reflects_the_real_elapsed_window():
    session = {"phase_timings": {"recon": {
        "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:07:30+00:00",
    }}}
    assert format_phase_duration(session, "recon") == "7m 30s"


def test_format_duration_between_is_empty_with_no_start():
    assert format_duration_between(None, None) == ""


# --- format_accumulated_duration (hypothesis_verification's own card: a pre-summed real-work
# total across possibly several far-apart passes, never a naive started_at/finished_at span) ---


def test_format_accumulated_duration_is_empty_with_nothing_recorded():
    assert format_accumulated_duration(None) == ""
    assert format_accumulated_duration(0) == ""


def test_format_accumulated_duration_matches_the_same_dhms_shape_as_duration_between():
    assert format_accumulated_duration(450) == "7m 30s"


# --- _stamp_task_timings ---


def test_stamps_started_at_the_first_time_a_task_is_seen_as_non_pending():
    tasks = [{"text": "Task A", "status": "active", "subtasks": []}]
    _stamp_task_timings(tasks, previous_tasks=[])
    assert tasks[0].get("started_at") is not None


def test_never_stamps_started_at_for_a_task_still_pending():
    tasks = [{"text": "Task A", "status": "pending", "subtasks": []}]
    _stamp_task_timings(tasks, previous_tasks=[])
    assert "started_at" not in tasks[0]


def test_stamps_finished_at_the_first_time_a_task_is_seen_as_done():
    tasks = [{"text": "Task A", "status": "done", "subtasks": []}]
    _stamp_task_timings(tasks, previous_tasks=[])
    assert tasks[0].get("started_at") is not None
    assert tasks[0].get("finished_at") is not None


def test_preserves_a_previously_recorded_started_at_across_revisions():
    """A task the model already marked 'active' in an earlier update_plan call must keep its real
    original start time on a later revision, not get a fresh (later, wrong) timestamp."""
    previous = [{"text": "Task A", "status": "active", "started_at": "2026-01-01T00:00:00+00:00", "subtasks": []}]
    tasks = [{"text": "Task A", "status": "done", "subtasks": []}]
    _stamp_task_timings(tasks, previous_tasks=previous)
    assert tasks[0]["started_at"] == "2026-01-01T00:00:00+00:00"
    assert tasks[0]["finished_at"] is not None


def test_never_overwrites_an_already_recorded_finished_at():
    previous = [{
        "text": "Task A", "status": "done",
        "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:05:00+00:00",
        "subtasks": [],
    }]
    tasks = [{"text": "Task A", "status": "done", "subtasks": []}]
    _stamp_task_timings(tasks, previous_tasks=previous)
    assert tasks[0]["finished_at"] == "2026-01-01T00:05:00+00:00"


def test_a_reworded_task_loses_its_prior_timing_instead_of_misattributing_it():
    """No stable id exists for a task -- matching is by TEXT, so a task the model rewords between
    revisions is treated as a brand new task (safe degradation), never wrongly inherits another
    task's timing."""
    previous = [{"text": "Old wording", "status": "active", "started_at": "2026-01-01T00:00:00+00:00", "subtasks": []}]
    tasks = [{"text": "New wording", "status": "done", "subtasks": []}]
    _stamp_task_timings(tasks, previous_tasks=previous)
    assert tasks[0]["started_at"] != "2026-01-01T00:00:00+00:00"


def test_stamps_subtask_level_timings_matched_by_text_the_same_way():
    tasks = [{"text": "Task A", "status": "active", "subtasks": [
        {"text": "Subtask 1", "status": "done"},
        {"text": "Subtask 2", "status": "pending"},
    ]}]
    _stamp_task_timings(tasks, previous_tasks=[])
    assert tasks[0]["subtasks"][0].get("started_at") is not None
    assert tasks[0]["subtasks"][0].get("finished_at") is not None
    assert "started_at" not in tasks[0]["subtasks"][1]


# --- real-span estimation (real incident: batched-done tasks used to collapse to started_at ==
# finished_at, rendering as a misleading "0s" -- confirmed live: a real session's recon phase ran
# ~4.5 real minutes of genuine, successful tool calls (crt_sh_lookup, subdomain_enum, subfinder,
# dns_lookup, whois_lookup, nmap, record_target x2) before reporting them all "done" in ONE
# update_plan batch; the model just never checked in incrementally. Hiding the number entirely was
# a worse fix than the original "0s" -- the real, operator-facing complaint was "I need to know
# these actually ran for real, not that they happened instantly or got skipped." This anchors a
# task/subtask's own started_at to the LATEST real known boundary (phase_started_at for the very
# first thing, or the previous task's own finished_at), and evenly splits the known window across
# however many subtasks resolve together in one batch -- always a real, non-fabricated span. ---


def test_the_very_first_task_anchors_to_phase_started_at_not_now():
    tasks = [{"text": "Task A", "status": "done", "subtasks": []}]
    _stamp_task_timings(tasks, previous_tasks=[], phase_started_at="2026-01-01T00:00:00+00:00")
    assert tasks[0]["started_at"] == "2026-01-01T00:00:00+00:00"
    # finished_at is real "now" -- genuinely later than a phase that started at a fixed past time.
    assert tasks[0]["finished_at"] > tasks[0]["started_at"]


def test_several_subtasks_batched_done_together_get_distinct_non_zero_spans():
    """The real incident this responds to: several real, successful tool calls got reported "done"
    in the exact same update_plan call -- each subtask must still get its OWN real, non-identical
    slice of the known window, never all collapsing to the same instant."""
    tasks = [{"text": "Task A", "status": "done", "subtasks": [
        {"text": "S1", "status": "done"},
        {"text": "S2", "status": "done"},
        {"text": "S3", "status": "done"},
    ]}]
    _stamp_task_timings(tasks, previous_tasks=[], phase_started_at="2026-01-01T00:00:00+00:00")

    subtasks = tasks[0]["subtasks"]
    starts = [s["started_at"] for s in subtasks]
    finishes = [s["finished_at"] for s in subtasks]
    assert len(set(starts)) == 3  # each got a distinct starting point
    for s in subtasks:
        assert s["started_at"] != s["finished_at"]  # never a zero-width window
    # Chronological order preserved -- S1's slice ends no later than S2's starts, etc.
    assert starts[0] <= finishes[0] <= starts[1] <= finishes[1] <= starts[2] <= finishes[2]


def test_a_second_task_anchors_to_the_first_tasks_own_finished_at():
    """Sequential tasks across separate update_plan calls (the common real pattern) must chain
    off each other's real boundaries, not each restart from phase_started_at."""
    tasks = [
        {"text": "Task A", "status": "done", "subtasks": []},
        {"text": "Task B", "status": "done", "subtasks": []},
    ]
    _stamp_task_timings(tasks, previous_tasks=[], phase_started_at="2026-01-01T00:00:00+00:00")
    assert tasks[1]["started_at"] == tasks[0]["finished_at"]


def test_a_subtask_already_individually_timed_keeps_its_own_real_data_not_the_split_estimate():
    previous = [{"text": "Task A", "status": "active", "subtasks": [
        {"text": "S1", "status": "done", "started_at": "2026-01-01T00:00:00+00:00", "finished_at": "2026-01-01T00:02:00+00:00"},
    ]}]
    tasks = [{"text": "Task A", "status": "done", "subtasks": [
        {"text": "S1", "status": "done"},
        {"text": "S2", "status": "done"},  # newly resolving alongside an already-timed sibling
    ]}]
    _stamp_task_timings(tasks, previous_tasks=previous, phase_started_at="2026-01-01T00:00:00+00:00")
    assert tasks[0]["subtasks"][0]["started_at"] == "2026-01-01T00:00:00+00:00"
    assert tasks[0]["subtasks"][0]["finished_at"] == "2026-01-01T00:02:00+00:00"
    # S2 is real and non-zero too, anchored off the task's own start, not S1's already-known window.
    assert tasks[0]["subtasks"][1]["started_at"] != tasks[0]["subtasks"][1]["finished_at"]
