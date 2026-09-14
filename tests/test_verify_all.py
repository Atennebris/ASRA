"""run_all_hypotheses_verification / run_all_findings_verification: the Hypotheses/Findings tabs'
own "Verify/recheck all" buttons -- every hypothesis/finding, first to last, reusing the existing
single-item mechanisms (run_hypothesis_verification/run_focused_exploit) in a sequential loop
instead of requiring an operator to click through a whole batch by hand. See main.py's
verify_all_hypotheses/verify_all_findings routes for how this gets triggered from the UI.
"""
import asyncio
import logging

import agent.core as core
import agent.utils.debug as debug_mod
import agent.utils.logger as logger_mod
from agent.core import run_all_findings_verification, run_all_hypotheses_verification
from sessions import store


def _run(coro):
    return asyncio.run(coro)


def _hypothesis(hyp_id, status="unconfirmed"):
    return {
        "id": hyp_id, "text": f"hypothesis {hyp_id}", "evidence": "", "source_phase": "recon",
        "source": "agent", "status": status, "resolution_note": None,
        "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
    }


def _session(session_id, hypotheses=None, findings=None):
    return {
        "session_id": session_id, "target": "example.com", "status": "completed",
        "logs": [], "findings": findings or [], "hypotheses": hypotheses or [], "approvals": [],
        "chat": {"summary": "", "messages": []},
    }


def test_run_all_hypotheses_verification_processes_every_hypothesis_in_order(monkeypatch):
    session_id = "usr_verify_all_hyp_order"
    # Deliberately mixed statuses -- "recheck all" must re-visit an already-resolved one too, not
    # just the still-open "c".
    session = _session(session_id, hypotheses=[_hypothesis("a"), _hypothesis("b", status="ruled_out"), _hypothesis("c")])
    store.save_session(session_id, session)
    called = []

    async def fake_verify(sid, raw_text="", hypothesis_id=None, provider_id=None):
        called.append(hypothesis_id)

    monkeypatch.setattr(core, "run_hypothesis_verification", fake_verify)

    _run(run_all_hypotheses_verification(session_id))

    assert called == ["a", "b", "c"]


def test_run_all_hypotheses_verification_stops_early_if_operator_interrupts(monkeypatch):
    session_id = "usr_verify_all_hyp_stop"
    session = _session(session_id, hypotheses=[_hypothesis("a"), _hypothesis("b"), _hypothesis("c")])
    store.save_session(session_id, session)
    called = []

    async def fake_verify(sid, raw_text="", hypothesis_id=None, provider_id=None):
        called.append(hypothesis_id)
        if hypothesis_id == "b":
            current = store.load_session(sid)
            current["status"] = "interrupted"
            store.save_session(sid, current)

    monkeypatch.setattr(core, "run_hypothesis_verification", fake_verify)

    _run(run_all_hypotheses_verification(session_id))

    assert called == ["a", "b"]  # "c" never reached


def test_run_all_hypotheses_verification_noop_with_no_hypotheses(monkeypatch):
    session_id = "usr_verify_all_hyp_empty"
    store.save_session(session_id, _session(session_id))
    called = []

    async def fake_verify(*args, **kwargs):
        called.append(1)

    monkeypatch.setattr(core, "run_hypothesis_verification", fake_verify)

    _run(run_all_hypotheses_verification(session_id))

    assert called == []


def test_run_all_hypotheses_verification_unknown_session_is_a_noop(monkeypatch):
    called = []

    async def fake_verify(*args, **kwargs):
        called.append(1)

    monkeypatch.setattr(core, "run_hypothesis_verification", fake_verify)

    _run(run_all_hypotheses_verification("usr_does_not_exist"))  # must not raise

    assert called == []


def test_run_all_findings_verification_processes_every_finding_in_order(monkeypatch):
    session_id = "usr_verify_all_finding_order"
    session = _session(session_id, findings=[{"title": "F1"}, {"title": "F2"}, {"title": "F3"}])
    store.save_session(session_id, session)
    called = []

    async def fake_exploit(sid, finding_title, provider_id=None, rerun_chain=True):
        called.append(finding_title)

    monkeypatch.setattr(core, "run_focused_exploit", fake_exploit)

    _run(run_all_findings_verification(session_id))

    assert called == ["F1", "F2", "F3"]


def test_run_all_findings_verification_stops_early_if_operator_interrupts(monkeypatch):
    session_id = "usr_verify_all_finding_stop"
    session = _session(session_id, findings=[{"title": "F1"}, {"title": "F2"}, {"title": "F3"}])
    store.save_session(session_id, session)
    called = []

    async def fake_exploit(sid, finding_title, provider_id=None, rerun_chain=True):
        called.append(finding_title)
        if finding_title == "F1":
            current = store.load_session(sid)
            current["status"] = "interrupted"
            store.save_session(sid, current)

    monkeypatch.setattr(core, "run_focused_exploit", fake_exploit)

    _run(run_all_findings_verification(session_id))

    assert called == ["F1"]  # "F2"/"F3" never reached


def test_run_all_findings_verification_noop_with_no_findings(monkeypatch):
    session_id = "usr_verify_all_finding_empty"
    store.save_session(session_id, _session(session_id))
    called = []

    async def fake_exploit(*args, **kwargs):
        called.append(1)

    monkeypatch.setattr(core, "run_focused_exploit", fake_exploit)

    _run(run_all_findings_verification(session_id))

    assert called == []


def test_run_all_findings_verification_runs_one_end_of_batch_chain_pass_when_something_changed(monkeypatch):
    """Real, confirmed incident this covers: 'Verify/recheck all' re-verified every finding one at
    a time and never gave Chain a single fresh look at the combined result -- confirmed live
    (a real HackerOne-style session): an operator saw every finding individually reconfirmed and
    nothing more. Each per-finding call must run with rerun_chain=False (no per-finding Chain), and
    exactly ONE Chain+Validate pass must run at the very end, once, seeing the whole batch's
    combined evidence."""
    session_id = "usr_verify_all_chain_once"
    session = _session(session_id, findings=[{"title": "F1"}, {"title": "F2"}])
    store.save_session(session_id, session)
    rerun_chain_seen = []

    async def fake_exploit(sid, finding_title, provider_id=None, rerun_chain=True):
        rerun_chain_seen.append(rerun_chain)
        return finding_title == "F2"  # only F2 "materially changed"

    chain_pass_called = []

    async def fake_post_verify_all_chain_pass(sid, provider_id):
        chain_pass_called.append(sid)

    monkeypatch.setattr(core, "run_focused_exploit", fake_exploit)
    monkeypatch.setattr(core, "_run_post_verify_all_chain_pass", fake_post_verify_all_chain_pass)

    _run(run_all_findings_verification(session_id))

    assert rerun_chain_seen == [False, False]  # never asked run_focused_exploit to chain itself
    assert chain_pass_called == [session_id]  # exactly once, at the end


def test_run_all_findings_verification_skips_the_end_of_batch_chain_pass_when_nothing_changed(monkeypatch):
    session_id = "usr_verify_all_chain_skip"
    session = _session(session_id, findings=[{"title": "F1"}, {"title": "F2"}])
    store.save_session(session_id, session)

    async def fake_exploit(sid, finding_title, provider_id=None, rerun_chain=True):
        return False  # nothing ever changed

    def _fail_if_called(sid, provider_id):
        raise AssertionError("the end-of-batch chain pass must not run when nothing changed")

    monkeypatch.setattr(core, "run_focused_exploit", fake_exploit)
    monkeypatch.setattr(core, "_run_post_verify_all_chain_pass", _fail_if_called)

    _run(run_all_findings_verification(session_id))  # must not raise


def test_run_all_hypotheses_verification_writes_to_the_debug_log_when_debug_is_on(monkeypatch, tmp_path):
    """This project's debug-module discipline -- a new mechanism's key steps must actually show up
    under get_logger("AGENT") once DEBUG=true, same pattern test_debug_module.py's own
    test_client_event_endpoint_logs_ui_category uses for the "UI" category."""
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path)
    monkeypatch.setattr(debug_mod, "is_debug_enabled", lambda: True)
    logging.getLogger("asra.AGENT").handlers.clear()
    logger_mod._configured.discard("AGENT")
    # agent/core.py's `logger` is a module-level variable bound ONCE at import time -- unlike
    # main.py's client-event route (which calls get_logger("UI") fresh per request, so clearing
    # _configured alone is enough for it), core.logger already holds a reference to the
    # logging.Logger singleton from that first, DEBUG=false import-time call. Discarding "AGENT"
    # from _configured doesn't reach into that already-bound reference by itself -- re-calling
    # get_logger("AGENT") here re-runs _configure() on the exact same singleton object core.logger
    # already points to (logging.getLogger(name) always returns the same object per name), which is
    # what actually attaches the real file handler this test needs.
    logger_mod.get_logger("AGENT")
    try:
        session_id = "usr_verify_all_debug_log"
        store.save_session(session_id, _session(session_id))  # no hypotheses -> cheap no-op path

        _run(run_all_hypotheses_verification(session_id))

        log_content = (tmp_path / "debug.log").read_text(encoding="utf-8")
        assert f"session={session_id} no hypotheses to verify" in log_content
    finally:
        logging.getLogger("asra.AGENT").handlers.clear()
        logger_mod._configured.discard("AGENT")


def test_run_all_hypotheses_verification_writes_its_own_queued_and_finished_lines_to_the_SESSION_log(monkeypatch, tmp_path):
    """Real, confirmed incident this fixes (Safety-Bug-Bounty-rescan-usr_e6c98c): this wrapper's
    own "queued"/"finished" bookkeeping lines landed ONLY in the global debug.log, never in this
    session's own project-folder debug.log -- current_session_id was only ever set INSIDE each
    looped run_hypothesis_verification call (reset again before this wrapper's own next log line
    runs), so the wrapper's own lines logged with no session context set at all."""
    monkeypatch.setattr(debug_mod, "resolve_global_app_dir", lambda: tmp_path / "global")
    monkeypatch.setattr(debug_mod, "is_debug_enabled", lambda: True)
    session_folder = tmp_path / "session-folder"
    import sessions.store as store_mod
    monkeypatch.setattr(store_mod, "get_session_folder", lambda session_id: str(session_folder))
    logging.getLogger("asra.AGENT").handlers.clear()
    logger_mod._configured.discard("AGENT")
    logger_mod.get_logger("AGENT")
    try:
        session_id = "usr_verify_all_session_log"
        store.save_session(session_id, _session(session_id, hypotheses=[_hypothesis("h1")]))

        async def fake_verify(sid, raw_text="", hypothesis_id=None, provider_id=None):
            pass

        monkeypatch.setattr(core, "run_hypothesis_verification", fake_verify)

        _run(run_all_hypotheses_verification(session_id))

        session_log = (session_folder / "debug.log").read_text(encoding="utf-8")
        assert f"session={session_id} verify-all hypotheses: 1 hypothesis(es) queued" in session_log
        assert f"session={session_id} verify-all hypotheses: finished, 1/1 checked" in session_log
    finally:
        logging.getLogger("asra.AGENT").handlers.clear()
        logger_mod._configured.discard("AGENT")
