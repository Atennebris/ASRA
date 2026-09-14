"""_auto_record_cracked_credentials_finding / _harvest_completed_background_jobs (agent/core.py) --
deterministic, LLM-free auto-recording of a finding once a background brute-force job (hydra/
web_login_bruteforce) comes back with credentials. Same "a structured positive result doesn't need
an LLM's permission to become a finding" reasoning as cve_lookup's own auto-record path, applied to
a background job's own eventual result instead.

Real, confirmed incident this whole mechanism exists because of: a live hydra RDP brute-force got
cut off from the only phase polling it by the stall detector, quietly succeeded with 6 valid-looking
credentials a few minutes later, and NOTHING downstream ever turned that into a finding -- the raw
result sat in session["background_jobs"] forever, discovered only by a manual log-review long after
the scan "finished". These tests cover both halves of that fix: the live-poll path (the moment
something calls background_job_check on a finished job) and the safety-net sweep (a job that only
finishes AFTER the phase polling it has already moved on, reaped instead by await_all_running_jobs).

A SECOND real incident, discovered by manually re-testing that exact finding against the real
target: all 6 "confirmed" RDP credential pairs failed a real mstsc logon, with typos/lockout/an
actual password change all independently ruled out -- Hydra's own rdp module gave a false positive,
a real, documented limitation of that specific module (NLA/CredSSP negotiation ambiguity), unlike
its other protocol modules which complete a real accept/reject handshake. The tests below also cover
the resulting fix: an rdp-sourced hydra hit is recorded as a High, `verification="inferred"`,
`exploited=False` lead that explicitly demands manual confirmation, never claimed with the same
confidence as every other protocol this same function handles.
"""
import asyncio

import agent.core as core
from agent.core import RunContext, _auto_record_cracked_credentials_finding, _harvest_completed_background_jobs
from sessions import store

import pytest


@pytest.fixture(autouse=True)
def _isolated_session_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def _run(coro):
    return asyncio.run(coro)


def _session_with_job(job: dict) -> dict:
    session_id = "usr_cred_finding_test"
    session = {
        "session_id": session_id, "logs": [], "findings": [], "hypotheses": [], "status": "processing",
        "background_jobs": {"job1": job},
    }
    store.save_session(session_id, session)
    return session


def _ctx(session) -> RunContext:
    return RunContext(llm=object(), session=session, session_id=session["session_id"])


def _hydra_rdp_job(**overrides) -> dict:
    # protocol="rdp" -- matches the real incident: hydra_start's own extra_metadata (agent/tools/
    # native.py) is what lets this function tell an rdp hit apart from a reliable one.
    job = {
        "tool": "hydra", "status": "ok", "target": "play.example.com", "protocol": "rdp",
        "result": {"credentials": [
            {"host": "play.example.com", "login": "Administrator", "password": "changeme1", "port": 3389},
            {"host": "play.example.com", "login": "admin", "password": "letmein123", "port": 3389},
        ]},
    }
    job.update(overrides)
    return job


def _hydra_ssh_job(**overrides) -> dict:
    job = {
        "tool": "hydra", "status": "ok", "target": "db.example.com", "protocol": "ssh",
        "result": {"credentials": [{"host": "db.example.com", "login": "root", "password": "toor", "port": 22}]},
    }
    job.update(overrides)
    return job


def test_live_poll_of_a_finished_rdp_hydra_job_records_an_unconfirmed_lead_not_a_verified_finding():
    session = _session_with_job(_hydra_rdp_job())
    ctx = _ctx(session)
    result = {"status": "ok", "result": session["background_jobs"]["job1"]["result"]}

    _run(_auto_record_cracked_credentials_finding(ctx, "job1", result))

    assert len(ctx.session["findings"]) == 1
    finding = ctx.session["findings"][0]
    # NOT full confidence -- Hydra's own rdp module has a real false-positive history, this is a
    # candidate to manually confirm, not proven access.
    assert finding["severity"] == "High"
    assert finding["exploited"] is False
    assert finding["verification"] == "inferred"
    assert "needs manual confirmation" in finding["title"]
    assert "false-positive" in finding["description"]
    assert "Administrator:changeme1" in finding["evidence_ref"]
    assert "admin:letmein123" in finding["evidence_ref"]


def test_live_poll_of_a_finished_ssh_hydra_job_still_records_a_verified_critical_finding():
    # ssh (and every other network/web protocol module) completes a real protocol-level accept/
    # reject handshake -- unlike rdp, it keeps its full original confidence.
    session = _session_with_job(_hydra_ssh_job())
    ctx = _ctx(session)
    result = {"status": "ok", "result": session["background_jobs"]["job1"]["result"]}

    _run(_auto_record_cracked_credentials_finding(ctx, "job1", result))

    assert len(ctx.session["findings"]) == 1
    finding = ctx.session["findings"][0]
    assert finding["severity"] == "Critical"
    assert finding["exploited"] is True
    assert finding["verification"] == "verified"
    assert "root:toor" in finding["evidence_ref"]


def test_a_still_running_job_records_nothing():
    session = _session_with_job(_hydra_rdp_job(status="running", result=None))
    ctx = _ctx(session)

    _run(_auto_record_cracked_credentials_finding(ctx, "job1", {"status": "running", "result": None}))

    assert ctx.session["findings"] == []


def test_an_empty_credential_result_records_nothing():
    session = _session_with_job(_hydra_rdp_job(result={"credentials": []}))
    ctx = _ctx(session)

    _run(_auto_record_cracked_credentials_finding(ctx, "job1", {"status": "ok", "result": {"credentials": []}}))

    assert ctx.session["findings"] == []


def test_a_non_credential_cracking_job_is_untouched():
    session = _session_with_job({"tool": "afl_fuzz", "status": "ok", "result": {"crashes": 1}})
    ctx = _ctx(session)

    _run(_auto_record_cracked_credentials_finding(ctx, "job1", {"status": "ok", "result": {"crashes": 1}}))

    assert ctx.session["findings"] == []


def test_checking_the_same_finished_job_twice_never_double_records():
    # A live poll, then the end-of-run safety sweep re-observing the exact same already-finished
    # job (or the model itself polling it again after the fact) must not produce two findings.
    session = _session_with_job(_hydra_rdp_job())
    ctx = _ctx(session)
    result = {"status": "ok", "result": session["background_jobs"]["job1"]["result"]}

    _run(_auto_record_cracked_credentials_finding(ctx, "job1", result))
    _run(_auto_record_cracked_credentials_finding(ctx, "job1", result))

    assert len(ctx.session["findings"]) == 1


def test_harvest_completed_background_jobs_catches_a_job_the_live_poll_path_never_saw():
    # The exact gap the safety-net sweep exists for: a job reaped by await_all_running_jobs directly
    # (background_jobs.py's own _reap) never goes through the tool-dispatch path at all -- nothing
    # would call the live-poll function above for it without this sweep.
    session = _session_with_job(_hydra_rdp_job())
    ctx = _ctx(session)

    _run(_harvest_completed_background_jobs(ctx))

    assert len(ctx.session["findings"]) == 1
    assert ctx.session["background_jobs"]["job1"]["_credential_finding_recorded"] is True


def test_harvest_completed_background_jobs_ignores_a_still_running_job():
    session = _session_with_job(_hydra_rdp_job(status="running", result=None))
    ctx = _ctx(session)

    _run(_harvest_completed_background_jobs(ctx))

    assert ctx.session["findings"] == []


def test_notifies_on_the_auto_recorded_finding(monkeypatch):
    notified = []
    monkeypatch.setattr(core, "notify_high_severity_finding", lambda *a, **kw: notified.append((a, kw)))
    session = _session_with_job(_hydra_rdp_job())
    ctx = _ctx(session)

    _run(_harvest_completed_background_jobs(ctx))

    assert notified
