"""Unit tests for the chat-to-agent instruction queue in agent/core.py — the
put-back semantics (a non-matching instruction must survive a drain/pop call untouched, in
order) are exactly the kind of thing worth pinning down directly, not just via a live run.
"""
import asyncio

import agent.core as core
from agent.core import (
    RunContext,
    _drain_pending_guidance,
    _drain_pending_hypotheses,
    _pop_deep_dive_instruction,
    _pop_skip_instruction,
    get_instruction_queue,
)


def _run(coro):
    return asyncio.run(coro)


def test_drain_pending_guidance_returns_queued_text_in_order():
    session_id = "usr_instr_1"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "add_guidance", "text": "first hint"})
    queue.put_nowait({"type": "add_guidance", "text": "second hint"})

    result = _drain_pending_guidance(session_id)

    assert result == ["first hint", "second hint"]
    assert queue.empty()


def test_drain_pending_guidance_leaves_skip_finding_instructions_in_queue():
    session_id = "usr_instr_2"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "skip_finding", "finding_title": "X"})
    queue.put_nowait({"type": "add_guidance", "text": "hint"})

    result = _drain_pending_guidance(session_id)

    assert result == ["hint"]
    assert queue.qsize() == 1
    assert queue.get_nowait() == {"type": "skip_finding", "finding_title": "X"}


def test_drain_pending_guidance_empty_queue_returns_empty_list():
    assert _drain_pending_guidance("usr_instr_empty") == []


def _ctx(session_id):
    session = {"session_id": session_id, "target": "example.com", "status": "processing", "logs": [], "findings": [], "hypotheses": []}
    return RunContext(llm=None, session=session, session_id=session_id)


def test_drain_pending_hypotheses_structures_persists_and_returns_added_entries(monkeypatch):
    """_structure_hypothesis_text (a real LLM call) is mocked here -- this test is about the
    drain/persist mechanics, not the structuring itself, which has its own dedicated tests in
    tests/test_hypothesis_structuring.py."""
    session_id = "usr_instr_hyp_1"
    ctx = _ctx(session_id)
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "add_hypothesis", "raw_text": "confirmed on a different scan: exposed .git, saw a 403 on /.git/config"})

    async def fake_structure(ctx, raw_text):
        return {"text": "check for exposed .git", "evidence": "saw a 403 on /.git/config"}

    monkeypatch.setattr(core, "_structure_hypothesis_text", fake_structure)

    result = _run(_drain_pending_hypotheses(ctx, "exploit"))

    assert len(result) == 1
    assert result[0]["text"] == "check for exposed .git"
    assert len(ctx.session["hypotheses"]) == 1
    entry = ctx.session["hypotheses"][0]
    assert entry["text"] == "check for exposed .git"
    assert entry["evidence"] == "saw a 403 on /.git/config"
    assert entry["source"] == "user"
    assert entry["source_phase"] == "exploit"
    assert queue.empty()


def test_drain_pending_hypotheses_skips_persisting_when_structuring_yields_nothing(monkeypatch):
    ctx = _ctx("usr_instr_hyp_blank")
    queue = get_instruction_queue("usr_instr_hyp_blank")
    queue.put_nowait({"type": "add_hypothesis", "raw_text": "   "})

    async def fake_structure(ctx, raw_text):
        return {"text": "", "evidence": ""}

    monkeypatch.setattr(core, "_structure_hypothesis_text", fake_structure)

    result = _run(_drain_pending_hypotheses(ctx, "recon"))

    assert result == []
    assert ctx.session["hypotheses"] == []


def test_drain_pending_hypotheses_leaves_other_instruction_types_in_queue(monkeypatch):
    session_id = "usr_instr_hyp_2"
    ctx = _ctx(session_id)
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "deep_dive", "finding_title": "X"})
    queue.put_nowait({"type": "add_hypothesis", "raw_text": "hint"})
    monkeypatch.setattr(core, "_structure_hypothesis_text", lambda ctx, raw_text: asyncio.sleep(0, result={"text": raw_text, "evidence": ""}))

    result = _run(_drain_pending_hypotheses(ctx, "recon"))

    assert len(result) == 1
    assert queue.qsize() == 1
    assert queue.get_nowait() == {"type": "deep_dive", "finding_title": "X"}


def test_drain_pending_hypotheses_empty_queue_returns_empty_list_and_persists_nothing():
    ctx = _ctx("usr_instr_hyp_empty")
    assert _run(_drain_pending_hypotheses(ctx, "recon")) == []
    assert ctx.session["hypotheses"] == []


def test_drain_pending_hypotheses_prioritizes_an_existing_open_entry_without_duplicating():
    session_id = "usr_instr_hyp_prioritize"
    ctx = _ctx(session_id)
    ctx.session["hypotheses"] = [{
        "id": "hyp1", "text": "old lead", "evidence": "", "source_phase": "recon", "source": "agent",
        "status": "unconfirmed", "resolution_note": None, "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": None,
    }]
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "prioritize_hypothesis", "hypothesis_id": "hyp1"})

    result = _run(_drain_pending_hypotheses(ctx, "exploit"))

    assert len(result) == 1
    assert result[0]["id"] == "hyp1"
    assert len(ctx.session["hypotheses"]) == 1  # no duplicate created
    assert queue.empty()


def test_drain_pending_hypotheses_prioritize_silently_skips_a_resolved_or_missing_id():
    session_id = "usr_instr_hyp_prioritize_stale"
    ctx = _ctx(session_id)
    ctx.session["hypotheses"] = [{
        "id": "hyp1", "text": "old lead", "evidence": "", "source_phase": "recon", "source": "agent",
        "status": "confirmed", "resolution_note": "already handled", "created_at": "2026-01-01T00:00:00+00:00", "resolved_at": "2026-01-02T00:00:00+00:00",
    }]
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "prioritize_hypothesis", "hypothesis_id": "hyp1"})
    queue.put_nowait({"type": "prioritize_hypothesis", "hypothesis_id": "does-not-exist"})

    result = _run(_drain_pending_hypotheses(ctx, "exploit"))

    assert result == []


def test_pop_skip_instruction_matches_and_consumes_exact_title():
    session_id = "usr_instr_3"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "skip_finding", "finding_title": "Reflected XSS"})

    matched = _pop_skip_instruction(session_id, "Reflected XSS")

    assert matched is True
    assert queue.empty()


def test_pop_skip_instruction_no_match_returns_false_and_preserves_queue():
    session_id = "usr_instr_4"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "skip_finding", "finding_title": "Other Finding"})

    matched = _pop_skip_instruction(session_id, "Reflected XSS")

    assert matched is False
    assert queue.qsize() == 1
    assert queue.get_nowait() == {"type": "skip_finding", "finding_title": "Other Finding"}


def test_pop_skip_instruction_for_not_yet_reached_finding_survives_for_later():
    """A skip queued for a finding the exploit loop hasn't reached yet must not be lost when an
    earlier finding's check doesn't match it.
    """
    session_id = "usr_instr_5"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "skip_finding", "finding_title": "Later Finding"})

    # First finding in the loop doesn't match — instruction must survive.
    assert _pop_skip_instruction(session_id, "First Finding") is False
    # Second finding in the loop does match.
    assert _pop_skip_instruction(session_id, "Later Finding") is True
    assert queue.empty()


def test_pop_skip_instruction_leaves_add_guidance_in_queue():
    session_id = "usr_instr_6"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "add_guidance", "text": "hint"})

    matched = _pop_skip_instruction(session_id, "Anything")

    assert matched is False
    assert queue.qsize() == 1
    assert queue.get_nowait() == {"type": "add_guidance", "text": "hint"}


def test_pop_deep_dive_instruction_returns_title_and_consumes_it():
    session_id = "usr_instr_7"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "deep_dive", "finding_title": "SQL Injection"})

    assert _pop_deep_dive_instruction(session_id) == "SQL Injection"
    assert queue.empty()


def test_pop_deep_dive_instruction_returns_none_for_empty_queue():
    assert _pop_deep_dive_instruction("usr_instr_empty_dd") is None


def test_pop_deep_dive_instruction_leaves_other_instruction_types_in_queue():
    session_id = "usr_instr_8"
    queue = get_instruction_queue(session_id)
    queue.put_nowait({"type": "add_guidance", "text": "hint"})
    queue.put_nowait({"type": "skip_finding", "finding_title": "Other"})

    assert _pop_deep_dive_instruction(session_id) is None
    assert queue.qsize() == 2
