"""Unit tests for the chat-to-agent instruction queue in agent/core.py — the
put-back semantics (a non-matching instruction must survive a drain/pop call untouched, in
order) are exactly the kind of thing worth pinning down directly, not just via a live run.
"""
from agent.core import (
    _drain_pending_guidance,
    _pop_deep_dive_instruction,
    _pop_skip_instruction,
    get_instruction_queue,
)


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
