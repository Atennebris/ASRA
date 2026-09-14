"""agent/core.py's _append_log now stamps every session.json log entry with a real "at" timestamp
(same key/convention as _record_approval's own event timestamps) -- without it, correlating one
specific step to a real point in time (was this during a provider outage? how long did this phase
actually take?) meant manually grepping debug.log for matching text and reading its timestamp off
a completely separate file, exactly what a session log-review audit had to do by hand.
"""
from datetime import datetime

from agent.core import RunContext, _append_log


def test_append_log_stamps_a_real_iso_timestamp():
    session = {"session_id": "usr_ts_test", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _append_log(ctx, "recon", "some thought", "nmap -F -sV example.com", "success", None)

    entry = session["logs"][0]
    assert "at" in entry
    # Round-trips through fromisoformat -- proves it's a real, parseable timestamp, not a placeholder.
    parsed = datetime.fromisoformat(entry["at"])
    assert parsed.tzinfo is not None  # timezone-aware, same as every other timestamp in this project


def test_append_log_timestamps_are_in_chronological_order_across_steps():
    session = {"session_id": "usr_ts_order_test", "logs": []}
    ctx = RunContext(llm=None, session=session, session_id=session["session_id"])

    _append_log(ctx, "recon", None, "step one", "success", None)
    _append_log(ctx, "recon", None, "step two", "success", None)

    first_at = datetime.fromisoformat(session["logs"][0]["at"])
    second_at = datetime.fromisoformat(session["logs"][1]["at"])
    assert second_at >= first_at
