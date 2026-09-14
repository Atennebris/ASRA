"""main.py's _efficiency_needle_point (the Summary tab's efficiency-gauge needle geometry, pure
presentation math kept separate from compute_efficiency_score's own score formula) plus a real
end-to-end render check that the gauge actually shows up with sane numbers on a real session page.
"""
import pathlib
import tempfile

from fastapi.testclient import TestClient

import main
from sessions import store


def test_needle_point_at_score_zero_points_straight_up():
    point = main._efficiency_needle_point(0)
    assert point["x"] == 100.0  # centered horizontally
    assert point["y"] < 100  # above the pivot (SVG y grows downward)


def test_needle_point_at_score_minus_100_points_left():
    point = main._efficiency_needle_point(-100)
    assert point["x"] < 100
    assert abs(point["y"] - 100) < 0.01  # level with the pivot


def test_needle_point_at_score_plus_100_points_right():
    point = main._efficiency_needle_point(100)
    assert point["x"] > 100
    assert abs(point["y"] - 100) < 0.01


def test_needle_point_clamps_an_out_of_range_score():
    assert main._efficiency_needle_point(500) == main._efficiency_needle_point(100)
    assert main._efficiency_needle_point(-500) == main._efficiency_needle_point(-100)


def _client_with_session(session):
    tmp = pathlib.Path(tempfile.mkdtemp())
    store.SESSIONS_DIR = tmp
    store.INDEX_PATH = tmp / "sessions_index.json"
    main.SESSIONS_DIR = tmp
    store.save_session(session["session_id"], session)
    return TestClient(main.app)


def test_gauge_renders_on_a_session_with_real_phase_efficiency_data():
    session = {
        "session_id": "usr_gauge_smoke", "name": "test", "target": "example.com", "status": "completed",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
        "phase_efficiency": {
            "recon": {"tool_calls": 40, "retried": 1, "non_ok": 1, "duplicates": 0},
            "analyze": {"tool_calls": 30, "retried": 0, "non_ok": 0, "duplicates": 0},
        },
        "stall_events": [],
    }
    client = _client_with_session(session)
    html = client.get("/session/usr_gauge_smoke").text
    assert "Process efficiency" in html
    assert "70 tool call" in html  # 40 + 30
    assert "efficiency-gradient" in html


def test_gauge_is_absent_when_the_session_has_no_tool_call_data_yet():
    session = {
        "session_id": "usr_gauge_no_data", "name": "test", "target": "example.com", "status": "pending",
        "created_at": "2026-01-01T00:00:00+00:00", "logs": [], "findings": [], "approvals": [],
        "chat": {"summary": "", "messages": []},
    }
    client = _client_with_session(session)
    html = client.get("/session/usr_gauge_no_data").text
    assert "Process efficiency" not in html
