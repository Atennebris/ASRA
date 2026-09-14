"""main.py's _load_session_for_stream -- the SSE poll loops behind #session-stream/#chat-stream/
Live View (stream_session/chat_stream/toolkit_screencast_stream) all read a session on every tick
for as long as a browser tab stays open. Real, confirmed incident this fixes: sessions/store.py's
load_session() retries a torn/corrupt JSON read for ~4s BLOCKING (a plain time.sleep loop, not an
await) before RAISING json.JSONDecodeError -- called with no try/except from inside an async
generator, that ~4s froze the whole process event loop (every other tab, every other route), and
the raised exception then killed the StreamingResponse, which made the browser's own EventSource
auto-reconnect instantly, hitting the same broken read again: a continuous freeze-then-crash loop
for as long as that one project's tab stayed open. Observed live in debug.log (96 identical "still
unreadable" lines in one minute for one real project, plus real client-side "sse: error/
reconnecting" events for that same project on a later day).
"""
import json

import main
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path)
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")


def test_load_session_for_stream_returns_the_session_normally(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("example.com", name="Stream Test Project")

    result = main._load_session_for_stream(session_id)

    assert result is not None
    assert result["session_id"] == session_id


def test_load_session_for_stream_returns_none_for_an_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)

    assert main._load_session_for_stream("usr_does_not_exist") is None


def test_load_session_for_stream_degrades_gracefully_on_a_corrupt_read_instead_of_raising(tmp_path, monkeypatch):
    """The real bug: load_session() raising json.JSONDecodeError straight out of an SSE poll loop
    with no try/except -- this helper exists specifically to turn that into a clean None (treated
    identically to "session not found": the poll loop just ends, no crash, no reconnect storm)."""
    _isolate(tmp_path, monkeypatch)

    def _raise(session_id):
        raise json.JSONDecodeError("Extra data", "{}garbage", 2)

    monkeypatch.setattr(main, "load_session", _raise)

    assert main._load_session_for_stream("usr_whatever") is None
