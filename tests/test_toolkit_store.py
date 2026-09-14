"""Smoke tests for agent/tools/toolkit_store.py -- captured-traffic schema + append/load, plus
is_text_content_type/encode_body (shared by every real producer of a traffic entry: the mitmproxy
addon in agent/tools/toolkit_proxy.py, and the Repeater send engine in
agent/tools/toolkit_repeater.py)."""
import base64
import json

import pytest

from agent.tools import toolkit_store


@pytest.fixture(autouse=True)
def _isolated_locks():
    """Each test starts with a clean lock registry -- the module-level dict otherwise accumulates
    one entry per distinct tmp_path across the whole test run, harmless but worth not relying on."""
    toolkit_store._write_locks.clear()


def _entry(session_id="sess_1", **overrides):
    base = toolkit_store.build_traffic_entry(
        session_id=session_id,
        method="GET",
        url="https://example.com/",
        request_headers={"User-Agent": "test"},
        request_body="",
        response_status=200,
        response_headers={"Content-Type": "text/html"},
        response_body="<html></html>",
    )
    base.update(overrides)
    return base


def test_build_traffic_entry_has_expected_schema():
    entry = _entry()
    assert set(entry) == {
        "id", "timestamp", "session_id", "method", "url",
        "request_headers", "request_body", "request_body_encoding", "request_content_length",
        "response_status", "response_headers", "response_body", "response_body_encoding", "response_content_length",
        "source", "duration_ms", "intruder_run_id", "intruder_payload_values", "flags",
    }
    assert entry["source"] == "proxy"
    assert entry["request_body_encoding"] == "text"
    assert entry["response_body_encoding"] == "text"
    assert entry["response_content_length"] == len(entry["response_body"])
    assert entry["duration_ms"] is None
    assert entry["intruder_run_id"] is None
    assert entry["intruder_payload_values"] is None


def test_build_traffic_entry_ids_are_unique():
    assert _entry()["id"] != _entry()["id"]


def test_append_traffic_entry_returns_false_without_project_folder(monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: None)
    assert toolkit_store.append_traffic_entry(_entry()) is False


def test_append_and_load_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))

    entry = _entry()
    assert toolkit_store.append_traffic_entry(entry) is True

    loaded = toolkit_store.load_traffic_entries("sess_1")
    assert loaded == [entry]


def test_append_writes_jsonl_one_line_per_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))

    toolkit_store.append_traffic_entry(_entry())
    toolkit_store.append_traffic_entry(_entry())

    traffic_path = tmp_path / "toolkit" / "traffic.jsonl"
    lines = traffic_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # each line is independently valid JSON


def test_load_traffic_entries_preserves_order(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))

    first = _entry(url="https://example.com/first")
    second = _entry(url="https://example.com/second")
    toolkit_store.append_traffic_entry(first)
    toolkit_store.append_traffic_entry(second)

    loaded = toolkit_store.load_traffic_entries("sess_1")
    assert [e["url"] for e in loaded] == ["https://example.com/first", "https://example.com/second"]


def test_load_traffic_entries_empty_when_no_project_folder(monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: None)
    assert toolkit_store.load_traffic_entries("sess_missing") == []


def test_load_traffic_entries_skips_corrupt_lines(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))

    traffic_dir = tmp_path / "toolkit"
    traffic_dir.mkdir()
    good = _entry()
    traffic_path = traffic_dir / "traffic.jsonl"
    traffic_path.write_text(
        json.dumps(good) + "\n" + "not valid json\n",
        encoding="utf-8",
    )

    loaded = toolkit_store.load_traffic_entries("sess_1")
    assert loaded == [good]


def test_load_matching_traffic_entries_filters_and_orders_oldest_of_batch_first(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))
    toolkit_store.append_traffic_entry(_entry(url="https://example.com/a", method="GET"))
    toolkit_store.append_traffic_entry(_entry(url="https://example.com/b", method="POST"))
    toolkit_store.append_traffic_entry(_entry(url="https://example.com/c", method="POST"))

    matches, truncated = toolkit_store.load_matching_traffic_entries(
        "sess_1", lambda e: e["method"] == "POST", limit=10,
    )
    assert truncated is False
    assert [e["url"] for e in matches] == ["https://example.com/b", "https://example.com/c"]


def test_load_matching_traffic_entries_respects_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))
    for i in range(5):
        toolkit_store.append_traffic_entry(_entry(url=f"https://example.com/{i}"))

    matches, truncated = toolkit_store.load_matching_traffic_entries("sess_1", lambda e: True, limit=2)
    assert truncated is False
    # Newest 2 (matches found scanning backward, then re-ordered oldest-of-batch-first).
    assert [e["url"] for e in matches] == ["https://example.com/3", "https://example.com/4"]


def test_load_matching_traffic_entries_reports_truncation_when_scan_cap_hit(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))
    for i in range(10):
        toolkit_store.append_traffic_entry(_entry(url=f"https://example.com/{i}", method="GET"))

    # Predicate that never matches, small scan cap -- forces truncation before exhausting the file.
    matches, truncated = toolkit_store.load_matching_traffic_entries(
        "sess_1", lambda e: e["method"] == "POST", limit=10, max_scan=3,
    )
    assert matches == []
    assert truncated is True


def test_load_matching_traffic_entries_no_project_folder_returns_empty(monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: None)
    matches, truncated = toolkit_store.load_matching_traffic_entries("sess_missing", lambda e: True, limit=10)
    assert matches == []
    assert truncated is False


def test_delete_traffic_entry_removes_only_the_matching_entry(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))
    keep = _entry(url="https://example.com/keep")
    drop = _entry(url="https://example.com/drop")
    toolkit_store.append_traffic_entry(keep)
    toolkit_store.append_traffic_entry(drop)

    assert toolkit_store.delete_traffic_entry("sess_1", drop["id"]) is True

    remaining = toolkit_store.load_traffic_entries("sess_1")
    assert [e["id"] for e in remaining] == [keep["id"]]


def test_delete_traffic_entry_returns_false_for_an_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))
    toolkit_store.append_traffic_entry(_entry())

    assert toolkit_store.delete_traffic_entry("sess_1", "not-a-real-id") is False
    assert len(toolkit_store.load_traffic_entries("sess_1")) == 1  # untouched


def test_delete_traffic_entry_returns_false_with_no_project_folder(monkeypatch):
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: None)
    assert toolkit_store.delete_traffic_entry("sess_missing", "any-id") is False


def test_delete_traffic_entry_works_on_the_standalone_store():
    entry = _entry(session_id=None)
    toolkit_store.append_traffic_entry(entry)

    assert toolkit_store.delete_traffic_entry(None, entry["id"]) is True
    assert toolkit_store.load_traffic_entries(None) == []


# --- is_text_content_type / encode_body ---------------------------------------------------------


@pytest.mark.parametrize("content_type", [
    "text/html", "text/html; charset=utf-8", "text/css", "text/plain",
    "application/json", "application/javascript", "application/xml", "application/xhtml+xml",
    "application/x-www-form-urlencoded", "application/ld+json",
    "application/vnd.api+json", "application/atom+xml",
    "image/svg+xml",  # genuinely XML text content, unlike raster image formats
])
def test_is_text_content_type_true_for_known_text_types(content_type):
    assert toolkit_store.is_text_content_type(content_type) is True


@pytest.mark.parametrize("content_type", [
    # image/svg+xml is deliberately excluded here -- it's genuinely XML text content (the "+xml"
    # suffix check below correctly treats it as text, not binary), unlike the truly binary raster
    # image formats below.
    "image/jpeg", "image/png", "font/woff2", "video/mp4",
    "application/octet-stream", "application/pdf", "application/zip", "application/wasm",
])
def test_is_text_content_type_false_for_known_binary_types(content_type):
    assert toolkit_store.is_text_content_type(content_type) is False


def test_encode_body_empty_bytes_is_always_text():
    assert toolkit_store.encode_body("image/jpeg", b"") == ("", "text")


def test_encode_body_known_text_type_decodes_as_text():
    body, encoding = toolkit_store.encode_body("text/html", b"<html></html>")
    assert encoding == "text"
    assert body == "<html></html>"


def test_encode_body_no_content_type_but_valid_utf8_is_text():
    body, encoding = toolkit_store.encode_body("", "plain text, no header".encode())
    assert encoding == "text"
    assert body == "plain text, no header"


def test_encode_body_binary_content_type_is_base64_not_mojibake():
    """Real incident this guards against: an image/jpeg response used to be force-decoded as text
    (get_text()), rendering as garbled symbols in the Site Map's raw detail view."""
    raw_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x00\x00\x00\x01\x00\x01\x00\x00"
    body, encoding = toolkit_store.encode_body("image/jpeg", raw_jpeg)
    assert encoding == "base64"
    assert base64.b64decode(body) == raw_jpeg


def test_encode_body_no_content_type_and_not_valid_utf8_falls_back_to_base64():
    raw_binary = b"\x00\x01\xfe\xff\x80\x81"  # not valid UTF-8
    body, encoding = toolkit_store.encode_body("", raw_binary)
    assert encoding == "base64"
    assert base64.b64decode(body) == raw_binary


# --- standalone global store (session_id=None) --------------------------------------------------
# tests/conftest.py's autouse _never_touch_real_app_state fixture already points APP_DATA_DIR at a
# fresh per-test tmp dir and clears resolve_global_app_dir's lru_cache, so no extra isolation setup
# is needed here -- every test in this file already gets its own throwaway global store for free.


def test_build_traffic_entry_allows_a_none_session_id():
    entry = _entry(session_id=None)
    assert entry["session_id"] is None


def test_append_and_load_round_trip_for_the_standalone_store():
    entry = _entry(session_id=None)
    assert toolkit_store.append_traffic_entry(entry) is True

    loaded = toolkit_store.load_traffic_entries(None)
    assert loaded == [entry]


def test_standalone_store_is_isolated_from_a_real_projects_store(tmp_path, monkeypatch):
    """The two storage backends must never bleed into each other -- a real session's traffic must
    not show up in the standalone store's list, and vice versa."""
    monkeypatch.setattr(toolkit_store, "get_session_folder", lambda session_id: str(tmp_path))

    toolkit_store.append_traffic_entry(_entry(session_id="sess_1", url="https://example.com/project"))
    toolkit_store.append_traffic_entry(_entry(session_id=None, url="https://example.com/standalone"))

    project_urls = [e["url"] for e in toolkit_store.load_traffic_entries("sess_1")]
    standalone_urls = [e["url"] for e in toolkit_store.load_traffic_entries(None)]

    assert project_urls == ["https://example.com/project"]
    assert standalone_urls == ["https://example.com/standalone"]


def test_get_traffic_entry_finds_an_entry_in_the_standalone_store():
    entry = _entry(session_id=None)
    toolkit_store.append_traffic_entry(entry)
    assert toolkit_store.get_traffic_entry(None, entry["id"]) == entry


def test_load_traffic_entries_empty_for_a_fresh_standalone_store():
    assert toolkit_store.load_traffic_entries(None) == []
