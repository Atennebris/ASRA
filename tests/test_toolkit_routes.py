"""Route-level tests for the native toolkit's Site Map (main.py): GET .../toolkit/traffic
(listing) and GET .../toolkit/traffic/{entry_id} (raw detail) -- 404 handling, newest-first
ordering, the empty-state message, and the detail view's body-truncation cap. Never drives a real
mitmproxy/browser -- traffic entries are seeded directly via toolkit_store, same "mocked at the
manager/store boundary" convention as tests/test_toolkit_proxy.py.
"""
from fastapi.testclient import TestClient

import main
import projects.paths as project_paths
from agent.tools import toolkit_store
from sessions import store


def _isolate(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SESSIONS_DIR", tmp_path / "legacy")
    monkeypatch.setattr(store, "INDEX_PATH", tmp_path / "sessions_index.json")
    monkeypatch.setattr(store, "SUMMARY_INDEX_PATH", tmp_path / "sessions_summary.json")
    monkeypatch.setenv("PROJECTS_DIR", str(tmp_path / "projects"))
    project_paths.resolve_projects_base_dir.cache_clear()


def _seed_entry(session_id, **overrides):
    entry = toolkit_store.build_traffic_entry(
        session_id=session_id, method="GET", url="https://example.com/",
        request_headers={"User-Agent": "test"}, request_body="",
        response_status=200, response_headers={"Content-Type": "text/html"},
        response_body="<html></html>",
    )
    entry.update(overrides)
    toolkit_store.append_traffic_entry(entry)
    return entry


# --- GET .../toolkit/traffic (listing) ---------------------------------------------------------


def test_traffic_list_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/traffic")
    assert resp.status_code == 404


def test_traffic_list_empty_state_for_no_captures_yet(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic")
    assert resp.status_code == 200
    assert "No traffic captured yet" in resp.text


def test_traffic_list_shows_newest_capture_first(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    _seed_entry(session_id, url="https://example.com/first")
    _seed_entry(session_id, url="https://example.com/second")

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic")

    assert resp.status_code == 200
    first_pos = resp.text.index("https://example.com/first")
    second_pos = resp.text.index("https://example.com/second")
    assert second_pos < first_pos  # second was captured later, must render first (newest-first)


# --- GET .../toolkit/traffic/{entry_id} (raw detail) --------------------------------------------


def test_traffic_detail_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/traffic/whatever")
    assert resp.status_code == 404


def test_traffic_detail_404s_for_unknown_entry(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic/does-not-exist")
    assert resp.status_code == 404


def test_traffic_detail_renders_method_url_status_and_headers(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(
        session_id, method="POST", url="https://example.com/login",
        response_status=302, response_headers={"Location": "https://example.com/home"},
    )

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic/{entry['id']}")

    assert resp.status_code == 200
    assert "POST" in resp.text
    assert "https://example.com/login" in resp.text
    assert "302" in resp.text
    assert "Location: https://example.com/home" in resp.text


def test_traffic_detail_truncates_a_very_large_body(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    huge_body = "A" * (main._TOOLKIT_DETAIL_MAX_BODY_CHARS + 5000)
    entry = _seed_entry(session_id, response_body=huge_body)

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic/{entry['id']}")

    assert resp.status_code == 200
    assert "(truncated" in resp.text
    # The rendered page must not contain the full untruncated body -- only the capped prefix.
    assert huge_body not in resp.text


def test_traffic_detail_renders_binary_image_body_as_img_not_garbled_text(tmp_path, monkeypatch):
    """Route-level regression for the real bug a user found live: a JPEG response used to render
    as mojibake in the raw detail view. A base64-encoded image/* body must render as a real <img>
    tag, never the raw base64/decoded bytes dumped as text."""
    import base64
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    raw_jpeg = b"\xff\xd8\xff\xe0fake-jpeg-bytes"
    entry = _seed_entry(
        session_id,
        response_headers={"Content-Type": "image/jpeg"},
        response_body=base64.b64encode(raw_jpeg).decode("ascii"),
        response_body_encoding="base64",
        response_content_length=len(raw_jpeg),
    )

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic/{entry['id']}")

    assert resp.status_code == 200
    assert '<img src="data:image/jpeg;base64,' in resp.text
    assert base64.b64encode(raw_jpeg).decode("ascii") in resp.text
    assert "binary content" not in resp.text  # image/* gets a real preview, not the generic notice


def test_traffic_detail_renders_non_image_binary_as_placeholder_not_bytes(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(
        session_id,
        response_headers={"Content-Type": "application/octet-stream"},
        response_body="not-real-base64-but-that-is-fine-for-this-test",
        response_body_encoding="base64",
        response_content_length=12345,
    )

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic/{entry['id']}")

    assert resp.status_code == 200
    assert "binary content" in resp.text
    assert "application/octet-stream" in resp.text
    assert "12345 bytes" in resp.text
    assert "<img" not in resp.text


def test_traffic_list_shows_the_real_byte_count_for_a_base64_body(tmp_path, monkeypatch):
    """entry.response_content_length, not len(entry.response_body) -- a base64 string is ~4/3x
    longer than the real bytes it encodes, so using the raw string length would show a wrong,
    misleadingly large number for every image/binary response in the Site Map table."""
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    _seed_entry(
        session_id,
        response_headers={"Content-Type": "image/png"},
        response_body="a" * 1000,  # a long base64 string
        response_body_encoding="base64",
        response_content_length=750,  # the real, much smaller byte count
    )

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic")

    assert resp.status_code == 200
    assert "750 B" in resp.text
    assert "1000 B" not in resp.text


def test_traffic_detail_does_not_truncate_a_small_body(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(session_id, response_body="short body")

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/traffic/{entry['id']}")

    assert resp.status_code == 200
    assert "(truncated" not in resp.text
    assert "short body" in resp.text


# --- Live View toggle panel (GET .../toolkit/screencast-panel) --------------------------------
# The SSE stream route's own generator loop is deliberately not exercised here at the streaming
# level -- same precedent tests/test_chat_routes.py already established for chat_stream (a
# structurally identical route): the real CDP wiring is covered by tests/test_screencast.py
# (mocked at the manager boundary) and by this phase's own live, out-of-band manual check.


def test_screencast_panel_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/screencast-panel")
    assert resp.status_code == 404


def test_screencast_panel_defaults_to_the_off_state(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/screencast-panel")
    assert resp.status_code == 200
    assert "Show live view" in resp.text
    assert "sse-connect" not in resp.text  # off state must never carry a live connection


def test_screencast_panel_on_state_wires_up_the_sse_connection(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/screencast-panel?visible=true")
    assert resp.status_code == 200
    assert "Hide" in resp.text
    assert f"/api/session/{session_id}/toolkit/screencast/stream" in resp.text


def test_screencast_stream_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/screencast/stream")
    assert resp.status_code == 404


# --- Live View input forwarding (POST .../toolkit/live-view/input) -----------------------------
# The real dispatch (page.mouse/page.keyboard) is covered at the manager level by
# tests/test_screencast.py -- this only checks the route's own wiring: 404, JSON parsing, and that
# BrowserSessionManager.dispatch_live_view_input is actually called with the parsed payload.


class _FakeLiveViewManager:
    def __init__(self):
        self.calls: list[dict] = []

    async def dispatch_live_view_input(self, session_id, event_type, **kwargs):
        self.calls.append({"session_id": session_id, "type": event_type, **kwargs})
        return {"status": "ok"}


def test_live_view_input_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_missing/toolkit/live-view/input", json={"type": "click", "x": 1, "y": 2})
    assert resp.status_code == 404


def test_live_view_input_forwards_the_parsed_payload_to_the_manager(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    fake_manager = _FakeLiveViewManager()
    monkeypatch.setattr(main, "get_browser_manager", lambda: fake_manager)
    client = TestClient(main.app)

    resp = client.post(
        f"/api/session/{session_id}/toolkit/live-view/input",
        json={"type": "click", "x": 10.5, "y": 20.5, "button": "right", "click_count": 2},
    )

    assert resp.status_code == 204
    assert fake_manager.calls == [{
        "session_id": session_id, "type": "click", "x": 10.5, "y": 20.5,
        "button": "right", "click_count": 2, "key": "", "dx": 0.0, "dy": 0.0,
    }]


def test_live_view_input_ignores_a_malformed_body_instead_of_erroring(tmp_path, monkeypatch):
    """Real, best-effort telemetry-shaped contract (same as debug_client_event) -- a background
    fetch() call the operator never sees the response of must never surface a 4xx for a body-
    parsing hiccup."""
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/live-view/input",
        content=b"not json", headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 204


# --- Repeater (GET .../toolkit/repeater, POST .../toolkit/repeater/send) -----------------------
# send_raw_request's own real HTTP dispatch is mocked out here (monkeypatched to a fake async
# function) -- its real dispatch logic (httpx.MockTransport, text/binary encoding) is covered by
# tests/test_toolkit_repeater.py; these tests are about the ROUTE's own request/response wiring
# (form parsing, prefill, history, error surfacing), same "mock at the boundary" split as
# test_chat_routes.py already uses for main.run_session.


async def _fake_send_raw_request_ok(*, session_id, method, url, headers, body):
    entry = toolkit_store.build_traffic_entry(
        session_id=session_id, method=method, url=url,
        request_headers=headers, request_body=body,
        response_status=200, response_headers={"Content-Type": "text/plain"}, response_body="ok",
        source="repeater",
    )
    toolkit_store.append_traffic_entry(entry)
    return {"status": "ok", "entry": entry}


async def _fake_send_raw_request_error(*, session_id, method, url, headers, body):
    return {"status": "error", "error": "connection refused"}


def test_repeater_panel_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/repeater")
    assert resp.status_code == 404


def test_repeater_panel_defaults_empty_with_no_entry_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/repeater")
    assert resp.status_code == 200
    assert 'value="GET"' in resp.text
    assert "Send failed" not in resp.text


def test_repeater_panel_default_method_field_shows_the_select_with_a_custom_option(tmp_path, monkeypatch):
    """The method field is a real <select> (GET/POST/.../CONNECT) with a literal "CUSTOM" option
    as the last entry -- picking it reveals a free-text input in the same spot for a nonstandard
    verb (WebDAV methods, a deliberately malformed one). Not a datalist, not anything that
    remembers past values -- this is exactly what was asked for, nothing more."""
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/repeater")

    assert resp.status_code == 200
    assert '<option value="CUSTOM"' in resp.text
    assert '<option value="GET" selected>' in resp.text
    # The select is the visible/active control by default -- not hidden, not disabled.
    assert 'name="method"\n            onchange=' in resp.text  # the <select>, not the <input>


def test_repeater_panel_prefills_a_non_standard_method_into_the_custom_input(tmp_path, monkeypatch):
    """Reloading a history entry sent with a nonstandard verb (e.g. PROPFIND) must show it in the
    CUSTOM text field, already selected -- not silently fall back to GET."""
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(session_id, method="PROPFIND", url="https://example.com/dav", source="repeater")

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/repeater?entry_id={entry['id']}")

    assert resp.status_code == 200
    assert '<option value="CUSTOM" selected>' in resp.text
    assert 'value="PROPFIND"' in resp.text


def test_repeater_panel_prefills_from_a_site_map_entry_without_a_response_yet(tmp_path, monkeypatch):
    """A Site Map (source="proxy") entry sent to Repeater for the first time -- prefills the
    request fields, but shows no response pane yet (Repeater hasn't sent it itself)."""
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(session_id, method="POST", url="https://example.com/login", request_body="a=1")

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/repeater?entry_id={entry['id']}")

    assert resp.status_code == 200
    assert 'value="POST"' in resp.text
    assert 'value="https://example.com/login"' in resp.text
    assert "a=1" in resp.text
    assert "Response" not in resp.text  # no Repeater response pane for a fresh proxy capture


def test_repeater_panel_reloads_a_past_repeater_attempt_with_its_own_response(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(
        session_id, method="GET", url="https://example.com/api", source="repeater",
        response_status=201, response_body="created",
    )

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/repeater?entry_id={entry['id']}")

    assert resp.status_code == 200
    assert "201" in resp.text
    assert "created" in resp.text


def test_repeater_panel_shows_a_note_instead_of_a_binary_request_body(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(
        session_id, method="POST", url="https://example.com/upload",
        request_body="notarealimagebutbase64shaped", request_body_encoding="base64", request_content_length=999,
    )

    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/repeater?entry_id={entry['id']}")

    assert resp.status_code == 200
    assert "binary body" in resp.text
    assert "notarealimagebutbase64shaped" not in resp.text  # never dumped as an editable text value


def test_repeater_send_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_missing/toolkit/repeater/send", data={"method": "GET", "url": "https://example.com/"})
    assert resp.status_code == 404


def test_repeater_send_success_shows_response_and_adds_to_history(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "send_raw_request", _fake_send_raw_request_ok)
    session_id = store.create_session("https://example.com")

    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/repeater/send",
        data={"method": "get", "url": "https://example.com/x", "headers_text": "X-Test: 1", "body": ""},
    )

    assert resp.status_code == 200
    assert "200" in resp.text
    assert ">ok<" in resp.text or "ok" in resp.text
    assert "History (1)" in resp.text
    assert "Send failed" not in resp.text


def test_repeater_send_failure_shows_error_not_a_crash(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "send_raw_request", _fake_send_raw_request_error)
    session_id = store.create_session("https://example.com")

    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/repeater/send",
        data={"method": "GET", "url": "not a url", "headers_text": "", "body": ""},
    )

    assert resp.status_code == 200
    assert "Send failed" in resp.text
    assert "connection refused" in resp.text
    assert toolkit_store.load_traffic_entries(session_id) == []


def test_repeater_history_delete_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_missing/toolkit/repeater/history/some-id/delete")
    assert resp.status_code == 404


def test_repeater_history_delete_removes_the_entry_and_returns_the_history_fragment(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    keep = _seed_entry(session_id, method="GET", url="https://example.com/keep", source="repeater")
    drop = _seed_entry(session_id, method="PROPFIND", url="https://example.com/drop", source="repeater")

    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/toolkit/repeater/history/{drop['id']}/delete")

    assert resp.status_code == 200
    assert "History (1)" in resp.text
    assert "example.com/keep" in resp.text
    assert "example.com/drop" not in resp.text
    # The route re-renders only the history fragment, never the full editor form.
    assert 'id="toolkit-repeater-history"' in resp.text
    assert 'id="toolkit-repeater-container"' not in resp.text
    assert [e["id"] for e in main._repeater_history(session_id)] == [keep["id"]]


def test_repeater_history_delete_of_an_unknown_entry_is_a_no_op_not_a_crash(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    _seed_entry(session_id, method="GET", url="https://example.com/x", source="repeater")

    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/toolkit/repeater/history/not-a-real-id/delete")

    assert resp.status_code == 200
    assert "History (1)" in resp.text


# --- Decoder (GET .../toolkit/decoder, POST .../toolkit/decoder/run) --------------------------
# run_codec's own scheme behavior is covered by tests/test_toolkit_decoder.py; these are about the
# ROUTE's own wiring (404s, blank default, form round-trip, error surfacing) -- same "mock at the
# boundary" split the Repeater route tests above already use.


def test_decoder_panel_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/decoder")
    assert resp.status_code == 404


def test_decoder_panel_defaults_to_base64_encode_blank(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/decoder")
    assert resp.status_code == 200
    assert 'value="base64" selected' in resp.text
    assert 'value="encode" checked' in resp.text
    assert "Output" not in resp.text


def test_decoder_run_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post(
        "/api/session/usr_missing/toolkit/decoder/run",
        data={"scheme": "base64", "mode": "encode", "input_text": "hi"},
    )
    assert resp.status_code == 404


def test_decoder_run_encodes_and_shows_output(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/decoder/run",
        data={"scheme": "base64", "mode": "encode", "input_text": "hello"},
    )
    assert resp.status_code == 200
    assert "aGVsbG8=" in resp.text
    assert 'value="decode" checked' not in resp.text


def test_decoder_run_decodes(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/decoder/run",
        data={"scheme": "base64", "mode": "decode", "input_text": "aGVsbG8="},
    )
    assert resp.status_code == 200
    assert ">hello<" in resp.text


def test_decoder_run_invalid_input_shows_error_not_a_crash(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/decoder/run",
        data={"scheme": "hex", "mode": "decode", "input_text": "not hex"},
    )
    assert resp.status_code == 200
    assert "Output" not in resp.text
    assert resp.text.count("bg-severity-high") >= 1


def test_decoder_run_preserves_the_typed_input_on_the_form(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/decoder/run",
        data={"scheme": "url", "mode": "encode", "input_text": "a b"},
    )
    assert resp.status_code == 200
    assert "a b" in resp.text
    assert "a%20b" in resp.text


# --- Comparer (GET .../toolkit/comparer, POST .../toolkit/comparer/run) -----------------------
# diff_entries' own diff/lookup logic is covered by tests/test_toolkit_comparer.py; these are about
# the ROUTE's own wiring (404s, blank default, form round-trip, error surfacing) -- same
# "mock at the boundary" split the Repeater/Decoder route tests above already use.


def test_comparer_panel_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/comparer")
    assert resp.status_code == 404


def test_comparer_panel_lists_captured_entries_in_both_selects(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(session_id, url="https://example.com/login")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/comparer")
    assert resp.status_code == 200
    assert resp.text.count(f'value="{entry["id"]}"') == 2  # appears in select A and select B
    assert "Select two entries" in resp.text


def test_comparer_run_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_missing/toolkit/comparer/run", data={"entry_id_a": "a", "entry_id_b": "b", "part": "response"})
    assert resp.status_code == 404


def test_comparer_run_shows_a_diff_table_for_two_valid_entries(tmp_path, monkeypatch):
    # "alpha" is a shared whole-word prefix, so it survives char-level diffing as one contiguous
    # unchanged span -- unlike "world"/"there" (share only a coincidental "r"), whose own
    # char-level spans can legitimately fragment across multiple <mark> tags (real, correct
    # SequenceMatcher behavior, not a bug -- see tests/test_toolkit_comparer.py's own
    # test_diff_lines_replace_row_carries_char_level_spans for the fragment-level assertions).
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry_a = _seed_entry(session_id, response_body="alpha bravo")
    entry_b = _seed_entry(session_id, response_body="alpha charlie")
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/comparer/run",
        data={"entry_id_a": entry_a["id"], "entry_id_b": entry_b["id"], "part": "response"},
    )
    assert resp.status_code == 200
    assert "<table" in resp.text
    assert "alpha" in resp.text
    assert "<mark" in resp.text
    assert "Select two entries" not in resp.text


def test_comparer_run_shows_error_for_a_missing_entry_not_a_crash(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(session_id)
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/comparer/run",
        data={"entry_id_a": entry["id"], "entry_id_b": "missing", "part": "response"},
    )
    assert resp.status_code == 200
    assert "not found" in resp.text
    assert "<table" not in resp.text


# --- Intruder (GET .../toolkit/intruder, POST .../intruder/run, GET .../intruder/results/{id}) --
# toolkit_intruder.py's own diff/lookup/send logic is covered by tests/test_toolkit_intruder.py;
# these are about the ROUTE's own wiring. start_attack_in_background/attack_status are monkeypatched
# for the run route (deterministic, no real background asyncio.Task scheduling nuance under
# TestClient) -- the real end-to-end background-task behavior is proven by a live server run
# instead, same "mock at the boundary, real behavior proven live" split every other toolkit route
# test file already uses.


def test_intruder_panel_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/intruder")
    assert resp.status_code == 404


def test_intruder_panel_defaults_empty_with_no_entry_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/intruder")
    assert resp.status_code == 200
    assert 'value="GET"' in resp.text
    assert "Start attack" in resp.text


def test_intruder_panel_prefills_from_a_site_map_entry(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    entry = _seed_entry(session_id, method="POST", url="https://example.com/login")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/intruder?entry_id={entry['id']}")
    assert resp.status_code == 200
    assert 'value="POST"' in resp.text
    assert 'value="https://example.com/login"' in resp.text


def test_intruder_run_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post(
        "/api/session/usr_missing/toolkit/intruder/run",
        data={"method": "GET", "url": "https://example.com/§1§", "mode": "sniper", "payload_text": "A"},
    )
    assert resp.status_code == 404


def test_intruder_run_invalid_template_shows_error_not_a_crash(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/intruder/run",
        data={"method": "GET", "url": "https://example.com/no-positions", "mode": "sniper", "payload_text": "A"},
    )
    assert resp.status_code == 200
    assert "position" in resp.text
    assert "toolkit-intruder-results" not in resp.text


def test_intruder_run_success_wires_the_results_poller(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    import agent.tools.toolkit_intruder as toolkit_intruder_mod
    monkeypatch.setattr(
        toolkit_intruder_mod, "start_attack_in_background",
        lambda **kwargs: {"status": "ok", "run_id": "fixed-run-id", "expected": 2},
    )
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/intruder/run",
        data={"method": "GET", "url": "https://example.com/§1§", "mode": "sniper", "payload_text": "A\nB"},
    )
    assert resp.status_code == 200
    assert "toolkit-intruder-results" in resp.text
    assert "/toolkit/intruder/results/fixed-run-id" in resp.text
    assert "expected=2" in resp.text


def test_intruder_results_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/intruder/results/some-run")
    assert resp.status_code == 404


def test_intruder_results_shows_only_entries_for_this_run_id(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    _seed_entry(session_id, source="intruder", intruder_run_id="run-a", intruder_payload_values=["A"], url="https://example.com/A")
    _seed_entry(session_id, source="intruder", intruder_run_id="run-b", intruder_payload_values=["Z"], url="https://example.com/Z")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/intruder/results/run-a?expected=1")
    assert resp.status_code == 200
    assert "1/1 attempt" in resp.text
    assert "https://example.com/Z" not in resp.text


def test_intruder_results_flags_the_minority_response_as_an_anomaly(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    for i in range(3):
        _seed_entry(
            session_id, source="intruder", intruder_run_id="run-a", intruder_payload_values=[f"v{i}"],
            response_status=200, response_content_length=100,
        )
    _seed_entry(
        session_id, source="intruder", intruder_run_id="run-a", intruder_payload_values=["odd"],
        response_status=500, response_content_length=999,
    )
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/intruder/results/run-a?expected=4")
    assert resp.status_code == 200
    assert resp.text.count("bg-severity-high/10") >= 1  # the anomalous row is highlighted


def test_intruder_results_anomalies_only_filters_out_the_baseline_rows(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    for i in range(3):
        _seed_entry(
            session_id, source="intruder", intruder_run_id="run-a", intruder_payload_values=[f"v{i}"],
            response_status=200, response_content_length=100,
        )
    _seed_entry(
        session_id, source="intruder", intruder_run_id="run-a", intruder_payload_values=["odd"],
        response_status=500, response_content_length=999,
    )
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/intruder/results/run-a?expected=4&anomalies_only=true")
    assert resp.status_code == 200
    assert "odd" in resp.text
    assert "v0" not in resp.text


# --- Sequencer (GET .../toolkit/sequencer, POST .../sequencer/analyze) -------------------------


def test_sequencer_panel_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/session/usr_missing/toolkit/sequencer")
    assert resp.status_code == 404


def test_sequencer_panel_defaults_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/sequencer")
    assert resp.status_code == 200
    assert "Analyze" in resp.text


def test_sequencer_analyze_404s_for_unknown_session(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post("/api/session/usr_missing/toolkit/sequencer/analyze", data={"header_name": "X-Token"})
    assert resp.status_code == 404


def test_sequencer_analyze_requires_a_header_name(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.post(f"/api/session/{session_id}/toolkit/sequencer/analyze", data={"header_name": ""})
    assert resp.status_code == 200
    assert "Name the header" in resp.text


def test_sequencer_analyze_stored_mode_analyzes_captured_traffic(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    for i in range(20):
        _seed_entry(session_id, response_headers={"X-Token": f"sess{i:04d}"})
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/sequencer/analyze",
        data={"collect_mode": "stored", "header_name": "X-Token"},
    )
    assert resp.status_code == 200
    assert "weak" in resp.text


def test_sequencer_analyze_too_few_samples_shows_error_not_a_crash(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    _seed_entry(session_id, response_headers={"X-Token": "only-one"})
    client = TestClient(main.app)
    resp = client.post(
        f"/api/session/{session_id}/toolkit/sequencer/analyze",
        data={"collect_mode": "stored", "header_name": "X-Token"},
    )
    assert resp.status_code == 200
    assert "need at least" in resp.text


# --- Standalone /toolkit (no project/session at all) ------------------------------------------
# The /toolkit page and every /api/toolkit/... route are the un-prefixed twin of the routes above
# (main.py's double-decorator pattern, session_id defaulting to None) -- these tests cover the
# standalone-specific behavior (no 404 guard since there's no session to be missing, the
# toolkit-panel-standalone wrapper id, isolation from any real project's own store) rather than
# re-proving every engine behavior already covered session-scoped above.


def test_toolkit_standalone_page_renders_with_the_standalone_wrapper(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/toolkit")
    assert resp.status_code == 200
    assert "Toolkit" in resp.text
    assert 'id="toolkit-panel-standalone"' in resp.text
    assert 'id="toolkit-panel"' not in resp.text  # never the session-embedded wrapper id
    assert "toolkit-live-view" not in resp.text  # no agent browser to show a live view of


def test_toolkit_traffic_list_standalone_empty_state(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/toolkit/traffic")
    assert resp.status_code == 200
    assert "No traffic yet" in resp.text


def test_toolkit_traffic_list_standalone_shows_a_captured_entry(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    entry = toolkit_store.build_traffic_entry(
        session_id=None, method="GET", url="https://example.com/standalone-hit",
        request_headers={}, request_body="",
        response_status=200, response_headers={}, response_body="ok",
    )
    toolkit_store.append_traffic_entry(entry)

    client = TestClient(main.app)
    resp = client.get("/api/toolkit/traffic")
    assert resp.status_code == 200
    assert "https://example.com/standalone-hit" in resp.text


def test_toolkit_traffic_detail_standalone_404s_for_unknown_entry(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/toolkit/traffic/does-not-exist")
    assert resp.status_code == 404


def test_toolkit_repeater_panel_standalone_defaults_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/toolkit/repeater")
    assert resp.status_code == 200
    assert 'value="GET"' in resp.text


def test_toolkit_repeater_send_standalone_success_lands_in_the_global_store_only(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "send_raw_request", _fake_send_raw_request_ok)
    session_id = store.create_session("https://example.com")  # a real project, must stay untouched

    client = TestClient(main.app)
    resp = client.post(
        "/api/toolkit/repeater/send",
        data={"method": "GET", "url": "https://example.com/x", "headers_text": "", "body": ""},
    )

    assert resp.status_code == 200
    assert "200" in resp.text
    assert toolkit_store.load_traffic_entries(session_id) == []  # the real project's store is untouched
    global_entries = toolkit_store.load_traffic_entries(None)
    assert len(global_entries) == 1
    assert global_entries[0]["session_id"] is None


def test_toolkit_decoder_run_standalone_encodes(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.post(
        "/api/toolkit/decoder/run",
        data={"scheme": "base64", "mode": "encode", "input_text": "hello"},
    )
    assert resp.status_code == 200
    assert "aGVsbG8=" in resp.text


def test_toolkit_comparer_panel_standalone_lists_global_entries_only(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    _seed_entry(session_id, url="https://example.com/project-only")
    global_entry = toolkit_store.build_traffic_entry(
        session_id=None, method="GET", url="https://example.com/global-only",
        request_headers={}, request_body="",
        response_status=200, response_headers={}, response_body="ok",
    )
    toolkit_store.append_traffic_entry(global_entry)

    client = TestClient(main.app)
    resp = client.get("/api/toolkit/comparer")
    assert resp.status_code == 200
    assert f'value="{global_entry["id"]}"' in resp.text


def test_toolkit_intruder_panel_standalone_defaults_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/toolkit/intruder")
    assert resp.status_code == 200
    assert "Start attack" in resp.text


def test_toolkit_sequencer_panel_standalone_defaults_empty(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    client = TestClient(main.app)
    resp = client.get("/api/toolkit/sequencer")
    assert resp.status_code == 200
    assert "Analyze" in resp.text


def test_toolkit_session_scoped_routes_still_use_the_session_wrapper_not_standalone(tmp_path, monkeypatch):
    """Regression guard for the double-decorator refactor -- a real session_id must still route to
    the per-project store and the session-embedded wrapper id, never silently fall through to the
    standalone global one."""
    _isolate(tmp_path, monkeypatch)
    session_id = store.create_session("https://example.com")
    client = TestClient(main.app)
    resp = client.get(f"/api/session/{session_id}/toolkit/repeater")
    assert resp.status_code == 200
    assert f"/api/session/{session_id}/toolkit" in resp.text


def test_parse_header_lines_skips_blank_and_malformed_lines():
    parsed = main._parse_header_lines("Host: example.com\n\nbad line no colon\nX-Test:  value with spaces  \n")
    assert parsed == {"Host": "example.com", "X-Test": "value with spaces"}


def test_format_header_lines_round_trips_with_parse():
    headers = {"Host": "example.com", "User-Agent": "test"}
    assert main._parse_header_lines(main._format_header_lines(headers)) == headers
