"""Standalone Terminal tab's HTTP/WebSocket routes (main.py's /terminal, /api/terminal/*,
/ws/terminal/{id}) -- real round trips through the actual ASGI app (FastAPI TestClient), including
a real PTY child process on the other end for the routes that create one. See
test_terminal_manager.py for the PTY backend's own read/write/echo behavior (exercised there inside
one single coherent event loop, exactly how the real server runs) -- these tests stick to what the
routing/wiring layer itself is responsible for: creating/closing a session over HTTP, the WS
handshake accepting or rejecting a connection, and the desktop-mode WebSocket token gate
(main.py's _desktop_ui_token_ok) -- the one piece that can't be exercised at the terminal_manager
level since it lives entirely in main.py's own route.

Deliberately does NOT wait on live PTY bytes arriving over a WebSocket opened through a bare
(non-context-manager) TestClient() call -- Starlette's TestClient spins up a brand-new, throwaway
event loop/thread ("portal") for EVERY separate call unless the client itself is entered via `with`
(confirmed against starlette.testclient.TestClient._portal_factory), so a terminal created by one
client.post() has its PTY reader (asyncio.get_running_loop().add_reader, agent/tools/
terminal_manager.py) registered on a loop that's already torn down by the time a later,
independent client.websocket_connect() call could ever see output from it -- a real, confirmed way
to hang a test indefinitely, and purely a TestClient artifact: a real uvicorn server runs exactly
ONE event loop for its entire lifetime, so production never hits this. Using `with TestClient(...)
as client:` instead would fix the loop-sharing problem but starts the app's real lifespan (git
fetch update-check, OpenAI SDK warm-up, the fleet worker) -- overhead and network access no other
test in this suite currently pays, so it's avoided here too.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

import agent.tools  # noqa: F401  (side effect: populates TOOL_REGISTRY)
import main
from agent.tools import terminal_manager, terminal_settings


@pytest.fixture(autouse=True)
def _cleanup_terminals():
    # terminal_settings' skip_close_confirm is deliberately a real in-memory, process-wide flag
    # now (see that module's own docstring) -- reset both before AND after each test, since it's
    # shared across every test FILE in the same pytest run, not just within this one.
    terminal_settings._skip_close_confirm = False
    yield
    terminal_manager.shutdown_all()
    terminal_settings._skip_close_confirm = False


def test_terminal_page_loads():
    client = TestClient(main.app)
    resp = client.get("/terminal")
    assert resp.status_code == 200
    assert 'id="terminal-panes"' in resp.text
    assert 'data-skip-close-confirm="false"' in resp.text


def test_terminal_page_reflects_saved_skip_close_confirm_setting():
    terminal_settings.save_skip_close_confirm(True)
    client = TestClient(main.app)
    resp = client.get("/terminal")
    assert 'data-skip-close-confirm="true"' in resp.text


def test_list_terminal_shells_route():
    client = TestClient(main.app)
    resp = client.get("/api/terminal/shells")
    assert resp.status_code == 200
    body = resp.json()
    assert body["shells"]
    assert body["default"]
    assert all("path" in s and "name" in s and s["kind"] in ("wsl", "windows") for s in body["shells"])


def test_create_terminal_route_response_includes_kind(tmp_path):
    client = TestClient(main.app)
    resp = client.post("/api/terminal/new", json={"cwd": str(tmp_path)})
    body = resp.json()
    assert body["kind"] == "wsl"  # the default shell is always a real WSL/Linux one
    terminal_manager.close_terminal(body["terminal_id"])


def test_list_terminal_sessions_route_reflects_create_and_close(tmp_path):
    """Backs static/js/terminal.js's restoreTabs() -- a real page reload has to be able to tell
    which of its previously-open tabs are still actually running server-side, or it always spawns a
    brand-new shell and orphans the old one (the exact bug this endpoint exists to fix)."""
    client = TestClient(main.app)
    resp = client.get("/api/terminal/list")
    assert resp.status_code == 200
    assert resp.json() == {"terminals": []}

    created = client.post("/api/terminal/new", json={"cwd": str(tmp_path)}).json()
    resp = client.get("/api/terminal/list")
    body = resp.json()["terminals"]
    assert len(body) == 1
    assert body[0] == {
        "terminal_id": created["terminal_id"],
        "cwd": created["cwd"],
        "shell": created["shell"],
        "kind": created["kind"],
        "exited": False,
    }

    client.post(f"/api/terminal/{created['terminal_id']}/close")
    assert client.get("/api/terminal/list").json() == {"terminals": []}


def test_save_terminal_settings_route_round_trips():
    client = TestClient(main.app)
    resp = client.post("/api/terminal/settings", json={"skip_close_confirm": True})
    assert resp.status_code == 204
    assert terminal_settings.load_terminal_settings() == {"skip_close_confirm": True}

    resp = client.post("/api/terminal/settings", json={"skip_close_confirm": False})
    assert resp.status_code == 204
    assert terminal_settings.load_terminal_settings() == {"skip_close_confirm": False}


def test_create_terminal_route_honors_a_valid_shell_override(tmp_path):
    client = TestClient(main.app)
    shells = client.get("/api/terminal/shells").json()["shells"]
    chosen = shells[0]["path"]
    resp = client.post("/api/terminal/new", json={"cwd": str(tmp_path), "shell": chosen})
    body = resp.json()
    assert body["shell"] == chosen
    terminal_manager.close_terminal(body["terminal_id"])


def test_create_and_close_terminal_route(tmp_path):
    client = TestClient(main.app)
    resp = client.post("/api/terminal/new", json={"cwd": str(tmp_path)})
    assert resp.status_code == 200
    body = resp.json()
    assert body["cwd"] == str(tmp_path)
    terminal_id = body["terminal_id"]
    assert terminal_manager.get_terminal(terminal_id) is not None

    resp = client.post(f"/api/terminal/{terminal_id}/close")
    assert resp.status_code == 204
    assert terminal_manager.get_terminal(terminal_id) is None


def test_ws_terminal_unknown_id_sends_error_and_closes():
    client = TestClient(main.app)
    with client.websocket_connect("/ws/terminal/does-not-exist") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"


def test_ws_terminal_attaches_and_accepts_input_without_error(tmp_path):
    """Proves the route wires attach()/write_input/resize/detach correctly, without depending on
    ever observing a live PTY byte arrive back (see module docstring) -- write_input/resize are
    plain synchronous os.write/ioctl calls, so accepting them here already proves the connection
    reached the real session, regardless of which loop is doing the reading on the other side."""
    async def _make():
        return await terminal_manager.create_terminal(str(tmp_path))

    session = asyncio.run(_make())
    try:
        client = TestClient(main.app)
        with client.websocket_connect(f"/ws/terminal/{session.id}") as ws:
            ws.send_bytes(b"\x01\x00\x50\x00\x18")  # resize: 80 cols, 24 rows
            ws.send_bytes(b"\x00echo not_awaited\n")  # stdin -- fire and forget, no reply awaited
    finally:
        terminal_manager.close_terminal(session.id)


def test_ws_terminal_rejects_connection_without_desktop_token(monkeypatch):
    monkeypatch.setenv("ASRA_UI_TOKEN", "s3cret-desktop-token")
    session = asyncio.run(terminal_manager.create_terminal(None))
    try:
        client = TestClient(main.app)
        with pytest.raises(Exception):
            with client.websocket_connect(f"/ws/terminal/{session.id}"):
                pass
    finally:
        terminal_manager.close_terminal(session.id)


def test_ws_terminal_accepts_connection_with_matching_desktop_token(monkeypatch, tmp_path):
    monkeypatch.setenv("ASRA_UI_TOKEN", "s3cret-desktop-token")
    session = asyncio.run(terminal_manager.create_terminal(str(tmp_path)))
    try:
        client = TestClient(main.app)
        url = f"/ws/terminal/{session.id}?__asra=s3cret-desktop-token"
        with client.websocket_connect(url) as ws:
            ws.send_bytes(b"\x00echo not_awaited\n")
    finally:
        terminal_manager.close_terminal(session.id)
